//! Principal mnemonic → stable ID resolution.
//!
//! Persistent rules identify principals by stable IDs (`device-XXXXXXXX` /
//! `user-XXXXXXXX`), never by mnemonics (AGENTS.md §9).  A mnemonic given
//! when a rule is created is resolved here: first against local knowledge
//! (own identity + peer list), then via the coordinator.  If it cannot be
//! resolved the rule is rejected.  The original mnemonic is kept separately,
//! for display only.
//!
//! Device mnemonics: `pc.abjust` (device handle . user handle) or `pc`
//! (a device of the *local* user — 3.0.x semantics).  User mnemonics: `abjust`.

use super::parse::is_stable_id;
use msst_acl_engine::PermissionGroup;
use msst_core_state::peer_list::PeerList;
use std::collections::BTreeMap;

/// Principal kind of a mnemonic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Device,
    User,
}

/// Why a mnemonic could not be resolved.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolveFailure {
    /// Neither local state nor the coordinator know this mnemonic.
    NotFound { mnemonic: String },
    /// The coordinator could not be asked (network / HTTP error).
    Unavailable { mnemonic: String, reason: String },
}

impl std::fmt::Display for ResolveFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveFailure::NotFound { mnemonic } => write!(f, "mnemonic '{}' does not match any known device or user", mnemonic),
            ResolveFailure::Unavailable { mnemonic, reason } => {
                write!(f, "cannot resolve mnemonic '{}': coordinator unavailable ({})", mnemonic, reason)
            }
        }
    }
}

/// The local identity, for resolving mnemonics that refer to ourselves.
#[derive(Debug, Clone, Default)]
pub struct LocalIdentity {
    pub device_id: String,
    pub device_handle: String,
    pub user_id: String,
    pub user_handle: String,
}

impl LocalIdentity {
    /// The user label used in hostnames: the handle, or the ID if unset.
    pub fn user_label(&self) -> &str {
        if self.user_handle.is_empty() { &self.user_id } else { &self.user_handle }
    }
}

/// Remote (coordinator) lookups.  `Ok(None)` = definitively unknown.
pub trait RemoteResolver {
    /// Resolve an ezPlay hostname (`<device>.<user>.ezplay.net.msst2031.cn`) to a device ID.
    fn device_id(&self, hostname: &str) -> impl std::future::Future<Output = Result<Option<String>, String>> + Send;
    /// Resolve a user handle to a user ID.
    fn user_id(&self, handle: &str) -> impl std::future::Future<Output = Result<Option<String>, String>> + Send;
}

/// All mnemonics (non-ID, non-wildcard principals) in a permission group.
pub fn mnemonics(pg: &PermissionGroup) -> Vec<(Kind, String)> {
    match pg {
        PermissionGroup::Devices { ids } => ids.iter().filter(|i| !is_stable_id("device", i)).map(|i| (Kind::Device, i.clone())).collect(),
        PermissionGroup::Users { ids } => ids.iter().filter(|i| !is_stable_id("user", i)).map(|i| (Kind::User, i.clone())).collect(),
        PermissionGroup::Space => Vec::new(),
    }
}

/// Resolve a mnemonic from local knowledge only (no I/O).
pub fn resolve_locally(kind: Kind, mnemonic: &str, me: &LocalIdentity, peers: &PeerList) -> Option<String> {
    match kind {
        Kind::Device => {
            let (dev, user) = match mnemonic.split_once('.') {
                Some((d, u)) => (d, Some(u)),
                None => (mnemonic, None),
            };
            let user_is_me = user.is_none_or(|u| u == me.user_handle || u == me.user_id);
            if user_is_me && !me.device_handle.is_empty() && dev == me.device_handle {
                return Some(me.device_id.clone());
            }
            peers.resolve_device_mnemonic(mnemonic, &me.user_id).map(str::to_string)
        }
        Kind::User => {
            if !me.user_handle.is_empty() && mnemonic == me.user_handle {
                return Some(me.user_id.clone());
            }
            peers.resolve_user_handle(mnemonic).map(str::to_string)
        }
    }
}

/// The hostname the coordinator's DNS resolves for a device mnemonic.
pub fn device_hostname(mnemonic: &str, me: &LocalIdentity) -> String {
    if mnemonic.contains('.') {
        format!("{}{}", mnemonic, crate::dns::EZPLAY_SUFFIX)
    } else {
        format!("{}.{}{}", mnemonic, me.user_label(), crate::dns::EZPLAY_SUFFIX)
    }
}

/// Resolve the mnemonics that local knowledge could not, via the coordinator.
/// Fails on the first mnemonic that cannot be resolved.
pub async fn resolve_remotely<R: RemoteResolver>(
    pending: &[(Kind, String)],
    me: &LocalIdentity,
    remote: &R,
) -> Result<BTreeMap<String, String>, ResolveFailure> {
    let mut out = BTreeMap::new();
    for (kind, m) in pending {
        let result = match kind {
            Kind::Device => remote.device_id(&device_hostname(m, me)).await,
            Kind::User => remote.user_id(m).await,
        };
        let expected = if *kind == Kind::Device { "device" } else { "user" };
        match result {
            Ok(Some(id)) if is_stable_id(expected, &id) => {
                out.insert(m.clone(), id);
            }
            Ok(_) => return Err(ResolveFailure::NotFound { mnemonic: m.clone() }),
            Err(reason) => return Err(ResolveFailure::Unavailable { mnemonic: m.clone(), reason }),
        }
    }
    Ok(out)
}

/// Replace mnemonics in `pg` using `resolved` (mnemonic → ID).
///
/// Returns the rewritten group and the display map (ID → mnemonic as
/// entered).  Duplicate IDs (e.g. `pc` and `device-…` naming the same
/// device) are collapsed.
pub fn apply_resolution(pg: &PermissionGroup, resolved: &BTreeMap<String, String>) -> (PermissionGroup, BTreeMap<String, String>) {
    let mut labels = BTreeMap::new();
    let mut rewrite = |ids: &Vec<String>| {
        let mut out: Vec<String> = Vec::new();
        for id in ids {
            let new = match resolved.get(id) {
                Some(stable) => {
                    labels.insert(stable.clone(), id.clone());
                    stable.clone()
                }
                None => id.clone(),
            };
            if !out.contains(&new) {
                out.push(new);
            }
        }
        out
    };
    let pg = match pg {
        PermissionGroup::Devices { ids } => PermissionGroup::Devices { ids: rewrite(ids) },
        PermissionGroup::Users { ids } => PermissionGroup::Users { ids: rewrite(ids) },
        PermissionGroup::Space => PermissionGroup::Space,
    };
    (pg, labels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn me() -> LocalIdentity {
        LocalIdentity {
            device_id: "device-00000001".into(),
            device_handle: "laptop".into(),
            user_id: "user-00000001".into(),
            user_handle: "abjust".into(),
        }
    }

    fn peers() -> PeerList {
        let mut pl = PeerList::new();
        let ip = |s: &str| s.parse().unwrap();
        // Another device of mine, and a friend's device.
        pl.upsert("device-00000002", ip("172.22.0.2"), ip("fd22:2222:2222:2222::2"), Some("user-00000001"), Some("pc"), Some("abjust"), None, None, None, true, 0);
        pl.upsert("device-0000000b", ip("172.22.0.11"), ip("fd22:2222:2222:2222::b"), Some("user-0000000b"), Some("pc"), Some("bob"), None, None, None, true, 0);
        pl
    }

    struct FakeRemote {
        devices: HashMap<String, String>,
        users: HashMap<String, String>,
        down: bool,
    }

    impl RemoteResolver for FakeRemote {
        async fn device_id(&self, hostname: &str) -> Result<Option<String>, String> {
            if self.down { return Err("connection refused".into()); }
            Ok(self.devices.get(hostname).cloned())
        }
        async fn user_id(&self, handle: &str) -> Result<Option<String>, String> {
            if self.down { return Err("connection refused".into()); }
            Ok(self.users.get(handle).cloned())
        }
    }

    #[test]
    fn local_resolution() {
        let (me, pl) = (me(), peers());
        // Simple device handle = one of *my* devices, never bob's "pc".
        assert_eq!(resolve_locally(Kind::Device, "pc", &me, &pl).as_deref(), Some("device-00000002"));
        assert_eq!(resolve_locally(Kind::Device, "pc.bob", &me, &pl).as_deref(), Some("device-0000000b"));
        assert_eq!(resolve_locally(Kind::Device, "laptop", &me, &pl).as_deref(), Some("device-00000001"));
        assert_eq!(resolve_locally(Kind::Device, "laptop.abjust", &me, &pl).as_deref(), Some("device-00000001"));
        assert_eq!(resolve_locally(Kind::Device, "nas", &me, &pl), None);
        assert_eq!(resolve_locally(Kind::User, "bob", &me, &pl).as_deref(), Some("user-0000000b"));
        assert_eq!(resolve_locally(Kind::User, "abjust", &me, &pl).as_deref(), Some("user-00000001"));
        assert_eq!(resolve_locally(Kind::User, "carol", &me, &pl), None);
    }

    #[test]
    fn hostnames_for_coordinator_lookup() {
        assert_eq!(device_hostname("nas", &me()), "nas.abjust.ezplay.net.msst2031.cn");
        assert_eq!(device_hostname("pc.carol", &me()), "pc.carol.ezplay.net.msst2031.cn");
        let mut no_handle = me();
        no_handle.user_handle.clear();
        assert_eq!(device_hostname("nas", &no_handle), "nas.user-00000001.ezplay.net.msst2031.cn");
    }

    #[tokio::test]
    async fn remote_resolution_success_not_found_and_unavailable() {
        let remote = FakeRemote {
            devices: [("nas.abjust.ezplay.net.msst2031.cn".to_string(), "device-0000000a".to_string())].into(),
            users: [("carol".to_string(), "user-0000000c".to_string())].into(),
            down: false,
        };
        let got = resolve_remotely(&[(Kind::Device, "nas".into()), (Kind::User, "carol".into())], &me(), &remote).await.unwrap();
        assert_eq!(got["nas"], "device-0000000a");
        assert_eq!(got["carol"], "user-0000000c");

        let err = resolve_remotely(&[(Kind::Device, "ghost".into())], &me(), &remote).await.unwrap_err();
        assert_eq!(err, ResolveFailure::NotFound { mnemonic: "ghost".into() });

        let down = FakeRemote { devices: HashMap::new(), users: HashMap::new(), down: true };
        let err = resolve_remotely(&[(Kind::User, "carol".into())], &me(), &down).await.unwrap_err();
        assert!(matches!(err, ResolveFailure::Unavailable { .. }));
    }

    #[tokio::test]
    async fn remote_answer_with_wrong_id_kind_is_rejected() {
        let remote = FakeRemote {
            devices: [("x.abjust.ezplay.net.msst2031.cn".to_string(), "user-0000000c".to_string())].into(),
            users: HashMap::new(),
            down: false,
        };
        assert!(resolve_remotely(&[(Kind::Device, "x".into())], &me(), &remote).await.is_err());
    }

    #[test]
    fn apply_rewrites_ids_and_records_labels() {
        let pg = PermissionGroup::Devices { ids: vec!["pc".into(), "device-00000002".into(), "*".into(), "pc.bob".into()] };
        assert_eq!(mnemonics(&pg), vec![(Kind::Device, "pc".to_string()), (Kind::Device, "pc.bob".to_string())]);
        let resolved: BTreeMap<_, _> = [("pc".to_string(), "device-00000002".to_string()), ("pc.bob".to_string(), "device-0000000b".to_string())].into();
        let (pg, labels) = apply_resolution(&pg, &resolved);
        assert!(matches!(&pg, PermissionGroup::Devices { ids } if ids == &vec!["device-00000002".to_string(), "*".to_string(), "device-0000000b".to_string()]));
        assert_eq!(labels["device-00000002"], "pc");
        assert_eq!(labels["device-0000000b"], "pc.bob");
        assert!(mnemonics(&pg).is_empty());
    }
}
