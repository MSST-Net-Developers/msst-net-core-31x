//! Local identity — keypair, user/device IDs and auth credentials.
//!
//! Ported from 3.0.x `identity.rs`.  The on-disk format (`private.key` +
//! `identity.json`) is unchanged so an existing 3.0.x data directory keeps
//! its device ID, user ID and virtual IPs after upgrading.

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::{debug, error, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub handle: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub handle: String,
    pub display_name: String,
    /// Server-assigned ezPlay hostname, e.g. "abjust-archlinux.abjust.ezplay.msst.net".
    /// Populated (and persisted) after the first successful coordinator registration.
    #[serde(default)]
    pub hostname: String,
    /// Override IPv4 address assigned by the coordinator when the deterministically
    /// derived address was already in use by another device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_ipv4: Option<String>,
}

/// OIDC-derived credentials, persisted alongside the identity.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthCredentials {
    /// OIDC-derived user_id (overrides the locally-derived one once authenticated).
    pub user_id: String,
    pub access_token: String,
    pub refresh_token: String,
    /// Unix timestamp when `access_token` expires.
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityFile {
    pub user: UserInfo,
    pub device: DeviceInfo,
    /// Present only after the user completes the OIDC auth flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthCredentials>,
}

#[derive(Clone)]
pub struct Identity {
    pub user: UserInfo,
    pub device: DeviceInfo,
    pub secret_key: [u8; 32],
    pub public_key: [u8; 32],
    pub auth: Option<AuthCredentials>,
}

// Hand-written so the secret key can never end up in a log line.
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("user", &self.user)
            .field("device", &self.device)
            .field("public_key", &STANDARD.encode(self.public_key))
            .field("authenticated", &self.auth.is_some())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// WireGuard-compatible base64-encoded public key.
    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.public_key)
    }

    /// [`Identity::virtual_ips`] in canonical text form (RFC 5952), for
    /// Controllers.  The raw form is kept for the coordinator `register`
    /// message, which 3.0.x sends exactly as derived.
    pub fn virtual_ips_canonical(&self) -> (String, String) {
        let (v4, v6) = self.virtual_ips();
        let canon = |s: String| s.parse::<std::net::IpAddr>().map(|a| a.to_string()).unwrap_or(s);
        (canon(v4), canon(v6))
    }

    /// The virtual IPv4/IPv6 addresses of this device.
    ///
    /// IPv4 is the coordinator-assigned override when present (conflict
    /// resolution), otherwise the address derived from the device ID.
    pub fn virtual_ips(&self) -> (String, String) {
        let (derived_ipv4, ipv6) = crate::ip::derive_ips(crate::ip::extract_hex(&self.device.id));
        let ipv4 = self
            .device
            .assigned_ipv4
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or(derived_ipv4);
        (ipv4, ipv6)
    }
}

pub(crate) fn derive_id(pubkey: &[u8; 32], prefix: &str) -> String {
    let hash = Sha256::digest(pubkey);
    // First 4 bytes (8 hex chars) as the ID suffix.
    let hex_str: String = hash[..4].iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}-{}", prefix, hex_str)
}

pub fn load_or_create(data_dir: &Path) -> Result<Identity> {
    let identity_path = data_dir.join("identity.json");
    let privkey_path = data_dir.join("private.key");

    // Load or generate the Curve25519 keypair (WireGuard-compatible format).
    // NOTE: never log the raw private key bytes — only the public key.
    let (secret_bytes, public_bytes) = if privkey_path.exists() {
        let key_b64 = std::fs::read_to_string(&privkey_path).inspect_err(|e| {
            error!("Failed to read private key file {:?}: {}", privkey_path, e)
        })?;
        let key_vec = STANDARD.decode(key_b64.trim()).inspect_err(|e| {
            error!("Failed to decode private key file {:?}: {}", privkey_path, e)
        })?;
        if key_vec.len() != 32 {
            anyhow::bail!(
                "Invalid private key length in {:?}: expected 32 bytes, got {}",
                privkey_path,
                key_vec.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_vec);
        let secret = StaticSecret::from(arr);
        let public = PublicKey::from(&secret);
        info!(
            "Loaded existing Curve25519 keypair from {:?} (public key: {})",
            privkey_path,
            STANDARD.encode(public.as_bytes())
        );
        (secret.to_bytes(), *public.as_bytes())
    } else {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let sb = secret.to_bytes();
        let pb = *public.as_bytes();
        write_private_key(&privkey_path, &STANDARD.encode(sb)).inspect_err(|e| {
            error!("Failed to write private key file {:?}: {}", privkey_path, e)
        })?;
        info!(
            "Generated new Curve25519 keypair (public key: {}), saved to {:?}",
            STANDARD.encode(pb),
            privkey_path
        );
        (sb, pb)
    };

    let (user, device, auth) = if identity_path.exists() {
        let content = std::fs::read_to_string(&identity_path).inspect_err(|e| {
            error!("Failed to read identity file {:?}: {}", identity_path, e)
        })?;
        let id_file: IdentityFile = serde_json::from_str(&content).inspect_err(|e| {
            error!("Failed to parse identity file {:?}: {}", identity_path, e)
        })?;
        let mut user = id_file.user;
        let mut device = id_file.device;
        let auth = id_file.auth;
        // Migrate legacy ID prefixes: "dev-" → "device-", "usr-" → "user-"
        let mut migrated = false;
        if let Some(hex) = user.id.strip_prefix("usr-") {
            user.id = format!("user-{}", hex);
            migrated = true;
        }
        if let Some(hex) = device.id.strip_prefix("dev-") {
            device.id = format!("device-{}", hex);
            migrated = true;
        }
        // The Coordinator only accepts a device ID derived from the key
        // (keyproof v1, client change 3).  A mismatch means identity.json is
        // stale relative to private.key (e.g. a regenerated key): re-derive
        // the ID and drop what the Coordinator assigned to the old ID,
        // instead of being rejected with `invalid_device_key` forever.
        let derived = derive_id(&public_bytes, "device");
        if device.id != derived {
            warn!(
                "identity: device ID {} does not match private.key — re-deriving {} (assigned IPv4 and hostname reset)",
                device.id, derived
            );
            device.id = derived;
            device.assigned_ipv4 = None;
            device.hostname = String::new();
            migrated = true;
        }
        if migrated {
            let updated = IdentityFile { user: user.clone(), device: device.clone(), auth: auth.clone() };
            std::fs::write(&identity_path, serde_json::to_string_pretty(&updated)?).inspect_err(|e| {
                error!("Failed to write migrated identity file {:?}: {}", identity_path, e)
            })?;
            info!("Migrated identity file {:?}", identity_path);
        } else {
            debug!(
                "Loaded identity file {:?} (user={}, device={})",
                identity_path, user.id, device.id
            );
        }
        (user, device, auth)
    } else {
        let user = UserInfo {
            id: derive_id(&public_bytes, "user"),
            handle: String::new(),
            display_name: String::new(),
        };
        let device = DeviceInfo {
            id: derive_id(&public_bytes, "device"),
            handle: String::new(),
            display_name: String::new(),
            hostname: String::new(),
            assigned_ipv4: None,
        };
        let id_file = IdentityFile { user: user.clone(), device: device.clone(), auth: None };
        std::fs::write(&identity_path, serde_json::to_string_pretty(&id_file)?).inspect_err(|e| {
            error!("Failed to write identity file {:?}: {}", identity_path, e)
        })?;
        info!("Created identity file: {:?}", identity_path);
        (user, device, None)
    };

    Ok(Identity { user, device, secret_key: secret_bytes, public_key: public_bytes, auth })
}

/// Persist the mutable parts (user/device info, auth) back to `identity.json`.
/// The keypair file is not touched.
pub fn save(data_dir: &Path, identity: &Identity) -> Result<()> {
    let identity_path = data_dir.join("identity.json");
    let id_file = IdentityFile {
        user: identity.user.clone(),
        device: identity.device.clone(),
        auth: identity.auth.clone(),
    };
    std::fs::write(&identity_path, serde_json::to_string_pretty(&id_file)?).inspect_err(|e| {
        error!("Failed to persist identity file {:?}: {}", identity_path, e)
    })?;
    info!("Persisted identity file: {:?}", identity_path);
    Ok(())
}

/// Write the private key with owner-only permissions on Unix.
fn write_private_key(path: &Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "msst-identity-test-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn create_then_reload_is_stable() {
        let dir = temp_dir("stable");
        let a = load_or_create(&dir).unwrap();
        let b = load_or_create(&dir).unwrap();
        assert_eq!(a.device.id, b.device.id);
        assert_eq!(a.user.id, b.user.id);
        assert_eq!(a.secret_key, b.secret_key);
        assert!(a.device.id.starts_with("device-") && a.device.id.len() == 15);
        assert!(a.user.id.starts_with("user-") && a.user.id.len() == 13);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ids_derive_from_public_key() {
        let dir = temp_dir("derive");
        let id = load_or_create(&dir).unwrap();
        assert_eq!(id.device.id, derive_id(&id.public_key, "device"));
        assert_eq!(id.user.id, derive_id(&id.public_key, "user"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_3_0_x_identity_file_and_migrates_legacy_prefixes() {
        let dir = temp_dir("legacy");
        // A key + identity file as written by 3.0.x (legacy prefixes).
        let public = PublicKey::from(&StaticSecret::from([7u8; 32]));
        let hex = derive_id(public.as_bytes(), "device").trim_start_matches("device-").to_string();
        std::fs::write(dir.join("private.key"), STANDARD.encode([7u8; 32])).unwrap();
        std::fs::write(
            dir.join("identity.json"),
            format!(
                r#"{{"user":{{"id":"usr-11223344","handle":"abjust","display_name":"A"}},
                "device":{{"id":"dev-{hex}","handle":"pc","display_name":"PC",
                          "hostname":"pc.abjust.ezplay.msst.net","assigned_ipv4":"172.22.9.9"}},
                "auth":{{"user_id":"user-11223344","access_token":"t","refresh_token":"r","expires_at":1}}}}"#
            ),
        )
        .unwrap();
        let id = load_or_create(&dir).unwrap();
        assert_eq!(id.user.id, "user-11223344");
        assert_eq!(id.device.id, format!("device-{}", hex));
        assert_eq!(id.device.hostname, "pc.abjust.ezplay.msst.net");
        assert!(id.auth.is_some());
        // Coordinator-assigned IPv4 wins over the derived one.
        assert_eq!(id.virtual_ips().0, "172.22.9.9");
        // Canonical form for Controllers; the raw derivation is unchanged.
        let mut zero = id.clone();
        zero.device.id = "device-00000001".into();
        zero.device.assigned_ipv4 = None;
        assert_eq!(zero.virtual_ips().1, "fd22:2222:2222:2222::0000:0001");
        assert_eq!(zero.virtual_ips_canonical().1, "fd22:2222:2222:2222::1");
        // Migration was written back.
        let reloaded: IdentityFile =
            serde_json::from_str(&std::fs::read_to_string(dir.join("identity.json")).unwrap()).unwrap();
        assert_eq!(reloaded.device.id, format!("device-{}", hex));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_device_id_is_rederived_from_key() {
        let dir = temp_dir("stale-id");
        std::fs::write(dir.join("private.key"), STANDARD.encode([1u8; 32])).unwrap();
        std::fs::write(
            dir.join("identity.json"),
            r#"{"user":{"id":"user-11223344","handle":"abjust","display_name":"A"},
                "device":{"id":"device-a1b2c3d4","handle":"pc","display_name":"PC",
                          "hostname":"pc.abjust.ezplay.msst.net","assigned_ipv4":"172.22.9.9"}}"#,
        )
        .unwrap();
        let id = load_or_create(&dir).unwrap();
        // DEVICE_KEY_PROOF.md vector: key 32 × 0x01 → device-1a92f238.
        assert_eq!(id.device.id, "device-1a92f238");
        assert_eq!(id.device.assigned_ipv4, None);
        assert_eq!(id.device.hostname, "");
        // Handles, names and the user ID are kept.
        assert_eq!((id.device.handle.as_str(), id.user.id.as_str()), ("pc", "user-11223344"));
        let reloaded: IdentityFile =
            serde_json::from_str(&std::fs::read_to_string(dir.join("identity.json")).unwrap()).unwrap();
        assert_eq!(reloaded.device.id, "device-1a92f238");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let dir = temp_dir("debug");
        let id = load_or_create(&dir).unwrap();
        let secret_b64 = STANDARD.encode(id.secret_key);
        assert!(!format!("{:?}", id).contains(&secret_b64));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
