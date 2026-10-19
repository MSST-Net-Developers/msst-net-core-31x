//! IPC access control for the Unix-socket transport.
//!
//! Ported from 3.0.x `ipc.rs`.  Core is privileged, so being able to open
//! the socket is not enough: every accepted connection's kernel-verified
//! peer UID (SO_PEERCRED / getpeereid via tokio's `peer_cred()`) decides,
//! before any frame is exchanged, whether it may connect and with which
//! [`Role`] (protocol 0.4, `msst_ipc_protocol::access`):
//!
//! - **admin**: Core's own user, root, the `sudo` invoker, and members of
//!   the local group [`ADMIN_GROUP`] (looked up at every connect, so adding
//!   a user to the group needs no Core restart);
//! - **viewer**: any other user with an active local login session;
//! - everyone else is refused.
//!
//! The socket file is often world-connectable (0666) because Core commonly
//! runs as a root daemon while the Controller runs as the logged-in user;
//! file permissions alone can't tell that user apart from any other local
//! account, which is why the UID check exists.

#![cfg(unix)]

use msst_ipc_protocol::Role;
#[cfg(not(target_os = "android"))]
use std::ffi::{CStr, CString};
use std::path::Path;
use tracing::{debug, warn};

/// Local group whose members get the admin role.
pub const ADMIN_GROUP: &str = "msst-net";

/// The role of a peer UID, or `None` if it may not connect at all.
///
/// A local login session is a `/run/user/<uid>` directory owned by that UID
/// with mode 0700 (the guarantee that protects `$XDG_RUNTIME_DIR`) on Linux,
/// and the console user on macOS.
pub fn peer_role(peer_uid: u32) -> Option<Role> {
    let self_uid = unsafe { libc::geteuid() };
    let sudo_uid = std::env::var("SUDO_UID").ok().and_then(|s| s.parse().ok());
    classify(peer_uid, self_uid, sudo_uid, |uid| in_group(uid, ADMIN_GROUP), has_local_session)
}

/// The pure role rule (see [`peer_role`]).
pub fn classify(
    peer_uid: u32,
    self_uid: u32,
    sudo_uid: Option<u32>,
    in_admin_group: impl Fn(u32) -> bool,
    has_local_session: impl Fn(u32) -> bool,
) -> Option<Role> {
    if peer_uid == self_uid || peer_uid == 0 || sudo_uid == Some(peer_uid) || in_admin_group(peer_uid) {
        Some(Role::Admin)
    } else if has_local_session(peer_uid) {
        Some(Role::Viewer)
    } else {
        None
    }
}

/// Android (embedded Core): the app-private socket's only peer is the app
/// itself, which is admin as Core's own user; there are no local groups.
#[cfg(target_os = "android")]
fn in_group(_uid: u32, _group: &str) -> bool {
    false
}

/// Whether `uid` is a member of the local group `group` (as its primary
/// group or as a listed member).  A missing group means no members.
#[cfg(not(target_os = "android"))]
fn in_group(uid: u32, group: &str) -> bool {
    let Some((user, primary_gid)) = user_entry(uid) else { return false };
    let Some((gid, members)) = group_entry(group) else { return false };
    primary_gid == gid || members.contains(&user)
}

/// `(name, primary gid)` of a UID.
#[cfg(not(target_os = "android"))]
fn user_entry(uid: u32) -> Option<(String, libc::gid_t)> {
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid as libc::uid_t, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded, so pw_name points into `buf`.
    let name = unsafe { CStr::from_ptr(pw.pw_name) }.to_string_lossy().into_owned();
    Some((name, pw.pw_gid))
}

/// `(gid, member names)` of a group.
#[cfg(not(target_os = "android"))]
fn group_entry(name: &str) -> Option<(libc::gid_t, Vec<String>)> {
    let cname = CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 64 * 1024];
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::group = std::ptr::null_mut();
    let rc = unsafe { libc::getgrnam_r(cname.as_ptr(), &mut gr, buf.as_mut_ptr(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() {
        return None;
    }
    let mut members = Vec::new();
    let mut p = gr.gr_mem;
    // SAFETY: gr_mem is a NULL-terminated array of C strings inside `buf`.
    unsafe {
        while !p.is_null() && !(*p).is_null() {
            members.push(CStr::from_ptr(*p).to_string_lossy().into_owned());
            p = p.add(1);
        }
    }
    Some((gr.gr_gid, members))
}

#[cfg(target_os = "linux")]
fn has_local_session(uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(format!("/run/user/{}", uid))
        .is_ok_and(|m| m.is_dir() && m.uid() == uid && (m.mode() & 0o777) == 0o700)
}

#[cfg(target_os = "macos")]
fn has_local_session(uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/dev/console").is_ok_and(|m| m.uid() == uid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn has_local_session(_uid: u32) -> bool {
    false
}

/// Socket file mode for the current deployment.
///
/// - `sudo` invocation: 0660, chowned to the invoking user.
/// - Root daemon (systemd/launchd): 0666; `is_peer_authorized` gates use.
/// - Unprivileged run: 0600 — only our own user ever connects.
pub fn socket_mode(euid: u32, via_sudo: bool) -> u32 {
    if via_sudo {
        0o660
    } else if euid == 0 {
        0o666
    } else {
        0o600
    }
}

/// Apply [`socket_mode`] to the bound socket (and chown under `sudo`).
pub fn set_socket_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let via_sudo = std::env::var("SUDO_UID").is_ok();
    let mode = socket_mode(unsafe { libc::geteuid() }, via_sudo);
    match std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        Ok(()) => debug!("IPC: socket permissions set to {:o}", mode),
        Err(e) => warn!("IPC: failed to set socket permissions to {:o}: {}", mode, e),
    }
    if via_sudo {
        chown_to_sudo_user(path);
    }
}

/// The socket directory: root-owned, world-traversable, not world-writable,
/// so unprivileged processes cannot replace the socket file.
pub fn secure_socket_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)) {
        warn!("IPC: failed to set permissions on socket directory {:?}: {}", dir, e);
    }
}

/// Chown `path` to `SUDO_UID:SUDO_GID` (sudo invocation only).
pub fn chown_to_sudo_user(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let parse = |k: &str| std::env::var(k).ok().and_then(|s| s.parse::<u32>().ok());
    let (Some(uid), Some(gid)) = (parse("SUDO_UID"), parse("SUDO_GID")) else { return };
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return };
    if unsafe { libc::chown(cpath.as_ptr(), uid, gid) } != 0 {
        warn!("IPC: chown to {}:{} failed: {}", uid, gid, std::io::Error::last_os_error());
    } else {
        debug!("IPC: socket chowned to invoking user {}:{}", uid, gid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_rule() {
        let none = |_| false;
        assert_eq!(classify(1000, 1000, None, none, none), Some(Role::Admin)); // same user
        assert_eq!(classify(0, 1000, None, none, none), Some(Role::Admin)); // root
        assert_eq!(classify(1000, 0, Some(1000), none, none), Some(Role::Admin)); // sudo invoker
        assert_eq!(classify(1001, 0, Some(1000), none, none), None); // another account
        assert_eq!(classify(1001, 0, None, none, |u| u == 1001), Some(Role::Viewer)); // logged-in user
        assert_eq!(classify(1001, 0, None, |u| u == 1001, |u| u == 1001), Some(Role::Admin)); // group member
        assert_eq!(classify(1002, 0, None, |u| u == 1002, none), Some(Role::Admin)); // member without a session
    }

    #[test]
    #[cfg(not(target_os = "android"))]
    fn group_lookup() {
        // root's primary group is gid 0, named "root" on Linux, "wheel" on macOS.
        let (name, gid) = user_entry(0).unwrap();
        assert_eq!((name.as_str(), gid), ("root", 0));
        let group = if cfg!(target_os = "macos") { "wheel" } else { "root" };
        assert!(in_group(0, group));
        assert!(!in_group(0, "msst-net-no-such-group"));
        assert!(user_entry(u32::MAX - 1).is_none());
    }

    #[test]
    fn socket_modes() {
        assert_eq!(socket_mode(0, true), 0o660);
        assert_eq!(socket_mode(0, false), 0o666);
        assert_eq!(socket_mode(1000, false), 0o600);
    }

    #[test]
    fn own_uid_is_admin() {
        assert_eq!(peer_role(unsafe { libc::geteuid() }), Some(Role::Admin));
    }
}
