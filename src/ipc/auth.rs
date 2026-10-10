//! IPC access control for the Unix-socket transport.
//!
//! Ported from 3.0.x `ipc.rs`.  Core is privileged, so being able to open
//! the socket is not enough: every accepted connection's kernel-verified
//! peer UID (SO_PEERCRED / getpeereid via tokio's `peer_cred()`) must be
//! authorized before any frame is exchanged.
//!
//! The socket file is often world-connectable (0666) because Core commonly
//! runs as a root daemon while the Controller runs as the logged-in user;
//! file permissions alone can't tell that user apart from any other local
//! account, which is why the UID check exists.

#![cfg(unix)]

use std::path::Path;
use tracing::{debug, warn};

/// Whether a peer UID may use the IPC socket.
///
/// Allowed: Core's own effective UID, root, the user who invoked Core via
/// `sudo` (`SUDO_UID`), and — on Linux — any UID with an active local login
/// session (a `/run/user/<uid>` directory owned by that UID with mode 0700,
/// the same guarantee that protects `$XDG_RUNTIME_DIR`); on macOS, the
/// console user.
pub fn is_peer_authorized(peer_uid: u32) -> bool {
    let self_uid = unsafe { libc::geteuid() };
    let sudo_uid = std::env::var("SUDO_UID").ok().and_then(|s| s.parse().ok());
    decide(peer_uid, self_uid, sudo_uid, has_local_session)
}

/// The pure authorization rule (see [`is_peer_authorized`]).
pub fn decide(
    peer_uid: u32,
    self_uid: u32,
    sudo_uid: Option<u32>,
    has_local_session: impl Fn(u32) -> bool,
) -> bool {
    peer_uid == self_uid || peer_uid == 0 || sudo_uid == Some(peer_uid) || has_local_session(peer_uid)
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
    fn authorization_rule() {
        let no_session = |_| false;
        assert!(decide(1000, 1000, None, no_session)); // same user
        assert!(decide(0, 1000, None, no_session)); // root
        assert!(decide(1000, 0, Some(1000), no_session)); // sudo invoker
        assert!(!decide(1001, 0, Some(1000), no_session)); // another account
        assert!(!decide(1001, 0, None, no_session));
        assert!(decide(1001, 0, None, |u| u == 1001)); // logged-in user
    }

    #[test]
    fn socket_modes() {
        assert_eq!(socket_mode(0, true), 0o660);
        assert_eq!(socket_mode(0, false), 0o666);
        assert_eq!(socket_mode(1000, false), 0o600);
    }

    #[test]
    fn own_uid_is_authorized() {
        assert!(is_peer_authorized(unsafe { libc::geteuid() }));
    }
}
