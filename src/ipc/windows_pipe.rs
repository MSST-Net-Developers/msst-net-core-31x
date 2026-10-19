//! Windows IPC transport: a named pipe restricted by its ACL.
//!
//! The Windows counterpart of the Unix socket's peer-UID check.  Only
//! these principals may open the pipe:
//! - `SY` LocalSystem and `BA` Administrators — full access;
//! - `IU` interactive users (logged-in desktop / RDP sessions) — read/write.
//! Services, network logons and every other account are refused by the
//! kernel before any byte is exchanged.  Additionally:
//! - `PIPE_REJECT_REMOTE_CLIENTS` refuses connections over the network;
//! - `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first instance makes startup fail
//!   if another process already owns the pipe name (no squatting).
//!
//! (3.0.x used a NULL DACL — anyone, including network logons, could
//! connect.)  The protocol on top is unchanged: `serve_client`.
//!
//! Role (protocol 0.4): after the version handshake (impersonation needs
//! data read from the pipe first) Core impersonates the client briefly and
//! checks its token.  Admin: LocalSystem, Core's own user, elevated
//! Administrators (a UAC-filtered token has that group deny-only, so it
//! doesn't count) and members of [`ADMIN_GROUP`].  Everyone else the DACL
//! lets in (interactive users) is a viewer; so is a client whose identity
//! can't be read.

#![cfg(windows)]

use msst_ipc_protocol::Role;
use std::os::windows::io::{AsRawHandle, RawHandle};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tracing::warn;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, TRUE};
use winapi::shared::sddl::{ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, SDDL_REVISION_1};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::namedpipeapi::ImpersonateNamedPipeClient;
use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken};
use winapi::um::securitybaseapi::{CheckTokenMembership, EqualSid, GetTokenInformation, RevertToSelf};
use winapi::um::winbase::LookupAccountNameW;
use winapi::um::winnt::{TokenUser, HANDLE, PSID, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::namedpipeapi::CreateNamedPipeW;
use winapi::um::winbase::{
    LocalFree, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

/// Protected DACL: SYSTEM + Administrators full, interactive users read/write.
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Create one pipe instance carrying [`PIPE_SDDL`].
pub fn create_instance(name: &str, first: bool) -> std::io::Result<NamedPipeServer> {
    unsafe {
        let mut sd = std::ptr::null_mut();
        let sddl = wide(PIPE_SDDL);
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1 as u32, &mut sd, std::ptr::null_mut()) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: FALSE,
        };
        let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
        let name = wide(name);
        let handle = CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            65536,
            65536,
            0,
            &mut sa,
        );
        let err = std::io::Error::last_os_error();
        LocalFree(sd);
        if handle == INVALID_HANDLE_VALUE {
            return Err(err);
        }
        NamedPipeServer::from_raw_handle(handle as RawHandle)
    }
}

/// Local group whose members get the admin role.
pub const ADMIN_GROUP: &str = "MSST-Net Administrators";

/// LocalSystem and BUILTIN\Administrators.
const ADMIN_SIDS: &[&str] = &["S-1-5-18", "S-1-5-32-544"];

/// The role of the client connected to `pipe`.  Call only after data has
/// been read from the pipe (the version handshake).
pub fn client_role(pipe: &NamedPipeServer) -> Option<Role> {
    match unsafe { client_token_role(pipe.as_raw_handle()) } {
        Ok(role) => Some(role),
        Err(e) => {
            warn!("IPC: cannot read the pipe client's identity ({}); treating it as a viewer", e);
            Some(Role::Viewer)
        }
    }
}

struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn check(ok: BOOL) -> std::io::Result<()> {
    if ok == 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

/// Impersonate the client just long enough to open its token.
unsafe fn client_token(pipe: RawHandle) -> std::io::Result<Owned> {
    unsafe {
        check(ImpersonateNamedPipeClient(pipe as HANDLE))?;
        let mut tok: HANDLE = std::ptr::null_mut();
        // OpenAsSelf: the access check uses Core's own identity.
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &mut tok);
        let err = std::io::Error::last_os_error();
        if RevertToSelf() == 0 {
            // Continuing as the client would be a privilege confusion.
            panic!("IPC: RevertToSelf failed: {}", std::io::Error::last_os_error());
        }
        if opened == 0 {
            return Err(err);
        }
        Ok(Owned(tok))
    }
}

unsafe fn client_token_role(pipe: RawHandle) -> std::io::Result<Role> {
    unsafe {
        let tok = client_token(pipe)?;
        if is_own_user(tok.0)? {
            return Ok(Role::Admin);
        }
        for sid in ADMIN_SIDS {
            if let Some(sid) = string_sid(sid) {
                let member = is_member(tok.0, sid.0);
                winapi::um::winbase::LocalFree(sid.0 as _);
                if member? {
                    return Ok(Role::Admin);
                }
            }
        }
        if let Some(sid) = account_sid(ADMIN_GROUP) {
            if is_member(tok.0, sid.as_ptr() as PSID)? {
                return Ok(Role::Admin);
            }
        }
        Ok(Role::Viewer)
    }
}

unsafe fn is_member(tok: HANDLE, sid: PSID) -> std::io::Result<bool> {
    let mut member: BOOL = FALSE;
    check(unsafe { CheckTokenMembership(tok, sid, &mut member) })?;
    Ok(member != 0)
}

/// A SID from its string form; freed with `LocalFree` by the caller.
struct LocalSid(PSID);

fn string_sid(s: &str) -> Option<LocalSid> {
    let mut sid: PSID = std::ptr::null_mut();
    let w = wide(s);
    (unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut sid) } != 0).then_some(LocalSid(sid))
}

/// The SID of a local account or group, or `None` if it doesn't exist.
fn account_sid(name: &str) -> Option<Vec<u8>> {
    let w = wide(name);
    let mut sid = vec![0u8; 256];
    let mut sid_len = sid.len() as DWORD;
    let mut domain = vec![0u16; 256];
    let mut domain_len = domain.len() as DWORD;
    let mut use_: SID_NAME_USE = 0;
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            w.as_ptr(),
            sid.as_mut_ptr() as PSID,
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut use_,
        )
    };
    (ok != 0).then_some(sid)
}

/// The user SID in `tok` equals Core's own user SID.
unsafe fn is_own_user(tok: HANDLE) -> std::io::Result<bool> {
    unsafe {
        let mut own: HANDLE = std::ptr::null_mut();
        check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut own))?;
        let own = Owned(own);
        let a = token_user(tok)?;
        let b = token_user(own.0)?;
        let sa = (*(a.as_ptr() as *const TOKEN_USER)).User.Sid;
        let sb = (*(b.as_ptr() as *const TOKEN_USER)).User.Sid;
        Ok(EqualSid(sa, sb) != 0)
    }
}

/// `TOKEN_USER` (with its SID) in an aligned buffer.
unsafe fn token_user(tok: HANDLE) -> std::io::Result<Vec<u64>> {
    let mut buf = vec![0u64; 64];
    let mut len: DWORD = 0;
    check(unsafe {
        GetTokenInformation(tok, TokenUser, buf.as_mut_ptr() as _, (buf.len() * 8) as DWORD, &mut len)
    })?;
    Ok(buf)
}
