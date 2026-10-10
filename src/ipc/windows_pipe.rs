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

#![cfg(windows)]

use std::os::windows::io::RawHandle;
use tokio::net::windows::named_pipe::NamedPipeServer;
use winapi::shared::minwindef::FALSE;
use winapi::shared::sddl::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
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
