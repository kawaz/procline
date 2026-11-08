//! UNIX domain socket peer audit tokens and their libbsm accessors.

use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, BorrowedFd};

use procline_core::AuditToken;

/// `audit_token_t` is `unsigned int val[8]` (`<mach/message.h>`). Its C layout is required for libbsm's by-value arguments.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawAuditToken {
    val: [u32; 8],
}

const _: () = assert!(size_of::<RawAuditToken>() == 32);

#[link(name = "bsm")]
unsafe extern "C" {
    fn audit_token_to_pid(token: RawAuditToken) -> libc::pid_t;
    fn audit_token_to_asid(token: RawAuditToken) -> libc::pid_t;
    fn audit_token_to_pidversion(token: RawAuditToken) -> libc::c_int;
}

/// `getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN)` (`<sys/un.h>`) on a connected UNIX domain socket.
pub(crate) fn peer_token(fd: BorrowedFd<'_>) -> io::Result<AuditToken> {
    let mut token = RawAuditToken { val: [0; 8] };
    let mut len = libc::socklen_t::try_from(size_of::<RawAuditToken>())
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: `fd` is borrowed and valid for the call, and `token` is a writable 32-byte `audit_token_t`; `len` initially states that size and receives the actual byte count.
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            (&raw mut token).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(len).ok() != Some(size_of::<RawAuditToken>()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peer audit token of {len} bytes, expected 32"),
        ));
    }
    Ok(AuditToken(token.val))
}

/// The peer pid embedded in the token (`<bsm/libbsm.h>`).
pub(crate) fn pid(token: AuditToken) -> i32 {
    // SAFETY: `RawAuditToken` has the exact `audit_token_t` C layout; libbsm only reads its by-value argument.
    unsafe { audit_token_to_pid(RawAuditToken { val: token.0 }) }
}

/// The peer audit session ID embedded in the token (`<bsm/libbsm.h>`).
pub(crate) fn asid(token: AuditToken) -> u32 {
    // SAFETY: `RawAuditToken` matches the by-value C argument; `au_asid_t` is `pid_t` (signed), so cast preserves its 32-bit ID even for the sentinel value.
    unsafe { audit_token_to_asid(RawAuditToken { val: token.0 }) as u32 }
}

/// The pid version of the running image embedded in the token (`<bsm/libbsm.h>`).
pub(crate) fn pidversion(token: AuditToken) -> i32 {
    // SAFETY: `RawAuditToken` has the exact `audit_token_t` C layout; libbsm only reads its by-value argument.
    unsafe { audit_token_to_pidversion(RawAuditToken { val: token.0 }) }
}
