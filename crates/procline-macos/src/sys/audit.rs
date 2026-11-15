//! The values embedded in an audit token, read with libbsm.

use std::mem::size_of;

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

/// The pid of the process the token names (`<bsm/libbsm.h>`).
pub(crate) fn pid(token: AuditToken) -> i32 {
    // SAFETY: `RawAuditToken` has the exact `audit_token_t` C layout; libbsm only reads its by-value argument.
    unsafe { audit_token_to_pid(RawAuditToken { val: token.0 }) }
}

/// The audit session ID of the process the token names (`<bsm/libbsm.h>`).
pub(crate) fn asid(token: AuditToken) -> u32 {
    // SAFETY: `RawAuditToken` matches the by-value C argument; `au_asid_t` is `pid_t` (signed), so cast preserves its 32-bit ID even for the sentinel value.
    unsafe { audit_token_to_asid(RawAuditToken { val: token.0 }) as u32 }
}

/// The pid version of the running image embedded in the token (`<bsm/libbsm.h>`).
pub(crate) fn pidversion(token: AuditToken) -> i32 {
    // SAFETY: `RawAuditToken` has the exact `audit_token_t` C layout; libbsm only reads its by-value argument.
    unsafe { audit_token_to_pidversion(RawAuditToken { val: token.0 }) }
}
