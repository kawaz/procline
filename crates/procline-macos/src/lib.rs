//! Collects a process and its ancestors on macOS, and reads the epochs of the host (the boot UUID, the time of the last wake).

#![deny(unsafe_code)]

mod collect;
mod file;
mod path_meta;
mod procargs;
mod signing;
#[allow(
    unsafe_code,
    reason = "the FFI layer: the only module that calls the OS through unsafe"
)]
mod sys;

use std::fmt;
use std::io;
use std::os::fd::AsFd;
use std::time::Duration;

use procline_core::{EnvPolicy, ProcessChain, Redaction};

/// What to collect besides the always-collected items.
pub struct CollectOptions {
    pub env: EnvPolicy,
    /// How the collected environment values are redacted.
    pub redaction: Redaction,
    pub icon: bool,
    /// Hash the contents of the executable (`ProcessInfo.digest`); off unless set.
    pub digest: bool,
    /// Read the bundle ID and version of the nearest `.app` above the executable from its `Contents/Info.plist` (`ProcessInfo.bundle`, for display; the bundle ID sealed by the signature is `VerifiedSignature.bundle_id`). Only a regular file of at most 1 MiB is read, and only the values directly under its top-level dictionary are taken, within limits on the parsing events and the bytes the parsing reads; anything else leaves it `None`. Off leaves it `None` and skips parsing a file that the owner of the process can write.
    pub bundle: bool,
    /// Verify the code signature of every process (`ProcessInfo.code_signing`). Off leaves it `None` and makes the chain unusable for `binary` conditions, but cuts the time to well under a millisecond for a first, light pass (a Touch ID prompt that only needs names and paths).
    pub signature: bool,
    /// The time the verification of the signatures of one collection may take. Once it runs out, the processes whose verification has not started are `CodeSigning::NotChecked`; a verification under way is not cut short. `None` verifies every process.
    pub signature_budget: Option<Duration>,
    /// Fill `NamedId.names` with every name that resolves to each uid / gid by enumerating the user and group databases once per collection (about 16 ms on a Mac with a few hundred system accounts; a resident daemon can cache the result). Off keeps only the representative name.
    pub all_names: bool,
    pub max_ancestors: usize,
}

/// Design rationale: `Redaction` holds closures, which have no `Debug`, `Clone` or `PartialEq`, so `CollectOptions` derives none of them; `Debug` is written by hand and leaves out `redaction`.
impl fmt::Debug for CollectOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CollectOptions")
            .field("env", &self.env)
            .field("icon", &self.icon)
            .field("digest", &self.digest)
            .field("bundle", &self.bundle)
            .field("signature", &self.signature)
            .field("signature_budget", &self.signature_budget)
            .field("all_names", &self.all_names)
            .field("max_ancestors", &self.max_ancestors)
            .finish_non_exhaustive()
    }
}

/// The boot UUID of the running system (`kern.bootsessionuuid`): a new value at every boot. The same value as `ProcessChain::boot_uuid` of the collections made during this boot.
pub fn boot_session_uuid() -> io::Result<String> {
    sys::proc::boot_session_uuid()
}

/// The time of the last wake from sleep (`kern.waketime`), in seconds since the epoch (the microseconds dropped): a new value at every wake.
pub fn wake_time_secs() -> io::Result<i64> {
    sys::proc::wake_time_secs()
}

/// Collects the peer of a connected UNIX domain socket and its ancestors. The peer's audit token identifies its process and addresses its code signature; the other processes' signatures are looked up by pid.
///
/// Signatures are verified with requirements and without the network (`procline_core::verify`); when the executable cannot be read or was replaced, the signature the kernel keeps for the running code is verified instead. The results are not cached.
///
/// The identifiers are recorded and read again at the end as for [`collect_pid`]. A peer that has exited (also one not yet reaped by its parent) makes the collection fail: with `Peer` (`ENOTCONN`) when every process holding the other end of the socket has exited before the audit token is read, with `NoSuchProcess` when the peer exited after that and before it was recorded, and with `IdentityChanged` when it exited after it was recorded. When only the process that last sent or received on the other end has exited while another process still holds that end, the audit token cannot be read and the collection fails with `Peer` (`EINVAL`); once that pid belongs to another process, the token is that process's and it is the one collected.
pub fn collect_peer<S: AsFd>(
    stream: &S,
    options: &CollectOptions,
) -> Result<ProcessChain, CollectError> {
    collect::collect_peer(stream.as_fd(), options)
}

/// Collects the process with the given pid and its ancestors.
///
/// The identifiers of every process are recorded first, everything else is read by pid, and the identifiers are read again at the end: if the target, or an ancestor that is still the same process, no longer runs the same image (an `exec` in between), the result is discarded with `IdentityChanged`; if an ancestor is no longer the same process, the chain ends before it with `Truncated::AncestorExited`. The code signature is looked up by pid.
///
/// A process that has exited but has not yet been reaped by its parent (a zombie) counts as exited: an ancestor ends the chain as above, and a target that has exited, before or during the collection, makes it fail with `NoSuchProcess`.
pub fn collect_pid(pid: i32, options: &CollectOptions) -> Result<ProcessChain, CollectError> {
    collect::collect_pid(pid, options)
}

/// Collection failed as a whole.
#[derive(Debug)]
pub enum CollectError {
    /// The peer's audit token (`LOCAL_PEERTOKEN`) could not be read; `ENOTCONN` when every process holding the other end of the socket has exited, `EINVAL` when the process that last sent or received on the other end has exited while another process still holds that end.
    Peer(io::Error),
    /// No process with the pid exists, or it has exited and awaits being reaped by its parent.
    NoSuchProcess { pid: i32 },
    /// The identifiers of the target process could not be read for a reason other than its absence.
    Unreadable { pid: i32, source: io::Error },
    /// The boot UUID (`kern.bootsessionuuid`) could not be read.
    BootUuid(io::Error),
    /// An identifier recorded at the start changed before collection finished: the target was replaced or ran `exec`, or an ancestor ran `exec`. For `collect_peer`, also a peer that exited after it was recorded.
    IdentityChanged,
}

impl fmt::Display for CollectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Peer(err) => write!(f, "cannot read the peer of the socket: {err}"),
            Self::NoSuchProcess { pid } => write!(f, "no process with pid {pid}"),
            Self::Unreadable { pid, source } => {
                write!(f, "cannot read the process with pid {pid}: {source}")
            }
            Self::BootUuid(err) => write!(f, "cannot read the boot UUID: {err}"),
            Self::IdentityChanged => {
                f.write_str("a process of the chain was replaced or ran another program while collecting; retry the collection")
            }
        }
    }
}

impl std::error::Error for CollectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Peer(err) | Self::Unreadable { source: err, .. } | Self::BootUuid(err) => {
                Some(err)
            }
            Self::NoSuchProcess { .. } | Self::IdentityChanged => None,
        }
    }
}
