//! Collects a process and its ancestors on macOS, and provides the `os.*` vocabulary items.

mod collect;
mod file;
mod os_items;
mod path_meta;
mod procargs;
mod signing;
mod sys;

use std::fmt;
use std::io;
use std::os::fd::AsFd;

use procline_core::{EnvPolicy, ProcessChain, Redaction};

/// What to collect besides the always-collected items.
pub struct CollectOptions {
    pub env: EnvPolicy,
    /// How the collected environment values are redacted.
    pub redaction: Redaction,
    pub icon: bool,
    /// Hash the contents of the executable (`ProcessInfo.digest`); off unless set.
    pub digest: bool,
    /// Verify the code signature of every process (`ProcessInfo.code_signing`). Off leaves it `None` and makes the chain unusable for `binary` conditions, but cuts the time to well under a millisecond for a first, light pass (a Touch ID prompt that only needs names and paths).
    pub signature: bool,
    pub max_ancestors: usize,
}

/// Design rationale: `Redaction` holds closures, which have no `Debug`, `Clone` or `PartialEq`, so `CollectOptions` derives none of them; `Debug` is written by hand and leaves out `redaction`.
impl fmt::Debug for CollectOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CollectOptions")
            .field("env", &self.env)
            .field("icon", &self.icon)
            .field("digest", &self.digest)
            .field("signature", &self.signature)
            .field("max_ancestors", &self.max_ancestors)
            .finish_non_exhaustive()
    }
}

/// The `os.*` items (`os.session`, `os.console_user`, `os.login_session`, `os.not_remote`, `os.console_active`), for the application to add with `Vocabulary::register`.
///
/// `os.session` observes the levels `boot` and `awake`; the level `unlocked` is not observed yet, so pinning it fails with `Unobservable`. `os.console_user`, `os.not_remote` and `os.console_active` are not implemented yet: observing them fails, so grants using them are undecidable and none can be made.
pub fn os_items() -> Vec<procline_acl::Item> {
    os_items::items()
}

/// Collects the peer of a connected UNIX domain socket and its ancestors. The peer's audit token identifies its process and addresses its code signature; the other processes' signatures are looked up by pid.
pub fn collect_peer<S: AsFd>(
    stream: &S,
    options: &CollectOptions,
) -> Result<ProcessChain, CollectError> {
    collect::collect_peer(stream.as_fd(), options)
}

/// Collects the process with the given pid and its ancestors.
///
/// The identifiers of every process are recorded first, everything else is read by pid, and the identifiers are read again at the end: if the target is no longer the same process running the same image (no `exec` in between), the result is discarded with `IdentityChanged`; if an ancestor is no longer the same process, the chain ends before it with `Truncated::AncestorExited`. The code signature is looked up by pid.
pub fn collect_pid(pid: i32, options: &CollectOptions) -> Result<ProcessChain, CollectError> {
    collect::collect_pid(pid, options)
}

/// Collection failed as a whole.
#[derive(Debug)]
pub enum CollectError {
    /// The peer credentials of the socket could not be read.
    Peer(io::Error),
    /// No process with the pid exists.
    NoSuchProcess { pid: i32 },
    /// The identifiers of the target process could not be read for a reason other than its absence.
    Unreadable { pid: i32, source: io::Error },
    /// The boot UUID (`kern.bootsessionuuid`) could not be read.
    BootUuid(io::Error),
    /// An identifier recorded at the start changed before collection finished.
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
                f.write_str("the process was replaced while collecting; retry the collection")
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
