//! Collects a process and its ancestors on macOS.

use std::fmt;
use std::io;
use std::os::fd::AsFd;

use procline_core::{EnvPolicy, ProcessChain};

/// What to collect besides the always-collected items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectOptions {
    pub env: EnvPolicy,
    pub icon: bool,
    pub max_ancestors: usize,
}

/// Collects the peer of a connected UNIX domain socket and its ancestors.
pub fn collect_peer<S: AsFd>(
    _stream: &S,
    _options: &CollectOptions,
) -> Result<ProcessChain, CollectError> {
    todo!()
}

/// Collects the process with the given pid and its ancestors.
pub fn collect_pid(_pid: i32, _options: &CollectOptions) -> Result<ProcessChain, CollectError> {
    todo!()
}

/// Collection failed as a whole.
#[derive(Debug)]
pub enum CollectError {
    /// The peer credentials of the socket could not be read.
    Peer(io::Error),
    /// No process with the pid exists.
    NoSuchProcess { pid: i32 },
    /// An identifier recorded at the start changed before collection finished.
    IdentityChanged,
}

impl fmt::Display for CollectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Peer(err) => write!(f, "cannot read the peer of the socket: {err}"),
            Self::NoSuchProcess { pid } => write!(f, "no process with pid {pid}"),
            Self::IdentityChanged => {
                f.write_str("the process was replaced while collecting; retry the collection")
            }
        }
    }
}

impl std::error::Error for CollectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Peer(err) => Some(err),
            Self::NoSuchProcess { .. } | Self::IdentityChanged => None,
        }
    }
}
