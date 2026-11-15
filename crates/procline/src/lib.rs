//! Entry crate: the core types, and the collector for the build target OS.

#![forbid(unsafe_code)]

pub use procline_core::*;

#[cfg(target_os = "macos")]
pub use procline_macos::{
    CollectError, CollectOptions, boot_session_uuid, collect_peer, collect_pid, wake_time_secs,
};
