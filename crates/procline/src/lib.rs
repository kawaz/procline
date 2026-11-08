//! Entry crate: the core types and the collector for the build target OS.

pub use procline_core::*;

#[cfg(target_os = "macos")]
pub use procline_macos::{CollectError, CollectOptions, collect_peer, collect_pid};
