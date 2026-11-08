use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::signature::{Bundle, CodeSigning, SignatureTrust};

/// The target process first, followed by its ancestors up to launchd.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessChain {
    processes: Vec<ProcessInfo>,
    /// The ancestor walk stopped before reaching the root.
    pub truncated: bool,
}

impl ProcessChain {
    /// Builds a chain from the target and its ancestors in order.
    pub fn new(processes: Vec<ProcessInfo>, truncated: bool) -> Self {
        Self {
            processes,
            truncated,
        }
    }

    /// `[0]` is the target, the rest are its ancestors.
    pub fn processes(&self) -> &[ProcessInfo] {
        &self.processes
    }
}

/// What was collected about one process. Items that could not be collected are empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub identity: Identity,
    pub credentials: Option<Credentials>,
    pub code_signing: Option<CodeSigning>,
    pub path: Option<PathBuf>,
    pub bundle: Option<Bundle>,
    /// pid of the responsible process.
    pub responsible_pid: Option<i32>,
    pub name: Option<String>,
    pub argv: Option<Vec<String>>,
    pub cwd: Option<PathBuf>,
    pub tty: Option<String>,
    /// Collected according to `EnvPolicy`, already redacted.
    pub env: Option<BTreeMap<String, String>>,
    /// Display-only icon, PNG bytes.
    pub icon_png: Option<Vec<u8>>,
}

impl ProcessInfo {
    /// Trust level of the code signature, if the signing state was collected.
    pub fn signature_trust(&self) -> Option<SignatureTrust> {
        self.code_signing.as_ref().map(CodeSigning::trust)
    }
}

/// Identifiers that pin down one process stronger than a pid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Present only for the connected peer.
    pub audit_token: Option<AuditToken>,
    pub unique_id: Option<u64>,
    pub parent_unique_id: Option<u64>,
    pub pid: i32,
    pub start_time: Option<StartTime>,
    pub asid: Option<u32>,
}

impl Identity {
    /// The identifiers that make up the pin value of the `process` matcher item.
    pub fn process_identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            unique_id: self.unique_id,
            pid: self.pid,
            start_time: self.start_time,
        }
    }
}

/// The pin value of the `process` matcher item ("this individual process"): every identifier available when it was pinned.
///
/// Matching compares by the strongest identifier present on both sides, at worst the pair of pid and start time. The derived `==` compares the fields as written and is not that matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub unique_id: Option<u64>,
    pub pid: i32,
    pub start_time: Option<StartTime>,
}

/// Opaque audit token of a connected peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditToken(pub [u32; 8]);

/// Process start time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StartTime {
    pub secs: u64,
    pub micros: u32,
}

/// uid / gid / groups. Matching uses the numbers, names are for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub uid: NamedId,
    pub gid: NamedId,
    pub groups: Vec<NamedId>,
}

/// A numeric ID with every name that resolves to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedId {
    pub id: u32,
    pub names: Vec<String>,
}
