use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::signature::{Bundle, CodeSigning, SignatureTrust};

/// The target process first, followed by its ancestors up to launchd.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessChain {
    processes: Vec<ProcessInfo>,
    /// The boot UUID (`kern.bootsessionuuid`) of the system the chain was collected on; `Identity::process_identity` takes it.
    pub boot_uuid: String,
    /// Why the ancestor walk stopped before reaching the root; `None` when it reached the root. On a truncated chain, a grant with conditions on the ancestors that does not match cannot be decided; one that matches also matches the whole chain.
    pub truncated: Option<Truncated>,
}

impl ProcessChain {
    /// Builds a chain from the target and its ancestors in order, with the boot UUID of the system they run on.
    pub fn new(
        processes: Vec<ProcessInfo>,
        boot_uuid: String,
        truncated: Option<Truncated>,
    ) -> Self {
        Self {
            processes,
            boot_uuid,
            truncated,
        }
    }

    /// `[0]` is the target, the rest are its ancestors.
    pub fn processes(&self) -> &[ProcessInfo] {
        &self.processes
    }
}

/// Why the ancestor walk of a chain stopped before reaching the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Truncated {
    /// The walk reached `max_ancestors` of the collect options.
    MaxAncestors,
    /// An ancestor exited during the walk.
    AncestorExited,
    /// An ancestor could not be read.
    Unavailable,
}

/// What was collected about one process. Items that could not be collected are empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub identity: Identity,
    pub credentials: Option<Credentials>,
    pub code_signing: Option<CodeSigning>,
    pub path: Option<PathBuf>,
    /// The owner of the file at `path` and whether the user can write it; decides the class of `path`.
    pub path_meta: Option<PathMeta>,
    /// Hash of the contents of the file at `path` (`sha256:…`); collected only when `digest` of the collect options is set.
    pub digest: Option<String>,
    /// The app bundle found by walking up from `path`; for display only. Matching on `bundle_id` uses `Signature.bundle_id`.
    pub bundle: Option<Bundle>,
    /// The individual responsible process, identified like the `process` matcher item.
    pub responsible: Option<ProcessIdentity>,
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

/// Attributes of the file at the executable path that decide how much the path pins down the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathMeta {
    pub owner_uid: u32,
    /// The user running the process can replace the file: it can write the file itself or any directory on the path to it.
    pub writable_by_user: bool,
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
    /// The identifiers that make up the pin value of the `process` matcher item, with the boot UUID of the chain (`ProcessChain.boot_uuid`).
    pub fn process_identity(&self, boot_uuid: &str) -> ProcessIdentity {
        ProcessIdentity {
            boot_uuid: boot_uuid.to_owned(),
            unique_id: self.unique_id,
            pid: self.pid,
            start_time: self.start_time,
        }
    }
}

/// The pin value of the `process` matcher item ("this individual process"): every identifier available when it was pinned.
///
/// It identifies the individual, which stays the same across an `exec` that replaces its code; the identity of the code is the `binary` item's, so pin both to pin both.
///
/// Matching compares every identifier present on both sides and requires all of them to be equal. The derived `==` compares the fields as written and is not that matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    /// The boot the process ran in, so identifiers reused after a restart do not match.
    pub boot_uuid: String,
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
