//! Synthetic processes and chains for the tests: nothing here calls the OS.

#![allow(dead_code, reason = "each test file uses part of the helpers")]

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use procline_acl::{Condition, ItemKind, MatchTarget, Matcher, Vocabulary};
use procline_core::{
    CdHash, CodeSigning, Credentials, Identity, NamedId, ProcessChain, ProcessInfo, Signature,
    SignatureValidity, StartTime,
};

/// The boot UUID of every synthetic chain.
pub const BOOT: &str = "7B1E0000-0000-0000-0000-000000000001";

/// A process with every identifier (pid, unique_id, start time) and nothing else collected. The unique_id and start time are derived from the pid so that distinct pids give distinct individuals.
pub fn process(pid: i32) -> ProcessInfo {
    let id = u64::try_from(pid).unwrap();
    ProcessInfo {
        identity: Identity {
            audit_token: None,
            unique_id: Some(10_000 + id),
            parent_unique_id: None,
            pid,
            start_time: Some(StartTime {
                secs: 1_762_570_000 + id,
                micros: 0,
            }),
            asid: None,
        },
        credentials: None,
        code_signing: None,
        path: None,
        path_meta: None,
        digest: None,
        bundle: None,
        responsible: None,
        name: None,
        argv: None,
        cwd: None,
        tty: None,
        env: None,
        icon_png: None,
    }
}

/// A process with only a name, for matching on `name`.
pub fn named(pid: i32, name: &str) -> ProcessInfo {
    ProcessInfo {
        name: Some(name.to_owned()),
        ..process(pid)
    }
}

/// A verified Developer ID style signature with the given Team ID and signing identifier.
pub fn signature(team_id: &str, signing_id: &str) -> Signature {
    Signature {
        validity: SignatureValidity::Valid,
        signing_id: Some(signing_id.to_owned()),
        team_id: Some(team_id.to_owned()),
        bundle_id: None,
        cdhash: Some(CdHash([0xab; 20])),
        certificates: Vec::new(),
        adhoc: false,
        hardened_runtime: true,
        platform: false,
        entitlements: None,
        notarized: Some(true),
        apple_anchored: Some(true),
    }
}

/// The process signed with the signature.
pub fn signed(process: ProcessInfo, signature: Signature) -> ProcessInfo {
    ProcessInfo {
        code_signing: Some(CodeSigning::Signed(signature)),
        ..process
    }
}

/// A process running as the user and group.
pub fn with_ids(process: ProcessInfo, uid: u32, gid: u32) -> ProcessInfo {
    ProcessInfo {
        credentials: Some(Credentials {
            uid: NamedId {
                id: uid,
                names: Vec::new(),
            },
            gid: NamedId {
                id: gid,
                names: Vec::new(),
            },
            groups: Vec::new(),
        }),
        ..process
    }
}

/// A process with the executable path.
pub fn at_path(process: ProcessInfo, path: &str) -> ProcessInfo {
    ProcessInfo {
        path: Some(PathBuf::from(path)),
        ..process
    }
}

/// A complete chain (it reached the root) collected in the boot `BOOT`.
pub fn chain(processes: Vec<ProcessInfo>) -> ProcessChain {
    ProcessChain::new(processes, BOOT.to_owned(), None)
}

/// The process as a matcher sees it in a chain collected in the boot `BOOT`.
pub fn target(process: &ProcessInfo) -> MatchTarget<'_> {
    MatchTarget {
        process,
        boot_uuid: BOOT,
    }
}

/// The matcher of a built-in item.
pub fn matcher<'v>(vocab: &'v Vocabulary, key: &str) -> &'v dyn Matcher {
    match vocab.get(key).map(|item| item.kind()) {
        Some(ItemKind::Matcher(matcher)) => matcher.as_ref(),
        _ => panic!("{key:?} is not a built-in matcher item"),
    }
}

/// The condition of a registered item.
pub fn condition<'v>(vocab: &'v Vocabulary, key: &str) -> &'v dyn Condition {
    match vocab.get(key).map(|item| item.kind()) {
        Some(ItemKind::Condition(condition)) => condition.as_ref(),
        _ => panic!("{key:?} is not a registered condition item"),
    }
}

/// The time `secs` seconds after the epoch.
pub fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// 2026-11-08T04:00:00Z (13:00 at +09:00), the time the tests treat as now.
pub const NOW: u64 = 1_794_110_400;

/// An epoch-style lifetime condition, as `os.session` or `app.unlock` would be: `pin` takes the observed value (`Unobservable` without one), `check` holds while the observed value equals the pinned one.
pub struct Epoch;

impl Condition for Epoch {
    fn kind(&self) -> procline_acl::ConditionKind {
        procline_acl::ConditionKind::Lifetime
    }
    /// Tests give the observed value with `EvalContext::with_observed`.
    fn observe(&self) -> Result<Option<serde_json::Value>, procline_acl::ObserveError> {
        Ok(None)
    }
    fn validate_args(&self, _args: Option<&serde_json::Value>) -> Result<(), String> {
        Ok(())
    }
    fn pin(
        &self,
        _args: Option<&serde_json::Value>,
        obs: &procline_acl::Observed<'_>,
        _chain: &ProcessChain,
    ) -> Result<Option<serde_json::Value>, procline_acl::PinError> {
        match obs.value {
            Ok(Some(value)) => Ok(Some(value.clone())),
            _ => Err(procline_acl::PinError::Unobservable),
        }
    }
    fn check(
        &self,
        _args: Option<&serde_json::Value>,
        pinned: Option<&serde_json::Value>,
        obs: &procline_acl::Observed<'_>,
        _chain: &ProcessChain,
    ) -> bool {
        matches!((pinned, obs.value), (Some(pinned), Ok(Some(observed))) if pinned == observed)
    }
    fn advance(&self, _pinned: Option<&serde_json::Value>) -> Option<serde_json::Value> {
        None
    }
}

/// The built-in vocabulary with `app.unlock` as an `Epoch`.
pub fn vocabulary() -> Vocabulary {
    let mut vocab = Vocabulary::builtin();
    vocab
        .register(procline_acl::Item::condition("app.unlock", Epoch))
        .unwrap();
    vocab
}
