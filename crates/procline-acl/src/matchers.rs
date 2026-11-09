//! The built-in matcher items, independent of the OS: `process`, `binary`, `uid`, `gid`, `path`, `cwd`, `argv`, `name`, `tty` and `responsible`.
//!
//! Each item accepts the value shapes of the matcher table of the design and rejects the others in `validate`:
//!
//! | item | exact | glob | regex | range | placeholder | class |
//! | --- | --- | --- | --- | --- | --- | --- |
//! | `process` | structured (`Process`) | - | - | - | yes | Strong |
//! | `binary` | structured (`Binary`, fields) | - | - | - | per field | Strong with a signature field, Medium with `digest` alone |
//! | `path` | absolute text | absolute | yes | - | yes | Strong when root-owned and not writable by the user, Medium otherwise or without a process |
//! | `cwd` | absolute text | absolute | - | - | yes | Weak |
//! | `name` | text | yes | - | - | yes | Weak |
//! | `tty` | text | - | - | - | yes | Weak |
//! | `argv` | text, any element | - | any element | - | - | Weak |
//! | `uid` | integer | - | - | yes | yes | Weak |
//! | `gid` | integer | - | - | - | yes | Weak |
//! | `responsible` | structured (`Process`) | - | - | - | yes | Medium |
//!
//! `class` returns `Weak` for a value of a shape the item rejects, so an invalid value never makes a rule look stronger.

use std::ffi::OsStr;
use std::path::Path;

use globset::{GlobBuilder, GlobMatcher};
use procline_core::{
    BinaryPin, CodeSigning, Pinnable, ProcessIdentity, ProcessInfo, Signature, SignatureValidity,
    Strength,
};
use regex::bytes::Regex;

use crate::subject::{Literal, MatchValue};
use crate::vocabulary::{MatchTarget, Matcher, ResolveError};

/// `process`: the individual process.
pub(crate) struct ProcessMatcher;

/// `responsible`: the individual responsible process, compared like `process`.
pub(crate) struct ResponsibleMatcher;

/// `binary`: the identity of the code.
pub(crate) struct BinaryMatcher;

/// `path`: the executable path.
pub(crate) struct PathMatcher;

/// `cwd`: the working directory.
pub(crate) struct CwdMatcher;

/// `name`: the process name.
pub(crate) struct NameMatcher;

/// `tty`: the controlling terminal.
pub(crate) struct TtyMatcher;

/// `argv`: the arguments, matched element by element.
pub(crate) struct ArgvMatcher;

/// `uid`: the user ID.
pub(crate) struct UidMatcher;

/// `gid`: the group ID.
pub(crate) struct GidMatcher;

impl Matcher for ProcessMatcher {
    fn matches(&self, target: MatchTarget<'_>, value: &MatchValue) -> bool {
        let MatchValue::Process(Pinnable::Value(pinned)) = value else {
            return false;
        };
        let actual = target.info.identity.process_identity(target.boot_uuid);
        same_individual(pinned, &actual)
    }

    fn class(&self, value: &MatchValue, _process: Option<&ProcessInfo>) -> Strength {
        match value {
            MatchValue::Process(_) => Strength::Strong,
            _ => Strength::Weak,
        }
    }

    fn validate(&self, value: &MatchValue) -> Result<(), String> {
        validate_identity(value)
    }

    fn resolve(
        &self,
        value: &MatchValue,
        target: MatchTarget<'_>,
    ) -> Result<MatchValue, ResolveError> {
        match value {
            MatchValue::Process(Pinnable::Pin) => Ok(MatchValue::Process(Pinnable::Value(
                target.info.identity.process_identity(target.boot_uuid),
            ))),
            other => Ok(other.clone()),
        }
    }
}

impl Matcher for ResponsibleMatcher {
    fn matches(&self, target: MatchTarget<'_>, value: &MatchValue) -> bool {
        let MatchValue::Process(Pinnable::Value(pinned)) = value else {
            return false;
        };
        target
            .info
            .responsible
            .as_ref()
            .is_some_and(|actual| same_individual(pinned, actual))
    }

    fn class(&self, value: &MatchValue, _process: Option<&ProcessInfo>) -> Strength {
        match value {
            MatchValue::Process(_) => Strength::Medium,
            _ => Strength::Weak,
        }
    }

    fn validate(&self, value: &MatchValue) -> Result<(), String> {
        validate_identity(value)
    }

    fn resolve(
        &self,
        value: &MatchValue,
        target: MatchTarget<'_>,
    ) -> Result<MatchValue, ResolveError> {
        match value {
            MatchValue::Process(Pinnable::Pin) => target
                .info
                .responsible
                .clone()
                .map(|identity| MatchValue::Process(Pinnable::Value(identity)))
                .ok_or(ResolveError::ValueUnavailable { field: None }),
            other => Ok(other.clone()),
        }
    }
}

/// Every identifier present on both sides is equal. The boot UUID is always present, so identifiers reused after a restart do not match. The pid alone is not enough, since pids are reused within a boot: at least one of `unique_id` and `start_time` must be present on both sides.
fn same_individual(pinned: &ProcessIdentity, actual: &ProcessIdentity) -> bool {
    let unique_id = pinned.unique_id.zip(actual.unique_id);
    let start_time = pinned.start_time.zip(actual.start_time);
    if unique_id.is_none() && start_time.is_none() {
        return false;
    }
    pinned.boot_uuid == actual.boot_uuid
        && pinned.pid == actual.pid
        && unique_id.is_none_or(|(a, b)| a == b)
        && start_time.is_none_or(|(a, b)| a == b)
}

/// The shape of a `process` or `responsible` value: the placeholder, or an identity that can match (a boot UUID, and `unique_id` or `start_time` besides the pid).
fn validate_identity(value: &MatchValue) -> Result<(), String> {
    match value {
        MatchValue::Process(Pinnable::Pin) => Ok(()),
        MatchValue::Process(Pinnable::Value(identity)) => {
            if identity.boot_uuid.is_empty() {
                return Err("boot_uuid is empty; give the boot UUID the process ran in".to_owned());
            }
            if identity.unique_id.is_none() && identity.start_time.is_none() {
                return Err("only pid is given, and pids are reused; give unique_id or start_time as well".to_owned());
            }
            Ok(())
        }
        _ => Err("takes an object of process identifiers ({boot_uuid, unique_id, pid, start_time}) or true".to_owned()),
    }
}

impl Matcher for BinaryMatcher {
    fn matches(&self, target: MatchTarget<'_>, value: &MatchValue) -> bool {
        let MatchValue::Binary(pin) = value else {
            return false;
        };
        if pin.validate().is_err() {
            return false;
        }
        let process = target.info;
        let signature = verified_signature(process);
        field_matches(&pin.digest, process.digest.as_ref())
            && field_matches(&pin.team_id, signature.and_then(|s| s.team_id.as_ref()))
            && field_matches(
                &pin.signing_id,
                signature.and_then(|s| s.signing_id.as_ref()),
            )
            && field_matches(&pin.bundle_id, signature.and_then(|s| s.bundle_id.as_ref()))
            && field_matches(&pin.cdhash, signature.and_then(|s| s.cdhash.as_ref()))
    }

    fn class(&self, value: &MatchValue, _process: Option<&ProcessInfo>) -> Strength {
        let MatchValue::Binary(pin) = value else {
            return Strength::Weak;
        };
        if pin.team_id.is_some()
            || pin.signing_id.is_some()
            || pin.bundle_id.is_some()
            || pin.cdhash.is_some()
        {
            Strength::Strong
        } else if pin.digest.is_some() {
            Strength::Medium
        } else {
            Strength::Weak
        }
    }

    fn validate(&self, value: &MatchValue) -> Result<(), String> {
        match value {
            MatchValue::Binary(pin) => pin.validate().map_err(|err| err.to_string()),
            _ => Err(
                "takes an object of fields ({digest, team_id, signing_id, bundle_id, cdhash})"
                    .to_owned(),
            ),
        }
    }

    fn resolve(
        &self,
        value: &MatchValue,
        target: MatchTarget<'_>,
    ) -> Result<MatchValue, ResolveError> {
        let MatchValue::Binary(pin) = value else {
            return Ok(value.clone());
        };
        let process = target.info;
        let signature = verified_signature(process);
        Ok(MatchValue::Binary(BinaryPin {
            digest: fill(&pin.digest, process.digest.as_ref(), "digest")?,
            team_id: fill(
                &pin.team_id,
                signature.and_then(|s| s.team_id.as_ref()),
                "team_id",
            )?,
            signing_id: fill(
                &pin.signing_id,
                signature.and_then(|s| s.signing_id.as_ref()),
                "signing_id",
            )?,
            bundle_id: fill(
                &pin.bundle_id,
                signature.and_then(|s| s.bundle_id.as_ref()),
                "bundle_id",
            )?,
            cdhash: fill(
                &pin.cdhash,
                signature.and_then(|s| s.cdhash.as_ref()),
                "cdhash",
            )?,
        }))
    }
}

/// The signature whose fields can be matched: signed, and verified. The fields of an unverified signature say nothing about the code.
fn verified_signature(process: &ProcessInfo) -> Option<&Signature> {
    match &process.code_signing {
        Some(CodeSigning::Signed(signature)) if signature.validity == SignatureValidity::Valid => {
            Some(signature)
        }
        _ => None,
    }
}

/// An absent field asks nothing; a concrete field must equal the actual value; a placeholder never matches (it is resolved before matching).
fn field_matches<T: PartialEq>(field: &Option<Pinnable<T>>, actual: Option<&T>) -> bool {
    match field {
        None => true,
        Some(Pinnable::Pin) => false,
        Some(Pinnable::Value(expected)) => actual == Some(expected),
    }
}

/// Replaces a placeholder field with the actual value, failing when the process has none.
fn fill<T: Clone>(
    field: &Option<Pinnable<T>>,
    actual: Option<&T>,
    name: &str,
) -> Result<Option<Pinnable<T>>, ResolveError> {
    match field {
        Some(Pinnable::Pin) => actual
            .map(|value| Some(Pinnable::Value(value.clone())))
            .ok_or_else(|| ResolveError::ValueUnavailable {
                field: Some(name.to_owned()),
            }),
        other => Ok(other.clone()),
    }
}

impl Matcher for PathMatcher {
    fn matches(&self, target: MatchTarget<'_>, value: &MatchValue) -> bool {
        let Some(path) = target.info.path.as_deref() else {
            return false;
        };
        match value {
            MatchValue::Exact(Literal::Text(expected)) => {
                is_absolute(expected) && path.as_os_str() == OsStr::new(expected)
            }
            MatchValue::Glob(pattern) => path_glob_matches(pattern, path),
            MatchValue::Regex(pattern) => compile_regex(pattern)
                .is_ok_and(|re| re.is_match(path.as_os_str().as_encoded_bytes())),
            _ => false,
        }
    }

    fn class(&self, value: &MatchValue, process: Option<&ProcessInfo>) -> Strength {
        match value {
            MatchValue::Pin
            | MatchValue::Exact(Literal::Text(_))
            | MatchValue::Glob(_)
            | MatchValue::Regex(_) => {
                let protected = process
                    .and_then(|p| p.path_meta)
                    .is_some_and(|meta| meta.owner_uid == 0 && !meta.writable_by_user);
                if protected {
                    Strength::Strong
                } else {
                    Strength::Medium
                }
            }
            _ => Strength::Weak,
        }
    }

    fn validate(&self, value: &MatchValue) -> Result<(), String> {
        match value {
            MatchValue::Pin => Ok(()),
            MatchValue::Exact(Literal::Text(path)) => require_absolute(path),
            MatchValue::Glob(pattern) => {
                require_absolute(pattern)?;
                compile_glob(pattern).map(drop)
            }
            MatchValue::Regex(pattern) => compile_regex(pattern).map(drop),
            _ => Err("takes an absolute path, {\"glob\": …}, {\"regex\": …} or true".to_owned()),
        }
    }

    fn resolve(
        &self,
        value: &MatchValue,
        target: MatchTarget<'_>,
    ) -> Result<MatchValue, ResolveError> {
        match value {
            MatchValue::Pin => resolve_path(target.info.path.as_deref()),
            other => Ok(other.clone()),
        }
    }
}

impl Matcher for CwdMatcher {
    fn matches(&self, target: MatchTarget<'_>, value: &MatchValue) -> bool {
        let Some(cwd) = target.info.cwd.as_deref() else {
            return false;
        };
        match value {
            MatchValue::Exact(Literal::Text(expected)) => {
                is_absolute(expected) && cwd.as_os_str() == OsStr::new(expected)
            }
            MatchValue::Glob(pattern) => path_glob_matches(pattern, cwd),
            _ => false,
        }
    }

    fn class(&self, _value: &MatchValue, _process: Option<&ProcessInfo>) -> Strength {
        Strength::Weak
    }

    fn validate(&self, value: &MatchValue) -> Result<(), String> {
        match value {
            MatchValue::Pin => Ok(()),
            MatchValue::Exact(Literal::Text(path)) => require_absolute(path),
            MatchValue::Glob(pattern) => {
                require_absolute(pattern)?;
                compile_glob(pattern).map(drop)
            }
            _ => Err("takes an absolute path, {\"glob\": …} or true".to_owned()),
        }
    }

    fn resolve(
        &self,
        value: &MatchValue,
        target: MatchTarget<'_>,
    ) -> Result<MatchValue, ResolveError> {
        match value {
            MatchValue::Pin => resolve_path(target.info.cwd.as_deref()),
            other => Ok(other.clone()),
        }
    }
}

impl Matcher for NameMatcher {
    fn matches(&self, target: MatchTarget<'_>, value: &MatchValue) -> bool {
        let Some(name) = target.info.name.as_deref() else {
            return false;
        };
        match value {
            MatchValue::Exact(Literal::Text(expected)) => name == expected,
            MatchValue::Glob(pattern) => {
                compile_glob(pattern).is_ok_and(|glob| glob.is_match(name))
            }
            _ => false,
        }
    }

    fn class(&self, _value: &MatchValue, _process: Option<&ProcessInfo>) -> Strength {
        Strength::Weak
    }

    fn validate(&self, value: &MatchValue) -> Result<(), String> {
        match value {
            MatchValue::Pin | MatchValue::Exact(Literal::Text(_)) => Ok(()),
            MatchValue::Glob(pattern) => compile_glob(pattern).map(drop),
            _ => Err("takes a name, {\"glob\": …} or true".to_owned()),
        }
    }

    fn resolve(
        &self,
        value: &MatchValue,
        target: MatchTarget<'_>,
    ) -> Result<MatchValue, ResolveError> {
        match value {
            MatchValue::Pin => resolve_text(target.info.name.as_ref()),
            other => Ok(other.clone()),
        }
    }
}

impl Matcher for TtyMatcher {
    fn matches(&self, target: MatchTarget<'_>, value: &MatchValue) -> bool {
        match value {
            MatchValue::Exact(Literal::Text(expected)) => {
                target.info.tty.as_ref() == Some(expected)
            }
            _ => false,
        }
    }

    fn class(&self, _value: &MatchValue, _process: Option<&ProcessInfo>) -> Strength {
        Strength::Weak
    }

    fn validate(&self, value: &MatchValue) -> Result<(), String> {
        match value {
            MatchValue::Pin | MatchValue::Exact(Literal::Text(_)) => Ok(()),
            _ => Err("takes a terminal name or true".to_owned()),
        }
    }

    fn resolve(
        &self,
        value: &MatchValue,
        target: MatchTarget<'_>,
    ) -> Result<MatchValue, ResolveError> {
        match value {
            MatchValue::Pin => resolve_text(target.info.tty.as_ref()),
            other => Ok(other.clone()),
        }
    }
}

/// `argv` has no placeholder: the value is one string matched against each element, and the arguments of a process are a list with no single element to pin.
impl Matcher for ArgvMatcher {
    fn matches(&self, target: MatchTarget<'_>, value: &MatchValue) -> bool {
        let Some(argv) = target.info.argv.as_deref() else {
            return false;
        };
        match value {
            MatchValue::Exact(Literal::Text(expected)) => argv.iter().any(|arg| arg == expected),
            MatchValue::Regex(pattern) => compile_regex(pattern)
                .is_ok_and(|re| argv.iter().any(|arg| re.is_match(arg.as_bytes()))),
            _ => false,
        }
    }

    fn class(&self, _value: &MatchValue, _process: Option<&ProcessInfo>) -> Strength {
        Strength::Weak
    }

    fn validate(&self, value: &MatchValue) -> Result<(), String> {
        match value {
            MatchValue::Exact(Literal::Text(_)) => Ok(()),
            MatchValue::Regex(pattern) => compile_regex(pattern).map(drop),
            MatchValue::Pin => Err(
                "argv cannot be pinned, since it is a list; write an element or {\"regex\": …}"
                    .to_owned(),
            ),
            _ => Err("takes an element or {\"regex\": …}".to_owned()),
        }
    }

    fn resolve(
        &self,
        value: &MatchValue,
        _target: MatchTarget<'_>,
    ) -> Result<MatchValue, ResolveError> {
        match value {
            MatchValue::Pin => Err(ResolveError::ValueUnavailable { field: None }),
            other => Ok(other.clone()),
        }
    }
}

impl Matcher for UidMatcher {
    fn matches(&self, target: MatchTarget<'_>, value: &MatchValue) -> bool {
        let Some(credentials) = &target.info.credentials else {
            return false;
        };
        id_matches(value, credentials.uid.id, IdShapes::WithRange)
    }

    fn class(&self, _value: &MatchValue, _process: Option<&ProcessInfo>) -> Strength {
        Strength::Weak
    }

    fn validate(&self, value: &MatchValue) -> Result<(), String> {
        validate_id(value, IdShapes::WithRange)
    }

    fn resolve(
        &self,
        value: &MatchValue,
        target: MatchTarget<'_>,
    ) -> Result<MatchValue, ResolveError> {
        match value {
            MatchValue::Pin => resolve_id(target.info.credentials.as_ref().map(|c| c.uid.id)),
            other => Ok(other.clone()),
        }
    }
}

impl Matcher for GidMatcher {
    fn matches(&self, target: MatchTarget<'_>, value: &MatchValue) -> bool {
        let Some(credentials) = &target.info.credentials else {
            return false;
        };
        id_matches(value, credentials.gid.id, IdShapes::ExactOnly)
    }

    fn class(&self, _value: &MatchValue, _process: Option<&ProcessInfo>) -> Strength {
        Strength::Weak
    }

    fn validate(&self, value: &MatchValue) -> Result<(), String> {
        validate_id(value, IdShapes::ExactOnly)
    }

    fn resolve(
        &self,
        value: &MatchValue,
        target: MatchTarget<'_>,
    ) -> Result<MatchValue, ResolveError> {
        match value {
            MatchValue::Pin => resolve_id(target.info.credentials.as_ref().map(|c| c.gid.id)),
            other => Ok(other.clone()),
        }
    }
}

/// Whether a numeric ID item takes a range besides an exact ID (`uid` does, `gid` does not).
#[derive(Clone, Copy)]
enum IdShapes {
    ExactOnly,
    WithRange,
}

fn id_matches(value: &MatchValue, actual: u32, shapes: IdShapes) -> bool {
    match (value, shapes) {
        (MatchValue::Exact(Literal::Integer(expected)), _) => i64::from(actual) == *expected,
        (MatchValue::Range { min, max }, IdShapes::WithRange) => {
            (*min..=*max).contains(&i64::from(actual))
        }
        _ => false,
    }
}

fn validate_id(value: &MatchValue, shapes: IdShapes) -> Result<(), String> {
    match (value, shapes) {
        (MatchValue::Pin, _) => Ok(()),
        (MatchValue::Exact(Literal::Integer(id)), _) => require_id(*id),
        (MatchValue::Range { min, max }, IdShapes::WithRange) => {
            require_id(*min)?;
            require_id(*max)?;
            if min > max {
                return Err(format!("min {min} is greater than max {max}; swap them"));
            }
            Ok(())
        }
        (_, IdShapes::WithRange) => {
            Err("takes a number, {\"min\": …, \"max\": …} or true".to_owned())
        }
        (_, IdShapes::ExactOnly) => Err("takes a number or true".to_owned()),
    }
}

fn require_id(id: i64) -> Result<(), String> {
    if u32::try_from(id).is_ok() {
        Ok(())
    } else {
        Err(format!("{id} is not an ID; IDs are 0 to {}", u32::MAX))
    }
}

fn resolve_id(actual: Option<u32>) -> Result<MatchValue, ResolveError> {
    actual
        .map(|id| MatchValue::Exact(Literal::Integer(i64::from(id))))
        .ok_or(ResolveError::ValueUnavailable { field: None })
}

fn resolve_text(actual: Option<&String>) -> Result<MatchValue, ResolveError> {
    actual
        .map(|text| MatchValue::Exact(Literal::Text(text.clone())))
        .ok_or(ResolveError::ValueUnavailable { field: None })
}

/// A path that is not valid UTF-8 cannot be written as a value, so it is unavailable for pinning.
fn resolve_path(actual: Option<&Path>) -> Result<MatchValue, ResolveError> {
    actual
        .and_then(Path::to_str)
        .map(|text| MatchValue::Exact(Literal::Text(text.to_owned())))
        .ok_or(ResolveError::ValueUnavailable { field: None })
}

/// Paths and cwds are written absolute; `~` and relative paths are not interpreted.
fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

fn require_absolute(path: &str) -> Result<(), String> {
    if is_absolute(path) {
        Ok(())
    } else {
        Err(format!(
            "{path:?} is not absolute; write it from \"/\" (\"~\" is not expanded)"
        ))
    }
}

fn path_glob_matches(pattern: &str, path: &Path) -> bool {
    is_absolute(pattern) && compile_glob(pattern).is_ok_and(|glob| glob.is_match(path))
}

/// `*` and `?` stay within one path component and `**` crosses components, as in shells.
fn compile_glob(pattern: &str) -> Result<GlobMatcher, String> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map(|glob| glob.compile_matcher())
        .map_err(|err| format!("invalid glob: {err}"))
}

/// Unanchored: the pattern matches anywhere in the string unless it anchors itself with `^` / `$`.
fn compile_regex(pattern: &str) -> Result<Regex, String> {
    Regex::new(pattern).map_err(|err| format!("invalid regex: {err}"))
}
