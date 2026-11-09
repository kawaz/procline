use std::collections::BTreeMap;
use std::fmt;

use procline_core::{ProcessChain, ProcessInfo, Strength};

use crate::conditions::{Age, TimeWindow, Until, Uses};
use crate::context::Observed;
use crate::matchers::{
    ArgvMatcher, BinaryMatcher, CwdMatcher, GidMatcher, NameMatcher, PathMatcher, ProcessMatcher,
    ResponsibleMatcher, TtyMatcher, UidMatcher,
};
use crate::subject::MatchValue;

/// Every item usable in a rule: `match` keys, lifetime scopes and state conditions.
#[derive(Default)]
pub struct Vocabulary {
    items: BTreeMap<String, Item>,
}

impl Vocabulary {
    /// The built-in items, all independent of the OS: the matcher items (`process` (identifies the individual process), `binary`, `uid`, `gid`, `path`, `cwd`, `argv`, `name`, `tty`, `responsible`), `time.window`, and `until` / `age` / `uses`. The `os.*` items come from the collector crate of the OS (`procline_macos::os_items`); the application adds them with `register`.
    pub fn builtin() -> Self {
        let mut vocab = Self::default();
        for item in [
            Item::matcher("process", ProcessMatcher),
            Item::matcher("binary", BinaryMatcher),
            Item::matcher("uid", UidMatcher),
            Item::matcher("gid", GidMatcher),
            Item::matcher("path", PathMatcher),
            Item::matcher("cwd", CwdMatcher),
            Item::matcher("argv", ArgvMatcher),
            Item::matcher("name", NameMatcher),
            Item::matcher("tty", TtyMatcher),
            Item::matcher("responsible", ResponsibleMatcher),
            Item::condition("until", Until),
            Item::condition("age", Age),
            Item::condition("uses", Uses),
            Item::condition("time.window", TimeWindow),
        ] {
            vocab.items.insert(item.key.clone(), item);
        }
        vocab
    }

    /// Adds an item. Fails on a duplicate key or a key outside the allowed namespace.
    ///
    /// A registered key starts with `os.` (the host state and epochs, provided by the collector crate of the OS) or `app.` (the application's own items), followed by a non-empty name. Keys without a prefix (the attributes of the process itself, and `until` / `age` / `uses`) and `time.` belong to the built-in vocabulary.
    pub fn register(&mut self, item: Item) -> Result<(), RegisterError> {
        if !is_registrable_key(&item.key) {
            return Err(RegisterError::Namespace { key: item.key });
        }
        if self.items.contains_key(&item.key) {
            return Err(RegisterError::Duplicate { key: item.key });
        }
        self.items.insert(item.key.clone(), item);
        Ok(())
    }

    /// Looks up a registered item.
    pub fn get(&self, key: &str) -> Option<&Item> {
        self.items.get(key)
    }

    /// The condition item registered under the key; `None` for an unregistered key or a matcher item.
    pub(crate) fn condition(&self, key: &str) -> Option<&dyn Condition> {
        match self.items.get(key)?.kind() {
            ItemKind::Condition(condition) => Some(condition.as_ref()),
            ItemKind::Matcher(_) => None,
        }
    }

    /// The matcher item registered under the key; `None` for an unregistered key or a condition item.
    pub(crate) fn matcher(&self, key: &str) -> Option<&dyn Matcher> {
        match self.items.get(key)?.kind() {
            ItemKind::Matcher(matcher) => Some(matcher.as_ref()),
            ItemKind::Condition(_) => None,
        }
    }

    /// Every condition item with its key.
    pub(crate) fn conditions(&self) -> impl Iterator<Item = (&str, &dyn Condition)> {
        self.items
            .iter()
            .filter_map(|(key, item)| match item.kind() {
                ItemKind::Condition(condition) => Some((key.as_str(), condition.as_ref())),
                ItemKind::Matcher(_) => None,
            })
    }

    /// The class the matcher item decides from the value, and from the process when one is given (see `Matcher::class`); for a list (`MatchValue::AnyOf`), the weakest class among its values, since any of them lets a process through. `None` for an unregistered key or a condition item.
    pub fn class(
        &self,
        key: &str,
        value: &MatchValue,
        process: Option<&ProcessInfo>,
    ) -> Option<Strength> {
        match self.items.get(key)?.kind() {
            ItemKind::Matcher(matcher) => Some(value_class(matcher.as_ref(), value, process)),
            ItemKind::Condition(_) => None,
        }
    }
}

// The entry points to a matcher item for every caller. A list of alternatives (`MatchValue::AnyOf`) is taken apart here, so an item (built-in or registered by the application) only ever sees one value.

/// Whether the process satisfies the value: for a list, one of its values.
pub(crate) fn value_matches(
    matcher: &dyn Matcher,
    target: MatchTarget<'_>,
    value: &MatchValue,
) -> bool {
    match value {
        MatchValue::AnyOf(values) => values.iter().any(|value| matcher.matches(target, value)),
        value => matcher.matches(target, value),
    }
}

/// The class of the value: for a list, the weakest class among its values (`Weak` for an empty list, which `validate_value` rejects).
pub(crate) fn value_class(
    matcher: &dyn Matcher,
    value: &MatchValue,
    process: Option<&ProcessInfo>,
) -> Strength {
    match value {
        MatchValue::AnyOf(values) => values
            .iter()
            .map(|value| matcher.class(value, process))
            .min()
            .unwrap_or(Strength::Weak),
        value => matcher.class(value, process),
    }
}

/// Checks the value: for a list, its shape (`MatchValue::check_alternatives`) and then each value by the item's rules.
pub(crate) fn validate_value(matcher: &dyn Matcher, value: &MatchValue) -> Result<(), String> {
    match value {
        MatchValue::AnyOf(values) => {
            MatchValue::check_alternatives(values)?;
            values.iter().enumerate().try_for_each(|(position, value)| {
                matcher
                    .validate(value)
                    .map_err(|reason| format!("value {position} of the list: {reason}"))
            })
        }
        value => matcher.validate(value),
    }
}

/// Replaces the placeholders of the value with the actual values of the process. A list holds no placeholder, so it comes back as is.
pub(crate) fn resolve_value(
    matcher: &dyn Matcher,
    value: &MatchValue,
    target: MatchTarget<'_>,
) -> Result<MatchValue, ResolveError> {
    match value {
        MatchValue::AnyOf(_) => Ok(value.clone()),
        value => matcher.resolve(value, target),
    }
}

/// The namespaces `register` accepts: `os.` and `app.`, each followed by a non-empty name.
fn is_registrable_key(key: &str) -> bool {
    ["os.", "app."].iter().any(|prefix| {
        key.strip_prefix(prefix)
            .is_some_and(|name| !name.is_empty())
    })
}

/// One registrable item: key and its implementation. The item itself owns the shape and validity of its values.
pub struct Item {
    key: String,
    kind: ItemKind,
}

impl Item {
    /// A matcher item; its implementation decides the class from the value.
    pub fn matcher(key: impl Into<String>, matcher: impl Matcher + 'static) -> Self {
        Self {
            key: key.into(),
            kind: ItemKind::Matcher(Box::new(matcher)),
        }
    }

    /// A matcher item with a constant class and a closure. An item whose class varies with the value implements `Matcher` and registers with `Item::matcher`.
    pub fn matcher_fn<F>(key: impl Into<String>, class: Strength, matches: F) -> Self
    where
        F: Fn(MatchTarget<'_>, &MatchValue) -> bool + Send + Sync + 'static,
    {
        Self::matcher(key, ConstClassMatcher { class, matches })
    }

    /// A condition item, lifetime or state as its implementation tells.
    pub fn condition(key: impl Into<String>, condition: impl Condition + 'static) -> Self {
        Self {
            key: key.into(),
            kind: ItemKind::Condition(Box::new(condition)),
        }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn kind(&self) -> &ItemKind {
        &self.kind
    }

    /// Lifetime or state for condition items, `None` for matcher items.
    pub fn condition_kind(&self) -> Option<ConditionKind> {
        match &self.kind {
            ItemKind::Matcher(_) => None,
            ItemKind::Condition(condition) => Some(condition.kind()),
        }
    }
}

/// The implementation of an item.
pub enum ItemKind {
    Matcher(Box<dyn Matcher>),
    Condition(Box<dyn Condition>),
}

/// One process of a collected snapshot (`ProcessChain`) as a matcher sees it: its `ProcessInfo` and the boot UUID of the chain (`ProcessChain.boot_uuid`), which the identifiers of the `process` item are paired with. Matching never touches the OS; everything is read from the snapshot.
///
/// An item sees no ancestors: the only value from the chain it needs is the boot UUID.
#[derive(Debug, Clone, Copy)]
pub struct MatchTarget<'a> {
    pub info: &'a ProcessInfo,
    pub boot_uuid: &'a str,
}

/// Matches one process against the value written in `match`, checks and resolves that value, and decides its class.
///
/// `value` is never a list (`MatchValue::AnyOf`): the vocabulary checks the shape of a list, calls the item once per value, and combines the results (one value matches, every value is valid, the weakest class), so an item implements only its own values.
pub trait Matcher: Send + Sync {
    /// Whether the process satisfies the value. A value that `validate` rejects, a placeholder included, never matches.
    fn matches(&self, target: MatchTarget<'_>, value: &MatchValue) -> bool;

    /// The class of the value, placeholders included (a placeholder names its field, so the class is known before the value is). Most items return a constant; `binary` returns the strongest field present (`Strong` with a signature field, `Medium` with `digest` alone).
    ///
    /// `process` is the matched process when granting or evaluating, and `None` when building or loading. An item whose class depends on the process decides it from `process` when given, and returns the weaker class otherwise: `path` is `Strong` when its `PathMeta` shows a root-owned path the user cannot write, `Medium` otherwise or without `process`.
    fn class(&self, value: &MatchValue, process: Option<&ProcessInfo>) -> Strength;

    /// Checks the shape and validity of the value, placeholders included. Loading the list and `RuleBuilder::build` call it; `Err` holds the reason.
    fn validate(&self, value: &MatchValue) -> Result<(), String>;

    /// Replaces every placeholder of the value with the actual value of the process; a value without placeholders comes back as is.
    fn resolve(
        &self,
        value: &MatchValue,
        target: MatchTarget<'_>,
    ) -> Result<MatchValue, ResolveError>;
}

/// A closure matcher whose class is the same for every value.
struct ConstClassMatcher<F> {
    class: Strength,
    matches: F,
}

impl<F> Matcher for ConstClassMatcher<F>
where
    F: Fn(MatchTarget<'_>, &MatchValue) -> bool + Send + Sync,
{
    fn matches(&self, target: MatchTarget<'_>, value: &MatchValue) -> bool {
        (self.matches)(target, value)
    }

    fn class(&self, _value: &MatchValue, _process: Option<&ProcessInfo>) -> Strength {
        self.class
    }

    /// A closure item does not check its values: every value is accepted.
    fn validate(&self, _value: &MatchValue) -> Result<(), String> {
        Ok(())
    }

    /// A closure item cannot read the actual value of a process, so a placeholder fails; write concrete values for it.
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

/// Resolving a placeholder of a matcher value failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// The process has no actual value for the placeholder (for example `team_id: true` on an unsigned process); `field` names the field of a structured value.
    ValueUnavailable { field: Option<String> },
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueUnavailable { field: None } => {
                f.write_str("the process has no value for the placeholder; choose another item")
            }
            Self::ValueUnavailable { field: Some(field) } => write!(
                f,
                "the process has no value for {field:?}; choose another field"
            ),
        }
    }
}

impl std::error::Error for ResolveError {}

/// A lifetime, consumable or state condition, as pure functions over its own pin value only.
pub trait Condition: Send + Sync {
    fn kind(&self) -> ConditionKind;

    /// Observes the current value (an epoch, the screen lock state, ...). `EvalContext::capture` calls it once per evaluation.
    ///
    /// `Ok(None)` when there is nothing to observe or the current time is outside the period (for a lifetime condition, `check` is then false and the grant expires). `Err` when observing failed (a system call failed); a grant using the condition is then undecidable in that evaluation, neither allowed nor expired.
    fn observe(&self) -> Result<Option<serde_json::Value>, ObserveError>;

    /// Checks the arguments written in the rule. Loading the list and `RuleBuilder::build` call it; `Err` holds the reason.
    fn validate_args(&self, args: Option<&serde_json::Value>) -> Result<(), String>;

    /// Called once when a grant is made. `chain` is the chain being approved, for conditions that pin a value of the peer (the asid of `os.login_session`). State conditions return `Ok(None)`; a lifetime condition whose observation is `Ok(None)` or `Err` fails with `Unobservable`, so no grant is made.
    fn pin(
        &self,
        args: Option<&serde_json::Value>,
        obs: &Observed<'_>,
        chain: &ProcessChain,
    ) -> Result<Option<serde_json::Value>, PinError>;

    /// Decides whether the condition holds. No side effects.
    fn check(
        &self,
        args: Option<&serde_json::Value>,
        pinned: Option<&serde_json::Value>,
        obs: &Observed<'_>,
        chain: &ProcessChain,
    ) -> bool;

    /// Called only for the adopted grant. Returns the new pin value, or `None` when unchanged.
    fn advance(&self, pinned: Option<&serde_json::Value>) -> Option<serde_json::Value>;
}

/// Observing the current value of a condition failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserveError {
    pub reason: String,
}

impl fmt::Display for ObserveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot observe the current value: {}", self.reason)
    }
}

impl std::error::Error for ObserveError {}

/// Whether a false condition expires the grant forever or only while false.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionKind {
    Lifetime,
    State,
}

/// Pinning a condition failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// The current value cannot be observed; the grant would expire at once.
    Unobservable,
    /// The arguments of the condition are not valid.
    InvalidArgs { reason: String },
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unobservable => {
                f.write_str("the current value cannot be observed; the grant would expire at once")
            }
            Self::InvalidArgs { reason } => {
                write!(f, "invalid arguments: {reason}; fix them in the rule")
            }
        }
    }
}

impl std::error::Error for PinError {}

/// Registering an item failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
    Duplicate { key: String },
    Namespace { key: String },
}

impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate { key } => write!(f, "item {key:?} is already registered"),
            Self::Namespace { key } => {
                write!(
                    f,
                    "item {key:?} is outside the allowed namespace; use the \"app.\" prefix"
                )
            }
        }
    }
}

impl std::error::Error for RegisterError {}
