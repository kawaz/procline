use std::collections::BTreeMap;
use std::fmt;

use procline_core::{ProcessChain, ProcessInfo, Strength};

use crate::context::Observed;
use crate::subject::MatchValue;

/// Every item usable in a rule: `match` keys, lifetime scopes and state conditions.
#[derive(Default)]
pub struct Vocabulary {
    items: BTreeMap<String, Item>,
}

impl Vocabulary {
    /// The built-in items (`process` (identifies the individual process), `binary` and the other matcher items, `os.session` and the other `os.*` items, `time.*`, `until` / `age` / `uses`).
    pub fn builtin() -> Self {
        todo!()
    }

    /// Adds an item. Fails on a duplicate key or a key outside the allowed namespace.
    pub fn register(&mut self, _item: Item) -> Result<(), RegisterError> {
        todo!()
    }

    /// Looks up a registered item.
    pub fn get(&self, key: &str) -> Option<&Item> {
        self.items.get(key)
    }

    /// The class the matcher item decides from the value, and from the process when one is given (see `Matcher::class`); `None` for an unregistered key or a condition item.
    pub fn class(
        &self,
        _key: &str,
        _value: &MatchValue,
        _process: Option<&ProcessInfo>,
    ) -> Option<Strength> {
        todo!()
    }
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
        F: Fn(&ProcessInfo, &MatchValue) -> bool + Send + Sync + 'static,
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

/// Matches one process against the value written in `match`, checks and resolves that value, and decides its class.
pub trait Matcher: Send + Sync {
    fn matches(&self, process: &ProcessInfo, value: &MatchValue) -> bool;

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
        process: &ProcessInfo,
    ) -> Result<MatchValue, ResolveError>;
}

/// A closure matcher whose class is the same for every value.
struct ConstClassMatcher<F> {
    class: Strength,
    matches: F,
}

impl<F> Matcher for ConstClassMatcher<F>
where
    F: Fn(&ProcessInfo, &MatchValue) -> bool + Send + Sync,
{
    fn matches(&self, process: &ProcessInfo, value: &MatchValue) -> bool {
        (self.matches)(process, value)
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
        _process: &ProcessInfo,
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

    /// Observes the current value (an epoch, the screen lock state, ...). `EvalContext::capture` calls it once per evaluation. `None` when there is nothing to observe.
    fn observe(&self) -> Option<serde_json::Value>;

    /// Checks the arguments written in the rule. Loading the list and `RuleBuilder::build` call it; `Err` holds the reason.
    fn validate_args(&self, args: Option<&serde_json::Value>) -> Result<(), String>;

    /// Called once when a grant is made. `chain` is the chain being approved, for conditions that pin a value of the peer (the asid of `os.login_session`). State conditions return `Ok(None)`; a lifetime condition without an observed value fails with `Unobservable`, so no grant is made.
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
