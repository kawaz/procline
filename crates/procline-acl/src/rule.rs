use std::time::SystemTime;

use crate::subject::{Subject, SubjectRef};

/// A static definition: who, on what, until when and under which state, with which effect. Conditions stay symbolic; evaluation sees only the grants made from rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub effect: Effect,
    pub subject: SubjectRef,
    /// Globs over the strings of `Target`; empty matches every target. The target vocabulary belongs to the application.
    pub targets: Vec<String>,
    /// ANDed conditions, lifetime and state alike.
    pub conditions: Vec<ConditionUse>,
}

/// Outcome of a matching grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    Allow,
    Deny,
    Ask,
}

/// One entry of a rule's `conditions`: the item key and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionUse {
    pub key: String,
    pub args: Option<serde_json::Value>,
}

impl ConditionUse {
    /// A condition without arguments.
    pub fn named(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            args: None,
        }
    }

    /// A condition with arguments.
    pub fn with_args(key: impl Into<String>, args: serde_json::Value) -> Self {
        Self {
            key: key.into(),
            args: Some(args),
        }
    }
}

/// A rule applied to an actual process, with each condition pinned to a concrete value. Self-contained and immutable: an update is a new value made by the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    /// The rule the grant was made from, for display and cleanup.
    pub rule_id: String,
    pub effect: Effect,
    /// The subject of the rule with a named subject expanded and every placeholder filled in. Tag names stay as names.
    pub subject: Subject,
    /// Globs over the strings of `Target`, as in the rule; empty matches every target.
    pub targets: Vec<String>,
    pub conditions: Vec<PinnedCondition>,
    pub created_at: SystemTime,
    pub created_from: Option<String>,
}

/// One entry of a grant's `conditions`: the item key, the original arguments if needed, and the pin value (absent for state conditions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedCondition {
    pub key: String,
    pub args: Option<serde_json::Value>,
    pub pinned: Option<serde_json::Value>,
}

/// The thing being accessed, in the application's target vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target(pub String);
