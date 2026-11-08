use crate::subject::SubjectRef;
use crate::vocabulary::Epoch;

/// Who, on what, until when and under which state, with which effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub effect: Effect,
    pub subject: SubjectRef,
    /// Patterns over targets; the target vocabulary belongs to the application.
    pub targets: Vec<String>,
    /// ANDed conditions, lifetime and state alike.
    pub conditions: Vec<ConditionUse>,
    pub created_from: Option<String>,
}

/// Outcome of a matching rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    Allow,
    Deny,
    Ask,
}

/// One entry of `conditions`: the item key, its arguments and, for lifetime items, the recorded epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionUse {
    pub key: String,
    pub args: Option<serde_json::Value>,
    pub epoch: Option<Epoch>,
}

impl ConditionUse {
    /// A condition without arguments.
    pub fn named(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            args: None,
            epoch: None,
        }
    }

    /// A condition with arguments.
    pub fn with_args(key: impl Into<String>, args: serde_json::Value) -> Self {
        Self {
            key: key.into(),
            args: Some(args),
            epoch: None,
        }
    }
}

/// A rule before its epochs are recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preset {
    pub name: String,
    pub effect: Effect,
    pub subject: SubjectRef,
    pub targets: Vec<String>,
    pub conditions: Vec<ConditionUse>,
}

/// The thing being accessed, in the application's target vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target(pub String);
