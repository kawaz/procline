use std::fmt;

use procline_core::Strength;

use crate::policy::TaggedChain;
use crate::rule::{ConditionUse, Effect, Rule};
use crate::subject::{Subject, SubjectRef};
use crate::vocabulary::Vocabulary;

/// Builds a subject from the collected values of one process of a tagged chain.
#[expect(dead_code, reason = "read once build is implemented")]
pub struct SubjectBuilder<'a> {
    tagged: &'a TaggedChain<'a>,
    index: usize,
    pins: Vec<String>,
    tags: Vec<String>,
}

impl<'a> SubjectBuilder<'a> {
    /// Starts from the process at `index` of the chain (`0` is the target).
    pub fn from(tagged: &'a TaggedChain<'a>, index: usize) -> Self {
        Self {
            tagged,
            index,
            pins: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Pins the item and every item it depends on, with the collected values.
    pub fn pin(mut self, key: impl Into<String>) -> Self {
        self.pins.push(key.into());
        self
    }

    /// Requires a tag the process carries.
    pub fn tag(mut self, name: impl Into<String>) -> Self {
        self.tags.push(name.into());
        self
    }

    /// Resolves the pins against the vocabulary and the collected values.
    pub fn build(self) -> Result<Subject, BuildError> {
        todo!()
    }
}

/// Builds a static rule and checks its depends and its strength against its scopes.
#[expect(dead_code, reason = "read once build is implemented")]
pub struct RuleBuilder<'v> {
    vocab: &'v Vocabulary,
    subject: SubjectRef,
    targets: Vec<String>,
    conditions: Vec<ConditionUse>,
    effect: Option<Effect>,
}

impl<'v> RuleBuilder<'v> {
    pub fn new(subject: SubjectRef, vocab: &'v Vocabulary) -> Self {
        Self {
            vocab,
            subject,
            targets: Vec::new(),
            conditions: Vec::new(),
            effect: None,
        }
    }

    pub fn targets<T: Into<String>>(mut self, targets: impl IntoIterator<Item = T>) -> Self {
        self.targets.extend(targets.into_iter().map(Into::into));
        self
    }

    /// Adds a condition; it stays symbolic until the rule is granted.
    pub fn condition(mut self, condition: ConditionUse) -> Self {
        self.conditions.push(condition);
        self
    }

    pub fn allow(self) -> Self {
        self.effect(Effect::Allow)
    }

    pub fn deny(self) -> Self {
        self.effect(Effect::Deny)
    }

    pub fn ask(self) -> Self {
        self.effect(Effect::Ask)
    }

    fn effect(mut self, effect: Effect) -> Self {
        self.effect = Some(effect);
        self
    }

    /// Checks depends and the strength / scope constraint (by the presence of lifetime conditions) and returns the static rule.
    pub fn build(self) -> Result<Rule, BuildError> {
        todo!()
    }
}

/// Building a subject or a rule failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    UnknownItem {
        key: String,
    },
    /// The collected process has no value for the item.
    ValueUnavailable {
        key: String,
    },
    /// An item is used without an item it depends on.
    MissingDependency {
        key: String,
        missing: String,
    },
    /// The scopes are too long-lived for the strength of the subject.
    ScopeTooWeak {
        class: Strength,
    },
    /// No effect was chosen.
    MissingEffect,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownItem { key } => write!(f, "{key:?} is not registered in the vocabulary"),
            Self::ValueUnavailable { key } => {
                write!(
                    f,
                    "the process has no collected value for {key:?}; choose another item"
                )
            }
            Self::MissingDependency { key, missing } => {
                write!(
                    f,
                    "{key:?} is used without {missing:?}, which it depends on; pin {missing:?} too"
                )
            }
            Self::ScopeTooWeak { class } => write!(
                f,
                "an allow rule of class {class:?} needs a shorter scope; add an epoch scope, a shorter `until` or `uses`"
            ),
            Self::MissingEffect => f.write_str("no effect chosen; call allow, deny or ask"),
        }
    }
}

impl std::error::Error for BuildError {}
