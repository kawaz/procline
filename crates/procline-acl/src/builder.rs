use std::fmt;

use procline_core::{BinaryField, Strength};

use crate::policy::Policy;
use crate::rule::{ConditionUse, Effect, Rule};
use crate::subject::{AncestorMatch, MatchValue, Subject, SubjectRef};

/// Builds a subject from chosen items. It holds no collected values: a pinned item is written as a placeholder, and `Policy::grant` fills in the actual values.
#[derive(Debug, Clone, Default)]
pub struct SubjectBuilder {
    pins: Vec<(String, PinSpec)>,
    exacts: Vec<(String, MatchValue)>,
    tags: Vec<String>,
    ancestors: Vec<AncestorMatch>,
    include_self: bool,
}

impl SubjectBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pins the item, as far as `spec` chooses: the chosen part becomes a placeholder.
    pub fn pin(mut self, key: impl Into<String>, spec: PinSpec) -> Self {
        self.pins.push((key.into(), spec));
        self
    }

    /// Matches the item against a concrete value.
    pub fn exact(mut self, key: impl Into<String>, value: MatchValue) -> Self {
        self.exacts.push((key.into(), value));
        self
    }

    /// Requires a tag the process carries.
    pub fn tag(mut self, name: impl Into<String>) -> Self {
        self.tags.push(name.into());
        self
    }

    /// Appends an entry to `ancestors`; entries go nearest first.
    pub fn ancestor(mut self, ancestor: AncestorMatch) -> Self {
        self.ancestors.push(ancestor);
        self
    }

    /// Lets the sequence of `ancestors` start at the process itself.
    pub fn include_self(mut self) -> Self {
        self.include_self = true;
        self
    }

    /// Combines the placeholders and the concrete values into a subject. Checks the values only (the validity rules of `binary`, an empty subject); checking the keys against the vocabulary is `RuleBuilder::build`'s job.
    ///
    /// `pin` and `exact` on the same `binary` key merge field by field into one value; a field given by both is a `Conflict`. An item with an unstructured value and `process` hold one value, so a second `pin` or `exact` on the key is a `Conflict`.
    pub fn build(self) -> Result<Subject, BuildError> {
        todo!()
    }
}

/// Builds one entry of a subject's `ancestors`, in the same way as `SubjectBuilder`.
#[derive(Debug, Clone, Default)]
pub struct AncestorBuilder {
    pins: Vec<(String, PinSpec)>,
    exacts: Vec<(String, MatchValue)>,
    tags: Vec<String>,
}

impl AncestorBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pins the item of the ancestor, as far as `spec` chooses: the chosen part becomes a placeholder.
    pub fn pin(mut self, key: impl Into<String>, spec: PinSpec) -> Self {
        self.pins.push((key.into(), spec));
        self
    }

    /// Matches the item of the ancestor against a concrete value.
    pub fn exact(mut self, key: impl Into<String>, value: MatchValue) -> Self {
        self.exacts.push((key.into(), value));
        self
    }

    /// Requires a tag the ancestor carries.
    pub fn tag(mut self, name: impl Into<String>) -> Self {
        self.tags.push(name.into());
        self
    }

    /// Combines the placeholders and the concrete values into an entry, checking and merging them as `SubjectBuilder::build` does.
    pub fn build(self) -> Result<AncestorMatch, BuildError> {
        todo!()
    }
}

/// How much of an item's value to pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSpec {
    /// The whole value (`process`, and items with an unstructured value).
    All,
    /// The chosen fields of `binary`; the fields the validity rules require are added.
    Binary(Vec<BinaryField>),
}

/// Builds a static rule and checks its values and its strength against its scopes. Made by `Policy::rule_builder`, since the strength needs the definitions of tags and named subjects in the list as well as the vocabulary.
#[expect(dead_code, reason = "read once build is implemented")]
pub struct RuleBuilder<'p> {
    policy: &'p Policy<'p>,
    id: String,
    subject: SubjectRef,
    targets: Vec<String>,
    conditions: Vec<ConditionUse>,
    effect: Option<Effect>,
}

impl<'p> RuleBuilder<'p> {
    pub(crate) fn new(policy: &'p Policy<'p>, id: String, subject: SubjectRef) -> Self {
        Self {
            policy,
            id,
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

    /// Checks the keys of the subject and the conditions against the vocabulary, the names of tags and subjects against the list, the validity of the values (`Matcher::validate`, `Condition::validate_args`), and the strength of an `allow` rule against the policy's `AllowConstraints`, and returns the static rule. The strength is decided without a process (`path` counts as `Medium`). Of the scopes, the presence of lifetime conditions and the length of `age` are checked here; the time of an `until` is checked by `Policy::grant` against the time of granting.
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
    /// A tag name is not defined in the list.
    UnknownTag {
        name: String,
    },
    /// The subject is referenced by a name that is not defined in the list.
    UnknownSubject {
        name: String,
    },
    /// The value of an item breaks the item's validity rules.
    InvalidValue {
        key: String,
        reason: String,
    },
    /// The item, or the field of a structured value, is given twice (by `pin` and `exact`, or by two calls).
    Conflict {
        key: String,
        field: Option<String>,
    },
    /// The subject or the `ancestors` entry has no condition at all.
    Empty,
    /// The conditions of an `allow` rule do not satisfy the `AllowConstraints` for the class of its strength.
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
            Self::UnknownTag { name } => {
                write!(
                    f,
                    "no tag named {name:?} in the list; define it in the list"
                )
            }
            Self::UnknownSubject { name } => write!(
                f,
                "no subject named {name:?} in the list; define it in the list"
            ),
            Self::InvalidValue { key, reason } => {
                write!(f, "the value of {key:?} is not valid: {reason}")
            }
            Self::Conflict { key, field: None } => {
                write!(f, "{key:?} is given twice; give it once")
            }
            Self::Conflict {
                key,
                field: Some(field),
            } => write!(f, "{field:?} of {key:?} is given twice; give it once"),
            Self::Empty => f.write_str("no condition is given; give an item, a tag or an ancestor"),
            Self::ScopeTooWeak { class } => write!(
                f,
                "an allow rule of class {class:?} lacks the scope the constraints require for that class; add a scope they accept"
            ),
            Self::MissingEffect => f.write_str("no effect chosen; call allow, deny or ask"),
        }
    }
}

impl std::error::Error for BuildError {}
