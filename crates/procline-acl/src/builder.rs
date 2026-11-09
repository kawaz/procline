use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use procline_core::{BinaryField, BinaryPin, Pinnable, Strength};

use crate::policy::{Policy, rule_meets, target_glob};
use crate::rule::{ConditionUse, Effect, Rule};
use crate::subject::{AncestorMatch, MatchValue, Subject, SubjectRef};
use crate::vocabulary::validate_value;

/// The key of the `binary` item, whose fields `pin` and `exact` merge.
const BINARY: &str = "binary";

/// The items whose value is a process identity (`MatchValue::Process`), so `PinSpec::All` pins them with `Process(Pin)` instead of `Pin`.
///
/// Design rationale: the builder holds no vocabulary (it only shapes values; `RuleBuilder::build` checks them), so it cannot ask an item for the shape of its placeholder. The built-in structured items are named here; an application item takes the unstructured placeholder `Pin`.
const PROCESS_ITEMS: [&str; 2] = ["process", "responsible"];

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

    /// Matches the item against one of the concrete values (`MatchValue::AnyOf`).
    pub fn any_of(
        self,
        key: impl Into<String>,
        values: impl IntoIterator<Item = MatchValue>,
    ) -> Self {
        self.exact(key, MatchValue::AnyOf(values.into_iter().collect()))
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

    /// Combines the placeholders and the concrete values into a subject. Checks the values only (the validity rules of `binary`, the shape of a list, an empty subject); checking the keys against the vocabulary is `RuleBuilder::build`'s job.
    ///
    /// `pin` and `exact` on the same `binary` key merge field by field into one value; a field given by both is a `Conflict`. An item with an unstructured value and `process` hold one value, so a second `pin` or `exact` on the key is a `Conflict`. A list (`any_of`) is one value too: it does not merge with another `pin` or `exact` on the key.
    pub fn build(self) -> Result<Subject, BuildError> {
        let r#match = combine(self.pins, self.exacts)?;
        if r#match.is_empty() && self.tags.is_empty() && self.ancestors.is_empty() {
            return Err(BuildError::Empty);
        }
        Ok(Subject {
            r#match,
            tags: self.tags,
            ancestors: self.ancestors,
            include_self: self.include_self,
        })
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

    /// Matches the item of the ancestor against one of the concrete values (`MatchValue::AnyOf`).
    pub fn any_of(
        self,
        key: impl Into<String>,
        values: impl IntoIterator<Item = MatchValue>,
    ) -> Self {
        self.exact(key, MatchValue::AnyOf(values.into_iter().collect()))
    }

    /// Requires a tag the ancestor carries.
    pub fn tag(mut self, name: impl Into<String>) -> Self {
        self.tags.push(name.into());
        self
    }

    /// Combines the placeholders and the concrete values into an entry, checking and merging them as `SubjectBuilder::build` does.
    pub fn build(self) -> Result<AncestorMatch, BuildError> {
        let r#match = combine(self.pins, self.exacts)?;
        if r#match.is_empty() && self.tags.is_empty() {
            return Err(BuildError::Empty);
        }
        Ok(AncestorMatch {
            r#match,
            tags: self.tags,
        })
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
    ///
    /// A `ScopeOption::UntilWithin` is met here by an `age` no longer than it, or by any `until`, whose time `Policy::grant` measures.
    pub fn build(self) -> Result<Rule, BuildError> {
        let effect = self.effect.ok_or(BuildError::MissingEffect)?;
        let policy = self.policy;
        let subject = policy
            .expand(&self.subject)
            .map_err(|name| BuildError::UnknownSubject { name })?;
        check_entries(policy, &subject.r#match, &subject.tags)?;
        for entry in &subject.ancestors {
            check_entries(policy, &entry.r#match, &entry.tags)?;
        }
        for ConditionUse { key, args } in &self.conditions {
            let condition = policy
                .vocab()
                .condition(key)
                .ok_or_else(|| BuildError::UnknownItem { key: key.clone() })?;
            condition
                .validate_args(args.as_ref())
                .map_err(|reason| BuildError::InvalidValue {
                    key: key.clone(),
                    reason,
                })?;
        }
        for glob in &self.targets {
            target_glob(glob).map_err(|err| BuildError::InvalidValue {
                key: "targets".to_owned(),
                reason: format!("invalid glob: {err}"),
            })?;
        }
        if effect == Effect::Allow {
            let class = policy.own_class(subject, None);
            let met = policy
                .constraints()
                .requirement(class)
                .is_met(|option| rule_meets(&self.conditions, option));
            if !met {
                return Err(BuildError::ScopeTooWeak { class });
            }
        }
        Ok(Rule {
            id: self.id,
            effect,
            subject: self.subject,
            targets: self.targets,
            conditions: self.conditions,
        })
    }
}

/// The keys against the vocabulary (registered matcher items), the values against their items (`Matcher::validate`), and the tag names against the list.
fn check_entries(
    policy: &Policy<'_>,
    entries: &BTreeMap<String, MatchValue>,
    tags: &[String],
) -> Result<(), BuildError> {
    for (key, value) in entries {
        let matcher = policy
            .vocab()
            .matcher(key)
            .ok_or_else(|| BuildError::UnknownItem { key: key.clone() })?;
        validate_value(matcher, value).map_err(|reason| BuildError::InvalidValue {
            key: key.clone(),
            reason,
        })?;
    }
    match tags.iter().find(|name| !policy.has_tag(name)) {
        Some(name) => Err(BuildError::UnknownTag { name: name.clone() }),
        None => Ok(()),
    }
}

/// Merges the placeholders and the concrete values of a builder into `match`.
///
/// `binary` merges field by field (a field given twice is a `Conflict` naming it), then the fields the chosen placeholder fields require are added as placeholders when absent (`signing_id` needs `team_id`, `bundle_id` needs `team_id` and `signing_id`), and the merged value is checked with `BinaryPin::validate`. Any other key takes one value: a second one is a `Conflict`.
///
/// A list is checked for its shape (`MatchValue::check_alternatives`), and on `binary` each of its values with `BinaryPin::validate`.
fn combine(
    pins: Vec<(String, PinSpec)>,
    exacts: Vec<(String, MatchValue)>,
) -> Result<BTreeMap<String, MatchValue>, BuildError> {
    let mut entries = BTreeMap::new();
    let mut required = BTreeSet::new();
    for (key, spec) in pins {
        let value = match (spec, key.as_str()) {
            (PinSpec::All, BINARY) => {
                return Err(BuildError::InvalidValue {
                    key,
                    reason: "binary pins the chosen fields; use PinSpec::Binary".to_owned(),
                });
            }
            (PinSpec::All, process) if PROCESS_ITEMS.contains(&process) => {
                MatchValue::Process(Pinnable::Pin)
            }
            (PinSpec::All, _) => MatchValue::Pin,
            (PinSpec::Binary(fields), BINARY) => {
                let fields: BTreeSet<BinaryField> = fields.into_iter().collect();
                required.extend(fields.iter().flat_map(|field| requirements(*field)));
                MatchValue::Binary(placeholders(&fields))
            }
            (PinSpec::Binary(_), _) => {
                return Err(BuildError::InvalidValue {
                    key,
                    reason: "PinSpec::Binary is for the binary item; use PinSpec::All".to_owned(),
                });
            }
        };
        insert(&mut entries, key, value)?;
    }
    for (key, value) in exacts {
        if let MatchValue::AnyOf(values) = &value {
            check_list(&key, values)?;
        }
        if value.has_placeholder() {
            return Err(BuildError::InvalidValue {
                key,
                reason: "exact takes a concrete value; pin a placeholder with pin".to_owned(),
            });
        }
        insert(&mut entries, key, value)?;
    }
    if let Some(MatchValue::Binary(pin)) = entries.get_mut(BINARY) {
        for field in required {
            pin_if_absent(pin, field);
        }
        pin.validate().map_err(|err| BuildError::InvalidValue {
            key: BINARY.to_owned(),
            reason: err.to_string(),
        })?;
    }
    Ok(entries)
}

/// The shape of a list given to `any_of`, and the validity rules of `binary` for each value on that key.
fn check_list(key: &str, values: &[MatchValue]) -> Result<(), BuildError> {
    let invalid = |reason: String| BuildError::InvalidValue {
        key: key.to_owned(),
        reason,
    };
    MatchValue::check_alternatives(values).map_err(invalid)?;
    if key == BINARY {
        for value in values {
            if let MatchValue::Binary(pin) = value {
                pin.validate().map_err(|err| invalid(err.to_string()))?;
            }
        }
    }
    Ok(())
}

fn insert(
    entries: &mut BTreeMap<String, MatchValue>,
    key: String,
    value: MatchValue,
) -> Result<(), BuildError> {
    match (entries.get_mut(&key), value) {
        (None, value) => {
            entries.insert(key, value);
            Ok(())
        }
        (Some(MatchValue::Binary(merged)), MatchValue::Binary(added)) => {
            merge_binary(merged, added).map_err(|field| BuildError::Conflict {
                key,
                field: Some(field.to_owned()),
            })
        }
        (Some(_), _) => Err(BuildError::Conflict { key, field: None }),
    }
}

/// Moves the fields of `added` into `merged`; `Err` with the name of a field both have.
fn merge_binary(merged: &mut BinaryPin, added: BinaryPin) -> Result<(), &'static str> {
    let BinaryPin {
        digest,
        team_id,
        signing_id,
        bundle_id,
        cdhash,
    } = added;
    merge_field(&mut merged.digest, digest, "digest")?;
    merge_field(&mut merged.team_id, team_id, "team_id")?;
    merge_field(&mut merged.signing_id, signing_id, "signing_id")?;
    merge_field(&mut merged.bundle_id, bundle_id, "bundle_id")?;
    merge_field(&mut merged.cdhash, cdhash, "cdhash")
}

fn merge_field<T>(
    merged: &mut Option<T>,
    added: Option<T>,
    name: &'static str,
) -> Result<(), &'static str> {
    match (merged.is_some(), added) {
        (_, None) => Ok(()),
        (false, added) => {
            *merged = added;
            Ok(())
        }
        (true, Some(_)) => Err(name),
    }
}

/// The fields the validity rules of `binary` require alongside a field.
fn requirements(field: BinaryField) -> &'static [BinaryField] {
    match field {
        BinaryField::SigningId => &[BinaryField::TeamId],
        BinaryField::BundleId => &[BinaryField::TeamId, BinaryField::SigningId],
        BinaryField::Digest | BinaryField::TeamId | BinaryField::CdHash => &[],
    }
}

/// A `binary` value with a placeholder in each of the fields.
fn placeholders(fields: &BTreeSet<BinaryField>) -> BinaryPin {
    let mut pin = BinaryPin {
        digest: None,
        team_id: None,
        signing_id: None,
        bundle_id: None,
        cdhash: None,
    };
    for field in fields {
        pin_if_absent(&mut pin, *field);
    }
    pin
}

/// Puts a placeholder in the field unless it already has a value or a placeholder.
fn pin_if_absent(pin: &mut BinaryPin, field: BinaryField) {
    fn fill<T>(slot: &mut Option<Pinnable<T>>) {
        slot.get_or_insert(Pinnable::Pin);
    }
    match field {
        BinaryField::Digest => fill(&mut pin.digest),
        BinaryField::TeamId => fill(&mut pin.team_id),
        BinaryField::SigningId => fill(&mut pin.signing_id),
        BinaryField::BundleId => fill(&mut pin.bundle_id),
        BinaryField::CdHash => fill(&mut pin.cdhash),
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
