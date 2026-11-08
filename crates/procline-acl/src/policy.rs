use std::collections::BTreeSet;
use std::fmt;

use procline_core::{ProcessChain, Strength};

use crate::builder::RuleBuilder;
use crate::constraints::AllowConstraints;
use crate::context::EvalContext;
use crate::rule::{Effect, Grant, Rule, Target};
use crate::subject::{Subject, SubjectRef, Tag};
use crate::vocabulary::{PinError, Vocabulary};

/// The verified list of subjects, tags and rules, and the grants evaluation looks at.
#[expect(dead_code, reason = "read once loading and evaluation are implemented")]
pub struct Policy<'v> {
    vocab: &'v Vocabulary,
    constraints: AllowConstraints,
    /// The effect when no grant is adopted.
    default_effect: Effect,
    subjects: Vec<(String, Subject)>,
    tags: Vec<Tag>,
    rules: Vec<Rule>,
    grants: Vec<Grant>,
}

/// Verifies the signature over serialized bytes (the list, or one grant).
pub trait PolicyVerifier {
    /// `kind` tells what the bytes are, so a signature made for one kind does not verify as the other.
    fn verify(&self, kind: SignedKind, bytes: &[u8], signature: &[u8]) -> bool;
}

/// What signed bytes are: the list or one grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignedKind {
    List,
    Grant,
}

impl<'v> Policy<'v> {
    /// Verifies the signature (as `SignedKind::List`), then parses and checks the list against the vocabulary (unknown items, validity of the values), the names of tags and subjects, and the `allow` rules against `constraints`. `default_effect` is the effect when no grant is adopted.
    ///
    /// A rule becomes a permanent grant when it has no lifetime or consumable condition, no placeholder, and no condition whose pin needs the chain or an observed value (`os.login_session` and the like); any other rule becomes a grant only through approval (`grant`). A placeholder outside the inline subject of a rule is `InvalidValue`.
    ///
    /// After loading the list again, check the stored grants again with `load_grant`: a changed tag definition can lower their strength.
    pub fn load_verified(
        _bytes: &[u8],
        _signature: &[u8],
        _verifier: &dyn PolicyVerifier,
        _vocab: &'v Vocabulary,
        _constraints: AllowConstraints,
        _default_effect: Effect,
    ) -> Result<Self, LoadError> {
        todo!()
    }

    /// Starts a rule with the given id and subject; `RuleBuilder::build` checks it against this policy's vocabulary, list and `AllowConstraints`.
    pub fn rule_builder(&self, id: impl Into<String>, subject: SubjectRef) -> RuleBuilder<'_> {
        RuleBuilder::new(self, id.into(), subject)
    }

    /// Verifies the signature of one stored grant (as `SignedKind::Grant`), then parses and checks it against the vocabulary (unknown items, validity of the values), the tag names, and an `allow` grant against the `AllowConstraints`. A `ScopeOption::UntilWithin` is measured from the grant's `created_at`. Does not add it; call `add_grant`.
    pub fn load_grant(
        &self,
        _bytes: &[u8],
        _signature: &[u8],
        _verifier: &dyn PolicyVerifier,
    ) -> Result<Grant, LoadError> {
        todo!()
    }

    /// Adds a grant to the ones evaluation looks at, replacing the grant with the same id. Call it once the application has stored the grant (a new one from `grant`, an `updated_grant`, or one read back by `load_grant`).
    pub fn add_grant(&mut self, _grant: Grant) {
        todo!()
    }

    /// Removes the grant with the id, for example one listed in `Decision.expired`. Returns the removed grant.
    pub fn remove_grant(&mut self, _id: &str) -> Option<Grant> {
        todo!()
    }

    /// Every grant evaluation looks at, for cleanup.
    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.iter()
    }

    /// Fills in the placeholders of the rule's subject from `tagged` (via `resolve_subject`), checks an `allow` rule against the `AllowConstraints`, pins the conditions, and returns the resulting grant without adding it. The application signs and stores it, then calls `add_grant`.
    pub fn grant(
        &self,
        _rule: &Rule,
        _tagged: &TaggedChain<'_>,
        _ctx: &EvalContext,
    ) -> Result<Grant, GrantError> {
        todo!()
    }

    /// Resolves a name to the subject in the list, then replaces every placeholder with the actual value: those of `match` from the target (the first process of the chain), those of an `ancestors` entry from the ancestor the entry matched. Lets an approval screen show what will be pinned before the user approves.
    pub fn resolve_subject(
        &self,
        _subject: &SubjectRef,
        _tagged: &TaggedChain<'_>,
    ) -> Result<Subject, GrantError> {
        todo!()
    }

    /// Attaches the tags each process of the chain carries. The result borrows the vocabulary and the chain, not the policy.
    pub fn tag<'c>(&self, _chain: &'c ProcessChain) -> TaggedChain<'c>
    where
        'v: 'c,
    {
        todo!()
    }

    /// Decides the effect for the target and advances the adopted grant. Memory is not changed: the application stores `updated_grant` and replaces it with `add_grant`, and removes the grants in `expired`.
    ///
    /// The application serializes `evaluate`, storing and `add_grant`: evaluations running at once can consume a `uses` beyond its limit.
    pub fn evaluate(
        &self,
        _tagged: &TaggedChain<'_>,
        _target: &Target,
        _ctx: &EvalContext,
    ) -> Decision {
        todo!()
    }

    /// Decides the effect for the target without advancing any grant; `updated_grant` is always `None`.
    ///
    /// `expired` is filled in but does not make expiry final: the application does not remove grants because of it.
    pub fn explain(
        &self,
        _tagged: &TaggedChain<'_>,
        _target: &Target,
        _ctx: &EvalContext,
    ) -> Decision {
        todo!()
    }
}

/// A chain with the tags of each process, index-aligned with `chain.processes()`.
pub struct TaggedChain<'a> {
    pub vocab: &'a Vocabulary,
    pub chain: &'a ProcessChain,
    pub tags: Vec<BTreeSet<String>>,
    /// The tags whose presence could not be decided because the chain is truncated. An approval screen shows them apart from the tags a process does not carry.
    pub undecidable_tags: BTreeSet<String>,
}

/// Result of an evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub effect: Effect,
    /// The adopted grant; `None` when the default effect of the policy applied.
    pub grant_id: Option<String>,
    /// For display to the user; not for the peer, since it shows which condition failed.
    pub trace: Trace,
    /// The new version of the adopted grant when `advance` changed it. The application signs and stores it before handing out the value.
    pub updated_grant: Option<Grant>,
    /// Ids of the grants whose lifetime condition was false in this evaluation. From `evaluate`, expiry is final and the application removes them; from `explain`, it is not.
    pub expired: Vec<String>,
    /// Ids of the grants that could not be decided in this evaluation, neither allowed nor expired. They did not take part in deciding the effect.
    ///
    /// A grant is listed when the chain is truncated, the grant has conditions on the ancestors (`ancestors`, or a tag whose definition has them, following tags that reference other tags), and it did not match: the conditions of a subject only add requirements, so a grant that matches the truncated chain also matches the whole chain and takes part. A grant is also listed when `observe` of one of its conditions failed.
    pub undecidable: Vec<String>,
}

/// Why each grant matched or did not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trace {
    pub entries: Vec<TraceEntry>,
}

/// One checked item of one grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEntry {
    pub grant_id: String,
    pub key: String,
    /// Index into the chain of the process the item matched, if any.
    pub process: Option<usize>,
    pub matched: bool,
}

/// Loading the list or a grant failed.
#[derive(Debug)]
pub enum LoadError {
    InvalidSignature,
    Parse(serde_json::Error),
    /// A `match` key, scope or condition is not in the vocabulary.
    UnknownItem {
        key: String,
    },
    /// A tag name is not defined in the list.
    UnknownTag {
        name: String,
    },
    /// A rule references a subject name that is not defined in the list.
    UnknownSubject {
        name: String,
    },
    TagCycle {
        tags: Vec<String>,
    },
    /// The value of an item breaks the item's validity rules, or a placeholder is written where none is allowed (a grant, a tag definition, a named subject, a rule that becomes a permanent grant).
    InvalidValue {
        key: String,
        reason: String,
    },
    /// The conditions of an `allow` rule or grant do not satisfy the `AllowConstraints` for the class of its strength.
    ScopeTooWeak {
        rule_id: String,
        class: Strength,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => f.write_str("the signature does not verify"),
            Self::Parse(err) => write!(f, "cannot parse: {err}"),
            Self::UnknownItem { key } => {
                write!(
                    f,
                    "{key:?} is not registered in the vocabulary; register it before loading"
                )
            }
            Self::UnknownTag { name } => {
                write!(
                    f,
                    "no tag named {name:?} in the list; define it in the list"
                )
            }
            Self::UnknownSubject { name } => {
                write!(
                    f,
                    "no subject named {name:?} in the list; define it in the list"
                )
            }
            Self::TagCycle { tags } => {
                write!(f, "tag definitions form a cycle: {}", tags.join(" -> "))
            }
            Self::InvalidValue { key, reason } => {
                write!(f, "the value of {key:?} is not valid: {reason}")
            }
            Self::ScopeTooWeak { rule_id, class } => write!(
                f,
                "the allow rule {rule_id:?} of class {class:?} lacks the scope the constraints require for that class; add a scope they accept"
            ),
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(err) => Some(err),
            _ => None,
        }
    }
}

/// Making a grant from a rule failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    UnknownItem {
        key: String,
    },
    /// The subject is referenced by a name that is not in the list.
    UnknownSubject {
        name: String,
    },
    /// The arguments or value of a condition break the item's validity rules.
    InvalidValue {
        key: String,
        reason: String,
    },
    /// A condition could not be pinned.
    Pin {
        key: String,
        error: PinError,
    },
    /// A placeholder of the subject has no actual value to fill in (for example `team_id: true` on an unsigned process); `field` names the field of a structured value.
    ValueUnavailable {
        key: String,
        field: Option<String>,
    },
    /// The `allow` rule does not satisfy the `AllowConstraints` for the class of its strength, decided from the matched process (`path`) or by an `until` beyond the allowed time from now.
    ScopeTooWeak {
        class: Strength,
    },
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownItem { key } => write!(f, "{key:?} is not registered in the vocabulary"),
            Self::UnknownSubject { name } => write!(f, "no subject named {name:?} in the list"),
            Self::InvalidValue { key, reason } => {
                write!(f, "the value of {key:?} is not valid: {reason}")
            }
            Self::Pin { key, error } => write!(f, "cannot pin {key:?}: {error}"),
            Self::ValueUnavailable { key, field: None } => {
                write!(
                    f,
                    "the process has no value for {key:?}; choose another item"
                )
            }
            Self::ValueUnavailable {
                key,
                field: Some(field),
            } => write!(
                f,
                "the process has no value for {field:?} of {key:?}; choose another field"
            ),
            Self::ScopeTooWeak { class } => write!(
                f,
                "an allow rule of class {class:?} lacks the scope the constraints require for that class; add a scope they accept"
            ),
        }
    }
}

impl std::error::Error for GrantError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pin { error, .. } => Some(error),
            _ => None,
        }
    }
}
