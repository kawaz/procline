use std::collections::BTreeSet;
use std::fmt;

use procline_core::ProcessChain;

use crate::context::EvalContext;
use crate::rule::{Effect, Grant, Rule, Target};
use crate::subject::{Subject, Tag};
use crate::vocabulary::{PinError, Vocabulary};

/// The verified list of subjects, tags and rules, and the grants evaluation looks at.
#[expect(dead_code, reason = "read once loading and evaluation are implemented")]
pub struct Policy<'v> {
    vocab: &'v Vocabulary,
    subjects: Vec<(String, Subject)>,
    tags: Vec<Tag>,
    rules: Vec<Rule>,
    grants: Vec<Grant>,
}

/// Verifies the signature over serialized bytes (the list, or one grant).
pub trait PolicyVerifier {
    fn verify(&self, bytes: &[u8], signature: &[u8]) -> bool;
}

impl<'v> Policy<'v> {
    /// Verifies the signature, then parses and checks the list against the vocabulary (unknown items, validity of the values). Rules without lifetime conditions become permanent grants.
    pub fn load_verified(
        _bytes: &[u8],
        _signature: &[u8],
        _verifier: &dyn PolicyVerifier,
        _vocab: &'v Vocabulary,
    ) -> Result<Self, LoadError> {
        todo!()
    }

    /// Verifies the signature of one stored grant, then parses and checks it against the vocabulary (unknown items, validity of the values).
    pub fn load_grant(
        &self,
        _bytes: &[u8],
        _signature: &[u8],
        _verifier: &dyn PolicyVerifier,
    ) -> Result<Grant, LoadError> {
        todo!()
    }

    /// Adds a grant read back by `load_grant`.
    pub fn add_grant(&mut self, _grant: Grant) {
        todo!()
    }

    /// Pins the conditions of the rule and adds the resulting grant; the application signs and stores the returned grant.
    pub fn grant(&mut self, _rule: &Rule, _ctx: &EvalContext) -> Result<Grant, GrantError> {
        todo!()
    }

    /// Attaches the tags each process of the chain carries.
    pub fn tag<'c>(&'c self, _chain: &'c ProcessChain) -> TaggedChain<'c> {
        todo!()
    }

    /// Decides the effect for the target and advances the adopted grant, replacing it in memory.
    pub fn evaluate(
        &mut self,
        _tagged: &TaggedChain<'_>,
        _target: &Target,
        _ctx: &EvalContext,
    ) -> Decision {
        todo!()
    }

    /// Decides the effect for the target without advancing any grant; `updated_grant` is always `None`.
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
}

/// Result of an evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub effect: Effect,
    /// The adopted grant; `None` when the default effect applied.
    pub grant_id: Option<String>,
    pub trace: Trace,
    /// The new version of the adopted grant when `advance` changed it. The application signs and stores it before handing out the value.
    pub updated_grant: Option<Grant>,
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
    TagCycle {
        tags: Vec<String>,
    },
    /// The value of an item breaks the item's validity rules.
    InvalidValue {
        key: String,
        reason: String,
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
            Self::TagCycle { tags } => {
                write!(f, "tag definitions form a cycle: {}", tags.join(" -> "))
            }
            Self::InvalidValue { key, reason } => {
                write!(f, "the value of {key:?} is not valid: {reason}")
            }
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
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownItem { key } => write!(f, "{key:?} is not registered in the vocabulary"),
            Self::InvalidValue { key, reason } => {
                write!(f, "the value of {key:?} is not valid: {reason}")
            }
            Self::Pin { key, error } => write!(f, "cannot pin {key:?}: {error}"),
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
