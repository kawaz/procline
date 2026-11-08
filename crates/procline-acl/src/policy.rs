use std::collections::BTreeSet;
use std::fmt;

use procline_core::ProcessChain;

use crate::context::EvalContext;
use crate::rule::{Effect, Preset, Rule, Target};
use crate::subject::{Subject, Tag};
use crate::vocabulary::Vocabulary;

/// The verified list of subjects, tags, rules and presets.
#[expect(dead_code, reason = "read once loading and evaluation are implemented")]
pub struct Policy<'v> {
    vocab: &'v Vocabulary,
    subjects: Vec<(String, Subject)>,
    tags: Vec<Tag>,
    rules: Vec<Rule>,
    presets: Vec<Preset>,
}

/// Verifies the signature over the serialized list.
pub trait PolicyVerifier {
    fn verify(&self, bytes: &[u8], signature: &[u8]) -> bool;
}

impl<'v> Policy<'v> {
    /// Verifies the signature, then parses and checks the list against the vocabulary.
    pub fn load_verified(
        _bytes: &[u8],
        _signature: &[u8],
        _verifier: &dyn PolicyVerifier,
        _vocab: &'v Vocabulary,
    ) -> Result<Self, LoadError> {
        todo!()
    }

    /// Attaches the tags each process of the chain carries.
    pub fn tag<'c>(&'c self, _chain: &'c ProcessChain) -> TaggedChain<'c> {
        todo!()
    }

    /// Decides the effect for the target and explains why.
    pub fn evaluate(
        &self,
        _tagged: &TaggedChain<'_>,
        _target: &Target,
        _ctx: &EvalContext,
    ) -> Decision {
        todo!()
    }

    /// Records the current epochs into the preset and returns it as a normal rule.
    pub fn instantiate_preset(&self, _name: &str, _ctx: &EvalContext) -> Result<Rule, PresetError> {
        todo!()
    }

    /// Counts one actual use of the rule for `uses`.
    pub fn record_use(&mut self, _rule_id: &str) -> Result<(), RecordUseError> {
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
    /// The rule that decided the effect; `None` when the default effect applied.
    pub matched_rule: Option<String>,
    pub trace: Trace,
}

/// Why each rule matched or did not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trace {
    pub entries: Vec<TraceEntry>,
}

/// One checked item of one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEntry {
    pub rule_id: String,
    pub key: String,
    /// Index into the chain of the process the item matched, if any.
    pub process: Option<usize>,
    pub matched: bool,
}

/// Loading the list failed.
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
    /// An item is pinned without an item it depends on.
    MissingDependency {
        key: String,
        missing: String,
    },
    /// The same item is given different values.
    ConflictingValue {
        key: String,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => f.write_str("the signature of the rule list does not verify"),
            Self::Parse(err) => write!(f, "cannot parse the rule list: {err}"),
            Self::UnknownItem { key } => {
                write!(
                    f,
                    "{key:?} is not registered in the vocabulary; register it before loading"
                )
            }
            Self::TagCycle { tags } => {
                write!(f, "tag definitions form a cycle: {}", tags.join(" -> "))
            }
            Self::MissingDependency { key, missing } => {
                write!(
                    f,
                    "{key:?} is pinned without {missing:?}, which it depends on; pin {missing:?} too"
                )
            }
            Self::ConflictingValue { key } => write!(f, "{key:?} is given conflicting values"),
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

/// Instantiating a preset failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresetError {
    UnknownPreset {
        name: String,
    },
    /// The epoch of a lifetime item could not be determined.
    EpochUnavailable {
        key: String,
    },
}

impl fmt::Display for PresetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPreset { name } => write!(f, "no preset named {name:?}"),
            Self::EpochUnavailable { key } => {
                write!(
                    f,
                    "the current epoch of {key:?} cannot be determined; the rule would expire at once"
                )
            }
        }
    }
}

impl std::error::Error for PresetError {}

/// Recording a use failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordUseError {
    UnknownRule { rule_id: String },
}

impl fmt::Display for RecordUseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRule { rule_id } => write!(f, "no rule with id {rule_id:?}"),
        }
    }
}

impl std::error::Error for RecordUseError {}
