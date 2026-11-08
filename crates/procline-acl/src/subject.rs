use std::collections::BTreeMap;

use procline_core::{BinaryPin, ProcessIdentity};

/// A condition on one process, optionally with conditions on its ancestors. All parts are ANDed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subject {
    /// Conditions on the process itself, keyed by item. Flat: a structured value stays under its own key.
    pub r#match: BTreeMap<String, MatchValue>,
    /// Tags the process itself must carry.
    pub tags: Vec<String>,
    pub ancestors: Vec<AncestorCondition>,
}

/// A value to match an item against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchValue {
    Exact(Literal),
    Glob(String),
    Regex(String),
    /// Inclusive numeric range.
    Range {
        min: i64,
        max: i64,
    },
    /// The individual process (`process` item). Compared by the strongest identifier present on both sides.
    Process(ProcessIdentity),
    /// The identity of the code (`binary` item). Every field present is checked.
    Binary(BinaryPin),
}

/// A literal compared for exact match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Literal {
    Bool(bool),
    Integer(i64),
    Text(String),
}

/// One entry of `ancestors`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncestorCondition {
    pub selector: AncestorSelector,
    /// Also consider the process itself as a candidate.
    pub include_self: bool,
}

/// Which ancestors the nested subject applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AncestorSelector {
    /// Any ancestor.
    Any(SubjectRef),
    /// The ancestor `n` levels up.
    At(usize, SubjectRef),
    /// Ancestors in this order.
    Chain(Vec<SubjectRef>),
}

/// A subject written in place or referenced by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectRef {
    Inline(Box<Subject>),
    Named(String),
}

/// A named subject; matching processes carry the tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub name: String,
    pub subject: SubjectRef,
}
