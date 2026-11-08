use std::collections::BTreeMap;

use procline_core::{BinaryPin, Pinnable, ProcessIdentity};

/// A condition on one process and on its ancestors. All parts are ANDed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subject {
    /// Conditions on the process itself, keyed by item. Flat: a structured value stays under its own key.
    pub r#match: BTreeMap<String, MatchValue>,
    /// Tags the process itself must carry.
    pub tags: Vec<String>,
    /// Conditions on the ancestors, nearest first. Each entry matches some ancestor, in this order, with other ancestors allowed in between (a subsequence).
    ///
    /// Matching is greedy from the near side: each entry takes the nearest matching ancestor above the one the previous entry took, so the ancestor whose values fill in an entry's placeholders is unique.
    pub ancestors: Vec<AncestorMatch>,
    /// Let the sequence of `ancestors` start at the process itself instead of its parent.
    pub include_self: bool,
}

/// One entry of `ancestors`: conditions on one ancestor. It has no `ancestors` of its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AncestorMatch {
    /// Conditions on the ancestor, keyed by item.
    pub r#match: BTreeMap<String, MatchValue>,
    /// Tags the ancestor must carry.
    pub tags: Vec<String>,
}

/// A value to match an item against.
///
/// Placeholders (`true`) are written only in the inline subject of a rule; a grant, a tag definition and a named subject hold none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchValue {
    /// Placeholder of an item with an unstructured value (`true` in JSON): a grant pins the actual value of the matched process, compared for exact match.
    Pin,
    /// A number or a string in JSON, as is.
    Exact(Literal),
    /// `{"glob": "…"}` in JSON.
    Glob(String),
    /// `{"regex": "…"}` in JSON. On `argv` it is matched against each element, not against the joined string.
    Regex(String),
    /// Inclusive numeric range, `{"min": …, "max": …}` in JSON.
    Range { min: i64, max: i64 },
    /// The individual process (`process` item), or a placeholder for the matched one. Every identifier present on both sides is compared, and all must be equal.
    Process(Pinnable<ProcessIdentity>),
    /// The identity of the code (`binary` item). Every field present is checked; each field may be a placeholder.
    Binary(BinaryPin),
}

/// A literal compared for exact match. There is no boolean literal: `true` in JSON is the placeholder; an item with a truth value takes a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Literal {
    Integer(i64),
    Text(String),
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
