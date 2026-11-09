use std::collections::BTreeMap;

use procline_core::{BinaryPin, Pinnable, ProcessIdentity};

/// A condition on one process and on its ancestors. All parts are ANDed; the only alternatives are the values of one item (`MatchValue::AnyOf`) and the several definitions of one tag name (`Tag`).
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
    /// Alternatives for one item, an array in JSON: the item matches when one of the values does. One level only (no list in a list), no placeholder (a grant cannot pin one value out of several), and not empty. The vocabulary checks the list and hands the item one value at a time, so an item never sees a list.
    AnyOf(Vec<MatchValue>),
}

impl MatchValue {
    /// The value is or holds a placeholder a grant fills in (`Pin`, `Process(Pin)`, or a `Binary` with a placeholder field). A list (`AnyOf`) holds none: a placeholder written in one is not filled in, and `validate` rejects it.
    pub(crate) fn has_placeholder(&self) -> bool {
        match self {
            Self::Pin | Self::Process(Pinnable::Pin) => true,
            Self::Binary(pin) => {
                matches!(pin.digest, Some(Pinnable::Pin))
                    || matches!(pin.team_id, Some(Pinnable::Pin))
                    || matches!(pin.signing_id, Some(Pinnable::Pin))
                    || matches!(pin.bundle_id, Some(Pinnable::Pin))
                    || matches!(pin.cdhash, Some(Pinnable::Pin))
            }
            Self::Exact(_)
            | Self::Glob(_)
            | Self::Regex(_)
            | Self::Range { .. }
            | Self::Process(Pinnable::Value(_))
            | Self::AnyOf(_) => false,
        }
    }

    /// The shape rules of a list of alternatives, the same for every item: not empty, no list in it, no placeholder in it. The values themselves are the item's to check.
    pub(crate) fn check_alternatives(values: &[MatchValue]) -> Result<(), String> {
        if values.is_empty() {
            return Err("an empty list matches nothing; give at least one value".to_owned());
        }
        if values.iter().any(|value| matches!(value, Self::AnyOf(_))) {
            return Err("a list cannot hold a list; write the values in one list".to_owned());
        }
        if values.iter().any(Self::has_placeholder) {
            return Err("a list cannot hold a placeholder (true), since a grant pins one value; pin the item without a list".to_owned());
        }
        Ok(())
    }

    /// The name of the first placeholder field of a `Binary` value, for an error that names it.
    pub(crate) fn placeholder_field(&self) -> Option<&'static str> {
        let Self::Binary(pin) = self else {
            return None;
        };
        [
            ("digest", matches!(pin.digest, Some(Pinnable::Pin))),
            ("team_id", matches!(pin.team_id, Some(Pinnable::Pin))),
            ("signing_id", matches!(pin.signing_id, Some(Pinnable::Pin))),
            ("bundle_id", matches!(pin.bundle_id, Some(Pinnable::Pin))),
            ("cdhash", matches!(pin.cdhash, Some(Pinnable::Pin))),
        ]
        .into_iter()
        .find_map(|(name, pinned)| pinned.then_some(name))
    }
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

/// A named subject; matching processes carry the tag. A name may have several definitions: a process carries the tag when one of them matches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub name: String,
    pub subject: SubjectRef,
}
