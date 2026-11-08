use std::collections::BTreeMap;
use std::fmt;

use procline_core::{ProcessChain, ProcessInfo, Strength};

use crate::context::EvalContext;
use crate::subject::MatchValue;

/// Every item usable in a rule: `match` keys, lifetime scopes and state conditions.
#[derive(Default)]
pub struct Vocabulary {
    items: BTreeMap<String, Item>,
}

impl Vocabulary {
    /// The built-in items (signature chain, identifiers, `os.*`, `time.*`, `until` / `age` / `uses` / `process`).
    pub fn builtin() -> Self {
        todo!()
    }

    /// Adds an item. Fails on a duplicate key, an unregistered or cyclic dependency, or a key outside the allowed namespace.
    pub fn register(&mut self, _item: Item) -> Result<(), RegisterError> {
        todo!()
    }

    /// Looks up a registered item.
    pub fn get(&self, key: &str) -> Option<&Item> {
        self.items.get(key)
    }

    /// The chains (items connected by `depends`), each with its items ordered by depth.
    pub fn chains(&self) -> Vec<Chain> {
        todo!()
    }

    /// The class of the chain the matcher item belongs to.
    pub fn class(&self, _key: &str) -> Option<Strength> {
        todo!()
    }

    /// The item and every item it transitively depends on.
    pub fn closure(&self, _key: &str) -> Option<Vec<&str>> {
        todo!()
    }
}

/// One registrable item: key, depends and its implementation.
pub struct Item {
    key: String,
    depends: Vec<String>,
    /// Class given to a root matcher item; dependent items inherit from their roots.
    class: Option<Strength>,
    kind: ItemKind,
}

impl Item {
    /// A root matcher item (no depends) with its class.
    pub fn root_matcher(
        key: impl Into<String>,
        class: Strength,
        matcher: impl Matcher + 'static,
    ) -> Self {
        Self {
            key: key.into(),
            depends: Vec::new(),
            class: Some(class),
            kind: ItemKind::Matcher(Box::new(matcher)),
        }
    }

    /// A matcher item that depends on other items and inherits their class.
    pub fn matcher<D: Into<String>>(
        key: impl Into<String>,
        depends: impl IntoIterator<Item = D>,
        matcher: impl Matcher + 'static,
    ) -> Self {
        Self {
            key: key.into(),
            depends: depends.into_iter().map(Into::into).collect(),
            class: None,
            kind: ItemKind::Matcher(Box::new(matcher)),
        }
    }

    /// A lifetime scope item.
    pub fn epoch<D: Into<String>>(
        key: impl Into<String>,
        depends: impl IntoIterator<Item = D>,
        provider: impl EpochProvider + 'static,
    ) -> Self {
        Self {
            key: key.into(),
            depends: depends.into_iter().map(Into::into).collect(),
            class: None,
            kind: ItemKind::Epoch(Box::new(provider)),
        }
    }

    /// A state condition item.
    pub fn condition<D: Into<String>>(
        key: impl Into<String>,
        depends: impl IntoIterator<Item = D>,
        condition: impl Condition + 'static,
    ) -> Self {
        Self {
            key: key.into(),
            depends: depends.into_iter().map(Into::into).collect(),
            class: None,
            kind: ItemKind::Condition(Box::new(condition)),
        }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn depends(&self) -> &[String] {
        &self.depends
    }

    /// The class given at registration; only root matcher items have one.
    pub fn root_class(&self) -> Option<Strength> {
        self.class
    }

    pub fn kind(&self) -> &ItemKind {
        &self.kind
    }

    /// Lifetime or state for condition items, `None` for matcher items.
    pub fn condition_kind(&self) -> Option<ConditionKind> {
        match self.kind {
            ItemKind::Matcher(_) => None,
            ItemKind::Epoch(_) => Some(ConditionKind::Lifetime),
            ItemKind::Condition(_) => Some(ConditionKind::State),
        }
    }
}

/// The implementation of an item.
pub enum ItemKind {
    Matcher(Box<dyn Matcher>),
    Epoch(Box<dyn EpochProvider>),
    Condition(Box<dyn Condition>),
}

/// Matches one process against the value written in `match`.
pub trait Matcher: Send + Sync {
    fn matches(&self, process: &ProcessInfo, value: &MatchValue) -> bool;
}

impl<F> Matcher for F
where
    F: Fn(&ProcessInfo, &MatchValue) -> bool + Send + Sync,
{
    fn matches(&self, process: &ProcessInfo, value: &MatchValue) -> bool {
        self(process, value)
    }
}

/// Returns the current epoch of a lifetime scope; `None` means the scope cannot be determined (treated as expired).
pub trait EpochProvider: Send + Sync {
    fn current(&self, ctx: &EvalContext) -> Option<Epoch>;
}

/// Evaluates a state condition.
pub trait Condition: Send + Sync {
    fn eval(&self, chain: &ProcessChain, args: &serde_json::Value, ctx: &EvalContext) -> bool;
}

/// Whether a false condition expires the rule forever or only while false.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionKind {
    Lifetime,
    State,
}

/// Opaque epoch value recorded when a rule is created.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Epoch(pub String);

/// Items connected by `depends`, with the class taken from its roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub class: Strength,
    /// Ordered from the root to the leaves.
    pub items: Vec<(String, Depth)>,
}

/// Distance from the root within a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Depth(pub u8);

/// Registering an item failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
    Duplicate {
        key: String,
    },
    UnknownDependency {
        key: String,
        missing: String,
    },
    Cycle {
        key: String,
    },
    Namespace {
        key: String,
    },
    /// A matcher item without depends was registered without a class.
    MissingClass {
        key: String,
    },
}

impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate { key } => write!(f, "item {key:?} is already registered"),
            Self::UnknownDependency { key, missing } => write!(
                f,
                "item {key:?} depends on {missing:?}, which is not registered; register it first"
            ),
            Self::Cycle { key } => write!(f, "the depends of item {key:?} form a cycle"),
            Self::Namespace { key } => {
                write!(
                    f,
                    "item {key:?} is outside the allowed namespace; use the \"app.\" prefix"
                )
            }
            Self::MissingClass { key } => write!(
                f,
                "matcher item {key:?} has no depends and no class; register it as a root matcher with a class"
            ),
        }
    }
}

impl std::error::Error for RegisterError {}
