//! Access control rules over a process lineage.

mod builder;
mod conditions;
mod constraints;
mod context;
mod matchers;
mod matching;
mod policy;
mod rule;
mod subject;
mod vocabulary;

pub use builder::{AncestorBuilder, BuildError, PinSpec, RuleBuilder, SubjectBuilder};
pub use constraints::{AllowConstraints, ScopeOption, ScopeRequirement};
pub use context::{EvalContext, Observed};
pub use policy::{
    Decision, GrantError, LoadError, Policy, PolicyVerifier, SignedKind, TaggedChain, Trace,
    TraceEntry,
};
pub use rule::{ConditionUse, Effect, Grant, PinnedCondition, Rule, Target};
pub use subject::{AncestorMatch, Literal, MatchValue, Subject, SubjectRef, Tag};
pub use vocabulary::{
    Condition, ConditionKind, Item, ItemKind, MatchTarget, Matcher, ObserveError, PinError,
    RegisterError, ResolveError, Vocabulary,
};
