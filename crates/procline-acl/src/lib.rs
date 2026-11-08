//! Access control rules over a process lineage.

mod builder;
mod context;
mod policy;
mod rule;
mod subject;
mod vocabulary;

pub use builder::{BuildError, RuleBuilder, SubjectBuilder};
pub use context::EvalContext;
pub use policy::{
    Decision, LoadError, Policy, PolicyVerifier, PresetError, RecordUseError, TaggedChain, Trace,
    TraceEntry,
};
pub use rule::{ConditionUse, Effect, Preset, Rule, Target};
pub use subject::{
    AncestorCondition, AncestorSelector, Literal, MatchValue, Subject, SubjectRef, Tag,
};
pub use vocabulary::{
    Chain, Condition, ConditionKind, Depth, Epoch, EpochProvider, Item, ItemKind, Matcher,
    RegisterError, Vocabulary,
};
