use std::collections::BTreeMap;
use std::time::SystemTime;

use crate::vocabulary::Vocabulary;

/// Time and observed values captured once at the start of an evaluation, so they do not change midway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalContext {
    now: SystemTime,
    observed: BTreeMap<String, Option<serde_json::Value>>,
}

impl EvalContext {
    /// Captures the current time and calls `observe` once on every condition item, keeping the results by key.
    pub fn capture(_vocab: &Vocabulary) -> Self {
        todo!()
    }

    /// A context with the given time and no observed values; tests fill them with `with_observed`.
    pub fn new(now: SystemTime) -> Self {
        Self {
            now,
            observed: BTreeMap::new(),
        }
    }

    /// Sets the observed value of a condition item; `None` means nothing could be observed.
    pub fn with_observed(
        mut self,
        key: impl Into<String>,
        value: Option<serde_json::Value>,
    ) -> Self {
        self.observed.insert(key.into(), value);
        self
    }

    pub fn now(&self) -> SystemTime {
        self.now
    }

    /// The observed value of a condition item.
    pub fn observed(&self, key: &str) -> Option<&serde_json::Value> {
        self.observed.get(key).and_then(Option::as_ref)
    }
}

/// What one condition sees: the captured time and its own observed value. The policy builds it per condition, since a condition does not know its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observed<'a> {
    pub now: SystemTime,
    /// The result of `observe`; `None` when nothing was observed.
    pub value: Option<&'a serde_json::Value>,
}
