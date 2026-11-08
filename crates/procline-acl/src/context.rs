use std::collections::BTreeMap;
use std::time::SystemTime;

use crate::vocabulary::{ObserveError, Vocabulary};

/// Time and observed values captured once at the start of an evaluation, so they do not change midway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalContext {
    now: SystemTime,
    observed: BTreeMap<String, Result<Option<serde_json::Value>, ObserveError>>,
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

    /// Sets the result of `observe` for a condition item: `Ok(None)` when there is nothing to observe, `Err` when observing failed.
    pub fn with_observed(
        mut self,
        key: impl Into<String>,
        value: Result<Option<serde_json::Value>, ObserveError>,
    ) -> Self {
        self.observed.insert(key.into(), value);
        self
    }

    pub fn now(&self) -> SystemTime {
        self.now
    }

    /// The result of `observe` for a condition item; `Ok(None)` also for a key that was not observed.
    pub fn observed(&self, key: &str) -> Result<Option<&serde_json::Value>, &ObserveError> {
        match self.observed.get(key) {
            Some(Ok(value)) => Ok(value.as_ref()),
            Some(Err(err)) => Err(err),
            None => Ok(None),
        }
    }
}

/// What one condition sees: the captured time and its own observed value. The policy builds it per condition, since a condition does not know its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observed<'a> {
    pub now: SystemTime,
    /// The result of `observe`: `Ok(None)` when there is nothing to observe, `Err` when observing failed.
    pub value: Result<Option<&'a serde_json::Value>, &'a ObserveError>,
}
