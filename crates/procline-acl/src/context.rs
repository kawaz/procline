use std::collections::BTreeMap;
use std::time::SystemTime;

use crate::vocabulary::{Epoch, Vocabulary};

/// Time and epochs captured once at the start of an evaluation, so they do not change midway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalContext {
    now: SystemTime,
    epochs: BTreeMap<String, Option<Epoch>>,
}

impl EvalContext {
    /// Captures the current time and the epoch of every lifetime item.
    pub fn capture(_vocab: &Vocabulary) -> Self {
        todo!()
    }

    /// A context with the given time and no epochs; tests fill epochs with `with_epoch`.
    pub fn new(now: SystemTime) -> Self {
        Self {
            now,
            epochs: BTreeMap::new(),
        }
    }

    /// Sets the epoch of a lifetime item; `None` means it cannot be determined.
    pub fn with_epoch(mut self, key: impl Into<String>, epoch: Option<Epoch>) -> Self {
        self.epochs.insert(key.into(), epoch);
        self
    }

    pub fn now(&self) -> SystemTime {
        self.now
    }

    /// The captured epoch of a lifetime item.
    pub fn epoch(&self, key: &str) -> Option<&Epoch> {
        self.epochs.get(key).and_then(Option::as_ref)
    }
}
