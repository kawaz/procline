//! The built-in conditions independent of the OS: `until`, `age`, `uses` and `time.window`.

use procline_core::ProcessChain;

use crate::context::Observed;
use crate::vocabulary::{Condition, ConditionKind, ObserveError, PinError};

/// `until`: the grant lives until the time given as its argument.
pub(crate) struct Until;

/// `age`: the grant lives for the duration given as its argument; a grant holds it as an `until`.
pub(crate) struct Age;

/// `uses`: the grant can be adopted the number of times given as its argument.
pub(crate) struct Uses;

/// `time.window`: holds on the days of the week and the hours given as its argument.
pub(crate) struct TimeWindow;

impl Condition for Until {
    fn kind(&self) -> ConditionKind {
        ConditionKind::Lifetime
    }

    fn observe(&self) -> Result<Option<serde_json::Value>, ObserveError> {
        todo!()
    }

    fn validate_args(&self, _args: Option<&serde_json::Value>) -> Result<(), String> {
        todo!()
    }

    fn pin(
        &self,
        _args: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> Result<Option<serde_json::Value>, PinError> {
        todo!()
    }

    fn check(
        &self,
        _args: Option<&serde_json::Value>,
        _pinned: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> bool {
        todo!()
    }

    fn advance(&self, _pinned: Option<&serde_json::Value>) -> Option<serde_json::Value> {
        todo!()
    }
}

impl Condition for Age {
    fn kind(&self) -> ConditionKind {
        ConditionKind::Lifetime
    }

    fn observe(&self) -> Result<Option<serde_json::Value>, ObserveError> {
        todo!()
    }

    fn validate_args(&self, _args: Option<&serde_json::Value>) -> Result<(), String> {
        todo!()
    }

    fn pin(
        &self,
        _args: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> Result<Option<serde_json::Value>, PinError> {
        todo!()
    }

    fn check(
        &self,
        _args: Option<&serde_json::Value>,
        _pinned: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> bool {
        todo!()
    }

    fn advance(&self, _pinned: Option<&serde_json::Value>) -> Option<serde_json::Value> {
        todo!()
    }
}

impl Condition for Uses {
    fn kind(&self) -> ConditionKind {
        ConditionKind::Lifetime
    }

    fn observe(&self) -> Result<Option<serde_json::Value>, ObserveError> {
        todo!()
    }

    fn validate_args(&self, _args: Option<&serde_json::Value>) -> Result<(), String> {
        todo!()
    }

    fn pin(
        &self,
        _args: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> Result<Option<serde_json::Value>, PinError> {
        todo!()
    }

    fn check(
        &self,
        _args: Option<&serde_json::Value>,
        _pinned: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> bool {
        todo!()
    }

    fn advance(&self, _pinned: Option<&serde_json::Value>) -> Option<serde_json::Value> {
        todo!()
    }
}

impl Condition for TimeWindow {
    fn kind(&self) -> ConditionKind {
        ConditionKind::State
    }

    fn observe(&self) -> Result<Option<serde_json::Value>, ObserveError> {
        todo!()
    }

    fn validate_args(&self, _args: Option<&serde_json::Value>) -> Result<(), String> {
        todo!()
    }

    fn pin(
        &self,
        _args: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> Result<Option<serde_json::Value>, PinError> {
        todo!()
    }

    fn check(
        &self,
        _args: Option<&serde_json::Value>,
        _pinned: Option<&serde_json::Value>,
        _obs: &Observed<'_>,
        _chain: &ProcessChain,
    ) -> bool {
        todo!()
    }

    fn advance(&self, _pinned: Option<&serde_json::Value>) -> Option<serde_json::Value> {
        todo!()
    }
}
