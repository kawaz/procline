use std::time::Duration;

/// The scopes an `allow` rule needs for each class of its strength. The application gives it to `Policy::load_verified`; the crate has no default. `RuleBuilder::build`, loading the list and `Policy::grant` / `Policy::load_grant` check against it. `deny` and `ask` are not constrained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowConstraints {
    pub strong: ScopeRequirement,
    pub medium: ScopeRequirement,
    pub weak: ScopeRequirement,
}

/// What the conditions of an `allow` rule of one class must include.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeRequirement {
    /// No scope is needed.
    Unrestricted,
    /// At least one of the options.
    AnyOf(Vec<ScopeOption>),
}

/// One way to satisfy a `ScopeRequirement`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeOption {
    /// The condition with this key is among the conditions (for example `os.session`, `app.unlock`, `uses`).
    ///
    /// `Condition("age")` and `Condition("until")` can be written, but a grant holds an `age` converted to an `until`, so `Condition("age")` is never satisfied by a grant. Constrain time with `UntilWithin`.
    Condition(String),
    /// The grant expires within the duration of being made: an `age` no longer than it (checked by `RuleBuilder::build` and loading), or an `until` no later than the time of granting plus it (checked by `Policy::grant` with the `now` of the context, and by `Policy::load_grant` from the grant's `created_at`).
    UntilWithin(Duration),
}
