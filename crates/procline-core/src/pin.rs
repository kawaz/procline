/// A value written in a rule: either a concrete value or a placeholder that a grant fills in with the actual value of the matched process.
///
/// In JSON, `true` is `Pin` and anything else is the value of `T`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pinnable<T> {
    /// Placeholder: pin the actual value of the matched process when the rule is granted.
    Pin,
    /// A concrete value, matched as written.
    Value(T),
}
