use serde::{Deserialize, Serialize};

/// A level of the `os.session` lifetime condition, named after its period. Level N pins the generations of every level up to N. Ordered so that `Unlocked` is the greatest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLevel {
    /// From boot until restart.
    Boot,
    /// From wake until sleep or hibernation.
    Awake,
    /// From unlock until the screen locks (manually, by the idle auto-lock or by the screen saver).
    Unlocked,
}
