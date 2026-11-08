use serde::{Deserialize, Serialize};

/// Class the matcher item decides from the value: how far the condition pins down the approved individual process or code. Ordered so that `Strong` is the greatest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    Weak,
    Medium,
    Strong,
}
