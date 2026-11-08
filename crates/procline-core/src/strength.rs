use serde::{Deserialize, Serialize};

/// Class of a chain: whether a process of the same uid can forge the value. Ordered so that `Strong` is the greatest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strength {
    Weak,
    Medium,
    Strong,
}
