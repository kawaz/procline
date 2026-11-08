use std::fmt;

use serde::{Deserialize, Serialize};

use crate::signature::CdHash;

/// The pin value of the `binary` matcher item: the identity of the code, as any number of fields. Every field present is checked (AND); the fields taken from the signature match only when the signature verifies.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryPin {
    /// Hash of the contents of the file at the executable path (`sha256:…`).
    pub digest: Option<String>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub bundle_id: Option<String>,
    /// Determines every other signature field, so it is the strongest field.
    pub cdhash: Option<CdHash>,
}

impl BinaryPin {
    /// Checks the validity rules: `signing_id` needs `team_id`, `bundle_id` needs `team_id` and `signing_id`, and at least one field is present.
    pub fn validate(&self) -> Result<(), BinaryPinError> {
        todo!()
    }
}

/// One field of a `binary` value, to choose which fields to pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BinaryField {
    Digest,
    TeamId,
    SigningId,
    BundleId,
    CdHash,
}

/// A `binary` value breaks a validity rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryPinError {
    /// `signing_id` is present without `team_id`; anyone, even an ad-hoc signer, can claim a signing identifier.
    SigningIdWithoutTeamId,
    /// `bundle_id` is present without `team_id` and `signing_id`; anyone can write an Info.plist.
    BundleIdWithoutSigner,
    /// No field is present.
    Empty,
}

impl fmt::Display for BinaryPinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigningIdWithoutTeamId => {
                f.write_str("signing_id is given without team_id; add team_id")
            }
            Self::BundleIdWithoutSigner => f.write_str(
                "bundle_id is given without team_id and signing_id; add team_id and signing_id",
            ),
            Self::Empty => f.write_str("no field is given; give at least one field"),
        }
    }
}

impl std::error::Error for BinaryPinError {}
