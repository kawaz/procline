use std::fmt;

use crate::pin::Pinnable;
use crate::signature::CdHash;

/// The value of the `binary` matcher item: the identity of the code, as any number of fields. Every field present is checked (AND); the fields taken from the signature match only when the signature verifies.
///
/// Each field present is a concrete value or a placeholder (`Pinnable::Pin`) that a grant fills in with the value of the matched process. A grant holds no placeholder.
///
/// In JSON, an object with the fields `digest`, `team_id`, `signing_id`, `bundle_id` and `cdhash`, each optional; a field is `true` for a placeholder or its value otherwise (`cdhash` as a lowercase hex string). Unknown fields are rejected. Example: `{"signing_id": "com.googlecode.iterm2", "team_id": true}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BinaryPin {
    /// Hash of the contents of the file at the executable path (`sha256:…`).
    pub digest: Option<Pinnable<String>>,
    pub team_id: Option<Pinnable<String>>,
    pub signing_id: Option<Pinnable<String>>,
    /// Matched against `Signature.bundle_id` (the sealed Info.plist), not `ProcessInfo.bundle`.
    pub bundle_id: Option<Pinnable<String>>,
    /// Determines every other signature field, so it is the strongest field.
    pub cdhash: Option<Pinnable<CdHash>>,
}

impl BinaryPin {
    /// Checks the validity rules: `signing_id` needs `team_id`, `bundle_id` needs `team_id` and `signing_id`, and at least one field is present. A placeholder counts as present.
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

/// A `binary` value breaks a validity rule. A field given as a placeholder counts as given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryPinError {
    /// `signing_id` is given without `team_id`; anyone, even an ad-hoc signer, can claim a signing identifier.
    SigningIdWithoutTeamId,
    /// `bundle_id` is given without `team_id` and `signing_id`; anyone can write an Info.plist.
    BundleIdWithoutSigner,
    /// No field is given.
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
