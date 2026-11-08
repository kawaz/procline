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
        let Self {
            digest,
            team_id,
            signing_id,
            bundle_id,
            cdhash,
        } = self;
        if digest.is_none()
            && team_id.is_none()
            && signing_id.is_none()
            && bundle_id.is_none()
            && cdhash.is_none()
        {
            return Err(BinaryPinError::Empty);
        }
        if signing_id.is_some() && team_id.is_none() {
            return Err(BinaryPinError::SigningIdWithoutTeamId);
        }
        if bundle_id.is_some() && (team_id.is_none() || signing_id.is_none()) {
            return Err(BinaryPinError::BundleIdWithoutSigner);
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::{BinaryPin, BinaryPinError};
    use crate::pin::Pinnable;
    use crate::signature::CdHash;

    fn empty() -> BinaryPin {
        BinaryPin {
            digest: None,
            team_id: None,
            signing_id: None,
            bundle_id: None,
            cdhash: None,
        }
    }

    fn text(value: &str) -> Option<Pinnable<String>> {
        Some(Pinnable::Value(value.to_owned()))
    }

    // 何も絞らない値は「どのコードでもよい」になり、binary を書いた意味が無いので不正にする。
    #[test]
    fn empty_value_is_invalid() {
        assert_eq!(empty().validate(), Err(BinaryPinError::Empty));
    }

    // cdhash と digest は単独でコードを決める (cdhash は CodeDirectory が identifier / Team ID / Info.plist のハッシュを含み、digest はファイルの内容そのもの) ので、他の field なしで妥当。
    #[test]
    fn cdhash_or_digest_alone_is_valid() {
        let cdhash = BinaryPin {
            cdhash: Some(Pinnable::Value(CdHash([1; 20]))),
            ..empty()
        };
        assert_eq!(cdhash.validate(), Ok(()));
        let digest = BinaryPin {
            digest: text("sha256:00"),
            ..empty()
        };
        assert_eq!(digest.validate(), Ok(()));
    }

    // team_id は署名者を決めるので単独で妥当。
    #[test]
    fn team_id_alone_is_valid() {
        let value = BinaryPin {
            team_id: text("TEAMID1234"),
            ..empty()
        };
        assert_eq!(value.validate(), Ok(()));
    }

    // signing identifier は開発者が自由に名乗れ、ad-hoc 署名でも同じ名前を付けられるので、Team ID と組でなければ何も特定しない。
    #[test]
    fn signing_id_needs_team_id() {
        let value = BinaryPin {
            signing_id: text("com.example.tool"),
            ..empty()
        };
        assert_eq!(
            value.validate(),
            Err(BinaryPinError::SigningIdWithoutTeamId)
        );
    }

    // bundle ID は Info.plist の値で誰でも書けるので、署名者 (team_id) と signing identifier の両方と組でなければ不正。片方だけでも足りない。
    #[test]
    fn bundle_id_needs_team_id_and_signing_id() {
        let alone = BinaryPin {
            bundle_id: text("com.example.app"),
            ..empty()
        };
        assert_eq!(alone.validate(), Err(BinaryPinError::BundleIdWithoutSigner));
        let team_only = BinaryPin {
            team_id: text("TEAMID1234"),
            bundle_id: text("com.example.app"),
            ..empty()
        };
        assert_eq!(
            team_only.validate(),
            Err(BinaryPinError::BundleIdWithoutSigner)
        );
        let both = BinaryPin {
            team_id: text("TEAMID1234"),
            signing_id: text("com.example.app"),
            bundle_id: text("com.example.app"),
            ..empty()
        };
        assert_eq!(both.validate(), Ok(()));
    }

    // placeholder (true) の field も「ある」と数える。`{"signing_id": "com.googlecode.iterm2", "team_id": true}` は signing identifier で見つけて Team ID を pin する正当な書き方で、grant を作るときに team_id が実値で埋まる。
    #[test]
    fn placeholder_counts_as_present() {
        let value = BinaryPin {
            team_id: Some(Pinnable::Pin),
            signing_id: text("com.googlecode.iterm2"),
            ..empty()
        };
        assert_eq!(value.validate(), Ok(()));
        let all_pins = BinaryPin {
            team_id: Some(Pinnable::Pin),
            signing_id: Some(Pinnable::Pin),
            bundle_id: Some(Pinnable::Pin),
            ..empty()
        };
        assert_eq!(all_pins.validate(), Ok(()));
    }
}
