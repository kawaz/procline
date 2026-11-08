use std::fmt;

use serde::{Deserialize, Serialize};

/// Whether the executable is signed at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeSigning {
    Unsigned,
    Signed(Signature),
}

impl CodeSigning {
    /// Trust level shown next to the icon and name.
    pub fn trust(&self) -> SignatureTrust {
        todo!()
    }
}

/// Code signature of the executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub validity: SignatureValidity,
    pub signing_id: Option<String>,
    pub team_id: Option<String>,
    /// The bundle identifier from the sealed Info.plist (`kSecCodeInfoPList`); `binary`'s `bundle_id` matches against it.
    pub bundle_id: Option<String>,
    pub cdhash: Option<CdHash>,
    /// Signer certificate chain, leaf first.
    pub certificates: Vec<Certificate>,
    pub adhoc: bool,
    pub hardened_runtime: bool,
    pub platform: bool,
    pub entitlements: Option<serde_json::Map<String, serde_json::Value>>,
    /// `None` when notarization could not be determined.
    pub notarized: Option<bool>,
}

/// Result of validating the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureValidity {
    Valid,
    Invalid { reason: String },
}

/// Code directory hash. Serialized as a lowercase hex string (the form `codesign -dvvv` prints).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CdHash(pub [u8; 20]);

impl fmt::Display for CdHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for CdHash {
    type Err = CdHashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 40 {
            return Err(CdHashParseError {
                input: s.to_owned(),
            });
        }
        let mut bytes = [0u8; 20];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(chunk).map_err(|_| CdHashParseError {
                input: s.to_owned(),
            })?;
            bytes[i] = u8::from_str_radix(pair, 16).map_err(|_| CdHashParseError {
                input: s.to_owned(),
            })?;
        }
        Ok(Self(bytes))
    }
}

/// A cdhash string is not 40 hex digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdHashParseError {
    pub input: String,
}

impl fmt::Display for CdHashParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cdhash {:?} is not 40 hex digits", self.input)
    }
}

impl std::error::Error for CdHashParseError {}

impl Serialize for CdHash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for CdHash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::CdHash;

    // JSON の形は hex 文字列 (DESIGN の binary の値の形)。往復で元に戻ることが `cdhash` を手で書ける前提。
    #[test]
    fn cdhash_round_trips_as_hex_string() {
        let hash = CdHash([
            0x01, 0xab, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x7e,
        ]);
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, "\"01abff000000000000000000000000000000007e\"");
        let back: CdHash = serde_json::from_str(&json).unwrap();
        assert_eq!(back, hash);
    }

    // 長さや文字が違う入力はエラーにし、黙って別の値に丸めない。
    #[test]
    fn cdhash_rejects_non_hex_or_wrong_length() {
        assert!(serde_json::from_str::<CdHash>("\"01ab\"").is_err());
        assert!(serde_json::from_str::<CdHash>(&format!("\"{}\"", "zz".repeat(20))).is_err());
    }
}

/// One certificate of the signer chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    pub summary: String,
    pub der: Vec<u8>,
}

/// Trust level derived from the code signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureTrust {
    Platform,
    /// Distributed through the App Store: signed by Apple, without a notarization ticket. Shown without a warning.
    AppStore,
    Notarized,
    DeveloperId,
    AdHoc,
    Unsigned,
    Invalid,
}

/// App bundle found by walking up from the executable path. For display only; matching uses `Signature.bundle_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub id: Option<String>,
    pub version: Option<String>,
}
