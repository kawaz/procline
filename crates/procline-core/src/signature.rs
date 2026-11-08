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

/// Code directory hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CdHash(pub [u8; 20]);

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
    Notarized,
    DeveloperId,
    AdHoc,
    Unsigned,
    Invalid,
}

/// App bundle found by walking up from the executable path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub id: Option<String>,
    pub version: Option<String>,
}
