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
    ///
    /// Decided in this order: unsigned, invalid, ad-hoc, not anchored at Apple, platform binary, then the kind of the leaf certificate.
    ///
    /// Every level above `AdHoc` needs `apple_anchored == Some(true)`: without it the platform mark and the certificate names are whatever the signer wrote, so a signature that is valid but not shown to chain to an Apple root is `Unknown`.
    ///
    /// The kind of the leaf certificate of an Apple-anchored chain is provisionally told from its subject summary: `Apple Mac OS Application Signing` is App Store, `Developer ID Application: …` is Developer ID (notarized when `notarized` is `Some(true)`). Any other Apple-issued leaf (`Apple Development: …`, `Apple Distribution: …`) falls back to `DeveloperId`, the weakest Apple-anchored level, so it is shown with a warning. Telling the kind from the certificate extension OIDs replaces the summary match.
    pub fn trust(&self) -> SignatureTrust {
        let signature = match self {
            Self::Unsigned => return SignatureTrust::Unsigned,
            Self::Signed(signature) => signature,
        };
        if let SignatureValidity::Invalid { .. } = signature.validity {
            return SignatureTrust::Invalid;
        }
        if signature.adhoc {
            return SignatureTrust::AdHoc;
        }
        if signature.apple_anchored != Some(true) {
            return SignatureTrust::Unknown;
        }
        if signature.platform {
            return SignatureTrust::Platform;
        }
        let leaf = signature
            .certificates
            .first()
            .map_or("", |cert| cert.summary.as_str());
        if leaf == APP_STORE_LEAF {
            return SignatureTrust::AppStore;
        }
        if leaf.starts_with(DEVELOPER_ID_LEAF_PREFIX) && signature.notarized == Some(true) {
            return SignatureTrust::Notarized;
        }
        SignatureTrust::DeveloperId
    }
}

/// Subject summary of the leaf certificate of App Store apps.
const APP_STORE_LEAF: &str = "Apple Mac OS Application Signing";

/// Prefix of the subject summary of a Developer ID application certificate (`Developer ID Application: <name> (<team>)`).
const DEVELOPER_ID_LEAF_PREFIX: &str = "Developer ID Application: ";

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
    /// Result of evaluating the requirement `anchor apple generic` with `SecCodeCheckValidity`: the certificate chain ends at an Apple root. `None` when it could not be evaluated.
    pub apple_anchored: Option<bool>,
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

    use super::{Certificate, CodeSigning, Signature, SignatureTrust, SignatureValidity};

    /// 検証に通り Apple のルートに連鎖する、どの区分にも当たらない署名 (platform でも ad-hoc でもなく、証明書なし)。各ケースはここから 1 項目だけ変えて境界を見る。
    fn signed(leaf: Option<&str>) -> Signature {
        Signature {
            validity: SignatureValidity::Valid,
            signing_id: Some("com.example.tool".to_owned()),
            team_id: Some("TEAMID1234".to_owned()),
            bundle_id: None,
            cdhash: None,
            certificates: leaf
                .map(|summary| Certificate {
                    summary: summary.to_owned(),
                    der: Vec::new(),
                })
                .into_iter()
                .collect(),
            adhoc: false,
            hardened_runtime: true,
            platform: false,
            entitlements: None,
            notarized: None,
            apple_anchored: Some(true),
        }
    }

    fn trust(signature: Signature) -> SignatureTrust {
        CodeSigning::Signed(signature).trust()
    }

    // 署名が無いプロセスは他のどの属性も持たないので Unsigned (画面の ⛔ 署名なし)。
    #[test]
    fn unsigned_is_unsigned() {
        assert_eq!(CodeSigning::Unsigned.trust(), SignatureTrust::Unsigned);
    }

    // 検証に失敗した署名は、platform や App Store の印を持っていても Invalid。壊れた署名の field は信用できないので、他の判定より先に見る。
    #[test]
    fn invalid_wins_over_every_other_mark() {
        let mut s = signed(Some("Apple Mac OS Application Signing"));
        s.platform = true;
        s.validity = SignatureValidity::Invalid {
            reason: "a sealed resource is missing or invalid".to_owned(),
        };
        assert_eq!(trust(s), SignatureTrust::Invalid);
    }

    // platform binary は Apple が OS に入れたコードなので、証明書の名前に関係なく Platform (警告なし)。
    #[test]
    fn platform_binary_is_platform() {
        let mut s = signed(Some("Software Signing"));
        s.platform = true;
        assert_eq!(trust(s), SignatureTrust::Platform);
    }

    // ad-hoc 署名は署名者を持たないので AdHoc。リンカが自動で付ける署名もこれに当たる。Apple への連鎖は ad-hoc には無いので、apple_anchored が false でも AdHoc のまま (Unknown にしない)。platform の印が付いていても AdHoc: 印は署名者が書けるもので、OS の platform binary は ad-hoc で署名されていない (macOS 26.5.2 の /bin、/usr/bin、/usr/libexec、/sbin、/usr/sbin の platform binary 1344 本に ad-hoc は 0 本)。
    #[test]
    fn adhoc_is_adhoc() {
        let mut s = signed(None);
        s.adhoc = true;
        s.apple_anchored = Some(false);
        assert_eq!(trust(s.clone()), SignatureTrust::AdHoc);
        s.platform = true;
        assert_eq!(trust(s), SignatureTrust::AdHoc);
    }

    // Apple のルートへの連鎖が確かめられない署名は、platform の印や証明書の名前があっても Unknown。印も名前も署名者が自由に書けるので、連鎖が確かめられて初めて Platform / AppStore / DeveloperId / Notarized を名乗れる。連鎖しない (false) ときも、評価できなかった (None) ときも同じ扱い。
    #[test]
    fn unanchored_signature_is_unknown() {
        for anchored in [Some(false), None] {
            let mut s = signed(Some("Developer ID Application: Example Inc. (TEAMID1234)"));
            s.notarized = Some(true);
            s.apple_anchored = anchored;
            assert_eq!(trust(s), SignatureTrust::Unknown, "{anchored:?}");
            let mut s = signed(Some("Apple Mac OS Application Signing"));
            s.platform = true;
            s.apple_anchored = anchored;
            assert_eq!(trust(s), SignatureTrust::Unknown, "{anchored:?}");
        }
    }

    // App Store 配布のアプリは leaf が "Apple Mac OS Application Signing" で、公証チケットを持たなくても AppStore (警告なし)。
    #[test]
    fn app_store_leaf_is_app_store() {
        assert_eq!(
            trust(signed(Some("Apple Mac OS Application Signing"))),
            SignatureTrust::AppStore
        );
    }

    // Developer ID の署名は、公証が確かめられたときだけ Notarized。公証が否定された (false) ときと、確かめていない (None) ときは DeveloperId (⚠️ 未公証) に倒す。
    #[test]
    fn developer_id_is_notarized_only_when_confirmed() {
        let leaf = Some("Developer ID Application: Example Inc. (TEAMID1234)");
        let mut s = signed(leaf);
        s.notarized = Some(true);
        assert_eq!(trust(s), SignatureTrust::Notarized);
        let mut s = signed(leaf);
        s.notarized = Some(false);
        assert_eq!(trust(s), SignatureTrust::DeveloperId);
        assert_eq!(trust(signed(leaf)), SignatureTrust::DeveloperId);
    }

    // Apple に連鎖するが Developer ID でない leaf (開発用の "Apple Development"、名前の無い証明書) は、公証済みと記録されていても Notarized にしない。公証は Developer ID 配布の仕組みなので、他の証明書では信頼度を上げる根拠にならない。
    #[test]
    fn other_leaf_falls_back_to_developer_id() {
        let mut s = signed(Some("Apple Development: someone@example.com (ABCDE12345)"));
        s.notarized = Some(true);
        assert_eq!(trust(s), SignatureTrust::DeveloperId);
        assert_eq!(trust(signed(None)), SignatureTrust::DeveloperId);
    }

    // leaf の名前は前方一致でなく区分の名前そのもので見る。"Apple Mac OS Application Signing" で始まる別の名前を App Store にしない。
    #[test]
    fn app_store_leaf_must_match_exactly() {
        assert_eq!(
            trust(signed(Some("Apple Mac OS Application Signing (fake)"))),
            SignatureTrust::DeveloperId
        );
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
    /// Validly signed, but the chain is not shown to end at an Apple root (a self-made or third-party certificate, or the anchor could not be evaluated). Shown with a warning.
    Unknown,
    Unsigned,
    Invalid,
}

/// App bundle found by walking up from the executable path. For display only; matching uses `Signature.bundle_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub id: Option<String>,
    pub version: Option<String>,
}
