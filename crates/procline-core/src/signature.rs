use std::fmt;

use serde::{Deserialize, Serialize};

/// The code signature of a running process as verified with code signing requirements. `ProcessInfo.code_signing` is `None` when the signature was not collected.
///
/// Only a verified signature carries an identity (identifier, cdhash, certificates, Team ID, bundle ID, entitlements): when the verification fails, what the Security framework reports may describe another file (the one that replaced the executable), not the running code.
///
/// JSON: the variant is `state` (`verified`, `failed`, `unsigned`, `not_checked`), beside the `mark` of `CodeSigning::mark`; a verified signature adds the fields of `VerifiedSignature`, a failed one `failure`. Reading the JSON decides the mark again from the facts and rejects a `mark` that differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "Wire", try_from = "Wire")]
pub enum CodeSigning {
    Verified(VerifiedSignature),
    Failed(FailureReason),
    Unsigned,
    /// Not verified, because the time budget of the collection ran out first.
    NotChecked,
}

impl CodeSigning {
    /// The trust mark: whose code the binary was verified to be. It says nothing about whether running it is safe (`zsh` and `sudo` are always `Apple`).
    ///
    /// The one place the mark is decided. Under Apple's own root it is `Apple`; under a certificate Apple issued, the kind of the certificate (`DeveloperIdNotarized`, `DeveloperId`, `MacAppStore`, `Development`, `AppleIssuedOther`); any other certificate is `OtherCertificate`, a signature without a certificate `Adhoc`, and the outcomes without an identity `Failed`, `Unsigned`, `NotChecked`. The hardened runtime and platform binary state are facts beside it and do not change it.
    pub fn mark(&self) -> Mark {
        match self {
            Self::NotChecked => Mark::NotChecked,
            Self::Unsigned => Mark::Unsigned,
            Self::Failed(_) => Mark::Failed,
            Self::Verified(signature) => match &signature.signer {
                Signer::AdHoc { .. } => Mark::Adhoc,
                Signer::Certificate { root, .. } => match root {
                    Root::Apple { .. } => Mark::Apple,
                    Root::Other => Mark::OtherCertificate,
                    Root::AppleIssued { kind, .. } => match kind {
                        CertificateKind::DeveloperId { notarized: true } => {
                            Mark::DeveloperIdNotarized
                        }
                        CertificateKind::DeveloperId { notarized: false } => Mark::DeveloperId,
                        CertificateKind::MacAppStore => Mark::MacAppStore,
                        CertificateKind::Development => Mark::Development,
                        CertificateKind::Other => Mark::AppleIssuedOther,
                    },
                },
            },
        }
    }
}

/// Why the verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    /// The executable was updated or replaced while the process ran.
    Replaced,
    /// The executable is gone.
    Missing,
    Other,
}

/// A signature that verified. The identity of the code is only here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignature {
    /// The signing identifier (`kSecCodeInfoIdentifier`).
    pub identifier: String,
    /// `kSecCodeInfoUnique` of the code that verified: the cdhash of the running code, which the Security framework compares with the kernel's while verifying.
    pub cdhash: CdHash,
    pub signer: Signer,
    /// From the kernel's dynamic status of the running code.
    pub runtime: RuntimeState,
    /// The entitlements sealed in the signature, in dictionary form.
    pub entitlements: Option<serde_json::Map<String, serde_json::Value>>,
    /// `CFBundleIdentifier` of the Info.plist sealed in the signature.
    pub bundle_id: Option<String>,
    pub verified_from: VerifiedFrom,
}

impl VerifiedSignature {
    /// The Team ID, only under Apple's roots (`Root::Apple`, `Root::AppleIssued`): the signer writes it into the code directory, so under any other root, and for an ad-hoc signature, it shows nothing and is `None`.
    pub fn team_id(&self) -> Option<&str> {
        match &self.signer {
            Signer::Certificate {
                root: Root::Apple { team_id } | Root::AppleIssued { team_id, .. },
                ..
            } => team_id.as_deref(),
            Signer::Certificate {
                root: Root::Other, ..
            }
            | Signer::AdHoc { .. } => None,
        }
    }

    /// The signing identifier; the value `binary`'s `signing_id` matches.
    pub fn signing_id(&self) -> &str {
        &self.identifier
    }

    /// The bundle identifier from the sealed Info.plist; the value `binary`'s `bundle_id` matches.
    pub fn bundle_id(&self) -> Option<&str> {
        self.bundle_id.as_deref()
    }

    /// The cdhash of the running code; the value `binary`'s `cdhash` matches.
    pub fn cdhash(&self) -> &CdHash {
        &self.cdhash
    }
}

/// Who signed the code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Signer {
    /// No certificate. `linker_signed`: the signature the linker adds (`kSecCodeSignatureLinkerSigned`).
    AdHoc { linker_signed: bool },
    /// The certificate chain, leaf first, and its root as the requirements decided it.
    Certificate { chain: Vec<Certificate>, root: Root },
}

/// Where the certificate chain ends, as the requirements decided it. The Team ID is kept only under Apple's roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Root {
    /// `anchor apple`: Apple's own code.
    Apple { team_id: Option<String> },
    /// `anchor apple generic` without `anchor apple`: a certificate Apple issued to a developer.
    AppleIssued {
        team_id: Option<String>,
        #[serde(rename = "certificate_kind")]
        kind: CertificateKind,
    },
    /// Neither: a self-signed certificate or another authority.
    Other,
}

/// The kind of a certificate Apple issued, from the extension OIDs together with `anchor apple generic`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CertificateKind {
    /// `notarized`: the requirement `notarized` holds, evaluated without the network.
    DeveloperId {
        notarized: bool,
    },
    MacAppStore,
    /// Apple Development.
    Development,
    Other,
}

/// The protection of the running code, from the kernel's dynamic status (`kSecCodeInfoStatus`), not the code directory flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeState {
    /// `CS_RUNTIME` (0x10000).
    pub hardened_runtime: bool,
    /// `kSecCodeStatusPlatform` (0x04000000).
    pub platform_binary: bool,
    /// `kSecCodeStatusDebugged` (0x10000000).
    pub debugged: bool,
}

/// What was verified: the executable on disk (the usual way), or the signature the kernel keeps for the running code (`kSecGuestAttributeDynamicCode`, used only when the usual way could not read the executable or found it changed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedFrom {
    Disk,
    RunningCode,
}

/// The trust mark (`CodeSigning::mark`). The words and colors are the application's; this is the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mark {
    Apple,
    DeveloperIdNotarized,
    DeveloperId,
    MacAppStore,
    Development,
    AppleIssuedOther,
    OtherCertificate,
    Adhoc,
    Failed,
    Unsigned,
    NotChecked,
}

/// The JSON form of `CodeSigning`: the shape of the type with its mark beside it.
///
/// Design rationale: the variant's fields are listed here instead of flattening `VerifiedSignature`, since serde cannot reject unknown keys of a flattened struct, and an unknown key in a signature is rejected rather than dropped.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Wire {
    Verified {
        mark: Mark,
        identifier: String,
        cdhash: CdHash,
        signer: Signer,
        runtime: RuntimeState,
        entitlements: Option<serde_json::Map<String, serde_json::Value>>,
        bundle_id: Option<String>,
        verified_from: VerifiedFrom,
    },
    Failed {
        mark: Mark,
        failure: FailureReason,
    },
    Unsigned {
        mark: Mark,
    },
    NotChecked {
        mark: Mark,
    },
}

impl From<CodeSigning> for Wire {
    fn from(signing: CodeSigning) -> Self {
        let mark = signing.mark();
        match signing {
            CodeSigning::Verified(VerifiedSignature {
                identifier,
                cdhash,
                signer,
                runtime,
                entitlements,
                bundle_id,
                verified_from,
            }) => Self::Verified {
                mark,
                identifier,
                cdhash,
                signer,
                runtime,
                entitlements,
                bundle_id,
                verified_from,
            },
            CodeSigning::Failed(failure) => Self::Failed { mark, failure },
            CodeSigning::Unsigned => Self::Unsigned { mark },
            CodeSigning::NotChecked => Self::NotChecked { mark },
        }
    }
}

impl TryFrom<Wire> for CodeSigning {
    type Error = MarkMismatch;

    fn try_from(wire: Wire) -> Result<Self, Self::Error> {
        let (written, signing) = match wire {
            Wire::Verified {
                mark,
                identifier,
                cdhash,
                signer,
                runtime,
                entitlements,
                bundle_id,
                verified_from,
            } => (
                mark,
                Self::Verified(VerifiedSignature {
                    identifier,
                    cdhash,
                    signer,
                    runtime,
                    entitlements,
                    bundle_id,
                    verified_from,
                }),
            ),
            Wire::Failed { mark, failure } => (mark, Self::Failed(failure)),
            Wire::Unsigned { mark } => (mark, Self::Unsigned),
            Wire::NotChecked { mark } => (mark, Self::NotChecked),
        };
        let decided = signing.mark();
        if written == decided {
            Ok(signing)
        } else {
            Err(MarkMismatch { written, decided })
        }
    }
}

/// The `mark` of a `code_signing` in JSON is not the one its facts decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkMismatch {
    pub written: Mark,
    pub decided: Mark,
}

impl fmt::Display for MarkMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the mark {:?} does not follow from the signature, which gives {:?}",
            self.written, self.decided
        )
    }
}

impl std::error::Error for MarkMismatch {}

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

/// One certificate of the signer chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub summary: String,
    /// DER bytes; JSON carries them as base64url without padding.
    #[serde(with = "base64url")]
    pub der: Vec<u8>,
}

/// serde adapter: `Vec<u8>` as a base64url (no padding) string, the form every byte string in the JSON takes.
mod base64url {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD.decode(s).map_err(serde::de::Error::custom)
    }
}

/// App bundle found by walking up from the executable path. For display only; matching uses `VerifiedSignature.bundle_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub id: Option<String>,
    pub version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// 検証に成功した署名。印は signer だけで決まるので、他の field は固定にしておき、各ケースは signer だけを変える。
    fn verified(signer: Signer) -> CodeSigning {
        CodeSigning::Verified(VerifiedSignature {
            identifier: "com.example.tool".to_owned(),
            cdhash: CdHash([0x36; 20]),
            signer,
            runtime: RuntimeState {
                hardened_runtime: true,
                platform_binary: false,
                debugged: false,
            },
            entitlements: None,
            bundle_id: None,
            verified_from: VerifiedFrom::Disk,
        })
    }

    fn certificate(root: Root) -> CodeSigning {
        verified(Signer::Certificate {
            chain: vec![Certificate {
                summary: "Developer ID Application: Example (ABCDE12345)".to_owned(),
                der: vec![0x30, 0x82],
            }],
            root,
        })
    }

    fn issued(kind: CertificateKind) -> CodeSigning {
        certificate(Root::AppleIssued {
            team_id: Some("ABCDE12345".to_owned()),
            kind,
        })
    }

    // 印の表の全 11 行。1 行に 1 つの事実の組を置き、その印と JSON の値 (snake_case) を確かめる。印は「このバイナリが誰のものと確かめられたか」だけで決まる: 根が Apple 自身なら apple、Apple が発行した証明書なら種類 (Developer ID は公証の有無で 2 つ)、それ以外の証明書は other_certificate、証明書が無ければ adhoc、身元の無い 3 つの結果はそれぞれ failed / unsigned / not_checked。
    #[test]
    fn every_row_of_the_mark_table() {
        let rows = [
            (
                certificate(Root::Apple { team_id: None }),
                Mark::Apple,
                "apple",
            ),
            (
                issued(CertificateKind::DeveloperId { notarized: true }),
                Mark::DeveloperIdNotarized,
                "developer_id_notarized",
            ),
            (
                issued(CertificateKind::DeveloperId { notarized: false }),
                Mark::DeveloperId,
                "developer_id",
            ),
            (
                issued(CertificateKind::MacAppStore),
                Mark::MacAppStore,
                "mac_app_store",
            ),
            (
                issued(CertificateKind::Development),
                Mark::Development,
                "development",
            ),
            (
                issued(CertificateKind::Other),
                Mark::AppleIssuedOther,
                "apple_issued_other",
            ),
            (
                certificate(Root::Other),
                Mark::OtherCertificate,
                "other_certificate",
            ),
            (
                verified(Signer::AdHoc {
                    linker_signed: true,
                }),
                Mark::Adhoc,
                "adhoc",
            ),
            (
                CodeSigning::Failed(FailureReason::Replaced),
                Mark::Failed,
                "failed",
            ),
            (CodeSigning::Unsigned, Mark::Unsigned, "unsigned"),
            (CodeSigning::NotChecked, Mark::NotChecked, "not_checked"),
        ];
        assert_eq!(rows.len(), 11);
        for (signing, expected, wire) in rows {
            assert_eq!(signing.mark(), expected, "{signing:?}");
            assert_eq!(serde_json::to_value(expected).unwrap(), wire);
            assert_eq!(serde_json::to_value(&signing).unwrap()["mark"], wire);
        }
    }

    // 印は hardened runtime や platform binary に左右されない (色を付けない事実として別に出す)。保護の無い Apple のコードも、debugged なものも、根が Apple 自身なら apple のまま。
    #[test]
    fn runtime_state_does_not_change_the_mark() {
        for runtime in [
            RuntimeState {
                hardened_runtime: false,
                platform_binary: false,
                debugged: true,
            },
            RuntimeState {
                hardened_runtime: true,
                platform_binary: true,
                debugged: false,
            },
        ] {
            let CodeSigning::Verified(mut signature) = certificate(Root::Apple { team_id: None })
            else {
                unreachable!()
            };
            signature.runtime = runtime;
            assert_eq!(CodeSigning::Verified(signature).mark(), Mark::Apple);
        }
    }

    // Team ID は署名する側が CodeDirectory に書く値なので、根が Apple (自身か発行) の時だけ照合元になる。自己署名・独自の認証局 (根が Other) と ad-hoc は、Team ID を名乗っていても None。signing_id / bundle_id / cdhash は検証に成功した署名なら常に取れる。
    #[test]
    fn team_id_only_under_apple_roots() {
        let team = |signing: CodeSigning| match signing {
            CodeSigning::Verified(signature) => signature.team_id().map(str::to_owned),
            other => panic!("not verified: {other:?}"),
        };
        assert_eq!(
            team(certificate(Root::Apple {
                team_id: Some("59GAB85EFG".to_owned())
            })),
            Some("59GAB85EFG".to_owned())
        );
        assert_eq!(
            team(issued(CertificateKind::Development)),
            Some("ABCDE12345".to_owned())
        );
        assert_eq!(team(certificate(Root::Other)), None);
        assert_eq!(
            team(verified(Signer::AdHoc {
                linker_signed: false
            })),
            None
        );
        let CodeSigning::Verified(signature) = issued(CertificateKind::MacAppStore) else {
            unreachable!()
        };
        assert_eq!(signature.signing_id(), "com.example.tool");
        assert_eq!(signature.cdhash(), &CdHash([0x36; 20]));
        assert_eq!(signature.bundle_id(), None);
    }

    // JSON は型の形をそのまま写す: state で分け、その state に当てはまらない要素はキーごと無い。Option の値 (entitlements、bundle_id、team_id) は null で書く。バイト列は base64url (padding なし)、enum の値は snake_case。
    #[test]
    fn json_follows_the_shape_of_the_type() {
        let mut entitlements = serde_json::Map::new();
        entitlements.insert(
            "com.apple.security.app-sandbox".to_owned(),
            serde_json::Value::Bool(true),
        );
        let signing = CodeSigning::Verified(VerifiedSignature {
            identifier: "com.example.app".to_owned(),
            cdhash: CdHash([0x36; 20]),
            signer: Signer::Certificate {
                chain: vec![Certificate {
                    summary: "Developer ID Application: Example (ABCDE12345)".to_owned(),
                    der: vec![0xfb, 0xff],
                }],
                root: Root::AppleIssued {
                    team_id: Some("ABCDE12345".to_owned()),
                    kind: CertificateKind::DeveloperId { notarized: true },
                },
            },
            runtime: RuntimeState {
                hardened_runtime: true,
                platform_binary: false,
                debugged: false,
            },
            entitlements: Some(entitlements),
            bundle_id: Some("com.example.app".to_owned()),
            verified_from: VerifiedFrom::RunningCode,
        });
        assert_eq!(
            serde_json::to_value(&signing).unwrap(),
            serde_json::json!({
                "state": "verified", "mark": "developer_id_notarized",
                "identifier": "com.example.app", "cdhash": "36".repeat(20),
                "signer": {"kind": "certificate",
                           "chain": [{"summary": "Developer ID Application: Example (ABCDE12345)", "der": "-_8"}],
                           "root": {"kind": "apple_issued", "team_id": "ABCDE12345",
                                    "certificate_kind": {"kind": "developer_id", "notarized": true}}},
                "runtime": {"hardened_runtime": true, "platform_binary": false, "debugged": false},
                "entitlements": {"com.apple.security.app-sandbox": true},
                "bundle_id": "com.example.app",
                "verified_from": "running_code"
            })
        );
        assert_eq!(
            serde_json::to_value(verified(Signer::AdHoc {
                linker_signed: true
            }))
            .unwrap()["signer"],
            serde_json::json!({"kind": "ad_hoc", "linker_signed": true})
        );
        assert_eq!(
            serde_json::to_value(certificate(Root::Other)).unwrap()["signer"]["root"],
            serde_json::json!({"kind": "other"})
        );
        assert_eq!(
            serde_json::to_value(certificate(Root::Apple { team_id: None })).unwrap()["signer"]["root"],
            serde_json::json!({"kind": "apple", "team_id": null})
        );
        assert_eq!(
            serde_json::to_value(issued(CertificateKind::MacAppStore)).unwrap()["signer"]["root"]["certificate_kind"],
            serde_json::json!({"kind": "mac_app_store"})
        );
        assert_eq!(
            serde_json::to_value(CodeSigning::Failed(FailureReason::Replaced)).unwrap(),
            serde_json::json!({"state": "failed", "mark": "failed", "failure": "replaced"})
        );
        assert_eq!(
            serde_json::to_value(CodeSigning::Unsigned).unwrap(),
            serde_json::json!({"state": "unsigned", "mark": "unsigned"})
        );
        assert_eq!(
            serde_json::to_value(CodeSigning::NotChecked).unwrap(),
            serde_json::json!({"state": "not_checked", "mark": "not_checked"})
        );
        let back: CodeSigning =
            serde_json::from_value(serde_json::to_value(&signing).unwrap()).unwrap();
        assert_eq!(back, signing);
    }

    // 書き出した JSON を読むと元の値に戻る (全 state、全 signer / root / 種類)。保存した収集結果を読み直しても事実が変わらないこと。
    #[test]
    fn json_round_trips_every_shape() {
        let shapes = [
            certificate(Root::Apple {
                team_id: Some("59GAB85EFG".to_owned()),
            }),
            issued(CertificateKind::DeveloperId { notarized: false }),
            issued(CertificateKind::Development),
            issued(CertificateKind::Other),
            certificate(Root::Other),
            verified(Signer::AdHoc {
                linker_signed: false,
            }),
            CodeSigning::Failed(FailureReason::Missing),
            CodeSigning::Failed(FailureReason::Other),
            CodeSigning::Unsigned,
            CodeSigning::NotChecked,
        ];
        for signing in shapes {
            let json = serde_json::to_string(&signing).unwrap();
            let back: CodeSigning = serde_json::from_str(&json).unwrap();
            assert_eq!(back, signing, "{json}");
        }
    }

    // 読み込みは印を事実から決め直し、書かれた印と違えばエラーにする。印は表示の元なので、JSON を書き換えて ad-hoc の署名に apple の印を付けても、そのまま通さない。印が無い JSON も、未知のキーを持つ JSON も読まない (黙って補ったり捨てたりしない)。
    #[test]
    fn reading_rejects_a_mark_the_facts_do_not_give() {
        let mut json = serde_json::to_value(verified(Signer::AdHoc {
            linker_signed: true,
        }))
        .unwrap();
        json["mark"] = serde_json::json!("apple");
        let err = serde_json::from_value::<CodeSigning>(json).unwrap_err();
        assert!(err.to_string().contains("Adhoc"), "{err}");

        let mismatched = serde_json::json!({"state": "unsigned", "mark": "not_checked"});
        assert!(serde_json::from_value::<CodeSigning>(mismatched).is_err());

        let without_mark = serde_json::json!({"state": "failed", "failure": "missing"});
        assert!(serde_json::from_value::<CodeSigning>(without_mark).is_err());

        let unknown_key =
            serde_json::json!({"state": "unsigned", "mark": "unsigned", "team_id": "X"});
        assert!(serde_json::from_value::<CodeSigning>(unknown_key).is_err());

        let mut identity_on_failure =
            serde_json::to_value(CodeSigning::Failed(FailureReason::Replaced)).unwrap();
        identity_on_failure["identifier"] = serde_json::json!("com.example.tool");
        assert!(serde_json::from_value::<CodeSigning>(identity_on_failure).is_err());
    }
}
