//! The verification of the code signature of a running process: the order of the checks, the classification of failures, and when to fall back to the signature the kernel keeps. The OS crate supplies the Security framework calls through [`SigningCalls`] and passes back their raw results; everything decided from them is here, in one place.

use std::time::Duration;

use crate::signature::{
    CdHash, Certificate, CertificateKind, CodeSigning, FailureReason, Root, RuntimeState, Signer,
    VerifiedFrom, VerifiedSignature,
};

/// The code signing requirements evaluated against a running process. The conditions on the kind of certificate are meaningful only together with `anchor apple generic` (a self-signed certificate can carry the same extension OIDs), so each of them includes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Requirement {
    AnchorApple,
    AnchorAppleGeneric,
    MacAppStore,
    DeveloperId,
    Development,
    Notarized,
}

impl Requirement {
    /// Every requirement. The OS crate compiles each the first time a check needs it, and keeps it for the rest of the collection.
    pub const ALL: [Requirement; 6] = [
        Requirement::AnchorApple,
        Requirement::AnchorAppleGeneric,
        Requirement::MacAppStore,
        Requirement::DeveloperId,
        Requirement::Development,
        Requirement::Notarized,
    ];

    /// The requirement in the requirement language.
    pub fn text(self) -> &'static str {
        match self {
            Requirement::AnchorApple => "anchor apple",
            Requirement::AnchorAppleGeneric => "anchor apple generic",
            Requirement::MacAppStore => {
                "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists"
            }
            Requirement::DeveloperId => {
                "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
            }
            Requirement::Development => {
                "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.12] exists"
            }
            Requirement::Notarized => "notarized",
        }
    }
}

/// `errSecCSReqFailed`: the code is valid and does not satisfy the requirement.
pub const REQUIREMENT_NOT_SATISFIED: i32 = -67050;
/// `errSecCSUnsigned`.
pub const UNSIGNED: i32 = -67062;
/// `errSecCSStaticCodeChanged`: the executable on disk is not what is running.
pub const CODE_CHANGED: i32 = -67034;
/// What the Security framework returns when the executable is gone (ENOENT in its POSIX error range; observed).
pub const FILE_MISSING: i32 = 100_002;
/// What the Security framework returns when the executable cannot be read (EACCES in its POSIX error range; observed for a running setuid `sudo` seen from the user).
pub const FILE_UNREADABLE: i32 = 100_013;

/// `kSecCodeSignatureLinkerSigned` (code directory flags).
const FLAG_LINKER_SIGNED: u32 = 0x2_0000;
/// `CS_RUNTIME` (dynamic status).
const STATUS_RUNTIME: u32 = 0x1_0000;
/// `kSecCodeStatusPlatform` (dynamic status).
const STATUS_PLATFORM: u32 = 0x0400_0000;
/// `kSecCodeStatusDebugged` (dynamic status).
const STATUS_DEBUGGED: u32 = 0x1000_0000;

/// How the code object of the process is looked up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lookup {
    /// The usual way: the signature of the executable on disk, tied to the running code.
    Usual,
    /// With `kSecGuestAttributeDynamicCode`: the signature the kernel keeps for the running code. Only used when the usual way fails with `FILE_UNREADABLE` or `CODE_CHANGED`.
    RunningCode,
}

/// What `SecCodeCopySigningInformation` (signing, requirement and dynamic information) reports, raw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SigningInfo {
    /// `kSecCodeInfoIdentifier`.
    pub identifier: Option<String>,
    /// `kSecCodeInfoUnique`, when it is a 20-byte cdhash.
    pub cdhash: Option<CdHash>,
    /// `kSecCodeInfoTeamIdentifier`.
    pub team_id: Option<String>,
    /// `kSecCodeInfoCertificates`, leaf first; empty without certificates.
    pub certificates: Vec<Certificate>,
    /// `kSecCodeInfoFlags`.
    pub flags: Option<u32>,
    /// `kSecCodeInfoStatus`.
    pub status: Option<u32>,
    /// `kSecCodeInfoEntitlementsDict`.
    pub entitlements: Option<serde_json::Map<String, serde_json::Value>>,
    /// `kSecCodeInfoEntitlements` (the entitlements blob) is present, whether or not it came in dictionary form too.
    pub entitlements_blob: bool,
    /// `CFBundleIdentifier` of `kSecCodeInfoPList`.
    pub bundle_id: Option<String>,
}

/// The Security framework calls the verification of one process needs, each returning the raw OSStatus. An implementation addresses one process (by audit token for a socket peer, by pid otherwise).
pub trait SigningCalls {
    type Code;
    /// `SecCodeCopyGuestWithAttributes` for the process, adding `kSecGuestAttributeDynamicCode` for `Lookup::RunningCode`.
    fn open(&self, lookup: Lookup) -> Result<Self::Code, i32>;
    /// `SecCodeCheckValidity` with `kSecCSNoNetworkAccess`, without a requirement (`None`) or with one. A requirement that failed to compile returns the status of its compilation.
    fn check(&self, code: &Self::Code, requirement: Option<Requirement>) -> i32;
    /// `SecCodeCopySigningInformation`.
    fn info(&self, code: &Self::Code) -> Result<SigningInfo, i32>;
}

/// The failure a status of the Security framework means: the executable replaced, gone, or anything else.
pub fn failure_reason(status: i32) -> FailureReason {
    match status {
        CODE_CHANGED => FailureReason::Replaced,
        FILE_MISSING => FailureReason::Missing,
        _ => FailureReason::Other,
    }
}

/// Verifies one running process.
///
/// 1. Look up the code and check it without a requirement. `UNSIGNED` from the check is `Unsigned`.
/// 2. When the lookup or the check fails with `FILE_UNREADABLE` or `CODE_CHANGED`, do both again on the signature the kernel keeps (`Lookup::RunningCode`) and go on with it; if that fails at any step, the result is `Failed`, classified by the status of the usual way. Any other failure is `Failed` by its own status.
/// 3. Read the signing information; without the identifier, the cdhash, the flags or the status, or with entitlements that are not in dictionary form, `Failed(Other)`.
/// 4. Without certificates the signer is ad-hoc. Otherwise the root is the first of `anchor apple` and `anchor apple generic` that holds; only under `anchor apple generic` the kind is the first of Mac App Store, Developer ID and development that holds, and only for Developer ID `notarized` is evaluated.
/// 5. A requirement check that neither holds (0) nor fails to hold (`REQUIREMENT_NOT_SATISFIED`) makes the result `Failed`, classified by its status.
pub fn verify<C: SigningCalls>(calls: &C) -> CodeSigning {
    match attempt(calls, Lookup::Usual) {
        Ok(signature) => CodeSigning::Verified(signature),
        Err(Stop::Unsigned) => CodeSigning::Unsigned,
        Err(Stop::Early(status)) if matches!(status, FILE_UNREADABLE | CODE_CHANGED) => {
            match attempt(calls, Lookup::RunningCode) {
                Ok(signature) => CodeSigning::Verified(signature),
                Err(_) => CodeSigning::Failed(failure_reason(status)),
            }
        }
        Err(Stop::Early(status) | Stop::Late(status)) => {
            CodeSigning::Failed(failure_reason(status))
        }
        Err(Stop::Incomplete) => CodeSigning::Failed(FailureReason::Other),
    }
}

/// Where one attempt stopped.
enum Stop {
    /// The check without a requirement said the code is not signed.
    Unsigned,
    /// The lookup or the check without a requirement failed with the status.
    Early(i32),
    /// A later step failed with the status.
    Late(i32),
    /// The signing information lacks an element the identity needs (`FailureReason::Other`); the call succeeded, so there is no status.
    Incomplete,
}

fn attempt<C: SigningCalls>(calls: &C, lookup: Lookup) -> Result<VerifiedSignature, Stop> {
    let code = calls.open(lookup).map_err(Stop::Early)?;
    match calls.check(&code, None) {
        0 => {}
        UNSIGNED => return Err(Stop::Unsigned),
        status => return Err(Stop::Early(status)),
    }
    let info = calls.info(&code).map_err(Stop::Late)?;
    let (Some(identifier), Some(cdhash), Some(flags), Some(status)) =
        (info.identifier, info.cdhash, info.flags, info.status)
    else {
        return Err(Stop::Incomplete);
    };
    if info.entitlements_blob && info.entitlements.is_none() {
        return Err(Stop::Incomplete);
    }
    let satisfies = |requirement| match calls.check(&code, Some(requirement)) {
        0 => Ok(true),
        REQUIREMENT_NOT_SATISFIED => Ok(false),
        status => Err(Stop::Late(status)),
    };
    let signer = if info.certificates.is_empty() {
        Signer::AdHoc {
            linker_signed: flags & FLAG_LINKER_SIGNED != 0,
        }
    } else {
        let root = if satisfies(Requirement::AnchorApple)? {
            Root::Apple {
                team_id: info.team_id,
            }
        } else if satisfies(Requirement::AnchorAppleGeneric)? {
            let kind = if satisfies(Requirement::MacAppStore)? {
                CertificateKind::MacAppStore
            } else if satisfies(Requirement::DeveloperId)? {
                CertificateKind::DeveloperId {
                    notarized: satisfies(Requirement::Notarized)?,
                }
            } else if satisfies(Requirement::Development)? {
                CertificateKind::Development
            } else {
                CertificateKind::Other
            };
            Root::AppleIssued {
                team_id: info.team_id,
                kind,
            }
        } else {
            Root::Other
        };
        Signer::Certificate {
            chain: info.certificates,
            root,
        }
    };
    Ok(VerifiedSignature {
        identifier,
        cdhash,
        signer,
        runtime: RuntimeState {
            hardened_runtime: status & STATUS_RUNTIME != 0,
            platform_binary: status & STATUS_PLATFORM != 0,
            debugged: status & STATUS_DEBUGGED != 0,
        },
        entitlements: info.entitlements,
        bundle_id: info.bundle_id,
        verified_from: match lookup {
            Lookup::Usual => VerifiedFrom::Disk,
            Lookup::RunningCode => VerifiedFrom::RunningCode,
        },
    })
}

/// Verifies the processes in order within the time budget of a collection. `elapsed` is the time since the first verification started; once it reaches `budget`, every process not yet verified is `NotChecked` (a verification under way is not cut short). Without a budget, every process is verified. A failure of one process does not affect the others.
pub fn verify_chain<C: SigningCalls>(
    processes: &[C],
    budget: Option<Duration>,
    mut elapsed: impl FnMut() -> Duration,
) -> Vec<CodeSigning> {
    processes
        .iter()
        .map(|calls| match budget {
            Some(budget) if elapsed() >= budget => CodeSigning::NotChecked,
            _ => verify(calls),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;
    use crate::signature::Mark;

    /// 偽の Security framework から見た 1 プロセス。通常の方法と pid ベース (RunningCode) で別の振る舞いを持たせられる。
    #[derive(Clone, Default)]
    struct FakeCode {
        /// open の失敗 (None は SecCode が得られる)。
        open: Option<i32>,
        /// requirement 無しの検証の戻り値。
        validity: i32,
        /// 署名の情報 (None は info が -67061 で失敗)。
        info: Option<SigningInfo>,
        /// 成立する requirement。
        satisfied: Vec<Requirement>,
        /// 成立・不成立の代わりにこの戻り値を返す requirement。
        broken: Option<(Requirement, i32)>,
    }

    #[derive(Default)]
    struct Fake {
        usual: FakeCode,
        running: FakeCode,
        asked: RefCell<Vec<(Lookup, Requirement)>>,
        opened: RefCell<Vec<Lookup>>,
    }

    impl SigningCalls for Fake {
        type Code = (Lookup, FakeCode);

        fn open(&self, lookup: Lookup) -> Result<Self::Code, i32> {
            self.opened.borrow_mut().push(lookup);
            let code = match lookup {
                Lookup::Usual => &self.usual,
                Lookup::RunningCode => &self.running,
            };
            match code.open {
                Some(status) => Err(status),
                None => Ok((lookup, code.clone())),
            }
        }

        fn check(&self, (lookup, code): &Self::Code, requirement: Option<Requirement>) -> i32 {
            let Some(requirement) = requirement else {
                return code.validity;
            };
            self.asked.borrow_mut().push((*lookup, requirement));
            match code.broken {
                Some((broken, status)) if broken == requirement => status,
                _ if code.satisfied.contains(&requirement) => 0,
                _ => REQUIREMENT_NOT_SATISFIED,
            }
        }

        fn info(&self, (_, code): &Self::Code) -> Result<SigningInfo, i32> {
            code.info.clone().ok_or(-67061)
        }
    }

    fn info(certificates: usize, flags: u32, status: u32) -> SigningInfo {
        SigningInfo {
            identifier: Some("com.example.tool".to_owned()),
            cdhash: Some(CdHash([0xd6; 20])),
            team_id: Some("ABCDE12345".to_owned()),
            certificates: (0..certificates)
                .map(|i| Certificate {
                    summary: Some(format!("certificate {i}")),
                    der: vec![u8::try_from(i).unwrap()],
                })
                .collect(),
            flags: Some(flags),
            status: Some(status),
            entitlements: None,
            entitlements_blob: false,
            bundle_id: Some("com.example.tool".to_owned()),
        }
    }

    fn signed(certificates: usize, satisfied: &[Requirement]) -> FakeCode {
        FakeCode {
            info: Some(info(certificates, 0, 0x1_0000)),
            satisfied: satisfied.to_vec(),
            ..FakeCode::default()
        }
    }

    fn usual(code: FakeCode) -> Fake {
        Fake {
            usual: code,
            running: FakeCode {
                open: Some(-1),
                ..FakeCode::default()
            },
            ..Fake::default()
        }
    }

    use Requirement::*;

    // 根は anchor apple → anchor apple generic の順で最初に成立したもの。種類は根が Apple の発行 (anchor apple generic だけ成立) の時だけ Mac App Store → Developer ID → 開発用の順で問い、notarized は Developer ID の時だけ問う。問い合わせた requirement の列まで確かめる: 余計な問い合わせは時間を使い、順序が違うと Mac App Store の中間を開発用と取り違える (TN3127 の開発用の条件は Mac App Store の中間も満たすので、開発用は leaf の OID で、Mac App Store より後に問う)。
    // 最後のケース: 自己署名の証明書は種類の OID も notarized も名乗れる (証明書の拡張は署名する側が書ける)。根が Apple でなければ種類を問い合わせず、other_certificate になる。
    #[test]
    fn requirements_are_evaluated_in_the_fixed_order() {
        let cases: [(&[Requirement], Mark, &[Requirement]); 7] = [
            (
                &[AnchorApple, AnchorAppleGeneric],
                Mark::Apple,
                &[AnchorApple],
            ),
            (
                &[AnchorAppleGeneric, MacAppStore, Development],
                Mark::MacAppStore,
                &[AnchorApple, AnchorAppleGeneric, MacAppStore],
            ),
            (
                &[AnchorAppleGeneric, DeveloperId, Notarized],
                Mark::DeveloperIdNotarized,
                &[
                    AnchorApple,
                    AnchorAppleGeneric,
                    MacAppStore,
                    DeveloperId,
                    Notarized,
                ],
            ),
            (
                &[AnchorAppleGeneric, DeveloperId],
                Mark::DeveloperId,
                &[
                    AnchorApple,
                    AnchorAppleGeneric,
                    MacAppStore,
                    DeveloperId,
                    Notarized,
                ],
            ),
            (
                &[AnchorAppleGeneric, Development, Notarized],
                Mark::Development,
                &[
                    AnchorApple,
                    AnchorAppleGeneric,
                    MacAppStore,
                    DeveloperId,
                    Development,
                ],
            ),
            (
                &[AnchorAppleGeneric],
                Mark::AppleIssuedOther,
                &[
                    AnchorApple,
                    AnchorAppleGeneric,
                    MacAppStore,
                    DeveloperId,
                    Development,
                ],
            ),
            (
                &[MacAppStore, DeveloperId, Development, Notarized],
                Mark::OtherCertificate,
                &[AnchorApple, AnchorAppleGeneric],
            ),
        ];
        for (satisfied, expected, asked) in cases {
            let calls = usual(signed(2, satisfied));
            assert_eq!(verify(&calls).mark(), expected, "{satisfied:?}");
            let asked_usual: Vec<Requirement> =
                calls.asked.borrow().iter().map(|(_, r)| *r).collect();
            assert_eq!(asked_usual, asked, "{satisfied:?}");
        }
    }

    // 証明書が無ければ ad-hoc で、requirement は 1 つも問い合わせない (ad-hoc には根が無い)。linker_signed は CodeDirectory の flags の kSecCodeSignatureLinkerSigned (0x20000) から取る。
    #[test]
    fn no_certificate_is_adhoc_without_asking_requirements() {
        for (flags, linker_signed) in [(0x2_0002, true), (0x2, false)] {
            let mut code = signed(0, &[AnchorApple, AnchorAppleGeneric]);
            code.info = Some(info(0, flags, 0));
            let calls = usual(code);
            let CodeSigning::Verified(signature) = verify(&calls) else {
                panic!("not verified")
            };
            assert_eq!(signature.signer, Signer::AdHoc { linker_signed });
            assert!(calls.asked.borrow().is_empty());
        }
    }

    // 要約の無い証明書 (subject が空の自己署名で、Security framework が要約を作れない) でも、根と種類は requirement だけで決まる。要約は表示専用で判定に使わない (署名する側が subject を自由に書ける)。Apple の根を満たさなければ other_certificate になり、要約は None のまま列に残る。
    #[test]
    fn a_certificate_without_summary_is_judged_by_requirements_only() {
        let mut code = signed(1, &[]);
        let mut signing_info = info(1, 0, 0);
        signing_info.certificates[0].summary = None;
        code.info = Some(signing_info);
        let result = verify(&usual(code));
        assert_eq!(result.mark(), Mark::OtherCertificate);
        let CodeSigning::Verified(signature) = result else {
            unreachable!()
        };
        let Signer::Certificate { chain, .. } = signature.signer else {
            panic!("not a certificate signer")
        };
        assert_eq!(chain[0].summary, None);
    }

    // 身元の値の出どころ: identifier・cdhash・証明書の連なり・Team ID・entitlements・bundle ID は署名の情報から、hardened runtime・platform binary・debugged はカーネルの動的な status から取る。CodeDirectory の flags の kSecCodeSignatureRuntime (0x10000) は hardened runtime に使わない (走っている sudo は flags に無く status にある、という観測があるため)。
    #[test]
    fn verified_elements_come_from_the_signing_information_and_status() {
        let mut entitlements = serde_json::Map::new();
        entitlements.insert(
            "com.apple.security.get-task-allow".to_owned(),
            serde_json::Value::Bool(true),
        );
        let mut code = signed(1, &[AnchorApple]);
        let mut signing_info = info(1, 0x1_0000, 0x0400_0000 | 0x1000_0000 | 0x1);
        signing_info.entitlements = Some(entitlements.clone());
        signing_info.entitlements_blob = true;
        code.info = Some(signing_info);
        let CodeSigning::Verified(signature) = verify(&usual(code)) else {
            panic!("not verified")
        };
        assert_eq!(
            signature,
            VerifiedSignature {
                identifier: "com.example.tool".to_owned(),
                cdhash: CdHash([0xd6; 20]),
                signer: Signer::Certificate {
                    chain: vec![Certificate {
                        summary: Some("certificate 0".to_owned()),
                        der: vec![0],
                    }],
                    root: Root::Apple {
                        team_id: Some("ABCDE12345".to_owned())
                    },
                },
                runtime: RuntimeState {
                    hardened_runtime: false,
                    platform_binary: true,
                    debugged: true,
                },
                entitlements: Some(entitlements),
                bundle_id: Some("com.example.tool".to_owned()),
                verified_from: VerifiedFrom::Disk,
            }
        );
        let CodeSigning::Verified(signature) = verify(&usual(signed(1, &[AnchorApple]))) else {
            panic!("not verified")
        };
        assert!(signature.runtime.hardened_runtime);
    }

    // 戻り値 → 理由の分類。-67034 (errSecCSStaticCodeChanged) は走っている間に実行ファイルが差し替えられた、100002 (ENOENT) は実行ファイルが消えた、それ以外 (ESRCH 100003、壊れた署名 -67061、更新された app bundle -67030、プロセスが無い -67065、確保の失敗など) は Other。
    #[test]
    fn failure_codes_are_classified() {
        assert_eq!(failure_reason(-67034), FailureReason::Replaced);
        assert_eq!(failure_reason(100_002), FailureReason::Missing);
        for status in [100_003, 100_013, -67061, -67030, -67065, -67062, 2, -1] {
            assert_eq!(failure_reason(status), FailureReason::Other, "{status}");
        }
    }

    // 通常の方法の失敗の扱い。requirement 無しの検証の -67062 は Unsigned。100013 (実行ファイルを読めない) と -67034 (差し替えられた) 以外の失敗は、pid ベースに切り替えずにその戻り値で分類する (説明の無い属性に頼る範囲を、通常の方法で読めない・食い違う時だけに絞るため)。実行ファイルが消えた (open が 100002) は pid ベースでも身元が取れない (観測) ので Missing のまま。
    #[test]
    fn usual_failures_without_fallback() {
        let cases = [
            (
                FakeCode {
                    validity: UNSIGNED,
                    ..FakeCode::default()
                },
                CodeSigning::Unsigned,
            ),
            (
                FakeCode {
                    open: Some(FILE_MISSING),
                    ..FakeCode::default()
                },
                CodeSigning::Failed(FailureReason::Missing),
            ),
            (
                FakeCode {
                    open: Some(-67065),
                    ..FakeCode::default()
                },
                CodeSigning::Failed(FailureReason::Other),
            ),
            (
                FakeCode {
                    validity: -67030,
                    ..FakeCode::default()
                },
                CodeSigning::Failed(FailureReason::Other),
            ),
        ];
        for (code, expected) in cases {
            let calls = Fake {
                usual: code,
                running: signed(0, &[]),
                ..Fake::default()
            };
            assert_eq!(verify(&calls), expected);
            assert_eq!(calls.opened.borrow().as_slice(), &[Lookup::Usual]);
        }
    }

    // 通常の方法が 100013 か -67034 で失敗した時だけ、カーネルが持つ署名 (pid ベース) で検証し直す。open で失敗しても requirement 無しの検証で失敗しても同じ。pid ベースで通れば、その結果 (verified_from は running_code) を使う。走っている setuid の sudo (読めない) と、単体の実行ファイルの差し替え (-67034) はこれで検証できる。
    #[test]
    fn unreadable_or_changed_falls_back_to_the_running_code() {
        let triggers = [
            FakeCode {
                open: Some(FILE_UNREADABLE),
                ..FakeCode::default()
            },
            FakeCode {
                validity: FILE_UNREADABLE,
                ..FakeCode::default()
            },
            FakeCode {
                validity: CODE_CHANGED,
                ..FakeCode::default()
            },
            FakeCode {
                open: Some(CODE_CHANGED),
                ..FakeCode::default()
            },
        ];
        for code in triggers {
            let calls = Fake {
                usual: code,
                running: signed(1, &[AnchorApple]),
                ..Fake::default()
            };
            let result = verify(&calls);
            assert_eq!(result.mark(), Mark::Apple);
            let CodeSigning::Verified(signature) = result else {
                unreachable!()
            };
            assert_eq!(signature.verified_from, VerifiedFrom::RunningCode);
            assert_eq!(
                calls.opened.borrow().as_slice(),
                &[Lookup::Usual, Lookup::RunningCode]
            );
            assert_eq!(
                calls.asked.borrow().as_slice(),
                &[(Lookup::RunningCode, AnchorApple)]
            );
        }
    }

    // pid ベースでもどこかの段で失敗したら Failed で、理由は通常の方法の戻り値で決める (-67034 なら Replaced、100013 なら Other)。pid ベースの戻り値 (削除された時の -67065 や 100002) で分類しない: 何が起きたかを表すのは通常の方法の失敗のほう。requirement 無しの検証が通っても署名の情報や requirement の評価で落ちる (実行ファイルの削除で観測) ので、後段の失敗も同じ扱い。
    #[test]
    fn running_code_failure_is_classified_by_the_usual_status() {
        let failing_running_codes = [
            FakeCode {
                open: Some(-67065),
                ..FakeCode::default()
            },
            FakeCode {
                validity: -67061,
                ..FakeCode::default()
            },
            FakeCode {
                info: None,
                ..signed(1, &[])
            },
            FakeCode {
                broken: Some((AnchorApple, -67065)),
                ..signed(1, &[])
            },
            FakeCode {
                validity: UNSIGNED,
                ..FakeCode::default()
            },
        ];
        for (usual_status, expected) in [
            (CODE_CHANGED, FailureReason::Replaced),
            (FILE_UNREADABLE, FailureReason::Other),
        ] {
            for running in failing_running_codes.clone() {
                let calls = Fake {
                    usual: FakeCode {
                        validity: usual_status,
                        ..FakeCode::default()
                    },
                    running,
                    ..Fake::default()
                };
                assert_eq!(verify(&calls), CodeSigning::Failed(expected));
            }
        }
    }

    // 検証は通っても、署名の情報が欠けていれば身元を作れないので Failed(Other)。identifier・cdhash・flags・status のどれか 1 つでも欠けたら、署名の情報そのものが取れなくても同じ。entitlements が dict の形で取れないのに blob はある時も Failed(Other): 保護を緩める entitlement の有無を確かめられないまま「無い」と言わないため。
    #[test]
    fn incomplete_signing_information_fails() {
        let mut incomplete: Vec<SigningInfo> = Vec::new();
        for drop in 0..4 {
            let mut i = info(1, 0, 0);
            match drop {
                0 => i.identifier = None,
                1 => i.cdhash = None,
                2 => i.flags = None,
                _ => i.status = None,
            }
            incomplete.push(i);
        }
        let mut blob_only = info(1, 0, 0);
        blob_only.entitlements_blob = true;
        incomplete.push(blob_only);
        for signing_info in incomplete {
            let code = FakeCode {
                info: Some(signing_info.clone()),
                ..signed(1, &[AnchorApple])
            };
            assert_eq!(
                verify(&usual(code)),
                CodeSigning::Failed(FailureReason::Other),
                "{signing_info:?}"
            );
        }
        let no_info = FakeCode {
            info: None,
            ..signed(1, &[AnchorApple])
        };
        assert_eq!(
            verify(&usual(no_info)),
            CodeSigning::Failed(FailureReason::Other)
        );
        let mut no_entitlements = info(1, 0, 0);
        no_entitlements.entitlements_blob = false;
        let code = FakeCode {
            info: Some(no_entitlements),
            ..signed(1, &[AnchorApple])
        };
        assert_eq!(verify(&usual(code)).mark(), Mark::Apple);
    }

    // requirement の評価が成立 (0) と不成立 (-67050) 以外を返したら、その戻り値で Failed に分類する (評価できなかったことを「満たさない」と読み替えない)。コンパイルに失敗した requirement も、その戻り値を返したものとして同じ扱い。どの段の requirement でも同じ。
    #[test]
    fn a_requirement_that_cannot_be_evaluated_fails() {
        let cases = [
            (AnchorApple, &[][..], -67034, FailureReason::Replaced),
            (AnchorAppleGeneric, &[][..], 100_002, FailureReason::Missing),
            (
                MacAppStore,
                &[AnchorAppleGeneric][..],
                -67065,
                FailureReason::Other,
            ),
            (
                Notarized,
                &[AnchorAppleGeneric, DeveloperId][..],
                -67052,
                FailureReason::Other,
            ),
        ];
        for (broken, satisfied, status, expected) in cases {
            let code = FakeCode {
                broken: Some((broken, status)),
                ..signed(1, satisfied)
            };
            let calls = usual(code);
            assert_eq!(verify(&calls), CodeSigning::Failed(expected), "{broken:?}");
            assert_eq!(calls.opened.borrow().as_slice(), &[Lookup::Usual]);
        }
    }

    // 収集の時間の予算: 予算に達した時点で、検証を始めていないプロセスは全部 NotChecked。始めた検証は途中で打ち切らない (1 回の Security framework の呼び出しは止められない)。時刻は注入し、3 つ目の検証の前に予算に達したものとして、先頭の 2 つだけが検証されることを見る。1 つの失敗は他に及ばない。予算が無ければ全部検証する。
    #[test]
    fn budget_stops_the_chain_and_failures_stay_local() {
        let processes = [
            usual(signed(1, &[AnchorApple])),
            usual(FakeCode {
                open: Some(FILE_MISSING),
                ..FakeCode::default()
            }),
            usual(signed(1, &[AnchorApple])),
            usual(signed(0, &[])),
        ];
        let ticks = Cell::new(0u64);
        let elapsed = || {
            let now = ticks.get();
            ticks.set(now + 1);
            Duration::from_millis(now * 400)
        };
        let results = verify_chain(&processes, Some(Duration::from_millis(800)), elapsed);
        assert_eq!(
            results.iter().map(CodeSigning::mark).collect::<Vec<_>>(),
            [
                Mark::Apple,
                Mark::Failed,
                Mark::NotChecked,
                Mark::NotChecked
            ]
        );
        assert!(processes[2].opened.borrow().is_empty());

        let unlimited = verify_chain(&processes, None, || Duration::from_secs(3600));
        assert_eq!(
            unlimited.iter().map(CodeSigning::mark).collect::<Vec<_>>(),
            [Mark::Apple, Mark::Failed, Mark::Apple, Mark::Adhoc]
        );
    }

    // requirement の文字列は固定: 種類の条件は全部 anchor apple generic と組 (OID の条件は Apple の根と組の時だけ意味を持つ)。Developer ID は中間の 6.2.6 と leaf の 6.1.13、Mac App Store は leaf の 6.1.9、開発用は leaf の 6.1.12。
    #[test]
    fn requirement_texts_are_fixed() {
        assert_eq!(AnchorApple.text(), "anchor apple");
        assert_eq!(AnchorAppleGeneric.text(), "anchor apple generic");
        assert_eq!(
            MacAppStore.text(),
            "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists"
        );
        assert_eq!(
            DeveloperId.text(),
            "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
        );
        assert_eq!(
            Development.text(),
            "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.12] exists"
        );
        assert_eq!(Notarized.text(), "notarized");
        for requirement in Requirement::ALL {
            if requirement != AnchorApple && requirement != Notarized {
                assert!(requirement.text().starts_with("anchor apple generic"));
            }
        }
    }
}
