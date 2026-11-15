//! The code signature of running processes: the Security framework calls `procline_core::verify` needs, for one process each.

use std::time::{Duration, Instant};

use procline_core::verify::{self, Lookup, Requirement, SigningCalls, SigningInfo};
use procline_core::{CdHash, Certificate, CodeSigning};
use security_framework::os::macos::code_signing::{SecCode, SecRequirement};

use crate::sys::security::{self, Guest};

/// Every requirement of `Requirement::ALL`, compiled once per collection. A requirement that failed to compile keeps the status of its compilation, which its checks return.
struct Requirements(Vec<(Requirement, Result<SecRequirement, i32>)>);

impl Requirements {
    fn compile() -> Self {
        Self(
            Requirement::ALL
                .into_iter()
                .map(|requirement| (requirement, security::requirement(requirement.text())))
                .collect(),
        )
    }

    fn get(&self, requirement: Requirement) -> Result<&SecRequirement, i32> {
        self.0
            .iter()
            .find(|(r, _)| *r == requirement)
            .map_or(Err(-1), |(_, compiled)| compiled.as_ref().map_err(|s| *s))
    }
}

/// The calls for one process.
struct Calls<'a> {
    guest: Guest,
    requirements: &'a Requirements,
}

impl SigningCalls for Calls<'_> {
    type Code = SecCode;

    fn open(&self, lookup: Lookup) -> Result<SecCode, i32> {
        security::guest(self.guest, lookup == Lookup::RunningCode)
    }

    fn check(&self, code: &SecCode, requirement: Option<Requirement>) -> i32 {
        match requirement {
            None => security::check(code, None),
            Some(requirement) => match self.requirements.get(requirement) {
                Ok(compiled) => security::check(code, Some(compiled)),
                Err(status) => status,
            },
        }
    }

    fn info(&self, code: &SecCode) -> Result<SigningInfo, i32> {
        let info = security::signing_information(code)?;
        Ok(SigningInfo {
            identifier: info.identifier(),
            cdhash: info
                .unique()
                .and_then(|bytes| <[u8; 20]>::try_from(bytes.as_slice()).ok())
                .map(CdHash),
            team_id: info.team_identifier(),
            certificates: info
                .certificates()
                .into_iter()
                .map(|(summary, der)| Certificate { summary, der })
                .collect(),
            flags: info.flags(),
            status: info.status(),
            entitlements: info.entitlements(),
            entitlements_blob: info.has_entitlements_blob(),
            bundle_id: info.plist_string("CFBundleIdentifier"),
        })
    }
}

/// Verifies the processes in order, with the requirements compiled once. With a `budget`, the processes not yet verified when it runs out (measured from the start of this call) are `NotChecked`.
pub(crate) fn verify_chain(guests: &[Guest], budget: Option<Duration>) -> Vec<CodeSigning> {
    let started = Instant::now();
    let requirements = Requirements::compile();
    let calls: Vec<Calls<'_>> = guests
        .iter()
        .map(|&guest| Calls {
            guest,
            requirements: &requirements,
        })
        .collect();
    verify::verify_chain(&calls, budget, || started.elapsed())
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, Stdio};

    use procline_core::verify::{Lookup, Requirement, SigningCalls, SigningInfo};
    use procline_core::{CodeSigning, VerifiedFrom};
    use security_framework::os::macos::code_signing::SecCode;

    use super::{Calls, Requirements};
    use crate::sys::security::Guest;

    /// Set in the environment of a copy of this test binary that `wait_helper` keeps running.
    const WAIT: &str = "PROCLINE_SIGNING_TEST_WAIT";

    // 単独のテストではない: 下のテストがこのテストのバイナリのコピーを子として起こす時 (WAIT を渡す)、ready を出してから標準入力が閉じるまで生き続ける役をする。普通に cargo test で走った時は何もせずに終わる。
    #[test]
    fn wait_helper() {
        if std::env::var_os(WAIT).is_some() {
            println!("ready");
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
        }
    }

    /// A copy of this test binary (signed ad-hoc by the linker; a copy of an Apple platform binary is killed outside its place) in a temporary directory, running `wait_helper`; killed and removed with the value.
    struct RunningCopy {
        dir: tempfile::TempDir,
        child: Child,
        _stdin: ChildStdin,
        _stdout: BufReader<std::process::ChildStdout>,
    }

    impl RunningCopy {
        /// Returns once the copy printed `ready`, so it has finished starting.
        fn start() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("copy");
            std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
            let mut child = Command::new(&path)
                .args(["--exact", "signing::tests::wait_helper", "--nocapture"])
                .env_clear()
                .env(WAIT, "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let stdin = child.stdin.take().unwrap();
            let mut stdout = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            while line != "ready\n" {
                line.clear();
                assert_ne!(stdout.read_line(&mut line).unwrap(), 0, "the copy ended");
            }
            Self {
                dir,
                child,
                _stdin: stdin,
                _stdout: stdout,
            }
        }

        fn path(&self) -> PathBuf {
            self.dir.path().join("copy")
        }

        fn pid(&self) -> i32 {
            i32::try_from(self.child.id()).unwrap()
        }
    }

    impl Drop for RunningCopy {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// What happens to the executable of the running copy between the check and the reading of the signing information.
    #[derive(Debug, Clone, Copy)]
    enum Swap {
        /// Renamed over by a copy of `/usr/bin/true`, signed by Apple (with certificates).
        AppleSigned,
        /// Renamed over by a copy of `/usr/bin/true` signed again ad-hoc with another identifier (without certificates, so no requirement is evaluated after the signing information is read).
        AdHoc,
        /// Removed.
        Removed,
    }

    impl Swap {
        /// Prepares the file that takes the place of the executable, in the same directory (a rename stays on one file system).
        fn prepare(self, executable: &Path) -> Option<PathBuf> {
            let replacement = executable.with_extension("replacement");
            match self {
                Self::Removed => return None,
                Self::AppleSigned => {
                    std::fs::copy("/usr/bin/true", &replacement).unwrap();
                }
                Self::AdHoc => {
                    std::fs::copy("/usr/bin/true", &replacement).unwrap();
                    let signed = Command::new("/usr/bin/codesign")
                        .args([
                            "--force",
                            "--sign",
                            "-",
                            "--identifier",
                            "com.example.replacement",
                        ])
                        .arg(&replacement)
                        .stderr(Stdio::null())
                        .status()
                        .unwrap();
                    assert!(signed.success());
                }
            }
            Some(replacement)
        }
    }

    /// The calls of a process, swapping its executable right after the first check without a requirement of the usual lookup, before its signing information is read.
    struct SwappedAfterCheck<'a> {
        calls: Calls<'a>,
        executable: PathBuf,
        /// `None` removes the executable.
        replacement: Option<PathBuf>,
        swapped: std::cell::Cell<bool>,
    }

    impl SwappedAfterCheck<'_> {
        fn swap(&self) {
            match &self.replacement {
                Some(replacement) => std::fs::rename(replacement, &self.executable).unwrap(),
                None => std::fs::remove_file(&self.executable).unwrap(),
            }
        }
    }

    impl SigningCalls for SwappedAfterCheck<'_> {
        type Code = (Lookup, SecCode);

        fn open(&self, lookup: Lookup) -> Result<Self::Code, i32> {
            self.calls.open(lookup).map(|code| (lookup, code))
        }

        fn check(&self, (lookup, code): &Self::Code, requirement: Option<Requirement>) -> i32 {
            let status = self.calls.check(code, requirement);
            if *lookup == Lookup::Usual && requirement.is_none() && !self.swapped.get() {
                self.swapped.set(true);
                self.swap();
            }
            status
        }

        fn info(&self, (_, code): &Self::Code) -> Result<SigningInfo, i32> {
            self.calls.info(code)
        }
    }

    // 要求なしの検証が通った直後、署名の情報を読む前に、走っているコードの実行ファイルを差し替える。SecCode.h は「Code の署名の情報の一部はディスクから読む」と書くので、署名の情報が差し替えた先のファイルから読まれると、検証に成功した結果に別のファイルの身元 (identifier、cdhash、署名者) が付く。走っているコードが ad-hoc なら、署名の情報の後に requirement の評価が無いので、そこでも気づけない。
    // 結果は、走っているコード (このテストのバイナリのコピー。同じバイナリなので、このプロセス自身と identifier・cdhash・署名者が同じ) の身元か、Failed (身元を持たない) でなければならない。走っているコードは linker が署名した ad-hoc。差し替え方は 3 通り: Apple の署名のファイル (証明書あり)、identifier を変えて署名し直した ad-hoc のファイル (証明書なし。後に requirement の評価が無い)、削除。
    // 前提として、差し替えの後に SecCode を開き直すと差し替えに気づく (ディスクから検証した Verified にならない) ことを確かめる。これが崩れると、差し替えが効いていないのにこのテストが通ってしまう。
    // macOS 26.5.2 での観測: 3 通りとも、差し替えの前に開いた SecCode は検証した静的なコードを持ち続け、署名の情報は差し替える前のもの (Verified、verified_from は disk、身元は走っているコード) だった。開き直すと、置き換えた 2 通りは running_code に切り替えて Verified、削除は Failed(Missing)。時機は検証の呼び出しの間に差し替えを挟んで作る (時間待ちをしない)。
    #[test]
    fn replacement_between_the_check_and_the_signing_information() {
        let requirements = Requirements::compile();
        let own = procline_core::verify::verify(&Calls {
            guest: Guest::Pid(i32::try_from(std::process::id()).unwrap()),
            requirements: &requirements,
        });
        let CodeSigning::Verified(own) = own else {
            panic!("the own signature does not verify: {own:?}");
        };
        for swap in [Swap::AppleSigned, Swap::AdHoc, Swap::Removed] {
            let copy = RunningCopy::start();
            let calls = SwappedAfterCheck {
                calls: Calls {
                    guest: Guest::Pid(copy.pid()),
                    requirements: &requirements,
                },
                executable: copy.path(),
                replacement: swap.prepare(&copy.path()),
                swapped: std::cell::Cell::new(false),
            };
            let result = procline_core::verify::verify(&calls);
            assert!(calls.swapped.get(), "{swap:?}");
            let fresh = procline_core::verify::verify(&calls.calls);
            assert!(
                !matches!(&fresh, CodeSigning::Verified(s) if s.verified_from == VerifiedFrom::Disk),
                "{swap:?}: a lookup after the swap does not see it: {fresh:?}"
            );
            match &result {
                CodeSigning::Verified(signature) => {
                    assert_eq!(signature.identifier, own.identifier, "{swap:?} {result:?}");
                    assert_eq!(signature.cdhash, own.cdhash, "{swap:?} {result:?}");
                    assert_eq!(signature.signer, own.signer, "{swap:?} {result:?}");
                }
                CodeSigning::Failed(_) => {}
                other => panic!("{swap:?}: unexpected {other:?}"),
            }
        }
    }
}
