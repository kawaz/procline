//! The class of the built-in matcher items (`binary`, `process`) decided from the protection of a running process collected by `procline-macos` (DR-0012).

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use procline_acl::{MatchValue, Vocabulary};
use procline_core::{
    BinaryPin, CodeSigning, EnvPolicy, Pinnable, ProcessChain, ProcessInfo, Redaction, Strength,
};
use procline_macos::{CollectOptions, collect_pid};

fn options() -> CollectOptions {
    CollectOptions {
        env: EnvPolicy::None,
        redaction: Redaction::default(),
        icon: false,
        digest: false,
        signature: true,
        signature_budget: None,
        all_names: true,
        max_ancestors: 64,
    }
}

/// A child that is killed and reaped when the test ends, also on failure.
struct Spawned(Child);

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn target(chain: &ProcessChain) -> &ProcessInfo {
    &chain.processes()[0]
}

/// A copy of this test binary in a temporary directory, running `stay_alive_helper` with a cleared environment that holds `STAY_ALIVE`. It lives until its standard input is closed; the value kills it, reaps it and removes the directory when dropped, also on failure.
struct RunningCopy {
    child: Spawned,
    _stdin: ChildStdin,
    /// Kept open so that the copy does not get `SIGPIPE` if it writes again.
    _stdout: BufReader<ChildStdout>,
    _dir: tempfile::TempDir,
}

impl RunningCopy {
    /// `prepare` gets the path of the copy before it is started (to sign it again). Returns once the copy printed `ready`, so it has finished starting; fails, instead of waiting on, when it ends before that.
    fn start_prepared(prepare: impl FnOnce(&Path)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("copy");
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        prepare(&path);
        let mut child = Command::new(&path)
            .args(["--exact", "stay_alive_helper"])
            .env_clear()
            .env(STAY_ALIVE, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let child = Spawned(child);
        let mut stdout = BufReader::new(stdout);
        let mut line = String::new();
        while line != "ready\n" {
            line.clear();
            let read = stdout.read_line(&mut line).unwrap();
            assert_ne!(read, 0, "the copy ended before it was ready");
        }
        Self {
            child,
            _stdin: stdin,
            _stdout: stdout,
            _dir: dir,
        }
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.child.0.id()).unwrap()
    }
}

/// The entitlements that relax the protection of the hardened runtime (DR-0012).
const RELAXING_ENTITLEMENTS: [&str; 4] = [
    "com.apple.security.get-task-allow",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.disable-executable-page-protection",
];

/// Signs the file again ad-hoc (`codesign --sign - --force`), with the hardened runtime when `runtime`, and with the one entitlement (set to `true`) when given. The entitlements plist is written beside the file.
fn sign_again(path: &Path, runtime: bool, entitlement: Option<&str>) {
    let mut codesign = Command::new("/usr/bin/codesign");
    codesign.args(["--sign", "-", "--force"]);
    if runtime {
        codesign.args(["--options", "runtime"]);
    }
    if let Some(key) = entitlement {
        let plist = path.with_extension("entitlements.plist");
        std::fs::write(
            &plist,
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                 <plist version=\"1.0\"><dict><key>{key}</key><true/></dict></plist>\n"
            ),
        )
        .unwrap();
        codesign.arg("--entitlements").arg(&plist);
    }
    let status = codesign
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "codesign failed for {path:?}");
}

// 走っているプロセスの署名から、カーネルの動的な status (hardened runtime) と署名に封じられた entitlements を読み、それが強さのクラスを決める (DR-0012)。合成した ProcessInfo ではなく、実際に起こしたプロセスを集めた結果で確かめる: 署名の情報から entitlements や status を読む経路が抜けると、合成データのテストは通っても、実物のプロセスはすべて「保護を緩める entitlement なし」に見えてしまう。
// このテストのバイナリのコピーを ad-hoc で署名し直し (codesign --sign - --force)、4 通りで起こして collect_pid で集める:
// - (a) --options runtime だけ: status に CS_RUNTIME があり、保護を緩める 4 つの entitlement のどれも無い = 保護あり。binary の署名由来の field も process も強。
// - (b) --options runtime と com.apple.security.get-task-allow: 宣言済みのデバッガが利用者の認可で接続できる = 認可で開く。binary も process も中。
// - (c) --options runtime と com.apple.security.cs.disable-library-validation: 読み込むライブラリを同じ uid が置き換えれば別の署名のコードがその身元で動く = 開いている。binary も process も弱。
// - (d) hardened runtime なし (entitlement なし): 起動時に DYLD_INSERT_LIBRARIES で差し込める = binary は弱。process は走っている個体を乗っ取る経路だけが関係し、entitlement を持たないプロセスからの接続はカーネルが断り、宣言済みのデバッガも利用者の認可の段に進むだけなので中。
// binary の値は cdhash (ad-hoc の署名でも持てる署名由来の field で、Team ID を持たない ad-hoc でも書ける)、process の値は集めたプロセスの識別子。クラスは組み込みの語彙の class に、集めたプロセスを渡して決める。
#[test]
fn the_protection_of_a_running_copy_decides_the_class() {
    let vocab = Vocabulary::builtin();
    let cases = [
        ("runtime", true, None, Strength::Strong, Strength::Strong),
        (
            "runtime and get-task-allow",
            true,
            Some("com.apple.security.get-task-allow"),
            Strength::Medium,
            Strength::Medium,
        ),
        (
            "runtime and disable-library-validation",
            true,
            Some("com.apple.security.cs.disable-library-validation"),
            Strength::Weak,
            Strength::Weak,
        ),
        ("no runtime", false, None, Strength::Weak, Strength::Medium),
    ];
    for (case, runtime, entitlement, binary_class, process_class) in cases {
        let copy = RunningCopy::start_prepared(|path| sign_again(path, runtime, entitlement));
        let options = CollectOptions {
            max_ancestors: 0,
            ..options()
        };
        let chain = collect_pid(copy.pid(), &options).unwrap();
        let info = target(&chain);
        let Some(CodeSigning::Verified(signature)) = &info.code_signing else {
            panic!(
                "{case}: expected a verified signature: {:?}",
                info.code_signing
            );
        };
        assert_eq!(signature.runtime.hardened_runtime, runtime, "{case}");
        assert!(!signature.runtime.debugged, "{case}");
        let present: Vec<&str> = RELAXING_ENTITLEMENTS
            .into_iter()
            .filter(|key| {
                signature
                    .entitlements
                    .as_ref()
                    .is_some_and(|entitlements| entitlements.contains_key(*key))
            })
            .collect();
        assert_eq!(present, Vec::from_iter(entitlement), "{case}");

        let binary = MatchValue::Binary(BinaryPin {
            digest: None,
            team_id: None,
            signing_id: None,
            bundle_id: None,
            cdhash: Some(Pinnable::Value(signature.cdhash)),
        });
        assert_eq!(
            vocab.class("binary", &binary, Some(info)),
            Some(binary_class),
            "{case}: binary"
        );
        let process = MatchValue::Process(Pinnable::Value(
            info.identity.process_identity(chain.boot_uuid()),
        ));
        assert_eq!(
            vocab.class("process", &process, Some(info)),
            Some(process_class),
            "{case}: process"
        );
    }
}

/// Set in the environment of a copy of this test binary that `stay_alive_helper` keeps running.
const STAY_ALIVE: &str = "PROCLINE_TEST_STAY_ALIVE";

// 単独のテストではない: 他のテストがこのテストのバイナリ (かそのコピー) を子として起こすとき (STAY_ALIVE を渡す)、ready を出してから標準入力が閉じるまで生き続ける役をする。起こした側は ready を読んでから集め、終わったら子を kill する。普通に cargo test で走ったときは何もせずに終わる。ready は libtest の出力の取り込み (print! の系統だけが対象) を通らないよう、標準出力に直接書く。
#[test]
fn stay_alive_helper() {
    if std::env::var_os(STAY_ALIVE).is_some() {
        let mut stdout = std::io::stdout();
        stdout.write_all(b"ready\n").unwrap();
        stdout.flush().unwrap();
        let _ = std::io::stdin().read_line(&mut String::new());
    }
}
