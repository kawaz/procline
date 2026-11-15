//! Whether `collect_pid` reads the `Info.plist` of the app bundle around a running process, as `CollectOptions::bundle` says.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use procline_core::{EnvPolicy, ProcessChain, ProcessInfo, Redaction};
use procline_macos::{CollectOptions, collect_pid};

/// The target only, nothing else optional; `bundle` as given.
fn options(bundle: bool) -> CollectOptions {
    CollectOptions {
        env: EnvPolicy::None,
        redaction: Redaction::default(),
        icon: false,
        digest: false,
        bundle,
        signature: false,
        signature_budget: None,
        all_names: false,
        max_ancestors: 0,
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

/// A copy of this test binary at `X.app/Contents/MacOS/copy` in a temporary directory, beside an `X.app/Contents/Info.plist` with the bundle ID `com.example.procline-test` and the version `1.2`, running `stay_alive_helper` with a cleared environment that holds `STAY_ALIVE`. It lives until its standard input is closed; the value kills it, reaps it and removes the directory when dropped, also on failure.
struct RunningAppCopy {
    child: Spawned,
    _stdin: ChildStdin,
    /// Kept open so that the copy does not get `SIGPIPE` if it writes again.
    _stdout: BufReader<ChildStdout>,
    _dir: tempfile::TempDir,
}

impl RunningAppCopy {
    /// Returns once the copy printed `ready`, so it has finished starting; fails, instead of waiting on, when it ends before that.
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let contents = dir.path().join("X.app/Contents");
        std::fs::create_dir_all(contents.join("MacOS")).unwrap();
        std::fs::write(
            contents.join("Info.plist"),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <plist version=\"1.0\"><dict>\
             <key>CFBundleIdentifier</key><string>com.example.procline-test</string>\
             <key>CFBundleShortVersionString</key><string>1.2</string>\
             </dict></plist>\n",
        )
        .unwrap();
        let path = contents.join("MacOS/copy");
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
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

// bundle の指定が収集に効くことを、.app の中から起こした実プロセスで確かめる。同じ対象を 2 通りで集める:
// - bundle: true: 実行パスの上の X.app/Contents/Info.plist から bundle ID と版を読む (表示用の ProcessInfo.bundle)。
// - bundle: false: ProcessInfo.bundle は None。Info.plist はプロセスの持ち主が中身を決められるファイルなので、表示用の bundle を使わない利用者がその解析を省けるようにする (署名で封印された bundle ID は VerifiedSignature.bundle_id にあり、こちらの指定とは関係しない)。
// 同じ対象・同じ Info.plist で true が読めていることが、false の None が「指定で切った」結果であって「読めなかった」結果ではないことの裏付けになる。署名の検証はこの確かめに要らないので切る。
#[test]
fn the_bundle_option_decides_whether_the_info_plist_is_read() {
    let copy = RunningAppCopy::start();

    let on = collect_pid(copy.pid(), &options(true)).unwrap();
    let bundle = target(&on).bundle.as_ref().unwrap();
    assert_eq!(bundle.id.as_deref(), Some("com.example.procline-test"));
    assert_eq!(bundle.version.as_deref(), Some("1.2"));

    let off = collect_pid(copy.pid(), &options(false)).unwrap();
    assert_eq!(target(&off).bundle, None);
}

/// Set in the environment of a copy of this test binary that `stay_alive_helper` keeps running.
const STAY_ALIVE: &str = "PROCLINE_TEST_STAY_ALIVE";

// 単独のテストではない: 他のテストがこのテストのバイナリのコピーを子として起こすとき (STAY_ALIVE を渡す)、ready を出してから標準入力が閉じるまで生き続ける役をする。起こした側は ready を読んでから集め、終わったら子を kill する。普通に cargo test で走ったときは何もせずに終わる。ready は libtest の出力の取り込み (print! の系統だけが対象) を通らないよう、標準出力に直接書く。
#[test]
fn stay_alive_helper() {
    if std::env::var_os(STAY_ALIVE).is_some() {
        let mut stdout = std::io::stdout();
        stdout.write_all(b"ready\n").unwrap();
        stdout.flush().unwrap();
        let _ = std::io::stdin().read_line(&mut String::new());
    }
}
