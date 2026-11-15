//! `collect_pid` against real processes of the machine running the tests.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use procline_core::{
    CodeSigning, EnvPolicy, FailureReason, Mark, ProcessChain, ProcessInfo, Redaction, Signer,
    Truncated, VerifiedFrom,
};
use procline_macos::{CollectError, CollectOptions, collect_pid};

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

fn own_pid() -> i32 {
    i32::try_from(std::process::id()).unwrap()
}

/// A spawned child that is killed when the test ends, also on failure.
struct Spawned(Child);

impl Spawned {
    /// `std::process::Command::spawn` returns after the child has executed the program, so the child already runs the new image when this returns.
    fn spawn(command: &mut Command) -> Self {
        Self(
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.0.id()).unwrap()
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn command_output(program: &str, args: &[&str]) -> String {
    let out = Command::new(program).args(args).output().unwrap();
    assert!(out.status.success(), "{program} {args:?} failed");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// The pids of the chain, for failure messages (the whole chain would print the argv of every ancestor).
fn pids(chain: &ProcessChain) -> Vec<i32> {
    chain.processes().iter().map(|p| p.identity.pid).collect()
}

fn target(chain: &ProcessChain) -> &ProcessInfo {
    &chain.processes()[0]
}

// 自分のプロセスについて、常に集める項目が埋まり、OS の別の窓口 (std の API、sysctl コマンド) から見た値と一致する。同じ uid のプロセスは argv と cwd も読めるので、それらも空でない。
#[test]
fn own_process_has_the_always_collected_items() {
    let chain = collect_pid(own_pid(), &options()).unwrap();
    let me = target(&chain);
    assert_eq!(me.identity.pid, own_pid());
    assert!(me.identity.unique_id.is_some());
    assert!(me.identity.start_time.is_some());
    let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
    assert_eq!(me.path.as_deref(), Some(exe.as_path()));
    assert!(me.name.as_deref().is_some_and(|n| !n.is_empty()));
    assert_eq!(me.argv, Some(std::env::args().collect::<Vec<_>>()));
    let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
    assert_eq!(me.cwd.as_deref(), Some(cwd.as_path()));
    let credentials = me.credentials.as_ref().unwrap();
    // SAFETY: geteuid and getegid only return the ids of the calling process.
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    assert_eq!(credentials.uid.id, euid);
    assert_eq!(credentials.gid.id, egid);
    // The representative OS lookup name must also be present in the complete name list.
    let uid_name = credentials.uid.name.as_ref().unwrap();
    assert!(credentials.uid.names.contains(uid_name));
    for group in &credentials.groups {
        if let Some(name) = &group.name {
            assert!(group.names.contains(name));
        }
    }
    // The kernel lists the effective gid first in the credential's groups.
    assert_eq!(credentials.groups.first().map(|g| g.id), Some(egid));
    assert_eq!(
        chain.boot_uuid(),
        command_output("/usr/sbin/sysctl", &["-n", "kern.bootsessionuuid"])
    );
    // `EnvPolicy::None` (the default) collects no environment at all.
    assert_eq!(me.env, None);
}

// 列の 2 番目は親 (このテストを起動したプロセス) で、子の parent_unique_id が親の unique_id と一致する。祖先は pid でなくこの一意な ID で繋がっていることを確かめる (pid だけだと、親が終わって pid が再利用されたとき別のプロセスを親と取り違える)。
#[test]
fn parent_is_second_and_linked_by_unique_id() {
    let chain = collect_pid(own_pid(), &options()).unwrap();
    let parent_pid = i32::try_from(std::os::unix::process::parent_id()).unwrap();
    let processes = chain.processes();
    assert!(processes.len() >= 2, "chain: {:?}", pids(&chain));
    assert_eq!(processes[1].identity.pid, parent_pid);
    assert_eq!(
        processes[0].identity.parent_unique_id,
        processes[1].identity.unique_id
    );
}

// 祖先の列は launchd (pid 1) に届くか、親子の繋がりが本当に切れている所で AncestorExited で終わる。
//
// どちらになるかはテストを起動した環境で決まる。祖先のどれかの元の親が終了して launchd に付け替えられていると (二重 fork したデーモンや、親が先に終わった端末内のプロセス)、そのプロセスの ppid は 1 になるが、カーネルの parent_unique_id は元の親の値のまま変わらない。launchd はその元の親ではないので、列はそこで AncestorExited で終わる (launchd を親として繋ぐと、実在しない親子関係を列に書くことになる)。
//
// そこで、終わり方ごとにその理由が正しいことを OS の別の窓口から確かめる: launchd に届いたなら最後は pid 1。途切れたなら、最後のプロセスの今の ppid (ps で見る) を集め直すと、その unique_id は最後のプロセスの parent_unique_id と一致しない。
#[test]
fn chain_reaches_launchd_or_ends_where_the_lineage_breaks() {
    let chain = collect_pid(own_pid(), &options()).unwrap();
    let last = chain.processes().last().unwrap();
    match chain.truncated() {
        None => assert_eq!(last.identity.pid, 1),
        Some(Truncated::AncestorExited) => {
            let ppid: i32 = command_output(
                "/bin/ps",
                &["-o", "ppid=", "-p", &last.identity.pid.to_string()],
            )
            .parse()
            .unwrap();
            let parent = collect_pid(ppid, &options()).unwrap();
            assert_ne!(
                target(&parent).identity.unique_id,
                last.identity.parent_unique_id,
                "the walk stopped at pid {} though its parent {ppid} is still linked",
                last.identity.pid
            );
        }
        other => panic!("unexpected truncation {other:?}: {:?}", pids(&chain)),
    }
}

// launchd 自身を集めると、列は launchd 1 つだけで、根に届いている (truncated は None)。root のプロセスでも識別子と実行パスは読める (argv と cwd は同じ uid でないので読めない)。署名は別 uid でもユーザ権限から検証でき、根が Apple 自身 (anchor apple) なので印は apple。hardened runtime と platform binary はカーネルの動的な status にある。
#[test]
fn launchd_is_the_root() {
    let chain = collect_pid(1, &options()).unwrap();
    assert_eq!(chain.processes().len(), 1);
    assert_eq!(chain.truncated(), None);
    let launchd = target(&chain);
    assert!(launchd.identity.unique_id.is_some());
    assert_eq!(launchd.path.as_deref(), Some(Path::new("/sbin/launchd")));
    assert_eq!(
        launchd.code_signing.as_ref().map(CodeSigning::mark),
        Some(Mark::Apple)
    );
    let Some(CodeSigning::Verified(signature)) = &launchd.code_signing else {
        unreachable!()
    };
    assert_eq!(signature.identifier, "com.apple.xpc.launchd");
    assert!(signature.runtime.hardened_runtime);
    assert!(signature.runtime.platform_binary);
    assert!(!signature.runtime.debugged);
}

// macOS の pid は PID_MAX (99999) より小さいので、i32::MAX のプロセスは存在しない。収集全体が NoSuchProcess で失敗し、空の列を返さない。
#[test]
fn missing_pid_is_no_such_process() {
    match collect_pid(i32::MAX, &options()) {
        Err(CollectError::NoSuchProcess { pid }) => assert_eq!(pid, i32::MAX),
        other => panic!("expected NoSuchProcess, got {other:?}"),
    }
}

// max_ancestors は対象を除いた祖先の数の上限。0 なら対象だけ、1 なら対象と親で、どちらも根に届いていないので MaxAncestors で終わる。
#[test]
fn max_ancestors_bounds_the_ancestors() {
    for max in [0, 1] {
        let mut opts = options();
        opts.max_ancestors = max;
        let chain = collect_pid(own_pid(), &opts).unwrap();
        assert_eq!(chain.processes().len(), max + 1);
        assert_eq!(chain.truncated(), Some(Truncated::MaxAncestors));
    }
}

// /bin/sleep は Apple の platform binary: 署名が検証に通り、根は Apple 自身 (anchor apple) で印は apple、署名の識別子は com.apple.sleep。ディスク上の実行ファイルを検証できるので verified_from は disk。hardened runtime と platform binary はカーネルの動的な status から取る (CodeDirectory の flags でなく)。実行パスは root 所有で、利用者は (ファイルにも途中のディレクトリにも) 書けない。親はこのテストのプロセス。
#[test]
fn sleep_is_a_platform_binary_the_user_cannot_replace() {
    let sleep = Spawned::spawn(Command::new("/bin/sleep").arg("30"));
    let chain = collect_pid(sleep.pid(), &options()).unwrap();
    let info = target(&chain);
    assert_eq!(info.path.as_deref(), Some(Path::new("/bin/sleep")));
    let Some(CodeSigning::Verified(signature)) = &info.code_signing else {
        panic!("expected a verified signature: {:?}", info.code_signing);
    };
    assert_eq!(signature.identifier, "com.apple.sleep");
    assert_eq!(signature.verified_from, VerifiedFrom::Disk);
    assert!(signature.runtime.platform_binary);
    assert!(signature.runtime.hardened_runtime);
    assert_eq!(signature.team_id(), None);
    assert_eq!(
        info.code_signing.as_ref().map(CodeSigning::mark),
        Some(Mark::Apple)
    );
    let meta = info.path_meta.unwrap();
    assert_eq!(meta.owner_uid, 0);
    assert!(!meta.writable_by_user);
    assert_eq!(chain.processes()[1].identity.pid, own_pid());
}

// このテストのバイナリはリンカが付けた ad-hoc 署名 (証明書なし、kSecCodeSignatureLinkerSigned) なので、検証には通るが印は adhoc で、根の requirement は問わない。Team ID は持たない。hardened runtime なしでリンクされているので、カーネルの status にも CS_RUNTIME は無い。
#[test]
fn linker_signed_test_binary_is_adhoc() {
    let chain = collect_pid(own_pid(), &options()).unwrap();
    let Some(CodeSigning::Verified(signature)) = &target(&chain).code_signing else {
        panic!(
            "expected a verified signature: {:?}",
            target(&chain).code_signing
        );
    };
    assert_eq!(
        signature.signer,
        Signer::AdHoc {
            linker_signed: true
        }
    );
    assert_eq!(signature.team_id(), None);
    assert!(!signature.runtime.hardened_runtime);
    assert!(!signature.runtime.platform_binary);
    assert_eq!(
        target(&chain).code_signing.as_ref().map(CodeSigning::mark),
        Some(Mark::Adhoc)
    );
}

/// This test binary, or a copy of it, running `stay_alive_helper` with a cleared environment that holds `STAY_ALIVE` and the given variables. It lives until its standard input is closed; the value kills it and reaps it when dropped, also on failure.
struct Helper {
    child: Spawned,
    _stdin: ChildStdin,
    /// Kept open so that the helper does not get `SIGPIPE` if it writes again.
    _stdout: BufReader<ChildStdout>,
}

impl Helper {
    /// Returns once the helper printed `ready`, so it has finished starting (not merely once it was spawned: a copy deleted right after it was spawned made the Security framework answer ESRCH (100003) instead of ENOENT (100002) for the lookup by pid, observed on macOS 26.5.2). Fails, instead of waiting on, when it ends before that.
    fn start(program: &Path, env: &[(&str, &str)]) -> Self {
        let mut child = Command::new(program)
            .args(["--exact", "stay_alive_helper"])
            .env_clear()
            .env(STAY_ALIVE, "1")
            .envs(env.iter().copied())
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
            assert_ne!(read, 0, "the helper ended before it was ready");
        }
        Self {
            child,
            _stdin: stdin,
            _stdout: stdout,
        }
    }

    fn pid(&self) -> i32 {
        self.child.pid()
    }
}

/// A copy of this test binary in a temporary directory, running as a `Helper`; the directory and the process go away with the value.
struct RunningCopy {
    dir: tempfile::TempDir,
    helper: Helper,
}

impl RunningCopy {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("copy");
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let helper = Helper::start(&path, &[]);
        Self { dir, helper }
    }

    fn path(&self) -> std::path::PathBuf {
        self.dir.path().join("copy")
    }
}

// 走っているプロセスの実行ファイルを rename で差し替える (/usr/bin/true のコピーを置く)。通常の方法はディスク上の差し替えた先を見て -67034 で失敗するので、pid に kSecGuestAttributeDynamicCode を足して、カーネルが持つ走っているコードの署名で検証し直す。身元は差し替える前のコード (このテストのバイナリ) のもので、差し替えた先 (com.apple.true、印は apple) を返さない。
#[test]
fn replaced_executable_is_verified_from_the_running_code() {
    let own = collect_pid(own_pid(), &options()).unwrap();
    let Some(CodeSigning::Verified(own)) = &target(&own).code_signing else {
        panic!("expected the own signature to verify");
    };
    let copy = RunningCopy::start();
    let replacement = copy.dir.path().join("replacement");
    std::fs::copy("/usr/bin/true", &replacement).unwrap();
    std::fs::rename(&replacement, copy.path()).unwrap();

    let chain = collect_pid(copy.helper.pid(), &options()).unwrap();
    let Some(CodeSigning::Verified(signature)) = &target(&chain).code_signing else {
        panic!(
            "expected a verified signature: {:?}",
            target(&chain).code_signing
        );
    };
    assert_eq!(signature.verified_from, VerifiedFrom::RunningCode);
    assert_eq!(signature.identifier, own.identifier);
    assert_eq!(signature.cdhash, own.cdhash);
    assert_eq!(
        target(&chain).code_signing.as_ref().map(CodeSigning::mark),
        Some(Mark::Adhoc)
    );
}

// 走っているプロセスの実行ファイルを削除すると、通常の方法では SecCode が得られず (100002)、pid ベースでも身元が取れないので、検証の結果は Failed(Missing)。身元 (identifier 等) は持たない。走っているコードが改ざんされたわけではないが、確かめられないものは確かめたと言わない。
#[test]
fn deleted_executable_is_failed_missing() {
    let copy = RunningCopy::start();
    std::fs::remove_file(copy.path()).unwrap();
    let chain = collect_pid(copy.helper.pid(), &options()).unwrap();
    assert_eq!(
        target(&chain).code_signing,
        Some(CodeSigning::Failed(FailureReason::Missing))
    );
}

// 収集に検証の時間の予算を与え、それが 0 なら、どのプロセスも検証を始める前に予算を超えているので全部 not_checked (検証しなかったことを、検証に失敗したことや未署名と区別して返す)。予算を与えなければ全部検証する。
#[test]
fn zero_budget_checks_nothing() {
    let mut opts = options();
    opts.signature_budget = Some(std::time::Duration::ZERO);
    let chain = collect_pid(own_pid(), &opts).unwrap();
    assert!(
        chain
            .processes()
            .iter()
            .all(|p| p.code_signing == Some(CodeSigning::NotChecked)),
        "{:?}",
        pids(&chain)
    );
    let chain = collect_pid(own_pid(), &options()).unwrap();
    assert!(
        chain
            .processes()
            .iter()
            .all(|p| !matches!(p.code_signing, Some(CodeSigning::NotChecked) | None))
    );
}

// digest は実行ファイルの内容の sha256 で、shasum の結果と同じ値を `sha256:<hex>` の形で持つ。digest を頼まなければ集めない (大きなファイルを読むので既定は off)。
#[test]
fn digest_is_the_sha256_of_the_executable() {
    let sleep = Spawned::spawn(Command::new("/bin/sleep").arg("30"));
    let without = collect_pid(sleep.pid(), &options()).unwrap();
    assert_eq!(target(&without).digest, None);
    let mut opts = options();
    opts.digest = true;
    let chain = collect_pid(sleep.pid(), &opts).unwrap();
    let expected = command_output("/usr/bin/shasum", &["-a", "256", "/bin/sleep"]);
    let expected = expected.split_whitespace().next().unwrap();
    assert_eq!(target(&chain).digest, Some(format!("sha256:{expected}")));
}

/// `EnvPolicy::All` for the target only: the ancestors of the child (this test binary, cargo, the shell) carry the real environment, which the tests must not collect.
fn env_all_target_only() -> CollectOptions {
    CollectOptions {
        env: EnvPolicy::All,
        max_ancestors: 0,
        ..options()
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

// env を All で集めると、子に渡した変数の名前がすべて入り、カーネルが env の後に置く dyld 向けの文字列 (executable_path= 等) は入らない。
//
// 値は assert しない (env の値をテストの出力に出さない運用のため)。伏せ字が値に効くことは、合成データで procargs::select_env の単体テストが固定している。子は platform binary でないもの (このテストのバイナリ、リンカの ad-hoc 署名) にする。platform binary の env はカーネルが返さない (次のテスト)。子の env は env_clear で中身を決めてある。
#[test]
fn env_all_collects_the_child_variable_names() {
    let exe = std::env::current_exe().unwrap();
    let child = Helper::start(&exe, &[("PLAIN", "visible"), ("API_TOKEN", "hidden")]);
    let chain = collect_pid(child.pid(), &env_all_target_only()).unwrap();
    let info = target(&chain);
    let exe = exe.to_str().unwrap().to_owned();
    assert_eq!(
        info.argv,
        Some(vec![
            exe,
            "--exact".to_owned(),
            "stay_alive_helper".to_owned()
        ])
    );
    let names: Option<Vec<&str>> = info
        .env
        .as_ref()
        .map(|env| env.keys().map(String::as_str).collect());
    assert_eq!(names, Some(vec!["API_TOKEN", "PLAIN", STAY_ALIVE]));
}

// platform binary (/bin/sleep) の env は、同じ uid でもカーネルが KERN_PROCARGS2 に入れない (macOS 26 の実機で観測)。env は「空」でなく None (読めなかった) になり、argv は読める。この境界が変わったら (OS が env を返すようになったら) このテストが落ちて知らせる。
#[test]
fn platform_binary_env_is_not_readable() {
    let sleep = Spawned::spawn(
        Command::new("/bin/sleep")
            .arg("30")
            .env_clear()
            .env("PLAIN", "visible"),
    );
    let chain = collect_pid(sleep.pid(), &env_all_target_only()).unwrap();
    let info = target(&chain);
    assert_eq!(
        info.argv,
        Some(vec!["/bin/sleep".to_owned(), "30".to_owned()])
    );
    assert_eq!(info.env, None);
}

// 収集結果を JSON に書き出した形 (表示、ログ、他のプロセスへの受け渡しに使う形) を、署名の証明書を含む実データで確かめる。列は processes / boot_uuid / truncated の 3 つのキーだけを持ち、processes は列と同じ数と順で、各行は ProcessInfo の全 field をキーに持つ (取れなかった項目も null で書き、キーを落とさない)。署名は state と mark を並べ、証明書の連なりは収集した枚数のまま、DER は文字列 (base64url) で書く。ProcessChain は JSON から読めない (評価に渡す chain は評価するプロセスが自分で収集したものに限る) ので、書き出した値を収集した値と突き合わせる。失敗のメッセージに env や証明書のバイト列を出さないよう、比べるのはキー、識別子、印、枚数だけにする。
#[test]
fn chain_is_written_to_json_in_the_shape_of_the_type() {
    const PROCESS_KEYS: [&str; 14] = [
        "argv",
        "bundle",
        "code_signing",
        "credentials",
        "cwd",
        "digest",
        "env",
        "icon_png",
        "identity",
        "name",
        "path",
        "path_meta",
        "responsible",
        "tty",
    ];
    let keys = |value: &serde_json::Value| -> Vec<String> {
        let mut keys: Vec<String> = value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    };
    let chain = collect_pid(own_pid(), &options()).unwrap();
    let json = serde_json::to_value(&chain).unwrap();
    assert_eq!(keys(&json), ["boot_uuid", "processes", "truncated"]);
    assert_eq!(json["boot_uuid"], chain.boot_uuid());
    assert_eq!(
        json["truncated"],
        serde_json::to_value(chain.truncated()).unwrap()
    );
    let written = json["processes"].as_array().expect("processes is an array");
    assert_eq!(written.len(), chain.processes().len());
    let mut certificates = 0;
    for (index, (row, info)) in written.iter().zip(chain.processes()).enumerate() {
        assert_eq!(keys(row), PROCESS_KEYS, "process {index}");
        assert_eq!(row["identity"]["pid"], info.identity.pid, "process {index}");
        let Some(signing) = &info.code_signing else {
            assert_eq!(
                row["code_signing"],
                serde_json::Value::Null,
                "process {index}"
            );
            continue;
        };
        assert_eq!(
            row["code_signing"]["mark"],
            serde_json::to_value(signing.mark()).unwrap(),
            "process {index}"
        );
        assert!(row["code_signing"]["state"].is_string(), "process {index}");
        if let CodeSigning::Verified(signature) = signing
            && let Signer::Certificate {
                chain: collected, ..
            } = &signature.signer
        {
            let chain_json = row["code_signing"]["signer"]["chain"]
                .as_array()
                .expect("the certificate chain is an array");
            assert_eq!(chain_json.len(), collected.len(), "process {index}");
            assert!(
                chain_json
                    .iter()
                    .all(|certificate| certificate["der"].is_string()),
                "process {index}"
            );
            certificates += collected.len();
        }
    }
    // 祖先には Apple の証明書で署名されたもの (launchd、シェル) が入るので、証明書の形を少なくとも 1 枚は確かめている。
    assert!(certificates > 0);
}
