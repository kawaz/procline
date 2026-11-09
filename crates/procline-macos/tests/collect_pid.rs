//! `collect_pid` against real processes of the machine running the tests.

use std::path::Path;
use std::process::{Child, Command, Stdio};

use procline_core::{
    CodeSigning, EnvPolicy, ProcessChain, ProcessInfo, Redaction, SignatureTrust, Truncated,
};
use procline_macos::{CollectError, CollectOptions, collect_pid};

fn options() -> CollectOptions {
    CollectOptions {
        env: EnvPolicy::None,
        redaction: Redaction::default(),
        icon: false,
        digest: false,
        signature: true,
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
        chain.boot_uuid,
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
    match chain.truncated {
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

// launchd 自身を集めると、列は launchd 1 つだけで、根に届いている (truncated は None)。root のプロセスでも識別子と実行パスは読める (argv と cwd は同じ uid でないので読めない)。
#[test]
fn launchd_is_the_root() {
    let chain = collect_pid(1, &options()).unwrap();
    assert_eq!(chain.processes().len(), 1);
    assert_eq!(chain.truncated, None);
    let launchd = target(&chain);
    assert!(launchd.identity.unique_id.is_some());
    assert_eq!(launchd.path.as_deref(), Some(Path::new("/sbin/launchd")));
    assert_eq!(launchd.signature_trust(), Some(SignatureTrust::Platform));
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
        assert_eq!(chain.truncated, Some(Truncated::MaxAncestors));
    }
}

// /bin/sleep は Apple の platform binary: 署名が検証に通り、Apple のルートに連鎖し (`anchor apple generic` を満たす)、信頼度は Platform、署名の識別子は com.apple.sleep。実行パスは root 所有で、利用者は (ファイルにも途中のディレクトリにも) 書けない。親はこのテストのプロセス。
#[test]
fn sleep_is_a_platform_binary_the_user_cannot_replace() {
    let sleep = Spawned::spawn(Command::new("/bin/sleep").arg("30"));
    let chain = collect_pid(sleep.pid(), &options()).unwrap();
    let info = target(&chain);
    assert_eq!(info.path.as_deref(), Some(Path::new("/bin/sleep")));
    let Some(CodeSigning::Signed(signature)) = &info.code_signing else {
        panic!("expected a signature: {:?}", info.code_signing);
    };
    assert_eq!(signature.signing_id.as_deref(), Some("com.apple.sleep"));
    assert!(signature.platform);
    assert_eq!(signature.apple_anchored, Some(true));
    assert_eq!(info.signature_trust(), Some(SignatureTrust::Platform));
    let meta = info.path_meta.unwrap();
    assert_eq!(meta.owner_uid, 0);
    assert!(!meta.writable_by_user);
    assert_eq!(chain.processes()[1].identity.pid, own_pid());
}

// このテストのバイナリはリンカが付けた ad-hoc 署名なので、検証には通るが `anchor apple generic` を満たさない。満たさないこと (errSecCSReqFailed) は「評価できなかった」(None) でなく false として記録され、信頼度は AdHoc になる。
#[test]
fn linker_signed_test_binary_is_adhoc_and_not_apple_anchored() {
    let chain = collect_pid(own_pid(), &options()).unwrap();
    let Some(CodeSigning::Signed(signature)) = &target(&chain).code_signing else {
        panic!("expected a signature: {:?}", target(&chain).code_signing);
    };
    assert!(signature.adhoc);
    assert_eq!(signature.apple_anchored, Some(false));
    assert_eq!(
        target(&chain).signature_trust(),
        Some(SignatureTrust::AdHoc)
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

// 単独のテストではない: env のテストがこのテストのバイナリを子として起こすとき (STAY_ALIVE を渡す)、集められるまで生き続ける役をする。普通に cargo test で走ったときは何もせずに終わる。60 秒は env のテストが子を kill するまでの上限で、待ち合わせではない。
#[test]
fn stay_alive_helper() {
    if std::env::var_os(STAY_ALIVE).is_some() {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

// env を All で集めると、子に渡した変数の名前がすべて入り、カーネルが env の後に置く dyld 向けの文字列 (executable_path= 等) は入らない。
//
// 値は assert しない (env の値をテストの出力に出さない運用のため)。伏せ字が値に効くことは、合成データで procargs::select_env の単体テストが固定している。子は platform binary でないもの (このテストのバイナリ、リンカの ad-hoc 署名) にする。platform binary の env はカーネルが返さない (次のテスト)。子の env は env_clear で中身を決めてある。
#[test]
fn env_all_collects_the_child_variable_names() {
    let exe = std::env::current_exe().unwrap();
    let child = Spawned::spawn(
        Command::new(&exe)
            .args(["--exact", "stay_alive_helper"])
            .env_clear()
            .env(STAY_ALIVE, "1")
            .env("PLAIN", "visible")
            .env("API_TOKEN", "hidden"),
    );
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

// 収集結果は JSON に書き出して読み戻すと元と等しい (承認画面やルールの保存に JSON で渡しても情報が落ちない)。署名の証明書や entitlements を含む実データで確かめる。
#[test]
fn chain_round_trips_through_json() {
    let chain = collect_pid(own_pid(), &options()).unwrap();
    let json = serde_json::to_string(&chain).unwrap();
    let back: ProcessChain = serde_json::from_str(&json).unwrap();
    assert_eq!(back, chain);
}
