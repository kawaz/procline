//! UNIX domain socket peers, including the identity of a child process connected from another process.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};

use procline_core::{CodeSigning, EnvPolicy, FailureReason, Mark, Redaction, VerifiedFrom};
use procline_macos::{CollectError, CollectOptions, collect_peer, collect_pid};

fn options() -> CollectOptions {
    CollectOptions {
        env: EnvPolicy::None,
        redaction: Redaction::default(),
        icon: false,
        digest: false,
        bundle: true,
        signature: true,
        signature_budget: None,
        all_names: false,
        max_ancestors: 64,
    }
}

fn own_pid() -> i32 {
    i32::try_from(std::process::id()).unwrap()
}

/// The connection helper must be reaped even if a test fails.
struct Spawned(Child);

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

const SOCKET_PATH: &str = "PROCLINE_TEST_SOCKET_PATH";

// This helper runs only when explicitly re-executed by the separate-process test. After connecting it signals readiness and waits for the parent; it must stay alive while the parent collects process attributes.
#[test]
fn connect_helper() {
    let Some(path) = std::env::var_os(SOCKET_PATH) else {
        return;
    };
    let mut stream = UnixStream::connect(path).unwrap();
    stream.write_all(&[1]).unwrap();
    let mut response = [0];
    stream.read_exact(&mut response).unwrap();
}

// A socketpair's connected peer is the test process itself. The audit token and audit session are set only on that target, its pid is correct, and its audit-token-based signature matches the pid-based signature of the same running code.
#[test]
fn socketpair_identifies_own_process() {
    let (socket, _peer) = UnixStream::pair().unwrap();
    let chain = collect_peer(&socket, &options()).unwrap();
    let me = &chain.processes()[0];
    let pid_chain = collect_pid(own_pid(), &options()).unwrap();
    assert_eq!(me.identity.pid, own_pid());
    assert!(me.identity.audit_token.is_some());
    assert!(me.identity.asid.is_some());
    assert_eq!(me.code_signing, pid_chain.processes()[0].code_signing);
    assert!(me.code_signing.is_some());
    assert!(
        chain.processes()[1..].iter().all(
            |process| process.identity.audit_token.is_none() && process.identity.asid.is_none()
        )
    );
}

// Another process connects to a real listener. Its token must resolve to the child's pid, not the accepting process's pid, and its code signature must be collected by that audit token.
#[test]
fn listener_identifies_child_process() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("peer.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let exe = std::env::current_exe().unwrap();
    let child = Spawned(
        Command::new(exe)
            .args(["--exact", "connect_helper"])
            .env_clear()
            .env(SOCKET_PATH, &socket_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let (mut socket, _) = listener.accept().unwrap();
    let mut ready = [0];
    socket.read_exact(&mut ready).unwrap();
    let chain = collect_peer(&socket, &options()).unwrap();
    let peer = &chain.processes()[0];
    assert_eq!(peer.identity.pid, i32::try_from(child.0.id()).unwrap());
    assert!(peer.identity.audit_token.is_some());
    assert!(peer.identity.asid.is_some());
    assert_eq!(
        peer.code_signing.as_ref().map(CodeSigning::mark),
        Some(Mark::Adhoc)
    );
    assert_ne!(peer.identity.pid, own_pid());
}

// 接続相手の実行ファイルを、接続の後に別のファイル (/usr/bin/true のコピー) で rename して差し替える。通常の方法はディスク上の差し替えた先を見て -67034 で失敗するので、audit token のまま kSecGuestAttributeDynamicCode を足して、カーネルが持つ走っているコードの署名で検証し直す。結果は差し替える前のコード (このテストのバイナリのコピー) の身元で、verified_from は running_code。差し替えた先 (com.apple.true) の身元を接続相手の身元として返さないこと。コピーは一時ディレクトリに置き、テストの終わりに消える。
#[test]
fn replaced_peer_is_verified_from_the_running_code() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("peer.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let copy = dir.path().join("peer-copy");
    std::fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();
    let child = Spawned(
        Command::new(&copy)
            .args(["--exact", "connect_helper"])
            .env_clear()
            .env(SOCKET_PATH, &socket_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let (mut socket, _) = listener.accept().unwrap();
    let mut ready = [0];
    socket.read_exact(&mut ready).unwrap();
    let replacement = dir.path().join("replacement");
    std::fs::copy("/usr/bin/true", &replacement).unwrap();
    std::fs::rename(&replacement, &copy).unwrap();

    let chain = collect_peer(&socket, &options()).unwrap();
    let peer = &chain.processes()[0];
    assert_eq!(peer.identity.pid, i32::try_from(child.0.id()).unwrap());
    let Some(CodeSigning::Verified(signature)) = &peer.code_signing else {
        panic!("expected a verified signature: {:?}", peer.code_signing);
    };
    assert_eq!(signature.verified_from, VerifiedFrom::RunningCode);
    let own = collect_pid(own_pid(), &options()).unwrap();
    let Some(CodeSigning::Verified(own)) = &own.processes()[0].code_signing else {
        panic!("expected the own signature to verify");
    };
    assert_eq!(signature.identifier, own.identifier);
    assert_eq!(signature.cdhash, own.cdhash);
    assert_ne!(signature.identifier, "com.apple.true");
}

// 接続相手の実行ファイルを、接続の後に削除する。pid の側 (collect_pid の deleted_executable_is_failed_missing) と同じく、通常の方法が 100002 (実行ファイルが無い) で失敗し、pid ベースへの切り替えの対象 (100013 と -67034) ではないので、検証の結果は Failed(Missing) で、身元は持たない。削除は接続相手が接続して ready を送った後 (起動を終えた後) に行う。コピーは一時ディレクトリに置き、テストの終わりに消える。
#[test]
fn deleted_peer_is_failed_missing() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("peer.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let copy = dir.path().join("peer-copy");
    std::fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();
    let child = Spawned(
        Command::new(&copy)
            .args(["--exact", "connect_helper"])
            .env_clear()
            .env(SOCKET_PATH, &socket_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let (mut socket, _) = listener.accept().unwrap();
    let mut ready = [0];
    socket.read_exact(&mut ready).unwrap();
    std::fs::remove_file(&copy).unwrap();

    let chain = collect_peer(&socket, &options()).unwrap();
    let peer = &chain.processes()[0];
    assert_eq!(peer.identity.pid, i32::try_from(child.0.id()).unwrap());
    assert_eq!(
        peer.code_signing,
        Some(CodeSigning::Failed(FailureReason::Missing))
    );
}

// A socket that is not connected has no peer audit token and must return Peer instead of returning an unrelated process or an empty chain.
#[test]
fn unconnected_socket_has_no_peer() {
    let dir = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(dir.path().join("unused.sock")).unwrap();
    assert!(matches!(
        collect_peer(&listener, &options()),
        Err(CollectError::Peer(_))
    ));
}
