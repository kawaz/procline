//! Collecting by an audit token the caller passes: the process it names, including a child process of this test, and the failures when that process ran `exec` or exited after the token was taken.

use std::io::{Read, Write};
use std::mem::size_of_val;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use procline_core::{
    AuditToken, CodeSigning, EnvPolicy, FailureReason, Mark, Redaction, VerifiedFrom,
};
use procline_macos::{CollectError, CollectOptions, collect_audit_token, collect_pid};

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

/// The audit token of the process connected to `stream` (`getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`, `<sys/un.h>`). One way a caller gets a token to pass, used by these tests; not an entry point of procline.
fn token_of_connected(stream: &UnixStream) -> AuditToken {
    let mut token = [0u32; 8];
    let mut len = libc::socklen_t::try_from(size_of_val(&token)).unwrap();
    // SAFETY: `stream` is open for the call, and `token` is a writable 32-byte `audit_token_t`; `len` initially states that size and receives the actual byte count.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            (&raw mut token).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    assert_eq!(usize::try_from(len).unwrap(), size_of_val(&token));
    AuditToken(token)
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
const EXEC_SOCKET_PATH: &str = "PROCLINE_TEST_EXEC_SOCKET_PATH";

// This helper runs only when explicitly re-executed by a separate-process test. After connecting it signals readiness and waits for the parent; it must stay alive while the parent collects process attributes.
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

// This helper runs only when re-executed by `exec_after_the_token_is_identity_changed`. It connects and signals readiness like `connect_helper`, then, on the parent's byte, runs `exec` of /bin/cat in the same process with the stream as its stdin and stdout. cat writes back what the parent sends next, so a byte coming back means the `exec` is done (the new image is running); it then waits on the stream.
#[test]
fn connect_then_exec_helper() {
    let Some(path) = std::env::var_os(EXEC_SOCKET_PATH) else {
        return;
    };
    let mut stream = UnixStream::connect(path).unwrap();
    stream.write_all(&[1]).unwrap();
    let mut go = [0];
    stream.read_exact(&mut go).unwrap();
    let input = OwnedFd::from(stream.try_clone().unwrap());
    let err = Command::new("/bin/cat")
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(OwnedFd::from(stream)))
        .exec();
    panic!("exec of /bin/cat failed: {err}");
}

/// Spawns `exe` (this test binary or a copy) running `helper`, connected to a new listener, and returns it with the accepted stream once the helper signalled readiness.
fn spawn_connected(
    exe: &Path,
    helper: &str,
    path_var: &str,
) -> (Spawned, UnixStream, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("target.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let child = Spawned(
        Command::new(exe)
            .args(["--exact", helper])
            .env_clear()
            .env(path_var, &socket_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let (mut socket, _) = listener.accept().unwrap();
    let mut ready = [0];
    socket.read_exact(&mut ready).unwrap();
    (child, socket, dir)
}

// The token of this test process itself (a socketpair's other end is held by the process that made it). The audit token and audit session are set only on the target, the token on it is the one passed, its pid is correct, and its audit-token-based signature matches the pid-based signature of the same running code.
#[test]
fn own_token_identifies_own_process() {
    let (socket, _other) = UnixStream::pair().unwrap();
    let token = token_of_connected(&socket);
    let chain = collect_audit_token(token, &options()).unwrap();
    let me = &chain.processes()[0];
    let pid_chain = collect_pid(own_pid(), &options()).unwrap();
    assert_eq!(me.identity.pid, own_pid());
    assert_eq!(me.identity.audit_token, Some(token));
    assert!(me.identity.asid.is_some());
    assert_eq!(me.code_signing, pid_chain.processes()[0].code_signing);
    assert!(me.code_signing.is_some());
    assert!(
        chain.processes()[1..].iter().all(
            |process| process.identity.audit_token.is_none() && process.identity.asid.is_none()
        )
    );
}

// The token of another process (a child of this test). The target must be the child's pid, not this process's pid, and its code signature must be collected by that audit token.
#[test]
fn token_of_a_child_identifies_the_child() {
    let exe = std::env::current_exe().unwrap();
    let (child, socket, _dir) = spawn_connected(&exe, "connect_helper", SOCKET_PATH);
    let token = token_of_connected(&socket);
    let chain = collect_audit_token(token, &options()).unwrap();
    let target = &chain.processes()[0];
    assert_eq!(target.identity.pid, i32::try_from(child.0.id()).unwrap());
    assert_eq!(target.identity.audit_token, Some(token));
    assert!(target.identity.asid.is_some());
    assert_eq!(
        target.code_signing.as_ref().map(CodeSigning::mark),
        Some(Mark::Adhoc)
    );
    assert_ne!(target.identity.pid, own_pid());
}

// token を取った後に、対象のプロセスが exec する (同じ pid・同じ個体のまま、カーネルが pid version を増やす)。token は exec の前のイメージを指すので、対象を記録した時の pid version が token の pid version と違い、IdentityChanged で失敗する。この比較が無いと、token と食い違う行が Ok で返る: pid で読む属性 (実行パス、argv) は exec の後の /bin/cat を指し、署名は token が指す exec の前のイメージを引けずに Failed になる (macOS 26.5.2 で観測)。exec の完了は、送った 1 バイトを exec の後の cat が送り返すことで知る (時間待ちをしない)。
#[test]
fn exec_after_the_token_is_identity_changed() {
    let exe = std::env::current_exe().unwrap();
    let (child, mut socket, _dir) =
        spawn_connected(&exe, "connect_then_exec_helper", EXEC_SOCKET_PATH);
    let token = token_of_connected(&socket);
    socket.write_all(&[1]).unwrap();
    socket.write_all(b"x").unwrap();
    let mut echoed = [0];
    socket.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, *b"x");
    let pid = collect_pid(i32::try_from(child.0.id()).unwrap(), &options()).unwrap();
    assert_eq!(
        pid.processes()[0].path.as_deref(),
        Some(Path::new("/bin/cat"))
    );

    let result = collect_audit_token(token, &options());
    assert!(
        matches!(result, Err(CollectError::IdentityChanged)),
        "{:?}",
        result
            .as_ref()
            .map(|chain| chain.processes()[0].identity.pid)
    );
}

// token を取った後に、対象のプロセスが終わって回収される。その pid のプロセスはもう無いので NoSuchProcess (pid で集めた時と同じ)。終わった後の値や、空の列を返さない。回収の後にその pid を別のプロセスが使うのは、macOS が pid を順に払い出して一巡するまで起きない。
#[test]
fn exited_target_is_no_such_process() {
    let exe = std::env::current_exe().unwrap();
    let (mut child, socket, _dir) = spawn_connected(&exe, "connect_helper", SOCKET_PATH);
    let token = token_of_connected(&socket);
    let pid = i32::try_from(child.0.id()).unwrap();
    child.0.kill().unwrap();
    child.0.wait().unwrap();

    let result = collect_audit_token(token, &options());
    assert!(
        matches!(result, Err(CollectError::NoSuchProcess { pid: gone }) if gone == pid),
        "{:?}",
        result
            .as_ref()
            .map(|chain| chain.processes()[0].identity.pid)
    );
}

// 対象の実行ファイルを、token を取った後に別のファイル (/usr/bin/true のコピー) で rename して差し替える。通常の方法はディスク上の差し替えた先を見て -67034 で失敗するので、audit token のまま kSecGuestAttributeDynamicCode を足して、カーネルが持つ走っているコードの署名で検証し直す。結果は差し替える前のコード (このテストのバイナリのコピー) の身元で、verified_from は running_code。差し替えた先 (com.apple.true) の身元を対象の身元として返さないこと。コピーは一時ディレクトリに置き、テストの終わりに消える。
#[test]
fn replaced_target_is_verified_from_the_running_code() {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("target-copy");
    std::fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();
    let (child, socket, _socket_dir) = spawn_connected(&copy, "connect_helper", SOCKET_PATH);
    let token = token_of_connected(&socket);
    let replacement = dir.path().join("replacement");
    std::fs::copy("/usr/bin/true", &replacement).unwrap();
    std::fs::rename(&replacement, &copy).unwrap();

    let chain = collect_audit_token(token, &options()).unwrap();
    let target = &chain.processes()[0];
    assert_eq!(target.identity.pid, i32::try_from(child.0.id()).unwrap());
    let Some(CodeSigning::Verified(signature)) = &target.code_signing else {
        panic!("expected a verified signature: {:?}", target.code_signing);
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

// 対象の実行ファイルを、token を取った後に削除する。pid の側 (collect_pid の deleted_executable_is_failed_missing) と同じく、通常の方法が 100002 (実行ファイルが無い) で失敗し、pid ベースへの切り替えの対象 (100013 と -67034) ではないので、検証の結果は Failed(Missing) で、身元は持たない。削除は対象が接続して ready を送った後 (起動を終えた後) に行う。コピーは一時ディレクトリに置き、テストの終わりに消える。
#[test]
fn deleted_target_is_failed_missing() {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("target-copy");
    std::fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();
    let (child, socket, _socket_dir) = spawn_connected(&copy, "connect_helper", SOCKET_PATH);
    let token = token_of_connected(&socket);
    std::fs::remove_file(&copy).unwrap();

    let chain = collect_audit_token(token, &options()).unwrap();
    let target = &chain.processes()[0];
    assert_eq!(target.identity.pid, i32::try_from(child.0.id()).unwrap());
    assert_eq!(
        target.code_signing,
        Some(CodeSigning::Failed(FailureReason::Missing))
    );
}
