//! UNIX domain socket peers, including the identity of a child process connected from another process.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};

use procline_core::{EnvPolicy, Redaction};
use procline_macos::{CollectError, CollectOptions, collect_peer, collect_pid};

fn options() -> CollectOptions {
    CollectOptions {
        env: EnvPolicy::None,
        redaction: Redaction::default(),
        icon: false,
        digest: false,
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
    assert!(peer.code_signing.is_some());
    assert_ne!(peer.identity.pid, own_pid());
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
