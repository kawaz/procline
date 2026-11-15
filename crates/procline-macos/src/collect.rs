//! Walking from a process to launchd, and keeping the result consistent with the processes it describes.

use std::collections::HashMap;
use std::io;
use std::os::fd::BorrowedFd;

use procline_core::{
    AuditToken, CodeSigning, Credentials, Identity, NamedId, ProcessChain, ProcessIdentity,
    ProcessInfo, StartTime, Truncated,
};

use crate::sys::peer;
use crate::sys::proc::{self as sys, KinfoProc, UniqueIds};
use crate::sys::security::Guest;
use crate::{CollectError, CollectOptions, file, path_meta, procargs, signing};

/// The identifiers of one process, recorded before anything else about it is read.
struct Recorded {
    pid: i32,
    kinfo: KinfoProc,
    /// `None` when the SPI is unavailable; the start time then identifies the process with the pid.
    ids: Option<UniqueIds>,
}

impl Recorded {
    fn read(pid: i32) -> io::Result<Self> {
        let kinfo = sys::kinfo_proc(pid)?;
        Ok(Self {
            pid,
            kinfo,
            ids: sys::unique_ids(pid).ok(),
        })
    }

    fn start_time(&self) -> StartTime {
        StartTime {
            secs: self.kinfo.start_secs,
            micros: self.kinfo.start_micros,
        }
    }

    fn unique_id(&self) -> Option<u64> {
        self.ids.map(|ids| ids.unique_id)
    }

    fn identity(&self) -> Identity {
        Identity {
            audit_token: None,
            unique_id: self.unique_id(),
            parent_unique_id: self.ids.map(|ids| ids.parent_unique_id),
            pid: self.pid,
            start_time: Some(self.start_time()),
            asid: None,
        }
    }

    /// Both describe the same individual process: the start time and, when both have it, the unique ID are equal. An `exec` keeps the individual.
    fn same_individual(&self, other: &Self) -> bool {
        let unique_ids_agree = match (self.unique_id(), other.unique_id()) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        };
        self.pid == other.pid && self.start_time() == other.start_time() && unique_ids_agree
    }

    /// The same individual still runs the same image: no `exec` happened in between (the pid version is bumped by every `exec`).
    fn same_image(&self, other: &Self) -> bool {
        let versions_agree = match (self.ids, other.ids) {
            (Some(a), Some(b)) => a.id_version == b.id_version,
            _ => true,
        };
        self.same_individual(other) && versions_agree
    }

    /// `self` is the process that `child` names as its parent, not another process that took over the parent's pid after it exited. Compared by unique ID when both have it, else by the parent having started no later than the child.
    fn is_parent_of(&self, child: &Self) -> bool {
        match (self.unique_id(), child.ids.map(|ids| ids.parent_unique_id)) {
            (Some(id), Some(parent_id)) => id == parent_id,
            _ => self.start_time() <= child.start_time(),
        }
    }
}

fn is_no_such_process(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::ESRCH)
}

/// Pids at which the walk has reached the root: launchd (1), and the kernel (0) for a walk that starts there.
fn is_root(pid: i32) -> bool {
    pid <= 1
}

/// Records the target and its ancestors up to the root, stopping early at `max_ancestors` ancestors or at an ancestor that cannot be read.
fn walk(target: Recorded, max_ancestors: usize) -> (Vec<Recorded>, Option<Truncated>) {
    let mut chain = vec![target];
    loop {
        // The chain starts with the target and only grows, so it has a last element.
        let current = &chain[chain.len() - 1];
        if is_root(current.pid) {
            return (chain, None);
        }
        if chain.len() > max_ancestors {
            return (chain, Some(Truncated::MaxAncestors));
        }
        let parent = match Recorded::read(current.kinfo.ppid) {
            Ok(parent) => parent,
            Err(err) if is_no_such_process(&err) => {
                return (chain, Some(Truncated::AncestorExited));
            }
            Err(_) => return (chain, Some(Truncated::Unavailable)),
        };
        if !parent.is_parent_of(current) {
            return (chain, Some(Truncated::AncestorExited));
        }
        chain.push(parent);
    }
}

/// Name resolution for one collection. The representative name comes from `getpwuid_r` / `getgrgid_r`; the complete name lists come from one enumeration of the user and group databases, done the first time a complete list is needed (`CollectOptions.all_names`).
#[derive(Default)]
struct Names {
    users: HashMap<u32, Option<String>>,
    groups: HashMap<u32, Option<String>>,
    all_users: Option<HashMap<u32, Vec<String>>>,
    all_groups: Option<HashMap<u32, Vec<String>>>,
    all_names: bool,
}

impl Names {
    fn new(all_names: bool) -> Self {
        Self {
            all_names,
            ..Self::default()
        }
    }

    fn user(&mut self, uid: u32) -> NamedId {
        let name = self
            .users
            .entry(uid)
            .or_insert_with(|| sys::user_name(uid))
            .clone();
        let names = if self.all_names {
            with_representative(
                self.all_users
                    .get_or_insert_with(sys::all_user_names)
                    .get(&uid)
                    .cloned()
                    .unwrap_or_default(),
                &name,
            )
        } else {
            name.iter().cloned().collect()
        };
        NamedId {
            id: uid,
            name,
            names,
        }
    }

    fn group(&mut self, gid: u32) -> NamedId {
        let name = self
            .groups
            .entry(gid)
            .or_insert_with(|| sys::group_name(gid))
            .clone();
        let names = if self.all_names {
            with_representative(
                self.all_groups
                    .get_or_insert_with(sys::all_group_names)
                    .get(&gid)
                    .cloned()
                    .unwrap_or_default(),
                &name,
            )
        } else {
            name.iter().cloned().collect()
        };
        NamedId {
            id: gid,
            name,
            names,
        }
    }
}

/// The enumerated names with the representative name added when the enumeration did not list it (an id that a directory service resolves but does not enumerate).
fn with_representative(mut names: Vec<String>, representative: &Option<String>) -> Vec<String> {
    if let Some(name) = representative
        && !names.contains(name)
    {
        names.insert(0, name.clone());
    }
    names
}

/// uid, gid and groups of the credential. Each id carries its representative name and, with `all_names`, every name that resolves to it. `groups` is the credential's group list as the kernel reports it (at most 16, the effective gid first).
fn credentials(kinfo: &KinfoProc, names: &mut Names) -> Option<Credentials> {
    let gid = *kinfo.groups.first()?;
    Some(Credentials {
        uid: names.user(kinfo.uid),
        gid: names.group(gid),
        groups: kinfo.groups.iter().map(|&g| names.group(g)).collect(),
    })
}

fn process_info(
    record: &Recorded,
    boot_uuid: &str,
    options: &CollectOptions,
    names: &mut Names,
    peer_token: Option<AuditToken>,
    code_signing: Option<CodeSigning>,
) -> ProcessInfo {
    let pid = record.pid;
    let path = sys::pid_path(pid).ok();
    let args = sys::procargs2(pid)
        .ok()
        .and_then(|area| procargs::parse(&area));
    let (argv, env) = match args {
        Some(args) => (
            Some(args.argv),
            args.env
                .and_then(|env| procargs::select_env(env, &options.env, &options.redaction)),
        ),
        None => (None, None),
    };
    let name = sys::bsd_name(pid).or_else(|| {
        let comm = record.kinfo.comm.clone();
        (!comm.is_empty()).then_some(comm)
    });
    let mut identity = record.identity();
    if let Some(token) = peer_token {
        identity.audit_token = Some(token);
        identity.asid = Some(peer::asid(token));
    }
    ProcessInfo {
        identity,
        credentials: credentials(&record.kinfo, names),
        code_signing,
        path_meta: path
            .as_deref()
            .and_then(|p| path_meta::path_meta(p, record.kinfo.uid, &record.kinfo.groups)),
        digest: if options.digest {
            path.as_deref().and_then(|p| file::sha256(p).ok())
        } else {
            None
        },
        bundle: path.as_deref().and_then(file::bundle),
        responsible: responsible(pid, boot_uuid),
        name,
        argv,
        cwd: sys::cwd(pid).ok(),
        tty: record.kinfo.tty_dev.and_then(sys::tty_name),
        env,
        icon_png: None,
        path,
    }
}

/// The individual responsible for `pid`, identified when its pid is looked up.
fn responsible(pid: i32, boot_uuid: &str) -> Option<ProcessIdentity> {
    let responsible = Recorded::read(sys::responsible_pid(pid)?).ok()?;
    Some(responsible.identity().process_identity(boot_uuid))
}

pub(crate) fn collect_pid(
    pid: i32,
    options: &CollectOptions,
) -> Result<ProcessChain, CollectError> {
    let boot_uuid = sys::boot_session_uuid().map_err(CollectError::BootUuid)?;
    let target = read_target(pid)?;
    collect_recorded(target, &boot_uuid, options, None)
}

/// Capture the socket identity before reading any process attributes. The token's pid version ties the pid-based reads to the same executable image used by the audit-token-based signature lookup.
pub(crate) fn collect_peer(
    fd: BorrowedFd<'_>,
    options: &CollectOptions,
) -> Result<ProcessChain, CollectError> {
    let token = peer::peer_token(fd).map_err(CollectError::Peer)?;
    let pid = peer::pid(token);
    let boot_uuid = sys::boot_session_uuid().map_err(CollectError::BootUuid)?;
    let target = read_target(pid)?;
    if target
        .ids
        .is_some_and(|ids| ids.id_version != peer::pidversion(token))
    {
        return Err(CollectError::IdentityChanged);
    }
    let chain = collect_recorded(target, &boot_uuid, options, Some(token))?;
    if peer::peer_token(fd).ok() != Some(token) {
        return Err(CollectError::IdentityChanged);
    }
    Ok(chain)
}

fn read_target(pid: i32) -> Result<Recorded, CollectError> {
    Recorded::read(pid).map_err(|source| {
        if is_no_such_process(&source) {
            CollectError::NoSuchProcess { pid }
        } else {
            CollectError::Unreadable { pid, source }
        }
    })
}

fn collect_recorded(
    target: Recorded,
    boot_uuid: &str,
    options: &CollectOptions,
    peer_token: Option<AuditToken>,
) -> Result<ProcessChain, CollectError> {
    let (records, truncated) = walk(target, options.max_ancestors);
    let signatures = signatures(&records, options, peer_token);
    describe_and_recheck(
        &records, truncated, signatures, boot_uuid, options, peer_token,
    )
}

/// The code signature of every recorded process, in order, or all `None` when signatures are not collected. The peer's signature is addressed by its audit token, so a process that took over its pid is not verified in its place.
fn signatures(
    records: &[Recorded],
    options: &CollectOptions,
    peer_token: Option<AuditToken>,
) -> Vec<Option<CodeSigning>> {
    if !options.signature {
        return vec![None; records.len()];
    }
    let guests: Vec<Guest> = records
        .iter()
        .enumerate()
        .map(|(index, record)| match peer_token {
            Some(token) if index == 0 => Guest::AuditToken(token),
            _ => Guest::Pid(record.pid),
        })
        .collect();
    signing::verify_chain(&guests, options.signature_budget)
        .into_iter()
        .map(Some)
        .collect()
}

/// Reads the other attributes of the recorded processes, then reads their identifiers again and keeps the result only if it describes the processes that were recorded.
fn describe_and_recheck(
    records: &[Recorded],
    mut truncated: Option<Truncated>,
    signatures: Vec<Option<CodeSigning>>,
    boot_uuid: &str,
    options: &CollectOptions,
    peer_token: Option<AuditToken>,
) -> Result<ProcessChain, CollectError> {
    let mut names = Names::new(options.all_names);
    let mut processes: Vec<ProcessInfo> = records
        .iter()
        .zip(signatures)
        .enumerate()
        .map(|(index, (record, code_signing))| {
            process_info(
                record,
                boot_uuid,
                options,
                &mut names,
                if index == 0 { peer_token } else { None },
                code_signing,
            )
        })
        .collect();

    // Everything except the peer signature was read by pid, which another process can take over once the recorded one exits; rechecking the identifiers rejects mixed-up data. An ancestor that exited ends the chain before it; an ancestor that is still the same individual but ran `exec` in between makes the whole result unusable, since its signature, path and arguments may describe different images.
    for (index, record) in records.iter().enumerate() {
        let now = Recorded::read(record.pid);
        if index == 0 {
            match now {
                Ok(now)
                    if record.same_image(&now)
                        && peer_token.is_none_or(|token| {
                            now.ids
                                .is_none_or(|ids| ids.id_version == peer::pidversion(token))
                        }) => {}
                Err(err) if is_no_such_process(&err) && peer_token.is_none() => {
                    return Err(CollectError::NoSuchProcess { pid: record.pid });
                }
                _ => return Err(CollectError::IdentityChanged),
            }
        } else {
            match now {
                Ok(now) if record.same_image(&now) => {}
                Ok(now) if record.same_individual(&now) => {
                    return Err(CollectError::IdentityChanged);
                }
                _ => {
                    processes.truncate(index);
                    truncated = Some(Truncated::AncestorExited);
                    break;
                }
            }
        }
    }
    Ok(ProcessChain::new(
        processes,
        boot_uuid.to_owned(),
        truncated,
    ))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, ChildStdin, Command, Stdio};

    use procline_core::{CodeSigning, EnvPolicy, ProcessChain, Redaction, Truncated};

    use super::{Recorded, describe_and_recheck, signatures, walk};
    use crate::sys::proc as sys;
    use crate::{CollectError, CollectOptions};

    /// Waits for `exec` of one process with a kqueue (`EVFILT_PROC`, `NOTE_EXEC`), without polling. Registered before the `exec` is triggered, so the event is not missed.
    struct ExecWatch(i32);

    impl ExecWatch {
        fn new(pid: i32) -> Self {
            // SAFETY: kqueue takes no arguments and returns a new descriptor or -1.
            let kq = unsafe { libc::kqueue() };
            assert!(kq >= 0);
            let change = libc::kevent {
                ident: usize::try_from(pid).unwrap(),
                filter: libc::EVFILT_PROC,
                flags: libc::EV_ADD | libc::EV_ONESHOT,
                fflags: libc::NOTE_EXEC,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            // SAFETY: one change from a valid kevent, no events asked for.
            let n =
                unsafe { libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
            assert_eq!(n, 0);
            Self(kq)
        }

        fn wait(&self) {
            let mut event = libc::kevent {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            // SAFETY: room for one event, no timeout (blocks until the exec).
            let n = unsafe {
                libc::kevent(self.0, std::ptr::null(), 0, &mut event, 1, std::ptr::null())
            };
            assert_eq!(n, 1);
            assert_ne!(event.fflags & libc::NOTE_EXEC, 0);
        }
    }

    impl Drop for ExecWatch {
        fn drop(&mut self) {
            // SAFETY: the descriptor is owned by this value.
            unsafe { libc::close(self.0) };
        }
    }

    /// `/bin/sh` and the target: a subshell of sh that only forks, never runs `exec`, and stays blocked opening a FIFO nobody writes to. So the only `exec` and the only exit while a chain is collected are the ones the test makes sh do. sh leads its own process group; dropping the value kills the group (both processes) and reaps sh, also when an assertion failed.
    struct Family {
        sh: Child,
        stdin: ChildStdin,
        target: i32,
        _fifo_dir: tempfile::TempDir,
    }

    impl Family {
        fn start() -> Self {
            let fifo_dir = tempfile::tempdir().unwrap();
            let fifo = fifo_dir.path().join("never-written");
            let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: a NUL-terminated path in a directory this test owns.
            assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
            let mut sh = Command::new("/bin/sh")
                .args([
                    "-c",
                    "( read never < \"$1\" ) & echo $!; read line; exec /bin/sleep 60",
                    "sh",
                ])
                .arg(&fifo)
                .process_group(0)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let stdin = sh.stdin.take().unwrap();
            let stdout = sh.stdout.take().unwrap();
            let mut family = Self {
                sh,
                stdin,
                target: 0,
                _fifo_dir: fifo_dir,
            };
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).unwrap();
            family.target = line.trim().parse().unwrap();
            family
        }

        fn sh_pid(&self) -> i32 {
            i32::try_from(self.sh.id()).unwrap()
        }

        /// Lets sh run `exec /bin/sleep` and returns once the exec is done. The kqueue is registered before sh is let go, so the event is not missed.
        fn exec_sh(&mut self) {
            let watch = ExecWatch::new(self.sh_pid());
            self.stdin.write_all(b"\n").unwrap();
            self.stdin.flush().unwrap();
            watch.wait();
        }

        /// Kills sh and reaps it, so its pid no longer names it. The target stays, reparented to launchd.
        fn end_sh(&mut self) {
            self.sh.kill().unwrap();
            self.sh.wait().unwrap();
        }
    }

    impl Drop for Family {
        fn drop(&mut self) {
            // The group keeps sh's pid as its id while the target is in it, also after sh was reaped, so the signal does not reach another process.
            // SAFETY: killpg only sends a signal.
            unsafe { libc::killpg(self.sh_pid(), libc::SIGKILL) };
            let _ = self.sh.wait();
        }
    }

    /// Collects the chain of the target (the target and sh, cut at `max_ancestors` 1) with `between` run after the signatures are verified and before the other attributes are read. Returns the verified signatures with the result.
    fn collect_with(
        family: &mut Family,
        between: impl FnOnce(&mut Family),
    ) -> (Vec<Option<CodeSigning>>, Result<ProcessChain, CollectError>) {
        let options = CollectOptions {
            env: EnvPolicy::None,
            redaction: Redaction::default(),
            icon: false,
            digest: false,
            signature: true,
            signature_budget: None,
            all_names: false,
            max_ancestors: 1,
        };
        let boot_uuid = sys::boot_session_uuid().unwrap();
        let (records, truncated) = walk(Recorded::read(family.target).unwrap(), 1);
        assert_eq!(
            records.iter().map(|r| r.pid).collect::<Vec<_>>(),
            [family.target, family.sh_pid()]
        );
        let verified = signatures(&records, &options, None);
        between(family);
        let result = describe_and_recheck(
            &records,
            truncated,
            verified.clone(),
            &boot_uuid,
            &options,
            None,
        );
        (verified, result)
    }

    fn identifier(signing: Option<&CodeSigning>) -> Option<&str> {
        match signing {
            Some(CodeSigning::Verified(signature)) => Some(&signature.identifier),
            _ => None,
        }
    }

    // 収集の最後の確かめ直しで、祖先に起きた変化を 3 通りに分ける。対象は sh の子のサブシェル、祖先は sh。sh を動かすのは、署名を検証した後・ほかの属性を読む前で、祖先が exec すると「署名は exec の前のイメージ、実行パスと argv は後のイメージ」という混ざった結果ができる時機。
    // - 何も起きない: 列はそのまま (対象と sh の 2 つで、max_ancestors で途切れる)。
    // - sh が exec する: 同じ個体のまま、pid version (exec のたびにカーネルが増やす) だけが変わる。結果を捨てて IdentityChanged にする。列を sh の手前で途切れさせて残りを返すのではない: sh は生きていて親子関係は本物なので、途切れさせると「祖先が終わった」と偽ることになる。集め直せば (exec の後の像だけを読むので) 通り、sh は /bin/sleep として、exec の前に検証したものとは別の署名で出る (= 捨てた結果は 2 つのイメージが混ざっていた)。
    // - sh が終わって回収される: その pid はもう sh を指さない。列を sh の手前で AncestorExited で終える (祖先が途中で終わるのは普通に起きる)。
    // 時機は収集の段の間で sh を動かして作る。exec の完了は kqueue の NOTE_EXEC、終了は wait で待つ (時間待ちをしない)。
    #[test]
    fn the_recheck_tells_an_ancestor_exec_from_an_ancestor_exit() {
        let mut family = Family::start();
        let (_, unchanged) = collect_with(&mut family, |_| {});
        let unchanged = unchanged.unwrap();
        assert_eq!(unchanged.processes().len(), 2);
        assert_eq!(unchanged.truncated, Some(Truncated::MaxAncestors));

        let mut family = Family::start();
        let (verified, exec) = collect_with(&mut family, Family::exec_sh);
        assert!(
            matches!(exec, Err(CollectError::IdentityChanged)),
            "{exec:?}"
        );
        let (_, again) = collect_with(&mut family, |_| {});
        let again = again.unwrap();
        assert_eq!(
            again.processes()[1].path.as_deref(),
            Some(Path::new("/bin/sleep"))
        );
        let before = identifier(verified[1].as_ref()).unwrap();
        let after = identifier(again.processes()[1].code_signing.as_ref()).unwrap();
        assert_ne!(before, after);

        let mut family = Family::start();
        let (_, exit) = collect_with(&mut family, Family::end_sh);
        let exit = exit.unwrap();
        assert_eq!(exit.processes().len(), 1);
        assert_eq!(exit.processes()[0].identity.pid, family.target);
        assert_eq!(exit.truncated, Some(Truncated::AncestorExited));
    }
}
