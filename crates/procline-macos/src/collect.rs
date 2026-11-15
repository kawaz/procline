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
    ///
    /// The pid version comes with the unique IDs; when they could not be read for either record (`ids` is `None`, the SPI unavailable), an `exec` in between is not detected and this is `same_individual` alone.
    fn same_image(&self, other: &Self) -> bool {
        let versions_agree = match (self.ids, other.ids) {
            (Some(a), Some(b)) => a.id_version == b.id_version,
            _ => true,
        };
        self.same_individual(other) && versions_agree
    }

    /// `self` is the process that `child` names as its parent, not another process that took over the parent's pid after it exited, nor launchd standing in for a parent that exited. Compared by unique ID when both have it, else by the parent having started no later than the child.
    ///
    /// When both have the unique IDs and `self` is launchd, the child must also have been forked by this launchd: its original parent's pid version equals launchd's pid version. A process whose parent exited is reparented to launchd and keeps the unique ID of the exited parent as its parent's, until it runs `exec`: the kernel then rewrites the parent's unique ID with launchd's, and only the original parent's pid version still names the exited parent (`p_orig_ppidversion`, which the kernel sets at the `fork` and keeps through `exec`; equal to launchd's pid version for every process launchd started that was observed, and not for a process that ran `exec` after reparenting, on macOS 26.5.2). Without the unique IDs this is not checked, and a reparented process links to launchd (launchd started before it).
    ///
    /// Design rationale: the pid versions are compared only when the parent is launchd. A parent other than launchd may have run `exec` after forking the child, which gives it a new pid version while the child keeps the one from the fork, so the versions of a real parent and child need not agree; the unique IDs already link them. A process whose parent exits is reparented to launchd, so a parent other than launchd that the unique IDs name is the process that forked the child (or, after an `exec` of the child, its parent at that `exec`).
    fn is_parent_of(&self, child: &Self) -> bool {
        match (self.ids, child.ids) {
            (Some(parent), Some(child_ids)) => {
                parent.unique_id == child_ids.parent_unique_id
                    && (!is_launchd(self.pid)
                        || child_ids.orig_parent_id_version == parent.id_version)
            }
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

/// launchd, which the kernel makes the parent of every process whose parent exited.
fn is_launchd(pid: i32) -> bool {
    pid == 1
}

/// Records the target and its ancestors up to the root, stopping early at `max_ancestors` ancestors, at an ancestor that cannot be read, or where the parent has exited (`AncestorExited`, also when the process was reparented to launchd: see `is_parent_of`).
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
        bundle: if options.bundle {
            path.as_deref().and_then(file::bundle)
        } else {
            None
        },
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
                // Classified as in `walk`: another individual at the pid, or no process at it, means the recorded ancestor exited; any other failure to read it is unavailable.
                Ok(_) => {
                    processes.truncate(index);
                    truncated = Some(Truncated::AncestorExited);
                    break;
                }
                Err(err) => {
                    processes.truncate(index);
                    truncated = Some(if is_no_such_process(&err) {
                        Truncated::AncestorExited
                    } else {
                        Truncated::Unavailable
                    });
                    break;
                }
            }
        }
    }
    Ok(ProcessChain::from_collected(
        processes,
        boot_uuid.to_owned(),
        truncated,
    ))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::AsFd;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, ChildStdin, Command, Stdio};

    use procline_core::{CodeSigning, EnvPolicy, ProcessChain, Redaction, Truncated};

    use super::{Recorded, describe_and_recheck, signatures, walk};
    use crate::sys::proc as sys;
    use crate::sys::test_support::{
        Arrival, ProcessEvent, ProcessWatch, kill_process_group, make_fifo,
        wait_connection_or_exit, wait_exited_unreaped,
    };
    use crate::{CollectError, CollectOptions};

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
            make_fifo(&fifo).unwrap();
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

        /// Lets sh run `exec /bin/sleep` and returns once the exec is done. The kqueue is registered before sh is let go, so the event is not missed; sh exiting without the exec fails the test instead of leaving it waiting.
        fn exec_sh(&mut self) {
            let watch = ProcessWatch::new(self.sh_pid()).unwrap();
            self.stdin.write_all(b"\n").unwrap();
            self.stdin.flush().unwrap();
            assert_eq!(
                watch.wait().unwrap(),
                ProcessEvent::Exec,
                "sh exited without running exec"
            );
        }

        /// Kills sh and reaps it, so its pid no longer names it. The target stays, reparented to launchd.
        fn end_sh(&mut self) {
            self.sh.kill().unwrap();
            self.sh.wait().unwrap();
        }

        /// Kills sh and leaves it unreaped (a zombie): this test is its parent and does not collect it until the value is dropped.
        fn zombify_sh(&mut self) {
            zombify(&mut self.sh);
        }
    }

    /// Kills the child and returns once it has exited, without reaping it, so it stays a zombie until `Child::wait`.
    fn zombify(child: &mut Child) {
        child.kill().unwrap();
        wait_exited_unreaped(child.id()).unwrap();
    }

    /// `/usr/bin/nc` connected to a socket this test listens on: a direct child of this test, so it stays a zombie when killed until it is reaped, and the accepted stream gives its audit token. The connection is made by nc itself, so its `exec` is done once it is accepted. Dropping the value kills and reaps it.
    struct Connected {
        child: Child,
        stream: std::os::unix::net::UnixStream,
        _dir: tempfile::TempDir,
    }

    impl Connected {
        /// Returns once nc's connection is accepted; fails instead of waiting on when nc exits without connecting.
        fn start() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("s");
            let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            let child = Command::new("/usr/bin/nc")
                .arg("-U")
                .arg(&path)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            // Owned by the value before accepting, so the child is killed also when accepting fails; the placeholder stream is replaced by the accepted one.
            let mut connected = Self {
                child,
                stream: std::os::unix::net::UnixStream::pair().unwrap().0,
                _dir: dir,
            };
            let arrival = wait_connection_or_exit(listener.as_fd(), connected.pid()).unwrap();
            assert_eq!(arrival, Arrival::Connection, "nc exited without connecting");
            connected.stream = listener.accept().unwrap().0;
            connected
        }

        fn pid(&self) -> i32 {
            i32::try_from(self.child.id()).unwrap()
        }
    }

    impl Drop for Connected {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Drop for Family {
        fn drop(&mut self) {
            // The group keeps sh's pid as its id while the target is in it, also after sh was reaped, so the signal does not reach another process.
            let _ = kill_process_group(self.sh_pid());
            let _ = self.sh.wait();
        }
    }

    /// Collects the chain of the target (the target and sh, cut at `max_ancestors` 1) with `between` run after the signatures are verified and before the other attributes are read. Returns the verified signatures with the result.
    fn collect_with(
        family: &mut Family,
        between: impl FnOnce(&mut Family),
    ) -> (Vec<Option<CodeSigning>>, Result<ProcessChain, CollectError>) {
        let options = options();
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

    /// Signatures on, nothing else optional, the target and one ancestor.
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
            max_ancestors: 1,
        }
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
        assert_eq!(unchanged.truncated(), Some(Truncated::MaxAncestors));

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
        assert_eq!(exit.truncated(), Some(Truncated::AncestorExited));
    }

    // 終了して親にまだ回収されていないプロセス (zombie) は、終わったプロセスとして扱う。カーネルは zombie についても kinfo_proc を返し、起動時刻は生前と同じなので、起動時刻で個体を見ると生きている祖先と区別できない (unique ID は読めず、SPI が無い時と同じ None になる)。kinfo_proc の p_stat が SZOMB なら「そのプロセスは無い」(ESRCH) とし、回収済みのプロセスと同じ分岐に乗せる: 祖先なら列をその手前で AncestorExited で終える (祖先は途中で終了していることがあり、途切れたと分かる形で列を終える)。
    // 時機は 2 つ (このテストと次のテスト): 対象を記録した後・親を読む前 (walk の前) と、署名を検証した後・最後の確かめ直しの前。どちらも sh を kill して waitid(WNOWAIT) で終了を待ち、回収しない (このテストが sh の親。時間待ちをしない)。zombie として扱わないと、前者は親として受け入れ (unique ID なし・署名は failed・path なし)、後者は生前の unique ID と署名を持った行を途切れの印なしで返していた。
    #[test]
    fn a_zombie_ancestor_before_the_walk_ends_the_chain() {
        let mut family = Family::start();
        let target = Recorded::read(family.target).unwrap();
        family.zombify_sh();
        let (records, truncated) = walk(target, 1);
        assert_eq!(
            records.iter().map(|r| r.pid).collect::<Vec<_>>(),
            [family.target]
        );
        assert_eq!(truncated, Some(Truncated::AncestorExited));
    }

    // 上と同じ規則の、もう 1 つの時機: 署名を検証した後・最後の確かめ直しの前に祖先が zombie になる。
    #[test]
    fn a_zombie_ancestor_after_the_signatures_ends_the_chain() {
        let mut family = Family::start();
        let (_, result) = collect_with(&mut family, Family::zombify_sh);
        let chain = result.unwrap();
        assert_eq!(
            chain
                .processes()
                .iter()
                .map(|p| p.identity.pid)
                .collect::<Vec<_>>(),
            [family.target]
        );
        assert_eq!(chain.truncated(), Some(Truncated::AncestorExited));
    }

    // 対象 (列の先頭) が収集の途中で zombie になったら、回収されて消えた時と同じエラー: pid で集めた時は NoSuchProcess (その pid のプロセスはもう無い)、接続相手は IdentityChanged (接続を記録した個体が、収集の終わりにはもういない)。生前の値で Ok を返さない。対象は nc で、このテストの直接の子なので、kill して waitid(WNOWAIT) で待てば回収されずに残る。時機は署名を検証した後・最後の確かめ直しの前。
    #[test]
    fn a_target_that_became_a_zombie_is_gone() {
        let options = options();
        let boot_uuid = sys::boot_session_uuid().unwrap();
        for peer in [false, true] {
            let mut connected = Connected::start();
            let pid = connected.pid();
            let peer_token =
                peer.then(|| crate::sys::peer::peer_token(connected.stream.as_fd()).unwrap());
            let (records, truncated) = walk(Recorded::read(pid).unwrap(), 1);
            let verified = signatures(&records, &options, peer_token);
            zombify(&mut connected.child);
            let result = describe_and_recheck(
                &records, truncated, verified, &boot_uuid, &options, peer_token,
            );
            match (peer, result) {
                (false, Err(CollectError::NoSuchProcess { pid: gone })) => assert_eq!(gone, pid),
                (true, Err(CollectError::IdentityChanged)) => {}
                (peer, result) => panic!("peer {peer}: {}", outline(&result)),
            }
        }
    }

    /// The kind of a collection result and the pids of its chain, for a failure message without the certificate bytes of the whole chain.
    fn outline(result: &Result<ProcessChain, CollectError>) -> String {
        match result {
            Ok(chain) => format!(
                "Ok, pids {:?}, truncated {:?}",
                chain
                    .processes()
                    .iter()
                    .map(|p| p.identity.pid)
                    .collect::<Vec<_>>(),
                chain.truncated()
            ),
            Err(err) => format!("Err({err:?})"),
        }
    }
}
