//! Walking from a process to launchd, and keeping the result consistent with the processes it describes.

use std::collections::HashMap;
use std::io;
use std::os::fd::BorrowedFd;

use procline_core::{
    AuditToken, Credentials, Identity, NamedId, ProcessChain, ProcessIdentity, ProcessInfo,
    StartTime, Truncated,
};

use crate::sys::peer;
use crate::sys::proc::{self as sys, KinfoProc, UniqueIds};
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

/// Names of uids and gids, looked up once per collection.
#[derive(Default)]
struct Names {
    users: HashMap<u32, Vec<String>>,
    groups: HashMap<u32, Vec<String>>,
}

impl Names {
    fn user(&mut self, uid: u32) -> NamedId {
        let names = self
            .users
            .entry(uid)
            .or_insert_with(|| sys::user_name(uid).into_iter().collect());
        NamedId {
            id: uid,
            names: names.clone(),
        }
    }

    fn group(&mut self, gid: u32) -> NamedId {
        let names = self
            .groups
            .entry(gid)
            .or_insert_with(|| sys::group_name(gid).into_iter().collect());
        NamedId {
            id: gid,
            names: names.clone(),
        }
    }
}

/// uid, gid and groups of the credential. Each id carries the one name `getpwuid_r` / `getgrgid_r` resolve it to. `groups` is the credential's group list as the kernel reports it (at most 16, the effective gid first).
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
        code_signing: match peer_token {
            Some(token) => signing::code_signing_for_peer(token),
            None => signing::code_signing(pid),
        },
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
    let pid = target.pid;
    let (records, mut truncated) = walk(target, options.max_ancestors);
    let mut names = Names::default();
    let mut processes: Vec<ProcessInfo> = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            process_info(
                record,
                boot_uuid,
                options,
                &mut names,
                if index == 0 { peer_token } else { None },
            )
        })
        .collect();

    // Everything except the peer signature was read by pid, which another process can take over once the recorded one exits; rechecking the identifiers rejects mixed-up data.
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
                    return Err(CollectError::NoSuchProcess { pid });
                }
                _ => return Err(CollectError::IdentityChanged),
            }
        } else if !now.is_ok_and(|now| record.same_individual(&now)) {
            processes.truncate(index);
            truncated = Some(Truncated::AncestorExited);
            break;
        }
    }
    Ok(ProcessChain::new(
        processes,
        boot_uuid.to_owned(),
        truncated,
    ))
}
