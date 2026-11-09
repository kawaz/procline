//! BSD process information: `sysctl`, `proc_pidinfo`, `proc_pidpath`, and the passwd / group / tty name lookups.

use std::collections::HashMap;
use std::ffi::{CStr, OsStr, c_char, c_int};
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::Mutex;

/// The fields of `struct kinfo_proc` the collector reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KinfoProc {
    pub ppid: i32,
    /// Effective uid (`e_ucred.cr_uid`).
    pub uid: u32,
    /// `e_ucred.cr_groups[..cr_ngroups]`; the first entry is the effective gid. The kernel copies at most `NGROUPS` (16).
    pub groups: Vec<u32>,
    pub start_secs: u64,
    pub start_micros: u32,
    /// `p_comm`, at most `MAXCOMLEN` (16) bytes.
    pub comm: String,
    /// The controlling terminal device, when the process has one.
    pub tty_dev: Option<libc::dev_t>,
}

/// Layout of `struct kinfo_proc` on macOS (`<sys/sysctl.h>` `struct kinfo_proc`, `<sys/proc.h>` `struct extern_proc`).
///
/// Design rationale: the struct has some 60 fields, most of them kernel pointers this crate never reads, and libc has no definition for Apple targets. Instead of copying the whole definition, the sysctl fills a byte buffer of the struct's size and the few fields are read at their offsets. The size and offsets were measured with `sizeof` / `offsetof` by compiling the SDK headers (MacOSX 26 SDK, arm64); `kinfo_proc` is the ABI `ps(1)` has relied on for decades, so it does not move.
mod kinfo {
    pub const SIZE: usize = 648;
    /// `kp_proc.p_un.__p_starttime.tv_sec` (`long`).
    pub const START_SEC: usize = 0;
    /// `kp_proc.p_un.__p_starttime.tv_usec` (`suseconds_t`, 32 bit).
    pub const START_USEC: usize = 8;
    /// `kp_proc.p_comm` (`char[MAXCOMLEN + 1]`).
    pub const COMM: usize = 243;
    pub const COMM_LEN: usize = 17;
    /// `kp_eproc.e_ucred.cr_uid`.
    pub const CR_UID: usize = 420;
    /// `kp_eproc.e_ucred.cr_ngroups` (`short`).
    pub const CR_NGROUPS: usize = 424;
    /// `kp_eproc.e_ucred.cr_groups` (`gid_t[NGROUPS]`).
    pub const CR_GROUPS: usize = 428;
    pub const NGROUPS: usize = 16;
    /// `kp_eproc.e_ppid`.
    pub const PPID: usize = 560;
    /// `kp_eproc.e_tdev` (`dev_t`).
    pub const TDEV: usize = 572;
    /// `kp_eproc.e_flag`.
    pub const FLAG: usize = 612;
    /// `EPROC_CTTY`: the controlling tty vnode is active.
    pub const EPROC_CTTY: i32 = 0x01;
}

fn read_array<const N: usize>(buf: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[offset..offset + N]);
    out
}

fn no_such_process() -> io::Error {
    io::Error::from_raw_os_error(libc::ESRCH)
}

/// `sysctl({CTL_KERN, KERN_PROC, KERN_PROC_PID, pid})`. Readable for every process regardless of its uid. A pid with no process is `ESRCH`.
pub(crate) fn kinfo_proc(pid: i32) -> io::Result<KinfoProc> {
    let mut buf = [0u8; kinfo::SIZE];
    let mut size = buf.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    // SAFETY: `mib` holds 4 ints, `buf` is writable for `size` bytes, and the kernel writes at most `size` bytes and stores the written length in `size`.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr().cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // The kernel answers a pid with no process with success and zero bytes.
    if size == 0 {
        return Err(no_such_process());
    }
    if size != kinfo::SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("kinfo_proc of {size} bytes, expected {}", kinfo::SIZE),
        ));
    }
    let ngroups = i16::from_ne_bytes(read_array(&buf, kinfo::CR_NGROUPS));
    let ngroups = usize::try_from(ngroups).unwrap_or(0).min(kinfo::NGROUPS);
    let groups = (0..ngroups)
        .map(|i| u32::from_ne_bytes(read_array(&buf, kinfo::CR_GROUPS + i * 4)))
        .collect();
    let flag = i32::from_ne_bytes(read_array(&buf, kinfo::FLAG));
    let tdev = libc::dev_t::from_ne_bytes(read_array(&buf, kinfo::TDEV));
    // NODEV is `(dev_t)-1`.
    let tty_dev = (flag & kinfo::EPROC_CTTY != 0 && tdev != -1).then_some(tdev);
    let comm = &buf[kinfo::COMM..kinfo::COMM + kinfo::COMM_LEN];
    Ok(KinfoProc {
        ppid: i32::from_ne_bytes(read_array(&buf, kinfo::PPID)),
        uid: u32::from_ne_bytes(read_array(&buf, kinfo::CR_UID)),
        groups,
        start_secs: u64::from_ne_bytes(read_array(&buf, kinfo::START_SEC)),
        start_micros: u32::from_ne_bytes(read_array(&buf, kinfo::START_USEC)),
        comm: c_bytes_to_string(comm),
        tty_dev,
    })
}

/// A C string in a fixed buffer: up to the first NUL, lossily decoded.
fn c_bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn c_chars_to_bytes(chars: &[c_char]) -> Vec<u8> {
    chars.iter().map(|c| c.cast_unsigned()).collect()
}

/// Marks the structs `proc_pidinfo` fills: plain integers and arrays, so every bit pattern is a valid value.
///
/// # Safety
///
/// The implementor holds only integer and integer-array fields.
unsafe trait PidInfo: Copy {
    const FLAVOR: c_int;
}

// SAFETY: `proc_bsdinfo` is integers and `char` arrays only (`<sys/proc_info.h>` `struct proc_bsdinfo`).
unsafe impl PidInfo for libc::proc_bsdinfo {
    const FLAVOR: c_int = libc::PROC_PIDTBSDINFO;
}

// SAFETY: `proc_vnodepathinfo` is integers and `char` arrays only (`<sys/proc_info.h>` `struct vnode_info_path`).
unsafe impl PidInfo for libc::proc_vnodepathinfo {
    const FLAVOR: c_int = libc::PROC_PIDVNODEPATHINFO;
}

/// `struct proc_uniqidentifierinfo`, which the SDK leaves out (`#ifdef PRIVATE`).
///
/// Layout from xnu `bsd/sys/proc_info_private.h` (`struct proc_uniqidentifierinfo`, 56 bytes); the public SDK's `<kern/kcdata.h>` `struct crashinfo_proc_uniqidentifierinfo` has the same size and the same offsets for `p_uuid`, `p_uniqueid` and `p_puniqueid`.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcUniqIdentifierInfo {
    _p_uuid: [u8; 16],
    p_uniqueid: u64,
    p_puniqueid: u64,
    p_idversion: i32,
    _p_orig_ppidversion: i32,
    _p_reserve2: u64,
    _p_reserve3: u64,
}

const _: () = assert!(size_of::<ProcUniqIdentifierInfo>() == 56);

// SAFETY: the struct above is integers and a byte array only.
unsafe impl PidInfo for ProcUniqIdentifierInfo {
    /// `PROC_PIDUNIQIDENTIFIERINFO` from xnu `bsd/sys/proc_info_private.h`; the SDK skips 17 in its flavor list.
    const FLAVOR: c_int = 17;
}

fn pidinfo<T: PidInfo>(pid: i32) -> io::Result<T> {
    let mut out = MaybeUninit::<T>::zeroed();
    let size = c_int::try_from(size_of::<T>()).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: `out` is writable for `size` bytes and `proc_pidinfo` writes at most `size` bytes.
    let written = unsafe { libc::proc_pidinfo(pid, T::FLAVOR, 0, out.as_mut_ptr().cast(), size) };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    if written != size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "proc_pidinfo flavor {} wrote {written} of {size} bytes",
                T::FLAVOR
            ),
        ));
    }
    // SAFETY: the buffer was zeroed and then filled, and `PidInfo` guarantees every bit pattern is a valid `T`.
    Ok(unsafe { out.assume_init() })
}

/// `pbi_name` of `PROC_PIDTBSDINFO` (up to 32 bytes, longer than `p_comm`). `None` when it is empty or the process belongs to another uid (`EPERM`).
pub(crate) fn bsd_name(pid: i32) -> Option<String> {
    let info: libc::proc_bsdinfo = pidinfo(pid).ok()?;
    let name = c_bytes_to_string(&c_chars_to_bytes(&info.pbi_name));
    (!name.is_empty()).then_some(name)
}

/// The identifiers of `PROC_PIDUNIQIDENTIFIERINFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UniqueIds {
    pub unique_id: u64,
    pub parent_unique_id: u64,
    /// The pid version, which the kernel bumps on every `exec` (the `pidversion` of an audit token).
    pub id_version: i32,
}

/// `proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)`. Readable for processes of any uid.
pub(crate) fn unique_ids(pid: i32) -> io::Result<UniqueIds> {
    let info: ProcUniqIdentifierInfo = pidinfo(pid)?;
    Ok(UniqueIds {
        unique_id: info.p_uniqueid,
        parent_unique_id: info.p_puniqueid,
        id_version: info.p_idversion,
    })
}

/// `proc_pidpath`.
pub(crate) fn pid_path(pid: i32) -> io::Result<PathBuf> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let size = u32::try_from(buf.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: `buf` is writable for `size` bytes and `proc_pidpath` writes at most that many.
    let len = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), size) };
    if len <= 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(usize::try_from(len).map_err(|_| io::ErrorKind::InvalidData)?);
    Ok(PathBuf::from(OsStr::from_bytes(&buf)))
}

/// The current directory from `PROC_PIDVNODEPATHINFO`. Only for processes of the same uid (else `EPERM`).
pub(crate) fn cwd(pid: i32) -> io::Result<PathBuf> {
    let info: libc::proc_vnodepathinfo = pidinfo(pid)?;
    // libc splits the `char[MAXPATHLEN]` into 32 rows of 32.
    let bytes = c_chars_to_bytes(info.pvi_cdir.vip_path.as_flattened());
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "empty cwd"));
    }
    Ok(PathBuf::from(OsStr::from_bytes(&bytes[..end])))
}

/// The raw `KERN_PROCARGS2` area (argc, exec path, argv, env). Only for processes of the same uid (else `EINVAL`).
pub(crate) fn procargs2(pid: i32) -> io::Result<Vec<u8>> {
    let mut argmax: c_int = 0;
    let mut size = size_of::<c_int>();
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: `argmax` is writable for `size` (= sizeof(int)) bytes.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&raw mut argmax).cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u8; usize::try_from(argmax).map_err(|_| io::ErrorKind::InvalidData)?];
    let mut size = buf.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // SAFETY: `buf` is writable for `size` bytes; the kernel stores the written length in `size`.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(size);
    Ok(buf)
}

/// `sysctlbyname("kern.bootsessionuuid")`.
pub(crate) fn boot_session_uuid() -> io::Result<String> {
    let mut buf = [0u8; 64];
    let mut size = buf.len();
    // SAFETY: the name is NUL-terminated, `buf` is writable for `size` bytes, and the kernel stores the written length in `size`.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let uuid = c_bytes_to_string(&buf[..size.min(buf.len())]);
    if uuid.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "empty boot UUID"));
    }
    Ok(uuid)
}

/// `sysctlbyname("kern.waketime")`: the seconds since the epoch of the last wake from sleep (`struct timeval`, the microseconds dropped).
pub(crate) fn wake_time_secs() -> io::Result<i64> {
    let mut buf = MaybeUninit::<libc::timeval>::zeroed();
    let mut size = size_of::<libc::timeval>();
    // SAFETY: the name is NUL-terminated, `buf` is writable for one `struct timeval` (`size` bytes), and the kernel stores the written length in `size`.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.waketime".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if size != size_of::<libc::timeval>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kern.waketime is not a struct timeval",
        ));
    }
    // SAFETY: `sysctlbyname` succeeded and wrote a whole `struct timeval`, which holds only integers.
    let wake = unsafe { buf.assume_init() };
    Ok(wake.tv_sec)
}

/// `MNT_RDONLY` (`<sys/mount.h>`).
const MNT_RDONLY: u32 = 0x0000_0001;

/// The file system holding `path` is mounted read-only (`statfs` `f_flags & MNT_RDONLY`), as the sealed system volume is.
pub(crate) fn is_on_read_only_mount(path: &std::path::Path) -> io::Result<bool> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut buf = MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: `path` is NUL-terminated and `buf` is writable for one `struct statfs`.
    let rc = unsafe { libc::statfs(path.as_ptr(), buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `statfs` succeeded and filled the struct, which holds only integers and `char` arrays.
    let buf = unsafe { buf.assume_init() };
    Ok(buf.f_flags & MNT_RDONLY != 0)
}

/// Upper bound for the `getpwuid_r` / `getgrgid_r` buffer; a group with every user as a member stays well below it.
const MAX_LOOKUP_BUF: usize = 1 << 20;

/// Serializes passwd and group enumeration, whose libc cursors are process-global and not thread-safe. Other code using these libc functions directly must coordinate independently.
static DIRECTORY_ENUMERATION: Mutex<()> = Mutex::new(());

/// Enumerates all passwd entries once, preserving every name for shared numeric IDs.
pub(crate) fn all_user_names() -> HashMap<u32, Vec<String>> {
    let _guard = DIRECTORY_ENUMERATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut names: HashMap<u32, Vec<String>> = HashMap::new();
    // SAFETY: the mutex protects the process-global passwd cursor until endpwent; each returned name is copied before the next getpwent call.
    unsafe {
        libc::setpwent();
        loop {
            let entry = libc::getpwent();
            if entry.is_null() {
                break;
            }
            if !(*entry).pw_name.is_null() {
                let name = CStr::from_ptr((*entry).pw_name)
                    .to_string_lossy()
                    .into_owned();
                let aliases = names.entry((*entry).pw_uid).or_default();
                if !aliases.contains(&name) {
                    aliases.push(name);
                }
            }
        }
        libc::endpwent();
    }
    names
}

/// Enumerates all group entries once, preserving every name for shared numeric IDs.
pub(crate) fn all_group_names() -> HashMap<u32, Vec<String>> {
    let _guard = DIRECTORY_ENUMERATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut names: HashMap<u32, Vec<String>> = HashMap::new();
    // SAFETY: the mutex protects the process-global group cursor until endgrent; each returned name is copied before the next getgrent call.
    unsafe {
        libc::setgrent();
        loop {
            let entry = libc::getgrent();
            if entry.is_null() {
                break;
            }
            if !(*entry).gr_name.is_null() {
                let name = CStr::from_ptr((*entry).gr_name)
                    .to_string_lossy()
                    .into_owned();
                let aliases = names.entry((*entry).gr_gid).or_default();
                if !aliases.contains(&name) {
                    aliases.push(name);
                }
            }
        }
        libc::endgrent();
    }
    names
}

/// The login name of `uid` (`getpwuid_r`).
pub(crate) fn user_name(uid: u32) -> Option<String> {
    let mut len = 4096;
    loop {
        let mut buf = vec![0 as c_char; len];
        let mut pwd = MaybeUninit::<libc::passwd>::zeroed();
        let mut result: *mut libc::passwd = ptr::null_mut();
        // SAFETY: `pwd` and `buf` are writable, `buf` has `len` bytes, and `result` receives either NULL or `pwd`'s address.
        let rc =
            unsafe { libc::getpwuid_r(uid, pwd.as_mut_ptr(), buf.as_mut_ptr(), len, &mut result) };
        if rc == libc::ERANGE && len < MAX_LOOKUP_BUF {
            len *= 2;
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        // SAFETY: on success `pw_name` points at a NUL-terminated string inside `buf`, which is still alive.
        let name = unsafe { CStr::from_ptr((*result).pw_name) };
        return Some(name.to_string_lossy().into_owned());
    }
}

/// The name of `gid` (`getgrgid_r`).
pub(crate) fn group_name(gid: u32) -> Option<String> {
    let mut len = 4096;
    loop {
        let mut buf = vec![0 as c_char; len];
        let mut grp = MaybeUninit::<libc::group>::zeroed();
        let mut result: *mut libc::group = ptr::null_mut();
        // SAFETY: `grp` and `buf` are writable, `buf` has `len` bytes, and `result` receives either NULL or `grp`'s address.
        let rc =
            unsafe { libc::getgrgid_r(gid, grp.as_mut_ptr(), buf.as_mut_ptr(), len, &mut result) };
        if rc == libc::ERANGE && len < MAX_LOOKUP_BUF {
            len *= 2;
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        // SAFETY: on success `gr_name` points at a NUL-terminated string inside `buf`, which is still alive.
        let name = unsafe { CStr::from_ptr((*result).gr_name) };
        return Some(name.to_string_lossy().into_owned());
    }
}

unsafe extern "C" {
    /// `<_stdlib.h>`: the reentrant `devname`.
    fn devname_r(dev: libc::dev_t, mode: libc::mode_t, buf: *mut c_char, len: c_int)
    -> *mut c_char;

    /// Private API of libsystem (no header). Returns the pid of the process responsible for `pid`, or -1.
    fn responsibility_get_pid_responsible_for_pid(pid: libc::pid_t) -> libc::pid_t;
}

/// The device name of a character device (`ttys003`), via `devname_r`.
pub(crate) fn tty_name(dev: libc::dev_t) -> Option<String> {
    let mut buf = [0 as c_char; 64];
    let len = c_int::try_from(buf.len()).ok()?;
    // SAFETY: `buf` is writable for `len` bytes; `devname_r` writes a NUL-terminated name into it and returns `buf` or NULL.
    let name = unsafe { devname_r(dev, libc::S_IFCHR, buf.as_mut_ptr(), len) };
    if name.is_null() {
        return None;
    }
    // SAFETY: a non-NULL result is a NUL-terminated string within `buf` (or a static string of libc).
    let name = unsafe { CStr::from_ptr(name) };
    Some(name.to_string_lossy().into_owned())
}

/// `responsibility_get_pid_responsible_for_pid`; `None` when it fails.
pub(crate) fn responsible_pid(pid: i32) -> Option<i32> {
    // SAFETY: takes and returns plain integers.
    let responsible = unsafe { responsibility_get_pid_responsible_for_pid(pid) };
    (responsible > 0).then_some(responsible)
}
