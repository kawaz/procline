//! The system calls of the tests' scaffolding (waiting for a process to run `exec` or to exit, FIFOs, zombies, process groups), as safe functions, so the tests outside this module hold no `unsafe`.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::Path;

/// What a watched process did first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessEvent {
    /// It ran `exec` (it may also have exited since).
    Exec,
    /// It exited without running `exec`.
    Exit,
}

/// Waits with a kqueue (`EVFILT_PROC` with `NOTE_EXEC` and `NOTE_EXIT`) for one process to run `exec` or to exit, without polling. Registered before the process is let go, so the event is not missed.
pub(crate) struct ProcessWatch {
    kq: OwnedFd,
    /// The process was already gone when the watch was registered.
    gone: bool,
}

impl ProcessWatch {
    pub(crate) fn new(pid: i32) -> io::Result<Self> {
        let kq = new_kqueue()?;
        let gone = !register_process(&kq, pid, libc::NOTE_EXEC | libc::NOTE_EXIT)?;
        Ok(Self { kq, gone })
    }

    /// Blocks until the process runs `exec` or exits.
    pub(crate) fn wait(&self) -> io::Result<ProcessEvent> {
        if self.gone {
            return Ok(ProcessEvent::Exit);
        }
        let mut events = [empty_event(); 1];
        let n = wait_events(&self.kq, &mut events)?;
        if n != 1 {
            return Err(io::Error::other(format!("kevent returned {n} events")));
        }
        if events[0].fflags & libc::NOTE_EXEC != 0 {
            Ok(ProcessEvent::Exec)
        } else {
            Ok(ProcessEvent::Exit)
        }
    }
}

/// What came first for a listening socket and the process expected to connect to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arrival {
    /// A connection is waiting to be accepted.
    Connection,
    /// The process exited (or was gone before the wait) with no connection waiting.
    Exited,
}

/// Blocks until `listener` has a connection to accept or the process `pid` exits, with one kqueue (`EVFILT_READ` on the socket, `EVFILT_PROC` with `NOTE_EXIT`), without polling. A connection that is waiting wins over an exit seen at the same time.
pub(crate) fn wait_connection_or_exit(listener: BorrowedFd<'_>, pid: i32) -> io::Result<Arrival> {
    let kq = new_kqueue()?;
    let ident = usize::try_from(listener.as_raw_fd()).map_err(io::Error::other)?;
    register(
        &kq,
        libc::kevent {
            ident,
            filter: libc::EVFILT_READ,
            flags: libc::EV_ADD | libc::EV_ONESHOT,
            ..empty_event()
        },
    )?;
    let exited = !register_process(&kq, pid, libc::NOTE_EXIT)?;
    let mut events = [empty_event(); 2];
    let n = if exited {
        // The process is gone; only a connection it made before exiting can still be waiting, and its readiness is reported at once.
        pending_events(&kq, &mut events)?
    } else {
        wait_events(&kq, &mut events)?
    };
    let readable = events[..n]
        .iter()
        .any(|event| event.filter == libc::EVFILT_READ);
    Ok(if readable {
        Arrival::Connection
    } else {
        Arrival::Exited
    })
}

/// `mkfifo(path, 0600)`.
pub(crate) fn make_fifo(path: &Path) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: `path` is a NUL-terminated string that lives for the call.
    if unsafe { libc::mkfifo(path.as_ptr(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Blocks until the child `pid` of this process has exited, without reaping it (`waitid` with `WEXITED | WNOWAIT`), so it stays a zombie until it is waited for.
pub(crate) fn wait_exited_unreaped(pid: u32) -> io::Result<()> {
    // SAFETY: `siginfo_t` holds only integers and pointers, for which all-zero is a valid value; it is only written by `waitid`.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a writable `siginfo_t` for the call; the other arguments are plain values.
    let rc = unsafe { libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED | libc::WNOWAIT) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `killpg(pgid, SIGKILL)`.
pub(crate) fn kill_process_group(pgid: i32) -> io::Result<()> {
    // SAFETY: killpg only sends a signal; it takes plain integers.
    if unsafe { libc::killpg(pgid, libc::SIGKILL) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn new_kqueue() -> io::Result<OwnedFd> {
    // SAFETY: kqueue takes no arguments and returns a new descriptor or -1.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `kq` is a descriptor kqueue just created, owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(kq) })
}

fn empty_event() -> libc::kevent {
    libc::kevent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

/// Registers `EVFILT_PROC` with `fflags` for the process; `false` when it is already gone. The kernel refuses the registration with `ESRCH` for a process that has exited, also one not yet reaped (a zombie; observed on macOS 26.5.2), so its exit would never be reported.
fn register_process(kq: &OwnedFd, pid: i32, fflags: u32) -> io::Result<bool> {
    let change = libc::kevent {
        ident: usize::try_from(pid).map_err(io::Error::other)?,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ONESHOT,
        fflags,
        ..empty_event()
    };
    match register(kq, change) {
        Ok(()) => Ok(true),
        Err(err) if err.raw_os_error() == Some(libc::ESRCH) => Ok(false),
        Err(err) => Err(err),
    }
}

/// Adds one change to the kqueue, asking for no events.
fn register(kq: &OwnedFd, change: libc::kevent) -> io::Result<()> {
    // SAFETY: one change read from a valid `kevent`, no event buffer, no timeout.
    let n = unsafe {
        libc::kevent(
            kq.as_raw_fd(),
            &change,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Blocks until at least one event arrives; returns how many were written into `events`.
fn wait_events(kq: &OwnedFd, events: &mut [libc::kevent]) -> io::Result<usize> {
    collect_events(kq, events, std::ptr::null())
}

/// The events already pending, without blocking (a zero timeout).
fn pending_events(kq: &OwnedFd, events: &mut [libc::kevent]) -> io::Result<usize> {
    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    collect_events(kq, events, &zero)
}

fn collect_events(
    kq: &OwnedFd,
    events: &mut [libc::kevent],
    timeout: *const libc::timespec,
) -> io::Result<usize> {
    let capacity = libc::c_int::try_from(events.len()).map_err(io::Error::other)?;
    // SAFETY: `events` is writable for `capacity` events; `timeout` is NULL (block) or points at a `timespec` that lives for the call.
    let n = unsafe {
        libc::kevent(
            kq.as_raw_fd(),
            std::ptr::null(),
            0,
            events.as_mut_ptr(),
            capacity,
            timeout,
        )
    };
    usize::try_from(n).map_err(|_| io::Error::last_os_error())
}
