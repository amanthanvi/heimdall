//! Platform time sources (ADR-0005 §3.6 "Clocks"; overview §5, §9).
//!
//! * **Continuous clock** (counts sleep): Linux `clock_gettime(CLOCK_BOOTTIME)`;
//!   macOS `mach_continuous_time()` scaled by `mach_timebase_info`; Windows
//!   `QueryInterruptTime` (interrupt time **including** suspend; the unbiased
//!   variant excludes it and is not used).
//! * **Boot ID**: Linux `/proc/sys/kernel/random/boot_id`; macOS
//!   `sysctlbyname("kern.bootsessionuuid")`; Windows the Session Manager
//!   `BootId` counter (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\
//!   Memory Management\PrefetchParameters\BootId`, a DWORD incremented at each
//!   boot) [I]: chosen because it is stable within a boot and changes across boots
//!   without depending on the wall clock; evidenced in M04 (ADR-0005 §3.6 "to be
//!   selected and evidenced in M04").
//! * **Synchronization** ([`SystemTimeSync`]): returns `Unknown` on every
//!   platform in M01 until M03/M04 evidence selects the trustworthy signal
//!   (candidates: Linux `adjtimex`/`STA_UNSYNC` as used by `timedatectl
//!   NTPSynchronized`; macOS the time daemon's state; Windows `w32tm /query
//!   /status`) [I]. `Unknown` fails closed in the gate (ADR-0006 §10).
//! * **Process start time** ([`process_start_time`]): defeats PID reuse when an
//!   `instance.json` is validated (spec §4.2, §13.3). Linux `/proc/<pid>/stat`
//!   field 22 qualified by the boot ID (`None` in state `Z`/`X`: exited, even
//!   if not yet reaped); macOS `proc_pidinfo(PROC_PIDTBSDINFO)`;
//!   Windows `OpenProcess` + `GetProcessTimes` creation time.
//!
//! **Failure policy (fail closed).** The continuous reading is clamped so it
//! never decreases within the process; a failed read returns the last value, so
//! the gate sees the wall clock outrun a frozen continuous clock and reports
//! `TIME_UNCERTAIN`. The boot ID is cached after the first successful read; the
//! runtime calls [`SystemClock::try_new`] at start-up and refuses to start when it
//! fails (no time safety without a boot ID). If a read nonetheless fails later in
//! a process that never obtained one, [`Clock::boot_id`] returns a per-process
//! sentinel (`unavailable:<pid>:<nanos>`) that equals no persisted boot ID, so
//! every persisted anchor is treated as another boot (`NeedsAnchor`) and the gate
//! requires synchronized time or an attended confirmation.
//!
//! This module is the second `unsafe` boundary of the workspace (the first is
//! `heimdall_ipc::windows`). Each `unsafe` block is a single FFI call wrapped in a
//! safe function; its invariants are stated at the call. No `unsafe` leaves this
//! module.
//!
//! | Platform | `unsafe` call | Invariant |
//! |---|---|---|
//! | macOS | `mach_continuous_time()` | no arguments, cannot fail |
//! | macOS | `mach_timebase_info(&mut info)` | valid, aligned, writable out-pointer |
//! | macOS | `sysctlbyname("kern.bootsessionuuid", buf, &mut len, null, 0)` | NUL-terminated name; `buf` writable for `len` bytes; no new value |
//! | macOS | `proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &mut info, size_of(info))` | out-buffer exactly the struct size; result checked equal to it |
//! | Linux | `clock_gettime(CLOCK_BOOTTIME, &mut ts)` | valid, aligned, writable out-pointer; return code checked |
//! | Windows | `QueryInterruptTime(&mut t)` | valid out-pointer, cannot fail |
//! | Windows | `RegGetValueW(HKLM, subkey, "BootId", RRF_RT_REG_DWORD, null, &mut v, &mut 4)` | NUL-terminated UTF-16 names; 4-byte out-buffer and size |
//! | Windows | `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)` / `GetProcessTimes` / `GetExitCodeProcess` / `CloseHandle` | handle checked non-null, closed exactly once |
//! | Windows | `SetHandleInformation(std handle, HANDLE_FLAG_INHERIT, 0)` | this process's own standard handle as std holds it (null skipped); only the inherit flag changes, the handle stays open and valid; a failure is ignored |
//! | Linux (x86_64, aarch64) | `syscall(SYS_close_range, 3, ~0, 0 \| CLOSE_RANGE_CLOEXEC)` | integers only, this process's descriptors above 2; result checked, failure selects the fallback; `0` (close) only under the precondition below |
//! | Unix | `fcntl(fd, F_GETFD)` / `fcntl(fd, F_SETFD, flags \| FD_CLOEXEC)` | integers only; a number that is not open returns -1 (checked); only the close-on-exec flag is added |
//! | Unix | `close(fd)` (fd > 2) | only from `close_inherited_descriptors`, called by `service run` before it opens anything, so no live object owns the descriptor; EBADF for gaps ignored |
//! | Unix | `getrlimit(RLIMIT_NOFILE, &mut rl)` | valid, aligned, writable out-pointer; return code checked; only the hard limit bounds the last-resort loop, and an infinite or over-cap one is an error, not a partial scan |
//! | Unix (unit tests only) | `fcntl(fd, F_DUPFD, n)` / `OwnedFd::from_raw_fd` | integers only; result checked; the duplicate is owned once and closed when the S04 fallback test ends; never in a release build |
//!
//! **Inherited descriptors** ([`disinherit_descriptors_above_stdio`],
//! [`close_inherited_descriptors`]; ADR-0006 §13.8 item 7): the launcher marks
//! every descriptor above 2 of the client close-on-exec before it spawns the
//! detached runtime, and `service run` closes every descriptor above 2 before it
//! opens anything, so the long-lived runtime never holds a caller's pipe.
//!
//! **Detached children** ([`disinherit_standard_handles`]; ADR-0006 §13.6 item 8):
//! before the launcher spawns the on-demand runtime, Windows clients clear the
//! inherit flag on their own standard handles, because `CreateProcess` with
//! inheritance (which the standard library always requests when stdio is set)
//! passes **every** inheritable handle, not only the `NUL` stdio it sets; a
//! client started with pipes as stdio would otherwise leave them open in the
//! long-lived runtime, and its caller would never see end of output (observed
//! natively: the e2e launcher case hung until its timeout).

#![allow(unsafe_code)]

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_domain::time::{BootId, Clock, SyncStatus, TimeSync};

/// The operating system's three time sources.
#[derive(Debug, Default)]
pub struct SystemClock;

/// Highest continuous reading returned so far (nanoseconds), for the
/// never-decreasing clamp.
static LAST_CONTINUOUS_NANOS: AtomicU64 = AtomicU64::new(0);

/// Boot ID cache (first successful read wins for the process lifetime).
static BOOT_ID: OnceLock<BootId> = OnceLock::new();

/// Per-process sentinel used only if no boot ID could ever be read.
static SENTINEL_BOOT_ID: OnceLock<BootId> = OnceLock::new();

impl SystemClock {
    /// New. Prefer [`try_new`](Self::try_new) in the runtime.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// New, after proving both platform sources work on this host: the boot ID
    /// is read (and cached) and the continuous clock is read. The runtime refuses
    /// to start when this fails.
    pub fn try_new() -> std::io::Result<Self> {
        boot_id_cached()?;
        os::continuous_nanos()?;
        Ok(Self)
    }

    /// Read the boot-scoped continuous clock (see module docs), clamped so it
    /// never decreases within this process.
    fn read_continuous() -> Duration {
        let nanos = match os::continuous_nanos() {
            Ok(n) => LAST_CONTINUOUS_NANOS.fetch_max(n, Ordering::AcqRel).max(n),
            Err(_) => LAST_CONTINUOUS_NANOS.load(Ordering::Acquire),
        };
        Duration::from_nanos(nanos)
    }

    /// Read the platform boot identifier (see module docs). Cached after the first
    /// successful read; failure yields the per-process sentinel (module docs).
    fn read_boot_id() -> BootId {
        match boot_id_cached() {
            Ok(id) => id,
            Err(_) => SENTINEL_BOOT_ID
                .get_or_init(|| {
                    let nanos = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_nanos());
                    BootId(format!("unavailable:{}:{nanos}", std::process::id()))
                })
                .clone(),
        }
    }
}

fn boot_id_cached() -> std::io::Result<BootId> {
    if let Some(id) = BOOT_ID.get() {
        return Ok(id.clone());
    }
    let raw = os::boot_id()?;
    let id = raw.trim();
    if id.is_empty() || id.len() > 128 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "platform boot identifier is empty or implausible",
        ));
    }
    Ok(BOOT_ID.get_or_init(|| BootId(id.to_owned())).clone())
}

impl Clock for SystemClock {
    fn wall(&self) -> Timestamp {
        Timestamp::now()
    }

    fn continuous(&self) -> Duration {
        Self::read_continuous()
    }

    fn boot_id(&self) -> BootId {
        Self::read_boot_id()
    }
}

/// Platform synchronization report. Returns [`SyncStatus::Unknown`] on every
/// platform in M01 (module docs); the time gate therefore requires an attended
/// confirmation after every reboot until a signal is evidenced.
#[derive(Debug, Default)]
pub struct SystemTimeSync;

impl TimeSync for SystemTimeSync {
    fn status(&self) -> SyncStatus {
        SyncStatus::Unknown
    }
}

/// Read the platform boot identifier without the cache (tests compare two
/// independent reads; production code uses [`Clock::boot_id`]).
#[doc(hidden)]
pub fn read_boot_id_uncached() -> std::io::Result<String> {
    os::boot_id().map(|s| s.trim().to_owned())
}

/// Windows: clear `HANDLE_FLAG_INHERIT` on this process's standard input,
/// output and error handles, so a child spawned afterwards (the detached
/// on-demand runtime) never holds the caller's console or pipe handles. This
/// process keeps using them normally. Unix: nothing to do here (the spawn
/// replaces descriptors 0-2); descriptors above 2 are handled by
/// [`disinherit_descriptors_above_stdio`].
pub fn disinherit_standard_handles() {
    os::disinherit_standard_handles();
}

/// Unix: mark every open descriptor above 2 of this process close-on-exec
/// (ADR-0006 §13.8 item 7), so a child spawned afterwards (the detached
/// on-demand runtime) receives only the three standard descriptors the spawn
/// sets. The standard library opens its own descriptors close-on-exec, but a
/// descriptor this process **inherited** without the flag (from a caller, or
/// leaked into it by a caller's concurrent spawn) would otherwise pass on to the
/// long-lived runtime and keep the caller's pipe open (observed: the e2e
/// concurrent-start case hung on exactly that). This process keeps using every
/// descriptor normally; only children it executes later lose them.
///
/// Linux (x86_64, aarch64) uses `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`; when
/// that fails (kernel before 5.11) and elsewhere, the open descriptors are listed
/// from `/proc/self/fd` (Linux) or `/dev/fd`, and when that fails every number
/// below the `RLIMIT_NOFILE` **hard** limit is visited, if it is finite and at
/// most 1 048 576.
///
/// # Errors
///
/// When none of the three covers every descriptor (no `close_range`, no listing,
/// and a hard limit that is unreadable, infinite or above the cap), a fixed
/// `Unsupported` error; nothing is claimed after a partial scan, and the
/// launcher then spawns nothing. Windows: a no-op that always succeeds (see
/// [`disinherit_standard_handles`]).
pub fn disinherit_descriptors_above_stdio() -> std::io::Result<()> {
    #[cfg(unix)]
    return fds::above_stdio(fds::Action::CloseOnExec);
    #[cfg(not(unix))]
    Ok(())
}

/// Unix: close every descriptor above 2 (ADR-0006 §13.8 item 7). The runtime
/// calls this first thing at start-up, before it opens any descriptor of its
/// own, so it holds nothing inherited from whatever started it (a client's
/// output pipe held by the long-lived runtime keeps that client's caller waiting
/// for end of file). Same mechanisms and fallbacks as
/// [`disinherit_descriptors_above_stdio`], with `close` in place of the flag.
///
/// **Precondition:** no live object of this process owns a descriptor above 2
/// (it is called before anything is opened); never call it from a process that
/// has opened files, sockets or pipes, such as a test harness. Windows: a no-op
/// that always succeeds (the launcher passes no handle beyond the null standard
/// handles).
///
/// # Errors
///
/// As [`disinherit_descriptors_above_stdio`]: when no mechanism covers every
/// descriptor, a fixed `Unsupported` error, and the runtime refuses to start.
pub fn close_inherited_descriptors() -> std::io::Result<()> {
    #[cfg(unix)]
    return fds::above_stdio(fds::Action::Close);
    #[cfg(not(unix))]
    Ok(())
}

/// ⟨ADR-0008 §17.34 item 2 (W5-F03)⟩ Whether this process's effective user has a
/// **user private group** (the Debian/Ubuntu scheme OpenSSH's `user-group-modes` accepts):
/// its primary group's name is the user's name and the group lists no other member.
/// `Ok(Some(gid))` with that group, `Ok(None)` when the primary group is not private,
/// `Err` when the user or the group cannot be looked up (`getpwuid_r`, `getgrgid_r`).
#[cfg(unix)]
pub fn user_private_group() -> std::io::Result<Option<u32>> {
    // SAFETY: `geteuid` has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let (user, gid) = unix_names::user(uid)?;
    let (group, members) = unix_names::group(gid)?;
    Ok((group == user && members.iter().all(|m| *m == user)).then_some(gid))
}

/// ⟨ADR-0008 §17.34 item 1 (the purge's read census)⟩ The (device, inode) of every
/// **regular file** this process has an open descriptor for, one entry per descriptor
/// (so a file open twice appears twice). Each descriptor number listed in `/dev/fd`
/// (Linux: `/proc/self/fd`) is examined with `fstat` on the number itself: nothing is
/// opened or closed, so no POSIX lock another descriptor holds on the file is released.
/// A number closed meanwhile is skipped.
///
/// # Errors
/// The descriptor directory cannot be read.
#[cfg(unix)]
pub fn regular_file_descriptors() -> std::io::Result<Vec<(u64, u64)>> {
    let dir = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    let numbers: Vec<libc::c_int> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    let mut out = Vec::new();
    for fd in numbers {
        // SAFETY: an all-zero `stat` is a valid out-value; `fstat` on any descriptor
        // number only reads its metadata (a closed number fails with EBADF).
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `st` is a valid out-pointer for the call.
        if unsafe { libc::fstat(fd, &mut st) } == 0 && st.st_mode & libc::S_IFMT == libc::S_IFREG {
            #[allow(clippy::unnecessary_cast, clippy::cast_sign_loss)]
            out.push((st.st_dev as u64, st.st_ino as u64));
        }
    }
    Ok(out)
}

#[cfg(unix)]
mod unix_names {
    use std::ffi::CStr;
    use std::io;

    /// A buffer large enough for one passwd or group entry, grown on `ERANGE`.
    fn with_buffer<T>(
        mut call: impl FnMut(&mut [libc::c_char]) -> io::Result<Option<T>>,
    ) -> io::Result<T> {
        let mut len = 1024usize;
        loop {
            let mut buf = vec![0 as libc::c_char; len];
            match call(&mut buf) {
                Ok(Some(v)) => return Ok(v),
                Ok(None) => return Err(io::Error::new(io::ErrorKind::NotFound, "no such entry")),
                Err(e) if e.raw_os_error() == Some(libc::ERANGE) && len < 1 << 20 => len *= 4,
                Err(e) => return Err(e),
            }
        }
    }

    /// The name and primary group of `uid`.
    pub(super) fn user(uid: libc::uid_t) -> io::Result<(String, libc::gid_t)> {
        with_buffer(|buf| {
            // SAFETY: an all-zero passwd is a valid out-value; `getpwuid_r` fills it.
            let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
            let mut out: *mut libc::passwd = std::ptr::null_mut();
            // SAFETY: every pointer is valid for the call; `buf` outlives it and its
            // length is passed; `out` is null or points at `pw`.
            let rc =
                unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc));
            }
            if out.is_null() || pw.pw_name.is_null() {
                return Ok(None);
            }
            // SAFETY: `pw_name` points into `buf`, NUL-terminated by `getpwuid_r`.
            let name = unsafe { CStr::from_ptr(pw.pw_name) }
                .to_string_lossy()
                .into_owned();
            Ok(Some((name, pw.pw_gid)))
        })
    }

    /// The name and the listed members of `gid`.
    pub(super) fn group(gid: libc::gid_t) -> io::Result<(String, Vec<String>)> {
        with_buffer(|buf| {
            // SAFETY: an all-zero group is a valid out-value; `getgrgid_r` fills it.
            let mut gr: libc::group = unsafe { std::mem::zeroed() };
            let mut out: *mut libc::group = std::ptr::null_mut();
            // SAFETY: as in `user`.
            let rc =
                unsafe { libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr(), buf.len(), &mut out) };
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc));
            }
            if out.is_null() || gr.gr_name.is_null() {
                return Ok(None);
            }
            // SAFETY: `gr_name` points into `buf`, NUL-terminated.
            let name = unsafe { CStr::from_ptr(gr.gr_name) }
                .to_string_lossy()
                .into_owned();
            let mut members = Vec::new();
            let mut p = gr.gr_mem;
            // SAFETY: `gr_mem` is a NULL-terminated array of NUL-terminated strings in
            // `buf`; it is read up to its terminator only.
            unsafe {
                while !p.is_null() && !(*p).is_null() {
                    members.push(CStr::from_ptr(*p).to_string_lossy().into_owned());
                    p = p.add(1);
                }
            }
            Ok(Some((name, members)))
        })
    }
}

/// Opaque OS start time of process `pid`, or `None` when the process does not
/// exist (or cannot be queried). Equal strings mean the same process instance;
/// the format is platform-specific and only compared for equality.
#[must_use]
pub fn process_start_time(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    os::process_start_time(pid)
}

/// ⟨M03⟩ U0b row 28 (ADR-0008 D5 §6.3; §17.13 item 2): the start time (field 22)
/// of a whole `/proc/<pid>/stat` text through the shared parser
/// [`heimdall_domain::procstat::parse`], keeping this runtime's own rules, so
/// [`process_start_time`]'s semantics are unchanged (wave-0 verify E9, reading (a)):
///
/// * a process that has exited is not alive, even while its parent has not reaped
///   it (state `Z` zombie or `X` dead), as on Windows (exit code checked) and macOS
///   (no BSD info for a zombie);
/// * the process group (field 5) is **not** required: `/proc` shows group 0 for a
///   kernel thread and for a process whose group leader is outside the reader's
///   PID namespace (inference), and such a process still has a start time. The
///   shared [`heimdall_domain::procstat::parse_start_time`] applies every other check
///   of the shared rule (the last `)`, at least 20 tokens, a one-letter state, a
///   decimal start time) and skips only the group's.
///
/// Pure (no I/O), so it is tested on every platform with synthetic lines.
#[must_use]
pub fn stat_start_time(stat: &str) -> Option<u64> {
    let (state, start_time) = heimdall_domain::procstat::parse_start_time(stat).ok()?;
    if matches!(state, 'Z' | 'X') {
        return None;
    }
    Some(start_time)
}

/// Descriptor hygiene for the detached runtime (ADR-0006 §13.8 item 7; see
/// [`disinherit_descriptors_above_stdio`] and [`close_inherited_descriptors`]).
#[cfg(unix)]
mod fds {
    use std::io;

    use libc::c_int;

    /// Largest `RLIMIT_NOFILE` hard limit the last-resort loop visits up to.
    const HARD_LIMIT_CAP: libc::rlim_t = 1 << 20;

    /// What to do with each descriptor above 2.
    #[derive(Debug, Clone, Copy)]
    pub(super) enum Action {
        /// `close`.
        Close,
        /// Set `FD_CLOEXEC`.
        CloseOnExec,
    }

    /// The mechanisms [`above_stdio_with`] uses, injectable so unit tests can
    /// force the fallbacks; production always uses [`SYSTEM`].
    #[derive(Clone, Copy)]
    pub(super) struct Strategy {
        /// One call covering every descriptor above 2; `true` on success.
        pub(super) close_range: fn(Action) -> bool,
        /// The open descriptors above 2; `None` when they cannot be listed.
        pub(super) listed: fn() -> Option<Vec<c_int>>,
        /// `RLIMIT_NOFILE`; `None` when it cannot be read.
        pub(super) nofile_limit: fn() -> Option<libc::rlimit>,
        /// Act on one descriptor.
        pub(super) apply: fn(c_int, Action),
    }

    /// The operating system's mechanisms.
    pub(super) const SYSTEM: Strategy = Strategy {
        close_range,
        listed,
        nofile_limit,
        apply,
    };

    pub(super) fn above_stdio(action: Action) -> io::Result<()> {
        above_stdio_with(action, &SYSTEM)
    }

    pub(super) fn above_stdio_with(action: Action, strategy: &Strategy) -> io::Result<()> {
        if (strategy.close_range)(action) {
            return Ok(());
        }
        if let Some(listed) = (strategy.listed)() {
            for fd in listed {
                (strategy.apply)(fd, action);
            }
            return Ok(());
        }
        let bound = scan_bound((strategy.nofile_limit)())?;
        for fd in 3..bound {
            (strategy.apply)(fd, action);
        }
        Ok(())
    }

    /// Exclusive bound of the last-resort loop: the `RLIMIT_NOFILE` **hard**
    /// limit, which no open descriptor can reach (a soft limit may have been
    /// lowered after descriptors were opened), when it is finite and at most
    /// [`HARD_LIMIT_CAP`]. Otherwise (unreadable, infinite or larger) no scan
    /// is complete, and an error is returned instead of a partial scan (review
    /// round 3, S04).
    fn scan_bound(limit: Option<libc::rlimit>) -> io::Result<c_int> {
        limit
            .map(|l| l.rlim_max)
            .filter(|&hard| hard != libc::RLIM_INFINITY && hard <= HARD_LIMIT_CAP)
            .and_then(|hard| c_int::try_from(hard).ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "inherited descriptors cannot be enumerated or bounded",
                )
            })
    }

    /// Linux 5.11+: one `close_range` call covers every descriptor above 2.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn close_range(action: Action) -> bool {
        let flags: libc::c_uint = match action {
            Action::Close => 0,
            Action::CloseOnExec => libc::CLOSE_RANGE_CLOEXEC,
        };
        // SAFETY: `close_range(first, last, flags)` takes three integers and no
        // pointer; it closes or flags descriptors of this process only. For
        // `Close` the precondition of `close_inherited_descriptors` holds (no
        // live object owns a descriptor above 2). The result is checked; any
        // failure (ENOSYS on an older kernel, EINVAL) selects the fallback.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_uint,
                libc::c_uint::MAX,
                flags,
            )
        };
        rc == 0
    }

    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    fn close_range(_action: Action) -> bool {
        false
    }

    /// Open descriptors above 2, from the kernel's per-process listing. `None`
    /// when the listing is unavailable or unreadable (the caller then loops).
    /// The listing's own directory descriptor appears in it; it is closed when
    /// the iterator drops, before any entry is acted on, so acting on its number
    /// afterwards fails harmlessly with `EBADF`.
    fn listed() -> Option<Vec<c_int>> {
        let dir = if cfg!(any(target_os = "linux", target_os = "android")) {
            "/proc/self/fd"
        } else {
            "/dev/fd"
        };
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).ok()? {
            let name = entry.ok()?.file_name();
            let fd: c_int = name.to_str()?.parse().ok()?;
            if fd > 2 {
                out.push(fd);
            }
        }
        Some(out)
    }

    /// This process's `RLIMIT_NOFILE`, or `None` when it cannot be read.
    pub(super) fn nofile_limit() -> Option<libc::rlimit> {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid, aligned, writable `rlimit`; the call only
        // writes it and its return code is checked before the value is used.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) };
        (rc == 0).then_some(limit)
    }

    fn apply(fd: c_int, action: Action) {
        match action {
            Action::Close => {
                // SAFETY: `close` takes an integer; a number that is not open
                // fails with EBADF, which is ignored. The precondition of
                // `close_inherited_descriptors` (no live object of this process
                // owns a descriptor above 2) rules out closing one in use.
                unsafe { libc::close(fd) };
            }
            Action::CloseOnExec => {
                // SAFETY: `fcntl(fd, F_GETFD)` takes an integer and returns the
                // descriptor flags or -1 (not open), checked below.
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
                    // SAFETY: as above; only the close-on-exec flag is added, the
                    // descriptor stays open and usable by this process.
                    unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
                }
            }
        }
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    mod tests {
        //! Fallback tests (review round 3, S04). `close_range` and the listing
        //! are forced to fail, and `RLIMIT_NOFILE` is read, through
        //! [`Strategy`]; nothing here is reachable from a release build. The
        //! limit is lowered through the seam, not with `setrlimit`: lowering a
        //! real (on macOS infinite) hard limit is irreversible for the shared
        //! test process, and doing it in a spawned child races with the
        //! `flock` test in `instance` (a spawn briefly shares every open file
        //! description; observed 17 failures in 150 runs).

        use std::os::fd::AsRawFd as _;
        use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

        use super::*;

        fn no_close_range(_: Action) -> bool {
            false
        }

        fn no_listing() -> Option<Vec<c_int>> {
            None
        }

        /// No `close_range`, no listing; real `RLIMIT_NOFILE` and `fcntl`.
        const NO_ENUMERATION: Strategy = Strategy {
            close_range: no_close_range,
            listed: no_listing,
            ..SYSTEM
        };

        fn descriptor_flags(fd: c_int) -> c_int {
            // SAFETY: integer arguments; -1 (not open) is asserted against.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0, "descriptor {fd} is not open");
            flags
        }

        /// The open descriptor of the test below (only that test sets it).
        static HIGH: AtomicI32 = AtomicI32::new(0);

        /// Soft limit lowered to 64, below [`HIGH`]; finite hard limit above it.
        fn lowered_soft_limit() -> Option<libc::rlimit> {
            let high = HIGH.load(Ordering::SeqCst);
            Some(libc::rlimit {
                rlim_cur: 64,
                rlim_max: libc::rlim_t::try_from(high).unwrap() + 1,
            })
        }

        #[test]
        fn hard_limit_scan_reaches_a_descriptor_above_a_lowered_soft_limit() {
            let real = nofile_limit().expect("getrlimit");
            let target = c_int::try_from(real.rlim_cur.min(1024)).unwrap() - 16;
            assert!(
                target > 64,
                "soft limit {} too low for this test",
                real.rlim_cur
            );
            let file = std::fs::File::open("/dev/null").unwrap();
            // SAFETY (test only): integer arguments; F_DUPFD duplicates into the
            // lowest free number >= `target` without FD_CLOEXEC; checked below.
            let high = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, target) };
            assert!(high >= target, "F_DUPFD returned {high}");
            // SAFETY: `high` was just returned by F_DUPFD and nothing else owns
            // it; the OwnedFd closes it exactly once when the test ends.
            let _owned =
                unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(high) };
            assert_eq!(descriptor_flags(high) & libc::FD_CLOEXEC, 0);
            HIGH.store(high, Ordering::SeqCst);
            let strategy = Strategy {
                nofile_limit: lowered_soft_limit,
                ..NO_ENUMERATION
            };

            above_stdio_with(Action::CloseOnExec, &strategy).expect("finite hard limit");

            assert_ne!(
                descriptor_flags(high) & libc::FD_CLOEXEC,
                0,
                "descriptor {high} above the lowered soft limit 64 was not reached"
            );
        }

        static APPLIED: AtomicUsize = AtomicUsize::new(0);

        fn count(_: c_int, _: Action) {
            APPLIED.fetch_add(1, Ordering::SeqCst);
        }

        #[test]
        fn unbounded_or_over_cap_hard_limit_without_enumeration_is_an_error() {
            fn infinite() -> Option<libc::rlimit> {
                Some(libc::rlimit {
                    rlim_cur: 256,
                    rlim_max: libc::RLIM_INFINITY,
                })
            }
            fn over_cap() -> Option<libc::rlimit> {
                Some(libc::rlimit {
                    rlim_cur: 256,
                    rlim_max: 1_048_577,
                })
            }
            fn unreadable() -> Option<libc::rlimit> {
                None
            }
            for nofile_limit in [infinite as fn() -> _, over_cap, unreadable] {
                let strategy = Strategy {
                    nofile_limit,
                    apply: count,
                    ..NO_ENUMERATION
                };
                for action in [Action::Close, Action::CloseOnExec] {
                    assert!(above_stdio_with(action, &strategy).is_err(), "{action:?}");
                }
            }
            assert_eq!(APPLIED.load(Ordering::SeqCst), 0, "nothing is acted on");
        }
    }
}

#[cfg(target_os = "macos")]
mod os {
    use std::io;

    #[repr(C)]
    #[derive(Default)]
    struct MachTimebaseInfo {
        numer: u32,
        denom: u32,
    }

    // Declared here (not through libc, whose Mach bindings are deprecated in
    // favour of a crate the workspace does not carry). Both live in libSystem.
    unsafe extern "C" {
        fn mach_continuous_time() -> u64;
        fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
    }

    fn timebase() -> io::Result<(u32, u32)> {
        static TIMEBASE: std::sync::OnceLock<(u32, u32)> = std::sync::OnceLock::new();
        if let Some(tb) = TIMEBASE.get() {
            return Ok(*tb);
        }
        let mut info = MachTimebaseInfo::default();
        // SAFETY: `info` is a valid, aligned, writable `mach_timebase_info_data_t`
        // (two u32, repr(C)); the call only writes it.
        let rc = unsafe { mach_timebase_info(&raw mut info) };
        if rc != 0 || info.numer == 0 || info.denom == 0 {
            return Err(io::Error::other("mach_timebase_info failed"));
        }
        Ok(*TIMEBASE.get_or_init(|| (info.numer, info.denom)))
    }

    pub(super) fn continuous_nanos() -> io::Result<u64> {
        let (numer, denom) = timebase()?;
        // SAFETY: no arguments; returns the continuous tick count and cannot fail.
        let ticks = unsafe { mach_continuous_time() };
        let nanos = u128::from(ticks) * u128::from(numer) / u128::from(denom);
        u64::try_from(nanos).map_err(|_| io::Error::other("continuous clock overflow"))
    }

    pub(super) fn boot_id() -> io::Result<String> {
        const NAME: &[u8] = b"kern.bootsessionuuid\0";
        let mut buf = [0u8; 128];
        let mut len: libc::size_t = buf.len();
        // SAFETY: NAME is NUL-terminated; `buf` is writable for `len` bytes and
        // `len` is a valid in/out pointer; no new value is set (null, 0).
        let rc = unsafe {
            libc::sysctlbyname(
                NAME.as_ptr().cast(),
                buf.as_mut_ptr().cast(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let bytes = buf.get(..len.min(buf.len())).unwrap_or(&[]);
        let text = bytes.split(|b| *b == 0).next().unwrap_or(&[]);
        String::from_utf8(text.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "boot session UUID"))
    }

    pub(super) fn process_start_time(pid: u32) -> Option<String> {
        let pid = libc::c_int::try_from(pid).ok()?;
        // SAFETY: `proc_bsdinfo` is plain old data; all-zero is a valid value.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
        // SAFETY: the out-buffer is exactly `size` writable bytes of a
        // `proc_bsdinfo`; the result is checked to equal `size` before use.
        let rc = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
        };
        if rc != size {
            return None;
        }
        Some(format!(
            "{}.{:06}",
            info.pbi_start_tvsec, info.pbi_start_tvusec
        ))
    }

    pub(super) fn disinherit_standard_handles() {}
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod os {
    use std::io;

    pub(super) fn continuous_nanos() -> io::Result<u64> {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid, aligned, writable timespec; the return code is
        // checked before the value is used.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut ts) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let secs = u64::try_from(ts.tv_sec).map_err(|_| io::Error::other("negative clock"))?;
        let nanos = u64::try_from(ts.tv_nsec).map_err(|_| io::Error::other("negative clock"))?;
        secs.checked_mul(1_000_000_000)
            .and_then(|s| s.checked_add(nanos))
            .ok_or_else(|| io::Error::other("continuous clock overflow"))
    }

    pub(super) fn boot_id() -> io::Result<String> {
        let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        Ok(text.trim().to_owned())
    }

    pub(super) fn process_start_time(pid: u32) -> Option<String> {
        // Field 22 (starttime, clock ticks since boot) of /proc/<pid>/stat, read
        // by the shared parser (⟨M03⟩ U0b row 28; ADR-0008 §17.13 item 2): fields
        // are counted after the last ')', since the command name may contain
        // spaces, parentheses and newlines.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let start = super::stat_start_time(&stat)?;
        let boot = super::boot_id_cached().ok()?;
        Some(format!("{}:{start}", boot.0))
    }

    pub(super) fn disinherit_standard_handles() {}
}

#[cfg(windows)]
mod os {
    use std::io;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_SUCCESS, FILETIME, HANDLE_FLAG_INHERIT, STILL_ACTIVE,
        SetHandleInformation,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::Win32::System::WindowsProgramming::QueryInterruptTime;

    pub(super) fn continuous_nanos() -> io::Result<u64> {
        let mut t: u64 = 0;
        // SAFETY: `t` is a valid, aligned, writable u64; the call cannot fail.
        unsafe { QueryInterruptTime(&raw mut t) };
        // 100 ns units.
        t.checked_mul(100)
            .ok_or_else(|| io::Error::other("continuous clock overflow"))
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(super) fn boot_id() -> io::Result<String> {
        let subkey = wide(
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
        );
        let value = wide("BootId");
        let mut data: u32 = 0;
        let mut size: u32 = 4;
        // SAFETY: `subkey` and `value` are NUL-terminated UTF-16 strings that
        // outlive the call; `data` is a writable 4-byte buffer and `size` states
        // exactly that; RRF_RT_REG_DWORD restricts the type to a DWORD.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                (&raw mut data).cast(),
                &raw mut size,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(io::Error::other("Session Manager BootId is unavailable"));
        }
        Ok(format!("bootid-{data}"))
    }

    pub(super) fn process_start_time(pid: u32) -> Option<String> {
        // SAFETY: plain call; a null handle is checked below.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return None;
        }
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        let mut code: u32 = 0;
        // SAFETY: `handle` is a live process handle opened above with query
        // rights; all out-pointers are valid, aligned and writable.
        let times_ok = unsafe {
            GetProcessTimes(
                handle,
                &raw mut created,
                &raw mut exited,
                &raw mut kernel,
                &raw mut user,
            )
        } != 0;
        // SAFETY: as above; `code` is a writable u32.
        let code_ok = unsafe { GetExitCodeProcess(handle, &raw mut code) } != 0;
        // SAFETY: `handle` was returned by OpenProcess and is closed exactly once.
        unsafe { CloseHandle(handle) };
        // A process that has exited is not alive, even if a handle keeps it known.
        if !times_ok || !code_ok || code != STILL_ACTIVE.cast_unsigned() {
            return None;
        }
        let t = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        Some(t.to_string())
    }

    pub(super) fn disinherit_standard_handles() {
        use std::os::windows::io::AsRawHandle as _;
        for handle in [
            std::io::stdin().as_raw_handle(),
            std::io::stdout().as_raw_handle(),
            std::io::stderr().as_raw_handle(),
        ] {
            if handle.is_null() {
                continue;
            }
            // SAFETY: `handle` is this process's own standard handle as the
            // standard library holds it (null skipped above); changing its
            // inherit flag neither closes nor invalidates it. An invalid or
            // console pseudo handle makes the call fail, which is ignored.
            unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
        }
    }
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    windows
)))]
mod os {
    use std::io;

    pub(super) fn continuous_nanos() -> io::Result<u64> {
        Err(io::Error::other("no continuous clock on this platform"))
    }

    pub(super) fn boot_id() -> io::Result<String> {
        Err(io::Error::other("no boot identifier on this platform"))
    }

    pub(super) fn process_start_time(_pid: u32) -> Option<String> {
        None
    }

    pub(super) fn disinherit_standard_handles() {}
}
