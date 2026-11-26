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
//!   platform until native negative evidence exists (ADR-0010 §9 item 6, M04-D06).
//!   Trust stays off in M04: the attended time confirmation after a reboot is the
//!   only path. The read-only observations of [`observe_time_sync`] are for
//!   diagnostics and never feed the gate:
//!   * **Linux** `adjtimex(modes = 0)` mapped by [`map_timex`] with the rule systemd
//!     uses for `NTPSynchronized` (`ntp_synced()` in `timedated.c`, v255): `maxerror`
//!     (microseconds) below 16 000 000, with `STA_UNSYNC` deliberately ignored (a
//!     kernel that is told not to touch the RTC sets it while synchronized);
//!   * **macOS** `ntp_adjtime(modes = 0)`, the same `struct timex` through the
//!     documented BSD interface, read the same way [I];
//!   * **Windows** has no documented, locale-independent, read-only interface for
//!     "synchronized" (`w32tm` prints localized text), so the observation is
//!     [`SyncObservation::NoInterface`].
//!
//!   The Windows `BootId` below is likewise an observation: the reboot row is B12.
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
//! | Windows | `GetSecurityInfo(dir handle, SE_FILE_OBJECT, OWNER \| DACL, ...)` / `GetSecurityDescriptorControl` / `GetAclInformation` / `GetAce` / `ConvertSidToStringSidW` / `LocalFree` (`win_acl::read_facts`) | the handle is an open `READ_CONTROL` directory handle that outlives the call; every out-pointer valid; the ACL, ACE and SID pointers are read only while the `LocalFree`-owned descriptor is alive; the ACE index is below the reported count; the SID-string scan is bounded |
//! | Windows | `ConvertStringSecurityDescriptorToSecurityDescriptorW` / `CreateDirectoryW(path, &SECURITY_ATTRIBUTES)` / `LocalFree` (`win_acl::create_dir_with_sddl`) | NUL-terminated UTF-16 strings and a descriptor that outlive the call; the directory is created exclusively with the protected owner-only DACL |
//! | Windows | ⟨M04 review-fix⟩ `ConvertStringSecurityDescriptorToSecurityDescriptorW` / `GetSecurityDescriptorDacl` / `SetSecurityInfo(dir handle, SE_FILE_OBJECT, DACL \| PROTECTED_DACL, …)` / `LocalFree` (`win_acl::narrow_legacy`) | one `READ_CONTROL \| WRITE_DAC` handle on the directory itself (a final reparse point opened as the link); the descriptor read through it must judge `LegacyInherited` before the call; the new DACL points into a descriptor that outlives the call; owner, group and SACL are not set |
//! | Windows | ⟨M08 U2b-1, H15⟩ `MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING \| MOVEFILE_WRITE_THROUGH)` ([`rename_replacing`]) | two NUL-terminated UTF-16 paths with no interior NUL that outlive the call; constant flags; the result is checked |
//! | Windows | `FreeConsole()` (⟨M04⟩ U1, [`detach_console`], `service run --login` only) | no arguments; a failure (no console) is ignored |
//! | Windows | `SetHandleInformation(std handle, HANDLE_FLAG_INHERIT, 0)` | this process's own standard handle as std holds it (null skipped); only the inherit flag changes, the handle stays open and valid; a failure is ignored |
//! | Linux | `adjtimex(&mut tx)` with `tx` zeroed (`modes = 0`) | read-only query: valid, aligned, writable out-pointer; a negative return is an error, never a reading |
//! | macOS | `ntp_adjtime(&mut tx)` with `tx` zeroed (`modes = 0`) | read-only query: valid, aligned, writable out-pointer; a negative return is an error, never a reading |
//! | Linux (x86_64, aarch64) | `syscall(SYS_close_range, 3, ~0, 0 \| CLOSE_RANGE_CLOEXEC)` | integers only, this process's descriptors above 2; result checked, failure selects the fallback; `0` (close) only under the precondition below |
//! | Unix | `fcntl(fd, F_GETFD)` / `fcntl(fd, F_SETFD, flags \| FD_CLOEXEC)` | integers only; a number that is not open returns -1 (checked); only the close-on-exec flag is added |
//! | Unix | `close(fd)` (fd > 2) | only from `close_inherited_descriptors`, called by `service run` before it opens anything, so no live object owns the descriptor; EBADF for gaps ignored |
//! | Unix | `getrlimit(RLIMIT_NOFILE, &mut rl)` | valid, aligned, writable out-pointer; return code checked; only the hard limit bounds the last-resort loop, and an infinite or over-cap one is an error, not a partial scan |
//! | Unix | ⟨M06 W5⟩ `getuid()`, `getpwuid_r(uid, &mut pw, buf, len, &mut out)` ([`account_entry`]) | as the user-private-group lookup: the buffer outlives every read of `pw_name`, `pw_dir` and `pw_shell`, grown on `ERANGE` up to 1 MiB; each field is copied out before the buffer is freed; an empty name or a relative home or shell is refused |
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

    /// `None` when the platform source fails now ([`Self::continuous`] then answers the
    /// last value, which a commit-time check must not read as "no time elapsed").
    fn try_continuous(&self) -> Option<Duration> {
        let nanos = os::continuous_nanos().ok()?;
        Some(Duration::from_nanos(
            LAST_CONTINUOUS_NANOS
                .fetch_max(nanos, Ordering::AcqRel)
                .max(nanos),
        ))
    }

    fn boot_id(&self) -> BootId {
        Self::read_boot_id()
    }
}

/// Platform synchronization report. Returns [`SyncStatus::Unknown`] on every
/// platform (module docs): the time gate requires an attended confirmation after
/// every reboot until native negative evidence enables a signal (ADR-0010 §9
/// item 6). [`observe_time_sync`] reads the candidate interfaces for diagnostics
/// only.
#[derive(Debug, Default)]
pub struct SystemTimeSync;

impl TimeSync for SystemTimeSync {
    fn status(&self) -> SyncStatus {
        SyncStatus::Unknown
    }
}

/// `maxerror` (microseconds) at and above which systemd reports the clock not
/// synchronized: 16 seconds (`ntp_synced()`, systemd v255 `timedated.c`).
pub const NTP_SYNCED_MAX_ERROR_US: i64 = 16_000_000;

/// `STA_UNSYNC` of `struct timex.status` (`<sys/timex.h>`, the same value on Linux
/// and the BSDs). Reported, never used by the rule.
const STA_UNSYNC: i64 = 0x0040;

/// What a read-only kernel interface reported. An observation: it never reaches the
/// time gate ([`SystemTimeSync`] stays `Unknown`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncObservation {
    /// The rule reads "synchronized" (`maxerror` below [`NTP_SYNCED_MAX_ERROR_US`]).
    Synchronized {
        /// The kernel's maximum error estimate, microseconds.
        max_error_us: i64,
        /// Whether `STA_UNSYNC` was set (ignored by the rule).
        sta_unsync: bool,
    },
    /// The rule reads "not synchronized" (`maxerror` at or above the threshold).
    NotSynchronized {
        /// The kernel's maximum error estimate, microseconds.
        max_error_us: i64,
        /// Whether `STA_UNSYNC` was set (ignored by the rule).
        sta_unsync: bool,
    },
    /// The interface failed or returned a value no rule can read (a negative
    /// `maxerror`, an errno): no observation, and never "synchronized".
    Unavailable {
        /// What went wrong, without paths or secrets.
        why: String,
    },
    /// This platform has no documented, locale-independent read-only interface.
    NoInterface,
}

impl SyncObservation {
    /// The observation as the wire word: `synchronized`, `not_synchronized`,
    /// `unavailable` or `no_interface`.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            SyncObservation::Synchronized { .. } => "synchronized",
            SyncObservation::NotSynchronized { .. } => "not_synchronized",
            SyncObservation::Unavailable { .. } => "unavailable",
            SyncObservation::NoInterface => "no_interface",
        }
    }
}

/// One observation and the interface it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeObservation {
    /// The interface: `adjtimex`, `ntp_adjtime` or `none`.
    pub interface: &'static str,
    /// What it reported.
    pub reading: SyncObservation,
}

/// The mapper of `adjtimex`/`ntp_adjtime` (modes 0): `rc` is the call's return value
/// (negative: failed), `max_error_us` and `status` the `timex` fields. systemd's rule:
/// only a failed call or a `maxerror` of 16 s or more is "not synchronized", and
/// `STA_UNSYNC` is ignored; a negative `maxerror` is not a reading (units cannot be
/// trusted), so it is `Unavailable`, never "synchronized".
#[must_use]
pub fn map_timex(rc: i64, max_error_us: i64, status: i64) -> SyncObservation {
    if rc < 0 {
        return SyncObservation::Unavailable {
            why: "the time query failed".to_owned(),
        };
    }
    if max_error_us < 0 {
        return SyncObservation::Unavailable {
            why: "the kernel reported a negative maximum error".to_owned(),
        };
    }
    let sta_unsync = status & STA_UNSYNC != 0;
    if max_error_us < NTP_SYNCED_MAX_ERROR_US {
        SyncObservation::Synchronized {
            max_error_us,
            sta_unsync,
        }
    } else {
        SyncObservation::NotSynchronized {
            max_error_us,
            sta_unsync,
        }
    }
}

/// Read this host's synchronization observation (read-only, no privilege, no
/// subprocess; module docs). Diagnostics only: the time gate does not read it.
#[must_use]
pub fn observe_time_sync() -> TimeObservation {
    os::time_observation()
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

/// ⟨M04⟩ U1 (ADR-0010 §1 item 2): Windows: detach this process from the console it was
/// started with (`FreeConsole`), so the login entry's `service run --login`, which the
/// `Run` value starts in a console window of its own, does not keep that window open
/// while the runtime runs. Its standard handles stop working; `--login` logs to its file
/// only. Unix: nothing to do (launchd and systemd attach no terminal).
pub fn detach_console() {
    os::detach_console();
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

/// ⟨M06 W5; ADR-0012 §4 item 5 "Launcher-set values" ⟨2026-11-22⟩⟩ The account database's
/// entry of this process's real user (`getpwuid_r(getuid())`): what the launcher of runner
/// work sets `HOME`, `USER`, `LOGNAME` and `SHELL` from. Never the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountEntry {
    /// The login name (`pw_name`).
    pub name: std::ffi::OsString,
    /// The home directory (`pw_dir`), absolute.
    pub home: std::ffi::OsString,
    /// The login shell (`pw_shell`), absolute.
    pub shell: std::ffi::OsString,
}

/// The [`AccountEntry`] of this process's real user.
///
/// # Errors
/// The account has no entry, the call fails, or the entry's name is empty or its home or
/// shell is not an absolute path (nothing is guessed in its place).
#[cfg(unix)]
pub fn account_entry() -> std::io::Result<AccountEntry> {
    // SAFETY: `getuid` has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    unix_names::account(uid)
}

/// See the Unix function: runner work is launched on Unix only (m06-plan §5).
///
/// # Errors
/// Always.
#[cfg(not(unix))]
pub fn account_entry() -> std::io::Result<AccountEntry> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no account database on this platform",
    ))
}

#[cfg(unix)]
mod unix_names {
    use std::ffi::CStr;
    use std::io;

    /// The whole entry of `uid` (`pw_name`, `pw_dir`, `pw_shell`), each copied out of the
    /// buffer before it is freed.
    pub(super) fn account(uid: libc::uid_t) -> io::Result<super::AccountEntry> {
        use std::os::unix::ffi::OsStringExt;
        let entry = with_buffer(|buf| {
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
            if out.is_null() || pw.pw_name.is_null() || pw.pw_dir.is_null() || pw.pw_shell.is_null()
            {
                return Ok(None);
            }
            // SAFETY: the three fields point into `buf`, each NUL-terminated by
            // `getpwuid_r`; the bytes are copied before `buf` is dropped.
            let field = |p: *const libc::c_char| {
                std::ffi::OsString::from_vec(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
            };
            Ok(Some(super::AccountEntry {
                name: field(pw.pw_name),
                home: field(pw.pw_dir),
                shell: field(pw.pw_shell),
            }))
        })?;
        let absolute = |v: &std::ffi::OsStr| std::path::Path::new(v).is_absolute();
        if entry.name.is_empty() || !absolute(&entry.home) || !absolute(&entry.shell) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the account entry has no name, absolute home or absolute shell",
            ));
        }
        Ok(entry)
    }

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

    pub(super) fn detach_console() {}

    // `c_long` is `i64` on 64-bit hosts and `i32` on 32-bit ones: the conversions stay.
    #[allow(clippy::useless_conversion)]
    pub(super) fn time_observation() -> super::TimeObservation {
        // SAFETY: an all-zero `timex` is a valid out-value (`modes = 0` is a read-only
        // query).
        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        // SAFETY: `tx` is a valid, aligned, writable `timex` with `modes == 0`, which
        // asks the kernel to report and change nothing; a negative return is an error.
        let rc = unsafe { libc::ntp_adjtime(&raw mut tx) };
        super::TimeObservation {
            interface: "ntp_adjtime",
            reading: super::map_timex(i64::from(rc), i64::from(tx.maxerror), i64::from(tx.status)),
        }
    }
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

    pub(super) fn detach_console() {}

    // `c_long` is `i64` on 64-bit hosts and `i32` on 32-bit ones: the conversions stay.
    #[allow(clippy::useless_conversion)]
    pub(super) fn time_observation() -> super::TimeObservation {
        // SAFETY: an all-zero `timex` is a valid out-value (`modes = 0` is a read-only
        // query).
        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        // SAFETY: `tx` is a valid, aligned, writable `timex` with `modes == 0`, which
        // asks the kernel to report and change nothing (no privilege needed); a
        // negative return is an error.
        let rc = unsafe { libc::adjtimex(&raw mut tx) };
        super::TimeObservation {
            interface: "adjtimex",
            reading: super::map_timex(i64::from(rc), i64::from(tx.maxerror), i64::from(tx.status)),
        }
    }
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

    pub(super) fn detach_console() {
        // SAFETY: no arguments; detaches this process from its console, if it has one
        // (a failure, for a process without a console, is ignored).
        unsafe { windows_sys::Win32::System::Console::FreeConsole() };
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

    pub(super) fn time_observation() -> super::TimeObservation {
        // No documented, locale-independent, read-only "synchronized" interface
        // (module docs): `w32tm` prints localized text, and the adjustment query
        // reports whether the OS may adjust the clock, not whether it did.
        super::TimeObservation {
            interface: "none",
            reading: super::SyncObservation::NoInterface,
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

    pub(super) fn detach_console() {}

    pub(super) fn time_observation() -> super::TimeObservation {
        super::TimeObservation {
            interface: "none",
            reading: super::SyncObservation::NoInterface,
        }
    }
}

/// ⟨M08 U2b-1; ADR-0014 §3.6 "Platforms", delta H15⟩ Rename `from` over `to` on one volume,
/// replacing `to` atomically: the store layout's pointer switch and its intent's update
/// (`crate::state::PlatformFs`).
///
/// * **Windows:** `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`,
///   which returns only once the move has been written to the disk. Windows has no
///   directory sync, so this is what stands in for one there; the caller has flushed the
///   renamed file before the call.
/// * **Unix:** `rename(2)`. The caller then syncs the directory.
///
/// # Errors
/// The rename failed; `to` is then unchanged.
pub fn rename_replacing(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        win_move::move_replacing_write_through(from, to)
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(from, to)
    }
}

/// The Windows state directory's ACL (ADR-0010 §1 item 7; ADR-0006 §13.12 item 4): a
/// fresh directory is created with an explicit **protected, owner-only** DACL
/// ([`create_protected_dir`]), and an existing one is checked with [`check_owner_only`]
/// and refused, never repaired, when it is anything else. [`judge`] is the pure rule and
/// runs on every platform; the two functions that touch the OS are `cfg(windows)`.
///
/// The rule: the object's owner is the current user; the DACL is present and protected
/// (`SE_DACL_PROTECTED`: nothing inherited from the parent); and every ACE is an
/// allow-ACE for the current user, with at least one. A NULL DACL (everyone), an empty
/// DACL, a deny ACE, an object ACE and any other principal (SYSTEM and Administrators
/// included) all fail it.
pub mod state_dir_acl {
    #[cfg(windows)]
    use std::path::Path;

    /// The kind of one ACE, as far as the rule reads it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AceKind {
        /// `ACCESS_ALLOWED_ACE_TYPE`.
        Allow,
        /// Any other ACE type (deny, object, callback, audit, ...), by its type byte.
        Other(u8),
    }

    /// One ACE of a DACL: its kind, the SID (string form) it names, its access mask and
    /// its ACE flags.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AceFacts {
        /// The kind.
        pub kind: AceKind,
        /// The trustee's SID, `S-1-...`.
        pub sid: String,
        /// The access mask (`ACCESS_MASK`).
        pub mask: u32,
        /// The ACE flags (`ACE_HEADER.AceFlags`).
        pub flags: u8,
    }

    /// `FILE_ALL_ACCESS`.
    pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
    /// `GENERIC_ALL`.
    pub const GENERIC_ALL: u32 = 0x1000_0000;
    /// `OBJECT_INHERIT_ACE`.
    pub const OBJECT_INHERIT_ACE: u8 = 0x01;
    /// `CONTAINER_INHERIT_ACE`.
    pub const CONTAINER_INHERIT_ACE: u8 = 0x02;
    /// `INHERIT_ONLY_ACE`.
    pub const INHERIT_ONLY_ACE: u8 = 0x08;
    /// `INHERITED_ACE`.
    pub const INHERITED_ACE: u8 = 0x10;

    /// ⟨Re-check M04-W1-RC01⟩ Whether `ace` already grants `user_sid` everything the
    /// owner-only replacement `(A;OICI;GA;;;<user>)` grants: full control on the directory
    /// itself (not inherit-only) and inherited by files and subdirectories. Only then is
    /// the narrowing removal-only.
    fn grants_full_inheritable(ace: &AceFacts, user_sid: &str) -> bool {
        ace.kind == AceKind::Allow
            && ace.sid == user_sid
            && (ace.mask & GENERIC_ALL != 0 || ace.mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS)
            && ace.flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
                == OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            && ace.flags & INHERIT_ONLY_ACE == 0
    }

    /// What was read from a directory's security descriptor.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DaclFacts {
        /// The owner's SID.
        pub owner_sid: String,
        /// Whether the descriptor has a DACL at all (a NULL DACL grants everyone).
        pub dacl_present: bool,
        /// `SE_DACL_PROTECTED`.
        pub protected: bool,
        /// The ACEs in order.
        pub aces: Vec<AceFacts>,
    }

    /// The rule's answer.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Verdict {
        /// Protected, owned by the user, granting the user alone.
        OwnerOnly,
        /// No DACL: access for everyone.
        NoDacl,
        /// The DACL inherits from its parent.
        NotProtected,
        /// Owned by another principal.
        ForeignOwner,
        /// An ACE that is not an allow-ACE for the user.
        ForeignAce,
        /// No ACE: the user would have no access.
        NoAccess,
        /// ⟨M04 review-fix round⟩ The access-control list a Heimdall build before M04 gave
        /// the directory: owned by the user, not protected, and inherited from the profile,
        /// granting only the user, `SYSTEM` and `BUILTIN\Administrators` (the principals
        /// ADR-0010 §1 already excludes from its claims). [`migrate_legacy`] narrows it to
        /// the protected owner-only DACL once; nothing wider is ever accepted or changed.
        LegacyInherited,
    }

    /// `SYSTEM` (`S-1-5-18`).
    pub const SYSTEM_SID: &str = "S-1-5-18";
    /// `BUILTIN\Administrators` (`S-1-5-32-544`).
    pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

    impl Verdict {
        /// A fixed sentence for the refusal (no SID, no path).
        #[must_use]
        pub fn describe(self) -> &'static str {
            match self {
                Verdict::OwnerOnly => "the state directory is owner-only",
                Verdict::NoDacl => "the state directory has no access-control list",
                Verdict::NotProtected => {
                    "the state directory inherits an access-control list that lets another principal read it, or limits your own access"
                }
                Verdict::ForeignOwner => "the state directory is owned by another principal",
                Verdict::ForeignAce => {
                    "the state directory grants access to another principal or denies one"
                }
                Verdict::NoAccess => "the state directory's access-control list grants no access",
                Verdict::LegacyInherited => {
                    "the state directory has the inherited access-control list of a build before M04"
                }
            }
        }
    }

    /// The rule (module docs), for the current user's SID `user_sid`.
    #[must_use]
    pub fn judge(facts: &DaclFacts, user_sid: &str) -> Verdict {
        if !facts.dacl_present {
            return Verdict::NoDacl;
        }
        if !facts.protected {
            // A pre-M04 directory: the profile's inherited list, nobody but the user, SYSTEM
            // and Administrators, the user among them with full control inherited by files
            // and subdirectories (re-check M04-W1-RC01: so the narrowing only removes
            // access; a read-only or inherit-only owner entry is refused unchanged).
            let legacy = facts.owner_sid == user_sid
                && facts
                    .aces
                    .iter()
                    .any(|a| grants_full_inheritable(a, user_sid))
                && facts.aces.iter().all(|a| {
                    a.kind == AceKind::Allow
                        && (a.sid == user_sid || a.sid == SYSTEM_SID || a.sid == ADMINISTRATORS_SID)
                });
            return if legacy {
                Verdict::LegacyInherited
            } else {
                Verdict::NotProtected
            };
        }
        if facts.owner_sid != user_sid {
            return Verdict::ForeignOwner;
        }
        if facts
            .aces
            .iter()
            .any(|a| a.kind != AceKind::Allow || a.sid != user_sid)
        {
            return Verdict::ForeignAce;
        }
        if facts.aces.is_empty() {
            return Verdict::NoAccess;
        }
        Verdict::OwnerOnly
    }

    /// Read the directory's owner and DACL and apply [`judge`] with the current user's
    /// SID. The directory is opened for `READ_CONTROL` only, and a final reparse point
    /// is opened as the link, not followed (the caller has already required a real
    /// directory).
    ///
    /// # Errors
    /// The directory or its security information cannot be read.
    #[cfg(windows)]
    pub fn check_owner_only(dir: &Path) -> std::io::Result<Verdict> {
        let user = heimdall_ipc::windows::current_user_sid()?;
        let facts = super::win_acl::read_facts(dir)?;
        Ok(judge(&facts, &user))
    }

    /// ⟨M08 U2b-1; ADR-0014 §3.6⟩ The rule for a directory Heimdall creates **inside** the
    /// protected state directory: `generations/` and each generation directory. Such a
    /// directory inherits the state directory's one owner-only entry. So it must be owned by
    /// the user, have a DACL, and hold at least one entry, every one of them an allow-entry
    /// for the user alone. The entries may be inherited or explicit, the DACL protected or
    /// not. Anything else is refused and never repaired, as for the state directory itself.
    #[must_use]
    pub fn judge_inside(facts: &DaclFacts, user_sid: &str) -> Verdict {
        if !facts.dacl_present {
            return Verdict::NoDacl;
        }
        if facts.owner_sid != user_sid {
            return Verdict::ForeignOwner;
        }
        if facts
            .aces
            .iter()
            .any(|a| a.kind != AceKind::Allow || a.sid != user_sid)
        {
            return Verdict::ForeignAce;
        }
        if facts.aces.is_empty() {
            return Verdict::NoAccess;
        }
        Verdict::OwnerOnly
    }

    /// ⟨M08 U2b-1⟩ Read a directory inside the state directory as [`check_owner_only`]
    /// reads the state directory, and apply [`judge_inside`] with the current user's SID.
    ///
    /// # Errors
    /// The directory or its security information cannot be read.
    #[cfg(windows)]
    pub fn check_inside_owner_only(dir: &Path) -> std::io::Result<Verdict> {
        let user = heimdall_ipc::windows::current_user_sid()?;
        let facts = super::win_acl::read_facts(dir)?;
        Ok(judge_inside(&facts, &user))
    }

    /// ⟨M04 Windows fix round⟩ The owner and DACL facts of `path` (a directory or a file),
    /// read as [`check_owner_only`] reads them, for exact native assertions.
    ///
    /// # Errors
    /// The path or its security information cannot be read.
    #[cfg(windows)]
    pub fn dacl_facts(path: &Path) -> std::io::Result<DaclFacts> {
        super::win_acl::read_facts(path)
    }

    /// Create the directory `dir` (its parent must exist) **exclusively**, owned by the
    /// current user, with the protected DACL `D:P(A;OICI;GA;;;<user>)`: owner-only, and
    /// inherited by what is created inside, so the state database and its backups carry
    /// the same descriptor.
    ///
    /// # Errors
    /// The directory exists (`AlreadyExists`), or the descriptor or the directory could
    /// not be made.
    #[cfg(windows)]
    pub fn create_protected_dir(dir: &Path) -> std::io::Result<()> {
        let user = heimdall_ipc::windows::current_user_sid()?;
        super::win_acl::create_dir_with_sddl(dir, &format!("O:{user}D:P(A;OICI;GA;;;{user})"))
    }

    /// ⟨M04 review-fix round⟩ Narrow a [`Verdict::LegacyInherited`] directory to the protected
    /// owner-only DACL `D:P(A;OICI;GA;;;<user>)`, through a handle opened on the directory
    /// itself (`READ_CONTROL | WRITE_DAC`, a final reparse point opened as the link), after
    /// judging that same handle's descriptor again: only that exact shape is changed, and
    /// the change only removes access (`SYSTEM`, Administrators and the inheritance). Files
    /// already inside keep what they inherited, which names no other principal.
    ///
    /// # Errors
    /// The directory is no longer the legacy shape (`PermissionDenied`, nothing changed), or
    /// its descriptor cannot be read or set.
    #[cfg(windows)]
    pub fn migrate_legacy(dir: &Path) -> std::io::Result<()> {
        let user = heimdall_ipc::windows::current_user_sid()?;
        super::win_acl::narrow_legacy(dir, &user, &format!("D:P(A;OICI;GA;;;{user})"))
    }
}

/// ⟨M08 U2b-1, H15⟩ The write-through rename ([`rename_replacing`]).
#[cfg(windows)]
mod win_move {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    /// `path` as a NUL-terminated UTF-16 string; a path holding a NUL is refused.
    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let units: Vec<u16> = path.as_os_str().encode_wide().collect();
        if units.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a path holds a NUL character",
            ));
        }
        Ok(units.into_iter().chain(Some(0)).collect())
    }

    pub(super) fn move_replacing_write_through(from: &Path, to: &Path) -> io::Result<()> {
        let (from, to) = (wide(from)?, wide(to)?);
        // SAFETY: `from` and `to` are NUL-terminated UTF-16 strings with no interior NUL that
        // outlive the call; the flags are constants; the result is checked.
        let ok = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
mod win_acl {
    use std::ffi::{OsStr, c_void};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    use super::state_dir_acl::{AceFacts, AceKind, DaclFacts};

    /// `READ_CONTROL`: read the owner and the DACL.
    const READ_CONTROL: u32 = 0x0002_0000;
    /// `WRITE_DAC`: replace the DACL (the legacy narrowing only).
    const WRITE_DAC: u32 = 0x0004_0000;
    /// `ACCESS_ALLOWED_ACE_TYPE`.
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    /// Longest SID string accepted (the ipc module's bound).
    const MAX_SID_STRING_CHARS: usize = 192;
    /// Most ACEs read from one DACL (an ACL holds at most 64 KiB; a state directory's
    /// has one). More is not owner-only.
    const MAX_ACES: u32 = 1024;

    /// Memory an API documents `LocalFree` as the release function of.
    struct LocalAllocation(*mut c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from an API that allocates with LocalAlloc
                // (the security descriptor, the SID string) and is freed exactly once.
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    /// `ConvertSidToStringSidW` of a SID the caller keeps alive.
    fn sid_string(sid: PSID) -> io::Result<String> {
        let mut wide: *mut u16 = ptr::null_mut();
        // SAFETY: `sid` points at a valid SID inside a descriptor the caller keeps
        // alive; `wide` is a valid out-pointer.
        if unsafe { ConvertSidToStringSidW(sid, &raw mut wide) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _free = LocalAllocation(wide.cast());
        let mut len = 0usize;
        // SAFETY: `wide` is a NUL-terminated UTF-16 string returned by the call above;
        // the scan stops at the terminator, and at the bound for a string that has none.
        while len < MAX_SID_STRING_CHARS && unsafe { *wide.add(len) } != 0 {
            len += 1;
        }
        if len == MAX_SID_STRING_CHARS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SID string too long",
            ));
        }
        // SAFETY: `len` units were just read from the string.
        let units = unsafe { std::slice::from_raw_parts(wide, len) };
        String::from_utf16(units)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SID string is not UTF-16"))
    }

    /// The owner and DACL of the directory `dir`, read through a `READ_CONTROL` handle
    /// opened on the directory itself (backup semantics for a directory; a final reparse
    /// point is opened as the link, not followed).
    pub(super) fn read_facts(dir: &Path) -> io::Result<DaclFacts> {
        let handle = open_dir(dir, READ_CONTROL)?;
        facts_of(&handle)
    }

    /// The directory `dir` itself (backup semantics; a final reparse point opened as the
    /// link, not followed), with `access`.
    fn open_dir(dir: &Path, access: u32) -> io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .access_mode(access)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir)
    }

    /// ⟨M04 review-fix round⟩ `state_dir_acl::migrate_legacy`: through one `READ_CONTROL |
    /// WRITE_DAC` handle, judge the descriptor again and, only when it is the legacy shape,
    /// set the protected DACL of `sddl` (`DACL_SECURITY_INFORMATION |
    /// PROTECTED_DACL_SECURITY_INFORMATION`; the owner is not touched).
    pub(super) fn narrow_legacy(dir: &Path, user: &str, sddl: &str) -> io::Result<()> {
        let handle = open_dir(dir, READ_CONTROL | WRITE_DAC)?;
        let facts = facts_of(&handle)?;
        if super::state_dir_acl::judge(&facts, user)
            != super::state_dir_acl::Verdict::LegacyInherited
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the state directory is not the pre-M04 shape any more; nothing was changed",
            ));
        }
        let wide: Vec<u16> = OsStr::new(sddl).encode_wide().chain(Some(0)).collect();
        let mut descriptor: *mut c_void = ptr::null_mut();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call;
        // `descriptor` is a valid out-pointer; the size out-pointer may be null.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor = LocalAllocation(descriptor);
        let mut present: windows_sys::core::BOOL = 0;
        let mut defaulted: windows_sys::core::BOOL = 0;
        let mut dacl: *mut ACL = ptr::null_mut();
        // SAFETY: `descriptor` is the valid descriptor converted above (alive until this
        // function returns, and `dacl` points into it); the out-pointers are valid.
        if unsafe {
            GetSecurityDescriptorDacl(
                descriptor.0,
                &raw mut present,
                &raw mut dacl,
                &raw mut defaulted,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if present == 0 || dacl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no DACL in the descriptor",
            ));
        }
        // SAFETY: `handle` is an open directory handle with `WRITE_DAC`; `dacl` is a valid ACL
        // inside the descriptor that outlives the call; owner, group and SACL are not set
        // (null with their flags absent).
        let rc = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null(),
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(
                i32::try_from(rc).unwrap_or(i32::MAX),
            ));
        }
        Ok(())
    }

    /// The owner and DACL behind an open directory handle.
    fn facts_of(handle: &std::fs::File) -> io::Result<DaclFacts> {
        let mut owner: PSID = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `handle` is an open file handle owned by `handle` for the call; each
        // out-pointer is valid; the group and SACL out-pointers may be null. On success
        // `descriptor` is a LocalAlloc block that owns `owner` and `dacl`.
        let rc = unsafe {
            GetSecurityInfo(
                handle.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &raw mut owner,
                ptr::null_mut(),
                &raw mut dacl,
                ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(
                i32::try_from(rc).unwrap_or(i32::MAX),
            ));
        }
        let _descriptor = LocalAllocation(descriptor);
        if owner.is_null() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "no owner"));
        }
        let owner_sid = sid_string(owner)?;
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        // SAFETY: `descriptor` is the valid descriptor from the call above; the
        // out-pointers are valid.
        if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let protected = control & SE_DACL_PROTECTED != 0;
        if dacl.is_null() {
            return Ok(DaclFacts {
                owner_sid,
                dacl_present: false,
                protected,
                aces: Vec::new(),
            });
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: `dacl` is a valid ACL inside `descriptor`; `info` is a valid,
        // correctly sized out-buffer for the `AclSizeInformation` class.
        if unsafe {
            GetAclInformation(
                dacl,
                (&raw mut info).cast(),
                u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(u32::MAX),
                AclSizeInformation,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut aces = Vec::new();
        for i in 0..info.AceCount.min(MAX_ACES) {
            let mut ace: *mut c_void = ptr::null_mut();
            // SAFETY: `dacl` is valid and `i` is below its ACE count; `ace` is a valid
            // out-pointer, and the ACE it receives lives inside `dacl`.
            if unsafe { GetAce(dacl, i, &raw mut ace) } == 0 || ace.is_null() {
                return Err(io::Error::last_os_error());
            }
            let header = ace.cast::<windows_sys::Win32::Security::ACE_HEADER>();
            // SAFETY: every ACE begins with an ACE_HEADER.
            let (kind, flags) = unsafe { ((*header).AceType, (*header).AceFlags) };
            if kind == ACCESS_ALLOWED_ACE_TYPE {
                let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
                // SAFETY: an access-allowed ACE is an ACCESS_ALLOWED_ACE; its `Mask`
                // follows the header.
                let mask = unsafe { (*allowed).Mask };
                // SAFETY: an access-allowed ACE holds its SID from `SidStart` on; the
                // address is taken without reading through it.
                let sid = unsafe { (&raw mut (*allowed).SidStart).cast::<c_void>() };
                aces.push(AceFacts {
                    kind: AceKind::Allow,
                    sid: sid_string(sid)?,
                    mask,
                    flags,
                });
            } else {
                aces.push(AceFacts {
                    kind: AceKind::Other(kind),
                    sid: String::new(),
                    mask: 0,
                    flags,
                });
            }
        }
        if info.AceCount > MAX_ACES {
            // More ACEs than any owner-only descriptor has: report one that fails the rule.
            aces.push(AceFacts {
                kind: AceKind::Other(u8::MAX),
                sid: String::new(),
                mask: 0,
                flags: 0,
            });
        }
        Ok(DaclFacts {
            owner_sid,
            dacl_present: true,
            protected,
            aces,
        })
    }

    /// `CreateDirectoryW` with the descriptor `sddl` (exclusive: an existing entry fails
    /// with `ERROR_ALREADY_EXISTS`).
    pub(super) fn create_dir_with_sddl(dir: &Path, sddl: &str) -> io::Result<()> {
        let sddl: Vec<u16> = OsStr::new(sddl).encode_wide().chain(Some(0)).collect();
        let mut descriptor: *mut c_void = ptr::null_mut();
        // SAFETY: `sddl` is a NUL-terminated UTF-16 string that outlives the call;
        // `descriptor` is a valid out-pointer; the size out-pointer may be null.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor = LocalAllocation(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide` is NUL-terminated; `attributes` and its descriptor (freed only
        // when this function returns) outlive the call.
        if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod time_observation_tests {
    use super::{NTP_SYNCED_MAX_ERROR_US, SyncObservation, map_timex, observe_time_sync};

    /// ADR-0010 §6 item 3 / §9 item 6 (M04-D06): the Linux `adjtimex` mapper, with
    /// systemd's `NTPSynchronized` rule. Error: a failed call and a nonsense
    /// `maxerror` are never "synchronized". Units: `maxerror` is microseconds, so the
    /// threshold is 16 000 000. Threshold: one below reads synchronized, the value
    /// itself does not. `STA_UNSYNC` is reported and ignored. The mapper feeds an
    /// observation only; that the gate's source stays `Unknown` is pinned by
    /// `integration_runtime` (`SystemTimeSync.status()`).
    #[test]
    fn adjtimex_status_maps_to_sync_status() {
        const STA_UNSYNC: i64 = 0x0040;
        const STA_PLL: i64 = 0x0001;
        // Error cases.
        for rc in [-1_i64, i64::MIN] {
            assert!(
                matches!(map_timex(rc, 0, 0), SyncObservation::Unavailable { .. }),
                "rc {rc}"
            );
        }
        assert!(matches!(
            map_timex(0, -1, 0),
            SyncObservation::Unavailable { .. }
        ));
        // Threshold, in microseconds.
        assert_eq!(NTP_SYNCED_MAX_ERROR_US, 16_000_000);
        assert_eq!(
            map_timex(0, 0, 0),
            SyncObservation::Synchronized {
                max_error_us: 0,
                sta_unsync: false
            }
        );
        assert_eq!(
            map_timex(0, 15_999_999, 0),
            SyncObservation::Synchronized {
                max_error_us: 15_999_999,
                sta_unsync: false
            }
        );
        assert_eq!(
            map_timex(0, 16_000_000, 0),
            SyncObservation::NotSynchronized {
                max_error_us: 16_000_000,
                sta_unsync: false
            }
        );
        // Units: the kernel's own default of 16 s expressed in milliseconds (16_000)
        // is a small error, which is why the unit matters.
        assert!(matches!(
            map_timex(0, 16_000, 0),
            SyncObservation::Synchronized { .. }
        ));
        // `STA_UNSYNC` does not decide (systemd ignores it), whatever the state the
        // call returned (a positive return such as TIME_ERROR is not an error).
        assert_eq!(
            map_timex(5, 1_000, STA_UNSYNC | STA_PLL),
            SyncObservation::Synchronized {
                max_error_us: 1_000,
                sta_unsync: true
            }
        );
        assert_eq!(
            map_timex(0, 16_000_000, STA_UNSYNC),
            SyncObservation::NotSynchronized {
                max_error_us: 16_000_000,
                sta_unsync: true
            }
        );
    }

    /// The real read is read-only and returns an observation on every host (the value
    /// is the host's and is not asserted).
    #[test]
    fn the_host_observation_names_its_interface() {
        let obs = observe_time_sync();
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(["adjtimex", "ntp_adjtime"].contains(&obs.interface));
            assert_ne!(obs.reading, SyncObservation::NoInterface);
        } else {
            assert_eq!(obs.reading, SyncObservation::NoInterface);
        }
    }
}

#[cfg(test)]
mod state_dir_acl_tests {
    use super::state_dir_acl::{
        AceFacts, AceKind, CONTAINER_INHERIT_ACE, DaclFacts, FILE_ALL_ACCESS, GENERIC_ALL,
        INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE, Verdict, judge, judge_inside,
    };

    const ME: &str = "S-1-5-21-1-2-3-1001";
    /// `INHERITED_ACE`.
    const INHERITED: u8 = 0x10;
    const OICI: u8 = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;

    /// The profile's inherited entry, `(A;OICIID;FA;;;<sid>)`.
    fn allow(sid: &str) -> AceFacts {
        ace(sid, FILE_ALL_ACCESS, OICI | INHERITED)
    }

    fn ace(sid: &str, mask: u32, flags: u8) -> AceFacts {
        AceFacts {
            kind: AceKind::Allow,
            sid: sid.to_owned(),
            mask,
            flags,
        }
    }

    fn facts(protected: bool, owner: &str, aces: Vec<AceFacts>) -> DaclFacts {
        DaclFacts {
            owner_sid: owner.to_owned(),
            dacl_present: true,
            protected,
            aces,
        }
    }

    /// ADR-0010 §1 item 7: the rule that decides `state_dir_unsafe`. Only a protected
    /// DACL owned by the user and granting the user alone passes; each other shape of
    /// the inherited `%LOCALAPPDATA%` ACL, and of a loosened one, fails by its own
    /// verdict. (The Windows-native cases run the same rule against a real directory:
    /// `windows_state_dir_not_owner_only_is_refused` and the fresh-directory start.)
    #[test]
    fn the_owner_only_rule_passes_one_shape_and_refuses_the_rest() {
        assert_eq!(
            judge(&facts(true, ME, vec![allow(ME)]), ME),
            Verdict::OwnerOnly
        );
        // Two allow-ACEs for the user (the user's own, split by inheritance flags).
        assert_eq!(
            judge(&facts(true, ME, vec![allow(ME), allow(ME)]), ME),
            Verdict::OwnerOnly
        );
        // The default inherited ACL of a pre-M04 directory: not protected, the user, SYSTEM
        // and Administrators. The one shape the upgrade narrows (`migrate_legacy`).
        assert_eq!(
            judge(
                &facts(
                    false,
                    ME,
                    vec![allow("S-1-5-18"), allow("S-1-5-32-544"), allow(ME)]
                ),
                ME
            ),
            Verdict::LegacyInherited
        );
        // An explicit `GENERIC_ALL` owner entry inherited by files and subdirectories is
        // the same full control.
        assert_eq!(
            judge(&facts(false, ME, vec![ace(ME, GENERIC_ALL, OICI)]), ME),
            Verdict::LegacyInherited
        );
        // ⟨Re-check M04-W1-RC01⟩ The narrowing grants `(A;OICI;GA;;;<user>)`, so it is
        // removal-only only when the user's own entry already grants that. A read-only, an
        // inherit-only, or a not-inheritable owner entry is refused unchanged.
        let file_generic_read = 0x0012_0089;
        for (what, owner_ace) in [
            ("read-only", ace(ME, file_generic_read, OICI | INHERITED)),
            (
                "inherit-only",
                ace(ME, FILE_ALL_ACCESS, OICI | INHERIT_ONLY_ACE),
            ),
            ("files only", ace(ME, FILE_ALL_ACCESS, OBJECT_INHERIT_ACE)),
            ("this folder only", ace(ME, FILE_ALL_ACCESS, INHERITED)),
        ] {
            assert_eq!(
                judge(&facts(false, ME, vec![allow("S-1-5-18"), owner_ace]), ME),
                Verdict::NotProtected,
                "{what}"
            );
        }
        // ⟨M04 review-fix round⟩ Any other inherited list is refused, never narrowed: one
        // granting Everyone or Users, one owned by someone else, one with a deny ACE, one
        // without the user.
        let deny_ace = AceFacts {
            kind: AceKind::Other(1),
            sid: "S-1-5-18".to_owned(),
            mask: FILE_ALL_ACCESS,
            flags: 0,
        };
        for (what, f) in [
            (
                "everyone",
                facts(false, ME, vec![allow(ME), allow("S-1-1-0")]),
            ),
            (
                "users",
                facts(false, ME, vec![allow(ME), allow("S-1-5-32-545")]),
            ),
            // ⟨M04 Windows fix round⟩ The profile observed on the PC (ADR-0010 §11): the
            // stock entries plus an inherited read-and-execute entry for a local group.
            (
                "a local group with read and execute",
                facts(
                    false,
                    ME,
                    vec![
                        ace("S-1-5-21-9-8-7-1009", 0x0012_00a9, OICI | INHERITED),
                        allow("S-1-5-18"),
                        allow("S-1-5-32-544"),
                        allow(ME),
                    ],
                ),
            ),
            (
                "another owner",
                facts(false, "S-1-5-32-544", vec![allow(ME)]),
            ),
            ("a deny ace", facts(false, ME, vec![allow(ME), deny_ace])),
            ("not the user", facts(false, ME, vec![allow("S-1-5-18")])),
            ("empty", facts(false, ME, vec![])),
        ] {
            assert_eq!(judge(&f, ME), Verdict::NotProtected, "{what}");
        }
        // Protected, but granting SYSTEM or Everyone as well.
        for other in ["S-1-5-18", "S-1-1-0", "S-1-5-32-544"] {
            assert_eq!(
                judge(&facts(true, ME, vec![allow(ME), allow(other)]), ME),
                Verdict::ForeignAce,
                "{other}"
            );
        }
        // A deny ACE or any other ACE type is not owner-only.
        let deny = AceFacts {
            kind: AceKind::Other(1),
            sid: String::new(),
            mask: 0,
            flags: 0,
        };
        assert_eq!(
            judge(&facts(true, ME, vec![allow(ME), deny]), ME),
            Verdict::ForeignAce
        );
        // Another owner, an empty DACL and a NULL DACL.
        assert_eq!(
            judge(&facts(true, "S-1-5-32-544", vec![allow(ME)]), ME),
            Verdict::ForeignOwner
        );
        assert_eq!(judge(&facts(true, ME, vec![]), ME), Verdict::NoAccess);
        let null = DaclFacts {
            owner_sid: ME.to_owned(),
            dacl_present: false,
            protected: true,
            aces: vec![],
        };
        assert_eq!(judge(&null, ME), Verdict::NoDacl);
    }

    /// ⟨M08 U2b-1; ADR-0014 §3.6⟩ The rule for a directory inside the state directory
    /// (`generations/`, a generation): the one inherited owner-only entry passes, protected
    /// or not; another principal, a deny entry, another owner, no entry and no DACL fail.
    /// (Windows native: `windows_generation_directory_not_owner_only_is_refused`.)
    #[test]
    fn a_directory_inside_the_state_directory_passes_only_with_the_users_entries() {
        for protected in [false, true] {
            assert_eq!(
                judge_inside(&facts(protected, ME, vec![allow(ME)]), ME),
                Verdict::OwnerOnly,
                "protected {protected}"
            );
        }
        for other in ["S-1-5-18", "S-1-1-0", "S-1-5-32-544"] {
            assert_eq!(
                judge_inside(&facts(false, ME, vec![allow(ME), allow(other)]), ME),
                Verdict::ForeignAce,
                "{other}"
            );
        }
        let deny = AceFacts {
            kind: AceKind::Other(1),
            sid: ME.to_owned(),
            mask: 0,
            flags: 0,
        };
        assert_eq!(
            judge_inside(&facts(false, ME, vec![allow(ME), deny]), ME),
            Verdict::ForeignAce
        );
        assert_eq!(
            judge_inside(&facts(false, "S-1-5-32-544", vec![allow(ME)]), ME),
            Verdict::ForeignOwner
        );
        assert_eq!(
            judge_inside(&facts(false, ME, vec![]), ME),
            Verdict::NoAccess
        );
        let null = DaclFacts {
            owner_sid: ME.to_owned(),
            dacl_present: false,
            protected: false,
            aces: vec![],
        };
        assert_eq!(judge_inside(&null, ME), Verdict::NoDacl);
    }
}
