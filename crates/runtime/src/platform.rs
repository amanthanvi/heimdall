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
//!   field 22 qualified by the boot ID; macOS `proc_pidinfo(PROC_PIDTBSDINFO)`;
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
        // Field 22 (starttime, clock ticks since boot) of /proc/<pid>/stat. The
        // command name (field 2) may contain spaces and parentheses, so fields are
        // counted after the last ')'.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after = stat.get(stat.rfind(')')? + 1..)?;
        // `after` starts at field 3 (state); starttime is field 22 → index 19.
        let start = after.split_whitespace().nth(19)?;
        if start.is_empty() || !start.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let boot = super::boot_id_cached().ok()?;
        Some(format!("{}:{start}", boot.0))
    }
}

#[cfg(windows)]
mod os {
    use std::io;

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, FILETIME, STILL_ACTIVE};
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
}
