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
//! * **Synchronization** ([`SystemTimeSync`]): stub returning `Unknown` on every
//!   platform until M03/M04 evidence selects the trustworthy signal (Linux
//!   `timedatectl show -p NTPSynchronized`; macOS the time daemon's state; Windows
//!   `w32tm /query /status`) [I]. `Unknown` fails closed in the gate.
//!
//! This module is the second `unsafe` boundary of the workspace (the first is
//! `heimdall_ipc::windows`): the continuous-clock and boot-ID syscalls are thin FFI
//! wrappers with documented invariants. Bodies are M01-U8.

#![allow(unsafe_code)]

use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_domain::time::{BootId, Clock, SyncStatus, TimeSync};

/// The operating system's three time sources.
#[derive(Debug, Default)]
pub struct SystemClock;

impl SystemClock {
    /// New.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Read the boot-scoped continuous clock (see module docs).
    fn read_continuous() -> Duration {
        todo!("M01-U8: CLOCK_BOOTTIME / mach_continuous_time / QueryInterruptTime")
    }

    /// Read the platform boot identifier (see module docs). Cached after the first
    /// successful read; a read failure is fatal for the runtime (no time safety
    /// without a boot ID).
    fn read_boot_id() -> BootId {
        todo!("M01-U8: boot_id file / kern.bootsessionuuid / Session Manager BootId")
    }
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

/// Platform synchronization report. **Stub**: returns [`SyncStatus::Unknown`]
/// until the per-platform signal is evidenced (M03/M04); the time gate therefore
/// requires an attended confirmation after every reboot until then.
#[derive(Debug, Default)]
pub struct SystemTimeSync;

impl TimeSync for SystemTimeSync {
    fn status(&self) -> SyncStatus {
        SyncStatus::Unknown
    }
}
