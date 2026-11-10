//! The credential crate's only `unsafe` module (overview §9 item 4; ADR-0008 D1, D2,
//! §18; m03-plan U1 `sys`): memory locking of K_env and K_verify, and the process-wide
//! mitigations applied at runtime start and in the issuer child.
//!
//! These are **mitigations, not a boundary** (ADR-0005 §3.6, ADR-0008 D1): the same OS
//! user stays the boundary (`workload_isolation: shared_os_user`). A lock that fails is
//! recorded as a degraded mitigation ([`MemLock::is_locked`] false,
//! [`HardeningReport::mlock_ok`] false) and never refuses a key. Windows has no
//! process-wide mitigation (disclosed, D1).
//!
//! Every platform call is wrapped in a safe function whose invariant is stated here; no
//! `unsafe` leaves this module, and no other module of the crate has any.
//!
//! | Function | Platform | Call | Invariant |
//! |---|---|---|---|
//! | [`lock_pages`] | Unix | `mlock(addr, len)` | `addr`/`len` come from a live `&mut [u8]` the caller owns, so the range is mapped for the call; `mlock` only changes residency and never reads or writes the bytes; a failure (`ENOMEM`/`EPERM`/`EAGAIN`, e.g. `RLIMIT_MEMLOCK`) is returned as an unlocked [`MemLock`], never an error that refuses the key |
//! | [`lock_pages`] | Windows | `VirtualLock(addr, len)` | as above (a live caller-owned range); a failure (working-set quota) is an unlocked [`MemLock`] |
//! | [`MemLock`] drop | Unix | `munlock(addr, len)` | called once, only for a range [`lock_pages`] locked; the owner (the vault's `SecretKey`) zeroizes the bytes **before** dropping the `MemLock` and frees them **after**, so the range is still mapped; `munlock` never dereferences the range (the kernel validates it and fails with `ENOMEM` if unmapped), so it cannot touch memory unsafely |
//! | [`MemLock`] drop | Windows | `VirtualUnlock(addr, len)` | as above: once, for a range `VirtualLock` locked, after zeroization and before the free |
//! | [`page_size`] | Unix | `sysconf(_SC_PAGESIZE)` | no precondition; a non-positive answer falls back to 4096 |
//! | [`harden_process`] | Linux | `prctl(PR_SET_DUMPABLE, 0)`, then `prctl(PR_GET_DUMPABLE)` (read back) | called at runtime start and in the issuer child, before any key exists; only clears the dumpable flag (non-dumpable: no core file, `/proc/<pid>` owned by root, same-user `ptrace` attach refused); the flag is reset by `execve` of a child, so spawned programs are unaffected |
//! | [`harden_process`] | Linux, macOS | `setrlimit(RLIMIT_CORE, {0, 0})`, then `getrlimit(RLIMIT_CORE)` (read back) | only lowers the limit (soft and hard to 0, which an unprivileged process can always do); the `rlimit` structs live on the stack for the calls; inherited by children, which is intended (no core file anywhere below the runtime) |
//!
//! Page granularity: `mlock`/`VirtualLock` lock whole pages and do not nest, so an
//! unlock of one region unlocks every byte on its pages. The vault therefore keeps each
//! key on a page of its own (an aligned page inside a two-page allocation it owns) and
//! locks exactly that page, so no two keys share a locked page.

#![allow(unsafe_code)]

/// A page-lock record for one region (ADR-0008 D1). Dropping it unlocks the region
/// once, if it was locked. It holds the region's address as an integer, so its owner
/// must zeroize the bytes before dropping it and free them after (the vault's
/// `SecretKey` does exactly that). Not `Clone`: one lock, one unlock.
#[derive(Debug)]
pub struct MemLock {
    addr: usize,
    len: usize,
    locked: bool,
    os_error: Option<i32>,
}

impl MemLock {
    /// A record of no lock (an empty region, or a platform without page locking).
    #[must_use]
    pub fn none() -> MemLock {
        MemLock {
            addr: 0,
            len: 0,
            locked: false,
            os_error: None,
        }
    }

    /// Whether the region's pages are locked against swap. `false` is the degraded
    /// mitigation of ADR-0008 D1 (the key is kept anyway).
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// The OS error code of a failed lock (nonsecret), if any.
    #[must_use]
    pub fn os_error(&self) -> Option<i32> {
        self.os_error
    }

    /// The length of the locked region in bytes (0 when not locked).
    #[must_use]
    pub fn len(&self) -> usize {
        if self.locked { self.len } else { 0 }
    }

    /// Whether nothing is locked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for MemLock {
    fn drop(&mut self) {
        if self.locked {
            platform::unlock(self.addr, self.len);
            self.locked = false;
        }
    }
}

/// Lock the pages spanning `buf` against swap (`mlock` on Unix, `VirtualLock` on
/// Windows). Never fails: a lock the OS refuses gives an unlocked [`MemLock`]
/// ([`MemLock::is_locked`] false), the degraded mitigation of ADR-0008 D1. An empty
/// `buf` locks nothing.
#[must_use]
pub fn lock_pages(buf: &mut [u8]) -> MemLock {
    if buf.is_empty() {
        return MemLock::none();
    }
    let addr = buf.as_mut_ptr().expose_provenance();
    let len = buf.len();
    match platform::lock(addr, len) {
        Ok(()) => MemLock {
            addr,
            len,
            locked: true,
            os_error: None,
        },
        Err(code) => MemLock {
            addr,
            len,
            locked: false,
            os_error: Some(code),
        },
    }
}

/// The memory page size in bytes (Unix `sysconf(_SC_PAGESIZE)`; Windows 4096, the page
/// size of every Windows architecture Heimdall supports).
#[must_use]
pub fn page_size() -> usize {
    platform::page_size()
}

/// What [`harden_process`] achieved, read back from the OS after the calls (nonsecret).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardeningReport {
    /// Linux: the dumpable flag read back with `PR_GET_DUMPABLE` (`Some(false)` once
    /// hardened). `None` where the platform has no such flag (macOS, Windows) or the
    /// read failed.
    pub dumpable: Option<bool>,
    /// Linux and macOS: the `RLIMIT_CORE` soft limit read back with `getrlimit`
    /// (`Some(0)` once hardened). `None` on Windows (no core limit) or when the read
    /// failed.
    pub core_limit: Option<u64>,
    /// Whether a probe page could be locked against swap in this process (the vault's
    /// page locks are expected to succeed too). `false` is a degraded mitigation.
    pub mlock_ok: bool,
}

/// Apply the process-wide mitigations of ADR-0008 D1, at runtime start and in the
/// issuer child, before any key exists: Linux `prctl(PR_SET_DUMPABLE, 0)` and
/// `setrlimit(RLIMIT_CORE, 0)`; macOS `setrlimit(RLIMIT_CORE, 0)`; Windows nothing
/// (disclosed). Never fails; the report says what holds afterwards.
#[must_use]
pub fn harden_process() -> HardeningReport {
    let dumpable = platform::clear_dumpable();
    let core_limit = platform::zero_core_limit();
    HardeningReport {
        dumpable,
        core_limit,
        mlock_ok: probe_lock(),
    }
}

/// Lock and unlock one page this function owns.
fn probe_lock() -> bool {
    let page = page_size();
    let mut buf = vec![0u8; page.saturating_mul(2)];
    let Some(region) = exclusive_page(&mut buf, page) else {
        return false;
    };
    let lock = lock_pages(region);
    lock.is_locked()
}

/// The first whole page inside `buf` (page-aligned, `page` bytes), if `buf` holds one.
/// Safe address arithmetic only: the slice stays inside `buf`.
pub(crate) fn exclusive_page(buf: &mut [u8], page: usize) -> Option<&mut [u8]> {
    if page == 0 {
        return None;
    }
    let addr = buf.as_ptr().addr();
    let offset = (page - addr % page) % page;
    buf.get_mut(offset..offset.checked_add(page)?)
}

#[cfg(unix)]
mod platform {
    /// `mlock`; `Err(errno)` on failure.
    pub(super) fn lock(addr: usize, len: usize) -> Result<(), i32> {
        let ptr = std::ptr::with_exposed_provenance::<libc::c_void>(addr);
        // SAFETY: `addr`/`len` describe a live `&mut [u8]` owned by the caller of
        // `lock_pages` for the duration of this call (module table, row 1). `mlock`
        // changes residency only; it never reads or writes the bytes.
        let r = unsafe { libc::mlock(ptr, len) };
        if r == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        }
    }

    /// `munlock`; the result is ignored (nothing to recover).
    pub(super) fn unlock(addr: usize, len: usize) {
        let ptr = std::ptr::with_exposed_provenance::<libc::c_void>(addr);
        // SAFETY: called once per successful `mlock`, by `MemLock::drop`, while the
        // owner still holds the (already zeroized) allocation (module table, row 3).
        // `munlock` never dereferences the range; an unmapped range fails with ENOMEM.
        let _ = unsafe { libc::munlock(ptr, len) };
    }

    pub(super) fn page_size() -> usize {
        // SAFETY: `sysconf` has no preconditions (module table, `page_size`).
        let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(n).ok().filter(|&n| n > 0).unwrap_or(4096)
    }

    /// Linux: clear the dumpable flag and read it back.
    #[cfg(target_os = "linux")]
    pub(super) fn clear_dumpable() -> Option<bool> {
        // SAFETY: `prctl(PR_SET_DUMPABLE, 0)` takes integer arguments only and changes
        // this process's dumpable flag (module table, `harden_process` row 1).
        let off: libc::c_ulong = 0;
        let _ = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, off) };
        // SAFETY: `prctl(PR_GET_DUMPABLE)` takes no pointer and only reads the flag.
        let state = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        (state >= 0).then_some(state != 0)
    }

    /// No dumpable flag outside Linux.
    #[cfg(not(target_os = "linux"))]
    pub(super) fn clear_dumpable() -> Option<bool> {
        None
    }

    /// Lower `RLIMIT_CORE` to 0 (soft and hard) and read the soft limit back.
    pub(super) fn zero_core_limit() -> Option<u64> {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `zero` is a valid `rlimit` on the stack for the call; lowering a
        // limit needs no privilege (module table, `harden_process` row 2).
        let _ = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const zero) };
        let mut now = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `now` is a valid, writable `rlimit` on the stack for the call.
        let r = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut now) };
        (r == 0).then_some(now.rlim_cur)
    }
}

#[cfg(windows)]
mod platform {
    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

    /// `VirtualLock`; `Err(GetLastError)` on failure.
    pub(super) fn lock(addr: usize, len: usize) -> Result<(), i32> {
        let ptr = std::ptr::with_exposed_provenance::<core::ffi::c_void>(addr);
        // SAFETY: `addr`/`len` describe a live `&mut [u8]` owned by the caller of
        // `lock_pages` for the duration of this call (module table, row 2).
        // `VirtualLock` changes residency only.
        let ok = unsafe { VirtualLock(ptr, len) };
        if ok != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        }
    }

    /// `VirtualUnlock`; the result is ignored.
    pub(super) fn unlock(addr: usize, len: usize) {
        let ptr = std::ptr::with_exposed_provenance::<core::ffi::c_void>(addr);
        // SAFETY: once per successful `VirtualLock`, by `MemLock::drop`, while the owner
        // still holds the (already zeroized) allocation (module table, row 4).
        let _ = unsafe { VirtualUnlock(ptr, len) };
    }

    pub(super) fn page_size() -> usize {
        4096
    }

    /// Windows has no dumpable flag (ADR-0008 D1: no additional mitigation).
    pub(super) fn clear_dumpable() -> Option<bool> {
        None
    }

    /// Windows has no core limit (ADR-0008 D1: no additional mitigation).
    pub(super) fn zero_core_limit() -> Option<u64> {
        None
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    pub(super) fn lock(_addr: usize, _len: usize) -> Result<(), i32> {
        Err(0)
    }
    pub(super) fn unlock(_addr: usize, _len: usize) {}
    pub(super) fn page_size() -> usize {
        4096
    }
    pub(super) fn clear_dumpable() -> Option<bool> {
        None
    }
    pub(super) fn zero_core_limit() -> Option<u64> {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_page_is_aligned_and_inside_the_buffer() {
        let page = page_size();
        let mut buf = vec![0u8; page * 2];
        let start = buf.as_ptr().addr();
        let region = exclusive_page(&mut buf, page).unwrap();
        assert_eq!(region.len(), page);
        let at = region.as_ptr().addr();
        assert_eq!(at % page, 0);
        assert!(at >= start && at + page <= start + page * 2);
        assert!(exclusive_page(&mut [0u8; 3], page).is_none() || page <= 3);
    }

    #[test]
    fn empty_region_locks_nothing() {
        let lock = lock_pages(&mut []);
        assert!(!lock.is_locked());
        assert!(lock.is_empty());
    }
}
