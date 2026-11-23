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
//! | `macos::add_generic_password_trusting_self` | macOS | `SecTrustedApplicationCreateFromPath(NULL)`, `SecTrustedApplicationCopyRequirement`, `SecCodeCopySelf`, `SecCodeCheckValidity`, `SecAccessCreate`, `SecKeychainItemCreateFromContent(kSecGenericPasswordItemClass)` (the K_mgmt item) | the trusted-application, requirement, code and access objects are wrapped under the create rule (`CFType`) and released exactly once; the attribute buffers and the secret slice outlive the call, which copies them; the item reference out-pointer is NULL (nothing to release); the keychain reference is borrowed from a live `SecKeychain`; nothing is written unless the running code satisfies the trusted application's requirement (fail closed) |
//! | `macos::keychain_status` | macOS | `SecKeychainGetStatus` | the keychain reference is borrowed from a live `SecKeychain`; `status` is a valid out-pointer |
//! | `macos::delete_keychain` (test configuration only) | macOS | `SecKeychainDelete` | only on a keychain opened by path from the test's scratch directory, never one on the search list; the `SecKeychain` outlives the call and is released after it |
//! | `windows::protect` | Windows | `CryptProtectData(CRYPTPROTECT_UI_FORBIDDEN)`, `LocalFree` | input, entropy and description outlive the call, which only reads them; the output blob is copied out and freed with `LocalFree` exactly once |
//! | `windows::unprotect` | Windows | `CryptUnprotectData(CRYPTPROTECT_UI_FORBIDDEN)`, `LocalFree` | as `protect`; the plaintext output is copied into a zeroizing buffer, then overwritten with zeros in place, then freed with `LocalFree` exactly once; no description is requested |
//! | `windows::create_owner_only_new`, `windows::create_owner_only_dir` | Windows | `OpenProcessToken`, `GetTokenInformation(TokenUser)`, `ConvertSidToStringSidW`, `ConvertStringSecurityDescriptorToSecurityDescriptorW` (`O:<user>D:P(A;;FA;;;<user>)`, directories `OICI`), `CreateFileW(CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT)` / `CreateDirectoryW` with that `SECURITY_ATTRIBUTES`, `LocalFree` | every `LocalAlloc`ed buffer freed exactly once after its last use; the descriptor outlives the creating call, which copies it; a reparse point at the name is the existing entry, never followed; handles are not inheritable and are owned by `File`/`OwnedHandle` |
//! | `windows::dacl_sddl` | Windows | `CreateFileW(READ_CONTROL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS \| FILE_FLAG_OPEN_REPARSE_POINT)`, `GetSecurityInfo(DACL)`, `ConvertSecurityDescriptorToStringSecurityDescriptorW`, `LocalFree` | the handle is owned by an `OwnedHandle`; each `LocalAlloc`ed result is freed exactly once after its last use; the SDDL string is read up to its terminator, bounded |
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

/// macOS: the keychain calls `security-framework` 3.7.0 does not wrap (the K_mgmt login-keychain store).
#[cfg(target_os = "macos")]
pub(crate) mod macos {
    use std::ffi::{c_char, c_void};
    use std::ptr;

    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, CFTypeRef, TCFType};
    use core_foundation::string::CFString;
    use security_framework::os::macos::keychain::SecKeychain;

    /// An `OSStatus`.
    pub(crate) type OsStatus = i32;

    /// `errSecParam`.
    const ERR_SEC_PARAM: OsStatus = -50;
    /// `errSecCSReqFailed`: the running code does not satisfy the requirement of the
    /// application the access list would trust ([`add_generic_password_trusting_self`]).
    pub(crate) const ERR_CS_REQ_FAILED: OsStatus = -67050;
    /// `kSecGenericPasswordItemClass` (`'genp'`).
    const GENERIC_PASSWORD_CLASS: u32 = u32::from_be_bytes(*b"genp");
    /// `kSecServiceItemAttr` (`'svce'`).
    const SERVICE_ATTR: u32 = u32::from_be_bytes(*b"svce");
    /// `kSecAccountItemAttr` (`'acct'`).
    const ACCOUNT_ATTR: u32 = u32::from_be_bytes(*b"acct");
    /// `kSecLabelItemAttr` (`'labl'`).
    const LABEL_ATTR: u32 = u32::from_be_bytes(*b"labl");
    /// `kSecUnlockStateStatus`.
    pub(crate) const UNLOCK_STATE_STATUS: u32 = 1;

    #[repr(C)]
    struct SecKeychainAttribute {
        tag: u32,
        length: u32,
        data: *mut c_void,
    }

    #[repr(C)]
    struct SecKeychainAttributeList {
        count: u32,
        attr: *mut SecKeychainAttribute,
    }

    // Security.framework (also linked by security-framework-sys).
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecTrustedApplicationCreateFromPath(
            path: *const c_char,
            app: *mut CFTypeRef,
        ) -> OsStatus;
        fn SecAccessCreate(
            descriptor: CFTypeRef,
            trusted_list: CFTypeRef,
            access: *mut CFTypeRef,
        ) -> OsStatus;
        fn SecKeychainItemCreateFromContent(
            item_class: u32,
            attr_list: *mut SecKeychainAttributeList,
            length: u32,
            data: *const c_void,
            keychain: *mut c_void,
            initial_access: CFTypeRef,
            item: *mut *mut c_void,
        ) -> OsStatus;
        fn SecKeychainGetStatus(keychain: *mut c_void, status: *mut u32) -> OsStatus;
        fn SecTrustedApplicationCopyRequirement(
            app: CFTypeRef,
            requirement: *mut CFTypeRef,
        ) -> OsStatus;
        fn SecCodeCopySelf(flags: u32, code: *mut CFTypeRef) -> OsStatus;
        fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> OsStatus;
        #[cfg(debug_assertions)]
        fn SecKeychainDelete(keychain: *mut c_void) -> OsStatus;
    }

    fn keychain_ref(keychain: &SecKeychain) -> *mut c_void {
        keychain.as_concrete_TypeRef().cast::<c_void>()
    }

    fn len(bytes: &[u8]) -> Result<u32, OsStatus> {
        u32::try_from(bytes.len()).map_err(|_| ERR_SEC_PARAM)
    }

    /// Add a generic-password item (`service`, `account`, `label`) holding `secret` to
    /// `keychain`, with an access list (SecAccess) whose only trusted application is
    /// this executable (ADR-0008 D1).
    ///
    /// ⟨M03 wave 5, round 3⟩ `SecTrustedApplicationCreateFromPath(NULL)` reads the code
    /// **at this program's path on disk**, not the running code. When that file was
    /// replaced after the program started (an update; a rebuild of a shared build tree),
    /// the access list would trust the new file, and this process's own read-back would
    /// need a prompt (`errSecAuthFailed` with interaction off, reported as
    /// `issuer_store_locked`), leaving an item no registration names. So before anything
    /// is written, the running code must satisfy the trusted application's own
    /// requirement (`SecCodeCheckValidity`); otherwise nothing is written
    /// ([`ERR_CS_REQ_FAILED`]). A Developer ID update that keeps the designated
    /// requirement still passes.
    ///
    /// # Errors
    /// The failing call's `OSStatus` (`errSecDuplicateItem` when the item exists;
    /// [`ERR_CS_REQ_FAILED`] when the executable on disk is not the running program).
    pub(crate) fn add_generic_password_trusting_self(
        keychain: &SecKeychain,
        service: &str,
        account: &str,
        label: &str,
        secret: &[u8],
    ) -> Result<(), OsStatus> {
        let mut app: CFTypeRef = ptr::null();
        // SAFETY: a NULL path names the calling executable; `app` is a valid
        // out-pointer.
        let status = unsafe { SecTrustedApplicationCreateFromPath(ptr::null(), &raw mut app) };
        if status != 0 || app.is_null() {
            return Err(if status == 0 { ERR_SEC_PARAM } else { status });
        }
        // SAFETY: the call succeeded, so `app` is a +1 CF object owned here alone;
        // CFType releases it exactly once.
        let app = unsafe { CFType::wrap_under_create_rule(app) };
        running_code_satisfies(&app)?;
        let trusted = CFArray::from_CFTypes(&[app]);
        let descriptor = CFString::new(label);
        let mut access: CFTypeRef = ptr::null();
        // SAFETY: `descriptor` and `trusted` are live CF objects for the call;
        // `access` is a valid out-pointer.
        let status = unsafe {
            SecAccessCreate(
                descriptor.as_CFTypeRef(),
                trusted.as_CFTypeRef(),
                &raw mut access,
            )
        };
        if status != 0 || access.is_null() {
            return Err(if status == 0 { ERR_SEC_PARAM } else { status });
        }
        // SAFETY: as for `app`.
        let access = unsafe { CFType::wrap_under_create_rule(access) };
        let mut service_bytes = service.as_bytes().to_vec();
        let mut account_bytes = account.as_bytes().to_vec();
        let mut label_bytes = label.as_bytes().to_vec();
        let mut attrs = [
            SecKeychainAttribute {
                tag: SERVICE_ATTR,
                length: len(&service_bytes)?,
                data: service_bytes.as_mut_ptr().cast::<c_void>(),
            },
            SecKeychainAttribute {
                tag: ACCOUNT_ATTR,
                length: len(&account_bytes)?,
                data: account_bytes.as_mut_ptr().cast::<c_void>(),
            },
            SecKeychainAttribute {
                tag: LABEL_ATTR,
                length: len(&label_bytes)?,
                data: label_bytes.as_mut_ptr().cast::<c_void>(),
            },
        ];
        let mut list = SecKeychainAttributeList {
            count: 3,
            attr: attrs.as_mut_ptr(),
        };
        let secret_len = len(secret)?;
        // SAFETY: `list`, the three attribute buffers and `secret` outlive the call,
        // which copies them; the keychain and access references are borrowed from live
        // objects; the item out-pointer is NULL, so nothing is returned to release.
        let status = unsafe {
            SecKeychainItemCreateFromContent(
                GENERIC_PASSWORD_CLASS,
                &raw mut list,
                secret_len,
                secret.as_ptr().cast::<c_void>(),
                keychain_ref(keychain),
                access.as_CFTypeRef(),
                ptr::null_mut(),
            )
        };
        drop((service_bytes, account_bytes, label_bytes, access, trusted));
        if status == 0 { Ok(()) } else { Err(status) }
    }

    /// `SecKeychainGetStatus`: the keychain's status bits.
    ///
    /// # Errors
    /// The `OSStatus` (`errSecNoSuchKeychain` when it does not exist).
    pub(crate) fn keychain_status(keychain: &SecKeychain) -> Result<u32, OsStatus> {
        let mut status = 0u32;
        // SAFETY: the keychain reference is borrowed from a live object; `status` is a
        // valid out-pointer.
        let rc = unsafe { SecKeychainGetStatus(keychain_ref(keychain), &raw mut status) };
        if rc == 0 { Ok(status) } else { Err(rc) }
    }

    /// Whether the running program satisfies `app`'s requirement (see
    /// [`add_generic_password_trusting_self`]); [`ERR_CS_REQ_FAILED`] when it does not or
    /// when either cannot be read (fail closed).
    fn running_code_satisfies(app: &CFType) -> Result<(), OsStatus> {
        let mut requirement: CFTypeRef = ptr::null();
        // SAFETY: `app` is a live SecTrustedApplication; `requirement` is a valid
        // out-pointer.
        let status = unsafe {
            SecTrustedApplicationCopyRequirement(app.as_CFTypeRef(), &raw mut requirement)
        };
        if status != 0 || requirement.is_null() {
            return Err(ERR_CS_REQ_FAILED);
        }
        // SAFETY: the call succeeded, so `requirement` is a +1 CF object owned here alone.
        let requirement = unsafe { CFType::wrap_under_create_rule(requirement) };
        let mut code: CFTypeRef = ptr::null();
        // SAFETY: `code` is a valid out-pointer; flags 0 (`kSecCSDefaultFlags`).
        let status = unsafe { SecCodeCopySelf(0, &raw mut code) };
        if status != 0 || code.is_null() {
            return Err(ERR_CS_REQ_FAILED);
        }
        // SAFETY: as for `requirement`.
        let code = unsafe { CFType::wrap_under_create_rule(code) };
        // SAFETY: both references are live CF objects for the call.
        let status =
            unsafe { SecCodeCheckValidity(code.as_CFTypeRef(), 0, requirement.as_CFTypeRef()) };
        if status == 0 {
            Ok(())
        } else {
            Err(ERR_CS_REQ_FAILED)
        }
    }

    /// `SecKeychainDelete` on a disposable file keychain (test configuration only).
    ///
    /// # Errors
    /// The `OSStatus`.
    #[cfg(debug_assertions)]
    pub(crate) fn delete_keychain(keychain: SecKeychain) -> Result<(), OsStatus> {
        // SAFETY: the reference is borrowed from `keychain`, which stays alive until
        // after the call and is then released by its own drop.
        let rc = unsafe { SecKeychainDelete(keychain_ref(&keychain)) };
        drop(keychain);
        if rc == 0 { Ok(()) } else { Err(rc) }
    }
}

/// Windows: DPAPI and owner-only DACLs for the K_mgmt blob store.
#[cfg(windows)]
pub(crate) mod windows {
    use std::ffi::{OsStr, c_void};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use zeroize::{Zeroize, Zeroizing};

    /// Largest `TokenUser` buffer accepted.
    const MAX_TOKEN_INFO_BYTES: u32 = 4096;

    /// Memory an API documents `LocalFree` as the release for.
    struct LocalAllocation(*mut c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from an API that allocates with LocalAlloc
                // (DPAPI output, SDDL and SID string conversions) and is freed exactly
                // once here.
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let w: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        if w[..w.len() - 1].contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains a NUL",
            ));
        }
        Ok(w)
    }

    fn blob(bytes: &[u8]) -> io::Result<CRYPT_INTEGER_BLOB> {
        Ok(CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(bytes.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too large"))?,
            // DPAPI only reads its input blobs.
            pbData: bytes.as_ptr().cast_mut(),
        })
    }

    /// `CryptProtectData` for the current user, with `entropy`, the UI forbidden.
    ///
    /// # Errors
    /// The OS error.
    pub(crate) fn protect(plain: &[u8], entropy: &[u8], description: &str) -> io::Result<Vec<u8>> {
        let input = blob(plain)?;
        let entropy = blob(entropy)?;
        let description: Vec<u16> = OsStr::new(description)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        // SAFETY: the input, entropy and description buffers outlive the call, which
        // only reads them; no prompt structure; `out` is a valid out-pointer.
        let ok = unsafe {
            CryptProtectData(
                &raw const input,
                description.as_ptr(),
                &raw const entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut out,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = LocalAllocation(out.pbData.cast::<c_void>());
        let len = out.cbData as usize;
        let bytes = if len == 0 || out.pbData.is_null() {
            Vec::new()
        } else {
            // SAFETY: on success `out.pbData` points at `out.cbData` initialized
            // bytes, alive until `owned` frees them below.
            unsafe { std::slice::from_raw_parts(out.pbData, len) }.to_vec()
        };
        drop(owned);
        Ok(bytes)
    }

    /// `CryptUnprotectData` with `entropy`, the UI forbidden. The plaintext is copied
    /// into a zeroizing buffer and the system's copy is zeroed before it is freed.
    ///
    /// # Errors
    /// The OS error.
    pub(crate) fn unprotect(sealed: &[u8], entropy: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let input = blob(sealed)?;
        let entropy = blob(entropy)?;
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        // SAFETY: as `protect`; no description is requested (NULL out-pointer).
        let ok = unsafe {
            CryptUnprotectData(
                &raw const input,
                ptr::null_mut(),
                &raw const entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut out,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = LocalAllocation(out.pbData.cast::<c_void>());
        let len = out.cbData as usize;
        let mut plain = Zeroizing::new(Vec::with_capacity(len));
        if len > 0 && !out.pbData.is_null() {
            // SAFETY: on success `out.pbData` points at `out.cbData` initialized,
            // writable bytes owned by this process until `owned` frees them.
            let system = unsafe { std::slice::from_raw_parts_mut(out.pbData, len) };
            plain.extend_from_slice(system);
            system.zeroize();
        }
        drop(owned);
        Ok(plain)
    }

    fn process_token() -> io::Result<OwnedHandle> {
        let mut raw: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing;
        // `raw` is a valid out-pointer for the call.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: OpenProcessToken succeeded, so `raw` is a token handle owned here
        // alone; OwnedHandle closes it exactly once.
        Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
    }

    fn wide_to_string(text: *const u16, max: usize) -> io::Result<String> {
        let mut len = 0usize;
        // SAFETY: the caller passes a NUL-terminated UTF-16 string returned by a
        // conversion API; it is read up to its terminator, bounded by `max`.
        while len < max && unsafe { *text.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` units starting at `text` are initialized (read above).
        let units = unsafe { std::slice::from_raw_parts(text, len) };
        String::from_utf16(units).map_err(|_| io::Error::other("not UTF-16"))
    }

    /// The process user's SID, as a string (`S-1-…`).
    ///
    /// # Errors
    /// The OS error.
    pub(crate) fn current_user_sid() -> io::Result<String> {
        let token = process_token()?;
        let handle = token.as_raw_handle() as HANDLE;
        let mut needed = 0u32;
        // SAFETY: size query: null buffer, length 0, valid out-pointer.
        unsafe { GetTokenInformation(handle, TokenUser, ptr::null_mut(), 0, &raw mut needed) };
        if needed == 0 || needed > MAX_TOKEN_INFO_BYTES {
            return Err(io::Error::other("token information size unavailable"));
        }
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let mut written = 0u32;
        // SAFETY: `buffer` holds at least `needed` bytes, is 8-byte aligned (enough for
        // TOKEN_USER) and outlives the call.
        let ok = unsafe {
            GetTokenInformation(
                handle,
                TokenUser,
                buffer.as_mut_ptr().cast::<c_void>(),
                needed,
                &raw mut written,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetTokenInformation(TokenUser) filled `buffer` with a TOKEN_USER
        // whose SID points inside `buffer`, alive across the conversion below.
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: `sid` is a valid SID inside `buffer`; `text` a valid out-pointer.
        if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let alloc = LocalAllocation(text.cast::<c_void>());
        let sid = wide_to_string(text, 256)?;
        drop(alloc);
        if !sid.starts_with("S-1-") || !sid[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-') {
            return Err(io::Error::other("not a SID string"));
        }
        Ok(sid)
    }

    /// The protected owner-only DACL Heimdall writes: one ACE granting full access to
    /// the process user (`OICI` inheritance on a directory).
    pub(crate) fn owner_only_dacl(sid: &str, directory: bool) -> String {
        let flags = if directory { "OICI" } else { "" };
        format!("D:P(A;{flags};FA;;;{sid})")
    }

    fn owner_only_descriptor(directory: bool) -> io::Result<LocalAllocation> {
        let sid = current_user_sid()?;
        let sddl: Vec<u16> = OsStr::new(&format!("O:{sid}{}", owner_only_dacl(&sid, directory)))
            .encode_wide()
            .chain(Some(0))
            .collect();
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
        Ok(LocalAllocation(descriptor))
    }

    fn attributes(descriptor: &LocalAllocation) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        }
    }

    /// Create `path` exclusively (`CREATE_NEW`, never following a reparse point) with
    /// a protected owner-only DACL; the handle is not inheritable.
    ///
    /// # Errors
    /// `AlreadyExists` when the name exists; any other OS error.
    pub(crate) fn create_owner_only_new(path: &Path) -> io::Result<std::fs::File> {
        let descriptor = owner_only_descriptor(false)?;
        let attributes = attributes(&descriptor);
        let name = wide(path)?;
        // SAFETY: `name` is NUL-terminated and outlives the call; `attributes` and the
        // descriptor it points at outlive the call, which copies the descriptor; a
        // null template handle is allowed.
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ,
                &raw const attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        let error = io::Error::last_os_error();
        drop(descriptor);
        if raw == INVALID_HANDLE_VALUE {
            return Err(error);
        }
        // SAFETY: CreateFileW succeeded; the handle is owned here alone and handed to
        // File, which closes it exactly once.
        Ok(unsafe { std::fs::File::from_raw_handle(raw as RawHandle) })
    }

    /// Create the directory `path` with a protected owner-only DACL (inherited by its
    /// children). An existing entry is `AlreadyExists` and is left unchanged.
    ///
    /// # Errors
    /// The OS error.
    pub(crate) fn create_owner_only_dir(path: &Path) -> io::Result<()> {
        let descriptor = owner_only_descriptor(true)?;
        let attributes = attributes(&descriptor);
        let name = wide(path)?;
        // SAFETY: as `create_owner_only_new`.
        let ok = unsafe { CreateDirectoryW(name.as_ptr(), &raw const attributes) };
        let error = io::Error::last_os_error();
        drop(descriptor);
        if ok == 0 { Err(error) } else { Ok(()) }
    }

    /// The DACL of `path` as SDDL (`D:P(…)`), read without following a reparse point.
    ///
    /// # Errors
    /// The OS error.
    pub(crate) fn dacl_sddl(path: &Path) -> io::Result<String> {
        let name = wide(path)?;
        // SAFETY: `name` is NUL-terminated and outlives the call; no security
        // attributes; a null template handle is allowed.
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateFileW succeeded; the handle is owned here alone.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        let sddl = handle_dacl(handle.as_raw_handle(), SE_FILE_OBJECT);
        drop(handle);
        sddl
    }

    /// ⟨M06 W5⟩ The DACL of the named pipe behind the open `handle` (either end) as SDDL,
    /// for the K_mgmt session agent's tests. The handle must stay open for the call.
    ///
    /// # Errors
    /// The OS error.
    #[cfg(test)]
    pub(crate) fn pipe_handle_dacl_sddl(handle: RawHandle) -> io::Result<String> {
        handle_dacl(
            handle,
            windows_sys::Win32::Security::Authorization::SE_KERNEL_OBJECT,
        )
    }

    /// The DACL of the object behind `handle`, which the caller keeps open for the call.
    fn handle_dacl(
        handle: RawHandle,
        object_type: windows_sys::Win32::Security::Authorization::SE_OBJECT_TYPE,
    ) -> io::Result<String> {
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: the caller keeps the handle open for the call; only the DACL is
        // requested and the descriptor out-pointer is valid.
        let rc = unsafe {
            GetSecurityInfo(
                handle as HANDLE,
                object_type,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(
                i32::try_from(rc).unwrap_or(i32::MAX),
            ));
        }
        let descriptor = LocalAllocation(descriptor);
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: `descriptor` is a valid self-relative descriptor alive for the call;
        // `text` is a valid out-pointer; the length out-pointer may be null.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &raw mut text,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let alloc = LocalAllocation(text.cast::<c_void>());
        let sddl = wide_to_string(text, 4096);
        drop(alloc);
        drop(descriptor);
        sddl
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
