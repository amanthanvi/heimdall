//! The issuer's one `unsafe` module (m03-plan U4; ADR-0008 D1; overview §9): the
//! keychain access list and item creation on macOS, DPAPI, owner-only DACLs and the
//! console mode on Windows. Every platform call is wrapped in a safe function whose
//! invariant is documented below; no `unsafe` leaves this module. Linux needs none
//! (the Secret Service client is a crate; the terminal's echo goes through rustix).
//!
//! | Function | Platform | Call | Invariant |
//! |---|---|---|---|
//! | `macos::add_generic_password_trusting_self` | macOS | `SecTrustedApplicationCreateFromPath(NULL)`, `SecAccessCreate`, `SecKeychainItemCreateFromContent(kSecGenericPasswordItemClass)` | the trusted-application and access objects are wrapped under the create rule (`CFType`) and released exactly once; the attribute buffers and the secret slice outlive the call, which copies them; the item reference out-pointer is NULL (nothing to release); the keychain reference is borrowed from a live `SecKeychain` |
//! | `macos::keychain_status` | macOS | `SecKeychainGetStatus` | the keychain reference is borrowed from a live `SecKeychain`; `status` is a valid out-pointer |
//! | `macos::delete_keychain` (test configuration only) | macOS | `SecKeychainDelete` | only on a keychain opened by path from the test's scratch directory, never one on the search list; the `SecKeychain` outlives the call and is released after it |
//! | `windows::protect` | Windows | `CryptProtectData(CRYPTPROTECT_UI_FORBIDDEN)`, `LocalFree` | input, entropy and description outlive the call, which only reads them; the output blob is copied out and freed with `LocalFree` exactly once |
//! | `windows::unprotect` | Windows | `CryptUnprotectData(CRYPTPROTECT_UI_FORBIDDEN)`, `LocalFree` | as `protect`; the plaintext output is copied into a zeroizing buffer, then overwritten with zeros in place, then freed with `LocalFree` exactly once; no description is requested |
//! | `windows::create_owner_only_new`, `windows::create_owner_only_dir` | Windows | `OpenProcessToken`, `GetTokenInformation(TokenUser)`, `ConvertSidToStringSidW`, `ConvertStringSecurityDescriptorToSecurityDescriptorW` (`O:<user>D:P(A;;FA;;;<user>)`, directories `OICI`), `CreateFileW(CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT)` / `CreateDirectoryW` with that `SECURITY_ATTRIBUTES`, `LocalFree` | the localenv pattern (ADR-0007 §12.15 item 8 E4): every `LocalAlloc`ed buffer freed exactly once after its last use; the descriptor outlives the creating call, which copies it; a reparse point at the name is the existing entry, never followed; handles are not inheritable and are owned by `File`/`OwnedHandle` |
//! | `windows::dacl_sddl` | Windows | `CreateFileW(READ_CONTROL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS \| FILE_FLAG_OPEN_REPARSE_POINT)`, `GetSecurityInfo(DACL)`, `ConvertSecurityDescriptorToStringSecurityDescriptorW`, `LocalFree` | the handle is owned by an `OwnedHandle`; each `LocalAlloc`ed result is freed exactly once after its last use; the SDDL string is read up to its terminator, bounded |
//! | `windows::console_mode`, `windows::set_console_mode` | Windows | `GetConsoleMode`, `SetConsoleMode` | the handle is borrowed from a live `File` opened on `CONIN$`/`CONOUT$`; `mode` is a valid out-pointer |

#![allow(unsafe_code)]

/// macOS: the keychain calls `security-framework` 3.7.0 does not wrap.
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
    /// # Errors
    /// The failing call's `OSStatus` (`errSecDuplicateItem` when the item exists).
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

/// Windows: DPAPI, owner-only DACLs, the console mode.
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
    use windows_sys::Win32::System::Console::{GetConsoleMode, SetConsoleMode};
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
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: the handle is open for the call; only the DACL is requested and the
        // descriptor out-pointer is valid.
        let rc = unsafe {
            GetSecurityInfo(
                handle.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
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
        drop(handle);
        sddl
    }

    /// The console mode of `console` (a `CONIN$`/`CONOUT$` file).
    ///
    /// # Errors
    /// The OS error (not a console).
    pub(crate) fn console_mode(console: &std::fs::File) -> io::Result<u32> {
        let mut mode = 0u32;
        // SAFETY: the handle is borrowed from a live File; `mode` is a valid
        // out-pointer.
        if unsafe { GetConsoleMode(console.as_raw_handle() as HANDLE, &raw mut mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(mode)
    }

    /// Set the console mode of `console`.
    ///
    /// # Errors
    /// The OS error.
    pub(crate) fn set_console_mode(console: &std::fs::File, mode: u32) -> io::Result<()> {
        // SAFETY: the handle is borrowed from a live File.
        if unsafe { SetConsoleMode(console.as_raw_handle() as HANDLE, mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
