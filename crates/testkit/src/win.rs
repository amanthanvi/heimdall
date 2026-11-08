//! Windows access-control helpers for the fixtures (ADR-0007 §12.47 item 8, WU-0; audit
//! G-T1, G-1): the faithful Windows forms of the Unix assumptions the tests make.
//!
//! * **File mode → DACL.** Heimdall's owner-only form is a protected DACL with one ACE
//!   granting the process user full access, with `OICI` only on a directory
//!   (`D:P(A;;FA;;;<sid>)`, `D:P(A;OICI;FA;;;<sid>)`; `localenv` `sys::quarantine`,
//!   ADR-0007 §12.43 item 3, which compares exactly this text). [`is_owner_only`] is the
//!   check a test ports `mode & 0o077 == 0` to, and [`set_owner_only`] is `chmod 600`
//!   (`700` for a directory), for example for a private key file `ssh.exe` must accept.
//! * **Unreadable file → deny-read ACE.** [`deny_read`] puts an explicit deny ACE for
//!   `FILE_READ_DATA` (`FILE_LIST_DIRECTORY` on a directory) for the process user first in
//!   the DACL, which is what `chmod a-r` means to its owner. Every other right, deleting
//!   included, stays as it was. The returned guard writes the original DACL back on drop.
//! * **The current user as a principal.** [`current_principal`] is
//!   `PrincipalRef::WindowsUser` with the process token's user SID, as the runtime's
//!   transport establishes it (`runtime::dispatch`).
//!
//! Descriptors are written with `SetFileSecurityW`, exactly as given: observed natively,
//! `SetNamedSecurityInfoW` adds the auto-inherited flag (`D:PAI(…)`), which is not the form
//! Heimdall creates or accepts. Every path API here refuses a reparse point instead of
//! following it. No SID is printed by any error.
//!
//! `unsafe`: this module calls the Win32 security API (`GetNamedSecurityInfoW`,
//! `SetFileSecurityW`, the SDDL conversions, `LocalFree`). Each call gets NUL-terminated
//! buffers that outlive it and valid out-pointers, and each `LocalAlloc`ed result is freed
//! exactly once after its last use (`LocalAllocation`).
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr;

use heimdall_domain::principal::PrincipalRef;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SetFileSecurityW,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

/// Longest SDDL string read back, in UTF-16 units.
const MAX_SDDL: usize = 16 * 1024;

/// The process user's SID string (`S-1-5-21-…`), from the process token.
///
/// # Errors
/// The token cannot be read.
pub fn current_user_sid() -> io::Result<String> {
    heimdall_ipc::windows::current_user_sid()
}

/// The process user as the transport identifies it: `PrincipalRef::WindowsUser`.
///
/// # Errors
/// The token cannot be read.
pub fn current_principal() -> io::Result<PrincipalRef> {
    Ok(PrincipalRef::WindowsUser {
        sid: current_user_sid()?,
    })
}

/// Heimdall's owner-only DACL for the process user, in SDDL: protected, one ACE granting
/// full access, inherited by children (`OICI`) only for a directory.
///
/// # Errors
/// The token cannot be read.
pub fn owner_only_dacl(directory: bool) -> io::Result<String> {
    let sid = current_user_sid()?;
    let flags = if directory { "OICI" } else { "" };
    Ok(format!("D:P(A;{flags};FA;;;{sid})"))
}

/// The DACL of `path` in SDDL (`D:…`).
///
/// # Errors
/// `path` is missing, a reparse point, or its security cannot be read.
pub fn dacl_sddl(path: &Path) -> io::Result<String> {
    kind_of(path)?;
    named_security(path, DACL_SECURITY_INFORMATION)?.to_sddl(DACL_SECURITY_INFORMATION)
}

/// The owner SID string of `path`.
///
/// # Errors
/// `path` is missing, a reparse point, or its security cannot be read.
pub fn owner_sid(path: &Path) -> io::Result<String> {
    kind_of(path)?;
    let text =
        named_security(path, OWNER_SECURITY_INFORMATION)?.to_sddl(OWNER_SECURITY_INFORMATION)?;
    text.strip_prefix("O:")
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("the owner is not in SDDL form"))
}

/// Whether `path` is owner-only: owned by the process user, with exactly Heimdall's
/// owner-only DACL for its kind ([`owner_only_dacl`]). A reparse point is never
/// owner-only.
///
/// # Errors
/// `path` is missing, or its security cannot be read.
pub fn is_owner_only(path: &Path) -> io::Result<bool> {
    let directory = match kind_of(path) {
        Ok(directory) => directory,
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => return Ok(false),
        Err(e) => return Err(e),
    };
    Ok(owner_sid(path)? == current_user_sid()? && dacl_sddl(path)? == owner_only_dacl(directory)?)
}

/// Give `path` exactly Heimdall's owner-only DACL for its kind (protected, so nothing is
/// inherited): the faithful form of `chmod 600` (`700` for a directory). Existing
/// children of a directory keep their own DACLs.
///
/// # Errors
/// `path` is missing, a reparse point, or its DACL cannot be set.
pub fn set_owner_only(path: &Path) -> io::Result<()> {
    let directory = kind_of(path)?;
    set_dacl_sddl(path, &owner_only_dacl(directory)?)
}

/// An explicit deny-read ACE for the process user on one path; dropping it writes the
/// original DACL back (best effort; [`DenyRead::restore`] reports the outcome).
#[derive(Debug)]
pub struct DenyRead {
    path: PathBuf,
    original: Option<String>,
}

impl DenyRead {
    /// Write the original DACL back now.
    ///
    /// # Errors
    /// The DACL cannot be set.
    pub fn restore(mut self) -> io::Result<()> {
        self.put_back()
    }

    fn put_back(&mut self) -> io::Result<()> {
        match self.original.take() {
            Some(original) => set_dacl_sddl(&self.path, &original),
            None => Ok(()),
        }
    }
}

impl Drop for DenyRead {
    fn drop(&mut self) {
        let _ = self.put_back();
    }
}

/// Deny the process user `FILE_READ_DATA` on `path` (`FILE_LIST_DIRECTORY` for a
/// directory) with an explicit ACE first in its DACL (deny ACEs come first in canonical
/// order), so opening it for reading fails with access denied while every other right,
/// and deleting it, stay as they were. The DACL's flags and other ACEs are unchanged.
///
/// # Errors
/// `path` is missing, a reparse point, has no DACL, or its DACL cannot be read or set.
pub fn deny_read(path: &Path) -> io::Result<DenyRead> {
    let original = dacl_sddl(path)?;
    let denied = with_deny_read_ace(&original, &current_user_sid()?)?;
    let guard = DenyRead {
        path: path.to_path_buf(),
        original: Some(original),
    };
    set_dacl_sddl(path, &denied)?;
    Ok(guard)
}

/// `dacl` (`D:<flags>(ace)…`) with `(D;;0x1;;;<sid>)` (deny `FILE_READ_DATA`) inserted
/// before its first ACE.
fn with_deny_read_ace(dacl: &str, sid: &str) -> io::Result<String> {
    let Some(body) = dacl.strip_prefix("D:") else {
        return Err(io::Error::other("not a DACL in SDDL form"));
    };
    if body.starts_with("NO_ACCESS_CONTROL") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a NULL DACL has no ACE order to keep",
        ));
    }
    let at = body.find('(').unwrap_or(body.len());
    let (flags, aces) = body.split_at(at);
    Ok(format!("D:{flags}(D;;0x1;;;{sid}){aces}"))
}

/// Whether `path` is a directory; `InvalidInput` for a reparse point (never followed).
fn kind_of(path: &Path) -> io::Result<bool> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a reparse point is not followed",
        ));
    }
    Ok(meta.is_dir())
}

fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let w: Vec<u16> = path.as_os_str().encode_wide().collect();
    if w.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL",
        ));
    }
    Ok(w.into_iter().chain(Some(0)).collect())
}

fn win32_error(rc: u32) -> io::Error {
    io::Error::from_raw_os_error(i32::try_from(rc).unwrap_or(i32::MAX))
}

/// Memory an API documents `LocalFree` as the release for; freed exactly once.
struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API that allocates with LocalAlloc and is
            // freed exactly once here.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

/// A self-relative security descriptor (LocalAlloc'ed).
struct SecurityDescriptor(LocalAllocation);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<SecurityDescriptor> {
        let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd: *mut c_void = ptr::null_mut();
        // SAFETY: `text` is NUL-terminated and outlives the call; `sd` is a valid
        // out-pointer; the size out-pointer may be null.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut sd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(SecurityDescriptor(LocalAllocation(sd)))
    }

    fn to_sddl(&self, info: u32) -> io::Result<String> {
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: the descriptor is valid and alive for the call; `text` is a valid
        // out-pointer; the length out-pointer may be null.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self.0.0,
                SDDL_REVISION_1,
                info,
                &raw mut text,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let alloc = LocalAllocation(text.cast::<c_void>());
        let out = wide_to_string(text, MAX_SDDL);
        drop(alloc);
        out
    }
}

fn named_security(path: &Path, info: u32) -> io::Result<SecurityDescriptor> {
    let name = wide(path)?;
    let mut sd: *mut c_void = ptr::null_mut();
    // SAFETY: `name` is NUL-terminated and outlives the call; only the descriptor
    // out-pointer is requested (the others may be null); the descriptor is
    // LocalAlloc'ed and owned by the returned value.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            info,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(win32_error(rc));
    }
    Ok(SecurityDescriptor(LocalAllocation(sd)))
}

/// `dacl` with the auto-inherit request (`AR`) added when its flags carry `AI`: observed
/// natively, `SetFileSecurityW` keeps the auto-inherited flag only with that request, and
/// drops it otherwise (`D:AI(…)` read back as `D:(…)`). `AR` itself is not stored.
fn with_auto_inherit_request(dacl: &str) -> String {
    if let Some(body) = dacl.strip_prefix("D:") {
        let flags = &body[..body.find('(').unwrap_or(body.len())];
        if flags.contains("AI") && !flags.contains("AR") {
            return format!("D:AR{body}");
        }
    }
    dacl.to_owned()
}

/// Write the DACL of `path` exactly as `sddl` (`D:…`) gives it, flags included.
fn set_dacl_sddl(path: &Path, sddl: &str) -> io::Result<()> {
    kind_of(path)?;
    let name = wide(path)?;
    let sd = SecurityDescriptor::from_sddl(&with_auto_inherit_request(sddl))?;
    // SAFETY: `name` is NUL-terminated and `sd` a valid self-relative descriptor, both
    // alive for the call; only its DACL is applied.
    if unsafe { SetFileSecurityW(name.as_ptr(), DACL_SECURITY_INFORMATION, sd.0.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn wide_to_string(text: *const u16, max: usize) -> io::Result<String> {
    if text.is_null() {
        return Err(io::Error::other("no string"));
    }
    let mut len = 0usize;
    // SAFETY: `text` is a NUL-terminated UTF-16 string owned by the caller's allocation;
    // the scan is bounded by `max` and stops at the terminator.
    while len <= max && unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    if len > max {
        return Err(io::Error::other("string too long"));
    }
    // SAFETY: the first `len` units were just read as initialized.
    let units = unsafe { std::slice::from_raw_parts(text, len) };
    String::from_utf16(units).map_err(|_| io::Error::other("not UTF-16"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::home::Scratch;

    #[test]
    fn current_principal_is_the_token_user() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-"));
        assert_eq!(
            current_principal().unwrap(),
            PrincipalRef::WindowsUser { sid: sid.clone() }
        );
        assert_eq!(
            owner_only_dacl(false).unwrap(),
            format!("D:P(A;;FA;;;{sid})")
        );
        assert_eq!(
            owner_only_dacl(true).unwrap(),
            format!("D:P(A;OICI;FA;;;{sid})")
        );
    }

    #[test]
    fn the_deny_ace_goes_first_and_keeps_the_flags() {
        let s = "S-1-5-21-1-2-3-1001";
        assert_eq!(
            with_deny_read_ace("D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)", s).unwrap(),
            "D:AI(D;;0x1;;;S-1-5-21-1-2-3-1001)(A;ID;FA;;;SY)(A;ID;FA;;;BA)"
        );
        assert_eq!(
            with_deny_read_ace("D:P", s).unwrap(),
            "D:P(D;;0x1;;;S-1-5-21-1-2-3-1001)"
        );
        assert!(with_deny_read_ace("D:NO_ACCESS_CONTROL", s).is_err());
        assert!(with_deny_read_ace("O:BA", s).is_err());
        assert_eq!(
            with_auto_inherit_request("D:AI(A;;FA;;;SY)"),
            "D:ARAI(A;;FA;;;SY)"
        );
        assert_eq!(
            with_auto_inherit_request("D:PAI(A;;FA;;;SY)"),
            "D:ARPAI(A;;FA;;;SY)"
        );
        assert_eq!(
            with_auto_inherit_request("D:P(A;;FA;;;SY)"),
            "D:P(A;;FA;;;SY)"
        );
        assert_eq!(
            with_auto_inherit_request("D:ARAI(A;;FA;;;SY)"),
            "D:ARAI(A;;FA;;;SY)"
        );
    }

    #[test]
    fn owner_only_is_set_and_checked_for_files_and_directories() {
        let s = Scratch::new().unwrap();
        let file = s.path().join("key");
        fs::write(&file, b"k").unwrap();
        let dir = s.path().join("d");
        fs::create_dir(&dir).unwrap();
        // Created under the inherited ACL: not owner-only (the control).
        assert!(!is_owner_only(&file).unwrap());
        assert!(!is_owner_only(&dir).unwrap());
        set_owner_only(&file).unwrap();
        set_owner_only(&dir).unwrap();
        assert!(is_owner_only(&file).unwrap());
        assert!(is_owner_only(&dir).unwrap());
        assert_eq!(dacl_sddl(&file).unwrap(), owner_only_dacl(false).unwrap());
        assert_eq!(dacl_sddl(&dir).unwrap(), owner_only_dacl(true).unwrap());
        assert_eq!(owner_sid(&file).unwrap(), current_user_sid().unwrap());
        // The file form is not the directory form: kinds are not interchangeable.
        assert_ne!(
            owner_only_dacl(false).unwrap(),
            owner_only_dacl(true).unwrap()
        );
        // Still readable and writable by the owner.
        fs::write(&file, b"k2").unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"k2");
        // A file created in the owner-only directory inherits the file form.
        let child = dir.join("c");
        fs::write(&child, b"c").unwrap();
        assert!(
            dacl_sddl(&child)
                .unwrap()
                .contains(&current_user_sid().unwrap())
        );
        assert!(fs::remove_file(&child).is_ok());
        assert!(is_owner_only(&s.path().join("absent")).is_err());
    }

    #[test]
    fn a_reparse_point_is_never_owner_only_and_never_followed() {
        let s = Scratch::new().unwrap();
        let target = s.path().join("t");
        fs::create_dir(&target).unwrap();
        set_owner_only(&target).unwrap();
        let link = s.path().join("l");
        // A directory symbolic link needs Developer Mode; a junction does not, but
        // std cannot create one. Skip only the link half when it cannot be created.
        if std::os::windows::fs::symlink_dir(&target, &link).is_ok() {
            assert!(!is_owner_only(&link).unwrap());
            assert_eq!(
                set_owner_only(&link).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert!(deny_read(&link).is_err());
        }
        assert!(is_owner_only(&target).unwrap());
    }

    #[test]
    fn deny_read_blocks_reading_keeps_delete_and_restores_the_dacl() {
        let s = Scratch::new().unwrap();
        let file = s.path().join("include");
        fs::write(&file, b"Host x\n").unwrap();
        let before = dacl_sddl(&file).unwrap();
        let sid = current_user_sid().unwrap();
        let guard = deny_read(&file).unwrap();
        let denied = dacl_sddl(&file).unwrap();
        // Exactly the original DACL with the deny ACE first: flags and ACEs unchanged.
        assert_eq!(
            denied,
            with_deny_read_ace(&before, &sid)
                .unwrap()
                .replace("(D;;0x1;", "(D;;CC;"),
            "an explicit deny FILE_READ_DATA ACE for the user, first"
        );
        assert_eq!(
            fs::read(&file).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        // Metadata stays readable; only the content is denied.
        assert!(fs::metadata(&file).is_ok());
        guard.restore().unwrap();
        assert_eq!(dacl_sddl(&file).unwrap(), before);
        assert_eq!(fs::read(&file).unwrap(), b"Host x\n");

        // Drop restores too; and an unreadable file can still be deleted (scratch
        // cleanup never needs the guard).
        {
            let _g = deny_read(&file).unwrap();
            assert!(fs::read(&file).is_err());
        }
        assert_eq!(dacl_sddl(&file).unwrap(), before);
        let held = deny_read(&file).unwrap();
        fs::remove_file(&file).unwrap();
        assert!(!file.exists());
        drop(held);

        // On an owner-only (protected) file the protection is kept and restored.
        let key = s.path().join("key");
        fs::write(&key, b"k").unwrap();
        set_owner_only(&key).unwrap();
        let g = deny_read(&key).unwrap();
        assert_eq!(
            dacl_sddl(&key).unwrap(),
            format!("D:P(D;;CC;;;{sid})(A;;FA;;;{sid})")
        );
        assert!(fs::read(&key).is_err());
        drop(g);
        assert!(is_owner_only(&key).unwrap());

        // A directory: listing is denied, then restored.
        let dir = s.path().join("dir");
        fs::create_dir(&dir).unwrap();
        let g = deny_read(&dir).unwrap();
        assert_eq!(
            fs::read_dir(&dir).map(|_| ()).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(g);
        assert!(fs::read_dir(&dir).is_ok());
    }
}
