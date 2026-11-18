//! Windows login autostart: the per-user Run value (M04 U1; ADR-0010 §1; m04-plan U1).
//! Owner: the M04 track.
//!
//! The entry is the string value `Heimdall-<installation token>` under
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` ([`RUN_SUBKEY`]), holding
//! `"<absolute heimdall.exe>" service run --login`. It is a `REG_SZ`; a value of that name
//! with another type or other data is foreign (`login_entry_conflict`) and is never
//! written over or deleted. Per-user, Medium integrity, no elevation (HKCU). The subkey is
//! injected: a test passes `Software\HeimdallTest\<unique>` and deletes it
//! ([`delete_scratch_key`]); nothing in this crate's tests names the real Run key.
//!
//! `unsafe`: the registry calls below, each wrapped in a safe function with its invariants
//! at the call (inventory: overview §9).

#![allow(unsafe_code)]

use std::io;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW,
};

use super::render::{self, LoginCommand};
use super::{EntryState, InstallOutcome, LoginError, LoginHost, LoginKind, RemoveOutcome};

/// The per-user Run key.
pub const RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// The longest value data read (UTF-16 bytes): anything larger is not Heimdall's.
const MAX_VALUE_BYTES: u32 = 64 * 1024;

fn wide(text: &str) -> io::Result<Vec<u16>> {
    if text.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in a registry name",
        ));
    }
    Ok(text.encode_utf16().chain(Some(0)).collect())
}

fn check(code: u32) -> io::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(
            i32::try_from(code).unwrap_or(i32::MAX),
        ))
    }
}

/// An open registry key, closed on drop.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful RegOpenKeyExW/RegCreateKeyExW and is
        // closed exactly once here.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

/// Open `subkey` under HKCU with `access`; `None` when it does not exist.
fn open(subkey: &str, access: u32) -> io::Result<Option<Key>> {
    let name = wide(subkey)?;
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the call; `key` is
    // a valid out-pointer.
    let rc = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, name.as_ptr(), 0, access, &raw mut key) };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    check(rc)?;
    Ok(Some(Key(key)))
}

/// Open or create `subkey` under HKCU for reading and writing values.
fn open_or_create(subkey: &str) -> io::Result<Key> {
    let name = wide(subkey)?;
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: `name` is NUL-terminated and outlives the call; the class and security
    // attributes may be null; `key` and the disposition out-pointers are valid (the
    // disposition may be null).
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            name.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            std::ptr::null(),
            &raw mut key,
            std::ptr::null_mut(),
        )
    };
    check(rc)?;
    Ok(Key(key))
}

/// What a value holds.
enum Value {
    Absent,
    /// A `REG_SZ` (trailing NULs trimmed), or `None` when it is another type, too large,
    /// or not valid UTF-16.
    Text(Option<String>),
}

fn read_value(key: &Key, name: &str) -> io::Result<Value> {
    let name = wide(name)?;
    let mut kind: u32 = 0;
    let mut size: u32 = 0;
    // SAFETY: `name` is NUL-terminated; with a null data pointer the call only reports
    // the type and the size; the out-pointers are valid.
    let rc = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null(),
            &raw mut kind,
            std::ptr::null_mut(),
            &raw mut size,
        )
    };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(Value::Absent);
    }
    check(rc)?;
    if kind != REG_SZ || size > MAX_VALUE_BYTES {
        return Ok(Value::Text(None));
    }
    let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
    let mut capacity = u32::try_from(buffer.len() * 2).unwrap_or(u32::MAX);
    // SAFETY: `buffer` is writable for `capacity` bytes and outlives the call; the
    // out-pointers are valid.
    let rc = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null(),
            &raw mut kind,
            buffer.as_mut_ptr().cast::<u8>(),
            &raw mut capacity,
        )
    };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(Value::Absent);
    }
    check(rc)?;
    if kind != REG_SZ {
        return Ok(Value::Text(None));
    }
    let units = (capacity as usize / 2).min(buffer.len());
    let mut units = &buffer[..units];
    while let [rest @ .., 0] = units {
        units = rest;
    }
    Ok(Value::Text(String::from_utf16(units).ok()))
}

fn write_value(key: &Key, name: &str, data: &str) -> io::Result<()> {
    let name = wide(name)?;
    let data = wide(data)?;
    let bytes = u32::try_from(data.len() * 2)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "value too large"))?;
    // SAFETY: `name` and `data` are NUL-terminated UTF-16 buffers that outlive the call;
    // `bytes` is the data's size in bytes including the terminator.
    let rc = unsafe {
        RegSetValueExW(
            key.0,
            name.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr().cast::<u8>(),
            bytes,
        )
    };
    check(rc)
}

fn delete_value(key: &Key, name: &str) -> io::Result<()> {
    let name = wide(name)?;
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let rc = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
    if rc == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    check(rc)
}

/// The Run-value host.
#[derive(Debug)]
pub struct RunValueHost {
    subkey: String,
    value_name: String,
}

impl RunValueHost {
    /// A host over `HKCU\<subkey>` with the value `Heimdall-<token>`.
    #[must_use]
    pub fn new(subkey: &str, token: &str) -> Self {
        Self {
            subkey: subkey.to_owned(),
            value_name: render::run_value_name(token),
        }
    }
}

impl LoginHost for RunValueHost {
    fn kind(&self) -> LoginKind {
        LoginKind::RunValue
    }

    fn location(&self) -> String {
        format!(r"HKCU\{}\{}", self.subkey, self.value_name)
    }

    fn render(&self, command: &LoginCommand) -> Result<String, LoginError> {
        Ok(render::run_value_data(command))
    }

    fn observe(&self) -> Result<EntryState, LoginError> {
        let Some(key) = open(&self.subkey, KEY_QUERY_VALUE)? else {
            return Ok(EntryState::Absent);
        };
        Ok(match read_value(&key, &self.value_name)? {
            Value::Absent => EntryState::Absent,
            Value::Text(None) => EntryState::Foreign,
            Value::Text(Some(data)) => {
                render::owned_run_value(&data).map_or(EntryState::Foreign, EntryState::Owned)
            }
        })
    }

    fn install(&self, command: &LoginCommand) -> Result<InstallOutcome, LoginError> {
        let outcome = match self.observe()? {
            EntryState::Foreign => return Err(LoginError::Conflict),
            EntryState::Owned(current) if &current == command => {
                return Ok(InstallOutcome::Unchanged);
            }
            EntryState::Owned(_) => InstallOutcome::Updated,
            EntryState::Absent => InstallOutcome::Created,
        };
        let key = open_or_create(&self.subkey)?;
        write_value(&key, &self.value_name, &render::run_value_data(command))?;
        Ok(outcome)
    }

    fn remove(&self) -> Result<RemoveOutcome, LoginError> {
        match self.observe()? {
            EntryState::Absent => Ok(RemoveOutcome::Absent),
            EntryState::Foreign => Err(LoginError::Conflict),
            EntryState::Owned(_) => {
                let Some(key) = open(&self.subkey, KEY_SET_VALUE)? else {
                    return Ok(RemoveOutcome::Absent);
                };
                delete_value(&key, &self.value_name)?;
                Ok(RemoveOutcome::Removed)
            }
        }
    }
}

/// Prefix a scratch subkey must carry ([`delete_scratch_key`]).
pub const SCRATCH_PREFIX: &str = r"Software\HeimdallTest\";

/// Delete a scratch key a test made under `HKCU\Software\HeimdallTest\`, and its parent
/// when that is empty. The prefix is required: this can never delete the real Run key or
/// anything outside Heimdall's own test namespace.
///
/// # Errors
/// The name is outside the scratch namespace, or the key could not be deleted.
#[doc(hidden)]
pub fn delete_scratch_key(subkey: &str) -> io::Result<()> {
    let inside = subkey.len() > SCRATCH_PREFIX.len()
        && subkey[..SCRATCH_PREFIX.len()].eq_ignore_ascii_case(SCRATCH_PREFIX)
        && !subkey.contains("..");
    if !inside {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a scratch registry key",
        ));
    }
    let name = wide(subkey)?;
    // SAFETY: `name` is NUL-terminated and outlives the call; the key is deleted only
    // when it has no subkeys.
    let rc = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, name.as_ptr()) };
    if rc != ERROR_FILE_NOT_FOUND {
        check(rc)?;
    }
    let parent = wide(SCRATCH_PREFIX.trim_end_matches('\\'))?;
    // SAFETY: as above; a parent that still has subkeys is not deleted (the failure is
    // ignored).
    let _ = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, parent.as_ptr()) };
    Ok(())
}
