//! Read-only Lxss registry read for WSL distribution discovery (M04 U3; ADR-0010 §2; m04-plan
//! U3). Windows only. Owner: the M04 track.
//!
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss` holds one subkey per registered
//! distribution, named by its registration GUID in braces. [`read_entries`] opens the key with
//! `KEY_READ` only (never write access), enumerates the subkeys, and reads exactly four values
//! of each: `DistributionName` (`REG_SZ`), `Version`, `DefaultUid` and `State` (`DWORD`). Other
//! values are never read. A value that is absent or of another type is `None`: the pure parser
//! (`heimdall_wsl::discover::parse_lxss_entry`) decides what an entry is; nothing here guesses.

use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_READ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegCloseKey, RegEnumKeyExW,
    RegGetValueW, RegOpenKeyExW,
};

use super::SysError;

/// The key, below `HKEY_CURRENT_USER`.
const LXSS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Lxss";

/// The longest registry key name (255 characters) plus its terminator.
const KEY_NAME_MAX: usize = 256;

/// The most subkeys read (a bound on a hostile registry, not a real limit).
const ENTRIES_MAX: u32 = 1024;

/// The most UTF-16 units of `DistributionName` read.
const NAME_UNITS_MAX: usize = 1024;

/// One subkey's values, raw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawEntry {
    /// The subkey name (`{GUID}`).
    pub subkey: String,
    /// `DistributionName`.
    pub name: Option<String>,
    /// `Version`.
    pub version: Option<u32>,
    /// `DefaultUid`.
    pub default_uid: Option<u32>,
    /// `State`.
    pub state: Option<u32>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn err(call: &'static str, rc: u32) -> SysError {
    SysError::new(call, format!("os error {rc}"))
}

/// An open registry key, closed exactly once on drop.
struct Key(HKEY);

impl Key {
    /// Open `subkey` of `parent` with `KEY_READ`.
    fn open(parent: HKEY, subkey: &str) -> Result<Key, u32> {
        let name = wide(subkey);
        let mut out: HKEY = ptr::null_mut();
        // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the call; `out` is a
        // writable HKEY; `KEY_READ` is the only access requested.
        let rc = unsafe { RegOpenKeyExW(parent, name.as_ptr(), 0, KEY_READ, &raw mut out) };
        if rc == ERROR_SUCCESS {
            Ok(Key(out))
        } else {
            Err(rc)
        }
    }

    fn dword(&self, value: &str) -> Option<u32> {
        let name = wide(value);
        let mut data: u32 = 0;
        let mut size: u32 = 4;
        // SAFETY: `self.0` is an open key; `name` is NUL-terminated and outlives the call;
        // `data` is a writable 4-byte buffer and `size` states exactly that; the flag
        // restricts the type to a DWORD.
        let rc = unsafe {
            RegGetValueW(
                self.0,
                ptr::null(),
                name.as_ptr(),
                RRF_RT_REG_DWORD,
                ptr::null_mut(),
                (&raw mut data).cast(),
                &raw mut size,
            )
        };
        (rc == ERROR_SUCCESS && size == 4).then_some(data)
    }

    fn string(&self, value: &str) -> Option<String> {
        let name = wide(value);
        let mut size: u32 = 0;
        // SAFETY: as `dword`; a null data pointer asks only for the required byte size.
        let rc = unsafe {
            RegGetValueW(
                self.0,
                ptr::null(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut size,
            )
        };
        if rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA {
            return None;
        }
        let units = (size as usize).div_ceil(2);
        if units == 0 || units > NAME_UNITS_MAX {
            return None;
        }
        let mut buf = vec![0u16; units];
        let mut bytes = u32::try_from(units * 2).ok()?;
        // SAFETY: `buf` holds `bytes` writable bytes and `bytes` states exactly that;
        // RRF_RT_REG_SZ makes the registry NUL-terminate the string.
        let rc = unsafe {
            RegGetValueW(
                self.0,
                ptr::null(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &raw mut bytes,
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let written = (bytes as usize / 2).min(buf.len());
        let end = buf[..written]
            .iter()
            .position(|&u| u == 0)
            .unwrap_or(written);
        String::from_utf16(&buf[..end]).ok()
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by `RegOpenKeyExW` and is closed exactly once.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Read every subkey of the Lxss key. A key that does not exist (WSL never used) is an empty
/// list.
///
/// # Errors
/// [`SysError`] when the key cannot be opened or enumerated for any other reason.
pub fn read_entries() -> Result<Vec<RawEntry>, SysError> {
    let lxss = match Key::open(HKEY_CURRENT_USER, LXSS_KEY) {
        Ok(k) => k,
        Err(rc) if rc == ERROR_FILE_NOT_FOUND => return Ok(Vec::new()),
        Err(rc) => return Err(err("RegOpenKeyExW", rc)),
    };
    let mut out = Vec::new();
    for index in 0..ENTRIES_MAX {
        let mut name = [0u16; KEY_NAME_MAX];
        let mut len = KEY_NAME_MAX as u32;
        // SAFETY: `lxss.0` is an open key; `name` is a writable buffer of `len` UTF-16 units and
        // `len` states exactly that; the reserved, class and time pointers are null as allowed.
        let rc = unsafe {
            RegEnumKeyExW(
                lxss.0,
                index,
                name.as_mut_ptr(),
                &raw mut len,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if rc != ERROR_SUCCESS {
            return Err(err("RegEnumKeyExW", rc));
        }
        let Ok(subkey) = String::from_utf16(&name[..(len as usize).min(KEY_NAME_MAX)]) else {
            out.push(RawEntry::default());
            continue;
        };
        let mut entry = RawEntry {
            subkey: subkey.clone(),
            ..RawEntry::default()
        };
        if let Ok(key) = Key::open(lxss.0, &subkey) {
            entry.name = key.string("DistributionName");
            entry.version = key.dword("Version");
            entry.default_uid = key.dword("DefaultUid");
            entry.state = key.dword("State");
        }
        out.push(entry);
    }
    Ok(out)
}
