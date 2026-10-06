//! Windows only: the kernel's view of what an open handle is (round 4, contract §9.6).
//!
//! std's `Metadata::is_file()` on Windows means "neither a directory nor a symlink",
//! so a named pipe or a character device opened by path reports `is_file() == true`
//! and `len() == 0`. `GetFileType` asks the I/O manager for the device type instead:
//! `FILE_TYPE_DISK` for files on a file system, `FILE_TYPE_PIPE` for named and
//! anonymous pipes, `FILE_TYPE_CHAR` for consoles and devices such as `NUL`.

use std::fs::File;
use std::os::windows::io::AsRawHandle;

pub use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_DISK, FILE_TYPE_PIPE};

/// `GetFileType` of an open handle (`FILE_TYPE_UNKNOWN` = 0 on error).
#[allow(unsafe_code)]
pub fn file_type(f: &File) -> u32 {
    // SAFETY: the handle is owned by `f` and stays open for the duration of the call;
    // GetFileType only queries the handle's device type and does not retain it.
    unsafe { windows_sys::Win32::Storage::FileSystem::GetFileType(f.as_raw_handle()) }
}
