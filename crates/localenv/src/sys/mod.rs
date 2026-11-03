//! The third `unsafe` module (overview §9 item 3; ADR-0007 §13; m02-plan U0, U3, U4).
//!
//! Every platform call below is wrapped in a safe function whose invariant is documented
//! on it, and no `unsafe` leaves this module. U3's bodies are here (ADR-0007 §12.15 item
//! 9); U4's are in `quarantine` (owner W2-U4a), re-exported so every public path is
//! `sys::…`.
//!
//! The atomic exchange and the no-replace rename on Unix do **not** live here: they
//! go through rustix's reviewed safe `fs::renameat_with` (Linux `renameat2`
//! `RENAME_EXCHANGE`/`RENAME_NOREPLACE`, macOS `renameatx_np` `RENAME_SWAP`/
//! `RENAME_EXCL`; m02-plan §6 P5, checked at rustix 1.1.6). Birth time comes from
//! rustix `statx` (`STATX_BTIME`) on Linux and `fstat` (`st_birthtimespec`) on
//! macOS, both safe. A probe's own process group is requested through the safe
//! `std::os::unix::process::CommandExt::process_group(0)`.
//!
//! | Function | Platform | Call | Invariant |
//! |---|---|---|---|
//! | [`account_home`] | Unix | `getuid`, `sysconf(_SC_GETPW_R_SIZE_MAX)`, `getpwuid_r` | the account database's home, never `$HOME` (ADR-0007 F19); the buffer outlives every read of `pw_dir`, grown on `ERANGE` up to 1 MiB; an empty or relative home is refused |
//! | [`account_home`] | Windows | `OpenProcessToken(TOKEN_QUERY)`, `GetUserProfileDirectoryW` (userenv; the profile folder, the same value `SHGetKnownFolderPath(FOLDERID_Profile)` returns, without the `CoTaskMemFree` the enabled windows-sys features do not provide) | the token handle owned by an `OwnedHandle` and closed exactly once; the buffer sized by the first call |
//! | [`account_name`] | Unix | as [`account_home`] (`pw_name`) | as [`account_home`]; the name is copied out of the buffer before it is freed |
//! | [`current_uid`] | Unix | `getuid` | no precondition; cannot fail |
//! | [`killpg`] | Unix | `getpgrp`, `killpg(pgid, SIGKILL)` | only a process group a probe or local query created (`process_group(0)`, so the group ID is the child's PID); never 0, 1, a negative ID or this process's own group; called only while the group leader is alive or an unreaped zombie, so the ID cannot have been reused |
//! | [`exited_unreaped`] | Unix | `waitid(P_PID, pid, WEXITED \| WNOHANG \| WNOWAIT)` | only a child this process spawned and has not reaped; `WNOWAIT` leaves it a zombie, which keeps its PID (and so its process group ID) from being reused until `Child::wait` reaps it |
//! | [`JobObject`] | Windows | `CreateJobObjectW`, `SetInformationJobObject(JobObjectExtendedLimitInformation, KILL_ON_JOB_CLOSE)`, `OpenProcess(PROCESS_SET_QUOTA \| PROCESS_TERMINATE)`, `AssignProcessToJobObject`, `CloseHandle` (through `OwnedHandle`) | no breakaway flag is ever set; the job handle is owned by one `OwnedHandle` and closed exactly once, on drop, which kills every process still in the job; a process handle opened for assignment is closed exactly once |
//! | [`replace_file`] | Windows | `ReplaceFileW` with a backup name | the backup keeps the displaced file's identity (`windows_replace_retains_displaced_identity_without_race`); W2-U4a |
//! | [`handle_identity`] | Windows | `GetFileInformationByHandleEx(FileIdInfo)` | volume serial and 128-bit file ID of an open handle; W2-U4a |
//! | `quarantine::fsentry::euid` | Unix | `geteuid()` | no preconditions; cannot fail; W2-U4a |
//! | `quarantine::fsentry::replace` | Windows | `ReplaceFileW(…, REPLACEFILE_WRITE_THROUGH)` | NUL-terminated wide paths that outlive the call; W2-U4a |
//! | `quarantine::fsentry` | Windows | `CreateFileW`, `CreateDirectoryW`, `MoveFileExW` (never `MOVEFILE_REPLACE_EXISTING`), `GetFileInformationByHandle`, `GetFileInformationByHandleEx(FileBasicInfo, FileAttributeTagInfo)`, `GetFinalPathNameByHandleW`, `FlushFileBuffers` | every returned handle is owned by an `OwnedHandle`/`File` and closed exactly once; buffers are sized for the call; W2-U4a |
//! | `quarantine::fsentry` | Windows | `GetSecurityInfo(SE_FILE_OBJECT)`, `ConvertSidToStringSidW`, `ConvertSecurityDescriptorToStringSecurityDescriptorW`, `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `LocalFree` | each `LocalAlloc`ed result is freed exactly once, after the last pointer into it is used; W2-U4a |
//! | `QuarantineDir::rmdir_if_empty` | Windows | `SetFileInformationByHandle` with a POSIX-semantics delete disposition | only on the quarantine directory's own pinned handle; cannot remove an entry (an empty-directory removal); W2-U4a |
//! | [`QuarantineDir::remove_verified`] | all | Unix: `openat` + `fstat`, then `unlinkat` relative to the quarantine's directory handle; Windows: `SetFileInformationByHandle(FileDispositionInfoEx)` on a handle whose identity was checked | **the only removal in the crate**: a name inside the validated `.hm-quarantine` directory, whose identity and digest equal the expected ones at removal (ADR-0007 §5.3); W2-U4a |
//! | [`adopt_inherited_fd`] | Unix | `fcntl(F_GETFD)`, `fstat`, `fcntl(F_GETFL)`, `OwnedFd::from_raw_fd`, `fcntl(F_SETFD, FD_CLOEXEC)`, `fcntl(F_SETFL, flags & !O_NONBLOCK)` | `run --meta-fd`: the descriptor is above 2, open, a pipe, socket or regular file opened for writing; at most one adoption per process (an atomic guard), so this function never creates two owners of one descriptor; close-on-exec and blocking after adoption (ADR-0007 §8, §12.15 item 8 E1; U8) |
//! | [`create_owner_only_exclusive`] | Unix | `open(O_WRONLY \| O_CREAT \| O_EXCL \| O_NOFOLLOW \| O_CLOEXEC, 0600)` through `std::fs::OpenOptions` (no `unsafe` needed) | never follows or replaces an existing entry (a symlink at the name is `EEXIST`); the mode can only be narrowed by the umask |
//! | [`create_owner_only_exclusive`] | Windows | `OpenProcessToken`, `GetTokenInformation(TokenUser)`, `ConvertSidToStringSidW`, `ConvertStringSecurityDescriptorToSecurityDescriptorW` (`O:<user>D:P(A;;FA;;;<user>)`), `CreateFileW(CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT)` with that `SECURITY_ATTRIBUTES`, `LocalFree` | every `LocalAlloc`ed buffer freed exactly once after its last use; the descriptor outlives `CreateFileW`, which copies it; a reparse point at the name is the existing entry, never followed; the handle is not inheritable (ADR-0007 §12.15 item 8 E4) |
#![allow(unsafe_code)]

use std::path::PathBuf;

/// A platform call failed. The message names the call, never a path's content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{call} failed: {detail}")]
pub struct SysError {
    /// The call.
    pub call: &'static str,
    /// The OS error, redacted.
    pub detail: String,
}

impl SysError {
    fn new(call: &'static str, detail: impl Into<String>) -> Self {
        Self {
            call,
            detail: detail.into(),
        }
    }

    /// The last OS error of `call`, as its kind and raw code only.
    fn last_os(call: &'static str) -> Self {
        let e = std::io::Error::last_os_error();
        Self::new(
            call,
            format!(
                "{:?} (os error {})",
                e.kind(),
                e.raw_os_error().unwrap_or(0)
            ),
        )
    }
}

// M02 wave 2 (ADR-0007 §12.15 item 9): U4's platform calls live in `quarantine`
// (owned by W2-U4a), re-exported so every public path stays `sys::…`.
mod quarantine;
pub use quarantine::*;

/// The account's home directory from the account database (ADR-0007 F19): Unix
/// `getpwuid_r(getuid())`, Windows the profile folder of the process token. Never
/// `$HOME` or `%USERPROFILE%`.
///
/// # Errors
/// [`SysError`] when the account has no entry, the entry has no absolute home, or the
/// call fails.
pub fn account_home() -> Result<PathBuf, SysError> {
    #[cfg(unix)]
    {
        unix::account_home()
    }
    #[cfg(windows)]
    {
        windows::account_home()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(SysError::new("account_home", "unsupported platform"))
    }
}

/// The real user ID of this process.
#[cfg(unix)]
#[must_use]
pub fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail (POSIX).
    unsafe { libc::getuid() }
}

/// The account's login name from the account database (`getpwuid_r(getuid())`), for
/// `%u` and `Match localuser` as OpenSSH computes them (never `$USER`).
///
/// # Errors
/// [`SysError`].
#[cfg(unix)]
pub fn account_name() -> Result<String, SysError> {
    unix::account_entry().map(|(name, _)| name)
}

/// Kill a probe's process group with `SIGKILL`. A group that no longer exists
/// (`ESRCH`) is not an error.
///
/// The caller passes the PID of a child it spawned with `process_group(0)` (so the
/// group ID is that PID) and has not yet reaped: the leader alive or a zombie keeps
/// the ID from being reused (see [`exited_unreaped`]).
///
/// # Errors
/// [`SysError`] for 0, 1, an ID that is not a valid `pid_t`, this process's own
/// group, or a failed call.
#[cfg(unix)]
pub fn killpg(pgid: u32) -> Result<(), SysError> {
    let pg = libc::pid_t::try_from(pgid)
        .map_err(|_| SysError::new("killpg", "process group ID out of range"))?;
    if pg <= 1 {
        return Err(SysError::new(
            "killpg",
            "refused: not a probe process group",
        ));
    }
    // SAFETY: getpgrp has no preconditions and cannot fail (POSIX).
    let own = unsafe { libc::getpgrp() };
    if pg == own {
        return Err(SysError::new("killpg", "refused: this process's own group"));
    }
    // SAFETY: plain syscall on an integer group ID; the invariant that the ID names
    // a group this process created and whose leader is unreaped is the caller's
    // (documented above and in the module table).
    let rc = unsafe { libc::killpg(pg, libc::SIGKILL) };
    if rc == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(SysError::new(
        "killpg",
        format!(
            "{:?} (os error {})",
            e.kind(),
            e.raw_os_error().unwrap_or(0)
        ),
    ))
}

/// Whether the child `pid` has exited, **without reaping it** (`waitid` with
/// `WNOWAIT`): it stays a zombie until `Child::wait`, so its PID and process group ID
/// cannot be reused while [`killpg`] runs on the group.
///
/// # Errors
/// [`SysError`] when `pid` is not an unreaped child of this process.
#[cfg(unix)]
pub fn exited_unreaped(pid: u32) -> Result<bool, SysError> {
    let id = libc::id_t::try_from(pid)
        .map_err(|_| SysError::new("waitid", "process ID out of range"))?;
    loop {
        // SAFETY: siginfo_t is plain old data; all-zero is a valid value, and with
        // WNOHANG an unchanged child leaves si_pid at 0 (POSIX waitid).
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid, writable siginfo_t for the duration of the call;
        // WNOWAIT leaves the child waitable, so its later reap by `Child::wait` is
        // unaffected.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                id,
                &raw mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            return Ok(siginfo_pid(&info) != 0);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(SysError::new(
            "waitid",
            format!(
                "{:?} (os error {})",
                e.kind(),
                e.raw_os_error().unwrap_or(0)
            ),
        ));
    }
}

#[cfg(target_os = "linux")]
fn siginfo_pid(info: &libc::siginfo_t) -> libc::pid_t {
    // SAFETY: waitid filled `info` (or left it zeroed); si_pid reads the field of the
    // SIGCHLD union arm, which is the arm waitid writes.
    unsafe { info.si_pid() }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn siginfo_pid(info: &libc::siginfo_t) -> libc::pid_t {
    info.si_pid
}

/// A kill-on-close job object without breakaway (Windows probes and local queries).
/// Dropping it closes the job handle, which kills every process still in the job.
#[cfg(windows)]
#[derive(Debug)]
pub struct JobObject {
    handle: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
impl JobObject {
    /// Create the job.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn kill_on_close() -> Result<Self, SysError> {
        windows::job_kill_on_close().map(|handle| Self { handle })
    }

    /// Put the process `pid` in the job. Prefer [`JobObject::assign_child`], which
    /// cannot name a reused PID.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn assign(&self, pid: u32) -> Result<(), SysError> {
        windows::job_assign_pid(&self.handle, pid)
    }

    /// Put a child this process spawned (and has not waited for) in the job, through
    /// its process handle.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn assign_child(&self, child: &std::process::Child) -> Result<(), SysError> {
        use std::os::windows::io::AsRawHandle;
        windows::job_assign_handle(&self.handle, child.as_raw_handle())
    }
}

/// Adopt the descriptor `run --meta-fd <n>` names (Unix only; ADR-0007 §8, §12.15 item
/// 8 E1). The descriptor must be above 2 (stdin, stdout and stderr are never adopted),
/// open, a pipe, a socket or a regular file, and open for writing. After adoption it is
/// close-on-exec, and an inherited `O_NONBLOCK` is cleared, so a write blocks rather
/// than fails with `EAGAIN` (the flag is on the open file description, which the parent
/// shares).
///
/// At most one descriptor is adopted per process (`run` has exactly one side channel);
/// a second call is refused, so this safe function never creates a second owner of a
/// descriptor it already adopted. The number must name a descriptor this process
/// inherited and does not otherwise use: that is the caller's contract (`run` adopts it
/// while parsing its arguments).
///
/// # Errors
/// [`SysError`] when it is not open, is not a pipe, socket or regular file, is not
/// writable, a descriptor was already adopted, or a flag cannot be set.
#[cfg(unix)]
pub fn adopt_inherited_fd(raw: i32) -> Result<std::os::fd::OwnedFd, SysError> {
    unix::adopt_inherited_fd(raw)
}

/// Create `path` exclusively with owner-only access (ADR-0007 §12.15 item 8 E4; used
/// by `run --meta-file` from wave 3).
///
/// * Unix: `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, mode 0600 (the umask can
///   only narrow it). An existing entry, a symbolic link included, is `AlreadyExists`
///   and is never followed or replaced.
/// * Windows: `CREATE_NEW` with `FILE_FLAG_OPEN_REPARSE_POINT` and a protected DACL
///   granting full access to the current user only (`O:<user>D:P(A;;FA;;;<user>)`)
///   through `SECURITY_ATTRIBUTES`; the handle is not inheritable.
///
/// The result is `std::io::Result` so a caller keeps `ErrorKind::AlreadyExists`
/// (`MetaError::Exists`); the error never carries the path.
///
/// # Errors
/// `AlreadyExists` when the name exists; any other creation failure.
pub fn create_owner_only_exclusive(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        options.open(path)
    }
    #[cfg(windows)]
    {
        windows::create_owner_only_exclusive(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "owner-only creation is not supported on this platform",
        ))
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::{CStr, OsStr};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::SysError;

    /// Largest `getpwuid_r` buffer tried.
    const MAX_PW_BUFFER: usize = 1 << 20;

    pub(super) fn account_home() -> Result<PathBuf, SysError> {
        account_entry().map(|(_, home)| home)
    }

    /// The login name and home of this process's real user ID.
    pub(super) fn account_entry() -> Result<(String, PathBuf), SysError> {
        // SAFETY: getuid has no preconditions and cannot fail (POSIX).
        let uid = unsafe { libc::getuid() };
        // SAFETY: sysconf with a valid name constant has no preconditions.
        let hint = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
        let mut size = usize::try_from(hint)
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or(1024)
            .min(MAX_PW_BUFFER);
        loop {
            let mut buf = vec![0 as libc::c_char; size];
            let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            // SAFETY: `pwd` is valid writable storage for one passwd, `buf` is valid
            // writable storage of `buf.len()` bytes, `result` a valid out-pointer; all
            // outlive the call.
            let rc = unsafe {
                libc::getpwuid_r(
                    uid,
                    pwd.as_mut_ptr(),
                    buf.as_mut_ptr(),
                    buf.len(),
                    &raw mut result,
                )
            };
            if rc == libc::ERANGE && size < MAX_PW_BUFFER {
                size = (size * 2).min(MAX_PW_BUFFER);
                continue;
            }
            if rc != 0 {
                return Err(SysError::new("getpwuid_r", format!("os error {rc}")));
            }
            if result.is_null() {
                return Err(SysError::new("getpwuid_r", "no account entry"));
            }
            // SAFETY: getpwuid_r returned 0 with a non-null result, which points at
            // `pwd`, now initialized; its pw_dir points into `buf`, alive here.
            let dir = unsafe { (*result).pw_dir };
            if dir.is_null() {
                return Err(SysError::new("getpwuid_r", "account entry has no home"));
            }
            // SAFETY: pw_dir is a NUL-terminated string inside `buf` (getpwuid_r's
            // contract), and `buf` outlives this borrow, which is copied below.
            let bytes = unsafe { CStr::from_ptr(dir) }.to_bytes();
            let home = PathBuf::from(OsStr::from_bytes(bytes));
            if !home.is_absolute() {
                return Err(SysError::new(
                    "getpwuid_r",
                    "account home is empty or relative",
                ));
            }
            // SAFETY: as above; pw_name is a NUL-terminated string inside `buf`, or
            // null.
            let name_ptr = unsafe { (*result).pw_name };
            let name = if name_ptr.is_null() {
                String::new()
            } else {
                // SAFETY: non-null pw_name points into `buf`, alive here; copied out.
                String::from_utf8_lossy(unsafe { CStr::from_ptr(name_ptr) }.to_bytes()).into_owned()
            };
            return Ok((name, home));
        }
    }

    /// Set once the first descriptor is adopted.
    static ADOPTED: AtomicBool = AtomicBool::new(false);

    fn fcntl_get(raw: i32, cmd: libc::c_int, call: &'static str) -> Result<libc::c_int, SysError> {
        // SAFETY: F_GETFD/F_GETFL on an integer descriptor read flags only; an invalid
        // descriptor fails with EBADF and has no other effect.
        let v = unsafe { libc::fcntl(raw, cmd) };
        if v < 0 {
            Err(SysError::last_os(call))
        } else {
            Ok(v)
        }
    }

    pub(super) fn adopt_inherited_fd(raw: i32) -> Result<OwnedFd, SysError> {
        if raw < 3 {
            return Err(SysError::new(
                "adopt_inherited_fd",
                "refused: standard descriptors are never adopted",
            ));
        }
        let fd_flags = fcntl_get(raw, libc::F_GETFD, "fcntl(F_GETFD)")?;
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `st` is valid writable storage for one stat; `raw` was just shown
        // to be open by F_GETFD.
        if unsafe { libc::fstat(raw, st.as_mut_ptr()) } != 0 {
            return Err(SysError::last_os("fstat"));
        }
        // SAFETY: fstat returned 0, so `st` is initialized.
        let mode = unsafe { st.assume_init() }.st_mode & libc::S_IFMT;
        if !matches!(mode, libc::S_IFIFO | libc::S_IFSOCK | libc::S_IFREG) {
            return Err(SysError::new(
                "adopt_inherited_fd",
                "refused: not a pipe, socket or regular file",
            ));
        }
        let fl_flags = fcntl_get(raw, libc::F_GETFL, "fcntl(F_GETFL)")?;
        if !matches!(fl_flags & libc::O_ACCMODE, libc::O_WRONLY | libc::O_RDWR) {
            return Err(SysError::new(
                "adopt_inherited_fd",
                "refused: not open for writing",
            ));
        }
        if ADOPTED.swap(true, Ordering::SeqCst) {
            return Err(SysError::new(
                "adopt_inherited_fd",
                "refused: a descriptor was already adopted by this process",
            ));
        }
        // SAFETY: `raw` is open (F_GETFD succeeded), above 2, and this process adopts
        // at most one descriptor (the guard above), so this function creates no second
        // owner; that no other part of the process already owns the number is the
        // caller's contract (an inherited `--meta-fd`).
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: plain fcntl on the descriptor `owned` now owns; sets a flag only.
        if unsafe { libc::fcntl(raw, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } != 0 {
            return Err(SysError::last_os("fcntl(F_SETFD)"));
        }
        if fl_flags & libc::O_NONBLOCK != 0 {
            // SAFETY: as above; clears O_NONBLOCK on the owned descriptor.
            if unsafe { libc::fcntl(raw, libc::F_SETFL, fl_flags & !libc::O_NONBLOCK) } != 0 {
                return Err(SysError::last_os("fcntl(F_SETFL)"));
            }
        }
        Ok(owned)
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::{OsStr, OsString, c_void};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::path::{Path, PathBuf};
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
    };
    use windows_sys::Win32::UI::Shell::GetUserProfileDirectoryW;

    use super::SysError;

    /// Largest profile path accepted, in UTF-16 units.
    const MAX_PROFILE_CHARS: u32 = 32_768;
    /// Largest `TokenUser` buffer accepted.
    const MAX_TOKEN_INFO_BYTES: u32 = 4096;

    fn process_token() -> Result<OwnedHandle, SysError> {
        let mut raw: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing;
        // `raw` is a valid out-pointer for the call.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw) } == 0 {
            return Err(SysError::last_os("OpenProcessToken"));
        }
        // SAFETY: OpenProcessToken succeeded, so `raw` is a token handle owned here
        // alone; OwnedHandle closes it exactly once.
        Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
    }

    pub(super) fn account_home() -> Result<PathBuf, SysError> {
        let token = process_token()?;
        let mut size: u32 = 0;
        // SAFETY: size query: a null buffer with a valid size out-pointer; the call
        // fails with ERROR_INSUFFICIENT_BUFFER and reports the size in characters.
        unsafe {
            GetUserProfileDirectoryW(
                token.as_raw_handle() as HANDLE,
                ptr::null_mut(),
                &raw mut size,
            )
        };
        if size == 0 || size > MAX_PROFILE_CHARS {
            return Err(SysError::new(
                "GetUserProfileDirectoryW",
                "profile size unavailable",
            ));
        }
        let mut buf = vec![0u16; size as usize];
        let mut len = size;
        // SAFETY: `buf` holds `len` UTF-16 units and outlives the call; the token is
        // open for its duration.
        let ok = unsafe {
            GetUserProfileDirectoryW(
                token.as_raw_handle() as HANDLE,
                buf.as_mut_ptr(),
                &raw mut len,
            )
        };
        if ok == 0 {
            return Err(SysError::last_os("GetUserProfileDirectoryW"));
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let home = PathBuf::from(OsString::from_wide(&buf[..end]));
        if !home.is_absolute() {
            return Err(SysError::new(
                "GetUserProfileDirectoryW",
                "profile folder is empty or relative",
            ));
        }
        Ok(home)
    }

    pub(super) fn job_kill_on_close() -> Result<OwnedHandle, SysError> {
        // SAFETY: null attributes and a null name create an unnamed job with the
        // default security descriptor.
        let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if raw.is_null() {
            return Err(SysError::last_os("CreateJobObjectW"));
        }
        // SAFETY: CreateJobObjectW succeeded; the handle is owned here alone.
        let job = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        // SAFETY: the structure is plain data; all-zero is valid, and only
        // LimitFlags is set below (no breakaway flag).
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
            .map_err(|_| SysError::new("SetInformationJobObject", "size out of range"))?;
        // SAFETY: `info` is a valid JOBOBJECT_EXTENDED_LIMIT_INFORMATION of `size`
        // bytes that outlives the call; the job handle is open.
        let ok = unsafe {
            SetInformationJobObject(
                job.as_raw_handle() as HANDLE,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast::<c_void>(),
                size,
            )
        };
        if ok == 0 {
            return Err(SysError::last_os("SetInformationJobObject"));
        }
        Ok(job)
    }

    pub(super) fn job_assign_handle(job: &OwnedHandle, process: RawHandle) -> Result<(), SysError> {
        // SAFETY: both handles are open for the call (the job owned by `job`, the
        // process by the caller's `Child`).
        let ok =
            unsafe { AssignProcessToJobObject(job.as_raw_handle() as HANDLE, process as HANDLE) };
        if ok == 0 {
            return Err(SysError::last_os("AssignProcessToJobObject"));
        }
        Ok(())
    }

    pub(super) fn job_assign_pid(job: &OwnedHandle, pid: u32) -> Result<(), SysError> {
        // SAFETY: plain call; a failure returns null.
        let raw = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
        if raw.is_null() {
            return Err(SysError::last_os("OpenProcess"));
        }
        // SAFETY: OpenProcess succeeded; the handle is owned here and closed once.
        let process = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        job_assign_handle(job, process.as_raw_handle())
    }

    /// Memory an API documents `LocalFree` as the release for.
    struct LocalAllocation(*mut c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from an API that allocates with LocalAlloc
                // (SDDL and SID string conversions) and is freed exactly once here.
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    fn current_user_sid() -> Result<String, SysError> {
        let token = process_token()?;
        let handle = token.as_raw_handle() as HANDLE;
        let mut needed = 0u32;
        // SAFETY: size query: null buffer, length 0, valid out-pointer.
        unsafe { GetTokenInformation(handle, TokenUser, ptr::null_mut(), 0, &raw mut needed) };
        if needed == 0 || needed > MAX_TOKEN_INFO_BYTES {
            return Err(SysError::new(
                "GetTokenInformation",
                "token information size unavailable",
            ));
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
            return Err(SysError::last_os("GetTokenInformation"));
        }
        // SAFETY: GetTokenInformation(TokenUser) filled `buffer` with a TOKEN_USER
        // whose SID points inside `buffer`, alive across the conversion below.
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: `sid` is a valid SID inside `buffer`; `text` a valid out-pointer.
        if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
            return Err(SysError::last_os("ConvertSidToStringSidW"));
        }
        let text = LocalAllocation(text.cast::<c_void>());
        let wide = text.0.cast::<u16>();
        let mut len = 0usize;
        // SAFETY: ConvertSidToStringSidW returned a NUL-terminated UTF-16 string; it
        // is read up to its terminator (bounded at 256 units, longer than any SID).
        while len < 256 && unsafe { *wide.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` units starting at `wide` are initialized (read above).
        let units = unsafe { std::slice::from_raw_parts(wide, len) };
        let sid = String::from_utf16(units)
            .map_err(|_| SysError::new("ConvertSidToStringSidW", "not UTF-16"))?;
        drop(text);
        if !sid.starts_with("S-1-") || !sid[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-') {
            return Err(SysError::new("ConvertSidToStringSidW", "not a SID string"));
        }
        Ok(sid)
    }

    pub(super) fn create_owner_only_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
        let sid = current_user_sid().map_err(|e| std::io::Error::other(e.to_string()))?;
        let sddl: Vec<u16> = OsStr::new(&format!("O:{sid}D:P(A;;FA;;;{sid})"))
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
            return Err(std::io::Error::last_os_error());
        }
        let descriptor = LocalAllocation(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        if wide[..wide.len() - 1].contains(&0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path contains a NUL",
            ));
        }
        // SAFETY: `wide` is NUL-terminated and outlives the call; `attributes` and the
        // descriptor it points at outlive the call, which copies the descriptor; a
        // null template handle is allowed.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ,
                &raw const attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        let error = std::io::Error::last_os_error();
        drop(descriptor);
        if raw == INVALID_HANDLE_VALUE {
            return Err(error);
        }
        // SAFETY: CreateFileW succeeded; the handle is owned here alone and handed to
        // File, which closes it exactly once.
        Ok(unsafe { std::fs::File::from_raw_handle(raw as RawHandle) })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[test]
    fn account_home_is_absolute_and_never_read_from_home_variable() {
        let home = super::account_home().unwrap();
        assert!(home.is_absolute());
        // F19: the account database, not `$HOME`. The variable is not consulted at
        // all, so the answer is the same whatever it holds; a mismatch with `$HOME`
        // is the doctor's `home_mismatch` finding, not an error here.
        assert_eq!(super::account_home().unwrap(), home);
    }

    #[cfg(unix)]
    #[test]
    fn killpg_refuses_reserved_and_own_groups() {
        assert!(super::killpg(0).is_err());
        assert!(super::killpg(1).is_err());
        assert!(super::killpg(u32::MAX).is_err());
        // SAFETY: getpgrp has no preconditions and cannot fail.
        let own = unsafe { libc::getpgrp() };
        let own = u32::try_from(own).unwrap();
        if own > 1 {
            // Refused, never signalled (this test would not survive a SIGKILL).
            assert!(super::killpg(own).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn killpg_kills_a_spawned_group_and_exited_unreaped_keeps_the_zombie() {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 30 & sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        assert!(!super::exited_unreaped(pid).unwrap());
        super::killpg(pid).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !super::exited_unreaped(pid).unwrap() {
            assert!(std::time::Instant::now() < deadline, "group not killed");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // Still waitable: WNOWAIT left the zombie for Child::wait.
        let status = child.wait().unwrap();
        assert!(!status.success());
        // A reaped child is no longer ours to query.
        assert!(super::exited_unreaped(pid).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn create_owner_only_exclusive_is_0600_exclusive_and_never_follows_a_link() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta.ndjson");
        let f = super::create_owner_only_exclusive(&path).unwrap();
        let mode = f.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "group/other bits set: {mode:o}");
        drop(f);
        assert_eq!(
            super::create_owner_only_exclusive(&path)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            super::create_owner_only_exclusive(&link)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert!(!target.exists(), "the link's target was created");
    }

    /// One test owns every adoption in this process: the guard allows one.
    #[cfg(unix)]
    #[test]
    fn adopt_inherited_fd_checks_type_and_mode_once_and_clears_nonblock() {
        use std::os::fd::{AsRawFd, IntoRawFd};
        use std::os::unix::fs::OpenOptionsExt;
        // Standard descriptors and negative numbers are refused.
        for fd in [-1, 0, 1, 2] {
            assert!(super::adopt_inherited_fd(fd).is_err(), "{fd}");
        }
        // A closed descriptor: open then close, and the number is free.
        let dir = tempfile::tempdir().unwrap();
        let closed = std::fs::File::create(dir.path().join("c"))
            .unwrap()
            .into_raw_fd();
        // Closed again through a File that takes the ownership back.
        drop(retake_and_close(closed));
        assert!(super::adopt_inherited_fd(closed).is_err());
        // A directory is not a pipe, socket or regular file.
        let d = std::fs::File::open(dir.path()).unwrap();
        assert!(super::adopt_inherited_fd(d.as_raw_fd()).is_err());
        // A read-only file is not writable.
        let ro_path = dir.path().join("ro");
        std::fs::write(&ro_path, b"").unwrap();
        let ro = std::fs::File::open(&ro_path).unwrap();
        assert!(super::adopt_inherited_fd(ro.as_raw_fd()).is_err());
        // A non-blocking, inheritable pipe writer: adopted, made blocking and
        // close-on-exec.
        let (reader, writer) = std::io::pipe().unwrap();
        let raw = writer.into_raw_fd();
        set_flags_for_test(raw);
        let owned = super::adopt_inherited_fd(raw).unwrap();
        assert_eq!(owned.as_raw_fd(), raw);
        let (fd_flags, fl_flags) = flags_for_test(raw);
        assert_ne!(fd_flags & libc::FD_CLOEXEC, 0, "close-on-exec not set");
        assert_eq!(fl_flags & libc::O_NONBLOCK, 0, "O_NONBLOCK not cleared");
        // A second adoption in this process is refused, whatever the descriptor.
        let other = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.path().join("w"))
            .unwrap();
        assert!(super::adopt_inherited_fd(other.as_raw_fd()).is_err());
        drop(owned);
        drop(reader);
    }

    #[cfg(unix)]
    fn retake_and_close(raw: i32) -> std::fs::File {
        use std::os::fd::FromRawFd;
        // SAFETY: `raw` came from `into_raw_fd` just before; ownership returns here
        // and the File closes it on drop.
        unsafe { std::fs::File::from_raw_fd(raw) }
    }

    #[cfg(unix)]
    fn set_flags_for_test(raw: i32) {
        // SAFETY: test-only flag changes on a descriptor this test owns.
        unsafe {
            let fd = libc::fcntl(raw, libc::F_GETFD);
            assert!(fd >= 0);
            assert_eq!(libc::fcntl(raw, libc::F_SETFD, fd & !libc::FD_CLOEXEC), 0);
            let fl = libc::fcntl(raw, libc::F_GETFL);
            assert!(fl >= 0);
            assert_eq!(libc::fcntl(raw, libc::F_SETFL, fl | libc::O_NONBLOCK), 0);
        }
        let (fd_flags, fl_flags) = flags_for_test(raw);
        assert_eq!(fd_flags & libc::FD_CLOEXEC, 0);
        assert_ne!(fl_flags & libc::O_NONBLOCK, 0);
    }

    #[cfg(unix)]
    fn flags_for_test(raw: i32) -> (i32, i32) {
        // SAFETY: test-only flag reads on an open descriptor.
        unsafe {
            (
                libc::fcntl(raw, libc::F_GETFD),
                libc::fcntl(raw, libc::F_GETFL),
            )
        }
    }
}
