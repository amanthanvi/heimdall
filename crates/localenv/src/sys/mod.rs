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
//! | [`account_name`] | Windows | token `TokenUser`, `LookupAccountSidW`, `GetComputerNameW`, CRT `_wcslwr_s` | the token and aligned SID buffer outlive lookup; local accounts omit the computer domain, other accounts retain it; lowercase matches Win32-OpenSSH `pw_name`; no environment lookup |
//! | [`current_uid`] | Unix | `getuid` | no precondition; cannot fail |
//! | [`killpg`] | Unix | `getpgrp`, `killpg(pgid, SIGKILL)` | only a process group a probe or local query created (`process_group(0)`, so the group ID is the child's PID); never 0, 1, a negative ID or this process's own group; called only while the group leader is alive or an unreaped zombie, so the ID cannot have been reused |
//! | [`exited_unreaped`] | Unix | `waitid(P_PID, pid, WEXITED \| WNOHANG \| WNOWAIT)` | only a child this process spawned and has not reaped; `WNOWAIT` leaves it a zombie, which keeps its PID (and so its process group ID) from being reused until `Child::wait` reaps it |
//! | [`JobObject`] | Windows | `CreateJobObjectW`, `SetInformationJobObject(JobObjectExtendedLimitInformation, KILL_ON_JOB_CLOSE)`, `OpenProcess(PROCESS_SET_QUOTA \| PROCESS_TERMINATE)`, `AssignProcessToJobObject`, `CloseHandle` (through `OwnedHandle`) | no breakaway flag is ever set; the job handle is owned by one `OwnedHandle` and closed exactly once, on drop, which kills every process still in the job; a process handle opened for assignment is closed exactly once |
//! | ⟨M03⟩ [`JobObject::contains_pid`] | Windows | `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `IsProcessInJob` | the process handle is owned by an `OwnedHandle` and closed exactly once; a process that cannot be opened is an error, never "not in the job" (U7) |
//! | ⟨M03⟩ [`JobObject::spawn_suspended`], [`SuspendedChild`] | Windows | `CreateProcessW` through std with `CREATE_SUSPENDED` as the only creation flag, the [`JobObject`] calls, `GetProcessTimes` + `GetExitCodeProcess` on the child's handle; `resume`: `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`, `Thread32First`/`Thread32Next`, `OpenThread(THREAD_SUSPEND_RESUME)`, `ResumeThread` | the child is assigned to the kill-on-close job (no breakaway) before it runs any code; a failed assignment or time read terminates and reaps the still-suspended child; `resume` resumes exactly one thread from a suspend count of 1, else closes the job (the child dies never having run); every snapshot, thread and job handle is owned by one `OwnedHandle` and closed exactly once; the child's PID cannot be reused while `std::process::Child` holds its handle (ADR-0008 D8 item 2; §17.4 item 8; U7) |
//! | ⟨M03⟩ [`current_job_process_ids`] | Windows | `IsProcessInJob(GetCurrentProcess(), NULL)`, `QueryInformationJobObject(NULL, JobObjectBasicProcessIdList)` | the pseudo-handle of `GetCurrentProcess` is never closed; a null job handle names the calling process's immediate job; the list is written into a `usize`-aligned buffer of 4 096 + 2 slots whose byte length is passed, the header read only after success, and the IDs read as a safe slice bounded by both the reported count and the buffer (§17.20 item 12; U7's no-job test) |
//! | ⟨M03⟩ [`ProcessPin`], [`VerifiedProcess`] | Linux | `pidfd_open`, `pidfd_send_signal` (rustix, safe), `readlink(/proc/<pid>/exe)` (std) | the pidfd is opened **before** the caller compares the start token and before the image is read, so a matching start time proves the pidfd names that process, and every signal goes through the pidfd (no PID-reuse race); never PID 0, 1 or this process (ADR-0008 D8 item 2 "Closing"; U7) |
//! | ⟨M03⟩ [`ProcessPin`], [`VerifiedProcess`] | macOS | `kill(pid, 0)` and `kill(pid, SIGTERM \| SIGKILL)` (rustix, safe), `proc_pidpath` | `proc_pidpath` writes at most the buffer's `PROC_PIDPATHINFO_MAXSIZE` bytes and its returned length is checked before any read; a signal is sent only after the caller's start-token match and the image match; the small reuse window between that check and `kill` is disclosed (D8 item 2); never PID 0, 1 or this process (U7) |
//! | ⟨M03⟩ [`ProcessPin`], [`VerifiedProcess`] | Windows | `OpenProcess(PROCESS_TERMINATE \| PROCESS_QUERY_LIMITED_INFORMATION)`, `GetProcessTimes`, `GetExitCodeProcess`, `QueryFullProcessImageNameW(PROCESS_NAME_WIN32)`, `TerminateProcess` | the creation time and image are read on the same handle `TerminateProcess` uses, which pins the process; the handle is owned by one `OwnedHandle` and closed exactly once; the image buffer is 32 768 units and the returned length is checked before use (U7) |
//! | [`replace_file`] | Windows | `ReplaceFileW` with a backup name | the backup keeps the displaced file's identity (`windows_replace_retains_displaced_identity_without_race`); W2-U4a |
//! | [`handle_identity`] | Windows | `GetFileInformationByHandleEx(FileIdInfo)` | volume serial and 128-bit file ID of an open handle; W2-U4a |
//! | `quarantine::fsentry::euid` | Unix | `geteuid()` | no preconditions; cannot fail; W2-U4a |
//! | `quarantine::fsentry::replace` | Windows | `ReplaceFileW(…, REPLACEFILE_WRITE_THROUGH)` | NUL-terminated wide paths that outlive the call; W2-U4a |
//! | `quarantine::fsentry` | Windows | `CreateFileW`, `CreateDirectoryW`, `MoveFileExW` (never `MOVEFILE_REPLACE_EXISTING`), `GetFileInformationByHandle`, `GetFileInformationByHandleEx(FileBasicInfo, FileAttributeTagInfo)`, `GetFinalPathNameByHandleW`, `FlushFileBuffers` | every returned handle is owned by an `OwnedHandle`/`File` and closed exactly once; buffers are sized for the call; W2-U4a |
//! | `quarantine::fsentry` | Windows | `GetSecurityInfo(SE_FILE_OBJECT)`, `ConvertSidToStringSidW`, `ConvertSecurityDescriptorToStringSecurityDescriptorW`, `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `LocalFree` | each `LocalAlloc`ed result is freed exactly once, after the last pointer into it is used; W2-U4a |
//! | `QuarantineDir::rmdir_if_empty` | Windows | `SetFileInformationByHandle` with a POSIX-semantics delete disposition | only on a separate DELETE handle revalidated against the released quarantine pin; cannot remove an entry (an empty-directory removal); W2-U4a |
//! | [`QuarantineDir::remove_verified`] | all | Unix: `openat` + `fstat`, then `unlinkat` relative to the quarantine's directory handle; Windows: `SetFileInformationByHandle(FileDispositionInfoEx)` on a handle whose identity was checked | **the only removal in the crate**: a name inside the validated `.hm-quarantine` directory, whose identity and digest equal the expected ones at removal (ADR-0007 §5.3); W2-U4a |
//! | [`adopt_inherited_fd`] | Unix | `fcntl(F_GETFD)`, `fstat`, `fcntl(F_GETFL)`, `fcntl(F_DUPFD_CLOEXEC)`, `OwnedFd::from_raw_fd` on the duplicate, `fcntl(F_SETFD, FD_CLOEXEC)`, `fcntl(F_SETFL, flags & !O_NONBLOCK)` | `run --meta-fd`: the descriptor is above 2, open, a pipe, socket or regular file opened for writing; the returned `OwnedFd` owns a fresh duplicate, never the inherited number, so no descriptor ever has two owners (X01, §12.18 item 1); at most one adoption per process; close-on-exec and blocking after adoption (ADR-0007 §8, §12.15 item 8 E1; U8) |
//! | [`create_owner_only_exclusive`] | Unix | `open(O_WRONLY \| O_CREAT \| O_EXCL \| O_NOFOLLOW \| O_CLOEXEC, 0600)` through `std::fs::OpenOptions` (no `unsafe` needed) | never follows or replaces an existing entry (a symlink at the name is `EEXIST`); the mode can only be narrowed by the umask |
//! | [`create_owner_only_exclusive`] | Windows | `OpenProcessToken`, `GetTokenInformation(TokenUser)`, `ConvertSidToStringSidW`, `ConvertStringSecurityDescriptorToSecurityDescriptorW` (`O:<user>D:P(A;;FA;;;<user>)`), `CreateFileW(CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT)` with that `SECURITY_ATTRIBUTES`, `LocalFree` | every `LocalAlloc`ed buffer freed exactly once after its last use; the descriptor outlives `CreateFileW`, which copies it; a reparse point at the name is the existing entry, never followed; the handle is not inheritable (ADR-0007 §12.15 item 8 E4) |
//! | ⟨M03⟩ [`ManagedDir`] | all | none of its own: Unix rustix `openat(O_DIRECTORY \| O_NOFOLLOW)`, `fstat`, `mkdirat`, `fchmod`, `renameat`, `fdopendir` relative to a verified directory descriptor (safe), every removal through [`QuarantineDir::remove_verified`]; Windows the `quarantine::fsentry` pin (`FILE_FLAG_OPEN_REPARSE_POINT`, no delete sharing), owner SID and owner-only DACL checks, `CreateDirectoryW` with the owner-only DACL, `ReplaceFileW`, no-replace `MoveFileExW` (their rows above) | every level below the anchor is opened relative to its verified parent, a symlink or reparse point is refused, an existing directory that is not owner-only is refused (`managed_dir_unsafe`) and never repaired; files are written to an exclusive temporary name and renamed over the target relative to the same handle; a directory is never removed (ADR-0008 §17.20 item 7; W3-S04) |
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

// ⟨M03⟩ ADR-0008 §17.20 item 7 (W3-S04): the managed directories' anchored file work
// (no `unsafe` of its own; it composes `quarantine::fsentry`).
mod managed_dir;
pub use managed_dir::*;

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

/// The process token's account name in Win32-OpenSSH's lowercase `pw_name` form.
/// Local accounts omit the machine domain; other accounts retain `domain\name`.
/// Never reads `USER`, `USERNAME` or `USERDOMAIN`.
///
/// # Errors
/// [`SysError`] when the token or its named user account cannot be resolved.
#[cfg(windows)]
pub fn account_name() -> Result<String, SysError> {
    windows::account_name()
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

    /// ⟨M03⟩ Whether the live process `pid` is in this job (`IsProcessInJob`), read on a
    /// handle opened with `PROCESS_QUERY_LIMITED_INFORMATION` (U7's
    /// `windows_ssh_grandchild_inside_job`). A process that cannot be opened is an
    /// error, never `false`.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn contains_pid(&self, pid: u32) -> Result<bool, SysError> {
        windows::job_contains_pid(&self.handle, pid)
    }

    /// ⟨M03⟩ ADR-0008 D8 item 2 step 1 (§17.4 item 8; m03-plan U7): spawn `command`
    /// **suspended** (`CREATE_SUSPENDED`, the command's only creation flag) and assign
    /// it to a new kill-on-close job without breakaway, before any of its code runs. Its
    /// creation time is read on the child's own handle.
    ///
    /// The child never runs until [`SuspendedChild::resume`]. If the assignment or the
    /// creation-time read fails, the child is terminated (it is still suspended) and
    /// waited for, and the error returned: no child ever runs outside the job.
    ///
    /// # Errors
    /// [`SysError`] (`CreateProcessW` through std, the job, the assignment, the time).
    pub fn spawn_suspended(mut command: std::process::Command) -> Result<SuspendedChild, SysError> {
        use std::os::windows::process::CommandExt;
        let job = JobObject::kill_on_close()?;
        command.creation_flags(windows::CREATE_SUSPENDED_FLAG);
        let mut child = command.spawn().map_err(|e| {
            SysError::new(
                "CreateProcessW",
                format!(
                    "{:?} (os error {})",
                    e.kind(),
                    e.raw_os_error().unwrap_or(0)
                ),
            )
        })?;
        let contained = job
            .assign_child(&child)
            .and_then(|()| windows::child_creation_time(&child));
        match contained {
            Ok(created_at) => Ok(SuspendedChild {
                pid: child.id(),
                created_at,
                job,
                child,
            }),
            Err(e) => {
                // Still suspended: it has run no code. Terminate and reap it.
                let _ = child.kill();
                let _ = child.wait();
                Err(e)
            }
        }
    }
}

/// ⟨M03⟩ A child created suspended inside its kill-on-close job
/// ([`JobObject::spawn_suspended`]; ADR-0008 D8 item 2). It has run no code. The launcher
/// registers `pid` and `created_at` (the creation time read on the child's handle, the
/// value `Connections::Register` carries) while it stays suspended, then calls
/// [`SuspendedChild::resume`] only after a successful reply; any refusal is
/// [`SuspendedChild::close`] (or a drop), which closes the job and so kills the child
/// before it ever ran.
#[cfg(windows)]
#[derive(Debug)]
pub struct SuspendedChild {
    /// The child's PID (stable: this value holds the child's process handle).
    pub pid: u32,
    /// The child's creation time, read on its handle (`GetProcessTimes`).
    pub created_at: heimdall_contract::Timestamp,
    /// The kill-on-close job holding the child.
    pub job: JobObject,
    child: std::process::Child,
}

/// ⟨M03⟩ A resumed contained child: the job stays open as long as this value (the
/// launcher) does, so the launcher's death ends the child (ADR-0008 D8 item 2).
#[cfg(windows)]
#[derive(Debug)]
pub struct ContainedChild {
    /// The kill-on-close job holding the child.
    pub job: JobObject,
    /// The running child.
    pub child: std::process::Child,
}

#[cfg(windows)]
impl SuspendedChild {
    /// Resume the child's only thread (a `CREATE_SUSPENDED` process has exactly one),
    /// found by a thread snapshot (`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`) and
    /// opened with `THREAD_SUSPEND_RESUME`. Anything but exactly one thread resumed from
    /// a suspend count of 1 is an error, and the job is then closed (the child dies).
    ///
    /// # Errors
    /// [`SysError`]; the child has been terminated.
    pub fn resume(self) -> Result<ContainedChild, SysError> {
        match windows::resume_only_thread(self.pid) {
            Ok(()) => Ok(ContainedChild {
                job: self.job,
                child: self.child,
            }),
            Err(e) => {
                self.close();
                Err(e)
            }
        }
    }

    /// Close the job, which kills the still-suspended child, and reap it.
    pub fn close(self) {
        let SuspendedChild { job, mut child, .. } = self;
        drop(job);
        // The job's close terminated it; `kill` covers a job close that did not.
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// ⟨M03⟩ The job this process is directly in, if any (ADR-0008 §17.20 item 12): `None`
/// when `IsProcessInJob(GetCurrentProcess(), NULL)` is false; otherwise the IDs of the
/// processes in the calling process's **immediate** job (for nested jobs, the
/// innermost), from `QueryInformationJobObject(NULL, JobObjectBasicProcessIdList)`.
/// U7's `windows_non_ssh_run_has_no_job_object_by_default` reads it inside the child
/// `run` launched: a job of the child's own would not contain the launcher.
///
/// # Errors
/// [`SysError`] (either call; more than 4 096 processes in the job is
/// `ERROR_MORE_DATA`).
#[cfg(windows)]
pub fn current_job_process_ids() -> Result<Option<Vec<u32>>, SysError> {
    windows::current_job_process_ids()
}

// --- ⟨M03⟩ owned-connection identity and signalling (ADR-0008 D8 item 2 "Closing";
// reading R8) ---------------------------------------------------------------------------

/// ⟨M03⟩ A process pinned for verification and signalling (ADR-0008 D8 item 2):
///
/// * **Linux:** a pidfd (`pidfd_open`, rustix's safe wrapper), opened **before** any
///   verification, so a later matching start time proves the pidfd names that process,
///   and every signal goes through it (no PID-reuse race);
/// * **macOS:** the PID only. A small reuse window remains between the verification and
///   `kill` (disclosed, D8 item 2);
/// * **Windows:** a handle opened with `PROCESS_TERMINATE |
///   PROCESS_QUERY_LIMITED_INFORMATION`; the creation time and the image are read on it,
///   and `TerminateProcess` is called on it.
///
/// A pin cannot signal: only [`ProcessPin::verify`] makes a [`VerifiedProcess`], and
/// only from a matching start identity and image. Nothing here looks a process up by
/// name or pattern.
#[derive(Debug)]
pub struct ProcessPin {
    pid: u32,
    #[cfg(target_os = "linux")]
    fd: std::os::fd::OwnedFd,
    #[cfg(windows)]
    handle: std::os::windows::io::OwnedHandle,
}

/// ⟨M03⟩ A process whose start identity and image were verified
/// ([`ProcessPin::verify`]): the only value that can be signalled.
#[derive(Debug)]
pub struct VerifiedProcess(ProcessPin);

impl ProcessPin {
    /// Pin `pid`. `Ok(None)`: no such process (Linux/macOS `ESRCH`; Windows
    /// `ERROR_INVALID_PARAMETER`). PID 0, 1 and this process are refused.
    ///
    /// # Errors
    /// [`SysError`] (another failure, for example access denied: the caller reports the
    /// identity unverified).
    pub fn open(pid: u32) -> Result<Option<ProcessPin>, SysError> {
        if pid <= 1 || pid == std::process::id() {
            return Err(SysError::new("process_pin", "refused process ID"));
        }
        #[cfg(target_os = "linux")]
        {
            let raw = i32::try_from(pid)
                .ok()
                .and_then(rustix::process::Pid::from_raw)
                .ok_or_else(|| SysError::new("pidfd_open", "process ID out of range"))?;
            match rustix::process::pidfd_open(raw, rustix::process::PidfdFlags::empty()) {
                Ok(fd) => Ok(Some(ProcessPin { pid, fd })),
                Err(rustix::io::Errno::SRCH) => Ok(None),
                Err(e) => Err(SysError::new(
                    "pidfd_open",
                    format!("os error {}", e.raw_os_error()),
                )),
            }
        }
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            let raw = i32::try_from(pid)
                .ok()
                .and_then(rustix::process::Pid::from_raw)
                .ok_or_else(|| SysError::new("kill", "process ID out of range"))?;
            match rustix::process::test_kill_process(raw) {
                Ok(()) | Err(rustix::io::Errno::PERM) => Ok(Some(ProcessPin { pid })),
                Err(rustix::io::Errno::SRCH) => Ok(None),
                Err(e) => Err(SysError::new(
                    "kill",
                    format!("os error {}", e.raw_os_error()),
                )),
            }
        }
        #[cfg(windows)]
        {
            windows::open_process_pin(pid).map(|h| h.map(|handle| ProcessPin { pid, handle }))
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(SysError::new("process_pin", "unsupported platform"))
        }
    }

    /// The pinned PID.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The process's executable image: Linux `/proc/<pid>/exe` (read after the pidfd
    /// was opened), macOS `proc_pidpath`, Windows `QueryFullProcessImageNameW` on the
    /// pinned handle. `None` when it cannot be read (exited, or not this user's).
    #[must_use]
    pub fn image(&self) -> Option<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_link(format!("/proc/{}/exe", self.pid)).ok()
        }
        #[cfg(target_os = "macos")]
        {
            unix::proc_pidpath(self.pid)
        }
        #[cfg(windows)]
        {
            windows::process_image(&self.handle)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            None
        }
    }

    /// Windows: the creation time read on the pinned handle (`GetProcessTimes`), as the
    /// `Timestamp` `Connections::Register` carries; `None` once the process has exited.
    #[cfg(windows)]
    #[must_use]
    pub fn created_at(&self) -> Option<heimdall_contract::Timestamp> {
        windows::handle_creation_time(&self.handle)
    }

    /// Verify the pin. `start_token_matches` is the caller's comparison of the
    /// persisted start token with one read **after** [`ProcessPin::open`] (on Unix from
    /// the same source that wrote it, `heimdall_runtime::platform::process_start_time`;
    /// on Windows [`ProcessPin::created_at`]). The image is read here, after that, and
    /// must equal `expected_image` (Unix: after canonicalizing `expected_image`;
    /// Windows: ASCII case-insensitively, without a `\\?\` prefix). A process still
    /// running another image (on Unix `heimdall` before or after a failed `exec`) is
    /// refused. `None`: not verified, never to be signalled.
    #[must_use]
    pub fn verify(
        self,
        start_token_matches: bool,
        expected_image: &std::path::Path,
    ) -> Option<VerifiedProcess> {
        if !start_token_matches {
            return None;
        }
        let image = self.image()?;
        image_matches(&image, expected_image).then_some(VerifiedProcess(self))
    }
}

/// Whether a read process image is the expected one (see [`ProcessPin::verify`]).
fn image_matches(image: &std::path::Path, expected: &std::path::Path) -> bool {
    #[cfg(windows)]
    {
        let strip = |p: &std::path::Path| {
            let s = p.to_string_lossy().into_owned();
            s.strip_prefix("\\\\?\\").map(str::to_owned).unwrap_or(s)
        };
        strip(image).eq_ignore_ascii_case(&strip(expected))
    }
    #[cfg(not(windows))]
    {
        let expected = std::fs::canonicalize(expected).unwrap_or_else(|_| expected.to_path_buf());
        image == expected
    }
}

/// A signal to a verified process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessSignal {
    /// Unix `SIGTERM`; Windows `TerminateProcess`.
    Terminate,
    /// Unix `SIGKILL`; Windows `TerminateProcess`.
    Kill,
}

impl VerifiedProcess {
    /// The verified PID.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.0.pid
    }

    /// Send `signal`: Linux `pidfd_send_signal` on the pidfd; macOS `kill` on the PID;
    /// Windows `TerminateProcess` (exit code 1) on the handle. A process that is already
    /// gone (`ESRCH`; Windows: already exited) is not an error.
    ///
    /// # Errors
    /// [`SysError`].
    pub fn signal(&self, signal: ProcessSignal) -> Result<(), SysError> {
        #[cfg(unix)]
        let sig = match signal {
            ProcessSignal::Terminate => rustix::process::Signal::TERM,
            ProcessSignal::Kill => rustix::process::Signal::KILL,
        };
        #[cfg(target_os = "linux")]
        {
            match rustix::process::pidfd_send_signal(&self.0.fd, sig) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
                Err(e) => Err(SysError::new(
                    "pidfd_send_signal",
                    format!("os error {}", e.raw_os_error()),
                )),
            }
        }
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            let raw = i32::try_from(self.0.pid)
                .ok()
                .and_then(rustix::process::Pid::from_raw)
                .ok_or_else(|| SysError::new("kill", "process ID out of range"))?;
            match rustix::process::kill_process(raw, sig) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
                Err(e) => Err(SysError::new(
                    "kill",
                    format!("os error {}", e.raw_os_error()),
                )),
            }
        }
        #[cfg(windows)]
        {
            let _ = signal;
            windows::terminate(&self.0.handle)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = signal;
            Err(SysError::new("signal", "unsupported platform"))
        }
    }

    /// Windows: whether the process has exited (`GetExitCodeProcess` on the handle).
    #[cfg(windows)]
    #[must_use]
    pub fn exited(&self) -> bool {
        windows::handle_creation_time(&self.0.handle).is_none()
    }
}

/// Adopt the descriptor `run --meta-fd <n>` names (Unix only; ADR-0007 §8, §12.15 item
/// 8 E1). The descriptor must be above 2 (stdin, stdout and stderr are never adopted),
/// open, a pipe, a socket or a regular file, and open for writing. After adoption it is
/// close-on-exec, and an inherited `O_NONBLOCK` is cleared, so a write blocks rather
/// than fails with `EAGAIN` (the flag is on the open file description, which the parent
/// shares).
///
/// The descriptor is **duplicated**, not taken (wave-2 review X01; ADR-0007 §12.18 item
/// 1): the returned [`std::os::fd::OwnedFd`] owns a new descriptor (`F_DUPFD_CLOEXEC`,
/// number 3 or above) that nothing else in the process refers to, so this safe function
/// never creates a second owner of `raw`, whoever owns it. `raw` itself is neither closed
/// nor taken; it is only made close-on-exec, so an exec closes every descriptor of the
/// side channel (§8). At most one descriptor is adopted per process (`run` has exactly
/// one side channel); a second call is refused.
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
        // SAFETY: F_DUPFD_CLOEXEC on an open integer descriptor (F_GETFD succeeded)
        // creates a new close-on-exec descriptor numbered 3 or above and has no other
        // effect; `raw` is neither closed nor taken.
        let dup = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
        if dup < 0 {
            return Err(SysError::last_os("fcntl(F_DUPFD_CLOEXEC)"));
        }
        // SAFETY: `dup` was created by the call above and nothing else in the process
        // refers to it, so `owned` is its only owner (X01: no second owner of `raw`).
        let owned = unsafe { OwnedFd::from_raw_fd(dup) };
        // SAFETY: F_SETFD on an open integer descriptor sets a flag only; `raw` is not
        // closed or taken. The inherited number becomes close-on-exec as well (§8).
        if unsafe { libc::fcntl(raw, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } != 0 {
            return Err(SysError::last_os("fcntl(F_SETFD)"));
        }
        if fl_flags & libc::O_NONBLOCK != 0 {
            // SAFETY: F_SETFL on the descriptor `owned` owns; O_NONBLOCK lives on the
            // open file description, which `raw` shares, so both become blocking.
            if unsafe { libc::fcntl(dup, libc::F_SETFL, fl_flags & !libc::O_NONBLOCK) } != 0 {
                return Err(SysError::last_os("fcntl(F_SETFL)"));
            }
        }
        Ok(owned)
    }

    /// ⟨M03⟩ The executable path of `pid` (`proc_pidpath`), or `None`.
    #[cfg(target_os = "macos")]
    pub(super) fn proc_pidpath(pid: u32) -> Option<PathBuf> {
        let pid = libc::c_int::try_from(pid).ok()?;
        let size = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE).ok()?;
        let mut buf = vec![0u8; size];
        let len = u32::try_from(buf.len()).ok()?;
        // SAFETY: `buf` is `len` writable bytes that outlive the call; proc_pidpath
        // writes at most `len` bytes and returns the length written (0 or less on
        // failure), checked before any read.
        let rc = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), len) };
        let n = usize::try_from(rc)
            .ok()
            .filter(|n| *n > 0 && *n <= buf.len())?;
        buf.truncate(n);
        Some(PathBuf::from(OsStr::from_bytes(&buf)))
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
        FILETIME, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
        STILL_ACTIVE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, IsWellKnownSid, LookupAccountSidW, SECURITY_ATTRIBUTES, SidTypeUser,
        TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_PROCESS_ID_LIST,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicProcessIdList,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, GetCurrentProcess, GetExitCodeProcess, GetProcessTimes, OpenProcess,
        OpenProcessToken, OpenThread, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SET_QUOTA, PROCESS_TERMINATE, QueryFullProcessImageNameW, ResumeThread,
        THREAD_SUSPEND_RESUME, TerminateProcess,
    };
    use windows_sys::Win32::System::WindowsProgramming::GetComputerNameW;
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

    /// The same name resolution as Win32-OpenSSH 9.5p2 win32compat/pwd.c:
    /// local SAM accounts have no domain prefix; other users use domain\name.
    /// Its CRT wide-character lowercase runs before conversion to UTF-8.
    pub(super) fn account_name() -> Result<String, SysError> {
        let token = process_token()?;
        let mut needed = 0u32;
        // SAFETY: size query with a valid token and size out-pointer.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle() as HANDLE,
                TokenUser,
                ptr::null_mut(),
                0,
                &raw mut needed,
            );
        }
        if needed < size_of::<TOKEN_USER>() as u32 || needed > MAX_TOKEN_INFO_BYTES {
            return Err(SysError::new(
                "GetTokenInformation",
                "token information size unavailable",
            ));
        }
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: the aligned buffer holds at least `needed` bytes and outlives all
        // reads of TOKEN_USER and the SID inside it; the token remains open.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle() as HANDLE,
                TokenUser,
                buffer.as_mut_ptr().cast::<c_void>(),
                needed,
                &raw mut needed,
            )
        } == 0
        {
            return Err(SysError::last_os("GetTokenInformation"));
        }
        // SAFETY: the successful call initialized TOKEN_USER in the aligned buffer.
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let (mut names, mut domains, mut kind) = (0u32, 0u32, 0i32);
        // SAFETY: SID remains in `buffer`; null output buffers query their sizes.
        unsafe {
            LookupAccountSidW(
                ptr::null(),
                sid,
                ptr::null_mut(),
                &raw mut names,
                ptr::null_mut(),
                &raw mut domains,
                &raw mut kind,
            );
        }
        if names == 0 || names > MAX_PROFILE_CHARS || domains > MAX_PROFILE_CHARS {
            return Err(SysError::new(
                "LookupAccountSidW",
                "account size unavailable",
            ));
        }
        let mut name = vec![0u16; names as usize];
        let mut domain = vec![0u16; domains.max(1) as usize];
        // SAFETY: both buffers match the reported capacities; SID and buffers live
        // across the call. The returned lengths exclude the terminating NULs.
        if unsafe {
            LookupAccountSidW(
                ptr::null(),
                sid,
                name.as_mut_ptr(),
                &raw mut names,
                domain.as_mut_ptr(),
                &raw mut domains,
                &raw mut kind,
            )
        } == 0
        {
            return Err(SysError::last_os("LookupAccountSidW"));
        }
        if kind != SidTypeUser
            || names == 0
            || names as usize >= name.len()
            || domains as usize >= domain.len()
        {
            return Err(SysError::new(
                "LookupAccountSidW",
                "not a named user account",
            ));
        }
        name.truncate(names as usize);
        domain.truncate(domains as usize);
        let mut computer = [0u16; 256];
        let mut count = computer.len() as u32;
        // SAFETY: a writable buffer of `count` units and a valid count out-pointer.
        if unsafe { GetComputerNameW(computer.as_mut_ptr(), &raw mut count) } == 0 {
            return Err(SysError::last_os("GetComputerNameW"));
        }
        let lower = |mut text: Vec<u16>| -> Result<Vec<u16>, SysError> {
            unsafe extern "C" {
                fn _wcslwr_s(text: *mut u16, size: usize) -> i32;
            }
            text.push(0);
            // SAFETY: writable NUL-terminated UTF-16, capacity includes the NUL.
            if unsafe { _wcslwr_s(text.as_mut_ptr(), text.len()) } != 0 {
                return Err(SysError::new("_wcslwr_s", "account lowercase failed"));
            }
            text.pop();
            Ok(text)
        };
        let local = lower(domain.clone())? == lower(computer[..count as usize].to_vec())?;
        // SAFETY: SID is valid inside the still-live token information buffer.
        let system = unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0;
        let mut resolved = if local || system { Vec::new() } else { domain };
        if !resolved.is_empty() {
            resolved.push(u16::from(b'\\'));
        }
        resolved.extend(name);
        String::from_utf16(&lower(resolved)?)
            .map_err(|_| SysError::new("LookupAccountSidW", "account name is not UTF-16"))
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

    // --- ⟨M03⟩ contained launch and owned-connection identity (U7; reading R8) -------

    /// `CREATE_SUSPENDED`, the only creation flag of a contained launch.
    pub(super) const CREATE_SUSPENDED_FLAG: u32 = CREATE_SUSPENDED;

    /// The `ERROR_INVALID_PARAMETER` `OpenProcess` returns for a PID with no process.
    const ERROR_INVALID_PARAMETER: i32 = 87;

    /// Windows FILETIME ticks (100 ns since 1601-01-01) at the Unix epoch.
    const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

    pub(super) fn job_contains_pid(job: &OwnedHandle, pid: u32) -> Result<bool, SysError> {
        // SAFETY: plain call; a failure returns null.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() {
            return Err(SysError::last_os("OpenProcess"));
        }
        // SAFETY: OpenProcess succeeded; the handle is owned here and closed once.
        let process = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        let mut inside: windows_sys::core::BOOL = 0;
        // SAFETY: both handles are open for the call; `inside` is a valid out-pointer.
        let ok = unsafe {
            IsProcessInJob(
                process.as_raw_handle() as HANDLE,
                job.as_raw_handle() as HANDLE,
                &raw mut inside,
            )
        };
        if ok == 0 {
            return Err(SysError::last_os("IsProcessInJob"));
        }
        Ok(inside != 0)
    }

    /// See [`super::current_job_process_ids`].
    pub(super) fn current_job_process_ids() -> Result<Option<Vec<u32>>, SysError> {
        let mut inside: windows_sys::core::BOOL = 0;
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no closing; a
        // null job handle asks about any job; `inside` is a valid out-pointer.
        let ok = unsafe { IsProcessInJob(GetCurrentProcess(), ptr::null_mut(), &raw mut inside) };
        if ok == 0 {
            return Err(SysError::last_os("IsProcessInJob"));
        }
        if inside == 0 {
            return Ok(None);
        }
        const SLOTS: usize = 4096;
        let first = std::mem::offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList);
        if first % size_of::<usize>() != 0
            || std::mem::align_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() > align_of::<usize>()
        {
            return Err(SysError::new(
                "QueryInformationJobObject",
                "unexpected list layout",
            ));
        }
        let first = first / size_of::<usize>();
        let mut buf = vec![0usize; first + SLOTS];
        let bytes = u32::try_from(buf.len() * size_of::<usize>())
            .map_err(|_| SysError::new("QueryInformationJobObject", "buffer too large"))?;
        // SAFETY: a null job handle names the calling process's immediate job; `buf` is
        // writable for `bytes` bytes and aligned for the structure (checked above); the
        // returned-length pointer may be null.
        let ok = unsafe {
            QueryInformationJobObject(
                ptr::null_mut(),
                JobObjectBasicProcessIdList,
                buf.as_mut_ptr().cast::<c_void>(),
                bytes,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(SysError::last_os("QueryInformationJobObject"));
        }
        // SAFETY: the call succeeded, so the header at the start of `buf` (aligned and
        // inside it) is initialized.
        let listed = unsafe {
            (*buf.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>()).NumberOfProcessIdsInList
        };
        let n = usize::try_from(listed).unwrap_or(SLOTS).min(SLOTS);
        Ok(Some(
            buf[first..first + n]
                .iter()
                .filter_map(|&id| u32::try_from(id).ok())
                .collect(),
        ))
    }

    /// The creation time of a **live** process, read on `handle` (`GetProcessTimes`;
    /// `GetExitCodeProcess` says it is still active), as a `Timestamp`.
    fn creation_time(handle: HANDLE) -> Option<heimdall_contract::Timestamp> {
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: `handle` is an open process handle with query rights (the caller's);
        // every out-pointer is valid, aligned and writable.
        let times = unsafe {
            GetProcessTimes(
                handle,
                &raw mut created,
                &raw mut exited,
                &raw mut kernel,
                &raw mut user,
            )
        };
        let mut code: u32 = 0;
        // SAFETY: as above; `code` is a writable u32.
        let alive = unsafe { GetExitCodeProcess(handle, &raw mut code) } != 0
            && code == STILL_ACTIVE.cast_unsigned();
        if times == 0 || !alive {
            return None;
        }
        let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        let since_epoch = ticks.checked_sub(FILETIME_UNIX_EPOCH)?;
        heimdall_contract::Timestamp::from_nanosecond(i128::from(since_epoch) * 100).ok()
    }

    pub(super) fn handle_creation_time(
        handle: &OwnedHandle,
    ) -> Option<heimdall_contract::Timestamp> {
        creation_time(handle.as_raw_handle() as HANDLE)
    }

    pub(super) fn child_creation_time(
        child: &std::process::Child,
    ) -> Result<heimdall_contract::Timestamp, SysError> {
        creation_time(child.as_raw_handle() as HANDLE)
            .ok_or_else(|| SysError::new("GetProcessTimes", "creation time unavailable"))
    }

    /// Resume the only thread of the suspended process `pid` (module docs of
    /// `SuspendedChild::resume`).
    pub(super) fn resume_only_thread(pid: u32) -> Result<(), SysError> {
        // SAFETY: plain call; a failure returns INVALID_HANDLE_VALUE.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return Err(SysError::last_os("CreateToolhelp32Snapshot"));
        }
        // SAFETY: the snapshot handle is owned here alone and closed exactly once.
        let snap = unsafe { OwnedHandle::from_raw_handle(snap as RawHandle) };
        // SAFETY: plain old data; all-zero is valid, and dwSize is set before use.
        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = u32::try_from(size_of::<THREADENTRY32>())
            .map_err(|_| SysError::new("Thread32First", "size out of range"))?;
        let mut threads = Vec::new();
        // SAFETY: the snapshot is open; `entry` is a valid THREADENTRY32 with dwSize set.
        let mut more =
            unsafe { Thread32First(snap.as_raw_handle() as HANDLE, &raw mut entry) } != 0;
        while more {
            if entry.th32OwnerProcessID == pid {
                threads.push(entry.th32ThreadID);
            }
            // SAFETY: as above.
            more = unsafe { Thread32Next(snap.as_raw_handle() as HANDLE, &raw mut entry) } != 0;
        }
        drop(snap);
        let [thread] = threads[..] else {
            return Err(SysError::new(
                "Thread32Next",
                format!("{} threads in a suspended child", threads.len()),
            ));
        };
        // SAFETY: plain call; a failure returns null.
        let raw = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread) };
        if raw.is_null() {
            return Err(SysError::last_os("OpenThread"));
        }
        // SAFETY: OpenThread succeeded; the handle is owned here and closed once.
        let thread = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        // SAFETY: an open thread handle with THREAD_SUSPEND_RESUME.
        let previous = unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) };
        if previous == u32::MAX {
            return Err(SysError::last_os("ResumeThread"));
        }
        if previous != 1 {
            return Err(SysError::new(
                "ResumeThread",
                format!("suspend count {previous}"),
            ));
        }
        Ok(())
    }

    pub(super) fn open_process_pin(pid: u32) -> Result<Option<OwnedHandle>, SysError> {
        // SAFETY: plain call; a failure returns null.
        let raw = unsafe {
            OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        if raw.is_null() {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(ERROR_INVALID_PARAMETER) {
                return Ok(None);
            }
            return Err(SysError::new(
                "OpenProcess",
                format!(
                    "{:?} (os error {})",
                    e.kind(),
                    e.raw_os_error().unwrap_or(0)
                ),
            ));
        }
        // SAFETY: OpenProcess succeeded; the handle is owned by the pin and closed once.
        Ok(Some(unsafe {
            OwnedHandle::from_raw_handle(raw as RawHandle)
        }))
    }

    pub(super) fn process_image(handle: &OwnedHandle) -> Option<PathBuf> {
        let mut buf = vec![0u16; MAX_PROFILE_CHARS as usize];
        let mut len = MAX_PROFILE_CHARS;
        // SAFETY: `buf` holds `len` UTF-16 units and outlives the call; the handle has
        // PROCESS_QUERY_LIMITED_INFORMATION; `len` is updated to the units written.
        let ok = unsafe {
            QueryFullProcessImageNameW(
                handle.as_raw_handle() as HANDLE,
                PROCESS_NAME_WIN32,
                buf.as_mut_ptr(),
                &raw mut len,
            )
        };
        if ok == 0 || len as usize > buf.len() {
            return None;
        }
        Some(PathBuf::from(OsString::from_wide(&buf[..len as usize])))
    }

    pub(super) fn terminate(handle: &OwnedHandle) -> Result<(), SysError> {
        if creation_time(handle.as_raw_handle() as HANDLE).is_none() {
            return Ok(());
        }
        // SAFETY: an open process handle with PROCESS_TERMINATE.
        if unsafe { TerminateProcess(handle.as_raw_handle() as HANDLE, 1) } == 0 {
            // Exited between the check and the call: access denied on an exiting
            // process; re-check before reporting.
            if creation_time(handle.as_raw_handle() as HANDLE).is_none() {
                return Ok(());
            }
            return Err(SysError::last_os("TerminateProcess"));
        }
        Ok(())
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
        // A non-blocking, inheritable pipe writer that another object in this process
        // still owns (`writer`): adopted as a duplicate, made blocking and close-on-exec.
        let (mut reader, mut writer) = std::io::pipe().unwrap();
        let raw = writer.as_raw_fd();
        set_flags_for_test(raw);
        let owned = super::adopt_inherited_fd(raw).unwrap();
        // X01 (ADR-0007 §12.18 item 1): the adopted descriptor is a new one, so dropping
        // it cannot close the number `writer` owns.
        assert_ne!(
            owned.as_raw_fd(),
            raw,
            "adoption took the caller's descriptor"
        );
        for fd in [raw, owned.as_raw_fd()] {
            let (fd_flags, fl_flags) = flags_for_test(fd);
            assert_ne!(
                fd_flags & libc::FD_CLOEXEC,
                0,
                "close-on-exec not set on {fd}"
            );
            assert_eq!(
                fl_flags & libc::O_NONBLOCK,
                0,
                "O_NONBLOCK not cleared on {fd}"
            );
        }
        // The reviewer's scenario: drop the adopted descriptor, open an unrelated file
        // (which may reuse a freed number), then write through the original owner. The
        // bytes reach the pipe, never the unrelated file.
        drop(owned);
        let unrelated_path = dir.path().join("unrelated");
        let unrelated = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&unrelated_path)
            .unwrap();
        {
            use std::io::{Read, Write};
            writer.write_all(b"meta").unwrap();
            drop(writer);
            let mut got = Vec::new();
            reader.read_to_end(&mut got).unwrap();
            assert_eq!(got, b"meta", "the original owner's writes went elsewhere");
        }
        drop(unrelated);
        assert_eq!(
            std::fs::metadata(&unrelated_path).unwrap().len(),
            0,
            "a write through the original owner reached an unrelated file"
        );
        // A second adoption in this process is refused, whatever the descriptor.
        let other = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.path().join("w"))
            .unwrap();
        assert!(super::adopt_inherited_fd(other.as_raw_fd()).is_err());
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
