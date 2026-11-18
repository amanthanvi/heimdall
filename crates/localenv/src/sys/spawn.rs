//! Explicit handle-list process spawn (M04 U2; ADR-0010 §1 item 6, closing ADR-0006 §13.9;
//! m04-plan U2). Owner: the M04 track.
//!
//! **What it guarantees.** A child started here inherits **exactly** its three standard
//! stream handles and nothing else this process holds as inheritable. On Windows that is
//! `CreateProcessW` with `bInheritHandles = TRUE` and a `STARTUPINFOEXW` whose
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` names only the child-side stream handles; std's
//! `Command` cannot pass the attribute (`CommandExt::raw_attribute` is not stable in the
//! pinned 1.99.1), so the call is made here. On Unix it is std's spawn with the streams
//! set explicitly (std opens every descriptor close-on-exec, so nothing else is passed).
//!
//! **The pipe ends.** The parent's end of a pipe is never inheritable. The child's end is
//! made inheritable only after both ends exist, only while the spawn lock is held, and is
//! closed in this process as soon as `CreateProcessW` returns. The lock excludes a
//! concurrent `spawn_listed`; a concurrent std `Command::spawn` in this process (every
//! other spawn site) takes no such lock, so for the length of one `CreateProcessW` it could
//! still inherit these three ends. That window is the residual of the spawn sites not yet
//! converted (m04 U2 notes); once every runtime child starts here it is empty.
//!
//! **Reading `Command`.** The program, arguments, environment changes and working directory
//! are read through `get_program`, `get_args`, `get_envs` and `get_current_dir`. std offers
//! no getter for `env_clear` or for the stream configuration, so [`spawn_with_handle_list`]
//! always runs with all three streams piped and treats the command as inheriting this
//! process's environment; a caller that needs a cleared environment, a null stream or
//! creation flags uses [`spawn_listed`] and [`ListedSpawn`].

use std::fs::File;
use std::process::Command;

use super::SysError;

/// How one standard stream of the child is connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListedStdio {
    /// A pipe to this process (the matching [`ListedChild`] field holds the parent's end).
    Piped,
    /// The null device (the matching [`ListedChild`] field is `None`).
    Null,
}

/// Options [`std::process::Command`] cannot carry for [`spawn_listed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListedSpawn {
    /// The child's standard input.
    pub stdin: ListedStdio,
    /// The child's standard output.
    pub stdout: ListedStdio,
    /// The child's standard error.
    pub stderr: ListedStdio,
    /// Start from an empty environment (what `Command::env_clear` does) instead of this
    /// process's, before the command's own changes.
    pub env_clear: bool,
    /// Windows process-creation flags (`DETACHED_PROCESS`, …); ignored elsewhere.
    pub creation_flags: u32,
}

impl ListedSpawn {
    /// Three pipes, the inherited environment, no creation flags (what
    /// [`spawn_with_handle_list`] uses).
    #[must_use]
    pub const fn piped() -> Self {
        Self {
            stdin: ListedStdio::Piped,
            stdout: ListedStdio::Piped,
            stderr: ListedStdio::Piped,
            env_clear: false,
            creation_flags: 0,
        }
    }
}

/// A child started with an explicit inherited-handle list.
#[derive(Debug)]
pub struct ListedChild {
    /// The parent's end of the child's standard input (`None` for [`ListedStdio::Null`]).
    pub stdin: Option<File>,
    /// The parent's end of the child's standard output.
    pub stdout: Option<File>,
    /// The parent's end of the child's standard error.
    pub stderr: Option<File>,
    inner: imp::Process,
}

impl ListedChild {
    /// The child's process ID. Stable while this value lives (it holds the child's
    /// process handle, so the ID cannot be reused).
    #[must_use]
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    /// The exit code once the child has exited (`None` while it runs). On Unix a child
    /// ended by a signal reads as the negated signal number.
    ///
    /// # Errors
    /// The wait failed.
    pub fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        self.inner.try_wait()
    }

    /// Wait for the child to exit and return its exit code.
    ///
    /// # Errors
    /// The wait failed.
    pub fn wait(&mut self) -> std::io::Result<i32> {
        self.inner.wait()
    }

    /// End the child through its own handle (never by PID lookup). A child that has
    /// already exited is left as it is.
    ///
    /// # Errors
    /// The termination failed while the child was still running.
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.inner.kill()
    }
}

/// Start `cmd` with its three standard streams piped and an explicit inherited-handle
/// list (module docs). Program, arguments, environment changes and working directory are
/// read from `cmd`.
///
/// Windows: `STARTUPINFOEXW` with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` holding exactly the
/// three child-side pipe handles (`bInheritHandles` TRUE), so no other inheritable handle of
/// this process reaches the child. Unix: std's spawn with piped streams (every descriptor is
/// close-on-exec).
///
/// `Command::env_clear` is not observable through std, so a cleared environment is read as
/// an inherited one here; use [`spawn_listed`] with [`ListedSpawn::env_clear`] for it.
///
/// # Errors
/// [`SysError`] naming the failed call (never an argument or an environment value).
pub fn spawn_with_handle_list(cmd: &Command) -> Result<ListedChild, SysError> {
    spawn_listed(cmd, &ListedSpawn::piped())
}

/// [`spawn_with_handle_list`] with explicit stream, environment and creation options.
///
/// # Errors
/// [`SysError`] naming the failed call.
pub fn spawn_listed(cmd: &Command, options: &ListedSpawn) -> Result<ListedChild, SysError> {
    imp::spawn(cmd, options)
}

// --- the pure parts of the Windows spawn, compiled on every host so they are unit-tested
// on any of them ---------------------------------------------------------------------------

/// UTF-16 text, as Windows takes command lines and environment blocks.
#[cfg(any(windows, test))]
mod wide {
    /// A name or value in UTF-16 code units.
    pub(super) type Units = Vec<u16>;

    /// A request that cannot be expressed in a command line or an environment block.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Refused {
        /// A NUL in a program, argument, name or value.
        Nul,
        /// An empty environment name, or a name holding `=` after its first unit.
        Name,
        /// A quote in the program name (no escape exists for argv[0]).
        ProgramQuote,
    }

    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;
    const SPACE: u16 = b' ' as u16;
    const TAB: u16 = b'\t' as u16;
    const EQUALS: u16 = b'=' as u16;

    /// Append `arg` to `line` by the rules std's Windows `Command` uses (what
    /// `CommandLineToArgvW` and the C runtime parse back to `arg`): quoted when it is empty
    /// or holds a space or a tab; every `"` escaped; the backslashes before a `"` (or before
    /// the closing quote) doubled.
    pub(super) fn push_arg(line: &mut Units, arg: &[u16]) {
        let quote = arg.is_empty() || arg.iter().any(|&c| c == SPACE || c == TAB);
        if quote {
            line.push(QUOTE);
        }
        let mut backslashes = 0usize;
        for &c in arg {
            if c == BACKSLASH {
                backslashes += 1;
            } else {
                if c == QUOTE {
                    line.extend(std::iter::repeat_n(BACKSLASH, backslashes + 1));
                }
                backslashes = 0;
            }
            line.push(c);
        }
        if quote {
            line.extend(std::iter::repeat_n(BACKSLASH, backslashes));
            line.push(QUOTE);
        }
    }

    /// The command line, NUL-terminated: `program` in quotes, then each argument by
    /// [`push_arg`].
    pub(super) fn command_line(program: &[u16], args: &[Units]) -> Result<Units, Refused> {
        if program.contains(&0) || args.iter().any(|a| a.contains(&0)) {
            return Err(Refused::Nul);
        }
        if program.contains(&QUOTE) {
            return Err(Refused::ProgramQuote);
        }
        let mut line = Vec::with_capacity(program.len() + 4);
        line.push(QUOTE);
        line.extend_from_slice(program);
        line.push(QUOTE);
        for arg in args {
            line.push(SPACE);
            push_arg(&mut line, arg);
        }
        line.push(0);
        Ok(line)
    }

    /// The comparison key of an environment name: Windows compares names
    /// case-insensitively.
    fn key(name: &[u16]) -> String {
        String::from_utf16_lossy(name).to_uppercase()
    }

    /// The child's environment: `inherited` (or nothing when `clear`), then each change in
    /// order (`Some(value)` sets, `None` removes), names matched case-insensitively. A set
    /// keeps the spelling of the name it was given.
    pub(super) fn merge_environment(
        inherited: Vec<(Units, Units)>,
        changes: Vec<(Units, Option<Units>)>,
        clear: bool,
    ) -> Vec<(Units, Units)> {
        let mut vars = if clear { Vec::new() } else { inherited };
        for (name, value) in changes {
            let k = key(&name);
            vars.retain(|(n, _)| key(n) != k);
            if let Some(value) = value {
                vars.push((name, value));
            }
        }
        vars
    }

    /// The `lpEnvironment` block (UTF-16): `NAME=value` entries sorted by name, each
    /// NUL-terminated, the block ending in an extra NUL. A leading `=` in a name is allowed
    /// (the per-drive working directories `=C:`); any other `=`, an empty name or a NUL is
    /// refused.
    pub(super) fn environment_block(vars: &[(Units, Units)]) -> Result<Units, Refused> {
        let mut sorted: Vec<&(Units, Units)> = vars.iter().collect();
        sorted.sort_by_key(|(name, _)| key(name));
        let mut block = Vec::new();
        for (name, value) in sorted {
            if name.is_empty() || name.iter().skip(1).any(|&c| c == EQUALS) {
                return Err(Refused::Name);
            }
            if name.contains(&0) || value.contains(&0) {
                return Err(Refused::Nul);
            }
            block.extend_from_slice(name);
            block.push(EQUALS);
            block.extend_from_slice(value);
            block.push(0);
        }
        if block.is_empty() {
            block.push(0);
        }
        block.push(0);
        Ok(block)
    }
}

// --- Windows ---------------------------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use std::ffi::{OsStr, OsString, c_void};
    use std::fs::File;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Mutex, PoisonError};

    use windows_sys::Win32::Foundation::{
        GENERIC_READ, GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
        SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
        InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
        STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
        WaitForSingleObject,
    };

    use super::wide::{self, Refused, Units};
    use super::{ListedChild, ListedSpawn, ListedStdio};
    use crate::sys::SysError;

    /// Serializes the window in which a child-side stream handle is inheritable: one
    /// `spawn_listed` at a time creates, marks, passes and closes its three handles.
    static SPAWN_LOCK: Mutex<()> = Mutex::new(());

    /// The exit code given to a child ended by [`Process::kill`].
    const KILLED: u32 = 1;

    /// A running child: its process handle, held from creation (so its ID is not reused).
    #[derive(Debug)]
    pub(super) struct Process {
        handle: OwnedHandle,
        pid: u32,
    }

    impl Process {
        pub(super) fn id(&self) -> u32 {
            self.pid
        }

        fn wait_for(&self, millis: u32) -> std::io::Result<Option<i32>> {
            // SAFETY: the process handle is open (owned by `self`).
            match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), millis) } {
                WAIT_OBJECT_0 => {}
                WAIT_TIMEOUT => return Ok(None),
                _ => return Err(std::io::Error::last_os_error()),
            }
            let mut code = 0u32;
            // SAFETY: the process handle is open; `code` is a valid out-pointer.
            if unsafe { GetExitCodeProcess(self.handle.as_raw_handle(), &raw mut code) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Some(code.cast_signed()))
        }

        pub(super) fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            self.wait_for(0)
        }

        pub(super) fn wait(&mut self) -> std::io::Result<i32> {
            loop {
                if let Some(code) = self.wait_for(INFINITE)? {
                    return Ok(code);
                }
            }
        }

        pub(super) fn kill(&mut self) -> std::io::Result<()> {
            // SAFETY: the process handle is open and has PROCESS_ALL_ACCESS (it came from
            // `CreateProcessW`).
            if unsafe { TerminateProcess(self.handle.as_raw_handle(), KILLED) } == 0 {
                // Exited between the caller's check and the call: not an error.
                return match self.try_wait() {
                    Ok(Some(_)) => Ok(()),
                    _ => Err(std::io::Error::last_os_error()),
                };
            }
            Ok(())
        }
    }

    /// A process-thread attribute list in its own pointer-aligned buffer, deleted once on
    /// drop.
    struct AttributeList {
        buffer: Vec<usize>,
        initialized: bool,
    }

    impl AttributeList {
        fn new(count: u32) -> Result<Self, SysError> {
            let mut size = 0usize;
            // SAFETY: a null list asks for the size only; `size` is a valid out-pointer.
            // The call fails by design (ERROR_INSUFFICIENT_BUFFER) and reports the size.
            let _ = unsafe {
                InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &raw mut size)
            };
            if size == 0 {
                return Err(SysError::last_os("InitializeProcThreadAttributeList"));
            }
            let mut list = Self {
                buffer: vec![0usize; size.div_ceil(size_of::<usize>())],
                initialized: false,
            };
            // SAFETY: the buffer holds at least `size` bytes, pointer-aligned, and lives as
            // long as `list`.
            if unsafe { InitializeProcThreadAttributeList(list.as_ptr(), count, 0, &raw mut size) }
                == 0
            {
                return Err(SysError::last_os("InitializeProcThreadAttributeList"));
            }
            list.initialized = true;
            Ok(list)
        }

        fn as_ptr(&mut self) -> *mut c_void {
            self.buffer.as_mut_ptr().cast()
        }

        /// Restrict inheritance to `handles`.
        fn set_handle_list(&mut self, handles: &mut [HANDLE]) -> Result<(), SysError> {
            // SAFETY: the list is initialized; `handles` is a live array of open,
            // inheritable handles that outlives the `CreateProcessW` this list is used for
            // (the caller keeps both until it returns); the size is the array's byte length.
            let ok = unsafe {
                UpdateProcThreadAttribute(
                    self.as_ptr(),
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_mut_ptr().cast::<c_void>(),
                    std::mem::size_of_val(handles),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            };
            if ok == 0 {
                return Err(SysError::last_os("UpdateProcThreadAttribute"));
            }
            Ok(())
        }
    }

    impl Drop for AttributeList {
        fn drop(&mut self) {
            if self.initialized {
                // SAFETY: initialized by `InitializeProcThreadAttributeList`, deleted once.
                unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
            }
        }
    }

    /// One stream: the handle the child gets, and this process's end of the pipe.
    struct Stream {
        child: OwnedHandle,
        parent: Option<File>,
    }

    fn set_inheritable(handle: &OwnedHandle) -> Result<(), SysError> {
        // SAFETY: the handle is open (owned by the caller).
        let ok = unsafe {
            SetHandleInformation(
                handle.as_raw_handle(),
                HANDLE_FLAG_INHERIT,
                HANDLE_FLAG_INHERIT,
            )
        };
        if ok == 0 {
            return Err(SysError::last_os("SetHandleInformation"));
        }
        Ok(())
    }

    /// One stream. `input`: the child reads it. A pipe's child end is made inheritable only
    /// here, after both ends exist, and the parent's end never is; the null device is opened
    /// inheritable. The caller holds [`SPAWN_LOCK`].
    fn stream(kind: ListedStdio, input: bool) -> Result<Stream, SysError> {
        match kind {
            ListedStdio::Piped => {
                let mut read: HANDLE = std::ptr::null_mut();
                let mut write: HANDLE = std::ptr::null_mut();
                // SAFETY: two valid out-pointers; no security attributes (neither end is
                // inheritable); the default buffer size.
                if unsafe { CreatePipe(&raw mut read, &raw mut write, std::ptr::null(), 0) } == 0 {
                    return Err(SysError::last_os("CreatePipe"));
                }
                // SAFETY: both handles were just created, are open, and are owned by
                // nothing else.
                let (read, write) = unsafe {
                    (
                        OwnedHandle::from_raw_handle(read),
                        OwnedHandle::from_raw_handle(write),
                    )
                };
                let (child, parent) = if input { (read, write) } else { (write, read) };
                set_inheritable(&child)?;
                Ok(Stream {
                    child,
                    parent: Some(File::from(parent)),
                })
            }
            ListedStdio::Null => {
                let name: Vec<u16> = "NUL".encode_utf16().chain(std::iter::once(0)).collect();
                let attributes = SECURITY_ATTRIBUTES {
                    nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
                    lpSecurityDescriptor: std::ptr::null_mut(),
                    bInheritHandle: 1,
                };
                // SAFETY: `name` is a NUL-terminated wide string and `attributes` a valid
                // SECURITY_ATTRIBUTES, both alive for the call.
                let raw = unsafe {
                    CreateFileW(
                        name.as_ptr(),
                        if input { GENERIC_READ } else { GENERIC_WRITE },
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        &raw const attributes,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        std::ptr::null_mut(),
                    )
                };
                if raw == INVALID_HANDLE_VALUE {
                    return Err(SysError::last_os("CreateFileW(NUL)"));
                }
                Ok(Stream {
                    // SAFETY: CreateFileW succeeded; the handle is owned here alone.
                    child: unsafe { OwnedHandle::from_raw_handle(raw) },
                    parent: None,
                })
            }
        }
    }

    fn units(s: &OsStr) -> Units {
        s.encode_wide().collect()
    }

    fn refused(what: &'static str, r: &Refused) -> SysError {
        SysError::new(
            what,
            match r {
                Refused::Nul => "a NUL in the request",
                Refused::Name => "an environment name is empty or holds '='",
                Refused::ProgramQuote => "a quote in the program path",
            },
        )
    }

    /// The program to run: an absolute or separator-bearing path as given, a bare name
    /// searched in `path` (the child's `PATH`; never the working directory), with `.exe`
    /// added when the name has no extension (as std does).
    fn resolve_program(program: &Path, path: Option<&OsStr>) -> Option<PathBuf> {
        let with_extension = |p: &Path| {
            if p.extension().is_none() {
                p.with_extension("exe")
            } else {
                p.to_path_buf()
            }
        };
        let text = program.as_os_str().to_string_lossy();
        if program.is_absolute() || text.contains(['\\', '/', ':']) {
            return Some(with_extension(program));
        }
        let name = with_extension(program);
        std::env::split_paths(path?)
            .map(|dir| dir.join(&name))
            .find(|candidate| candidate.is_file())
    }

    pub(super) fn spawn(cmd: &Command, options: &ListedSpawn) -> Result<ListedChild, SysError> {
        // The request, read from `cmd` and turned into what CreateProcessW takes.
        let changes: Vec<(Units, Option<Units>)> = cmd
            .get_envs()
            .map(|(k, v)| (units(k), v.map(units)))
            .collect();
        let inherited: Vec<(Units, Units)> = std::env::vars_os()
            .map(|(k, v)| (units(&k), units(&v)))
            .collect();
        let vars = wide::merge_environment(inherited, changes, options.env_clear);
        let path = vars
            .iter()
            .find(|(n, _)| String::from_utf16_lossy(n).eq_ignore_ascii_case("PATH"))
            .map(|(_, v)| OsString::from_wide(v));
        let program = resolve_program(Path::new(cmd.get_program()), path.as_deref())
            .ok_or_else(|| SysError::new("CreateProcessW", "program not found"))?;
        let args: Vec<Units> = cmd.get_args().map(units).collect();
        let mut line = wide::command_line(&units(program.as_os_str()), &args)
            .map_err(|r| refused("CreateProcessW", &r))?;
        let block = wide::environment_block(&vars).map_err(|r| refused("CreateProcessW", &r))?;
        let mut application = units(program.as_os_str());
        if application.contains(&0) {
            return Err(refused("CreateProcessW", &Refused::Nul));
        }
        application.push(0);
        let directory = cmd
            .get_current_dir()
            .map(|d| {
                let mut w = units(d.as_os_str());
                if w.contains(&0) {
                    return Err(refused("CreateProcessW", &Refused::Nul));
                }
                w.push(0);
                Ok(w)
            })
            .transpose()?;

        // The handles, the attribute list and the call, under the spawn lock.
        let _lock = SPAWN_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let stdin = stream(options.stdin, true)?;
        let stdout = stream(options.stdout, false)?;
        let stderr = stream(options.stderr, false)?;
        let mut handles = [
            stdin.child.as_raw_handle(),
            stdout.child.as_raw_handle(),
            stderr.child.as_raw_handle(),
        ];
        let mut attributes = AttributeList::new(1)?;
        attributes.set_handle_list(&mut handles)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).unwrap_or(0);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
        startup.lpAttributeList = attributes.as_ptr();
        let mut info = PROCESS_INFORMATION::default();
        // SAFETY: every string is a NUL-terminated buffer alive for the call (the command
        // line mutable, as the API requires); the environment block is double-NUL-terminated
        // UTF-16 (hence CREATE_UNICODE_ENVIRONMENT); `startup` is a STARTUPINFOEXW with its
        // size set, three open inheritable standard handles, and an initialized attribute
        // list holding exactly those handles (hence EXTENDED_STARTUPINFO_PRESENT and
        // bInheritHandles TRUE); `info` is a valid out-pointer.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | options.creation_flags,
                block.as_ptr().cast(),
                directory.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
                (&raw const startup).cast(),
                &raw mut info,
            )
        };
        if created == 0 {
            return Err(SysError::last_os("CreateProcessW"));
        }
        // SAFETY: both handles were just returned by CreateProcessW, are open, and are
        // owned by nothing else.
        let (process, thread) = unsafe {
            (
                OwnedHandle::from_raw_handle(info.hProcess),
                OwnedHandle::from_raw_handle(info.hThread),
            )
        };
        drop(thread);
        // The child's ends close here, so no inheritable stream handle outlives the spawn.
        drop(attributes);
        let (stdin, stdout, stderr) = (stdin.parent, stdout.parent, stderr.parent);
        Ok(ListedChild {
            stdin,
            stdout,
            stderr,
            inner: Process {
                handle: process,
                pid: info.dwProcessId,
            },
        })
    }
}

// --- Unix ------------------------------------------------------------------------------------

#[cfg(unix)]
mod imp {
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Command, ExitStatus, Stdio};

    use super::{ListedChild, ListedSpawn, ListedStdio};
    use crate::sys::SysError;

    /// A running child on its own `std::process::Child` (which keeps it unreaped until
    /// waited for, so its PID cannot be reused).
    #[derive(Debug)]
    pub(super) struct Process(Child);

    fn code(status: ExitStatus) -> i32 {
        status
            .code()
            .or_else(|| status.signal().map(|s| -s))
            .unwrap_or(-1)
    }

    impl Process {
        pub(super) fn id(&self) -> u32 {
            self.0.id()
        }

        pub(super) fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            Ok(self.0.try_wait()?.map(code))
        }

        pub(super) fn wait(&mut self) -> std::io::Result<i32> {
            Ok(code(self.0.wait()?))
        }

        pub(super) fn kill(&mut self) -> std::io::Result<()> {
            if self.0.try_wait()?.is_some() {
                return Ok(());
            }
            self.0.kill()
        }
    }

    fn stdio(kind: ListedStdio) -> Stdio {
        match kind {
            ListedStdio::Piped => Stdio::piped(),
            ListedStdio::Null => Stdio::null(),
        }
    }

    pub(super) fn spawn(cmd: &Command, options: &ListedSpawn) -> Result<ListedChild, SysError> {
        let mut real = Command::new(cmd.get_program());
        real.args(cmd.get_args());
        if options.env_clear {
            real.env_clear();
        }
        for (k, v) in cmd.get_envs() {
            match v {
                Some(v) => real.env(k, v),
                None => real.env_remove(k),
            };
        }
        if let Some(dir) = cmd.get_current_dir() {
            real.current_dir(dir);
        }
        real.stdin(stdio(options.stdin))
            .stdout(stdio(options.stdout))
            .stderr(stdio(options.stderr));
        let mut child = real.spawn().map_err(|e| {
            SysError::new(
                "spawn",
                format!(
                    "{:?} (os error {})",
                    e.kind(),
                    e.raw_os_error().unwrap_or(0)
                ),
            )
        })?;
        Ok(ListedChild {
            stdin: child.stdin.take().map(|s| File::from(OwnedFd::from(s))),
            stdout: child.stdout.take().map(|s| File::from(OwnedFd::from(s))),
            stderr: child.stderr.take().map(|s| File::from(OwnedFd::from(s))),
            inner: Process(child),
        })
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use std::process::Command;

    use super::{ListedChild, ListedSpawn};
    use crate::sys::SysError;

    #[derive(Debug)]
    pub(super) struct Process;

    impl Process {
        pub(super) fn id(&self) -> u32 {
            0
        }
        pub(super) fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            Ok(None)
        }
        pub(super) fn wait(&mut self) -> std::io::Result<i32> {
            Ok(0)
        }
        pub(super) fn kill(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    pub(super) fn spawn(_cmd: &Command, _options: &ListedSpawn) -> Result<ListedChild, SysError> {
        Err(SysError::new("spawn", "unsupported platform"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::wide::{
        Refused, Units, command_line, environment_block, merge_environment, push_arg,
    };

    fn u(s: &str) -> Units {
        s.encode_utf16().collect()
    }

    fn text(units: &[u16]) -> String {
        String::from_utf16(units).unwrap()
    }

    fn quoted(arg: &str) -> String {
        let mut line = Vec::new();
        push_arg(&mut line, &u(arg));
        text(&line)
    }

    /// std's rules: quote only for an empty argument, a space or a tab; escape every `"`;
    /// double the backslashes that precede a `"` or the closing quote.
    #[test]
    fn arguments_are_quoted_by_the_rules_std_uses() {
        assert_eq!(quoted("plain"), "plain");
        assert_eq!(quoted(""), r#""""#);
        assert_eq!(quoted("a b"), r#""a b""#);
        assert_eq!(quoted("a\tb"), "\"a\tb\"");
        assert_eq!(quoted(r#"a"b"#), r#"a\"b"#);
        assert_eq!(quoted(r"C:\dir\"), r"C:\dir\");
        assert_eq!(quoted(r"C:\my dir\"), r#""C:\my dir\\""#);
        assert_eq!(quoted(r#"a\"b c"#), r#""a\\\"b c""#);
        assert_eq!(quoted(r"\\server\share"), r"\\server\share");
    }

    #[test]
    fn the_command_line_quotes_the_program_and_ends_in_nul() {
        let line = command_line(&u(r"C:\Program Files\x.exe"), &[u("-a"), u("b c")]).unwrap();
        assert_eq!(line.last(), Some(&0));
        assert_eq!(
            text(&line[..line.len() - 1]),
            r#""C:\Program Files\x.exe" -a "b c""#
        );
        assert_eq!(
            command_line(&u(r#"a"b"#), &[]).unwrap_err(),
            Refused::ProgramQuote
        );
        assert_eq!(
            command_line(&u("x"), &[vec![u16::from(b'a'), 0]]).unwrap_err(),
            Refused::Nul
        );
    }

    #[test]
    fn environment_changes_apply_case_insensitively_and_clear_drops_the_inherited() {
        let inherited = vec![
            (u("Path"), u("p")),
            (u("KEEP"), u("k")),
            (u("DROP"), u("d")),
        ];
        let changes = vec![
            (u("PATH"), Some(u("q"))),
            (u("drop"), None),
            (u("NEW"), Some(u("n"))),
        ];
        let merged = merge_environment(inherited.clone(), changes.clone(), false);
        let names: Vec<String> = merged.iter().map(|(n, _)| text(n)).collect();
        assert_eq!(names, ["KEEP", "PATH", "NEW"]);
        assert_eq!(text(&merged[1].1), "q");

        let cleared = merge_environment(inherited, changes, true);
        let names: Vec<String> = cleared.iter().map(|(n, _)| text(n)).collect();
        assert_eq!(names, ["PATH", "NEW"]);
    }

    #[test]
    fn the_environment_block_is_sorted_double_nul_terminated_and_checks_names() {
        let block =
            environment_block(&[(u("b"), u("2")), (u("A"), u("1")), (u("=C:"), u(r"C:\x"))])
                .unwrap();
        assert_eq!(text(&block), "=C:=C:\\x\0A=1\0b=2\0\0");
        assert_eq!(environment_block(&[]).unwrap(), vec![0, 0]);
        assert_eq!(
            environment_block(&[(u("a=b"), u("v"))]).unwrap_err(),
            Refused::Name
        );
        assert_eq!(
            environment_block(&[(u(""), u("v"))]).unwrap_err(),
            Refused::Name
        );
        assert_eq!(
            environment_block(&[(u("a"), vec![u16::from(b'v'), 0])]).unwrap_err(),
            Refused::Nul
        );
    }

    #[cfg(unix)]
    mod unix {
        use std::io::{Read, Write};
        use std::process::Command;

        use super::super::{ListedSpawn, ListedStdio, spawn_listed, spawn_with_handle_list};

        /// The Unix path: three pipes, the command's environment changes and working
        /// directory, the exit code, and a kill through the handle.
        #[test]
        fn a_listed_child_gets_piped_streams_its_environment_and_reports_its_exit() {
            let mut cmd = Command::new("/bin/sh");
            cmd.args([
                "-c",
                "read line; echo \"$line:$HM_LISTED:${HM_GONE-unset}\"; exit 7",
            ])
            .env("HM_LISTED", "yes")
            .env_remove("HM_GONE");
            let mut child = spawn_with_handle_list(&cmd).unwrap();
            child.stdin.take().unwrap().write_all(b"hi\n").unwrap();
            let mut out = String::new();
            child
                .stdout
                .take()
                .unwrap()
                .read_to_string(&mut out)
                .unwrap();
            assert_eq!(out, "hi:yes:unset\n");
            assert_eq!(child.wait().unwrap(), 7);
            assert_eq!(child.try_wait().unwrap(), Some(7));
            child.kill().unwrap();
        }

        #[test]
        fn env_clear_and_null_streams_are_honoured_and_kill_ends_the_child() {
            let mut cmd = Command::new("/bin/sh");
            cmd.args(["-c", "test -z \"$HOME\" && sleep 30"]);
            let options = ListedSpawn {
                stdin: ListedStdio::Null,
                stdout: ListedStdio::Null,
                stderr: ListedStdio::Null,
                env_clear: true,
                creation_flags: 0,
            };
            let mut child = spawn_listed(&cmd, &options).unwrap();
            assert!(child.stdin.is_none() && child.stdout.is_none() && child.stderr.is_none());
            assert_eq!(child.try_wait().unwrap(), None);
            child.kill().unwrap();
            assert_eq!(child.wait().unwrap(), -9);
        }
    }
}
