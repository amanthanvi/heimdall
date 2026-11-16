//! ⟨M03 wave 6, U13; ADR-0008 §17.26 item 8, §17.28 item 4⟩ The Windows pseudoconsole
//! (ConPTY) behind [`crate::console`]: a program started on a console of its own, with
//! no window, whose input this process types and whose output it reads.
//!
//! The approach is the one G02 proved natively (`tests/native/windows-g02/G02X1Native.cs`,
//! `X1Pty.Start`):
//!
//! 1. two anonymous pipes, one for the console's input and one for its output, none of
//!    their handles inheritable;
//! 2. `CreatePseudoConsole` on the console's ends (no flags: no cursor inheritance, so
//!    the pseudoconsole never waits for a cursor-position reply); this process then
//!    closes those ends (the pseudoconsole holds its own);
//! 3. a reader thread drains the output pipe into the transcript until end of file (the
//!    pseudoconsole closed), so the pseudoconsole never blocks on a full pipe;
//! 4. a process-thread attribute list holding `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`, in a
//!    `STARTUPINFOEXW` with `STARTF_USESTDHANDLES` and **null** standard handles (G02's
//!    `StdMode = 1`: without it the program can inherit this process's redirected
//!    handles; with null handles the console attach gives it the pseudoconsole's), and
//!    `CreateProcessW` with `bInheritHandles = FALSE`,
//!    `EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT`, an explicit sorted
//!    UTF-16 environment block and a command line quoted by the MSVC argument rules.
//!
//! **Ctrl-C.** `send(&[0x03])` on the pseudoconsole's input is Ctrl-C typed at the
//! console: a `CTRL_C_EVENT` for every attached process whose console input is processed,
//! and the byte itself for a reader that turned processed input off. A process created
//! after `SetConsoleCtrlHandler(NULL, TRUE)` (or `CREATE_NEW_PROCESS_GROUP`) inherits an
//! "ignore Ctrl-C" attribute and never runs its handlers for that event (ADR-0007 §12.44
//! item 2; G02 `ChildCtrlCProcessed`). **Decision:** [`spawn`] clears this process's
//! attribute (`SetConsoleCtrlHandler(NULL, FALSE)`) immediately before `CreateProcessW`,
//! so every program on a pseudoconsole, and everything it starts, gets the normal
//! disposition whatever the test runner inherited; no Ctrl-C case passes or fails
//! because of how the runner was started. It is never set again: the attribute is
//! undocumented to read, and setting it would hand "ignore" to every process the test
//! binary starts afterwards. The only lasting effect is that this test process itself
//! processes Ctrl-C typed at *its own* console (the pseudoconsoles never reach it), as a
//! normally started test runner does. Best effort: a failure leaves the attribute as it
//! was, which `console`'s Windows Ctrl-C test then shows.
//!
//! **Lifetime.** [`Child::close`] closes the pseudoconsole (its attached programs end
//! with it; the pseudoconsole writes its last output and closes its end of the output
//! pipe, so the reader sees end of file) and the input pipe; [`Child::kill`] terminates
//! the program through the process handle this module holds since its creation (never by
//! a PID lookup, which could name a reused PID) and waits for it. Every handle is an
//! [`OwnedHandle`] or a [`PseudoConsole`] with exactly one owner, so each is closed once,
//! on every path, panics included.
//!
//! `unsafe`, call by call (each with the invariant it relies on):
//! * `CreatePipe`: two valid out-pointers; each returned handle is wrapped in an
//!   [`OwnedHandle`] at once (`OwnedHandle::from_raw_handle`: the handle is open and owned
//!   by nothing else).
//! * `CreatePseudoConsole`: the two pipe ends are live handles borrowed for the call; the
//!   returned `HPCON` is wrapped in a [`PseudoConsole`] at once, which calls
//!   `ClosePseudoConsole` exactly once.
//! * `InitializeProcThreadAttributeList` / `UpdateProcThreadAttribute` /
//!   `DeleteProcThreadAttributeList`: the list lives in a pointer-aligned buffer of the
//!   size the first call reported, owned by an [`AttributeList`] that outlives
//!   `CreateProcessW` and deletes the list once; the pseudoconsole attribute's value is
//!   the `HPCON` itself (as documented), alive until after `CreateProcessW`.
//! * `SetConsoleCtrlHandler(None, FALSE)`: no pointer; it changes only this process's
//!   attribute (decision above).
//! * `CreateProcessW`: every string is a NUL-terminated UTF-16 buffer that outlives the
//!   call (the command line mutable, as required); the environment block is
//!   double-NUL-terminated; the startup information and the process information are
//!   valid for the call; both returned handles are wrapped in [`OwnedHandle`]s at once.
//! * `WaitForSingleObject` / `GetExitCodeProcess` / `TerminateProcess`: the process
//!   handle is borrowed from the live [`OwnedHandle`]; the exit code's out-pointer is a
//!   local.
#![allow(unsafe_code)]

use std::ffi::{OsStr, OsString, c_void};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Console::{
    COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

/// The variables carried over from this process when the command does not set them
/// ([`crate::console`] module docs): the Windows networking and process APIs need them.
const CARRIED: [&str; 4] = ["SystemRoot", "windir", "ComSpec", "PATHEXT"];

/// The exit code [`Child::kill`] gives the program (G02's `X1Pty.Kill`).
const KILLED: u32 = 0xDEAD;

/// How long [`Child::kill`] waits for the terminated program to be gone.
const KILL_WAIT_MS: u32 = 30_000;

/// A pseudoconsole, closed exactly once on drop (`ClosePseudoConsole`).
struct PseudoConsole(HPCON);

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful `CreatePseudoConsole` and is owned only
        // by this value, which drops once.
        unsafe { ClosePseudoConsole(self.0) };
    }
}

/// A process-thread attribute list in its own pointer-aligned buffer, deleted once on
/// drop.
struct AttributeList {
    buffer: Vec<usize>,
    initialized: bool,
}

impl AttributeList {
    /// A list with room for `count` attributes.
    fn new(count: u32) -> io::Result<AttributeList> {
        let mut size = 0usize;
        // SAFETY: a null list asks for the size only; `size` is a valid out-pointer. The
        // call fails by design (ERROR_INSUFFICIENT_BUFFER) and reports the size.
        let _ = unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &raw mut size)
        };
        if size == 0 {
            return Err(last_error("InitializeProcThreadAttributeList (size)"));
        }
        let words = size.div_ceil(size_of::<usize>());
        let mut list = AttributeList {
            buffer: vec![0usize; words],
            initialized: false,
        };
        // SAFETY: the buffer holds at least `size` bytes, pointer-aligned, and lives as
        // long as `list`.
        if unsafe { InitializeProcThreadAttributeList(list.as_ptr(), count, 0, &raw mut size) } == 0
        {
            return Err(last_error("InitializeProcThreadAttributeList"));
        }
        list.initialized = true;
        Ok(list)
    }

    fn as_ptr(&mut self) -> *mut c_void {
        self.buffer.as_mut_ptr().cast()
    }

    /// Attach the program to `console`.
    fn set_pseudoconsole(&mut self, console: &PseudoConsole) -> io::Result<()> {
        // SAFETY: the list is initialized; the attribute's value is the HPCON itself (not
        // a pointer to it, as documented for PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE), and the
        // pseudoconsole outlives the `CreateProcessW` this list is used for.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                std::ptr::without_provenance::<c_void>(console.0.cast_unsigned()),
                size_of::<HPCON>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(last_error("UpdateProcThreadAttribute(PSEUDOCONSOLE)"));
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

/// The last OS error, named by the step that failed (never a secret: no argument or
/// environment value is ever part of it).
fn last_error(step: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{step} failed: {e}"))
}

/// An anonymous pipe: (read end, write end), neither inheritable.
fn pipe(what: &str) -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    // SAFETY: two valid out-pointers; no security attributes (not inheritable); the
    // default buffer size.
    if unsafe { CreatePipe(&raw mut read, &raw mut write, std::ptr::null(), 0) } == 0 {
        return Err(last_error(what));
    }
    // SAFETY: both handles were just created, are open, and are owned by nothing else.
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    })
}

/// `s` as UTF-16 with a terminating NUL; an embedded NUL is refused.
fn wide(s: &OsStr, what: &str) -> io::Result<Vec<u16>> {
    let mut w: Vec<u16> = s.encode_wide().collect();
    if w.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{what} contains a NUL"),
        ));
    }
    w.push(0);
    Ok(w)
}

/// Append `arg` to `line` by the MSVC argument rules (what `CommandLineToArgvW` and the
/// C runtime parse back to `arg`): unquoted when it has no blank or quote and is not
/// empty; otherwise in quotes, each `"` escaped, and the backslashes before a `"` or the
/// closing quote doubled.
fn push_arg(line: &mut Vec<u16>, arg: &OsStr) {
    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;
    let units: Vec<u16> = arg.encode_wide().collect();
    let plain = !units.is_empty()
        && !units
            .iter()
            .any(|&c| c == u16::from(b' ') || c == u16::from(b'\t') || c == QUOTE);
    if plain {
        line.extend_from_slice(&units);
        return;
    }
    line.push(QUOTE);
    let mut backslashes = 0usize;
    for &c in &units {
        match c {
            BACKSLASH => {
                backslashes += 1;
                line.push(c);
            }
            QUOTE => {
                // The backslashes already written, doubled, then an escaped quote.
                line.extend(std::iter::repeat_n(BACKSLASH, backslashes + 1));
                line.push(QUOTE);
                backslashes = 0;
            }
            _ => {
                backslashes = 0;
                line.push(c);
            }
        }
    }
    // Backslashes before the closing quote are doubled.
    line.extend(std::iter::repeat_n(BACKSLASH, backslashes));
    line.push(QUOTE);
}

/// The command line: `program` quoted (argv[0] has no escapes, and a path holds no
/// quote), then each argument by [`push_arg`], NUL-terminated.
fn command_line(program: &Path, args: &[OsString]) -> io::Result<Vec<u16>> {
    let mut line = Vec::new();
    let program = wide(program.as_os_str(), "the program path")?;
    line.push(u16::from(b'"'));
    line.extend_from_slice(&program[..program.len() - 1]);
    line.push(u16::from(b'"'));
    for arg in args {
        if arg.encode_wide().any(|c| c == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an argument contains a NUL",
            ));
        }
        line.push(u16::from(b' '));
        push_arg(&mut line, arg);
    }
    line.push(0);
    Ok(line)
}

/// The environment block: `env`, plus [`CARRIED`] from this process where `env` does not
/// name them (names compare case-insensitively), sorted by name as Windows requires,
/// each `NAME=value` NUL-terminated, the block ending in an extra NUL.
fn environment_block(env: &[(OsString, OsString)]) -> io::Result<Vec<u16>> {
    let upper = |k: &OsStr| k.to_string_lossy().to_uppercase();
    let mut vars: Vec<(OsString, OsString)> = env.to_vec();
    for name in CARRIED {
        let set = vars.iter().any(|(k, _)| upper(k) == name.to_uppercase());
        if !set && let Some(value) = std::env::var_os(name) {
            vars.push((name.into(), value));
        }
    }
    vars.sort_by_key(|(k, _)| upper(k));
    let mut block = Vec::new();
    for (k, v) in &vars {
        if k.is_empty() || k.encode_wide().any(|c| c == 0 || c == u16::from(b'=')) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an environment name is empty or contains '=' or a NUL",
            ));
        }
        block.extend(k.encode_wide());
        block.push(u16::from(b'='));
        block.extend_from_slice(&{
            let mut value = wide(v, "an environment value")?;
            value.pop();
            value
        });
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

/// A program started on a pseudoconsole ([`spawn`]).
pub(crate) struct Child {
    /// The program's process handle, held since its creation.
    process: OwnedHandle,
    pid: u32,
    /// The pseudoconsole's input (what this process types); `None` once closed.
    input: Option<File>,
    /// `None` once closed.
    console: Option<PseudoConsole>,
}

/// Start `program` with `args` on a new `cols`×`rows` pseudoconsole, with exactly `env`
/// (plus [`CARRIED`]) and the working directory `cwd`; every byte the console shows is
/// appended to `output` by the returned reader thread, which ends when the pseudoconsole
/// is closed ([`Child::close`]).
///
/// # Errors
/// A pipe, the pseudoconsole or the process cannot be created (the step is named; no
/// argument or environment value is ever in the error).
pub(crate) fn spawn(
    program: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
    cwd: Option<&Path>,
    cols: u16,
    rows: u16,
    output: Arc<Mutex<Vec<u8>>>,
) -> io::Result<(Child, JoinHandle<()>)> {
    let mut line = command_line(program, args)?;
    let application = if program.is_absolute() {
        Some(wide(program.as_os_str(), "the program path")?)
    } else {
        None
    };
    let block = environment_block(env)?;
    let dir = cwd
        .map(|d| wide(d.as_os_str(), "the working directory"))
        .transpose()?;

    let (input_read, input_write) = pipe("CreatePipe (console input)")?;
    let (output_read, output_write) = pipe("CreatePipe (console output)")?;
    let size = COORD {
        X: i16::try_from(cols).unwrap_or(i16::MAX),
        Y: i16::try_from(rows).unwrap_or(i16::MAX),
    };
    let mut hpc: HPCON = 0;
    // SAFETY: both pipe ends are live for the call; `hpc` is a valid out-pointer.
    let hr = unsafe {
        CreatePseudoConsole(
            size,
            input_read.as_raw_handle(),
            output_write.as_raw_handle(),
            0,
            &raw mut hpc,
        )
    };
    if hr != 0 {
        return Err(io::Error::other(format!(
            "CreatePseudoConsole failed: HRESULT 0x{:08x}",
            hr.cast_unsigned()
        )));
    }
    let console = PseudoConsole(hpc);
    // The pseudoconsole holds its own handles to its ends.
    drop(input_read);
    drop(output_write);

    let mut reader_end = File::from(output_read);
    let reader = std::thread::Builder::new()
        .name("hm-conpty-reader".into())
        .spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader_end.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => output
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    // A broken pipe is the pseudoconsole closing its end.
                    Err(_) => break,
                }
            }
        })?;

    let mut attributes = AttributeList::new(1)?;
    attributes.set_pseudoconsole(&console)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).unwrap_or(u32::MAX);
    // Null standard handles (module docs): the console attach gives the program the
    // pseudoconsole's.
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.lpAttributeList = attributes.as_ptr();
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: no pointer; this process's "ignore Ctrl-C" attribute is cleared so the
    // program is created with the normal disposition (module docs: the decision). Best
    // effort: on failure the attribute stays as it was.
    let _ = unsafe { SetConsoleCtrlHandler(None, 0) };
    // SAFETY: every string is a NUL-terminated buffer alive for the call (the command
    // line mutable); the environment block is double-NUL-terminated UTF-16 (hence
    // CREATE_UNICODE_ENVIRONMENT); `startup` is a STARTUPINFOEXW with its size set and an
    // initialized attribute list (hence EXTENDED_STARTUPINFO_PRESENT); `info` is a valid
    // out-pointer; no handle is inherited.
    let created = unsafe {
        CreateProcessW(
            application
                .as_ref()
                .map_or(std::ptr::null(), |a| a.as_ptr()),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            block.as_ptr().cast(),
            dir.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
            (&raw const startup).cast(),
            &raw mut info,
        )
    };
    if created == 0 {
        let e = last_error("CreateProcessW");
        // Closing the pseudoconsole ends the reader thread.
        drop(console);
        return Err(e);
    }
    drop(attributes);
    // SAFETY: both handles were just returned by CreateProcessW, are open, and are owned
    // by nothing else.
    let (process, thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(info.hProcess),
            OwnedHandle::from_raw_handle(info.hThread),
        )
    };
    drop(thread);
    Ok((
        Child {
            process,
            pid: info.dwProcessId,
            input: Some(File::from(input_write)),
            console: Some(console),
        },
        reader,
    ))
}

impl Child {
    /// Type `bytes` at the console.
    ///
    /// # Errors
    /// The console's input is closed.
    pub(crate) fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "terminal closed"))?;
        input.write_all(bytes)?;
        input.flush()
    }

    /// The program's exit code once it has ended (an NTSTATUS such as
    /// `STATUS_CONTROL_C_EXIT`, 0xC000013A, reads as a negative number).
    pub(crate) fn try_wait(&mut self) -> Option<i32> {
        // SAFETY: the process handle is live (owned by `self`).
        if unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } != WAIT_OBJECT_0 {
            return None;
        }
        let mut code = 0u32;
        // SAFETY: the process handle is live; `code` is a valid out-pointer.
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &raw mut code) } == 0 {
            return None;
        }
        Some(code.cast_signed())
    }

    /// Terminate the program through its own handle, then wait (bounded) until it is
    /// gone. A program that already ended is left as it is.
    pub(crate) fn kill(&mut self) {
        // SAFETY: the process handle is live; a program that already ended makes the
        // call fail harmlessly.
        unsafe {
            let _ = TerminateProcess(self.process.as_raw_handle(), KILLED);
            let _ = WaitForSingleObject(self.process.as_raw_handle(), KILL_WAIT_MS);
        }
    }

    /// Close the pseudoconsole (its programs end with it; the reader sees end of file
    /// once its last output is drained) and the input. Idempotent.
    pub(crate) fn close(&mut self) {
        drop(self.console.take());
        drop(self.input.take());
    }

    /// The program's PID (for diagnostics; never used to find the process).
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_text(args: &[&str]) -> String {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let line = command_line(Path::new(r"C:\Program Files\x\p.exe"), &args).unwrap();
        String::from_utf16(&line[..line.len() - 1]).unwrap()
    }

    #[test]
    fn command_line_follows_the_msvc_rules() {
        assert_eq!(
            line_text(&["a", "b c", "", r#"q"x"#, r"tail\", r"bs\\ q", r#"e\"q"#]),
            r#""C:\Program Files\x\p.exe" a "b c" "" "q\"x" tail\ "bs\\ q" "e\\\"q""#
        );
        assert_eq!(
            line_text(&[r"a b\"]),
            r#""C:\Program Files\x\p.exe" "a b\\""#
        );
    }

    #[test]
    fn environment_block_is_sorted_and_carries_the_system_variables() {
        let block = environment_block(&[
            ("b".into(), "2".into()),
            ("A".into(), "1".into()),
            ("SYSTEMROOT".into(), "mine".into()),
        ])
        .unwrap();
        assert_eq!(&block[block.len() - 2..], &[0, 0]);
        let text = String::from_utf16(&block).unwrap();
        let vars: Vec<&str> = text.split('\0').filter(|v| !v.is_empty()).collect();
        assert_eq!(vars[0], "A=1");
        assert_eq!(vars[1], "b=2");
        assert!(vars.contains(&"SYSTEMROOT=mine"), "{vars:?}");
        assert!(
            !vars.iter().any(|v| v.starts_with("SystemRoot=")),
            "a set name is not carried again: {vars:?}"
        );
        let mut sorted = vars.clone();
        sorted.sort_by_key(|v| v.split('=').next().unwrap_or("").to_uppercase());
        assert_eq!(vars, sorted);
        assert!(environment_block(&[("a=b".into(), "c".into())]).is_err());
        assert_eq!(environment_block(&[]).unwrap().last(), Some(&0));
    }
}
