//! ⟨M03 wave 6, U13; ADR-0008 §17.26 item 8, §17.28 item 4⟩ A program run on a terminal,
//! the same way on every platform, for the interactive e2e cases that must also run on
//! Windows (typed confirmations, the issuer ceremonies, Ctrl-C at a prompt, the TUI).
//!
//! * **Unix:** under `script(1)`, as the M01–M03 typed-confirmation cases already run
//!   (`script -q -e -c '<argv>' /dev/null` on Linux, `script -q /dev/null <argv>` on
//!   macOS and the BSDs): the program is the session leader of a new pseudo-terminal, this
//!   process talks to `script` over pipes, and `script` relays both ways. Signal
//!   dispositions the test runner ignored are inherited (see [`crate::term`]); a case
//!   that depends on `^C` reaching the program uses its own pty child instead.
//! * **Windows:** on a pseudoconsole (ConPTY), with no window, through
//!   [`conpty`](self::imp): the program's standard handles are the pseudoconsole, so
//!   `stdin().is_terminal()` holds and `CONIN$`/`CONOUT$` open it.
//!
//! **The environment is explicit.** The program gets only the variables the command sets
//! (as `Command::env_clear` would), except that on Windows `SystemRoot`, `windir`,
//! `ComSpec` and `PATHEXT` are carried over from this process when the command does not
//! set them (the Windows networking and process APIs need them). No `HEIMDALL_*`, agent
//! or Git variable is ever inherited.
//!
//! **The transcript** is every byte the terminal showed, kept in memory; [`Terminal::text`]
//! is the same with escape sequences and carriage returns removed, which is what
//! [`Terminal::expect`] searches. Nothing here prints it.
//!
//! **Lifetime:** dropping a [`Terminal`] whose program still runs kills it through its own
//! handle (never by name or PID lookup) and reaps it.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// ETX, what a terminal sends for Ctrl-C.
pub const CTRL_C: u8 = 0x03;

/// How to start a program on a terminal ([`TerminalCommand::spawn`]).
#[derive(Debug, Clone)]
pub struct TerminalCommand {
    program: PathBuf,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    cwd: Option<PathBuf>,
    cols: u16,
    rows: u16,
}

impl TerminalCommand {
    /// The program (an absolute path is best: the environment is explicit), no arguments,
    /// an empty environment, this process's working directory, 120×40.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> TerminalCommand {
        TerminalCommand {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            cols: 120,
            rows: 40,
        }
    }

    /// One more argument.
    #[must_use]
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> TerminalCommand {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    /// More arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> TerminalCommand
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    /// Set one environment variable (a later value for the same name replaces it).
    #[must_use]
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> TerminalCommand {
        let key = key.as_ref().to_owned();
        self.env.retain(|(k, _)| !same_name(k, &key));
        self.env.push((key, value.as_ref().to_owned()));
        self
    }

    /// The working directory.
    #[must_use]
    pub fn current_dir(mut self, dir: impl Into<PathBuf>) -> TerminalCommand {
        self.cwd = Some(dir.into());
        self
    }

    /// The terminal's size in columns and rows.
    #[must_use]
    pub fn size(mut self, cols: u16, rows: u16) -> TerminalCommand {
        self.cols = cols.max(20);
        self.rows = rows.max(5);
        self
    }

    /// The program.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Start it.
    ///
    /// # Errors
    /// When the terminal cannot be created or the program cannot be started (on Unix,
    /// also when `script(1)` is missing: the case is then blocked on it, never passed).
    pub fn spawn(&self) -> io::Result<Terminal> {
        let output = Arc::new(Mutex::new(Vec::new()));
        let (inner, reader) = imp::spawn(self, Arc::clone(&output))?;
        Ok(Terminal {
            inner,
            output,
            reader: Some(reader),
            exit: None,
        })
    }
}

/// Environment names compare case-insensitively on Windows.
fn same_name(a: &OsStr, b: &OsStr) -> bool {
    if cfg!(windows) {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    } else {
        a == b
    }
}

/// [`Terminal::expect`] gave up: the text never showed, or the program ended first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalTimeout {
    /// What was awaited.
    pub needle: String,
    /// The program's exit code when it had already ended.
    pub exited: Option<i32>,
    /// The terminal's text so far ([`Terminal::text`]).
    pub text: String,
}

impl fmt::Display for TerminalTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.exited {
            Some(code) => write!(
                f,
                "the program exited ({code}) before {:?} showed; terminal text: {}",
                self.needle, self.text
            ),
            None => write!(
                f,
                "{:?} did not show in time; terminal text: {}",
                self.needle, self.text
            ),
        }
    }
}

impl std::error::Error for TerminalTimeout {}

/// A program running on a terminal ([`TerminalCommand::spawn`]).
pub struct Terminal {
    inner: imp::Child,
    output: Arc<Mutex<Vec<u8>>>,
    reader: Option<JoinHandle<()>>,
    exit: Option<i32>,
}

impl fmt::Debug for Terminal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Terminal")
            .field("pid", &self.pid())
            .field("exit", &self.exit)
            .finish_non_exhaustive()
    }
}

impl Terminal {
    /// Type `bytes` at the terminal (`b"yes\r"` answers a prompt; a pseudoconsole and a
    /// pty in canonical mode both take `\r` as Enter).
    ///
    /// # Errors
    /// When the terminal's input is closed.
    pub fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.inner.send(bytes)
    }

    /// Press Ctrl-C: [`CTRL_C`] typed at the terminal. A pty with `ISIG` set turns it into
    /// SIGINT for the foreground process group; a pseudoconsole turns it into a
    /// `CTRL_C_EVENT` for every process attached to it whose console input is processed,
    /// and delivers the byte itself to a reader that turned processed input off.
    ///
    /// # Errors
    /// When the terminal's input is closed.
    pub fn interrupt(&mut self) -> io::Result<()> {
        self.inner.send(&[CTRL_C])
    }

    /// Every byte the terminal showed so far.
    #[must_use]
    pub fn output(&self) -> Vec<u8> {
        self.output
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The terminal's text so far: [`Terminal::output`] with escape sequences and
    /// carriage returns removed ([`strip_escapes`]).
    #[must_use]
    pub fn text(&self) -> String {
        strip_escapes(&self.output())
    }

    /// Wait until [`Terminal::text`] contains `needle`.
    ///
    /// # Errors
    /// [`TerminalTimeout`] when it did not show within `timeout`, or the program ended
    /// (and its output was drained) without showing it.
    pub fn expect(&mut self, needle: &str, timeout: Duration) -> Result<(), TerminalTimeout> {
        let start = Instant::now();
        loop {
            if self.text().contains(needle) {
                return Ok(());
            }
            if let Some(code) = self.try_wait() {
                // The reader may still be draining the last output.
                std::thread::sleep(Duration::from_millis(200));
                if self.text().contains(needle) {
                    return Ok(());
                }
                return Err(TerminalTimeout {
                    needle: needle.to_owned(),
                    exited: Some(code),
                    text: self.text(),
                });
            }
            if start.elapsed() >= timeout {
                return Err(TerminalTimeout {
                    needle: needle.to_owned(),
                    exited: None,
                    text: self.text(),
                });
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// The program's exit code if it has ended (on Unix, `script`'s, which is the
    /// program's; a program ended by a signal reads as `128 + signal`).
    pub fn try_wait(&mut self) -> Option<i32> {
        if self.exit.is_none() {
            self.exit = self.inner.try_wait();
        }
        self.exit
    }

    /// Wait for the program to end, up to `timeout`; then close the terminal and collect
    /// the rest of its output. `None`: it was still running at the deadline, and has been
    /// killed through its own handle.
    pub fn wait(&mut self, timeout: Duration) -> Option<i32> {
        let start = Instant::now();
        let code = loop {
            if let Some(code) = self.try_wait() {
                break Some(code);
            }
            if start.elapsed() >= timeout {
                self.inner.kill();
                break None;
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        self.finish();
        code
    }

    /// The process this terminal started (on Unix, `script`; on Windows, the program).
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.inner.pid()
    }

    /// Close the terminal's input and output and join the reader.
    fn finish(&mut self) {
        self.inner.close();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if self.try_wait().is_none() {
            self.inner.kill();
        }
        self.finish();
    }
}

/// `bytes` as text with escape sequences (CSI `ESC [ … final`, OSC `ESC ] … BEL|ST`, and
/// two-byte `ESC x`), carriage returns and other C0 controls except `\n` and `\t`
/// removed. A pseudoconsole repaints with cursor moves, so a word may arrive split by
/// sequences; the result joins it again.
#[must_use]
pub fn strip_escapes(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.next() {
                Some('[') => {
                    // Parameters and intermediates, then one final byte in 0x40..=0x7e.
                    for c in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // Until BEL or ST (ESC \).
                    while let Some(c) = chars.next() {
                        if c == '\u{7}' {
                            break;
                        }
                        if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            },
            '\n' | '\t' => out.push(c),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(unix)]
mod imp {
    //! `script(1)` (module docs).
    use std::io::{self, Read as _, Write as _};
    use std::process::{ChildStdin, Command, Stdio};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::thread::JoinHandle;

    use super::TerminalCommand;

    pub(super) struct Child {
        child: std::process::Child,
        stdin: Option<ChildStdin>,
    }

    /// `'…'` for `sh -c`, with each `'` as `'\''`.
    fn sh_quote(arg: &std::ffi::OsStr) -> String {
        format!("'{}'", arg.to_string_lossy().replace('\'', r"'\''"))
    }

    pub(super) fn spawn(
        cmd: &TerminalCommand,
        output: Arc<Mutex<Vec<u8>>>,
    ) -> io::Result<(Child, JoinHandle<()>)> {
        let script = crate::home::find_program("script").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "blocked: script(1) is needed for the terminal cases",
            )
        })?;
        let mut command = Command::new(script);
        if cfg!(target_os = "linux") {
            let line: Vec<String> = std::iter::once(cmd.program.as_os_str())
                .chain(cmd.args.iter().map(std::ffi::OsString::as_os_str))
                .map(sh_quote)
                .collect();
            command.args(["-q", "-e", "-c", &line.join(" "), "/dev/null"]);
        } else {
            command
                .args(["-q", "/dev/null"])
                .arg(&cmd.program)
                .args(&cmd.args);
        }
        command.env_clear();
        for (k, v) in &cmd.env {
            command.env(k, v);
        }
        // The size, for programs that read it from the environment (script(1) gives the
        // pty its own default size).
        command
            .env("COLUMNS", cmd.cols.to_string())
            .env("LINES", cmd.rows.to_string());
        if let Some(dir) = &cmd.cwd {
            command.current_dir(dir);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take();
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("script(1) has no stdout"))?;
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 {
                    break;
                }
                output
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(&buf[..n]);
            }
        });
        Ok((Child { child, stdin }, reader))
    }

    impl Child {
        pub(super) fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            let stdin = self
                .stdin
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "terminal closed"))?;
            stdin.write_all(bytes)?;
            stdin.flush()
        }

        pub(super) fn try_wait(&mut self) -> Option<i32> {
            use std::os::unix::process::ExitStatusExt as _;
            match self.child.try_wait() {
                Ok(Some(s)) => Some(s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))),
                _ => None,
            }
        }

        pub(super) fn kill(&mut self) {
            // Our own unreaped child: its PID cannot have been reused.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }

        pub(super) fn close(&mut self) {
            self.stdin = None;
        }

        pub(super) fn pid(&self) -> u32 {
            self.child.id()
        }
    }
}

#[cfg(windows)]
mod imp {
    //! The pseudoconsole (ConPTY), `crate::conpty` (module docs).
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;

    use super::TerminalCommand;

    pub(super) use crate::conpty::Child;

    pub(super) fn spawn(
        cmd: &TerminalCommand,
        output: Arc<Mutex<Vec<u8>>>,
    ) -> io::Result<(Child, JoinHandle<()>)> {
        crate::conpty::spawn(
            &cmd.program,
            &cmd.args,
            &cmd.env,
            cmd.cwd.as_deref(),
            cmd.cols,
            cmd.rows,
            output,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_escapes_joins_text_split_by_sequences() {
        let raw = b"\x1b[?25l\x1b[2;1HType \x1b[1my\x1b[0mes\r\n\x1b]0;title\x07[y/N]: \x1b[K";
        assert_eq!(strip_escapes(raw), "Type yes\n[y/N]: ");
        assert_eq!(strip_escapes(b"a\x1b]8;;x\x1b\\b\tc\x08"), "ab\tc");
    }

    /// The Unix side end to end: a prompt, a typed answer, the exit code and the text.
    #[cfg(unix)]
    #[test]
    fn unix_terminal_types_an_answer_and_reports_the_exit_code() {
        let sh = crate::home::find_program("sh").expect("sh");
        let mut t = TerminalCommand::new(sh)
            .args([
                "-c",
                "[ -t 0 ] && [ -t 1 ] || exit 9; printf 'answer? '; read a; \
                 [ \"$a\" = yes ] && { echo ok-$a; exit 3; }; exit 4",
            ])
            .env("PATH", "/usr/bin:/bin")
            .spawn()
            .expect("script(1)");
        t.expect("answer? ", Duration::from_secs(20)).unwrap();
        t.send(b"yes\r").unwrap();
        assert_eq!(t.wait(Duration::from_secs(20)), Some(3), "{}", t.text());
        assert!(t.text().contains("ok-yes"), "{}", t.text());
    }

    /// The program the Windows terminal tests start on a pseudoconsole: this test binary
    /// again, in child mode (`HM_CONSOLE_CHILD`): exit 9 unless stdin and stdout are the
    /// console; otherwise it prompts `answer? `, reads one line from stdin (the console in
    /// its default mode: line input, echo, processed input) and exits 3 after printing
    /// `ok-yes` when the line is `yes` in mode `answer`, 4 otherwise.
    #[cfg(windows)]
    #[test]
    #[ignore = "child-mode entry of the Windows terminal tests, started by them"]
    fn windows_console_child() {
        use std::io::{BufRead as _, IsTerminal as _, Write as _};
        let Ok(mode) = std::env::var("HM_CONSOLE_CHILD") else {
            return;
        };
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            std::process::exit(9);
        }
        let mut out = std::io::stdout();
        let _ = out.write_all(b"answer? ").and_then(|()| out.flush());
        let mut line = String::new();
        let n = std::io::stdin().lock().read_line(&mut line).unwrap_or(0);
        if mode == "answer" && n > 0 && line.trim() == "yes" {
            let _ = out.write_all(b"ok-yes\r\n").and_then(|()| out.flush());
            std::process::exit(3);
        }
        std::process::exit(4);
    }

    /// [`windows_console_child`] in `mode`, on a pseudoconsole.
    #[cfg(windows)]
    fn windows_child(mode: &str) -> TerminalCommand {
        TerminalCommand::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "console::tests::windows_console_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env("HM_CONSOLE_CHILD", mode)
    }

    /// ⟨M03 wave 6, U13⟩ The Windows side end to end (the façade over `conpty`): the
    /// program's stdin and stdout are the pseudoconsole (null standard handles at
    /// creation), a typed answer with `\r` reaches its line read, and the exit code and
    /// the console's text come back.
    #[cfg(windows)]
    #[test]
    fn windows_terminal_types_an_answer_and_reports_the_exit_code() {
        let mut t = windows_child("answer").spawn().expect("pseudoconsole");
        // Without the blank before the cursor (the console may leave it out).
        t.expect("answer?", Duration::from_secs(60))
            .unwrap_or_else(|e| panic!("{e}"));
        t.send(b"yes\r").unwrap();
        assert_eq!(t.wait(Duration::from_secs(60)), Some(3), "{}", t.text());
        assert!(t.text().contains("ok-yes"), "{}", t.text());
    }

    /// ⟨M03 wave 6, U13; ADR-0008 §17.28 item 4⟩ [`Terminal::interrupt`] on Windows is
    /// Ctrl-C typed at the pseudoconsole: a `CTRL_C_EVENT` for a program reading with
    /// processed input, whose default handler ends it with `STATUS_CONTROL_C_EXIT`
    /// (0xC000013A). It holds whatever "ignore Ctrl-C" attribute the test runner passed
    /// down, because `conpty` clears this process's before creating the program: the
    /// Ctrl-C cases of the e2e suites depend on exactly that.
    #[cfg(windows)]
    #[test]
    fn windows_terminal_ctrl_c_reaches_a_processed_input_reader() {
        const STATUS_CONTROL_C_EXIT: u32 = 0xC000_013A;
        let mut t = windows_child("wait").spawn().expect("pseudoconsole");
        t.expect("answer?", Duration::from_secs(60))
            .unwrap_or_else(|e| panic!("{e}"));
        std::thread::sleep(Duration::from_millis(300));
        t.interrupt().unwrap();
        assert_eq!(
            t.wait(Duration::from_secs(60)),
            Some(STATUS_CONTROL_C_EXIT.cast_signed()),
            "{}",
            t.text()
        );
    }
}
