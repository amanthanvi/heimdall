//! ⟨M03 wave 6, U13; ADR-0008 §17.26 item 8⟩ `e2e_cli_m03` submodule `windows_console`
//! (Windows only): a CLI case on a **pseudoconsole** (`heimdall_testkit::console`, ConPTY),
//! the Windows form of the Unix suites' pty child.
//!
//! The pseudoconsole runs this test binary again in child mode ([`console_child`]): it is
//! attached to the pseudoconsole (its standard handles are the console's), and it starts
//! the case's program with **stdin** the console (or `NUL`, [`Wiring::stdin_console`]),
//! **stdout** a file of its own, and **stderr** the console or a file
//! ([`Wiring::stderr_console`]), then exits with the program's exit code. So a case shows
//! what reaches the console (`CONIN$`/`CONOUT$`, the prompts, the passphrase) apart from
//! what reaches stdout and stderr, as the Unix pty child does with the slave as the
//! controlling terminal.
//!
//! **Ctrl-C.** The program is attached to the same console, so Ctrl-C typed at it reaches
//! the program as on a real console. The child itself survives it: it holds a Ctrl-C
//! listener (tokio's console control handler answers `CTRL_C_EVENT` while a listener
//! lives), so the case's exit code is always the program's, never the child's. The
//! program is created with the normal Ctrl-C disposition whatever the test runner
//! inherited (`heimdall_testkit::console` clears the "ignore Ctrl-C" attribute before it
//! starts the child, and the child passes the cleared attribute on).
//!
//! **Diagnostics.** Every wait that fails panics with the console's text, escape
//! sequences removed and any passphrase-shaped run replaced ([`Case::shown`]), and the
//! exit code when the program had ended. Nothing here prints a typed passphrase: it is
//! typed through the console's input only, never an argument or a variable.
#![allow(clippy::panic)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use heimdall_testkit::assert_no_canary;
use heimdall_testkit::console::{Terminal, TerminalCommand, strip_escapes};

use super::Out;

const ARGV: &str = "HM_W_CONSOLE_ARGV";
const ENVS: &str = "HM_W_CONSOLE_ENV";
const STDOUT: &str = "HM_W_CONSOLE_STDOUT";
/// Present: stderr goes to this file (else it is the console).
const STDERR: &str = "HM_W_CONSOLE_STDERR";
/// Present: stdin is `NUL` (else it is the console).
const STDIN_NUL: &str = "HM_W_CONSOLE_STDIN_NUL";

/// How long a case may wait for a prompt or for the program to end.
pub(super) const LIMIT: Duration = Duration::from_secs(120);

/// Child-mode entry: start the program in [`ARGV`] with exactly [`ENVS`], stdin, stdout
/// and stderr as the variables say, wait, and exit with its exit code (module docs).
#[test]
#[ignore = "child-mode entry of the Windows console cases, started by them"]
fn console_child() {
    let (Ok(argv), Ok(envs), Some(stdout)) = (
        std::env::var(ARGV),
        std::env::var(ENVS),
        std::env::var_os(STDOUT),
    ) else {
        return;
    };
    // Held until the process exits: Ctrl-C at the console ends the program, not this.
    let ctrl_c = tokio::signal::windows::ctrl_c().expect("a Ctrl-C listener");
    let argv: Vec<String> = serde_json::from_str(&argv).unwrap();
    let envs: Vec<(String, String)> = serde_json::from_str(&envs).unwrap();
    let stdin = if std::env::var_os(STDIN_NUL).is_some() {
        Stdio::null()
    } else {
        Stdio::inherit()
    };
    let stderr = match std::env::var_os(STDERR) {
        Some(path) => Stdio::from(std::fs::File::create(path).unwrap()),
        None => Stdio::inherit(),
    };
    let status = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .envs(envs)
        .stdin(stdin)
        .stdout(std::fs::File::create(stdout).unwrap())
        .stderr(stderr)
        .status()
        .unwrap_or_else(|e| panic!("the case's program did not start: {e}"));
    drop(ctrl_c);
    std::process::exit(status.code().unwrap_or(-1));
}

/// Where a case's stdin and stderr go (stdout is always its own file).
#[derive(Clone, Copy)]
pub(super) struct Wiring {
    /// stdin is the console (else `NUL`).
    pub(super) stdin_console: bool,
    /// stderr is the console (else its own file).
    pub(super) stderr_console: bool,
}

/// A ceremony's invocation: stdin the console (an interactive invocation), stdout and
/// stderr their own files, so only the console shows the ceremony.
pub(super) const CEREMONY: Wiring = Wiring {
    stdin_console: true,
    stderr_console: false,
};
/// ⟨ADR-0008 §17.27 item 5⟩ stdin redirected (`NUL`) while the console stays attached.
pub(super) const REDIRECTED_STDIN: Wiring = Wiring {
    stdin_console: false,
    stderr_console: false,
};
/// An ordinary prompt: stdin and stderr the console (the prompt and the disclosures are
/// written to stderr), stdout its own file (the envelope).
pub(super) const PROMPT: Wiring = Wiring {
    stdin_console: true,
    stderr_console: true,
};

/// The variables a Windows program needs from this process (the networking, crypto and
/// process APIs read them), added to a case's environment when it does not set them.
pub(super) fn system_env() -> Vec<(OsString, OsString)> {
    ["SystemRoot", "windir", "ComSpec", "PATHEXT", "TEMP", "TMP"]
        .iter()
        .filter_map(|k| std::env::var_os(k).map(|v| (OsString::from(k), v)))
        .collect()
}

/// One started case: the console, what the test gave it, its output files.
pub(super) struct Case {
    term: Terminal,
    /// Every argument and variable the test gave (the passphrase must be in none).
    pub(super) given: Vec<OsString>,
    stdout: PathBuf,
    stderr: Option<PathBuf>,
}

/// Start `argv` (its program an absolute path) with exactly `env` (plus
/// [`system_env`]) on a new pseudoconsole, wired as `wiring` says; the output files go
/// to `dir`, named after `case`.
pub(super) fn start(
    dir: &Path,
    case: &str,
    argv: &[OsString],
    env: &[(OsString, OsString)],
    wiring: Wiring,
) -> Case {
    let exe = std::env::current_exe().unwrap();
    let stdout = dir.join(format!("{case}.stdout"));
    let stderr = (!wiring.stderr_console).then(|| dir.join(format!("{case}.stderr")));
    let mut vars: Vec<(String, String)> = env
        .iter()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect();
    for (k, v) in system_env() {
        let k = k.to_string_lossy().into_owned();
        if !vars.iter().any(|(n, _)| n.eq_ignore_ascii_case(&k)) {
            vars.push((k, v.to_string_lossy().into_owned()));
        }
    }
    let argv_text: Vec<String> = argv
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let entry = [
        "--exact",
        "windows_console::console_child",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
        "-q",
    ];
    let mut cmd = TerminalCommand::new(&exe)
        .args(entry)
        .current_dir(dir)
        .size(200, 50)
        .env(ARGV, serde_json::to_string(&argv_text).unwrap())
        .env(ENVS, serde_json::to_string(&vars).unwrap())
        .env(STDOUT, &stdout);
    if let Some(e) = &stderr {
        cmd = cmd.env(STDERR, e);
    }
    if !wiring.stdin_console {
        cmd = cmd.env(STDIN_NUL, "1");
    }
    let term = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("{case}: the pseudoconsole did not start: {e}"));
    let mut given: Vec<OsString> = vec![exe.into_os_string()];
    given.extend(entry.iter().map(OsString::from));
    given.extend(argv.iter().cloned());
    given.extend(vars.into_iter().flat_map(|(k, v)| [k.into(), v.into()]));
    Case {
        term,
        given,
        stdout,
        stderr,
    }
}

/// `text` with every passphrase-shaped run (26 base32 symbols in groups of five)
/// replaced, for failure messages.
pub(super) fn redacted(text: &str) -> String {
    let mut out = text.to_owned();
    for spaced in [text.to_owned(), escapes_as_spaces(text.as_bytes())] {
        if let Some(found) = heimdall_testkit::ca::ceremony::find_passphrase(spaced.as_bytes()) {
            let joined = String::from_utf8_lossy(&found).into_owned();
            for form in passphrase_forms(&joined) {
                out = out.replace(&form, "<passphrase>");
            }
        }
    }
    out
}

/// `bytes` as text with each escape sequence replaced by one space (the pseudoconsole may
/// move the cursor instead of writing the blanks between a passphrase's groups) and
/// other controls but `\n` removed.
pub(super) fn escapes_as_spaces(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut spaced = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => {
                match chars.next() {
                    Some('[') => {
                        for c in chars.by_ref() {
                            if ('\u{40}'..='\u{7e}').contains(&c) {
                                break;
                            }
                        }
                    }
                    Some(']') => {
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
                }
                spaced.push(' ');
            }
            '\n' => spaced.push('\n'),
            c if c.is_control() => {}
            c => spaced.push(c),
        }
    }
    spaced
}

/// The ASCII letters and digits of `text`: what is compared across the console's
/// re-rendering.
pub(super) fn squash(text: &str) -> String {
    text.chars().filter(char::is_ascii_alphanumeric).collect()
}

/// Every form a shown passphrase may take: joined, grouped by spaces, grouped by `-`.
pub(super) fn passphrase_forms(joined: &str) -> Vec<String> {
    let groups: Vec<String> = joined
        .as_bytes()
        .chunks(5)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    vec![joined.to_owned(), groups.join(" "), groups.join("-")]
}

impl Case {
    /// The console's text (escapes removed), any passphrase replaced: what a failure
    /// message shows.
    pub(super) fn shown(&self) -> String {
        redacted(&self.term.text())
    }

    /// The console's text, escapes removed (may hold a shown passphrase: never print).
    pub(super) fn text(&self) -> String {
        self.term.text()
    }

    /// The first passphrase the console showed (never printed).
    pub(super) fn passphrase(&self) -> Option<String> {
        let raw = self.term.output();
        [strip_escapes(&raw), escapes_as_spaces(&raw)]
            .iter()
            .find_map(|t| heimdall_testkit::ca::ceremony::find_passphrase(t.as_bytes()))
            .map(|p| String::from_utf8_lossy(&p).into_owned())
    }

    /// Wait until the console shows `needle`, compared by [`squash`] (the console's
    /// re-rendering may wrap a line, move the cursor instead of writing blanks, and
    /// leave out the blank before the cursor at a prompt); panics with [`Case::shown`]
    /// and the exit code otherwise.
    pub(super) fn expect(&mut self, needle: &str) {
        let want = squash(needle);
        let deadline = std::time::Instant::now() + LIMIT;
        loop {
            if squash(&self.term.text()).contains(&want) {
                return;
            }
            if let Some(code) = self.term.try_wait() {
                // The reader may still be draining the last output.
                std::thread::sleep(Duration::from_millis(300));
                if squash(&self.term.text()).contains(&want) {
                    return;
                }
                panic!(
                    "the program exited ({code}) before {needle:?} showed; console: {}",
                    self.shown()
                );
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{needle:?} did not show in time; console: {}",
                self.shown()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Type `bytes` at the console, after a short pause (the program's read is posted).
    pub(super) fn send(&mut self, bytes: &[u8]) {
        std::thread::sleep(Duration::from_millis(300));
        self.term.send(bytes).unwrap();
    }

    /// Wait for the program to end, up to `limit`: its exit code and its stdout and
    /// stderr (scanned for canaries; no panic). `None` while it still runs at `limit`
    /// (the console is then closed, which ends it).
    pub(super) fn finish_within(&mut self, limit: Duration) -> Option<Out> {
        let code = self.term.wait(limit)?;
        let stdout = std::fs::read_to_string(&self.stdout).unwrap_or_default();
        let stderr = self
            .stderr
            .as_ref()
            .map(|p| std::fs::read_to_string(p).unwrap_or_default())
            .unwrap_or_default();
        assert_no_canary(&stdout);
        assert_no_canary(&stderr);
        assert_no_canary(&self.term.text());
        assert!(
            !stderr.contains("panicked") && !self.term.text().contains("panicked"),
            "{stderr}\n{}",
            self.shown()
        );
        Some(Out {
            code,
            stdout,
            stderr,
        })
    }

    /// [`Case::finish_within`] [`LIMIT`], panicking with the console's text when the
    /// program does not end.
    pub(super) fn finish(&mut self) -> Out {
        let out = self.finish_within(LIMIT);
        out.unwrap_or_else(|| panic!("the case did not finish; console: {}", self.shown()))
    }
}
