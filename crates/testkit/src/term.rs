//! The terminal session of the e2e pseudo-terminal cases (Unix; ADR-0007 §12.32 item 9).
//!
//! A pty case re-executes its test binary as the session leader of a new session on the
//! pty (`setsid`, `TIOCSCTTY`) and `exec`s the program under test there. Signal
//! dispositions survive `execve` when they are `SIG_IGN`, so every process of that session
//! inherits what the test runner ignored: a test binary started as a background job of a
//! non-interactive shell (POSIX gives such a job SIGINT and SIGQUIT ignored), under `nohup`
//! (SIGHUP), or by a CI runner, passes those on. A non-interactive `/bin/sh` cannot trap a
//! signal that was ignored on entry, and `sleep` ignores it too, so a `^C` typed at the pty
//! then reaches nobody: `a27_ctrl_c_reaches_child_once` failed exactly so ("heimdall did
//! not finish") whenever its runner ignored SIGINT, and passed otherwise.
//!
//! A terminal emulator starts its session with the default dispositions.
//! [`default_terminal_signals_for_exec`] gives the pty session the same: it installs a
//! handler (tokio's) for each terminal-generated signal, and a handler, unlike `SIG_IGN`,
//! does not survive `execve`, so the program the session leader execs next starts with
//! the default disposition of every one of them. No `unsafe`, no `sigaction` here.

use std::io;

use tokio::signal::unix::{SignalKind, signal};

/// The signals a terminal generates or that a session's hang-up and job control send:
/// SIGINT, SIGQUIT, SIGHUP, SIGWINCH, SIGTSTP, SIGTTIN and SIGTTOU.
#[must_use]
pub fn terminal_signals() -> [SignalKind; 7] {
    use rustix::process::Signal;
    [
        SignalKind::interrupt(),
        SignalKind::quit(),
        SignalKind::hangup(),
        SignalKind::window_change(),
        SignalKind::from_raw(Signal::TSTP.as_raw()),
        SignalKind::from_raw(Signal::TTIN.as_raw()),
        SignalKind::from_raw(Signal::TTOU.as_raw()),
    ]
}

/// Make the next `exec` of this process start with the default disposition of every
/// [`terminal_signals`] signal, whatever this process inherited (module docs). Call it in
/// a pty case's session leader just before it execs the program under test. Until that
/// exec, the signals are caught and dropped by tokio's handler (never acted on).
///
/// # Errors
/// When a runtime cannot be built or a handler cannot be installed; the caller must then
/// not exec (the session would keep the inherited dispositions).
pub fn default_terminal_signals_for_exec() -> io::Result<()> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .build()?;
                let _entered = runtime.enter();
                for kind in terminal_signals() {
                    // tokio never unregisters the OS handler, so dropping the stream (and
                    // the runtime) leaves the handler installed until the exec.
                    drop(signal(kind)?);
                }
                Ok(())
            })
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("the signal registration panicked")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe each shell runs: it traps each signal, sends it to itself, and prints
    /// `caught-<SIG>` when the trap ran. A non-interactive shell cannot trap a signal
    /// that was ignored on entry, so an ignored one prints nothing.
    const PROBE: &str =
        "for s in INT QUIT HUP; do trap \"echo caught-$s\" $s; kill -$s $$; done; echo end";

    /// A child started after the call gets the defaults, even though this process ignored
    /// SIGINT, SIGQUIT and SIGHUP first (`trap '' INT QUIT HUP` in a shell that then execs
    /// a fresh copy of this test binary, which calls the function and execs the probe).
    /// The control: the same chain without the call keeps them ignored.
    #[test]
    fn a_runner_that_ignores_sigint_hands_on_the_default_after_the_call() {
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                "trap '' INT QUIT HUP; exec \"$@\"",
                "sh",
                exe.to_str().unwrap(),
                "--exact",
                "term::tests::term_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env("HM_TESTKIT_TERM_CHILD", PROBE)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        for name in ["INT", "QUIT", "HUP"] {
            assert!(
                text.lines().any(|l| l == format!("caught-{name}")),
                "{name} reaches its trap after the call: {text}"
            );
        }
        let out = std::process::Command::new("/bin/sh")
            .args(["-c", "trap '' INT QUIT HUP; exec /bin/sh -c \"$0\"", PROBE])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.lines().any(|l| l == "end"), "{text}");
        assert!(
            !text.contains("caught-"),
            "without the call every one stays ignored: {text}"
        );
    }

    /// Child-mode entry of the test above; does nothing in a normal run.
    #[test]
    #[ignore = "child-mode entry of term::tests, started by them"]
    fn term_child() {
        use std::os::unix::process::CommandExt as _;
        let Some(probe) = std::env::var_os("HM_TESTKIT_TERM_CHILD") else {
            return;
        };
        default_terminal_signals_for_exec().unwrap();
        let err = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(probe)
            .env_remove("HM_TESTKIT_TERM_CHILD")
            .exec();
        panic!("exec failed: {err}");
    }
}
