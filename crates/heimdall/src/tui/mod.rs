//! `heimdall tui`: the first useful TUI (m02-plan U10; spec §12; plan M02-T05).
//!
//! [`run`] keeps Ratatui on the main thread and the IPC with the runtime on a worker
//! thread with a current-thread tokio runtime (overview §3). The TUI is a client like
//! the CLI and authorizes nothing itself (R-UX-05): every effect is a request the
//! runtime decides, and every owner confirmation follows the client confirmation
//! contract (ADR-0006 §3.1): a typed `y`/`yes`, default No.
//!
//! **Views** ([`model`], [`view`]): the overview (Ready, Working or Needs attention, from
//! the passive doctor's findings and `inspect`; a held setup operation is Needs
//! attention with its two repairs); destinations and profiles with immediate search
//! that never probes; the destination detail (each value's provenance and freshness,
//! the provider status, the interaction basis with its date, the identity selection,
//! the projection state); the operation detail through `observe events`; and the
//! pending-decision modal (before, after and restore columns for `ApplyProjection`,
//! the decision text for `DeclareInteraction`).
//!
//! **Connect** hands the terminal to `ssh <alias>` through
//! `heimdall_launch::handoff::run_foreground`, the `system(3)` model of ADR-0007 §8:
//! the TUI restores cooked mode and leaves the alternate screen, keeps the child in its
//! own process group with SIGINT handled (the TUI survives Ctrl-C, the child gets it),
//! leaves SIGTSTP at its default (the shell stops and continues both as one job),
//! waits, then re-enters and repaints without querying the terminal.
//!
//! **Probes** are labelled actions naming their level; a level that runs the real
//! configuration tree needs the typed authorization ([`model`]).
//!
//! **Exits:** `q` or Ctrl-C exits 0; a hang-up exits 129; SIGTERM 143 and SIGINT 130
//! (from another process: Ctrl-C at the keyboard is a key in raw mode). Every exit,
//! and a panic of the TUI's thread, restores the terminal first ([`term`]).
//!
//! **Entry.** `heimdall tui`, and a bare `heimdall` with a terminal on stdin and stdout
//! and neither `--json` nor `--non-interactive` (overview §3; ADR-0007 §12.30 item 5;
//! `cli::bare`, which leaves every other bare invocation to `status`).
//!
//! **Refusals before the terminal is touched** (usage, exit 2): `--json` (the TUI has
//! no machine output), `--non-interactive` (the TUI is interactive), a stdin or stdout
//! that is not a terminal, and a `HEIMDALL_TEST_*` variable in a release build.
//!
//! **Test configuration** (debug builds only; a release build refuses `tui` when one is
//! set): `HEIMDALL_TEST_SSH_HOME` (scratch account home for the static pass and the
//! probes, with isolation arguments on every probe client) as for `run`/`connect`;
//! `HEIMDALL_TEST_TUI_PANIC=after_first_frame` (panic once the first frame is drawn,
//! for `panic_restores_terminal`); and `HEIMDALL_TEST_TUI_SCREEN=<absolute path>`
//! (each drawn frame's text is written there, so the end-to-end suite reads the
//! screen without parsing the terminal stream).

mod data;
mod keys;
mod m03;
mod model;
mod term;
mod view;
mod worker;

use std::ffi::OsString;
use std::io::IsTerminal as _;
use std::time::{Duration, Instant};

use heimdall_contract::{Code, ExitCode, Timestamp};
use heimdall_launch::env::EnvDelta;
use heimdall_launch::handoff::{ChildOutcome, run_foreground};
use heimdall_launch::resolve::resolve_program;
use heimdall_localenv::clients::{ClientKind, ClientsConfig, selected_path, sha256_file};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::paths::SshPaths;
use ratatui::Terminal;

use crate::client::{Ctx, error};
use crate::output;
use crate::testcfg;
use model::{App, Effect};
use worker::{Event, Worker, WorkerConfig};

/// Debug builds only: `after_first_frame` panics once the first frame is drawn.
pub(crate) const PANIC_ENV: &str = "HEIMDALL_TEST_TUI_PANIC";

/// Debug builds only: an absolute path where every drawn frame's text is written
/// (rows joined by newlines, replaced atomically), so a test reads the screen without
/// parsing the terminal stream.
pub(crate) const SCREEN_ENV: &str = "HEIMDALL_TEST_TUI_SCREEN";

/// How often the listings (and an open operation's events) are re-read.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// How long the main loop waits for a key before it looks at the worker again.
const INPUT_WAIT: Duration = Duration::from_millis(100);

/// After a connect handoff, a SIGINT is the child's Ctrl-C, never a request to quit.
const INTERRUPT_GRACE: Duration = Duration::from_millis(500);

/// The longest alias the connect action passes to `ssh` (as `heimdall connect`).
const MAX_ALIAS_BYTES: usize = 255;

/// What `tui` runs with.
#[derive(Debug, Clone)]
pub(crate) struct TuiConfig {
    ctx: Ctx,
    no_color: bool,
}

impl TuiConfig {
    /// From the invocation: the global flags, and `NO_COLOR` (set and non-empty turns
    /// color off; no-color.org).
    #[must_use]
    pub(crate) fn from_ctx(ctx: &Ctx) -> Self {
        Self {
            ctx: ctx.clone(),
            no_color: std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()),
        }
    }
}

/// How the event loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    Quit,
    Hangup,
    Signal(i32),
}

fn usage(ctx: &Ctx, message: &str) -> ExitCode {
    let env = output::error_value(error(Code::UsageError, message));
    output::emit(&env, ctx.json);
    output::exit_code_for(env.code, false)
}

/// The TUI's own test hooks ([`PANIC_ENV`], [`SCREEN_ENV`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TestHooks {
    panic_after_first_frame: bool,
    screen: Option<std::path::PathBuf>,
}

/// Parse the TUI's own test hooks: parsed in debug builds, refused in release (as
/// every `HEIMDALL_TEST_*` variable is).
fn test_hooks(env: &dyn Fn(&str) -> Option<OsString>) -> Result<TestHooks, String> {
    let panic = env(PANIC_ENV);
    let screen = env(SCREEN_ENV);
    if panic.is_none() && screen.is_none() {
        return Ok(TestHooks::default());
    }
    if let Some(msg) = testcfg::refusal(testcfg::AVAILABLE, true) {
        return Err(msg.to_owned());
    }
    let panic_after_first_frame = match panic {
        None => false,
        Some(v) if v == "after_first_frame" => true,
        Some(_) => return Err(format!("{PANIC_ENV}: expected after_first_frame")),
    };
    let screen = match screen.map(std::path::PathBuf::from) {
        Some(p) if !p.is_absolute() => {
            return Err(format!("{SCREEN_ENV} must be an absolute path"));
        }
        other => other,
    };
    Ok(TestHooks {
        panic_after_first_frame,
        screen,
    })
}

/// Write the frame's text to `path` (test configuration only), replacing it whole.
fn dump_screen(buffer: &ratatui::buffer::Buffer, path: &std::path::Path) {
    let area = buffer.area;
    let mut text = String::new();
    for y in area.top()..area.bottom() {
        let row: String = (area.left()..area.right())
            .map(|x| buffer.cell((x, y)).map_or(" ", |c| c.symbol()))
            .collect();
        text.push_str(row.trim_end());
        text.push('\n');
    }
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// The isolation arguments every probe client gets under the test configuration
/// (ADR-0007 §9: isolation only, never selection options).
fn isolation_args(paths: &SshPaths) -> Vec<OsString> {
    let known = paths.user_dir.join("known_hosts");
    let global = paths.account_home.join("etc-ssh").join("ssh_known_hosts");
    vec![
        "-F".into(),
        paths.user_config.clone().into_os_string(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known.display()).into(),
        "-o".into(),
        format!("GlobalKnownHostsFile={}", global.display()).into(),
    ]
}

/// Handle `tui` (module docs).
pub(crate) fn run(config: TuiConfig) -> ExitCode {
    let ctx = &config.ctx;
    if ctx.json {
        return usage(
            ctx,
            "the TUI has no machine output; use the commands with --json",
        );
    }
    if ctx.non_interactive {
        return usage(
            ctx,
            "the TUI is interactive; --non-interactive cannot be honoured",
        );
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return usage(ctx, "the TUI needs a terminal on stdin and stdout");
    }
    let lookup = |n: &str| std::env::var_os(n);
    let hooks = match testcfg::launch_hooks(&lookup) {
        Ok(h) => h,
        Err(m) => return usage(ctx, &m),
    };
    let test = match test_hooks(&lookup) {
        Ok(t) => t,
        Err(m) => return usage(ctx, &m),
    };
    let config_dir = ctx.paths().ok().map(|p| p.config_dir);
    let (ssh_paths, isolation) = match &hooks.ssh_home {
        Some(home) => {
            let p = SshPaths::with_test_override(home.clone(), home.join("etc-ssh"));
            let iso = isolation_args(&p);
            (Some(p), Some(iso))
        }
        None => (SshPaths::resolve().ok(), None),
    };
    let worker = match worker::spawn(WorkerConfig {
        ctx: ctx.clone(),
        ssh_paths,
        env: Env::capture(),
        config_dir,
        isolation,
    }) {
        Ok(w) => w,
        Err(e) => {
            output::diagnostic(&format!(
                "heimdall: the TUI could not start its worker thread ({:?})",
                e.kind()
            ));
            return ExitCode::Internal;
        }
    };
    worker.send(model::Command::Refresh { doctor: true });
    term::install_panic_hook();
    if let Err(e) = term::enter() {
        term::leave();
        output::diagnostic(&format!(
            "heimdall: the terminal could not be set up ({:?})",
            e.kind()
        ));
        return ExitCode::Internal;
    }
    let result = Terminal::new(term::TermBackend::new()).and_then(|mut terminal| {
        let mut app = App::new(Timestamp::now(), config.no_color);
        event_loop(&mut terminal, &mut app, &worker, &test)
    });
    term::leave();
    if term::OTHER_THREAD_PANICKED.load(std::sync::atomic::Ordering::SeqCst) {
        output::diagnostic("heimdall: the TUI's worker thread stopped unexpectedly");
    }
    match result {
        Ok(Exit::Quit) => ExitCode::Success,
        Ok(Exit::Hangup) => std::process::exit(129),
        Ok(Exit::Signal(n)) => std::process::exit(128 + n),
        Err(e) if term::is_hangup(&e) => std::process::exit(129),
        Err(e) => {
            output::diagnostic(&format!("heimdall: terminal error ({:?})", e.kind()));
            ExitCode::Internal
        }
    }
}

type Term = Terminal<term::TermBackend>;

fn event_loop(
    terminal: &mut Term,
    app: &mut App,
    worker: &Worker,
    test: &TestHooks,
) -> std::io::Result<Exit> {
    let mut reader = term::Reader::new();
    let mut dirty = true;
    let mut first_frame = true;
    let mut last_poll = Instant::now();
    let mut worker_gone = false;
    let mut ignore_interrupts_until: Option<Instant> = None;
    loop {
        // Worker events first, so a key acts on the latest state.
        let mut effects = Vec::new();
        loop {
            match worker.events.try_recv() {
                Ok(Event::Update(u)) => {
                    effects.extend(app.apply(*u));
                    dirty = true;
                }
                Ok(Event::Resize) => dirty = true,
                Ok(Event::Signal(2))
                    if ignore_interrupts_until.is_some_and(|t| Instant::now() < t) => {}
                Ok(Event::Signal(n)) => return Ok(Exit::Signal(n)),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    if !worker_gone {
                        worker_gone = true;
                        app.status =
                            Some("the TUI's IPC worker stopped; quit and start again".to_owned());
                        dirty = true;
                    }
                    break;
                }
            }
        }
        if let Some(exit) = perform(terminal, app, worker, effects, &mut ignore_interrupts_until)? {
            return Ok(exit);
        }
        if last_poll.elapsed() >= POLL_INTERVAL {
            last_poll = Instant::now();
            for c in app.poll_commands() {
                worker.send(c);
            }
            app.now = Timestamp::now();
            dirty = true;
        }
        if dirty {
            app.now = Timestamp::now();
            let frame = terminal.draw(|f| view::render(f, app))?;
            if let Some(path) = &test.screen {
                dump_screen(frame.buffer, path);
            }
            dirty = false;
            if first_frame {
                first_frame = false;
                if test.panic_after_first_frame {
                    panic!(
                        "{PANIC_ENV}: the test configuration asked for a panic after the first frame"
                    );
                }
            }
        }
        match reader.next(INPUT_WAIT)? {
            term::Input::Idle => {}
            term::Input::Resize => dirty = true,
            term::Input::Hangup => return Ok(Exit::Hangup),
            term::Input::Keys(keys) => {
                for key in keys {
                    let effects = app.key(key);
                    dirty = true;
                    if let Some(exit) =
                        perform(terminal, app, worker, effects, &mut ignore_interrupts_until)?
                    {
                        return Ok(exit);
                    }
                }
            }
        }
    }
}

/// Carry out effects; `Some` ends the loop.
fn perform(
    terminal: &mut Term,
    app: &mut App,
    worker: &Worker,
    effects: Vec<Effect>,
    ignore_interrupts_until: &mut Option<Instant>,
) -> std::io::Result<Option<Exit>> {
    let mut queue: std::collections::VecDeque<Effect> = effects.into();
    while let Some(effect) = queue.pop_front() {
        match effect {
            Effect::Quit => return Ok(Some(Exit::Quit)),
            Effect::Worker(c) => {
                if !worker.send(c) {
                    app.status = Some("busy: the request queue is full; try again".to_owned());
                }
            }
            Effect::Connect(alias) => {
                let text = connect(terminal, &alias)?;
                *ignore_interrupts_until = Some(Instant::now() + INTERRUPT_GRACE);
                queue.extend(app.handoff_ended(text));
            }
        }
    }
    Ok(None)
}

/// Whether `alias` is a word `ssh` reads as a destination (as `heimdall connect`).
fn valid_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= MAX_ALIAS_BYTES
        && !alias.starts_with('-')
        && !alias.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// The connect action (module docs). Returns the status line describing the result.
fn connect(terminal: &mut Term, alias: &str) -> std::io::Result<String> {
    if !valid_alias(alias) {
        return Ok(
            "refused: the destination must be an alias (no leading '-', no spaces)".to_owned(),
        );
    }
    let env = Env::capture();
    let platform = Platform::current();
    let Some(client) = selected_path(&env, &ClientsConfig::default(), ClientKind::Ssh) else {
        return Ok(format!(
            "{alias}: no verified ssh client was found; nothing ran"
        ));
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"));
    let program = match resolve_program(client.as_os_str(), &env, &cwd, platform) {
        Ok(p) => p,
        Err(r) => {
            return Ok(format!(
                "{alias}: the verified client was refused ({}); nothing ran",
                r.reason()
            ));
        }
    };
    let digest = sha256_file(&program.path).unwrap_or_else(|| "unknown".to_owned());
    term::leave();
    output::diagnostic(&format!(
        "heimdall: ssh {alias} through the verified client {} (sha256 {digest}); the TUI resumes when it exits",
        program.path.display()
    ));
    let outcome = run_foreground(&program, &[OsString::from(alias)], &EnvDelta::default());
    term::enter()?;
    // A full repaint without any terminal query (Terminal::clear would ask for the
    // cursor position).
    let area = term::size()?;
    terminal.resize(ratatui::layout::Rect::new(0, 0, area.width, area.height))?;
    Ok(match outcome {
        Ok(ChildOutcome::Exited(code)) => format!("ssh {alias} exited with status {code}"),
        Ok(ChildOutcome::Signaled(signal)) => {
            format!("ssh {alias} was ended by signal {signal}")
        }
        Err(e) => format!("ssh {alias} could not be launched: {e}"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn connect_takes_only_an_alias() {
        for ok in ["alpha", "h1.example", "a_b-c"] {
            assert!(valid_alias(ok), "{ok}");
        }
        let long = "a".repeat(256);
        for bad in [
            "",
            "-oProxyCommand=x",
            "a b",
            "a\tb",
            "a\u{1b}b",
            long.as_str(),
        ] {
            assert!(!valid_alias(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_test_hooks_are_parsed_in_debug_and_refused_in_release() {
        let none = |_: &str| None;
        assert_eq!(test_hooks(&none), Ok(TestHooks::default()));
        let set =
            |k: &'static str, v: &'static str| move |n: &str| (n == k).then(|| OsString::from(v));
        // An absolute path on the host (a Unix path has no drive on Windows).
        let scratch_screen = if cfg!(windows) {
            "C:\\scratch\\screen"
        } else {
            "/scratch/screen"
        };
        let panic = test_hooks(&set(PANIC_ENV, "after_first_frame"));
        let screen = test_hooks(&set(SCREEN_ENV, scratch_screen));
        if testcfg::AVAILABLE {
            assert!(panic.unwrap().panic_after_first_frame);
            assert_eq!(
                screen.unwrap().screen.as_deref(),
                Some(std::path::Path::new(scratch_screen))
            );
            assert!(test_hooks(&set(PANIC_ENV, "now")).is_err());
            assert!(test_hooks(&set(SCREEN_ENV, "relative")).is_err());
        } else {
            assert!(panic.is_err(), "a release build refuses the test hooks");
            assert!(screen.is_err(), "a release build refuses the test hooks");
        }
    }

    #[test]
    fn probe_isolation_names_only_scratch_files() {
        let p = SshPaths::with_test_override(
            std::path::PathBuf::from("/scratch/home"),
            std::path::PathBuf::from("/scratch/home/etc-ssh"),
        );
        let args = isolation_args(&p);
        assert_eq!(args[0], "-F");
        // Joined with the host's separator (`\` on Windows).
        let config = std::path::Path::new("/scratch/home")
            .join(".ssh")
            .join("config");
        assert_eq!(args[1], config.as_os_str());
        for a in &args {
            let a = a.to_string_lossy();
            for forbidden in [
                "IdentityAgent",
                "IdentityFile",
                "IdentitiesOnly",
                "HostName",
                "User=",
                "Port",
            ] {
                assert!(!a.contains(forbidden), "{a}");
            }
        }
    }
}
