//! The CLI-side runner of client-executed remote steps (ADR-0008 D5 §6.3; m03-plan U5
//! `enroll::remote::SshStepRunner`).
//!
//! [`SshStepRunner::run`] runs **one** `ssh` process for a [`RemoteStep`]:
//!
//! ```text
//! <step.client> -o <pin> … (target, host trust, existing access, narrowing, in order)
//!               -T <step.alias> <step.remote_command>
//! ```
//!
//! * **Exactly the step.** Every pin is passed as `-o Key=Value`, in the step's order;
//!   nothing is added and nothing is dropped. The remote command must be the fixed
//!   [`STEP_REMOTE_COMMAND`]; the client path must be absolute; a pin key must be an
//!   option name and a value must hold no control character. A step that fails a check
//!   is refused before anything is spawned ([`StepRunError::InvalidStep`]).
//! * **`BatchMode`.** A [`TtyMode::Batch`] step must carry the pin `BatchMode=yes`
//!   (refused otherwise, so a step that could prompt never runs unattended). An
//!   interactive step runs with whatever `BatchMode` its pins say.
//! * **The ready handshake** (§17.4 item 2; B R2-04). The script is written to ssh's
//!   stdin **only after** the first stdout line is exactly [`READY_LINE`]. If the first
//!   line is anything else (a noisy login rc), or the run ends or times out first, the
//!   script is never written: stdin is closed and [`StepReport::script_sent`] is
//!   `false`.
//! * **Lifetime** (§17.4 item 2). On Unix ssh runs in its own process group
//!   (`process_group(0)`, safe std); the runner kills the whole group with `SIGKILL` on
//!   every way out of `run` (normal end, timeout, output bound, abort, unwinding), while
//!   the group leader is still unreaped (`waitid(WNOWAIT)` through rustix), so the ID
//!   cannot have been reused. [`StepAbort::abort`] is the hook the CLI's signal handlers
//!   call. **On Linux the child also gets `PR_SET_PDEATHSIG(SIGKILL)`**
//!   ([`PARENT_DEATH_SIGNAL_APPLIED`]; ADR-0008 §17.17 item 5), set in the crate's one
//!   `unsafe` module, `sys`, so a CLI killed by `SIGKILL` takes the step's `ssh` with it.
//!   On macOS a CLI killed by `SIGKILL` is covered by the handshake: a dead CLI never
//!   writes the script, and its closed pipes end ssh's input and output. **Windows** needs the kill-on-close
//!   job, which is `heimdall_localenv::sys::JobObject`; this crate has no `localenv`
//!   edge (m03-plan §0.6), so the CLI supplies it through [`StepContainment`], and a
//!   runner without one **refuses** on Windows ([`StepRunError::ContainmentUnavailable`];
//!   U5IO-Q2).
//! * **Bounds** (ADR-0008 D5 §6.3; `app::operations::Limits`): stdout at most 512 KiB
//!   (more kills the step, [`KillCause::StdoutBound`]); stderr read concurrently, at most
//!   64 KiB kept, of which a 4 KiB redacted excerpt is reported; `HM1 ready` within the
//!   30 s connect bound for a batch step (the interactive bound is the total, since a
//!   provider approval comes before the ready line); total `min(step.timeout_ms, 120 s)`
//!   or `min(step.timeout_ms, 300 s)` for an interactive step.
//! * **The owner's terminal** stays the controlling terminal for an interactive step: a
//!   provider dialog, an agent confirmation or a hardware touch work as in ordinary use.
//!   The runner never reads, parses or alters the terminal. Because ssh is in its own
//!   (background) process group, a passphrase prompt that ssh reads from `/dev/tty`
//!   stops it (`SIGTTIN`) until the total bound kills it, so such a step ends without
//!   the ready line and without a script (fail closed; U5IO-Q3,
//!   [`INTERACTIVE_FOREGROUND_HANDOFF`]).
//!
//! A run that the runner ended (or that ended on a signal) reports
//! [`KILLED_EXIT_STATUS`] (`-1`), which no process exit can produce, so the runtime's
//! classification never mistakes it for a documented exit code.
//!
//! [`SshStepRunner::effective_config`] runs `<client> -G` with exactly the step's pins,
//! alias and remote command (the `ssh -G` check of D5 §6.3, which the pure
//! `heimdall_registry::step::check_effective` compares); it does not connect.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use heimdall_contract::enrollment::{RemoteStep, SshOption};

/// The first stdout line of every step (the fixed remote command prints it).
pub const READY_LINE: &str = "HM1 ready";

/// The fixed remote command of every remote step (ADR-0008 D5 §6.3).
pub const STEP_REMOTE_COMMAND: &str = "printf 'HM1 ready\\n'; exec /bin/sh -s";

/// The exit status reported for a client the runner killed, or that ended on a
/// signal: no process exit status is negative.
pub const KILLED_EXIT_STATUS: i32 = -1;

/// The connect bound: `HM1 ready` must arrive within it for a batch step.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// `ssh -G`'s bound ([`SshStepRunner::effective_config`]).
pub const EFFECTIVE_CONFIG_TIMEOUT: Duration = Duration::from_secs(10);

/// `ssh -G`'s output bound.
pub const EFFECTIVE_CONFIG_MAX: usize = 256 * 1024;

/// Whether the step's child gets `PR_SET_PDEATHSIG(SIGKILL)`: `true` on Linux
/// (ADR-0008 §17.17 item 5; the `pre_exec` closure in `sys`), `false` elsewhere (the
/// signal is Linux-only).
pub const PARENT_DEATH_SIGNAL_APPLIED: bool = cfg!(target_os = "linux");

/// **Switch (U5IO-Q3).** Whether an interactive step's process group is given the
/// terminal's foreground: `false` (ssh stays in its own background group; a
/// `/dev/tty` prompt stops it until the bound).
pub const INTERACTIVE_FOREGROUND_HANDOFF: bool = false;

/// How often the run loop wakes to check the deadlines, the child and the abort flag.
const TICK: Duration = Duration::from_millis(10);

/// How long the readers may take to drain after the child ended.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// The longest first line read while waiting for the ready line.
const READY_LINE_MAX: usize = 4096;

/// Whether the owner's terminal is attached to the step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TtyMode {
    /// The owner's terminal is attached (a passphrase, a touch, a provider dialog).
    Interactive,
    /// No terminal; the step must carry `BatchMode=yes`.
    Batch,
}

/// Why the runner ended a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KillCause {
    /// `HM1 ready` did not arrive within the connect bound (batch steps).
    ConnectTimeout,
    /// The total bound passed.
    Timeout,
    /// stdout exceeded its bound.
    StdoutBound,
    /// [`StepAbort::abort`] was called (the CLI handled a signal).
    Aborted,
}

/// How the client's run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StepEnd {
    /// It exited with [`StepReport::exit_status`].
    Exited,
    /// It ended on a signal it was not sent by the runner.
    Signalled,
    /// The runner ended it.
    Killed(KillCause),
}

/// What tied ssh's lifetime to the CLI's in this run (evidence, ADR-0008 D5 §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LifetimeTie {
    /// ssh ran in its own process group, killed as a group (Unix).
    pub process_group: bool,
    /// The child had a parent-death signal (Linux; [`PARENT_DEATH_SIGNAL_APPLIED`]).
    pub parent_death_signal: bool,
    /// A [`StepContainment`] that ends the child with this process contained it
    /// (Windows: the kill-on-close job).
    pub contained: bool,
    /// The ready handshake was used (always).
    pub ready_handshake: bool,
}

/// What the CLI sends back as `Enrollment::StepResult` (ADR-0008 D5 §6.3 item 2), with
/// the runner's own evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    /// The client's exit status, or [`KILLED_EXIT_STATUS`].
    pub exit_status: i32,
    /// The client's stdout, at most 512 KiB (lossy UTF-8; HM1 output is ASCII).
    pub stdout: String,
    /// At most 4 KiB of stderr, redacted ([`redact_excerpt`]).
    pub stderr_excerpt: String,
    /// The first stdout line was exactly [`READY_LINE`].
    pub ready_seen: bool,
    /// The script was written (only after the ready line).
    pub script_sent: bool,
    /// How the run ended.
    pub ended: StepEnd,
    /// What tied ssh's lifetime to this process.
    pub lifetime: LifetimeTie,
}

/// Why a step was not run. Nothing was spawned and no script was sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StepRunError {
    /// The step runner is not in this build. Nothing ran.
    #[error("the remote step runner is not available in this build")]
    Unavailable,
    /// The step is not one this runner will run (a stable reason).
    #[error("the remote step is refused: {0}")]
    InvalidStep(&'static str),
    /// This platform needs a [`StepContainment`] (Windows: the kill-on-close job) and
    /// the runner has none.
    #[error("the remote step needs a containment this runner does not have")]
    ContainmentUnavailable,
    /// The runner was aborted before the step started.
    #[error("the remote step runner was aborted")]
    Aborted,
    /// The client could not be started (the I/O error kind only).
    #[error("the client could not be started: {0}")]
    Spawn(String),
    /// `ssh -G` failed (its exit status, or [`KILLED_EXIT_STATUS`]).
    #[error("ssh -G failed with status {0}")]
    EffectiveConfig(i32),
}

/// A spawned, contained child ([`StepContainment::spawn_contained`]).
pub struct Contained {
    /// The child.
    pub child: Child,
    /// Dropping it ends the child and every process it started (Windows: closes the
    /// kill-on-close job).
    pub guard: Box<dyn Send>,
}

impl std::fmt::Debug for Contained {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contained")
            .field("pid", &self.child.id())
            .finish_non_exhaustive()
    }
}

/// The platform containment the CLI supplies (U5IO-Q2): on Windows a kill-on-close job
/// object without breakaway (`heimdall_localenv::sys::JobObject`, M02's primitive;
/// ⟨M02?⟩ M14), into which the child is put before it can start another process.
pub trait StepContainment: Send + Sync {
    /// Spawn `command` contained. When the returned guard drops, or this process dies,
    /// the child and every process it started end.
    ///
    /// # Errors
    /// The child cannot be started or contained (an uncontained child must not be
    /// left running).
    fn spawn_contained(&self, command: &mut Command) -> std::io::Result<Contained>;

    /// Whether the containment ends the child when this process dies (a job object,
    /// a parent-death signal).
    fn ends_with_parent(&self) -> bool;
}

/// The CLI's signal hook: [`abort`](Self::abort) ends every run of the runner it came
/// from (its process group is killed) and refuses later runs.
#[derive(Debug, Clone)]
pub struct StepAbort {
    flag: Arc<AtomicBool>,
}

impl StepAbort {
    /// Abort (sticky).
    pub fn abort(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
}

/// The client-executed step runner (module documentation).
pub struct SshStepRunner {
    containment: Option<Box<dyn StepContainment>>,
    aborted: Arc<AtomicBool>,
    stdout_max: usize,
    stderr_max: usize,
    excerpt_max: usize,
    batch_total: Duration,
    interactive_total: Duration,
}

impl std::fmt::Debug for SshStepRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshStepRunner")
            .field("contained", &self.containment.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for SshStepRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl SshStepRunner {
    /// A runner with the ADR-0008 bounds (`app::operations::Limits`) and no
    /// containment (refused on Windows).
    #[must_use]
    pub fn new() -> Self {
        let limits = heimdall_app::operations::Limits::default();
        Self {
            containment: None,
            aborted: Arc::new(AtomicBool::new(false)),
            stdout_max: limits.remote_stdout_max,
            stderr_max: limits.remote_stderr_max,
            excerpt_max: limits.remote_stderr_excerpt,
            batch_total: limits.enrollment_step_timeout,
            interactive_total: limits.enrollment_step_timeout_interactive,
        }
    }

    /// This runner with `containment` (required on Windows).
    #[must_use]
    pub fn with_containment(mut self, containment: Box<dyn StepContainment>) -> Self {
        self.containment = Some(containment);
        self
    }

    /// The abort hook for the CLI's signal handlers.
    #[must_use]
    pub fn abort_handle(&self) -> StepAbort {
        StepAbort {
            flag: Arc::clone(&self.aborted),
        }
    }

    /// Run `step` once (module documentation).
    ///
    /// # Errors
    /// [`StepRunError`]: nothing was spawned and no script was sent.
    pub fn run(&self, step: &RemoteStep, tty: TtyMode) -> Result<StepReport, StepRunError> {
        let argv = step_argv(step, tty)?;
        if self.aborted.load(Ordering::SeqCst) {
            return Err(StepRunError::Aborted);
        }
        let cap = match tty {
            TtyMode::Batch => self.batch_total,
            TtyMode::Interactive => self.interactive_total,
        };
        let total = Duration::from_millis(step.timeout_ms).min(cap);
        let ready_bound = match tty {
            TtyMode::Batch => CONNECT_TIMEOUT.min(total),
            TtyMode::Interactive => total,
        };
        let mut cmd = Command::new(&step.client);
        cmd.args(&argv)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut running = self.spawn(&mut cmd)?;
        let lifetime = running.lifetime;
        let (Some(stdin), Some(stdout), Some(stderr)) = (
            running.child_mut().stdin.take(),
            running.child_mut().stdout.take(),
            running.child_mut().stderr.take(),
        ) else {
            running.kill();
            return Err(StepRunError::Spawn("pipes".into()));
        };
        let (tx, rx) = mpsc::channel::<Chunk>();
        let out_tx = tx.clone();
        let out_thread = std::thread::spawn(move || pump(stdout, &out_tx, Stream::Stdout));
        let err_thread = std::thread::spawn(move || pump(stderr, &tx, Stream::Stderr));

        let start = Instant::now();
        let mut stdin = Some(stdin);
        let mut writer: Option<std::thread::JoinHandle<()>> = None;
        let mut io = Collected::new(self.stdout_max, self.stderr_max);
        let mut ready_seen = false;
        let mut first_line_done = false;
        let mut script_sent = false;
        let mut killed: Option<KillCause> = None;
        let mut exited_at: Option<Instant> = None;
        loop {
            match rx.recv_timeout(TICK) {
                Ok(chunk) => {
                    if io.absorb(chunk) && killed.is_none() {
                        killed = Some(KillCause::StdoutBound);
                        running.kill_group();
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => std::thread::sleep(TICK),
            }
            if !first_line_done {
                if let Some(nl) = io.out.iter().position(|&b| b == b'\n') {
                    first_line_done = true;
                    // ⟨integrator, wave-1 review finding 4⟩ Exactly `HM1 ready\n`, as
                    // `heimdall_registry::hm1::handshake` requires: a `\r` before the
                    // newline is noise, so no script is sent (the classifier would read
                    // such a run as one that never printed the ready line).
                    let line = &io.out[..nl];
                    if line == READY_LINE.as_bytes() && killed.is_none() {
                        ready_seen = true;
                        if let Some(mut pipe) = stdin.take() {
                            let script = step.script.clone().into_bytes();
                            script_sent = true;
                            writer = Some(std::thread::spawn(move || {
                                let _ = pipe.write_all(&script);
                                let _ = pipe.flush();
                                drop(pipe);
                            }));
                        }
                    } else {
                        // Noise before the ready line: the script is never sent.
                        stdin = None;
                    }
                } else if io.out.len() > READY_LINE_MAX || io.out_eof {
                    first_line_done = true;
                    stdin = None;
                }
            }
            if killed.is_none() {
                let elapsed = start.elapsed();
                let cause = if self.aborted.load(Ordering::SeqCst) {
                    Some(KillCause::Aborted)
                } else if elapsed >= total {
                    Some(KillCause::Timeout)
                } else if !ready_seen && elapsed >= ready_bound {
                    Some(KillCause::ConnectTimeout)
                } else {
                    None
                };
                if let Some(cause) = cause {
                    killed = Some(cause);
                    if !script_sent {
                        stdin = None;
                    }
                    running.kill_group();
                }
            }
            if exited_at.is_none() && running.exited() {
                exited_at = Some(Instant::now());
                // Leftover members of the group (a configuration command ssh started)
                // end with it; the leader is still unreaped, so the ID is ours.
                running.kill_group();
            }
            if let Some(at) = exited_at
                && ((io.out_eof && io.err_eof) || at.elapsed() >= DRAIN_GRACE)
            {
                break;
            }
        }
        drop(stdin);
        let status = running.wait();
        // Whatever is still queued, then the readers: a reader whose pipe some process
        // outside the group still holds is left to end on its own (bounded wait).
        let tail = Instant::now() + DRAIN_GRACE;
        while !(io.out_eof && io.err_eof) && Instant::now() < tail {
            match rx.recv_timeout(TICK) {
                Ok(chunk) => {
                    let _ = io.absorb(chunk);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        while let Ok(chunk) = rx.try_recv() {
            let _ = io.absorb(chunk);
        }
        for handle in [Some(out_thread), Some(err_thread), writer]
            .into_iter()
            .flatten()
        {
            if handle.is_finished() {
                let _ = handle.join();
            }
        }
        let Collected { out, err, .. } = io;
        let (exit_status, ended) = match (killed, status) {
            (Some(cause), _) => (KILLED_EXIT_STATUS, StepEnd::Killed(cause)),
            (None, Some(code)) => (code, StepEnd::Exited),
            (None, None) => (KILLED_EXIT_STATUS, StepEnd::Signalled),
        };
        Ok(StepReport {
            exit_status,
            stdout: String::from_utf8_lossy(&out).into_owned(),
            stderr_excerpt: redact_excerpt(&err, self.excerpt_max),
            ready_seen,
            script_sent,
            ended,
            lifetime,
        })
    }

    /// `<client> -G` with exactly the step's pins, alias and remote command: the
    /// effective configuration the step would use (ADR-0008 D5 §6.3). It evaluates the
    /// configuration (its `Match exec` entries run, as in ordinary use) and does not
    /// connect. Bounded ([`EFFECTIVE_CONFIG_TIMEOUT`], [`EFFECTIVE_CONFIG_MAX`]).
    ///
    /// # Errors
    /// [`StepRunError`]: the step is invalid, the client cannot start, or `ssh -G`
    /// does not exit 0 within the bound.
    pub fn effective_config(&self, step: &RemoteStep) -> Result<String, StepRunError> {
        // `ssh -G` never prompts, so the batch rule is not applied to it.
        let argv = step_argv(step, TtyMode::Interactive)?;
        if self.aborted.load(Ordering::SeqCst) {
            return Err(StepRunError::Aborted);
        }
        let mut cmd = Command::new(&step.client);
        cmd.arg("-G")
            .args(&argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut running = self.spawn(&mut cmd)?;
        let Some(stdout) = running.child_mut().stdout.take() else {
            running.kill();
            return Err(StepRunError::Spawn("pipes".into()));
        };
        let (tx, rx) = mpsc::channel::<Chunk>();
        let reader = std::thread::spawn(move || pump(stdout, &tx, Stream::Stdout));
        let start = Instant::now();
        let mut out = Vec::new();
        let mut eof = false;
        let mut killed = false;
        loop {
            match rx.recv_timeout(TICK) {
                Ok(Chunk::Data(_, bytes)) => {
                    out.extend_from_slice(&bytes);
                    if out.len() > EFFECTIVE_CONFIG_MAX {
                        killed = true;
                    }
                }
                Ok(Chunk::Eof(_)) => eof = true,
                Err(_) => {}
            }
            if !killed
                && (start.elapsed() >= EFFECTIVE_CONFIG_TIMEOUT
                    || self.aborted.load(Ordering::SeqCst))
            {
                killed = true;
            }
            if killed {
                running.kill_group();
                break;
            }
            if eof && running.exited() {
                break;
            }
        }
        running.kill_group();
        let status = running.wait();
        let _ = reader.join();
        match (killed, status) {
            (false, Some(0)) => Ok(String::from_utf8_lossy(&out).into_owned()),
            (false, Some(code)) => Err(StepRunError::EffectiveConfig(code)),
            _ => Err(StepRunError::EffectiveConfig(KILLED_EXIT_STATUS)),
        }
    }

    fn spawn(&self, cmd: &mut Command) -> Result<Running, StepRunError> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        // ADR-0008 §17.17 item 5: the child dies with this thread, which spawns it and
        // then waits in `run` until the step has ended.
        #[cfg(target_os = "linux")]
        crate::sys::kill_with_parent(cmd);
        let spawn_err = |e: &std::io::Error| StepRunError::Spawn(format!("{:?}", e.kind()));
        match &self.containment {
            Some(c) => {
                let contained = c.spawn_contained(cmd).map_err(|e| spawn_err(&e))?;
                Ok(Running::new(
                    contained.child,
                    Some(contained.guard),
                    LifetimeTie {
                        process_group: cfg!(unix),
                        parent_death_signal: PARENT_DEATH_SIGNAL_APPLIED
                            || (cfg!(target_os = "linux") && c.ends_with_parent()),
                        contained: c.ends_with_parent(),
                        ready_handshake: true,
                    },
                ))
            }
            None if cfg!(windows) => Err(StepRunError::ContainmentUnavailable),
            None => {
                let child = cmd.spawn().map_err(|e| spawn_err(&e))?;
                Ok(Running::new(
                    child,
                    None,
                    LifetimeTie {
                        process_group: cfg!(unix),
                        parent_death_signal: PARENT_DEATH_SIGNAL_APPLIED,
                        contained: false,
                        ready_handshake: true,
                    },
                ))
            }
        }
    }
}

/// The argv after the client: every pin as `-o Key=Value` in order, `-T`, the alias,
/// the remote command (module documentation).
///
/// # Errors
/// [`StepRunError::InvalidStep`] with a stable reason.
pub fn step_argv(step: &RemoteStep, tty: TtyMode) -> Result<Vec<String>, StepRunError> {
    use StepRunError::InvalidStep as bad;
    if !std::path::Path::new(&step.client).is_absolute() {
        return Err(bad("client_not_absolute"));
    }
    if step.remote_command != STEP_REMOTE_COMMAND {
        return Err(bad("remote_command_not_fixed"));
    }
    if step.alias.is_empty()
        || step.alias.starts_with('-')
        || step
            .alias
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(bad("alias_invalid"));
    }
    if step.script.is_empty() {
        return Err(bad("script_empty"));
    }
    if step.timeout_ms == 0 {
        return Err(bad("timeout_zero"));
    }
    let pins: Vec<&SshOption> = step
        .pins
        .target
        .0
        .iter()
        .chain(&step.pins.host_trust.0)
        .chain(&step.pins.existing_access.0)
        .chain(&step.pins.narrowing.0)
        .collect();
    if pins.is_empty() {
        return Err(bad("no_pins"));
    }
    let mut batch_yes = false;
    let mut argv = Vec::with_capacity(pins.len() * 2 + 3);
    for pin in pins {
        if pin.key.is_empty() || !pin.key.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(bad("pin_key_invalid"));
        }
        if pin.value.is_empty() || pin.value.chars().any(char::is_control) {
            return Err(bad("pin_value_invalid"));
        }
        if pin.key.eq_ignore_ascii_case("BatchMode") {
            batch_yes = pin.value.eq_ignore_ascii_case("yes");
        }
        argv.push("-o".to_owned());
        argv.push(format!("{}={}", pin.key, pin.value));
    }
    if tty == TtyMode::Batch && !batch_yes {
        return Err(bad("batch_mode_pin"));
    }
    argv.push("-T".to_owned());
    argv.push(step.alias.clone());
    argv.push(step.remote_command.clone());
    Ok(argv)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    Stdout,
    Stderr,
}

enum Chunk {
    Data(Stream, Vec<u8>),
    Eof(Stream),
}

/// The bounded output of one run.
struct Collected {
    out: Vec<u8>,
    err: Vec<u8>,
    out_eof: bool,
    err_eof: bool,
    out_max: usize,
    err_max: usize,
    overflowed: bool,
}

impl Collected {
    fn new(out_max: usize, err_max: usize) -> Self {
        Self {
            out: Vec::new(),
            err: Vec::new(),
            out_eof: false,
            err_eof: false,
            out_max,
            err_max,
            overflowed: false,
        }
    }

    /// Take one chunk within the bounds; `true` the first time stdout overflows.
    fn absorb(&mut self, chunk: Chunk) -> bool {
        match chunk {
            Chunk::Data(Stream::Stdout, bytes) => {
                let room = self.out_max.saturating_sub(self.out.len());
                self.out.extend_from_slice(&bytes[..bytes.len().min(room)]);
                if bytes.len() > room && !self.overflowed {
                    self.overflowed = true;
                    return true;
                }
            }
            Chunk::Data(Stream::Stderr, bytes) => {
                // Read on and drop past the bound, so ssh never blocks on stderr.
                let room = self.err_max.saturating_sub(self.err.len());
                self.err.extend_from_slice(&bytes[..bytes.len().min(room)]);
            }
            Chunk::Eof(Stream::Stdout) => self.out_eof = true,
            Chunk::Eof(Stream::Stderr) => self.err_eof = true,
        }
        false
    }
}

fn pump(mut r: impl Read, tx: &mpsc::Sender<Chunk>, stream: Stream) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if tx.send(Chunk::Data(stream, buf[..n].to_vec())).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let _ = tx.send(Chunk::Eof(stream));
}

/// A running client whose lifetime ends with this value (its group is killed on
/// drop, before the leader is reaped).
struct Running {
    child: Child,
    guard: Option<Box<dyn Send>>,
    reaped: bool,
    lifetime: LifetimeTie,
}

impl Running {
    fn new(child: Child, guard: Option<Box<dyn Send>>, lifetime: LifetimeTie) -> Self {
        Self {
            child,
            guard,
            reaped: false,
            lifetime,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    /// Whether the leader has exited, without reaping it (Unix `waitid(WNOWAIT)`), so
    /// its group ID stays ours for [`kill_group`](Self::kill_group).
    fn exited(&mut self) -> bool {
        if self.reaped {
            return true;
        }
        #[cfg(unix)]
        {
            use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};
            let pid = Pid::from_child(&self.child);
            loop {
                match waitid(
                    WaitId::Pid(pid),
                    WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
                ) {
                    Ok(status) => return status.is_some(),
                    Err(rustix::io::Errno::INTR) => {}
                    // Not our unreaped child any more: treat as ended.
                    Err(_) => return true,
                }
            }
        }
        #[cfg(not(unix))]
        {
            matches!(self.child.try_wait(), Ok(Some(_)) | Err(_))
        }
    }

    /// Kill the whole group (Unix) while the leader is unreaped; elsewhere end the
    /// child (and the containment's processes) through the guard.
    fn kill_group(&mut self) {
        if self.reaped {
            return;
        }
        #[cfg(unix)]
        {
            use rustix::process::{Pid, Signal, kill_process_group};
            let pid = Pid::from_child(&self.child);
            // The group ID is the leader's PID (`process_group(0)`); never this
            // process's own group, since the child left it at spawn.
            let _ = kill_process_group(pid, Signal::KILL);
        }
        #[cfg(not(unix))]
        {
            let _ = self.child.kill();
        }
    }

    fn kill(&mut self) {
        self.kill_group();
        let _ = self.wait();
    }

    /// Reap the leader; its exit code, `None` when it ended on a signal.
    fn wait(&mut self) -> Option<i32> {
        if self.reaped {
            return None;
        }
        let status = self.child.wait().ok();
        self.reaped = true;
        // The containment's processes end with the guard.
        self.guard = None;
        status.and_then(|s| s.code())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.reaped {
            self.kill_group();
            let _ = self.child.wait();
            self.reaped = true;
        }
        self.guard = None;
    }
}

/// The redacted stderr excerpt: the **last** `max` bytes of `stderr` (where ssh's
/// error is), on a character boundary, with control characters other than newline and
/// tab replaced by `?`, home directories shown as `~`, and every token that looks
/// like a canary (`HEIMDALL_CANARY`) or key material (a run of at least 24 base64
/// characters mixing letter cases and digits, or 32 hex digits) replaced by
/// `[redacted]`.
#[must_use]
pub fn redact_excerpt(stderr: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(stderr);
    let mut cleaned = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() && c != '\n' && c != '\t' {
            cleaned.push('?');
        } else {
            cleaned.push(c);
        }
    }
    let homed = redact_homes(&cleaned);
    let mut out = String::with_capacity(homed.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if !run.is_empty() {
            if run.contains("HEIMDALL_CANARY") || key_like(run) {
                out.push_str("[redacted]");
            } else {
                out.push_str(run);
            }
            run.clear();
        }
    };
    for c in homed.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-') {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    if out.len() <= max {
        return out;
    }
    let mut start = out.len() - max;
    while !out.is_char_boundary(start) {
        start += 1;
    }
    out[start..].to_owned()
}

fn redact_homes(text: &str) -> String {
    let mut s = text.to_owned();
    for marker in ["/Users/", "/home/", "\\Users\\"] {
        let mut out = String::with_capacity(s.len());
        let mut rest = s.as_str();
        while let Some(at) = rest.find(marker) {
            out.push_str(&rest[..at]);
            let after = &rest[at + marker.len()..];
            let end = after
                .find(|c: char| c == '/' || c == '\\' || c.is_whitespace() || c == '\'' || c == '"')
                .unwrap_or(after.len());
            out.push('~');
            rest = &after[end..];
        }
        out.push_str(rest);
        s = out;
    }
    s
}

fn key_like(run: &str) -> bool {
    let core = run.trim_end_matches('=');
    if core.len() >= 32 && core.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }
    if core.len() < 24 {
        return false;
    }
    let upper = core.bytes().any(|b| b.is_ascii_uppercase());
    let lower = core.bytes().any(|b| b.is_ascii_lowercase());
    let digit = core.bytes().any(|b| b.is_ascii_digit());
    upper && lower && digit
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::enrollment::{NarrowingPins, RemoteStage, StepPins, TargetPins};

    fn opt(k: &str, v: &str) -> SshOption {
        SshOption {
            key: k.into(),
            value: v.into(),
        }
    }

    /// An absolute client path that does not exist, in this platform's form (a Unix
    /// path is not absolute on Windows; native Windows run, wave-1 item B6).
    const MISSING_CLIENT: &str = if cfg!(windows) {
        r"C:\nonexistent\heimdall-test-ssh.exe"
    } else {
        "/nonexistent/heimdall-test-ssh"
    };

    fn step() -> RemoteStep {
        RemoteStep {
            stage: RemoteStage::Inspect,
            step_token: "0".repeat(32),
            client: MISSING_CLIENT.into(),
            pins: StepPins {
                target: TargetPins(vec![opt("HostName", "127.0.0.1"), opt("Port", "22")]),
                narrowing: NarrowingPins(vec![opt("BatchMode", "yes")]),
                ..StepPins::default()
            },
            alias: "hm-test".into(),
            remote_command: STEP_REMOTE_COMMAND.into(),
            script: "hm_main\n".into(),
            timeout_ms: 1000,
            hard_deadline_ms: 1000,
            not_after_remote: None,
        }
    }

    #[test]
    fn argv_is_exactly_the_step_in_order() {
        let argv = step_argv(&step(), TtyMode::Batch).unwrap();
        assert_eq!(
            argv,
            [
                "-o",
                "HostName=127.0.0.1",
                "-o",
                "Port=22",
                "-o",
                "BatchMode=yes",
                "-T",
                "hm-test",
                STEP_REMOTE_COMMAND
            ]
        );
    }

    #[test]
    fn invalid_steps_are_refused_before_anything_runs() {
        let runner = SshStepRunner::new();
        let cases: Vec<(RemoteStep, TtyMode, &str)> = vec![
            (
                RemoteStep {
                    client: "ssh".into(),
                    ..step()
                },
                TtyMode::Batch,
                "client_not_absolute",
            ),
            (
                RemoteStep {
                    remote_command: "sh".into(),
                    ..step()
                },
                TtyMode::Batch,
                "remote_command_not_fixed",
            ),
            (
                RemoteStep {
                    alias: "-oProxyCommand=x".into(),
                    ..step()
                },
                TtyMode::Batch,
                "alias_invalid",
            ),
            (
                RemoteStep {
                    script: String::new(),
                    ..step()
                },
                TtyMode::Batch,
                "script_empty",
            ),
            (
                RemoteStep {
                    timeout_ms: 0,
                    ..step()
                },
                TtyMode::Batch,
                "timeout_zero",
            ),
            (
                {
                    let mut s = step();
                    s.pins.narrowing = NarrowingPins(vec![opt("BatchMode", "no")]);
                    s
                },
                TtyMode::Batch,
                "batch_mode_pin",
            ),
            (
                {
                    let mut s = step();
                    s.pins.target.0.push(opt("Host Name", "x"));
                    s
                },
                TtyMode::Batch,
                "pin_key_invalid",
            ),
            (
                {
                    let mut s = step();
                    s.pins.target.0.push(opt("HostName", "a\nb"));
                    s
                },
                TtyMode::Batch,
                "pin_value_invalid",
            ),
        ];
        for (s, tty, reason) in cases {
            assert_eq!(runner.run(&s, tty), Err(StepRunError::InvalidStep(reason)));
        }
        // An interactive step may run without BatchMode=yes.
        let mut s = step();
        s.pins.narrowing = NarrowingPins(vec![opt("BatchMode", "no")]);
        assert!(step_argv(&s, TtyMode::Interactive).is_ok());
    }

    #[test]
    fn a_missing_client_is_a_spawn_error_and_abort_is_sticky() {
        let runner = SshStepRunner::new();
        match runner.run(&step(), TtyMode::Batch) {
            Err(StepRunError::Spawn(_)) => {}
            Err(StepRunError::ContainmentUnavailable) if cfg!(windows) => {}
            other => panic!("{other:?}"),
        }
        runner.abort_handle().abort();
        assert_eq!(
            runner.run(&step(), TtyMode::Batch),
            Err(StepRunError::Aborted)
        );
    }

    #[test]
    fn excerpt_is_bounded_and_redacted() {
        let text = b"debug1: x\r\nHEIMDALL_CANARY_abc123 /Users/someone/.ssh/id \
                     AAAAC3NzaC1lZDI1NTE5AAAAIBn0aVeryLongKey12 \x07\nPermission denied (publickey).\n";
        let e = redact_excerpt(text, 4096);
        assert!(!e.contains("HEIMDALL_CANARY"));
        assert!(!e.contains("someone"));
        assert!(!e.contains("AAAAC3NzaC1lZDI1NTE5"));
        assert!(e.contains("~/.ssh/id"));
        assert!(e.ends_with("Permission denied (publickey).\n"));
        assert!(!e.contains('\x07') && !e.contains('\r'));
        let long = "é".repeat(5000);
        let e = redact_excerpt(long.as_bytes(), 4096);
        assert!(e.len() <= 4096);
    }
}
