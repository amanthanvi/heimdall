//! The Windows side of a `heimdall-wsl/1` session, and the projection writer and cleaner of one
//! distribution through it (ADR-0010 §3 items 3–4, §9 items 2 and 8; design U3 §3–§4).
//!
//! * [`HelperSession`] is generic over a [`Transport`] (a reader and writer pair, an optional
//!   diagnostics stream and a child handle), so the tests drive the real helper binary as a
//!   local child on macOS and Linux, while Windows starts it through `wsl.exe`
//!   ([`crate::host::WslExeLauncher`]).
//! * [`DistributionWriter`] implements [`ProjectionWriter`] for one distribution: each call
//!   opens one session and forwards the request. The caller's [`StageSink`] is the **durable
//!   sink**: a sink call from the helper is validated ([`proto::validate_receipt`],
//!   [`proto::validate_commit`]), made durable through the caller's sink, and only then
//!   acknowledged. A call that fails either way is answered `sink_failed` and the session ends,
//!   leaving the operation unresolved for a later `reconcile` (never a second `apply`).
//! * A session is opened only on a distribution the running set lists, unless the caller's
//!   policy is [`DistributionStart::Allowed`] (ADR-0010 §3 item 9, §9 item 2).

use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use heimdall_app::ports::{
    AdapterError, DistributionStart, DistributionTarget, HeldStep, ItemOutcome, PreviewError,
    ProjectionReceipt, ProjectionReconcile, ProjectionWriter, ReconcileError, ResourceCleaner,
    RunningState, SinkError, StageSink,
};
use heimdall_contract::doctor::AliasObservation;
use heimdall_contract::setup::{PreviewIntent, ProjectionItem};
use heimdall_domain::operation::StageReceipt;
use heimdall_domain::projection::{ProjectionPlan, ProjectionRecord, ProjectionSpec, SetupIntent};
use heimdall_domain::resource::ManagedResource;
use heimdall_localenv::sys::spawn::ListedChild;

use crate::proto::{
    self, ByeReason, DistContext, ErrorKind, Hello, HelperFrame, Inbound, SinkCalls, VERSION,
    WindowsFrame, WireItemOutcome,
};

/// Diagnostics kept from the helper's stderr.
pub const STDERR_KEEP: usize = 64 << 10;

/// What a session needs to control its child.
pub trait ChildControl: Send {
    /// The process ID (diagnostics, and tests that kill by exact PID).
    fn id(&self) -> u32;
    /// The exit code if it has exited.
    ///
    /// # Errors
    /// The OS error.
    fn try_wait(&mut self) -> std::io::Result<Option<i32>>;
    /// Kill it.
    ///
    /// # Errors
    /// The OS error.
    fn kill(&mut self) -> std::io::Result<()>;
}

impl ChildControl for ListedChild {
    fn id(&self) -> u32 {
        ListedChild::id(self)
    }
    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        ListedChild::try_wait(self)
    }
    fn kill(&mut self) -> std::io::Result<()> {
        ListedChild::kill(self)
    }
}

/// A started helper: the frames in, the frames out, the diagnostics and the child.
pub struct Transport {
    /// The helper's stdout.
    pub reader: Box<dyn Read + Send>,
    /// The helper's stdin.
    pub writer: Box<dyn Write + Send>,
    /// The helper's stderr.
    pub stderr: Option<Box<dyn Read + Send>>,
    /// The child.
    pub child: Box<dyn ChildControl>,
}

impl Transport {
    /// The transport of a child started through `spawn_listed` with all three streams piped.
    ///
    /// # Errors
    /// [`SessionError::HelperUnavailable`] when a pipe is missing (the child is killed).
    pub fn from_listed(mut child: ListedChild) -> Result<Transport, SessionError> {
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SessionError::HelperUnavailable("no pipes".to_owned()));
        };
        let stderr = child
            .stderr
            .take()
            .map(|f| Box::new(f) as Box<dyn Read + Send>);
        Ok(Transport {
            reader: Box::new(stdout),
            writer: Box::new(stdin),
            stderr,
            child: Box::new(child),
        })
    }
}

/// Starts helpers.
pub trait HelperLauncher: Send + Sync {
    /// Whether the distribution named `name` runs now (starts nothing).
    fn running(&self, name: &str) -> RunningState;

    /// Start a helper for `target`. On Windows this starts the distribution if it is stopped,
    /// which is why [`DistributionWriter`] calls it only under [`DistributionStart::Allowed`]
    /// or after the running set listed the distribution.
    ///
    /// # Errors
    /// [`SessionError::HelperUnavailable`]: no Linux-visible helper path, a missing or
    /// non-executable helper, or a process that cannot be started.
    fn launch(&self, target: &DistributionTarget) -> Result<Transport, SessionError>;

    /// ⟨M04 W2 review, M04-W2-R03⟩ [`Self::launch`] under `start`: with
    /// [`DistributionStart::Forbidden`], a fresh running listing immediately before each
    /// `wsl.exe` call this launch makes (none with `Allowed`), and [`SessionError::NotRunning`]
    /// with nothing started when one says the distribution is not running. The default makes
    /// one listing, then [`Self::launch`]; a launcher that makes several `wsl.exe` calls
    /// checks before each.
    ///
    /// # Errors
    /// [`SessionError`].
    fn launch_under(
        &self,
        target: &DistributionTarget,
        start: DistributionStart,
    ) -> Result<Transport, SessionError> {
        if start == DistributionStart::Forbidden
            && self.running(&target.name) != RunningState::Running
        {
            return Err(SessionError::NotRunning);
        }
        self.launch(target)
    }
}

/// A session or request failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The distribution is stopped and the caller may not start it.
    #[error("wsl_distribution_not_running")]
    NotRunning,
    /// The helper could not be started or never said hello.
    #[error("wsl_helper_unavailable: {0}")]
    HelperUnavailable(String),
    /// The hello does not match the record Windows holds.
    #[error("wsl_helper_unavailable: the hello does not match the record")]
    HelloMismatch,
    /// A framing or protocol violation: the session ended.
    #[error("wsl_helper_unavailable: protocol error")]
    Protocol,
    /// No frame in time: the session ended.
    #[error("wsl_helper_unavailable: timeout")]
    Timeout,
    /// The channel ended.
    #[error("wsl_helper_unavailable: the channel was lost")]
    Gone,
    /// The caller's sink refused a call; the helper was told `sink_failed`.
    #[error("the sink refused a call: {0}")]
    Sink(String),
    /// The helper sent a receipt or commit that fails validation; it was told `sink_failed`.
    #[error("the helper sent an invalid sink call: {0}")]
    Invalid(proto::Invalid),
    /// The helper answered `error`.
    #[error("the helper answered {kind:?}: {message}")]
    Remote {
        /// Which failure.
        kind: ErrorKind,
        /// Its bounded, nonsecret message.
        message: String,
    },
}

impl SessionError {
    /// The stable reason code the failure surfaces as.
    #[must_use]
    pub fn code(&self) -> String {
        match self {
            SessionError::NotRunning => "wsl_distribution_not_running".to_owned(),
            SessionError::Remote { kind, message } => match kind {
                ErrorKind::Busy => "wsl_helper_busy".to_owned(),
                ErrorKind::Unsupported => "wsl_helper_unsupported".to_owned(),
                ErrorKind::Unavailable | ErrorKind::IntentInvalid | ErrorKind::Adapter => {
                    message.clone()
                }
                _ => "wsl_helper_unavailable".to_owned(),
            },
            _ => "wsl_helper_unavailable".to_owned(),
        }
    }

    /// As the error of `apply`, `reconcile` and `observe_held`.
    #[must_use]
    pub fn into_reconcile(self) -> ReconcileError {
        match self {
            SessionError::Sink(m) => ReconcileError::Sink(SinkError(m)),
            SessionError::Remote {
                kind: ErrorKind::IntentInvalid,
                message,
            } => ReconcileError::IntentInvalid(message),
            SessionError::Remote {
                kind: ErrorKind::UnreadableReceipt,
                message,
            } => ReconcileError::UnreadableReceipt(message),
            SessionError::Remote {
                kind: ErrorKind::Sink,
                message,
            } => ReconcileError::Sink(SinkError(message)),
            other => ReconcileError::Unavailable(other.code()),
        }
    }

    /// As the error of `preview`.
    #[must_use]
    pub fn into_preview(self) -> PreviewError {
        match self {
            SessionError::Remote {
                kind: ErrorKind::TooLarge,
                ..
            } => PreviewError::TooLarge,
            other => PreviewError::Unavailable(other.code()),
        }
    }

    /// As the error of the cleaner: every failure is retryable except an unusable locator.
    #[must_use]
    pub fn into_adapter(self) -> AdapterError {
        match self {
            SessionError::Remote {
                kind: ErrorKind::Adapter,
                message,
            } => AdapterError::Protocol(message),
            other => AdapterError::Unavailable(other.code()),
        }
    }
}

/// What Windows holds about the distribution the helper must be in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    /// The name as last observed.
    pub name: String,
    /// The Linux account.
    pub account: String,
    /// The uid, when Windows knows one.
    pub uid: Option<u32>,
}

/// Compare a hello with the record. The helper must speak this version, run in the named
/// distribution (`$WSL_DISTRO_NAME` present and equal), as the named account, and as the
/// known uid when there is one.
///
/// # Errors
/// The [`ByeReason`] to send.
pub fn check_hello(hello: &Hello, expected: &Expected) -> Result<(), ByeReason> {
    if hello.version != VERSION {
        return Err(ByeReason::Version);
    }
    let same = hello.distribution.as_deref() == Some(expected.name.as_str())
        && hello.account == expected.account
        && expected.uid.is_none_or(|u| u == hello.uid);
    if same {
        Ok(())
    } else {
        Err(ByeReason::Mismatch)
    }
}

/// Kills and reaps the child when dropped, so no session leaves a helper behind.
pub(crate) struct ChildGuard(Box<dyn ChildControl>);

impl ChildGuard {
    /// The child's process ID.
    pub(crate) fn id(&self) -> u32 {
        self.0.id()
    }

    /// Whether the child has exited (or can no longer be asked).
    pub(crate) fn exited(&mut self) -> bool {
        !matches!(self.0.try_wait(), Ok(None))
    }

    /// Wait up to `grace` for a voluntary exit, then kill.
    pub(crate) fn finish(&mut self, grace: Duration) {
        let start = Instant::now();
        while start.elapsed() < grace {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.kill_and_reap();
    }

    pub(crate) fn kill_and_reap(&mut self) {
        let _ = self.0.kill();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

/// An open session taken apart (see [`HelperSession::into_parts`]).
pub(crate) struct SessionParts {
    pub(crate) rx: Receiver<Inbound<HelperFrame>>,
    pub(crate) writer: Box<dyn Write + Send>,
    pub(crate) child: ChildGuard,
    pub(crate) stderr: Arc<Mutex<Vec<u8>>>,
    pub(crate) hello: Hello,
}

/// One open session, past the hello. Dropping it ends the helper.
pub struct HelperSession {
    rx: Receiver<Inbound<HelperFrame>>,
    writer: Box<dyn Write + Send>,
    child: ChildGuard,
    stderr: Arc<Mutex<Vec<u8>>>,
    next_id: u64,
    hello: Hello,
}

impl HelperSession {
    /// Read the hello (within [`proto::HELLO_TIMEOUT`]), compare it with `expected`, and
    /// answer `welcome`. A mismatch is answered `bye` and the helper is ended.
    ///
    /// # Errors
    /// [`SessionError`].
    pub fn open(transport: Transport, expected: &Expected) -> Result<HelperSession, SessionError> {
        let Transport {
            reader,
            writer,
            stderr,
            child,
        } = transport;
        let child = ChildGuard(child);
        let kept = Arc::new(Mutex::new(Vec::new()));
        if let Some(mut err) = stderr {
            let sink = Arc::clone(&kept);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = err.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    // Keep the first 64 KiB; keep draining so the helper never blocks.
                    let mut k = sink.lock().unwrap_or_else(PoisonError::into_inner);
                    let room = STDERR_KEEP.saturating_sub(k.len());
                    k.extend_from_slice(&buf[..n.min(room)]);
                }
            });
        }
        let rx = proto::spawn_reader::<HelperFrame, _>(reader);
        let mut session = HelperSession {
            rx,
            writer,
            child,
            stderr: kept,
            next_id: 1,
            hello: Hello {
                version: String::new(),
                uid: 0,
                account: String::new(),
                distribution: None,
                interop: false,
                append_windows_path: None,
                arch: String::new(),
                helper_version: String::new(),
                run_dir: None,
            },
        };
        let hello = match session.rx.recv_timeout(proto::HELLO_TIMEOUT) {
            Ok(Inbound::Frame(HelperFrame::Hello(h))) => h,
            Ok(Inbound::Eof) | Err(RecvTimeoutError::Disconnected) => {
                return Err(SessionError::HelperUnavailable("no hello".to_owned()));
            }
            Err(RecvTimeoutError::Timeout) => {
                return Err(SessionError::HelperUnavailable(
                    "no hello in time".to_owned(),
                ));
            }
            Ok(_) => return Err(SessionError::Protocol),
        };
        if let Err(reason) = check_hello(&hello, expected) {
            let _ = proto::write_frame(&mut session.writer, &WindowsFrame::Bye { reason });
            return Err(SessionError::HelloMismatch);
        }
        session.hello = hello;
        session.send(&WindowsFrame::Welcome {
            version: VERSION.to_owned(),
        })?;
        Ok(session)
    }

    /// The pieces of an open session, for a session that keeps the channel open and serves
    /// frames of its own (the Mode B bridge).
    pub(crate) fn into_parts(self) -> SessionParts {
        SessionParts {
            rx: self.rx,
            writer: self.writer,
            child: self.child,
            stderr: self.stderr,
            hello: self.hello,
        }
    }

    /// The hello the helper sent.
    #[must_use]
    pub fn hello(&self) -> &Hello {
        &self.hello
    }

    /// The helper's process ID.
    #[must_use]
    pub fn helper_pid(&self) -> u32 {
        self.child.0.id()
    }

    /// Up to 64 KiB of the helper's stderr so far (diagnostics: never logged as content).
    #[must_use]
    pub fn stderr_tail(&self) -> Vec<u8> {
        self.stderr
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn send(&mut self, frame: &WindowsFrame) -> Result<(), SessionError> {
        proto::write_frame(&mut self.writer, frame).map_err(|_| SessionError::Gone)
    }

    fn fresh_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// The next frame within `timeout`; a silence ends the session.
    pub(crate) fn recv(&mut self, timeout: Duration) -> Result<HelperFrame, SessionError> {
        match self.rx.recv_timeout(timeout) {
            Ok(Inbound::Frame(f)) => Ok(f),
            Ok(Inbound::Eof) | Err(RecvTimeoutError::Disconnected) => Err(SessionError::Gone),
            Ok(Inbound::Broken(_)) => Err(SessionError::Protocol),
            Err(RecvTimeoutError::Timeout) => {
                self.child.kill_and_reap();
                Err(SessionError::Timeout)
            }
        }
    }

    /// A request with one final frame within [`proto::FINAL_FRAME_TIMEOUT`]; a sink frame is
    /// a call outside a sink request, a protocol error.
    fn call(&mut self, frame: &WindowsFrame, id: u64) -> Result<HelperFrame, SessionError> {
        self.send(frame)?;
        let reply = self.recv(proto::FINAL_FRAME_TIMEOUT)?;
        self.final_frame(reply, id)
    }

    fn final_frame(&mut self, reply: HelperFrame, id: u64) -> Result<HelperFrame, SessionError> {
        match reply {
            HelperFrame::Error {
                id: rid,
                kind,
                message,
            } if rid == id || rid == 0 => Err(SessionError::Remote { kind, message }),
            HelperFrame::PreviewOk { id: rid, .. }
            | HelperFrame::ApplyOk { id: rid, .. }
            | HelperFrame::ReconcileOk { id: rid, .. }
            | HelperFrame::ObserveOk { id: rid, .. }
            | HelperFrame::ObserveHeldOk { id: rid, .. }
            | HelperFrame::CleanOk { id: rid }
                if rid == id =>
            {
                Ok(reply)
            }
            _ => Err(SessionError::Protocol),
        }
    }

    /// A request whose sink calls run through `sink` (`apply`, `reconcile`): up to
    /// [`proto::IDLE_TIMEOUT`] of silence between frames, no total bound.
    fn call_with_sink(
        &mut self,
        frame: &WindowsFrame,
        id: u64,
        intent: &SetupIntent,
        namespace: &heimdall_contract::ids::EnvironmentId,
        sink: &mut dyn StageSink,
    ) -> Result<HelperFrame, SessionError> {
        self.send(frame)?;
        let mut calls = SinkCalls::new(id);
        loop {
            match self.recv(proto::IDLE_TIMEOUT)? {
                HelperFrame::SinkAppend {
                    id: rid,
                    seq,
                    receipt,
                } => {
                    calls.accept(rid, seq).map_err(|_| SessionError::Protocol)?;
                    let verdict = proto::validate_receipt(intent, &receipt)
                        .map_err(SessionError::Invalid)
                        .and_then(|()| {
                            sink.append(&receipt)
                                .map_err(|SinkError(m)| SessionError::Sink(m))
                        });
                    self.acknowledge(id, seq, verdict)?;
                }
                HelperFrame::SinkCommit {
                    id: rid,
                    seq,
                    commit,
                } => {
                    calls.accept(rid, seq).map_err(|_| SessionError::Protocol)?;
                    let verdict = proto::validate_commit(intent, namespace, &commit)
                        .map_err(SessionError::Invalid)
                        .and_then(|()| {
                            sink.commit_item(*commit)
                                .map_err(|SinkError(m)| SessionError::Sink(m))
                        });
                    self.acknowledge(id, seq, verdict)?;
                }
                other => return self.final_frame(other, id),
            }
        }
    }

    /// Answer a sink call: `sink_ack` once it is durable, else `sink_failed` and the session's
    /// end. A durable call whose ack cannot be sent is still durable on Windows.
    fn acknowledge(
        &mut self,
        id: u64,
        seq: u64,
        verdict: Result<(), SessionError>,
    ) -> Result<(), SessionError> {
        match verdict {
            Ok(()) => self.send(&WindowsFrame::SinkAck { id, seq }),
            Err(e) => {
                let _ = self.send(&WindowsFrame::SinkFailed { id, seq });
                self.child.kill_and_reap();
                Err(e)
            }
        }
    }

    /// `LocalProjection::preview` in the distribution.
    ///
    /// # Errors
    /// [`SessionError`].
    pub fn preview(
        &mut self,
        spec: &ProjectionSpec,
        intent: &PreviewIntent,
        ctx: &DistContext,
    ) -> Result<ProjectionPlan, SessionError> {
        let id = self.fresh_id();
        let frame = WindowsFrame::Preview {
            id,
            spec: Box::new(spec.clone()),
            intent: intent.clone(),
            ctx: ctx.clone(),
        };
        match self.call(&frame, id)? {
            HelperFrame::PreviewOk { plan, .. } => Ok(*plan),
            _ => Err(SessionError::Protocol),
        }
    }

    /// `LocalProjection::apply` in the distribution, over the durable `sink`.
    ///
    /// # Errors
    /// [`SessionError`].
    pub fn apply(
        &mut self,
        intent: &SetupIntent,
        ctx: &DistContext,
        sink: &mut dyn StageSink,
    ) -> Result<Vec<ItemOutcome>, SessionError> {
        let id = self.fresh_id();
        let frame = WindowsFrame::Apply {
            id,
            intent: Box::new(intent.clone()),
            ctx: ctx.clone(),
        };
        match self.call_with_sink(&frame, id, intent, &ctx.namespace, sink)? {
            HelperFrame::ApplyOk { items, .. } => outcomes(&items),
            _ => Err(SessionError::Protocol),
        }
    }

    /// `LocalProjection::reconcile` in the distribution, over the durable `sink`.
    ///
    /// # Errors
    /// [`SessionError`].
    pub fn reconcile(
        &mut self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
        ctx: &DistContext,
        sink: &mut dyn StageSink,
    ) -> Result<Vec<ItemOutcome>, SessionError> {
        let id = self.fresh_id();
        let frame = WindowsFrame::Reconcile {
            id,
            intent: Box::new(intent.clone()),
            receipts: receipts.to_vec(),
            ctx: ctx.clone(),
        };
        match self.call_with_sink(&frame, id, intent, &ctx.namespace, sink)? {
            HelperFrame::ReconcileOk { items, .. } => outcomes(&items),
            _ => Err(SessionError::Protocol),
        }
    }

    /// `LocalProjection::observe` in the distribution.
    ///
    /// # Errors
    /// [`SessionError`].
    pub fn observe(
        &mut self,
        record: &ProjectionRecord,
        aliases: &[String],
        ctx: &DistContext,
    ) -> Result<Vec<AliasObservation>, SessionError> {
        let id = self.fresh_id();
        let frame = WindowsFrame::Observe {
            id,
            record: Box::new(record.clone()),
            aliases: aliases.to_vec(),
            ctx: ctx.clone(),
        };
        match self.call(&frame, id)? {
            HelperFrame::ObserveOk { observations, .. } => Ok(observations),
            _ => Err(SessionError::Protocol),
        }
    }

    /// `LocalProjection::observe_held` in the distribution.
    ///
    /// # Errors
    /// [`SessionError`].
    pub fn observe_held(
        &mut self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
        ctx: &DistContext,
    ) -> Result<Vec<HeldStep>, SessionError> {
        let id = self.fresh_id();
        let frame = WindowsFrame::ObserveHeld {
            id,
            intent: Box::new(intent.clone()),
            receipts: receipts.to_vec(),
            ctx: ctx.clone(),
        };
        match self.call(&frame, id)? {
            HelperFrame::ObserveHeldOk { steps, .. } => steps
                .iter()
                .map(|s| HeldStep::try_from(s).map_err(|_| SessionError::Protocol))
                .collect(),
            _ => Err(SessionError::Protocol),
        }
    }

    /// `ProjectionCleaner::delete` in the distribution.
    ///
    /// # Errors
    /// [`SessionError`].
    pub fn clean(
        &mut self,
        resource: &ManagedResource,
        ctx: &DistContext,
    ) -> Result<(), SessionError> {
        let id = self.fresh_id();
        let frame = WindowsFrame::Clean {
            id,
            resource: Box::new(resource.clone()),
            ctx: ctx.clone(),
        };
        match self.call(&frame, id)? {
            HelperFrame::CleanOk { .. } => Ok(()),
            _ => Err(SessionError::Protocol),
        }
    }

    /// End the session politely: `shutdown`, a short wait for the exit, then the kill.
    pub fn close(mut self) {
        let _ = self.send(&WindowsFrame::Shutdown {});
        self.child.finish(Duration::from_secs(2));
    }
}

fn outcomes(items: &[WireItemOutcome]) -> Result<Vec<ItemOutcome>, SessionError> {
    items
        .iter()
        .map(|i| ItemOutcome::try_from(i).map_err(|_| SessionError::Protocol))
        .collect()
}

// --- the writer and the cleaner of one distribution ----------------------------------------

/// What both ports need: the launcher, the target, the start policy and the context.
#[derive(Clone)]
struct Binding {
    launcher: Arc<dyn HelperLauncher>,
    target: DistributionTarget,
    start: DistributionStart,
    ssh_exe_windows: String,
}

impl Binding {
    fn ctx(&self) -> DistContext {
        DistContext {
            guid: self.target.guid.clone(),
            namespace: self.target.namespace.clone(),
            ssh_exe_windows: self.ssh_exe_windows.clone(),
            items: std::iter::once(ProjectionItem::DistributionGit).collect(),
        }
    }

    /// Open a session: a stopped distribution is never started unless the policy allows it.
    fn open(&self) -> Result<HelperSession, SessionError> {
        if self.start == DistributionStart::Forbidden
            && self.launcher.running(&self.target.name) != RunningState::Running
        {
            return Err(SessionError::NotRunning);
        }
        let transport = self.launcher.launch(&self.target)?;
        HelperSession::open(
            transport,
            &Expected {
                name: self.target.name.clone(),
                account: self.target.account.clone(),
                uid: None,
            },
        )
    }
}

/// The projection writer of one distribution's Git item (Mode A), through its helper.
#[derive(Clone)]
pub struct DistributionWriter {
    binding: Binding,
}

impl DistributionWriter {
    /// A writer for `target` with the given start policy. `ssh_exe_windows` is the in-box
    /// `ssh.exe`'s Windows path (the helper translates it).
    #[must_use]
    pub fn new(
        launcher: Arc<dyn HelperLauncher>,
        target: DistributionTarget,
        start: DistributionStart,
        ssh_exe_windows: String,
    ) -> Self {
        Self {
            binding: Binding {
                launcher,
                target,
                start,
                ssh_exe_windows,
            },
        }
    }

    /// Whether this call may start a stopped distribution.
    #[must_use]
    pub fn start(&self) -> DistributionStart {
        self.binding.start
    }
}

impl ProjectionWriter for DistributionWriter {
    fn preview(
        &self,
        spec: &ProjectionSpec,
        intent: &PreviewIntent,
    ) -> Result<ProjectionPlan, PreviewError> {
        let mut s = self.binding.open().map_err(SessionError::into_preview)?;
        let r = s.preview(spec, intent, &self.binding.ctx());
        s.close();
        r.map_err(SessionError::into_preview)
    }

    fn apply(
        &self,
        intent: &SetupIntent,
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReceipt, ReconcileError> {
        let mut s = self.binding.open().map_err(SessionError::into_reconcile)?;
        let r = s.apply(intent, &self.binding.ctx(), sink);
        s.close();
        r.map(|items| ProjectionReceipt { items })
            .map_err(SessionError::into_reconcile)
    }

    fn reconcile(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
        sink: &mut dyn StageSink,
    ) -> Result<ProjectionReconcile, ReconcileError> {
        let mut s = self.binding.open().map_err(SessionError::into_reconcile)?;
        let r = s.reconcile(intent, receipts, &self.binding.ctx(), sink);
        s.close();
        r.map(|items| ProjectionReconcile { items })
            .map_err(SessionError::into_reconcile)
    }

    /// A passive observation cannot fail in the port: when the helper cannot be reached, nothing
    /// was observed and the list is empty (the caller reads absent aliases as unobserved).
    fn observe(&self, record: &ProjectionRecord, aliases: &[String]) -> Vec<AliasObservation> {
        let Ok(mut s) = self.binding.open() else {
            return Vec::new();
        };
        let r = s.observe(record, aliases, &self.binding.ctx());
        s.close();
        r.unwrap_or_default()
    }

    fn observe_held(
        &self,
        intent: &SetupIntent,
        receipts: &[StageReceipt],
    ) -> Result<Vec<HeldStep>, ReconcileError> {
        let mut s = self.binding.open().map_err(SessionError::into_reconcile)?;
        let r = s.observe_held(intent, receipts, &self.binding.ctx());
        s.close();
        r.map_err(SessionError::into_reconcile)
    }
}

/// The cleaner of one distribution's projection resources, through its helper. A stopped
/// distribution under [`DistributionStart::Forbidden`] answers the retryable
/// `Unavailable("wsl_distribution_not_running")`: nothing is deleted and the obligation stays.
#[derive(Clone)]
pub struct DistributionCleaner {
    binding: Binding,
}

impl DistributionCleaner {
    /// A cleaner for `target` with the given start policy.
    #[must_use]
    pub fn new(
        launcher: Arc<dyn HelperLauncher>,
        target: DistributionTarget,
        start: DistributionStart,
        ssh_exe_windows: String,
    ) -> Self {
        Self {
            binding: Binding {
                launcher,
                target,
                start,
                ssh_exe_windows,
            },
        }
    }
}

#[async_trait]
impl ResourceCleaner for DistributionCleaner {
    async fn delete(&self, resource: &ManagedResource) -> Result<(), AdapterError> {
        let binding = self.binding.clone();
        let resource = resource.clone();
        tokio::task::spawn_blocking(move || {
            let mut s = binding.open().map_err(SessionError::into_adapter)?;
            let r = s.clean(&resource, &binding.ctx());
            s.close();
            r.map_err(SessionError::into_adapter)
        })
        .await
        .map_err(|_| AdapterError::Unavailable("wsl_helper_unavailable".to_owned()))?
    }
}
