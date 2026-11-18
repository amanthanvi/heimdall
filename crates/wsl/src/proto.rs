//! `heimdall-wsl/1`: the frames, the framing, the wire mirrors and the checks Windows makes
//! before it persists anything the helper sends (ADR-0010 §3 items 3–4, §9 item 2; design
//! U3 §3). Pure: no process, no file, no clock.
//!
//! **Framing.** A 4-byte big-endian length `N`, then `N` bytes of one UTF-8 JSON object whose
//! string field `t` is the frame type. `N` is at most [`MAX_FRAME`] and is checked before
//! anything is allocated. Invalid JSON, an unknown `t`, a missing or unknown field, and a
//! frame the state does not expect are **protocol errors**: the receiver ends the session.
//!
//! **Directions.** [`HelperFrame`] travels helper → Windows, [`WindowsFrame`] Windows →
//! helper, so a frame in the wrong direction does not decode.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::Duration;

use heimdall_app::ports::{HeldStep, ItemOutcome};
use heimdall_contract::doctor::AliasObservation;
use heimdall_contract::environment::DistributionGuid;
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::setup::{ConflictKind, PreviewIntent, ProjectionItem};
use heimdall_domain::operation::{HoldReason, LocalReceipt, StageReceipt};
use heimdall_domain::projection::{
    EntryObs, FileRole, ItemCommit, ProjectionPlan, ProjectionRecord, ProjectionSpec, SetupIntent,
    StepFingerprint, StepObservation, StepShape,
};
use heimdall_domain::resource::ManagedResource;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The protocol version both hellos name.
pub const VERSION: &str = "heimdall-wsl/1";

/// The largest frame body: above the 1 MiB file bound with the JSON overhead.
pub const MAX_FRAME: usize = 8 << 20;

/// The longest `error.message`.
pub const MAX_MESSAGE: usize = 1024;

/// The most sink calls one request may make (above `apply::MAX_ITERATIONS` times the
/// receipts per step).
pub const MAX_SINK_CALLS: u64 = 8192;

/// The hello must arrive within this (a distribution cold start).
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(20);
/// `preview`, `observe`, `observe_held` and `clean`: the final frame within this.
pub const FINAL_FRAME_TIMEOUT: Duration = Duration::from_secs(30);
/// `apply` and `reconcile`: the longest silence between two helper frames.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// The helper's wait for a sink acknowledgment.
pub const SINK_ACK_TIMEOUT: Duration = Duration::from_secs(60);

/// Mode B: streams per binding.
pub const MAX_STREAMS_PER_BINDING: usize = 64;
/// Mode B: one agent message, decoded.
pub const MAX_AGENT_MESSAGE: usize = 256 << 10;
/// Mode B: idle time per stream.
pub const STREAM_IDLE: Duration = Duration::from_secs(30);

/// The helper's exit status after a protocol error.
pub const EXIT_PROTOCOL: i32 = 3;

// --- framing ------------------------------------------------------------------------

/// A framing failure.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The announced length is zero or above [`MAX_FRAME`]; nothing was allocated.
    #[error("frame length {0} out of bounds")]
    Length(usize),
    /// The body is not one frame of the expected direction.
    #[error("malformed frame")]
    Malformed,
    /// The stream ended inside a frame.
    #[error("the stream ended inside a frame")]
    Truncated,
    /// The transport failed.
    #[error("transport: {0}")]
    Io(std::io::ErrorKind),
}

/// Write one frame.
///
/// # Errors
/// [`FrameError::Length`] when the body exceeds [`MAX_FRAME`]; [`FrameError::Io`].
pub fn write_frame<T: Serialize>(w: &mut impl Write, frame: &T) -> Result<(), FrameError> {
    let body = serde_json::to_vec(frame).map_err(|_| FrameError::Malformed)?;
    if body.is_empty() || body.len() > MAX_FRAME {
        return Err(FrameError::Length(body.len()));
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::Length(body.len()))?;
    let io = |e: std::io::Error| FrameError::Io(e.kind());
    w.write_all(&len.to_be_bytes()).map_err(io)?;
    w.write_all(&body).map_err(io)?;
    w.flush().map_err(io)
}

/// Read one frame; `Ok(None)` for a clean end of stream at a frame boundary.
///
/// # Errors
/// [`FrameError`]: an oversized length is refused before the body is read.
pub fn read_frame<T: DeserializeOwned>(r: &mut impl Read) -> Result<Option<T>, FrameError> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < len.len() {
        match r.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FrameError::Io(e.kind())),
        }
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(FrameError::Length(n));
    }
    // `take` grows the buffer as bytes arrive: a lying length costs nothing up front.
    let mut body = Vec::new();
    let read = r
        .take(n as u64)
        .read_to_end(&mut body)
        .map_err(|e| FrameError::Io(e.kind()))?;
    if read != n {
        return Err(FrameError::Truncated);
    }
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|_| FrameError::Malformed)
}

/// What a reader thread reports.
#[derive(Debug)]
pub enum Inbound<T> {
    /// One frame.
    Frame(T),
    /// The stream ended cleanly at a frame boundary.
    Eof,
    /// A framing or protocol failure; the reader stopped.
    Broken(FrameError),
}

/// Read frames of `T` from `r` on a thread, so the owner can wait with a timeout. The thread
/// ends at the first end of stream or failure (so a killed peer ends it).
pub fn spawn_reader<T, R>(mut r: R) -> mpsc::Receiver<Inbound<T>>
where
    T: DeserializeOwned + Send + 'static,
    R: Read + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        loop {
            let event = match read_frame::<T>(&mut r) {
                Ok(Some(f)) => Inbound::Frame(f),
                Ok(None) => Inbound::Eof,
                Err(e) => Inbound::Broken(e),
            };
            let last = !matches!(event, Inbound::Frame(_));
            if tx.send(event).is_err() || last {
                return;
            }
        }
    });
    rx
}

// --- the frames ---------------------------------------------------------------------

/// `error.kind`: maps one to one onto `ReconcileError`, `PreviewError` or `AdapterError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// `ReconcileError::IntentInvalid`.
    IntentInvalid,
    /// `ReconcileError::UnreadableReceipt`.
    UnreadableReceipt,
    /// `ReconcileError::Sink`.
    Sink,
    /// `Unavailable` (`ReconcileError`, `PreviewError`, `AdapterError`).
    Unavailable,
    /// Another helper holds this account's instance lock.
    Busy,
    /// The frame is defined but not served in this build (Mode B before U4).
    Unsupported,
    /// A protocol violation the helper reports before it exits.
    Protocol,
    /// `AdapterError::Protocol` (a cleaner's unusable locator).
    Adapter,
    /// `PreviewError::TooLarge` (`projection_too_large`). **Beyond the design's list of
    /// kinds**: `PreviewError` has a variant `Unavailable` cannot carry.
    TooLarge,
}

/// The helper's first frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// [`VERSION`].
    pub version: String,
    /// `geteuid()`.
    pub uid: u32,
    /// `getpwuid_r(uid)` name.
    pub account: String,
    /// `$WSL_DISTRO_NAME`; `null` when unset (Windows refuses).
    pub distribution: Option<String>,
    /// Whether Windows interop is enabled in the distribution.
    pub interop: bool,
    /// `/etc/wsl.conf` `[interop] appendWindowsPath` (default true); `null` when the file
    /// does not parse.
    pub append_windows_path: Option<bool>,
    /// `std::env::consts::ARCH`.
    pub arch: String,
    /// The helper crate's version.
    pub helper_version: String,
}

/// Why Windows ends a session after the hello.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByeReason {
    /// The hello does not match the record Windows holds.
    Mismatch,
    /// The helper speaks another version.
    Version,
}

/// What the helper cannot derive itself (design §3.2, §3.2a).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistContext {
    /// The distribution's registration GUID; the intents it serves name it.
    pub guid: DistributionGuid,
    /// The projection namespace: the environment the commits are recorded under.
    pub namespace: EnvironmentId,
    /// The Windows path of the in-box `ssh.exe`; the helper translates it with
    /// `/usr/bin/wslpath -u`.
    pub ssh_exe_windows: String,
    /// The items the helper may touch.
    pub items: BTreeSet<ProjectionItem>,
}

/// Mode B's public material of one binding (defined now, served by U4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModeBPublic {
    /// Certificate lines.
    pub certs: Vec<String>,
    /// The managed include's text.
    pub ssh_config: String,
    /// The known-hosts text.
    pub known_hosts: String,
}

/// Helper → Windows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperFrame {
    /// The first frame.
    Hello(Hello),
    /// `preview`'s answer.
    PreviewOk {
        /// The request.
        id: u64,
        /// The plan.
        plan: Box<ProjectionPlan>,
    },
    /// `apply`'s answer.
    ApplyOk {
        /// The request.
        id: u64,
        /// One outcome per item.
        items: Vec<WireItemOutcome>,
    },
    /// `reconcile`'s answer.
    ReconcileOk {
        /// The request.
        id: u64,
        /// One outcome per item.
        items: Vec<WireItemOutcome>,
    },
    /// `observe`'s answer.
    ObserveOk {
        /// The request.
        id: u64,
        /// The observations.
        observations: Vec<AliasObservation>,
    },
    /// `observe_held`'s answer.
    ObserveHeldOk {
        /// The request.
        id: u64,
        /// The held steps.
        steps: Vec<WireHeldStep>,
    },
    /// `clean`'s answer.
    CleanOk {
        /// The request.
        id: u64,
    },
    /// A request ends in an error (`id` 0: not tied to a request).
    Error {
        /// The request.
        id: u64,
        /// Which failure.
        kind: ErrorKind,
        /// Bounded (1 KiB), nonsecret.
        message: String,
    },
    /// The proxy sink's `append`: durable on Windows before the ack.
    SinkAppend {
        /// The request.
        id: u64,
        /// 0, 1, 2, … per request.
        seq: u64,
        /// The receipt.
        receipt: LocalReceipt,
    },
    /// The proxy sink's `commit_item`.
    SinkCommit {
        /// The request.
        id: u64,
        /// As above.
        seq: u64,
        /// The commit.
        commit: Box<ItemCommit>,
    },
}

/// Windows → helper.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum WindowsFrame {
    /// The helper may serve requests.
    Welcome {
        /// [`VERSION`].
        version: String,
    },
    /// The session ends.
    Bye {
        /// Why.
        reason: ByeReason,
    },
    /// `LocalProjection::preview`.
    Preview {
        /// The request.
        id: u64,
        /// What to render from.
        spec: Box<ProjectionSpec>,
        /// What to do.
        intent: PreviewIntent,
        /// The context.
        ctx: DistContext,
    },
    /// `LocalProjection::apply`.
    Apply {
        /// The request.
        id: u64,
        /// The intent.
        intent: Box<SetupIntent>,
        /// The context.
        ctx: DistContext,
    },
    /// `LocalProjection::reconcile`.
    Reconcile {
        /// The request.
        id: u64,
        /// The intent.
        intent: Box<SetupIntent>,
        /// The durable receipts.
        receipts: Vec<StageReceipt>,
        /// The context.
        ctx: DistContext,
    },
    /// `LocalProjection::observe`.
    Observe {
        /// The request.
        id: u64,
        /// The record.
        record: Box<ProjectionRecord>,
        /// The aliases.
        aliases: Vec<String>,
        /// The context.
        ctx: DistContext,
    },
    /// `LocalProjection::observe_held`.
    ObserveHeld {
        /// The request.
        id: u64,
        /// The intent.
        intent: Box<SetupIntent>,
        /// The durable receipts.
        receipts: Vec<StageReceipt>,
        /// The context.
        ctx: DistContext,
    },
    /// `ProjectionCleaner::delete`.
    Clean {
        /// The request.
        id: u64,
        /// The resource.
        resource: Box<ManagedResource>,
        /// The context.
        ctx: DistContext,
    },
    /// The sink call `seq` is durable.
    SinkAck {
        /// The request.
        id: u64,
        /// The call.
        seq: u64,
    },
    /// The sink call `seq` failed.
    SinkFailed {
        /// The request.
        id: u64,
        /// The call.
        seq: u64,
    },
    /// The helper exits 0.
    Shutdown {},
    /// Mode B (served by U4; answered `unsupported` until then).
    Realize {
        /// The request.
        id: u64,
        /// The binding's tag.
        binding_tag: String,
        /// The generation.
        generation: u64,
        /// The public material.
        public: ModeBPublic,
        /// The binding's deadline (RFC 3339).
        deadline: String,
    },
    /// Mode B.
    Withdraw {
        /// The request.
        id: u64,
        /// The binding's tag.
        binding_tag: String,
        /// The generation.
        generation: u64,
    },
    /// Mode B: a stream opens.
    Open {
        /// The stream.
        stream: u64,
        /// The binding's tag.
        binding_tag: String,
    },
    /// Mode B: bytes of a stream.
    Data {
        /// The stream.
        stream: u64,
        /// Base64.
        bytes_b64: String,
    },
    /// Mode B: a stream closes.
    Close {
        /// The stream.
        stream: u64,
    },
}

impl WindowsFrame {
    /// Whether this is one of the Mode B frames (U4's).
    #[must_use]
    pub fn is_mode_b(&self) -> bool {
        matches!(
            self,
            WindowsFrame::Realize { .. }
                | WindowsFrame::Withdraw { .. }
                | WindowsFrame::Open { .. }
                | WindowsFrame::Data { .. }
                | WindowsFrame::Close { .. }
        )
    }

    /// The request or stream a Mode B frame names (a stream's number for the stream frames;
    /// the error answer carries it, 0 never).
    #[must_use]
    pub fn mode_b_id(&self) -> u64 {
        match self {
            WindowsFrame::Realize { id, .. } | WindowsFrame::Withdraw { id, .. } => *id,
            WindowsFrame::Open { stream, .. }
            | WindowsFrame::Data { stream, .. }
            | WindowsFrame::Close { stream } => *stream,
            _ => 0,
        }
    }
}

/// `message`, cut to [`MAX_MESSAGE`] bytes on a character boundary.
#[must_use]
pub fn bounded_message(message: &str) -> String {
    if message.len() <= MAX_MESSAGE {
        return message.to_owned();
    }
    let mut end = MAX_MESSAGE;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_owned()
}

// --- wire mirrors of the port types that are not serde -------------------------------

/// A step's three-name observation on the wire (symbols only, never content).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireObservation {
    /// The path's symbol.
    pub path: EntryObs,
    /// The aside name's symbol.
    pub aside: EntryObs,
    /// The slot's symbol.
    pub slot: EntryObs,
}

/// Wire mirror of `heimdall_app::ports::HeldStep`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireHeldStep {
    /// Index into `SetupIntent.files`.
    pub step: u16,
    /// The step's role.
    pub role: FileRole,
    /// The path, for display.
    pub path_display: String,
    /// Why it is held.
    pub reason: HoldReason,
    /// The recovery classification.
    pub observed: WireObservation,
    /// Content fingerprints.
    pub fingerprint: StepFingerprint,
}

/// Wire mirror of `heimdall_app::ports::ItemOutcome`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireItemOutcome {
    /// `ItemOutcome::Applied`.
    Applied {
        /// The item.
        item: ProjectionItem,
        /// The generation.
        generation: u64,
    },
    /// `ItemOutcome::NotApplied`.
    NotApplied {
        /// The item.
        item: ProjectionItem,
        /// Why.
        reason: Option<ConflictKind>,
    },
    /// `ItemOutcome::Restored`.
    Restored {
        /// The item.
        item: ProjectionItem,
        /// Why.
        reason: Option<ConflictKind>,
    },
    /// `ItemOutcome::ConflictPreserved`.
    ConflictPreserved {
        /// The item.
        item: ProjectionItem,
    },
    /// `ItemOutcome::Held`.
    Held {
        /// The item.
        item: ProjectionItem,
        /// The held steps.
        steps: Vec<WireHeldStep>,
    },
}

/// A wire value that has no port-type counterpart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a wire value the port type cannot represent")]
pub struct Unrepresentable;

impl From<&HeldStep> for WireHeldStep {
    fn from(h: &HeldStep) -> Self {
        WireHeldStep {
            step: h.step,
            role: h.role,
            path_display: h.path_display.clone(),
            reason: h.reason,
            observed: WireObservation {
                path: h.observed.path(),
                aside: h.observed.aside(),
                slot: h.observed.slot(),
            },
            fingerprint: h.fingerprint.clone(),
        }
    }
}

/// Rebuild a [`StepObservation`], whose only constructor is `normalize`: its three symbols
/// were normalized under the recovery state they were observed in, which does not cross the
/// wire, so a state under which the same three symbols are possible is searched. The symbols
/// of the result are exactly the wire's.
fn rebuild_observation(o: &WireObservation) -> Result<StepObservation, Unrepresentable> {
    use heimdall_domain::operation::{RestoreCause, SettleSource};
    use heimdall_domain::projection::{ItemState, RecoveryState, RestoreCtx, SettleCtx};
    let settlements = [
        None,
        Some(SettleSource::Path),
        Some(SettleSource::Staged),
        Some(SettleSource::Displaced),
    ];
    for shape in [
        StepShape::Replace,
        StepShape::Removal,
        StepShape::Create,
        StepShape::GitLock,
    ] {
        for source in settlements {
            for mismatch in [false, true] {
                for release_due in [false, true] {
                    let state = RecoveryState {
                        phase: None,
                        restore: if mismatch {
                            RestoreCtx::Due(RestoreCause::FileMismatch)
                        } else {
                            RestoreCtx::NotDue
                        },
                        settlement: source.map(|source| SettleCtx {
                            source,
                            create_restore: false,
                        }),
                        item: ItemState::Open,
                        release_due,
                    };
                    if let Ok(obs) =
                        StepObservation::normalize(o.path, o.aside, o.slot, &state, shape)
                    {
                        return Ok(obs);
                    }
                }
            }
        }
    }
    Err(Unrepresentable)
}

impl TryFrom<&WireHeldStep> for HeldStep {
    type Error = Unrepresentable;
    fn try_from(w: &WireHeldStep) -> Result<Self, Unrepresentable> {
        Ok(HeldStep {
            step: w.step,
            role: w.role,
            path_display: w.path_display.clone(),
            reason: w.reason,
            observed: rebuild_observation(&w.observed)?,
            fingerprint: w.fingerprint.clone(),
        })
    }
}

impl From<&ItemOutcome> for WireItemOutcome {
    fn from(o: &ItemOutcome) -> Self {
        match o {
            ItemOutcome::Applied { item, generation } => WireItemOutcome::Applied {
                item: *item,
                generation: *generation,
            },
            ItemOutcome::NotApplied { item, reason } => WireItemOutcome::NotApplied {
                item: *item,
                reason: *reason,
            },
            ItemOutcome::Restored { item, reason } => WireItemOutcome::Restored {
                item: *item,
                reason: *reason,
            },
            ItemOutcome::ConflictPreserved { item } => {
                WireItemOutcome::ConflictPreserved { item: *item }
            }
            ItemOutcome::Held { item, steps } => WireItemOutcome::Held {
                item: *item,
                steps: steps.iter().map(WireHeldStep::from).collect(),
            },
        }
    }
}

impl TryFrom<&WireItemOutcome> for ItemOutcome {
    type Error = Unrepresentable;
    fn try_from(w: &WireItemOutcome) -> Result<Self, Unrepresentable> {
        Ok(match w {
            WireItemOutcome::Applied { item, generation } => ItemOutcome::Applied {
                item: *item,
                generation: *generation,
            },
            WireItemOutcome::NotApplied { item, reason } => ItemOutcome::NotApplied {
                item: *item,
                reason: *reason,
            },
            WireItemOutcome::Restored { item, reason } => ItemOutcome::Restored {
                item: *item,
                reason: *reason,
            },
            WireItemOutcome::ConflictPreserved { item } => {
                ItemOutcome::ConflictPreserved { item: *item }
            }
            WireItemOutcome::Held { item, steps } => ItemOutcome::Held {
                item: *item,
                steps: steps
                    .iter()
                    .map(HeldStep::try_from)
                    .collect::<Result<_, _>>()?,
            },
        })
    }
}

// --- the sink exchange's state (both sides) -------------------------------------------

/// A violation of the sink exchange's rules: a protocol error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SinkViolation {
    /// A sink frame with no request in flight, or naming another request.
    #[error("a sink call outside its request")]
    OutsideRequest,
    /// `seq` is not the next number (a gap or a repeat).
    #[error("sink sequence gap or repeat")]
    Sequence,
    /// More than [`MAX_SINK_CALLS`] calls.
    #[error("too many sink calls")]
    TooMany,
}

/// The sink calls of the one request in flight (Windows side: what the helper sent; helper
/// side: what it sent and what was acknowledged).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkCalls {
    id: u64,
    next: u64,
}

impl SinkCalls {
    /// A request `id` with no call yet.
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self { id, next: 0 }
    }

    /// Accept the helper's call `seq` of request `id`.
    ///
    /// # Errors
    /// [`SinkViolation`].
    pub fn accept(&mut self, id: u64, seq: u64) -> Result<(), SinkViolation> {
        if id != self.id {
            return Err(SinkViolation::OutsideRequest);
        }
        if seq != self.next {
            return Err(SinkViolation::Sequence);
        }
        if seq >= MAX_SINK_CALLS {
            return Err(SinkViolation::TooMany);
        }
        self.next += 1;
        Ok(())
    }

    /// The `seq` of the next call (the helper's side).
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next
    }
}

// --- what Windows validates before it persists (design §3.5) --------------------------

/// A sink call that fails validation: answered `sink_failed`, the session ends and the
/// operation stays unresolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    /// A receipt names a step the intent does not have.
    #[error("a receipt names a step outside the intent")]
    Step,
    /// A receipt or commit names an item the intent does not have.
    #[error("a receipt or commit names an item outside the intent")]
    Item,
    /// A commit at another generation than the intent's.
    #[error("a commit at another generation")]
    Generation,
    /// A commit's record is for another environment.
    #[error("a commit's record is for another environment")]
    Environment,
    /// A commit's record holds an item other than the committed one, or another generation.
    #[error("a commit's record does not match the committed item")]
    Record,
    /// A commit names a file the intent has no step for.
    #[error("a commit names a file outside the intent's steps")]
    Resource,
}

/// The items the file steps of `intent` belong to (the writer's items).
#[must_use]
pub fn writer_items(intent: &SetupIntent) -> BTreeSet<ProjectionItem> {
    intent.files.iter().map(|s| s.role.item()).collect()
}

/// Check a receipt the helper sent against the intent it runs.
///
/// # Errors
/// [`Invalid`].
pub fn validate_receipt(intent: &SetupIntent, receipt: &LocalReceipt) -> Result<(), Invalid> {
    match receipt {
        LocalReceipt::File { step, .. } => {
            if usize::from(*step) < intent.files.len() {
                Ok(())
            } else {
                Err(Invalid::Step)
            }
        }
        LocalReceipt::Item { item, .. } => {
            if writer_items(intent).contains(item) {
                Ok(())
            } else {
                Err(Invalid::Item)
            }
        }
    }
}

/// Check an item commit the helper sent against the intent it runs and the namespace the
/// request was sent for.
///
/// # Errors
/// [`Invalid`].
pub fn validate_commit(
    intent: &SetupIntent,
    namespace: &EnvironmentId,
    commit: &ItemCommit,
) -> Result<(), Invalid> {
    if !writer_items(intent).contains(&commit.item) {
        return Err(Invalid::Item);
    }
    if commit.generation != intent.generation {
        return Err(Invalid::Generation);
    }
    if &commit.record.environment != namespace {
        return Err(Invalid::Environment);
    }
    let only_this = commit.record.items.len() == 1
        && commit
            .record
            .items
            .get(&commit.item)
            .is_some_and(|r| r.generation == commit.generation);
    if !only_this {
        return Err(Invalid::Record);
    }
    let known = |l: &heimdall_domain::projection::ProjectionLocator| {
        intent
            .files
            .iter()
            .any(|s| s.role == l.role && s.path == l.path && s.role.item() == commit.item)
    };
    if !commit.resources.iter().all(known) {
        return Err(Invalid::Resource);
    }
    if let Some(r) = commit.record.items.get(&commit.item)
        && !r.files.iter().all(known)
    {
        return Err(Invalid::Resource);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod tests {
    use super::*;
    use heimdall_domain::operation::{RestoreCause, SettleSource};
    use heimdall_domain::projection::{
        Base, ContentState, ItemRecord, ProjectionLocator, RecordedRole, RecoveryState, RestoreCtx,
        SettleCtx, StepContent, Target,
    };

    fn frame_bytes(json: &str) -> Vec<u8> {
        let mut v = u32::try_from(json.len()).unwrap().to_be_bytes().to_vec();
        v.extend_from_slice(json.as_bytes());
        v
    }

    fn read_windows(bytes: &[u8]) -> Result<Option<WindowsFrame>, FrameError> {
        read_frame::<WindowsFrame>(&mut &bytes[..])
    }

    /// `wsl_proto_bounds_and_unknown_frames_refused`: an oversized or zero length is refused
    /// before the body is read; invalid JSON, an unknown `t`, an unknown or missing field and a
    /// frame of the other direction do not decode; a truncated stream is not a clean end; a
    /// `seq` gap or repeat, a sink call outside its request and more than 8192 calls are
    /// violations; a Mode B frame decodes (so the helper can answer `unsupported`); an
    /// over-large frame is not written.
    #[test]
    fn wsl_proto_bounds_and_unknown_frames_refused() {
        // Lengths, checked before any allocation: only the 4 header bytes are supplied.
        let too_big = u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes();
        assert!(matches!(
            read_windows(&too_big),
            Err(FrameError::Length(n)) if n == MAX_FRAME + 1
        ));
        assert!(matches!(
            read_windows(&0u32.to_be_bytes()),
            Err(FrameError::Length(0))
        ));
        assert!(matches!(
            read_windows(&u32::MAX.to_be_bytes()),
            Err(FrameError::Length(_))
        ));

        // Bodies.
        for (name, json) in [
            ("bad json", "{not json"),
            ("unknown t", r#"{"t":"explode"}"#),
            ("no t", r#"{"id":1}"#),
            (
                "unknown field",
                r#"{"t":"welcome","version":"heimdall-wsl/1","extra":1}"#,
            ),
            ("missing field", r#"{"t":"welcome"}"#),
            ("wrong type", r#"{"t":"sink_ack","id":"x","seq":0}"#),
            ("not an object", "[1,2]"),
            // A helper → Windows frame does not decode as Windows → helper.
            ("wrong direction", r#"{"t":"clean_ok","id":1}"#),
        ] {
            assert!(
                matches!(read_windows(&frame_bytes(json)), Err(FrameError::Malformed)),
                "{name}"
            );
        }

        // Stream ends.
        assert!(
            read_windows(&[]).unwrap().is_none(),
            "a clean end at a boundary"
        );
        assert!(matches!(read_windows(&[0, 0]), Err(FrameError::Truncated)));
        let mut cut = frame_bytes(r#"{"t":"shutdown"}"#);
        cut.truncate(cut.len() - 2);
        assert!(matches!(read_windows(&cut), Err(FrameError::Truncated)));

        // The round trip, and Mode B decodes as Mode B.
        let mut wire = Vec::new();
        write_frame(&mut wire, &WindowsFrame::Shutdown {}).unwrap();
        assert_eq!(
            read_windows(&wire).unwrap(),
            Some(WindowsFrame::Shutdown {})
        );
        let realize = r#"{"t":"realize","id":7,"binding_tag":"b1","generation":2,
            "public":{"certs":[],"ssh_config":"","known_hosts":""},"deadline":"2026-11-18T10:00:00Z"}"#;
        let f = read_windows(&frame_bytes(realize)).unwrap().unwrap();
        assert!(f.is_mode_b());
        assert_eq!(f.mode_b_id(), 7);
        let open = read_windows(&frame_bytes(
            r#"{"t":"open","stream":9,"binding_tag":"b1"}"#,
        ))
        .unwrap()
        .unwrap();
        assert!(open.is_mode_b());
        assert_eq!(open.mode_b_id(), 9);
        assert!(!WindowsFrame::Shutdown {}.is_mode_b());

        // A frame above the bound is not written.
        let huge = HelperFrame::Error {
            id: 1,
            kind: ErrorKind::Unavailable,
            message: "x".repeat(MAX_FRAME),
        };
        assert!(matches!(
            write_frame(&mut Vec::new(), &huge),
            Err(FrameError::Length(_))
        ));
        assert_eq!(bounded_message(&"é".repeat(2000)).len(), MAX_MESSAGE);

        // The sink exchange's rules.
        let mut calls = SinkCalls::new(5);
        assert_eq!(calls.accept(5, 0), Ok(()));
        assert_eq!(calls.accept(5, 1), Ok(()));
        assert_eq!(calls.accept(5, 1), Err(SinkViolation::Sequence), "a repeat");
        assert_eq!(calls.accept(5, 3), Err(SinkViolation::Sequence), "a gap");
        assert_eq!(calls.accept(6, 2), Err(SinkViolation::OutsideRequest));
        let mut many = SinkCalls::new(1);
        for seq in 0..MAX_SINK_CALLS {
            many.accept(1, seq).unwrap();
        }
        assert_eq!(many.accept(1, MAX_SINK_CALLS), Err(SinkViolation::TooMany));
    }

    fn observations() -> Vec<EntryObs> {
        let mut v = vec![EntryObs::Absent, EntryObs::Foreign, EntryObs::Unobservable];
        for which in [
            RecordedRole::S,
            RecordedRole::V,
            RecordedRole::D,
            RecordedRole::Q,
        ] {
            for content in [ContentState::Unchanged, ContentState::Modified] {
                v.push(EntryObs::Recorded { which, content });
            }
        }
        v
    }

    /// The wire mirrors are lossless: every outcome and held step survives JSON and the
    /// conversion back, and a step observation that any recovery state admits is rebuilt with
    /// exactly its three symbols (`StepObservation` has no other constructor).
    #[test]
    fn wire_mirrors_round_trip_losslessly() {
        let all = observations();
        let mut admitted = 0usize;
        for shape in [
            StepShape::Replace,
            StepShape::Removal,
            StepShape::Create,
            StepShape::GitLock,
        ] {
            for source in [
                None,
                Some(SettleSource::Path),
                Some(SettleSource::Staged),
                Some(SettleSource::Displaced),
            ] {
                for restore in [
                    RestoreCtx::NotDue,
                    RestoreCtx::Due(RestoreCause::FileMismatch),
                    RestoreCtx::Done(RestoreCause::TransactionCheck),
                ] {
                    let state = RecoveryState {
                        phase: None,
                        restore,
                        settlement: source.map(|source| SettleCtx {
                            source,
                            create_restore: false,
                        }),
                        item: heimdall_domain::projection::ItemState::Open,
                        release_due: shape == StepShape::GitLock,
                    };
                    for &p in &all {
                        for &a in &all {
                            for &s in &all {
                                let Ok(obs) = StepObservation::normalize(p, a, s, &state, shape)
                                else {
                                    continue;
                                };
                                admitted += 1;
                                let wire = WireObservation {
                                    path: obs.path(),
                                    aside: obs.aside(),
                                    slot: obs.slot(),
                                };
                                let rebuilt = rebuild_observation(&wire)
                                    .unwrap_or_else(|_| panic!("{wire:?} under {shape:?}"));
                                assert_eq!(
                                    (rebuilt.path(), rebuilt.aside(), rebuilt.slot()),
                                    (p, a, s)
                                );
                            }
                        }
                    }
                }
            }
        }
        assert!(admitted > 1000, "{admitted}");

        let held = HeldStep {
            step: 3,
            role: FileRole::GitInclude,
            path_display: "~/.gitconfig".to_owned(),
            reason: HoldReason::ActiveEntryReplaced,
            observed: StepObservation::normalize(
                EntryObs::Foreign,
                EntryObs::Absent,
                EntryObs::Absent,
                &RecoveryState {
                    phase: None,
                    restore: RestoreCtx::NotDue,
                    settlement: None,
                    item: heimdall_domain::projection::ItemState::Open,
                    release_due: false,
                },
                StepShape::Replace,
            )
            .unwrap(),
            fingerprint: StepFingerprint {
                path: heimdall_domain::projection::EntryFingerprint::Absent,
                aside: vec![],
                slot: None,
            },
        };
        let outcomes = vec![
            ItemOutcome::Applied {
                item: ProjectionItem::Git,
                generation: 4,
            },
            ItemOutcome::NotApplied {
                item: ProjectionItem::Git,
                reason: Some(ConflictKind::GitConfigLocked),
            },
            ItemOutcome::Restored {
                item: ProjectionItem::Git,
                reason: None,
            },
            ItemOutcome::ConflictPreserved {
                item: ProjectionItem::Git,
            },
            ItemOutcome::Held {
                item: ProjectionItem::Git,
                steps: vec![held],
            },
        ];
        for o in outcomes {
            let wire = WireItemOutcome::from(&o);
            let json = serde_json::to_string(&wire).unwrap();
            let back: WireItemOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(back, wire);
            assert_eq!(ItemOutcome::try_from(&back).unwrap(), o);
        }
    }

    pub(crate) fn intent_with(roles: &[(FileRole, &str)], generation: u64) -> SetupIntent {
        SetupIntent {
            plan_digest: heimdall_contract::setup::PlanDigest::parse(&"0".repeat(64)).unwrap(),
            intent: PreviewIntent::Apply {
                include_git: false,
                items: [ProjectionItem::DistributionGit].into_iter().collect(),
                distribution: None,
            },
            generation,
            approval: None,
            consent: heimdall_domain::projection::ConsentRecord::default(),
            files: roles
                .iter()
                .map(|(role, path)| heimdall_domain::projection::FileStep {
                    role: *role,
                    path: (*path).to_owned(),
                    base: Base::Absent,
                    target: Target::Absent,
                    content: StepContent::absent(),
                    commit: false,
                    staged_name: None,
                    displaced_name: None,
                })
                .collect(),
            managed_pairs: BTreeSet::new(),
        }
    }

    fn commit_of(
        intent: &SetupIntent,
        namespace: &EnvironmentId,
        files: &[(FileRole, &str)],
    ) -> ItemCommit {
        let locators: Vec<ProjectionLocator> = files
            .iter()
            .map(|(role, path)| ProjectionLocator {
                role: *role,
                path: (*path).to_owned(),
                identity: heimdall_domain::projection::FileIdentity::Unix {
                    dev: 1,
                    ino: 2,
                    birth: None,
                },
                sha256: heimdall_domain::projection::Sha256Hex::parse(&"a".repeat(64)).unwrap(),
            })
            .collect();
        ItemCommit {
            item: ProjectionItem::Git,
            generation: intent.generation,
            resources: locators.clone(),
            record: ProjectionRecord {
                environment: namespace.clone(),
                items: [(
                    ProjectionItem::Git,
                    ItemRecord {
                        generation: intent.generation,
                        files: locators,
                        aliases: vec![],
                        include_file: None,
                        operation: heimdall_contract::ids::OperationId::from_random_bytes([0; 16]),
                        committed_at: heimdall_contract::Timestamp::now(),
                    },
                )]
                .into_iter()
                .collect(),
            },
            consent: heimdall_domain::projection::ConsentRecord::default(),
        }
    }

    /// What Windows validates before it persists anything the helper sent (design §3.5).
    #[test]
    fn helper_sink_calls_are_validated_before_they_are_persisted() {
        let files = [
            (FileRole::GitManaged, "/h/.config/heimdall/gitconfig"),
            (FileRole::GitInclude, "/h/.gitconfig"),
        ];
        let intent = intent_with(&files, 3);
        let ns = EnvironmentId::from_random_bytes([7; 16]);

        let file = |step| LocalReceipt::File {
            step,
            phase: heimdall_domain::operation::FilePhase::Exchanged,
        };
        assert_eq!(validate_receipt(&intent, &file(1)), Ok(()));
        assert_eq!(validate_receipt(&intent, &file(2)), Err(Invalid::Step));
        let item = |item| LocalReceipt::Item {
            item,
            phase: heimdall_domain::operation::ItemPhase::Committed { generation: 3 },
        };
        assert_eq!(
            validate_receipt(&intent, &item(ProjectionItem::Git)),
            Ok(())
        );
        assert_eq!(
            validate_receipt(&intent, &item(ProjectionItem::Ssh)),
            Err(Invalid::Item)
        );

        let good = commit_of(&intent, &ns, &files);
        assert_eq!(validate_commit(&intent, &ns, &good), Ok(()));
        let mut c = good.clone();
        c.item = ProjectionItem::Ssh;
        assert_eq!(validate_commit(&intent, &ns, &c), Err(Invalid::Item));
        let mut c = good.clone();
        c.generation = 4;
        assert_eq!(validate_commit(&intent, &ns, &c), Err(Invalid::Generation));
        let other = EnvironmentId::from_random_bytes([8; 16]);
        assert_eq!(
            validate_commit(&intent, &other, &good),
            Err(Invalid::Environment)
        );
        // A locator for a file the intent has no step for, in `resources` or in the record.
        let mut c = commit_of(
            &intent,
            &ns,
            &[(FileRole::GitManaged, "/elsewhere/gitconfig")],
        );
        assert_eq!(validate_commit(&intent, &ns, &c), Err(Invalid::Resource));
        c = good.clone();
        c.resources.truncate(1);
        c.record
            .items
            .get_mut(&ProjectionItem::Git)
            .unwrap()
            .files
            .push(ProjectionLocator {
                path: "/etc/passwd".to_owned(),
                ..c.resources[0].clone()
            });
        assert_eq!(validate_commit(&intent, &ns, &c), Err(Invalid::Resource));
        // A record that carries another item than the committed one.
        let mut c = good;
        c.record.items.insert(
            ProjectionItem::Ssh,
            c.record.items[&ProjectionItem::Git].clone(),
        );
        assert_eq!(validate_commit(&intent, &ns, &c), Err(Invalid::Record));
    }
}
