//! Heimdall test support (plan §6.1 pure model/property tests, §6.4 fault
//! injection). Never compiled into shipped binaries: only `dev-dependencies` name
//! this crate. Features: `store` (ScriptedFaults), `app` (FakeCredentialAdapter),
//! `managed` (M03: ScratchSecretStore, FakeSessionLockSource); `heimdall-ipc` uses
//! none of them (wave-1 E2).
//!
//! Canary rule (ADR-0004 §4): synthetic canary-format strings may appear in
//! fixtures, test inputs and harness assertions. A canary value appearing in
//! program output, logs, arguments or artifacts is a defect; [`assert_no_canary`]
//! is the shared assertion.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_domain::time::{BootId, Clock, SyncStatus, TimeSync};

/// Prefix of every synthetic canary. Values are generated per run by the test
/// that needs them and never committed.
pub const CANARY_PREFIX: &str = "HEIMDALL_CANARY_";

/// Panics if `output` contains any canary-format string.
pub fn assert_no_canary(output: &str) {
    assert!(!output.contains(CANARY_PREFIX), "canary leaked into output");
}

/// Deterministic three-source clock (ADR-0005 §3.6): wall, boot-scoped continuous
/// time that counts sleep, and a boot ID. Advances only when told.
///
/// * [`advance`](Self::advance): both clocks (normal passage of time, awake).
/// * [`advance_continuous_only`](Self::advance_continuous_only): continuous only
///   (sleep with the wall clock frozen until wake, or a stuck wall clock).
/// * [`set_wall`](Self::set_wall): step the wall clock (forward jump or rollback).
/// * [`reboot`](Self::reboot): new boot ID, continuous time restarts at zero, the
///   wall clock continues from `wall`. A **process restart** needs no clock call:
///   continuous time is boot-scoped and persisted anchors survive.
#[derive(Debug)]
pub struct VirtualClock {
    wall: Mutex<Timestamp>,
    continuous: Mutex<Duration>,
    boot: Mutex<u64>,
}

impl VirtualClock {
    /// Start at `wall`, continuous zero, boot 1.
    #[must_use]
    pub fn at(wall: Timestamp) -> Arc<Self> {
        Arc::new(Self {
            wall: Mutex::new(wall),
            continuous: Mutex::new(Duration::ZERO),
            boot: Mutex::new(1),
        })
    }

    /// Advance both clocks together.
    pub fn advance(&self, by: Duration) {
        let span = jiff::SignedDuration::try_from(by).expect("duration fits");
        let mut w = self.wall.lock().unwrap();
        *w = w.checked_add(span).expect("timestamp in range");
        *self.continuous.lock().unwrap() += by;
    }

    /// Advance only the continuous clock (wall frozen).
    pub fn advance_continuous_only(&self, by: Duration) {
        *self.continuous.lock().unwrap() += by;
    }

    /// Set wall time arbitrarily without touching the continuous clock.
    pub fn set_wall(&self, wall: Timestamp) {
        *self.wall.lock().unwrap() = wall;
    }

    /// Reboot: new boot ID, continuous restarts at zero, wall set to `wall`.
    pub fn reboot(&self, wall: Timestamp) {
        *self.boot.lock().unwrap() += 1;
        *self.continuous.lock().unwrap() = Duration::ZERO;
        *self.wall.lock().unwrap() = wall;
    }
}

impl Clock for VirtualClock {
    fn wall(&self) -> Timestamp {
        *self.wall.lock().unwrap()
    }
    fn continuous(&self) -> Duration {
        *self.continuous.lock().unwrap()
    }
    fn boot_id(&self) -> BootId {
        BootId(format!("virtual-boot-{}", *self.boot.lock().unwrap()))
    }
}

/// Scripted synchronization report.
#[derive(Debug)]
pub struct ScriptedTimeSync {
    status: Mutex<SyncStatus>,
}

impl ScriptedTimeSync {
    /// New with an initial status.
    #[must_use]
    pub fn new(status: SyncStatus) -> Arc<Self> {
        Arc::new(Self {
            status: Mutex::new(status),
        })
    }

    /// Change the reported status.
    pub fn set(&self, status: SyncStatus) {
        *self.status.lock().unwrap() = status;
    }
}

impl TimeSync for ScriptedTimeSync {
    fn status(&self) -> SyncStatus {
        *self.status.lock().unwrap()
    }
}

#[cfg(feature = "store")]
mod faults {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use heimdall_store::{FaultAction, FaultHook, FaultPoint};

    /// Scripted store fault hook: a queue of `(point, action)`; unmatched points
    /// continue. Records every point visited for assertions.
    #[derive(Debug, Default)]
    pub struct ScriptedFaults {
        script: Mutex<VecDeque<(FaultPoint, FaultAction)>>,
        visited: Mutex<Vec<FaultPoint>>,
    }

    impl ScriptedFaults {
        /// New with a script.
        #[must_use]
        pub fn new(script: impl IntoIterator<Item = (FaultPoint, FaultAction)>) -> Arc<Self> {
            Arc::new(Self {
                script: Mutex::new(script.into_iter().collect()),
                visited: Mutex::new(Vec::new()),
            })
        }

        /// Points visited so far.
        #[must_use]
        pub fn visited(&self) -> Vec<FaultPoint> {
            self.visited.lock().unwrap().clone()
        }
    }

    impl FaultHook for ScriptedFaults {
        fn at(&self, point: FaultPoint) -> FaultAction {
            self.visited.lock().unwrap().push(point);
            let mut script = self.script.lock().unwrap();
            match script.front() {
                Some((p, _)) if *p == point => script
                    .pop_front()
                    .map(|(_, a)| a)
                    .unwrap_or(FaultAction::Continue),
                _ => FaultAction::Continue,
            }
        }
    }
}

#[cfg(feature = "store")]
pub use faults::ScriptedFaults;

#[cfg(feature = "app")]
mod fake_adapter {
    use std::collections::{BTreeMap, VecDeque};
    use std::io::{BufRead, Write};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use heimdall_app::ensure::{EnsureStage, StageHook};
    use heimdall_app::ports::{
        AdapterDescriptor, AdapterError, CredentialAdapter, IntegrationSnapshot, PrepareOutcome,
        PreparePair, PrepareRequest, ReconcileOutcome, RevokeOutcome,
    };
    use heimdall_contract::Timestamp;
    use heimdall_contract::ids::GrantId;

    /// One scripted adapter response.
    ///
    /// ⟨M02⟩ U0b row 24 (M2-T06) adds the hang steps. A hung call waits until
    /// [`FakeCredentialAdapter::release_hangs`]; a runtime that bounds the call drops
    /// its future first, so a released hang that is still awaited (and therefore does
    /// more work) is counted by [`FakeCredentialAdapter::work_after_drop`]. The two
    /// prepare steps go in the `prepare` script; `HangReconcile` and `HangRevoke` are
    /// armed for the next `reconcile` or `revoke` call with
    /// [`FakeCredentialAdapter::arm`] (in the prepare script they are refused with
    /// `Unavailable`).
    #[derive(Debug, Clone)]
    pub enum FakeStep {
        /// Succeed with these facts.
        Prepare(PrepareOutcome),
        /// Fail with this error.
        Fail(AdapterError),
        /// Perform the effect but report `OutcomeUnknown` (lost acknowledgment);
        /// `reconcile` later answers `Applied`.
        ApplyButLoseReply(PrepareOutcome),
        /// ⟨M02⟩ Apply the effect (recorded as for `Prepare`, so `reconcile` answers
        /// `Applied`), then never return until released.
        ApplyThenHang(PrepareOutcome),
        /// ⟨M02⟩ Hang before any effect. Only a released hang that is still awaited
        /// applies the effect, which is late work.
        HangBeforeEffect(PrepareOutcome),
        /// ⟨M02⟩ The next `reconcile` hangs, then answers as usual if released.
        HangReconcile,
        /// ⟨M02⟩ The next `revoke` hangs, then revokes as usual if released.
        HangRevoke,
    }

    /// ⟨M02⟩ One entry of the fake's ordered journal (U0b row 24: "the call follows
    /// the effect in the fake's ledger").
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FakeEvent {
        /// An effect was applied under this token.
        Effect(String),
        /// A `revoke` call for this grant returned.
        Revoke(GrantId),
    }

    /// ⟨M02⟩ The release gate every hung call waits on, and its counters.
    #[derive(Debug, Default)]
    struct Hangs {
        /// Released generations and the wakers of the hung calls.
        state: Mutex<(u64, Vec<std::task::Waker>)>,
        /// Hangs entered.
        entered: AtomicUsize,
        /// Hangs whose future was dropped before it was released.
        dropped: AtomicUsize,
        /// Work done by hangs that were released while their future was still awaited.
        late: AtomicUsize,
        /// Armed reconcile and revoke hangs.
        reconcile: AtomicUsize,
        revoke: AtomicUsize,
    }

    /// ⟨M02⟩ One hung call: pending until the gate's generation moves past the one it
    /// started in. Counts itself dropped when dropped before that.
    struct Hang<'a> {
        hangs: &'a Hangs,
        generation: u64,
        done: bool,
    }

    impl std::future::Future for Hang<'_> {
        type Output = ();

        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            let mut state = self.hangs.state.lock().unwrap();
            if state.0 > self.generation {
                drop(state);
                self.done = true;
                return std::task::Poll::Ready(());
            }
            state.1.push(cx.waker().clone());
            std::task::Poll::Pending
        }
    }

    impl Drop for Hang<'_> {
        fn drop(&mut self) {
            if !self.done {
                self.hangs.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    impl Hangs {
        fn hang(&self) -> Hang<'_> {
            self.entered.fetch_add(1, Ordering::SeqCst);
            Hang {
                hangs: self,
                generation: self.state.lock().unwrap().0,
                done: false,
            }
        }

        fn take(counter: &AtomicUsize) -> bool {
            counter
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        }
    }

    /// Fake credential adapter with a response script and side-effect counters
    /// (plan §6.4 "add a canary side effect and count actual remote changes").
    /// Effects are keyed by `effect_token`: a repeated token never counts twice.
    ///
    /// **Durable effect ledger** (ADR-0006 §13.4 N06). [`Self::new`] keeps effects
    /// in memory only, so a new instance knows nothing of an earlier one's effects:
    /// that models an in-process reconstruction at best. [`Self::with_ledger`]
    /// stands in for the external system: every applied effect is appended (and
    /// `fsync`ed) to a disposable file **before** `prepare` returns, keyed by
    /// `effect_token`, and every `prepare`/`reconcile`/`effect_count` re-reads the
    /// file. The ledger survives the death of the process that wrote it, so a new
    /// adapter instance in a restarted service reports `reconcile → Applied` for an
    /// effect recorded before the crash. One writer at a time is assumed; on read
    /// the first record of a token wins. Use only a file inside a test's own temp
    /// directory.
    pub struct FakeCredentialAdapter {
        descriptor: AdapterDescriptor,
        script: Mutex<VecDeque<FakeStep>>,
        /// Effects actually applied, by token (counts "remote changes"). With a
        /// ledger, a cache of the ledger refreshed on every adapter call.
        pub effects: Mutex<BTreeMap<String, PrepareOutcome>>,
        /// Revocations applied.
        pub revocations: Mutex<Vec<GrantId>>,
        ledger: Option<PathBuf>,
        /// ⟨M02⟩ U0b row 24: hung calls and their counters.
        hangs: Hangs,
        /// ⟨M02⟩ Effects and revocations, in order.
        journal: Mutex<Vec<FakeEvent>>,
        /// ⟨M02⟩ ADR-0007 §12.30 item 1: the `interactive` flag of every `prepare`
        /// call, in order.
        interactive_flags: Mutex<Vec<bool>>,
    }

    /// One ledger line: the effect token and the outcome the effect produced.
    fn ledger_line(token: &str, out: &PrepareOutcome) -> String {
        let mut line = serde_json::json!({
            "effect_token": token,
            "usable_until": out.usable_until,
            "offline_until": out.offline_until,
            "refresh_dependency": out.refresh_dependency,
            "enforcement": out.enforcement,
            "credential_ref": out.credential_ref,
            // ⟨M02⟩ U0b row 15: the outcome's new fields survive a restart too.
            "availability": out.availability,
            "provider": out.provider,
            "integration": out.integration,
        })
        .to_string();
        line.push('\n');
        line
    }

    fn bad(e: serde_json::Error) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }

    fn parse_line(line: &str) -> std::io::Result<(String, PrepareOutcome)> {
        let v: serde_json::Value = serde_json::from_str(line).map_err(bad)?;
        let get = |k: &str| v[k].clone();
        // ⟨M02⟩ A field an older ledger line lacks reads as its default.
        let present = |k: &str| v.get(k).is_some_and(|x| !x.is_null());
        Ok((
            serde_json::from_value(get("effect_token")).map_err(bad)?,
            PrepareOutcome {
                usable_until: serde_json::from_value(get("usable_until")).map_err(bad)?,
                offline_until: serde_json::from_value(get("offline_until")).map_err(bad)?,
                refresh_dependency: serde_json::from_value(get("refresh_dependency"))
                    .map_err(bad)?,
                enforcement: serde_json::from_value(get("enforcement")).map_err(bad)?,
                credential_ref: serde_json::from_value(get("credential_ref")).map_err(bad)?,
                availability: if present("availability") {
                    serde_json::from_value(get("availability")).map_err(bad)?
                } else {
                    Default::default()
                },
                provider: serde_json::from_value(get("provider")).map_err(bad)?,
                integration: if present("integration") {
                    serde_json::from_value(get("integration")).map_err(bad)?
                } else {
                    Default::default()
                },
            },
        ))
    }

    /// Every complete record in a ledger file, in append order (duplicates kept,
    /// so a double application is visible). A torn final line without its newline
    /// (a writer killed mid-append) is not a record.
    fn read_ledger(path: &Path) -> std::io::Result<Vec<(String, PrepareOutcome)>> {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut reader = std::io::BufReader::new(file);
        let mut out = Vec::new();
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 || !line.ends_with('\n') {
                break;
            }
            out.push(parse_line(line.trim_end())?);
        }
        Ok(out)
    }

    impl std::fmt::Debug for FakeCredentialAdapter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FakeCredentialAdapter")
                .field("mechanism", &self.descriptor.identity.mechanism)
                .finish_non_exhaustive()
        }
    }

    impl FakeCredentialAdapter {
        /// New fake with a descriptor and a script. An exhausted script repeats its
        /// last step; an empty script fails with `Unavailable`.
        #[must_use]
        pub fn new(
            descriptor: AdapterDescriptor,
            script: impl IntoIterator<Item = FakeStep>,
        ) -> Arc<Self> {
            Arc::new(Self {
                descriptor,
                script: Mutex::new(script.into_iter().collect()),
                effects: Mutex::new(BTreeMap::new()),
                revocations: Mutex::new(Vec::new()),
                ledger: None,
                hangs: Hangs::default(),
                journal: Mutex::new(Vec::new()),
                interactive_flags: Mutex::new(Vec::new()),
            })
        }

        /// ⟨M02⟩ U0b row 24: arm a step for the next call. `HangReconcile` and
        /// `HangRevoke` make the next `reconcile` or `revoke` hang (each arming
        /// counts once); any other step goes to the front of the `prepare` script.
        pub fn arm(&self, step: FakeStep) {
            match step {
                FakeStep::HangReconcile => {
                    self.hangs.reconcile.fetch_add(1, Ordering::SeqCst);
                }
                FakeStep::HangRevoke => {
                    self.hangs.revoke.fetch_add(1, Ordering::SeqCst);
                }
                other => self.script.lock().unwrap().push_front(other),
            }
        }

        /// ⟨M02⟩ Release every call hung so far. A call still awaited then finishes
        /// and its work is counted by [`Self::work_after_drop`].
        pub fn release_hangs(&self) {
            let wakers = {
                let mut state = self.hangs.state.lock().unwrap();
                state.0 += 1;
                std::mem::take(&mut state.1)
            };
            for w in wakers {
                w.wake();
            }
        }

        /// ⟨M02⟩ Calls that entered a hang.
        #[must_use]
        pub fn hangs_entered(&self) -> usize {
            self.hangs.entered.load(Ordering::SeqCst)
        }

        /// ⟨M02⟩ Hung calls whose future was dropped before being released.
        #[must_use]
        pub fn hangs_dropped(&self) -> usize {
            self.hangs.dropped.load(Ordering::SeqCst)
        }

        /// ⟨M02⟩ Work done after a hang was released by a call whose future was
        /// still awaited. A runtime that drops the future when its bound elapses
        /// (U0b row 24) keeps this at 0.
        #[must_use]
        pub fn work_after_drop(&self) -> usize {
            self.hangs.late.load(Ordering::SeqCst)
        }

        /// ⟨M02⟩ ADR-0007 §12.30 item 1: the `interactive` flag of every `prepare` call.
        #[must_use]
        pub fn interactive_flags(&self) -> Vec<bool> {
            self.interactive_flags.lock().unwrap().clone()
        }

        /// ⟨M02⟩ Effects and revocations, in order.
        #[must_use]
        pub fn journal(&self) -> Vec<FakeEvent> {
            self.journal.lock().unwrap().clone()
        }

        /// New fake whose effects are recorded in the durable, append-only ledger
        /// at `path` (created if missing) and read back from it, so effects survive
        /// the death of the process (ADR-0006 §13.4 N06). Several instances, in one
        /// process or across a kill and restart, over the same `path` see the same
        /// effects. Errors only when the file cannot be created or holds a malformed
        /// record.
        pub fn with_ledger(
            descriptor: AdapterDescriptor,
            script: impl IntoIterator<Item = FakeStep>,
            path: impl Into<PathBuf>,
        ) -> std::io::Result<Arc<Self>> {
            let path = path.into();
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            let adapter = Self {
                descriptor,
                script: Mutex::new(script.into_iter().collect()),
                effects: Mutex::new(BTreeMap::new()),
                revocations: Mutex::new(Vec::new()),
                ledger: Some(path),
                hangs: Hangs::default(),
                journal: Mutex::new(Vec::new()),
                interactive_flags: Mutex::new(Vec::new()),
            };
            adapter.refresh()?;
            Ok(Arc::new(adapter))
        }

        /// The effect tokens recorded in the ledger at `path`, in append order,
        /// duplicates kept (`len() == 1` is "exactly one effect"). For process-crash
        /// tests that count effects after the service was killed and restarted.
        pub fn ledger_entries(path: impl AsRef<Path>) -> std::io::Result<Vec<String>> {
            Ok(read_ledger(path.as_ref())?
                .into_iter()
                .map(|(token, _)| token)
                .collect())
        }

        /// Number of distinct effects applied (re-read from the ledger when there
        /// is one).
        #[must_use]
        pub fn effect_count(&self) -> usize {
            self.refresh().expect("ledger readable");
            self.effects.lock().unwrap().len()
        }

        /// Reload the cache from the ledger (no-op without one). First record wins.
        fn refresh(&self) -> std::io::Result<()> {
            let Some(path) = &self.ledger else {
                return Ok(());
            };
            let records = read_ledger(path)?;
            let mut effects = self.effects.lock().unwrap();
            for (token, out) in records {
                effects.entry(token).or_insert(out);
            }
            Ok(())
        }

        /// Record an applied effect: durably in the ledger first (when there is
        /// one), then in memory.
        fn record(&self, token: &str, out: &PrepareOutcome) -> Result<(), AdapterError> {
            if let Some(path) = &self.ledger {
                let io = |e: std::io::Error| {
                    AdapterError::Unavailable(format!("fake ledger: {}", e.kind()))
                };
                let mut file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(path)
                    .map_err(io)?;
                file.write_all(ledger_line(token, out).as_bytes())
                    .map_err(io)?;
                file.sync_data().map_err(io)?;
            }
            self.effects
                .lock()
                .unwrap()
                .insert(token.to_owned(), out.clone());
            self.journal
                .lock()
                .unwrap()
                .push(FakeEvent::Effect(token.to_owned()));
            Ok(())
        }

        /// ⟨M02⟩ Wait at the release gate; a hang that returns was released while
        /// still awaited, so whatever its call does next is late work.
        async fn hang(&self) {
            self.hangs.hang().await;
            self.hangs.late.fetch_add(1, Ordering::SeqCst);
        }

        fn refreshed(&self) -> Result<(), AdapterError> {
            self.refresh()
                .map_err(|e| AdapterError::Unavailable(format!("fake ledger: {}", e.kind())))
        }

        fn next_step(&self) -> FakeStep {
            let mut s = self.script.lock().unwrap();
            if s.len() > 1 {
                s.pop_front().expect("non-empty")
            } else {
                s.front()
                    .cloned()
                    .unwrap_or(FakeStep::Fail(AdapterError::Unavailable(
                        "empty script".into(),
                    )))
            }
        }
    }

    #[async_trait]
    impl CredentialAdapter for FakeCredentialAdapter {
        fn descriptor(&self) -> &AdapterDescriptor {
            &self.descriptor
        }

        async fn prepare(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
            self.interactive_flags.lock().unwrap().push(req.interactive);
            self.refreshed()?;
            if let Some(done) = self.effects.lock().unwrap().get(req.effect_token) {
                return Ok(done.clone());
            }
            match self.next_step() {
                FakeStep::Prepare(out) => {
                    self.record(req.effect_token, &out)?;
                    Ok(out)
                }
                FakeStep::ApplyButLoseReply(out) => {
                    self.record(req.effect_token, &out)?;
                    Err(AdapterError::OutcomeUnknown("reply lost".into()))
                }
                FakeStep::Fail(e) => Err(e),
                FakeStep::ApplyThenHang(out) => {
                    self.record(req.effect_token, &out)?;
                    self.hang().await;
                    Ok(out)
                }
                FakeStep::HangBeforeEffect(out) => {
                    self.hang().await;
                    self.record(req.effect_token, &out)?;
                    Ok(out)
                }
                FakeStep::HangReconcile | FakeStep::HangRevoke => Err(AdapterError::Unavailable(
                    "a reconcile or revoke hang is armed, not scripted".into(),
                )),
            }
        }

        /// ⟨M02⟩ ADR-0007 §12.26 item 2: the fake reads no source.
        fn read_sources(&self, _pairs: &[PreparePair]) -> IntegrationSnapshot {
            IntegrationSnapshot::default()
        }

        /// ⟨M02⟩ ADR-0007 §12.26 item 2: the fake's `prepare`, which reads only its
        /// own script and ledger (the snapshot is empty).
        async fn prepare_from(
            &self,
            req: PrepareRequest<'_>,
            _sources: &IntegrationSnapshot,
        ) -> Result<PrepareOutcome, AdapterError> {
            self.prepare(req).await
        }

        async fn renew(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
            self.prepare(req).await
        }

        async fn reconcile(
            &self,
            _grant: &GrantId,
            effect_token: &str,
        ) -> Result<ReconcileOutcome, AdapterError> {
            if Hangs::take(&self.hangs.reconcile) {
                self.hang().await;
            }
            self.refreshed()?;
            Ok(match self.effects.lock().unwrap().get(effect_token) {
                Some(out) => ReconcileOutcome::Applied(out.clone()),
                None => ReconcileOutcome::NotApplied,
            })
        }

        async fn revoke(
            &self,
            grant: &GrantId,
            _now: Timestamp,
        ) -> Result<RevokeOutcome, AdapterError> {
            if Hangs::take(&self.hangs.revoke) {
                self.hang().await;
            }
            self.revocations.lock().unwrap().push(grant.clone());
            self.journal
                .lock()
                .unwrap()
                .push(FakeEvent::Revoke(grant.clone()));
            Ok(RevokeOutcome {
                remote_pending: Vec::new(),
                latest_possible_credential_expiry: None,
                remote_effects: Vec::new(), // M03 wave 0 (A2)
            })
        }
    }

    /// Scripted pipeline hook: fail `before`/`after` the named stage with a code
    /// once; records visits (plan §6.4; review F09).
    #[derive(Debug, Default)]
    pub struct ScriptedStageHook {
        before: Mutex<BTreeMap<EnsureStage, heimdall_contract::Code>>,
        after: Mutex<BTreeMap<EnsureStage, heimdall_contract::Code>>,
        /// Stages visited as `(stage, "before"|"after")`.
        pub visited: Mutex<Vec<(EnsureStage, &'static str)>>,
    }

    impl ScriptedStageHook {
        /// New hook with failures before and after the given stages.
        #[must_use]
        pub fn new(
            before: impl IntoIterator<Item = (EnsureStage, heimdall_contract::Code)>,
            after: impl IntoIterator<Item = (EnsureStage, heimdall_contract::Code)>,
        ) -> Arc<Self> {
            Arc::new(Self {
                before: Mutex::new(before.into_iter().collect()),
                after: Mutex::new(after.into_iter().collect()),
                visited: Mutex::new(Vec::new()),
            })
        }
    }

    impl StageHook for ScriptedStageHook {
        fn before(&self, stage: EnsureStage) -> Result<(), heimdall_contract::Code> {
            self.visited.lock().unwrap().push((stage, "before"));
            match self.before.lock().unwrap().remove(&stage) {
                Some(code) => Err(code),
                None => Ok(()),
            }
        }
        fn after(&self, stage: EnsureStage) -> Result<(), heimdall_contract::Code> {
            self.visited.lock().unwrap().push((stage, "after"));
            match self.after.lock().unwrap().remove(&stage) {
                Some(code) => Err(code),
                None => Ok(()),
            }
        }
    }
}

#[cfg(feature = "app")]
pub use fake_adapter::{FakeCredentialAdapter, FakeEvent, FakeStep, ScriptedStageHook};

/// N06 (ADR-0006 §13.4): the durable effect ledger. The in-process cases build a
/// second adapter instance in the same process (labelled **in-process**); the
/// child-process case kills a real process after the effect (process death).
#[cfg(all(test, feature = "app"))]
mod ledger_tests {
    use std::collections::BTreeSet;
    use std::future::Future;
    use std::path::Path;
    use std::task::{Context, Poll, Waker};

    use heimdall_app::ports::{
        AdapterDescriptor, AdapterError, CredentialAdapter, InteractionRequirement, LockContinuity,
        PrepareOutcome, PrepareRequest, ReconcileOutcome,
    };
    use heimdall_contract::ids::{EnvironmentId, GrantId};
    use heimdall_contract::request::{DeadlineIntent, RefreshDependency, RequiredCapabilities};
    use heimdall_contract::{GrantState, Timestamp};
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::grant::{AuthorizationSource, GrantSnapshot};
    use heimdall_domain::operation::AdapterIdentity;
    use heimdall_domain::policy::{AuthorityGeneration, PolicyRevision};
    use heimdall_domain::scope::Scope;
    use heimdall_domain::time::Deadline;

    use super::{FakeCredentialAdapter, FakeStep, assert_no_canary};

    /// The fake's futures never pend; poll once with a no-op waker.
    fn ready<F: Future>(f: F) -> F::Output {
        let mut f = std::pin::pin!(f);
        match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("fake adapter future pended"),
        }
    }

    fn t0() -> Timestamp {
        "2026-10-02T09:00:00Z".parse().unwrap()
    }

    fn descriptor() -> AdapterDescriptor {
        AdapterDescriptor {
            identity: AdapterIdentity {
                mechanism: "fake".into(),
                instance: "ledger".into(),
            },
            capabilities: BTreeSet::new(),
            external_side_effects: true,
            interaction: InteractionRequirement::None,
            enforcement: EnforcementEvidence::unknown(),
            lock_continuity: LockContinuity::Unknown,
            remote_credential_effect: false, // M03 wave 0 (A2)
        }
    }

    fn outcome() -> PrepareOutcome {
        PrepareOutcome {
            usable_until: t0(),
            offline_until: t0(),
            refresh_dependency: RefreshDependency::None,
            enforcement: EnforcementEvidence::unknown(),
            credential_ref: "cred-ref-1".into(),
            availability: Default::default(),
            provider: None,
            integration: Default::default(),
        }
    }

    fn grant() -> GrantSnapshot {
        GrantSnapshot {
            id: GrantId::from_random_bytes([1; 16]),
            environment: EnvironmentId::from_random_bytes([2; 16]),
            scope: Scope::empty(),
            starts_at: t0(),
            deadline: Deadline {
                intent: DeadlineIntent::Duration("PT1H".into()),
                resolved_at: t0(),
                effective: t0(),
            },
            parent: None,
            source: AuthorizationSource::StandingPolicy {
                revision: PolicyRevision(1),
            },
            generation: AuthorityGeneration(1),
            state: GrantState::Preparing,
            enforcement: EnforcementEvidence::unknown(),
        }
    }

    fn prepare(
        a: &FakeCredentialAdapter,
        g: &GrantSnapshot,
        token: &str,
    ) -> Result<PrepareOutcome, AdapterError> {
        let required = RequiredCapabilities::default();
        ready(a.prepare(PrepareRequest {
            grant: g,
            scope: &g.scope,
            required: &required,
            interactive: false,
            effect_token: token,
            now: t0(),
            pairs: &[],
        }))
    }

    #[test]
    fn in_process_new_instance_over_the_same_ledger_reconciles_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("effects.ledger");
        let g = grant();
        {
            let a = FakeCredentialAdapter::with_ledger(
                descriptor(),
                [FakeStep::ApplyButLoseReply(outcome())],
                &path,
            )
            .unwrap();
            assert!(matches!(
                prepare(&a, &g, "eff_1"),
                Err(AdapterError::OutcomeUnknown(_))
            ));
            assert_eq!(a.effect_count(), 1);
        } // instance dropped (in-process reconstruction, not a process crash)
        let b = FakeCredentialAdapter::with_ledger(descriptor(), [], &path).unwrap();
        assert_eq!(
            ready(b.reconcile(&g.id, "eff_1")).unwrap(),
            ReconcileOutcome::Applied(outcome())
        );
        assert_eq!(
            ready(b.reconcile(&g.id, "eff_other")).unwrap(),
            ReconcileOutcome::NotApplied
        );
        // A retried prepare with the same token returns the recorded effect and
        // applies nothing new (the empty script would fail if consulted).
        assert_eq!(prepare(&b, &g, "eff_1").unwrap(), outcome());
        assert_eq!(b.effect_count(), 1);
        assert_eq!(
            FakeCredentialAdapter::ledger_entries(&path).unwrap(),
            ["eff_1"]
        );
        // Contrast: a memory-only fake knows nothing of it.
        let fresh = FakeCredentialAdapter::new(descriptor(), []);
        assert_eq!(
            ready(fresh.reconcile(&g.id, "eff_1")).unwrap(),
            ReconcileOutcome::NotApplied
        );
        let raw = std::fs::read_to_string(&path).unwrap();
        assert_no_canary(&raw);
    }

    #[test]
    fn two_live_instances_share_effects_through_the_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("effects.ledger");
        let g = grant();
        let a =
            FakeCredentialAdapter::with_ledger(descriptor(), [FakeStep::Prepare(outcome())], &path)
                .unwrap();
        let b =
            FakeCredentialAdapter::with_ledger(descriptor(), [FakeStep::Prepare(outcome())], &path)
                .unwrap();
        prepare(&a, &g, "eff_1").unwrap();
        // `b` was built before the effect; it sees it on its next call.
        assert_eq!(prepare(&b, &g, "eff_1").unwrap(), outcome());
        prepare(&b, &g, "eff_2").unwrap();
        assert_eq!(a.effect_count(), 2);
        assert_eq!(
            FakeCredentialAdapter::ledger_entries(&path).unwrap(),
            ["eff_1", "eff_2"]
        );
    }

    #[test]
    fn torn_final_record_is_not_an_effect_and_malformed_records_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("effects.ledger");
        let g = grant();
        let a =
            FakeCredentialAdapter::with_ledger(descriptor(), [FakeStep::Prepare(outcome())], &path)
                .unwrap();
        prepare(&a, &g, "eff_1").unwrap();
        // A writer killed mid-append leaves a line without its newline.
        let mut raw = std::fs::read_to_string(&path).unwrap();
        raw.push_str("{\"effect_token\":\"eff_2\",\"usab");
        std::fs::write(&path, &raw).unwrap();
        assert_eq!(
            FakeCredentialAdapter::ledger_entries(&path).unwrap(),
            ["eff_1"]
        );
        // A complete but malformed record is an error, never silently skipped.
        let bad = dir.path().join("bad.ledger");
        std::fs::write(&bad, "not json\n").unwrap();
        assert!(FakeCredentialAdapter::with_ledger(descriptor(), [], &bad).is_err());
        assert!(FakeCredentialAdapter::ledger_entries(&bad).is_err());
        // Missing file: no entries.
        assert!(
            FakeCredentialAdapter::ledger_entries(dir.path().join("none"))
                .unwrap()
                .is_empty()
        );
    }

    const CHILD_ENV: &str = "HEIMDALL_TESTKIT_LEDGER_CHILD";

    /// Child half of the process-death test: when `CHILD_ENV` names a ledger, apply
    /// one effect (reply lost), then wait to be killed (bounded: it exits by itself
    /// after 60 s). Without the variable (a normal test run) it does nothing.
    #[test]
    fn ledger_child_process_helper() {
        let Some(path) = std::env::var_os(CHILD_ENV) else {
            return;
        };
        let a = FakeCredentialAdapter::with_ledger(
            descriptor(),
            [FakeStep::ApplyButLoseReply(outcome())],
            Path::new(&path),
        )
        .unwrap();
        let _ = prepare(&a, &grant(), "eff_crash");
        std::thread::sleep(std::time::Duration::from_secs(60));
        std::process::exit(3);
    }

    /// Process death (not in-process): a child process applies the effect and is
    /// killed (through its own `Child` handle, so exactly that process) before any
    /// receipt; a new adapter instance in this process, over the same ledger,
    /// reconciles `Applied`, and a retry adds no second effect.
    #[test]
    fn effect_survives_the_death_of_the_process_that_applied_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("effects.ledger");
        let exe = std::env::current_exe().unwrap();
        let mut child = std::process::Command::new(exe)
            .args([
                "--exact",
                "ledger_tests::ledger_child_process_helper",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, &path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while FakeCredentialAdapter::ledger_entries(&path)
            .unwrap()
            .is_empty()
        {
            assert!(
                std::time::Instant::now() < deadline,
                "child never applied the effect"
            );
            assert!(child.try_wait().unwrap().is_none(), "child ended early");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        child.kill().unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(!out.status.success(), "the child must have been killed");
        assert_no_canary(&String::from_utf8_lossy(&out.stdout));
        assert_no_canary(&String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            FakeCredentialAdapter::ledger_entries(&path).unwrap(),
            ["eff_crash"]
        );
        let g = grant();
        let b = FakeCredentialAdapter::with_ledger(descriptor(), [], &path).unwrap();
        assert_eq!(
            ready(b.reconcile(&g.id, "eff_crash")).unwrap(),
            ReconcileOutcome::Applied(outcome())
        );
        assert_eq!(prepare(&b, &g, "eff_crash").unwrap(), outcome());
        assert_eq!(
            FakeCredentialAdapter::ledger_entries(&path).unwrap(),
            ["eff_crash"],
            "exactly one effect"
        );
    }
}

// ADR-0007 §12.32 item 3: the repository root (`HM_REPO_ROOT`) for every test that reads
// repository files. No feature: every test graph has it.
pub mod repo;

// M02-U7 process fixtures (m02-plan §0, U7; ADR-0007 §9). Feature `fixtures`.
#[cfg(feature = "fixtures")]
pub mod agent;
#[cfg(feature = "fixtures")]
pub mod home;
#[cfg(feature = "fixtures")]
pub mod hook;
#[cfg(feature = "fixtures")]
pub mod sshd;
// ADR-0007 §12.32 item 9: the e2e pty cases' session starts with the default terminal
// signal dispositions, whatever the test runner ignored.
#[cfg(all(unix, feature = "fixtures"))]
pub mod term;

// M03 test-configuration gates (m03-plan U0 "Frozen in wave 0"; ADR-0008 D1, D9; F23).
// Feature `managed`: `ScratchSecretStore` (body U4's) and `FakeSessionLockSource`.
#[cfg(feature = "managed")]
pub mod scratch_store;
#[cfg(feature = "managed")]
pub mod session_lock;

/// Proptest strategies for domain values (plan §6.3). Seeds: tests set
/// `ProptestConfig { cases, .. }` and commit `proptest-regressions/` files; the
/// harness prints the seed on failure, which is reproducible with
/// `PROPTEST_RNG_SEED` or the regression file.
pub mod strategies {
    use heimdall_contract::ids::{AccountName, DestinationId};
    use heimdall_contract::request::Capability;
    use heimdall_domain::scope::{AccessPair, Scope};
    use proptest::prelude::*;

    /// Small universe of destinations so intersections are interesting.
    pub fn access_pair() -> impl Strategy<Value = AccessPair> {
        (0u8..6, 0u8..3).prop_map(|(d, a)| AccessPair {
            destination: DestinationId::parse(&format!("h{d}")).expect("valid"),
            account: AccountName::parse(&format!("u{a}")).expect("valid"),
        })
    }

    /// Capability.
    pub fn capability() -> impl Strategy<Value = Capability> {
        prop_oneof![
            Just(Capability::SshAuthentication),
            Just(Capability::GitSigning),
            Just(Capability::AgentForwarding)
        ]
    }

    /// Scope with 0..8 pairs and 0..3 capabilities.
    pub fn scope() -> impl Strategy<Value = Scope> {
        (
            prop::collection::btree_set(access_pair(), 0..8),
            prop::collection::btree_set(capability(), 0..3),
        )
            .prop_map(|(pairs, capabilities)| Scope {
                pairs,
                capabilities,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_clock_sleeps_restarts_and_reboots() {
        let t0: Timestamp = "2026-10-01T00:00:00Z".parse().unwrap();
        let c = VirtualClock::at(t0);
        let b1 = c.boot_id();
        c.advance(Duration::from_secs(60));
        c.advance_continuous_only(Duration::from_secs(60));
        assert_eq!(c.continuous(), Duration::from_secs(120));
        assert_eq!(
            c.wall(),
            t0.checked_add(jiff::SignedDuration::from_secs(60)).unwrap()
        );
        c.set_wall(t0);
        assert_eq!(c.wall(), t0);
        assert_eq!(c.boot_id(), b1);
        c.reboot(t0);
        assert_ne!(c.boot_id(), b1);
        assert_eq!(c.continuous(), Duration::ZERO);
    }

    #[cfg(feature = "store")]
    #[test]
    fn scripted_faults_match_in_order() {
        use heimdall_store::{FaultAction, FaultHook, FaultPoint};
        let f = ScriptedFaults::new([(FaultPoint::BeforeCommit, FaultAction::Fail)]);
        assert_eq!(f.at(FaultPoint::BeforeTransaction), FaultAction::Continue);
        assert_eq!(f.at(FaultPoint::BeforeCommit), FaultAction::Fail);
        assert_eq!(f.at(FaultPoint::BeforeCommit), FaultAction::Continue);
        assert_eq!(f.visited().len(), 3);
    }
}
