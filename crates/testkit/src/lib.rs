//! Heimdall test support (plan §6.1 pure model/property tests, §6.4 fault
//! injection). Never compiled into shipped binaries: only `dev-dependencies` name
//! this crate. Features: `store` (ScriptedFaults), `app` (FakeCredentialAdapter);
//! `heimdall-ipc` uses neither (wave-1 E2).
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
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use heimdall_app::ensure::{EnsureStage, StageHook};
    use heimdall_app::ports::{
        AdapterDescriptor, AdapterError, CredentialAdapter, PrepareOutcome, PrepareRequest,
        ReconcileOutcome, RevokeOutcome,
    };
    use heimdall_contract::Timestamp;
    use heimdall_contract::ids::GrantId;

    /// One scripted adapter response.
    #[derive(Debug, Clone)]
    pub enum FakeStep {
        /// Succeed with these facts.
        Prepare(PrepareOutcome),
        /// Fail with this error.
        Fail(AdapterError),
        /// Perform the effect but report `OutcomeUnknown` (lost acknowledgment);
        /// `reconcile` later answers `Applied`.
        ApplyButLoseReply(PrepareOutcome),
    }

    /// Fake credential adapter with a response script and side-effect counters
    /// (plan §6.4 "add a canary side effect and count actual remote changes").
    /// Effects are keyed by `effect_token`: a repeated token never counts twice.
    pub struct FakeCredentialAdapter {
        descriptor: AdapterDescriptor,
        script: Mutex<VecDeque<FakeStep>>,
        /// Effects actually applied, by token (counts "remote changes").
        pub effects: Mutex<BTreeMap<String, PrepareOutcome>>,
        /// Revocations applied.
        pub revocations: Mutex<Vec<GrantId>>,
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
            })
        }

        /// Number of distinct effects applied.
        #[must_use]
        pub fn effect_count(&self) -> usize {
            self.effects.lock().unwrap().len()
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
            if let Some(done) = self.effects.lock().unwrap().get(req.effect_token) {
                return Ok(done.clone());
            }
            match self.next_step() {
                FakeStep::Prepare(out) => {
                    self.effects
                        .lock()
                        .unwrap()
                        .insert(req.effect_token.to_owned(), out.clone());
                    Ok(out)
                }
                FakeStep::ApplyButLoseReply(out) => {
                    self.effects
                        .lock()
                        .unwrap()
                        .insert(req.effect_token.to_owned(), out);
                    Err(AdapterError::OutcomeUnknown("reply lost".into()))
                }
                FakeStep::Fail(e) => Err(e),
            }
        }

        async fn renew(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
            self.prepare(req).await
        }

        async fn reconcile(
            &self,
            _grant: &GrantId,
            effect_token: &str,
        ) -> Result<ReconcileOutcome, AdapterError> {
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
            self.revocations.lock().unwrap().push(grant.clone());
            Ok(RevokeOutcome {
                remote_pending: Vec::new(),
                latest_possible_credential_expiry: None,
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
pub use fake_adapter::{FakeCredentialAdapter, FakeStep, ScriptedStageHook};

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
