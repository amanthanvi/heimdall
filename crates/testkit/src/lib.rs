//! Heimdall test support (plan §6.1 pure model/property tests, §6.4 fault
//! injection). Never compiled into shipped binaries: only `dev-dependencies` name
//! this crate.
//!
//! Canary rule (ADR-0004 §4): synthetic canary-format strings may appear in
//! fixtures, test inputs and harness assertions. A canary value appearing in
//! program output, logs, arguments or artifacts is a defect; [`assert_no_canary`]
//! is the shared assertion.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use heimdall_app::ports::{
    AdapterDescriptor, AdapterError, CredentialAdapter, PrepareOutcome, PrepareRequest,
    RevokeOutcome,
};
use heimdall_contract::Timestamp;
use heimdall_contract::ids::GrantId;
use heimdall_domain::time::Clock;
use heimdall_store::{FaultAction, FaultHook, FaultPoint};

/// Prefix of every synthetic canary. Values are generated per run by the test
/// that needs them and never committed.
pub const CANARY_PREFIX: &str = "HEIMDALL_CANARY_";

/// Panics if `output` contains any canary-format string.
pub fn assert_no_canary(output: &str) {
    assert!(!output.contains(CANARY_PREFIX), "canary leaked into output");
}

/// Deterministic clock: wall and monotonic advance only when told. Supports
/// rollback (`set_wall` backwards) and monotonic-only advance (sleep simulation).
#[derive(Debug)]
pub struct VirtualClock {
    wall: Mutex<Timestamp>,
    mono: Mutex<Duration>,
}

impl VirtualClock {
    /// Start at `wall`, monotonic zero.
    #[must_use]
    pub fn at(wall: Timestamp) -> Arc<Self> {
        Arc::new(Self {
            wall: Mutex::new(wall),
            mono: Mutex::new(Duration::ZERO),
        })
    }

    /// Advance both clocks together (normal passage of time).
    pub fn advance(&self, by: Duration) {
        let span = jiff::SignedDuration::try_from(by).expect("duration fits");
        let mut w = self.wall.lock().unwrap();
        *w = w.checked_add(span).expect("timestamp in range");
        *self.mono.lock().unwrap() += by;
    }

    /// Advance only monotonic (wall frozen: a stuck or stepped-back wall clock).
    pub fn advance_monotonic_only(&self, by: Duration) {
        *self.mono.lock().unwrap() += by;
    }

    /// Set wall time arbitrarily (forward jump or rollback) without touching
    /// monotonic.
    pub fn set_wall(&self, wall: Timestamp) {
        *self.wall.lock().unwrap() = wall;
    }

    /// Simulate a process restart: monotonic resets to zero; wall continues.
    pub fn restart(&self) {
        *self.mono.lock().unwrap() = Duration::ZERO;
    }
}

impl Clock for VirtualClock {
    fn wall(&self) -> Timestamp {
        *self.wall.lock().unwrap()
    }
    fn monotonic(&self) -> Duration {
        *self.mono.lock().unwrap()
    }
}

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

/// One scripted adapter response.
#[derive(Debug, Clone)]
pub enum FakeStep {
    /// Succeed with these facts.
    Prepare(PrepareOutcome),
    /// Fail with this error.
    Fail(AdapterError),
}

/// Fake credential adapter with a response script and side-effect counters
/// (plan §6.4 "add a canary side effect and count actual remote changes").
pub struct FakeCredentialAdapter {
    descriptor: AdapterDescriptor,
    script: Mutex<VecDeque<FakeStep>>,
    /// Number of `prepare` calls that reported success (counts "remote changes").
    pub effects: Mutex<u32>,
    /// Revocations applied.
    pub revocations: Mutex<Vec<GrantId>>,
}

impl std::fmt::Debug for FakeCredentialAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeCredentialAdapter")
            .field("mechanism", &self.descriptor.mechanism)
            .finish_non_exhaustive()
    }
}

impl FakeCredentialAdapter {
    /// New fake with a descriptor and a script. An exhausted script repeats its last
    /// step; an empty script fails with `Unavailable`.
    #[must_use]
    pub fn new(
        descriptor: AdapterDescriptor,
        script: impl IntoIterator<Item = FakeStep>,
    ) -> Arc<Self> {
        Arc::new(Self {
            descriptor,
            script: Mutex::new(script.into_iter().collect()),
            effects: Mutex::new(0),
            revocations: Mutex::new(Vec::new()),
        })
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

    async fn prepare(&self, _req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        match self.next_step() {
            FakeStep::Prepare(out) => {
                *self.effects.lock().unwrap() += 1;
                Ok(out)
            }
            FakeStep::Fail(e) => Err(e),
        }
    }

    async fn renew(&self, req: PrepareRequest<'_>) -> Result<PrepareOutcome, AdapterError> {
        self.prepare(req).await
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
    fn virtual_clock_rolls_back_and_restarts() {
        let t0: Timestamp = "2026-10-01T00:00:00Z".parse().unwrap();
        let c = VirtualClock::at(t0);
        c.advance(Duration::from_secs(60));
        assert_eq!(c.monotonic(), Duration::from_secs(60));
        c.set_wall(t0);
        assert_eq!(c.wall(), t0);
        c.restart();
        assert_eq!(c.monotonic(), Duration::ZERO);
    }

    #[test]
    fn scripted_faults_match_in_order() {
        let f = ScriptedFaults::new([(FaultPoint::BeforeCommit, FaultAction::Fail)]);
        assert_eq!(f.at(FaultPoint::BeforeTransaction), FaultAction::Continue);
        assert_eq!(f.at(FaultPoint::BeforeCommit), FaultAction::Fail);
        assert_eq!(f.at(FaultPoint::BeforeCommit), FaultAction::Continue);
        assert_eq!(f.visited().len(), 3);
    }
}
