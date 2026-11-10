//! The managed signer (ADR-0008 D2 items 1–5, 3a; m03-plan U2 `ManagedSigner`): an
//! `ipc::signing::Signer` per endpoint kind (environment, binding, verification).
//!
//! **Every `sign`** follows D2 item 3a, in this order, with a test-only pause point
//! ([`SignHook`]) after each step:
//!
//! 1. resolve the requested key on this endpoint ([`SignerTable::resolve`]: a listed
//!    certificate, never the plain K_env), parse the data as a userauth request
//!    ([`purpose::parse_userauth`]), and check its purpose ([`purpose::check`]: the
//!    presented `key_blob` is one of the grant's certificates and `user` the account
//!    of the pair it names; [`purpose::check_bound`] once the connection is bound;
//!    a forwarded bind refuses unless that certificate permits agent forwarding);
//! 2. [`SignatureAuthority::precheck`] (an early refusal only);
//! 3. [`SignatureAuthority::admit`], which takes the grant's gate shared and reads
//!    fresh under it, returning a `SignPermit` with its absolute expiry. Both calls
//!    are bounded by `signature_authorization_timeout` here too;
//! 4. `KeyVault::sign` **on the blocking pool under `signing_budget`**: on overrun
//!    the permit (and the gate) is dropped at once and the late signature, when it
//!    arrives, is discarded;
//! 5. return [`SignOutcome::signature`] with the permit as an
//!    `ipc::signing::PermitGuard`, so `serve()` reserves outbound capacity (its wait
//!    cancelled at the permit's expiry), runs the release check, enqueues without
//!    waiting, and only then drops the permit (steps 6–9).
//!
//! A refusal at any step returns `SSH_AGENT_FAILURE` with no reason; the nonsecret
//! code is recorded ([`ManagedSigner::refusals`]).
//!
//! **Session-bind** (D2 item 5): [`session_bind::accept`] parses and verifies the
//! host's signature. A failed verification **poisons** the connection: every later
//! sign and bind on it is refused. `ipc::signing::SigningSession` is frozen and only
//! its `bind` slot is the signer's, so the poison is a sentinel record there with an
//! empty session identifier, which no verified bind can have (1–128 bytes). A
//! forwarding bind stays recorded as forwarding for the rest of the connection.
//!
//! **Verification endpoints** (reading R3, INT-Q13): a verification signature is sent
//! only with a permit, like a grant's ([`VERIFICATION_UNGATED_SIGNING`] is `false`).
//! Production `Operations` refuses every verification subject, so until the
//! orchestrator rules INT-Q13 every verification signature is refused. The endpoint
//! counts sign requests per key fingerprint and session-binds received (D5 §6.5
//! item 1; [`VerificationCounters`]).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use heimdall_app::managed::SignPermit;
use heimdall_app::operations::Limits;
use heimdall_app::ports::{
    SignRefusal, SignatureAuthority, SignatureRequestFacts, SignatureSubject, SignerEndpoint,
};
use heimdall_ipc::signing::{
    PermitGuard, ReleaseCheck, ServeLimits, SessionBindRecord, SignOutcome, Signer, SigningSession,
};

use crate::purpose::{self, PurposeRefusal};
use crate::session_bind;
use crate::table::{SignTarget, SignerTable};

/// ⟨INT-Q13⟩ Whether a verification-endpoint signature may be sent **without** a
/// permit. `false`: no ungated path exists; a verification signature needs a permit
/// from the `SignatureAuthority` exactly like a grant's (reading R3). In production
/// `Operations` refuses every `SignatureSubject::Verification`, so every verification
/// signature is refused until the orchestrator rules INT-Q13.
pub const VERIFICATION_UNGATED_SIGNING: bool = false;

/// How many refusal codes a signer keeps for inspection (oldest dropped first).
pub const REFUSAL_LOG_MAX: usize = 256;

/// The signer's bounds, from `app::operations::Limits` (m03-plan §5 item 17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerLimits {
    /// `signing_budget` (1 s): the longest `KeyVault::sign` may take.
    pub signing_budget: Duration,
    /// `signature_authorization_timeout` (2 s), applied to `precheck` and `admit`
    /// each.
    pub authorization_timeout: Duration,
    /// The per-connection limits `serve()` runs with (`signing_enqueue_timeout`).
    pub serve: ServeLimits,
}

impl SignerLimits {
    /// The signer's bounds from the runtime's `Limits`.
    #[must_use]
    pub fn from_limits(limits: &Limits) -> SignerLimits {
        SignerLimits {
            signing_budget: limits.signing_budget,
            authorization_timeout: limits.signature_authorization_timeout,
            serve: ServeLimits {
                enqueue_timeout: limits.signing_enqueue_timeout,
                ..ServeLimits::default()
            },
        }
    }
}

impl Default for SignerLimits {
    fn default() -> Self {
        SignerLimits::from_limits(&Limits::default())
    }
}

/// A point of the sign path (D2 item 3a) where the test-only [`SignHook`] runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SignStep {
    /// After step 1 (the key resolved, the purpose and bind checks passed).
    Purpose,
    /// After step 2 (the pre-check passed).
    Prechecked,
    /// After steps 3–4 (admitted: the permit is held).
    Admitted,
    /// Inside step 5, after the blocking signature started and before it is awaited
    /// (time spent here counts against `signing_budget`).
    Signing,
    /// After step 5 (signed within the budget), just before the outcome returns to
    /// `serve()`.
    Signed,
}

/// The future a [`SignHook`] returns.
pub type HookFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// A test-only pause point after each sign step (deterministic interleavings, the M01
/// `StageHook` pattern). Production signers have none.
pub trait SignHook: Send + Sync {
    /// Called at `step` of a sign request on `endpoint`; the sign path waits for it.
    fn at<'a>(&'a self, endpoint: &'a SignerEndpoint, step: SignStep) -> HookFuture<'a>;
}

/// The verification endpoint's counters (ADR-0008 D5 §6.5 item 1): sign requests per
/// key fingerprint (counted when a request names this endpoint's K_verify or its
/// current certificate, before any check, whether or not it is signed) and
/// `session-bind@openssh.com` extensions received.
#[derive(Debug, Default)]
pub struct VerificationCounters {
    signatures: Mutex<BTreeMap<String, u32>>,
    session_binds: Mutex<u32>,
}

impl VerificationCounters {
    /// Sign requests recorded for `key_fingerprint` (`SHA256:…`).
    #[must_use]
    pub fn signatures(&self, key_fingerprint: &str) -> u32 {
        self.signatures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key_fingerprint)
            .copied()
            .unwrap_or(0)
    }

    /// Session-binds received.
    #[must_use]
    pub fn session_binds(&self) -> u32 {
        *self
            .session_binds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn count_signature(&self, key_fingerprint: &str) {
        let mut m = self
            .signatures
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let n = m.entry(key_fingerprint.to_owned()).or_default();
        *n = n.saturating_add(1);
    }

    fn count_bind(&self) {
        let mut n = self
            .session_binds
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *n = n.saturating_add(1);
    }
}

/// What one signer saw of `session-bind@openssh.com` (ADR-0008 D2 item 5): binds
/// accepted and refused, and sign requests that passed the purpose check on a bound
/// connection or on one without a bind (`session_bind: absent`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BindStats {
    /// Binds whose host signature verified.
    pub accepted: u32,
    /// Binds refused (malformed, bad signature, or on a poisoned connection).
    pub refused: u32,
    /// Purpose-checked sign requests on a bound connection.
    pub signs_bound: u32,
    /// Purpose-checked sign requests on a connection with no bind (`absent`).
    pub signs_unbound: u32,
}

/// The opaque permit `serve()` holds until the enqueue (ADR-0008 D2 item 3a; §18).
struct PermitRelease(SignPermit);

impl ReleaseCheck for PermitRelease {
    fn may_release(&self) -> bool {
        self.0.may_release()
    }

    fn expires_at(&self) -> tokio::time::Instant {
        self.0.expires_at()
    }
}

/// Whether `bind` is the poison sentinel of a failed session-bind (module docs).
#[must_use]
pub fn is_poisoned(bind: &SessionBindRecord) -> bool {
    bind.session_id.is_empty()
}

fn poison() -> SessionBindRecord {
    SessionBindRecord {
        host_key: Vec::new(),
        session_id: Vec::new(),
        signature: Vec::new(),
        is_forwarding: true,
    }
}

/// One endpoint's signer (ADR-0008 D2). Cheap to share (`Arc`).
pub struct ManagedSigner {
    endpoint: SignerEndpoint,
    table: SignerTable,
    authority: Arc<dyn SignatureAuthority>,
    limits: SignerLimits,
    hook: Option<Arc<dyn SignHook>>,
    counters: Option<Arc<VerificationCounters>>,
    refusals: Mutex<Vec<&'static str>>,
    binds: Mutex<BindStats>,
}

impl std::fmt::Debug for ManagedSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedSigner")
            .field("endpoint", &self.endpoint)
            .field("hook", &self.hook.is_some())
            .finish_non_exhaustive()
    }
}

impl ManagedSigner {
    /// A signer for `endpoint` over `table`, authorized by `authority`. A
    /// verification endpoint gets its [`VerificationCounters`].
    #[must_use]
    pub fn new(
        endpoint: SignerEndpoint,
        table: SignerTable,
        authority: Arc<dyn SignatureAuthority>,
        limits: SignerLimits,
    ) -> ManagedSigner {
        let counters = matches!(endpoint, SignerEndpoint::Verification(_))
            .then(|| Arc::new(VerificationCounters::default()));
        ManagedSigner {
            endpoint,
            table,
            authority,
            limits,
            hook: None,
            counters,
            refusals: Mutex::new(Vec::new()),
            binds: Mutex::new(BindStats::default()),
        }
    }

    /// Install the test-only pause hook.
    #[must_use]
    pub fn with_hook(mut self, hook: Arc<dyn SignHook>) -> ManagedSigner {
        self.hook = Some(hook);
        self
    }

    /// The endpoint this signer serves.
    #[must_use]
    pub fn endpoint(&self) -> &SignerEndpoint {
        &self.endpoint
    }

    /// The verification counters (a verification endpoint only).
    #[must_use]
    pub fn counters(&self) -> Option<&Arc<VerificationCounters>> {
        self.counters.as_ref()
    }

    /// The nonsecret refusal codes recorded, oldest first (at most
    /// [`REFUSAL_LOG_MAX`]).
    #[must_use]
    pub fn refusals(&self) -> Vec<&'static str> {
        self.refusals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// What this signer saw of session-bind so far.
    #[must_use]
    pub fn bind_stats(&self) -> BindStats {
        *self.binds.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn note_bind(&self, f: impl FnOnce(&mut BindStats)) {
        f(&mut self.binds.lock().unwrap_or_else(PoisonError::into_inner));
    }

    fn refuse(&self, code: &'static str) -> SignOutcome {
        let mut r = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
        if r.len() >= REFUSAL_LOG_MAX {
            r.remove(0);
        }
        r.push(code);
        SignOutcome::failure()
    }

    async fn pause(&self, step: SignStep) {
        if let Some(h) = &self.hook {
            h.at(&self.endpoint, step).await;
        }
    }

    /// Step 1: the purpose and bind checks.
    fn purpose(
        &self,
        session: &SigningSession,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
        target: &SignTarget,
    ) -> Result<purpose::PairRef, &'static str> {
        let request = purpose::parse_userauth(data).map_err(PurposeRefusal::code)?;
        let is_verification = matches!(target.subject, SignatureSubject::Verification(_));
        // A grant endpoint signs only for the certificate it listed and the client
        // presents (F17). A verification endpoint may be asked under the plain
        // K_verify (reading R3), but the presented key must be its certificate.
        if !is_verification && request.key_blob != key_blob {
            return Err("request_key_mismatch");
        }
        let pair = purpose::check(&request, &target.certs, flags).map_err(PurposeRefusal::code)?;
        if is_verification {
            let current = match &target.subject {
                SignatureSubject::Verification(op) => {
                    self.table.current_verification_certificate(op)
                }
                _ => None,
            };
            if current.as_deref() != Some(request.key_blob.as_slice()) {
                return Err("not_current_certificate");
            }
        }
        if let Some(bind) = &session.bind {
            purpose::check_bound(&request, bind).map_err(PurposeRefusal::code)?;
            if bind.is_forwarding && !target.forwarding.contains(&pair.pair) {
                return Err("forwarding_not_permitted");
            }
        }
        Ok(pair)
    }

    async fn sign_inner(
        &self,
        session: &SigningSession,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<(Vec<u8>, SignPermit), &'static str> {
        if session.bind.as_ref().is_some_and(is_poisoned) {
            return Err("session_bind_failed");
        }
        let target = self
            .table
            .resolve(&self.endpoint, key_blob)
            .ok_or("key_not_listed")?;
        if let Some(c) = &self.counters {
            c.count_signature(&target.key_fingerprint);
        }
        // Step 1.
        let pair = self.purpose(session, key_blob, data, flags, &target)?;
        let bound = session.bind.is_some();
        self.note_bind(|b| {
            if bound {
                b.signs_bound = b.signs_bound.saturating_add(1);
            } else {
                b.signs_unbound = b.signs_unbound.saturating_add(1);
            }
        });
        self.pause(SignStep::Purpose).await;
        let facts = SignatureRequestFacts {
            endpoint: self.endpoint.clone(),
            subject: target.subject.clone(),
            pair: pair.pair,
            key_fingerprint: target.key_fingerprint.clone(),
        };
        let bound = self.limits.authorization_timeout;
        // Step 2: an early refusal only.
        match tokio::time::timeout(bound, self.authority.precheck(&facts)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e.code()),
            Err(_) => return Err(SignRefusal::AuthorizationTimeout.code()),
        }
        self.pause(SignStep::Prechecked).await;
        // Steps 3–4: the gate shared, the fresh read under it, the permit.
        let permit = match tokio::time::timeout(bound, self.authority.admit(&facts)).await {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => return Err(e.code()),
            Err(_) => return Err(SignRefusal::AuthorizationTimeout.code()),
        };
        self.pause(SignStep::Admitted).await;
        // The key may have been destroyed between resolution and admission.
        let slot = self
            .table
            .resolve(&self.endpoint, key_blob)
            .map(|t| t.slot)
            .filter(|s| *s == target.slot)
            .ok_or("key_destroyed")?;
        // Step 5: the blocking pool, under the budget. On overrun the permit drops
        // here (releasing the gate) and the detached task's late result is discarded.
        let vault = Arc::clone(self.table.vault());
        let to_sign = data.to_vec();
        let signing = tokio::task::spawn_blocking(move || vault.sign(&slot, &to_sign));
        let budgeted = async {
            self.pause(SignStep::Signing).await;
            signing.await
        };
        let signature = match tokio::time::timeout(self.limits.signing_budget, budgeted).await {
            Ok(Ok(Ok(sig))) => sig,
            Ok(Ok(Err(_))) => return Err("vault_sign_failed"),
            Ok(Err(_)) => return Err("vault_sign_panicked"),
            Err(_) => {
                drop(permit);
                return Err("signing_budget_exceeded");
            }
        };
        self.pause(SignStep::Signed).await;
        Ok((signature, permit))
    }
}

#[async_trait]
impl Signer for ManagedSigner {
    async fn identities(&self, _session: &SigningSession) -> Vec<(Vec<u8>, String)> {
        self.table.list(&self.endpoint)
    }

    async fn sign(
        &self,
        session: &SigningSession,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> SignOutcome {
        match self.sign_inner(session, key_blob, data, flags).await {
            Ok((signature, permit)) => {
                SignOutcome::signature(&signature, PermitGuard(Box::new(PermitRelease(permit))))
            }
            Err(code) => self.refuse(code),
        }
    }

    fn session_bind(&self, session: &mut SigningSession, payload: &[u8]) -> bool {
        if let Some(c) = &self.counters {
            c.count_bind();
        }
        if session.bind.as_ref().is_some_and(is_poisoned) {
            self.note_bind(|b| b.refused = b.refused.saturating_add(1));
            return false;
        }
        match session_bind::accept(payload) {
            Ok((_, mut record)) => {
                self.note_bind(|b| b.accepted = b.accepted.saturating_add(1));
                // A forwarding hop recorded earlier on this connection stays recorded.
                if session.bind.as_ref().is_some_and(|b| b.is_forwarding) {
                    record.is_forwarding = true;
                }
                session.bind = Some(record);
                true
            }
            Err(_) => {
                self.note_bind(|b| b.refused = b.refused.saturating_add(1));
                // D2 item 5: a failed verification makes this connection refuse every
                // later sign (and bind).
                session.bind = Some(poison());
                false
            }
        }
    }
}
