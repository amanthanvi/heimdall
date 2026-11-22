//! ⟨M06 W3 `driver`⟩ The controller's sync and issuance driver against the runner's real
//! store, operations, runner runtime and sync service (`runner_sync_fixture_m06`), with the
//! orchestrator's rulings of 2026-11-21 on U4's questions (ADR-0012 §7.4; ADR-0006 §18.7
//! items 11–13). Disposable state only.
//!
//! * **Both ends gate** (item 11): the runner refuses `prepare_remote_grant` and
//!   `install_certificate` (`resync_pending`) from a session that skipped the authority
//!   report, per session, and again after an effect delivered in that session; the
//!   controller's driver prepares nothing while its barrier is closed.
//! * **Remote issuance** (§4.2): prepare, reserve and publish behind the barrier, sign,
//!   install; only for the issuing controller's own grants.
//! * **The policy ID in the prepare answer** (item 12): the barrier refuses a paused scope
//!   before it reserves.
//! * **A revoke is never defeated by a stale generation.**
//! * **A cutoff that fired under uncertain time stays fired**, and the controller's view and
//!   the doctor's reading say why.
//! * **The owner's local narrowing of a runner's grant or policy** becomes one outbox row.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

#[path = "runner_fixture_m06.rs"]
mod fixture;
#[path = "runner_sync_fixture_m06.rs"]
mod sync_fixture;

use std::collections::BTreeSet;
use std::time::Duration;

use fixture::*;
use heimdall_app::OpError;
use heimdall_app::remote_status::{
    IssuanceGate, Narrowing, RunnerChannel, early_cutoffs, resync, status_of,
};
use heimdall_app::remote_status_driver::{
    ControllerSync, RemoteAsk, RemoteIssueInput, RemoteIssuer, RemoteSubject,
    cutoff_all_on_runners, cutoff_of_all, deliver_runner_grant, narrow_runner_grant,
    narrow_runner_policy, policy_on_runner, revoke_on_runner, runner_deliveries,
};
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{Envelope, reason};
use heimdall_contract::ids::{CaFingerprint, GrantId};
use heimdall_contract::remote::{EffectTarget, Role, RunnerRequest};
use heimdall_contract::request::PolicyAction;
use heimdall_contract::trust::PolicyTarget;
use heimdall_contract::{GrantState, Timestamp};
use heimdall_credential::cert::{CertificateProfile, SecretCaKey, build_and_sign};
use heimdall_domain::issuance::{IssuanceEntry, IssuanceState};
use heimdall_domain::time::Clock;
use heimdall_issuer::remote::{PreparedRemoteGrant, RemoteExpectation, verify_prepared};
use heimdall_store::ext_effects::AppliedRecord;
use sync_fixture::*;

/// This controller's issuer over a fixture CA: the real `verify_prepared`, and a signature
/// that certifies exactly the reserved bounds.
struct FixtureIssuer<'a> {
    ca: &'a SecretCaKey,
}

#[async_trait::async_trait]
impl RemoteIssuer for FixtureIssuer<'_> {
    fn ca(&self) -> Result<CaFingerprint, OpError> {
        Ok(self.ca.fingerprint().unwrap())
    }

    fn verify(
        &self,
        ask: &RemoteAsk,
        answer: serde_json::Value,
        now: Timestamp,
    ) -> Result<RemoteSubject, OpError> {
        let prepared: PreparedRemoteGrant = serde_json::from_value(answer).unwrap();
        let expected = RemoteExpectation {
            environment: ask.environment.clone(),
            grant: ask.grant.clone(),
            grant_generation: ask.grant_generation,
            controller: ask.controller.clone(),
            ca_fingerprint: ask.ca_fingerprint.clone(),
        };
        let request = verify_prepared(&expected, &prepared, now).map_err(|r| {
            let e = OpError::new(Code::CapabilityUnavailable, r.to_string());
            match r.reason() {
                Some(why) => e.with_reason(why),
                None => e,
            }
        })?;
        Ok(RemoteSubject {
            subject_public_key: request.subject_public_key,
            subject_fingerprint: request.subject_fingerprint,
            pairs: request.pairs,
            bound: request.bound,
            policy: request.policy,
        })
    }

    async fn sign(&self, entry: &IssuanceEntry, subject: &str) -> Result<String, OpError> {
        let b = &entry.bounds;
        let profile = CertificateProfile {
            serial: b.serial,
            key_id: b.key_id.clone(),
            principal: b.principal.clone(),
            valid_after: b.valid_after.as_second(),
            valid_before: b.valid_before.as_second(),
            extensions: b.extensions.clone(),
            subject_fingerprint: b.subject_fingerprint.clone(),
            ca_fingerprint: b.ca_fingerprint.clone(),
        };
        let subject = ssh_key::PublicKey::from_openssh(subject).unwrap();
        Ok(build_and_sign(&profile, &subject, self.ca)
            .unwrap()
            .to_openssh()
            .unwrap())
    }
}

fn input(r: &Rig, grant: &GrantId) -> RemoteIssueInput {
    RemoteIssueInput {
        grant: grant.clone(),
        grant_generation: r.w.generation(),
        lifetime: Duration::from_secs(30 * 60),
    }
}

/// Record `c`'s pin of the runner in its own store (the hosted pass and the fan-out read it).
fn record_pin(c: &Controller) {
    c.store
        .transaction(|tx| {
            tx.put_remote_environment_pin(
                &c.pin.environment,
                &c.pin.destination,
                &c.pin.route.runner.account,
                &c.pin.key_fingerprint,
                &serde_json::to_string(&c.pin).unwrap(),
                t0(),
            )
        })
        .unwrap();
}

/// `c` records that it delivered the fixture grant to the runner: `pairs`, `permit-pty`,
/// until `expires_at` (ADR-0005 §3.5 "Remote reservations", condition 6).
fn deliver(c: &Controller, r: &Rig, pairs: &[&str], expires_at: Timestamp) {
    let pairs: BTreeSet<_> = pairs.iter().map(|d| pair(d)).collect();
    let now = c.now();
    c.store
        .transaction(|tx| {
            deliver_runner_grant(
                tx,
                &c.pin,
                &r.w.grant,
                &pairs,
                &BTreeSet::from(["permit-pty".to_owned()]),
                expires_at,
                now,
            )
        })
        .unwrap()
        .unwrap();
}

/// The whole fixture grant, to its deadline.
fn deliver_all(c: &Controller, r: &Rig) {
    deliver(c, r, &["h1", "h2"], deadline());
}

/// A driver over the fixture controller's store and clock.
fn driver(c: &Controller) -> ControllerSync {
    ControllerSync::new(c.store.clone(), c.clock.clone())
}

async fn resync_with(d: &ControllerSync, c: &Controller, s: &mut Session<'_>) {
    resync(d.store(), c.clock.as_ref(), d.barrier(), &c.pin, s)
        .await
        .unwrap();
}

/// The reconnect order over a fixture channel, with its outcome (as
/// `ControllerSync::on_session` runs it over a management session).
trait OnChannel {
    async fn on_channel(
        &self,
        c: &Controller,
        s: &mut Session<'_>,
    ) -> heimdall_app::remote_status::ResyncOutcome;
}

impl OnChannel for ControllerSync {
    async fn on_channel(
        &self,
        c: &Controller,
        s: &mut Session<'_>,
    ) -> heimdall_app::remote_status::ResyncOutcome {
        resync(self.store(), c.clock.as_ref(), self.barrier(), &c.pin, s)
            .await
            .unwrap()
    }
}

fn refusal(env: &Envelope<serde_json::Value>) -> (Code, Option<String>) {
    (
        env.code.clone(),
        env.data["error"]["reason"].as_str().map(str::to_owned),
    )
}

fn resync_pending() -> (Code, Option<String>) {
    (
        Code::CapabilityUnavailable,
        Some(reason::RESYNC_PENDING.to_owned()),
    )
}

/// The runner is the authority on resynchronization: a session that skips the authority
/// report is refused prepare and install, whatever the controller does. The gate is per
/// session, and an effect delivered in a session gates it again until a fresh report.
#[tokio::test]
async fn a_session_that_skips_the_report_cannot_prepare_or_install() {
    let r = rig().await;
    r.w.trust(&r.w.ca_a, &controller_a());
    r.w.designate(&controller_a());
    let prepare = RunnerRequest::PrepareRemoteGrant {
        grant: r.w.grant.clone(),
        grant_generation: r.w.generation(),
    };

    // No report in this session: refused before any issuance check, nothing generated.
    let mut s = r.session(&controller_a());
    assert_eq!(
        refusal(&s.call(prepare.clone()).await.unwrap()),
        resync_pending()
    );
    assert!(r.w.runner.issuance().keys().grants().is_empty());
    // The time exchange is not issuance and is not gated.
    assert_eq!(
        s.call(RunnerRequest::TimeChallenge).await.unwrap().code,
        Code::Ok
    );

    // The report opens this session only.
    assert_eq!(
        s.call(RunnerRequest::AuthorityReport).await.unwrap().code,
        Code::Ok
    );
    let mut other = r.session(&controller_a());
    other.connection = 8;
    assert_eq!(
        refusal(&other.call(prepare.clone()).await.unwrap()),
        resync_pending(),
        "another session of the same controller is still gated"
    );
    assert_eq!(s.call(prepare.clone()).await.unwrap().code, Code::Ok);

    // An effect delivered in the session makes its view stale: gated until a fresh report.
    // (A grant ID this runner does not hold: tombstoned, with no bearing on the fixture
    // grant, so what refuses below is the gate alone.)
    let delivered = s
        .call(RunnerRequest::DeliverEffect {
            effect: effect(1),
            target: EffectTarget::GrantRevoke {
                grant: GrantId::from_random_bytes([0x44; 16]),
                grant_generation: 0,
            },
        })
        .await
        .unwrap();
    assert_eq!(delivered.code, Code::Ok);
    // The tombstone moved the runner's authority generation: issuance starts over.
    let prepare = RunnerRequest::PrepareRemoteGrant {
        grant: r.w.grant.clone(),
        grant_generation: r.w.generation(),
    };
    let install = |certificate: String| RunnerRequest::InstallCertificate {
        grant: r.w.grant.clone(),
        grant_generation: r.w.generation(),
        certificate,
    };
    assert_eq!(
        refusal(&s.call(prepare.clone()).await.unwrap()),
        resync_pending()
    );
    assert_eq!(
        refusal(
            &s.call(install("ssh-ed25519-cert-v01@openssh.com AAAA".into()))
                .await
                .unwrap()
        ),
        resync_pending(),
        "install is gated before the certificate is even read"
    );
    assert!(r.w.runner.issuance().keys().installed().is_empty());

    // A fresh report in this session: prepare and install are served again.
    assert_eq!(
        s.call(RunnerRequest::AuthorityReport).await.unwrap().code,
        Code::Ok
    );
    let prepared = s.call(prepare).await.unwrap();
    assert_eq!(prepared.code, Code::Ok, "{:?}", prepared.data);
    let prepared: PreparedRemoteGrant = serde_json::from_value(prepared.data).unwrap();
    assert_eq!(
        prepared.policy,
        Some(policy_id()),
        "the prepare answer names the policy"
    );
    r.w.good_sample();
    let valid_before = Timestamp::from_second(plus(r.w.clock.wall(), HOUR).as_second()).unwrap();
    let certificate = r.w.sign(&r.w.ca_a, &prepared, &pair("h1"), valid_before);
    let done = s.call(install(certificate)).await.unwrap();
    assert_eq!(done.code, Code::Ok, "{:?}", done.data);
    assert_eq!(r.w.runner.issuance().keys().installed().len(), 1);
}

const MINUTE: Duration = Duration::from_secs(60);

/// Remote issuance end to end at the library level: nothing is prepared while the barrier is
/// closed; after the resynchronization the driver prepares, reserves and publishes behind
/// the barrier, signs, and installs one certificate per pair. The ledger counts them and
/// knows which runner the grant lives on. Another controller cannot issue for the grant.
#[tokio::test]
async fn remote_issuance_runs_only_after_the_barrier_and_only_for_the_issuer() {
    let r = rig().await;
    r.w.trust(&r.w.ca_a, &controller_a());
    r.w.trust(&r.w.ca_b, &controller_b());
    r.w.designate(&controller_a());
    let a = controller(&r, &controller_a(), Role::Owner);
    let d = driver(&a);
    let issuer = FixtureIssuer { ca: &r.w.ca_a };
    let ask = input(&r, &r.w.grant);

    // A grant this controller holds no record of delivering: nothing is asked of the runner.
    let mut s = r.session(&controller_a());
    let e = d.issue(&a.pin, &mut s, &issuer, &ask).await.unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.reason, None);
    assert_eq!(s.sent(), 0);
    deliver_all(&a, &r);

    // Before the resynchronization: `resync_pending`, and nothing was sent to the runner.
    let e = d.issue(&a.pin, &mut s, &issuer, &ask).await.unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.reason.as_deref(), Some(reason::RESYNC_PENDING));
    assert_eq!(s.sent(), 0);

    resync_with(&d, &a, &mut s).await;
    let issued = d.issue(&a.pin, &mut s, &issuer, &ask).await.unwrap();
    assert_eq!(issued.certificates.len(), 2, "one certificate per pair");
    // Installed on the runner, pinned to this controller, with the bounds reserved here.
    let installed = r.w.runner.issuance().keys().installed();
    assert_eq!(installed.len(), 2);
    let entries = a
        .store
        .transaction(|tx| tx.issuance_entries(&r.w.grant))
        .unwrap();
    assert_eq!(entries.len(), 2);
    for e in &entries {
        assert_eq!(e.state, IssuanceState::Published);
        assert!(e.bounds.key_id.contains(r.w.env.as_str()));
        assert!(e.bounds.valid_before <= plus(a.now(), 30 * MINUTE));
        assert!(
            installed
                .iter()
                .any(|(_, _, _, c)| c.serial == e.bounds.serial
                    && c.valid_before == e.bounds.valid_before)
        );
    }

    // ADR-0012 §8 item 3: the second controller cannot issue for the first's grant. The
    // runner refuses its prepare (the grant's pin) and its ledger stays empty.
    let b = controller(&r, &controller_b(), Role::Owner);
    deliver_all(&b, &r);
    let db = driver(&b);
    let mut sb = r.session(&controller_b());
    sb.connection = 9;
    resync_with(&db, &b, &mut sb).await;
    // Time is bounded for B only by the report (A's sample of this boot).
    let e = db
        .issue(&b.pin, &mut sb, &FixtureIssuer { ca: &r.w.ca_b }, &ask)
        .await
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::ISSUER_UNTRUSTED));
    assert!(
        b.store
            .transaction(|tx| tx.issuance_entries(&r.w.grant))
            .unwrap()
            .is_empty()
    );

    // A requester's pin never issues, and nothing is sent.
    let v = controller(&r, &controller_a(), Role::Requester);
    let before = s.sent();
    let e = driver(&v)
        .issue(&v.pin, &mut s, &issuer, &ask)
        .await
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::ROLE_INSUFFICIENT));
    assert_eq!(s.sent(), before);
}

/// ADR-0006 §18.7 item 12: the prepare answer names the runner's policy, so the barrier
/// refuses a paused scope before anything is reserved or signed.
#[tokio::test]
async fn the_prepared_policy_lets_the_barrier_refuse_a_paused_scope_before_reserving() {
    let r = rig().await;
    r.w.trust(&r.w.ca_a, &controller_a());
    r.w.designate(&controller_a());
    let a = controller(&r, &controller_a(), Role::Owner);
    deliver_all(&a, &r);
    let d = driver(&a);
    // The other owner paused the policy while A was away.
    r.deliver(
        &controller_b(),
        &effect(7),
        &EffectTarget::PolicyPause {
            policy: policy_id(),
            revision: 1,
        },
    )
    .await
    .unwrap();
    let mut s = r.session(&controller_a());
    resync_with(&d, &a, &mut s).await;
    let e = d
        .issue(
            &a.pin,
            &mut s,
            &FixtureIssuer { ca: &r.w.ca_a },
            &input(&r, &r.w.grant),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::PolicyPaused);
    assert!(
        a.store
            .transaction(|tx| tx.issuance_entries(&r.w.grant))
            .unwrap()
            .is_empty(),
        "refused before the reservation"
    );
    assert!(r.w.runner.issuance().keys().installed().is_empty());
}

/// A compromised runner's side of a management session: it strips the policy from its
/// prepare answers and, when `hide_report` is set, every policy and delivered revision from
/// its authority reports.
struct Lying<'a> {
    inner: Session<'a>,
    hide_report: bool,
    /// Prepare answers that carried a policy and lost it.
    stripped: usize,
    /// Prepare requests seen.
    prepares: usize,
}

#[async_trait::async_trait]
impl RunnerChannel for Lying<'_> {
    fn environment(&self) -> &heimdall_contract::ids::EnvironmentId {
        self.inner.environment()
    }

    fn client(&self) -> Option<&heimdall_contract::ids::ClientId> {
        self.inner.client()
    }

    async fn call(
        &mut self,
        request: RunnerRequest,
    ) -> Result<Envelope<serde_json::Value>, OpError> {
        let prepare = matches!(request, RunnerRequest::PrepareRemoteGrant { .. });
        let report = matches!(request, RunnerRequest::AuthorityReport);
        let mut env = self.inner.call(request).await?;
        if let Some(data) = env.data.as_object_mut() {
            if prepare {
                self.prepares += 1;
                self.stripped += usize::from(data.remove("policy").is_some());
            }
            if report && self.hide_report {
                data.insert("policy_revisions".into(), serde_json::json!([]));
                data.insert("policies".into(), serde_json::json!([]));
            }
        }
        Ok(env)
    }
}

/// ⟨M06-W3-R02⟩ The policy a prepare answer names is the runner's word, and a compromised
/// runner can leave it out. While a pause holds for the runner, an answer without a policy
/// is refused before anything is reserved or signed.
#[tokio::test]
async fn a_prepare_answer_stripped_of_its_policy_cannot_pass_a_pause() {
    let r = rig().await;
    r.w.trust(&r.w.ca_a, &controller_a());
    r.w.designate(&controller_a());
    let a = controller(&r, &controller_a(), Role::Owner);
    deliver_all(&a, &r);
    let d = driver(&a);
    r.deliver(
        &controller_b(),
        &effect(7),
        &EffectTarget::PolicyPause {
            policy: policy_id(),
            revision: 1,
        },
    )
    .await
    .unwrap();
    let mut s = Lying {
        inner: r.session(&controller_a()),
        hide_report: false,
        stripped: 0,
        prepares: 0,
    };
    resync(d.store(), a.clock.as_ref(), d.barrier(), &a.pin, &mut s)
        .await
        .unwrap();
    let e = d
        .issue(
            &a.pin,
            &mut s,
            &FixtureIssuer { ca: &r.w.ca_a },
            &input(&r, &r.w.grant),
        )
        .await
        .unwrap_err();
    assert_eq!(
        s.stripped, 1,
        "the answer reached the driver without its policy"
    );
    assert_eq!(e.code, Code::PolicyPaused);
    assert!(
        a.store
            .transaction(|tx| tx.issuance_entries(&r.w.grant))
            .unwrap()
            .is_empty(),
        "nothing was reserved"
    );
    assert!(r.w.runner.issuance().keys().installed().is_empty());
}

/// ⟨M06-W3-R02⟩ A cutoff of every policy that this controller delivered blocks all issuance
/// for that runner from the controller's own record of the delivery: a runner whose report
/// hides every policy and revision is not even asked to prepare.
#[tokio::test]
async fn a_delivered_cutoff_of_every_policy_holds_whatever_the_runner_reports() {
    let r = rig().await;
    r.w.trust(&r.w.ca_a, &controller_a());
    r.w.designate(&controller_a());
    let a = controller(&r, &controller_a(), Role::Owner);
    record_pin(&a);
    deliver_all(&a, &r);
    let d = driver(&a);
    let sent = cutoff_all_on_runners(&a.store, a.now(), a.now()).unwrap();
    assert_eq!(sent.len(), 1);
    // Delivered and acknowledged at the reconnect.
    let mut s = r.session(&controller_a());
    resync_with(&d, &a, &mut s).await;
    assert_eq!(a.pending(), 0);
    // A later session with a runner that hides the cutoff.
    let mut s = Lying {
        inner: r.session(&controller_a()),
        hide_report: true,
        stripped: 0,
        prepares: 0,
    };
    s.inner.connection = 11;
    let outcome = resync(d.store(), a.clock.as_ref(), d.barrier(), &a.pin, &mut s)
        .await
        .unwrap();
    assert!(outcome.report.policies.is_empty() && outcome.report.policy_revisions.is_empty());
    let e = d
        .issue(
            &a.pin,
            &mut s,
            &FixtureIssuer { ca: &r.w.ca_a },
            &input(&r, &r.w.grant),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::PolicyCutoff);
    assert_eq!(s.prepares, 0, "the runner was not asked to prepare");
    assert!(
        a.store
            .transaction(|tx| tx.issuance_entries(&r.w.grant))
            .unwrap()
            .is_empty()
    );
}

/// ⟨M06-W3-R02⟩ A grant another controller revoked on the runner is tombstoned in this
/// controller's ledger at the reconciliation even when this ledger holds no issuance entry
/// for it (the issuer child's own check reads this ledger).
#[tokio::test]
async fn a_reported_tombstone_is_recorded_without_any_counted_history() {
    let r = rig().await;
    let a = controller(&r, &controller_a(), Role::Owner);
    let d = driver(&a);
    r.deliver(
        &controller_b(),
        &effect(8),
        &EffectTarget::GrantRevoke {
            grant: r.w.grant.clone(),
            grant_generation: r.w.generation(),
        },
    )
    .await
    .unwrap();
    assert!(
        a.store
            .transaction(|tx| tx.issuance_entries(&r.w.grant))
            .unwrap()
            .is_empty()
    );
    let mut s = r.session(&controller_a());
    let outcome = d.on_channel(&a, &mut s).await;
    assert!(
        outcome.revoked.is_empty(),
        "no residual of this ledger's to report"
    );
    assert!(
        a.store
            .transaction(|tx| tx.tombstone(&r.w.grant))
            .unwrap()
            .is_some(),
        "the reported tombstone is in this ledger"
    );
}

/// ADR-0012 §7.4 (ruling of 2026-11-21): the generation a revoke carries is for idempotency
/// and audit only. A revoke naming an older generation, delivered after the runner's
/// authority moved on, revokes the grant as it is now; so does one naming a later generation.
#[tokio::test]
async fn a_revoke_naming_a_stale_generation_still_revokes_the_grant() {
    for offset in [-1i64, 5] {
        let r = rig().await;
        let b = controller(&r, &controller_b(), Role::Owner);
        let named = r.w.generation();
        // The runner's authority moves on after the controller last saw the grant.
        r.w.store
            .transaction(|tx| tx.upsert_policy(&policy(&r.w.env, None, 2), false))
            .unwrap();
        assert!(r.w.generation() > named, "the runner's generation moved");
        let stale = u64::try_from(i64::try_from(named).unwrap() + offset).unwrap();
        let key = b
            .produce(&Narrowing::RevokeGrant {
                grant: r.w.grant.clone(),
                grant_generation: stale,
            })
            .unwrap();
        let mut s = r.session(&controller_b());
        let out = b.resync(&mut s).await.unwrap();
        assert_eq!(out.acknowledged.len(), 1);
        assert_eq!(out.acknowledged[0].key, key);
        assert!(matches!(
            out.acknowledged[0].record,
            AppliedRecord::GrantTombstone {
                known: true,
                key_destroyed: true,
                ..
            }
        ));
        assert!(
            r.w.store
                .transaction(|tx| tx.tombstone(&r.w.grant))
                .unwrap()
                .is_some()
        );
        assert_ne!(r.grant_state(), GrantState::Active);
    }
}

/// ADR-0012 §7.4 (ruling of 2026-11-21): a cutoff delivered under unbounded uncertain time
/// fires at once. When the runner's time is certain again, and the same effect is delivered
/// again with trusted time, it stays fired: the policy keeps the early instant. The runner's
/// report, the controller's view and the doctor's reading say it fired early because time
/// was uncertain.
#[tokio::test]
async fn a_cutoff_fired_under_uncertain_time_stays_fired_and_says_why() {
    let r = rig().await;
    let b = controller(&r, &controller_b(), Role::Owner);
    let at = plus(b.now(), 6 * HOUR);
    let key = b
        .produce(&Narrowing::Cutoff {
            scope: PolicyTarget::All,
            at,
        })
        .unwrap();
    let certain = r.w.clock.wall();
    r.make_time_uncertain().await;
    let mut s = r.session(&controller_b());
    b.resync(&mut s).await.unwrap();
    let fired_at = r.policy().cutoff_at.unwrap();
    assert!(fired_at <= r.w.clock.wall() && fired_at < at);

    // Time is certain again (the wall clock is back above the high-water mark).
    r.w.clock.set_wall(plus(certain, MINUTE));
    r.ops.timegate().check().await.unwrap();
    assert!(r.w.clock.wall() < at, "the owner's instant is still ahead");
    // The same effect again, judged with trusted time: nothing is un-fired.
    let again = r
        .deliver(&controller_b(), &key.effect, &key.target)
        .await
        .unwrap();
    assert!(matches!(
        again.record,
        AppliedRecord::PolicyRevision { fired: true, .. }
    ));
    assert_eq!(r.policy().cutoff_at, Some(fired_at), "it stays fired");
    let rows =
        r.w.store
            .transaction(|tx| tx.remote_policy_revisions())
            .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].cutoff_at, Some(at), "the owner's instant is kept");
    assert_eq!(rows[0].fired_uncertain_at, Some(fired_at));

    // The runner's doctor reading, and the controller's view after its next report.
    let local = r.w.store.transaction(early_cutoffs).unwrap();
    assert_eq!(local.len(), 1);
    assert_eq!(local[0].0, None);
    assert_eq!(local[0].1.reason, "time_uncertain");
    assert!(local[0].1.statement().contains("uncertain"));
    let mut s = r.session(&controller_b());
    b.resync(&mut s).await.unwrap();
    let status = b.status(true);
    assert_eq!(status.cutoffs_fired_early.len(), 1);
    assert_eq!(status.cutoffs_fired_early[0].at, at);
    assert_eq!(status.cutoffs_fired_early[0].fired_at, fired_at);
    let json = serde_json::to_value(&status).unwrap();
    assert_eq!(json["cutoffs_fired_early"][0]["reason"], "time_uncertain");
    assert!(
        json.get("environment").is_none(),
        "the fields sit in the environment's own entry"
    );
}

/// The owner's local `revoke`, `policy pause` and `policy cutoff` of something that lives on
/// a runner become one outbox row each (`remote_pending`), reused when the request repeats;
/// the reconnect delivers and acknowledges them, and the view states the residual from the
/// counted history, never as a bare deadline.
#[tokio::test]
async fn a_local_narrowing_of_a_runners_grant_or_policy_is_one_pending_effect() {
    let r = rig().await;
    r.w.trust(&r.w.ca_a, &controller_a());
    r.w.designate(&controller_a());
    let a = controller(&r, &controller_a(), Role::Owner);
    a.store
        .transaction(|tx| {
            tx.put_remote_environment_pin(
                &a.pin.environment,
                &a.pin.destination,
                &a.pin.route.runner.account,
                &a.pin.key_fingerprint,
                &serde_json::to_string(&a.pin).unwrap(),
                t0(),
            )
        })
        .unwrap();
    let d = driver(&a);
    let now = a.now();

    // Unknown to every record: the local answer stands.
    assert!(
        a.store
            .transaction(|tx| narrow_runner_grant(tx, &r.w.grant, now))
            .unwrap()
            .is_none()
    );
    let pause = PolicyAction::Pause {
        policy_id: Some(policy_id()),
        target: None,
    };
    assert!(
        a.store
            .transaction(|tx| narrow_runner_policy(tx, &pause, now))
            .unwrap()
            .is_none()
    );

    // After issuing, the ledger ties the grant to the runner and the report lists its policy.
    deliver_all(&a, &r);
    let mut s = r.session(&controller_a());
    resync_with(&d, &a, &mut s).await;
    d.issue(
        &a.pin,
        &mut s,
        &FixtureIssuer { ca: &r.w.ca_a },
        &input(&r, &r.w.grant),
    )
    .await
    .unwrap();
    d.session_closed(&a.pin.environment);

    let first = a
        .store
        .transaction(|tx| narrow_runner_grant(tx, &r.w.grant, now))
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(first.produced);
    assert_eq!(first.environment, r.w.env);
    let repeated = a
        .store
        .transaction(|tx| narrow_runner_grant(tx, &r.w.grant, now))
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!repeated.produced);
    assert_eq!(repeated.key, first.key);
    let paused = a
        .store
        .transaction(|tx| narrow_runner_policy(tx, &pause, now))
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        paused.key.target,
        EffectTarget::PolicyPause { .. }
    ));
    // A scope is not one policy: this path sends none (a cutoff of every policy fans out
    // through `cutoff_all_on_runners`, below; a profile's or a workspace's stays local).
    let all = PolicyAction::Cutoff {
        policy_id: None,
        at: plus(now, HOUR),
        target: Some(PolicyTarget::All),
    };
    assert!(
        a.store
            .transaction(|tx| narrow_runner_policy(tx, &all, now))
            .unwrap()
            .is_none()
    );
    assert_eq!(a.pending(), 2);

    // Disconnected: pending, the barrier closed, the residual stated from the ledger.
    let view = |open: bool| {
        a.store
            .transaction(|tx| status_of(tx, &a.pin.environment, open, Some(d.barrier()), a.now()))
            .unwrap()
    };
    let before = view(false);
    assert_eq!(before.remote_pending.len(), 2);
    assert_eq!(before.issuance, IssuanceGate::AwaitingResync);
    assert_eq!(before.residuals.len(), 1);
    assert!(!before.residuals[0].acknowledged);
    assert!(
        before.residuals[0]
            .statement
            .contains("plus an unmeasured destination-clock error")
    );

    // Reconnect: delivered, acknowledged, the barrier opens.
    let mut s = r.session(&controller_a());
    s.connection = 11;
    resync_with(&d, &a, &mut s).await;
    let after = view(true);
    assert!(after.remote_pending.is_empty());
    assert_eq!(after.issuance, IssuanceGate::Reconciled);
    assert!(after.residuals[0].acknowledged);
    assert_ne!(r.grant_state(), GrantState::Active);
    assert!(r.w.runner.issuance().keys().installed().is_empty());

    // The local operations' answers (what the dispatcher returns in place of `NOT_FOUND`).
    let revoked = revoke_on_runner(&a.store, &r.w.grant, a.now())
        .expect("a recorded runner's grant")
        .unwrap();
    assert!(!revoked.data.local_applied);
    assert_eq!(revoked.data.remote_pending, vec![r.w.grant.clone()]);
    assert!(revoked.data.latest_possible_credential_expiry.is_some());
    assert!(revoke_on_runner(&a.store, &GrantId::from_random_bytes([0x55; 16]), a.now()).is_none());
    let paused = policy_on_runner(&a.store, &pause, a.now())
        .expect("a policy the runner's report listed")
        .unwrap();
    assert_eq!(paused.data["remote_pending"], true);
    assert_eq!(paused.data["environment"], r.w.env.as_str());
    assert!(policy_on_runner(&a.store, &all, a.now()).is_none());
}

// --- ⟨M06 W3 host⟩ the certificate's content is this controller's; the hosted pass -----------

/// ADR-0005 §3.5 "Remote reservations", conditions 6 and 7, at the driver: the runner's
/// prepare answer only narrows. An answer naming a pair this controller did not deliver is
/// refused before anything is reserved; a longer validity (the asked lifetime, and the
/// runner's own later bound) is cut to the delivered grant's expiry; the extensions are the
/// delivered ones. Nothing is ever signed as the runner asked.
#[tokio::test]
async fn the_runners_answer_only_narrows_what_this_controller_delivered() {
    let r = rig().await;
    r.w.trust(&r.w.ca_a, &controller_a());
    r.w.designate(&controller_a());
    let issuer = FixtureIssuer { ca: &r.w.ca_a };

    // An extra principal: the controller delivered h1; the runner's grant (and so its
    // answer) names h1 and h2. Refused whole: no entry, nothing installed.
    let a = controller(&r, &controller_a(), Role::Owner);
    deliver(&a, &r, &["h1"], deadline());
    let d = driver(&a);
    let mut s = r.session(&controller_a());
    resync_with(&d, &a, &mut s).await;
    let e = d
        .issue(&a.pin, &mut s, &issuer, &input(&r, &r.w.grant))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable, "{e:?}");
    assert!(
        a.store
            .transaction(|tx| tx.issuance_entries(&r.w.grant))
            .unwrap()
            .is_empty(),
        "refused before the reservation"
    );
    assert!(r.w.runner.issuance().keys().installed().is_empty());

    // A longer validity: five hours asked, the runner's bound is two hours, the delivered
    // grant expires in one. The certificate ends at the delivered expiry.
    let a = controller(&r, &controller_a(), Role::Owner);
    let expires = plus(a.now(), HOUR);
    deliver(&a, &r, &["h1", "h2"], expires);
    let d = driver(&a);
    let mut s = r.session(&controller_a());
    s.connection = 21;
    resync_with(&d, &a, &mut s).await;
    let issued = d
        .issue(
            &a.pin,
            &mut s,
            &issuer,
            &RemoteIssueInput {
                lifetime: Duration::from_secs(5 * 3600),
                ..input(&r, &r.w.grant)
            },
        )
        .await
        .unwrap();
    assert_eq!(issued.certificates.len(), 2);
    let entries = a
        .store
        .transaction(|tx| tx.issuance_entries(&r.w.grant))
        .unwrap();
    for e in &entries {
        assert_eq!(
            e.bounds.valid_before, expires,
            "cut to the delivered expiry"
        );
        assert_eq!(
            e.bounds.extensions,
            BTreeSet::from(["permit-pty".to_owned()]),
            "the delivered extensions"
        );
    }
    for (_, _, _, c) in r.w.runner.issuance().keys().installed() {
        assert_eq!(c.valid_before, expires);
    }
    // The key binding the reservation rests on is on record, for the issuer's own check.
    let record = a
        .store
        .transaction(|tx| tx.delivered_grant(&r.w.env, &r.w.grant))
        .unwrap()
        .unwrap();
    let binding = record.prepared.expect("the verified answer's binding");
    assert_eq!(binding.grant_generation, r.w.generation());
    assert_eq!(binding.key_fingerprint, r.w.k_env().fingerprint);
    assert_eq!(binding.runner_bound, deadline());
    assert_eq!(
        Some(binding.report_at),
        d.barrier().reconciliation(&r.w.env).map(|x| x.at)
    );

    // Re-recording a delivered grant can only narrow it.
    deliver(&a, &r, &["h1", "h2", "h3"], plus(a.now(), 9 * HOUR));
    let again = a
        .store
        .transaction(|tx| tx.delivered_grant(&r.w.env, &r.w.grant))
        .unwrap()
        .unwrap();
    assert_eq!(again.pairs, BTreeSet::from([pair("h1"), pair("h2")]));
    assert_eq!(again.expires_at, expires);
    // A limited role records nothing.
    let v = controller(&r, &controller_a(), Role::Requester);
    let refused = v
        .store
        .transaction(|tx| {
            deliver_runner_grant(
                tx,
                &v.pin,
                &r.w.grant,
                &BTreeSet::from([pair("h1")]),
                &BTreeSet::new(),
                deadline(),
                v.now(),
            )
        })
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.reason.as_deref(), Some(reason::ROLE_INSUFFICIENT));
}

/// The hosted pass (`ControllerSync::maintain`): after a resynchronization it issues for the
/// delivered grants the report shows no certificate for, and for nothing else; a failure is
/// recorded with the grant and shown by the status view until an issuance succeeds.
#[tokio::test]
async fn the_hosted_pass_issues_for_delivered_grants_and_records_failures() {
    let r = rig().await;
    r.w.trust(&r.w.ca_a, &controller_a());
    let a = controller(&r, &controller_a(), Role::Owner);
    record_pin(&a);
    deliver_all(&a, &r);
    let d = driver(&a);
    let issuer = FixtureIssuer { ca: &r.w.ca_a };
    let view = || {
        a.store
            .transaction(|tx| status_of(tx, &r.w.env, true, Some(d.barrier()), a.now()))
            .unwrap()
    };

    // No designated time source yet: the runner's time is unbounded, nothing is issued, and
    // the failure is on record.
    let mut s = r.session(&controller_a());
    let first = d.on_channel(&a, &mut s).await;
    let m = d.maintain(&a.pin, &mut s, &issuer, &first.report).await;
    assert!(m.issued.is_empty());
    assert_eq!(m.failed.len(), 1);
    assert_eq!(m.failed[0].1.code, Code::TimeUncertain);
    let failures = view().issuance_failures;
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].grant, r.w.grant);
    assert_eq!(failures[0].reason, "time_uncertain");
    assert!(r.w.runner.issuance().keys().installed().is_empty());

    // Designated: the next pass issues both pairs and clears the failure.
    r.w.designate(&controller_a());
    let mut s = r.session(&controller_a());
    s.connection = 31;
    let second = d.on_channel(&a, &mut s).await;
    let m = d.maintain(&a.pin, &mut s, &issuer, &second.report).await;
    assert!(m.failed.is_empty(), "{:?}", m.failed);
    assert_eq!(m.issued.len(), 1);
    assert_eq!(m.issued[0].certificates.len(), 2);
    assert!(view().issuance_failures.is_empty());
    assert_eq!(r.w.runner.issuance().keys().installed().len(), 2);
    // The certificates run to the delivered grant's bound: no renewal is needed within it.
    for (_, _, _, c) in r.w.runner.issuance().keys().installed() {
        assert_eq!(c.valid_before, deadline());
    }

    // A later pass: the report shows both certificates, nothing more is reserved.
    let third = d.on_channel(&a, &mut s).await;
    let before = s.sent();
    let m = d.maintain(&a.pin, &mut s, &issuer, &third.report).await;
    assert!(m.issued.is_empty() && m.failed.is_empty());
    assert_eq!(s.sent(), before, "nothing asked of the runner");
    assert_eq!(
        a.store
            .transaction(|tx| tx.issuance_entries(&r.w.grant))
            .unwrap()
            .len(),
        2
    );

    // Revoked on the runner: the pass leaves it alone (a revoked grant is never issued for).
    a.produce(&Narrowing::RevokeGrant {
        grant: r.w.grant.clone(),
        grant_generation: r.w.generation(),
    })
    .unwrap();
    let fourth = d.on_channel(&a, &mut s).await;
    let before = s.sent();
    let m = d.maintain(&a.pin, &mut s, &issuer, &fourth.report).await;
    assert!(m.issued.is_empty() && m.failed.is_empty());
    assert_eq!(s.sent(), before);
}

/// Ruling on `driver` Q2: a local cutoff of **every** policy fans out to every runner this
/// controller owns, as one pending effect each; the answer lists every runner it was
/// delivered to and every runner it is still pending on. A profile's, a workspace's or one
/// policy's cutoff does not fan out; a runner this controller does not own gets nothing.
#[tokio::test]
async fn a_cutoff_of_every_policy_fans_out_to_every_owned_runner() {
    let r = rig().await;
    r.w.trust(&r.w.ca_a, &controller_a());
    r.w.designate(&controller_a());
    let a = controller(&r, &controller_a(), Role::Owner);
    record_pin(&a);
    let d = driver(&a);
    let at = plus(a.now(), HOUR);
    let cutoff = |target: PolicyTarget| PolicyAction::Cutoff {
        policy_id: None,
        at,
        target: Some(target),
    };
    assert_eq!(cutoff_of_all(&cutoff(PolicyTarget::All)), Some(at));
    assert_eq!(
        cutoff_of_all(&cutoff(PolicyTarget::Profile { profile: profile() })),
        None
    );
    assert_eq!(
        cutoff_of_all(&cutoff(PolicyTarget::Policy {
            policy_id: policy_id()
        })),
        None
    );
    assert_eq!(
        cutoff_of_all(&PolicyAction::Pause {
            policy_id: None,
            target: Some(PolicyTarget::All)
        }),
        None
    );

    let sent = cutoff_all_on_runners(&a.store, at, a.now()).unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].environment, r.w.env);
    assert!(sent[0].produced);
    assert!(matches!(
        &sent[0].key.target,
        EffectTarget::PolicyCutoff { scope: PolicyTarget::All, at: t, .. } if *t == at
    ));
    // Repeating the request reuses the pending row.
    let again = cutoff_all_on_runners(&a.store, at, a.now()).unwrap();
    assert_eq!(again[0].key, sent[0].key);
    assert!(!again[0].produced);
    assert_eq!(a.pending(), 1);

    // Pending until delivered: in the answer, and in the status view.
    let listed = runner_deliveries(&a.store, &sent);
    assert_eq!(listed["delivered"].as_array().unwrap().len(), 0);
    assert_eq!(listed["pending"][0]["environment"], r.w.env.as_str());
    assert_eq!(a.status(false).remote_pending.len(), 1);

    // Delivered at the reconnect: acknowledged, listed as delivered, and the runner's
    // policy carries the cutoff.
    let mut s = r.session(&controller_a());
    resync_with(&d, &a, &mut s).await;
    let listed = runner_deliveries(&a.store, &sent);
    assert_eq!(listed["delivered"][0]["environment"], r.w.env.as_str());
    assert_eq!(listed["pending"].as_array().unwrap().len(), 0);
    assert!(a.status(true).remote_pending.is_empty());
    assert_eq!(a.pending(), 0);

    // A runner this controller is not an owner of: nothing is produced for it.
    let v = controller(&r, &controller_a(), Role::Viewer);
    record_pin(&v);
    assert!(
        cutoff_all_on_runners(&v.store, at, v.now())
            .unwrap()
            .is_empty()
    );
    assert_eq!(v.pending(), 0);
}

// --- a runner grant's binding (ADR-0012 §4.1, §4.6; integrator item, followups DONE-b Q2) ----

/// A signature authority that admits nothing: the listing never signs.
#[cfg(unix)]
struct NoAuthority;

#[cfg(unix)]
#[async_trait::async_trait]
impl heimdall_app::ports::SignatureAuthority for NoAuthority {
    async fn precheck(
        &self,
        _facts: &heimdall_app::ports::SignatureRequestFacts,
    ) -> Result<(), heimdall_app::ports::SignRefusal> {
        Err(heimdall_app::ports::SignRefusal::Unavailable)
    }
    async fn admit(
        &self,
        _facts: &heimdall_app::ports::SignatureRequestFacts,
    ) -> Result<heimdall_app::managed::SignPermit, heimdall_app::ports::SignRefusal> {
        Err(heimdall_app::ports::SignRefusal::Unavailable)
    }
}

/// The endpoints source as the runtime's `LateRegistry` routes a runner grant's binding: to
/// the runner's own binding endpoints, and to nothing else here.
#[cfg(unix)]
struct RunnerOnly(heimdall_runtime::service::RunnerBindingEndpoints);

#[cfg(unix)]
impl heimdall_adapters::managed::effects::BindingEndpoints for RunnerOnly {
    fn binding_endpoint(
        &self,
        binding: &heimdall_contract::ids::BindingId,
    ) -> Option<heimdall_contract::provider::EndpointRef> {
        self.0.endpoint(binding)
    }

    fn create_binding_endpoint_at(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        generation: u64,
        placement: &heimdall_credential::endpoints::EndpointPlacement,
    ) -> Result<heimdall_contract::provider::EndpointRef, heimdall_app::ports::AdapterError> {
        self.0.create(binding, generation, placement).unwrap_or(Err(
            heimdall_app::ports::AdapterError::Unavailable("binding_endpoint_unavailable".into()),
        ))
    }

    fn remove_binding_endpoint(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        generation: u64,
    ) -> Result<bool, heimdall_app::ports::AdapterError> {
        self.0.remove(binding, generation)
    }

    fn runner_grant_content(
        &self,
        binding: &heimdall_contract::ids::BindingId,
        grant: &GrantId,
    ) -> Option<(String, Vec<heimdall_app::ports::MaterializedCertificate>)> {
        self.0.installed(binding, grant)
    }
}

#[cfg(unix)]
struct NativeScopes;

#[cfg(unix)]
impl heimdall_adapters::managed::effects::GrantScopes for NativeScopes {}

/// After a remote issuance, a binding of the runner's grant is materialized from the
/// runner's own signer (`ManagedEffectsImpl::materialize`, the runner-grant path): its
/// endpoint lists exactly the K_env certificates the runner installed, never the plain K_env
/// and never the CA's key; its files carry K_env.pub and those certificates; a binding of a
/// grant the runner signer does not hold is refused as before. After the owner's revoke is
/// delivered the endpoint lists nothing.
#[cfg(unix)]
#[tokio::test]
async fn a_remotely_issued_grants_binding_lists_the_runners_k_env_identity_only() {
    use heimdall_adapters::managed::effects::ManagedEffectsImpl;
    use heimdall_adapters::managed::files::SlotRoot;
    use heimdall_app::ports::{
        DistributionStart, ManagedEffects as _, MaterializeSource, MaterializeSpec,
    };
    use heimdall_contract::ids::BindingId;
    use heimdall_credential::endpoints::EndpointLayout;
    use heimdall_credential::table::SignerTable;
    use heimdall_credential::vault::KeyVault;
    use heimdall_runtime::service::RunnerBindingEndpoints;
    use heimdall_testkit::agent::{AgentConnection, Endpoint};

    let r = rig().await;
    r.w.trust(&r.w.ca_a, &controller_a());
    r.w.designate(&controller_a());
    let a = controller(&r, &controller_a(), Role::Owner);
    let d = driver(&a);
    deliver_all(&a, &r);
    let mut s = r.session(&controller_a());
    resync_with(&d, &a, &mut s).await;
    d.issue(
        &a.pin,
        &mut s,
        &FixtureIssuer { ca: &r.w.ca_a },
        &input(&r, &r.w.grant),
    )
    .await
    .unwrap();
    let installed: Vec<Vec<u8>> =
        r.w.runner
            .issuance()
            .keys()
            .installed()
            .iter()
            .map(|(_, _, _, c)| {
                ssh_key::Certificate::from_openssh(c.certificate.trim())
                    .unwrap()
                    .to_bytes()
                    .unwrap()
            })
            .collect();
    assert_eq!(installed.len(), 2);

    // The runner's managed effects: their own (empty) signer table, and the runner's binding
    // endpoints behind the endpoints source. A short directory keeps the socket path legal.
    let dir = tempfile::Builder::new()
        .prefix("hm-rd")
        .tempdir_in("/tmp")
        .unwrap();
    // The runtime directory anchor is owner-only in production (`Paths::ensure` creates it
    // 0700 explicitly); `tempfile` leaves it to the umask, and under umask 002 the anchor
    // check refuses the 0775 result (`managed_dir_unsafe`).
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let stop = tokio_util::sync::CancellationToken::new();
    let binding = BindingId::from_random_bytes([0x81; 16]);
    let foreign = BindingId::from_random_bytes([0x82; 16]);
    let foreign_grant = GrantId::from_random_bytes([0x83; 16]);
    let (g, b, f, fg) = (
        r.w.grant.clone(),
        binding.clone(),
        foreign.clone(),
        foreign_grant.clone(),
    );
    let endpoints = RunnerBindingEndpoints::new(
        std::sync::Arc::clone(&r.w.runner),
        EndpointLayout::unix(dir.path()).unwrap(),
        heimdall_ipc::endpoint::ExpectedOwner::Uid(heimdall_ipc::unix::current_uid()),
        std::sync::Arc::new(NoAuthority),
        heimdall_credential::signer::SignerLimits::default(),
        stop.clone(),
        std::sync::Arc::new(move |id: &BindingId| {
            if id == &b {
                Some(g.clone())
            } else if id == &f {
                Some(fg.clone())
            } else {
                None
            }
        }),
    );
    let effects = ManagedEffectsImpl::new(
        SignerTable::new(std::sync::Arc::new(KeyVault::new())),
        std::sync::Arc::new(RunnerOnly(endpoints.clone())),
        std::sync::Arc::new(NativeScopes),
        dir.path().to_path_buf(),
        SlotRoot {
            data_dir: dir.path().join("state"),
            environment: r.w.env.clone(),
        },
    );
    let spec = |grant: &GrantId| MaterializeSpec {
        generation: 1,
        source: MaterializeSource::InstalledKeyOf {
            grant: grant.clone(),
        },
        environment_slots: false,
        start: DistributionStart::Forbidden,
    };

    // A grant the runner signer does not hold: refused as before, nothing created.
    assert!(
        effects
            .materialize(&foreign, &spec(&foreign_grant))
            .is_err()
    );
    assert!(endpoints.endpoint(&foreign).is_none());

    let files = effects.materialize(&binding, &spec(&r.w.grant)).unwrap();
    let endpoint = files
        .endpoint
        .expect("the materialization created the endpoint");
    assert_eq!(endpoints.endpoint(&binding), Some(endpoint.clone()));
    let k_env = r.w.k_env();
    assert!(
        files.files.iter().any(|p| {
            std::fs::read_to_string(p).is_ok_and(|t| t.trim() == k_env.openssh_line.trim())
        }),
        "the binding's key file is K_env.pub"
    );
    let socket = Endpoint::UnixSocket(endpoint.locator.clone().into());
    let list = |socket: Endpoint| async move {
        tokio::task::spawn_blocking(move || {
            AgentConnection::connect(&socket, Duration::from_secs(10))
                .unwrap()
                .list()
                .unwrap()
        })
        .await
        .unwrap()
    };
    let mut listed: Vec<Vec<u8>> = list(socket.clone())
        .await
        .into_iter()
        .map(|(blob, _)| blob)
        .collect();
    listed.sort();
    let mut expected = installed.clone();
    expected.sort();
    assert_eq!(listed, expected, "exactly the runner's K_env certificates");
    let ca = r.w.ca_a.public_key().to_bytes().unwrap();
    assert!(listed.iter().all(|blob| blob != &k_env.blob && blob != &ca));

    // The owner's revoke, delivered at the next reconnect: the endpoint lists nothing.
    a.produce(&Narrowing::RevokeGrant {
        grant: r.w.grant.clone(),
        grant_generation: r.w.generation(),
    })
    .unwrap();
    let mut s = r.session(&controller_a());
    s.connection = 12;
    resync_with(&d, &a, &mut s).await;
    assert!(list(socket).await.is_empty(), "nothing after the revoke");
    assert!(effects.materialize(&binding, &spec(&r.w.grant)).is_err());
    endpoints.stop_all();
    stop.cancel();
}

// --- ⟨M06 W3 grant-path⟩ how a grant comes to exist on a runner ----------------------------
//
// ADR-0012 §4 item 2 (the ⟨2026-11-21⟩ bullets) and ADR-0005 §3.5 conditions 6 and 8, against
// the runner's real `ensure` pipeline with the runner's own adapter for `managed_certificate`
// (`heimdall_runtime::runner::adapter`), the real runner runtime, and this controller's real
// driver. Only where a binding's endpoint and files would be created is a fixture.

mod grant_path {
    use std::sync::{Arc, Mutex};

    use heimdall_app::context::Caller;
    use heimdall_app::ensure::NoStageHook;
    use heimdall_app::operations::Limits;
    use heimdall_app::ports::AdapterError;
    use heimdall_app::remote_env::{ManagementCall, ManagementSession, SessionHello};
    use heimdall_app::remote_status_driver::{Forwarded, SessionChannel, forwarded_ask};
    use heimdall_app::{Operations, OperationsConfig};
    use heimdall_contract::ids::{BindingId, ClientId, RequestId, WorkId};
    use heimdall_contract::provider::EndpointRef;
    use heimdall_contract::request::{
        AccessPairRef, DeadlineIntent, EnsureRequest, InteractionMode, RequiredCapabilities,
        WaitMode,
    };
    use heimdall_domain::issuance::principal_for;
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::time::{SyncStatus, TimePolicy};
    use heimdall_remote::sync::RunnerSync;
    use heimdall_runtime::runner::adapter::{RunnerManagedAdapter, RunnerMaterializer};
    use heimdall_testkit::ScriptedTimeSync;

    use super::*;

    /// Where a binding would be realized: records what it was asked, creates nothing.
    #[derive(Default)]
    struct Materialized {
        made: Mutex<Vec<(BindingId, GrantId)>>,
        cleared: Mutex<Vec<GrantId>>,
    }

    impl RunnerMaterializer for Materialized {
        fn materialize(
            &self,
            binding: &BindingId,
            grant: &GrantId,
        ) -> Result<EndpointRef, AdapterError> {
            self.made
                .lock()
                .unwrap()
                .push((binding.clone(), grant.clone()));
            Ok(serde_json::from_value(serde_json::json!({
                "kind": "unix_socket",
                "locator": format!("/fixture/{}.sock", binding.as_str()),
            }))
            .expect("an endpoint reference"))
        }

        fn clear(&self, grant: &GrantId) -> Result<(), AdapterError> {
            self.cleared.lock().unwrap().push(grant.clone());
            Ok(())
        }
    }

    /// The sync fixture's rig, as a runner runtime wires it: the runner's adapter for the
    /// managed mechanism, the `ensure` pipeline reading the runner's signer, and a completed
    /// install driving the waiting operations on.
    async fn runner_rig() -> (Rig, Arc<Materialized>) {
        let w = world();
        w.store
            .transaction(|tx| {
                let mut e = tx.environment(&w.env)?.unwrap();
                e.permissions = heimdall_domain::environment::EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                };
                tx.upsert_environment(&e)
            })
            .unwrap();
        let materialized = Arc::new(Materialized::default());
        let adapter = Arc::new(RunnerManagedAdapter::new(w.store.clone()));
        adapter.bind(w.runner.clone(), materialized.clone());
        let time_sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let ops = Operations::start(OperationsConfig {
            store: w.store.clone(),
            clock: w.clock.clone(),
            time_sync: time_sync.clone(),
            time_policy: TimePolicy::default(),
            environment: w.env.clone(),
            adapters: vec![adapter],
            stage_hook: Arc::new(NoStageHook),
            limits: Limits::default(),
            default_window: 12 * HOUR,
            projection: None,
        })
        .await
        .unwrap();
        ops.set_runner_grants(w.runner.clone());
        let (resumed, handle) = (ops.clone(), tokio::runtime::Handle::current());
        w.runner.on_issued(Arc::new(move |grant| {
            let (ops, grant) = (resumed.clone(), grant.clone());
            handle.spawn(async move {
                ops.runner_grant_issued(&grant).await.unwrap();
            });
        }));
        let sync = RunnerSync::new(w.store.clone(), ops.clone(), w.clock.clone());
        (
            Rig {
                w,
                ops,
                sync,
                time_sync,
            },
            materialized,
        )
    }

    /// A management session to the rig's runner as the hosted driver holds it: the `runner/1`
    /// forms go where the fixture session sends them, and a forwarded `ensure` reaches the
    /// runner's real pipeline as the paired client's request. `admits` replaces the pairs
    /// the runner sees (a runner that admits more than it was asked).
    struct Managed<'a> {
        rig: &'a Rig,
        inner: Session<'a>,
        hello: SessionHello,
        admits: Option<BTreeSet<AccessPairRef>>,
        ensures: usize,
    }

    fn managed<'a>(rig: &'a Rig, client: &ClientId) -> Managed<'a> {
        Managed {
            rig,
            inner: rig.session(client),
            hello: SessionHello {
                environment: rig.w.env.clone(),
                role: Some(Role::Owner),
                client: Some(client.clone()),
            },
            admits: None,
            ensures: 0,
        }
    }

    #[async_trait::async_trait]
    impl ManagementSession for Managed<'_> {
        fn hello(&self) -> &SessionHello {
            &self.hello
        }

        fn runner_negotiated(&self) -> bool {
            true
        }

        async fn call(
            &mut self,
            call: ManagementCall,
        ) -> Result<Envelope<serde_json::Value>, OpError> {
            match call {
                ManagementCall::Runner(request) => self.inner.call(request).await,
                ManagementCall::Ensure(mut request) => {
                    self.ensures += 1;
                    if let Some(pairs) = &self.admits {
                        request.scope.clone_from(pairs);
                    }
                    let caller = Rig::caller(&self.inner.client);
                    Ok(heimdall_runtime::dispatch::render(
                        self.rig.ops.ensure(&caller, *request).await,
                    ))
                }
                ManagementCall::Environment(_) => Err(OpError::new(
                    Code::UsageError,
                    "not a form this fixture session carries",
                )),
            }
        }
    }

    fn ensure_request(r: &Rig, id: &str, pairs: &[&str]) -> EnsureRequest {
        EnsureRequest {
            profile: Some(profile()),
            profile_revision: None,
            scope: pairs.iter().map(|d| pair(d)).collect(),
            environment: Some(r.w.env.clone()),
            work_id: WorkId::parse("job-1").unwrap(),
            until: Some(DeadlineIntent::Duration("1h".into())),
            required_capabilities: RequiredCapabilities::default(),
            request_id: RequestId::parse(id).unwrap(),
            interaction: InteractionMode::NonInteractive,
            wait: WaitMode::default(),
            connection: None,
            context: None,
            covered_only: false,
        }
    }

    fn grant_state(r: &Rig, grant: &GrantId) -> GrantState {
        r.w.store
            .transaction(|tx| tx.grant(grant))
            .unwrap()
            .unwrap()
            .state
    }

    fn pairs_of(r: &Rig, grant: &GrantId) -> BTreeSet<AccessPairRef> {
        r.w.store
            .transaction(|tx| tx.grant(grant))
            .unwrap()
            .unwrap()
            .scope
            .pairs
    }

    /// The fixture controller A, trusted and designated, with its pin on record.
    fn issuing_controller(r: &Rig) -> Controller {
        r.w.trust(&r.w.ca_a, &controller_a());
        r.w.designate(&controller_a());
        let a = controller(r, &controller_a(), Role::Owner);
        record_pin(&a);
        a
    }

    /// One hosted pass over `s`: the reconnect order, then issuance for the delivered grants.
    async fn pass(
        d: &ControllerSync,
        a: &Controller,
        s: &mut Managed<'_>,
        issuer: &dyn RemoteIssuer,
    ) -> heimdall_app::remote_status_driver::Maintained {
        let outcome = d.on_session(&a.pin, s).await.unwrap();
        let mut channel = SessionChannel::new(s).unwrap();
        d.maintain(&a.pin, &mut channel, issuer, &outcome.report)
            .await
    }

    /// What this controller asks is exactly what it records: pairs and a deadline it named.
    #[test]
    fn a_forwarded_ensure_names_its_pairs_and_its_deadline() {
        let now = t0();
        let base = EnsureRequest {
            profile: Some(profile()),
            profile_revision: None,
            scope: [pair("h1")].into_iter().collect(),
            environment: None,
            work_id: WorkId::parse("job-1").unwrap(),
            until: Some(DeadlineIntent::Duration("1h".into())),
            required_capabilities: RequiredCapabilities::default(),
            request_id: RequestId::parse("r").unwrap(),
            interaction: InteractionMode::NonInteractive,
            wait: WaitMode::default(),
            connection: None,
            context: None,
            covered_only: false,
        };
        let ask = forwarded_ask(&base, now).unwrap();
        assert_eq!(ask.pairs, BTreeSet::from([pair("h1")]));
        assert_eq!(ask.expires_at, plus(now, HOUR));
        assert_eq!(ask.extensions, BTreeSet::from(["permit-pty".to_owned()]));
        for broken in [
            EnsureRequest {
                scope: BTreeSet::new(),
                ..base.clone()
            },
            EnsureRequest {
                until: None,
                ..base.clone()
            },
            EnsureRequest {
                until: Some(DeadlineIntent::Absolute("2026-11-21T08:00:00Z".into())),
                ..base.clone()
            },
        ] {
            let e = forwarded_ask(&broken, now).unwrap_err();
            assert_eq!(e.code, Code::UsageError);
            assert_eq!(e.effect_status, heimdall_contract::EffectStatus::None);
        }
    }

    /// The product path, end to end on the library level: a forwarded `ensure` is admitted by
    /// the runner under its own standing policy and waits (`preparing`, no key, no attempt);
    /// the controller records exactly what it asked; the hosted pass signs within that record
    /// and nothing else; the install drives the runner's waiting `ensure` to a binding
    /// realized from the runner's signer, whose refresh dependency is the controller.
    #[tokio::test]
    async fn a_forwarded_ensure_waits_for_its_issuer_and_is_signed_within_its_record() {
        let (r, materialized) = runner_rig().await;
        let a = issuing_controller(&r);
        let d = driver(&a);
        let issuer = FixtureIssuer { ca: &r.w.ca_a };
        let mut s = managed(&r, &controller_a());
        d.on_session(&a.pin, &mut s).await.unwrap();

        // Only h1 of the profile's two pairs is asked for.
        let request = ensure_request(&r, "fwd-1", &["h1"]);
        let asked_at = a.now();
        let Forwarded::Pending { grant, record } =
            d.forward_ensure(&a.pin, &mut s, &request).await.unwrap()
        else {
            panic!("the grant waits for its issuer");
        };
        assert_ne!(grant, r.w.grant);
        assert_eq!(record.pairs, BTreeSet::from([pair("h1")]));
        assert_eq!(record.extensions, BTreeSet::from(["permit-pty".to_owned()]));
        assert_eq!(record.expires_at, plus(asked_at, HOUR));
        // On the runner: admitted and waiting. No key, nothing realized, nothing in any ledger.
        assert_eq!(grant_state(&r, &grant), GrantState::Preparing);
        assert_eq!(pairs_of(&r, &grant), BTreeSet::from([pair("h1")]));
        assert!(r.w.runner.issuance().keys().public_key(&grant).is_none());
        assert!(materialized.made.lock().unwrap().is_empty());
        assert!(
            a.store
                .transaction(|tx| tx.issuance_entries(&grant))
                .unwrap()
                .is_empty()
        );
        // The same request again reads the same grant; the record does not widen.
        let Forwarded::Pending { grant: again, .. } =
            d.forward_ensure(&a.pin, &mut s, &request).await.unwrap()
        else {
            panic!("still pending");
        };
        assert_eq!(again, grant);

        // The hosted pass: one certificate, for the pair asked, inside the record.
        let m = pass(&d, &a, &mut s, &issuer).await;
        assert!(m.failed.is_empty(), "{:?}", m.failed);
        assert_eq!(
            m.issued.len(),
            1,
            "the seeded grant has no record: untouched"
        );
        assert_eq!(m.issued[0].grant, grant);
        let entries = a
            .store
            .transaction(|tx| tx.issuance_entries(&grant))
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].pair, pair("h1"));
        assert_eq!(entries[0].bounds.principal, principal_for(&pair("h1")));
        assert_eq!(
            entries[0].bounds.extensions,
            BTreeSet::from(["permit-pty".to_owned()])
        );
        assert!(entries[0].bounds.valid_before <= record.expires_at);
        assert!(
            a.store
                .transaction(|tx| tx.issuance_entries(&r.w.grant))
                .unwrap()
                .is_empty()
        );

        // The install drives the waiting `ensure` on: read it through the same request.
        let mut ready = None;
        for _ in 0..500 {
            match d.forward_ensure(&a.pin, &mut s, &request).await.unwrap() {
                Forwarded::Ready { grant: g, data } => {
                    assert_eq!(g, grant);
                    ready = Some(data);
                    break;
                }
                Forwarded::Pending { .. } => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
        let data = ready.expect("the runner's ensure settles once its certificate is installed");
        assert_eq!(data["refresh_dependency"], "controller");
        assert_eq!(data["credential_mechanism"], "managed_certificate");
        assert_eq!(grant_state(&r, &grant), GrantState::Active);
        let made = materialized.made.lock().unwrap().clone();
        assert_eq!(made.len(), 1, "one binding, realized once");
        assert_eq!(made[0].1, grant);
        assert_eq!(data["binding_id"], made[0].0.as_str());
        // Usable no longer than the certificate the controller issued.
        let until: Timestamp = serde_json::from_value(data["usable_until"].clone()).unwrap();
        assert_eq!(until, entries[0].bounds.valid_before);
        // Nothing more is reserved by a later pass.
        let m = pass(&d, &a, &mut s, &issuer).await;
        assert!(
            m.issued.is_empty() && m.failed.is_empty(),
            "{:?} {:?}",
            m.issued,
            m.failed
        );
    }

    /// A grant the runner admitted for a request no controller forwarded is never signed: the
    /// hosted pass asks nothing for it, a direct ask is refused before anything is sent, and
    /// the grant stays pending, saying what it waits for.
    #[tokio::test]
    async fn a_runner_originated_pending_grant_outside_any_controller_record_is_never_signed() {
        let (r, materialized) = runner_rig().await;
        let a = issuing_controller(&r);
        let d = driver(&a);
        let issuer = FixtureIssuer { ca: &r.w.ca_a };

        // The runner's own local owner asks (no controller is involved).
        let local = Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 1000 },
            role: ClientRole::Owner,
            remote_client: None,
        });
        let request = ensure_request(&r, "local-1", &["h1"]);
        let e = r.ops.ensure(&local, request.clone()).await.unwrap_err();
        assert_eq!(e.code, Code::Accepted, "{e:?}");
        assert!(e.message.contains("controller_dependency"), "{}", e.message);
        let resource = e.resource.expect("the pending grant is named");
        assert_eq!(resource.kind, "grant");
        let grant = GrantId::parse(resource.id.as_deref().unwrap()).unwrap();
        assert_eq!(grant_state(&r, &grant), GrantState::Preparing);

        // The hosted pass: this controller delivered nothing, so it asks nothing.
        let mut s = managed(&r, &controller_a());
        let outcome = d.on_session(&a.pin, &mut s).await.unwrap();
        let before = s.inner.sent();
        let m = {
            let mut channel = SessionChannel::new(&mut s).unwrap();
            d.maintain(&a.pin, &mut channel, &issuer, &outcome.report)
                .await
        };
        assert!(m.issued.is_empty() && m.failed.is_empty());
        assert_eq!(s.inner.sent(), before, "nothing asked of the runner");
        // Asked for by name: refused before anything is prepared.
        let refused = {
            let mut channel = SessionChannel::new(&mut s).unwrap();
            d.issue(
                &a.pin,
                &mut channel,
                &issuer,
                &RemoteIssueInput {
                    grant: grant.clone(),
                    grant_generation: r.w.generation(),
                    lifetime: Duration::from_secs(1800),
                },
            )
            .await
            .unwrap_err()
        };
        assert!(
            refused.message.contains("holds no record of delivering"),
            "{}",
            refused.message
        );
        assert_eq!(s.inner.sent(), before, "still nothing asked of the runner");
        assert!(
            a.store
                .transaction(|tx| tx.issuance_entries(&grant))
                .unwrap()
                .is_empty()
        );
        assert!(r.w.runner.issuance().keys().public_key(&grant).is_none());
        // Still pending on the runner, and nothing was realized for it.
        assert_eq!(grant_state(&r, &grant), GrantState::Preparing);
        let e = r.ops.ensure(&local, request).await.unwrap_err();
        assert_eq!(e.code, Code::Accepted);
        assert!(materialized.made.lock().unwrap().is_empty());
    }

    /// A runner that admits more than it was asked gets nothing signed: the controller's
    /// record holds only the pair it asked for, the prepare answer names another, and the
    /// whole answer is refused with a message that says so. Nothing is reserved or installed.
    #[tokio::test]
    async fn a_runner_answer_that_widens_a_forwarded_ensure_is_refused_whole() {
        let (r, materialized) = runner_rig().await;
        let a = issuing_controller(&r);
        let d = driver(&a);
        let issuer = FixtureIssuer { ca: &r.w.ca_a };
        let mut s = managed(&r, &controller_a());
        s.admits = Some(BTreeSet::from([pair("h1"), pair("h2")]));
        d.on_session(&a.pin, &mut s).await.unwrap();

        let request = ensure_request(&r, "fwd-wide", &["h1"]);
        let Forwarded::Pending { grant, record } =
            d.forward_ensure(&a.pin, &mut s, &request).await.unwrap()
        else {
            panic!("pending");
        };
        assert_eq!(record.pairs, BTreeSet::from([pair("h1")]), "what was asked");
        assert_eq!(
            pairs_of(&r, &grant),
            BTreeSet::from([pair("h1"), pair("h2")]),
            "what the runner admitted"
        );

        let m = pass(&d, &a, &mut s, &issuer).await;
        assert!(m.issued.is_empty());
        assert_eq!(m.failed.len(), 1);
        assert_eq!(m.failed[0].0, grant);
        assert!(
            m.failed[0]
                .1
                .message
                .contains("names a pair this controller did not deliver"),
            "{}",
            m.failed[0].1.message
        );
        assert!(
            a.store
                .transaction(|tx| tx.issuance_entries(&grant))
                .unwrap()
                .is_empty(),
            "nothing reserved"
        );
        assert!(r.w.runner.issuance().keys().installed().is_empty());
        assert_eq!(grant_state(&r, &grant), GrantState::Preparing);
        assert!(materialized.made.lock().unwrap().is_empty());
    }

    /// A request beyond the runner's standing policy is the runner's to decide, at the runner:
    /// the forwarded `ensure` comes back with the runner-local decision reference, the
    /// controller records nothing, and nothing is issued.
    #[tokio::test]
    async fn a_forwarded_ensure_beyond_the_runners_policy_waits_for_a_runner_local_decision() {
        let (r, _materialized) = runner_rig().await;
        let a = issuing_controller(&r);
        let d = driver(&a);
        let issuer = FixtureIssuer { ca: &r.w.ca_a };
        // The runner's policy now covers h2 only.
        let mut narrowed = policy(&r.w.env, None, 2);
        narrowed.scope.pairs = BTreeSet::from([pair("h2")]);
        r.w.store
            .transaction(|tx| tx.upsert_policy(&narrowed, false))
            .unwrap();
        let mut s = managed(&r, &controller_a());
        d.on_session(&a.pin, &mut s).await.unwrap();

        let e = d
            .forward_ensure(&a.pin, &mut s, &ensure_request(&r, "fwd-beyond", &["h1"]))
            .await
            .unwrap_err();
        assert!(
            matches!(e.code, Code::ApprovalRequired | Code::InteractionRequired),
            "{e:?}"
        );
        assert!(e.next.decision_ref.is_some(), "{e:?}");
        assert!(
            a.store
                .transaction(|tx| tx.delivered_grants(Some(&r.w.env)))
                .unwrap()
                .is_empty(),
            "nothing is recorded for a request the runner has not admitted"
        );
        let m = pass(&d, &a, &mut s, &issuer).await;
        assert!(m.issued.is_empty() && m.failed.is_empty());
        assert!(r.w.runner.issuance().keys().installed().is_empty());
    }
}
