//! ⟨M03 wave 5, round 8; ADR-0008 §17.31 item 2 (W5-C02), §17.28 item 1⟩ The uninstall
//! fence where the reservations are made, end to end at fixture level ([`World`]: the
//! real step protocol against the loopback sshd, the real Verifier, the `TestCa`-backed
//! issuer). The re-check's three probes (`wave5-recheck.md` § W5-C02), each refused or
//! deferred while another connection holds the fence:
//! * [`recheck_allowed_step_result_does_not_start_new_issuance_under_fence`] — a
//!   `StepResult` for an append dispatched before the fence, delivered through a
//!   non-holder dispatcher, is recorded; its initial verification is deferred (no
//!   certificate, no verification entry);
//! * [`recheck_verification_reservation_refused_under_uninstall_fence`] — a direct
//!   verification reservation is refused, nothing written;
//! * [`recheck_direct_admission_refused_under_uninstall_fence`] — a direct application
//!   admission (`enrollment.apply`, and `enrollment.step`) is refused, nothing written.
//!
//! And [`deferred_verification_runs_after_the_fence_lifts`]: once the fence is lifted
//! (the uninstall refused), the next `enroll step` runs the deferred verification and
//! the enrollment completes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::fx::*;
use heimdall_runtime::dispatch::{EventRelay, OperationsDispatcher};
use tokio_util::sync::CancellationToken;

/// The fence holder's connection identity in these tests (never one a dispatcher
/// hands out, which count up from 1).
const HOLDER: u64 = u64::MAX - 8;

fn fence_refusal(e: &OpError) -> bool {
    e.code == Code::ServiceUnavailable && e.reason.as_deref() == Some("uninstall_in_progress")
}

/// A control connection that is not the fence holder (the runtime's dispatcher).
fn other_connection(w: &World) -> OperationsDispatcher {
    let relay = EventRelay::spawn(&w.ops, CancellationToken::new());
    let clock: Arc<dyn Clock> = w.clock.clone();
    OperationsDispatcher::new(w.ops.clone(), relay, clock)
}

/// An apply approved and inspected, its append run against the server before the
/// fence; then the fence taken (by [`HOLDER`]) and the append's result delivered
/// through another connection's dispatcher. Returns the operation and the issuer's
/// signature count before the result.
async fn append_result_under_fence(w: &World, rid: &str) -> (OperationId, usize) {
    let op = w.approved(&w.spec(), rid).await;
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("inspect");
    };
    w.run_and_report(&op, &step).await;
    let StepAnswer::Step { step } = w.step_answer(&op).await else {
        panic!("append");
    };
    assert_eq!(step.stage, RemoteStage::Append);
    let (exit_status, stdout, stderr_excerpt) = run_step(&w.home, &step).await;
    w.ops.uninstall_fence_acquire(HOLDER).await.unwrap();
    let signed = w.issuer.signed.load(Ordering::SeqCst);
    let env = other_connection(w)
        .handle_as(
            &unattended(),
            heimdall_contract::request::Request::Enrollment(EnrollmentRequest::StepResult {
                operation_id: op.clone(),
                step_token: step.step_token.clone(),
                exit_status,
                stdout,
                stderr_excerpt,
            }),
        )
        .await;
    assert_eq!(
        env.code,
        Code::Ok,
        "the pre-fence result is accepted: {env:?}"
    );
    let recorded: StepRecorded = serde_json::from_value(env.data).unwrap();
    assert_eq!(recorded.stage, RemoteStage::Append);
    assert_eq!(
        recorded.state,
        EnrollmentState::AppliedUnverified,
        "{recorded:?}"
    );
    (op, signed)
}

/// `recheck_allowed_step_result_does_not_start_new_issuance_under_fence` (§17.31 item
/// 2; re-check W5-C02's first probe): the allowed `StepResult` is recorded durably (the
/// append confirmed, the record `applied_unverified`, nothing outstanding), and its
/// initial verification is deferred: no certificate is signed, no verification entry
/// reserved, no verification started, while the fence is held.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn recheck_allowed_step_result_does_not_start_new_issuance_under_fence() {
    let w = World::new().await;
    let (op, signed) = append_result_under_fence(&w, "req_g8_sr").await;
    assert_eq!(
        w.issuer.signed.load(Ordering::SeqCst),
        signed,
        "no verification certificate is signed under the fence"
    );
    assert!(w.tx(|tx| tx.verification_entries(&op)).is_empty());
    assert!(
        !w.receipts(&op)
            .iter()
            .any(|r| r.stage == enrollment_stage::VERIFY_STARTED),
        "no verification attempt started"
    );
    let r = w.records().pop().unwrap();
    assert_eq!(r.state, EnrollmentState::AppliedUnverified);
    assert_eq!(w.marker_lines(), 1, "the remote truth is kept");
    assert_eq!(w.op(&op).state, OperationState::Running);
    assert!(
        w.journal(&op).outstanding.is_none(),
        "the result is recorded"
    );
    // Continuing it is refused while the fence is held, through either route.
    let e = w.step(&op).await.unwrap_err();
    assert!(fence_refusal(&e), "{e:?}");
    assert_eq!(w.issuer.signed.load(Ordering::SeqCst), signed);
    assert_eq!(
        w.records().pop().unwrap().state,
        EnrollmentState::AppliedUnverified
    );
    assert!(!w.ops.uninstall_fence_release(HOLDER));
}

/// `deferred_verification_runs_after_the_fence_lifts` (§17.31 item 2): the uninstall
/// refuses and lifts the fence; the normal drive (`enroll step`) picks the deferred
/// follow-through up, verifies with fresh certificates and completes the enrollment.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn deferred_verification_runs_after_the_fence_lifts() {
    let w = World::new().await;
    let (op, signed) = append_result_under_fence(&w, "req_g8_lift").await;
    assert_eq!(w.issuer.signed.load(Ordering::SeqCst), signed);
    assert!(!w.ops.uninstall_fence_release(HOLDER));
    let result = w.drive(&op).await.unwrap();
    assert_eq!(result.state, EnrollmentState::Verified, "{result:?}");
    assert!(
        w.issuer.signed.load(Ordering::SeqCst) > signed,
        "the deferred verification signed its certificates"
    );
    assert_eq!(w.op(&op).state, OperationState::Succeeded);
    assert_eq!(w.records().pop().unwrap().state, EnrollmentState::Verified);
}

/// `recheck_verification_reservation_refused_under_uninstall_fence` (§17.31 item 2;
/// re-check W5-C02's second probe): a verification reservation the predicate admits
/// (an apply's own approval at its own `verifying` stage) is refused
/// `SERVICE_UNAVAILABLE` / `uninstall_in_progress` while another connection holds the
/// fence, nothing written; the same reservation is admitted once the fence is lifted.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn recheck_verification_reservation_refused_under_uninstall_fence() {
    let w = World::new().await;
    // A real apply's `EnrollAccount` summary, which the forged decision reuses.
    let spec = w.spec();
    let plan = w.preview(&spec).await;
    let pending = w
        .apply(
            &attended(),
            &spec,
            &plan,
            "req_g8_vr",
            InteractionMode::NonInteractive,
        )
        .await;
    let decision =
        heimdall_contract::ids::DecisionId::parse(pending.next.decision_ref.as_deref().unwrap())
            .unwrap();
    let (plan_digest, summary) = match w.tx(|tx| tx.decision(&decision)).unwrap().kind {
        heimdall_domain::decision::DecisionKind::EnrollAccount {
            plan_digest,
            summary,
            ..
        } => (plan_digest, summary),
        k => panic!("{k:?}"),
    };
    w.decide(&pending, Verdict::Deny).await.unwrap();
    let y = w.seed(
        EnrollmentState::Verifying,
        EnrollmentForm::Account,
        w.served_target(),
        None,
    );
    let mut journal = Journal {
        enrollment: Some(y.id.clone()),
        ..Journal::default()
    };
    let b = w.forge_op(
        OperationKind::EnrollmentApply,
        OperationState::Running,
        None,
        &journal,
        &[World::append_confirmed(&y.marker), World::verify_started()],
    );
    let own = w.approved_decision(heimdall_domain::decision::DecisionKind::EnrollAccount {
        operation: b.clone(),
        plan_digest,
        summary,
    });
    journal.approval = Some(heimdall_app::enrollment::ApprovalFact {
        decision: own,
        at: w.clock.wall(),
    });
    w.put_journal(&b, &journal);
    w.ops.uninstall_fence_acquire(HOLDER).await.unwrap();
    let now = w.clock.wall();
    let e = w
        .ops
        .reserve_verification(heimdall_app::operations::VerificationRequest {
            operation: b.clone(),
            enrollment: y.id.clone(),
            pair: w.pair(),
            ca_fingerprint: w.issuer.ca.fingerprint().clone(),
            purpose: heimdall_domain::verification::VerificationPurpose::Positive,
            principal: format!("hm:{}:{}", w.destination.as_str(), w.account.as_str()),
            key_id: "verify-key".into(),
            valid_after: Timestamp::from_second(now.as_second() - 60).unwrap(),
            valid_before: Timestamp::from_second(now.as_second() + 240).unwrap(),
            extensions: std::collections::BTreeSet::new(),
            subject_fingerprint: "SHA256:kverify".into(),
            subject_registered: true,
        })
        .await
        .expect_err("refused under the fence");
    assert!(fence_refusal(&e), "{e:?}");
    assert!(w.tx(|tx| tx.verification_entries(&b)).is_empty());
    assert!(!w.ops.uninstall_fence_release(HOLDER));
    assert_eq!(
        w.reserve(&b, &y.id).await,
        Ok(()),
        "admitted after the lift"
    );
}

/// `recheck_direct_admission_refused_under_uninstall_fence` (§17.31 item 2; re-check
/// W5-C02's third probe): a direct application admission (not through the dispatcher)
/// is refused `SERVICE_UNAVAILABLE` / `uninstall_in_progress` while another connection
/// holds the fence: `enrollment.apply` creates no operation, record or decision, and an
/// approved operation's `enrollment.step` dispatches nothing. The read-only preview is
/// still answered. After the lift each is admitted again.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn recheck_direct_admission_refused_under_uninstall_fence() {
    let w = World::new().await;
    let spec = w.spec();
    let plan = w.preview(&spec).await;
    let open = |w: &World| w.tx(|tx| tx.open_operations()).len();
    let (ops_before, records_before) = (open(&w), w.records().len());
    w.ops.uninstall_fence_acquire(HOLDER).await.unwrap();
    let _ = w.preview(&spec).await;
    let e = w
        .apply(
            &attended(),
            &spec,
            &plan,
            "req_g8_da",
            InteractionMode::NonInteractive,
        )
        .await;
    assert!(fence_refusal(&e), "{e:?}");
    assert!(
        e.operation_id.is_none() && e.next.decision_ref.is_none(),
        "{e:?}"
    );
    assert_eq!(open(&w), ops_before, "no operation admitted");
    assert_eq!(w.records().len(), records_before, "no record admitted");
    assert!(!w.ops.uninstall_fence_release(HOLDER));
    let e = w
        .apply(
            &attended(),
            &spec,
            &plan,
            "req_g8_da",
            InteractionMode::NonInteractive,
        )
        .await;
    assert_eq!(
        e.code,
        Code::ApprovalRequired,
        "admitted after the lift: {e:?}"
    );
    w.decide(&e, Verdict::Deny).await.unwrap();
    // `enrollment.step` of an approved operation: nothing dispatched under the fence.
    let approved = w.approved(&w.spec(), "req_g8_da_step").await;
    w.ops.uninstall_fence_acquire(HOLDER).await.unwrap();
    let e = w.step(&approved).await.unwrap_err();
    assert!(fence_refusal(&e), "{e:?}");
    assert!(
        w.journal(&approved).outstanding.is_none(),
        "nothing dispatched"
    );
    assert!(!w.ops.uninstall_fence_release(HOLDER));
    let StepAnswer::Step { step } = w.step_answer(&approved).await else {
        panic!("inspect after the lift");
    };
    assert_eq!(step.stage, RemoteStage::Inspect);
}

/// ⟨ADR-0008 §17.31 item 2 (W5-C02); integrator, round 8⟩ The direct in-process route into
/// issuer work goes through the same boundary as the dispatcher: under the fence a
/// non-holder's `issuer.retire` and `issuer.unlock` are refused `uninstall_in_progress`
/// before anything is read or written, while `issuer.status` (read-only) is still answered;
/// after the lift the retire is judged on its merits again.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn recheck_direct_issuer_request_refused_under_uninstall_fence() {
    use heimdall_contract::issuer::IssuerRequest;
    let w = World::new().await;
    let retire = || IssuerRequest::Retire {
        ca_fingerprint: w.issuer.ca.fingerprint().clone(),
        deleted_locator: None,
    };
    w.ops.uninstall_fence_acquire(HOLDER).await.unwrap();
    for req in [retire(), IssuerRequest::Unlock] {
        let e = w.ops.issuer_request(&attended(), req).await.unwrap_err();
        assert!(fence_refusal(&e), "{e:?}");
    }
    w.ops
        .issuer_request(&attended(), IssuerRequest::Status)
        .await
        .expect("a read-only status is answered under the fence");
    assert!(!w.ops.uninstall_fence_release(HOLDER));
    match w.ops.issuer_request(&attended(), retire()).await {
        Ok(_) => {}
        Err(e) => assert!(!fence_refusal(&e), "refused after the lift: {e:?}"),
    }
}

/// ⟨ADR-0008 §17.31 item 8 (Q-G8-2); round 9⟩ A fence refusal at a verification's
/// certificate reservation says nothing about the remote: `enroll verify` returns the
/// refusal itself, and the enrollment's evidence, verdict and hold stay as they were (it
/// is never recorded as an inconclusive verification). The refusal is forced with the
/// debug-only `debug_refuse_next_reservation`: every public route into verification now
/// holds an admission, so a real fence acquisition waits for it (the path is defence in
/// depth). The record is left in the state its operation started (`reverifying`, the
/// operation open; Q-I-R9-1 asks how it is resumed).
// Unix only: the system form (as `supervisor_reverifies_before_freshness_lapses`).
#[cfg(unix)]
#[tokio::test]
async fn verification_fence_refusal_is_returned_and_changes_no_evidence() {
    let w = World::with(WorldOptions {
        form: EnrollmentForm::System,
        ..WorldOptions::default()
    })
    .await;
    let (record, _) = w.system_verified().await;
    let before = w.record(&record.id);
    w.ops.debug_refuse_next_reservation();
    let e = w
        .ops
        .enrollment_request(
            &unattended(),
            EnrollmentRequest::Verify {
                enrollment_id: record.id.clone(),
                request_id: RequestId::parse("req_r9_fence").unwrap(),
                mode: VerifyMode::Presence,
                wait: heimdall_contract::request::WaitMode::default(),
            },
        )
        .await
        .unwrap_err();
    assert!(fence_refusal(&e), "the refusal is returned: {e:?}");
    let after = w.record(&record.id);
    assert_eq!(after.evidence, before.evidence, "evidence unchanged");
    assert_eq!(after.verified_at, before.verified_at, "no verdict recorded");
    assert_eq!(after.hold, before.hold, "no hold recorded");
    assert!(
        matches!(
            after.state,
            EnrollmentState::Verified | EnrollmentState::Reverifying
        ),
        "no verdict recorded: {:?}",
        after.state
    );
}

/// ⟨ADR-0008 §17.31 item 9 (Q-I-R9-1); round 9⟩ The re-verification pass's own operation
/// left without a verdict by a fence refusal is resumed by the pass once the fence is
/// lifted (never while it is held), exactly once, to a verdict: one verification
/// reservation, the record `verified` with fresh evidence, and a later pass resumes
/// nothing more.
// Unix only: the system form (as `supervisor_reverifies_before_freshness_lapses`).
#[cfg(unix)]
#[tokio::test]
async fn refused_reverification_is_resumed_once_after_the_fence_lifts() {
    let w = World::with(WorldOptions {
        form: EnrollmentForm::System,
        limits: heimdall_app::operations::Limits {
            reverify_after: std::time::Duration::from_secs(1),
            ..heimdall_app::operations::Limits::default()
        },
        ..WorldOptions::default()
    })
    .await;
    let (record, _) = w.system_verified().await;
    let first = w.record(&record.id).verified_at;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    // The pass's re-verification is refused at its reservation: no verdict.
    w.ops.debug_refuse_next_reservation();
    let done = w.ops.reverify_pass().await.unwrap();
    assert!(!done.contains(&record.id), "refused, not done: {done:?}");
    let r = w.record(&record.id);
    assert_eq!(r.state, EnrollmentState::Reverifying, "no verdict");
    assert_eq!(r.verified_at, first, "no evidence recorded");
    let op = w
        .tx(|tx| tx.open_operations())
        .into_iter()
        .find(|o| o.kind == heimdall_domain::operation::OperationKind::EnrollmentVerify)
        .expect("the pass's operation stays open")
        .id;
    let entries = |w: &World| w.tx(|tx| tx.verification_entries(&op)).len();
    assert_eq!(entries(&w), 0, "nothing reserved");
    // While an uninstall holds the fence the pass resumes nothing.
    w.ops.uninstall_fence_acquire(HOLDER).await.unwrap();
    assert!(w.ops.reverify_pass().await.unwrap().is_empty());
    assert_eq!(w.record(&record.id).state, EnrollmentState::Reverifying);
    assert_eq!(entries(&w), 0);
    assert!(!w.ops.uninstall_fence_release(HOLDER));
    // Lifted: resumed exactly once, to a verdict.
    let done = w.ops.reverify_pass().await.unwrap();
    assert_eq!(done, vec![record.id.clone()], "resumed once");
    let r = w.record(&record.id);
    assert_eq!(r.state, EnrollmentState::Verified, "a verdict");
    assert!(r.verified_at > first, "freshness renewed");
    // One verification run: one reservation per purpose, none twice.
    let purposes: Vec<String> = w
        .tx(|tx| tx.verification_entries(&op))
        .iter()
        .map(|e| format!("{:?}", e.purpose))
        .collect();
    let distinct: std::collections::BTreeSet<&String> = purposes.iter().collect();
    assert!(!purposes.is_empty(), "the resumed run reserved");
    assert_eq!(distinct.len(), purposes.len(), "one run only: {purposes:?}");
    let reserved = purposes.len();
    assert!(
        w.tx(|tx| tx.open_operations()).iter().all(|o| o.id != op),
        "the operation settled"
    );
    // Nothing more to resume: a later pass reserves nothing for this operation.
    let _ = w.ops.reverify_pass().await.unwrap();
    assert_eq!(entries(&w), reserved, "never run twice");
}
