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
