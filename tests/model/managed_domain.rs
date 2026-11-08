//! M03 wave 0 (U0, U0b rows 2, 4, 12, 28): independent domain goldens for the managed
//! credential state machines and predicates (`model_managed_domain`, hosted by
//! `heimdall-domain`).
//!
//! Every expected value here is transcribed from `docs/architecture/m03-plan.md`
//! revision 6 and `docs/decisions/0008-managed-credential-integration.md` revision 6
//! (rulings §17.x win over the D text and the plan), never from the code under test.
//! Where the code disagrees, the test asserts the documents and fails.
//!
//! Repository files read at run time (through `heimdall_testkit::repo::repo_root`):
//! * `tests/model/golden/enrollment-transitions.golden.json` (D5 §6.2 as data);
//! * `tests/model/golden/enrollment-recovery-paths.json` (the recovery-path index);
//! * `docs/architecture/m03-plan.md` (the planned test names of U5 and U10);
//! * `tests/fixtures/procstat/*` (synthetic `/proc/<pid>/stat` texts).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde_json::{Value, json};

use heimdall_contract::GrantState;
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, BindingId, CaFingerprint, DestinationId, EnrollmentId, EnvironmentId,
    ForeignRemovalId, GrantId, IdentityId, OperationId,
};
use heimdall_contract::issuer::StoreKind;
use heimdall_contract::managed::{ClockMeasurement, DestinationClock, ResidualStatus};
use heimdall_contract::request::DeadlineIntent;
use heimdall_contract::setup::PlanDigest;
use heimdall_domain::decision::{
    DecisionKind, DisclosureKind, EnrollmentPlanSummary, SystemFormLines,
};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentEvent, EnrollmentEventKind, EnrollmentForm,
    EnrollmentHold, EnrollmentRecord, EnrollmentState, ExistingAccessRecord, ForeignRemovalRecord,
    ForeignRemovalTarget, HoldReason, NoProxy, RecordFacts, RegistryCanonical, RegistryRef,
    RegistryResolvedBy, foreign_transition, target_change_outcome, transition,
};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::{
    AuthorizationSource, DegradedReason, DegradedSignRule, GrantSnapshot,
};
use heimdall_domain::issuance::{
    CaEvent, CaState, CertificateBounds, EnrolledCas, IssuanceCheck, IssuanceRefusal,
    ca_transition, check as issuance_check, extension_profile, principal_for,
};
use heimdall_domain::managed::{SlotEvent, SlotRefusal, SlotState, slot_transition};
use heimdall_domain::operation::{
    AdapterIdentity, CancelRefusal, EffectClass, EffectReceipt, OperationKind, StageReceipt,
    enrollment_cancel_allowed as cancel_allowed,
};
use heimdall_domain::policy::AuthorityGeneration;
use heimdall_domain::procstat::{self, ProcStat, ProcStatError};
use heimdall_domain::revocation::{
    ObligationKind, RESIDUAL_DRIFT_PPM, RemoteObligation, measured_completion_bound, residual_step,
};
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{
    BootId, Deadline, TimeAnchor, TimeStatus, TimeUncertainty, admission, anchor_grant,
};
use heimdall_domain::verification::{
    VerificationCheck, VerificationPurpose, VerificationRefusal, VerificationVerdict,
    VerifyingOperation, check as verification_check,
};

// --- shared helpers ------------------------------------------------------------------

fn repo_text(rel: &str) -> String {
    let path = heimdall_testkit::repo::repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel} unreadable: {}", e.kind()))
}

fn repo_json(rel: &str) -> Value {
    serde_json::from_str(&repo_text(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn t(s: &str) -> Timestamp {
    s.parse().unwrap()
}

fn plus_ms(base: Timestamp, ms: i64) -> Timestamp {
    base.checked_add(jiff::SignedDuration::from_millis(ms))
        .unwrap()
}

fn ca(n: u8) -> CaFingerprint {
    // 43 characters of the base64 alphabet (synthetic, not a real key's digest).
    let c = char::from(b'A' + n);
    CaFingerprint::parse(&format!("SHA256:{}", c.to_string().repeat(43))).unwrap()
}

fn pair(d: &str, a: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(d).unwrap(),
        account: AccountName::parse(a).unwrap(),
    }
}

fn state_name(s: EnrollmentState) -> &'static str {
    s.as_str()
}

fn state_from(name: &str) -> EnrollmentState {
    *EnrollmentState::ALL
        .iter()
        .find(|s| s.as_str() == name)
        .unwrap_or_else(|| panic!("unknown state {name:?} in a golden"))
}

const FACTS: [(&str, RecordFacts); 4] = [
    (
        "own_account",
        RecordFacts {
            form: EnrollmentForm::Account,
            foreign: false,
        },
    ),
    (
        "own_system",
        RecordFacts {
            form: EnrollmentForm::System,
            foreign: false,
        },
    ),
    (
        "foreign_account",
        RecordFacts {
            form: EnrollmentForm::Account,
            foreign: true,
        },
    ),
    (
        "foreign_system",
        RecordFacts {
            form: EnrollmentForm::System,
            foreign: true,
        },
    ),
];

fn facts_name(f: RecordFacts) -> &'static str {
    FACTS
        .iter()
        .find(|(_, g)| *g == f)
        .map(|(n, _)| *n)
        .unwrap_or_else(|| panic!("RecordFacts outside the four combinations: {f:?}"))
}

fn facts_from(name: &str) -> RecordFacts {
    FACTS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, f)| *f)
        .unwrap_or_else(|| panic!("unknown facts {name:?}"))
}

/// A golden event pattern matches an event's serde form: equal objects (same key
/// set), where a pattern string `"*"` matches any value.
fn pattern_matches(pattern: &Value, actual: &Value) -> bool {
    match pattern {
        Value::String(s) if s == "*" => true,
        Value::Object(p) => actual.as_object().is_some_and(|a| {
            a.len() == p.len()
                && p.iter()
                    .all(|(k, pv)| a.get(k).is_some_and(|av| pattern_matches(pv, av)))
        }),
        _ => pattern == actual,
    }
}

struct Row {
    from: String,
    facts: Vec<String>,
    event: Value,
    to: Option<String>,
}

fn rows(doc: &Value, key: &str) -> Vec<Row> {
    doc[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| Row {
            from: r["from"].as_str().unwrap().to_owned(),
            facts: serde_json::from_value(r["facts"].clone()).unwrap(),
            event: r["event"].clone(),
            to: r["to"].as_str().map(str::to_owned),
        })
        .collect()
}

fn row_matches(r: &Row, state: EnrollmentState, event: &EnrollmentEvent, kind: &Value) -> bool {
    r.from == state_name(state)
        && r.facts.iter().any(|f| f == facts_name(event.record))
        && pattern_matches(&r.event, kind)
}

fn ev(record: RecordFacts, kind: EnrollmentEventKind) -> EnrollmentEvent {
    EnrollmentEvent { record, kind }
}

fn kind_from(v: &Value) -> EnrollmentEventKind {
    serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("event {v}: {e}"))
}

// --- the enrollment transition table (ADR-0008 D5 §6.2) ------------------------------

/// m03-plan U0: every (state, event) pair the domain exposes
/// (`EnrollmentState::ALL` × `EnrollmentEvent::all()`, i.e. `RecordFacts::ALL` ×
/// `EnrollmentEventKind::all()`), with the allowed ones exactly the golden
/// transcription of ADR-0008 D5 §6.2 (revision-3 paths, the foreign-removal admission
/// events, the target-change outcomes) and every other one refused.
#[test]
fn enrollment_transition_table_golden() {
    let doc = repo_json("tests/model/golden/enrollment-transitions.golden.json");
    let allowed = rows(&doc, "rows");
    let unspecified = rows(&doc, "unspecified");
    for r in allowed.iter().chain(&unspecified) {
        state_from(&r.from);
        r.facts.iter().for_each(|f| {
            facts_from(f);
        });
        if let Some(to) = &r.to {
            state_from(to);
        }
    }
    let events = EnrollmentEvent::all();
    // The enumeration covers the four record fact combinations.
    let seen_facts: BTreeSet<&str> = events.iter().map(|e| facts_name(e.record)).collect();
    assert_eq!(seen_facts.len(), 4);

    let mut used = vec![0_usize; allowed.len()];
    let mut mismatches = Vec::new();
    let mut pairs = 0_usize;
    for state in EnrollmentState::ALL {
        for event in &events {
            pairs += 1;
            let kind = serde_json::to_value(event.kind).unwrap();
            if unspecified
                .iter()
                .any(|r| row_matches(r, state, event, &kind))
            {
                continue;
            }
            let hits: Vec<usize> = allowed
                .iter()
                .enumerate()
                .filter(|(_, r)| row_matches(r, state, event, &kind))
                .map(|(i, _)| i)
                .collect();
            let targets: BTreeSet<&str> = hits
                .iter()
                .map(|&i| allowed[i].to.as_deref().unwrap())
                .collect();
            assert!(
                targets.len() <= 1,
                "golden is ambiguous for {} {} {kind}: {targets:?}",
                state_name(state),
                facts_name(event.record)
            );
            for &i in &hits {
                used[i] += 1;
            }
            let expected = targets.into_iter().next().map(state_from);
            let actual = transition(state, *event).ok();
            if expected != actual {
                mismatches.push(format!(
                    "{} [{}] {kind}: documents {:?}, code {:?}",
                    state_name(state),
                    facts_name(event.record),
                    expected.map(state_name),
                    actual.map(state_name)
                ));
            }
        }
    }
    assert!(
        pairs > 1000,
        "the enumeration is not vacuous ({pairs} pairs)"
    );
    let dead: Vec<String> = allowed
        .iter()
        .zip(&used)
        .filter(|(_, n)| **n == 0)
        .map(|(r, _)| format!("{} {:?} {}", r.from, r.facts, r.event))
        .collect();
    assert!(
        dead.is_empty(),
        "golden rows that match no enumerated pair (event vocabulary drift): {dead:#?}"
    );
    assert!(
        mismatches.is_empty(),
        "{} (state, event) pairs disagree with ADR-0008 D5 §6.2:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// The paths every unit-level case starts from: ADR-0008 D5 §6.4, §6.7, §6.8, §6.9,
/// D4 item 5 and §17.4 item 5, as found in the ADR (the index must list exactly these).
const RECOVERY_PATHS_IN_ADR: &[&str] = &[
    // §6.4 stages, commit points and recovery
    "e0_decision_withdrawn",
    "e1_approved_apply_redriven_on_reconcile",
    "e2b_bootstrap_confirmed_continues_at_e3",
    "e2b_bootstrap_parent_absent_failed_unwritten",
    "e2b_bootstrap_uncertain_reinspected",
    "e3_busy_bounded_retries",
    "e3_uncertain_reconciled_applied",
    "e4_inconclusive_retry_under_open_apply",
    "e4_failure_after_approval_lapsed_held",
    "e4_principals_not_enforced_rolled_back",
    "e4_positive_refused_rolled_back",
    "e4_host_key_mismatch_held_no_rollback",
    "e4_destination_clock_skew_no_rollback",
    "e5_not_committed_reverify_then_record",
    "e5p_rollback_lost_reply_reconciled",
    "e5p_rollback_redispatch_after_holder_gone",
    "e5p_rollback_registry_changed_held",
    // §6.7 reconciliation
    "r_not_applied_redispatch_within_validity",
    "r_approval_lapsed_withdrawn_late_write",
    "r_late_write_residual_on_withdrawn",
    "r_unreachable_stays_outcome_unknown",
    "r_damaged_line_held",
    "r_stale_holder_terminated_then_redispatch",
    "r_lock_holder_unresolved_manual_recovery_line_present",
    "r_lock_holder_unresolved_manual_recovery_line_absent",
    "r_lock_holder_unresolved_in_removal_states",
    "r_abandon_from_uncertain_states",
    // §6.8 removal and rollback
    "m_remove_verified",
    "m_remove_lost_reply_reconciled",
    "m_remove_registry_changed_held_then_new_decision",
    "m_remove_held_host_key_with_fresh_target",
    "m_remove_abandoned",
    // §6.9 system form (and its foreign records, D4 item 5)
    "s_enroll_manual_apply_then_verify",
    "s_verify_failure_or_inconclusive_back_to_manual_pending",
    "s_principals_not_enforced_held",
    "s_cancel_from_manual_pending_kept_until_absence_verified",
    "s_abandon_from_manual_pending",
    "s_manual_removal_with_absence_check",
    "s_absence_not_verified_back_to_pending",
    "s_cancel_manual_removal_returns_to_origin",
    "s_foreign_manual_route_never_removed",
    "s_foreign_abandon_keeps_pending_until_line_removed",
    "s_foreign_cancel_after_ca_not_held",
    "s_foreign_cancel_before_absence_check",
    // D4 item 5 foreign account form
    "f_approval_planned_to_removing",
    "f_denial_withdrawn",
    "f_lost_reply_reconciled_by_marker",
    "f_held_recovery_new_decision_or_abandon",
    // §17.4 item 5 held exits, re-enrollment; §6.5 re-verification
    "h_evidence_hold_reverified_by_owner",
    "h_host_key_hold_target_change_pass",
    "h_host_key_hold_target_change_fail_or_inconclusive",
    "h_held_abandoned",
    "h_reenroll_after_abandoned",
    "v_reverify_from_verified",
];

/// The m03-plan section of a unit (`### U5:` up to the next `### U`).
fn unit_section<'a>(plan: &'a str, unit: &str) -> &'a str {
    let start = plan
        .find(&format!("### {unit}:"))
        .unwrap_or_else(|| panic!("m03-plan has no {unit} section"));
    let rest = &plan[start + 4..];
    let end = rest.find("\n### U").unwrap_or(rest.len());
    &rest[..end]
}

/// m03-plan U0 (⟨r2⟩/⟨r3⟩; integrator reading E2): the case index lists every
/// recovery path ADR-0008 D5 §6.4, §6.7, §6.8, §6.9 and §17.4 item 5 document, each
/// path's transition sequence holds through the pure `transition`, and each names
/// the U5 or U10 test that will cover its I/O. That those tests exist becomes
/// enforceable when U5 and U10 land (status `planned` now); here the name must be a
/// test the plan lists in the owning unit's section.
#[test]
fn enrollment_recovery_paths_each_tested() {
    let doc = repo_json("tests/model/golden/enrollment-recovery-paths.json");
    let plan = repo_text("docs/architecture/m03-plan.md");
    let paths = doc["paths"].as_array().unwrap();
    let ids: BTreeSet<&str> = paths.iter().map(|p| p["id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), paths.len(), "duplicate path IDs");
    let required: BTreeSet<&str> = RECOVERY_PATHS_IN_ADR.iter().copied().collect();
    assert_eq!(
        ids, required,
        "the index must list exactly the recovery paths found in the ADR"
    );
    let mut failures = Vec::new();
    for p in paths {
        let id = p["id"].as_str().unwrap();
        let test = p["test"].as_str().unwrap_or_default();
        let owner = p["owner"].as_str().unwrap_or_default();
        assert!(
            !test.is_empty()
                && test
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "{id}: test name {test:?}"
        );
        assert!(matches!(owner, "U5" | "U10"), "{id}: owner {owner:?}");
        assert_eq!(p["status"], json!("planned"), "{id}: status");
        assert!(
            unit_section(&plan, owner).contains(&format!("`{test}`")),
            "{id}: {test} is not a test the plan lists under {owner}"
        );
        let seqs = p["sequences"].as_array().unwrap();
        assert!(!seqs.is_empty(), "{id}: no sequence");
        for (n, s) in seqs.iter().enumerate() {
            let record = facts_from(s["facts"].as_str().unwrap());
            let mut state = state_from(s["start"].as_str().unwrap());
            let steps = s["steps"].as_array().unwrap();
            assert!(!steps.is_empty(), "{id}#{n}: no step");
            for step in steps {
                let kind = kind_from(&step["event"]);
                let want = state_from(step["to"].as_str().unwrap());
                match transition(state, ev(record, kind)) {
                    Ok(next) if next == want => state = next,
                    got => {
                        failures.push(format!(
                            "{id}#{n}: {} --{}--> documents {}, code {:?}",
                            state_name(state),
                            step["event"],
                            state_name(want),
                            got.map(state_name)
                        ));
                        break;
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} recovery-path steps disagree with the ADR:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// --- foreign removal (ADR-0008 D4 item 5; §17.7 item 4, §17.10 item 2, §17.12 item 2) --

fn foreign_target(form: EnrollmentForm) -> ForeignRemovalTarget {
    ForeignRemovalTarget {
        local_alias: "lab".into(),
        bundle_destination_id: "dst_00112233445566778899aabbccddeeff".into(),
        bundle_hostname: "lab.example.internal".into(),
        bundle_port: 22,
        account: AccountName::parse("deploy").unwrap(),
        marker: "heimdall:enr_00112233445566778899aabbccddeeff".into(),
        ca_public_key: "ssh-ed25519 AAAASYNTHETICPLACEHOLDERNOTAKEY".into(),
        line_sha256: "0".repeat(64),
        registry: RegistryCanonical {
            path: None,
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        form,
    }
}

fn foreign(form: EnrollmentForm, state: EnrollmentState) -> ForeignRemovalRecord {
    ForeignRemovalRecord {
        id: ForeignRemovalId::from_random_bytes([7; 16]),
        target: foreign_target(form),
        state,
        operation: OperationId::from_random_bytes([8; 16]),
        created_at: t("2026-11-10T14:00:00Z"),
        removal_origin: None,
    }
}

/// Drive `kinds` from `record.state` through `foreign_transition`, returning every
/// state reached (or the first refusal).
fn drive_foreign(
    mut record: ForeignRemovalRecord,
    kinds: &[EnrollmentEventKind],
) -> Result<Vec<EnrollmentState>, (EnrollmentState, EnrollmentEventKind)> {
    let mut out = Vec::new();
    for &k in kinds {
        let next = foreign_transition(&record, k).map_err(|_| (record.state, k))?;
        record.state = next;
        out.push(next);
    }
    Ok(out)
}

/// m03-plan U0 ⟨r4⟩/⟨r5⟩: the five D4 item 5 routes through the pure transition
/// (approval, denial, a lost reply, held recovery, the system-form route), and the two
/// §17.10 item 2 paths (abandon keeps the residual; a cancel after `ca_not_held` never
/// reaches `planned` or `withdrawn`), plus §17.12 item 2's cancel before any check.
#[test]
fn foreign_removal_paths_golden() {
    use EnrollmentEventKind as K;
    use EnrollmentState as S;
    let account = EnrollmentForm::Account;
    let system = EnrollmentForm::System;

    // Approval: planned -> removing (approved RemoveEnrollment), then removed.
    assert_eq!(
        drive_foreign(
            foreign(account, S::Planned),
            &[K::RemoveEnrollmentApproved, K::RemovalConfirmed]
        ),
        Ok(vec![S::Removing, S::Removed])
    );
    // Denial: planned -> withdrawn, nothing remote.
    assert_eq!(
        drive_foreign(foreign(account, S::Planned), &[K::DecisionWithdrawn]),
        Ok(vec![S::Withdrawn])
    );
    // A lost reply: removing -> remove_unknown -> removed by marker.
    assert_eq!(
        drive_foreign(
            foreign(account, S::Planned),
            &[
                K::RemoveEnrollmentApproved,
                K::RemovalOutcomeLost,
                K::ReconcileApplied
            ]
        ),
        Ok(vec![S::Removing, S::RemoveUnknown, S::Removed])
    );
    // Held recovery: held -> removing (a fresh target), or held -> abandoned.
    assert_eq!(
        drive_foreign(
            foreign(account, S::Removing),
            &[K::RemovalHeld, K::RemoveEnrollmentApproved]
        ),
        Ok(vec![S::Held, S::Removing])
    );
    assert_eq!(
        drive_foreign(foreign(account, S::Held), &[K::OwnerAbandon]),
        Ok(vec![S::Abandoned])
    );
    // The system-form route: planned -> manual_removal_pending -> removal_verifying
    // -> manual_removal_pending (ca_not_held), never removed.
    assert_eq!(
        drive_foreign(
            foreign(system, S::Planned),
            &[
                K::ManualRemovalConfirmed,
                K::OwnerConfirmsRemoved,
                K::AbsenceNotVerified
            ]
        ),
        Ok(vec![
            S::ManualRemovalPending,
            S::RemovalVerifying,
            S::ManualRemovalPending
        ])
    );
    for origin in EnrollmentState::ALL {
        assert!(
            foreign_transition(
                &foreign(system, S::RemovalVerifying),
                K::AbsenceVerified { origin }
            )
            .is_err(),
            "a foreign absence check never passes (Q28), origin {origin:?}"
        );
    }
    // §17.10 item 2: manual_removal_pending -> abandoned (pending_until_line_removed kept).
    assert_eq!(
        drive_foreign(foreign(system, S::ManualRemovalPending), &[K::OwnerAbandon]),
        Ok(vec![S::Abandoned])
    );
    // §17.10 item 2: a cancel after ca_not_held stays, or returns to held; never
    // planned or withdrawn, whatever the origin.
    assert_eq!(
        foreign_transition(
            &foreign(system, S::ManualRemovalPending),
            K::OwnerCancelsManualRemoval {
                origin: S::Planned,
                ca_not_held_seen: true
            }
        )
        .ok(),
        Some(S::ManualRemovalPending)
    );
    assert_eq!(
        foreign_transition(
            &foreign(system, S::ManualRemovalPending),
            K::OwnerCancelsManualRemoval {
                origin: S::Held,
                ca_not_held_seen: true
            }
        )
        .ok(),
        Some(S::Held)
    );
    for origin in EnrollmentState::ALL {
        let r = foreign_transition(
            &foreign(system, S::ManualRemovalPending),
            K::OwnerCancelsManualRemoval {
                origin,
                ca_not_held_seen: true,
            },
        );
        assert!(
            !matches!(r, Ok(S::Planned | S::Withdrawn)),
            "origin {origin:?}: a known residual is never discarded"
        );
    }
    // §17.12 item 2: a cancel before any absence check returns to planned, which can
    // then be withdrawn.
    assert_eq!(
        drive_foreign(
            foreign(system, S::ManualRemovalPending),
            &[
                K::OwnerCancelsManualRemoval {
                    origin: S::Planned,
                    ca_not_held_seen: false
                },
                K::DecisionWithdrawn
            ]
        ),
        Ok(vec![S::Planned, S::Withdrawn])
    );
    // A foreign record never leaves the removal subset (D4 item 5).
    let subset: BTreeSet<EnrollmentState> = [
        S::Planned,
        S::Removing,
        S::RemoveUnknown,
        S::Removed,
        S::Held,
        S::Abandoned,
        S::Withdrawn,
        S::ManualRemovalPending,
        S::RemovalVerifying,
    ]
    .into();
    for state in EnrollmentState::ALL {
        for form in [account, system] {
            for kind in EnrollmentEventKind::all() {
                if let Ok(next) = foreign_transition(&foreign(form, state), kind) {
                    assert!(
                        subset.contains(&state) && subset.contains(&next),
                        "{state:?} -> {next:?} on {kind:?} leaves the foreign subset"
                    );
                }
            }
        }
    }
}

// --- target change (ADR-0008 D5 §6.2 reverifying r4; §6.5 item 3; §17.7 item 5) ------

fn target(host: &str, key: &str) -> ApprovedTarget {
    ApprovedTarget {
        hostname: host.into(),
        port: 22,
        user: AccountName::parse("deploy").unwrap(),
        proxy: NoProxy::None,
        host_key: ApprovedHostKey {
            algorithm: "ssh-ed25519".into(),
            key: key.into(),
            fingerprint: format!("SHA256:{}", key.repeat(43).get(..43).unwrap()),
        },
    }
}

fn record(
    state: EnrollmentState,
    hold: Option<HoldReason>,
    evidence_based: bool,
) -> EnrollmentRecord {
    let id = EnrollmentId::from_random_bytes([3; 16]);
    EnrollmentRecord {
        marker: format!("heimdall:{}", id.as_str()),
        id,
        destination: DestinationId::parse("lab").unwrap(),
        account: AccountName::parse("deploy").unwrap(),
        ca_fingerprint: ca(0),
        form: EnrollmentForm::Account,
        registry: RegistryRef {
            path_display: "$HOME/.ssh/authorized_keys".into(),
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        registry_canonical: RegistryCanonical {
            path: None,
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        line_sha256: "1".repeat(64),
        target: target("lab.example.internal", "A"),
        existing_access: ExistingAccessRecord {
            identity: IdentityId::from_random_bytes([4; 16]),
            endpoint: None,
            public_key_file: None,
        },
        hold: hold.map(|reason| EnrollmentHold {
            reason,
            evidence_based,
        }),
        removal_origin: None,
        late_write: None,
        state,
        verified_at: None,
        evidence: None,
        created_at: t("2026-11-10T14:00:00Z"),
        updated_at: t("2026-11-10T14:00:00Z"),
    }
}

/// m03-plan U0 ⟨r4⟩ (§17.7 item 5): a pass replaces the approved target with the
/// operation's proposed target in the same transition as the move to `verified`; a
/// failure or an inconclusive result leaves it unchanged, the record `held`, reason
/// unchanged. Only a `host_key_changed` hold has a target change.
#[test]
fn target_change_outcomes_golden() {
    let proposed = target("lab.example.internal", "B");
    let held = record(
        EnrollmentState::Reverifying,
        Some(HoldReason::HostKeyChanged),
        false,
    );
    let approved = held.target.clone();
    assert_ne!(approved, proposed);

    let pass = target_change_outcome(&held, &proposed, VerificationVerdict::Passed).unwrap();
    assert_eq!(pass.state, EnrollmentState::Verified);
    assert_eq!(pass.target, proposed, "a pass installs the proposed target");
    assert_eq!(pass.hold, None, "a verified record is not held");

    for verdict in VerificationVerdict::all() {
        if verdict == VerificationVerdict::Passed {
            continue;
        }
        let out = target_change_outcome(&held, &proposed, verdict)
            .unwrap_or_else(|e| panic!("{verdict:?}: {e}"));
        assert_eq!(out.state, EnrollmentState::Held, "{verdict:?}");
        assert_eq!(
            out.target, approved,
            "{verdict:?}: approved target unchanged"
        );
        assert_eq!(
            out.hold.map(|h| h.reason),
            Some(HoldReason::HostKeyChanged),
            "{verdict:?}: reason unchanged"
        );
    }
    // Not a target change: another hold, or a record not re-verifying.
    let evidence_hold = record(
        EnrollmentState::Reverifying,
        Some(HoldReason::PositiveRefused),
        true,
    );
    assert!(target_change_outcome(&evidence_hold, &proposed, VerificationVerdict::Passed).is_err());
    let still_held = record(
        EnrollmentState::Held,
        Some(HoldReason::HostKeyChanged),
        false,
    );
    assert!(target_change_outcome(&still_held, &proposed, VerificationVerdict::Passed).is_err());
}

// --- CA states (ADR-0008 D4 item 3) ------------------------------------------------------

/// D4 item 3's retirement table: `pending → active` (first verified enrollment),
/// `active | pending → retiring` (`Decide approve` on `RetireIssuer`), `retiring →
/// unloaded` (the child's confirmation), `unloaded → deleted` (the store re-read),
/// `deleted → retired`; everything else refused.
#[test]
fn ca_state_transition_golden() {
    use CaEvent as E;
    use CaState as S;
    let golden: Vec<((S, E), S)> = vec![
        ((S::Pending, E::FirstEnrollmentVerified), S::Active),
        ((S::Active, E::RetireApproved), S::Retiring),
        ((S::Pending, E::RetireApproved), S::Retiring),
        ((S::Retiring, E::UnloadConfirmed), S::Unloaded),
        ((S::Unloaded, E::StoreItemDeleted), S::Deleted),
        ((S::Deleted, E::RetirementRecorded), S::Retired),
    ];
    let events = [
        E::FirstEnrollmentVerified,
        E::RetireApproved,
        E::UnloadConfirmed,
        E::StoreItemDeleted,
        E::RetirementRecorded,
    ];
    assert_eq!(
        CaEvent::ALL.len(),
        events.len(),
        "a CA event the golden does not know"
    );
    let mut bad = Vec::new();
    for s in CaState::ALL {
        for e in CaEvent::ALL {
            let want = golden.iter().find(|(k, _)| *k == (s, e)).map(|(_, v)| *v);
            let got = ca_transition(s, e).ok();
            if want != got {
                bad.push(format!("{s:?} on {e:?}: documents {want:?}, code {got:?}"));
            }
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
    // `retired` is final.
    assert!(
        CaEvent::ALL
            .iter()
            .all(|&e| ca_transition(S::Retired, e).is_err())
    );
}

// --- remote residuals (ADR-0008 D7 item 3; §17.1 item 10) -------------------------------

fn obligation(kind: ObligationKind) -> RemoteObligation {
    RemoteObligation {
        grant: GrantId::from_random_bytes([9; 16]),
        adapter: AdapterIdentity {
            mechanism: "managed_certificate".into(),
            instance: String::new(),
        },
        reason: None,
        attempts: None,
        stopped: false,
        effect_round: None,
        effect_seq: None,
        kind,
    }
}

fn bounded(lvb: Timestamp, clock: DestinationClock, status: ResidualStatus) -> RemoteObligation {
    obligation(ObligationKind::BoundedByExpiry {
        latest_valid_before: lvb,
        clock,
        status,
    })
}

/// D7 item 3 through `residual_step`: measured → `bounded_complete` once
/// `latest_valid_before + behind_upper + rtt + 100 ppm × age` passed on safe time;
/// unmeasured → `nominally_expired` once `latest_valid_before` passed on safe time,
/// never `bounded_complete`; nothing moves on uncertain time; settled statuses stay.
#[test]
fn remote_obligation_status_golden() {
    let lvb = t("2026-11-10T22:00:00Z");
    // Measured 10 days before latest_valid_before; behind 1400 ms, rtt 38 ms.
    let m = ClockMeasurement {
        behind_upper_ms: 1400,
        rtt_ms: 38,
        measured_at: plus_ms(lvb, -864_000_000),
    };
    assert_eq!(RESIDUAL_DRIFT_PPM, 100, "residual_drift_ppm (§5 item 17)");
    // At lvb + 90 s the age is 864 090 s, the drift 86 409 ms, the bound lvb + 87 847 ms.
    let at90 = plus_ms(lvb, 90_000);
    assert_eq!(
        measured_completion_bound(lvb, &m, at90),
        Some(plus_ms(lvb, 1400 + 38 + 86_409))
    );
    // At lvb + 80 s the drift is 86 408 ms and the bound lvb + 87 846 ms: not passed.
    let at80 = plus_ms(lvb, 80_000);
    assert_eq!(
        measured_completion_bound(lvb, &m, at80),
        Some(plus_ms(lvb, 1400 + 38 + 86_408))
    );
    let measured = bounded(
        lvb,
        DestinationClock::Measured(m),
        ResidualStatus::PendingUntil,
    );
    let unmeasured = bounded(
        lvb,
        DestinationClock::Unmeasured,
        ResidualStatus::PendingUntil,
    );
    let cases: Vec<(&str, &RemoteObligation, Option<Timestamp>, ResidualStatus)> = vec![
        (
            "measured, before lvb",
            &measured,
            Some(plus_ms(lvb, -1)),
            ResidualStatus::PendingUntil,
        ),
        // Past latest_valid_before but before the measured bound: still pending, and
        // never "nominally expired" when a measurement exists.
        (
            "measured, lvb passed, bound not",
            &measured,
            Some(at80),
            ResidualStatus::PendingUntil,
        ),
        (
            "measured, bound passed",
            &measured,
            Some(at90),
            ResidualStatus::BoundedComplete,
        ),
        (
            "measured, uncertain time long after",
            &measured,
            None,
            ResidualStatus::PendingUntil,
        ),
        (
            "unmeasured, before lvb",
            &unmeasured,
            Some(plus_ms(lvb, -1)),
            ResidualStatus::PendingUntil,
        ),
        (
            "unmeasured, lvb passed",
            &unmeasured,
            Some(plus_ms(lvb, 1)),
            ResidualStatus::NominallyExpired,
        ),
        (
            "unmeasured, a year later",
            &unmeasured,
            Some(plus_ms(lvb, 31_536_000_000)),
            ResidualStatus::NominallyExpired,
        ),
        (
            "unmeasured, uncertain time",
            &unmeasured,
            None,
            ResidualStatus::PendingUntil,
        ),
    ];
    for (what, o, now, want) in cases {
        assert_eq!(residual_step(o, now), want, "{what}");
    }
    // A settled status never changes, and a nominally expired residual is never shown
    // as cleared.
    for (status, clock) in [
        (
            ResidualStatus::BoundedComplete,
            DestinationClock::Measured(m),
        ),
        (
            ResidualStatus::NominallyExpired,
            DestinationClock::Unmeasured,
        ),
        (
            ResidualStatus::NominallyExpired,
            DestinationClock::Measured(m),
        ),
    ] {
        let o = bounded(lvb, clock, status);
        for now in [None, Some(at90), Some(plus_ms(lvb, 31_536_000_000))] {
            assert_eq!(residual_step(&o, now), status, "{status:?} at {now:?}");
        }
    }
    // An obligation that needs a remote action is not time-driven: it never completes
    // or expires by time.
    let action = obligation(ObligationKind::NeedsRemoteAction);
    for now in [None, Some(at90), Some(plus_ms(lvb, 31_536_000_000))] {
        assert!(
            !matches!(
                residual_step(&action, now),
                ResidualStatus::BoundedComplete | ResidualStatus::NominallyExpired
            ),
            "needs_remote_action moved by time"
        );
    }
}

/// m03-plan U0: an M01/M02 obligation (no `kind`) decodes as `needs_remote_action`
/// and re-encodes byte-identically (the default is omitted).
#[test]
fn remote_obligation_without_kind_decodes_needs_remote_action() {
    let m02 = json!({
        "grant": "grant_09090909090909090909090909090909",
        "adapter": {"mechanism": "native_agent", "instance": "a1b2"},
        "attempts": 2,
        "effect_seq": 5
    });
    let o: RemoteObligation = serde_json::from_value(m02.clone()).unwrap();
    assert_eq!(o.kind, ObligationKind::NeedsRemoteAction);
    assert_eq!(serde_json::to_value(&o).unwrap(), m02);
    // The stored record's text, in the struct's field order (the store keeps the
    // serde_json output of an M01/M02 runtime): it re-encodes byte for byte.
    let text = r#"{"grant":"grant_09090909090909090909090909090909","adapter":{"mechanism":"native_agent","instance":"a1b2"},"attempts":2,"effect_seq":5}"#;
    let back: RemoteObligation = serde_json::from_str(text).unwrap();
    assert_eq!(serde_json::to_string(&back).unwrap(), text);
}

// --- slots (ADR-0008 D10 item 2) -----------------------------------------------------------

/// D10 item 2's slot table: `free(g)` + claim by b → `held(b, g+1)`; `held(b, g)` +
/// another binding → refused `managed_slot_held`; `held(b, g)` + b's grant ends or b
/// released → `clearing(g)`; `clearing(g)` + files removed → `free(g)`; restart: a held
/// slot stays held unless its grant ended (`clearing(g)`); `clearing` and `free` stay.
#[test]
fn slot_transition_table_golden() {
    let b = BindingId::from_random_bytes([1; 16]);
    let c = BindingId::from_random_bytes([2; 16]);
    let free = SlotState::Free { generation: 4 };
    let held = SlotState::Held {
        binding: b.clone(),
        generation: 5,
    };
    let clearing = SlotState::Clearing { generation: 5 };
    let claim_b = SlotEvent::Claim { binding: b.clone() };
    let claim_c = SlotEvent::Claim { binding: c.clone() };
    let release_b = SlotEvent::Release {
        binding: b.clone(),
        generation: 5,
    };
    let release_c = SlotEvent::Release {
        binding: c,
        generation: 5,
    };
    let stale_release = SlotEvent::Release {
        binding: b.clone(),
        generation: 4,
    };
    let removed = SlotEvent::FilesRemoved { generation: 5 };
    let removed_stale = SlotEvent::FilesRemoved { generation: 4 };
    let restart_live = SlotEvent::Restart { grant_ended: false };
    let restart_ended = SlotEvent::Restart { grant_ended: true };

    let allowed: Vec<(&SlotState, &SlotEvent, SlotState)> = vec![
        (&free, &claim_b, held.clone()),
        (
            &free,
            &claim_c,
            SlotState::Held {
                binding: BindingId::from_random_bytes([2; 16]),
                generation: 5,
            },
        ),
        (&held, &claim_b, held.clone()),
        (&held, &release_b, clearing.clone()),
        (&clearing, &removed, SlotState::Free { generation: 5 }),
        (&held, &restart_live, held.clone()),
        (&held, &restart_ended, clearing.clone()),
        (&clearing, &restart_live, clearing.clone()),
        (&clearing, &restart_ended, clearing.clone()),
        (&free, &restart_live, free.clone()),
        (&free, &restart_ended, free.clone()),
    ];
    for (s, e, want) in &allowed {
        assert_eq!(slot_transition(s, e).as_ref(), Ok(want), "{s:?} on {e:?}");
    }
    assert_eq!(
        slot_transition(&held, &claim_c),
        Err(SlotRefusal::ManagedSlotHeld),
        "another binding asks: managed_slot_held"
    );
    let events = [
        &claim_b,
        &claim_c,
        &release_b,
        &release_c,
        &stale_release,
        &removed,
        &removed_stale,
        &restart_live,
        &restart_ended,
    ];
    for s in [&free, &held, &clearing] {
        for e in events {
            if allowed.iter().any(|(as_, ae, _)| *as_ == s && *ae == e) {
                continue;
            }
            assert!(
                slot_transition(s, e).is_err(),
                "{s:?} on {e:?} is not in the D10 table: {:?}",
                slot_transition(s, e)
            );
        }
    }
    // The generation survives the cycle: the next claim gets g + 1, so a cleanup of
    // g never touches g + 1's files.
    let next = slot_transition(&SlotState::Free { generation: 5 }, &claim_b).unwrap();
    assert_eq!(next.generation(), 6);
}

// --- decision kinds (m03-plan §5 item 10) ----------------------------------------------

fn plan_summary() -> EnrollmentPlanSummary {
    EnrollmentPlanSummary {
        destination_id: DestinationId::parse("lab").unwrap(),
        alias: "lab".into(),
        account: AccountName::parse("deploy").unwrap(),
        form: EnrollmentForm::Account,
        registry: RegistryRef {
            path_display: "$HOME/.ssh/authorized_keys".into(),
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        line_sha256: "1".repeat(64),
        ca_fingerprint: ca(0),
        approved_target: target("lab.example.internal", "A"),
        invocation: vec!["-o".into(), "IdentitiesOnly=yes".into()],
        host_trust: vec!["StrictHostKeyChecking=yes".into()],
        bootstrap: true,
        disclosures: vec![DisclosureKind::CaTrustBlastRadius],
    }
}

/// m03-plan U0 `decision_kind_wire_forms` (§5 item 10): `RegisterIssuer`,
/// `RetireIssuer`, `EnrollAccount`, `EnrollSystemForm`, `RemoveEnrollment` and
/// `ApproveTargetChange`, each tagged `kind` in snake_case with exactly the plan's
/// fields, round-tripping.
#[test]
fn decision_kind_wire_forms() {
    let op = OperationId::from_random_bytes([5; 16]);
    let digest = PlanDigest::from_sha256([0x11; 32]);
    let cases: Vec<(DecisionKind, &str, &[&str])> = vec![
        (
            DecisionKind::RegisterIssuer {
                ca_fingerprint: ca(0),
                store: StoreKind::WindowsDpapi,
                backup_sha256: "2".repeat(64),
                rotation_of: Some(ca(1)),
                restored_without_log: false,
                disclosures: vec![DisclosureKind::SameUserIssuerBoundary],
            },
            "register_issuer",
            &[
                "ca_fingerprint",
                "store",
                "backup_sha256",
                "rotation_of",
                "restored_without_log",
                "disclosures",
            ],
        ),
        (
            DecisionKind::RetireIssuer {
                ca_fingerprint: ca(0),
                abandoned_enrollments: vec![EnrollmentId::from_random_bytes([6; 16])],
            },
            "retire_issuer",
            &["ca_fingerprint", "abandoned_enrollments"],
        ),
        (
            DecisionKind::EnrollAccount {
                operation: op.clone(),
                plan_digest: digest.clone(),
                summary: plan_summary(),
            },
            "enroll_account",
            &["operation", "plan_digest", "summary"],
        ),
        (
            DecisionKind::EnrollSystemForm {
                operation: op.clone(),
                plan_digest: digest,
                summary: plan_summary(),
                sshd_lines: SystemFormLines {
                    trusted_user_ca_keys_line: "ssh-ed25519 AAAASYNTHETICPLACEHOLDERNOTAKEY".into(),
                    principals_line: "hm:lab:deploy".into(),
                    sshd_directives: vec!["TrustedUserCAKeys /etc/ssh/heimdall_ca.pub".into()],
                },
            },
            "enroll_system_form",
            &["operation", "plan_digest", "summary", "sshd_lines"],
        ),
        (
            DecisionKind::RemoveEnrollment {
                operation: op.clone(),
                target: heimdall_contract::enrollment::RemovalTarget::Foreign(foreign_target(
                    EnrollmentForm::Account,
                )),
                invocation: vec!["-o".into(), "IdentitiesOnly=yes".into()],
                affected_grants: vec![GrantId::from_random_bytes([9; 16])],
                pair_residual_until: Some(t("2026-11-10T22:00:00Z")),
                fresh_target: Some(target("lab.example.internal", "B")),
            },
            "remove_enrollment",
            &[
                "operation",
                "target",
                "invocation",
                "affected_grants",
                "pair_residual_until",
                "fresh_target",
            ],
        ),
        (
            DecisionKind::ApproveTargetChange {
                operation: op,
                enrollment: EnrollmentId::from_random_bytes([3; 16]),
                approved: target("lab.example.internal", "A"),
                proposed: target("lab.example.internal", "B"),
            },
            "approve_target_change",
            &["operation", "enrollment", "approved", "proposed"],
        ),
    ];
    for (kind, tag, fields) in cases {
        assert!(kind.is_m03(), "{tag}");
        let v = serde_json::to_value(&kind).unwrap();
        assert_eq!(v["kind"], json!(tag));
        let keys: BTreeSet<&str> = v
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .filter(|k| *k != "kind")
            .collect();
        let want: BTreeSet<&str> = fields.iter().copied().collect();
        assert_eq!(keys, want, "{tag}: fields");
        let back: DecisionKind = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(back, kind, "{tag}: round trip");
    }
    // The foreign removal descriptor travels whole (the decision covers every field).
    let remove = serde_json::to_value(DecisionKind::RemoveEnrollment {
        operation: OperationId::from_random_bytes([5; 16]),
        target: heimdall_contract::enrollment::RemovalTarget::Foreign(foreign_target(
            EnrollmentForm::Account,
        )),
        invocation: vec![],
        affected_grants: vec![],
        pair_residual_until: None,
        fresh_target: None,
    })
    .unwrap();
    assert_eq!(remove["target"]["kind"], json!("foreign"));
    for f in [
        "local_alias",
        "bundle_destination_id",
        "bundle_hostname",
        "bundle_port",
        "account",
        "marker",
        "ca_public_key",
        "line_sha256",
        "registry",
        "form",
    ] {
        assert!(
            remove["target"].get(f).is_some(),
            "foreign target lacks {f}"
        );
    }
}

// --- the degraded sign rule (ADR-0008 D2 item 3; U0b row 12) ----------------------------

/// D2 item 3 / U0b row 12: `issuer_unavailable` and `pair_unenrolled` permit signing
/// with the installed key; `credential_reissue_pending` has no key;
/// `mechanism_unavailable` refuses.
#[test]
fn degraded_reason_sign_rule_table() {
    let table = [
        (
            DegradedReason::MechanismUnavailable,
            "mechanism_unavailable",
            DegradedSignRule::Refuse,
            false,
        ),
        (
            DegradedReason::CredentialReissuePending,
            "credential_reissue_pending",
            DegradedSignRule::NoKey,
            false,
        ),
        (
            DegradedReason::IssuerUnavailable,
            "issuer_unavailable",
            DegradedSignRule::Permit,
            true,
        ),
        (
            DegradedReason::PairUnenrolled,
            "pair_unenrolled",
            DegradedSignRule::Permit,
            true,
        ),
    ];
    for (reason, wire, rule, permits) in table {
        assert_eq!(serde_json::to_value(reason).unwrap(), json!(wire));
        assert_eq!(reason.sign_rule(), rule, "{wire}");
        assert_eq!(reason.permits_signing(), permits, "{wire}");
    }
}

// --- the extension profile (ADR-0008 D6 item 1; ADR-0005 §3.4) --------------------------

fn grant(capabilities: &[Capability]) -> GrantSnapshot {
    GrantSnapshot {
        id: GrantId::from_random_bytes([1; 16]),
        environment: EnvironmentId::from_random_bytes([2; 16]),
        scope: Scope {
            pairs: [pair("web", "deploy"), pair("jump", "ops")].into(),
            capabilities: capabilities.iter().copied().collect(),
        },
        starts_at: t("2026-11-10T09:00:00Z"),
        deadline: Deadline {
            intent: DeadlineIntent::Duration("PT2H".into()),
            resolved_at: t("2026-11-10T09:00:00Z"),
            effective: t("2026-11-10T11:00:00Z"),
        },
        parent: None,
        source: AuthorizationSource::OwnerDecision {
            operation_id: OperationId::from_random_bytes([3; 16]),
        },
        generation: AuthorityGeneration(7),
        state: GrantState::Active,
        enforcement: EnforcementEvidence::unknown(),
    }
}

/// D6 item 1 (which narrows ADR-0005 §3.4's table for M03): `permit-pty` for every
/// pair; `permit-agent-forwarding` only with the `agent-forwarding` capability;
/// `permit-port-forwarding` never in M03 (no route data until M04); `permit-user-rc`
/// never; `permit-X11-forwarding` never; `no-touch-required` never (ADR-0005 §3.4).
#[test]
fn extension_profile_matches_adr_0005_3_4_table() {
    let never = [
        "permit-port-forwarding",
        "permit-user-rc",
        "permit-X11-forwarding",
        "no-touch-required",
    ];
    let plain = grant(&[Capability::SshAuthentication]);
    let forwarding = grant(&[Capability::SshAuthentication, Capability::AgentForwarding]);
    let git = grant(&[Capability::SshAuthentication, Capability::GitSigning]);
    for p in [pair("web", "deploy"), pair("jump", "ops")] {
        let pty: BTreeSet<String> = ["permit-pty".to_owned()].into();
        assert_eq!(extension_profile(&plain, &p), pty, "{p:?}");
        assert_eq!(
            extension_profile(&git, &p),
            pty,
            "{p:?}: git signing adds nothing"
        );
        let with_agent: BTreeSet<String> = [
            "permit-pty".to_owned(),
            "permit-agent-forwarding".to_owned(),
        ]
        .into();
        assert_eq!(extension_profile(&forwarding, &p), with_agent, "{p:?}");
        for g in [&plain, &forwarding, &git] {
            let got = extension_profile(g, &p);
            for n in never {
                assert!(!got.contains(n), "{n} issued for {p:?}");
            }
        }
    }
}

// --- issuance CA refusals (U0b row 2; ADR-0008 D4 item 3) -------------------------------

struct Issue {
    grant: GrantSnapshot,
    pair: AccessPair,
    bounds: CertificateBounds,
    permitted: BTreeSet<String>,
}

impl Issue {
    fn new() -> Self {
        let grant = grant(&[Capability::SshAuthentication]);
        let p = pair("web", "deploy");
        Self {
            bounds: CertificateBounds {
                serial: 42,
                key_id: "k".into(),
                principal: principal_for(&p),
                valid_after: t("2026-11-10T09:00:00Z"),
                valid_before: t("2026-11-10T11:00:00Z"),
                extensions: ["permit-pty".to_owned()].into(),
                subject_fingerprint: "fp".into(),
                ca_fingerprint: None,
            },
            permitted: extension_profile(&grant, &p),
            grant,
            pair: p,
        }
    }

    fn check(&self, cas: Option<EnrolledCas<'_>>) -> Result<(), IssuanceRefusal> {
        let anchor = TimeAnchor {
            boot_id: BootId("boot-1".into()),
            continuous: Duration::ZERO,
            wall: t("2026-11-10T09:00:00Z"),
        };
        let now = TimeAnchor {
            boot_id: BootId("boot-1".into()),
            continuous: Duration::from_secs(600),
            wall: t("2026-11-10T09:10:00Z"),
        };
        let grant_anchor =
            anchor_grant(self.grant.id.clone(), anchor, self.grant.deadline.effective);
        issuance_check(&IssuanceCheck {
            grant: &self.grant,
            parent: None,
            ancestors: &[],
            policy: None,
            expected_policy_revision: None,
            current_generation: AuthorityGeneration(7),
            tombstoned: false,
            pair: &self.pair,
            bounds: &self.bounds,
            permitted_extensions: &self.permitted,
            new_activation: false,
            subject_registered: true,
            critical_option: false,
            time: TimeStatus::Safe,
            admission: admission(&grant_anchor, &now),
            now: now.wall,
            enrolled_cas: cas,
        })
    }
}

/// U0b row 2: the M01 inputs (no CA named, no CA facts) are unchanged.
#[test]
fn issuance_m01_inputs_unchanged() {
    let base = Issue::new();
    assert_eq!(base.check(None), Ok(()));
}

/// U0b row 2: `UnknownCa` for bounds naming no CA, or a CA that is not registered.
#[test]
fn issuance_refuses_unknown_ca() {
    let mut i = Issue::new();
    let verified = [ca(0)];
    // No ca_fingerprint with the managed inputs.
    assert_eq!(
        i.check(Some(EnrolledCas {
            verified_for_pair: &verified,
            ca_state: Some(CaState::Active),
        })),
        Err(IssuanceRefusal::UnknownCa)
    );
    // A CA that is not registered.
    i.bounds.ca_fingerprint = Some(ca(5));
    assert_eq!(
        i.check(Some(EnrolledCas {
            verified_for_pair: &verified,
            ca_state: None,
        })),
        Err(IssuanceRefusal::UnknownCa)
    );
}

/// U0b row 2: `CaNotVerifiedForPair` for a registered, active CA whose `verified`
/// enrollment does not cover the pair.
#[test]
fn issuance_refuses_ca_not_verified_for_pair() {
    let mut i = Issue::new();
    i.bounds.ca_fingerprint = Some(ca(1));
    let verified = [ca(0)];
    assert_eq!(
        i.check(Some(EnrolledCas {
            verified_for_pair: &verified,
            ca_state: Some(CaState::Active),
        })),
        Err(IssuanceRefusal::CaNotVerifiedForPair)
    );
    // The same CA, verified for the pair, issues.
    i.bounds.ca_fingerprint = Some(ca(0));
    assert_eq!(
        i.check(Some(EnrolledCas {
            verified_for_pair: &verified,
            ca_state: Some(CaState::Active),
        })),
        Ok(())
    );
}

/// D4 item 3: a CA in `retiring` (or further) gets no new reservation (`CaRetiring`).
#[test]
fn issuance_refuses_ca_retiring() {
    let mut i = Issue::new();
    i.bounds.ca_fingerprint = Some(ca(0));
    let verified = [ca(0)];
    for s in [
        CaState::Retiring,
        CaState::Unloaded,
        CaState::Deleted,
        CaState::Retired,
    ] {
        assert_eq!(
            i.check(Some(EnrolledCas {
                verified_for_pair: &verified,
                ca_state: Some(s),
            })),
            Err(IssuanceRefusal::CaRetiring),
            "{s:?}"
        );
    }
}

/// D4 item 3: "A `pending` CA signs only verification certificates for its own
/// enrollments", and grant issuance uses "the newest `active` CA that the pair has a
/// `verified` enrollment for": a grant certificate under a `pending` CA is refused.
#[test]
fn issuance_refuses_pending_ca_for_grant_certificates() {
    let mut i = Issue::new();
    i.bounds.ca_fingerprint = Some(ca(0));
    let verified = [ca(0)];
    assert!(
        i.check(Some(EnrolledCas {
            verified_for_pair: &verified,
            ca_state: Some(CaState::Pending),
        }))
        .is_err(),
        "a pending CA issued a grant certificate (ADR-0008 D4 item 3)"
    );
}

// --- the verification predicate (ADR-0008 D5 §6.5 item 2; U0b row 4) --------------------

struct Verify {
    op: VerifyingOperation,
    entry_pair: AccessPair,
    plan_pair: AccessPair,
    plan_ca: CaFingerprint,
    purpose: VerificationPurpose,
    bounds: CertificateBounds,
    subject_registered: bool,
    time: TimeStatus,
    now: Timestamp,
    entries: u32,
    attempts: u32,
}

impl Verify {
    fn new() -> Self {
        let p = pair("lab", "deploy");
        let now = t("2026-11-10T14:00:00Z");
        Self {
            op: VerifyingOperation {
                kind: OperationKind::EnrollmentApply,
                authorized: true,
                at_verification_stage: true,
            },
            entry_pair: p.clone(),
            plan_pair: p.clone(),
            plan_ca: ca(0),
            purpose: VerificationPurpose::Positive,
            bounds: CertificateBounds {
                serial: 7,
                key_id: "v".into(),
                principal: "hm:lab:deploy".into(),
                valid_after: plus_ms(now, -60_000),
                valid_before: plus_ms(now, 300_000),
                extensions: BTreeSet::new(),
                subject_fingerprint: "kverify".into(),
                ca_fingerprint: Some(ca(0)),
            },
            subject_registered: true,
            time: TimeStatus::Safe,
            now,
            entries: 1,
            attempts: 1,
        }
    }

    fn check(&self) -> Result<(), VerificationRefusal> {
        verification_check(&VerificationCheck {
            operation: self.op,
            entry_pair: &self.entry_pair,
            plan_pair: &self.plan_pair,
            plan_ca: &self.plan_ca,
            purpose: self.purpose,
            bounds: &self.bounds,
            subject_registered: self.subject_registered,
            time: self.time,
            now: self.now,
            max_validity: Duration::from_secs(300),
            entries_in_attempt: self.entries,
            attempts: self.attempts,
        })
    }
}

/// D5 §6.5 item 2, one refusal per predicate: an approved `enrollment.apply` or an
/// `enrollment.verify` at its verification stage; the plan's pair and CA; exactly
/// `hm:<destination-id>:<account>` or `hm:verify-negative:<32 hex>`; no extensions;
/// `valid_after` = now − 60 s and `valid_before` ≤ now + 300 s; K_verify registered;
/// `Safe` time; at most 4 entries per attempt and 3 attempts.
#[test]
fn verification_check_refuses_each_predicate() {
    use VerificationRefusal as R;
    assert_eq!(Verify::new().check(), Ok(()), "the baseline passes");
    let mut negative = Verify::new();
    negative.purpose = VerificationPurpose::Negative;
    negative.bounds.principal = format!("hm:verify-negative:{}", "0a".repeat(16));
    assert_eq!(negative.check(), Ok(()), "a negative entry passes");
    let mut verify_op = Verify::new();
    verify_op.op.kind = OperationKind::EnrollmentVerify;
    assert_eq!(verify_op.check(), Ok(()), "an enrollment.verify passes");
    let mut boundary = Verify::new();
    boundary.entries = 4;
    boundary.attempts = 3;
    assert_eq!(
        boundary.check(),
        Ok(()),
        "4 entries and 3 attempts are allowed"
    );

    type Mutation = fn(&mut Verify);
    let cases: Vec<(&str, R, Mutation)> = vec![
        ("an ensure operation", R::OperationNotVerifying, |v| {
            v.op.kind = OperationKind::Ensure
        }),
        ("an enrollment.remove", R::OperationNotVerifying, |v| {
            v.op.kind = OperationKind::EnrollmentRemove
        }),
        ("an unapproved apply", R::OperationNotVerifying, |v| {
            v.op.authorized = false
        }),
        (
            "not at the verification stage",
            R::OperationNotVerifying,
            |v| v.op.at_verification_stage = false,
        ),
        ("another pair", R::PairMismatch, |v| {
            v.entry_pair = pair("lab", "root")
        }),
        ("another CA", R::CaMismatch, |v| {
            v.bounds.ca_fingerprint = Some(ca(1))
        }),
        ("no CA", R::CaMismatch, |v| v.bounds.ca_fingerprint = None),
        ("another pair's principal", R::WrongPrincipal, |v| {
            v.bounds.principal = "hm:lab:root".into()
        }),
        (
            "a negative principal on a positive entry",
            R::WrongPrincipal,
            |v| {
                v.bounds.principal = format!("hm:verify-negative:{}", "0a".repeat(16));
            },
        ),
        ("a short nonce", R::WrongPrincipal, |v| {
            v.purpose = VerificationPurpose::Negative;
            v.bounds.principal = format!("hm:verify-negative:{}", "a".repeat(31));
        }),
        (
            "a positive principal on a negative entry",
            R::WrongPrincipal,
            |v| {
                v.purpose = VerificationPurpose::Negative;
            },
        ),
        ("an extension", R::ExtensionsPresent, |v| {
            v.bounds.extensions = ["permit-pty".to_owned()].into();
        }),
        ("valid_before past now + 300 s", R::ValidityTooLong, |v| {
            v.bounds.valid_before = plus_ms(v.now, 301_000);
        }),
        ("valid_after in the future", R::ValidityTooLong, |v| {
            v.bounds.valid_after = plus_ms(v.now, 1_000);
        }),
        ("an hour of backdating", R::ValidityTooLong, |v| {
            v.bounds.valid_after = plus_ms(v.now, -3_600_000);
        }),
        ("an unregistered subject", R::UnknownSubjectKey, |v| {
            v.subject_registered = false
        }),
        ("uncertain time", R::TimeUncertain, |v| {
            v.time = TimeStatus::Uncertain(TimeUncertainty::BelowHighWater {
                mark: v.now,
                observed: v.now,
            });
        }),
        ("a fifth entry", R::TooManyEntries, |v| v.entries = 5),
        ("a fourth attempt", R::TooManyEntries, |v| v.attempts = 4),
    ];
    let mut covered = BTreeSet::new();
    for (what, want, mutate) in cases {
        let mut v = Verify::new();
        mutate(&mut v);
        assert_eq!(v.check(), Err(want), "{what}");
        covered.insert(format!("{want:?}"));
    }
    assert_eq!(
        covered.len(),
        9,
        "one refusal per VerificationRefusal variant"
    );
}

// --- the shared /proc/<pid>/stat parser (§17.13 item 2; U0b row 28) ----------------------

fn procstat_fixtures() -> Vec<(String, Vec<u8>, Value)> {
    let root = heimdall_testkit::repo::repo_root().join("tests/fixtures/procstat");
    let golden: Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("golden.json")).unwrap()).unwrap();
    let mut out: Vec<(String, Vec<u8>, Value)> = golden["fixtures"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, want)| {
            let bytes = std::fs::read(root.join(name))
                .unwrap_or_else(|e| panic!("fixture {name}: {}", e.kind()));
            (name.clone(), bytes, want.clone())
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn procstat_error_name(e: ProcStatError) -> &'static str {
    match e {
        ProcStatError::NoCloseParen => "no_close_paren",
        ProcStatError::TooFewFields { .. } => "too_few_fields",
        ProcStatError::BadState => "bad_state",
        ProcStatError::BadProcessGroup => "bad_process_group",
        ProcStatError::BadStartTime => "bad_start_time",
        _ => "unknown_error",
    }
}

/// m03-plan U0 ⟨r6⟩ `procstat_parse_golden`: the synthetic fixture texts give the
/// expected process group and start time; malformed texts (fewer than 20 suffix
/// tokens, a non-decimal or zero process group, a non-decimal start time, no `)`, a
/// state that is not one letter) are rejected.
#[test]
fn procstat_parse_golden() {
    let fixtures = procstat_fixtures();
    assert!(fixtures.len() >= 15, "fixtures present");
    let mut rejected = BTreeSet::new();
    for (name, bytes, want) in &fixtures {
        let got = procstat::parse(bytes);
        if let Some(err) = want.get("error") {
            let e = got.expect_err(name);
            assert_eq!(procstat_error_name(e), err.as_str().unwrap(), "{name}");
            rejected.insert(err.as_str().unwrap().to_owned());
        } else {
            let p = got.unwrap_or_else(|e| panic!("{name}: {e}"));
            let want_state = want["state"].as_str().unwrap().chars().next().unwrap();
            assert_eq!(
                p,
                ProcStat {
                    state: want_state,
                    process_group: u32::try_from(want["process_group"].as_u64().unwrap()).unwrap(),
                    start_time: want["start_time"].as_u64().unwrap(),
                },
                "{name}"
            );
        }
    }
    let every: BTreeSet<String> = [
        "no_close_paren",
        "too_few_fields",
        "bad_state",
        "bad_process_group",
        "bad_start_time",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    assert_eq!(rejected, every, "every rejection class has a fixture");
}

/// m03-plan U0b row 28 `procstat_comm_with_spaces_parentheses_and_newline`: `comm`
/// values with spaces, `(`, `)` and a newline (including one that imitates the
/// following fields) do not move the fields.
#[test]
fn procstat_comm_with_spaces_parentheses_and_newline() {
    let fixtures = procstat_fixtures();
    let by_name: BTreeMap<&str, &Vec<u8>> =
        fixtures.iter().map(|(n, b, _)| (n.as_str(), b)).collect();
    let cases = [
        (
            "comm-spaces.stat",
            b" ".as_slice(),
            31337_u32,
            1_234_567_u64,
        ),
        ("comm-parentheses.stat", b") (".as_slice(), 77, 555),
        (
            "comm-spoofed-fields.stat",
            b") S 1 9 9 9".as_slice(),
            4100,
            42,
        ),
        ("comm-newline.stat", b"x\ny".as_slice(), 900, 8_000_000_000),
    ];
    for (name, needle, group, start) in cases {
        let bytes = by_name[name];
        assert!(
            bytes.windows(needle.len()).any(|w| w == needle),
            "{name} carries the tricky comm"
        );
        let p = procstat::parse(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!((p.process_group, p.start_time), (group, start), "{name}");
    }
    // Built in-line too, independent of the files: the last `)` wins.
    let tail = "S 1 4242 4242 0 -1 4194560 120 0 0 0 3 1 0 0 20 0 1 0 98765 2654208 230";
    for comm in ["a b c", "(", ")", "))", "x)\n(y", ") R 1 7 7 7 0 -1"] {
        let text = format!("4242 ({comm}) {tail}\n");
        let p = procstat::parse(text.as_bytes()).unwrap_or_else(|e| panic!("{comm:?}: {e}"));
        assert_eq!(
            (p.state, p.process_group, p.start_time),
            ('S', 4242, 98765),
            "{comm:?}"
        );
    }
}

// --- operation kinds and the cancel rule (m03-plan §5 item 11; D5 §6.4) ------------------

/// §5 item 11: `ALL` grows to 15; `enrollment.apply` and `enrollment.remove` are
/// `remote_mutation`, `enrollment.verify` is `local`; the M01/M02 kinds keep theirs.
#[test]
fn operation_kinds_all_15_with_effect_classes() {
    assert_eq!(OperationKind::ALL.len(), 15);
    let distinct: BTreeSet<OperationKind> = OperationKind::ALL.into_iter().collect();
    assert_eq!(distinct.len(), 15);
    let m03 = [
        (
            OperationKind::EnrollmentApply,
            "enrollment.apply",
            EffectClass::RemoteMutation,
        ),
        (
            OperationKind::EnrollmentVerify,
            "enrollment.verify",
            EffectClass::Local,
        ),
        (
            OperationKind::EnrollmentRemove,
            "enrollment.remove",
            EffectClass::RemoteMutation,
        ),
    ];
    for (k, name, class) in m03 {
        assert!(distinct.contains(&k));
        assert_eq!(k.as_str(), name);
        assert_eq!(serde_json::to_value(k).unwrap(), json!(name));
        assert_eq!(k.m03_effect_class(), Some(class), "{name}");
        assert!(k.is_enrollment(), "{name}");
        assert_eq!(k.m02_effect_class(), None, "{name}");
    }
    assert_eq!(
        OperationKind::ENROLLMENT
            .into_iter()
            .collect::<BTreeSet<_>>(),
        m03.iter().map(|(k, _, _)| *k).collect::<BTreeSet<_>>()
    );
    for k in OperationKind::ALL {
        if !m03.iter().any(|(m, _, _)| *m == k) {
            assert_eq!(k.m03_effect_class(), None, "{k:?}");
            assert!(!k.is_enrollment(), "{k:?}");
        }
    }
    // M02's effect classes are unchanged.
    for k in OperationKind::SETUP {
        assert_eq!(k.m02_effect_class(), Some(EffectClass::LocalResources));
    }
    assert_eq!(
        OperationKind::Catalog.m02_effect_class(),
        Some(EffectClass::Local)
    );
}

fn receipt(stage: &str, effect: EffectReceipt) -> StageReceipt {
    StageReceipt {
        stage: stage.into(),
        recorded_at: t("2026-11-10T14:00:00Z"),
        effect,
        local: None,
    }
}

/// D5 §6.4 and §5 item 11: cancelling an enrollment operation is allowed until a
/// remote mutation's `Attempted` receipt exists (E3 for an apply; the removal or the
/// rollback's removal), and refused with `remote_step_in_progress` after it.
#[test]
fn enrollment_cancel_allowed() {
    let adapter = AdapterIdentity {
        mechanism: "managed_certificate".into(),
        instance: String::new(),
    };
    let attempted = |token: &str| EffectReceipt::Attempted {
        adapter: adapter.clone(),
        effect_token: token.into(),
    };
    let marker = "heimdall:enr_00112233445566778899aabbccddeeff";
    let apply = OperationKind::EnrollmentApply;
    // Before E3: no receipt, the reads, the bootstrap, the verification.
    assert_eq!(cancel_allowed(apply, &[]), Ok(()));
    let before_e3 = [
        receipt("enroll.inspect.started", EffectReceipt::NotAttempted),
        receipt("enroll.inspect.observed", EffectReceipt::NotAttempted),
        receipt("enroll.bootstrap", attempted(&format!("{marker}:dir"))),
    ];
    assert_eq!(cancel_allowed(apply, &before_e3), Ok(()));
    // E3's Attempted receipt exists (or a later state of it).
    let mut e3 = before_e3.to_vec();
    e3.push(receipt("enroll.append", attempted(marker)));
    assert_eq!(
        cancel_allowed(apply, &e3),
        Err(CancelRefusal::RemoteStepInProgress)
    );
    let uncertain = [receipt(
        "enroll.append",
        EffectReceipt::Uncertain {
            adapter: adapter.clone(),
            effect_token: marker.into(),
        },
    )];
    assert_eq!(
        cancel_allowed(apply, &uncertain),
        Err(CancelRefusal::RemoteStepInProgress)
    );
    // The rollback's removal and an explicit removal.
    let rollback = [receipt(
        "enroll.rollback",
        attempted(&format!("{marker}:rm")),
    )];
    assert_eq!(
        cancel_allowed(apply, &rollback),
        Err(CancelRefusal::RemoteStepInProgress)
    );
    let remove = OperationKind::EnrollmentRemove;
    assert_eq!(cancel_allowed(remove, &before_e3[..2]), Ok(()));
    let removal = [receipt("enroll.remove", attempted(&format!("{marker}:rm")))];
    assert_eq!(
        cancel_allowed(remove, &removal),
        Err(CancelRefusal::RemoteStepInProgress)
    );
    // enrollment.verify has no remote mutation.
    let verify = [receipt(
        "enroll.verify.started",
        EffectReceipt::NotAttempted,
    )];
    assert_eq!(
        cancel_allowed(OperationKind::EnrollmentVerify, &verify),
        Ok(())
    );
    // The M01/M02 kinds are not governed by this rule.
    assert_eq!(cancel_allowed(OperationKind::Ensure, &e3), Ok(()));
}
