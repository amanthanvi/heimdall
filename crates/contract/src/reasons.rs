//! ⟨rev7⟩ The error-reason table (ADR-0013 §2.1, D8): what `heimdall --json schema show
//! reasons` prints, offline.
//!
//! One row per answer, a reason under one code with the `next.action` it carries
//! ([`NEXT_ACTIONS`] where that is not the code's default), built from every reason group of
//! [`crate::envelope::reason`], the setup
//! conflict kinds and manual reasons, the provider's non-interactive reasons, and the
//! reasons the M01/M02 groups document without a code binding ([`M02_CODES`], from their
//! emission sites). Pending-state reasons (no code) and resync reasons are listed apart, and
//! so are the reasons of a warning. A reader treats a reason it does not know as its code's
//! defaults (ADR-0013 §3.2).
//!
//! A code that is declared but not yet in the code table is named in `declared_codes`. None is
//! now: `REQUEST_STALE` joined the table with its emitter (M08 U2b-2; the ruling on ASK-CODE).

use std::collections::BTreeSet;

use crate::code::Code;
use crate::envelope::{m03_warning, reason};

/// The reasons whose group binds no code (`reason::ALL`, the setup conflict kinds, the
/// provider's non-interactive reasons and the literal reasons of the enrollment driver),
/// each with the codes its emission sites answer, read from the sources at revision 7's
/// base.
pub const M02_CODES: &[(&str, &[&str])] = &[
    (reason::NOT_FOUND, &["LAUNCH_FAILED"]),
    (reason::CURRENT_DIRECTORY, &["LAUNCH_FAILED"]),
    (reason::REFUSED_BATCH_PATH, &["LAUNCH_FAILED"]),
    (reason::REFUSED_ARGUMENT, &["LAUNCH_FAILED"]),
    (reason::NOT_EXECUTABLE, &["LAUNCH_FAILED"]),
    (reason::EXEC_ERROR, &["LAUNCH_FAILED"]),
    (reason::REFUSED_PATH, &["LAUNCH_FAILED"]),
    (reason::META_UNAVAILABLE, &["LAUNCH_FAILED"]),
    (reason::ENDPOINT_ABSENT, &["SERVICE_UNAVAILABLE"]),
    (reason::PROVIDER_INTERACTION, &["INTERACTION_REQUIRED"]),
    (reason::INTERACTION_UNKNOWN, &["INTERACTION_REQUIRED"]),
    (reason::MIXED_MECHANISMS, &["CAPABILITY_UNAVAILABLE"]),
    (reason::DRIVER_UNAVAILABLE, &["CAPABILITY_UNAVAILABLE"]),
    (
        reason::FALLBACK_IDENTITY_INTERACTION,
        &["INTERACTION_REQUIRED"],
    ),
    (reason::SETUP_IN_PROGRESS, &["CONFIG_CONFLICT"]),
    (
        reason::PROJECTION_HELD,
        &["CONFIG_CONFLICT", "OUTCOME_UNKNOWN"],
    ),
    (reason::PROJECTION_TOO_LARGE, &["CAPABILITY_UNAVAILABLE"]),
    (reason::PLAN_TOO_LARGE, &["CAPABILITY_UNAVAILABLE"]),
    (
        reason::VERIFIED_CLIENT_UNAVAILABLE,
        &["CAPABILITY_UNAVAILABLE"],
    ),
    (reason::BINDING_IN_USE, &["REQUEST_CONFLICT"]),
    (reason::BINDING_RELEASED, &["CREDENTIAL_EXPIRED"]),
    // The setup conflict kinds (`setup::ConflictKind`, also `manual_reason` values);
    // `projection_held` and `verified_client_unavailable` are above.
    (
        crate::setup::manual_reason::USER_CONFIG_CHANGED,
        &["CONFIG_CONFLICT"],
    ),
    (
        crate::setup::manual_reason::MANAGED_FILE_EDITED,
        &["CONFIG_CONFLICT"],
    ),
    (
        crate::setup::manual_reason::MARKER_EDITED,
        &["CONFIG_CONFLICT"],
    ),
    (
        crate::setup::manual_reason::MARKER_DUPLICATED,
        &["CONFIG_CONFLICT"],
    ),
    (
        crate::setup::manual_reason::INCLUDE_CONDITIONAL,
        &["CONFIG_CONFLICT"],
    ),
    (
        crate::setup::manual_reason::UNMANAGEABLE_FILE,
        &["CONFIG_CONFLICT"],
    ),
    (
        crate::setup::manual_reason::ALIAS_COLLISION,
        &["CONFIG_CONFLICT"],
    ),
    (
        crate::setup::manual_reason::CONCURRENT_WRITER,
        &["CONFIG_CONFLICT"],
    ),
    (
        crate::setup::manual_reason::GIT_CONFIG_LOCKED,
        &["CONFIG_CONFLICT"],
    ),
];

/// The literal reasons of the enrollment driver (M03; no constant), with their codes.
pub const M03_LITERAL_CODES: &[(&str, &[&str])] = &[
    ("provider_locked", &["PROVIDER_LOCKED"]),
    ("interaction_required", &["INTERACTION_REQUIRED"]),
    ("not_after_passed", &["CAPABILITY_UNAVAILABLE"]),
    ("nothing_to_reconcile", &["CONFIG_CONFLICT"]),
    ("abandon_not_allowed", &["CONFIG_CONFLICT"]),
    ("enrollment_state", &["CONFIG_CONFLICT"]),
    ("foreign_removal_open", &["CONFIG_CONFLICT"]),
];

/// Constants of the reason groups that are never written as `data.error.reason`: their
/// spellings name a doctor finding, a probe's decline reason, a setup plan's Git reason or
/// a data field (the provider's non-interactive reasons, which map to the envelope reasons
/// of the same name). They are not rows of the table.
pub const NOT_ERROR_REASONS: &[&str] = &[
    reason::IDENTITY_NOT_LISTED,
    reason::CONFIG_COMMANDS_NOT_AUTHORIZED,
    reason::GIT_SSH_COMMAND_PRESENT,
    reason::CONFIG_NOT_FULLY_READABLE,
    reason::GIT_CONFIG_UNREADABLE,
    reason::GIT_DEFAULT_NOT_BUNDLED_MSYS,
    crate::setup::manual_reason::ATOMIC_EXCHANGE_UNSUPPORTED,
    crate::setup::manual_reason::UNSUPPORTED_ENCODING,
    crate::setup::manual_reason::GIT_GLOBAL_REDIRECTED,
    crate::setup::manual_reason::INCLUDE_TARGET_GLOB,
];

/// The answers whose `next.action` is not their code's default, each `(reason, code,
/// action)`: the action its emission sites send, so a well-behaved agent stops instead of
/// looping (the contract owner's ruling of 2026-11-24). `retryable` is always the code's.
pub const NEXT_ACTIONS: &[(&str, &str, &str)] = &[
    // Read from the emission sites at revision 7's base (M03).
    (
        reason::PROJECTION_PENDING,
        "CAPABILITY_UNAVAILABLE",
        "setup_apply",
    ),
    (
        reason::REMOTE_STEP_IN_PROGRESS,
        "CAPABILITY_UNAVAILABLE",
        "reconcile",
    ),
    (
        reason::MANAGED_SLOT_HELD,
        "CONFIG_CONFLICT",
        "release_binding",
    ),
    // ⟨rev7⟩ The attended repair or restore is the owner's (ADR-0014 H4; U0-Q8).
    (reason::STATE_CORRUPT, "STATE_UNAVAILABLE", "owner_decision"),
    (
        reason::LEDGER_DAMAGED,
        "STATE_UNAVAILABLE",
        "owner_decision",
    ),
    // ⟨rev7⟩ A newer store needs a newer build.
    (
        reason::STATE_NEWER_THAN_BUILD,
        "STATE_UNAVAILABLE",
        "change_client",
    ),
    // ⟨rev7; review U0-R04⟩ A read refused before anything is sent: narrow it (ADR-0013 §4,
    // D19). The one documented exception is a reply that does not fit after dispatch: it keeps
    // its operation's true effect and reference, with next `observe`.
    (reason::RESPONSE_TOO_LARGE, "USAGE_ERROR", "narrow_request"),
    // ⟨rev7; U0-Q3⟩ The person said no: stop, do not ask again.
    (reason::DECISION_DENIED, "CAPABILITY_UNAVAILABLE", "none"),
    // ⟨rev7; ADR-0014 H10⟩ Only the owner's reauthorization or a new local decision reopens.
    (
        reason::CLIENT_QUARANTINED_AFTER_RESTORE,
        "CAPABILITY_UNAVAILABLE",
        "owner_decision",
    ),
    (
        reason::INVITATION_VOID_AFTER_RESTORE,
        "CAPABILITY_UNAVAILABLE",
        "owner_decision",
    ),
    (
        reason::EXPOSURE_DISABLED_AFTER_RESTORE,
        "CAPABILITY_UNAVAILABLE",
        "owner_decision",
    ),
];

/// Codes declared in the reason table but not yet in the code table: none. `REQUEST_STALE`
/// joined the code table with its emitter in M08 U2b-2 (the ruling on ASK-CODE).
pub const DECLARED_CODES: &[&str] = &[];

/// One answer of the table: a reason under one code, with the next action it carries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Row {
    /// The reason.
    pub reason: &'static str,
    /// A code it is emitted under.
    pub code: &'static str,
    /// The `next.action` that answer carries.
    pub next_action: &'static str,
}

fn code(c: &Code) -> &'static str {
    // Every code of a reason group is a table code; `as_str` borrows from the table.
    Code::all()
        .iter()
        .find(|k| *k == c)
        .map_or("INTERNAL_ERROR", Code::as_str)
}

fn default_next(code: &str) -> &'static str {
    Code::parse(code).default_next_action()
}

/// Every error answer, one row per (reason, code), sorted by reason then code.
#[must_use]
pub fn rows() -> Vec<Row> {
    let mut pairs: BTreeSet<(&'static str, &'static str)> = BTreeSet::new();
    for group in [M02_CODES, M03_LITERAL_CODES] {
        for (r, codes) in group {
            for c in *codes {
                pairs.insert((r, c));
            }
        }
    }
    for group in [
        reason::M03,
        reason::M03_REV5,
        reason::M04,
        reason::M05,
        reason::M06,
        reason::REV7,
    ] {
        for (r, c) in group {
            pairs.insert((r, code(c)));
        }
    }
    pairs
        .into_iter()
        .map(|(reason, code)| Row {
            reason,
            code,
            next_action: NEXT_ACTIONS
                .iter()
                .find(|(r, c, _)| *r == reason && *c == code)
                .map_or_else(|| default_next(code), |(_, _, a)| *a),
        })
        .collect()
}

/// The table as `schema show reasons` prints it (stable key and row order).
#[must_use]
pub fn table() -> serde_json::Value {
    let reasons: Vec<serde_json::Value> = rows()
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "reason": r.reason,
                "code": r.code,
                "next_action": r.next_action,
            })
        })
        .collect();
    let pending: Vec<serde_json::Value> = reason::M06_PENDING
        .iter()
        .map(|r| serde_json::json!({"reason": r, "field": "iroh_admission.reason"}))
        .chain(std::iter::once(serde_json::json!({
            "reason": "adapter_unavailable",
            "field": "remote_pending_reasons",
        })))
        .collect();
    let resync: Vec<&str> = vec![
        reason::BACKLOG_TOO_LONG,
        reason::CURSOR_INVALID,
        reason::EVENT_TOO_LARGE,
        reason::HISTORY_TRIMMED,
        reason::SUBSCRIBER_LAGGED,
    ];
    let warnings: Vec<serde_json::Value> = m03_warning::REASONS
        .iter()
        .map(|(r, w)| serde_json::json!({"reason": r, "warning": w}))
        .collect();
    serde_json::json!({
        "schema_version": crate::SCHEMA_VERSION,
        "reasons": reasons,
        "pending_reasons": pending,
        "resync_reasons": resync,
        "warning_reasons": warnings,
        "declared_codes": DECLARED_CODES,
    })
}
