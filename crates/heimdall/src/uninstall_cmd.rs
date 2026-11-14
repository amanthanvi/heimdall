//! `heimdall uninstall [--keep-remote-enrollments] [--purge-state [--bundle <file>]]`
//! (m02-plan U9; ADR-0007 §5.5; Q6 as qualified by §12.2 item 11).
//!
//! **⟨M03⟩ Remote enrollments and the K_ca store items** (m03-plan U0b row 18, U12;
//! ADR-0008 D4 item 6). Before anything else, uninstall reads the state database
//! read-only ([`Inventory`]): the enrollments that are not final, every enrollment's last
//! change, and each registered CA's store item.
//! * **Every uninstall lists the enrollments that are not final**, each with its marker,
//!   destination and state, and offers `heimdall enroll remove <enrollment>` first. A
//!   plain `uninstall` then needs an acknowledgement to leave them enrolled (ADR-0008
//!   §17.25 item 11, [`confirm_plain`]): a typed `yes`, or `--keep-remote-enrollments`
//!   (the explicit acknowledgement for a scripted uninstall; the state is kept). Without
//!   either, on no terminal or with `--non-interactive`, it ends with exit 3 and nothing
//!   was changed.
//! * **`--purge-state`** is refused while any remain (`CONFIG_CONFLICT`, exit 6,
//!   [`enrollment_refusal`]), unless `--keep-remote-enrollments` comes with a **fresh**
//!   recovery bundle (`--bundle <file>`, §17.25 item 8, [`check_bundle`]): an unredacted
//!   `heimdall-recovery-bundle/1` created no earlier than the last enrollment or CA
//!   change, listing every CA and every remaining enrollment in its current state,
//!   **and** whose SHA-256 equals a digest this installation recorded when its CLI
//!   confirmed writing a bundle (`Txn::bundle_digest_recorded_at`, read-only); its path
//!   is shown in the result, never recorded. A hand-made, foreign, stale or partial file
//!   is refused `bundle_required` (`CAPABILITY_UNAVAILABLE`, exit 4); a redacted one is
//!   `bundle_redacted` (exit 4).
//! * **The K_ca store item's fate is stated** on every outcome
//!   (`heimdall_issuer::retire::uninstall_store_plan`): kept while any enrollment under
//!   its CA is not final, naming the item and the reason; otherwise deletion is offered
//!   (the retirement steps run to `retired`, behind the `RetireIssuer` typed
//!   confirmation), with the reminder to destroy the offline backup. ⟨§17.25 item 9⟩
//!   Uninstall runs the one retire entry (`issuer_cmd::retire_to_retired`) inline, before
//!   the runtime stops ([`retire_offered`]); without a terminal or under
//!   `--non-interactive` it is not run and `heimdall issuer retire <fingerprint>` is
//!   offered. An item whose locator was never recorded is kept, as Heimdall cannot
//!   delete it by exact identity.
//!
//! 1. With no state store there is nothing to roll back: nothing is started, and what
//!    remains is reported.
//! 2. Otherwise the rollback of every item (`setup rollback`'s flow: preview, show,
//!    confirmation contract when it needs a decision, the plan digest). Uninstall is a
//!    setup operation, so a held operation refuses it (`setup_in_progress`, naming the
//!    held operation and both repair commands) and nothing else happens.
//! 3. Empty `.hm-quarantine` directories are removed with `rmdir`; non-empty ones stay,
//!    listed with their entries (`kind: quarantine`).
//! 4. The runtime stops gracefully (`Request::Shutdown`), which removes its endpoints and
//!    `instance.json`.
//! 5. What remains is listed: the state store (kept by default), snapshots under
//!    `<state>/backups`, `*.hm-conflict-*` files, non-empty quarantine directories, and
//!    an include block still present (manual mode).
//!
//! **Incomplete rollback** (a conflict, a block still present, a conflict file, a
//! non-empty quarantine): `CONFIG_CONFLICT`, effect `partial`, everything kept and
//! listed, including the recovery records. **`--purge-state`** refuses with
//! `CONFIG_CONFLICT` (exit 6) while the rollback is incomplete or any projection
//! resource is not confirmed absent; only then does it delete the state store and the
//! snapshots. It never reports an unresolved cleanup as success.
//!
//! **⟨ADR-0008 §17.31 item 1 (W5-C01)⟩ The deletion is excluded from every writer.** A
//! purge runs only after the runtime's stop is **confirmed**; a refused or failed
//! shutdown, or one whose connection is lost, refuses it (`SERVICE_UNAVAILABLE`, exit 5,
//! retryable, no reason; effect `partial`), deleting nothing. After the stop and before
//! its final inventory and bundle read, the CLI takes the runtime's own exclusive
//! instance lock (`<state>/service.lock`, which runtime start-up takes before it opens
//! the state database) and holds it through the deletion ([`purge_locked`]); a
//! replacement runtime holding it refuses the purge the same way. The lock file is kept
//! and released last.
//!
//! **Purging needs its own attended confirmation** (ADR-0007 §12.31 item 1, Q6). Before
//! anything is started or changed, `--purge-state` shows what it will discard (the state
//! database with its counts of operations, grants, decisions, catalog records, events and
//! idempotency records, the backups, and the conflict and quarantine copies it leaves
//! alone) and asks for a typed `y`/`yes`. A non-TTY stdin, `--non-interactive` (which
//! never stands in for the typed answer, unlike `doctor --allow-config-commands`), end of
//! input, an interruption, the prompt timeout and any other answer end the command at
//! once with exit 3 `INTERACTION_REQUIRED` (raised by this client, so with no
//! `decision_ref`): nothing was changed and everything is kept.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_contract::Timestamp;
use heimdall_contract::enrollment::{EnrollmentView, TargetSummary};
use heimdall_contract::envelope::{EffectStatus, Envelope, reason};
use heimdall_contract::ids::CaFingerprint;
use heimdall_contract::issuer::{CaState, RECOVERY_BUNDLE_SCHEMA, RecoveryBundle, StoreKind};
use heimdall_contract::request::{InspectSubject, Request, ShutdownRequest, UninstallFenceRequest};
use heimdall_contract::setup::{RemainingArtifact, RemainingArtifactKind};
use heimdall_contract::{Code, ExitCode};
use heimdall_domain::enrollment::{EnrollmentRecord, ForeignRemovalRecord};
use heimdall_issuer::retire::{KeepReason, StoreFate, uninstall_store_plan};
use heimdall_issuer::store::{SecretStoreKind, StoreItemRef};
use heimdall_store::ext::TableCounts;
use heimdall_store::{NoFaults, OpenEnrollmentOperation, Store, StoreError};

use crate::cli::{Prompter, TerminalPrompt, UninstallArgs};
use crate::client::Ctx;
use crate::output;
use crate::prompt::Answer;
use crate::setup_cmd::{
    Outcome, block, entries, inspect, non_interactive_reason, request_id, rollback_intent, shown,
};

/// How long uninstall waits for the cleaner to confirm the projection resources absent.
const CLEANUP_WAIT: Duration = Duration::from_secs(15);

/// How long uninstall waits for the runtime to remove its advertisement.
const STOP_WAIT: Duration = Duration::from_secs(20);

/// Handle `uninstall` (module docs).
pub(crate) fn run(ctx: &Ctx, args: UninstallArgs) -> ExitCode {
    block(ctx, uninstall(ctx, &args, &mut TerminalPrompt))
}

/// The largest recovery bundle read (bytes): anything larger is not a bundle.
const BUNDLE_MAX: u64 = 16 * 1024 * 1024;

/// The command offered for each enrollment that is not final.
const ENROLL_REMOVE: &str = "heimdall enroll remove <enrollment>";

/// One K_ca store item and its fate (D4 item 6).
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoreItem {
    /// The CA.
    ca: CaFingerprint,
    /// Its state.
    state: CaState,
    /// The platform store.
    store_kind: StoreKind,
    /// The exact locator this installation recorded, if any.
    locator: Option<String>,
    /// When the offline backup was made.
    backup_created_at: Timestamp,
    /// What uninstall does with it.
    fate: Fate,
    /// ⟨§17.25 item 9⟩ How the inline retirement of an offered item went, once tried.
    retire: Option<RetireRun>,
}

/// The inline retirement of a store item whose deletion is offered (ADR-0008 §17.25
/// item 9), when it did not reach `retired`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RetireRun {
    /// Not run (no terminal, or `--non-interactive`): why.
    NotRun(String),
    /// Run, and stopped before `retired` (declined, refused, or the issuer did not
    /// confirm in time): its code, reason and message.
    Stopped {
        /// The envelope code.
        code: Code,
        /// The error reason, if any.
        reason: Option<String>,
        /// The message.
        message: String,
    },
}

/// What uninstall does with a K_ca store item.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fate {
    /// Kept: enrollments under the CA are not final (their markers).
    KeptLive(Vec<String>),
    /// Kept: no locator was recorded, so it cannot be deleted by exact identity.
    KeptUnrecorded,
    /// Deletion offered: run inline before the runtime stops, behind the retirement's
    /// own typed confirmation; until it ran, `heimdall issuer retire`, with the backup
    /// reminder.
    DeletionOffered,
    /// Deleted: the inline retirement ran to `retired` (the item was deleted by its
    /// exact locator).
    Retired,
}

/// What uninstall reads from the state database before anything else, read-only:
/// ⟨ADR-0008 §17.27 item 1⟩ every outstanding remote obligation
/// (`Txn::outstanding_obligations`), the CAs and their store items.
#[derive(Debug, Default, Clone)]
struct Inventory {
    /// The outstanding enrollments, oldest first: every one that is not final, and
    /// every one in any state whose `late_write` residual is unresolved (W5-R02).
    open: Vec<EnrollmentRecord>,
    /// ⟨W5-R01⟩ The foreign removals that are not final (an abandoned system-form
    /// one, still `pending_until_line_removed`, included), oldest first.
    foreign: Vec<ForeignRemovalRecord>,
    /// The enrollment operations open or `outcome_unknown` (an enrollment in flight
    /// is itself an obligation, §17.27 item 2), oldest first.
    operations: Vec<OpenEnrollmentOperation>,
    /// ⟨ADR-0008 §17.28 item 1⟩ The enrollment operations with a dispatched step
    /// without its result, or an uncertain mutation (remote effect unknown), oldest
    /// first (`heimdall_app::operations::unresolved_remote_steps`).
    unresolved_steps: Vec<heimdall_contract::ids::OperationId>,
    /// The last enrollment or CA change: any enrollment record's `updated_at` (final
    /// ones included), any foreign removal's creation, and any CA's registration,
    /// backup and retirement times.
    last_change: Option<Timestamp>,
    /// Every registered CA (retired ones included) and its state, which a fresh bundle
    /// lists as it is now (a CA's state changes carry no time of their own).
    cas: Vec<(CaFingerprint, CaState)>,
    /// Each registered CA's store item that may still exist.
    items: Vec<StoreItem>,
    /// ⟨ADR-0008 §17.32 item 1 (W5-D01)⟩ Every recovery-relevant record, as read in the
    /// same transaction ([`RecoverySnapshot`]): the confirmation's read and the purge's
    /// final read under the lock both produce it.
    snapshot: RecoverySnapshot,
    /// ⟨ADR-0008 §17.32 item 7⟩ The access-grant revocations whose remote part is still
    /// pending (`Txn::remote_revocations`): unfinished security actions on a remote
    /// system, which a purge would lose with no retry.
    remote_revocations: Vec<heimdall_domain::revocation::PendingRemoteRevocation>,
}

/// ⟨ADR-0008 §17.32 item 1 (W5-D01; audit A2, A4, A5)⟩ Every recovery-relevant record of
/// the state database, as [`heimdall_store::ext_m03::TABLE_RECOVERY`] classifies its
/// tables:
/// * every row and column of each `Rows` table (`issuers`: every CA with its state,
///   store locator and displaced items, the `orphan_store_items`; `enrollments`: every
///   enrollment in every state, with its residual (`late_write` and its token), origin
///   and hold; `foreign_removals`: every one in every state; `pair_preferences`: each
///   pair's issuing set), so a column a later migration adds is compared too;
/// * the `Part`s: each open or unresolved enrollment operation whole, with a digest of
///   its journal (its stage receipts) and its outstanding step token, and their
///   unresolved remote steps (`operations`, kinds by [`OPERATION_RECOVERY`]); the
///   pending decisions of the kinds [`DECISION_RECOVERY`] includes, whole
///   (`decisions`); the `meta` keys `META_RECOVERY` includes; and the projection
///   resources not confirmed absent (`resources`).
///
/// The purge deletes only when its final snapshot, read under the instance lock, is the
/// confirmed one but for this uninstall's own changes ([`Inventory::unchanged_but_for`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct RecoverySnapshot {
    /// The `meta` rows `META_RECOVERY` includes (the installation's environment).
    meta: Vec<(String, String)>,
    /// Each `Rows` table's rows ([`heimdall_store::Txn::recovery_rows`]).
    rows: Vec<(&'static str, Vec<heimdall_store::ext_m03::RecoveryRow>)>,
    /// The open or unresolved enrollment operations, each whole with its journal.
    operations: Vec<OperationSnapshot>,
    /// Their unresolved remote steps.
    unresolved_steps: Vec<heimdall_contract::ids::OperationId>,
    /// The pending decisions of an included kind, each whole (its JSON), by ID.
    decisions: Vec<String>,
    /// The projection resources not confirmed absent (desired and observed), by ID.
    projections_not_absent: Vec<String>,
}

/// ⟨audit A5⟩ One open or unresolved enrollment operation in the snapshot.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct OperationSnapshot {
    /// The operation record, whole (its JSON).
    record: String,
    /// The SHA-256 of its stage receipts in order (its journal), as JSON.
    journal_sha256: String,
    /// The token of the step its current journal has outstanding, if any.
    outstanding_token: Option<String>,
}

/// The stage of the enrollment journal's receipts (`heimdall_app`'s `JOURNAL_STAGE`);
/// the digest covers every receipt whatever its stage, this only names the token.
const JOURNAL_STAGE: &str = "enroll.journal";

impl RecoverySnapshot {
    /// Read it in the caller's transaction (read-only).
    fn read(
        tx: &mut heimdall_store::Txn<'_>,
        operations: &[OpenEnrollmentOperation],
        unresolved_steps: &[heimdall_contract::ids::OperationId],
    ) -> heimdall_store::Result<RecoverySnapshot> {
        use heimdall_domain::operation::EffectReceipt;
        use heimdall_domain::resource::ResourceState;
        use heimdall_store::ext_m03::{RecoveryClass, TABLE_RECOVERY};
        let mut rows = Vec::new();
        for (name, class) in TABLE_RECOVERY {
            if *class == RecoveryClass::Rows {
                rows.push((*name, tx.recovery_rows(name)?));
            }
        }
        let mut ops = Vec::new();
        for o in operations.iter().filter(|o| operation_in_snapshot(o.kind)) {
            let record = tx.operation(&o.id)?;
            let receipts = tx.stage_receipts(&o.id)?;
            let outstanding_token = receipts
                .iter()
                .rev()
                .find_map(|r| match &r.effect {
                    EffectReceipt::Confirmed { credential_ref, .. } if r.stage == JOURNAL_STAGE => {
                        serde_json::from_str::<heimdall_app::enrollment::Journal>(credential_ref)
                            .ok()
                    }
                    _ => None,
                })
                .and_then(|j| j.outstanding.map(|s| s.token));
            ops.push(OperationSnapshot {
                record: serde_json::to_string(&record).unwrap_or_default(),
                journal_sha256: heimdall_issuer::backup::sha256_hex(
                    serde_json::to_string(&receipts)
                        .unwrap_or_default()
                        .as_bytes(),
                ),
                outstanding_token,
            });
        }
        let mut decisions: Vec<(String, String)> = tx
            .pending_decisions()?
            .into_iter()
            .filter(|d| decision_in_snapshot(&d.kind))
            .map(|d| {
                (
                    d.id.as_str().to_owned(),
                    serde_json::to_string(&d).unwrap_or_default(),
                )
            })
            .collect();
        decisions.sort();
        let projections_not_absent = match tx.self_environment()? {
            Some(env) => tx
                .projection_resources(&env)?
                .into_iter()
                .filter(|r| {
                    !(r.desired == ResourceState::Absent && r.observed == ResourceState::Absent)
                })
                .map(|r| r.id.as_str().to_owned())
                .collect(),
            None => Vec::new(),
        };
        Ok(RecoverySnapshot {
            meta: tx.recovery_meta()?,
            rows,
            operations: ops,
            unresolved_steps: unresolved_steps.to_vec(),
            decisions: decisions.into_iter().map(|(_, d)| d).collect(),
            projections_not_absent,
        })
    }

    /// The snapshot without the projection resources (they move with the rollback and
    /// the cleaner; the purge requires them absent under the lock instead).
    fn records(&self) -> RecoverySnapshot {
        RecoverySnapshot {
            projections_not_absent: Vec::new(),
            ..self.clone()
        }
    }
}

/// ⟨audit A2, A4⟩ How the recovery snapshot treats a **pending** decision, by kind
/// ([`decision_kind_name`]): `None` when it is in the snapshot, whole, otherwise why
/// not. A settled decision is in none: what its approval did is in the records it
/// wrote (the CAs, enrollments and operations compared). **A new `DecisionKind` is
/// classified here**: [`decision_kind_name`] matches without a wildcard (a new kind
/// does not compile until it is named), and `decision_kinds_are_classified_for_the_snapshot`
/// fails on a named kind that is not listed.
const DECISION_RECOVERY: &[(&str, Option<&str>)] = &[
    // Its `store_locator` (and a restore's `expected_store_locator`) can be the only
    // record of a K_ca store item already written.
    ("register_issuer", None),
    (
        "retire_issuer",
        Some("its approval's effect is the CA's state and store item, compared in `issuers`"),
    ),
    (
        "enroll_account",
        Some(
            "it waits on an open enrollment operation, compared with its journal; its approval's effect is in the enrollment records",
        ),
    ),
    (
        "enroll_system_form",
        Some(
            "it waits on an open enrollment operation, compared with its journal; its approval's effect is in the enrollment records",
        ),
    ),
    (
        "remove_enrollment",
        Some(
            "it waits on an open enrollment operation, compared with its journal; its approval's effect is in the enrollment and foreign-removal records",
        ),
    ),
    (
        "approve_target_change",
        Some(
            "its held enrollment is compared whole; its approval's effect is in the enrollment record",
        ),
    ),
    (
        "approve_authority",
        Some("access-grant authority (ADR-0008 §17.32 item 6: out)"),
    ),
    ("widen_policy", Some("a local standing-policy action")),
    ("confirm_time", Some("the local time")),
    (
        "apply_projection",
        Some(
            "a local projection change; this uninstall's own rollback asks one, and the projection resources are checked absent under the lock",
        ),
    ),
    ("declare_interaction", Some("a local catalog declaration")),
];

/// The name of a decision's kind in [`DECISION_RECOVERY`]. No wildcard: a new kind
/// does not compile until it is named, and then fails the classification test until it
/// is listed.
fn decision_kind_name(kind: &heimdall_domain::decision::DecisionKind) -> &'static str {
    use heimdall_domain::decision::DecisionKind as D;
    match kind {
        D::ApproveAuthority { .. } => "approve_authority",
        D::WidenPolicy { .. } => "widen_policy",
        D::ConfirmTime { .. } => "confirm_time",
        D::ApplyProjection { .. } => "apply_projection",
        D::DeclareInteraction { .. } => "declare_interaction",
        D::RegisterIssuer { .. } => "register_issuer",
        D::RetireIssuer { .. } => "retire_issuer",
        D::EnrollAccount { .. } => "enroll_account",
        D::EnrollSystemForm { .. } => "enroll_system_form",
        D::RemoveEnrollment { .. } => "remove_enrollment",
        D::ApproveTargetChange { .. } => "approve_target_change",
    }
}

/// Whether a pending decision of `kind` is in the recovery snapshot
/// ([`DECISION_RECOVERY`]; an unlisted kind is, fail closed).
fn decision_in_snapshot(kind: &heimdall_domain::decision::DecisionKind) -> bool {
    let name = decision_kind_name(kind);
    DECISION_RECOVERY
        .iter()
        .find(|(k, _)| *k == name)
        .is_none_or(|(_, why)| why.is_none())
}

/// ⟨ADR-0008 §17.32 items 1, 6⟩ How the recovery snapshot treats an open operation, by
/// kind: `None` when its open or unresolved operations are in the snapshot, otherwise
/// why not. **A new [`OperationKind`](heimdall_domain::operation::OperationKind) is
/// classified here**: `operation_kinds_are_classified_for_the_snapshot` fails on a kind
/// of `OperationKind::ALL` that is not listed.
const OPERATION_RECOVERY: &[(heimdall_domain::operation::OperationKind, Option<&str>)] = {
    use heimdall_domain::operation::OperationKind as K;
    const GRANT: &str = "access grants: their certificate issuance records are short-lived and create no new remote obligation; the lasting remote trust is the CA enrollment";
    &[
        (K::EnrollmentApply, None),
        (K::EnrollmentVerify, None),
        // A foreign removal runs as `enrollment.remove`, and is covered as its record too.
        (K::EnrollmentRemove, None),
        (K::Ensure, Some(GRANT)),
        (K::Bind, Some(GRANT)),
        (K::Delegate, Some(GRANT)),
        (
            K::Revoke,
            Some("a local grant revocation; no remote obligation"),
        ),
        (K::Cancel, Some("declared, never journaled")),
        (K::Release, Some("declared, never journaled")),
        (
            K::Policy,
            Some("declared, never journaled; standing policies are local"),
        ),
        (K::Probe, Some("reserved, never journaled")),
        (
            K::SetupApply,
            Some("local resources; the projection resources are checked absent under the lock"),
        ),
        (
            K::SetupRollback,
            Some("local resources; this uninstall's own rollback is one"),
        ),
        (
            K::SetupRepair,
            Some("local resources; the projection resources are checked absent under the lock"),
        ),
        (K::Catalog, Some("local catalog records")),
        // Issuer work (registration, retirement, restore) has no operation kind: it has
        // no remote effect, and its store items are covered by the CA, locator and
        // orphan-item entries of `issuers`.
    ]
};

/// Whether `kind`'s open operations are in the recovery snapshot ([`OPERATION_RECOVERY`];
/// an unlisted kind is, fail closed).
fn operation_in_snapshot(kind: heimdall_domain::operation::OperationKind) -> bool {
    OPERATION_RECOVERY
        .iter()
        .find(|(k, _)| *k == kind)
        .is_none_or(|(_, why)| why.is_none())
}

/// ⟨audit A3⟩ A CA as this uninstall's session observed it (`issuer.status`): its
/// state, recorded store locator and displaced store locators (sorted).
#[derive(Debug, Clone, PartialEq, Eq)]
struct CaObserved {
    /// Its state.
    state: CaState,
    /// Its recorded store locator.
    locator: Option<String>,
    /// Its displaced store locators, sorted.
    displaced: Vec<String>,
}

/// ⟨audit A3⟩ A retirement this uninstall ran that changed its CA: the CA as its own
/// session observed it just before and just after the run (under the uninstall fence,
/// so no other connection could retire it or approve its decision meanwhile). Only a
/// run with both observations and a difference between them is recorded; a declined
/// or refused run that changed nothing admits no change at all.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnRetirement {
    /// The CA.
    ca: CaFingerprint,
    /// Before the run.
    before: CaObserved,
    /// After it.
    after: CaObserved,
}

/// What this uninstall itself changed between its confirmation and the purge: its
/// retirement runs as observed, and its one retry of each pending remote revocation as
/// the runtime answered it. The purge's final check admits exactly these.
#[derive(Debug, Clone, Default)]
struct OwnChanges {
    /// The retirement runs that changed their CA.
    retirements: Vec<OwnRetirement>,
    /// The retry's answer per pending remote revocation.
    retries: Vec<RemoteRetry>,
}

/// The `meta` key of a pending remote revocation (`heimdall_store`'s
/// `remote_revocation:` prefix and the root grant).
fn remote_revocation_key(root: &str) -> String {
    format!("remote_revocation:{root}")
}

/// ⟨ADR-0008 §17.32 item 7; §17.33 item 3 (W5-E01)⟩ The `meta` rows are the confirmed
/// ones but for this uninstall's own retry: for each record it retried (and had
/// confirmed), the row now holds **exactly** the record the retry returned, byte for
/// byte in the store's form (`serde_json::to_string`, the store's `codec::doc`), or is
/// gone when the retry returned none. Anything else in it (a new obligation, another
/// count, stop, kind, effect or claim sequence, re-arm history or cap) is a difference,
/// and so is every change to any other row.
fn meta_unchanged_but_for(
    before: &[(String, String)],
    after: &[(String, String)],
    retries: &[RemoteRetry],
) -> bool {
    // ⟨audit B1⟩ A failed round admits nothing: its row must be the confirmed bytes.
    let retries: Vec<&RemoteRetry> = retries.iter().filter(|r| r.outcome != "failed").collect();
    let retried = |k: &str| {
        retries
            .iter()
            .find(|r| remote_revocation_key(&r.root_grant) == k)
    };
    let others = |rows: &[(String, String)]| -> Vec<(String, String)> {
        rows.iter()
            .filter(|(k, _)| retried(k).is_none())
            .cloned()
            .collect()
    };
    if others(before) != others(after) {
        return false;
    }
    retries.iter().all(|r| {
        let key = remote_revocation_key(&r.root_grant);
        let row = |rows: &[(String, String)]| {
            rows.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone())
        };
        if row(before).is_none() {
            return false;
        }
        match (&r.record, row(after)) {
            (None, None) => true,
            (Some(record), Some(stored)) => {
                serde_json::to_string(record).is_ok_and(|canonical| canonical == stored)
            }
            _ => false,
        }
    })
}

/// ⟨§17.32 item 7⟩ The retry's result in the report: `remote_revocation_retries` (each
/// record's outcome and whether it is still pending), or the reason it was not made.
fn with_retries(out: &mut Outcome, retried: &Result<Vec<RemoteRetry>, String>) {
    let (json, human) = match retried {
        Ok(r) if r.is_empty() => return,
        Ok(r) => (
            serde_json::to_value(r).unwrap_or(serde_json::Value::Null),
            r.iter()
                .map(|t| {
                    format!(
                        "    grant {}: {} ({} -> {} round(s)){}\n",
                        t.root_grant,
                        t.outcome,
                        t.attempts_before,
                        t.attempts_after,
                        if t.pending {
                            ", still pending"
                        } else {
                            ", done"
                        }
                    )
                })
                .collect::<String>(),
        ),
        Err(why) => (
            serde_json::json!({ "attempted": false, "message": why }),
            format!("    not made: {why}\n"),
        ),
    };
    if let serde_json::Value::Object(map) = &mut out.env.data {
        map.insert("remote_revocation_retries".to_owned(), json);
    }
    out.human.push_str(&format!(
        "Remote revocation retries (one attempt each):\n{human}"
    ));
}

/// The CA `ca` in an `issuer.status` answer, if readable.
fn observe_ca(env: &Envelope<serde_json::Value>, ca: &CaFingerprint) -> Option<CaObserved> {
    let st = crate::issuer_cmd::status_of(env)?;
    let row = st.cas.iter().find(|c| c.fingerprint == *ca)?;
    let mut displaced: Vec<String> = crate::issuer_cmd::displaced_of(&st, ca)
        .filter_map(|o| o.locator.clone())
        .collect();
    displaced.sort();
    Some(CaObserved {
        state: row.state,
        locator: row.store_locator.clone(),
        displaced,
    })
}

/// An `issuers` row taken apart: the row without its `state`, `retired_at` and
/// `record_json`'s `state`, `retired_at` and `displaced_store_locators`; the CA as
/// observed (state, recorded locator, sorted displaced locators); and whether
/// `retired_at` is set. `None` when the row is not well formed.
fn ca_parts(
    row: &[(String, String)],
) -> Option<(heimdall_store::ext_m03::RecoveryRow, CaObserved, bool)> {
    let mut state = None;
    let mut retired_at = false;
    let mut locator = None;
    let mut displaced = Vec::new();
    let mut out = Vec::new();
    for (c, v) in row {
        match c.as_str() {
            "state" => {
                state =
                    serde_json::from_value::<CaState>(serde_json::Value::String(v.clone())).ok();
            }
            "retired_at" => retired_at = v != "NULL",
            "record_json" => {
                let mut doc: serde_json::Value = serde_json::from_str(v).ok()?;
                let map = doc.as_object_mut()?;
                map.remove("state");
                map.remove("retired_at");
                if let Some(d) = map.remove("displaced_store_locators") {
                    displaced = serde_json::from_value(d).ok()?;
                }
                locator = map
                    .get("store_locator")
                    .and_then(|l| l.as_str())
                    .map(str::to_owned);
                out.push((c.clone(), doc.to_string()));
            }
            _ => out.push((c.clone(), v.clone())),
        }
    }
    displaced.sort();
    Some((
        out,
        CaObserved {
            state: state?,
            locator,
            displaced,
        },
        retired_at,
    ))
}

/// The CA fingerprint of an `issuers` row.
fn row_ca(row: &[(String, String)]) -> Option<&str> {
    row.iter()
        .find(|(c, _)| c == "ca_fingerprint")
        .map(|(_, v)| v.as_str())
}

/// The view `uninstall_store_plan` reads (it uses the CA, marker and state only).
fn view(r: &EnrollmentRecord) -> EnrollmentView {
    EnrollmentView {
        enrollment_id: r.id.clone(),
        destination_id: r.destination.clone(),
        account: r.account.clone(),
        form: r.form,
        ca_fingerprint: r.ca_fingerprint.clone(),
        marker: r.marker.clone(),
        state: r.state,
        registry: r.registry.clone(),
        verified_at: r.verified_at,
        evidence_fresh_until: None,
        pair_residual_until: None,
        destination_clock: heimdall_contract::managed::DestinationClock::default(),
        residual_status: None,
        approved_target: TargetSummary {
            hostname: r.target.hostname.clone(),
            port: r.target.port,
            user: r.target.user.clone(),
            host_key_fingerprint: r.target.host_key.fingerprint.clone(),
        },
        removal_purpose: r.removal_purpose(),
        live_grants: Vec::new(),
        open_operation_id: None,
        possible_late_write: r.late_write.is_some(),
        hold: None,
    }
}

impl Inventory {
    /// Read the database at `db` read-only (U0b row 18; verify-doc E12). A file older
    /// than the enrollment schema has none; a file that cannot be read says so (the
    /// purge is then refused).
    fn read(db: &Path) -> Result<Inventory, &'static str> {
        Self::read_opened(Store::open_read_only(db, Arc::new(NoFaults)))
    }

    /// [`Inventory::read`] from a store already opened read-only (the purge's final read
    /// of the quarantined database).
    fn read_opened(opened: Result<Store, StoreError>) -> Result<Inventory, &'static str> {
        let store = match opened {
            Ok(store) => store,
            Err(StoreError::OlderSchema { .. }) => return Ok(Inventory::default()),
            Err(_) => return Err("the database could not be opened read-only"),
        };
        Self::read_store(&store)
    }

    /// [`Inventory::read`] from an open store.
    fn read_store(store: &Store) -> Result<Inventory, &'static str> {
        store
            .transaction(|tx| {
                let outstanding = tx.outstanding_obligations()?;
                let unresolved = heimdall_app::operations::unresolved_remote_steps(tx)?;
                let issuers = tx.issuers()?;
                let mut all = outstanding.enrollments.clone();
                let mut locators = Vec::new();
                for i in &issuers {
                    for r in tx.enrollments_for_ca(&i.ca_fingerprint)? {
                        // Each record once: the open ones are already in.
                        if all.iter().all(|a| a.id != r.id) {
                            all.push(r);
                        }
                    }
                    locators.push(tx.issuer_store_locator(&i.ca_fingerprint)?);
                }
                let snapshot = (
                    RecoverySnapshot::read(tx, &outstanding.operations, &unresolved)?,
                    tx.remote_revocations()?,
                );
                Ok((outstanding, unresolved, all, issuers, locators, snapshot))
            })
            .map(
                |(
                    outstanding,
                    unresolved,
                    all,
                    issuers,
                    locators,
                    (snapshot, remote_revocations),
                )| {
                    let views: Vec<EnrollmentView> = all.iter().map(view).collect();
                    let cas = issuers
                        .iter()
                        .map(|i| (i.ca_fingerprint.clone(), i.state))
                        .collect();
                    let ca_change = issuers
                        .iter()
                        .flat_map(|i| [Some(i.created_at), Some(i.backup_created_at), i.retired_at])
                        .flatten()
                        .max();
                    let items = issuers
                        .into_iter()
                        .zip(locators)
                        .filter(|(i, _)| !matches!(i.state, CaState::Deleted | CaState::Retired))
                        .map(|(i, locator)| {
                            let item = StoreItemRef {
                                kind: SecretStoreKind::Product(i.store_kind),
                                fingerprint: i.ca_fingerprint.clone(),
                                locator: locator.clone().unwrap_or_default(),
                            };
                            let fate = match uninstall_store_plan(&views, &item) {
                                StoreFate::Keep(KeepReason::LiveEnrollments(markers)) => {
                                    Fate::KeptLive(markers)
                                }
                                _ if locator.is_none() => Fate::KeptUnrecorded,
                                _ => Fate::DeletionOffered,
                            };
                            StoreItem {
                                ca: i.ca_fingerprint,
                                state: i.state,
                                store_kind: i.store_kind,
                                locator,
                                backup_created_at: i.backup_created_at,
                                fate,
                                retire: None,
                            }
                        })
                        .collect();
                    Inventory {
                        last_change: all
                            .iter()
                            .map(|r| r.updated_at)
                            .chain(outstanding.foreign_removals.iter().map(|f| f.created_at))
                            .chain(ca_change)
                            .max(),
                        cas,
                        open: outstanding.enrollments,
                        foreign: outstanding.foreign_removals,
                        operations: outstanding.operations,
                        unresolved_steps: unresolved,
                        items,
                        snapshot,
                        remote_revocations,
                    }
                },
            )
            .map_err(|_| "the enrollments could not be read")
    }

    /// ⟨§17.27 item 1⟩ Whether no remote obligation is outstanding.
    fn clear(&self) -> bool {
        self.open.is_empty() && self.foreign.is_empty() && self.operations.is_empty()
    }

    /// How many remote obligations are outstanding.
    fn count(&self) -> usize {
        self.open.len() + self.foreign.len() + self.operations.len()
    }

    /// ⟨§17.27 item 2⟩ Whether `now` is the inventory the owner confirmed: the same
    /// outstanding obligations in the same states, the same CAs in the same states,
    /// and the same last change.
    /// ⟨§17.32 item 1⟩ And every recovery-relevant record ([`RecoverySnapshot`], but
    /// the projection resources).
    fn same_as(&self, now: &Inventory) -> bool {
        self.open == now.open
            && self.foreign == now.foreign
            && self.operations == now.operations
            && self.unresolved_steps == now.unresolved_steps
            && self.cas == now.cas
            && self.last_change == now.last_change
            && self.snapshot.records() == now.snapshot.records()
    }

    /// ⟨ADR-0008 §17.32 item 1 (W5-D01; audit A3)⟩ The purge's final check, under the
    /// instance lock: `now` is this (confirmed) inventory but for this uninstall's own
    /// changes, and every projection resource is confirmed absent. The only change
    /// admitted is exactly what one of this uninstall's retirement runs (`own`) was
    /// observed to do to its CA: the CA was as observed before the run, and is now as
    /// observed after it (state, recorded locator, displaced locators; `retired_at`
    /// set exactly when it is `retired`), every other field unchanged. Anything else (a
    /// CA, store locator, enrollment, residual, foreign removal, issuing set, pending
    /// registration, operation or its journal added, removed or replaced, by a runtime
    /// that started and stopped meanwhile or otherwise) is a difference.
    fn unchanged_but_for(&self, now: &Inventory, own: &OwnChanges) -> bool {
        let (a, b) = (&self.snapshot, &now.snapshot);
        if !b.projections_not_absent.is_empty()
            || !meta_unchanged_but_for(&a.meta, &b.meta, &own.retries)
            || a.operations != b.operations
            || a.unresolved_steps != b.unresolved_steps
            || a.decisions != b.decisions
            || a.rows.len() != b.rows.len()
        {
            return false;
        }
        let run = |row: &[(String, String)]| {
            row_ca(row).and_then(|ca| own.retirements.iter().find(|o| o.ca.as_str() == ca))
        };
        for ((ta, ra), (tb, rb)) in a.rows.iter().zip(&b.rows) {
            if ta != tb || ra.len() != rb.len() {
                return false;
            }
            if *ta != "issuers" {
                if ra != rb {
                    return false;
                }
                continue;
            }
            // Pair each confirmed CA with the one now, by fingerprint.
            for before in ra {
                let Some(after) = rb.iter().find(|r| row_ca(r) == row_ca(before)) else {
                    return false;
                };
                let Some(o) = run(before) else {
                    if before != after {
                        return false;
                    }
                    continue;
                };
                let (Some((nb, ob, _)), Some((na, oa, retired_at))) =
                    (ca_parts(before), ca_parts(after))
                else {
                    return false;
                };
                if nb != na
                    || ob != o.before
                    || oa != o.after
                    || retired_at != (oa.state == CaState::Retired)
                {
                    return false;
                }
            }
        }
        true
    }

    /// The `enrollments` listing (marker, destination, state, and the unresolved
    /// `late_write` residual when there is one).
    fn enrollments_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.open
                .iter()
                .map(|e| {
                    let mut v = serde_json::json!({
                        "marker": e.marker,
                        "destination_id": e.destination.as_str(),
                        "state": e.state.as_str(),
                    });
                    if let (Some(l), serde_json::Value::Object(map)) = (&e.late_write, &mut v) {
                        map.insert(
                            "late_write".to_owned(),
                            serde_json::json!({ "not_after_remote": l.not_after_remote }),
                        );
                    }
                    v
                })
                .collect(),
        )
    }

    /// ⟨W5-R01⟩ The `foreign_removals` listing: each by its public removal descriptor
    /// (never foreign bytes) and state.
    fn foreign_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.foreign
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "marker": f.target.marker,
                        "local_alias": f.target.local_alias,
                        "account": f.target.account.as_str(),
                        "form": f.target.form,
                        "line_sha256": f.target.line_sha256,
                        "state": f.state.as_str(),
                    })
                })
                .collect(),
        )
    }

    /// The `enrollment_operations` listing (operation, kind, state).
    fn operations_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.operations
                .iter()
                .map(|o| {
                    serde_json::json!({
                        "operation_id": o.id.as_str(),
                        "kind": o.kind.as_str(),
                        "state": o.state,
                    })
                })
                .collect(),
        )
    }

    /// Insert the inventory's listings into `map`: `enrollments` (unless present),
    /// `foreign_removals` and `enrollment_operations` when any.
    fn insert_listing(&self, map: &mut serde_json::Map<String, serde_json::Value>) {
        if !map.contains_key("enrollments") {
            map.insert("enrollments".to_owned(), self.enrollments_json());
        }
        if !self.foreign.is_empty() {
            map.insert("foreign_removals".to_owned(), self.foreign_json());
        }
        if !self.operations.is_empty() {
            map.insert("enrollment_operations".to_owned(), self.operations_json());
        }
        if !self.remote_revocations.is_empty() {
            map.insert(
                "pending_remote_revocations".to_owned(),
                self.remote_revocations_json(),
            );
        }
        if !self.unresolved_steps.is_empty() {
            map.insert(
                "unresolved_steps".to_owned(),
                serde_json::Value::Array(
                    self.unresolved_steps
                        .iter()
                        .map(|o| serde_json::Value::String(o.as_str().to_owned()))
                        .collect(),
                ),
            );
        }
    }

    /// ⟨§17.32 item 7⟩ The `pending_remote_revocations` listing: each revoked root grant,
    /// the grants it covers, the rounds attempted and whether the retries stopped.
    fn remote_revocations_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.remote_revocations
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "root_grant": r.root.as_str(),
                        "grants": r.grants.iter().map(|g| g.as_str()).collect::<Vec<_>>(),
                        "attempts": r.attempts,
                        "stopped": r.stopped,
                    })
                })
                .collect(),
        )
    }

    /// ⟨§17.32 item 7⟩ The human lines for the pending remote revocations (empty when
    /// none).
    fn remote_revocations_text(&self) -> String {
        if self.remote_revocations.is_empty() {
            return String::new();
        }
        let mut out = format!("  {REMOTE_REVOCATIONS}:\n");
        for r in &self.remote_revocations {
            out.push_str(&format!(
                "    grant {} (covering {}): {} round(s) attempted{}\n",
                r.root.as_str(),
                r.grants
                    .iter()
                    .map(|g| g.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                r.attempts,
                if r.stopped { ", retries stopped" } else { "" }
            ));
        }
        out
    }

    /// The `store_items` listing, each with its fate.
    fn store_items_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.items
                .iter()
                .map(|i| {
                    let (fate, why, markers) = match &i.fate {
                        Fate::KeptLive(m) => ("kept", Some("live_enrollments"), m.clone()),
                        Fate::KeptUnrecorded => ("kept", Some("locator_unrecorded"), Vec::new()),
                        Fate::DeletionOffered => ("deletion_offered", None, Vec::new()),
                        Fate::Retired => ("retired", None, Vec::new()),
                    };
                    let mut v = serde_json::json!({
                        "ca_fingerprint": i.ca.as_str(),
                        "ca_state": i.state,
                        "store_kind": i.store_kind,
                        "locator": i.locator,
                        "fate": fate,
                        "reason": why,
                        "markers": markers,
                        "message": item_line(i),
                    });
                    if i.fate == Fate::DeletionOffered
                        && let serde_json::Value::Object(map) = &mut v
                    {
                        map.insert(
                            "command".to_owned(),
                            serde_json::Value::String(retire_command(&i.ca)),
                        );
                        if let Some(run) = &i.retire {
                            map.insert(
                                "retire".to_owned(),
                                match run {
                                    RetireRun::NotRun(why) => {
                                        serde_json::json!({ "ran": false, "why": why })
                                    }
                                    RetireRun::Stopped {
                                        code,
                                        reason,
                                        message,
                                    } => serde_json::json!({
                                        "ran": true,
                                        "code": code,
                                        "reason": reason,
                                        "message": message,
                                    }),
                                },
                            );
                        }
                    }
                    v
                })
                .collect(),
        )
    }

    /// The human lines for the store items.
    fn store_items_text(&self) -> String {
        let mut out = String::new();
        if self.items.is_empty() {
            return out;
        }
        out.push_str("CA key (K_ca) store items:\n");
        for i in &self.items {
            out.push_str(&format!("    {}\n", item_line(i)));
        }
        out
    }
}

/// `heimdall issuer retire <fingerprint>`.
fn retire_command(ca: &CaFingerprint) -> String {
    format!("heimdall issuer retire {}", ca.as_str())
}

/// One store item's fate, named (D4 item 6).
fn item_line(i: &StoreItem) -> String {
    let kind = serde_json::to_value(i.store_kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let name = match &i.locator {
        Some(l) => format!("the {kind} item {l} of CA {}", i.ca.as_str()),
        None => format!(
            "the {kind} item of CA {} (locator not recorded)",
            i.ca.as_str()
        ),
    };
    match &i.fate {
        Fate::KeptLive(markers) => format!(
            "kept: {name}, because enrollments under this CA are not final ({}); remove them first with `{ENROLL_REMOVE}`",
            markers.join(", ")
        ),
        Fate::KeptUnrecorded => format!(
            "kept: {name}, because its exact locator was never recorded, so Heimdall cannot delete it; a later `heimdall issuer init` reports it as an orphan"
        ),
        Fate::DeletionOffered => {
            let run = match &i.retire {
                None => String::new(),
                Some(RetireRun::NotRun(why)) => {
                    format!(" Uninstall did not run it ({why}): it runs inline only on a terminal.")
                }
                Some(RetireRun::Stopped { message, .. }) => {
                    format!(" Uninstall ran it, and it stopped: {message}.")
                }
            };
            format!(
                "deletion offered: {name}; every enrollment under it is final, so the retirement steps delete it (run to `retired`, after a typed yes): uninstall runs them before the runtime stops, or run `{}`; then destroy the offline backup made {} yourself.{run}",
                retire_command(&i.ca),
                i.backup_created_at
            )
        }
        Fate::Retired => format!(
            "deleted: {name}; this uninstall retired the CA and deleted the item by its exact locator; destroy the offline backup made {} yourself",
            i.backup_created_at
        ),
    }
}

/// ⟨§17.27 item 1⟩ One line per outstanding remote obligation: each enrollment
/// (marker, destination, state, and its unresolved late write), each foreign removal
/// (marker, alias, account, form, state) and each enrollment operation in flight.
fn obligation_lines(inv: &Inventory) -> String {
    let mut out = String::new();
    for e in &inv.open {
        out.push_str(&format!(
            "    {} {} {}",
            e.marker,
            e.destination.as_str(),
            e.state.as_str()
        ));
        if let Some(l) = &e.late_write {
            out.push_str(&format!(
                " (late_write: an uncertain append may still land until remote time {}; its absence after that is not yet observed)",
                l.not_after_remote
            ));
        }
        out.push('\n');
    }
    for f in &inv.foreign {
        let form = serde_json::to_value(f.target.form)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let pending = if f.state == heimdall_contract::enrollment::EnrollmentState::Abandoned {
            " (pending_until_line_removed: its line may still trust the CA)"
        } else {
            ""
        };
        out.push_str(&format!(
            "    foreign removal {} via {} account {} ({form} form) {}{pending}\n",
            f.target.marker,
            f.target.local_alias,
            f.target.account.as_str(),
            f.state.as_str()
        ));
    }
    for o in &inv.operations {
        let state = serde_json::to_value(o.state)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        out.push_str(&format!(
            "    operation {} {} {state}\n",
            o.id.as_str(),
            o.kind.as_str()
        ));
    }
    out
}

/// The heading of the obligation listing.
const OBLIGATIONS: &str = "Outstanding remote obligations (enrollments that are not final or whose late write is unresolved, foreign removals that are not final, enrollment operations in flight)";

/// Add the inventory to `out`: `enrollments` (when any are not final and the key is
/// not there yet), `store_items` and, when one was accepted, `bundle`; and the same in
/// the human text.
fn annotate(mut out: Outcome, inv: &Inventory, bundle: Option<&str>) -> Outcome {
    let mut human = String::new();
    if let serde_json::Value::Object(map) = &mut out.env.data {
        if !inv.clear() && !map.contains_key("enrollments") {
            inv.insert_listing(map);
            human.push_str(&format!(
                "{OBLIGATIONS}; they stay:\n{}",
                obligation_lines(inv)
            ));
        }
        if !inv.items.is_empty() {
            map.insert("store_items".to_owned(), inv.store_items_json());
        }
        if !inv.remote_revocations.is_empty() && !map.contains_key("pending_remote_revocations") {
            map.insert(
                "pending_remote_revocations".to_owned(),
                inv.remote_revocations_json(),
            );
            human.push_str(&inv.remote_revocations_text());
        }
        if let Some(b) = bundle {
            map.insert(
                "bundle".to_owned(),
                serde_json::json!({ "path_display": b }),
            );
            human.push_str(&format!(
                "Recovery bundle recording the enrollments that stay: {b}\n"
            ));
        }
    }
    human.push_str(&inv.store_items_text());
    out.human.push_str(&human);
    out
}

/// A refusal with effect `none` carrying the `enrollments` listing.
fn enrollment_error(inv: &Inventory, error: heimdall_app::OpError, message: &str) -> Outcome {
    let mut env = output::error_value(error.with_effect(EffectStatus::None).into_envelope());
    if let serde_json::Value::Object(map) = &mut env.data {
        inv.insert_listing(map);
    }
    let human = format!("{OBLIGATIONS} ({message}):\n{}", obligation_lines(inv));
    Outcome::of(env).with_human(human)
}

/// `bundle_required` (or `bundle_redacted`): `CAPABILITY_UNAVAILABLE`, exit 4.
fn bundle_refusal(inv: &Inventory, why: &str, reason: &'static str) -> Outcome {
    enrollment_error(
        inv,
        heimdall_app::OpError::new(
            Code::CapabilityUnavailable,
            format!(
                "--purge-state --keep-remote-enrollments needs a fresh recovery bundle (--bundle <file>, written by this installation's `heimdall issuer bundle --out <file>` after the last enrollment or CA change): {why}; nothing was changed"
            ),
        )
        .with_reason(reason),
        "keeping them needs a fresh recovery bundle",
    )
}

/// How uninstall asks whether this installation recorded a bundle's SHA-256 (ADR-0008
/// §17.25 item 8; `Txn::bundle_digest_recorded_at` on the state database opened
/// read-only): `Ok(Some(created_at))` when recorded, `Ok(None)` when not, `Err` when the
/// record cannot be read.
type DigestRecord<'a> = &'a dyn Fn(&str) -> Result<Option<Timestamp>, ()>;

/// The digest record of the state database at `db`, read-only (nothing is created,
/// migrated or written).
fn recorded_digest(db: &Path, sha256: &str) -> Result<Option<Timestamp>, ()> {
    let store = Store::open_read_only(db, Arc::new(NoFaults)).map_err(|_| ())?;
    store
        .transaction(|tx| tx.bundle_digest_recorded_at(sha256))
        .map_err(|_| ())
}

/// Whether the file at `path` is a fresh recovery bundle for `inv` (D4 item 6, as
/// ADR-0008 §17.25 item 8 rules). Content: a `heimdall-recovery-bundle/1` document, not
/// redacted, created no earlier than the last enrollment or CA change, listing every
/// registered CA and every enrollment that is not final in its current state. Origin:
/// its SHA-256 (of the exact bytes read) equals a digest this installation recorded when
/// its CLI confirmed writing a bundle (`recorded`). A hand-made, foreign, stale or partial
/// file is `bundle_required`; a redacted one is `bundle_redacted`. `Err` is the refusal
/// with its reason.
fn check_bundle(
    inv: &Inventory,
    path: &Path,
    recorded: DigestRecord<'_>,
) -> Result<(), (String, &'static str)> {
    use std::io::Read as _;
    let required = |why: &str| Err((why.to_owned(), reason::BUNDLE_REQUIRED));
    let Ok(file) = std::fs::File::open(path) else {
        return required("the bundle file cannot be read");
    };
    let mut bytes = Vec::new();
    if file.take(BUNDLE_MAX + 1).read_to_end(&mut bytes).is_err() || bytes.len() as u64 > BUNDLE_MAX
    {
        return required("the bundle file cannot be read");
    }
    let Ok(bundle) = serde_json::from_slice::<RecoveryBundle>(&bytes) else {
        return required("the file is not a recovery bundle");
    };
    if bundle.schema != RECOVERY_BUNDLE_SCHEMA {
        return required("the file is not a recovery bundle");
    }
    if bundle.redacted {
        return Err((
            "the bundle is redacted, so it cannot guide a later removal".to_owned(),
            reason::BUNDLE_REDACTED,
        ));
    }
    if inv.last_change.is_some_and(|t| bundle.created_at < t) {
        return required("the bundle predates the last enrollment or CA change");
    }
    for (ca, state) in &inv.cas {
        if !bundle
            .cas
            .iter()
            .any(|b| b.fingerprint == *ca && b.state == *state)
        {
            return required("the bundle does not list every CA as it is now");
        }
    }
    for e in &inv.open {
        let late = e.late_write.as_ref().map(|l| l.not_after_remote);
        if !bundle.enrollments.iter().any(|b| {
            b.marker == e.marker
                && b.state == e.state
                && b.late_write.map(|l| l.not_after_remote) == late
        }) {
            return required("the bundle does not list every remaining enrollment as it is now");
        }
    }
    // ⟨§17.27 item 1 (W5-R01)⟩ every outstanding foreign removal, by its descriptor
    // and state.
    for f in &inv.foreign {
        let t = &f.target;
        if !bundle.foreign_removals.iter().any(|b| {
            b.marker == t.marker
                && b.local_alias == t.local_alias
                && b.account == t.account
                && b.line_sha256 == t.line_sha256
                && b.form == t.form
                && b.state == f.state
        }) {
            return required(
                "the bundle does not list every outstanding foreign removal as it is now",
            );
        }
    }
    match recorded(&heimdall_issuer::backup::sha256_hex(&bytes)) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => required(
            "this installation recorded no bundle with that SHA-256, so it is not one this installation wrote (hand-made, foreign, or changed since)",
        ),
        Err(()) => required("this installation's record of the bundles it wrote cannot be read"),
    }
}

/// The refusal of `--purge-state` while remote enrollments remain (U0b row 18; ADR-0008
/// D4 item 6). `Ok(None)`: the purge may go on to its own confirmation; `Ok(Some(path))`:
/// it may, keeping the enrollments recorded in the fresh bundle at that (displayed)
/// path. Nothing has been changed when it answers.
///
/// * none remain: no refusal (`--keep-remote-enrollments` is then moot);
/// * some remain: `CONFIG_CONFLICT` (exit 6), listing each marker, destination and state;
/// * `--keep-remote-enrollments` without `--bundle`, or with one that is not fresh
///   ([`check_bundle`]): `CAPABILITY_UNAVAILABLE` (`bundle_required`, exit 4; a redacted
///   one `bundle_redacted`).
fn enrollment_refusal(
    inv: &Inventory,
    args: &UninstallArgs,
    db: &Path,
) -> Result<Option<String>, Outcome> {
    enrollment_refusal_with(inv, args, &|sha| recorded_digest(db, sha))
}

/// [`enrollment_refusal`] with the digest record read through `recorded` (the purge's
/// final check: the quarantined database).
fn enrollment_refusal_with(
    inv: &Inventory,
    args: &UninstallArgs,
    recorded: DigestRecord<'_>,
) -> Result<Option<String>, Outcome> {
    if inv.clear() {
        return Ok(None);
    }
    if args.keep_remote_enrollments {
        let Some(path) = &args.bundle else {
            return Err(bundle_refusal(
                inv,
                "no bundle was given",
                reason::BUNDLE_REQUIRED,
            ));
        };
        return match check_bundle(inv, path, recorded) {
            Ok(()) => Ok(Some(heimdall_localenv::paths::display_path(&home(), path))),
            Err((why, r)) => Err(bundle_refusal(inv, &why, r)),
        };
    }
    Err(enrollment_error(
        inv,
        heimdall_app::OpError::new(
            Code::ConfigConflict,
            format!(
                "--purge-state refused: {} remote obligation(s) are outstanding (enrollments not final or with an unresolved late write, foreign removals not final, enrollment operations in flight); remove them with `{ENROLL_REMOVE}`, or keep them with --keep-remote-enrollments and a fresh recovery bundle; nothing was changed",
                inv.count()
            ),
        ),
        "remove them first",
    ))
}

/// ⟨ADR-0008 §17.32 item 7⟩ The heading of the pending remote revocations.
const REMOTE_REVOCATIONS: &str = "Access-grant revocations whose remote part is still pending (unfinished security actions on a remote system; before the runtime stops, uninstall makes one retry attempt for each; a purge then discards whatever is still pending with the state)";

/// ⟨ADR-0008 §17.32 item 7 (Q-I-R10-1)⟩ One record's answer to
/// `uninstall_fence.retry_remote_revocations` (the runtime's `RemoteRetry`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct RemoteRetry {
    /// The revoked root grant.
    root_grant: String,
    /// `completed`, `attempted_still_pending`, `not_attempted` or `failed`.
    outcome: String,
    /// Rounds before the attempt.
    attempts_before: u32,
    /// After it.
    attempts_after: u32,
    /// Whether its retries are stopped now.
    stopped: bool,
    /// Whether it is still pending.
    pending: bool,
    /// ⟨§17.33 item 3⟩ The complete record as stored right after the retry, or none
    /// once it is gone: the only change the final check admits for it.
    #[serde(default)]
    record: Option<heimdall_domain::revocation::PendingRemoteRevocation>,
}

/// ⟨ADR-0008 §17.32 item 7⟩ Make the one retry attempt per pending remote revocation on
/// uninstall's own session, which holds the fence, before the stop
/// (`uninstall_fence.retry_remote_revocations`). `Ok` with the runtime's answer per
/// record (none sent when nothing is pending); `Err` with the refusal's message when the
/// request failed (the attempt was not made).
async fn retry_remote_revocations<S: crate::cli::Session>(
    s: &mut S,
    inv: &Inventory,
) -> Result<Vec<RemoteRetry>, String> {
    if inv.remote_revocations.is_empty() {
        return Ok(Vec::new());
    }
    let env = s
        .request(Request::UninstallFence(
            UninstallFenceRequest::RetryRemoteRevocations,
        ))
        .await;
    if !env.code.is_success() {
        return Err(env
            .data
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("the runtime refused the retry")
            .to_owned());
    }
    env.data
        .get("remote_revocations")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or_else(|| "the runtime's answer to the retry could not be read".to_owned())
}

/// ⟨§17.32 item 7⟩ The inventory's pending remote revocations as the retry left them:
/// the completed ones leave the listing, the others carry their counts now.
fn apply_retries(inv: &mut Inventory, retries: &[RemoteRetry]) {
    inv.remote_revocations.retain_mut(|r| {
        match retries.iter().find(|t| t.root_grant == r.root.as_str()) {
            Some(t) => match &t.record {
                Some(record) => {
                    *r = record.clone();
                    true
                }
                None => false,
            },
            None => true,
        }
    });
}

/// The purge's refusal when the one retry attempt could not be made.
const RETRY_NOT_MADE: &str = "--purge-state refused: the one retry attempt of the pending remote revocations could not be made before the runtime stopped, so they would be discarded unretried; nothing was purged: the state database, the backups and every recovery record are kept. Run `heimdall uninstall --purge-state` again";

/// The refusal when the state database cannot be read for a purge.
fn unreadable(why: &str) -> Outcome {
    Outcome::of(output::error_value(
        heimdall_app::OpError::new(
            Code::ConfigConflict,
            format!(
                "--purge-state refused: {why}, so the remaining remote enrollments are unknown; nothing was changed"
            ),
        )
        .with_effect(EffectStatus::None)
        .into_envelope(),
    ))
}

/// The prompt of a plain `uninstall` while enrollments are not final (D4 item 6).
fn plain_ack_text(inv: &Inventory) -> String {
    format!(
        "{OBLIGATIONS}:\n{}Their lines stay on the destinations, and the state database (kept) still records them. To remove them first, answer no and run `{ENROLL_REMOVE}` for each.\n{}Uninstall anyway and leave them enrolled?\n",
        obligation_lines(inv),
        inv.store_items_text()
    )
}

/// The acknowledgement of a plain `uninstall` while enrollments are not final (ADR-0008
/// §17.25 item 11): `--keep-remote-enrollments` is the explicit acknowledgement (so a
/// scripted uninstall can go on; the state is kept, so nothing is lost); otherwise only a
/// typed `yes` goes on, and anything else, a non-TTY stdin and `--non-interactive` end it
/// with exit 3 (raised by this client, so with no `decision_ref`), nothing changed.
async fn confirm_plain<P: Prompter>(
    ctx: &Ctx,
    p: &mut P,
    inv: &Inventory,
    acknowledged: bool,
) -> Result<(), Outcome> {
    if acknowledged {
        return Ok(());
    }
    let refused = |why: &str| {
        enrollment_error(
            inv,
            heimdall_app::OpError::new(
                Code::InteractionRequired,
                format!(
                    "uninstall not confirmed ({why}): {} remote obligation(s) are outstanding; remove them first with `{ENROLL_REMOVE}`, or leave them enrolled by typing yes to `heimdall uninstall` on a terminal or by running `heimdall uninstall --keep-remote-enrollments`; nothing was changed",
                    inv.count()
                ),
            ),
            "remove them first",
        )
    };
    if !ctx.interactive() {
        return Err(refused(non_interactive_reason(ctx)));
    }
    let answer = p.ask(&plain_ack_text(inv)).await;
    if answer == Answer::Yes {
        Ok(())
    } else {
        Err(refused(answer.reason()))
    }
}

/// ⟨ADR-0008 §17.25 item 9⟩ Run the one retire entry (`issuer_cmd::retire_to_retired`:
/// the decision, its typed `yes`, the wait for `unloaded`, the exact-locator deletion and
/// the `deleted_locator` confirmation) inline, on the session uninstall holds and before
/// the runtime stops, for each store item whose deletion is offered. It is behind the
/// retirement's own typed confirmation, so without a terminal or under
/// `--non-interactive` nothing is sent (no decision is left pending) and the item stays
/// offered with `heimdall issuer retire <fingerprint>`.
///
/// ⟨audit A3⟩ Returns what each run did to its CA ([`OwnRetirement`]): the CA as this
/// session's `issuer.status` shows it just before and just after the run, recorded only
/// when both are readable and differ.
async fn retire_offered<S: crate::cli::Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    inv: &mut Inventory,
) -> Vec<OwnRetirement> {
    use heimdall_contract::issuer::IssuerRequest;
    let mut own = Vec::new();
    for item in inv
        .items
        .iter_mut()
        .filter(|i| i.fate == Fate::DeletionOffered)
    {
        if !ctx.interactive() {
            item.retire = Some(RetireRun::NotRun(non_interactive_reason(ctx).to_owned()));
            continue;
        }
        // ⟨ADR-0008 §17.27 item 3⟩ The item's fate and the backup reminder reach the
        // terminal (stderr) before the retirement's own confirmation, whatever the
        // output mode.
        crate::output::prompt(&format!("{}\n", item_line(item)));
        let before = observe_ca(
            &s.request(Request::Issuer(IssuerRequest::Status)).await,
            &item.ca,
        );
        let out = crate::issuer_cmd::retire_to_retired(s, p, ctx, &item.ca).await;
        let after = observe_ca(
            &s.request(Request::Issuer(IssuerRequest::Status)).await,
            &item.ca,
        );
        if let (Some(before), Some(after)) = (before, after)
            && before != after
        {
            own.push(OwnRetirement {
                ca: item.ca.clone(),
                before,
                after,
            });
        }
        if out.env.code.is_success() {
            item.fate = Fate::Retired;
            item.retire = None;
        } else {
            let error = out.env.data.get("error");
            let text = |k: &str| {
                error
                    .and_then(|e| e.get(k))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
            };
            item.retire = Some(RetireRun::Stopped {
                code: out.env.code.clone(),
                reason: text("reason"),
                message: text("message")
                    .unwrap_or_else(|| "the retirement did not finish".to_owned()),
            });
        }
    }
    own
}

/// The directories whose `*.hm-conflict-*` files and `.hm-quarantine` directories
/// uninstall and `setup status` report: the user's `~/.ssh`, Heimdall's configuration
/// directory and its `keys/`, and the Git homes (`~` and `$XDG_CONFIG_HOME/git`).
pub(crate) fn artifact_dirs(ctx: &Ctx) -> Result<Vec<PathBuf>, String> {
    let hooks = crate::testcfg::launch_hooks(&|n| std::env::var_os(n))?;
    let ssh = match &hooks.ssh_home {
        Some(h) => {
            heimdall_localenv::paths::SshPaths::with_test_override(h.clone(), h.join("etc-ssh"))
        }
        None => heimdall_localenv::paths::SshPaths::resolve().map_err(|e| e.0)?,
    };
    let heimdall = ctx.paths().map_err(|_| "paths".to_owned())?;
    let mut dirs = vec![
        ssh.user_dir.clone(),
        heimdall.config_dir.clone(),
        heimdall.config_dir.join("keys"),
        ssh.account_home.clone(),
        ssh.account_home.join(".config").join("git"),
    ];
    dirs.dedup();
    Ok(dirs)
}

/// The account home for display.
fn home() -> PathBuf {
    crate::testcfg::launch_hooks(&|n| std::env::var_os(n))
        .ok()
        .and_then(|h| h.ssh_home)
        .or_else(|| {
            heimdall_localenv::paths::SshPaths::resolve()
                .ok()
                .map(|p| p.account_home)
        })
        .unwrap_or_default()
}

/// Every non-empty `.hm-quarantine` directory under `dirs`, with its entries; with
/// `remove_empty`, empty ones are removed with `rmdir` first (it cannot remove an
/// entry). Each entry names the file it came from (the slot name's role) and why it
/// stayed: `modified_after_exchange` for the user's own regular file (Heimdall keeps a
/// moved entry only when its content changed after the move, ADR-0007 §5.3 step 8.4),
/// `foreign` otherwise.
pub(crate) fn quarantine_listing(dirs: &[PathBuf], remove_empty: bool) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let home = PathBuf::new();
    for dir in dirs {
        let q = dir.join(heimdall_localenv::sys::QUARANTINE_NAME);
        if !q.is_dir() {
            continue;
        }
        let items = entries(&q);
        if items.is_empty() {
            if remove_empty {
                let _ = std::fs::remove_dir(&q);
            }
            continue;
        }
        let listed: Vec<serde_json::Value> = items
            .iter()
            .map(|e| {
                let name = e
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let role = name.split('-').next().unwrap_or("").to_owned();
                let from = match role.as_str() {
                    "user_ssh" => dir.join("config"),
                    "managed_ssh" => dir.join("ssh_config"),
                    "git_include" => dir.join(".gitconfig"),
                    "git_managed" => dir.join("gitconfig"),
                    _ => dir.join(&role),
                };
                let regular = std::fs::symlink_metadata(e).is_ok_and(|m| m.file_type().is_file());
                serde_json::json!({
                    "name": name,
                    "from": shown(&from, &home),
                    "reason": if regular { "modified_after_exchange" } else { "foreign" },
                })
            })
            .collect();
        out.push(serde_json::json!({
            "path_display": shown(&q, &home),
            "entries": listed,
        }));
    }
    out
}

/// Every artifact left for the owner (module docs, step 5), shown under `home`.
fn remaining(ctx: &Ctx, dirs: &[PathBuf], purged: bool) -> Vec<RemainingArtifact> {
    let home = home();
    let mut out = Vec::new();
    let push = |out: &mut Vec<RemainingArtifact>, kind, p: &Path| {
        out.push(RemainingArtifact {
            kind,
            path_display: shown(p, &home),
        });
    };
    for dir in dirs {
        for e in entries(dir) {
            if e.file_name()
                .is_some_and(|n| n.to_string_lossy().contains(".hm-conflict-"))
            {
                push(&mut out, RemainingArtifactKind::ConflictFile, &e);
            }
        }
        let q = dir.join(heimdall_localenv::sys::QUARANTINE_NAME);
        if q.is_dir() && !entries(&q).is_empty() {
            push(&mut out, RemainingArtifactKind::Quarantine, &q);
        }
    }
    if let Some(user) = dirs.first().map(|d| d.join("config"))
        && let Ok(bytes) = std::fs::read(&user)
        && !heimdall_sshconf_blocks(&bytes)
    {
        push(&mut out, RemainingArtifactKind::ManualBlock, &user);
    }
    if let Ok(paths) = ctx.paths()
        && !purged
    {
        for b in entries(&paths.state_dir.join("backups")) {
            push(&mut out, RemainingArtifactKind::Backup, &b);
        }
        let db = paths
            .state_dir
            .join(heimdall_runtime::service::STATE_DB_FILE);
        if db.exists() {
            push(&mut out, RemainingArtifactKind::StateStore, &db);
        }
    }
    out
}

/// Whether the user file holds no Heimdall include block (`true`: none).
fn heimdall_sshconf_blocks(bytes: &[u8]) -> bool {
    heimdall_sshconf::edit::find_blocks(bytes).is_empty()
}

/// Whether every projection resource is confirmed absent (desired and observed).
fn resources_absent(data: &serde_json::Value) -> bool {
    data.get("projections")
        .and_then(|p| p.as_array())
        .is_none_or(|items| {
            items.iter().all(|r| {
                r.get("desired").and_then(|v| v.as_str()) == Some("absent")
                    && r.get("observed").and_then(|v| v.as_str()) == Some("absent")
            })
        })
}

/// Whether any setup operation is open or unresolved (`inspect operations`).
fn open_setup(data: &serde_json::Value) -> bool {
    data.get("operations")
        .and_then(|o| o.as_array())
        .is_some_and(|ops| {
            ops.iter().any(|o| {
                o.get("kind")
                    .and_then(|k| k.as_str())
                    .is_some_and(|k| k.starts_with("setup."))
                    && matches!(
                        o.get("state").and_then(|s| s.as_str()),
                        Some("queued" | "running" | "awaiting_approval" | "outcome_unknown")
                    )
            })
        })
}

/// Whether the projection record holds anything to roll back.
fn installed(data: &serde_json::Value) -> bool {
    data.get("record")
        .and_then(|r| r.get("items"))
        .and_then(|i| i.as_object())
        .is_some_and(|items| {
            items.values().any(|item| {
                item.get("files")
                    .and_then(|f| f.as_array())
                    .is_some_and(|f| !f.is_empty())
                    || item
                        .get("aliases")
                        .and_then(|a| a.as_array())
                        .is_some_and(|a| !a.is_empty())
            })
        })
}

/// What `--purge-state` discards, read before anything is changed.
#[derive(Debug)]
struct Discard {
    /// The state database, as displayed.
    database: String,
    /// Its size in bytes.
    bytes: u64,
    /// The record counts, or why they could not be read.
    counts: Result<TableCounts, &'static str>,
    /// The snapshots under `<state>/backups`, as displayed.
    backups: Vec<String>,
    /// Conflict files and non-empty quarantine directories: never removed by a purge
    /// (their presence makes it refuse), listed so the owner sees what stays.
    kept: Vec<String>,
    /// ⟨M03⟩ The remote enrollments a `--keep-remote-enrollments` purge leaves, with
    /// the fresh bundle that records them (D4 item 6).
    kept_remote: Option<String>,
    /// ⟨M03⟩ The K_ca store items' fates (D4 item 6).
    store_items: String,
    /// ⟨ADR-0008 §17.32 item 7⟩ The access-grant revocations whose remote part is still
    /// pending: discarded with the state, so confirmed knowingly.
    remote_revocations: String,
}

/// Count the rows of the database at `db`, table by table, whatever each row's state
/// ([`TableCounts`], ADR-0007 §12.32 item 7). Read-only: nothing is created, migrated or
/// repaired, and no runtime is started. `Err` names the failure's class, never a path
/// or the store's own text.
fn read_counts(db: &Path) -> Result<TableCounts, &'static str> {
    let store = Store::open_read_only(db, Arc::new(NoFaults))
        .map_err(|_| "the database could not be opened read-only")?;
    store
        .transaction(|tx| tx.table_counts())
        .map_err(|_| "the records could not be read")
}

impl Discard {
    /// Read what a purge of `state_dir` would discard.
    fn read(ctx: &Ctx, state_dir: &Path, dirs: &[PathBuf]) -> Discard {
        let home = home();
        let db = state_dir.join(heimdall_runtime::service::STATE_DB_FILE);
        Discard {
            database: shown(&db, &home),
            bytes: std::fs::metadata(&db).map_or(0, |m| m.len()),
            counts: read_counts(&db),
            backups: entries(&state_dir.join("backups"))
                .iter()
                .map(|b| shown(b, &home))
                .collect(),
            kept: remaining(ctx, dirs, false)
                .into_iter()
                .filter(|r| {
                    matches!(
                        r.kind,
                        RemainingArtifactKind::ConflictFile | RemainingArtifactKind::Quarantine
                    )
                })
                .map(|r| r.path_display)
                .collect(),
            kept_remote: None,
            store_items: String::new(),
            remote_revocations: String::new(),
        }
    }

    /// The text shown before the typed confirmation: everything the purge discards.
    fn text(&self) -> String {
        let mut out = String::from(
            "--purge-state permanently deletes Heimdall's state. None of it can be recovered.\n",
        );
        out.push_str(&format!(
            "  State database: {} ({} bytes)\n",
            self.database, self.bytes
        ));
        match &self.counts {
            Ok(c) => out.push_str(&format!(
                "    operations: {} (all states)\n    grants: {} (all states)\n    decisions: {} (all states)\n    catalog records: {} identities, {} destinations, {} profiles\n    events: {}\n    idempotency records: {}\n",
                c.operations,
                c.grants,
                c.decisions,
                c.identities,
                c.destinations,
                c.profiles,
                c.events,
                c.idempotency
            )),
            Err(why) => out.push_str(&format!(
                "    operations, grants, decisions, catalog records, events and idempotency records: not counted ({why}); they are discarded with it\n"
            )),
        }
        out.push_str(
            "    It also holds the standing policies, the tombstones and the recovery records, and the records this uninstall adds; all of them go too.\n",
        );
        if self.backups.is_empty() {
            out.push_str("  Backups of your original files: none\n");
        } else {
            out.push_str(&format!(
                "  Backups of your original files ({}):\n",
                self.backups.len()
            ));
            for b in &self.backups {
                out.push_str(&format!("    {b}\n"));
            }
        }
        if self.kept.is_empty() {
            out.push_str(
                "  Conflict and quarantine copies: none (a purge removes none, and is refused while any exist)\n",
            );
        } else {
            out.push_str(
                "  Conflict and quarantine copies, kept (a purge removes none, and is refused while any exist):\n",
            );
            for k in &self.kept {
                out.push_str(&format!("    {k}\n"));
            }
        }
        if let Some(k) = &self.kept_remote {
            out.push_str(k);
        }
        out.push_str(&self.store_items);
        out.push_str(&self.remote_revocations);
        out.push_str("Discard the state database and the backups?\n");
        out
    }
}

/// Exit 3 `INTERACTION_REQUIRED`, raised by this client (so with no `decision_ref`):
/// `--purge-state` was not confirmed and nothing was changed.
fn purge_not_confirmed(why: &str) -> Outcome {
    Outcome::of(output::error_value(
        heimdall_app::OpError::new(
            Code::InteractionRequired,
            format!(
                "--purge-state not confirmed ({why}): nothing was changed; the state database, the backups and every other record are kept. Run `heimdall uninstall --purge-state` on a terminal and type yes to purge, or `heimdall uninstall` to keep the state"
            ),
        )
        .with_effect(EffectStatus::None)
        .into_envelope(),
    ))
}

/// The attended confirmation of `--purge-state` (module docs). Without a terminal, or
/// with `--non-interactive`, nothing is read and nothing is asked; otherwise what
/// `read` finds is displayed and only a typed `y`/`yes` passes.
async fn confirm_purge<P: Prompter>(
    ctx: &Ctx,
    p: &mut P,
    read: impl FnOnce() -> Discard,
) -> Result<(), Outcome> {
    if !ctx.interactive() {
        return Err(purge_not_confirmed(&format!(
            "{}; it needs a typed yes on a terminal, which --non-interactive does not replace",
            non_interactive_reason(ctx)
        )));
    }
    let answer = p.ask(&read().text()).await;
    if answer == Answer::Yes {
        Ok(())
    } else {
        Err(purge_not_confirmed(answer.reason()))
    }
}

async fn uninstall<P: Prompter>(ctx: &Ctx, args: &UninstallArgs, prompt: &mut P) -> Outcome {
    // ⟨ADR-0008 §17.33 item 14⟩ The debug-only trusted top of the purge's secure-path
    // check; a release build refuses the variable (exit 2) before anything else.
    let trusted_top = match crate::testcfg::purge_trusted_top(&|n| std::env::var_os(n)) {
        Ok(t) => t,
        Err(m) => return crate::setup_cmd::usage(&m),
    };
    let purge = args.purge_state;
    let paths = match ctx.paths() {
        Ok(p) => p,
        Err(e) => return Outcome::of(output::error_value(*e)),
    };
    let dirs = artifact_dirs(ctx).unwrap_or_default();
    let db = paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    if !db.exists() {
        let _ = quarantine_listing(&dirs, true);
        let left = remaining(ctx, &dirs, false);
        return report(true, false, false, None, left, Vec::new());
    }
    // M03 (U0b row 18; D4 item 6): the enrollments and the store items, read-only first.
    // A purge is refused while remote enrollments remain (unless kept with a fresh
    // bundle), so the owner is not asked to type yes for something that will not happen;
    // a plain uninstall lists them and offers `enroll remove` first.
    let (mut inv, known) = match Inventory::read(&db) {
        Ok(inv) => (inv, true),
        Err(why) if purge => return unreadable(why),
        Err(_) => (Inventory::default(), false),
    };
    let mut bundle = None;
    if purge {
        match enrollment_refusal(&inv, args, &db) {
            Ok(b) => bundle = b,
            Err(refused) => return annotate(refused, &inv, None),
        }
    } else if !inv.clear()
        && let Err(refused) = confirm_plain(ctx, prompt, &inv, args.keep_remote_enrollments).await
    {
        return annotate(refused, &inv, None);
    }
    // Before anything is started or changed (ADR-0007 §12.31 item 1): a purge is shown
    // and confirmed first, so any answer but a typed yes leaves everything as it was.
    if purge
        && let Err(refused) = confirm_purge(ctx, prompt, || {
            let mut d = Discard::read(ctx, &paths.state_dir, &dirs);
            d.kept_remote = (!inv.clear()).then(|| {
                format!(
                    "  {OBLIGATIONS}, kept (recorded in {}):\n{}",
                    bundle.as_deref().unwrap_or_default(),
                    obligation_lines(&inv)
                )
            });
            d.store_items = inv.store_items_text();
            d.remote_revocations = inv.remote_revocations_text();
            d
        })
        .await
    {
        return annotate(refused, &inv, bundle.as_deref());
    }
    // ⟨ADR-0008 §17.27 item 2 (W5-S01)⟩ One session for the whole uninstall, with
    // `service-control/1`: it holds the uninstall fence from here until the runtime
    // stops (or this process ends), and asks for the stop itself.
    let mut client = match crate::client::connect_requiring(
        ctx,
        true,
        &[heimdall_contract::ipc::capability::SERVICE_CONTROL_V1],
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return Outcome::of(output::error_value(*e)),
    };
    // Close admission, then revalidate against the state about to be changed: an
    // inventory (or a bundle) that no longer matches what the owner confirmed lifts
    // the fence and stops here, with nothing deleted.
    if let Err(refused) = fence_and_revalidate(&mut client, &db, &inv, known, args).await {
        return refused;
    }
    let confirmed = inv.clone();
    let projections = match inspect(&mut client, InspectSubject::Projections).await {
        Ok(d) => d,
        Err(o) => return o,
    };
    let open = match inspect(&mut client, InspectSubject::Operations).await {
        Ok(d) => open_setup(&d),
        Err(o) => return o,
    };
    let mut rollback = None;
    let mut complete = true;
    // An open or held setup operation refuses the rollback (`setup_in_progress`), so
    // uninstall goes through the admission whenever one exists, even with nothing
    // committed (ADR-0007 §5.5: uninstall is a setup operation).
    if installed(&projections) || open {
        let rid = match request_id(None) {
            Ok(r) => r,
            Err(o) => return o,
        };
        let out =
            crate::setup_cmd::setup_flow(&mut client, prompt, ctx, &rollback_intent(false), rid)
                .await;
        let why = out
            .env
            .data
            .get("error")
            .and_then(|e| e.get("reason"))
            .and_then(|r| r.as_str())
            .map(str::to_owned);
        // A refusal before anything ran (a held operation, a decision not confirmed, a
        // runtime that cannot serve setup) ends uninstall here: nothing else changes.
        if out.env.code == Code::InteractionRequired
            || out.env.code == Code::ApprovalRequired
            || why.as_deref() == Some(reason::SETUP_IN_PROGRESS)
            || why.as_deref() == Some(reason::DRIVER_UNAVAILABLE)
            || out.env.code == Code::UsageError
        {
            return out;
        }
        complete = out.env.code.is_success();
        rollback = Some(if out.env.code.is_success() {
            out.env.data.clone()
        } else {
            out.env
                .data
                .get("setup")
                .cloned()
                .unwrap_or(serde_json::Value::Null)
        });
    }
    // The cleaner removes P and the key files; wait (bounded) for it to confirm.
    let deadline = Instant::now() + CLEANUP_WAIT;
    let mut absent = false;
    loop {
        if let Ok(data) = inspect(&mut client, InspectSubject::Projections).await {
            absent = resources_absent(&data);
        }
        if absent || !complete || Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let quarantine = quarantine_listing(&dirs, true);
    let mut left = remaining(ctx, &dirs, false);
    if left.iter().any(|r| {
        matches!(
            r.kind,
            RemainingArtifactKind::ConflictFile
                | RemainingArtifactKind::Quarantine
                | RemainingArtifactKind::ManualBlock
        )
    }) {
        complete = false;
    }
    // §17.25 item 9: the offered K_ca store items are retired inline, behind the
    // retirement's own typed confirmation, while the runtime still runs.
    let retirements = retire_offered(&mut client, prompt, ctx, &mut inv).await;
    // ⟨§17.32 item 7⟩ One retry attempt per pending remote revocation, on this session
    // (the fence holder), before the stop.
    let retried = retry_remote_revocations(&mut client, &inv).await;
    let own = OwnChanges {
        retirements,
        retries: retried.clone().unwrap_or_default(),
    };
    if let Ok(r) = &retried {
        apply_retries(&mut inv, r);
    }
    // Stop the runtime gracefully (it removes its endpoints and advertisement); the
    // fence ends with it.
    let stopped = stop_runtime(ctx, client).await;
    let mut purged = false;
    let mut refused_purge = false;
    // ⟨§17.27 item 2; §17.31 item 1 (W5-C01)⟩ The last check, only after a confirmed
    // stop and under the runtime's own instance lock ([`purge_locked`]): the
    // outstanding obligations are still exactly the confirmed ones (work admitted
    // before the fence and still running could have moved them), and no runtime can
    // start and write between that read and the deletion; or nothing is deleted.
    let mut changed = None;
    let mut unavailable = None;
    let mut stuck: Option<(&'static str, Vec<PathBuf>)> = None;
    let mut bundle_now = None;
    if purge && retried.is_err() {
        unavailable = Some(RETRY_NOT_MADE);
    } else if purge {
        // ⟨§17.32 item 1; audit A3⟩ What this uninstall's own retirement runs were
        // observed to do: the only change it made to the records.
        match purge_after_stop(
            stopped,
            complete && absent,
            (&paths.state_dir, &paths.runtime_dir, trusted_top.as_deref()),
            (&confirmed, &own),
            args,
            LOCK_WAIT,
            || {},
        )
        .await
        {
            PurgeEnd::Purged(Ok(())) => {
                purged = true;
                left = remaining(ctx, &dirs, purged);
            }
            PurgeEnd::Purged(Err(e)) => stuck = Some((QUARANTINE_PARTIAL, e.stuck)),
            PurgeEnd::Stuck(paths) => stuck = Some((QUARANTINE_STUCK, paths)),
            PurgeEnd::Incomplete => refused_purge = true,
            PurgeEnd::Changed(now) => changed = Some(now),
            PurgeEnd::Bundle(out) => bundle_now = Some(out),
            PurgeEnd::Unavailable(message) => unavailable = Some(message),
        }
    }
    if !complete {
        left.push(RemainingArtifact {
            kind: RemainingArtifactKind::RecoveryRecord,
            path_display: shown(&db, &home()),
        });
    }
    let mut out = report(
        complete && !refused_purge,
        stopped,
        purged,
        rollback,
        left,
        quarantine,
    );
    with_retries(&mut out, &retried);
    if purge {
        with_swept(&mut out, &paths.state_dir, &paths.runtime_dir);
    }
    if let Some(now) = changed {
        return inventory_changed(Some(out), &now, EffectStatus::Partial);
    }
    if let Some((message, paths)) = stuck {
        // ⟨§17.34 item 1; audit C1⟩ These are left at quarantine names (a refusal whose
        // rename-back failed, or a deletion that failed part-way).
        let home = home();
        let shown: Vec<String> = paths
            .iter()
            .map(|p| heimdall_localenv::paths::display_path(&home, p))
            .collect();
        let mut refused = not_purged(out, message);
        if let serde_json::Value::Object(map) = &mut refused.env.data {
            map.insert("left_in_quarantine".to_owned(), serde_json::json!(shown));
        }
        refused.human.push_str(&format!(
            "Left in quarantine (rename each back to the name after its `.hm-purge-<hex>-` prefix):\n{}",
            shown.iter().map(|p| format!("    {p}\n")).collect::<String>()
        ));
        return annotate(refused, &inv, bundle.as_deref());
    }
    if let Some(message) = unavailable {
        return annotate(not_purged(out, message), &inv, bundle.as_deref());
    }
    if let Some(refused) = bundle_now {
        return annotate(after_stop(out, refused), &inv, bundle.as_deref());
    }
    if refused_purge {
        let message = if complete {
            "--purge-state refused: a projection resource is not confirmed absent yet; nothing was purged"
        } else {
            "--purge-state refused: the rollback is incomplete; the state store, the recovery records, the backups and every conflict file are kept"
        };
        out = refuse(out, message);
    } else if !complete {
        out = refuse(
            out,
            "uninstall is incomplete: the rollback did not finish; the state store, the recovery records, the backups and every conflict file are kept",
        );
    }
    annotate(out, &inv, bundle.as_deref())
}

/// ⟨ADR-0008 §17.27 item 2 (W5-S01)⟩ After the owner's confirmation and before any
/// destructive step: close admission of new enrollment, CA and issuance work
/// (`UninstallFence::Acquire`, held by this session until it ends), re-read the
/// inventory and, for a purge, repeat the guard and the bundle check against the state
/// about to be destroyed. An inventory other than the confirmed one is
/// `uninstall_inventory_changed` (exit 4); any refusal lifts the fence first. Nothing
/// is deleted on any `Err`. A plain uninstall whose first read failed (`known`
/// false) has no confirmed inventory to compare, and keeps the state anyway.
async fn fence_and_revalidate<S: crate::cli::Session>(
    s: &mut S,
    db: &Path,
    confirmed: &Inventory,
    known: bool,
    args: &UninstallArgs,
) -> Result<(), Outcome> {
    let held = s
        .request(Request::UninstallFence(UninstallFenceRequest::Acquire))
        .await;
    if !held.code.is_success() {
        return Err(Outcome::of(held));
    }
    let refuse = async |s: &mut S, out: Outcome| {
        let _ = s
            .request(Request::UninstallFence(UninstallFenceRequest::Release))
            .await;
        Err(out)
    };
    if !known && !args.purge_state {
        return Ok(());
    }
    let now = match Inventory::read(db) {
        Ok(now) => now,
        Err(why) => return refuse(s, unreadable(why)).await,
    };
    if !confirmed.same_as(&now) {
        return refuse(s, inventory_changed(None, &now, EffectStatus::None)).await;
    }
    // ⟨ADR-0008 §17.28 item 1⟩ a dispatched step without its result (or an uncertain
    // mutation): its remote effect is unknown, so nothing is purged.
    if args.purge_state && !now.unresolved_steps.is_empty() {
        return refuse(s, step_unresolved(&now)).await;
    }
    if args.purge_state
        && let Err(refused) = enrollment_refusal(&now, args, db)
    {
        return refuse(s, annotate(refused, &now, None)).await;
    }
    Ok(())
}

/// `uninstall_remote_step_unresolved` (`CAPABILITY_UNAVAILABLE`, exit 4; ADR-0008
/// §17.28 item 1): under the fence, an enrollment operation still has a dispatched step
/// without its result (its remote effect is unknown); listed, nothing deleted.
fn step_unresolved(now: &Inventory) -> Outcome {
    let ops: Vec<&str> = now.unresolved_steps.iter().map(|o| o.as_str()).collect();
    let mut env = output::error_value(
        heimdall_app::OpError::new(
            Code::CapabilityUnavailable,
            format!(
                "--purge-state refused: enrollment operation(s) {} have a remote step dispatched without its result, so its remote effect is unknown; nothing was changed. Let the step finish (or reconcile the operation), then run `heimdall uninstall` again",
                ops.join(", ")
            ),
        )
        .with_reason(reason::UNINSTALL_REMOTE_STEP_UNRESOLVED)
        .with_effect(EffectStatus::None)
        .into_envelope(),
    );
    if let serde_json::Value::Object(map) = &mut env.data {
        now.insert_listing(map);
        map.insert(
            "next_command".to_owned(),
            serde_json::Value::String("heimdall uninstall".to_owned()),
        );
    }
    let human = format!(
        "{OBLIGATIONS}:\n{}Remote steps without a result: {}\nRun `heimdall uninstall` again once they are resolved.\n",
        obligation_lines(now),
        ops.join(", ")
    );
    Outcome::of(env).with_human(human)
}

/// `uninstall_inventory_changed` (`CAPABILITY_UNAVAILABLE`, exit 4; ADR-0008 §17.27
/// item 2): the outstanding obligations differ from the ones the owner confirmed.
/// Lists them as they are `now`; `base` (a later check's report) is kept under the
/// error; `effect` says what already happened (`none` before any destructive step).
fn inventory_changed(base: Option<Outcome>, now: &Inventory, effect: EffectStatus) -> Outcome {
    let done = if effect == EffectStatus::None {
        "nothing was changed"
    } else {
        "the state database, the backups and every recovery record are kept (nothing was purged)"
    };
    let mut env = output::error_value(
        heimdall_app::OpError::new(
            Code::CapabilityUnavailable,
            format!(
                "uninstall refused: the outstanding remote obligations changed since you confirmed them (an enrollment, removal or CA changed meanwhile); {done}. Run `heimdall uninstall` again to review them as they are now"
            ),
        )
        .with_reason(reason::UNINSTALL_INVENTORY_CHANGED)
        .with_effect(effect)
        .into_envelope(),
    );
    let mut human = String::new();
    if let Some(b) = base {
        if let (serde_json::Value::Object(map), serde_json::Value::Object(data)) =
            (&mut env.data, b.env.data)
        {
            for (k, v) in data {
                map.entry(k).or_insert(v);
            }
        }
        human = b.human;
    }
    if let serde_json::Value::Object(map) = &mut env.data {
        now.insert_listing(map);
        map.insert(
            "next_command".to_owned(),
            serde_json::Value::String("heimdall uninstall".to_owned()),
        );
    }
    human.push_str(&format!(
        "{OBLIGATIONS}, as they are now:\n{}Run `heimdall uninstall` again.\n",
        obligation_lines(now)
    ));
    Outcome::of(env).with_human(human)
}

/// `CONFIG_CONFLICT`, effect `partial`, keeping `out`'s data under the error.
fn refuse(out: Outcome, message: &str) -> Outcome {
    let mut env = output::error_value(
        heimdall_app::OpError::new(Code::ConfigConflict, message.to_owned())
            .with_effect(EffectStatus::Partial)
            .into_envelope(),
    );
    if let (serde_json::Value::Object(map), serde_json::Value::Object(data)) =
        (&mut env.data, out.env.data.clone())
    {
        for (k, v) in data {
            map.insert(k, v);
        }
    }
    Outcome::of(env).with_human(out.human)
}

fn report(
    _complete: bool,
    stopped: bool,
    purged: bool,
    rollback: Option<serde_json::Value>,
    left: Vec<RemainingArtifact>,
    quarantine: Vec<serde_json::Value>,
) -> Outcome {
    let mut human = String::new();
    if let Some(r) = &rollback {
        human.push_str(&output::render_setup_result(r));
    }
    human.push_str(&format!(
        "Runtime stopped: {stopped}\nState purged: {purged}\n"
    ));
    if !left.is_empty() {
        human.push_str("Remaining:\n");
        for r in &left {
            human.push_str(&format!(
                "    {} {}\n",
                serde_json::to_value(r.kind)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default(),
                r.path_display
            ));
        }
    }
    let env = Envelope::ok(serde_json::json!({
        "rollback": rollback,
        "runtime_stopped": stopped,
        "purged": purged,
        "remaining": left,
        "quarantine": quarantine,
    }));
    Outcome::of(env).with_human(human)
}

/// `Request::Shutdown` on uninstall's own session (it negotiated `service-control/1`
/// and holds the uninstall fence until the runtime closes it), then wait (bounded)
/// until the advertisement is gone.
/// `false` unless the stop is confirmed: a refused or failed request, or a connection
/// lost before its answer (a `SERVICE_UNAVAILABLE` transport failure), is not a stop.
async fn stop_runtime<S: crate::cli::Session>(ctx: &Ctx, mut c: S) -> bool {
    let env = c.request(Request::Shutdown(ShutdownRequest {})).await;
    drop(c);
    if env.code != Code::Ok {
        return false;
    }
    let Ok(paths) = ctx.paths() else {
        return false;
    };
    // The endpoints close before the runtime removes its advertisement (instance.json),
    // so "no live instance" alone can be seen while the process is still finishing. A
    // graceful stop is the advertisement gone; an instance that stopped being live but
    // left its advertisement (it died) counts as stopped only once the wait is over.
    let deadline = Instant::now() + STOP_WAIT;
    let mut not_live = false;
    while Instant::now() < deadline {
        let dir = &paths.runtime_dir;
        if matches!(
            heimdall_runtime::instance::InstanceInfo::read_file(dir),
            Ok(None)
        ) {
            return true;
        }
        not_live = matches!(
            heimdall_runtime::instance::InstanceInfo::read_valid(dir),
            Ok(None)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    not_live
}

/// How the purge's last step ended ([`purge_after_stop`]).
enum PurgeEnd {
    /// The rollback is incomplete or a projection resource is not confirmed absent:
    /// not attempted (the existing `CONFIG_CONFLICT` refusals).
    Incomplete,
    /// ⟨ADR-0008 §17.31 item 1 (W5-C01)⟩ Refused, nothing deleted: the runtime's stop
    /// was not confirmed, or its instance lock could not be taken
    /// (`SERVICE_UNAVAILABLE`, [`not_purged`]; the message).
    Unavailable(&'static str),
    /// Refused under the lock, nothing deleted: the outstanding obligations are not
    /// the confirmed ones (or could not be read: listed as none).
    Changed(Inventory),
    /// Refused under the lock, nothing deleted: the bundle no longer passes its check.
    Bundle(Outcome),
    /// Every check passed under the lock; the deletion's own result (⟨audit C1⟩ on a
    /// failure part-way, the entries left at quarantine names).
    Purged(Result<(), crate::purge_sweep::QuarantineError>),
    /// ⟨ADR-0008 §17.34 item 1⟩ Refused, nothing deleted, but these entries could not be
    /// renamed back from quarantine (their exact paths).
    Stuck(Vec<PathBuf>),
}

/// The stop was not confirmed (the request was refused or failed, the connection was
/// lost before its answer, or the runtime was still live at the end of the wait).
const NOT_STOPPED: &str = "--purge-state refused: the runtime did not confirm its shutdown (the shutdown request failed or its connection was lost), so it could still be writing; nothing was purged: the state database, the backups and every recovery record are kept. Stop the runtime (`heimdall service stop`) or wait for it to stop, then run `heimdall uninstall` again";

/// Another process (a replacement runtime) holds the instance lock.
const LOCK_HELD: &str = "--purge-state refused: a runtime started again while uninstall was running and holds this installation's instance lock, so it could be writing; nothing was purged: the state database, the backups and every recovery record are kept. Stop the runtime (`heimdall service stop`) or wait for it to stop, then run `heimdall uninstall` again";

/// The instance lock could not be taken (I/O).
const LOCK_FAILED: &str = "--purge-state refused: this installation's instance lock could not be taken, so a runtime could start and write; nothing was purged: the state database, the backups and every recovery record are kept. Run `heimdall uninstall --purge-state` again";

/// How long the purge waits for the runtime's instance lock after the confirmed stop:
/// a stopping runtime removes its advertisement before it releases the lock, so the
/// lock can still be held briefly; a lock still held at the end is a replacement.
const LOCK_WAIT: Duration = Duration::from_secs(10);

/// ⟨ADR-0008 §17.31 item 1 (W5-C01)⟩ The purge's last step. Not attempted while the
/// rollback is incomplete (`ready` false); refused, deleting nothing, unless the
/// runtime's stop was confirmed (`stopped`); otherwise [`purge_locked`].
async fn purge_after_stop(
    stopped: bool,
    ready: bool,
    dirs: (&Path, &Path, Option<&Path>),
    (confirmed, own): (&Inventory, &OwnChanges),
    args: &UninstallArgs,
    wait: Duration,
    paused: impl FnOnce(),
) -> PurgeEnd {
    if !ready {
        return PurgeEnd::Incomplete;
    }
    if !stopped {
        return PurgeEnd::Unavailable(NOT_STOPPED);
    }
    purge_locked(dirs, confirmed, own, args, wait, paused).await
}

/// ⟨ADR-0008 §17.31 item 1 (W5-C01)⟩ Under the runtime's own exclusive instance lock
/// (`<state>/service.lock`, [`heimdall_runtime::InstanceLock`], the lock runtime
/// start-up takes before it opens the store): the final inventory read, compared in
/// full with the confirmed one but for this uninstall's `own` retirements
/// ([`Inventory::unchanged_but_for`], §17.32 item 1), and the bundle's re-check, then
/// the deletion, then the release. While it is held no
/// runtime can start (start-up fails `AlreadyRunning` before it touches the state
/// database), so nothing can be written between the final read and the deletion; a
/// replacement runtime already holding it refuses the purge, deleting nothing.
///
/// The bundle is re-checked against the `confirmed` inventory (the file read again,
/// its digest looked up again in the database about to be deleted): this uninstall's
/// own retirements legitimately changed the CAs since.
///
/// The lock file itself is never deleted, and the lock is released only after the
/// deletion: unlinking a held lock file would let a start-up create a fresh file at
/// the same path and lock that one while this process still held the old one. After
/// the release a start-up finds no state database and begins a new installation.
///
/// `paused` runs between the final read and the deletion, with the lock held: tests
/// schedule a competing start-up there; the command passes a no-op (no test variable
/// reaches it).
async fn purge_locked(
    (state_dir, runtime_dir, top): (&Path, &Path, Option<&Path>),
    confirmed: &Inventory,
    own: &OwnChanges,
    args: &UninstallArgs,
    wait: Duration,
    paused: impl FnOnce(),
) -> PurgeEnd {
    use heimdall_runtime::service::STATE_DB_FILE;
    // ⟨§17.33 item 10 (audit B3)⟩ One anchored `<state>` (and `<run>`) for the lock, the
    // final read, the bundle check and the deletion.
    let Ok(anchors) = crate::purge_sweep::Anchors::open(state_dir, runtime_dir, top) else {
        return PurgeEnd::Unavailable(ROOTS_REFUSED);
    };
    let lock = match anchored_lock(&anchors, wait).await {
        Ok(lock) => lock,
        Err(why) => return PurgeEnd::Unavailable(why),
    };
    if anchors.verify(STATE_DB_FILE).is_err() {
        return PurgeEnd::Unavailable(ROOTS_REFUSED);
    }
    // ⟨§17.34 item 1 (W5-F01, F02)⟩ Quarantine every entry the purge removes (renamed to
    // random names in its anchored directory, each checked against its inspection), then
    // read and check the **quarantined** database, then delete only the quarantine names.
    let q = match anchors.quarantine(STATE_DB_FILE, || {}) {
        Ok(q) => q,
        Err(e) if !e.stuck.is_empty() => return PurgeEnd::Stuck(e.stuck),
        Err(_) => return PurgeEnd::Unavailable(SWEEP_REFUSED),
    };
    let back = |q: crate::purge_sweep::Quarantine<'_>, end: PurgeEnd| match q.restore() {
        Ok(()) => end,
        Err(stuck) => PurgeEnd::Stuck(stuck),
    };
    // ⟨audit C0⟩ One store, bound to the quarantined database (its `-wal` and `-shm`
    // held), for the final read and the bundle check; the read is confirmed to have
    // used exactly the held files before the store is dropped.
    #[cfg(test)]
    tests::final_read_hook(false);
    let read = q.read_db(
        |path| {
            let opened = Store::open_read_only(path, Arc::new(NoFaults));
            #[cfg(test)]
            tests::final_read_hook(true);
            opened
        },
        |store| final_checks(store, confirmed, own, args),
    );
    match read {
        Ok(None) => return back(q, PurgeEnd::Changed(Inventory::default())),
        Ok(Some((Some(end), _))) => return back(q, end),
        Ok(Some((None, Ok(())))) => {}
        Ok(Some((None, Err(_)))) | Err(_) => {
            return back(q, PurgeEnd::Unavailable(ROOTS_REFUSED));
        }
    }
    paused();
    // The roots still named, every quarantined entry still what was inspected: then
    // only the quarantine names are removed.
    if anchors.verify(STATE_DB_FILE).is_err() || q.validate().is_err() {
        return back(q, PurgeEnd::Unavailable(ROOTS_REFUSED));
    }
    let deleted = q.delete();
    drop(lock);
    PurgeEnd::Purged(deleted)
}

/// The final read's checks on the quarantined database: `None` when they pass, else the
/// refusal (an unreadable database is listed as holding no obligations).
fn final_checks(
    store: &Result<Store, StoreError>,
    confirmed: &Inventory,
    own: &OwnChanges,
    args: &UninstallArgs,
) -> Option<PurgeEnd> {
    let Ok(store) = store else {
        return Some(PurgeEnd::Changed(Inventory::default()));
    };
    match Inventory::read_store(store) {
        Ok(now) if confirmed.unchanged_but_for(&now, own) => {}
        Ok(now) => return Some(PurgeEnd::Changed(now)),
        Err(_) => return Some(PurgeEnd::Changed(Inventory::default())),
    }
    let recorded = |sha: &str| {
        store
            .transaction(|tx| tx.bundle_digest_recorded_at(sha))
            .map_err(|_| ())
    };
    enrollment_refusal_with(confirmed, args, &recorded)
        .err()
        .map(PurgeEnd::Bundle)
}

/// ⟨ADR-0008 §17.33 item 11 (audit B6)⟩ Name the directories the purge swept (human and
/// JSON `purge_roots`): it sweeps this CLI's resolved `<state>` and `<run>`, so files a
/// runtime left under another runtime directory (another `XDG_RUNTIME_DIR`) stay, and
/// the owner can find them.
fn with_swept(out: &mut Outcome, state_dir: &Path, runtime_dir: &Path) {
    let home = home();
    let (state, run) = (shown(state_dir, &home), shown(runtime_dir, &home));
    if let serde_json::Value::Object(map) = &mut out.env.data {
        map.insert(
            "purge_roots".to_owned(),
            serde_json::json!({ "state_dir": state, "runtime_dir": run }),
        );
    }
    out.human.push_str(&format!(
        "Purge roots: state {state}, runtime {run} (files a runtime left under another runtime directory are not swept)\n"
    ));
}

/// ⟨ADR-0008 §17.34 item 1⟩ The purge refused and some entries could not be renamed back
/// from quarantine (listed with the refusal).
const QUARANTINE_STUCK: &str = "--purge-state refused: an entry changed between its inspection and its deletion, so nothing was deleted; some entries could not be renamed back from their quarantine names and are listed below. Rename each back, then run `heimdall uninstall --purge-state` again";

/// ⟨audit C1⟩ The deletion failed part-way: what was not yet deleted (the state database
/// among it) was renamed back, and what could not be is listed.
const QUARANTINE_PARTIAL: &str = "--purge-state stopped part-way: a deletion failed, so the entries not yet deleted (the state database among them, deleted last) were renamed back to their names; any entry listed below is left at its quarantine name. Rename each back, or remove it, then run `heimdall uninstall --purge-state` again";

/// ⟨ADR-0008 §17.33 item 10⟩ The anchored roots could not be established or changed.
const ROOTS_REFUSED: &str = "--purge-state refused: the state or runtime directory, or one of its parent directories, is a link, is not this user's, or was replaced while uninstall was running; nothing was purged: the state database, the backups and every recovery record are kept. Run `heimdall uninstall --purge-state` again";

/// ⟨ADR-0008 §17.33 items 4, 10⟩ The sweep refused (a link or reparse point, a database
/// file that is not a regular file) or failed.
const SWEEP_REFUSED: &str = "--purge-state refused: the deletion met a link, a reparse point or an unexpected file inside the state or runtime directory and stopped; it never follows one. Remove it, then run `heimdall uninstall --purge-state` again";

/// Take `service.lock` through the anchored `<state>`, waiting at most `wait` while
/// another process holds it ([`LOCK_WAIT`]).
async fn anchored_lock(
    anchors: &crate::purge_sweep::Anchors,
    wait: Duration,
) -> Result<crate::purge_sweep::LockGuard, &'static str> {
    let deadline = Instant::now() + wait;
    loop {
        match anchors.try_lock() {
            Ok(Some(lock)) => return Ok(lock),
            Ok(None) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(None) => return Err(LOCK_HELD),
            Err(_) => return Err(LOCK_FAILED),
        }
    }
}

/// Take the runtime's instance lock for `state_dir` by path, waiting at most `wait` while
/// another process holds it (tests: whether the purge released it).
#[cfg(test)]
async fn instance_lock(
    state_dir: &Path,
    wait: Duration,
) -> Result<heimdall_runtime::InstanceLock, &'static str> {
    use heimdall_runtime::instance::InstanceError;
    let deadline = Instant::now() + wait;
    loop {
        match heimdall_runtime::InstanceLock::try_acquire(state_dir) {
            Ok(lock) => return Ok(lock),
            Err(InstanceError::AlreadyRunning) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(InstanceError::AlreadyRunning) => return Err(LOCK_HELD),
            Err(InstanceError::Io(_)) => return Err(LOCK_FAILED),
        }
    }
}

/// `SERVICE_UNAVAILABLE` (exit 5, retryable; no reason), effect `partial` (the
/// rollback and the stop happened; nothing was purged), keeping `out`'s report under
/// the error, with `heimdall uninstall --purge-state` as the next command.
fn not_purged(out: Outcome, message: &str) -> Outcome {
    // ⟨ADR-0008 §17.31 item 6⟩ an unconfirmed stop and a replacement runtime holding the
    // instance lock share the reason and the next step (the owner does the same thing);
    // the message says which case it was. A lock I/O failure stays reasonless.
    let unconfirmed_stop = message == NOT_STOPPED || message == LOCK_HELD;
    let mut error = heimdall_app::OpError::new(Code::ServiceUnavailable, message.to_owned())
        .with_effect(EffectStatus::Partial);
    if unconfirmed_stop {
        error = error.with_reason(reason::UNINSTALL_SHUTDOWN_UNCONFIRMED);
    }
    let refused =
        Outcome::of(output::error_value(error.into_envelope())).with_human(format!("{message}\n"));
    let mut refused = after_stop(out, refused);
    if let serde_json::Value::Object(map) = &mut refused.env.data {
        let (command, step) = if unconfirmed_stop {
            ("heimdall service stop", Some(SHUTDOWN_UNCONFIRMED_NEXT))
        } else {
            ("heimdall uninstall --purge-state", None)
        };
        map.insert(
            "next_command".to_owned(),
            serde_json::Value::String(command.to_owned()),
        );
        if let Some(step) = step {
            map.insert(
                "next_step".to_owned(),
                serde_json::Value::String(step.to_owned()),
            );
        }
    }
    refused
}

/// ⟨ADR-0008 §17.31 item 6⟩ The next step of `uninstall_shutdown_unconfirmed`.
const SHUTDOWN_UNCONFIRMED_NEXT: &str = "stop the runtime (`heimdall service stop`) or wait for it to stop, then run `heimdall uninstall` again";

/// A refusal raised after the stop: its effect is `partial` (the rollback and the stop
/// happened; nothing was purged), with `out`'s report (and human text) kept under it.
fn after_stop(out: Outcome, mut refused: Outcome) -> Outcome {
    if let serde_json::Value::Object(map) = &mut refused.env.data {
        if let Some(serde_json::Value::Object(error)) = map.get_mut("error") {
            error.insert(
                "effect_status".to_owned(),
                serde_json::to_value(EffectStatus::Partial).unwrap_or(serde_json::Value::Null),
            );
        }
        if let serde_json::Value::Object(data) = out.env.data {
            for (k, v) in data {
                map.entry(k).or_insert(v);
            }
        }
    }
    let human = std::mem::take(&mut refused.human);
    refused.with_human(format!("{}{human}", out.human))
}

/// ⟨ADR-0008 §17.32 item 7⟩ The directory of the environment's pair slots under the
/// state directory (`heimdall_localenv::projection::content::managed_slot_paths`:
/// `<state>/managed/<destination>/{key.pub,cert.pub}`).
#[cfg(test)]
const SLOT_DIR: &str = "managed";

/// ⟨ADR-0008 §17.32 item 7⟩ The binding endpoints' directory under the runtime
/// directory (`heimdall_credential::endpoints::BINDING_DIR`:
/// `<run>/b/<tag>/{agent.sock,key.pub,cert-*.pub,.generation}`).
#[cfg(test)]
const BINDING_DIR: &str = "b";

#[cfg(test)]
mod tests {
    use super::*;

    type FinalReadHook = Option<Box<dyn FnMut(bool)>>;

    thread_local! {
        static FINAL_READ_HOOK: std::cell::RefCell<FinalReadHook> =
            const { std::cell::RefCell::new(None) };
    }

    /// Called just before (`false`) and after (`true`) the purge's final read.
    pub(super) fn final_read_hook(after: bool) {
        FINAL_READ_HOOK.with(|h| {
            if let Some(f) = h.borrow_mut().as_mut() {
                f(after);
            }
        });
    }

    /// Scripted answers; an exhausted script is end of input.
    struct Script {
        answers: Vec<Answer>,
        shown: Vec<String>,
    }

    impl Prompter for Script {
        async fn ask(&mut self, text: &str) -> Answer {
            self.shown.push(text.to_owned());
            if self.answers.is_empty() {
                Answer::Eof
            } else {
                self.answers.remove(0)
            }
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| unreachable!())
            .block_on(f)
    }

    fn ctx(stdin_tty: bool, non_interactive: bool) -> Ctx {
        Ctx {
            json: true,
            non_interactive,
            home: None,
            stdin_tty,
        }
    }

    fn discard() -> Discard {
        Discard {
            database: "~/state/state.db".to_owned(),
            bytes: 4096,
            counts: Ok(TableCounts {
                operations: 7,
                grants: 2,
                decisions: 1,
                identities: 3,
                destinations: 4,
                profiles: 5,
                events: 11,
                idempotency: 6,
            }),
            backups: vec!["~/state/backups/ssh_config.20260101T000000Z.orig".to_owned()],
            kept: vec!["~/.ssh/config.hm-conflict-1".to_owned()],
            kept_remote: None,
            store_items: String::new(),
            remote_revocations: String::new(),
        }
    }

    /// ADR-0007 §12.31 item 1: only a typed yes confirms. Every other outcome of the
    /// prompt (no, end of input, an interruption, the timeout, unreadable input) is
    /// exit 3 `INTERACTION_REQUIRED` raised by this client: no `decision_ref`, effect
    /// `none`, and the message says everything is kept.
    #[test]
    fn purge_is_confirmed_only_by_a_typed_yes() {
        let attended = ctx(true, false);
        let mut yes = Script {
            answers: vec![Answer::Yes],
            shown: Vec::new(),
        };
        assert!(block_on(confirm_purge(&attended, &mut yes, discard)).is_ok());
        assert_eq!(yes.shown.len(), 1);
        for answer in [
            Answer::No,
            Answer::Eof,
            Answer::Interrupted,
            Answer::TimedOut,
            Answer::Unreadable,
        ] {
            let mut p = Script {
                answers: vec![answer],
                shown: Vec::new(),
            };
            let Err(out) = block_on(confirm_purge(&attended, &mut p, discard)) else {
                panic!("{answer:?} confirmed a purge");
            };
            assert_eq!(out.exit, ExitCode::InteractionRequired, "{answer:?}");
            assert_eq!(out.env.code, Code::InteractionRequired, "{answer:?}");
            assert!(
                out.env
                    .next
                    .as_ref()
                    .is_none_or(|n| n.decision_ref.is_none()),
                "{answer:?}: client-side, no decision_ref"
            );
            assert_eq!(out.env.data["error"]["effect_status"], "none", "{answer:?}");
            let message = out.env.data["error"]["message"]
                .as_str()
                .unwrap_or_default();
            assert!(
                message.contains("nothing was changed") && message.contains(answer.reason()),
                "{answer:?}: {message}"
            );
        }
    }

    /// A non-TTY stdin and `--non-interactive` (which is no stand-in for the typed
    /// answer here) refuse without reading the state or asking anything.
    #[test]
    fn purge_without_a_terminal_or_with_non_interactive_is_refused_unread_and_unasked() {
        for (tty, ni, why) in [
            (false, false, "stdin is not a terminal"),
            (true, true, "--non-interactive"),
            (false, true, "--non-interactive"),
        ] {
            let mut p = Script {
                answers: vec![Answer::Yes],
                shown: Vec::new(),
            };
            let read = std::cell::Cell::new(false);
            let result = block_on(confirm_purge(&ctx(tty, ni), &mut p, || {
                read.set(true);
                discard()
            }));
            let Err(out) = result else {
                panic!("tty={tty} ni={ni}: a purge was confirmed");
            };
            assert_eq!(out.exit, ExitCode::InteractionRequired);
            assert!(p.shown.is_empty(), "nothing is asked");
            assert!(!read.get(), "nothing is read");
            let message = out.env.data["error"]["message"]
                .as_str()
                .unwrap_or_default();
            assert!(message.contains(why), "{message}");
        }
    }

    /// The prompt lists everything the purge discards: the database with its size and
    /// every count, each backup, and the conflict and quarantine copies it leaves.
    #[test]
    fn the_purge_prompt_lists_the_database_counts_backups_and_kept_copies() {
        let text = discard().text();
        for needle in [
            "~/state/state.db (4096 bytes)",
            "operations: 7 (all states)",
            "grants: 2 (all states)",
            "decisions: 1 (all states)",
            "3 identities, 4 destinations, 5 profiles",
            "events: 11",
            "idempotency records: 6",
            "Backups of your original files (1):",
            "~/state/backups/ssh_config.20260101T000000Z.orig",
            "kept (a purge removes none",
            "~/.ssh/config.hm-conflict-1",
            "standing policies, the tombstones",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        let mut bare = discard();
        bare.backups.clear();
        bare.kept.clear();
        bare.counts = Err("the records could not be read");
        let text = bare.text();
        assert!(
            text.contains("Backups of your original files: none"),
            "{text}"
        );
        assert!(
            text.contains("Conflict and quarantine copies: none"),
            "{text}"
        );
        assert!(
            text.contains(
                "operations, grants, decisions, catalog records, events and idempotency records: not counted (the records could not be read); they are discarded with it"
            ),
            "{text}"
        );
    }

    /// The counts come from the store read-only: a fresh store counts nothing, a
    /// missing or foreign file is reported by class without opening a writer.
    #[test]
    fn counts_are_read_from_the_store_without_writing() {
        let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let db = d.path().join("state.db");
        assert!(read_counts(&db).is_err(), "a missing file is not created");
        assert!(!db.exists());
        drop(Store::open(&db, Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}")));
        let before = std::fs::read(&db).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(read_counts(&db), Ok(TableCounts::default()));
        assert_eq!(
            std::fs::read(&db).unwrap_or_else(|e| panic!("{e}")),
            before,
            "the read changed nothing"
        );
        std::fs::write(&db, b"not a database, not even close").unwrap_or_else(|e| panic!("{e}"));
        assert!(read_counts(&db).is_err());
    }

    #[test]
    fn resources_are_absent_only_when_desired_and_observed_absent() {
        let r =
            |d: &str, o: &str| serde_json::json!({"projections": [{"desired": d, "observed": o}]});
        assert!(resources_absent(&r("absent", "absent")));
        assert!(!resources_absent(&r("absent", "present")));
        assert!(!resources_absent(&r("absent", "unknown")));
        assert!(resources_absent(&serde_json::json!({"projections": []})));
    }

    #[test]
    fn an_empty_record_is_not_installed() {
        assert!(!installed(&serde_json::json!({"record": null})));
        assert!(!installed(
            &serde_json::json!({"record": {"items": {"ssh": {"files": [], "aliases": []}}}})
        ));
        assert!(installed(
            &serde_json::json!({"record": {"items": {"ssh": {"files": [{}], "aliases": []}}}})
        ));
    }

    #[test]
    fn quarantine_listing_removes_empty_dirs_and_lists_kept_entries() {
        let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let empty = d.path().join("a");
        let kept = d.path().join("b");
        std::fs::create_dir_all(empty.join(".hm-quarantine")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir_all(kept.join(".hm-quarantine")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(kept.join(".hm-quarantine/managed_ssh-4-0011"), b"x")
            .unwrap_or_else(|e| panic!("{e}"));
        let listed = quarantine_listing(&[empty.clone(), kept.clone()], true);
        assert!(
            !empty.join(".hm-quarantine").exists(),
            "rmdir of the empty one"
        );
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["entries"][0]["reason"], "modified_after_exchange");
        assert!(
            listed[0]["entries"][0]["from"]
                .as_str()
                .unwrap_or("")
                .ends_with("ssh_config")
        );
    }

    /// A record of enrollment `n` in `state`, changed at `t0 + n` seconds.
    fn record(n: u8, state: heimdall_contract::enrollment::EnrollmentState) -> EnrollmentRecord {
        use heimdall_contract::ids::{AccountName, DestinationId, EnrollmentId, IdentityId};
        use heimdall_domain::enrollment::{
            ApprovedHostKey, ApprovedTarget, EnrollmentForm, ExistingAccessRecord, NoProxy,
            RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
        };
        let id = EnrollmentId::from_random_bytes([n; 16]);
        let account = AccountName::parse("deploy").unwrap_or_else(|e| panic!("{e}"));
        let at = t0()
            .checked_add(Duration::from_secs(u64::from(n)))
            .unwrap_or_else(|_| panic!("time"));
        EnrollmentRecord {
            marker: marker_for(&id),
            id,
            destination: DestinationId::parse(&format!("dst-lab{n}"))
                .unwrap_or_else(|e| panic!("{e}")),
            account: account.clone(),
            ca_fingerprint: ca(),
            form: EnrollmentForm::Account,
            registry: RegistryRef {
                path_display: "~/.ssh/authorized_keys".into(),
                resolved_by: RegistryResolvedBy::RemoteHome,
            },
            registry_canonical: RegistryCanonical {
                path: None,
                resolved_by: RegistryResolvedBy::RemoteHome,
            },
            line_sha256: "ab".repeat(32),
            target: ApprovedTarget {
                hostname: "example.invalid".into(),
                port: 22,
                user: account,
                proxy: NoProxy::None,
                host_key: ApprovedHostKey {
                    algorithm: "ssh-ed25519".into(),
                    key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                    fingerprint: "SHA256:hostfixture".into(),
                },
            },
            existing_access: ExistingAccessRecord {
                identity: IdentityId::from_random_bytes([n; 16]),
                endpoint: None,
                public_key_file: None,
            },
            hold: None,
            removal_origin: None,
            late_write: None,
            state,
            verified_at: None,
            evidence: None,
            created_at: at,
            updated_at: at,
        }
    }

    fn t0() -> Timestamp {
        "2026-11-01T00:00:00Z"
            .parse()
            .unwrap_or_else(|_| panic!("timestamp"))
    }

    fn ca() -> CaFingerprint {
        CaFingerprint::parse(&format!("SHA256:{}", "A".repeat(43)))
            .unwrap_or_else(|e| panic!("{e}"))
    }

    fn inventory(open: Vec<EnrollmentRecord>) -> Inventory {
        Inventory {
            last_change: open.iter().map(|r| r.updated_at).max(),
            cas: vec![(ca(), CaState::Active)],
            open,
            ..Inventory::default()
        }
    }

    /// A bundle created at `at`, listing `records` (each in its state).
    fn bundle(at: Timestamp, records: &[EnrollmentRecord], redacted: bool) -> Vec<u8> {
        bundle_with(at, records, &[], redacted)
    }

    /// [`bundle`] with `foreign` removals too (each by its descriptor and state).
    fn bundle_with(
        at: Timestamp,
        records: &[EnrollmentRecord],
        foreign: &[ForeignRemovalRecord],
        redacted: bool,
    ) -> Vec<u8> {
        let foreign_removals: Vec<serde_json::Value> = foreign
            .iter()
            .map(|f| {
                serde_json::json!({
                    "marker": f.target.marker,
                    "local_alias": f.target.local_alias,
                    "bundle_destination_id": f.target.bundle_destination_id,
                    "hostname": f.target.bundle_hostname,
                    "port": f.target.bundle_port,
                    "account": f.target.account.as_str(),
                    "ca_public_key": f.target.ca_public_key,
                    "line_sha256": f.target.line_sha256,
                    "registry": f.target.registry,
                    "form": f.target.form,
                    "state": f.state.as_str(),
                })
            })
            .collect();
        let enrollments: Vec<serde_json::Value> = records
            .iter()
            .map(|r| {
                let mut v = serde_json::json!({
                    "marker": r.marker,
                    "destination_id": r.destination.as_str(),
                    "alias": "lab",
                    "account": "deploy",
                    "registry": {"resolved_by": "remote_home"},
                    "registry_path_display": "~/.ssh/authorized_keys",
                    "form": "account",
                    "state": r.state.as_str(),
                    "ca_fingerprint": r.ca_fingerprint.as_str(),
                    "ca_public_key": "ssh-ed25519 AAAA",
                    "line_sha256": r.line_sha256,
                });
                if let (Some(l), serde_json::Value::Object(map)) = (&r.late_write, &mut v) {
                    map.insert(
                        "late_write".to_owned(),
                        serde_json::json!({ "not_after_remote": l.not_after_remote }),
                    );
                }
                v
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "schema": RECOVERY_BUNDLE_SCHEMA,
            "created_at": at,
            "redacted": redacted,
            "cas": [{
                "fingerprint": ca().as_str(),
                "public_key": "ssh-ed25519 AAAA",
                "backup_sha256": "00".repeat(32),
                "backup_created_at": t0(),
                "state": "active",
            }],
            "enrollments": enrollments,
            "foreign_removals": foreign_removals,
            "instructions": [],
        }))
        .unwrap_or_default()
    }

    /// §17.25 item 8: a bundle is fresh only when its content is (written at or after
    /// the last change, every CA and remaining enrollment in its state, unredacted) and
    /// its SHA-256 is one this installation recorded. A stale, partial, other-state or
    /// redacted one is refused whatever the record; an unrecorded or unreadable record
    /// refuses a fresh one.
    #[test]
    fn a_bundle_is_fresh_only_with_fresh_content_and_a_recorded_digest() {
        use heimdall_contract::enrollment::EnrollmentState as S;
        let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let live = record(1, S::Verified);
        let other = record(2, S::AppliedUnverified);
        let inv = inventory(vec![live.clone(), other.clone()]);
        let late = t0()
            .checked_add(Duration::from_secs(10))
            .unwrap_or_else(|_| panic!("time"));
        let write = |name: &str, bytes: Vec<u8>| {
            let p = d.path().join(name);
            std::fs::write(&p, &bytes).unwrap_or_else(|e| panic!("{e}"));
            (p, heimdall_issuer::backup::sha256_hex(&bytes))
        };
        let any = |_: &str| Ok(Some(t0()));
        let none = |_: &str| Ok(None);
        let broken = |_: &str| Err(());
        let (fresh, digest) = write("fresh", bundle(late, &[live.clone(), other.clone()], false));
        let exact = |sha: &str| Ok((sha == digest).then(t0));
        assert_eq!(check_bundle(&inv, &fresh, &exact), Ok(()));
        for (record, why) in [
            (
                &none as DigestRecord<'_>,
                "recorded no bundle with that SHA-256",
            ),
            (&broken, "cannot be read"),
        ] {
            let Err((w, r)) = check_bundle(&inv, &fresh, record) else {
                panic!("an unrecorded digest was accepted");
            };
            assert_eq!(r, reason::BUNDLE_REQUIRED);
            assert!(w.contains(why), "{w}");
        }
        // The same content with one byte changed is another file: not recorded.
        let mut edited = std::fs::read(&fresh).unwrap_or_else(|e| panic!("{e}"));
        edited.push(b'\n');
        let (edited, _) = write("edited", edited);
        assert!(
            check_bundle(&inv, &edited, &exact).is_err_and(|(_, r)| r == reason::BUNDLE_REQUIRED)
        );
        let (at_change, _) = write(
            "at",
            bundle(other.updated_at, &[live.clone(), other.clone()], false),
        );
        assert_eq!(check_bundle(&inv, &at_change, &any), Ok(()));
        let (stale, _) = write(
            "stale",
            bundle(live.updated_at, &[live.clone(), other.clone()], false),
        );
        assert!(
            check_bundle(&inv, &stale, &any)
                .is_err_and(|(w, r)| { r == reason::BUNDLE_REQUIRED && w.contains("predates") })
        );
        let (partial, _) = write("partial", bundle(late, std::slice::from_ref(&live), false));
        assert!(
            check_bundle(&inv, &partial, &any).is_err_and(|(_, r)| r == reason::BUNDLE_REQUIRED)
        );
        let mut moved = other.clone();
        moved.state = S::Removing;
        let (wrong, _) = write("wrong", bundle(late, &[live.clone(), moved], false));
        assert!(check_bundle(&inv, &wrong, &any).is_err_and(|(_, r)| r == reason::BUNDLE_REQUIRED));
        // A CA whose state changed since (no time of its own): partial.
        let mut retiring = inventory(vec![live.clone(), other.clone()]);
        retiring.cas = vec![(ca(), CaState::Retiring)];
        assert!(
            check_bundle(&retiring, &fresh, &any)
                .is_err_and(|(w, r)| { r == reason::BUNDLE_REQUIRED && w.contains("every CA") })
        );
        let (redacted, _) = write("redacted", bundle(late, &[live, other], true));
        assert!(
            check_bundle(&inv, &redacted, &any).is_err_and(|(_, r)| r == reason::BUNDLE_REDACTED)
        );
        let big = d.path().join("big");
        let f = std::fs::File::create(&big).unwrap_or_else(|e| panic!("{e}"));
        f.set_len(BUNDLE_MAX + 1).unwrap_or_else(|e| panic!("{e}"));
        assert!(check_bundle(&inv, &big, &any).is_err_and(|(w, _)| w.contains("cannot be read")));
    }

    /// D4 item 6: a plain uninstall with enrollments that are not final goes on only
    /// after a typed yes; the prompt lists each marker and offers `enroll remove`.
    /// Every other answer, a non-TTY stdin and `--non-interactive` refuse (exit 3, no
    /// `decision_ref`), listing them.
    #[test]
    fn a_plain_uninstall_with_live_enrollments_needs_a_typed_yes() {
        use heimdall_contract::enrollment::EnrollmentState as S;
        let live = record(1, S::Verified);
        let inv = inventory(vec![live.clone()]);
        let mut yes = Script {
            answers: vec![Answer::Yes],
            shown: Vec::new(),
        };
        assert!(block_on(confirm_plain(&ctx(true, false), &mut yes, &inv, false)).is_ok());
        assert!(yes.shown[0].contains(&live.marker), "{}", yes.shown[0]);
        assert!(yes.shown[0].contains(ENROLL_REMOVE), "{}", yes.shown[0]);
        for (c, answers) in [
            (ctx(true, false), vec![Answer::No]),
            (ctx(true, false), vec![Answer::Eof]),
            (ctx(true, false), vec![Answer::Interrupted]),
            (ctx(true, false), vec![Answer::TimedOut]),
            (ctx(false, false), vec![Answer::Yes]),
            (ctx(true, true), vec![Answer::Yes]),
        ] {
            let mut p = Script {
                answers,
                shown: Vec::new(),
            };
            let Err(out) = block_on(confirm_plain(&c, &mut p, &inv, false)) else {
                panic!("acknowledged without a typed yes");
            };
            assert_eq!(out.exit, ExitCode::InteractionRequired);
            assert!(
                out.env
                    .next
                    .as_ref()
                    .is_none_or(|n| n.decision_ref.is_none())
            );
            assert_eq!(
                out.env.data["enrollments"][0]["marker"],
                live.marker.as_str()
            );
            assert!(out.human.contains(&live.marker));
            assert!(
                out.env.data["error"]["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("--keep-remote-enrollments")),
                "the scripted acknowledgement is named"
            );
        }
        // §17.25 item 11: `--keep-remote-enrollments` is the explicit acknowledgement,
        // with no terminal and under `--non-interactive`; nothing is asked.
        for c in [ctx(false, false), ctx(true, true), ctx(false, true)] {
            let mut p = Script {
                answers: Vec::new(),
                shown: Vec::new(),
            };
            assert!(block_on(confirm_plain(&c, &mut p, &inv, true)).is_ok());
            assert!(p.shown.is_empty(), "nothing is asked");
        }
    }

    /// D4 item 6: the store item's fate lines name the item and the reason, or the
    /// deletion command with the backup reminder.
    #[test]
    fn store_item_lines_name_the_item_and_the_fate() {
        let item = |fate, locator: Option<&str>| StoreItem {
            ca: ca(),
            state: CaState::Active,
            store_kind: StoreKind::MacosLoginKeychain,
            locator: locator.map(str::to_owned),
            backup_created_at: t0(),
            fate,
            retire: None,
        };
        let kept = item_line(&item(
            Fate::KeptLive(vec!["heimdall:enr_x".into()]),
            Some("L1"),
        ));
        assert!(
            kept.starts_with("kept: the macos_login_keychain item L1 of CA SHA256:"),
            "{kept}"
        );
        assert!(
            kept.contains("heimdall:enr_x") && kept.contains("not final"),
            "{kept}"
        );
        let offered = item_line(&item(Fate::DeletionOffered, Some("L1")));
        assert!(
            offered.contains("heimdall issuer retire SHA256:"),
            "{offered}"
        );
        assert!(offered.contains("destroy the offline backup"), "{offered}");
        let unrecorded = item_line(&item(Fate::KeptUnrecorded, None));
        assert!(unrecorded.contains("locator not recorded"), "{unrecorded}");
        let retired = item_line(&item(Fate::Retired, Some("L1")));
        assert!(
            retired.starts_with("deleted: the macos_login_keychain item L1"),
            "{retired}"
        );
        assert!(retired.contains("destroy the offline backup"), "{retired}");
    }

    /// A session that records what it is sent and refuses everything.
    #[derive(Default)]
    struct Recorder {
        sent: Vec<String>,
    }

    impl crate::cli::Session for Recorder {
        async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
            self.sent.push(request.kind().to_owned());
            crate::setup_cmd::failure(Code::ServiceUnavailable, "fixture: refused", None)
        }
        async fn attend(&mut self) -> Envelope<serde_json::Value> {
            self.sent.push("attend".to_owned());
            crate::setup_cmd::failure(Code::ServiceUnavailable, "fixture: refused", None)
        }
    }

    /// ADR-0008 §17.25 item 9: an offered item is retired inline through the one retire
    /// entry on an interactive terminal (here the entry's first step, `Attend`, is sent
    /// and refused, so the item stays offered with the entry's own stop); without a
    /// terminal or under `--non-interactive`, nothing is sent and the item stays offered
    /// with the reason. Kept items are never touched.
    #[test]
    fn offered_store_items_are_retired_inline_only_on_a_terminal() {
        let item = |fate| StoreItem {
            ca: ca(),
            state: CaState::Active,
            store_kind: StoreKind::MacosLoginKeychain,
            locator: Some("L1".to_owned()),
            backup_created_at: t0(),
            fate,
            retire: None,
        };
        let inv = || Inventory {
            items: vec![
                item(Fate::DeletionOffered),
                item(Fate::KeptLive(vec!["heimdall:enr_x".into()])),
            ],
            ..Inventory::default()
        };
        for (c, why) in [
            (ctx(false, false), "stdin is not a terminal"),
            (ctx(true, true), "--non-interactive"),
        ] {
            let mut s = Recorder::default();
            let mut p = Script {
                answers: vec![Answer::Yes],
                shown: Vec::new(),
            };
            let mut inv = inv();
            block_on(retire_offered(&mut s, &mut p, &c, &mut inv));
            assert!(s.sent.is_empty(), "nothing is sent: {:?}", s.sent);
            assert!(p.shown.is_empty());
            assert!(
                matches!(&inv.items[0].retire, Some(RetireRun::NotRun(w)) if w.contains(why)),
                "{:?}",
                inv.items[0]
            );
            assert_eq!(inv.items[0].fate, Fate::DeletionOffered);
            assert!(inv.items[1].retire.is_none());
            let json = inv.store_items_json();
            assert_eq!(json[0]["retire"]["ran"], false);
            assert_eq!(
                json[0]["command"],
                format!("heimdall issuer retire {}", ca().as_str())
            );
        }
        let mut s = Recorder::default();
        let mut p = Script {
            answers: vec![Answer::Yes],
            shown: Vec::new(),
        };
        let mut inv = inv();
        let own = block_on(retire_offered(&mut s, &mut p, &ctx(true, false), &mut inv));
        // ⟨audit A3⟩ The run is observed before and after (`issuer.status`); both
        // unreadable here, so no own change is recorded.
        assert_eq!(
            s.sent,
            vec![
                "issuer.status".to_owned(),
                "attend".to_owned(),
                "issuer.status".to_owned()
            ],
            "the entry ran inline, observed before and after"
        );
        assert!(own.is_empty());
        let Some(RetireRun::Stopped { code, message, .. }) = &inv.items[0].retire else {
            panic!("{:?}", inv.items[0]);
        };
        assert_eq!(*code, Code::ServiceUnavailable);
        assert!(message.contains("fixture: refused"), "{message}");
        assert_eq!(inv.items[0].fate, Fate::DeletionOffered);
        assert!(inv.items[1].retire.is_none(), "a kept item is not retired");
        assert_eq!(inv.store_items_json()[0]["retire"]["ran"], true);
    }

    /// A foreign system-form removal `n`, `planned` (its public descriptor only).
    fn foreign(n: u8) -> ForeignRemovalRecord {
        use heimdall_contract::enrollment::{
            EnrollmentForm, EnrollmentState, ForeignRemovalTarget, RegistryCanonical,
        };
        use heimdall_contract::ids::{AccountName, ForeignRemovalId, OperationId};
        use heimdall_domain::enrollment::RegistryResolvedBy;
        ForeignRemovalRecord {
            id: ForeignRemovalId::from_random_bytes([n; 16]),
            target: ForeignRemovalTarget {
                local_alias: format!("lab{n}"),
                bundle_destination_id: format!("dst-other{n}"),
                bundle_hostname: "example.invalid".into(),
                bundle_port: 22,
                account: AccountName::parse("deploy").unwrap_or_else(|e| panic!("{e}")),
                marker: format!("heimdall:enr_{}", "f".repeat(32)),
                ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIforeign".into(),
                line_sha256: "cd".repeat(32),
                registry: RegistryCanonical {
                    path: None,
                    resolved_by: RegistryResolvedBy::RemoteHome,
                },
                form: EnrollmentForm::System,
            },
            state: EnrollmentState::Planned,
            operation: OperationId::from_random_bytes([n; 16]),
            created_at: t0(),
            removal_origin: None,
        }
    }

    /// A fresh state database in `d` with `seed` applied.
    fn database(
        d: &Path,
        seed: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<()>,
    ) -> PathBuf {
        let db = d.join("state.db");
        let store = Store::open(&db, Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store.transaction(seed).unwrap_or_else(|e| panic!("{e}"));
        db
    }

    /// A purge with no acknowledgement and no bundle.
    fn plain_purge() -> UninstallArgs {
        UninstallArgs {
            keep_remote_enrollments: false,
            purge_state: true,
            bundle: None,
        }
    }

    /// `uninstall_purge_refuses_abandoned_foreign_system_form_removal` (ADR-0008 §17.27
    /// item 1, W5-R01, the reviewer's probe): a foreign system-form removal moved to
    /// `manual_removal_pending` and then abandoned (still `pending_until_line_removed`)
    /// is read by the real inventory and refuses a purge without the acknowledgement
    /// (`CONFIG_CONFLICT`) or without a bundle (`bundle_required`), listed by its
    /// descriptor.
    #[test]
    fn uninstall_purge_refuses_abandoned_foreign_system_form_removal() {
        use heimdall_contract::enrollment::EnrollmentState as S;
        use heimdall_domain::enrollment::EnrollmentEventKind as K;
        let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let f = foreign(4);
        let db = database(d.path(), |tx| {
            tx.insert_foreign_removal(&f)?;
            let mut r = tx
                .transition_foreign_removal(S::Planned, K::ManualRemovalConfirmed, &f)?
                .unwrap_or_else(|e| panic!("{e:?}"));
            r = tx
                .transition_foreign_removal(r.state, K::OwnerAbandon, &r)?
                .unwrap_or_else(|e| panic!("{e:?}"));
            assert_eq!(r.state, S::Abandoned);
            Ok(())
        });
        let inv = Inventory::read(&db).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(inv.foreign.len(), 1, "{inv:?}");
        assert!(!inv.clear());
        let Err(out) = enrollment_refusal(&inv, &plain_purge(), &db) else {
            panic!("an abandoned foreign removal let a purge through");
        };
        assert_eq!(out.env.code, Code::ConfigConflict);
        assert_eq!(
            out.env.data["foreign_removals"][0]["marker"],
            f.target.marker.as_str()
        );
        assert_eq!(out.env.data["foreign_removals"][0]["state"], "abandoned");
        assert!(
            out.human.contains("pending_until_line_removed"),
            "{}",
            out.human
        );
        let keep = UninstallArgs {
            keep_remote_enrollments: true,
            ..plain_purge()
        };
        let Err(out) = enrollment_refusal(&inv, &keep, &db) else {
            panic!("no bundle was needed");
        };
        assert_eq!(out.env.data["error"]["reason"], reason::BUNDLE_REQUIRED);
    }

    /// `uninstall_purge_refuses_withdrawn_late_write` (ADR-0008 §17.27 item 1, W5-R02,
    /// the reviewer's probe): a `withdrawn` record (final) whose `late_write` residual
    /// is unresolved, with a remote not-after still ahead and one already passed with no
    /// absence observed since, is outstanding: listed with its residual and refusing a
    /// purge without acknowledgement or bundle. A final record without it is not.
    #[test]
    fn uninstall_purge_refuses_withdrawn_late_write() {
        use heimdall_contract::enrollment::EnrollmentState as S;
        use heimdall_domain::enrollment::LateWrite;
        let now = Timestamp::now().as_second();
        for not_after in [now + 3600, now - 3600] {
            let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
            let mut late = record(1, S::Withdrawn);
            late.late_write = Some(LateWrite {
                step_token: "ab".repeat(16),
                not_after_remote: not_after,
            });
            let quiet = record(2, S::Withdrawn);
            let db = database(d.path(), |tx| {
                tx.insert_issuer(&issuer())?;
                tx.seed_enrollment(&late)?;
                tx.seed_enrollment(&quiet)
            });
            let inv = Inventory::read(&db).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(
                inv.open.iter().map(|r| &r.marker).collect::<Vec<_>>(),
                vec![&late.marker],
                "only the unresolved residual is outstanding"
            );
            let Err(out) = enrollment_refusal(&inv, &plain_purge(), &db) else {
                panic!("a withdrawn record with a late write let a purge through");
            };
            assert_eq!(out.env.code, Code::ConfigConflict);
            assert_eq!(
                out.env.data["enrollments"][0]["late_write"]["not_after_remote"],
                not_after
            );
            assert!(out.human.contains("late_write"), "{}", out.human);
        }
    }

    fn issuer() -> heimdall_store::IssuerRecord {
        heimdall_store::IssuerRecord {
            ca_fingerprint: ca(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture0".into(),
            state: CaState::Active,
            store_kind: StoreKind::LinuxSecretService,
            backup_sha256: "00".repeat(32),
            backup_created_at: t0(),
            restored_without_log: false,
            created_at: t0(),
            retired_at: None,
        }
    }

    /// ADR-0008 §17.27 item 1: the bundle's content check covers the outstanding
    /// foreign removals (descriptor and state) and each unresolved late write.
    #[test]
    fn a_bundle_lists_outstanding_foreign_removals_and_late_writes() {
        use heimdall_contract::enrollment::EnrollmentState as S;
        use heimdall_domain::enrollment::LateWrite;
        let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let mut late = record(1, S::Withdrawn);
        late.late_write = Some(LateWrite {
            step_token: "ab".repeat(16),
            not_after_remote: 1_900_000_000,
        });
        let mut abandoned = foreign(3);
        abandoned.state = S::Abandoned;
        let mut inv = inventory(vec![late.clone()]);
        inv.foreign = vec![abandoned.clone()];
        let at = t0()
            .checked_add(Duration::from_secs(60))
            .unwrap_or_else(|_| panic!("time"));
        let any = |_: &str| Ok(Some(t0()));
        let write = |name: &str, bytes: Vec<u8>| {
            let p = d.path().join(name);
            std::fs::write(&p, &bytes).unwrap_or_else(|e| panic!("{e}"));
            p
        };
        let full = write(
            "full",
            bundle_with(
                at,
                std::slice::from_ref(&late),
                std::slice::from_ref(&abandoned),
                false,
            ),
        );
        assert_eq!(check_bundle(&inv, &full, &any), Ok(()));
        let no_foreign = write("nf", bundle(at, std::slice::from_ref(&late), false));
        assert!(
            check_bundle(&inv, &no_foreign, &any)
                .is_err_and(|(w, r)| r == reason::BUNDLE_REQUIRED && w.contains("foreign removal"))
        );
        let mut planned = abandoned.clone();
        planned.state = S::Planned;
        let other_state = write(
            "os",
            bundle_with(at, std::slice::from_ref(&late), &[planned], false),
        );
        assert!(check_bundle(&inv, &other_state, &any).is_err());
        let mut quiet = late.clone();
        quiet.late_write = None;
        let no_late = write("nl", bundle_with(at, &[quiet], &[abandoned], false));
        assert!(
            check_bundle(&inv, &no_late, &any)
                .is_err_and(|(w, _)| w.contains("every remaining enrollment"))
        );
    }

    /// A session answering the fence's requests (`acquire`: `acquired`), recording
    /// every request kind it is sent.
    struct FenceSession {
        acquired: Envelope<serde_json::Value>,
        sent: Vec<String>,
        /// Run once, between the fence's acquisition and the inventory's re-read.
        between: Option<Box<dyn FnOnce()>>,
    }

    impl crate::cli::Session for FenceSession {
        async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
            self.sent.push(request.kind().to_owned());
            match request {
                Request::UninstallFence(UninstallFenceRequest::Acquire) => {
                    if let Some(f) = self.between.take() {
                        f();
                    }
                    self.acquired.clone()
                }
                _ => Envelope::ok(serde_json::json!({ "fence": "released" })),
            }
        }
        async fn attend(&mut self) -> Envelope<serde_json::Value> {
            Envelope::ok(serde_json::json!({}))
        }
    }

    /// `uninstall_revalidates_under_the_fence` (ADR-0008 §17.27 item 2, W5-S01): after
    /// the confirmation the fence is acquired first; an inventory that changed since
    /// (here an enrollment admitted while the owner was reading the prompt) is
    /// `uninstall_inventory_changed` (`CAPABILITY_UNAVAILABLE`, exit 4, effect `none`,
    /// listing it as it is now, naming `heimdall uninstall`), and the fence is released.
    /// An unchanged inventory goes on with the fence held; a refused acquisition stops
    /// with nothing else sent.
    #[test]
    fn uninstall_revalidates_under_the_fence() {
        use heimdall_contract::enrollment::EnrollmentState as S;
        let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let db = database(d.path(), |tx| tx.insert_issuer(&issuer()));
        let confirmed = Inventory::read(&db).unwrap_or_else(|e| panic!("{e}"));
        assert!(confirmed.clear());
        let ok = || Envelope::ok(serde_json::json!({ "fence": "held" }));
        // Unchanged: on, fence held (no release sent).
        let mut s = FenceSession {
            acquired: ok(),
            sent: Vec::new(),
            between: None,
        };
        assert!(
            block_on(fence_and_revalidate(
                &mut s,
                &db,
                &confirmed,
                true,
                &plain_purge()
            ))
            .is_ok()
        );
        assert_eq!(s.sent, vec!["uninstall_fence.acquire".to_owned()]);
        // An enrollment admitted after the confirmation: refused, released.
        let admitted = record(5, S::Planned);
        let db2 = db.clone();
        let r2 = admitted.clone();
        let mut s = FenceSession {
            acquired: ok(),
            sent: Vec::new(),
            between: Some(Box::new(move || {
                let store = Store::open(&db2, Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
                store
                    .transaction(|tx| tx.seed_enrollment(&r2))
                    .unwrap_or_else(|e| panic!("{e}"));
            })),
        };
        let Err(out) = block_on(fence_and_revalidate(
            &mut s,
            &db,
            &confirmed,
            true,
            &plain_purge(),
        )) else {
            panic!("a changed inventory was not refused");
        };
        assert_eq!(out.exit, ExitCode::Denied, "exit 4");
        assert_eq!(out.env.code, Code::CapabilityUnavailable);
        assert_eq!(
            out.env.data["error"]["reason"],
            reason::UNINSTALL_INVENTORY_CHANGED
        );
        assert_eq!(out.env.data["error"]["effect_status"], "none");
        assert_eq!(
            out.env.data["enrollments"][0]["marker"],
            admitted.marker.as_str()
        );
        assert_eq!(out.env.data["next_command"], "heimdall uninstall");
        assert_eq!(
            s.sent,
            vec![
                "uninstall_fence.acquire".to_owned(),
                "uninstall_fence.release".to_owned()
            ],
            "the fence is lifted after the refusal"
        );
        // A refused acquisition (another uninstall holds it): nothing else is sent.
        let mut s = FenceSession {
            acquired: crate::setup_cmd::failure(
                Code::ServiceUnavailable,
                "another uninstall holds the fence",
                Some(reason::UNINSTALL_IN_PROGRESS),
            ),
            sent: Vec::new(),
            between: None,
        };
        let Err(out) = block_on(fence_and_revalidate(
            &mut s,
            &db,
            &confirmed,
            true,
            &plain_purge(),
        )) else {
            panic!("a refused fence went on");
        };
        assert_eq!(out.env.code, Code::ServiceUnavailable);
        assert_eq!(s.sent, vec!["uninstall_fence.acquire".to_owned()]);
    }

    // --- ADR-0008 §17.31 item 1 (W5-C01): the purge holds the runtime's instance lock ---

    /// A disposable state directory (owner-only, whatever the umask) with a fresh state
    /// database holding one CA, and the inventory the owner confirmed.
    fn state_dir() -> (tempfile::TempDir, PathBuf, Inventory) {
        let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        let state = d.path().join("state");
        std::fs::create_dir(&state).unwrap_or_else(|e| panic!("{e}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        // The runtime directory beside it, owner-only as `Paths::ensure` makes it.
        let run = d.path().join("run");
        std::fs::create_dir(&run).unwrap_or_else(|e| panic!("{e}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        let db = database(&state, |tx| tx.insert_issuer(&issuer()));
        std::fs::create_dir(state.join("backups")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(state.join("backups").join("ssh_config.orig"), b"Host x\n")
            .unwrap_or_else(|e| panic!("{e}"));
        let confirmed = Inventory::read(&db).unwrap_or_else(|e| panic!("{e}"));
        assert!(confirmed.clear());
        (d, state, confirmed)
    }

    fn db_of(state: &Path) -> PathBuf {
        state.join(heimdall_runtime::service::STATE_DB_FILE)
    }

    /// The runtime directory beside a test's state directory.
    fn run_of(state: &Path) -> PathBuf {
        state.parent().unwrap_or(state).join("run")
    }

    /// The purge's last step after a confirmed stop, with a bounded lock wait.
    fn purge_now(
        state: &Path,
        confirmed: &Inventory,
        wait: Duration,
        paused: impl FnOnce(),
    ) -> PurgeEnd {
        block_on(purge_after_stop(
            true,
            true,
            (state, &run_of(state), state.parent()),
            (confirmed, &OwnChanges::default()),
            &plain_purge(),
            wait,
            paused,
        ))
    }

    fn refused_unavailable(end: &PurgeEnd) -> Option<&'static str> {
        match end {
            PurgeEnd::Unavailable(m) => Some(m),
            _ => None,
        }
    }

    /// A shutdown session answering every request with `answer`, recording each kind.
    struct Stop {
        answer: Envelope<serde_json::Value>,
        sent: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    }

    impl crate::cli::Session for Stop {
        async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
            self.sent.borrow_mut().push(request.kind().to_owned());
            self.answer.clone()
        }
        async fn attend(&mut self) -> Envelope<serde_json::Value> {
            Envelope::ok(serde_json::json!({}))
        }
    }

    /// `uninstall_purge_refuses_unconfirmed_stop` (ADR-0008 §17.31 item 1, W5-C01): a
    /// shutdown whose connection is lost before its answer (the client's transport
    /// failure, `SERVICE_UNAVAILABLE`) or that the runtime refuses is not a confirmed
    /// stop, and the purge after it deletes nothing: `SERVICE_UNAVAILABLE` (exit 5,
    /// retryable, no reason), effect `partial`, the report kept under it, naming
    /// `heimdall uninstall --purge-state`.
    #[test]
    fn uninstall_purge_refuses_unconfirmed_stop() {
        let (_d, state, confirmed) = state_dir();
        let db = db_of(&state);
        let before = std::fs::read(&db).unwrap_or_else(|e| panic!("{e}"));
        for answer in [
            crate::setup_cmd::failure(
                Code::ServiceUnavailable,
                "fixture: the connection was lost",
                None,
            ),
            crate::setup_cmd::failure(Code::CapabilityUnavailable, "fixture: refused", None),
        ] {
            let sent = std::rc::Rc::default();
            let s = Stop {
                answer,
                sent: std::rc::Rc::clone(&sent),
            };
            let stopped = block_on(stop_runtime(&ctx(true, false), s));
            assert_eq!(*sent.borrow(), vec!["shutdown".to_owned()]);
            assert!(!stopped, "an unconfirmed stop counted as stopped");
            let end = block_on(purge_after_stop(
                stopped,
                true,
                (&state, &run_of(&state), state.parent()),
                (&confirmed, &OwnChanges::default()),
                &plain_purge(),
                Duration::from_millis(200),
                || panic!("nothing is read or deleted after an unconfirmed stop"),
            ));
            let Some(message) = refused_unavailable(&end) else {
                panic!("an unconfirmed stop let the purge through");
            };
            assert_eq!(std::fs::read(&db).unwrap_or_else(|e| panic!("{e}")), before);
            assert!(state.join("backups").join("ssh_config.orig").exists());
            let out = not_purged(
                report(true, stopped, false, None, Vec::new(), Vec::new()),
                message,
            );
            assert_eq!(out.exit, ExitCode::Unavailable, "exit 5");
            assert_eq!(out.env.code, Code::ServiceUnavailable);
            let error = &out.env.data["error"];
            assert_eq!(error["retryable"], true, "{error}");
            assert_eq!(
                error["reason"], "uninstall_shutdown_unconfirmed",
                "§17.31 item 6: {error}"
            );
            assert_eq!(out.env.data["next_command"], "heimdall service stop");
            assert_eq!(out.env.data["next_step"], SHUTDOWN_UNCONFIRMED_NEXT);
            assert_eq!(error["effect_status"], "partial", "{error}");
            assert!(
                error["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("the runtime did not confirm its shutdown")
                        && m.contains("nothing was purged")),
                "{error}"
            );
            assert_eq!(out.env.data["runtime_stopped"], false);
            assert_eq!(out.env.data["purged"], false);
        }
    }

    /// The probe's options: a runtime over `root`'s state, run and log directories, with
    /// no projection and no managed wiring (nothing outside `root`, never the account's
    /// SSH files), on a virtual clock.
    fn runtime_paths(root: &Path) -> heimdall_runtime::Paths {
        heimdall_runtime::Paths {
            config_dir: root.join("config"),
            state_dir: root.join("state"),
            runtime_dir: root.join("run"),
            log_dir: root.join("log"),
        }
    }

    fn runtime_options() -> heimdall_runtime::service::ServiceOptions {
        let mut o = heimdall_runtime::service::ServiceOptions::with_clock(
            heimdall_testkit::VirtualClock::at(Timestamp::now()),
            heimdall_testkit::ScriptedTimeSync::new(heimdall_domain::time::SyncStatus::Unknown),
        );
        o.endpoint_prefix = "hmtest-".to_owned();
        o
    }

    /// A real runtime start-up over `root` on its own thread and executor: its result,
    /// the started service dropped (so its lock is released) before it returns.
    fn start_runtime(root: &Path) -> Result<(), String> {
        let paths = runtime_paths(root);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|e| panic!("{e}"));
            rt.block_on(async {
                heimdall_runtime::Service::start_with(
                    paths,
                    heimdall_runtime::Config::default(),
                    runtime_options(),
                    tokio_util::sync::CancellationToken::new(),
                )
                .await
                .map(drop)
                .map_err(|e| format!("{e:?}"))
            })
        })
        .join()
        .unwrap_or_else(|_| panic!("the start-up thread panicked"))
    }

    /// `uninstall_purge_excludes_runtime_start_while_locked` (ADR-0008 §17.31 item 1,
    /// W5-C01): at the point between the purge's final read and its deletion (the lock
    /// held), a real runtime start-up over the same state fails `AlreadyRunning` and
    /// writes nothing (the database is byte-identical); the purge then deletes the
    /// database and the backups, keeps the lock file and releases the lock, so the next
    /// start-up takes it.
    #[test]
    fn uninstall_purge_excludes_runtime_start_while_locked() {
        let (d, state, confirmed) = state_dir();
        let db = db_of(&state);
        let root = d.path().to_path_buf();
        let mut tried = None;
        let end = purge_now(&state, &confirmed, Duration::from_millis(200), || {
            // ⟨§17.34 item 1⟩ The database is in quarantine here; the refused start-up
            // must not create a new one at its name.
            tried = Some(start_runtime(&root));
            assert!(!db.exists(), "the refused start-up wrote nothing");
        });
        let tried = tried.unwrap_or_else(|| panic!("the pause point was not reached"));
        assert!(
            tried.as_ref().is_err_and(|e| e.contains("AlreadyRunning")),
            "a start-up got past the lock the purge holds: {tried:?}"
        );
        assert!(matches!(end, PurgeEnd::Purged(Ok(()))), "the purge ran");
        assert!(!db.exists(), "the database was deleted");
        assert!(!state.join("backups").exists(), "the backups were deleted");
        assert!(state.join("service.lock").exists(), "the lock file is kept");
        assert!(
            block_on(instance_lock(&state, Duration::from_secs(5))).is_ok(),
            "the lock is released after the deletion"
        );
    }

    /// `uninstall_purge_refuses_replacement_runtime` (ADR-0008 §17.31 item 1, W5-C01): a
    /// replacement runtime started after the stop holds the instance lock and writes (a
    /// foreign-removal obligation): the purge waits its bound, then refuses with nothing
    /// deleted (`SERVICE_UNAVAILABLE`), and the replacement's record is kept. A lock held
    /// only briefly (a stopping runtime releasing it after its advertisement) is waited
    /// for, and the purge then runs.
    #[test]
    fn uninstall_purge_refuses_replacement_runtime() {
        let (d, state, confirmed) = state_dir();
        let db = db_of(&state);
        let paths = runtime_paths(d.path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| panic!("{e}"));
        let service = rt
            .block_on(heimdall_runtime::Service::start_with(
                paths,
                heimdall_runtime::Config::default(),
                runtime_options(),
                tokio_util::sync::CancellationToken::new(),
            ))
            .unwrap_or_else(|e| panic!("{e:?}"));
        let f = foreign(6);
        service
            .store()
            .transaction(|tx| tx.insert_foreign_removal(&f))
            .unwrap_or_else(|e| panic!("{e}"));
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {
            panic!("nothing is read or deleted while a replacement holds the lock")
        });
        assert_eq!(
            refused_unavailable(&end),
            Some(LOCK_HELD),
            "a replacement runtime's lock did not refuse the purge"
        );
        // ⟨§17.31 item 6⟩ the shared reason, with a message naming this case.
        let out = not_purged(
            report(true, true, false, None, Vec::new(), Vec::new()),
            LOCK_HELD,
        );
        assert_eq!(out.exit, ExitCode::Unavailable, "exit 5");
        let error = &out.env.data["error"];
        assert_eq!(error["reason"], "uninstall_shutdown_unconfirmed", "{error}");
        assert!(
            error["message"].as_str().is_some_and(|m| m
                .contains("a runtime started again while uninstall was running")
                && !m.contains("did not confirm its shutdown")),
            "{error}"
        );
        assert_eq!(out.env.data["next_command"], "heimdall service stop");
        drop(service);
        drop(rt);
        assert!(db.exists(), "the database was not deleted");
        let now = Inventory::read(&db).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(now.foreign, vec![f], "the replacement's record is kept");
        // A briefly held lock is waited for.
        let (_d2, state2, confirmed2) = state_dir();
        let held =
            heimdall_runtime::InstanceLock::try_acquire(&state2).unwrap_or_else(|e| panic!("{e}"));
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            drop(held);
        });
        let end = purge_now(&state2, &confirmed2, Duration::from_secs(10), || {});
        release
            .join()
            .unwrap_or_else(|_| panic!("the holder thread panicked"));
        assert!(matches!(end, PurgeEnd::Purged(Ok(()))), "the purge waited");
        assert!(!db_of(&state2).exists());
    }

    /// `recheck_purge_must_exclude_writer_after_final_read` (the wave-5 re-check's
    /// scheduled interleaving, W5-C01; ADR-0008 §17.31 item 1): after the stop, a
    /// replacement takes the real `InstanceLock` and writes a foreign-removal obligation
    /// through a fresh `Store`; the purge refuses with nothing deleted. Scheduled at the
    /// point between the purge's final read and its deletion instead, the replacement
    /// cannot take the lock, so it cannot write there.
    #[test]
    fn recheck_purge_must_exclude_writer_after_final_read() {
        let (_d, state, confirmed) = state_dir();
        let db = db_of(&state);
        let replacement =
            heimdall_runtime::InstanceLock::try_acquire(&state).unwrap_or_else(|e| panic!("{e}"));
        let f = foreign(7);
        let store = Store::open(&db, Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store
            .transaction(|tx| tx.insert_foreign_removal(&f))
            .unwrap_or_else(|e| panic!("{e}"));
        drop(store);
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {
            panic!("the purge reached its deletion while a replacement held the lock")
        });
        assert_eq!(refused_unavailable(&end), Some(LOCK_HELD));
        assert!(
            db.exists(),
            "the database was deleted under the replacement"
        );
        let now = Inventory::read(&db).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(now.foreign, vec![f], "the replacement's obligation is kept");
        drop(replacement);
        // The writer scheduled after the final read: excluded.
        let (_d2, state2, confirmed2) = state_dir();
        let mut excluded = None;
        let end = purge_now(&state2, &confirmed2, Duration::from_millis(300), || {
            excluded = Some(matches!(
                heimdall_runtime::InstanceLock::try_acquire(&state2),
                Err(heimdall_runtime::instance::InstanceError::AlreadyRunning)
            ));
        });
        assert_eq!(
            excluded,
            Some(true),
            "a replacement took the lock between the final read and the deletion"
        );
        assert!(matches!(end, PurgeEnd::Purged(Ok(()))));
    }

    // --- ADR-0008 §17.32 item 1 (W5-D01): the final comparison covers every recovery record

    /// A second CA fingerprint (the replacement's).
    fn other_ca() -> CaFingerprint {
        CaFingerprint::parse(&format!("SHA256:{}", "B".repeat(43)))
            .unwrap_or_else(|e| panic!("{e}"))
    }

    fn other_issuer() -> heimdall_store::IssuerRecord {
        heimdall_store::IssuerRecord {
            ca_fingerprint: other_ca(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIreplacement".into(),
            ..issuer()
        }
    }

    /// A replacement runtime's write between the stop and the purge's lock: it takes
    /// the real instance lock, writes through a fresh `Store`, and releases the lock
    /// (it stopped).
    fn replacement_writes(
        state: &Path,
        write: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<()>,
    ) {
        let lock =
            heimdall_runtime::InstanceLock::try_acquire(state).unwrap_or_else(|e| panic!("{e}"));
        let store =
            Store::open(&db_of(state), Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store.transaction(write).unwrap_or_else(|e| panic!("{e}"));
        drop(store);
        drop(lock);
    }

    /// The final read now, compared with `confirmed` but for the `retired` CAs.
    fn unchanged(state: &Path, confirmed: &Inventory, own: &[OwnRetirement]) -> bool {
        let now = Inventory::read(&db_of(state)).unwrap_or_else(|e| panic!("{e}"));
        confirmed.unchanged_but_for(
            &now,
            &OwnChanges {
                retirements: own.to_vec(),
                retries: Vec::new(),
            },
        )
    }

    /// `recheck2_purge_refuses_new_ca_from_replacement_that_already_stopped` (the second
    /// re-check's probe, W5-D01; ADR-0008 §17.32 item 1): after the confirmed stop, a
    /// replacement takes the instance lock, records a new active CA (once without, once
    /// with its exact store locator) and releases the lock; the purge then takes the
    /// lock, finds the CA it was not shown and refuses `uninstall_inventory_changed`,
    /// deleting nothing: the new CA's record is kept.
    #[test]
    fn recheck2_purge_refuses_new_ca_from_replacement_that_already_stopped() {
        for with_locator in [false, true] {
            let (_d, state, confirmed) = state_dir();
            replacement_writes(&state, |tx| {
                tx.insert_issuer(&other_issuer())?;
                if with_locator {
                    tx.set_issuer_store_locator(&other_ca(), "replacement-item")?;
                }
                Ok(())
            });
            let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {
                panic!("the purge reached its deletion over a CA it was not shown")
            });
            let PurgeEnd::Changed(now) = end else {
                panic!("a new CA ({with_locator}) was purged");
            };
            let out = inventory_changed(None, &now, EffectStatus::Partial);
            assert_eq!(out.exit, ExitCode::Denied);
            assert_eq!(
                out.env.data["error"]["reason"],
                reason::UNINSTALL_INVENTORY_CHANGED
            );
            assert!(db_of(&state).exists(), "nothing was deleted");
            assert!(state.join("backups").exists());
            let now = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
            assert!(
                now.cas.iter().any(|(c, _)| *c == other_ca()),
                "the new CA is kept"
            );
        }
    }

    /// `operation_kinds_are_classified_for_the_snapshot` (ADR-0008 §17.32 items 1, 6):
    /// every `OperationKind::ALL` kind is classified exactly once in
    /// [`OPERATION_RECOVERY`], every excluded one with its reason; the included ones are
    /// exactly the enrollment kinds, the store's open-operation read
    /// (`outstanding_obligations` keeps `is_enrollment`).
    #[test]
    fn operation_kinds_are_classified_for_the_snapshot() {
        use heimdall_domain::operation::OperationKind;
        for kind in OperationKind::ALL {
            let entries: Vec<_> = OPERATION_RECOVERY
                .iter()
                .filter(|(k, _)| *k == kind)
                .collect();
            assert_eq!(
                entries.len(),
                1,
                "operation kind `{}` is classified {} times in OPERATION_RECOVERY (exactly once: included, or excluded with its reason)",
                kind.as_str(),
                entries.len()
            );
            let (_, why) = entries[0];
            assert_eq!(
                why.is_none(),
                kind.is_enrollment(),
                "operation kind `{}`: the snapshot includes exactly the enrollment kinds",
                kind.as_str()
            );
            assert!(
                why.is_none_or(|w| !w.is_empty()),
                "a reason for `{}`",
                kind.as_str()
            );
            assert_eq!(operation_in_snapshot(kind), kind.is_enrollment());
        }
        assert_eq!(
            OPERATION_RECOVERY.len(),
            OperationKind::ALL.len(),
            "no stray entry"
        );
    }

    /// `recovery_snapshot_classifies_every_table` (ADR-0008 §17.32 item 1, the rule for
    /// later): every table of a freshly migrated database is classified exactly once in
    /// `heimdall_store::ext_m03::TABLE_RECOVERY` (a migration adding a table fails here
    /// until it is classified), every ignored column exists, and every table classified
    /// `Rows` or `Part` has a case below proving a change to it refuses the purge (a new
    /// `Rows`/`Part` entry without a case fails here too).
    #[test]
    fn recovery_snapshot_classifies_every_table() {
        use heimdall_store::ext_m03::{RECOVERY_IGNORED_COLUMNS, RecoveryClass, TABLE_RECOVERY};
        let (_d, state, _) = state_dir();
        let schema = Store::open_read_only(&db_of(&state), Arc::new(NoFaults))
            .unwrap_or_else(|e| panic!("{e}"))
            .transaction(|tx| tx.schema_tables())
            .unwrap_or_else(|e| panic!("{e}"));
        let mut classified: Vec<String> = TABLE_RECOVERY
            .iter()
            .map(|(n, _)| (*n).to_owned())
            .collect();
        classified.sort();
        let before = classified.len();
        classified.dedup();
        assert_eq!(before, classified.len(), "a table is classified twice");
        assert_eq!(
            schema, classified,
            "every schema table is classified in TABLE_RECOVERY, and only those"
        );
        let store =
            Store::open(&db_of(&state), Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store
            .transaction(|tx| {
                tx.set_pair_preference(&pair_pref(), t0())?;
                Ok(())
            })
            .unwrap_or_else(|e| panic!("{e}"));
        drop(store);
        let rows = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        for (table, column, _) in RECOVERY_IGNORED_COLUMNS {
            let (_, r) = rows
                .snapshot
                .rows
                .iter()
                .find(|(t, _)| t == table)
                .unwrap_or_else(|| panic!("{table} is not a Rows table"));
            assert!(!r.is_empty(), "{table} seeded");
            assert!(
                !r[0].iter().any(|(c, _)| c == column),
                "{table}.{column} is ignored"
            );
        }
        for (table, class) in TABLE_RECOVERY {
            if matches!(class, RecoveryClass::Discarded(_)) {
                continue;
            }
            let cases = cases(table);
            assert!(!cases.is_empty(), "`{table}` has no case");
            for case in cases {
                assert!(
                    case_refuses(case.seed, case.change),
                    "`{table}`: {} did not refuse the purge",
                    case.what
                );
            }
        }
    }

    fn pair_pref() -> heimdall_domain::enrollment::PairPreference {
        use heimdall_contract::ids::{AccountName, DestinationId};
        heimdall_domain::enrollment::PairPreference {
            destination: DestinationId::parse("dst-lab1").unwrap_or_else(|e| panic!("{e}")),
            account: AccountName::parse("deploy").unwrap_or_else(|e| panic!("{e}")),
            mechanism: heimdall_contract::managed::PreferredMechanism::ManagedCertificate,
            projection: heimdall_domain::enrollment::ProjectionStatus::Pending,
            issuing_cas: std::iter::once(ca()).collect(),
        }
    }

    /// A write to the disposable database.
    type Write = Box<dyn FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<()>>;

    /// One change to a recovery-relevant record kind: `seed` before the confirmation,
    /// `change` by a replacement between the stop and the purge's lock.
    struct Case {
        what: &'static str,
        seed: Write,
        change: Write,
    }

    fn case(
        what: &'static str,
        seed: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<()> + 'static,
        change: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<()> + 'static,
    ) -> Case {
        Case {
            what,
            seed: Box::new(seed),
            change: Box::new(change),
        }
    }

    fn nothing(_: &mut heimdall_store::Txn<'_>) -> heimdall_store::Result<()> {
        Ok(())
    }

    /// In a fresh disposable database: `seed`, the confirmation's read, `change` by a
    /// replacement holding the instance lock, then the final check. `true`: refused.
    fn case_refuses(seed: Write, change: Write) -> bool {
        let (_d, state, _) = state_dir();
        let store =
            Store::open(&db_of(&state), Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store.transaction(seed).unwrap_or_else(|e| panic!("{e}"));
        drop(store);
        let confirmed = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        replacement_writes(&state, change);
        !unchanged(&state, &confirmed, &[])
    }

    /// A pending `RegisterIssuer` decision `n` for [`other_ca`], without a store locator.
    fn registration(n: u8, generation: u64) -> heimdall_domain::decision::DecisionRecord {
        use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
        DecisionRecord {
            id: heimdall_contract::ids::DecisionId::from_random_bytes([n; 16]),
            kind: DecisionKind::RegisterIssuer {
                ca_fingerprint: other_ca(),
                store: StoreKind::LinuxSecretService,
                backup_sha256: "11".repeat(32),
                rotation_of: None,
                restored_without_log: false,
                disclosures: Vec::new(),
                ca_public_key: Some(other_issuer().public_key),
                backup_created_at: Some(t0()),
                store_locator: None,
                expected_store_locator: None,
            },
            generation: heimdall_domain::policy::AuthorityGeneration(generation),
            created_at: t0(),
            expires_at: Timestamp::now()
                .checked_add(Duration::from_secs(3600))
                .unwrap_or_else(|_| panic!("time")),
            state: DecisionState::Pending,
            decided_at: None,
        }
    }

    /// The report a ceremony attaches to [`registration`]: the same facts with a locator.
    fn registration_report(locator: &str) -> heimdall_domain::decision::DecisionKind {
        let mut kind = registration(1, 0).kind;
        if let heimdall_domain::decision::DecisionKind::RegisterIssuer { store_locator, .. } =
            &mut kind
        {
            *store_locator = Some(locator.to_owned());
        }
        kind
    }

    /// A running `enrollment.apply` operation `n`.
    fn enrollment_op(n: u8) -> heimdall_domain::operation::OperationRecord {
        use heimdall_domain::operation::{
            EffectClass, OperationKind, OperationRecord, RecoveryMetadata,
        };
        OperationRecord {
            id: heimdall_contract::ids::OperationId::from_random_bytes([n; 16]),
            kind: OperationKind::EnrollmentApply,
            environment: heimdall_contract::ids::EnvironmentId::from_random_bytes([7; 16]),
            key: op_key(n),
            request_hash: heimdall_contract::canonical::RequestHash([n; 32]),
            effect_class: EffectClass::RemoteMutation,
            state: heimdall_contract::OperationState::Running,
            code: None,
            effect_status: EffectStatus::Unknown,
            result: None,
            created_at: t0(),
            updated_at: t0(),
            cancellation: None,
            recovery: RecoveryMetadata::default(),
        }
    }

    fn op_key(n: u8) -> heimdall_domain::idempotency::IdempotencyKey {
        use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
        heimdall_domain::idempotency::IdempotencyKey {
            caller: CallerContext {
                principal: PrincipalRef::UnixUser { uid: 501 },
                role: ClientRole::Owner,
            },
            kind: heimdall_domain::operation::OperationKind::EnrollmentApply,
            request_id: heimdall_contract::ids::RequestId::parse(&format!("p8-seed-{n}"))
                .unwrap_or_else(|e| panic!("{e}")),
        }
    }

    fn insert_op(tx: &mut heimdall_store::Txn<'_>, n: u8) -> heimdall_store::Result<()> {
        let op = enrollment_op(n);
        tx.insert_operation(
            &op,
            &heimdall_domain::idempotency::IdempotencyRecord {
                key: op.key.clone(),
                request_hash: op.request_hash,
                operation_id: op.id.clone(),
                created_at: t0(),
                expires_at: None,
            },
        )
    }

    fn receipt(stage: &str) -> heimdall_domain::operation::StageReceipt {
        heimdall_domain::operation::StageReceipt {
            stage: stage.to_owned(),
            recorded_at: t0(),
            effect: heimdall_domain::operation::EffectReceipt::NotAttempted,
            local: None,
        }
    }

    /// A projection resource of `env`, `desired`/`observed`.
    fn projection(
        env: &heimdall_contract::ids::EnvironmentId,
        desired: heimdall_domain::resource::ResourceState,
        observed: heimdall_domain::resource::ResourceState,
        generation: u64,
    ) -> heimdall_domain::resource::ManagedResource {
        use heimdall_domain::resource::{
            ManagedResource, OwnerRef, ResourceGeneration, ResourceKind,
        };
        ManagedResource {
            id: heimdall_contract::ids::ResourceId::from_random_bytes([5; 16]),
            kind: ResourceKind::ConfigProjection,
            owner: OwnerRef::Projection {
                environment: env.clone(),
            },
            generation: ResourceGeneration(generation),
            desired,
            observed,
            last_operation: None,
            locator: "fixture".to_owned(),
            updated_at: t0(),
        }
    }

    fn env7() -> heimdall_contract::ids::EnvironmentId {
        heimdall_contract::ids::EnvironmentId::from_random_bytes([7; 16])
    }

    /// The insert, modify and delete cases of each `Rows` or `Part` table, through the
    /// database (audit A4). A delete case exists where the store can delete or settle
    /// the record; it has no delete for a CA, an enrollment, a foreign removal, a pair
    /// preference or the environment (none is ever deleted by Heimdall: a replacement
    /// can only insert or modify them). Panics for a table without cases.
    fn cases(table: &str) -> Vec<Case> {
        use heimdall_contract::enrollment::EnrollmentState as S;
        use heimdall_domain::enrollment::EnrollmentEventKind as K;
        use heimdall_domain::issuance::CaEvent;
        use heimdall_domain::resource::ResourceState as R;
        match table {
            "issuers" => vec![
                case("insert a CA", nothing, |tx| {
                    tx.insert_issuer(&other_issuer())
                }),
                case("record a store locator", nothing, |tx| {
                    tx.set_issuer_store_locator(&ca(), "replacement-item")
                }),
                case("move the CA", nothing, |tx| {
                    tx.set_issuer_state(&ca(), CaState::Active, CaEvent::RetireApproved, t0())
                        .map(drop)
                }),
            ],
            "enrollments" => vec![
                case("insert a final enrollment", nothing, |tx| {
                    tx.seed_enrollment(&record(9, S::Withdrawn))
                }),
                case(
                    "move an enrollment",
                    |tx| tx.seed_enrollment(&record(8, S::Planned)),
                    |tx| {
                        tx.transition_enrollment(
                            S::Planned,
                            K::DecisionWithdrawn,
                            &record(8, S::Planned),
                        )
                        .map(drop)
                    },
                ),
            ],
            "foreign_removals" => vec![
                case("insert a foreign removal", nothing, |tx| {
                    tx.insert_foreign_removal(&foreign(9))
                }),
                case(
                    "move a foreign removal",
                    |tx| tx.insert_foreign_removal(&foreign(8)),
                    |tx| {
                        tx.transition_foreign_removal(
                            S::Planned,
                            K::ManualRemovalConfirmed,
                            &foreign(8),
                        )
                        .map(drop)
                    },
                ),
            ],
            "pair_preferences" => vec![
                case("insert a pair", nothing, |tx| {
                    tx.set_pair_preference(&pair_pref(), t0())
                }),
                case(
                    "add to an issuing set",
                    |tx| tx.set_pair_preference(&pair_pref(), t0()),
                    |tx| {
                        let mut p = pair_pref();
                        p.issuing_cas.insert(other_ca());
                        tx.set_pair_preference(&p, t0())
                    },
                ),
            ],
            "decisions" => vec![
                case("insert a pending registration", nothing, |tx| {
                    let g = tx.authority_generation()?.0;
                    tx.insert_decision(&registration(1, g))
                }),
                case(
                    "attach a store locator to a pending registration",
                    |tx| {
                        let g = tx.authority_generation()?.0;
                        tx.insert_decision(&registration(1, g))
                    },
                    |tx| {
                        tx.attach_register_issuer_store_locator(
                            &registration(1, 0).id,
                            &registration_report("replacement-item"),
                        )
                        .map(drop)
                    },
                ),
                case(
                    "settle a pending registration",
                    |tx| {
                        let g = tx.authority_generation()?.0;
                        tx.insert_decision(&registration(1, g))
                    },
                    |tx| {
                        tx.complete_decision(
                            &registration(1, 0).id,
                            heimdall_contract::request::Verdict::Deny,
                            t0(),
                        )
                        .map(drop)
                    },
                ),
            ],
            "operations" => vec![
                case("insert an open enrollment operation", nothing, |tx| {
                    insert_op(tx, 6)
                }),
                case(
                    "change its journal, its state unchanged",
                    |tx| insert_op(tx, 6),
                    |tx| tx.append_stage_receipt(&enrollment_op(6).id, &receipt("enroll.journal")),
                ),
                case(
                    "change its state",
                    |tx| insert_op(tx, 6),
                    |tx| {
                        let mut op = enrollment_op(6);
                        op.state = heimdall_contract::OperationState::OutcomeUnknown;
                        tx.update_operation(&op)
                    },
                ),
                case(
                    "settle it (it leaves the open set)",
                    |tx| insert_op(tx, 6),
                    |tx| {
                        let mut op = enrollment_op(6);
                        op.state = heimdall_contract::OperationState::Failed;
                        tx.update_operation(&op)
                    },
                ),
            ],
            "meta" => vec![
                case("record the environment", nothing, |tx| {
                    tx.init_self_environment(&env7())
                }),
                case("insert a pending remote revocation", nothing, seed_remote),
                case("modify a pending remote revocation", seed_remote, |tx| {
                    let mut r = remote_revocation();
                    r.attempts = 3;
                    tx.set_remote_revocation(&r)
                }),
                case("remove a pending remote revocation", seed_remote, |tx| {
                    tx.clear_remote_revocation(&remote_revocation().root)
                }),
            ],
            "resources" => vec![
                case(
                    "insert a present projection resource",
                    |tx| tx.init_self_environment(&env7()),
                    |tx| tx.upsert_resource(&projection(&env7(), R::Present, R::Present, 1), None),
                ),
                case(
                    "an absent projection resource observed present again",
                    |tx| {
                        tx.init_self_environment(&env7())?;
                        tx.upsert_resource(&projection(&env7(), R::Absent, R::Absent, 1), None)
                    },
                    |tx| {
                        tx.upsert_resource(
                            &projection(&env7(), R::Absent, R::Present, 2),
                            Some(heimdall_domain::resource::ResourceGeneration(1)),
                        )
                    },
                ),
            ],
            other => panic!(
                "`{other}` is classified Rows or Part but has no case here: add its insert, modify and delete cases"
            ),
        }
    }

    /// `decision_kinds_are_classified_for_the_snapshot` (audit A4): every
    /// `DecisionKind` variant (read from the domain source, so a new one is seen) is
    /// named by [`decision_kind_name`] and classified exactly once in
    /// [`DECISION_RECOVERY`], each excluded one with its reason; `RegisterIssuer` is
    /// included.
    #[test]
    fn decision_kinds_are_classified_for_the_snapshot() {
        let src = include_str!("../../domain/src/decision.rs");
        let body = &src[src
            .find("pub enum DecisionKind")
            .unwrap_or_else(|| panic!("no enum"))..];
        let body = &body[..body.find("\n}\n").unwrap_or_else(|| panic!("no end"))];
        let variants: Vec<String> = body
            .lines()
            .filter_map(|l| {
                let t = l.strip_prefix("    ")?;
                let first = t.chars().next()?;
                (first.is_ascii_uppercase() && !t.starts_with("///")).then(|| {
                    t.split([' ', '{', ',', '('])
                        .next()
                        .unwrap_or_default()
                        .to_owned()
                })
            })
            .collect();
        assert_eq!(variants.len(), 11, "{variants:?}");
        let snake = |v: &str| {
            let mut out = String::new();
            for (i, c) in v.chars().enumerate() {
                if c.is_ascii_uppercase() {
                    if i > 0 {
                        out.push('_');
                    }
                    out.push(c.to_ascii_lowercase());
                } else {
                    out.push(c);
                }
            }
            out
        };
        for v in &variants {
            let name = snake(v);
            let entries: Vec<_> = DECISION_RECOVERY
                .iter()
                .filter(|(k, _)| *k == name)
                .collect();
            assert_eq!(
                entries.len(),
                1,
                "decision kind `{name}` is classified {} times in DECISION_RECOVERY (exactly once: included, or excluded with its reason)",
                entries.len()
            );
            assert!(entries[0].1.is_none_or(|w| !w.is_empty()));
        }
        assert_eq!(DECISION_RECOVERY.len(), variants.len(), "no stray entry");
        assert!(decision_in_snapshot(&registration(1, 0).kind));
        assert_eq!(
            decision_kind_name(&registration(1, 0).kind),
            "register_issuer"
        );
    }

    /// `meta_keys_are_classified_for_the_snapshot` (audit A4): every `META_*` key
    /// constant of the store's sources is classified in `META_RECOVERY` (exactly, or by
    /// its prefix), and no store source writes a literal key past them.
    #[test]
    fn meta_keys_are_classified_for_the_snapshot() {
        use heimdall_store::ext_m03::META_RECOVERY;
        let sources = [
            include_str!("../../store/src/lib.rs"),
            include_str!("../../store/src/ext.rs"),
            include_str!("../../store/src/ext_m03.rs"),
        ];
        let mut keys = Vec::new();
        for src in sources {
            // Production code only: the test modules seed literal rows of their own.
            let code = src.split("#[cfg(test)]").next().unwrap_or_default();
            for line in code.lines() {
                let t = line.trim_start();
                if let Some(rest) = t
                    .strip_prefix("const META_")
                    .or_else(|| t.strip_prefix("pub const META_"))
                    && let Some(v) = rest.split('"').nth(1)
                    && rest.contains(": &str")
                {
                    keys.push(v.to_owned());
                }
                assert!(
                    !t.contains("set_meta(\"") && !t.contains(".meta(\""),
                    "a literal meta key: {t}"
                );
            }
        }
        assert!(keys.len() >= 19, "{keys:?}");
        for k in &keys {
            let classified = META_RECOVERY.iter().filter(|(m, _)| m == k).count();
            assert_eq!(
                classified, 1,
                "meta key `{k}` is classified {classified} times in META_RECOVERY"
            );
        }
        assert_eq!(META_RECOVERY.len(), keys.len(), "no stray entry");
    }

    /// `uninstall_purge_refuses_pending_registration_locator` (the audit's
    /// `revp_probe_pending_registration_locator_is_accepted`, A2): a replacement's init
    /// writes a K_ca store item, records its locator on a pending `RegisterIssuer`
    /// decision (the only record of the item) and stops; the purge then refuses
    /// `uninstall_inventory_changed`, deleting nothing.
    #[test]
    fn uninstall_purge_refuses_pending_registration_locator() {
        for attach_to_existing in [false, true] {
            let (_d, state, _) = state_dir();
            if attach_to_existing {
                let store = Store::open(&db_of(&state), Arc::new(NoFaults))
                    .unwrap_or_else(|e| panic!("{e}"));
                store
                    .transaction(|tx| {
                        let g = tx.authority_generation()?.0;
                        tx.insert_decision(&registration(1, g))
                    })
                    .unwrap_or_else(|e| panic!("{e}"));
            }
            let confirmed = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
            replacement_writes(&state, move |tx| {
                if !attach_to_existing {
                    let g = tx.authority_generation()?.0;
                    tx.insert_decision(&registration(1, g))?;
                }
                tx.attach_register_issuer_store_locator(
                    &registration(1, 0).id,
                    &registration_report("replacement-item"),
                )
                .map(drop)
            });
            let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {
                panic!("the purge reached its deletion over a pending registration's store item")
            });
            let PurgeEnd::Changed(now) = end else {
                panic!("a pending registration's store locator was purged ({attach_to_existing})");
            };
            let out = inventory_changed(None, &now, EffectStatus::Partial);
            assert_eq!(
                out.env.data["error"]["reason"],
                reason::UNINSTALL_INVENTORY_CHANGED
            );
            assert!(db_of(&state).exists(), "nothing was deleted");
        }
    }

    /// ⟨Converge⟩ `uninstall_purge_refuses_replaced_store_locator`: a replacement's
    /// restore replaces the recorded store locator (the old one displaced): refused,
    /// even for a CA whose retirement this uninstall ran (its displaced locators may
    /// only shrink, its recorded locator never changes).
    #[test]
    fn uninstall_purge_refuses_replaced_store_locator() {
        let (_d, state, _) = state_dir();
        let store =
            Store::open(&db_of(&state), Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store
            .transaction(|tx| tx.set_issuer_store_locator(&ca(), "item-1"))
            .unwrap_or_else(|e| panic!("{e}"));
        drop(store);
        let confirmed = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        replacement_writes(&state, |tx| {
            tx.replace_issuer_store_locator(&ca(), Some("item-1"), "item-2")
        });
        assert!(!unchanged(&state, &confirmed, &[]));
    }

    /// ⟨Converge⟩ `uninstall_purge_refuses_new_final_enrollment`: an enrollment record
    /// in a final state (no remote obligation, so the earlier obligation-only check let
    /// it through) added by a replacement is a difference.
    #[test]
    fn uninstall_purge_refuses_new_final_enrollment() {
        use heimdall_contract::enrollment::EnrollmentState as S;
        let (_d, state, confirmed) = state_dir();
        replacement_writes(&state, |tx| tx.seed_enrollment(&record(3, S::Withdrawn)));
        let now = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            now.clear(),
            "no obligation: only the full comparison sees it"
        );
        assert!(!confirmed.unchanged_but_for(&now, &OwnChanges::default()));
    }

    /// ⟨Converge⟩ `uninstall_purge_refuses_changed_issuing_set`: a pair's issuing set
    /// gaining a CA is a difference; its projection state (which the rollback changes)
    /// and its preference are not.
    #[test]
    fn uninstall_purge_refuses_changed_issuing_set() {
        let (_d, state, _) = state_dir();
        let store =
            Store::open(&db_of(&state), Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store
            .transaction(|tx| tx.set_pair_preference(&pair_pref(), t0()))
            .unwrap_or_else(|e| panic!("{e}"));
        drop(store);
        let confirmed = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        replacement_writes(&state, |tx| {
            let mut p = pair_pref();
            p.projection = heimdall_domain::enrollment::ProjectionStatus::Applied { generation: 4 };
            p.mechanism = heimdall_contract::managed::PreferredMechanism::Existing;
            tx.set_pair_preference(
                &p,
                t0().checked_add(Duration::from_secs(9))
                    .unwrap_or_else(|_| panic!("time")),
            )
        });
        assert!(
            unchanged(&state, &confirmed, &[]),
            "projection and preference ignored"
        );
        replacement_writes(&state, |tx| {
            let mut p = pair_pref();
            p.issuing_cas.insert(other_ca());
            tx.set_pair_preference(&p, t0())
        });
        assert!(!unchanged(&state, &confirmed, &[]));
    }

    fn observed(state: CaState, locator: Option<&str>, displaced: &[&str]) -> CaObserved {
        CaObserved {
            state,
            locator: locator.map(str::to_owned),
            displaced: displaced.iter().map(|d| (*d).to_owned()).collect(),
        }
    }

    /// Move [`ca`] along the retirement steps from `active` to `to`.
    fn retire_to(tx: &mut heimdall_store::Txn<'_>, to: CaState) -> heimdall_store::Result<()> {
        use heimdall_domain::issuance::CaEvent as E;
        let mut from = CaState::Active;
        for event in [
            E::RetireApproved,
            E::UnloadConfirmed,
            E::StoreItemDeleted,
            E::RetirementRecorded,
        ] {
            if from == to {
                break;
            }
            from = tx
                .set_issuer_state(&ca(), from, event, t0())?
                .unwrap_or_else(|e| panic!("{e:?}"))
                .state;
        }
        Ok(())
    }

    /// ⟨§17.32 item 1; audit A3⟩ `uninstall_purge_admits_only_its_own_retirement`: the
    /// change one of this uninstall's retirement runs was observed to make (`active` with
    /// a displaced item → `retired` with it confirmed deleted) is admitted, exactly: the
    /// same end state without the run, a run observed to end elsewhere, or a run of
    /// another CA is a difference.
    #[test]
    fn uninstall_purge_admits_only_its_own_retirement() {
        let (_d, state, _) = state_dir();
        let store =
            Store::open(&db_of(&state), Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store
            .transaction(|tx| {
                tx.set_issuer_store_locator(&ca(), "item-1")?;
                tx.replace_issuer_store_locator(&ca(), Some("item-1"), "item-2")
            })
            .unwrap_or_else(|e| panic!("{e}"));
        drop(store);
        let confirmed = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        replacement_writes(&state, |tx| {
            retire_to(tx, CaState::Retired)?;
            assert!(tx.resolve_displaced_store_locator(&ca(), "item-1")?);
            Ok(())
        });
        let run = |ca: CaFingerprint, to: CaState, displaced: &[&str]| OwnRetirement {
            ca,
            before: observed(CaState::Active, Some("item-2"), &["item-1"]),
            after: observed(to, Some("item-2"), displaced),
        };
        assert!(
            unchanged(&state, &confirmed, &[run(ca(), CaState::Retired, &[])]),
            "its own retirement is admitted"
        );
        assert!(!unchanged(&state, &confirmed, &[]), "anyone else's is not");
        assert!(!unchanged(
            &state,
            &confirmed,
            &[run(other_ca(), CaState::Retired, &[])]
        ));
        assert!(
            !unchanged(&state, &confirmed, &[run(ca(), CaState::Unloaded, &[])]),
            "a run observed to end at unloaded admits no later step"
        );
        assert!(
            !unchanged(
                &state,
                &confirmed,
                &[run(ca(), CaState::Retired, &["item-1"])]
            ),
            "a run observed to keep its displaced item admits no deletion"
        );
    }

    /// `uninstall_purge_refuses_foreign_change_after_declined_retire` (audit A3): a
    /// declined retirement run changes nothing and records no own change (its CA as
    /// observed before and after is the same); a later foreign change to that CA (the
    /// leftover decision approved elsewhere: `active` → `unloaded`) refuses the purge.
    #[test]
    fn uninstall_purge_refuses_foreign_change_after_declined_retire() {
        use heimdall_contract::issuer::{CaStatus, IssuerState, IssuerStatus};
        let (_d, state, confirmed) = state_dir();
        // The declined run, on a session whose status shows the CA active throughout.
        struct Declined {
            status: Envelope<serde_json::Value>,
        }
        impl crate::cli::Session for Declined {
            async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
                match request {
                    Request::Issuer(heimdall_contract::issuer::IssuerRequest::Status) => {
                        self.status.clone()
                    }
                    _ => crate::setup_cmd::failure(
                        Code::InteractionRequired,
                        "fixture: declined",
                        None,
                    ),
                }
            }
            async fn attend(&mut self) -> Envelope<serde_json::Value> {
                Envelope::ok(serde_json::json!({}))
            }
        }
        let st = IssuerStatus {
            state: IssuerState::NotInitialized,
            reason: None,
            cas: vec![CaStatus {
                fingerprint: ca(),
                state: CaState::Active,
                store: StoreKind::LinuxSecretService,
                backup_sha256: "00".repeat(32),
                backup_created_at: t0(),
                restored_without_log: false,
                enrollments: heimdall_contract::issuer::EnrollmentCounts::default(),
                store_locator: Some("item-1".to_owned()),
            }],
            orphan_store_items: Vec::new(),
            issuer_isolation: heimdall_contract::managed::IssuerIsolation::SameUserProcess,
            bundle_stale: false,
        };
        let mut s = Declined {
            status: Envelope::ok(serde_json::to_value(&st).unwrap_or_else(|e| panic!("{e}"))),
        };
        let mut inv = confirmed.clone();
        inv.items = vec![StoreItem {
            ca: ca(),
            state: CaState::Active,
            store_kind: StoreKind::LinuxSecretService,
            locator: Some("item-1".to_owned()),
            backup_created_at: t0(),
            fate: Fate::DeletionOffered,
            retire: None,
        }];
        let mut p = Script {
            answers: vec![Answer::No],
            shown: Vec::new(),
        };
        let own = block_on(retire_offered(&mut s, &mut p, &ctx(true, false), &mut inv));
        assert!(
            own.is_empty(),
            "a declined run records no own change: {own:?}"
        );
        assert!(matches!(
            inv.items[0].retire,
            Some(RetireRun::Stopped { .. })
        ));
        replacement_writes(&state, |tx| retire_to(tx, CaState::Unloaded));
        assert!(
            !unchanged(&state, &confirmed, &own),
            "the foreign change refuses"
        );
    }

    /// `uninstall_purge_refuses_journal_change_on_unchanged_state` (audit A5): an open
    /// enrollment operation whose journal changes (a receipt appended) while its state
    /// and its enrollment stay as they were refuses the purge.
    #[test]
    fn uninstall_purge_refuses_journal_change_on_unchanged_state() {
        assert!(case_refuses(
            Box::new(|tx| insert_op(tx, 6)),
            Box::new(|tx| tx.append_stage_receipt(&enrollment_op(6).id, &receipt("enroll.journal"))),
        ));
    }

    // --- ADR-0008 §17.32 item 7: pending remote revocations; the cleanup-intent paths

    /// A pending remote revocation of a revoked root grant (one attempt made).
    fn remote_revocation() -> heimdall_domain::revocation::PendingRemoteRevocation {
        let root = heimdall_contract::ids::GrantId::from_random_bytes([3; 16]);
        heimdall_domain::revocation::PendingRemoteRevocation {
            root: root.clone(),
            grants: vec![root],
            attempts: 1,
            last_attempt_at: t0(),
            stopped: false,
            obligations: Vec::new(),
            claimed_at: None,
            rearmed_effects: Vec::new(),
            cap: None,
            claim_seq: None,
        }
    }

    /// The root's tombstone and its pending remote revocation.
    fn seed_remote(tx: &mut heimdall_store::Txn<'_>) -> heimdall_store::Result<()> {
        let r = remote_revocation();
        tx.insert_tombstone(&heimdall_domain::revocation::Tombstone {
            grant: r.root.clone(),
            cascade: Vec::new(),
            generation: heimdall_domain::policy::AuthorityGeneration(0),
            revoked_at: t0(),
            remote_pending: Vec::new(),
            cause: heimdall_domain::revocation::RevocationCause::Revoke,
        })?;
        tx.set_remote_revocation(&r)
    }

    /// A session answering the fence's retry with `answer` (and recording each kind).
    struct Retry {
        answer: Envelope<serde_json::Value>,
        sent: Vec<String>,
    }

    impl crate::cli::Session for Retry {
        async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
            self.sent.push(request.kind().to_owned());
            self.answer.clone()
        }
        async fn attend(&mut self) -> Envelope<serde_json::Value> {
            Envelope::ok(serde_json::json!({}))
        }
    }

    /// The runtime's answer to the retry for [`remote_revocation`]: one round, still
    /// pending.
    fn retried_once() -> RemoteRetry {
        RemoteRetry {
            root_grant: remote_revocation().root.as_str().to_owned(),
            outcome: "attempted_still_pending".to_owned(),
            attempts_before: 1,
            attempts_after: 2,
            stopped: false,
            pending: true,
            record: Some(after_retry()),
        }
    }

    /// [`remote_revocation`] as the one retry left it: round 2 claimed and completed,
    /// with its adapter obligation still pending.
    fn after_retry() -> heimdall_domain::revocation::PendingRemoteRevocation {
        let mut r = remote_revocation();
        r.attempts = 2;
        r.last_attempt_at = t0()
            .checked_add(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("time"));
        r.claim_seq = Some(2);
        r.obligations = vec![obligation("fake-a")];
        r
    }

    /// A pending adapter obligation of [`remote_revocation`]'s root grant.
    fn obligation(instance: &str) -> heimdall_domain::revocation::RemoteObligation {
        heimdall_domain::revocation::RemoteObligation {
            grant: remote_revocation().root,
            adapter: heimdall_domain::operation::AdapterIdentity {
                mechanism: "fake".to_owned(),
                instance: instance.to_owned(),
            },
            reason: None,
            attempts: Some(2),
            stopped: false,
            effect_round: Some(1),
            effect_seq: Some(1),
            kind: heimdall_domain::revocation::ObligationKind::default(),
        }
    }

    /// `uninstall_lists_and_confirms_pending_remote_revocations` (ADR-0008 §17.32 item
    /// 7): a pending remote revocation is read by the inventory and shown, with the one
    /// retry it gets, in the purge confirmation's typed prompt; the retry is sent on
    /// uninstall's own session (`uninstall_fence.retry_remote_revocations`); what is
    /// still pending afterwards is listed in the report (human and JSON) with the
    /// attempt's outcome; nothing refuses the purge for it (a permanently gone remote
    /// never blocks uninstall).
    #[test]
    fn uninstall_lists_and_confirms_pending_remote_revocations() {
        let (_d, state, _) = state_dir();
        let store =
            Store::open(&db_of(&state), Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store
            .transaction(seed_remote)
            .unwrap_or_else(|e| panic!("{e}"));
        drop(store);
        let mut inv = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        let root = remote_revocation().root;
        assert_eq!(inv.remote_revocations, vec![remote_revocation()]);
        // The typed confirmation shows it.
        let mut yes = Script {
            answers: vec![Answer::Yes],
            shown: Vec::new(),
        };
        let inv2 = inv.clone();
        assert!(
            block_on(confirm_purge(&ctx(true, false), &mut yes, || {
                let mut d = discard();
                d.remote_revocations = inv2.remote_revocations_text();
                d
            }))
            .is_ok()
        );
        let shown = &yes.shown[0];
        assert!(shown.contains(REMOTE_REVOCATIONS), "{shown}");
        assert!(shown.contains(root.as_str()), "{shown}");
        assert!(shown.contains("one retry attempt"), "{shown}");
        // The one retry, on this session.
        let mut s = Retry {
            answer: Envelope::ok(serde_json::json!({ "remote_revocations": [retried_once()] })),
            sent: Vec::new(),
        };
        let retried = block_on(retry_remote_revocations(&mut s, &inv));
        assert_eq!(
            s.sent,
            vec!["uninstall_fence.retry_remote_revocations".to_owned()]
        );
        assert_eq!(retried, Ok(vec![retried_once()]));
        if let Ok(r) = &retried {
            apply_retries(&mut inv, r);
        }
        // The report lists what is still pending, with the attempt's outcome.
        let mut out = report(true, true, true, None, Vec::new(), Vec::new());
        with_retries(&mut out, &retried);
        let out = annotate(out, &inv, None);
        assert!(out.env.code.is_success(), "not refused for it");
        let listed = &out.env.data["pending_remote_revocations"][0];
        assert_eq!(listed["root_grant"], root.as_str());
        assert_eq!(listed["attempts"], 2, "the count after the retry");
        let r = &out.env.data["remote_revocation_retries"][0];
        assert_eq!(r["outcome"], "attempted_still_pending");
        assert_eq!(r["pending"], true);
        assert!(out.human.contains(REMOTE_REVOCATIONS), "{}", out.human);
        assert!(out.human.contains("still pending"), "{}", out.human);
        // Nothing pending: no retry is sent.
        let mut s = Retry {
            answer: Envelope::ok(serde_json::json!({})),
            sent: Vec::new(),
        };
        assert_eq!(
            block_on(retry_remote_revocations(&mut s, &Inventory::default())),
            Ok(Vec::new())
        );
        assert!(s.sent.is_empty());
    }

    /// `uninstall_purge_admits_exactly_its_own_retry` (ADR-0008 §17.32 item 7, §17.33
    /// item 3): the record exactly as this uninstall's one retry returned it is admitted
    /// by the final check; another record (another count), no record, or a "gone"
    /// answer while it is still stored is a difference.
    #[test]
    fn uninstall_purge_admits_exactly_its_own_retry() {
        let (_d, state, _) = state_dir();
        let store =
            Store::open(&db_of(&state), Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store
            .transaction(seed_remote)
            .unwrap_or_else(|e| panic!("{e}"));
        drop(store);
        let confirmed = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        replacement_writes(&state, |tx| tx.set_remote_revocation(&after_retry()));
        let now = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        let own = |retries: Vec<RemoteRetry>| OwnChanges {
            retirements: Vec::new(),
            retries,
        };
        assert!(confirmed.unchanged_but_for(&now, &own(vec![retried_once()])));
        assert!(!confirmed.unchanged_but_for(&now, &own(Vec::new())));
        let mut three = retried_once();
        if let Some(r) = &mut three.record {
            r.attempts = 3;
        }
        assert!(!confirmed.unchanged_but_for(&now, &own(vec![three])));
        let mut done = retried_once();
        done.pending = false;
        done.record = None;
        assert!(
            !confirmed.unchanged_but_for(&now, &own(vec![done])),
            "answered gone, still stored"
        );
    }

    /// `retry_allowance_admits_no_recreated_record_and_nothing_on_failure` (ADR-0008
    /// §17.33 item 3, audit B1): a round answered "removed" admits only its absence (a
    /// record re-created afterwards is a difference); a failed round admits nothing (the
    /// confirmed bytes stay admitted, any change, such as a claimed attempt, is a
    /// difference).
    #[test]
    fn retry_allowance_admits_no_recreated_record_and_nothing_on_failure() {
        let (_d, state, _) = state_dir();
        let store =
            Store::open(&db_of(&state), Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store
            .transaction(seed_remote)
            .unwrap_or_else(|e| panic!("{e}"));
        drop(store);
        let confirmed = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        let own = |r: RemoteRetry| OwnChanges {
            retirements: Vec::new(),
            retries: vec![r],
        };
        let mut completed = retried_once();
        completed.outcome = "completed".to_owned();
        completed.pending = false;
        completed.record = None;
        let mut failed = retried_once();
        failed.outcome = "failed".to_owned();
        failed.record = None;
        let unchanged = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            confirmed.unchanged_but_for(&unchanged, &own(failed.clone())),
            "a failed round admits the confirmed bytes"
        );
        assert!(
            !confirmed.unchanged_but_for(&unchanged, &own(completed.clone())),
            "answered removed, still stored (re-created)"
        );
        replacement_writes(&state, |tx| tx.set_remote_revocation(&after_retry()));
        let changed = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !confirmed.unchanged_but_for(&changed, &own(failed)),
            "a failed round admits no change"
        );
        replacement_writes(&state, |tx| {
            tx.clear_remote_revocation(&remote_revocation().root)
        });
        let removed = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            confirmed.unchanged_but_for(&removed, &own(completed)),
            "its absence is admitted"
        );
    }

    /// `recheck3_retry_allowance_rejects_new_remote_obligation` (the third re-check's
    /// probe, W5-E01; ADR-0008 §17.33 item 3): after the one retry returned its record,
    /// a replacement takes the instance lock and writes that record with a **new**
    /// adapter obligation and another claim sequence (the record-level attempt count and
    /// stop state as answered), and releases the lock; the purge refuses
    /// `uninstall_inventory_changed`, deleting nothing.
    #[test]
    fn recheck3_retry_allowance_rejects_new_remote_obligation() {
        let (_d, state, _) = state_dir();
        let store =
            Store::open(&db_of(&state), Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store
            .transaction(|tx| {
                seed_remote(tx)?;
                tx.set_remote_revocation(&after_retry())
            })
            .unwrap_or_else(|e| panic!("{e}"));
        drop(store);
        let mut confirmed = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        // The confirmation's read predates the retry: the record before it.
        replacement_writes(&state, |tx| tx.set_remote_revocation(&remote_revocation()));
        confirmed.snapshot = Inventory::read(&db_of(&state))
            .unwrap_or_else(|e| panic!("{e}"))
            .snapshot;
        replacement_writes(&state, |tx| {
            let mut r = after_retry();
            r.obligations.push(obligation("fake-b"));
            r.claim_seq = Some(3);
            tx.set_remote_revocation(&r)
        });
        let own = OwnChanges {
            retirements: Vec::new(),
            retries: vec![retried_once()],
        };
        let end = block_on(purge_after_stop(
            true,
            true,
            (&state, &run_of(&state), state.parent()),
            (&confirmed, &own),
            &plain_purge(),
            Duration::from_millis(300),
            || panic!("the purge reached its deletion over a new remote obligation"),
        ));
        let PurgeEnd::Changed(now) = end else {
            panic!("a new remote obligation was purged");
        };
        let out = inventory_changed(None, &now, EffectStatus::Partial);
        assert_eq!(
            out.env.data["error"]["reason"],
            reason::UNINSTALL_INVENTORY_CHANGED
        );
        assert!(db_of(&state).exists(), "nothing was deleted");
    }

    /// `uninstall_purge_refuses_remote_revocation_added_in_window` (ADR-0008 §17.32 item
    /// 7): a replacement that leaves a pending remote revocation between the stop and
    /// the purge's lock makes the purge refuse `uninstall_inventory_changed`, deleting
    /// nothing.
    #[test]
    fn uninstall_purge_refuses_remote_revocation_added_in_window() {
        let (_d, state, confirmed) = state_dir();
        replacement_writes(&state, seed_remote);
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {
            panic!("the purge reached its deletion over a pending remote revocation")
        });
        let PurgeEnd::Changed(now) = end else {
            panic!("a pending remote revocation was purged");
        };
        assert_eq!(now.remote_revocations, vec![remote_revocation()]);
        assert!(db_of(&state).exists());
    }

    /// `uninstall_purge_removes_every_cleanup_intent_path` (ADR-0008 §17.32 item 7, the
    /// condition for leaving `cleanup_intent:` out): with a cleanup intent recorded for
    /// a managed grant, every path its effects can leave (the binding directory with its
    /// endpoint socket, key, certificate and generation marker; the pair slot's key and
    /// certificate), each built by the product's own path functions, is gone after the
    /// purge, and nothing else in the runtime directory is touched.
    #[test]
    fn uninstall_purge_removes_every_cleanup_intent_path() {
        use heimdall_adapters::managed::files::{
            BINDING_KEY_FILE, GENERATION_FILE, binding_cert_name,
        };
        use heimdall_credential::endpoints::{EndpointTag, binding_dir, binding_socket};
        assert_eq!(BINDING_DIR, heimdall_credential::endpoints::BINDING_DIR);
        let (_d, state, confirmed) = state_dir();
        let run = run_of(&state);
        let store =
            Store::open(&db_of(&state), Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store
            .transaction(|tx| {
                tx.record_cleanup_intent(&heimdall_domain::revocation::CleanupIntent {
                    grant: heimdall_contract::ids::GrantId::from_random_bytes([4; 16]),
                    operation: heimdall_contract::ids::OperationId::from_random_bytes([4; 16]),
                    adapter: None,
                    effect_token: String::new(),
                    confirmed: false,
                    in_flight: false,
                    version: 0,
                    recorded_at: t0(),
                })
                .map(drop)
            })
            .unwrap_or_else(|e| panic!("{e}"));
        drop(store);
        let confirmed = Inventory {
            snapshot: Inventory::read(&db_of(&state))
                .unwrap_or_else(|e| panic!("{e}"))
                .snapshot,
            ..confirmed
        };
        let dest = heimdall_contract::ids::DestinationId::parse("dst-lab1")
            .unwrap_or_else(|e| panic!("{e}"));
        let tag = EndpointTag::parse("0123456789abcdef").unwrap_or_else(|| panic!("tag"));
        let bdir = binding_dir(&run, &tag);
        let slot = heimdall_localenv::projection::content::managed_slot_paths(&state, &dest)
            .unwrap_or_else(|e| panic!("{e:?}"));
        let paths = [
            binding_socket(&run, &tag),
            bdir.join(BINDING_KEY_FILE),
            bdir.join(binding_cert_name(&dest).unwrap_or_else(|e| panic!("{e:?}"))),
            bdir.join(GENERATION_FILE),
            slot.key_pub.clone(),
            slot.cert_pub.clone(),
            // ⟨§17.33 item 5⟩ `finish_slot`'s path: the slot's stable mux path, which
            // `clear_slot_path` clears.
            heimdall_localenv::projection::content::managed_mux_path(&run, &dest)
                .unwrap_or_else(|e| panic!("{e:?}")),
        ];
        for p in &paths {
            std::fs::create_dir_all(p.parent().unwrap_or(&run)).unwrap_or_else(|e| panic!("{e}"));
            std::fs::write(p, b"fixture\n").unwrap_or_else(|e| panic!("{e}"));
        }
        let keep = run.join("unrelated.txt");
        std::fs::write(&keep, b"x").unwrap_or_else(|e| panic!("{e}"));
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {});
        assert!(matches!(end, PurgeEnd::Purged(Ok(()))), "the purge ran");
        for p in &paths {
            assert!(!p.exists(), "{} survived the purge", p.display());
        }
        assert!(!bdir.exists() && !state.join(SLOT_DIR).exists());
        assert!(
            keep.exists(),
            "nothing else in the runtime directory is touched"
        );
    }

    /// A managed directory that is a link is refused, never followed: the purge stops
    /// before deleting anything (the database stays).
    #[cfg(unix)]
    #[test]
    fn uninstall_purge_refuses_a_linked_managed_dir() {
        let (d, state, confirmed) = state_dir();
        let elsewhere = d.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(elsewhere.join("keep"), b"x").unwrap_or_else(|e| panic!("{e}"));
        std::os::unix::fs::symlink(&elsewhere, state.join(SLOT_DIR))
            .unwrap_or_else(|e| panic!("{e}"));
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {});
        assert!(refused_whole(&end), "refused");
        assert!(elsewhere.join("keep").exists(), "the link was not followed");
        assert!(db_of(&state).exists(), "nothing else was deleted");
    }

    // --- ADR-0008 §17.33 items 4-5 (W5-E04, W5-E06): the anchored sweep ---------------

    /// A directory outside the purge's roots holding `b/marker` (what a replaced root or
    /// a nested link would point at).
    #[cfg(unix)]
    fn outside(d: &Path) -> PathBuf {
        let o = d.join("outside");
        std::fs::create_dir_all(o.join("b")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir_all(o.join("managed")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(o.join("b").join("marker"), b"keep").unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(o.join("managed").join("marker"), b"keep").unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(o.join(heimdall_runtime::service::STATE_DB_FILE), b"keep")
            .unwrap_or_else(|e| panic!("{e}"));
        o
    }

    /// `recheck3_purge_never_follows_runtime_root_replacement` (the third re-check's
    /// probe, W5-E04; ADR-0008 §17.33 item 4): at the point between the final read and
    /// the deletion, the runtime directory is replaced by a link to a directory outside
    /// the roots; the purge refuses, deleting nothing (the state database stays) and
    /// touching nothing outside.
    #[cfg(unix)]
    #[test]
    fn recheck3_purge_never_follows_runtime_root_replacement() {
        let (d, state, confirmed) = state_dir();
        let run = run_of(&state);
        let o = outside(d.path());
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {
            std::fs::rename(&run, d.path().join("run.old")).unwrap_or_else(|e| panic!("{e}"));
            std::os::unix::fs::symlink(&o, &run).unwrap_or_else(|e| panic!("{e}"));
        });
        assert!(refused_whole(&end), "refused");
        assert!(
            o.join("b").join("marker").exists(),
            "nothing outside is touched"
        );
        assert!(db_of(&state).exists(), "nothing was deleted");
    }

    /// ⟨Converge⟩ `uninstall_purge_never_follows_state_root_replacement`: the state
    /// directory replaced by a link at the same point; its database, snapshots and slots
    /// are reached only through the anchored root, so the purge refuses and the outside
    /// directory (with a file named as the database) is untouched.
    #[cfg(unix)]
    #[test]
    fn uninstall_purge_never_follows_state_root_replacement() {
        let (d, state, confirmed) = state_dir();
        let o = outside(d.path());
        let moved = d.path().join("state.old");
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {
            std::fs::rename(&state, &moved).unwrap_or_else(|e| panic!("{e}"));
            std::os::unix::fs::symlink(&o, &state).unwrap_or_else(|e| panic!("{e}"));
        });
        assert!(refused_whole(&end), "refused");
        assert!(o.join(heimdall_runtime::service::STATE_DB_FILE).exists());
        assert!(o.join("managed").join("marker").exists());
        assert!(db_of(&moved).exists(), "the real database was not deleted");
    }

    /// `recheck3_purge_does_not_follow_nested_links` (the nested-link case, ADR-0008
    /// §17.33 item 4): a binding directory that is a link to a directory outside the
    /// roots refuses the purge in its first pass: nothing is deleted, inside or outside.
    #[cfg(unix)]
    #[test]
    fn recheck3_purge_does_not_follow_nested_links() {
        let (d, state, confirmed) = state_dir();
        let run = run_of(&state);
        let o = outside(d.path());
        std::fs::create_dir(run.join("b")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(run.join("b").join("inside"), b"x").unwrap_or_else(|e| panic!("{e}"));
        std::os::unix::fs::symlink(o.join("b"), run.join("b").join("0123456789abcdef"))
            .unwrap_or_else(|e| panic!("{e}"));
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {});
        assert!(refused_whole(&end), "refused");
        assert!(
            o.join("b").join("marker").exists(),
            "nothing outside is touched"
        );
        assert!(
            run.join("b").join("inside").exists(),
            "nothing inside was deleted"
        );
        assert!(db_of(&state).exists());
    }

    /// `recheck3_purge_removes_cleanup_mux_path` (the third re-check's probe, W5-E06;
    /// ADR-0008 §17.33 item 5): a stale socket at the slot's stable mux path
    /// (`managed_mux_path`, which `finish_slot` clears), left with its cleanup record,
    /// is gone after the purge.
    #[cfg(unix)]
    #[test]
    fn recheck3_purge_removes_cleanup_mux_path() {
        let (_d, state, confirmed) = state_dir();
        let run = run_of(&state);
        let dest = heimdall_contract::ids::DestinationId::parse("dst-lab1")
            .unwrap_or_else(|e| panic!("{e}"));
        let mux = heimdall_localenv::projection::content::managed_mux_path(&run, &dest)
            .unwrap_or_else(|e| panic!("{e:?}"));
        std::fs::create_dir_all(mux.parent().unwrap_or(&run)).unwrap_or_else(|e| panic!("{e}"));
        drop(std::os::unix::net::UnixListener::bind(&mux).unwrap_or_else(|e| panic!("{e}")));
        assert!(
            std::fs::symlink_metadata(&mux).is_ok(),
            "the stale socket exists"
        );
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {});
        assert!(matches!(end, PurgeEnd::Purged(Ok(()))), "the purge ran");
        assert!(
            std::fs::symlink_metadata(&mux).is_err(),
            "the mux path was cleared"
        );
    }

    /// ⟨§17.33 item 4⟩ A runtime root that is not owner-only refuses the purge before
    /// anything is deleted.
    #[cfg(unix)]
    #[test]
    fn uninstall_purge_refuses_a_shared_runtime_root() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_d, state, confirmed) = state_dir();
        let run = run_of(&state);
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o770))
            .unwrap_or_else(|e| panic!("{e}"));
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {});
        assert!(refused_whole(&end), "refused");
        assert!(db_of(&state).exists());
    }

    // --- ADR-0008 §17.33 items 10-11 (audit B3, B4, B6) ---------------------------------

    /// Refused with nothing deleted: before the lock (the anchoring) or by the sweep.
    #[cfg(unix)]
    fn refused_whole(end: &PurgeEnd) -> bool {
        matches!(end, PurgeEnd::Unavailable(_) | PurgeEnd::Purged(Err(_)))
    }

    /// `uninstall_purge_refuses_a_replaced_common_parent` (ADR-0008 §17.33 item 10,
    /// after the audit's `rvprobe_purge_follows_a_replaced_ancestor`): at the point
    /// between the final read and the deletion, the directory holding both `<state>` and
    /// `<run>` is replaced by a link to another directory with its own `state.db`,
    /// `backups/` and `run/b`; the purge refuses and deletes nothing, there or here.
    #[cfg(unix)]
    #[test]
    fn uninstall_purge_refuses_a_replaced_common_parent() {
        use std::os::unix::fs::PermissionsExt as _;
        let (d, state, confirmed) = state_dir();
        let root = d.path().to_path_buf();
        let moved = root.with_extension("moved");
        let other = root.with_extension("other");
        for p in [
            other.join("state").join("backups"),
            other.join("run").join("b"),
        ] {
            std::fs::create_dir_all(&p).unwrap_or_else(|e| panic!("{e}"));
            std::fs::write(p.join("keep"), b"x").unwrap_or_else(|e| panic!("{e}"));
        }
        std::fs::write(other.join("state").join("state.db"), b"other")
            .unwrap_or_else(|e| panic!("{e}"));
        for p in [&other, &other.join("state"), &other.join("run")] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {
            std::fs::rename(&root, &moved).unwrap_or_else(|e| panic!("{e}"));
            std::os::unix::fs::symlink(&other, &root).unwrap_or_else(|e| panic!("{e}"));
        });
        let kept = [
            other.join("state").join("state.db"),
            other.join("state").join("backups").join("keep"),
            other.join("run").join("b").join("keep"),
        ];
        let ours = moved
            .join("state")
            .join(heimdall_runtime::service::STATE_DB_FILE);
        let (outside_kept, ours_kept) = (kept.iter().all(|p| p.exists()), ours.exists());
        // Put the scratch directory back for its own cleanup.
        std::fs::remove_file(&root).unwrap_or_else(|e| panic!("{e}"));
        std::fs::rename(&moved, &root).unwrap_or_else(|e| panic!("{e}"));
        std::fs::remove_dir_all(&other).unwrap_or_else(|e| panic!("{e}"));
        assert!(refused_whole(&end), "refused");
        assert!(outside_kept, "nothing in the other directory was deleted");
        assert!(ours_kept, "nothing of ours was deleted");
    }

    /// `uninstall_purge_refuses_a_swapped_owner_only_state` (ADR-0008 §17.33 item 10, after
    /// the audit's `rvprobe_purge_accepts_a_real_directory_root_swap`): `<state>` swapped
    /// for another real, owner-only directory with its own database between the final
    /// read and the deletion refuses: the anchored identity no longer matches the path,
    /// and nothing is deleted in either directory.
    #[cfg(unix)]
    #[test]
    fn uninstall_purge_refuses_a_swapped_owner_only_state() {
        use std::os::unix::fs::PermissionsExt as _;
        let (d, state, confirmed) = state_dir();
        let moved = d.path().join("state.moved");
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {
            std::fs::rename(&state, &moved).unwrap_or_else(|e| panic!("{e}"));
            std::fs::create_dir(&state).unwrap_or_else(|e| panic!("{e}"));
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|e| panic!("{e}"));
            std::fs::write(db_of(&state), b"another").unwrap_or_else(|e| panic!("{e}"));
        });
        assert!(refused_whole(&end), "refused");
        assert!(
            db_of(&state).exists(),
            "the swapped-in directory was not touched"
        );
        assert!(db_of(&moved).exists(), "the real database was not deleted");
        assert!(moved.join("backups").exists());
    }

    /// `uninstall_report_names_the_swept_roots` (ADR-0008 §17.33 item 11, audit B6): the
    /// report says which `<state>` and `<run>` the purge swept, in the JSON
    /// (`purge_roots`) and the human text.
    #[test]
    fn uninstall_report_names_the_swept_roots() {
        let mut out = report(true, true, true, None, Vec::new(), Vec::new());
        with_swept(&mut out, Path::new("/x/state"), Path::new("/x/run"));
        assert_eq!(out.env.data["purge_roots"]["state_dir"], "/x/state");
        assert_eq!(out.env.data["purge_roots"]["runtime_dir"], "/x/run");
        assert!(out.human.contains("runtime /x/run"), "{}", out.human);
    }

    /// `recheck4_transient_state_swap_must_keep_unconfirmed_recovery` (the fourth
    /// re-check's probe, W5-F01; ADR-0008 §17.34 item 1): a replacement adds a CA and a
    /// foreign removal the owner never confirmed; around the final read `<state>` is
    /// swapped for a decoy holding the confirmed copy, and swapped back after it. The
    /// read is of the quarantined database itself, so it sees the added records, the
    /// purge refuses, and the genuine database survives.
    #[cfg(unix)]
    #[test]
    fn recheck4_transient_state_swap_must_keep_unconfirmed_recovery() {
        use std::os::unix::fs::PermissionsExt as _;
        let (d, state, confirmed) = state_dir();
        let decoy = d.path().join("decoy");
        std::fs::create_dir(&decoy).unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("{e}"));
        std::fs::copy(db_of(&state), db_of(&decoy)).unwrap_or_else(|e| panic!("{e}"));
        replacement_writes(&state, |tx| {
            tx.insert_issuer(&other_issuer())?;
            tx.set_issuer_store_locator(&other_ca(), "replacement-item")?;
            tx.insert_foreign_removal(&foreign(7))
        });
        let saved = d.path().join("real-state");
        let (a, b, c) = (state.clone(), decoy.clone(), saved.clone());
        FINAL_READ_HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |after| {
                if after {
                    std::fs::rename(&a, &b).unwrap_or_else(|e| panic!("{e}"));
                    std::fs::rename(&c, &a).unwrap_or_else(|e| panic!("{e}"));
                } else {
                    std::fs::rename(&a, &c).unwrap_or_else(|e| panic!("{e}"));
                    std::fs::rename(&b, &a).unwrap_or_else(|e| panic!("{e}"));
                }
            }));
        });
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {});
        FINAL_READ_HOOK.with(|h| *h.borrow_mut() = None);
        assert!(
            matches!(end, PurgeEnd::Changed(_)),
            "the added records are seen"
        );
        assert!(
            db_of(&state).exists(),
            "an unconfirmed CA recovery record was deleted after a decoy final read"
        );
        let now = Inventory::read(&db_of(&state)).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            now.cas.iter().any(|(c, _)| *c == other_ca()),
            "restored intact"
        );
    }

    // --- the audit of the quarantine (C0) --------------------------------------------------

    /// `<db>-wal` (or another companion) of a state database path.
    #[cfg(unix)]
    fn companion(db: &Path, sfx: &str) -> PathBuf {
        let mut p = db.as_os_str().to_owned();
        p.push(sfx);
        PathBuf::from(p)
    }

    /// The quarantine path of the state database's file with suffix `sfx` (`""`, `-wal`):
    /// the quarantined database's path with `sfx` appended (whether or not that exists).
    #[cfg(unix)]
    fn quarantined(state: &Path, sfx: &str) -> PathBuf {
        let want = format!("-{}", heimdall_runtime::service::STATE_DB_FILE);
        let db = std::fs::read_dir(state)
            .unwrap_or_else(|e| panic!("{e}"))
            .flatten()
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .is_some_and(|n| n.starts_with(".hm-purge-") && n.ends_with(&want))
            })
            .unwrap_or_else(|| panic!("no quarantined database"));
        companion(&db, sfx)
    }

    /// `write` committed only to the state database's `-wal` (the database file itself
    /// left without it, as a crash before a checkpoint leaves it): the `-wal`'s bytes.
    /// The database file is restored to its bytes before the write; no `-wal` or `-shm`
    /// is left in `state`.
    #[cfg(unix)]
    fn wal_of(
        state: &Path,
        write: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<()>,
    ) -> Vec<u8> {
        let db = db_of(state);
        let before = std::fs::read(&db).unwrap_or_else(|e| panic!("{e}"));
        let lock =
            heimdall_runtime::InstanceLock::try_acquire(state).unwrap_or_else(|e| panic!("{e}"));
        let store = Store::open(&db, Arc::new(NoFaults)).unwrap_or_else(|e| panic!("{e}"));
        store.transaction(write).unwrap_or_else(|e| panic!("{e}"));
        let wal = std::fs::read(companion(&db, "-wal")).unwrap_or_else(|e| panic!("{e}"));
        drop(store);
        drop(lock);
        std::fs::write(&db, before).unwrap_or_else(|e| panic!("{e}"));
        for sfx in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(companion(&db, sfx));
        }
        assert!(!wal.is_empty());
        wal
    }

    /// The inventory a database file shows with `wal` as its `-wal`, read from a copy.
    #[cfg(unix)]
    fn read_with_wal(db: &Path, wal: &[u8]) -> Inventory {
        let d = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let copy = d.path().join("copy.db");
        std::fs::copy(db, &copy).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(companion(&copy, "-wal"), wal).unwrap_or_else(|e| panic!("{e}"));
        Inventory::read(&copy).unwrap_or_else(|e| panic!("{e}"))
    }

    /// `final_read_wal_swapped_during_open_keeps_committed_record` (the audit's
    /// `probe_c0_wal_swap_and_back_hides_committed_record`): the quarantined `-wal` holds
    /// a committed foreign-removal record the owner never confirmed. While the final read
    /// opens the database it is swapped for an empty file, and swapped back once SQLite
    /// holds that one. The census finds SQLite never opened the held `-wal`: refused,
    /// everything renamed back, the record intact.
    #[cfg(unix)]
    #[test]
    fn final_read_wal_swapped_during_open_keeps_committed_record() {
        let (d, state, confirmed) = state_dir();
        let db = db_of(&state);
        let wal = wal_of(&state, |tx| tx.insert_foreign_removal(&foreign(7)));
        assert!(
            !confirmed.unchanged_but_for(&read_with_wal(&db, &wal), &OwnChanges::default()),
            "the -wal holds the unconfirmed record"
        );
        std::fs::write(companion(&db, "-wal"), &wal).unwrap_or_else(|e| panic!("{e}"));
        let aside = d.path().join("aside-wal");
        let (st, a) = (state.clone(), aside.clone());
        FINAL_READ_HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |after| {
                let q = quarantined(&st, "-wal");
                if after {
                    std::fs::rename(&a, &q).unwrap_or_else(|e| panic!("{e}"));
                } else {
                    std::fs::rename(&q, &a).unwrap_or_else(|e| panic!("{e}"));
                    std::fs::write(&q, b"").unwrap_or_else(|e| panic!("{e}"));
                }
            }));
        });
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {});
        FINAL_READ_HOOK.with(|h| *h.borrow_mut() = None);
        assert!(!matches!(end, PurgeEnd::Purged(_)), "purged");
        assert!(
            db.exists() && companion(&db, "-wal").exists(),
            "the database and the -wal holding a committed record were deleted"
        );
        assert_eq!(
            std::fs::read(companion(&db, "-wal")).ok().as_deref(),
            Some(&wal[..])
        );
    }

    /// `final_read_refuses_a_planted_wal` (audit C0): no `-wal` existed at the inspection;
    /// one planted at the quarantine name (a log that hides a record the database file
    /// holds) is never what the final read uses: the purge created and holds that name's
    /// file, so the census refuses, and nothing is deleted.
    #[cfg(unix)]
    #[test]
    fn final_read_refuses_a_planted_wal() {
        let (_d, state, _) = state_dir();
        let db = db_of(&state);
        // A log of an earlier write (record 5, an account-form foreign removal taken to
        // `removed`, final: the inventory stays clear) ...
        let planted = wal_of(&state, |tx| {
            use heimdall_contract::enrollment::{EnrollmentForm, EnrollmentState as S};
            use heimdall_domain::enrollment::EnrollmentEventKind as K;
            let mut r = foreign(5);
            r.target.form = EnrollmentForm::Account;
            tx.insert_foreign_removal(&r)?;
            for (from, kind) in [
                (S::Planned, K::RemoveEnrollmentApproved),
                (S::Removing, K::RemovalOutcomeLost),
                (S::RemoveUnknown, K::ReconcileApplied),
            ] {
                r = tx
                    .transition_foreign_removal(from, kind, &r)?
                    .unwrap_or_else(|e| panic!("{e:?}"));
            }
            assert_eq!(r.state, S::Removed);
            Ok(())
        });
        std::fs::write(companion(&db, "-wal"), &planted).unwrap_or_else(|e| panic!("{e}"));
        replacement_writes(&state, |_| Ok(()));
        let confirmed = Inventory::read(&db).unwrap_or_else(|e| panic!("{e}"));
        assert!(confirmed.clear(), "{confirmed:?}");
        // ... then an unconfirmed record 7, which that log's pages hide.
        replacement_writes(&state, |tx| tx.insert_foreign_removal(&foreign(7)));
        for sfx in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(companion(&db, sfx));
        }
        let now = Inventory::read(&db).unwrap_or_else(|e| panic!("{e}"));
        assert!(!confirmed.unchanged_but_for(&now, &OwnChanges::default()));
        assert!(
            confirmed.unchanged_but_for(&read_with_wal(&db, &planted), &OwnChanges::default()),
            "the planted log hides record 7"
        );
        for sfx in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(companion(&db, sfx));
        }
        let st = state.clone();
        FINAL_READ_HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |after| {
                if !after {
                    let q = quarantined(&st, "-wal");
                    let tmp = st.join("planted.tmp");
                    std::fs::write(&tmp, &planted).unwrap_or_else(|e| panic!("{e}"));
                    std::fs::rename(&tmp, &q).unwrap_or_else(|e| panic!("{e}"));
                }
            }));
        });
        let end = purge_now(&state, &confirmed, Duration::from_millis(300), || {});
        FINAL_READ_HOOK.with(|h| *h.borrow_mut() = None);
        assert!(!matches!(end, PurgeEnd::Purged(_)), "purged");
        assert!(db.exists(), "the database holding record 7 was deleted");
        let after = Inventory::read(&db).unwrap_or_else(|e| panic!("{e}"));
        assert!(!confirmed.unchanged_but_for(&after, &OwnChanges::default()));
    }
}
