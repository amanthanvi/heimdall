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
        let store = match Store::open_read_only(db, Arc::new(NoFaults)) {
            Ok(store) => store,
            Err(StoreError::OlderSchema { .. }) => return Ok(Inventory::default()),
            Err(_) => return Err("the database could not be opened read-only"),
        };
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
                Ok((outstanding, unresolved, all, issuers, locators))
            })
            .map(|(outstanding, unresolved, all, issuers, locators)| {
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
                }
            })
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
    fn same_as(&self, now: &Inventory) -> bool {
        self.same_obligations(now) && self.cas == now.cas && self.last_change == now.last_change
    }

    /// ⟨§17.27 item 2⟩ The outstanding obligations alone (the last check before the
    /// state is deleted, after this uninstall's own retirements changed the CAs).
    fn same_obligations(&self, now: &Inventory) -> bool {
        self.open == now.open
            && self.foreign == now.foreign
            && self.operations == now.operations
            && self.unresolved_steps == now.unresolved_steps
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
        return match check_bundle(inv, path, &|sha| recorded_digest(db, sha)) {
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
async fn retire_offered<S: crate::cli::Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    inv: &mut Inventory,
) {
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
        let out = crate::issuer_cmd::retire_to_retired(s, p, ctx, &item.ca).await;
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
    retire_offered(&mut client, prompt, ctx, &mut inv).await;
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
    let mut bundle_now = None;
    if purge {
        match purge_after_stop(
            stopped,
            complete && absent,
            &paths.state_dir,
            &confirmed,
            args,
            LOCK_WAIT,
            || {},
        )
        .await
        {
            PurgeEnd::Purged(deleted) => {
                purged = deleted.is_ok();
                left = remaining(ctx, &dirs, purged);
            }
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
    if let Some(now) = changed {
        return inventory_changed(Some(out), &now, EffectStatus::Partial);
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
    /// Every check passed under the lock; the deletion's own result.
    Purged(std::io::Result<()>),
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
    state_dir: &Path,
    confirmed: &Inventory,
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
    purge_locked(state_dir, confirmed, args, wait, paused).await
}

/// ⟨ADR-0008 §17.31 item 1 (W5-C01)⟩ Under the runtime's own exclusive instance lock
/// (`<state>/service.lock`, [`heimdall_runtime::InstanceLock`], the lock runtime
/// start-up takes before it opens the store): the final inventory read and the
/// bundle's re-check, then the deletion, then the release. While it is held no
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
    state_dir: &Path,
    confirmed: &Inventory,
    args: &UninstallArgs,
    wait: Duration,
    paused: impl FnOnce(),
) -> PurgeEnd {
    let lock = match instance_lock(state_dir, wait).await {
        Ok(lock) => lock,
        Err(why) => return PurgeEnd::Unavailable(why),
    };
    let db = state_dir.join(heimdall_runtime::service::STATE_DB_FILE);
    match Inventory::read(&db) {
        Ok(now) if confirmed.same_obligations(&now) => {}
        Ok(now) => return PurgeEnd::Changed(now),
        Err(_) => return PurgeEnd::Changed(Inventory::default()),
    }
    if let Err(refused) = enrollment_refusal(confirmed, args, &db) {
        return PurgeEnd::Bundle(refused);
    }
    paused();
    let deleted = purge_state(state_dir);
    drop(lock);
    PurgeEnd::Purged(deleted)
}

/// Take the runtime's instance lock for `state_dir`, waiting at most `wait` while
/// another process holds it ([`LOCK_WAIT`]).
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

/// Delete the state store and the snapshots (only after every check passed, under the
/// instance lock: [`purge_locked`]).
fn purge_state(state_dir: &Path) -> std::io::Result<()> {
    let db = state_dir.join(heimdall_runtime::service::STATE_DB_FILE);
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = db.clone().into_os_string();
        name.push(suffix);
        match std::fs::remove_file(PathBuf::from(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    let backups = state_dir.join("backups");
    if backups.is_dir() {
        std::fs::remove_dir_all(backups)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        block_on(retire_offered(&mut s, &mut p, &ctx(true, false), &mut inv));
        assert_eq!(s.sent, vec!["attend".to_owned()], "the entry ran inline");
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
            state,
            confirmed,
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
                &state,
                &confirmed,
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
        let before = std::fs::read(&db).unwrap_or_else(|e| panic!("{e}"));
        let root = d.path().to_path_buf();
        let mut tried = None;
        let end = purge_now(&state, &confirmed, Duration::from_millis(200), || {
            tried = Some(start_runtime(&root));
            assert_eq!(
                std::fs::read(&db).unwrap_or_else(|e| panic!("{e}")),
                before,
                "the refused start-up wrote nothing"
            );
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
}
