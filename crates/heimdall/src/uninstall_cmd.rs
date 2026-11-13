//! `heimdall uninstall [--purge-state [--keep-remote-enrollments --bundle <file>]]`
//! (m02-plan U9; ADR-0007 §5.5; Q6 as qualified by §12.2 item 11).
//!
//! **⟨M03⟩ Remote enrollments and the K_ca store items** (m03-plan U0b row 18, U12;
//! ADR-0008 D4 item 6). Before anything else, uninstall reads the state database
//! read-only ([`Inventory`]): the enrollments that are not final, every enrollment's last
//! change, and each registered CA's store item.
//! * **Every uninstall lists the enrollments that are not final**, each with its marker,
//!   destination and state, and offers `heimdall enroll remove <enrollment>` first. A
//!   plain `uninstall` then needs a typed `yes` to leave them enrolled
//!   ([`PLAIN_UNINSTALL_ACK_REQUIRED`]); without a terminal, or with
//!   `--non-interactive`, it ends with exit 3 and nothing was changed.
//! * **`--purge-state`** is refused while any remain (`CONFIG_CONFLICT`, exit 6,
//!   [`enrollment_refusal`]), unless `--keep-remote-enrollments` comes with a **fresh**
//!   recovery bundle (`--bundle <file>`): one written after the last enrollment change
//!   that lists every remaining enrollment in its current state, not redacted
//!   ([`check_bundle`]); its path is recorded in the result. Without one the purge is
//!   refused `bundle_required` (`CAPABILITY_UNAVAILABLE`, exit 4); a redacted one is
//!   `bundle_redacted` (exit 4). ⟨U-Q1⟩ Freshness also needs this installation's record
//!   of writing that bundle ([`BUNDLE_WRITE_RECORD_REQUIRED`]); no such record exists
//!   yet, so every bundle is refused `bundle_required` until it does.
//! * **The K_ca store item's fate is stated** on every outcome
//!   (`heimdall_issuer::retire::uninstall_store_plan`): kept while any enrollment under
//!   its CA is not final, naming the item and the reason; otherwise deletion is offered
//!   (the retirement steps run to `retired`, behind the `RetireIssuer` typed
//!   confirmation) as the command `heimdall issuer retire <fingerprint>`, with the
//!   reminder to destroy the offline backup. ⟨U-Q3⟩ Uninstall does not yet run that
//!   deletion inline (it is the issuer CLI's R2B sequence); an item whose locator was
//!   never recorded is kept, as Heimdall cannot delete it by exact identity.
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
use heimdall_contract::request::{InspectSubject, Request, ShutdownRequest};
use heimdall_contract::setup::{RemainingArtifact, RemainingArtifactKind};
use heimdall_contract::{Code, ExitCode};
use heimdall_domain::enrollment::EnrollmentRecord;
use heimdall_issuer::retire::{KeepReason, StoreFate, uninstall_store_plan};
use heimdall_issuer::store::{SecretStoreKind, StoreItemRef};
use heimdall_store::ext::TableCounts;
use heimdall_store::{NoFaults, Store, StoreError};

use crate::cli::{Prompter, TerminalPrompt, UninstallArgs};
use crate::client::Ctx;
use crate::output;
use crate::prompt::Answer;
use crate::setup_cmd::{
    Outcome, block, entries, inspect, non_interactive_reason, request_id, rollback_intent, session,
    shown,
};

/// How long uninstall waits for the cleaner to confirm the projection resources absent.
const CLEANUP_WAIT: Duration = Duration::from_secs(15);

/// How long uninstall waits for the runtime to remove its advertisement.
const STOP_WAIT: Duration = Duration::from_secs(20);

/// Handle `uninstall` (module docs).
pub(crate) fn run(ctx: &Ctx, args: UninstallArgs) -> ExitCode {
    block(ctx, uninstall(ctx, &args, &mut TerminalPrompt))
}

/// ⟨U-Q2⟩ Switch: a plain `uninstall` with enrollments that are not final asks for a
/// typed `yes` before anything starts (D4 item 6: "offers `enroll remove` first"). The
/// fail-closed reading; `false` would list them and go on.
pub(crate) const PLAIN_UNINSTALL_ACK_REQUIRED: bool = true;

/// ⟨U-Q1⟩ Switch: a `--bundle` is fresh only when this installation also recorded
/// writing it (its path and time; worker I's optional `last_bundle_at`, U10B-Q3 (b)), on
/// top of [`check_bundle`]'s content check. Nothing records it yet, so with `true` every
/// bundle is refused `bundle_required`: the fail-closed reading until the ruling.
pub(crate) const BUNDLE_WRITE_RECORD_REQUIRED: bool = true;

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
}

/// What uninstall does with a K_ca store item.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fate {
    /// Kept: enrollments under the CA are not final (their markers).
    KeptLive(Vec<String>),
    /// Kept: no locator was recorded, so it cannot be deleted by exact identity.
    KeptUnrecorded,
    /// Deletion offered (`heimdall issuer retire`), with the backup reminder.
    DeletionOffered,
}

/// What uninstall reads from the state database before anything else, read-only.
#[derive(Debug, Default)]
struct Inventory {
    /// The enrollments that are not final, oldest first.
    open: Vec<EnrollmentRecord>,
    /// The last change of any enrollment record (final ones included).
    last_change: Option<Timestamp>,
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
                let open = tx.open_enrollments()?;
                let issuers = tx.issuers()?;
                let mut all = open.clone();
                let mut locators = Vec::new();
                for i in &issuers {
                    all.extend(tx.enrollments_for_ca(&i.ca_fingerprint)?);
                    locators.push(tx.issuer_store_locator(&i.ca_fingerprint)?);
                }
                Ok((open, all, issuers, locators))
            })
            .map(|(open, all, issuers, locators)| {
                let views: Vec<EnrollmentView> = all.iter().map(view).collect();
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
                        }
                    })
                    .collect();
                Inventory {
                    last_change: all.iter().map(|r| r.updated_at).max(),
                    open,
                    items,
                }
            })
            .map_err(|_| "the enrollments could not be read")
    }

    /// The `enrollments` listing (marker, destination, state).
    fn enrollments_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.open
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "marker": e.marker,
                        "destination_id": e.destination.as_str(),
                        "state": e.state.as_str(),
                    })
                })
                .collect(),
        )
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
        Fate::DeletionOffered => format!(
            "deletion offered: {name}; every enrollment under it is final, so `{}` deletes it (the retirement steps, run to `retired`, after a typed yes); then destroy the offline backup made {} yourself",
            retire_command(&i.ca),
            i.backup_created_at
        ),
    }
}

/// One line per remaining enrollment: marker, destination, state.
fn enrollment_lines(open: &[EnrollmentRecord]) -> String {
    let mut out = String::new();
    for e in open {
        out.push_str(&format!(
            "    {} {} {}\n",
            e.marker,
            e.destination.as_str(),
            e.state.as_str()
        ));
    }
    out
}

/// Add the inventory to `out`: `enrollments` (when any are not final and the key is
/// not there yet), `store_items` and, when one was accepted, `bundle`; and the same in
/// the human text.
fn annotate(mut out: Outcome, inv: &Inventory, bundle: Option<&str>) -> Outcome {
    let mut human = String::new();
    if let serde_json::Value::Object(map) = &mut out.env.data {
        if !inv.open.is_empty() && !map.contains_key("enrollments") {
            map.insert("enrollments".to_owned(), inv.enrollments_json());
            human.push_str(&format!(
                "Remote enrollments that are not final (they stay enrolled):\n{}",
                enrollment_lines(&inv.open)
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
        map.insert("enrollments".to_owned(), inv.enrollments_json());
    }
    let human = format!(
        "Remote enrollments that are not final ({message}):\n{}",
        enrollment_lines(&inv.open)
    );
    Outcome::of(env).with_human(human)
}

/// `bundle_required` (or `bundle_redacted`): `CAPABILITY_UNAVAILABLE`, exit 4.
fn bundle_refusal(inv: &Inventory, why: &str, reason: &'static str) -> Outcome {
    enrollment_error(
        inv,
        heimdall_app::OpError::new(
            Code::CapabilityUnavailable,
            format!(
                "--purge-state --keep-remote-enrollments needs a fresh recovery bundle (--bundle <file>, written by `heimdall issuer bundle --out <file>` after the last enrollment change): {why}; nothing was changed"
            ),
        )
        .with_reason(reason),
        "keeping them needs a fresh recovery bundle",
    )
}

/// Whether the file at `path` is a fresh recovery bundle for `inv` (D4 item 6): a
/// `heimdall-recovery-bundle/1` document, not redacted, written at or after the last
/// enrollment change, listing every enrollment that is not final in its current state.
/// `Err` is the refusal (`bundle_required`, or `bundle_redacted`) with its reason.
/// `record_required` is [`BUNDLE_WRITE_RECORD_REQUIRED`].
fn check_bundle(
    inv: &Inventory,
    path: &Path,
    record_required: bool,
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
        return required("the bundle predates the last enrollment change");
    }
    for e in &inv.open {
        if !bundle
            .enrollments
            .iter()
            .any(|b| b.marker == e.marker && b.state == e.state)
        {
            return required("the bundle does not list every remaining enrollment as it is now");
        }
    }
    if record_required {
        return required(
            "this installation has no record of writing that bundle (its path and time), so it cannot be proven fresh",
        );
    }
    Ok(())
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
fn enrollment_refusal(inv: &Inventory, args: &UninstallArgs) -> Result<Option<String>, Outcome> {
    if inv.open.is_empty() {
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
        return match check_bundle(inv, path, BUNDLE_WRITE_RECORD_REQUIRED) {
            Ok(()) => Ok(Some(heimdall_localenv::paths::display_path(&home(), path))),
            Err((why, r)) => Err(bundle_refusal(inv, &why, r)),
        };
    }
    Err(enrollment_error(
        inv,
        heimdall_app::OpError::new(
            Code::ConfigConflict,
            format!(
                "--purge-state refused: {} remote enrollment(s) are not final; remove them with `{ENROLL_REMOVE}`, or keep them with --keep-remote-enrollments and a fresh recovery bundle; nothing was changed",
                inv.open.len()
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
        "Remote enrollments that are not final:\n{}Their lines stay on the destinations, and the state database (kept) still records them. To remove them first, answer no and run `{ENROLL_REMOVE}` for each.\n{}Uninstall anyway and leave them enrolled?\n",
        enrollment_lines(&inv.open),
        inv.store_items_text()
    )
}

/// The attended acknowledgement of a plain `uninstall` while enrollments are not final
/// ([`PLAIN_UNINSTALL_ACK_REQUIRED`]): only a typed `yes` goes on; anything else, a
/// non-TTY stdin and `--non-interactive` end it with exit 3 (raised by this client, so
/// with no `decision_ref`), nothing changed.
async fn confirm_plain<P: Prompter>(ctx: &Ctx, p: &mut P, inv: &Inventory) -> Result<(), Outcome> {
    let refused = |why: &str| {
        enrollment_error(
            inv,
            heimdall_app::OpError::new(
                Code::InteractionRequired,
                format!(
                    "uninstall not confirmed ({why}): {} remote enrollment(s) are not final; remove them first with `{ENROLL_REMOVE}`, or run `heimdall uninstall` on a terminal and type yes to leave them enrolled; nothing was changed",
                    inv.open.len()
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
    let inv = match Inventory::read(&db) {
        Ok(inv) => inv,
        Err(why) if purge => return unreadable(why),
        Err(_) => Inventory::default(),
    };
    let mut bundle = None;
    if purge {
        match enrollment_refusal(&inv, args) {
            Ok(b) => bundle = b,
            Err(refused) => return annotate(refused, &inv, None),
        }
    } else if PLAIN_UNINSTALL_ACK_REQUIRED
        && !inv.open.is_empty()
        && let Err(refused) = confirm_plain(ctx, prompt, &inv).await
    {
        return annotate(refused, &inv, None);
    }
    // Before anything is started or changed (ADR-0007 §12.31 item 1): a purge is shown
    // and confirmed first, so any answer but a typed yes leaves everything as it was.
    if purge
        && let Err(refused) = confirm_purge(ctx, prompt, || {
            let mut d = Discard::read(ctx, &paths.state_dir, &dirs);
            d.kept_remote = (!inv.open.is_empty()).then(|| {
                format!(
                    "  Remote enrollments kept (recorded in {}):\n{}",
                    bundle.as_deref().unwrap_or_default(),
                    enrollment_lines(&inv.open)
                )
            });
            d.store_items = inv.store_items_text();
            d
        })
        .await
    {
        return annotate(refused, &inv, bundle.as_deref());
    }
    let mut client = match session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
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
    // Stop the runtime gracefully (it removes its endpoints and advertisement).
    let stopped = stop_runtime(ctx, client).await;
    let mut purged = false;
    let mut refused_purge = false;
    if purge {
        if complete && absent {
            purged = purge_state(&paths.state_dir).is_ok();
            left = remaining(ctx, &dirs, purged);
        } else {
            refused_purge = true;
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

/// `Request::Shutdown` on a session requiring `service-control/1`, then wait (bounded)
/// until the advertisement is gone.
async fn stop_runtime(ctx: &Ctx, client: crate::client::Client) -> bool {
    use heimdall_contract::ipc::capability::SERVICE_CONTROL_V1;
    drop(client);
    let Ok(mut c) = crate::client::connect_requiring(ctx, false, &[SERVICE_CONTROL_V1]).await
    else {
        return false;
    };
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

/// Delete the state store and the snapshots (only after every check passed).
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
            open,
            items: Vec::new(),
        }
    }

    /// A bundle created at `at`, listing `records` (each in its state).
    fn bundle(at: Timestamp, records: &[EnrollmentRecord], redacted: bool) -> Vec<u8> {
        let enrollments: Vec<serde_json::Value> = records
            .iter()
            .map(|r| {
                serde_json::json!({
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
                })
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "schema": RECOVERY_BUNDLE_SCHEMA,
            "created_at": at,
            "redacted": redacted,
            "cas": [],
            "enrollments": enrollments,
            "instructions": [],
        }))
        .unwrap_or_default()
    }

    /// D4 item 6: the content half of freshness. With the write-record switch off, a
    /// bundle written at or after the last change that lists every remaining enrollment
    /// in its state passes; a stale, partial, other-state or redacted one does not. With
    /// the switch on (as built), even the fresh one is `bundle_required`.
    #[test]
    fn a_bundle_is_fresh_only_after_the_last_change_and_complete() {
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
            std::fs::write(&p, bytes).unwrap_or_else(|e| panic!("{e}"));
            p
        };
        let fresh = write("fresh", bundle(late, &[live.clone(), other.clone()], false));
        assert_eq!(check_bundle(&inv, &fresh, false), Ok(()));
        let Err((why, r)) = check_bundle(&inv, &fresh, true) else {
            panic!("the write record is required");
        };
        assert_eq!(r, reason::BUNDLE_REQUIRED);
        assert!(why.contains("no record of writing"), "{why}");
        let at_change = write(
            "at",
            bundle(other.updated_at, &[live.clone(), other.clone()], false),
        );
        assert_eq!(check_bundle(&inv, &at_change, false), Ok(()));
        let stale = write(
            "stale",
            bundle(live.updated_at, &[live.clone(), other.clone()], false),
        );
        assert!(
            check_bundle(&inv, &stale, false)
                .is_err_and(|(w, r)| { r == reason::BUNDLE_REQUIRED && w.contains("predates") })
        );
        let partial = write("partial", bundle(late, std::slice::from_ref(&live), false));
        assert!(
            check_bundle(&inv, &partial, false).is_err_and(|(_, r)| r == reason::BUNDLE_REQUIRED)
        );
        let mut moved = other.clone();
        moved.state = S::Removing;
        let wrong = write("wrong", bundle(late, &[live.clone(), moved], false));
        assert!(
            check_bundle(&inv, &wrong, false).is_err_and(|(_, r)| r == reason::BUNDLE_REQUIRED)
        );
        let redacted = write("redacted", bundle(late, &[live, other], true));
        assert!(
            check_bundle(&inv, &redacted, false).is_err_and(|(_, r)| r == reason::BUNDLE_REDACTED)
        );
        let big = d.path().join("big");
        let f = std::fs::File::create(&big).unwrap_or_else(|e| panic!("{e}"));
        f.set_len(BUNDLE_MAX + 1).unwrap_or_else(|e| panic!("{e}"));
        assert!(check_bundle(&inv, &big, false).is_err_and(|(w, _)| w.contains("cannot be read")));
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
        assert!(block_on(confirm_plain(&ctx(true, false), &mut yes, &inv)).is_ok());
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
            let Err(out) = block_on(confirm_plain(&c, &mut p, &inv)) else {
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
    }
}
