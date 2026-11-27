//! ⟨M08 W4 U2b-3b; ADR-0014 §3.2 items 6, 9 and 10, §3.6; ADR-0006 §19.4, U0-Q8; deltas H3,
//! H4⟩ `heimdall state restore --backup <file>`, `heimdall state reset` and `heimdall state
//! repair`, and the refusal every other command gives a damaged or newer store.
//!
//! **Attended, always.** Each command first takes the runtime's own exclusive instance lock
//! (the restore protocol's item 2: while a runtime runs, it holds it; the issuer runs only as
//! the runtime's child), then reads what it would do, writing nothing, and shows it. Only then
//! is the owner asked for a typed confirmation on this terminal. `--non-interactive`, or a
//! standard input that is not a terminal, refuses there with `INTERACTION_REQUIRED` (exit 3,
//! effect `none`) after the disclosure is shown. The lock is held from before the first read
//! until after the switch, so nothing changes between what was shown and what is done.
//!
//! * **`state restore`** (ADR-0014 §3.6): the backup must be one of this installation's own,
//!   bound to its environment (`heimdall_store::restore`). It recovers identity and
//!   configuration and no authority: grants end, policies pause with a cutoff, paired clients
//!   are quarantined until reauthorized, invitations are void, the transport's exposure is
//!   disabled, and every request the ledger saw without a recorded end is fenced. The owner
//!   types `restore`. From a damaged state (no trusted record of the identity) the owner is
//!   shown the backup's environment ID and types it instead: the identity binding and the epoch
//!   then start from that backup.
//! * **`state reset`** (§3.2 item 10): a new, empty store with a **new identity**. It lists
//!   what it orphans on remote hosts from the old store; when nothing can be read it says so
//!   in plain words ([`heimdall_store::restore::NO_INVENTORY_SENTENCE`]), names where such
//!   residue would live, and needs that sentence typed as well as `reset`. It also recovers a
//!   purge that stopped while it removed the store's layout (W3-R04).
//! * **`state repair`** (U0-Q8, the ledger in 1.0): the decodable records after the damage
//!   become fences, the epoch rises, and the ledger is cut at the first damaged record. The
//!   owner types `repair`. The residual it states: a request among the dropped records retried
//!   without its epoch could run again.
//!
//! Every earlier generation is kept, whole, under its own name.

use std::path::Path;

use heimdall_contract::envelope::{EffectStatus, Envelope, ErrorData, NextAction, reason};
use heimdall_contract::lifecycle::{
    GenerationOperation, GenerationRecord, RepairReport, ResetReport, RestoreEpoch, RestoreReport,
};
use heimdall_contract::{Code, ExitCode, Timestamp};
use heimdall_runtime::Paths;
use heimdall_store::StoreError;
use heimdall_store::layout::stategen::{Operation, OperationRecord};
use heimdall_store::restore::{NO_INVENTORY_SENTENCE, Refusal, RestoreError};

use crate::client::Ctx;
use crate::output;
use crate::setup_cmd::{Outcome, block, failure};

/// One line the owner typed at the terminal, or `None` (end of input, an interrupt, no answer
/// in time, an unreadable input).
pub(crate) trait TypedLine {
    /// Show `text` on stderr, then read one line.
    async fn line(&mut self, text: &str) -> Option<String>;
}

/// The terminal: the prompt on stderr, the line from stdin within the prompt's timeout.
pub(crate) struct Terminal;

impl TypedLine for Terminal {
    async fn line(&mut self, text: &str) -> Option<String> {
        output::prompt(text);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let spawned = std::thread::Builder::new()
            .name("heimdall-typed".into())
            .spawn(move || {
                let mut line = String::new();
                let read = std::io::stdin().read_line(&mut line).map(|n| (n, line));
                let _ = tx.send(read);
            });
        if spawned.is_err() {
            return None;
        }
        tokio::select! {
            r = rx => match r {
                Ok(Ok((0, _))) | Ok(Err(_)) | Err(_) => None,
                Ok(Ok((_, line))) => Some(line),
            },
            _ = tokio::signal::ctrl_c() => None,
            () = tokio::time::sleep(crate::prompt::PROMPT_TIMEOUT) => None,
        }
    }
}

/// Whether `typed` is exactly `expected` (surrounding whitespace aside).
fn typed_is(typed: Option<&str>, expected: &str) -> bool {
    typed.is_some_and(|t| t.trim() == expected)
}

// --- the refusal of a damaged or newer store (H4) -----------------------------------------------

/// The recovery choices a damaged store names.
pub(crate) const RECOVERY_CHOICES: &str = "recover it at this machine with `heimdall state \
     restore --backup <file>` (identity and configuration from one of this installation's own \
     backups; it recovers no access) or `heimdall state reset` (a new identity); both keep \
     the damaged state as it is";

fn owner_decision() -> NextAction {
    NextAction {
        action: "owner_decision".to_owned(),
        ..NextAction::default()
    }
}

/// `STATE_UNAVAILABLE` / `state_corrupt`, next `owner_decision`, naming the recovery choices.
pub(crate) fn state_corrupt(detail: &str) -> Envelope<ErrorData> {
    heimdall_app::OpError::new(
        Code::StateUnavailable,
        format!(
            "the state store is damaged ({detail}), so Heimdall stops every operation that needs \
             it and writes nothing: {RECOVERY_CHOICES}"
        ),
    )
    .with_reason(reason::STATE_CORRUPT)
    .with_effect(EffectStatus::None)
    .with_next(owner_decision())
    .into_envelope()
}

/// `STATE_UNAVAILABLE` / `state_newer_than_build`, next `change_client`.
pub(crate) fn state_newer(found: u32, supported: u32) -> Envelope<ErrorData> {
    heimdall_app::OpError::new(
        Code::StateUnavailable,
        format!(
            "the state store was written by a newer Heimdall (schema {found}; this build reads \
             up to {supported}), so this build refuses it and changes nothing: run the newer \
             build"
        ),
    )
    .with_reason(reason::STATE_NEWER_THAN_BUILD)
    .with_effect(EffectStatus::None)
    .with_next(NextAction {
        action: "change_client".to_owned(),
        ..NextAction::default()
    })
    .into_envelope()
}

/// `STATE_UNAVAILABLE` / `ledger_damaged`, next `owner_decision`.
pub(crate) fn ledger_damaged() -> Envelope<ErrorData> {
    heimdall_app::OpError::new(
        Code::StateUnavailable,
        "the request ledger is damaged, so every request that would change state is refused: \
         repair it at this machine with `heimdall state repair`"
            .to_owned(),
    )
    .with_reason(reason::LEDGER_DAMAGED)
    .with_effect(EffectStatus::None)
    .with_next(owner_decision())
    .into_envelope()
}

/// A store error as its `STATE_UNAVAILABLE` answer: `state_corrupt` and
/// `state_newer_than_build` with their next actions; anything else plain.
pub(crate) fn store_unavailable(e: &StoreError) -> Envelope<ErrorData> {
    match e {
        StoreError::Corrupt(detail) => state_corrupt(detail),
        StoreError::NewerSchema { found, supported } => state_newer(*found, *supported),
        other => {
            heimdall_app::OpError::new(Code::StateUnavailable, format!("state store: {other}"))
                .with_effect(EffectStatus::None)
                .into_envelope()
        }
    }
}

/// ⟨H4⟩ What a command that needs the store answers when the store in `state_dir` is damaged
/// or newer than this build, read **without writing anything** (the pointer, the generation's
/// record, and a read-only open of the store that writes no file of its family, with its
/// integrity check); `None` when neither holds (a store this build can serve, migrate or
/// adopt, or a new installation). Asked only when no runtime serves the store
/// (`heimdall_store::Store::open_read_only_quiescent`). A damaged request ledger is
/// [`ledger_refusal`]'s: it never keeps a runtime from starting.
#[must_use]
pub(crate) fn state_refusal(state_dir: &Path) -> Option<Envelope<ErrorData>> {
    refusal_of(state_dir, true)
}

/// [`state_refusal`] without the integrity check, which reads the whole database: the CLI's
/// check before it starts a runtime (the start makes that check itself, and a failed start is
/// then answered by [`state_refusal`]).
#[must_use]
pub(crate) fn quick_state_refusal(state_dir: &Path) -> Option<Envelope<ErrorData>> {
    refusal_of(state_dir, false)
}

fn refusal_of(state_dir: &Path, deep: bool) -> Option<Envelope<ErrorData>> {
    if !state_dir.is_dir() {
        return None;
    }
    let located = match heimdall_store::layout::locate(state_dir) {
        Ok(l) => l,
        Err(e) => return Some(store_unavailable(&e)),
    };
    let db = located.db();
    if std::fs::symlink_metadata(db).is_ok() {
        if let Err(e) = heimdall_store::restore::peek_schema_version(db) {
            return Some(store_unavailable(&e));
        }
        if deep {
            let opened = heimdall_store::Store::open_read_only_quiescent(
                db,
                std::sync::Arc::new(heimdall_store::NoFaults),
            );
            // An older store is migrated at the next start, a fenced flat family is adopted
            // then: neither is refused here.
            if let Err(e @ (StoreError::Corrupt(_) | StoreError::NewerSchema { .. })) = opened {
                return Some(store_unavailable(&e));
            }
        }
    }
    None
}

/// ⟨U0-Q8⟩ `ledger_damaged` when the request ledger of `state_dir` is damaged (read only):
/// every request that would change state is refused until `heimdall state repair`. Not a
/// refusal to start: a runtime serves reads with a damaged ledger, so this is the doctor's
/// finding, never the CLI's reason not to start one.
#[must_use]
pub(crate) fn ledger_refusal(state_dir: &Path) -> Option<Envelope<ErrorData>> {
    if !state_dir.is_dir() {
        return None;
    }
    match heimdall_store::restore::ledger_damage(
        state_dir,
        &heimdall_runtime::state_store::PlatformFs,
    ) {
        Ok(Some(_)) | Err(_) => Some(ledger_damaged()),
        Ok(None) => None,
    }
}

// --- the commands ---------------------------------------------------------------------------------

/// `heimdall state restore --backup <file>`.
pub(crate) fn restore(ctx: &Ctx, backup: &Path) -> ExitCode {
    block(
        ctx,
        restore_with(ctx, backup, &mut Terminal, Timestamp::now()),
    )
}

/// `heimdall state reset`.
pub(crate) fn reset(ctx: &Ctx) -> ExitCode {
    block(ctx, reset_with(ctx, &mut Terminal, Timestamp::now()))
}

/// `heimdall state repair`.
pub(crate) fn repair(ctx: &Ctx) -> ExitCode {
    block(ctx, repair_with(ctx, &mut Terminal, Timestamp::now()))
}

/// The owner can attend here: an interactive invocation with a terminal on stdin
/// ([`Ctx::interactive`]).
fn attended(ctx: &Ctx) -> bool {
    ctx.interactive()
}

/// `INTERACTION_REQUIRED` (exit 3), effect `none`: this command is attended only. `shown` is
/// the disclosure (the human rendering); `said` is what the answer's message must also say,
/// for a reader of the envelope alone.
fn needs_attendance(what: &str, shown: String, said: &str) -> Outcome {
    let message = format!(
        "`heimdall state {what}` is attended only: run it at this machine's terminal, without \
         --non-interactive, and confirm it there; nothing was changed. {said}"
    );
    Outcome::of(failure(Code::InteractionRequired, &message, None)).with_human(shown)
}

/// The owner did not type the confirmation: nothing was changed (`INTERACTION_REQUIRED`,
/// exit 3, as an unconfirmed prompt elsewhere).
fn not_confirmed(what: &str, shown: String) -> Outcome {
    Outcome::of(failure(
        Code::InteractionRequired,
        &format!("`heimdall state {what}` was not confirmed; nothing was changed"),
        None,
    ))
    .with_human(shown)
}

/// The directories, and the runtime's instance lock (the exclusion).
fn exclusive(ctx: &Ctx, what: &str) -> Result<(Paths, heimdall_runtime::InstanceLock), Outcome> {
    let paths = ctx
        .paths()
        .map_err(|e| Outcome::of(output::error_value(*e)))?;
    if !paths.state_dir.is_dir() {
        return Err(Outcome::of(failure(
            Code::ConfigConflict,
            &format!(
                "there is no state directory here, so there is nothing to {what}: this is a new \
                 installation"
            ),
            None,
        )));
    }
    match heimdall_runtime::InstanceLock::try_acquire(&paths.state_dir) {
        Ok(lock) => Ok((paths, lock)),
        Err(heimdall_runtime::instance::InstanceError::AlreadyRunning) => {
            Err(Outcome::of(failure(
                Code::ServiceUnavailable,
                &format!(
                    "a Heimdall runtime (and with it the issuer) is running for this installation, \
                 and `heimdall state {what}` runs only while both are stopped; nothing was \
                 changed. Stop it with `heimdall service stop`, then run `heimdall state {what}` \
                 again"
                ),
                None,
            )))
        }
        Err(heimdall_runtime::instance::InstanceError::Io(_)) => Err(Outcome::of(failure(
            Code::StateUnavailable,
            "this installation's instance lock could not be taken; nothing was changed",
            None,
        ))),
    }
}

/// A restore's, a reset's or a repair's refusal as its answer.
fn refused(what: &str, e: &RestoreError) -> Outcome {
    let env = match e {
        RestoreError::Refused(Refusal::NotABackup(why)) => output::error_value(
            heimdall_app::OpError::new(
                Code::UsageError,
                format!("the file cannot be restored: {why}; nothing was changed"),
            )
            .with_effect(EffectStatus::None)
            .into_envelope(),
        ),
        RestoreError::Refused(Refusal::NewerThanBuild { found, supported }) => {
            output::error_value(state_newer(*found, *supported))
        }
        RestoreError::Refused(Refusal::StoreNewerThanBuild) => output::error_value(
            heimdall_app::OpError::new(
                Code::StateUnavailable,
                "the state store was written by a newer Heimdall, so this build refuses it and \
                 changes nothing: run the newer build"
                    .to_owned(),
            )
            .with_reason(reason::STATE_NEWER_THAN_BUILD)
            .with_effect(EffectStatus::None)
            .with_next(NextAction {
                action: "change_client".to_owned(),
                ..NextAction::default()
            })
            .into_envelope(),
        ),
        RestoreError::Refused(Refusal::EnvironmentMismatch) => failure(
            Code::ConfigConflict,
            "the backup belongs to another Heimdall installation (another environment ID), and a \
             restore never replaces the identity; nothing was changed. Starting over with a new \
             identity is `heimdall state reset`",
            None,
        ),
        RestoreError::Refused(Refusal::NotOwnBackup) => failure(
            Code::UsageError,
            "with no readable record of this installation's identity, only one of its own \
             backups is accepted: a `state.db.v<N>.backup` file in its state directory or in \
             one of its generation directories; nothing was changed",
            None,
        ),
        RestoreError::Refused(Refusal::WrongState(why)) => failure(
            Code::ConfigConflict,
            &format!("{why}; nothing was changed"),
            None,
        ),
        RestoreError::Refused(Refusal::RecoveryNotConfirmed) => failure(
            Code::InteractionRequired,
            &format!(
                "the damaged state's recovery was not confirmed; `heimdall state {what}` changed nothing"
            ),
            None,
        ),
        RestoreError::Store(e) => output::error_value(store_unavailable(e)),
    };
    Outcome::of(env)
}

fn operation_of(op: Operation) -> GenerationOperation {
    match op {
        Operation::Install => GenerationOperation::Install,
        Operation::Adopt => GenerationOperation::Adopt,
        Operation::Restore => GenerationOperation::Restore,
        Operation::Reset => GenerationOperation::Reset,
    }
}

fn generation_record(record: &OperationRecord) -> Result<GenerationRecord, Outcome> {
    let environment = heimdall_contract::ids::EnvironmentId::parse(&record.environment_id)
        .map_err(|_| {
            Outcome::of(output::error_value(state_corrupt(
                "the new generation's record names a malformed environment ID",
            )))
        })?;
    Ok(GenerationRecord {
        generation: record.generation.as_str().to_owned(),
        operation: operation_of(record.operation),
        created_at: record.created_at,
        from_generation: record
            .from_generation
            .as_ref()
            .map(|g| g.as_str().to_owned()),
        backup_sha256: record.backup_sha256.clone(),
        environment_id: environment,
        restore_epoch: RestoreEpoch(record.restore_epoch),
        migrations: Vec::new(),
    })
}

fn ok_outcome<T: serde::Serialize>(data: &T, human: String) -> Outcome {
    let value = serde_json::to_value(data).unwrap_or(serde_json::Value::Null);
    Outcome::of(Envelope::ok(value)).with_human(human)
}

/// `state restore` with its line reader and its time (module docs).
pub(crate) async fn restore_with<T: TypedLine>(
    ctx: &Ctx,
    backup: &Path,
    typed: &mut T,
    now: Timestamp,
) -> Outcome {
    let (paths, _lock) = match exclusive(ctx, "restore") {
        Ok(x) => x,
        Err(o) => return o,
    };
    let plan = match heimdall_runtime::state_store::plan_restore(&paths.state_dir, backup) {
        Ok(p) => p,
        Err(e) => return refused("restore", &e),
    };
    let retention = crate::service_cmd::load_config(&paths)
        .ok()
        .and_then(|c| c.retention_operations().ok())
        .unwrap_or(std::time::Duration::from_secs(7 * 24 * 3600));
    let mut shown = format!(
        "Restore from a backup of environment {} (schema {}, SHA-256 {}).\n\
         A restore recovers this installation's identity and configuration, and no access:\n\
         - every grant ends; its bindings are released;\n\
         - every standing policy is paused, with a cutoff now; workspace trust must be given again;\n\
         - every pending decision is closed; every unfinished operation is closed and never resumed;\n\
         - every paired client of this runner is quarantined until you reauthorize it here;\n\
         - every invitation in the backup is void;\n\
         - the Iroh transport's exposure is disabled (enable it again as the first time);\n\
         - every request received but not recorded as finished is refused for good.\n\
         The current state is kept, whole, under its own name.\n",
        plan.backup.environment.as_str(),
        plan.backup.schema_version,
        plan.backup.sha256,
    );
    let expected = if plan.recovery {
        shown.push_str(&format!(
            "The current state is damaged and no record of this installation's identity can be \
             trusted: the identity binding and the restore epoch start from this backup. Type \
             its environment ID, {}, to confirm.\n",
            plan.backup.environment.as_str()
        ));
        plan.backup.environment.as_str().to_owned()
    } else {
        shown.push_str("Type `restore` to confirm.\n");
        "restore".to_owned()
    };
    if !attended(ctx) {
        return needs_attendance(
            "restore",
            shown,
            "A restore recovers identity and configuration, and no access",
        );
    }
    output::prompt(&shown);
    let answer = typed.line("> ").await;
    if !typed_is(answer.as_deref(), &expected) {
        return not_confirmed("restore", shown);
    }
    let out = match heimdall_runtime::state_store::restore_locked(
        &paths.state_dir,
        backup,
        now,
        plan.recovery,
        retention,
    ) {
        Ok(o) => o,
        Err(e) => return refused("restore", &e),
    };
    let generation = match generation_record(&out.current.record) {
        Ok(g) => g,
        Err(o) => return o,
    };
    let left_behind = out.left_behind.as_ref().map_or_else(
        || heimdall_store::layout::DB_FILE.to_owned(),
        |g| g.as_str().to_owned(),
    );
    let mut human = format!(
        "Restored: generation {} (restore epoch {}), from the backup {}.\n\
         Ended {} grant(s); paused {} policy(ies); closed {} decision(s) and {} operation(s); \
         quarantined {} paired client(s); voided {} invitation(s).\n\
         Fenced {} request(s) from the request ledger ({}).\n",
        generation.generation,
        generation.restore_epoch.0,
        plan.backup.sha256,
        out.ended.grants_ended.len(),
        out.ended.policies_paused.len(),
        out.ended.decisions_closed.len(),
        out.ended.operations_closed.len(),
        out.ended.clients_quarantined.len(),
        out.ended.invitations_voided.len(),
        out.fenced_requests,
        if out.ledger_readable {
            "read whole"
        } else {
            "damaged or unreadable: every record that could be read was fenced"
        },
    );
    human.push_str(if out.carried_forward {
        "The replaced state was readable: its later revocations, retirements, unpairings, \
         cutoffs and finished requests were carried forward.\n"
    } else {
        "The replaced state could not be read: everything recovered is treated as possibly \
         revoked.\n"
    });
    if !out.ended.exposure_disabled.is_empty() {
        human.push_str(
            "The Iroh transport is disabled. `heimdall transport enable` exposes it again, as \
             the first time; `heimdall transport disable` removes the withdrawn key from its \
             platform store.\n",
        );
    }
    if out.remote_effects_pending > 0 {
        human.push_str(&format!(
            "{} remote effect(s) are pending until their runners acknowledge them.\n",
            out.remote_effects_pending
        ));
    }
    if !out.remote_residue.is_empty() {
        human.push_str("Left on remote hosts, which this restore cannot remove:\n");
        for r in &out.remote_residue {
            human.push_str(&format!("- {r}\n"));
        }
    }
    human.push_str(&format!("The earlier state is kept under {left_behind}.\n"));
    let report = RestoreReport {
        generation,
        left_behind,
        ended: out.ended.clone(),
        fenced_requests: out.fenced_requests,
        ledger_readable: out.ledger_readable,
        carried_forward: out.carried_forward,
        remote_effects_pending: out.remote_effects_pending,
        remote_residue: out.remote_residue.clone(),
    };
    ok_outcome(&report, human)
}

/// Where remote residue lives, named when no inventory can be read (ADR-0014 §3.2 item 10).
const RESIDUE_PLACES: &str = "remote enrollments are Heimdall-marked lines in \
     `~/.ssh/authorized_keys` (or the sshd configuration) on the destinations you enrolled; \
     a paired runner keeps this device's management line in its account's \
     `~/.ssh/authorized_keys`; a controller you paired with keeps this machine's pin";

/// `state reset` with its line reader and its time (module docs).
pub(crate) async fn reset_with<T: TypedLine>(ctx: &Ctx, typed: &mut T, now: Timestamp) -> Outcome {
    let (paths, _lock) = match exclusive(ctx, "reset") {
        Ok(x) => x,
        Err(o) => return o,
    };
    let inventory = match heimdall_runtime::state_store::reset_inventory(&paths.state_dir) {
        Ok(i) => i,
        Err(e) => return refused("reset", &e),
    };
    let mut shown = String::from(
        "Reset: start over with a new, empty state store and a NEW IDENTITY (a new environment \
         ID). Everything this installation recorded stops applying here; nothing of it is \
         deleted: the current state is kept, whole, under its own name.\n",
    );
    if inventory.readable {
        if inventory.orphaned.is_empty() {
            shown.push_str("The current state records nothing on remote hosts.\n");
        } else {
            shown.push_str("It leaves these behind on remote hosts:\n");
            for o in &inventory.orphaned {
                shown.push_str(&format!("- {o}\n"));
            }
        }
    } else {
        shown.push_str(&format!(
            "{NO_INVENTORY_SENTENCE}: the state that would list it cannot be read. Where such \
             residue would live: {RESIDUE_PLACES}.\n"
        ));
    }
    shown.push_str("Type `reset` to confirm.\n");
    if !attended(ctx) {
        let said = if inventory.readable {
            "A reset creates a new identity".to_owned()
        } else {
            format!(
                "A reset creates a new identity. {NO_INVENTORY_SENTENCE}: where such residue \
                 would live: {RESIDUE_PLACES}"
            )
        };
        return needs_attendance("reset", shown, &said);
    }
    output::prompt(&shown);
    if !typed_is(typed.line("> ").await.as_deref(), "reset") {
        return not_confirmed("reset", shown);
    }
    if !inventory.readable {
        output::prompt(&format!(
            "Type this sentence to confirm you accept it: {NO_INVENTORY_SENTENCE}\n"
        ));
        if !typed_is(typed.line("> ").await.as_deref(), NO_INVENTORY_SENTENCE) {
            return not_confirmed("reset", shown);
        }
    }
    let out = match heimdall_runtime::state_store::reset_locked(
        &paths.state_dir,
        now,
        inventory.recovery,
    ) {
        Ok(o) => o,
        Err(e) => return refused("reset", &e),
    };
    let generation = match generation_record(&out.current.record) {
        Ok(g) => g,
        Err(o) => return o,
    };
    let left_behind = out.left_behind.as_ref().map_or_else(
        || heimdall_store::layout::DB_FILE.to_owned(),
        |g| g.as_str().to_owned(),
    );
    let human = format!(
        "Reset: generation {} with the new identity {}. The earlier state is kept under {}.\n",
        generation.generation,
        generation.environment_id.as_str(),
        left_behind
    );
    let report = ResetReport {
        generation,
        left_behind,
        inventory_readable: inventory.readable,
        orphaned: inventory.orphaned,
    };
    ok_outcome(&report, human)
}

/// `state repair` with its line reader and its time (module docs).
pub(crate) async fn repair_with<T: TypedLine>(ctx: &Ctx, typed: &mut T, now: Timestamp) -> Outcome {
    let (paths, _lock) = match exclusive(ctx, "repair") {
        Ok(x) => x,
        Err(o) => return o,
    };
    let damage = match heimdall_store::restore::ledger_damage(
        &paths.state_dir,
        &heimdall_runtime::state_store::PlatformFs,
    ) {
        Ok(Some(scan)) => scan,
        Ok(None) => {
            return Outcome::of(failure(
                Code::ConfigConflict,
                "the request ledger is not damaged: there is nothing to repair; nothing was \
                 changed",
                None,
            ));
        }
        Err(e) => return refused("repair", &e),
    };
    let shown = format!(
        "Repair the request ledger: it is damaged at record {}. {} readable record(s) after the \
         damage become fences (each is refused for good if retried), the restore epoch rises \
         (every request minted before is refused), and the ledger is cut at the damage, dropping \
         {} unreadable record(s). A request among the dropped records, retried without its \
         epoch, could run again.\nType `repair` to confirm.\n",
        damage.damaged_at.unwrap_or(0),
        damage.after.len(),
        damage.dropped_records,
    );
    if !attended(ctx) {
        return needs_attendance(
            "repair",
            shown,
            "A request among the dropped records, retried without its epoch, could run again",
        );
    }
    output::prompt(&shown);
    if !typed_is(typed.line("> ").await.as_deref(), "repair") {
        return not_confirmed("repair", shown);
    }
    let out = match heimdall_runtime::state_store::repair_locked(&paths.state_dir, now) {
        Ok(o) => o,
        Err(e) => return refused("repair", &e),
    };
    let human = format!(
        "Repaired: {} record(s) fenced, {} dropped; the restore epoch is now {}.\n",
        out.fenced_records, out.dropped_records, out.restore_epoch.0
    );
    let report = RepairReport {
        fenced_records: out.fenced_records,
        dropped_records: out.dropped_records,
        restore_epoch: out.restore_epoch,
    };
    ok_outcome(&report, human)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    use heimdall_store::layout;
    use heimdall_store::{NoFaults, Store};

    use super::*;

    /// Lines typed at the "terminal", in order; `None` once they run out (end of input).
    struct Script(Vec<&'static str>);

    impl TypedLine for Script {
        async fn line(&mut self, _text: &str) -> Option<String> {
            if self.0.is_empty() {
                None
            } else {
                Some(format!("{}\n", self.0.remove(0)))
            }
        }
    }

    fn t0() -> Timestamp {
        "2026-11-27T09:00:00Z".parse().unwrap()
    }

    struct Home {
        _dir: tempfile::TempDir,
        home: PathBuf,
        paths: Paths,
    }

    /// A scratch home with its first generation installed.
    fn home() -> Home {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("hh");
        let paths = Paths::under(&home);
        paths.ensure().unwrap();
        drop(
            heimdall_runtime::state_store::open_locked(&paths.state_dir, Arc::new(NoFaults), t0())
                .unwrap(),
        );
        Home {
            _dir: dir,
            home,
            paths,
        }
    }

    fn ctx(home: &Home, interactive: bool) -> Ctx {
        Ctx {
            json: true,
            non_interactive: !interactive,
            home: Some(home.home.clone()),
            stdin_tty: interactive,
            request_epoch: None,
        }
    }

    fn run<F: std::future::Future<Output = Outcome>>(f: F) -> Outcome {
        crate::service_cmd::current_thread().unwrap().block_on(f)
    }

    /// Every file under `dir` with its bytes, the instance lock aside.
    fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(base, &p, out);
                } else if p.file_name().is_none_or(|n| n != "service.lock") {
                    out.insert(
                        p.strip_prefix(base).unwrap().to_string_lossy().into_owned(),
                        std::fs::read(&p).unwrap(),
                    );
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(dir, dir, &mut out);
        out
    }

    fn environment(paths: &Paths) -> heimdall_contract::ids::EnvironmentId {
        let db = layout::db_path(&paths.state_dir).unwrap();
        Store::open_read_only(&db, Arc::new(NoFaults))
            .unwrap()
            .transaction(|tx| tx.self_environment())
            .unwrap()
            .unwrap()
    }

    /// `reset_is_attended_and_says_it_creates_a_new_identity`: the disclosure says a new
    /// identity is created and lists what it orphans; non-interactive, and without the typed
    /// `reset`, nothing changes (exit 3); confirmed, a new environment ID is current at epoch
    /// 0 and the old generation is kept.
    #[test]
    fn reset_is_attended_and_says_it_creates_a_new_identity() {
        let h = home();
        let before_env = environment(&h.paths);
        let before = snapshot(&h.paths.state_dir);
        for (interactive, script) in [(false, vec!["reset"]), (true, vec!["no"]), (true, vec![])] {
            let out = run(reset_with(
                &ctx(&h, interactive),
                &mut Script(script.clone()),
                t0(),
            ));
            assert_eq!(
                out.exit,
                ExitCode::InteractionRequired,
                "{interactive} {script:?}"
            );
            assert!(out.human.contains("NEW IDENTITY"), "{}", out.human);
            assert!(
                out.human.contains("records nothing on remote hosts"),
                "{}",
                out.human
            );
            assert_eq!(snapshot(&h.paths.state_dir), before, "nothing changed");
        }
        let out = run(reset_with(&ctx(&h, true), &mut Script(vec!["reset"]), t0()));
        assert_eq!(out.exit, ExitCode::Success, "{:?}", out.env);
        let report: ResetReport = serde_json::from_value(out.env.data.clone()).unwrap();
        assert_eq!(report.generation.operation, GenerationOperation::Reset);
        assert_eq!(report.generation.restore_epoch, RestoreEpoch(0));
        assert!(report.inventory_readable);
        assert_ne!(
            report.generation.environment_id, before_env,
            "a new identity"
        );
        assert_eq!(environment(&h.paths), report.generation.environment_id);
        let kept = h
            .paths
            .state_dir
            .join("generations")
            .join(&report.left_behind);
        assert!(
            kept.join(layout::DB_FILE).is_file(),
            "the old generation is kept"
        );
    }

    /// `reset_without_any_readable_inventory_says_so_and_refuses_non_interactive`, with the
    /// interrupted purge it recovers (W3-R04): the generations are gone and the pointer is
    /// left. The reset says, in those words, that it cannot list what it leaves behind and
    /// where such residue would live; non-interactive it refuses; typing `reset` alone is not
    /// enough, the sentence is typed too; then a new generation is current and a runtime start
    /// serves it.
    #[test]
    fn reset_without_any_readable_inventory_says_so_and_refuses_non_interactive() {
        let h = home();
        std::fs::remove_dir_all(h.paths.state_dir.join("generations")).unwrap();
        assert!(matches!(
            state_refusal(&h.paths.state_dir).map(|e| e.data.error.reason),
            Some(Some(ref r)) if r == reason::STATE_CORRUPT
        ));
        let before = snapshot(&h.paths.state_dir);
        let out = run(reset_with(
            &ctx(&h, false),
            &mut Script(vec!["reset"]),
            t0(),
        ));
        assert_eq!(out.exit, ExitCode::InteractionRequired);
        assert!(out.human.contains(NO_INVENTORY_SENTENCE), "{}", out.human);
        let message = out.env.data["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            message.contains(NO_INVENTORY_SENTENCE) && message.contains("new identity"),
            "the envelope says so too: {message}"
        );
        assert!(
            out.human.contains("authorized_keys"),
            "names where residue lives"
        );
        assert_eq!(snapshot(&h.paths.state_dir), before);
        let out = run(reset_with(
            &ctx(&h, true),
            &mut Script(vec!["reset", "yes"]),
            t0(),
        ));
        assert_eq!(
            out.exit,
            ExitCode::InteractionRequired,
            "the sentence was not typed"
        );
        assert_eq!(snapshot(&h.paths.state_dir), before);
        let out = run(reset_with(
            &ctx(&h, true),
            &mut Script(vec!["reset", NO_INVENTORY_SENTENCE]),
            t0(),
        ));
        assert_eq!(out.exit, ExitCode::Success, "{:?}", out.env);
        let report: ResetReport = serde_json::from_value(out.env.data.clone()).unwrap();
        assert!(!report.inventory_readable);
        assert!(state_refusal(&h.paths.state_dir).is_none(), "recovered");
        let opened = heimdall_runtime::state_store::open_locked(
            &h.paths.state_dir,
            Arc::new(NoFaults),
            t0(),
        )
        .unwrap();
        assert_eq!(opened.current.name.as_str(), report.generation.generation);
    }

    /// `restore_is_refused_while_a_runtime_or_issuer_runs`: while the runtime's instance lock
    /// is held (a running runtime, whose child the issuer is, or another attended command),
    /// a restore, a reset and a repair are refused before anything is read, and nothing changes.
    #[test]
    fn restore_is_refused_while_a_runtime_or_issuer_runs() {
        let h = home();
        let backup = h.home.join("backup.db");
        Store::open_read_only(
            &layout::db_path(&h.paths.state_dir).unwrap(),
            Arc::new(NoFaults),
        )
        .unwrap()
        .vacuum_into(&backup)
        .unwrap();
        let before = snapshot(&h.paths.state_dir);
        let lock = heimdall_runtime::InstanceLock::try_acquire(&h.paths.state_dir).unwrap();
        for out in [
            run(restore_with(
                &ctx(&h, true),
                &backup,
                &mut Script(vec!["restore"]),
                t0(),
            )),
            run(reset_with(&ctx(&h, true), &mut Script(vec!["reset"]), t0())),
            run(repair_with(
                &ctx(&h, true),
                &mut Script(vec!["repair"]),
                t0(),
            )),
        ] {
            assert_eq!(out.env.code, Code::ServiceUnavailable, "{:?}", out.env);
            let message = out.env.data["error"]["message"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(message.contains("heimdall service stop"), "{message}");
            assert_eq!(snapshot(&h.paths.state_dir), before, "nothing changed");
        }
        drop(lock);
        // With the lock free, the same restore runs.
        let out = run(restore_with(
            &ctx(&h, true),
            &backup,
            &mut Script(vec!["restore"]),
            t0(),
        ));
        assert_eq!(out.exit, ExitCode::Success, "{:?}", out.env);
        let report: RestoreReport = serde_json::from_value(out.env.data).unwrap();
        assert_eq!(report.generation.operation, GenerationOperation::Restore);
        assert_eq!(report.generation.restore_epoch, RestoreEpoch(1));
        assert!(report.carried_forward && report.ledger_readable);
    }

    /// The restore is attended, and refuses another environment's backup with nothing changed.
    #[test]
    fn restore_is_attended_and_refuses_another_environments_backup() {
        let h = home();
        let other = home();
        let foreign = other.home.join("foreign.db");
        Store::open_read_only(
            &layout::db_path(&other.paths.state_dir).unwrap(),
            Arc::new(NoFaults),
        )
        .unwrap()
        .vacuum_into(&foreign)
        .unwrap();
        let own = h.home.join("own.db");
        Store::open_read_only(
            &layout::db_path(&h.paths.state_dir).unwrap(),
            Arc::new(NoFaults),
        )
        .unwrap()
        .vacuum_into(&own)
        .unwrap();
        let before = snapshot(&h.paths.state_dir);
        let out = run(restore_with(
            &ctx(&h, true),
            &foreign,
            &mut Script(vec!["restore"]),
            t0(),
        ));
        assert_eq!(out.env.code, Code::ConfigConflict, "{:?}", out.env);
        assert_eq!(snapshot(&h.paths.state_dir), before);
        let out = run(restore_with(
            &ctx(&h, false),
            &own,
            &mut Script(vec!["restore"]),
            t0(),
        ));
        assert_eq!(out.exit, ExitCode::InteractionRequired);
        assert!(out.human.contains("no access"), "{}", out.human);
        let out = run(restore_with(
            &ctx(&h, true),
            &own,
            &mut Script(vec!["yes"]),
            t0(),
        ));
        assert_eq!(out.exit, ExitCode::InteractionRequired);
        assert_eq!(snapshot(&h.paths.state_dir), before);
    }

    /// `state repair` is attended; a whole ledger has nothing to repair; a damaged one is
    /// repaired and the refusal it caused is gone.
    #[test]
    fn repair_is_attended_and_clears_the_ledger_refusal() {
        let h = home();
        let out = run(repair_with(
            &ctx(&h, true),
            &mut Script(vec!["repair"]),
            t0(),
        ));
        assert_eq!(out.env.code, Code::ConfigConflict, "nothing to repair");
        let ledger = heimdall_store::layout::stategen::Ledger::new(
            heimdall_store::layout::stategen::RealFs,
            &h.paths.state_dir,
        );
        for n in 1..=2u8 {
            ledger
                .append(heimdall_store::layout::stategen::Entry {
                    epoch: 0,
                    digest: [n; 32],
                })
                .unwrap();
        }
        let path = h
            .paths
            .state_dir
            .join(heimdall_store::layout::stategen::ledger::LEDGER);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[20] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            ledger_refusal(&h.paths.state_dir).and_then(|e| e.data.error.reason),
            Some(reason::LEDGER_DAMAGED.to_owned())
        );
        assert!(
            state_refusal(&h.paths.state_dir).is_none(),
            "a damaged ledger never keeps a runtime from starting"
        );
        let out = run(repair_with(
            &ctx(&h, false),
            &mut Script(vec!["repair"]),
            t0(),
        ));
        assert_eq!(out.exit, ExitCode::InteractionRequired);
        assert!(out.human.contains("could run again"), "states the residual");
        let out = run(repair_with(
            &ctx(&h, true),
            &mut Script(vec!["repair"]),
            t0(),
        ));
        assert_eq!(out.exit, ExitCode::Success, "{:?}", out.env);
        let report: RepairReport = serde_json::from_value(out.env.data).unwrap();
        assert_eq!(
            (report.fenced_records, report.restore_epoch),
            (1, RestoreEpoch(1))
        );
        assert!(ledger_refusal(&h.paths.state_dir).is_none());
    }
}
