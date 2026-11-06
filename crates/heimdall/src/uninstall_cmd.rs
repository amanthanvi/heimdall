//! `heimdall uninstall [--purge-state]` (m02-plan U9; ADR-0007 §5.5; Q6 as qualified by
//! §12.2 item 11).
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
//! database with its counts of operations, grants, decisions and catalog records, the
//! backups, and the conflict and quarantine copies it leaves alone) and asks for a typed
//! `y`/`yes`. A non-TTY stdin, `--non-interactive` (which never stands in for the typed
//! answer, unlike `doctor --allow-config-commands`), end of input, an interruption, the
//! prompt timeout and any other answer end the command at once with exit 3
//! `INTERACTION_REQUIRED` (raised by this client, so with no `decision_ref`): nothing was
//! changed and everything is kept.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_contract::envelope::{EffectStatus, Envelope, reason};
use heimdall_contract::request::{InspectSubject, Request, ShutdownRequest};
use heimdall_contract::setup::{RemainingArtifact, RemainingArtifactKind};
use heimdall_contract::{Code, ExitCode};
use heimdall_store::{NoFaults, Store};

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
    block(ctx, uninstall(ctx, args.purge_state, &mut TerminalPrompt))
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
    counts: Result<Counts, &'static str>,
    /// The snapshots under `<state>/backups`, as displayed.
    backups: Vec<String>,
    /// Conflict files and non-empty quarantine directories: never removed by a purge
    /// (their presence makes it refuse), listed so the owner sees what stays.
    kept: Vec<String>,
}

/// The state database's records, counted from the store opened read-only. The store
/// exposes no count of every row, so these are the records it lists: every operation,
/// the grants that are not terminal, the decisions that are pending, and the catalog's
/// identities, destinations and profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counts {
    operations: u64,
    live_grants: u64,
    pending_decisions: u64,
    identities: u64,
    destinations: u64,
    profiles: u64,
}

/// Count the records of the database at `db` (read-only: nothing is created, migrated
/// or repaired, and no runtime is started). `Err` names the failure's class, never a
/// path or the store's own text.
fn read_counts(db: &Path) -> Result<Counts, &'static str> {
    let store = Store::open_read_only(db, Arc::new(NoFaults))
        .map_err(|_| "the database could not be opened read-only")?;
    let n = |len: usize| u64::try_from(len).unwrap_or(u64::MAX);
    store
        .transaction(|tx| {
            Ok(Counts {
                operations: tx.operation_counts()?.iter().map(|(_, n)| *n).sum(),
                live_grants: n(tx.grants_due(heimdall_contract::Timestamp::MAX)?.len()),
                pending_decisions: n(tx.pending_decisions()?.len()),
                identities: n(tx.identities()?.len()),
                destinations: n(tx.destinations()?.len()),
                profiles: n(tx.profiles()?.len()),
            })
        })
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
                "    operations: {} (all states)\n    grants: {} (not ended)\n    decisions: {} (pending)\n    catalog records: {} identities, {} destinations, {} profiles\n",
                c.operations,
                c.live_grants,
                c.pending_decisions,
                c.identities,
                c.destinations,
                c.profiles
            )),
            Err(why) => out.push_str(&format!(
                "    operations, grants, decisions and catalog records: not counted ({why}); they are discarded with it\n"
            )),
        }
        out.push_str(
            "    It also holds the standing policies, the tombstones, the history of decisions and grants, the audit events and the recovery records, and the records this uninstall adds; all of them go too.\n",
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

async fn uninstall<P: Prompter>(ctx: &Ctx, purge: bool, prompt: &mut P) -> Outcome {
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
    // Before anything is started or changed (ADR-0007 §12.31 item 1): a purge is shown
    // and confirmed first, so any answer but a typed yes leaves everything as it was.
    if purge
        && let Err(refused) =
            confirm_purge(ctx, prompt, || Discard::read(ctx, &paths.state_dir, &dirs)).await
    {
        return refused;
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
    out
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
            counts: Ok(Counts {
                operations: 7,
                live_grants: 2,
                pending_decisions: 1,
                identities: 3,
                destinations: 4,
                profiles: 5,
            }),
            backups: vec!["~/state/backups/ssh_config.20260101T000000Z.orig".to_owned()],
            kept: vec!["~/.ssh/config.hm-conflict-1".to_owned()],
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
            "grants: 2 (not ended)",
            "decisions: 1 (pending)",
            "3 identities, 4 destinations, 5 profiles",
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
                "not counted (the records could not be read); they are discarded with it"
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
        assert_eq!(
            read_counts(&db),
            Ok(Counts {
                operations: 0,
                live_grants: 0,
                pending_decisions: 0,
                identities: 0,
                destinations: 0,
                profiles: 0,
            })
        );
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
}
