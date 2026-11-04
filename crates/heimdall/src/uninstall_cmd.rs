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

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use heimdall_contract::envelope::{EffectStatus, Envelope, reason};
use heimdall_contract::request::{InspectSubject, Request, ShutdownRequest};
use heimdall_contract::setup::{RemainingArtifact, RemainingArtifactKind};
use heimdall_contract::{Code, ExitCode};

use crate::cli::{TerminalPrompt, UninstallArgs};
use crate::client::Ctx;
use crate::output;
use crate::setup_cmd::{
    Outcome, block, entries, inspect, request_id, rollback_intent, session, shown,
};

/// How long uninstall waits for the cleaner to confirm the projection resources absent.
const CLEANUP_WAIT: Duration = Duration::from_secs(15);

/// How long uninstall waits for the runtime to remove its advertisement.
const STOP_WAIT: Duration = Duration::from_secs(20);

/// Handle `uninstall` (module docs).
pub(crate) fn run(ctx: &Ctx, args: UninstallArgs) -> ExitCode {
    block(ctx, uninstall(ctx, args.purge_state))
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

async fn uninstall(ctx: &Ctx, purge: bool) -> Outcome {
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
        let out = crate::setup_cmd::setup_flow(
            &mut client,
            &mut TerminalPrompt,
            ctx,
            &rollback_intent(false),
            rid,
        )
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
    let deadline = Instant::now() + STOP_WAIT;
    while Instant::now() < deadline {
        if matches!(
            heimdall_runtime::instance::InstanceInfo::read_valid(&paths.runtime_dir),
            Ok(None)
        ) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
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
