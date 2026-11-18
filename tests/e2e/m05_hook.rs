//! ⟨M05⟩ The shell hook warms the personal default (orchestrator ruling I-13, option 2;
//! ADR-0011 §3.2 (a), §10 item 3, R4) through the **real binary** (`HEIMDALL_E2E_BIN`, else
//! `CARGO_BIN_EXE_heimdall`), its CLI-started runtime and its **real** `internal issuer`
//! child, and the **system `ssh`** through the projection's ordinary alias against a real
//! loopback `sshd`.
//!
//! Cargo test target `e2e_hook_m05`, hosted by `heimdall`. The scaffolding is the exit
//! suite's [`world`] (a scratch home, the managed runtime, one pair on one server trusting
//! the run's CA for that pair's principal only; see `exit_m03/world.rs`). The world's
//! personal policy `exit-pol` is made the environment's `default` by seeding the store
//! (as the world seeds it), so no decision is ever raised for it: the decision rows that
//! exist are the world's own, from its attended setup, and none is pending when a test
//! begins. No default-profile preference is set, so the hook's own `ensure` in a directory
//! outside any workspace finds nothing to activate (`none`) and only the warm-up can
//! activate anything.
//!
//! * [`hook_warms_the_default_so_the_first_ordinary_ssh_logs_in`]: the ordinary alias's
//!   slot is free and no decision is pending; `activate --hook` in a directory outside any
//!   workspace (its answer and exit status as before, nothing on stderr) activates the
//!   default's covered scope as work `default:<env>:1`, whose binding holds the slot, with
//!   one `activated` event; the **first** ordinary `ssh` then logs in with that work's
//!   certificate, and the decision rows stay as they were (none added, none pending).
//! * [`hook_warm_up_creates_no_decision_when_the_default_does_not_cover`]: with no default
//!   policy, and then with the default paused, the hook prints only its usual answer,
//!   exits 0, adds no decision row, activates nothing and leaves the slot free (the
//!   paused case records one `blocked` event, so the warm-up did reach the endpoint).
//! * [`hook_without_a_runtime_prints_nothing_and_starts_none`] (every platform): with no
//!   runtime, the hook and its warm-up print nothing, exit 0 within the budget, and start
//!   and create nothing (the Heimdall home is never created).
//!
//! **Platforms.** The two journeys are Unix only (a loopback `sshd`, Unix sockets). Native
//! Windows has no shell integration (owner question Q6; ruling I-13 keeps its first-use
//! limitation): they are `blocked` there, as the U5 live journeys are.
//!
//! **Isolation** is the world's: a cleared environment, a scratch `HOME` and Heimdall home,
//! stdin closed, the decoy agent; no owner key, agent, keychain or `~/.ssh` is touched. Only
//! processes this test started are stopped (the runtime through `service stop` on its own
//! scratch home).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    missing_docs
)]
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

#[cfg(unix)]
#[path = "exit_m03/procs.rs"]
mod procs;
#[cfg(unix)]
#[path = "exit_m03/world.rs"]
mod world;

#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use heimdall_contract::event::{EventFilter, EventType};
#[cfg(unix)]
use heimdall_contract::ids::{AccountName, BindingId, DestinationId, PolicyId};
#[cfg(unix)]
use heimdall_contract::trust::{ActivationEventKind, ActivationEventPayload};
#[cfg(unix)]
use heimdall_domain::managed::SlotState;
#[cfg(unix)]
use heimdall_domain::policy::PolicyRevision;
#[cfg(unix)]
use heimdall_domain::scope::AccessPair;
#[cfg(unix)]
use world::{Out, World, WorldOptions};

/// The world's one pair.
#[cfg(unix)]
fn the_pair(w: &World) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(&w.pairs[0].destination).unwrap(),
        account: AccountName::parse(&w.pairs[0].account).unwrap(),
    }
}

/// The world's personal policy.
#[cfg(unix)]
fn policy() -> PolicyId {
    PolicyId::parse(world::POLICY).unwrap()
}

/// Mark the world's personal policy as the environment's `default` (a new revision; its
/// pause, if any, is kept). Seeded, as the world seeds it: no decision is raised for it.
#[cfg(unix)]
fn make_default(w: &World) {
    w.open_store()
        .transaction(|tx| {
            let mut p = tx.policy(&policy())?.expect("the world's policy");
            p.default = true;
            p.revision = PolicyRevision(p.revision.0 + 1);
            tx.upsert_policy(&p, false).map(drop)
        })
        .unwrap();
}

/// Every decision row, whatever its state, and how many are pending.
#[cfg(unix)]
fn decisions(w: &World) -> (u64, usize) {
    w.open_store()
        .transaction(|tx| {
            let all = tx.table_counts()?.decisions;
            Ok((all, tx.pending_decisions()?.len()))
        })
        .unwrap()
}

/// The ordinary alias's slot.
#[cfg(unix)]
fn slot(w: &World) -> SlotState {
    let pair = the_pair(w);
    w.open_store()
        .transaction(|tx| tx.slot(&w.environment, &pair))
        .unwrap()
}

/// The activation events recorded so far, oldest first.
#[cfg(unix)]
fn activation_events(w: &World) -> Vec<ActivationEventPayload> {
    let filter = EventFilter {
        operation_id: None,
        types: vec![EventType::Activation],
    };
    w.open_store()
        .transaction(|tx| tx.events_after(&w.environment, 0, &filter, 1000))
        .unwrap()
        .events
        .into_iter()
        .map(|e| serde_json::from_value(e.payload).unwrap())
        .collect()
}

/// The bindings of the default endpoint's work `n` (`default:<env>:<n>`): `(binding,
/// grant)`.
#[cfg(unix)]
fn default_work(w: &World, n: u64) -> Vec<(BindingId, String)> {
    let work = heimdall_app::operations::default_work_id(&w.environment, n).unwrap();
    w.open_store()
        .transaction(|tx| tx.bindings_for_work(&w.environment, &work))
        .unwrap()
        .into_iter()
        .map(|b| (b.id, b.grant.as_str().to_owned()))
        .collect()
}

/// `activate --hook --cwd <dir>` as the shell integration runs it (stdin closed; the test
/// process stands for the shell): the output and how long it took.
#[cfg(unix)]
fn hook(w: &World, dir: &std::path::Path) -> (Out, Duration) {
    let pid = std::process::id().to_string();
    let start = Instant::now();
    let out = w.cli(&[
        "activate",
        "--hook",
        "--cwd",
        dir.to_str().unwrap(),
        "--shell-pid",
        &pid,
    ]);
    (out, start.elapsed())
}

/// The hook's answer outside any workspace with no default-profile preference, exactly as
/// before the warm-up existed: `none 0 0`, nothing on stderr, exit 0.
#[cfg(unix)]
fn assert_answer_unchanged(w: &World, out: &Out, took: Duration) {
    assert_eq!(out.code, 0, "{}", w.redact(&format!("{out:?}")));
    assert_eq!(
        out.stdout,
        "none 0 0\n",
        "{}",
        w.redact(&format!("{out:?}"))
    );
    assert_eq!(out.stderr, "", "nothing printed: {}", w.redact(&out.stderr));
    assert!(
        took < Duration::from_secs(3),
        "the hook stays within its budget (process start included): {took:?}"
    );
}

/// Ruling I-13, option 2: with the hook, the **first** ordinary `ssh` after a free-slot
/// period logs in. Before the hook the slot is free and no decision is pending; the hook (in a
/// directory outside any workspace, so its own answer is `none`) warms the personal default
/// through the environment endpoint: work `default:<env>:1` holds the slot under `exit-pol`
/// with one `activated` event and no decision row added; the first `ssh` through the projection's
/// ordinary alias then logs in with that work's certificate.
#[cfg(unix)]
#[test]
fn hook_warms_the_default_so_the_first_ordinary_ssh_logs_in() {
    let (w, ca) = World::start(WorldOptions {
        pairs: 1,
        ..WorldOptions::default()
    });
    drop(ca);
    make_default(&w);
    assert!(
        matches!(slot(&w), SlotState::Free { .. }),
        "the ordinary alias's slot is free before the hook: {:?}",
        slot(&w)
    );
    // The world's own decision rows (from its attended setup), none of them pending.
    let base = decisions(&w);
    assert_eq!(base.1, 0, "no pending decision before the hook");
    assert!(activation_events(&w).is_empty());
    assert!(default_work(&w, 1).is_empty(), "no default work yet");

    let shell = w.subdir("shell");
    let (out, took) = hook(&w, &shell);
    assert_answer_unchanged(&w, &out, took);
    let held_at_return = matches!(slot(&w), SlotState::Held { .. });

    // The activation runs in the runtime whether or not the hook still waits (ruling 7):
    // wait (bounded) until it settles, as the moment before the user types `ssh`.
    let start = Instant::now();
    let binding = loop {
        if let SlotState::Held { binding, .. } = slot(&w) {
            break binding;
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "the warm-up activated nothing: slot {:?}, events {:?}",
            slot(&w),
            activation_events(&w)
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    println!(
        "m05 observation: hook {} warm-up: the hook took {} ms; the slot was held when it returned: {held_at_return}; held {} ms later",
        world::platform(),
        took.as_millis(),
        start.elapsed().as_millis()
    );
    let work = default_work(&w, 1);
    assert_eq!(work.len(), 1, "one binding of work default:<env>:1");
    let (b, grant) = &work[0];
    assert_eq!(*b, binding, "the default work's binding holds the slot");
    let events = activation_events(&w);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].kind, ActivationEventKind::Activated);
    assert_eq!(events[0].policy_id, Some(policy()));
    assert_eq!(events[0].workspace_id, None, "personal context");
    assert_eq!(decisions(&w), base, "the warm-up created no decision");

    // The first ordinary `ssh`: the projection's alias alone (no `run`, no binding of its
    // own), and it logs in with the default work's certificate.
    let marker = format!("hm-hook-{}", heimdall_testkit::agent::random_hex(6));
    let mark = w.pairs[0].sshd.log_mark();
    let login = w.projection_login(0, &marker);
    assert!(
        login.code == 0 && login.stdout.lines().any(|l| l.trim() == marker),
        "the first ordinary ssh logs in: {}",
        w.redact(&format!("{login:?}"))
    );
    let accepted = w.accepted_since(0, mark);
    assert_eq!(accepted.len(), 1, "one accepted login: {accepted:?}");
    assert!(
        accepted[0]
            .key_id
            .starts_with(&format!("heimdall:{}:{grant}:", w.environment.as_str())),
        "with the default work's certificate: {}",
        accepted[0].key_id
    );
    assert_eq!(accepted[0].ca_fingerprint, w.ca_fingerprint.as_str());
    assert_eq!(decisions(&w), base, "no decision after the login either");
    assert_eq!(activation_events(&w).len(), 1, "no second activation");
}

/// The warm-up never creates a decision and never activates what the default does not
/// cover: with **no default policy**, and then with the default **paused**, the hook's
/// answer, stderr and exit status are as before, no decision row is added, the slot stays
/// free and no `activated` event exists. The paused case records one `blocked` event
/// (`policy_paused`): the warm-up reached the endpoint and was refused at once.
#[cfg(unix)]
#[test]
fn hook_warm_up_creates_no_decision_when_the_default_does_not_cover() {
    let (w, ca) = World::start(WorldOptions {
        pairs: 1,
        ..WorldOptions::default()
    });
    drop(ca);
    let shell = w.subdir("shell");
    // The world's own settled decisions, and none pending.
    let base = decisions(&w);
    assert_eq!(base.1, 0);

    // No default policy.
    let (out, took) = hook(&w, &shell);
    assert_answer_unchanged(&w, &out, took);
    assert_eq!(decisions(&w), base, "no decision without a default");
    assert!(matches!(slot(&w), SlotState::Free { .. }), "{:?}", slot(&w));
    assert!(
        activation_events(&w).is_empty(),
        "{:?}",
        activation_events(&w)
    );
    assert!(default_work(&w, 1).is_empty());

    // The default, paused (a targeted pause is immediate and never a decision).
    let paused = w.cli(&["--json", "access", "pause", world::POLICY]);
    assert_eq!(paused.code, 0, "{}", w.redact(&format!("{paused:?}")));
    make_default(&w);
    assert_eq!(decisions(&w), base);
    let (out, took) = hook(&w, &shell);
    assert_answer_unchanged(&w, &out, took);
    let start = Instant::now();
    let events = loop {
        // The `blocked` event is recorded off the caller's path: wait (bounded).
        let e = activation_events(&w);
        if !e.is_empty() || start.elapsed() > Duration::from_secs(10) {
            break e;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].kind, ActivationEventKind::Blocked);
    assert_eq!(events[0].policy_id, Some(policy()));
    assert_eq!(events[0].reason.as_deref(), Some("policy_paused"));
    assert_eq!(decisions(&w), base, "no decision for a paused default");
    assert!(matches!(slot(&w), SlotState::Free { .. }), "{:?}", slot(&w));
    assert!(default_work(&w, 1).is_empty(), "nothing activated");
}

/// The hook with **no runtime** (every platform): its warm-up finds no endpoint, so the
/// hook prints nothing at all (its `unavailable` answer is silent), exits 0 within its
/// budget, and starts and creates nothing: the Heimdall home it names is never created.
#[test]
fn hook_without_a_runtime_prints_nothing_and_starts_none() {
    let scratch = tempfile::tempdir().unwrap();
    let hh = scratch.path().join("hh");
    let account = scratch.path().join("acct");
    let shell = scratch.path().join("shell");
    std::fs::create_dir_all(&account).unwrap();
    std::fs::create_dir_all(&shell).unwrap();
    let bin = std::env::var_os("HEIMDALL_E2E_BIN")
        .filter(|p| !p.is_empty())
        .map_or_else(
            || std::path::PathBuf::from(env!("CARGO_BIN_EXE_heimdall")),
            std::path::PathBuf::from,
        );
    let mut cmd = std::process::Command::new(bin);
    cmd.args(["activate", "--hook", "--cwd"])
        .arg(&shell)
        .args(["--shell-pid", &std::process::id().to_string()])
        .env_clear()
        .env("HEIMDALL_HOME", &hh)
        .env("HOME", &account)
        .current_dir(&shell)
        .stdin(std::process::Stdio::null());
    if cfg!(windows) {
        for k in ["SystemRoot", "PATH", "TEMP", "TMP"] {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
    } else {
        cmd.env("PATH", "/usr/bin:/bin");
    }
    let start = std::time::Instant::now();
    let out = cmd.output().expect("spawn heimdall");
    let took = start.elapsed();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    heimdall_testkit::assert_no_canary(&stdout);
    heimdall_testkit::assert_no_canary(&stderr);
    assert_eq!(out.status.code(), Some(0), "{stdout} {stderr}");
    assert_eq!(stdout, "", "nothing on stdout");
    assert_eq!(stderr, "", "nothing on stderr");
    assert!(took < std::time::Duration::from_secs(3), "{took:?}");
    assert!(
        !hh.exists(),
        "no runtime was started and nothing was created"
    );
}
