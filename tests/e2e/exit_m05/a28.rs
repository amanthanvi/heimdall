//! **A28's managed rows** (spec A28, R-AU-07, R-SE-03; ADR-0011 §6; m05-plan U8) through the
//! real binary: `run --parent-binding` and `access delegate`, the worker being this test
//! binary re-executed ([`crate::worker`]), against **two** servers that trust the world's CA,
//! each for its own pair's principal only (the different principal mapping of spec §14.3).
//! These are the real-binary versions of `managed_store::live_tests::delegation_m05`.
//!
//! * [`a28_child_subset_refusals_and_no_owner_functions`]:
//!   - **a broader or longer child is refused**: from a parent holding pair 1 only, a child
//!     asking for both pairs, and one asking for a deadline after the parent's, are each
//!     `DELEGATION_EXCEEDS_PARENT`, the program never runs and no grant is created;
//!   - **the child subset is server-enforced**: a child of a parent holding both pairs,
//!     narrowed to pair 1, logs in to pair 1's server through its own endpoint with its own
//!     grant's certificate (the key ID names the child's grant, a child of the parent's),
//!     and is refused by pair 2's server, which accepts nothing;
//!   - **the child handle has no owner functions**: the worker sees no `HEIMDALL_*` variable
//!     (no control locator reaches it) and an endpoint that lists exactly the child's one
//!     identity, none of the parent's; on that endpoint a control `hello` frame, an
//!     add-identity request (issuance in agent clothing) and an extension naming a Heimdall
//!     operation are each answered `SSH_AGENT_FAILURE` on a connection that stays usable,
//!     and they create and change nothing (pending decisions, grants, operations, events
//!     and idempotency records counted);
//!     a wider `access delegate` from the child's binding is refused, a narrower one is
//!     admitted and labelled `owner_functions: not_delegated`, `workload_isolation:
//!     shared_os_user`.
//! * [`a28_parent_end_cascades_child_login_fails`]: by **revoke** and by **cutoff** of the
//!   parent: the parent's and the child's grants leave `active`, and the child's next login,
//!   which the same server admitted before, fails.
//!
//! **After M03 E5:** the ended grants are asserted *no longer active* here; that they
//! reach `revoked` once their certificates' validity has passed is
//! `pending_e5::e5_revoked_and_stopped_managed_grants_reach_revoked_after_the_residual`.
//!
//! **Platforms.** Unix: two loopback `sshd`s. Windows: the harness's WSL sshd
//! (`HM_FIXTURE_SSHD_*`) for pair 1 and its strict WSL sshd (`HM_FIXTURE_SSHD_STRICT_*`,
//! `MaxAuthTries 3`, its authorized-keys file as the registry) for pair 2: the only second
//! server the Windows harness serves. The child's endpoint is a named pipe there (the worker
//! hands it to the in-box client as `//./pipe/<name>`).
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::time::Duration;

use heimdall_contract::ids::{BindingId, GrantId};
use serde_json::Value;

use crate::m05::{self, wait_for};
use crate::worker;
use crate::world::{World, WorldOptions};

/// A world of two pairs on two distinct servers ([`m05::second_server`]), with the
/// per-pair profiles `exit-1` and `exit-2`. The servers live in `scratch`.
fn world(scratch: &heimdall_testkit::home::Scratch) -> World {
    let (w, ca) = World::start(WorldOptions {
        pairs: 2,
        per_pair_profiles: true,
        servers: vec![m05::server(scratch), m05::second_server(scratch)],
        ..WorldOptions::default()
    });
    drop(ca);
    println!("m05 started-pid runtime {}", w.runtime_pid());
    w
}

/// `access ensure` of `profile` for `work`: `(binding, grant, data)`.
fn parent(w: &World, profile: &str, work: &str) -> (String, String, Value) {
    let d = w.ensure_on(profile, work, &format!("{work}-r"));
    (
        d["binding_id"].as_str().unwrap().to_owned(),
        d["grant_id"].as_str().unwrap().to_owned(),
        d,
    )
}

/// The `launching` record's binding (the child's) from a `run --meta-file` file.
fn launched_binding(meta: &std::path::Path) -> BindingId {
    let text = std::fs::read_to_string(meta).expect("the run records");
    let rec = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|r| r["binding_id"].is_string())
        .unwrap_or_else(|| panic!("no launching record: {text}"));
    BindingId::parse(rec["binding_id"].as_str().unwrap()).unwrap()
}

/// What the store holds that a frame must not change: pending decisions, grants,
/// operations, events and idempotency records.
fn ledger(w: &World) -> (usize, u64, u64, u64, u64) {
    m05::read(w, |tx| {
        let c = tx.table_counts()?;
        Ok((
            tx.pending_decisions()?.len(),
            c.grants,
            c.operations,
            c.events,
            c.idempotency,
        ))
    })
}

/// The control `hello` frame's body (a Heimdall IPC client message), as the in-process
/// row sends it.
fn hello_body() -> Vec<u8> {
    let hello = heimdall_contract::ipc::ClientMessage::Hello(heimdall_contract::ipc::ClientHello {
        protocol: heimdall_contract::PROTOCOL_VERSION,
        schema_version: heimdall_contract::SchemaVersion::current(),
        client: heimdall_contract::ipc::PeerInfo {
            name: "child".into(),
            version: "0".into(),
        },
        capabilities: heimdall_ipc::session::server_capabilities(),
        required: Default::default(),
        interaction: heimdall_contract::request::InteractionMode::NonInteractive,
    });
    serde_json::to_vec(&hello).unwrap()
}

/// `ssh-add -L` against `endpoint` (the parent's), bounded: the listed lines.
fn listed(endpoint: &str) -> Vec<String> {
    let mut cmd = std::process::Command::new(crate::world::openssh("ssh-add"));
    cmd.arg("-L").env_clear().env("SSH_AUTH_SOCK", endpoint);
    for k in ["SystemRoot", "PATH"] {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    #[cfg(windows)]
    for (k, v) in crate::world::openssh_startup_env() {
        cmd.env(k, v);
    }
    crate::world::run_bounded(&mut cmd, Duration::from_secs(20))
        .stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// The grants the store lists as not yet ended.
fn live_grants(w: &World) -> usize {
    m05::read(w, |tx| tx.grants_due(heimdall_contract::Timestamp::MAX)).len()
}

#[cfg(any(unix, windows))]
#[test]
fn a28_child_subset_refusals_and_no_owner_functions() {
    let scratch = heimdall_testkit::home::Scratch::new().unwrap();
    let w = world(&scratch);

    // A broader or a longer child: refused before anything exists.
    let (narrow, _, narrow_data) = parent(&w, "exit-1", "a28-narrow");
    let later = {
        let t: heimdall_contract::Timestamp =
            narrow_data["expires_at"].as_str().unwrap().parse().unwrap();
        heimdall_contract::Timestamp::from_second(t.as_second() + 3600)
            .unwrap()
            .to_string()
    };
    let grants = live_grants(&w);
    let (p1, p2) = (w.pairs[0].pair_arg(), w.pairs[1].pair_arg());
    for (what, extra) in [
        (
            "a wider scope",
            vec!["--scope", p1.as_str(), "--scope", p2.as_str()],
        ),
        (
            "a later deadline",
            vec!["--scope", p1.as_str(), "--until", later.as_str()],
        ),
    ] {
        let dir = w.subdir("refused");
        let (ran, meta) = (dir.join("ran"), dir.join("run.ndjson"));
        let mut args = vec!["--json", "--parent-binding", narrow.as_str()];
        args.extend(extra);
        let meta_arg = meta.to_str().unwrap().to_owned();
        args.extend(["--meta-file", meta_arg.as_str()]);
        let wk = w.spawn_run(&w.home.root, &args, vec![worker::signal(&ran)]);
        let out = wk.finish(Duration::from_secs(120));
        assert_ne!(out.code, 0, "{what}: {}", w.redact(&out.stderr));
        assert!(
            out.stderr.contains("DELEGATION_EXCEEDS_PARENT"),
            "{what}: {}",
            w.redact(&out.stderr)
        );
        assert!(!ran.exists(), "{what}: the program never ran");
        let record = std::fs::read_to_string(&meta).unwrap_or_default();
        assert!(!record.contains("launching"), "{what}: {record}");
    }
    assert_eq!(live_grants(&w), grants, "no grant, so no child key");

    // The child of a parent holding both pairs, narrowed to pair 1.
    let (parent_binding, parent_grant, parent_data) = parent(&w, "exit", "a28-parent");
    let parent_endpoint = parent_data["consumer"]["signing_endpoint"]
        .as_str()
        .expect("a managed binding names its signing endpoint")
        .to_owned();
    let parent_lines = listed(&parent_endpoint);
    assert_eq!(parent_lines.len(), 2, "the parent holds both pairs");
    let dir = w.subdir("child");
    let (s0, g0, s1, g1) = (
        dir.join("s0"),
        dir.join("g0"),
        dir.join("s1"),
        dir.join("g1"),
    );
    let meta = dir.join("run.ndjson");
    let (m1, m2) = (m05::marker("pair1"), m05::marker("pair2"));
    let frames = vec![
        hello_body(),
        // Add identity (17): an issuance request in agent clothing.
        vec![17, 0, 0, 0, 7, b's', b's', b'h', b'-', b'r', b's', b'a'],
        // An extension (27) naming a Heimdall-looking operation.
        [vec![27, 0, 0, 0, 8], b"issue@hm".to_vec()].concat(),
    ];
    let marks = [w.pairs[0].sshd.log_mark(), w.pairs[1].sshd.log_mark()];
    let meta_arg = meta.to_str().unwrap().to_owned();
    let mut child = w.spawn_run(
        &w.home.root,
        &[
            "--parent-binding",
            &parent_binding,
            "--scope",
            &p1,
            "--request-id",
            "a28-child",
            "--meta-file",
            &meta_arg,
        ],
        vec![
            worker::env_names(),
            worker::agent_list("own", None),
            worker::signal(&s0),
            worker::wait(&g0, Duration::from_secs(300)),
            worker::agent_frames("owner", &frames),
            worker::own_agent_login("pair1", &w.login_command(0, &m1), &m1),
            worker::own_agent_login("pair2", &w.login_command(1, &m2), &m2),
            worker::signal(&s1),
            worker::wait(&g1, Duration::from_secs(300)),
        ],
    );
    println!("m05 started-pid run-worker {}", child.pid());
    let results = child.wait_signal(&s0, Duration::from_secs(180));
    let before = ledger(&w);
    std::fs::write(&g0, b"").unwrap();
    let results_1 = child.wait_signal(&s1, Duration::from_secs(180));
    assert_eq!(ledger(&w), before, "the frames created and changed nothing");

    // No owner function reaches the worker.
    let names = worker::result(&results, "env_names", None)["names"].clone();
    let names: Vec<&str> = names
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    assert!(
        names
            .iter()
            .all(|n| !n.to_ascii_uppercase().starts_with("HEIMDALL_")),
        "no locator of the runtime reaches the worker: {names:?}"
    );
    assert!(
        w.env()
            .iter()
            .any(|(k, _)| k.to_string_lossy() == "HEIMDALL_HOME"),
        "the run's own environment did carry one (the control is real)"
    );
    let own = worker::result(&results, "agent_list", Some("own"));
    let own_lines: Vec<&str> = own["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    assert_eq!(
        own_lines.len(),
        1,
        "exactly the child's one identity: {own}"
    );
    assert!(
        parent_lines.iter().all(|p| p != own_lines[0]),
        "its own certificate"
    );
    let frames_r = worker::result(&results_1, "agent_frames", Some("owner"));
    assert!(frames_r["error"].is_null(), "{frames_r}");
    assert_eq!(
        frames_r["replies"],
        serde_json::json!([[5], [5], [5]]),
        "each frame is SSH_AGENT_FAILURE"
    );
    assert_eq!(
        frames_r["listed"], 1,
        "the connection stayed usable, one identity"
    );

    // The child's own grant, a child of the parent's, logged in to pair 1 and only there.
    let child_binding = launched_binding(&meta);
    let cb = m05::binding(&w, &child_binding);
    assert_eq!(
        cb.parent.as_ref().map(ToString::to_string),
        Some(parent_binding.clone())
    );
    let child_grant = m05::read(&w, |tx| tx.grant(&cb.grant)).unwrap();
    assert_eq!(
        child_grant.parent.as_ref().map(ToString::to_string),
        Some(parent_grant.clone())
    );
    assert_eq!(cb.scope.pairs.len(), 1, "the narrower scope");
    let r1 = worker::result(&results_1, "login", Some("pair1"));
    assert!(
        r1["exit"] == 0 && r1["marker_seen"] == true,
        "pair 1: {}",
        w.redact(&r1.to_string())
    );
    let r2 = worker::result(&results_1, "login", Some("pair2"));
    assert!(
        r2["exit"] != 0 && r2["marker_seen"] == false,
        "pair 2 refuses the child: {r2}"
    );
    let accepted = w.accepted_since(0, marks[0]);
    assert_eq!(accepted.len(), 1, "{accepted:?}");
    assert_eq!(
        m05::grant_of(&accepted[0].key_id),
        cb.grant.as_str(),
        "the child's grant authenticated, not the parent's"
    );
    assert!(
        w.accepted_since(1, marks[1]).is_empty(),
        "the second server, trusting the same CA under the other mapping, accepted nothing"
    );

    // The child's binding delegates only narrower.
    let wider = w.cli(&[
        "--json",
        "access",
        "delegate",
        "--parent",
        child_binding.as_str(),
        "--pair",
        &p1,
        "--pair",
        &p2,
        "--work-id",
        "a28-gc-wide",
        "--request-id",
        "a28-gc-wide",
    ]);
    assert_eq!(
        wider.json()["code"],
        "DELEGATION_EXCEEDS_PARENT",
        "{}",
        w.redact(&format!("{wider:?}"))
    );
    let narrower = w.cli(&[
        "--json",
        "access",
        "delegate",
        "--parent",
        child_binding.as_str(),
        "--pair",
        &p1,
        "--work-id",
        "a28-gc",
        "--request-id",
        "a28-gc",
    ]);
    let gc = narrower.json();
    assert_eq!(
        gc["code"],
        "ACCESS_READY",
        "{}",
        w.redact(&format!("{narrower:?}"))
    );
    assert_eq!(
        gc["data"]["enforcement"]["owner_functions"], "not_delegated",
        "{gc}"
    );
    assert_eq!(
        gc["data"]["enforcement"]["workload_isolation"], "shared_os_user",
        "{gc}"
    );
    let gc_end: heimdall_contract::Timestamp =
        gc["data"]["expires_at"].as_str().unwrap().parse().unwrap();
    assert!(
        gc_end <= child_grant.deadline.effective,
        "no longer than the child"
    );
    std::fs::write(&g1, b"").unwrap();
    let out = child.finish(Duration::from_secs(120));
    assert_eq!(out.code, 0, "{}", w.redact(&out.stderr));
    println!(
        "m05 observation: a28 {} subset=server_enforced wider=refused longer=refused frames=agent_failure owner_functions=not_delegated",
        crate::world::platform()
    );
    w.stop_runtime();
}

#[cfg(any(unix, windows))]
#[test]
fn a28_parent_end_cascades_child_login_fails() {
    let scratch = heimdall_testkit::home::Scratch::new().unwrap();
    let w = world(&scratch);
    let p1 = w.pairs[0].pair_arg();
    // The revoke first: a cutoff blocks the parent's policy from then on.
    for how in ["revoke", "cutoff"] {
        let (parent_binding, parent_grant, _) = parent(&w, "exit", &format!("a28-end-{how}"));
        let dir = w.subdir("child");
        let (s1, g1, s2) = (dir.join("s1"), dir.join("g1"), dir.join("s2"));
        let meta = dir.join("run.ndjson");
        let (m1, m2) = (m05::marker("before"), m05::marker("after"));
        let meta_arg = meta.to_str().unwrap().to_owned();
        let request = format!("a28-end-{how}-child");
        let mark = w.pairs[0].sshd.log_mark();
        let mut child = w.spawn_run(
            &w.home.root,
            &[
                "--parent-binding",
                &parent_binding,
                "--scope",
                &p1,
                "--request-id",
                &request,
                "--meta-file",
                &meta_arg,
            ],
            vec![
                worker::own_agent_login("before", &w.login_command(0, &m1), &m1),
                worker::signal(&s1),
                worker::wait(&g1, Duration::from_secs(300)),
                worker::own_agent_login_after("after", &w.login_command(0, &m2), &m2, "before"),
                worker::signal(&s2),
            ],
        );
        println!("m05 started-pid run-worker {}", child.pid());
        let results = child.wait_signal(&s1, Duration::from_secs(180));
        let r = worker::result(&results, "login", Some("before"));
        assert!(
            r["exit"] == 0 && r["marker_seen"] == true,
            "{how}: before: {}",
            w.redact(&r.to_string())
        );
        let cb = m05::binding(&w, &launched_binding(&meta));
        let child_grant: GrantId = cb.grant.clone();
        let accepted = w.accepted_since(0, mark);
        assert_eq!(accepted.len(), 1, "{how}: {accepted:?}");
        assert_eq!(m05::grant_of(&accepted[0].key_id), child_grant.as_str());
        let prefix = format!(
            "heimdall:{}:{}:",
            w.environment.as_str(),
            child_grant.as_str()
        );

        // ⟨W4 candidate⟩ The cutoff's instant, for the wait below.
        let cutoff_at = heimdall_contract::Timestamp::from_second(
            heimdall_contract::Timestamp::now().as_second() + 15,
        )
        .unwrap();
        match how {
            "revoke" => {
                w.revoke(&parent_grant, "a28-end-revoke-r");
            }
            _ => {
                let at = cutoff_at.to_string();
                let out = w.cli(&[
                    "--json",
                    "access",
                    "cutoff",
                    crate::world::POLICY,
                    "--at",
                    &at,
                ]);
                assert_eq!(out.code, 0, "{}", w.redact(&format!("{out:?}")));
            }
        }
        let ended = |w: &World| {
            (w.grant_state(&parent_grant) != "active"
                && w.grant_state(child_grant.as_str()) != "active")
                .then_some(())
        };
        // The claim is the child's next login, refused once the parent's end applies: at once
        // for a revocation, from the cutoff's instant for a cutoff (admission and the signing
        // gate check the bound at every use); it is asserted first. Then the stored grant
        // states, which the scheduler's pass sets (and with them the teardown of what the
        // grants own): for a revocation at once, for a cutoff at the pass it schedules for that
        // instant, within the same 90 s bound. ⟨Ruling I-26⟩ A timer wake that lands a few
        // milliseconds before the cutoff once left the states `active` until the idle bound
        // (300 s); a passed bound of a usable grant is now re-checked (`supervisor::wake_for`).
        if how == "revoke" {
            wait_for(
                &format!("{how}: the parent's and the child's grants end"),
                Duration::from_secs(90),
                || ended(&w),
            );
        } else {
            wait_for(
                &format!("{how}: the cutoff's instant passes"),
                Duration::from_secs(60),
                || {
                    (heimdall_contract::Timestamp::now().as_second() > cutoff_at.as_second() + 1)
                        .then_some(())
                },
            );
        }
        let mark = w.pairs[0].sshd.log_mark();
        std::fs::write(&g1, b"").unwrap();
        let out = child.finish(Duration::from_secs(120));
        let r = worker::result(&out.results, "login", Some("after"));
        assert!(
            r["exit"] != 0 && r["marker_seen"] == false,
            "{how}: the child's next login fails: {}",
            w.redact(&r.to_string())
        );
        let after = w.accepted_since(0, mark);
        assert!(
            after.iter().all(|c| !c.key_id.starts_with(&prefix)),
            "{how}: no accepted line for the child's grant after the parent's end: {after:?}"
        );
        let settle = std::time::Instant::now();
        wait_for(
            &format!("{how}: the parent's and the child's grants end"),
            Duration::from_secs(90),
            || ended(&w),
        );
        println!(
            "m05 observation: a28 {} parent_end={how} child_grant_state={} child_next_login=refused states_settled_after_login_s={}",
            crate::world::platform(),
            w.grant_state(child_grant.as_str()),
            settle.elapsed().as_secs()
        );
    }
    w.stop_runtime();
}
