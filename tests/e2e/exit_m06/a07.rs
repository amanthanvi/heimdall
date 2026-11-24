//! ⟨M06 W5 U7⟩ **A07's runner rows: revoke races and disconnected enforcement** (m06-plan
//! §3 row "A07 runner rows"; spec A07; R-AU-04, R-RT-02, R-SE-07), with real binaries on
//! one host. The model half of the row is U4's (`integration_runner_effects_m06`,
//! `integration_controller_driver_m06`); this is the journey.
//!
//! Driven here, one observation line each:
//!
//! * `issued`: a grant on the runner, issued by the controller, in use on the runner;
//! * `disconnected`: the management route is blocked; the controller reports the runner
//!   not connected and its issuance gated;
//! * `revoke-pending`: the owner's local revoke of the runner's grant while disconnected is
//!   one typed pending effect (`remote_pending`, target `grant_revoke`) with its residual
//!   stated, unacknowledged; nothing is applied on the runner yet (the grant still serves);
//! * `reconnect`: the route is back; the effect is delivered before anything is issued and
//!   acknowledged: nothing pending, the residual acknowledged with its counted statement,
//!   the runner's endpoint lists nothing and an onward login fails;
//! * `barrier`: issuance for the runner was gated while away and is open only after the
//!   resynchronization;
//! * `no-stale-reactivation`: the request that created the revoked grant, sent again, does
//!   not bring it back;
//! * `pause-pending`, `cutoff-pending`: disconnected again, the owner's pause and cutoff of
//!   the runner's policy are one typed pending effect each (`policy_pause`,
//!   `policy_cutoff`), not applied on the runner;
//! * `uncertain-time`: the runner is restarted with an unsynchronized clock before the
//!   route comes back: the reconnect still delivers both narrowings and they apply;
//! * `fresh-work-refused`: a fresh work ID after the reconciled pause and cutoff is refused
//!   by the runner; nothing is issued for it. (With the pause also in force and the runner's
//!   clock unsynchronized, this step shows a refusal only, not which narrowing caused it.)
//! * ⟨M06 exit⟩ `cutoff-refused`: the cutoff alone, with time certain. The runner restarts
//!   with a synchronized clock; its own owner lifts the delivered pause (`access resume
//!   runner-pol`, approved on the runner's terminal), so only the delivered, acknowledged and
//!   past cutoff is in force; a fresh work ID is then refused `POLICY_CUTOFF`, and nothing is
//!   issued for it.
//!
//! **Not driven here** (`NOT-COVERED.md`): a revoke racing an issuance in flight (model);
//! the separate runner host. ⟨`w5f`⟩ Namespaced acknowledgements between two producers are
//! T06's `effect-id-collision` step (two controllers, one effect ID, staged).

use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::GrantId;
use heimdall_domain::time::Clock as _;
use serde_json::Value;

use super::lift::at_runner;
use super::m06::{blocked, forwarded_ensure, logs, observe, runner_json};
use super::world::{HOUR, journey as start, listed_identities, onward_login};

const CASE: &str = "a07";

pub(crate) fn journey() {
    let Some(mut j) = start(|_| Vec::new(), 4 * HOUR) else {
        blocked(CASE, "no fixture sshd on this host");
        return;
    };
    let environment = j.environment.clone();
    let account = j.account.clone();

    // issued: the grant, in use on the runner.
    let (answer, _) = forwarded_ensure(&j, "job-a07", "a07-fwd-1", "1h");
    assert_eq!(answer["code"], "OK", "{answer}\n{}", logs(&j));
    let grant = GrantId::parse(answer["data"]["grant_id"].as_str().unwrap()).unwrap();
    let endpoint = answer["data"]["consumer"]["signing_endpoint"]
        .as_str()
        .unwrap()
        .to_owned();
    let listed = listed_identities(&endpoint);
    assert_eq!(listed.len(), 1, "{listed:?}");
    let dir = j.scratch.subdir("onward").unwrap();
    let (ok, out) = onward_login(&dir, &j.destination, &account, &endpoint, &listed[0]);
    assert!(ok, "{out}\n{}", logs(&j));
    j.controller
        .wait_for(&environment, "the grant is not reported", |e| {
            e["last_known_readiness"]
                .as_array()
                .is_some_and(|r| r.iter().any(|g| g["grant"] == grant.as_str()))
        });
    observe(CASE, "issued", "grant=issued onward_login=ok");

    // disconnected.
    j.reachable(false);
    j.controller.runtime_stop();
    j.controller.start();
    let away = j
        .controller
        .wait_for(&environment, "the runner is still reachable", |e| {
            e["connectivity"]["state"] != "connected"
        });
    assert_eq!(away["issuance"], "awaiting_resync", "{away}");
    observe(
        CASE,
        "disconnected",
        "connectivity=not_connected issuance=awaiting_resync",
    );

    // The three narrowings while disconnected: one typed pending effect each.
    let pending = |c: &super::world::ControllerRuntime| -> Vec<Value> {
        c.status(&environment)["remote_pending"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    };
    let revoked = j.controller.json(&["access", "revoke", grant.as_str()]);
    assert_eq!(revoked["code"], "OK", "{revoked}");
    assert_eq!(revoked["data"]["local_applied"], false, "{revoked}");
    assert_eq!(revoked["data"]["remote_pending"][0], grant.as_str());
    let after_revoke = pending(&j.controller);
    assert_eq!(after_revoke.len(), 1, "{after_revoke:?}");
    let status = j.controller.status(&environment);
    let residual = &status["residuals"][0];
    assert_eq!(residual["grant"], grant.as_str(), "{status}");
    assert_eq!(residual["acknowledged"], false, "{status}");
    assert!(
        residual["statement"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "{status}"
    );
    assert_eq!(after_revoke[0]["target"]["kind"], "grant_revoke");
    observe(
        CASE,
        "revoke-pending",
        format!(
            "local_applied=false remote_pending=1 target={} residual=stated acknowledged=false",
            after_revoke[0]["target"]["kind"].as_str().unwrap_or("none")
        ),
    );
    // Not applied on the runner yet: it still serves the grant.
    assert_eq!(listed_identities(&endpoint), listed);
    let (ok, out) = onward_login(&dir, &j.destination, &account, &endpoint, &listed[0]);
    assert!(ok, "the effects are only pending: {out}");

    // reconnect: an owner-awaited pass reconnects at once; the reconnect order delivers
    // the effects before anything else.
    j.reachable(true);
    let (replayed, _) = forwarded_ensure(&j, "job-a07", "a07-fwd-1", "1h");
    let applied = j
        .controller
        .wait_for(&environment, "the effects were not applied", |e| {
            e["remote_pending"].as_array().is_some_and(Vec::is_empty)
                && e["residuals"]
                    .as_array()
                    .is_some_and(|r| r.iter().any(|x| x["acknowledged"] == true))
        });
    assert_eq!(applied["residuals"][0]["grant"], grant.as_str());
    let statement = applied["residuals"][0]["statement"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(listed_identities(&endpoint).is_empty(), "revoked");
    let (ok, out) = onward_login(&dir, &j.destination, &account, &endpoint, &listed[0]);
    assert!(!ok, "no onward login after the revoke: {out}");
    observe(
        CASE,
        "reconnect",
        format!(
            "remote_pending=0 residual_acknowledged=true \
             residual_names_destination_clock_error={} runner_endpoint_identities=0 \
             onward_login=refused",
            statement.contains("destination-clock error")
        ),
    );

    // barrier: open only after the resynchronization.
    let open = j
        .controller
        .wait_for(&environment, "issuance did not reopen", |e| {
            e["issuance"] == "reconciled"
        });
    assert_eq!(open["connectivity"]["state"], "connected", "{open}");
    observe(
        CASE,
        "barrier",
        "while_disconnected=awaiting_resync after_resync=reconciled",
    );

    // no-stale-reactivation: the first request again does not bring the grant back.
    assert!(
        !(replayed["code"] == "OK" && !listed_identities(&endpoint).is_empty()),
        "{replayed}"
    );
    let (again, _) = forwarded_ensure(&j, "job-a07", "a07-fwd-1", "1h");
    assert!(listed_identities(&endpoint).is_empty(), "{again}");
    let after = j.controller.status(&environment);
    assert!(
        after
            .get("last_known_readiness")
            .and_then(Value::as_array)
            .is_none_or(|r| r.iter().all(|g| g["grant"] != grant.as_str())),
        "{after}"
    );
    observe(
        CASE,
        "no-stale-reactivation",
        format!(
            "same_request_again={} revoked_grant_identities=0 revoked_grant_readiness=none",
            again["code"].as_str().unwrap_or("none")
        ),
    );

    // The second round: disconnected again, the owner pauses and cuts off the runner's
    // policy; each is one more typed pending effect.
    j.reachable(false);
    j.controller.runtime_stop();
    j.controller.start();
    j.controller
        .wait_for(&environment, "the runner is still reachable", |e| {
            e["connectivity"]["state"] != "connected"
        });
    let paused = j.controller.json(&["access", "pause", "runner-pol"]);
    assert_eq!(paused["code"], "OK", "{paused}");
    let after_pause = pending(&j.controller);
    assert_eq!(after_pause.len(), 1, "{after_pause:?} {paused}");
    assert_eq!(after_pause[0]["target"]["kind"], "policy_pause");
    observe(
        CASE,
        "pause-pending",
        format!(
            "remote_pending=1 target={}",
            after_pause[0]["target"]["kind"].as_str().unwrap_or("none")
        ),
    );
    let cutoff_at =
        Timestamp::from_second(heimdall_runtime::platform::SystemClock.wall().as_second() + 5)
            .unwrap();
    let cut = j.controller.json(&[
        "access",
        "cutoff",
        "runner-pol",
        "--at",
        &cutoff_at.to_string(),
    ]);
    assert_eq!(cut["code"], "OK", "{cut}");
    let after_cutoff = pending(&j.controller);
    assert_eq!(after_cutoff.len(), 2, "{after_cutoff:?} {cut}");
    assert_eq!(after_cutoff[1]["target"]["kind"], "policy_cutoff");
    observe(
        CASE,
        "cutoff-pending",
        format!(
            "remote_pending=2 target={}",
            after_cutoff[1]["target"]["kind"].as_str().unwrap_or("none")
        ),
    );
    let policy_of = |j: &super::world::Journey| -> Value {
        let policies = runner_json(&j.runner, &["inspect", "policies"]);
        policies["data"]["items"]
            .as_array()
            .and_then(|all| all.iter().find(|p| p["policy_id"] == "runner-pol"))
            .cloned()
            .unwrap_or_else(|| panic!("the runner's policy: {policies}"))
    };
    let set = |v: &Value, field: &str| v.get(field).is_some_and(|x| !x.is_null());
    let before = policy_of(&j);
    assert!(
        !set(&before, "paused_since") && !set(&before, "cutoff_at"),
        "not applied on the runner while disconnected: {before}"
    );

    // uncertain-time: the runner restarts with an unsynchronized clock, then the route
    // comes back. The reconnect still delivers both narrowings, and they apply.
    j.runner.runtime_stop();
    j.runner.time_sync = "not_synchronized";
    j.runner.start();
    j.reachable(true);
    std::thread::sleep(Duration::from_secs(6));
    let (fresh, _) = forwarded_ensure(&j, "job-a07-fresh", "a07-fwd-2", "30m");
    assert!(
        !matches!(
            fresh["code"].as_str(),
            Some("OK" | "ACCESS_READY" | "ACCEPTED")
        ),
        "{fresh}"
    );
    j.controller
        .wait_for(&environment, "the narrowings were not applied", |e| {
            e["remote_pending"].as_array().is_some_and(Vec::is_empty)
        });
    let held = policy_of(&j);
    assert!(set(&held, "paused_since"), "{held}");
    assert!(set(&held, "cutoff_at"), "{held}");
    observe(
        CASE,
        "uncertain-time",
        "runner_time=not_synchronized remote_pending=0 policy_paused=applied \
         policy_cutoff=applied",
    );

    // fresh-work-refused: a fresh work ID after the reconciled pause and cutoff.
    observe(
        CASE,
        "fresh-work-refused",
        format!(
            "fresh_work_id={} issued=nothing",
            fresh["code"].as_str().unwrap_or("none")
        ),
    );
    let (second, _) = forwarded_ensure(&j, "job-a07-fresh-2", "a07-fwd-3", "30m");
    assert_eq!(second["code"], fresh["code"], "{second}");
    let after = j.controller.status(&environment);
    assert!(
        after.get("last_known_readiness").is_none(),
        "nothing was issued: {after}"
    );

    // cutoff-refused: the cutoff alone, after acknowledgement, with time certain.
    j.runner.runtime_stop();
    j.runner.time_sync = "synchronized";
    j.runner.start();
    j.controller
        .wait_for(&environment, "the controller did not reconnect", |e| {
            e["connectivity"]["state"] == "connected"
        });
    let asked = runner_json(
        &j.runner,
        &["--non-interactive", "access", "resume", "runner-pol"],
    );
    assert_eq!(asked["code"], "INTERACTION_REQUIRED", "{asked}");
    let decision = asked["next"]["decision_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("no decision: {asked}"))
        .to_owned();
    let (exit, lifted) = at_runner(&j, &["decision", "approve", &decision]);
    assert_eq!(lifted["code"], "OK", "exit {exit}: {lifted}");
    let only_cutoff = policy_of(&j);
    assert!(!set(&only_cutoff, "paused_since"), "{only_cutoff}");
    assert!(set(&only_cutoff, "cutoff_at"), "{only_cutoff}");
    let (cut_only, _) = forwarded_ensure(&j, "job-a07-cutoff", "a07-fwd-4", "30m");
    assert_eq!(cut_only["code"], "POLICY_CUTOFF", "{cut_only}");
    let after = j.controller.status(&environment);
    assert!(
        after.get("last_known_readiness").is_none(),
        "nothing was issued: {after}"
    );
    observe(
        CASE,
        "cutoff-refused",
        format!(
            "runner_time=synchronized remote_pending=0 policy_paused=lifted_at_runner \
             policy_cutoff=in_force fresh_work_id={} issued=nothing",
            cut_only["code"].as_str().unwrap_or("none")
        ),
    );
    drop(j);
}
