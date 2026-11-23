//! ⟨M06 W5 `w5m` L4⟩ **The lift of a delivered cutoff on a runner with no standing policy**
//! (ADR-0012 §7.4 ⟨2026-11-22⟩ "The in-force flag"; ADR-0006 §18.9 item 4), with real
//! binaries on one host. Observation lines: `m06 observation: lift <step>: <result>`.
//!
//! **The world** is the shared grant world (`world::journey`). Its runner is made
//! policy-less as a stated fixture step: its runtime is stopped, every seeded standing
//! policy is deleted from its state store, and it is started again. No product command
//! removes a standing policy.
//!
//! Driven here, one observation line each:
//!
//! * `baseline`: on the policy-less runner the controller's forwarded request is held for
//!   the runner's own owner (a grant beyond standing policy), approved on the runner's
//!   terminal, and then issued (`OK`): what "issuance resumes" must return to;
//! * `cutoff-all`: the controller's owner cuts off every policy (`access cutoff --all`):
//!   delivered and acknowledged, in force on the runner although it names no policy
//!   there; the controller's request for fresh work, admitted by the runner's own owner,
//!   is then **not issued**: it stays `ACCEPTED`, awaiting the controller's issuer;
//! * `ack-alone`: the owner's acknowledgement alone (`environment resume-issuance` on the
//!   controller's terminal, before any lift) resumes nothing: still not issued;
//! * `paired-cannot-lift`: nothing the controller sends lifts it; the runner's own
//!   unattended owner cannot either (the request needs a decision, nothing is lifted);
//! * `lift`: the runner's own owner clears the cutoff of exactly that scope on a terminal
//!   (`access cutoff --clear --all`); the approval text names the delivered effect (its
//!   scope, the controller that delivered it and when); after the typed `yes` the effect is
//!   no longer in force, and the controller's request answers as at `baseline` again.
//!
//! The other order (the lift first, then the acknowledgement) is T06's
//! (`lift-at-runner`, `first-acknowledges`).

use std::sync::Arc;

use heimdall_store::{NoFaults, Store};
use serde_json::Value;

use super::m06::{blocked, observe, runner_json};
use super::world::{HOUR, Journey, journey as start, on_terminal, state_db};

const CASE: &str = "lift";

/// The runner's local owner on a terminal: `heimdall --json <args…>`, typing `yes`.
fn at_runner(j: &Journey, args: &[&str]) -> (i32, Value) {
    let path = |p: &std::path::Path| p.to_string_lossy().into_owned();
    on_terminal(
        &j.runner.home,
        &[
            ("HOME", path(&j.runner.account)),
            ("HEIMDALL_HOME", path(&j.runner.home)),
            ("HEIMDALL_TEST_SSH_HOME", path(&j.runner.account)),
            ("HEIMDALL_TEST_TIME_SYNC", "synchronized".to_owned()),
        ],
        args,
        Some("yes"),
    )
}

/// The controller's forwarded `ensure` for fresh work, taken as far as it goes. A runner
/// with no standing policy holds the request for its own owner's decision (the grant is
/// beyond standing policy): that decision is approved on the runner's terminal and the
/// request repeated with the same request ID. The answer as it stands after a short wait:
/// issued (`OK`), or whatever kept it from being issued.
fn ensure(j: &Journey, n: u8) -> Value {
    let (work, request) = (format!("job-lift-{n}"), format!("lift-{n}"));
    let args = [
        "access",
        "ensure",
        "--profile",
        "runner-profile",
        "--environment",
        j.environment.as_str(),
        "--work-id",
        work.as_str(),
        "--for",
        "1h",
        "--request-id",
        request.as_str(),
    ];
    let mut answer = j.controller.json(&args);
    if answer["code"] == "INTERACTION_REQUIRED"
        && let Some(decision) = answer["next"]["decision_ref"].as_str()
    {
        let (exit, approved) = at_runner(j, &["decision", "approve", decision]);
        assert_eq!(approved["code"], "OK", "exit {exit}: {approved}");
        answer = j.controller.json(&args);
    }
    if answer["code"] != "ACCEPTED" {
        return answer;
    }
    let operation = answer["operation_id"].as_str().unwrap().to_owned();
    j.controller
        .json(&["operation", "wait", &operation, "--timeout-ms", "8000"])
}

/// What an answer is, for comparing two of them: its code and its reason.
fn shape(v: &Value) -> String {
    format!(
        "{}/{}",
        v["code"].as_str().unwrap_or("none"),
        v["data"]["error"]["reason"].as_str().unwrap_or("none")
    )
}

/// The in-force flags of the runner's delivered revisions (read-only, from its store).
fn in_force(j: &Journey) -> Vec<bool> {
    Store::open_read_only(&state_db(&j.runner.home), Arc::new(NoFaults))
        .unwrap()
        .transaction(|tx| tx.remote_policy_revisions())
        .unwrap()
        .iter()
        .map(|r| r.in_force)
        .collect()
}

pub(crate) fn journey() {
    let Some(mut j) = start(|_| Vec::new(), 4 * HOUR) else {
        blocked(CASE, "no fixture sshd on this host");
        return;
    };
    let environment = j.environment.clone();
    // The fixture step: a runner with no standing policy.
    j.runner.runtime_stop();
    {
        let store = Store::open(&state_db(&j.runner.home), Arc::new(NoFaults)).unwrap();
        let removed = store
            .transaction(|tx| {
                let mut n = 0;
                for p in tx.policies()? {
                    if tx.delete_policy(&p.id)? {
                        n += 1;
                    }
                }
                Ok(n)
            })
            .unwrap();
        assert!(removed >= 1, "the runner's seeded policies");
        assert!(store.transaction(|tx| tx.policies()).unwrap().is_empty());
    }
    j.runner.start();
    j.controller
        .wait_for(&environment, "the controller did not reconnect", |e| {
            e["connectivity"]["state"] == "connected"
        });
    let baseline = ensure(&j, 0);
    assert_eq!(
        baseline["code"],
        "OK",
        "{baseline}\n{}",
        super::m06::logs(&j)
    );
    observe(
        CASE,
        "baseline",
        format!(
            "runner_standing_policies=0(fixture:deleted_while_stopped) controller_request={}",
            shape(&baseline)
        ),
    );

    // cutoff-all.
    let at = heimdall_contract::Timestamp::from_second(
        heimdall_contract::Timestamp::now().as_second() + 2,
    )
    .unwrap();
    let cut = j
        .controller
        .json(&["access", "cutoff", "--all", "--at", &at.to_string()]);
    assert_eq!(cut["code"], "OK", "{cut}\n{}", j.controller.stderr());
    j.controller
        .wait_for(&environment, "the cutoff was not acknowledged", |e| {
            e["remote_pending"].as_array().is_some_and(Vec::is_empty)
        });
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert_eq!(in_force(&j), vec![true]);
    let refused = ensure(&j, 1);
    // Admitted by the runner's own owner, and then not issued: it awaits the issuer.
    assert_eq!(refused["code"], "ACCEPTED", "{refused}");
    assert_eq!(
        refused["data"]["refresh_dependency"], "controller",
        "{refused}"
    );
    observe(
        CASE,
        "cutoff-all",
        "by=controller_cli scope=all runner_standing_policies=0 delivered=true in_force=true \
         controller_request=ACCEPTED_pending_not_issued(admitted_by_runner_owner;awaits_issuer)",
    );

    // ack-alone.
    let (exit, acked) = j.controller.attended_at(
        &["environment", "resume-issuance", environment.as_str()],
        "Type yes to continue:",
        Some("yes"),
    );
    assert_eq!(acked["code"], "OK", "exit {exit}: {acked}");
    let still = ensure(&j, 2);
    assert_eq!(still["code"], "ACCEPTED", "{still}");
    assert_eq!(in_force(&j), vec![true]);
    observe(
        CASE,
        "ack-alone",
        "by=controller_owner_on_terminal command=environment_resume_issuance typed=yes \
         runner_reports=in_force controller_request=ACCEPTED_pending_not_issued",
    );

    // paired-cannot-lift: the controller's own clear names its own policies and lifts
    // nothing on the runner; the runner's unattended owner gets no lift either.
    let unattended = runner_json(
        &j.runner,
        &["--non-interactive", "access", "cutoff", "--clear", "--all"],
    );
    assert_ne!(unattended["code"], "OK", "{unattended}");
    assert_eq!(in_force(&j), vec![true]);
    assert_eq!(ensure(&j, 3)["code"], "ACCEPTED");
    observe(
        CASE,
        "paired-cannot-lift",
        format!(
            "runner_unattended_owner_clear={} in_force=true controller_request=ACCEPTED_pending_not_issued",
            unattended["code"].as_str().unwrap_or("none")
        ),
    );

    // lift.
    let (exit, lifted) = at_runner(&j, &["access", "cutoff", "--clear", "--all"]);
    assert_eq!(lifted["code"], "OK", "exit {exit}: {lifted}");
    assert_eq!(in_force(&j), vec![false]);
    let resumed = ensure(&j, 4);
    assert_eq!(
        shape(&resumed),
        shape(&baseline),
        "the request does not answer as before the cutoff: {resumed}"
    );
    assert_eq!(resumed["code"], "OK", "{resumed}");
    assert_eq!(lifted["data"]["changed"], true, "{lifted}");
    assert_eq!(lifted["data"]["target"]["kind"], "all", "{lifted}");
    observe(
        CASE,
        "lift",
        format!(
            "by=runner_local_owner_on_terminal command=access_cutoff_clear_all typed=yes \
             in_force=false acknowledged=earlier controller_request={} (as_at_baseline)",
            shape(&resumed)
        ),
    );
    drop(j);
}

/// ⟨M06 W5 `w5s`, M06-W5-R01⟩ **The lift of a delivered pause of a policy the runner holds**,
/// through the ordinary `access resume <policy>` (the untargeted form), with real binaries.
/// Observation lines: `m06 observation: lift-held <step>: <result>`.
///
/// * `issued-before`: ⟨M06 W5 `w5u`⟩ the runner's own owner pauses the policy locally and
///   asks `access resume runner-pol` before anything is delivered: a decision naming no
///   delivered effect;
/// * `pause-delivered`: the controller's owner pauses the runner's policy (`access pause
///   runner-pol`); delivered, applied (the runner's policy is paused) and in force;
/// * `stale`: the decision issued before the delivery is approved on the runner's terminal:
///   `DECISION_STALE` (exit 6, `next: fix_request`), naming the extra lift; the policy is
///   still paused and the delivered pause still in force;
/// * `named`: the runner's unattended owner's `access resume runner-pol` writes a decision
///   (`INTERACTION_REQUIRED`) and nothing else; `inspect decisions` on the runner shows it
///   naming the delivered pause (its scope key, kind, the delivering controller and when),
///   and it is still in force;
/// * `lift`: the runner's own owner approves that decision on a terminal (typed `yes`):
///   the policy is active and the delivered pause is no longer in force.
pub(crate) fn held_policy_journey() {
    const CASE: &str = "lift-held";
    let Some(j) = start(|_| Vec::new(), 4 * HOUR) else {
        blocked(CASE, "no fixture sshd on this host");
        return;
    };
    let environment = j.environment.clone();
    let runner_policy = |j: &Journey| -> Value {
        let policies = runner_json(&j.runner, &["inspect", "policies"]);
        policies["data"]["items"]
            .as_array()
            .and_then(|all| all.iter().find(|p| p["policy_id"] == "runner-pol"))
            .cloned()
            .unwrap_or_else(|| panic!("the runner's policy: {policies}"))
    };
    let paused = |v: &Value| v.get("paused_since").is_some_and(|x| !x.is_null());

    // issued-before: a decision made while nothing is delivered names no lift.
    let local = runner_json(&j.runner, &["access", "pause", "runner-pol"]);
    assert_eq!(local["code"], "OK", "{local}");
    let early = runner_json(
        &j.runner,
        &["--non-interactive", "access", "resume", "runner-pol"],
    );
    assert_eq!(early["code"], "INTERACTION_REQUIRED", "{early}");
    let early = early["next"]["decision_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("no decision: {early}"))
        .to_owned();
    observe(
        CASE,
        "issued-before",
        "by=runner_owner command=access_pause_then_access_resume_runner_pol \
         answer=INTERACTION_REQUIRED delivered=none",
    );

    // pause-delivered: once the controller has the runner's report (which lists its
    // policy), the controller's `access pause runner-pol` is a delivered effect.
    j.controller
        .wait_for(&environment, "the controller did not connect", |e| {
            e["connectivity"]["state"] == "connected"
        });
    let mut pause = Value::Null;
    for _ in 0..40 {
        pause = j.controller.json(&["access", "pause", "runner-pol"]);
        if pause["code"] != "NOT_FOUND" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    assert_eq!(pause["code"], "OK", "{pause}\n{}", j.controller.stderr());
    j.controller
        .wait_for(&environment, "the pause was not acknowledged", |e| {
            e["remote_pending"].as_array().is_some_and(Vec::is_empty)
        });
    assert!(paused(&runner_policy(&j)), "{}", runner_policy(&j));
    assert_eq!(in_force(&j), vec![true]);
    observe(
        CASE,
        "pause-delivered",
        "by=controller_cli command=access_pause_runner_pol applied_on_runner=true in_force=true",
    );

    // stale: the state changed after the early decision was issued.
    let (exit, refused) = at_runner(&j, &["decision", "approve", &early]);
    assert_eq!(exit, 6, "{refused}");
    assert_eq!(refused["code"], "DECISION_STALE", "{refused}");
    assert_eq!(refused["next"]["action"], "fix_request", "{refused}");
    let message = refused["data"]["error"]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(
        message.contains("a pause of policy:runner-pol"),
        "the refusal does not name the extra lift: {refused}"
    );
    assert!(paused(&runner_policy(&j)), "{}", runner_policy(&j));
    assert_eq!(in_force(&j), vec![true]);
    observe(
        CASE,
        "stale",
        "by=runner_local_owner_on_terminal command=decision_approve_early typed=yes \
         answer=DECISION_STALE exit=6 next=fix_request names=pause_of_policy:runner-pol \
         policy=paused in_force=true",
    );

    // named.
    let asked = runner_json(
        &j.runner,
        &["--non-interactive", "access", "resume", "runner-pol"],
    );
    assert_eq!(asked["code"], "INTERACTION_REQUIRED", "{asked}");
    let decision = asked["next"]["decision_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("no decision: {asked}"))
        .to_owned();
    let listed = runner_json(&j.runner, &["inspect", "decisions"]);
    let view = listed["data"]["decisions"]
        .as_array()
        .and_then(|all| all.iter().find(|d| d["decision_id"] == decision.as_str()))
        .cloned()
        .unwrap_or_else(|| panic!("the decision is not listed: {listed}"));
    let lifted = view["lifted_effects"]
        .as_array()
        .unwrap_or_else(|| panic!("the approval does not name the delivered pause: {view}"));
    assert_eq!(lifted.len(), 1, "{view}");
    assert_eq!(lifted[0]["scope_key"], "policy:runner-pol", "{view}");
    assert_eq!(lifted[0]["kind"], "pause", "{view}");
    assert!(lifted[0]["controller"].is_string(), "{view}");
    assert!(lifted[0]["delivered_at"].is_string(), "{view}");
    assert!(paused(&runner_policy(&j)));
    assert_eq!(in_force(&j), vec![true]);
    observe(
        CASE,
        "named",
        "by=runner_unattended_owner command=access_resume_runner_pol \
         answer=INTERACTION_REQUIRED decision_lifted_effects=1(scope_key=policy:runner-pol,kind=pause,controller,delivered_at) \
         in_force=true",
    );

    // lift.
    let (exit, approved) = at_runner(&j, &["decision", "approve", &decision]);
    assert_eq!(approved["code"], "OK", "exit {exit}: {approved}");
    assert!(!paused(&runner_policy(&j)), "{}", runner_policy(&j));
    assert_eq!(in_force(&j), vec![false]);
    observe(
        CASE,
        "lift",
        "by=runner_local_owner_on_terminal command=decision_approve typed=yes policy=active \
         in_force=false",
    );
    drop(j);
}
