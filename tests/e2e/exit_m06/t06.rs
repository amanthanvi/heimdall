//! ⟨M06 W5 U7⟩ **T06: the second controller** (m06-plan §3 row "T06 second controller",
//! U4b; ADR-0012 §8), with real binaries on one host: one runner, two controller
//! installations with their own K_mgmt, client and CA.
//!
//! Driven here, one observation line each:
//!
//! * `first-grant`: the first controller's grant on the runner, issued under its CA;
//! * `second-owner` ⟨`w5n`⟩: a second owner is invited by the first controller's owner
//!   (`environment invite --role owner` on a terminal), approved at the runner by its local
//!   owner (`decision approve` on the runner's terminal), and joins on its own device with
//!   the key that device made (`environment join --show-key`, then `environment join
//!   <bundle>` on a terminal). **All through the product CLI**: nothing is sent at the
//!   session level, and the second controller's record of the runner is the one `join`
//!   wrote. Its copy of the profile its requests name is still written by the test (no
//!   product command gives a controller a profile for a runner's pair);
//! * `first-controller-gone`: the first controller's runtime is stopped for the rest;
//! * `no-issuer`: the second controller, holding no issuer, cannot have anything issued:
//!   its forwarded request is refused `CAPABILITY_UNAVAILABLE` and nothing is sent;
//! * `narrowing`: the second controller delivers a typed narrowing effect for the first
//!   controller's grant (a revoke): applied on the runner, acknowledged to the second;
//! * `untrusted-issuer`: with an issuer the runner does not trust for it, its request is
//!   refused `issuer_untrusted`; the first controller's CA trust does not carry over;
//! * `own-grant`: once the runner's local owner trusts the second CA for the second client
//!   (`remote issuer-trust add` on the runner's terminal), the second controller's request
//!   is issued under its own CA, and it holds no issuance for the first controller's grant;
//! * `destination-trust`: the certificate logs in only at a destination that trusts the
//!   second CA: refused where only the first is trusted, accepted once the destination's
//!   administrator trusts the second.
//!
//! * `second-pause`, `second-cutoff` ⟨`w5f`⟩: the second controller's owner pauses the
//!   runner's policy and cuts it off (`access pause`, `access cutoff`: the product CLI),
//!   with the first controller stopped: each is one typed effect, applied on the runner
//!   (its own `inspect policies` shows the pause and the cutoff instant) and acknowledged
//!   to the second controller; its request for fresh work is then refused by the runner;
//! * `effect-id-collision` ⟨`w5f`; A07 "namespaced acknowledgements"⟩: the first controller
//!   comes back and pauses the same policy, **with the effect ID the second controller's
//!   pause had**. Two producers, one effect ID, one target. The runner acknowledges each
//!   producer's effect under that producer's own key: its durable acknowledgements hold
//!   one row per producer for the one ID, its policy revisions one per producer, the
//!   second controller's acknowledgement is unchanged, and the first controller sees its
//!   own effect acknowledged. **The collision itself is staged**: a controller mints its
//!   effect IDs at random, so the first controller's pause is produced by the real CLI
//!   while the route is blocked, and the effect ID of that one pending outbox row is
//!   rewritten (while its runtime is stopped) to the second controller's. Everything else,
//!   the delivery and both acknowledgements included, is the real binaries';
//!
//! * `first-cutoff-all`, `lift-at-runner`, `first-acknowledges` ⟨`w5m` L4; ADR-0012 §7.4
//!   "Two owner controllers"⟩: the first controller comes back and its owner cuts off every
//!   policy (`access cutoff --all`: the product CLI). While the runner reports that effect
//!   in force, **both** controllers' requests are refused. The runner's own owner then
//!   lifts it on a terminal (`access cutoff --clear --all`, the typed confirmation): the
//!   second controller's next request is issued with no acknowledgement of its own, and
//!   the first controller, which delivered the effect, stays refused until its own owner
//!   acknowledges the lift on a terminal (`environment resume-issuance`);
//!
//! **Not driven here** (`NOT-COVERED.md`): a re-issue after a lifted cutoff by a controller
//! without an issuer (the row's "renewal without an issuer"; the model's
//! `t06_renewal_without_an_issuer_is_capability_unavailable`); the Windows controller; a
//! separate runner host.

use std::sync::Arc;

use heimdall_contract::ids::{ClientId, GrantId};
use heimdall_credential::cert::SecretCaKey;
use heimdall_store::{NoFaults, Store};
use serde_json::Value;

use super::m06::{blocked, forwarded_ensure, logs, observe};
use super::world::{
    ControllerRuntime, HOUR, Journey, empty_controller, envelope, install_issuer, journey as start,
    listed_identities, onward_login, seed_controller_profile, state_db, wait_settled,
};

const CASE: &str = "t06";

/// The second controller's forwarded `ensure` (its own request IDs and work IDs).
fn second_ensure(j: &Journey, b: &ControllerRuntime, work: &str, request: &str) -> Value {
    let args = [
        "access",
        "ensure",
        "--profile",
        "runner-profile",
        "--environment",
        j.environment.as_str(),
        "--work-id",
        work,
        "--for",
        "30m",
        "--request-id",
        request,
    ];
    let mut answer = b.json(&args);
    if answer["code"] == "ACCEPTED" {
        let operation = answer["operation_id"]
            .as_str()
            .unwrap_or_else(|| panic!("the pending answer names no operation: {answer}"))
            .to_owned();
        // ⟨M08 W4 SEC-4, item 5⟩ Until it settles: every step that reaches this wait expects
        // the request issued, and an answer from a wait that ran out is not the result.
        answer = wait_settled(|args| b.json(args), &operation);
    }
    answer
}

/// The end of the typed confirmations of `environment invite` and `environment join`.
const CONFIRMATION: &str = "Type yes to continue";

/// ⟨M06 W5 `w5n`⟩ The second owner, **through the product CLI** on three terminals:
///
/// 1. the second device makes its own K_mgmt (`environment join --show-key`);
/// 2. the first controller's owner invites that key as an owner (`environment invite
///    --role owner`, the fingerprint shown, a typed `yes`): `APPROVAL_REQUIRED`, held for
///    the runner's local owner;
/// 3. the runner's local owner approves it on the runner's terminal (`decision approve`,
///    a typed `yes`);
/// 4. the same invitation request again returns the bundle;
/// 5. the second device joins with it (`environment join <bundle>`, a typed `yes`): the
///    product writes that device's record of the runner. Nothing is sent at the session
///    level and no record is seeded.
///
/// Returns the second device (not started; its profile still to be given) and its client.
fn enroll_second_owner(j: &Journey) -> (ControllerRuntime, ClientId) {
    let environment = j.environment.as_str();
    let second = empty_controller(&j.scratch, "d");
    let shown = second.json(&["environment", "join", "--show-key"]);
    assert_eq!(shown["code"], "OK", "{shown}");
    let key = shown["data"]["public_key"].as_str().unwrap().to_owned();
    let fingerprint = shown["data"]["fingerprint"].as_str().unwrap().to_owned();
    let invite = |retry: &[&str]| {
        let mut args = vec![
            "environment",
            "invite",
            environment,
            "--role",
            "owner",
            "--public-key",
            &key,
        ];
        args.extend(retry);
        j.controller.attended_at(&args, CONFIRMATION, Some("yes")).1
    };
    let pending = invite(&[]);
    assert_eq!(
        pending["code"],
        "APPROVAL_REQUIRED",
        "{pending}\n{}",
        logs(j)
    );
    let decision = pending["next"]["decision_ref"].as_str().unwrap().to_owned();
    // ⟨M08 U2b-2⟩ The retry the answer names, as it is passed back: the request ID with the
    // restore epoch the runner bound it to beside it.
    let message = pending["data"]["error"]["message"].as_str().unwrap();
    let retry: Vec<String> = message
        .rsplit(" again with ")
        .next()
        .unwrap()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    assert_eq!(retry.len(), 4, "{message}");
    assert_eq!(
        (retry[0].as_str(), retry[2].as_str()),
        ("--request-id", "--request-epoch"),
        "{message}"
    );
    assert!(retry[3].parse::<u64>().is_ok(), "{message}");
    // At the runner: its local owner, on a terminal.
    let path = |p: &std::path::Path| p.to_string_lossy().into_owned();
    let (code, approved) = super::world::on_terminal(
        &j.runner.home,
        &[
            ("HOME", path(&j.runner.account)),
            ("HEIMDALL_HOME", path(&j.runner.home)),
            ("HEIMDALL_TEST_SSH_HOME", path(&j.runner.account)),
            ("HEIMDALL_TEST_TIME_SYNC", "synchronized".to_owned()),
        ],
        &["decision", "approve", &decision],
        Some("yes"),
    );
    assert_eq!(code, 0, "{approved}");
    let retry: Vec<&str> = retry.iter().map(String::as_str).collect();
    let created = invite(&retry);
    assert_eq!(created["code"], "OK", "{created}\n{}", logs(j));
    let bundle = j.scratch.subdir("inv").unwrap().join("invitation.json");
    std::fs::write(&bundle, created["data"].to_string()).unwrap();
    let (code, joined) = second.attended_at(
        &["environment", "join", &bundle.to_string_lossy()],
        CONFIRMATION,
        Some("yes"),
    );
    assert_eq!(code, 0, "{joined}");
    assert_eq!(joined["data"]["role"], "owner", "{joined}");
    assert_eq!(joined["data"]["environment"], environment, "{joined}");
    assert_eq!(
        joined["data"]["key_fingerprint"],
        fingerprint.as_str(),
        "{joined}"
    );
    let invited = ClientId::parse(joined["data"]["client"].as_str().unwrap()).unwrap();
    (second, invited)
}

pub(crate) fn journey() {
    let Some(mut j) = start(|_| Vec::new(), 4 * HOUR) else {
        blocked(CASE, "no fixture sshd on this host");
        return;
    };
    let environment = j.environment.clone();
    let account = j.account.clone();

    // first-grant.
    let (answer, _) = forwarded_ensure(&j, "job-t06-a", "t06-a-1", "1h");
    assert_eq!(answer["code"], "OK", "{answer}\n{}", logs(&j));
    let first_grant = GrantId::parse(answer["data"]["grant_id"].as_str().unwrap()).unwrap();
    let first_endpoint = answer["data"]["consumer"]["signing_endpoint"]
        .as_str()
        .unwrap()
        .to_owned();
    let first_listed = listed_identities(&first_endpoint);
    assert_eq!(first_listed.len(), 1, "{first_listed:?}");
    let first_facts = heimdall_issuer::remote::read_certificate(&first_listed[0]).unwrap();
    assert_eq!(first_facts.ca_fingerprint, j.ca_fingerprint);
    observe(CASE, "first-grant", "issued_under=first_ca identities=1");

    // second-owner.
    let second_ca = SecretCaKey::generate().unwrap();
    let second_ca_line = second_ca.public_openssh().unwrap();
    let second_ca_fingerprint = second_ca.fingerprint().unwrap();
    assert_ne!(second_ca_fingerprint, j.ca_fingerprint);
    let (mut b, invited) = enroll_second_owner(&j);
    assert_ne!(invited, j.client);
    // The second device's own record of the runner is the one `join` wrote.
    let recorded = b.json(&["environment", "status"]);
    let entry = &recorded["data"]["environments"][0];
    assert_eq!(entry["environment"], environment.as_str(), "{recorded}");
    assert_eq!(entry["role"], "owner", "{recorded}");
    assert_eq!(entry["client"], invited.as_str(), "{recorded}");
    seed_controller_profile(&b, &j.pair);
    observe(
        CASE,
        "second-owner",
        "invited_by=first_owner_cli(environment_invite_--role_owner,typed_yes) \
         approved_by=runner_local_owner_terminal(decision_approve,typed_yes) \
         joined_by=second_device_cli(environment_join,typed_yes) key=made_by_join_--show-key \
         role=owner requests_at_session_level=none controller_record=written_by_join \
         seeded=its_copy_of_the_profile_only",
    );

    // first-controller-gone.
    j.controller.runtime_stop();
    observe(
        CASE,
        "first-controller-gone",
        "first_controller_runtime=stopped",
    );

    // no-issuer: nothing can be issued by a controller that holds no issuer.
    b.start();
    b.wait_for(&environment, "the second controller did not connect", |e| {
        e["connectivity"]["state"] == "connected"
    });
    let refused = second_ensure(&j, &b, "job-t06-b0", "t06-b-0");
    assert_eq!(refused["code"], "CAPABILITY_UNAVAILABLE", "{refused}");
    observe(
        CASE,
        "no-issuer",
        format!(
            "forwarded_request=CAPABILITY_UNAVAILABLE reason={} issued=nothing",
            refused["data"]["error"]["reason"]
                .as_str()
                .unwrap_or("none")
        ),
    );

    // narrowing: the second controller revokes the first controller's grant.
    let revoked = b.json(&["access", "revoke", first_grant.as_str()]);
    assert_eq!(revoked["code"], "OK", "{revoked}\n{}", b.stderr());
    let applied = b.wait_for(&environment, "the revoke was not applied", |e| {
        e["remote_pending"].as_array().is_some_and(Vec::is_empty)
            && e["residuals"]
                .as_array()
                .is_some_and(|r| r.iter().any(|x| x["acknowledged"] == true))
    });
    assert_eq!(applied["residuals"][0]["grant"], first_grant.as_str());
    assert!(
        listed_identities(&first_endpoint).is_empty(),
        "the first controller's grant is revoked on the runner"
    );
    observe(
        CASE,
        "narrowing",
        "effect=grant_revoke target=first_controllers_grant applied_on_runner=true \
         acknowledged_to=second_controller",
    );

    // untrusted-issuer: an issuer the runner does not trust for the second client.
    b.runtime_stop();
    install_issuer(&b, &second_ca);
    drop(second_ca);
    b.start();
    b.wait_for(
        &environment,
        "the second controller did not reconnect",
        |e| e["connectivity"]["state"] == "connected",
    );
    let untrusted = second_ensure(&j, &b, "job-t06-b1", "t06-b-1");
    assert_eq!(untrusted["code"], "CAPABILITY_UNAVAILABLE", "{untrusted}");
    assert_eq!(
        untrusted["data"]["error"]["reason"], "issuer_untrusted",
        "{untrusted}"
    );
    assert_eq!(untrusted["data"]["error"]["effect_status"], "none");
    observe(
        CASE,
        "untrusted-issuer",
        "forwarded_request=CAPABILITY_UNAVAILABLE reason=issuer_untrusted",
    );

    // own-grant: trusted at the runner by its local owner, the second CA issues.
    let ca_file = j.scratch.subdir("ca-b").unwrap().join("ca.pub");
    std::fs::write(&ca_file, format!("{}\n", second_ca_line.trim())).unwrap();
    let trusted = envelope(&j.runner.on_terminal(
        &[
            "remote".to_owned(),
            "issuer-trust".to_owned(),
            "add".to_owned(),
            ca_file.to_string_lossy().into_owned(),
            "--controller".to_owned(),
            invited.as_str().to_owned(),
        ],
        "yes",
    ));
    assert_eq!(trusted["code"], "OK", "{trusted}");
    let own = second_ensure(&j, &b, "job-t06-b2", "t06-b-2");
    assert_eq!(own["code"], "OK", "{own}\n{}", b.stderr());
    let own_grant = GrantId::parse(own["data"]["grant_id"].as_str().unwrap()).unwrap();
    assert_ne!(own_grant, first_grant);
    let endpoint = own["data"]["consumer"]["signing_endpoint"]
        .as_str()
        .unwrap()
        .to_owned();
    let listed = listed_identities(&endpoint);
    assert_eq!(listed.len(), 1, "{listed:?}");
    let facts = heimdall_issuer::remote::read_certificate(&listed[0]).unwrap();
    assert_eq!(facts.ca_fingerprint, second_ca_fingerprint);
    assert!(
        facts.key_id.contains(own_grant.as_str()),
        "{}",
        facts.key_id
    );
    {
        let store = Store::open_read_only(&state_db(&b.home), Arc::new(NoFaults)).unwrap();
        let (for_first, for_own) = store
            .transaction(|tx| {
                Ok((
                    tx.issuance_entries(&first_grant)?.len(),
                    tx.issuance_entries(&own_grant)?.len(),
                ))
            })
            .unwrap();
        assert_eq!(
            for_first, 0,
            "nothing issued for the first controller's grant"
        );
        assert_eq!(for_own, 1);
    }
    observe(
        CASE,
        "own-grant",
        "trusted_by=runner_local_owner_on_terminal issued_under=second_ca \
         issuance_entries_for_first_controllers_grant=0",
    );

    // destination-trust: only where the second CA is trusted.
    let dir = j.scratch.subdir("onward").unwrap();
    let (ok, out) = onward_login(&dir, &j.destination, &account, &endpoint, &listed[0]);
    assert!(!ok, "the destination trusts only the first CA: {out}");
    j.destination.trust_user_ca(second_ca_line.trim()).unwrap();
    let (ok, out) = onward_login(&dir, &j.destination, &account, &endpoint, &listed[0]);
    assert!(ok, "the destination now trusts the second CA: {out}");
    observe(
        CASE,
        "destination-trust",
        "destination_trusting_first_ca_only=refused destination_trusting_second_ca=ok",
    );

    lifted_cutoff(&mut j, &b);
    second_narrowings(&mut j, &mut b, &invited);
    drop(b);
    drop(j);
}

/// The first controller's forwarded `ensure`, answered as it stands after a short wait: a
/// request that is not issued stays what it was (a refusal, or a pending `ACCEPTED`).
fn first_ensure_now(j: &Journey, work: &str, request: &str) -> Value {
    let answer = j.controller.json(&[
        "access",
        "ensure",
        "--profile",
        "runner-profile",
        "--environment",
        j.environment.as_str(),
        "--work-id",
        work,
        "--for",
        "1h",
        "--request-id",
        request,
    ]);
    if answer["code"] != "ACCEPTED" {
        return answer;
    }
    let operation = answer["operation_id"].as_str().unwrap().to_owned();
    j.controller
        .json(&["operation", "wait", &operation, "--timeout-ms", "5000"])
}

/// `first-cutoff-all`, `lift-at-runner`, `first-acknowledges` ⟨`w5m` L4; ADR-0012 §7.4
/// "Two owner controllers"⟩ (module docs). The first controller is stopped and the second
/// connected and issuing when this starts; it ends the same way, with nothing in force.
fn lifted_cutoff(j: &mut Journey, b: &ControllerRuntime) {
    let environment = j.environment.clone();
    let issued = |v: &Value| matches!(v["code"].as_str(), Some("OK" | "ACCESS_READY"));
    let code = |v: &Value| v["code"].as_str().unwrap_or("none").to_owned();
    let settled = |c: &ControllerRuntime, what: &str| {
        c.wait_for(&environment, what, |e| {
            e["remote_pending"].as_array().is_some_and(Vec::is_empty)
        })
    };
    j.controller.start();
    j.controller.wait_for(
        &environment,
        "the first controller did not reconnect",
        |e| e["connectivity"]["state"] == "connected",
    );
    // first-cutoff-all: the first controller's owner cuts off every policy.
    let at = heimdall_contract::Timestamp::from_second(
        heimdall_contract::Timestamp::now().as_second() + 2,
    )
    .unwrap();
    let cut = j
        .controller
        .json(&["access", "cutoff", "--all", "--at", &at.to_string()]);
    assert_eq!(cut["code"], "OK", "{cut}\n{}", j.controller.stderr());
    settled(
        &j.controller,
        "the first controller's cutoff was not acknowledged",
    );
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(is_set(&runner_policy(j), "cutoff_at"));
    let b_blocked = second_ensure(j, b, "job-t06-l1", "t06-l-1");
    assert!(!issued(&b_blocked), "{b_blocked}");
    let a_blocked = first_ensure_now(j, "job-t06-la1", "t06-la-1");
    assert!(!issued(&a_blocked), "{a_blocked}");
    observe(
        CASE,
        "first-cutoff-all",
        format!(
            "by=first_controller_cli scope=all applied_on_runner=true in_force=true \
             second_controller_request={} first_controller_request={}",
            code(&b_blocked),
            code(&a_blocked)
        ),
    );

    // lift-at-runner: the runner's own owner clears the cutoff of exactly that scope, on a
    // terminal, with the typed confirmation.
    let path = |p: &std::path::Path| p.to_string_lossy().into_owned();
    let (exit, lifted) = super::world::on_terminal(
        &j.runner.home,
        &[
            ("HOME", path(&j.runner.account)),
            ("HEIMDALL_HOME", path(&j.runner.home)),
            ("HEIMDALL_TEST_SSH_HOME", path(&j.runner.account)),
            ("HEIMDALL_TEST_TIME_SYNC", "synchronized".to_owned()),
        ],
        &["access", "cutoff", "--clear", "--all"],
        Some("yes"),
    );
    assert_eq!(lifted["code"], "OK", "exit {exit}: {lifted}");
    assert!(!is_set(&runner_policy(j), "cutoff_at"));
    let in_force: Vec<bool> = Store::open_read_only(&state_db(&j.runner.home), Arc::new(NoFaults))
        .unwrap()
        .transaction(|tx| tx.remote_policy_revisions())
        .unwrap()
        .iter()
        .filter(|r| r.scope_key == "all")
        .map(|r| r.in_force)
        .collect();
    assert_eq!(
        in_force,
        vec![false],
        "the delivered cutoff is still in force"
    );
    // The second controller resumes with no acknowledgement of its own (the effect is not
    // its): its next request is issued.
    let b_resumed = second_ensure(j, b, "job-t06-l2", "t06-l-2");
    assert!(issued(&b_resumed), "{b_resumed}\n{}", b.stderr());
    // The first controller, which delivered it, stays blocked until its owner acknowledges.
    let a_still = first_ensure_now(j, "job-t06-la2", "t06-la-2");
    assert!(!issued(&a_still), "{a_still}");
    observe(
        CASE,
        "lift-at-runner",
        format!(
            "by=runner_local_owner_on_terminal command=access_cutoff_clear_all typed=yes \
             delivered_cutoff_in_force=false second_controller_request={} \
             (no_acknowledgement_of_its_own) first_controller_request={} (not_acknowledged_yet)",
            code(&b_resumed),
            code(&a_still)
        ),
    );

    // first-acknowledges: `environment resume-issuance` on the first controller's terminal.
    let (exit, acked) = j.controller.attended_at(
        &["environment", "resume-issuance", environment.as_str()],
        "Type yes to continue:",
        Some("yes"),
    );
    assert_eq!(acked["code"], "OK", "exit {exit}: {acked}");
    let (a_resumed, _) = forwarded_ensure(j, "job-t06-la3", "t06-la-3", "1h");
    assert!(issued(&a_resumed), "{a_resumed}\n{}", logs(j));
    observe(
        CASE,
        "first-acknowledges",
        format!(
            "by=first_controller_owner_on_terminal command=environment_resume_issuance \
             typed=yes first_controller_request={}",
            code(&a_resumed)
        ),
    );
    j.controller.runtime_stop();
}

/// The runner's own view of its standing policy (`inspect policies` at the runner).
fn runner_policy(j: &Journey) -> Value {
    let policies = super::m06::runner_json(&j.runner, &["inspect", "policies"]);
    policies["data"]["items"]
        .as_array()
        .and_then(|all| all.iter().find(|p| p["policy_id"] == "runner-pol"))
        .cloned()
        .unwrap_or_else(|| panic!("the runner's policy: {policies}"))
}

fn is_set(v: &Value, field: &str) -> bool {
    v.get(field).is_some_and(|x| !x.is_null())
}

/// The outbox rows of the controller at `home` for the runner (read-only).
fn outbox(
    home: &std::path::Path,
    environment: &heimdall_contract::ids::EnvironmentId,
) -> Vec<heimdall_store::ext_effects::OutboxEffect> {
    Store::open_read_only(&state_db(home), Arc::new(NoFaults))
        .unwrap()
        .transaction(|tx| tx.remote_effect_outbox(Some(environment), false))
        .unwrap()
}

/// `second-pause`, `second-cutoff`, `effect-id-collision` (module docs). The first
/// controller is stopped and the second connected when this starts.
fn second_narrowings(j: &mut Journey, b: &mut ControllerRuntime, second_client: &ClientId) {
    use heimdall_contract::remote::EffectTarget;
    use heimdall_store::ext_effects::{EffectKey, OutboxState};

    let environment = j.environment.clone();
    assert!(
        j.controller.runtime.is_none(),
        "the first controller is gone"
    );
    let before = runner_policy(j);
    assert!(
        !is_set(&before, "paused_since") && !is_set(&before, "cutoff_at"),
        "{before}"
    );
    let settled = |c: &ControllerRuntime, what: &str| {
        c.wait_for(&environment, what, |e| {
            e["remote_pending"].as_array().is_some_and(Vec::is_empty)
        })
    };

    // second-pause.
    let paused = b.json(&["access", "pause", "runner-pol"]);
    assert_eq!(paused["code"], "OK", "{paused}\n{}", b.stderr());
    settled(b, "the second controller's pause was not acknowledged");
    let held = runner_policy(j);
    assert!(is_set(&held, "paused_since"), "{held}");
    let pause_row = outbox(&b.home, &environment)
        .into_iter()
        .find(|e| matches!(e.key.target, EffectTarget::PolicyPause { .. }))
        .expect("the second controller's pause in its outbox");
    assert_eq!(pause_row.state, OutboxState::Acknowledged);
    assert_eq!(&pause_row.key.producer, second_client);
    observe(
        CASE,
        "second-pause",
        "by=second_controller_cli first_controller=stopped effect=policy_pause \
         applied_on_runner=true acknowledged_to=second_controller",
    );

    // second-cutoff.
    let at = heimdall_contract::Timestamp::from_second(
        heimdall_contract::Timestamp::now().as_second() + 3,
    )
    .unwrap();
    let cut = b.json(&["access", "cutoff", "runner-pol", "--at", &at.to_string()]);
    assert_eq!(cut["code"], "OK", "{cut}\n{}", b.stderr());
    settled(b, "the second controller's cutoff was not acknowledged");
    let held = runner_policy(j);
    assert!(is_set(&held, "cutoff_at"), "{held}");
    std::thread::sleep(std::time::Duration::from_secs(4));
    let fresh = second_ensure(j, b, "job-t06-b3", "t06-b-3");
    assert!(
        !matches!(
            fresh["code"].as_str(),
            Some("OK" | "ACCESS_READY" | "ACCEPTED")
        ),
        "fresh work after the second controller's pause and cutoff: {fresh}"
    );
    observe(
        CASE,
        "second-cutoff",
        format!(
            "by=second_controller_cli effect=policy_cutoff applied_on_runner=true \
             acknowledged_to=second_controller fresh_work={}",
            fresh["code"].as_str().unwrap_or("none")
        ),
    );

    // effect-id-collision: the first controller returns, disconnected, and pauses the same
    // policy; its one pending effect then gets the second controller's effect ID.
    j.reachable(false);
    j.controller.start();
    j.controller
        .wait_for(&environment, "the runner is reachable", |e| {
            e["connectivity"]["state"] != "connected"
        });
    let first_paused = j.controller.json(&["access", "pause", "runner-pol"]);
    assert_eq!(first_paused["code"], "OK", "{first_paused}");
    j.controller.runtime_stop();
    let rows = outbox(&j.controller.home, &environment);
    let pending: Vec<_> = rows
        .iter()
        .filter(|e| e.state == OutboxState::Pending)
        .collect();
    assert_eq!(pending.len(), 1, "{rows:?}");
    let own = pending[0].clone();
    assert!(matches!(own.key.target, EffectTarget::PolicyPause { .. }));
    assert_eq!(own.key.producer, j.client);
    assert_ne!(own.key.effect, pause_row.key.effect, "minted at random");
    let same_target = own.key.target == pause_row.key.target;
    let collided = EffectKey {
        producer: own.key.producer.clone(),
        effect: pause_row.key.effect.clone(),
        target: own.key.target.clone(),
    };
    {
        // The staged part: that one row's effect ID. Every other row is put back as it was.
        let store = Store::open(&state_db(&j.controller.home), Arc::new(NoFaults)).unwrap();
        store
            .transaction(|tx| {
                tx.forget_remote_effect_outbox(&environment)?;
                for row in &rows {
                    let key = if row.key == own.key {
                        &collided
                    } else {
                        &row.key
                    };
                    assert!(tx.enqueue_remote_effect(&environment, key, row.created_at)?);
                    if let (Some(ack), Some(at)) = (&row.ack, row.acknowledged_at) {
                        assert!(tx.acknowledge_remote_effect(ack, at)?);
                    }
                }
                Ok(())
            })
            .unwrap();
    }
    j.reachable(true);
    j.controller.start();
    settled(
        &j.controller,
        "the first controller's colliding pause was not acknowledged",
    );
    let first_row = outbox(&j.controller.home, &environment)
        .into_iter()
        .find(|e| e.key == collided)
        .expect("the first controller's effect");
    assert_eq!(first_row.state, OutboxState::Acknowledged, "{first_row:?}");
    let first_ack = first_row.ack.expect("its acknowledgement");
    assert_eq!(first_ack.key, collided, "acknowledged under its own key");
    // The second controller's acknowledgement is what it was.
    let second_row = outbox(&b.home, &environment)
        .into_iter()
        .find(|e| e.key == pause_row.key)
        .unwrap();
    assert_eq!(second_row, pause_row, "the other producer's row changed");
    // The runner: one durable acknowledgement and one policy revision per producer, for
    // the one effect ID.
    let (ack_first, ack_second, revisions) =
        Store::open_read_only(&state_db(&j.runner.home), Arc::new(NoFaults))
            .unwrap()
            .transaction(|tx| {
                Ok((
                    tx.remote_effect_ack(&collided)?,
                    tx.remote_effect_ack(&pause_row.key)?,
                    tx.remote_policy_revisions()?,
                ))
            })
            .unwrap();
    let ack_first = ack_first.expect("the runner's acknowledgement for the first producer");
    let ack_second = ack_second.expect("the runner's acknowledgement for the second producer");
    assert_eq!(ack_first.key.producer, j.client);
    assert_eq!(&ack_second.key.producer, second_client);
    assert_eq!(ack_first.key.effect, ack_second.key.effect);
    assert_eq!(Some(&ack_second), pause_row.ack.as_ref());
    let with_id: Vec<_> = revisions
        .iter()
        .filter(|r| r.effect == collided.effect)
        .map(|r| r.producer.clone())
        .collect();
    assert_eq!(with_id.len(), 2, "{revisions:?}");
    assert!(with_id.contains(&j.client) && with_id.contains(second_client));
    assert!(is_set(&runner_policy(j), "paused_since"));
    observe(
        CASE,
        "effect-id-collision",
        format!(
            "producers=2 effect_ids=1 same_target={same_target} \
             first_controllers_effect=product_cli_pause_while_disconnected \
             its_effect_id=rewritten_in_its_pending_outbox_row(staged) \
             delivered_by=first_controller_runtime runner_acknowledgements=one_per_producer \
             runner_policy_revisions=one_per_producer \
             second_controllers_acknowledgement=unchanged \
             first_controller_sees=its_own_effect_acknowledged"
        ),
    );
}
