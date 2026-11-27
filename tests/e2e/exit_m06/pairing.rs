//! ⟨M06 W5 `w5f`⟩ **Pairing, invitation and join through the product CLI** (A25's fixture
//! is the real pairing path; A24 "pairing through the controller CLI"). No step is seeded
//! or sent at the session level: every management request is one the real `heimdall`
//! sends over the real `ssh` and the runner's forced-command bridge. The world is
//! [`super::cli_world`], whose header says what the first controller's catalog is built
//! from.
//!
//! Steps (`m06 observation: a25-cli <step>: <result>`):
//! * `enrollment`: the controller's verified M03 enrollment of the runner account
//!   (`enroll verify`, the product's);
//! * `add-declined`: `environment add` on a pseudo-terminal, `no` typed at the runner's
//!   confirmation: nothing is enrolled on the runner and nothing recorded here;
//! * `add`: the same, `yes` typed: the bootstrap ssh session ran the runner's `remote
//!   init` (the runner-local confirmation on that terminal), the runner says its runtime
//!   does not run and offers to start it (accepted, typed: the product starts it,
//!   detached), the management line is in the runner account's `authorized_keys`, and the
//!   controller records the runner with role `owner`;
//! * `invite`, `approve`, `join`: `environment join --show-key` on a second device,
//!   `environment invite` on the first (its fingerprint confirmation typed), held by the
//!   runner for its **local** confirmation (`decision approve` typed at the runner),
//!   `invite` again with the request ID (the bundle), `environment join` on the second
//!   device (the host key and environment ID confirmation typed); the joined device then
//!   reads the runner over its own management session;
//! * `revoke-client`: the first controller revokes the second device's client; its next
//!   session is refused, and the first controller's still opens;
//! * `remove`: the first controller revokes itself and forgets the runner; its management
//!   line is gone from the runner account's `authorized_keys`.

use heimdall_testkit::home::Scratch;

use super::cli_world::{CONFIRMATION, CliWorld, Device};
use super::m06::{blocked, observe};

const CASE: &str = "a25-cli";

fn management_lines(lines: &[String]) -> Vec<&String> {
    lines
        .iter()
        .filter(|l| l.contains("remote serve"))
        .collect()
}

#[test]
fn restores_runner_then_bootstraps_a_fresh_owner_to_repair_pairings() {
    use heimdall_runtime::Paths;
    use heimdall_store::restore::HoldKind;
    use heimdall_store::{NoFaults, Store, layout};
    use std::sync::Arc;

    let w = match CliWorld::start() {
        Ok(w) => w,
        Err(why) => {
            blocked("restore-repair-pairings", &why);
            return;
        }
    };
    assert_eq!(w.verify_enrollment(), "verified");
    // The fresh controller has the fixture's verified bootstrap access, but a separate
    // state home and an empty K_mgmt store. Snapshot the catalog before any pairing exists.
    let scratch = Scratch::new().unwrap();
    let fresh = Device::new(&scratch, "fresh");
    let paths = Paths::under(&fresh.home);
    paths.ensure().unwrap();
    let controller_state = Paths::under(&w.controller.hh).state_dir;
    Store::open_read_only(
        &layout::db_path(&controller_state).unwrap(),
        Arc::new(NoFaults),
    )
    .unwrap()
    .vacuum_into(&paths.state_dir.join(layout::DB_FILE))
    .unwrap();
    let initial = w.environment_add("yes", "yes");
    assert_eq!(initial.code, Some(0), "{}", initial.text);
    let record = initial.json();
    let environment = record["data"]["environment"].as_str().unwrap();
    let old = record["data"]["client"].as_str().unwrap();
    assert!(w.runner_stop());
    let state = Paths::under(&w.runner.home).state_dir;
    let backup = scratch.path().join("runner-backup.db");
    Store::open_read_only_quiescent(&layout::db_path(&state).unwrap(), Arc::new(NoFaults))
        .unwrap()
        .vacuum_into(&backup)
        .unwrap();
    let restore = w.runner_typed(
        &["state", "restore", "--backup", backup.to_str().unwrap()],
        &[("Type `restore`", "restore")],
    );
    assert_eq!(restore.code, Some(0), "{}", restore.text);
    let holds =
        Store::open_read_only_quiescent(&layout::db_path(&state).unwrap(), Arc::new(NoFaults))
            .unwrap()
            .transaction(|tx| tx.restore_holds(Some(HoldKind::Client)))
            .unwrap();
    assert_eq!(holds.len(), 1);
    assert_eq!(holds[0].reference, old);

    let mut env = fresh.env();
    let ssh_home = w.controller.home.git_home.to_string_lossy();
    env.iter_mut()
        .find(|(k, _)| k == "HEIMDALL_TEST_SSH_HOME")
        .unwrap()
        .1 = ssh_home.into_owned();
    let bootstrapped = w.environment_add_from(&env, "yes", "yes");
    assert_eq!(bootstrapped.answered, 2, "{}", bootstrapped.text);
    assert_eq!(bootstrapped.code, Some(0), "{}", bootstrapped.text);
    let fresh_record = bootstrapped.json();
    assert_eq!(fresh_record["data"]["environment"], environment);
    assert_eq!(fresh_record["data"]["role"], "owner");
    assert_ne!(fresh_record["data"]["client"], old);

    let revoke = ["environment", "revoke-client", environment, old];
    assert_ne!(
        w.controller_json(&revoke).0,
        0,
        "old owner reached the restored runner"
    );
    let (code, revoked) = fresh.json(&revoke);
    assert_eq!(code, 0, "{revoked}");
    assert_eq!(revoked["data"]["state"], "revoked");

    let joining = Device::new(&scratch, "joining");
    let (code, shown) = joining.json(&["environment", "join", "--show-key"]);
    assert_eq!(code, 0, "{shown}");
    let key = shown["data"]["public_key"].as_str().unwrap();
    let mut invite = vec![
        "environment",
        "invite",
        environment,
        "--role",
        "owner",
        "--public-key",
        key,
        "--request-id",
        "re-pair-owner",
    ];
    let held = fresh.typed(&invite, &[(CONFIRMATION, "yes")]);
    let pending = held.json();
    assert_eq!(pending["code"], "APPROVAL_REQUIRED", "{}", held.text);
    let decision = pending["next"]["decision_ref"].as_str().unwrap();
    let approved = w.runner_typed(&["decision", "approve", decision], &[("[y/N]:", "yes")]);
    assert_eq!(approved.code, Some(0), "{}", approved.text);
    invite.extend(["--request-epoch", "1"]);
    let created = fresh.typed(&invite, &[(CONFIRMATION, "yes")]);
    assert_eq!(created.code, Some(0), "{}", created.text);
    let bundle = scratch.path().join("re-pair.json");
    std::fs::write(&bundle, created.json()["data"].to_string()).unwrap();
    let joined = joining.typed(
        &["environment", "join", bundle.to_str().unwrap()],
        &[(CONFIRMATION, "yes")],
    );
    assert_eq!(joined.code, Some(0), "{}", joined.text);
    let new = joined.json();
    assert_eq!(new["data"]["role"], "owner");
    assert_eq!(new["data"]["environment"], environment);
    assert_ne!(new["data"]["client"], old);
    assert_ne!(
        w.controller_json(&revoke).0,
        0,
        "revoked owner reached the runner"
    );
}

pub(crate) fn journey() {
    let mut w = match CliWorld::start() {
        Ok(w) => w,
        Err(why) => {
            blocked(CASE, &why);
            return;
        }
    };
    let state = w.verify_enrollment();
    assert_eq!(state, "verified");
    observe(
        CASE,
        "enrollment",
        "catalog=product_commands ca_and_enrollment_record=written_as_m03_exit_world \
         verified_by=product_enroll_verify state=verified",
    );
    let before = w.runner_key_lines();
    assert!(management_lines(&before).is_empty(), "{before:?}");

    // add-declined: `no` at the runner's confirmation.
    let declined = w.environment_add("no", "no");
    assert_eq!(declined.answered, 1, "{}", declined.text);
    let answer = declined.json();
    assert_ne!(declined.code, Some(0), "{}", declined.text);
    assert!(
        declined.text.contains("nothing was written"),
        "{}",
        declined.text
    );
    assert_eq!(
        w.runner_key_lines(),
        before,
        "a declined bootstrap wrote a line"
    );
    let (_, listed) = w.controller_json(&["environment", "status"]);
    assert_eq!(
        listed["data"]["environments"].as_array().map(Vec::len),
        Some(0),
        "{listed}"
    );
    observe(
        CASE,
        "add-declined",
        format!(
            "typed=no_at_runner_confirmation runner_wrote=nothing controller_recorded=nothing \
             controller_code={}",
            answer["code"].as_str().unwrap_or("none")
        ),
    );

    // add: `yes` at the runner's confirmation, `yes` at its offer to start its runtime.
    let added = w.environment_add("yes", "yes");
    let record = added.json();
    assert_eq!(added.answered, 2, "{}", added.text);
    assert_eq!(added.code, Some(0), "{}", added.text);
    assert_eq!(record["code"], "OK", "{record}");
    assert_eq!(record["data"]["role"], "owner", "{record}");
    assert_eq!(record["data"]["destination"], w.destination, "{record}");
    let environment = record["data"]["environment"].as_str().unwrap().to_owned();
    let first_client = record["data"]["client"].as_str().unwrap().to_owned();
    assert!(
        added.text.contains("runtime is NOT running"),
        "the runner did not say its runtime was not running: {}",
        added.text
    );
    assert!(w.runner_serves(), "the bootstrap did not start the runtime");
    let after = w.runner_key_lines();
    assert_eq!(management_lines(&after).len(), 1, "{after:?}");
    assert!(
        before.iter().all(|l| after.contains(l)),
        "the bootstrap removed a line of the account's authorized_keys"
    );
    let (_, own) = w.runner_json(&["status"]);
    let (code, status) = w.controller_json(&["environment", "status"]);
    assert_eq!(code, 0, "{status}");
    let entry = &status["data"]["environments"][0];
    assert_eq!(entry["environment"], environment, "{status} {own}");
    assert_eq!(entry["client"], first_client, "{status}");
    observe(
        CASE,
        "add",
        "bootstrap=ssh_session_on_terminal_over_verified_access \
         runner_confirmation=typed_yes_on_that_terminal runtime_said=not_running \
         runtime_offer=accepted runner_runtime=serving management_line=in_runner_authorized_keys \
         controller_record=owner seeded=nothing",
    );

    // invite / approve / join: a second device. ⟨M06 W5 `w5r`⟩ Its Heimdall home is long
    // enough that an agent socket under it could never bind (`Device::with_long_home`):
    // its join and its sessions below open because the agent's socket is in its own short
    // directory.
    let scratch = Scratch::new().unwrap();
    let second = Device::with_long_home(&scratch, "d2");
    let (code, shown) = second.json(&["environment", "join", "--show-key"]);
    assert_eq!(code, 0, "{shown}");
    let key = shown["data"]["public_key"].as_str().unwrap().to_owned();
    let fingerprint = shown["data"]["fingerprint"].as_str().unwrap().to_owned();
    let invite = |retry: &[&str]| {
        let mut args = vec![
            "environment",
            "invite",
            &environment,
            "--role",
            "requester",
            "--public-key",
            &key,
        ];
        args.extend(retry);
        w.controller_typed(&args, &[(CONFIRMATION, "yes")])
    };
    let held = invite(&[]);
    let pending = held.json();
    assert!(
        held.text.contains(&fingerprint),
        "the owner was not shown the invited key's fingerprint: {}",
        held.text
    );
    assert_eq!(pending["code"], "APPROVAL_REQUIRED", "{}", held.text);
    let decision = pending["next"]["decision_ref"].as_str().unwrap().to_owned();
    let message = pending["data"]["error"]["message"].as_str().unwrap();
    // ⟨M08 U2b-2⟩ The retry the answer names, as it is passed back: the request ID with the
    // restore epoch the runner bound it to beside it.
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
    let retry: Vec<&str> = retry.iter().map(String::as_str).collect();
    // Unconfirmed at the runner, the same request stays held (no bundle).
    let still = invite(&retry);
    assert_eq!(still.json()["code"], "APPROVAL_REQUIRED", "{}", still.text);
    observe(
        CASE,
        "invite",
        "owner_confirmation=typed_fingerprint_shown runner=holds_for_local_confirmation \
         answer=APPROVAL_REQUIRED bundle_before_runner_confirmation=none",
    );
    let approved = w.runner_typed(&["decision", "approve", &decision], &[("[y/N]:", "yes")]);
    assert_eq!(approved.answered, 1, "{}", approved.text);
    assert_eq!(approved.code, Some(0), "{}", approved.text);
    observe(
        CASE,
        "approve",
        "at=runner_local_terminal command=decision_approve typed=yes",
    );
    let created = invite(&retry);
    let bundle = created.json();
    assert_eq!(bundle["code"], "OK", "{}", created.text);
    let bundle_file = scratch.path().join("invitation.json");
    std::fs::write(&bundle_file, bundle["data"].to_string()).unwrap();
    let bundle_path = bundle_file.to_string_lossy().into_owned();
    // Declined at the joining device: nothing joined.
    let refused = second.typed(
        &["environment", "join", &bundle_path],
        &[(CONFIRMATION, "no")],
    );
    assert_ne!(refused.code, Some(0), "{}", refused.text);
    let (_, none) = second.json(&["environment", "status"]);
    assert_eq!(
        none["data"]["environments"].as_array().map(Vec::len),
        Some(0),
        "{none}"
    );
    let joined = second.typed(
        &["environment", "join", &bundle_path],
        &[(CONFIRMATION, "yes")],
    );
    let joined_record = joined.json();
    assert_eq!(joined.code, Some(0), "{}", joined.text);
    assert_eq!(
        joined_record["data"]["role"], "requester",
        "{joined_record}"
    );
    assert_eq!(joined_record["data"]["environment"], environment);
    let second_client = joined_record["data"]["client"].as_str().unwrap().to_owned();
    assert_ne!(second_client, first_client);
    assert!(
        joined.text.contains(&environment),
        "the joining device was not shown the environment ID: {}",
        joined.text
    );
    assert_eq!(management_lines(&w.runner_key_lines()).len(), 2);
    // The joined device's own management session (a limited role reads the runner's view).
    let (code, view) = second.json(&["environment", "status", &environment]);
    assert_eq!(code, 0, "{view}");
    assert_eq!(
        view["data"]["environments"][0]["runner_view"]["read"], true,
        "{view}"
    );
    observe(
        CASE,
        "join",
        "show_key=product bundle=from_invite_after_runner_confirmation \
         join_declined_at_device=nothing_joined join=typed_host_key_and_environment_confirmation \
         role=requester own_session=reads_runner seeded=nothing session_level=nothing \
         device_home_bytes=84",
    );

    // revoke-client: the first controller revokes the second device.
    let (code, revoked) =
        w.controller_json(&["environment", "revoke-client", &environment, &second_client]);
    assert_eq!(code, 0, "{revoked}");
    let (_, view) = second.json(&["environment", "status", &environment]);
    assert_eq!(
        view["data"]["environments"][0]["runner_view"]["read"], false,
        "a revoked client still read the runner: {view}"
    );
    assert_eq!(management_lines(&w.runner_key_lines()).len(), 1);
    // The first controller's own session still opens: revoking a client that is already
    // gone answers from the runner.
    let (_, again) =
        w.controller_json(&["environment", "revoke-client", &environment, &second_client]);
    observe(
        CASE,
        "revoke-client",
        format!(
            "by=first_controller_cli revoked_device_session=refused \
             its_management_line=removed owner_session=still_served repeat={}",
            again["code"].as_str().unwrap_or("none")
        ),
    );

    // remove: the first controller revokes itself and forgets the runner.
    let (code, removed) = w.controller_json(&["environment", "remove", &environment]);
    assert_eq!(code, 0, "{removed}");
    assert_eq!(removed["data"]["revoked_on_runner"], true, "{removed}");
    let (_, listed) = w.controller_json(&["environment", "status"]);
    assert_eq!(
        listed["data"]["environments"].as_array().map(Vec::len),
        Some(0),
        "{listed}"
    );
    let last = w.runner_key_lines();
    assert!(management_lines(&last).is_empty(), "{last:?}");
    assert!(
        before.iter().all(|l| last.contains(l)),
        "removal took a line that was not a management line"
    );
    observe(
        CASE,
        "remove",
        "by=first_controller_cli revoked_on_runner=true controller_record=forgotten \
         management_lines_left=0 other_authorized_keys_lines=kept",
    );
    assert!(w.runner_stop(), "the runner runtime did not stop");
    let _ = &mut w;
}
