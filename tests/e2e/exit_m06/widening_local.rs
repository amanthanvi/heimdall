//! ⟨M06 W5 `w5m`⟩ **Local widening decisions through the product CLI, on a controller**
//! (ADR-0006 §18.9 item 8; ADR-0012 §2.1, §3.10 item 4), with the real binary on one host.
//! Observation lines: `m06 observation: local-widening <step>: <result>`.
//!
//! **The installation** is M03's exit world (`exit_m03/world.rs`): a controller, never a
//! runner, whose catalog is built with the product's commands, so `route add` has the
//! managed catalog destination it needs and nothing is seeded.
//!
//! Driven here, one observation line each:
//!
//! * `route-unattended`: `route add --iroh <E> --relay <URL>` from a non-interactive
//!   session is answered `INTERACTION_REQUIRED` (the detail names the widening); no decision is recorded and the route list
//!   is unchanged;
//! * `route-submit`: the same command on a terminal answers `APPROVAL_REQUIRED` with the
//!   decision's reference and changes nothing; the owner's decision list shows the record
//!   with `origin: local`, no client, the exact request and the exact delta (the relay);
//! * `route-retry`: the command again (the CLI mints a fresh request ID) returns the same
//!   pending record: one record, not two;
//! * `route-approve-unattended`: `decision approve` without a terminal sends nothing;
//! * `route-approve`: `decision approve <ref>` on a terminal shows the recorded request
//!   and delta, takes a typed `yes`, and the route is then one of the destination's
//!   approved routes, with its relay policy; the decision is no longer pending;
//! * `route-declined`: another widening (another relay), submitted on a terminal and
//!   answered `no` at the approval prompt, changes nothing and stays pending.
//!
//! The serve widening on a runner is A26's (`exit_m06/a26.rs`, steps `serve-local-*`), and
//! `transport adopt-roost` is [`adopt_roost`], both with the `iroh` build: the transport
//! forms refuse before any record without it.

use std::sync::Arc;

use heimdall_contract::ids::DestinationId;
use heimdall_contract::route::{DestinationRoute, InfrastructureProfile, relay_display};
use heimdall_store::ext_transport::RouteConsentRecord;
use heimdall_store::{NoFaults, Store};
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::home::Scratch;
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};
use serde_json::Value;

use super::m03world::{Out, World, WorldOptions};
use super::m06::{blocked, observe};
use super::world::state_db;

const CASE: &str = "local-widening";
/// The destination in the world (`ex1`, alias `exit1`).
const DEST: &str = "ex1";
/// ⟨`w5s`, M06-W5-R05⟩ Each relay URL carries a token in its path: stored as given, never
/// shown (every answer shows scheme, host and port with the URL's digest).
const RELAY: &str = "https://relay.invalid./t0k3nRelayPath";
const OTHER_RELAY: &str = "https://other-relay.invalid./0therT0k3nPath";
const TOKENS: [&str; 2] = ["t0k3nRelayPath", "0therT0k3nPath"];

/// Neither relay URL's path appears in `text` (an answer, a prompt, a listing).
fn path_unseen(what: &str, text: &str) {
    for t in TOKENS {
        assert!(!text.contains(t), "{what} shows a relay URL's path");
    }
}

fn endpoint(c: char) -> String {
    c.to_string().repeat(64)
}

/// The envelope a terminal run printed (`--json`): the last JSON object of the transcript.
fn answer(out: &Out) -> Value {
    assert_no_canary(&out.stdout);
    assert!(!out.stdout.contains("panicked"), "{}", out.stdout);
    out.json()
}

/// The pending decisions the owner is shown.
fn decisions(w: &World) -> Vec<Value> {
    let listed = w.cli(&["--json", "inspect", "decisions"]).json();
    assert_eq!(listed["code"], "OK", "{listed}");
    listed["data"]["decisions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// The pending local widening records.
fn local_records(w: &World) -> Vec<Value> {
    decisions(w)
        .into_iter()
        .filter(|d| d["kind"] == "remote_widening")
        .inspect(|d| {
            assert_eq!(d["request"]["origin"], "local", "{d}");
            assert!(d["request"].get("client").is_none(), "{d}");
        })
        .collect()
}

fn decision_ref(answer: &Value) -> String {
    assert_eq!(answer["code"], "APPROVAL_REQUIRED", "{answer}");
    assert_eq!(answer["data"]["error"]["effect_status"], "none", "{answer}");
    answer["next"]["decision_ref"]
        .as_str()
        .unwrap_or_else(|| panic!("the pending answer names no decision: {answer}"))
        .to_owned()
}

/// The destination's stored routes and every recorded consent (read-only, from the
/// installation's state store; an unstored list is the definition's one route).
fn stored(w: &World) -> (Vec<DestinationRoute>, Vec<RouteConsentRecord>) {
    let dest = DestinationId::parse(DEST).unwrap();
    Store::open_read_only(&state_db(&w.hh), Arc::new(NoFaults))
        .unwrap()
        .transaction(|tx| Ok((tx.destination_routes(&dest)?, tx.all_route_consents()?)))
        .unwrap()
}

fn world() -> Option<World> {
    let scratch = Scratch::new().unwrap();
    let Ok(target) = LoopbackSshd::start(
        &scratch,
        SshdConfig {
            registry_seed: Some(Vec::new()),
            ..SshdConfig::default()
        },
    ) else {
        blocked(CASE, "no fixture sshd on this host");
        return None;
    };
    // The installation's key stores are fixtures: nothing here reaches the account's own.
    let stores = scratch.path().join("stores");
    let (mgmt, iroh) = (stores.join("mgmt"), stores.join("iroh"));
    for dir in [&mgmt, &iroh] {
        std::fs::create_dir_all(dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let (w, ca) = World::start(WorldOptions {
        pairs: 1,
        servers: vec![target],
        extra_env: vec![
            (
                "HEIMDALL_TEST_MGMT_STORE".to_owned(),
                format!("fixture-file:{}", mgmt.display()),
            ),
            (
                "HEIMDALL_TEST_IROH_KEY_STORE".to_owned(),
                iroh.to_string_lossy().into_owned(),
            ),
        ],
        ..WorldOptions::default()
    });
    drop(ca);
    // The scratch directory lives as long as the world's own (leaked into the process,
    // removed with the test's temporary directory tree by the fixture sshd's own scratch).
    std::mem::forget(scratch);
    Some(w)
}

/// A widening `route add` on a controller (module docs).
pub(crate) fn route_add() {
    let Some(w) = world() else {
        return;
    };
    let before = stored(&w);
    assert!(before.1.is_empty(), "a consent before any widening");
    let ep = endpoint('a');
    let add = [
        "--json", "route", "add", DEST, "--iroh", &ep, "--relay", RELAY,
    ];

    // route-unattended
    let unattended = w.cli(&add).json();
    // ⟨ADR-0006 §18.9 item 10⟩ `INTERACTION_REQUIRED`, the detail naming the widening.
    assert_eq!(unattended["code"], "INTERACTION_REQUIRED", "{unattended}");
    assert!(
        unattended["data"]["error"].get("reason").is_none(),
        "{unattended}"
    );
    let detail = unattended["data"]["error"]["message"].as_str().unwrap();
    assert!(
        detail.contains("`route.add` widens")
            && detail.contains(&format!("the relay {}", relay_display(RELAY))),
        "{detail}"
    );
    path_unseen("the unattended refusal", &unattended.to_string());
    assert!(local_records(&w).is_empty());
    assert_eq!(stored(&w), before);
    observe(
        CASE,
        "route-unattended",
        "command=route_add_iroh_relay session=non_interactive answer=INTERACTION_REQUIRED \
         detail=names_the_widening reason=none decisions_recorded=0 routes=unchanged",
    );

    // route-submit
    let submitted = w.confirm_answers(&add, &[]);
    let first = decision_ref(&answer(&submitted));
    assert_eq!(submitted.code, 3, "{}", w.redact(&submitted.stdout));
    let records = local_records(&w);
    assert_eq!(records.len(), 1, "{records:?}");
    let record = &records[0];
    assert_eq!(record["decision_id"], first.as_str(), "{record}");
    assert_eq!(record["request"]["request_kind"], "route.add", "{record}");
    assert_eq!(
        record["request"]["exposure"]["relays_added"],
        serde_json::json!([relay_display(RELAY)]),
        "{record}"
    );
    path_unseen("the approval request", &submitted.stdout);
    path_unseen("inspect decisions", &record.to_string());
    assert_eq!(
        record["request"]["request"]["route"]["endpoint"],
        ep.as_str(),
        "{record}"
    );
    assert_eq!(stored(&w), before, "a pending record wrote a route");
    observe(
        CASE,
        "route-submit",
        "command=route_add_iroh_relay session=terminal answer=APPROVAL_REQUIRED exit=3 \
         decision_ref=named record_origin=local record_client=none \
         delta_names_relay=true routes=unchanged",
    );

    // route-retry
    let retried = w.confirm_answers(&add, &[]);
    assert_eq!(decision_ref(&answer(&retried)), first);
    assert_eq!(local_records(&w).len(), 1, "a retry made a second record");
    observe(
        CASE,
        "route-retry",
        "same_command_again=APPROVAL_REQUIRED decision_ref=the_same pending_records=1",
    );

    // route-approve-unattended
    let silent = w.cli(&["--json", "decision", "approve", &first]);
    assert_eq!(silent.code, 3, "{}", silent.stdout);
    assert_eq!(local_records(&w).len(), 1);
    assert_eq!(stored(&w), before);
    observe(
        CASE,
        "route-approve-unattended",
        "command=decision_approve session=non_interactive exit=3 sent=nothing \
         record=still_pending routes=unchanged",
    );

    // route-declined: another widening, declined at the prompt.
    let other = endpoint('b');
    let other_add = [
        "--json",
        "route",
        "add",
        DEST,
        "--iroh",
        &other,
        "--relay",
        OTHER_RELAY,
    ];
    let second = decision_ref(&answer(&w.confirm_answers(&other_add, &[])));
    assert_ne!(second, first);
    let declined = w.confirm_answers(&["--json", "decision", "approve", &second], &["no"]);
    assert_eq!(declined.code, 3, "{}", w.redact(&declined.stdout));
    assert!(
        declined.stdout.contains(&relay_display(OTHER_RELAY)),
        "the prompt shows the delta"
    );
    path_unseen("the approval prompt", &declined.stdout);
    assert_eq!(
        local_records(&w).len(),
        2,
        "a declined prompt consumed a record"
    );
    assert_eq!(stored(&w), before);
    observe(
        CASE,
        "route-declined",
        "another_relay=APPROVAL_REQUIRED approve_prompt_answered=no exit=3 \
         record=still_pending routes=unchanged",
    );

    // route-approve
    let approved = w.confirm_answers(&["--json", "decision", "approve", &first], &["yes"]);
    let shown = &approved.stdout;
    path_unseen("the approval prompt and its answer", shown);
    assert!(
        shown.contains(&relay_display(RELAY))
            && shown.contains("\"origin\": \"local\"")
            && shown.contains(&ep),
        "the approval prompt did not show the recorded request and delta: {}",
        w.redact(shown)
    );
    let result = answer(&approved);
    assert_eq!(result["code"], "OK", "{result}");
    assert_eq!(approved.code, 0);
    let route = result["data"]["route"].as_str().unwrap().to_owned();
    let (routes, consents) = stored(&w);
    let added = routes
        .iter()
        .find(|r| r.id.as_str() == route)
        .expect("the approved route is stored");
    assert_eq!(
        added.exposure.as_ref().map(|e| &e.infrastructure),
        Some(&InfrastructureProfile::Custom {
            relays: vec![RELAY.to_owned()]
        })
    );
    // The recorded consent: this decision, this delta, this route; and no other.
    assert_eq!(consents.len(), 1, "{consents:?}");
    assert_eq!(consents[0].decision.as_str(), first);
    assert_eq!(
        consents[0].route.as_ref().map(|r| r.as_str()),
        Some(route.as_str())
    );
    assert_eq!(consents[0].delta.relays_added, vec![RELAY.to_owned()]);
    assert_eq!(added.consents, vec![consents[0].consent.clone()]);
    assert!(
        routes
            .iter()
            .all(|r| r.id.as_str() == route || r.exposure.is_none()),
        "another route gained a policy: {routes:?}"
    );
    let after = (routes, consents);
    // The same widening again is the route that now exists: no new record.
    let again = answer(&w.confirm_answers(&add, &[]));
    assert_eq!(again["code"], "OK", "{again}");
    assert_eq!(again["data"]["already_present"], true, "{again}");
    path_unseen("already_present", &again.to_string());
    for args in [
        &["--json", "inspect", "destinations"][..],
        &["--json", "operation", "events", "--limit", "500"][..],
    ] {
        let out = w.cli(args);
        assert_eq!(
            out.json()["code"],
            "OK",
            "{args:?}: {}",
            w.redact(&out.stdout)
        );
        path_unseen(&format!("{args:?}"), &out.stdout);
    }
    assert_eq!(again["data"]["route"], route.as_str(), "{again}");
    let left: Vec<String> = decisions(&w)
        .iter()
        .map(|d| d["decision_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        !left.contains(&first),
        "the approved record is still pending"
    );
    // A second approval of the consumed record applies nothing.
    let twice = w.confirm_answers(&["--json", "decision", "approve", &first], &["yes"]);
    assert_ne!(twice.code, 0, "{}", w.redact(&twice.stdout));
    assert_eq!(stored(&w), after);
    observe(
        CASE,
        "route-approve",
        "command=decision_approve session=terminal prompt_shows=request_and_delta typed=yes \
         answer=OK route=approved_with_relay_policy same_command_again=already_present \
         second_approval=refused",
    );
}

/// `transport adopt-roost` on a controller (module docs; the `iroh` build): refused
/// unattended; on a terminal a local decision record bound to the roost's endpoint and its
/// disclosed exposure; a retry returns it; the attended approval adds the roost as a route
/// with its recorded consent. Observation lines `roost-*`.
pub(crate) fn adopt_roost() {
    let Some(w) = world() else {
        return;
    };
    let before = stored(&w);
    let roost = endpoint('c');
    let adopt = [
        "--json",
        "transport",
        "adopt-roost",
        DEST,
        "--endpoint",
        &roost,
    ];

    let unattended = w.cli(&adopt).json();
    assert_eq!(unattended["code"], "INTERACTION_REQUIRED", "{unattended}");
    assert!(
        unattended["data"]["error"].get("reason").is_none(),
        "{unattended}"
    );
    let detail = unattended["data"]["error"]["message"].as_str().unwrap();
    assert!(
        detail.contains("`transport.adopt_roost` widens") && detail.contains("an external roost"),
        "{detail}"
    );
    assert!(local_records(&w).is_empty());
    assert_eq!(stored(&w), before);
    observe(
        CASE,
        "roost-unattended",
        "command=transport_adopt_roost session=non_interactive answer=INTERACTION_REQUIRED \
         detail=names_the_widening reason=none decisions_recorded=0 routes=unchanged",
    );

    let submitted = w.confirm_answers(&adopt, &[]);
    let first = decision_ref(&answer(&submitted));
    assert_eq!(submitted.code, 3, "{}", w.redact(&submitted.stdout));
    let records = local_records(&w);
    assert_eq!(records.len(), 1, "{records:?}");
    let record = &records[0];
    assert_eq!(record["decision_id"], first.as_str(), "{record}");
    assert_eq!(
        record["request"]["request_kind"], "transport.adopt_roost",
        "{record}"
    );
    assert_eq!(
        record["request"]["exposure"]["external_roost"],
        roost.as_str(),
        "{record}"
    );
    let retried = w.confirm_answers(&adopt, &[]);
    assert_eq!(decision_ref(&answer(&retried)), first);
    assert_eq!(local_records(&w).len(), 1, "a retry made a second record");
    assert_eq!(stored(&w), before, "a pending record wrote a route");
    observe(
        CASE,
        "roost-submit",
        "command=transport_adopt_roost session=terminal answer=APPROVAL_REQUIRED exit=3 \
         record_origin=local record_client=none delta_names_roost=true \
         same_command_again=the_same_record routes=unchanged",
    );

    let silent = w.cli(&["--json", "decision", "approve", &first]);
    assert_eq!(silent.code, 3, "{}", silent.stdout);
    assert_eq!(stored(&w), before);

    let approved = w.confirm_answers(&["--json", "decision", "approve", &first], &["yes"]);
    assert!(
        approved.stdout.contains(&roost) && approved.stdout.contains("\"origin\": \"local\""),
        "the approval prompt did not show the recorded request and delta: {}",
        w.redact(&approved.stdout)
    );
    let result = answer(&approved);
    assert_eq!(result["code"], "OK", "{result}");
    let route = result["data"]["route"].as_str().unwrap().to_owned();
    assert_eq!(
        result["data"]["disclosure"].as_array().map(Vec::len),
        Some(3),
        "{result}"
    );
    let (routes, consents) = stored(&w);
    let added = routes
        .iter()
        .find(|r| r.id.as_str() == route)
        .expect("the roost's route is stored");
    assert!(
        matches!(
            &added.route,
            heimdall_contract::route::RouteSpec::Iroh { endpoint, external_roost: true, .. }
                if endpoint.as_str() == roost
        ),
        "{added:?}"
    );
    assert_eq!(consents.len(), 1, "{consents:?}");
    assert_eq!(consents[0].decision.as_str(), first);
    assert_eq!(
        consents[0]
            .delta
            .external_roost
            .as_ref()
            .map(|e| e.as_str()),
        Some(roost.as_str())
    );
    assert_eq!(added.consents, vec![consents[0].consent.clone()]);
    assert!(local_records(&w).is_empty());
    // The roost again is refused (it is a route already) and makes no record.
    let again = answer(&w.confirm_answers(&adopt, &[]));
    assert_eq!(again["code"], "CONFIG_CONFLICT", "{again}");
    assert!(local_records(&w).is_empty());
    observe(
        CASE,
        "roost-approve",
        "unattended_decision_approve=nothing_sent terminal_decision_approve=OK typed=yes \
         prompt_shows=request_and_delta route=external_roost consent=this_decision_and_delta \
         disclosure_lines=3 same_command_again=CONFIG_CONFLICT_no_record",
    );
}
