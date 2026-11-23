//! ⟨M06 W5 `w5o` item 7⟩ **A26's Iroh leg through a projected alias**: a CONTROLLER
//! installation dials over Iroh with **ordinary `ssh <alias>`**, the real `--features iroh`
//! binary and real Iroh traffic on loopback. Observation lines:
//! `m06 observation: a26-iroh-alias <step>: <result> key_store=fixture_store`.
//!
//! Why a controller: a runner has no catalog pin and no alias projection of its grants
//! (ADR-0012 §5, ruling of 2026-11-22: a runner dialing onward over Iroh through a projected
//! alias is outside V1). The runner-as-dialer journey (`a26.rs`) stays the mechanism part:
//! the helper named by hand.
//!
//! **The installations** (one host; every K_iroh and K_mgmt in a fixture store, so this is
//! mechanism evidence with the product binary, never product persistence of a key):
//! * the *dialing* side is M03's exit world (`exit_m03/world.rs`): a controller whose
//!   catalog the product's own commands built (`identity adopt`, `destination add`,
//!   `destination prefer`, `setup apply`), with a managed-certificate destination `ex1`
//!   (alias `exit1`), a fixture sshd that trusts the world's CA. Nothing is seeded;
//! * the *serving* side is a runner (`a26::serving_runner`) whose serve child forwards to
//!   that same fixture sshd; a second serving runner forwards to a **wrong host** (a
//!   fixture sshd with its own per-run host key).
//!
//! Steps:
//! * `dialer-key`: the controller's real `transport enable` creates its endpoint key;
//! * `serve`: each serving runner's local owner enables serving on a terminal and approves
//!   the local decision with a typed `yes`;
//! * `route-widening`: on the controller, `route add ex1 --iroh <endpoint> --address
//!   <loopback> --relay <URL>` on a terminal is a widening: `APPROVAL_REQUIRED` with a
//!   local decision record (`origin: local`, no client) whose delta names the relay; the
//!   attended `decision approve` (typed `yes`) stores the route with its consent. The relay
//!   URL is a closed loopback port: nothing leaves the host, and the route still dials its
//!   approved direct address;
//! * `projected`: the routes change nothing until `setup apply`, whose diff shows the
//!   helper; then the alias names it with the catalog pin;
//! * `login-iroh`: `heimdall run --profile exit -- ssh -F <scratch config> exit1` logs in
//!   over the Iroh route (the destination sshd saw one connection, from the serve child;
//!   `inspect destinations` names the Iroh route as the one used);
//! * `helper-by-hand` (item 8): the route helper invoked with other arguments than the
//!   alias's own `ProxyCommand` is refused `host_pin_defeated: proxycommand` before any
//!   route: where P projects the alias through the helper, only that invocation connects;
//! * `failover`: with the serving runtime stopped, the same ordinary login fails over,
//!   before identification, to the destination's own address;
//! * `wrong-host`: an Iroh route to the wrong host's serving runner, preferred first: the
//!   client refuses its key under the catalog pin, nothing is reached on another route.
//!
//! **Isolation.** Every `ssh` is `-F <scratch config>` (`routes::ordinary_login`): the
//! account's `~/.ssh` and the system configuration are not read, and the helper's own
//! `ssh -G` reads the same scratch home (`HEIMDALL_TEST_SSH_HOME`). Loopback only.

use std::time::Duration;

use heimdall_testkit::home::Scratch;
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};
use serde_json::Value;

use super::a26::{local_owner_terminal, read, serving_runner, wait_for};
use super::m03world::{Out, World, WorldOptions};
use super::m06::{blocked, children_of};
use super::routes::{alias_block, inspected, ordinary_login};

const CASE: &str = "a26-iroh-alias";
const DEST: &str = "ex1";
const ALIAS: &str = "exit1";

fn observe(step: &str, result: &str) {
    super::m06::observe(CASE, step, format!("{result} key_store=fixture_store"));
}

fn ok(w: &World, args: &[&str]) -> Value {
    let out = w.cli(args);
    let answer = out.json();
    assert_eq!(answer["code"], "OK", "{args:?}: {answer} {}", out.stderr);
    answer
}

fn route_ids(answer: &Value) -> Vec<String> {
    answer["data"]["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_owned())
        .collect()
}

fn logged_in(out: &Out, marker: &str) -> bool {
    out.code == 0 && out.stdout.contains(marker)
}

fn connections(sshd: &LoopbackSshd, mark: u64) -> usize {
    sshd.log_lines_since(mark, "Connection from ").len()
}

/// A serving runner named `name` that serves `sshd_port` of this host's loopback to
/// `dialer`: its local owner enables serving on a terminal and approves the decision with a
/// typed `yes`. Returns the runner's world, its runtime's PID, its endpoint ID and the
/// port its serve child bound.
fn serving(
    scratch: &Scratch,
    name: &str,
    owner: u8,
    dialer: &str,
    account: &str,
    sshd_port: u16,
) -> Option<(super::a26::Serving, u32, String, u16)> {
    let (s, runtime) = serving_runner(scratch, name, [owner; 16], dialer, account)?;
    let port_text = sshd_port.to_string();
    let enable = ["transport", "enable", "--serve", "--sshd-port", &port_text];
    let (code, submitted) = local_owner_terminal(&s.runner, &enable, None);
    assert_eq!(submitted["code"], "APPROVAL_REQUIRED", "{submitted}");
    assert_eq!(code, 3, "{submitted}");
    let decision = submitted["next"]["decision_ref"]
        .as_str()
        .unwrap()
        .to_owned();
    let (code, approved) =
        local_owner_terminal(&s.runner, &["decision", "approve", &decision], Some("yes"));
    assert_eq!(approved["code"], "OK", "{approved}");
    assert_eq!(code, 0, "{approved}");
    assert_eq!(
        approved["data"]["store_kind"], "fixture_store",
        "{approved}"
    );
    let endpoint = approved["data"]["endpoint"].as_str().unwrap().to_owned();
    let port = wait_for(
        "the serve child bound no port",
        Duration::from_secs(30),
        || read(&s.runner.home, |tx| tx.transport_serve_port()),
    );
    wait_for("no serve child", Duration::from_secs(30), || {
        children_of(runtime).first().copied()
    });
    Some((s, runtime, endpoint, port))
}

pub(crate) fn journey() {
    let scratch = Scratch::new().unwrap();
    let Ok(target) = LoopbackSshd::start(
        &scratch,
        SshdConfig {
            registry_seed: Some(Vec::new()),
            ..SshdConfig::default()
        },
    ) else {
        blocked(CASE, "no fixture sshd on this host");
        return;
    };
    // The wrong host: its own per-run host key. Nothing authenticates there.
    let wrong = LoopbackSshd::start(&scratch, SshdConfig::default()).unwrap();
    // The controller's key stores are fixtures: nothing here reaches the account's own.
    let stores = scratch.path().join("stores");
    let (mgmt, iroh) = (stores.join("mgmt"), stores.join("iroh"));
    for dir in [&mgmt, &iroh] {
        std::fs::create_dir_all(dir).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
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
    let target = w.pairs[0].sshd.clone();
    let account = w.pairs[0].account.clone();
    let pin_file = w.hh.join("config").join("keys").join("host_pins");

    // dialer-key: the controller's own endpoint key (a minimal dialer needs no decision).
    let enabled = ok(&w, &["--json", "transport", "enable"]);
    assert_eq!(enabled["data"]["store_kind"], "fixture_store", "{enabled}");
    assert_eq!(enabled["data"]["serve"], false, "{enabled}");
    let dialer = enabled["data"]["endpoint"].as_str().unwrap().to_owned();
    observe(
        "dialer-key",
        "installation=controller command=transport_enable decision=none_needed serve=false \
         store_kind=fixture_store",
    );

    // serve: one runner in front of the destination, one in front of the wrong host.
    let Some((mut s, _, serving_endpoint, serve_port)) =
        serving(&scratch, "s", 0x31, &dialer, &account, target.port)
    else {
        blocked(CASE, "no fixture sshd for the serving runner");
        return;
    };
    let Some((x, _, wrong_endpoint, wrong_port)) =
        serving(&scratch, "x", 0x32, &dialer, &account, wrong.port)
    else {
        blocked(CASE, "no fixture sshd for the wrong host's serving runner");
        return;
    };
    observe(
        "serve",
        "serving_runners=2 (destination,wrong_host) each=local_owner_on_a_terminal_typed_yes \
         bind=loopback relays=none dialer_admitted_at=remote_init",
    );

    // route-widening: an Iroh route with a relay is a widening; approved locally.
    let closed = {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    let relay = format!("http://127.0.0.1:{closed}/");
    let address = format!("127.0.0.1:{serve_port}");
    let add = [
        "--json",
        "route",
        "add",
        DEST,
        "--iroh",
        &serving_endpoint,
        "--address",
        &address,
        "--relay",
        &relay,
    ];
    let unattended = w.cli(&add).json();
    assert_eq!(unattended["code"], "INTERACTION_REQUIRED", "{unattended}");
    let submitted = w.confirm_answers(&add, &[]);
    assert_eq!(submitted.code, 3, "{}", w.redact(&submitted.stdout));
    let pending = submitted.json();
    assert_eq!(pending["code"], "APPROVAL_REQUIRED", "{pending}");
    let decision = pending["next"]["decision_ref"].as_str().unwrap().to_owned();
    let listed = ok(&w, &["--json", "inspect", "decisions"]);
    let record = listed["data"]["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["decision_id"] == decision.as_str())
        .cloned()
        .unwrap_or_else(|| panic!("the decision is listed: {listed}"));
    assert_eq!(record["request"]["origin"], "local", "{record}");
    assert!(record["request"].get("client").is_none(), "{record}");
    assert_eq!(
        record["request"]["exposure"]["relays_added"],
        // ⟨`w5s`, M06-W5-R05⟩ Shown as scheme, host and port with the URL's digest.
        serde_json::json!([heimdall_contract::route::relay_display(&relay)]),
        "{record}"
    );
    let approved = w.confirm_answers(&["--json", "decision", "approve", &decision], &["yes"]);
    assert_eq!(approved.code, 0, "{}", w.redact(&approved.stdout));
    let approved = approved.json();
    assert_eq!(approved["code"], "OK", "{approved}");
    let iroh_route = approved["data"]["route"].as_str().unwrap().to_owned();
    let listed_routes = route_ids(&approved);
    assert_eq!(listed_routes.len(), 2, "{approved}");
    let own_route = listed_routes
        .iter()
        .find(|r| **r != iroh_route)
        .cloned()
        .unwrap();
    observe(
        "route-widening",
        "command=route_add_iroh_address_relay unattended=INTERACTION_REQUIRED \
         on_terminal=APPROVAL_REQUIRED record_origin=local record_client=none \
         delta_names_relay=true decision_approve_typed_yes=OK \
         approved=(definition_address,iroh) relay=closed_loopback_port",
    );

    // projected: nothing until `setup apply`, which shows the helper first.
    let before = alias_block(&w, ALIAS);
    assert!(
        !before.iter().any(|l| l.contains("ProxyCommand")) && !pin_file.exists(),
        "the route changed P without a setup apply: {before:?}"
    );
    let applied = w.confirm_answers(&["setup", "apply"], &["yes"]);
    assert_eq!(applied.code, 0, "{}", w.redact(&applied.stdout));
    assert!(
        applied.stdout.contains("ProxyCommand") && applied.stdout.contains("route connect"),
        "the apply did not show the helper before writing it: {}",
        w.redact(&applied.stdout)
    );
    let block = alias_block(&w, ALIAS);
    assert!(
        block
            .iter()
            .any(|l| l.trim_start().starts_with("ProxyCommand ") && l.contains("route connect")),
        "{block:?}"
    );
    assert!(
        block
            .iter()
            .any(|l| l.trim() == format!("HostKeyAlias hm-dest-{DEST}")),
        "{block:?}"
    );
    assert!(pin_file.exists());
    observe(
        "projected",
        "after_route_add=p_unchanged setup_apply_diff_shows=ProxyCommand_route_connect \
         alias_after=helper,HostKeyAlias,catalog_pin_file",
    );

    // login-iroh: ordinary `ssh exit1`, the Iroh route first.
    let preferred = ok(&w, &["--json", "route", "prefer", DEST, &iroh_route]);
    assert_eq!(route_ids(&preferred)[0], iroh_route);
    let t0 = target.log_mark();
    let over = ordinary_login(&w, ALIAS, "iroh-alias-1", "hm-iroh-alias");
    assert!(
        logged_in(&over, "hm-iroh-alias"),
        "an ordinary login over the Iroh route: {} {}",
        over.stdout,
        w.redact(&over.stderr)
    );
    assert_eq!(connections(&target, t0), 1);
    let health = inspected(&w, DEST)["route_health"]["result"].clone();
    assert_eq!(health["final_route"], iroh_route.as_str(), "{health}");
    assert_eq!(health["kind"], "health", "{health}");
    observe(
        "login-iroh",
        "dialer=controller login=ordinary_ssh_alias_through_heimdall_run \
         command_line_options=F_scratch_config,BatchMode,ConnectTimeout route_used=iroh \
         login_result=ok destination_connections=1 host_key=catalog_pin \
         credential=managed_certificate_of_the_aliases_own_endpoint \
         inspect_route_health=final_route_is_the_iroh_route",
    );

    // helper-by-hand: on this installation the alias is projected through the helper, so
    // a helper invocation that is not that alias's own proxy (here: another endpoint) is
    // refused before any route, whoever names it.
    let t0 = target.log_mark();
    let mut by_hand = std::process::Command::new(super::m03world::bin());
    by_hand
        .args([
            "route",
            "connect",
            "--destination",
            DEST,
            "--account",
            &account,
            "--endpoint",
        ])
        .arg(scratch.path().join("no-such-agent.sock"))
        .env_clear()
        .envs(w.env())
        .current_dir(&w.home.root)
        .stdin(std::process::Stdio::null());
    let out = super::m03world::run_bounded(&mut by_hand, Duration::from_secs(60));
    assert_ne!(out.code, 0, "{} {}", out.stdout, out.stderr);
    assert!(
        out.stderr.contains("host_pin_defeated: proxycommand"),
        "{}",
        w.redact(&out.stderr)
    );
    assert!(out.stdout.is_empty(), "the helper wrote SSH bytes");
    assert_eq!(connections(&target, t0), 0);
    observe(
        "helper-by-hand",
        "helper_invocation=not_the_projected_aliass_proxy (another_endpoint) \
         result=refused reason=host_pin_defeated setting=proxycommand routes_tried=0 \
         destination_connections=0",
    );

    // wrong-host: the wrong host's serving runner, first. Never retried on another route.
    let wrong_address = format!("127.0.0.1:{wrong_port}");
    let wrong_added = ok(
        &w,
        &[
            "--json",
            "route",
            "add",
            DEST,
            "--iroh",
            &wrong_endpoint,
            "--address",
            &wrong_address,
        ],
    );
    let wrong_route = wrong_added["data"]["route"].as_str().unwrap().to_owned();
    let preferred = ok(&w, &["--json", "route", "prefer", DEST, &wrong_route]);
    assert_eq!(route_ids(&preferred)[0], wrong_route);
    let (t0, w0) = (target.log_mark(), wrong.log_mark());
    let refused = ordinary_login(&w, ALIAS, "iroh-alias-wrong", "hm-iroh-wrong");
    assert!(
        !logged_in(&refused, "hm-iroh-wrong") && refused.code != 0,
        "a login over the wrong host's Iroh route succeeded: {} {}",
        refused.stdout,
        refused.stderr
    );
    assert!(
        refused.stderr.contains("Host key verification failed")
            || refused.stderr.contains("HOST IDENTIFICATION HAS CHANGED"),
        "the login did not fail on host trust: {}",
        w.redact(&refused.stderr)
    );
    assert_eq!(
        connections(&wrong, w0),
        1,
        "the wrong host was reached once"
    );
    assert_eq!(
        connections(&target, t0),
        0,
        "after a host-key refusal the helper went on to another route"
    );
    ok(&w, &["--json", "route", "remove", DEST, &wrong_route]);
    observe(
        "wrong-host",
        "preferred=iroh_route_to_the_wrong_hosts_serving_runner \
         approved_after_it=(iroh,definition_address) login_result=refused \
         cause=host_key_verification_under_the_catalog_pin wrong_host_connections=1 \
         destination_connections=0 retried_on_another_route=false",
    );

    // failover: the serving runtime stopped; the next approved route is the direct one.
    let preferred = ok(&w, &["--json", "route", "prefer", DEST, &iroh_route]);
    assert_eq!(route_ids(&preferred)[0], iroh_route);
    s.runner.runtime_stop();
    let t0 = target.log_mark();
    let failed_over = ordinary_login(&w, ALIAS, "iroh-alias-failover", "hm-iroh-failover");
    assert!(
        logged_in(&failed_over, "hm-iroh-failover"),
        "failover before identification: {} {}",
        failed_over.stdout,
        w.redact(&failed_over.stderr)
    );
    assert_eq!(connections(&target, t0), 1);
    let health = inspected(&w, DEST)["route_health"]["result"].clone();
    assert_eq!(health["kind"], "failed_over", "{health}");
    assert_eq!(
        health["attempts"][0]["route"],
        iroh_route.as_str(),
        "{health}"
    );
    assert!(health["attempts"][0]["failure"].is_string(), "{health}");
    assert_eq!(health["final_route"], own_route.as_str(), "{health}");
    observe(
        "failover",
        &format!(
            "serving_runtime=stopped login=ordinary_ssh_alias login_result=ok \
             first_attempt=iroh_route_{} failover=before_identification \
             final_route=definition_address destination_connections=1",
            health["attempts"][0]["failure"].as_str().unwrap_or("none")
        ),
    );
    drop(x);
    drop(s);
}
