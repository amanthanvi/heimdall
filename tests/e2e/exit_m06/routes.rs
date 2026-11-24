//! ⟨M06 W5 `w5f`, rewritten by `w5n`⟩ **A26's routes and host trust without Iroh** (m06-plan
//! §3 row "A26", "routes" and "host pins"; ADR-0012 §5), with the real binary on one host,
//! through **ordinary `ssh <alias>`**: every login here is `ssh -F <scratch config> exit1`
//! with no host-trust or proxy option on the command line, so the projected alias alone
//! decides the route helper, the catalog pin and the binding. Observation lines:
//! `m06 observation: a26-routes <step>: <result>`.
//!
//! **The installation** is M03's exit world (`exit_m03/world.rs`): its catalog is built
//! with the product's commands (`identity adopt`, `destination add`, `destination prefer`,
//! `setup apply`), so `route add` has the managed catalog destination it needs and nothing
//! is seeded for the routes. The destination `ex1` (alias `exit1`) is a fixture sshd that
//! trusts the world's CA; `ex2` is a second fixture sshd that permits forwarding to it (the
//! bastion); a third fixture sshd with its own host key is the **wrong host**. Logins are
//! `heimdall run --profile exit -- ssh …` (a managed binding holds the pairs' slots, which
//! is what the alias's own `IdentityAgent`, the environment endpoint, serves).
//!
//! Steps:
//! * `routes`: `route add --jump` and `route add --direct` approve a jump route and a second
//!   direct route (the wrong host) beside the destination's own address;
//! * `upgrade`: the routes are approved and P is **unchanged** (nothing is projected
//!   silently); `setup apply` shows the helper in its diff, and only then P names it, with
//!   the pin file holding the catalog's keys of the destination and the bastion;
//! * `jump` and `direct`: the jump route preferred first, then the destination's own
//!   address: both log in, the first through the bastion, with the route used read back
//!   from `inspect destinations` (`route_health`);
//! * `wrong-host`: the wrong host preferred first: the client refuses its key under the
//!   catalog pin and the helper does **not** go on to another approved route;
//! * `failover`: a closed port first: the helper moves on before any identification;
//! * `two-hop-substitution`: the bastion's key, then the destination's, substituted in the
//!   pin file: refused before any route is tried, nothing is reached;
//! * `host-pin-defeated`: a line above Heimdall's include block that weakens strict
//!   checking: the helper refuses `host_pin_defeated` naming the setting, nothing is
//!   reached, and `doctor` and `inspect destinations` report it; with the line gone the
//!   login works again.
//!
//! * `undetermined-backstop` (⟨`w5o`⟩): a pin setting behind a `Match exec` above the
//!   include block: the static doctor shows the pin status as undetermined and runs
//!   nothing; the helper's own `ssh -G` check refuses the login `host_pin_defeated` before
//!   any route.
//!
//! **Isolation.** `-F <scratch config>` only: the system configuration is not read, the
//! account's `~/.ssh` is not read, and the trust file is the scratch pin file the alias
//! itself names (a `UserKnownHostsFile` option on the command line would replace the very
//! setting under test). `BatchMode` and `ConnectTimeout` are the only options given.

use std::process::Command;
use std::time::Duration;

use heimdall_testkit::assert_no_canary;
use heimdall_testkit::home::Scratch;
use heimdall_testkit::sshd::{LOOPBACK, LoopbackSshd, SshdConfig};
use serde_json::Value;

use super::m03world::{self, Out, World, WorldOptions};
use super::m06::{blocked, observe};

const CASE: &str = "a26-routes";
/// The destination and the bastion in the world (`ex<n>` / `exit<n>`, in server order).
const DEST: &str = "ex1";
const ALIAS: &str = "exit1";
const BASTION: &str = "ex2";

/// `heimdall run --profile exit -- ssh -F <scratch config> -o BatchMode=yes -o
/// ConnectTimeout=30 exit1 'echo <marker>'`: an ordinary login through the projected alias,
/// retried while an earlier launch's binding still holds the pairs' slots.
pub(crate) fn ordinary_login(w: &World, alias: &str, work: &str, marker: &str) -> Out {
    slots_free(w);
    let mut last = None;
    for _ in 0..40 {
        let mut cmd = Command::new(m03world::bin());
        cmd.args([
            "run",
            "--profile",
            "exit",
            "--work-id",
            work,
            "--request-id",
            &format!("req-{work}"),
            "--",
        ])
        .arg(m03world::openssh("ssh"))
        .arg("-F")
        .arg(&w.home.user_config)
        .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=30", alias])
        .arg(format!("echo {marker}"))
        .env_clear()
        .envs(w.env())
        .current_dir(&w.home.root);
        let out = m03world::run_bounded(&mut cmd, Duration::from_secs(120));
        assert_no_canary(&out.stdout);
        assert_no_canary(&out.stderr);
        let held = out.stderr.contains("managed_slot_held");
        last = Some(out);
        if !held {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    last.unwrap()
}

/// Wait until no binding holds (or is handing over) any pair's ordinary-alias slot.
///
/// Each login here is new work. A launch that starts while the previous login's binding
/// is still being released **joins** its slot (ADR-0011 §5.2), and the slot is then handed
/// over and written again from the new grant: for that moment the environment endpoint
/// lists no certificate for the pair, which an ordinary `ssh` reads as no identity. That
/// window is M05's, not this journey's subject, so every login starts from free slots.
fn slots_free(w: &World) {
    use heimdall_domain::managed::SlotState;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let states: Vec<SlotState> = w
            .pairs
            .iter()
            .map(|p| {
                let pair = heimdall_domain::scope::AccessPair {
                    destination: heimdall_contract::ids::DestinationId::parse(&p.destination)
                        .unwrap(),
                    account: heimdall_contract::ids::AccountName::parse(&p.account).unwrap(),
                };
                w.read_store()
                    .transaction(|tx| tx.slot(&w.environment, &pair))
                    .unwrap()
            })
            .collect();
        if states.iter().all(|s| matches!(s, SlotState::Free { .. })) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the ordinary-alias slots did not become free: {states:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn login(w: &World, work: &str, marker: &str) -> Out {
    ordinary_login(w, ALIAS, work, marker)
}

fn logged_in(out: &Out, marker: &str) -> bool {
    out.code == 0 && out.stdout.contains(marker)
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

/// The connections `sshd` logged after `mark`.
fn connections(sshd: &LoopbackSshd, mark: u64) -> usize {
    sshd.log_lines_since(mark, "Connection from ").len()
}

/// The `Host <alias>` block of P.
pub(crate) fn alias_block(w: &World, alias: &str) -> Vec<String> {
    let managed = std::fs::read_to_string(w.hh.join("config").join("ssh_config")).unwrap();
    managed
        .lines()
        .skip_while(|l| l.trim() != format!("Host {alias}"))
        .skip(1)
        .take_while(|l| !l.starts_with("Host "))
        .map(str::to_owned)
        .collect()
}

/// `inspect destinations`' item of `destination`.
pub(crate) fn inspected(w: &World, destination: &str) -> Value {
    let listed = ok(w, &["--json", "inspect", "destinations"]);
    listed["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["destination_id"] == destination)
        .cloned()
        .unwrap_or_else(|| panic!("{destination} is listed: {listed}"))
}

/// `<type> <base64>` of an OpenSSH `known_hosts` or public-key line.
fn key_of(line: &str) -> String {
    let words: Vec<&str> = line.split_whitespace().collect();
    let at = words
        .iter()
        .position(|w| w.starts_with("ssh-") || w.starts_with("ecdsa-"))
        .expect("a key type");
    format!("{} {}", words[at], words[at + 1])
}

pub(crate) fn journey() {
    let scratch = Scratch::new().unwrap();
    let seeded = || SshdConfig {
        registry_seed: Some(Vec::new()),
        ..SshdConfig::default()
    };
    let Ok(target) = LoopbackSshd::start(&scratch, seeded()) else {
        blocked(CASE, "no fixture sshd on this host");
        return;
    };
    let bastion = LoopbackSshd::start(
        &scratch,
        SshdConfig {
            tcp_forwarding_permit_open: Some(vec![format!("{LOOPBACK}:{}", target.port)]),
            ..seeded()
        },
    )
    .unwrap();
    // The wrong host: its own per-run host key, at its own port. Nothing authenticates
    // there: the client refuses its key first.
    let wrong = LoopbackSshd::start(&scratch, SshdConfig::default()).unwrap();
    let (w, ca) = World::start(WorldOptions {
        pairs: 2,
        servers: vec![target, bastion],
        ..WorldOptions::default()
    });
    drop(ca);
    let target = w.pairs[0].sshd.clone();
    let bastion = w.pairs[1].sshd.clone();
    let account = w.pairs[0].account.clone();
    let pin_file = w.hh.join("config").join("keys").join("host_pins");
    let p_file = w.hh.join("config").join("ssh_config");

    // routes: a jump route and a second direct route, through the product.
    let jump = ok(&w, &["--json", "route", "add", DEST, "--jump", BASTION]);
    let jump_route = jump["data"]["route"].as_str().unwrap().to_owned();
    let own_route = route_ids(&jump)[0].clone();
    assert_eq!(route_ids(&jump), [own_route.clone(), jump_route.clone()]);
    let wrong_added = ok(
        &w,
        &[
            "--json",
            "route",
            "add",
            DEST,
            "--direct",
            &format!("{LOOPBACK}:{}", wrong.port),
        ],
    );
    let wrong_route = wrong_added["data"]["route"].as_str().unwrap().to_owned();
    assert_eq!(route_ids(&wrong_added).len(), 3, "{wrong_added}");
    observe(
        CASE,
        "routes",
        "catalog=product_commands route_add_jump=OK route_add_direct=OK approved=3 \
         (definition_address,jump_via_bastion,wrong_host_direct) seeded=nothing",
    );

    // upgrade: routes approved, nothing projected yet; `setup apply` shows it first.
    let p_before = std::fs::read_to_string(&p_file).unwrap();
    let before = alias_block(&w, ALIAS);
    assert!(
        !before.iter().any(|l| l.contains("ProxyCommand")) && !pin_file.exists(),
        "the routes changed P without a setup apply: {before:?}"
    );
    let user_before = std::fs::read(&w.home.user_config).unwrap();
    let applied = w.confirm_answers(&["setup", "apply"], &["yes"]);
    assert_eq!(applied.code, 0, "{}", w.redact(&applied.stdout));
    assert!(
        applied.stdout.contains("ProxyCommand") && applied.stdout.contains("route connect"),
        "the apply did not show the helper before writing it: {}",
        w.redact(&applied.stdout)
    );
    let block = alias_block(&w, ALIAS);
    let helper = block
        .iter()
        .find(|l| l.trim_start().starts_with("ProxyCommand "))
        .unwrap_or_else(|| panic!("the alias names the route helper: {block:?}"));
    let endpoint = block
        .iter()
        .find_map(|l| l.trim().strip_prefix("IdentityAgent "))
        .map(|v| v.trim_matches('"').to_owned())
        .expect("the alias's IdentityAgent");
    assert!(
        helper.contains(&format!(
            "route connect --destination {DEST} --account {account} --endpoint \"{endpoint}\""
        )),
        "{helper}"
    );
    for line in [
        format!("HostKeyAlias hm-dest-{DEST}"),
        "StrictHostKeyChecking yes".to_owned(),
        "GlobalKnownHostsFile none".to_owned(),
        "KnownHostsCommand none".to_owned(),
        "UpdateHostKeys no".to_owned(),
        "VerifyHostKeyDNS no".to_owned(),
        "ControlMaster no".to_owned(),
    ] {
        assert!(block.iter().any(|l| l.trim() == line), "{line}: {block:?}");
    }
    // Only the alias with routes changed; the user's file is byte-identical.
    assert_eq!(alias_block(&w, "exit2"), {
        p_before
            .lines()
            .skip_while(|l| l.trim() != "Host exit2")
            .skip(1)
            .take_while(|l| !l.starts_with("Host "))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    });
    assert_eq!(std::fs::read(&w.home.user_config).unwrap(), user_before);
    let pins = std::fs::read_to_string(&pin_file).unwrap();
    let (target_key, bastion_key) = (
        key_of(&target.host_key_line),
        key_of(&bastion.host_key_line),
    );
    assert_eq!(
        pins,
        format!("hm-dest-{DEST} {target_key}\nhm-dest-{BASTION} {bastion_key}\n"),
        "the pin file holds the catalog's keys only"
    );
    observe(
        CASE,
        "upgrade",
        "after_route_add=p_unchanged,no_pin_file setup_apply_diff_shows=ProxyCommand_route_connect \
         alias_after=helper,HostKeyAlias,StrictHostKeyChecking_yes,catalog_only_trust,no_multiplexing \
         helper_endpoint=the_aliases_own_IdentityAgent other_alias=byte_identical \
         user_config=byte_identical pin_file=destination_and_bastion_catalog_keys",
    );

    // jump: the jump route first. An ordinary login, through the bastion.
    let preferred = ok(&w, &["--json", "route", "prefer", DEST, &jump_route]);
    assert_eq!(route_ids(&preferred)[0], jump_route);
    let (t0, b0, w0) = (target.log_mark(), bastion.log_mark(), wrong.log_mark());
    let through = login(&w, "routes-jump", "hm-routes-jump");
    assert!(
        logged_in(&through, "hm-routes-jump"),
        "an ordinary login through the jump route: {} {}",
        through.stdout,
        through.stderr
    );
    assert_eq!(
        (
            connections(&bastion, b0),
            connections(&target, t0),
            connections(&wrong, w0)
        ),
        (1, 1, 0),
        "the bastion forwarded the one connection to the destination"
    );
    let health = inspected(&w, DEST)["route_health"].clone();
    assert_eq!(
        health["result"]["final_route"],
        jump_route.as_str(),
        "{health} {}",
        w.redact(&through.stderr)
    );
    assert_eq!(health["result"]["kind"], "health", "{health}");
    observe(
        CASE,
        "jump",
        "login=ordinary_ssh_alias preferred=jump_via_bastion login_result=ok bastion_connections=1 \
         destination_connections=1 wrong_host_connections=0 \
         inspect_route_health=final_route_is_the_jump_route binding=resolved_at_the_aliases_own_endpoint",
    );

    // direct: the destination's own address first.
    let preferred = ok(&w, &["--json", "route", "prefer", DEST, &own_route]);
    assert_eq!(route_ids(&preferred)[0], own_route);
    let (t0, b0) = (target.log_mark(), bastion.log_mark());
    let direct = login(&w, "routes-direct", "hm-routes-direct");
    assert!(
        logged_in(&direct, "hm-routes-direct"),
        "{} {}",
        direct.stdout,
        direct.stderr
    );
    assert_eq!(
        (connections(&bastion, b0), connections(&target, t0)),
        (0, 1)
    );
    assert_eq!(
        inspected(&w, DEST)["route_health"]["result"]["final_route"],
        own_route.as_str()
    );
    observe(
        CASE,
        "direct",
        "preferred=definition_address login_result=ok bastion_connections=0 \
         destination_connections=1 inspect_route_health=final_route_is_the_direct_route",
    );

    // wrong-host: the wrong host first; never retried on another route.
    let preferred = ok(&w, &["--json", "route", "prefer", DEST, &wrong_route]);
    assert_eq!(route_ids(&preferred)[0], wrong_route);
    let (t0, b0, w0) = (target.log_mark(), bastion.log_mark(), wrong.log_mark());
    let refused = login(&w, "routes-wrong", "hm-routes-wrong");
    assert!(
        !logged_in(&refused, "hm-routes-wrong") && refused.code != 0,
        "a login through the wrong host's route succeeded: {} {}",
        refused.stdout,
        refused.stderr
    );
    assert!(
        refused.stderr.contains("Host key verification failed")
            || refused.stderr.contains("HOST IDENTIFICATION HAS CHANGED"),
        "the login did not fail on host trust: {}",
        refused.stderr
    );
    assert_eq!(connections(&wrong, w0), 1, "the wrong host was dialed once");
    assert_eq!(
        (connections(&target, t0), connections(&bastion, b0)),
        (0, 0),
        "after a host-key refusal the helper went on to another route"
    );
    observe(
        CASE,
        "wrong-host",
        "preferred=wrong_host_direct approved_after_it=(definition_address,jump_via_bastion) \
         login_result=refused cause=host_key_verification_under_the_catalog_pin \
         wrong_host_connections=1 destination_connections=0 bastion_connections=0 \
         retried_on_another_route=false",
    );

    // failover: a closed port in place of the wrong host.
    let closed = {
        let listener = std::net::TcpListener::bind((LOOPBACK, 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    ok(&w, &["--json", "route", "remove", DEST, &wrong_route]);
    let closed_added = ok(
        &w,
        &[
            "--json",
            "route",
            "add",
            DEST,
            "--direct",
            &format!("{LOOPBACK}:{closed}"),
        ],
    );
    let closed_route = closed_added["data"]["route"].as_str().unwrap().to_owned();
    let first = ok(&w, &["--json", "route", "prefer", DEST, &closed_route]);
    assert_eq!(route_ids(&first)[0], closed_route);
    let t0 = target.log_mark();
    let over = login(&w, "routes-failover", "hm-routes-failover");
    assert!(
        logged_in(&over, "hm-routes-failover"),
        "failover before identification: {} {}",
        over.stdout,
        over.stderr
    );
    assert_eq!(connections(&target, t0), 1);
    let health = inspected(&w, DEST)["route_health"]["result"].clone();
    assert_eq!(health["kind"], "failed_over", "{health}");
    assert_eq!(
        health["attempts"][0]["route"],
        closed_route.as_str(),
        "{health}"
    );
    assert_eq!(health["attempts"][0]["failure"], "refused", "{health}");
    assert_eq!(health["final_route"], own_route.as_str(), "{health}");
    observe(
        CASE,
        "failover",
        "approved=(closed_port_direct,definition_address,jump_via_bastion) login_result=ok \
         failover=before_identification_to_the_next_approved_route \
         inspect_route_health=failed_over,first_attempt_refused,final_route_definition_address",
    );

    // two-hop-substitution: a substituted key in the pin file is refused before any route.
    let wrong_key = key_of(&wrong.host_key_line);
    let jump_first = ok(&w, &["--json", "route", "prefer", DEST, &jump_route]);
    assert_eq!(route_ids(&jump_first)[0], jump_route);
    for (hop, name, real) in [
        ("bastion", BASTION, &bastion_key),
        ("destination", DEST, &target_key),
    ] {
        std::fs::write(
            &pin_file,
            pins.replace(
                &format!("hm-dest-{name} {real}"),
                &format!("hm-dest-{name} {wrong_key}"),
            ),
        )
        .unwrap();
        let (t0, b0) = (target.log_mark(), bastion.log_mark());
        let out = login(&w, &format!("routes-sub-{hop}"), "hm-routes-sub");
        assert!(
            !logged_in(&out, "hm-routes-sub") && out.stderr.contains("host_pin_defeated"),
            "{hop}: {} {}",
            out.stdout,
            out.stderr
        );
        assert_eq!(
            (connections(&target, t0), connections(&bastion, b0)),
            (0, 0),
            "{hop}: a substituted pin was followed by a connection"
        );
    }
    std::fs::write(&pin_file, &pins).unwrap();
    let restored = login(&w, "routes-sub-restored", "hm-routes-restored");
    assert!(
        logged_in(&restored, "hm-routes-restored"),
        "{}",
        restored.stderr
    );
    observe(
        CASE,
        "two-hop-substitution",
        "pin_file_key_substituted=bastion,then_destination each=refused_host_pin_defeated \
         routes_tried=0 destination_connections=0 bastion_connections=0 \
         failed_over_to_the_direct_route=false catalog_pins_restored=login_ok_through_the_jump",
    );

    // host-pin-defeated: a setting above Heimdall's include block weakens strict checking.
    let user = std::fs::read_to_string(&w.home.user_config).unwrap();
    std::fs::write(
        &w.home.user_config,
        format!("StrictHostKeyChecking accept-new\n{user}"),
    )
    .unwrap();
    let (t0, b0) = (target.log_mark(), bastion.log_mark());
    let defeated = login(&w, "routes-defeated", "hm-routes-defeated");
    assert!(
        !logged_in(&defeated, "hm-routes-defeated") && defeated.code != 0,
        "an alias whose pin the configuration defeats logged in: {} {}",
        defeated.stdout,
        defeated.stderr
    );
    assert!(
        defeated
            .stderr
            .contains("host_pin_defeated: stricthostkeychecking"),
        "{}",
        defeated.stderr
    );
    assert_eq!(
        (connections(&target, t0), connections(&bastion, b0)),
        (0, 0)
    );
    let doctor = w.cli(&["--json", "doctor"]).json();
    let finding = doctor["data"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["code"] == "host_pin_defeated")
        .unwrap_or_else(|| panic!("the doctor reports host_pin_defeated: {doctor}"))
        .clone();
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains("stricthostkeychecking"),
        "{finding}"
    );
    let shown = inspected(&w, DEST)["host_pin_defeated"].clone();
    assert_eq!(shown["setting"], "stricthostkeychecking", "{shown}");
    std::fs::write(&w.home.user_config, &user).unwrap();
    let again = login(&w, "routes-undefeated", "hm-routes-undefeated");
    assert!(
        logged_in(&again, "hm-routes-undefeated"),
        "{}",
        again.stderr
    );
    assert!(
        inspected(&w, DEST).get("host_pin_defeated").is_none(),
        "a later login that verified still shows the defeat"
    );
    observe(
        CASE,
        "host-pin-defeated",
        "user_config_line_above_the_include_block=StrictHostKeyChecking_accept-new \
         ordinary_login=refused_by_the_route_helper reason=host_pin_defeated \
         setting=stricthostkeychecking routes_tried=0 destination_connections=0 \
         doctor=host_pin_defeated inspect_destinations=host_pin_defeated \
         line_removed=login_ok,inspect_clear",
    );

    // undetermined-backstop (⟨W5 `w5o` item 11⟩): a pin setting behind a `Match exec`. The
    // static check cannot decide it (the doctor says the pin status is undetermined, not
    // defeated, and runs nothing); the helper's own `ssh -G`, which evaluates the
    // condition as the client does, finds the pin defeated and refuses before any route.
    let ran = w.home.root.join("match-exec-ran");
    std::fs::write(
        &w.home.user_config,
        format!(
            "Match exec \"/usr/bin/touch {}\"\n    StrictHostKeyChecking no\nHost *\n{user}",
            ran.display()
        ),
    )
    .unwrap();
    let doctor = w.cli(&["--json", "doctor"]).json();
    let findings = doctor["data"]["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["code"] == "dynamic_match_unresolved"
                && f["message"].as_str().is_some_and(|m| m
                    .contains("host-key pin status: undetermined")
                    && m.contains(ALIAS))),
        "the static doctor shows the pin status as undetermined: {doctor}"
    );
    assert!(
        !findings.iter().any(|f| f["code"] == "host_pin_defeated"),
        "the static check called an undetermined setting a defeat: {doctor}"
    );
    assert!(
        !ran.exists(),
        "the static doctor ran the configuration's command"
    );
    let (t0, b0) = (target.log_mark(), bastion.log_mark());
    let backstop = login(&w, "routes-backstop", "hm-routes-backstop");
    assert!(
        !logged_in(&backstop, "hm-routes-backstop") && backstop.code != 0,
        "a pin defeated behind a Match exec logged in: {} {}",
        backstop.stdout,
        backstop.stderr
    );
    assert!(
        backstop
            .stderr
            .contains("host_pin_defeated: stricthostkeychecking"),
        "{}",
        backstop.stderr
    );
    assert_eq!(
        (connections(&target, t0), connections(&bastion, b0)),
        (0, 0)
    );
    assert!(
        ran.exists(),
        "the client's own evaluation runs the condition"
    );
    std::fs::write(&w.home.user_config, &user).unwrap();
    let again = login(&w, "routes-backstop-clear", "hm-routes-backstop-clear");
    assert!(
        logged_in(&again, "hm-routes-backstop-clear"),
        "{}",
        again.stderr
    );
    observe(
        CASE,
        "undetermined-backstop",
        "user_config=Match_exec_then_StrictHostKeyChecking_no_above_the_include \
         static_doctor=pin_status_undetermined,not_defeated,ran_nothing \
         ordinary_login=refused_by_the_route_helper_ssh_G reason=host_pin_defeated \
         setting=stricthostkeychecking routes_tried=0 destination_connections=0 \
         lines_removed=login_ok",
    );
}
