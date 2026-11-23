//! ⟨M06 W5 U7⟩ **A24: remote work without its controller** (m06-plan §3 rows "A24" and
//! "No silent controller socket"; spec A24; R-EN-05, R-AU-08), with real binaries on one
//! host.
//!
//! Driven here, one observation line each:
//!
//! * `pair`: the runner-local bootstrap (`remote init --issuer-ca` on a pseudo-terminal, a
//!   typed `yes`) enrolls the controller's K_mgmt as owner and trusts its CA; the
//!   controller's record of the runner is **seeded** in its store (not written by
//!   `environment add`, which needs a verified M03 enrollment);
//! * `approve`: the controller owner's `access ensure --environment <runner>` is admitted by
//!   the runner under the runner's own standing policy and issued by the controller's
//!   production issuer child;
//! * `readiness`: the answer and `environment status` state the earliest bound (the grant's
//!   deadline, which is the certificate's `valid_before`), the refresh dependency
//!   (`controller`) and the conditions; nothing promises more than the bound;
//! * `controller-leaves`: the controller's runtime and its issuer child are stopped (their
//!   process IDs are gone) and the management route is blocked;
//! * `onward-managed`: a new onward `ssh` from the runner to the managed destination
//!   succeeds with the runner's own K_env certificate;
//! * `work-clean-launch` ⟨W5⟩: with the controller gone, runner **work** is launched by the
//!   real `heimdall run` from a process that carries what an SSH session with agent
//!   forwarding leaves behind (`SSH_AUTH_SOCK` naming a disposable fixture agent that
//!   stands for the forwarded one, `SSH_CONNECTION`, a marker variable). The work's
//!   environment is exactly the clean launch's; its only agent is the binding's endpoint,
//!   which lists the K_env certificate and not the fixture agent's key; the forwarded
//!   agent is named `controller_dependency` and is nowhere in the work's environment;
//! * `ordinary-path-agent` ⟨W5⟩: the same fixture agent at its ordinary scratch path with
//!   no SSH session beside it (a signer that may relay to the controller) is reported
//!   `unknown` and is not passed either;
//! * `no-controller-socket`: the binding's endpoint is a socket under the runner's own home
//!   and lists exactly that certificate; neither runtime process is a child of an SSH
//!   session, and the runner's processes were started with no `SSH_AUTH_SOCK`;
//! * `bound`: at the predicted bound, with no controller, managed access fails: the
//!   destination refuses the certificate and `environment status` reports `bound_passed`;
//! * `after-bound`: the runner owner's new request for the managed pair (at a terminal,
//!   naming the controller's CA) is not reported ready: it is a pending grant that waits
//!   for its issuer and names the controller as its dependency;
//! * `forwarded-agent`: a management session that carries a forwarded agent is refused by
//!   the runner's bridge before any frame, so no controller agent reaches the runner.
//!
//! * `onward-fixed` ⟨`w5f`; ADR-0012 §4 item 6⟩: with the controller gone, a new onward
//!   login to a **fixed pair** (a second fixture sshd that trusts no CA and authorizes two
//!   plain keys). The pair is runner-local existing access: an alias of the runner
//!   account's own SSH configuration naming a per-run key **file** of the runner, recorded
//!   in the runner's catalog by the product (`destination add --observed`) and launched by
//!   the real `heimdall connect`, unattended, from a process that carries a forwarded agent
//!   (a counting fixture agent holding the *other* key the destination authorizes: the
//!   "controller's agent"). The destination accepts exactly the runner's own key; the
//!   forwarded agent is never contacted and is named `controller_dependency`;
//! * `fixed-agent-refused` ⟨`w5f`⟩: the same alias made to depend on that forwarded agent
//!   (`IdentityAgent` naming its socket) is refused unattended, `controller_dependency`,
//!   and the destination sees no new connection.
//!
//! **Not driven here** (the unit's `NOT-COVERED.md` has each with its reason): a fixed pair
//! whose existing access is an adopted **agent-held** identity bound by `ensure`/`run` (no
//! product record verifies a runner-local agent as independently managed, so unattended it
//! is refused by construction: `heimdall_runtime::runner::launch`'s tests); the runner
//! host's own socket inventory and "the
//! controller host shows no connection" (a second host); the Windows controller; the
//! lifecycle rows.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{ClientId, GrantId};
use heimdall_credential::mgmt::MgmtKey;
use heimdall_domain::time::Clock as _;
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::home::Scratch;
use serde_json::Value;

use super::m06::{
    alive, blocked, children_of, forwarded_ensure, logs, observe, runner_json, runtime_pid,
};
use super::world::{
    HOUR, Runner, bin, envelope, journey as start, listed_identities, onward_login, pending_grant,
    runner_attended,
};

const CASE: &str = "a24";

/// The lifetime of the journey's grant: long enough for every step before the bound on a
/// loaded host, short enough to wait for.
const LIFETIME_S: u64 = 75;

fn now() -> Timestamp {
    heimdall_runtime::platform::SystemClock.wall()
}

pub(crate) fn journey() {
    let Some(mut j) = start(|_| Vec::new(), 4 * HOUR) else {
        blocked(CASE, "no fixture sshd on this host");
        return;
    };
    let environment = j.environment.clone();
    let account = j.account.clone();
    observe(
        CASE,
        "pair",
        "runner=remote_init_confirmed_on_terminal owner_enrolled=true issuer_trusted=true \
         controller_record=seeded",
    );

    // approve: the forwarded request, admitted by the runner, issued by the controller.
    let asked_at = now();
    let (answer, _) = forwarded_ensure(&j, "job-a24", "a24-fwd-1", &format!("{LIFETIME_S}s"));
    assert_eq!(answer["code"], "OK", "{answer}\n{}", logs(&j));
    let ready = answer["data"].clone();
    let grant = GrantId::parse(ready["grant_id"].as_str().unwrap()).unwrap();
    assert_eq!(ready["environment_id"], environment.as_str());
    assert_eq!(ready["credential_mechanism"], "managed_certificate");
    observe(
        CASE,
        "approve",
        "admitted_by=runner_standing_policy mechanism=managed_certificate \
         issued_by=controller_issuer_child",
    );

    // readiness: the earliest bound, the dependency, the conditions.
    let ts = |v: &Value| -> Timestamp {
        v.as_str()
            .unwrap_or_else(|| panic!("no instant: {ready}"))
            .parse()
            .unwrap()
    };
    let expires = ts(&ready["expires_at"]);
    let offline_until = ts(&ready["offline_until"]);
    let usable_until = ts(&ready["usable_until"]);
    assert_eq!(ready["refresh_dependency"], "controller", "{ready}");
    assert!(
        offline_until <= expires && usable_until <= expires,
        "{ready}"
    );
    let lifetime = expires.duration_since(asked_at).as_secs();
    assert!(
        (0..=i64::try_from(LIFETIME_S).unwrap() + 2).contains(&lifetime),
        "the grant's deadline is the asked lifetime: {lifetime} s"
    );
    let status = j
        .controller
        .wait_for(&environment, "the grant is not reported", |e| {
            e["last_known_readiness"]
                .as_array()
                .is_some_and(|r| r.iter().any(|g| g["grant"] == grant.as_str()))
        });
    assert_eq!(status["connectivity"]["state"], "connected", "{status}");
    assert_eq!(status["issuance"], "reconciled", "{status}");
    assert!(status.get("issuance_failures").is_none(), "{status}");
    let known = status["last_known_readiness"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["grant"] == grant.as_str())
        .unwrap()
        .clone();
    assert_eq!(known["state"], "within_bound", "{status}");
    let bound = ts(&known["offline_until"]);
    assert!(bound <= expires, "never past the grant: {status}");
    let conditions = ready["conditions"].as_array().map_or(0, Vec::len);
    observe(
        CASE,
        "readiness",
        format!(
            "refresh_dependency=controller status=within_bound \
             earliest_bound=certificate_valid_before bound_within_grant_deadline=true \
             conditions={conditions}"
        ),
    );

    // The work on the runner: a local request covered by the live grant attaches to it.
    let local = runner_json(
        &j.runner,
        &[
            "access",
            "ensure",
            "--profile",
            "runner-profile",
            "--pair",
            &format!("h1:{account}"),
            "--work-id",
            "job-a24-local",
            "--for",
            "30s",
            "--request-id",
            "a24-local-1",
        ],
    );
    assert!(
        matches!(local["code"].as_str(), Some("OK" | "ACCESS_READY")),
        "{local}\n{}",
        logs(&j)
    );
    assert_eq!(local["data"]["grant_id"], grant.as_str(), "the same grant");
    assert_eq!(local["data"]["refresh_dependency"], "controller");
    let endpoint = local["data"]["consumer"]["signing_endpoint"]
        .as_str()
        .unwrap_or_else(|| panic!("the binding names no endpoint: {local}"))
        .to_owned();
    let listed = listed_identities(&endpoint);
    assert_eq!(listed.len(), 1, "{listed:?}");
    let facts =
        heimdall_issuer::remote::read_certificate(&listed[0]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(facts.ca_fingerprint, j.ca_fingerprint);
    assert_eq!(facts.principals, vec![j.principal.clone()]);
    assert_ne!(
        facts.subject_fingerprint, j.mgmt_fingerprint,
        "never K_mgmt"
    );

    // controller-leaves: its runtime and issuer child stop; the route is blocked.
    let runtime = runtime_pid(&j.controller).expect("the controller runtime");
    let children = children_of(runtime);
    assert!(
        !children.is_empty(),
        "the controller runtime runs its issuer child"
    );
    j.controller.runtime_stop();
    j.reachable(false);
    let start = Instant::now();
    while children.iter().any(|p| alive(*p)) || alive(runtime) {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "a controller process outlived `service stop`"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    observe(
        CASE,
        "controller-leaves",
        "controller_runtime=stopped issuer_child=stopped management_route=blocked",
    );

    // onward-managed: a new login from the runner, with nothing of the controller left.
    let dir = j.scratch.subdir("onward").unwrap();
    let (ok, out) = onward_login(&dir, &j.destination, &account, &endpoint, &listed[0]);
    assert!(
        ok,
        "onward ssh with the controller gone: {out}\n{}",
        logs(&j)
    );
    let accepted = j.destination.accepted_certificates();
    assert!(
        accepted.iter().any(|c| c.key_id == facts.key_id
            && c.serial == facts.serial
            && c.ca_fingerprint == j.ca_fingerprint.as_str()),
        "{accepted:?}"
    );
    observe(
        CASE,
        "onward-managed",
        "login=ok credential=runner_k_env_certificate signed_by=controller_ca \
         controller=stopped route=blocked",
    );

    // work-clean-launch, ordinary-path-agent: runner work through the real `run`.
    runner_work(&j, &endpoint, &listed);

    // onward-fixed, fixed-agent-refused: the fixed pair, the controller still gone.
    onward_fixed(&j);

    // no-controller-socket: the signer is the runner's own; nothing else is offered.
    let runner_home = std::fs::canonicalize(&j.runner.home).unwrap();
    let socket = std::fs::canonicalize(&endpoint).unwrap_or_else(|_| endpoint.clone().into());
    assert!(
        socket.starts_with(&runner_home),
        "the endpoint is under the runner's own home"
    );
    assert_eq!(listed_identities(&endpoint), listed);
    observe(
        CASE,
        "no-controller-socket",
        "endpoint=under_runner_home identities=1 identity=runner_k_env_certificate \
         runner_started_with_ssh_auth_sock=false",
    );

    // bound: at the predicted bound, with no controller, managed access fails.
    let wait = bound.duration_since(now()).as_secs().max(0) + 2;
    std::thread::sleep(Duration::from_secs(u64::try_from(wait).unwrap()));
    let (ok, out) = onward_login(&dir, &j.destination, &account, &endpoint, &listed[0]);
    assert!(!ok, "a login after the predicted bound: {out}");
    let passed = j.controller.status(&environment);
    let known = passed["last_known_readiness"]
        .as_array()
        .and_then(|r| r.iter().find(|g| g["grant"] == grant.as_str()))
        .unwrap_or_else(|| panic!("the grant left the status: {passed}"));
    assert_eq!(known["state"], "bound_passed", "{passed}");
    assert_ne!(passed["connectivity"]["state"], "connected", "{passed}");
    observe(
        CASE,
        "bound",
        "managed_login_at_predicted_bound=refused status=bound_passed controller=stopped",
    );

    // after-bound: the runner owner's new request for the managed pair (the CA named, at
    // a terminal) is not promised ready: it waits for its issuer and names the controller.
    let ca = j.ca_fingerprint.as_str().to_owned();
    let (_, later) = runner_attended(
        &j.runner,
        &[
            "access",
            "ensure",
            "--profile",
            "runner-profile",
            "--pair",
            &format!("h1:{account}"),
            "--work-id",
            "job-a24-later",
            "--for",
            "10m",
            "--request-id",
            "a24-local-2",
            "--issuer-ca",
            &ca,
            "--timeout-ms",
            "3000",
        ],
    );
    let waiting = pending_grant(&later);
    assert_ne!(waiting, grant, "a new grant, not the one past its bound");
    assert!(
        listed_identities(&endpoint).is_empty() || listed_identities(&endpoint) == listed,
        "nothing new is offered without the issuer"
    );
    observe(
        CASE,
        "after-bound",
        "new_managed_request=ACCEPTED_pending refresh_dependency=controller ready=false \
         issued=nothing",
    );
    drop(j);

    forwarded_agent();
}

/// What the launched work prints: its whole environment, a separator, then what its agent
/// lists.
const WORK_SCRIPT: &str = "/usr/bin/env; echo hm-a24-agent; ssh-add -L; echo hm-a24-end";

/// A marker variable of the launching process, as anything a session leaves behind.
const SESSION_MARK: &str = "HM_A24_SESSION_MARK";

/// One `heimdall run` of runner work on the runner, unattended, from a process whose
/// environment holds `extra` beside the runner's own. `(environment lines, agent lines,
/// stderr)`.
fn launch_work(
    j: &super::world::Journey,
    request: &str,
    extra: &[(&str, &std::ffi::OsStr)],
) -> (Vec<String>, Vec<String>, String) {
    let mut cmd = j.runner.command();
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let out = cmd
        .args([
            "--non-interactive",
            "run",
            "--profile",
            "runner-profile",
            "--work-id",
            "job-a24-local",
            "--request-id",
            request,
            "--",
            "/bin/sh",
            "-c",
            WORK_SCRIPT,
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    // The work's own output is scanned by the caller, after its agent was compared with
    // the fixture agent's (whose key comment is a canary: a leak there is the finding).
    assert_no_canary(&stderr);
    assert!(
        out.status.success() && stdout.contains("hm-a24-end"),
        "runner work did not run: {stdout}\n{stderr}\n{}",
        logs(j)
    );
    let (env, agent) = stdout.split_once("hm-a24-agent\n").unwrap();
    (
        env.lines().map(str::to_owned).collect(),
        agent
            .lines()
            .filter(|l| *l != "hm-a24-end")
            .map(str::to_owned)
            .collect(),
        stderr,
    )
}

/// `work-clean-launch` and `ordinary-path-agent` (module docs). `endpoint` is the live
/// binding's endpoint and `listed` what it lists.
fn runner_work(j: &super::world::Journey, endpoint: &str, listed: &[String]) {
    use heimdall_testkit::agent::{AgentOptions, DisposableSshAgent, FixtureKey, KeyConstraints};
    // The disposable fixture agent that stands for the controller's forwarded one. It is
    // this test's own, in its scratch directory, and holds one per-run key.
    let scratch = Scratch::new().unwrap();
    let Ok(mut forwarded) = DisposableSshAgent::start(&scratch, AgentOptions::default()) else {
        blocked(CASE, "no disposable ssh-agent on this host");
        return;
    };
    let key = FixtureKey::generate();
    forwarded.add_key(&key, KeyConstraints::default()).unwrap();
    let socket = forwarded.socket.clone();
    let socket_text = socket.to_string_lossy().into_owned();
    let stands_for = listed_identities(&socket_text);
    assert_eq!(stands_for.len(), 1, "the fixture agent holds its one key");
    assert_ne!(stands_for, listed);

    let runner_home = std::fs::canonicalize(&j.runner.home).unwrap();
    let first_endpoint = std::fs::canonicalize(endpoint).unwrap();
    let check = |env: &[String], agent: &[String]| {
        assert!(
            !agent.iter().any(|l| stands_for.contains(l)),
            "runner work's agent offers the forwarded agent's key: it was inherited"
        );
        let names: Vec<&str> = env
            .iter()
            .filter_map(|l| l.split_once('=').map(|(k, _)| k))
            .collect();
        let allowed = [
            "HOME",
            "USER",
            "LOGNAME",
            "SHELL",
            "HEIMDALL_HOME",
            "XDG_CONFIG_HOME",
            "XDG_STATE_HOME",
            "XDG_RUNTIME_DIR",
            "PATH",
            "LANG",
            "SSH_AUTH_SOCK",
            // What `sh` itself adds.
            "PWD",
            "SHLVL",
            "_",
            "OLDPWD",
        ];
        for name in &names {
            assert!(
                allowed.contains(name),
                "runner work inherited {name}: {names:?}"
            );
        }
        // The work's agent is its own binding's endpoint: a socket under the runner's own
        // home (each `run` binds its own; the first binding's is `endpoint`).
        let agent_socket = env
            .iter()
            .find_map(|l| l.strip_prefix("SSH_AUTH_SOCK="))
            .unwrap_or_else(|| panic!("runner work has no agent: {names:?}"));
        let resolved = std::fs::canonicalize(agent_socket).unwrap();
        assert!(
            resolved.starts_with(&runner_home) && first_endpoint.starts_with(&runner_home),
            "the work's agent is not an endpoint of this runner"
        );
        assert!(
            env.contains(&"PATH=/usr/local/bin:/usr/bin:/bin".to_owned()),
            "{names:?}"
        );
        // ⟨"Launcher-set values" ⟨2026-11-22⟩⟩ HOME is the account database's, never the
        // launching process's (this runner's scratch account directory).
        let home = env
            .iter()
            .find_map(|l| l.strip_prefix("HOME="))
            .unwrap_or_else(|| panic!("runner work has no HOME: {names:?}"));
        assert_ne!(
            std::path::Path::new(home),
            j.runner.account.as_path(),
            "runner work got the launching process's HOME"
        );
        for set in ["USER", "LOGNAME", "SHELL", "LANG"] {
            assert!(names.contains(&set), "runner work has no {set}: {names:?}");
        }
        assert!(
            !env.iter().any(|l| l.contains(&socket_text)),
            "the forwarded agent's socket reached runner work"
        );
        assert_eq!(
            agent, listed,
            "the work's agent lists the K_env certificate"
        );
        for line in env.iter().chain(agent) {
            assert_no_canary(line);
        }
    };

    // An SSH session with agent forwarding started the launching process.
    let (env, agent, stderr) = launch_work(
        j,
        "a24-work-1",
        &[
            ("SSH_AUTH_SOCK", socket.as_os_str()),
            (
                "SSH_CONNECTION",
                std::ffi::OsStr::new("127.0.0.1 50000 127.0.0.1 22"),
            ),
            (SESSION_MARK, std::ffi::OsStr::new("1")),
        ],
    );
    check(&env, &agent);
    assert!(
        stderr.contains(
            "runner work does not get the inherited agent (provenance: controller_dependency"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains(&socket_text), "a socket path was printed");
    observe(
        CASE,
        "work-clean-launch",
        "launched_by=heimdall_run controller=stopped environment=clean_allowlist_only \
         work_agent=binding_endpoint work_agent_lists=runner_k_env_certificate_only \
         forwarded_agent=fixture_agent_standing_for_it forwarded_agent_inherited=false \
         forwarded_agent_provenance=controller_dependency",
    );

    // The same agent at an ordinary path, with no SSH session beside it.
    let (env, agent, stderr) = launch_work(
        j,
        "a24-work-2",
        &[
            ("SSH_AUTH_SOCK", socket.as_os_str()),
            (SESSION_MARK, std::ffi::OsStr::new("1")),
        ],
    );
    check(&env, &agent);
    assert!(
        stderr.contains("runner work does not get the inherited agent (provenance: unknown"),
        "{stderr}"
    );
    assert!(!stderr.contains("controller_dependency"), "{stderr}");
    observe(
        CASE,
        "ordinary-path-agent",
        "agent_at_ordinary_path=fixture_agent provenance=unknown passed_to_work=false \
         unattended_launch_on_runner_signer=ok",
    );
    forwarded.stop();
}

/// `onward-fixed` and `fixed-agent-refused` (module docs). The controller is stopped and
/// the management route blocked when this runs.
fn onward_fixed(j: &super::world::Journey) {
    use std::os::unix::fs::PermissionsExt as _;

    use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};
    use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};

    const ALIAS: &str = "fixed1";
    let scratch = Scratch::new().unwrap();
    // The runner's own fixed key (a file of the runner account) and the key only the
    // forwarded agent holds. The destination authorizes both, so only the launch decides
    // which one is used.
    let own = FixtureKey::generate();
    let controllers = FixtureKey::generate();
    let Ok(fixed) = LoopbackSshd::start(
        &scratch,
        SshdConfig {
            authorized: vec![own.public().clone(), controllers.public().clone()],
            ..SshdConfig::default()
        },
    ) else {
        blocked(CASE, "no fixture sshd for the fixed pair");
        return;
    };
    let forwarded = FakeAgent::start(
        Endpoint::in_scratch(&scratch, "fwd").unwrap(),
        FakeAgentConfig {
            keys: vec![controllers.clone()],
            mode: AgentMode::Normal,
        },
    );
    let socket = forwarded.endpoint().locator();
    let socket_text = socket.to_string_lossy().into_owned();

    // The runner account's own SSH configuration: the alias, its key file, no agent.
    let ssh_dir = j.runner.account.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    let key_file = ssh_dir.join("id_fixed1");
    own.write_private(&key_file).unwrap();
    let known = ssh_dir.join("known_hosts_fixed1");
    std::fs::write(&known, format!("{}\n", fixed.host_key_line)).unwrap();
    let config = ssh_dir.join("config");
    let before = std::fs::read_to_string(&config).unwrap_or_default();
    let alias_block = |agent: &str| {
        format!(
            "Host {ALIAS}\n  HostName {}\n  Port {}\n  User {}\n  IdentityFile {}\n  \
             IdentitiesOnly yes\n  IdentityAgent {agent}\n  CertificateFile none\n  \
             UserKnownHostsFile {}\n  GlobalKnownHostsFile /dev/null\n  \
             StrictHostKeyChecking yes\n  ControlMaster no\n  ControlPath none\n  \
             BatchMode yes\n  PreferredAuthentications publickey\n  ConnectTimeout 20\n{before}",
            fixed.host,
            fixed.port,
            j.account,
            key_file.display(),
            known.display(),
        )
    };
    std::fs::write(&config, alias_block("none")).unwrap();
    // The client the product launches is the system `ssh`, reading that scratch
    // configuration in place of the account's own (`-F`; nothing else is added).
    let bin_dir = scratch.subdir("bin").unwrap();
    std::fs::write(
        bin_dir.join("ssh"),
        format!(
            "#!/bin/sh\nexec /usr/bin/ssh -F '{}' \"$@\"\n",
            config.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(bin_dir.join("ssh"), std::fs::Permissions::from_mode(0o700)).unwrap();

    // The runner's catalog learns the alias through the product.
    let added = runner_json(&j.runner, &["destination", "add", ALIAS, "--observed"]);
    assert_eq!(added["code"], "OK", "{added}");

    let connect = || {
        let out = j
            .runner
            .command()
            .env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()))
            .env("SSH_AUTH_SOCK", &socket)
            .env("SSH_CONNECTION", "127.0.0.1 50000 127.0.0.1 22")
            .args([
                "--json",
                "--non-interactive",
                "connect",
                ALIAS,
                "--allow-provider-interaction",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_no_canary(&stderr);
        assert!(!stderr.contains(&socket_text), "a socket path was printed");
        (out.status.success(), stderr)
    };
    assert!(j.controller.runtime.is_none(), "the controller is gone");
    let (ok, stderr) = connect();
    assert!(ok, "the fixed pair's login failed: {stderr}");
    let accepted = fixed.accepted_log();
    assert_eq!(accepted.len(), 1, "{accepted:?}");
    assert_eq!(
        accepted[0].fingerprint,
        own.fingerprint(),
        "the destination accepted a key that is not the runner's own"
    );
    assert_eq!(
        forwarded.contact_count(),
        0,
        "the forwarded agent was contacted"
    );
    assert!(
        stderr.contains(
            "runner work does not get the inherited agent (provenance: controller_dependency"
        ),
        "{stderr}"
    );
    observe(
        CASE,
        "onward-fixed",
        "launched_by=heimdall_connect unattended=true controller=stopped route=blocked \
         alias=runner_local_existing_access catalog=destination_add_observed login=ok \
         accepted_key=runner_own_key_file forwarded_agent_contacts=0 \
         forwarded_agent_provenance=controller_dependency",
    );

    // fixed-agent-refused: the alias now depends on the forwarded agent.
    std::fs::write(&config, alias_block(&socket_text)).unwrap();
    let (ok, stderr) = connect();
    assert!(!ok, "an unattended launch on the controller's agent ran");
    let answer: Value = stderr
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str(l).ok())
        .unwrap_or_else(|| panic!("no envelope: {stderr}"));
    assert_eq!(answer["code"], "CAPABILITY_UNAVAILABLE", "{answer}");
    assert_eq!(
        answer["data"]["error"]["reason"], "controller_dependency",
        "{answer}"
    );
    assert_eq!(
        fixed.accepted_log().len(),
        1,
        "a new login reached the destination"
    );
    assert_eq!(forwarded.contact_count(), 0);
    observe(
        CASE,
        "fixed-agent-refused",
        "alias_identity_agent=the_forwarded_agent unattended_connect=refused \
         code=CAPABILITY_UNAVAILABLE reason=controller_dependency destination_logins=none_new \
         forwarded_agent_contacts=0",
    );
    std::fs::write(&config, before).unwrap();
}

/// `forwarded-agent`: the forced command (the bridge), started as sshd would start it for a
/// session that forwards an agent, refuses before any frame; served without one.
fn forwarded_agent() {
    let scratch = Scratch::new().unwrap();
    let runner = Runner::named(&scratch, "fa");
    let key = MgmtKey::generate().unwrap().public().unwrap();
    let key_text = key
        .openssh_line
        .rsplit_once(' ')
        .map(|(k, _)| k.to_owned())
        .unwrap();
    let owner = ClientId::from_random_bytes([0x24; 16]);
    let init = envelope(&runner.remote_init(&owner, &key_text, "yes"));
    assert_eq!(init["code"], "OK", "{init}");
    let bridge = |agent: Option<&Path>| {
        let mut cmd = Command::new(bin());
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &runner.account)
            .args(["remote", "serve", "--client", owner.as_str(), "--home"])
            .arg(&runner.home)
            .stdin(Stdio::null());
        if let Some(agent) = agent {
            cmd.env("SSH_AUTH_SOCK", agent);
        }
        cmd.output().unwrap()
    };
    let served = bridge(None);
    assert!(served.status.success(), "{served:?}");
    let refused = bridge(Some(&scratch.path().join("forwarded-agent.sock")));
    let err = String::from_utf8_lossy(&refused.stderr).into_owned();
    assert_no_canary(&err);
    assert!(!refused.status.success(), "{refused:?}");
    let goodbye: Value = serde_json::from_slice(&refused.stdout[4..]).unwrap();
    assert_eq!(goodbye["type"], "goodbye", "{goodbye}");
    assert_eq!(goodbye["code"], "CAPABILITY_UNAVAILABLE", "{goodbye}");
    observe(
        CASE,
        "forwarded-agent",
        "session_with_forwarded_agent=refused_before_any_frame code=CAPABILITY_UNAVAILABLE \
         session_without=served",
    );
}
