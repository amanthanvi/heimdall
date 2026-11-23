//! ⟨M06 W5 `w5i`⟩ **`connect` on a runner goes through the clean launch** (ADR-0012 §4
//! item 5 "The declared pass-list" ⟨2026-11-22⟩; A24's "runner work" for `connect`). Real
//! binaries on one host: a runner (`remote init` on a pseudo-terminal, `service run
//! --runner`) whose catalog knows one existing-access alias, and the real `heimdall
//! connect` started unattended from a process that an SSH session with agent forwarding
//! would have started.
//!
//! * **The forwarded agent** is a disposable fixture `ssh-agent` of this test, holding one
//!   per-run key: it stands for the controller's.
//! * **The client** is a stand-in `ssh` first on `PATH` (the product launches the `ssh` it
//!   selects from `PATH`; no network is involved): it records its whole environment, its
//!   arguments and what its agent lists into the test's scratch directory. That is the
//!   connected session's environment as the client process has it.
//!
//! Steps (`m06 observation: connect-runner <step>: <result>`):
//! * `clean-launch`: the client's environment is exactly the declared pass-list's set
//!   variables, the fixed `PATH` and the launcher-set values (`HOME`, `USER`, `LOGNAME`,
//!   `SHELL` from the account database, never the launching process's scratch `HOME`;
//!   `LANG=C.UTF-8`, the launching process having none); no `SSH_AUTH_SOCK`, no session
//!   marker; its agent lists nothing of the forwarded agent; stderr names the inherited agent's
//!   provenance (`controller_dependency`) and never its path;
//! * `configured-agent`: the alias's own configuration names the forwarded socket as its
//!   `IdentityAgent`: the unattended `connect` is refused `CAPABILITY_UNAVAILABLE`,
//!   `controller_dependency`, and the client is never started;
//! * `ordinary-path-agent`: the same, with no SSH session beside it:
//!   `dependency_provenance_unknown`;
//! * `undetermined-agent` ⟨`w5f`; ADR-0012 §4 item 5 "An undetermined `IdentityAgent`"
//!   ⟨2026-11-22⟩⟩: the alias's `IdentityAgent` is a `~` path, has a `%` token, or is set
//!   inside a `Match exec` block: each unattended `connect` is refused
//!   `CAPABILITY_UNAVAILABLE`, `dependency_provenance_unknown`, naming the alias and why,
//!   and the client is never started; with `IdentityAgent none` it launches again.
//!
//! Not driven here: a managed pair's `connect` on a runner (it needs the controller's
//! issuer; its agents reach the same launch through the bind result), and a real sshd
//! behind the client.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Stdio;

use heimdall_contract::ids::ClientId;
use heimdall_contract::request::AccessPairRef;
use heimdall_credential::mgmt::MgmtKey;
use heimdall_domain::time::Clock as _;
use heimdall_testkit::agent::{AgentOptions, DisposableSshAgent, FixtureKey, KeyConstraints};
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::home::Scratch;
use serde_json::Value;

use super::m06::{blocked, observe};
use super::world::{HOUR, Runner, envelope, listed_identities, seed_runner_catalog_with};

const CASE: &str = "connect-runner";

/// A marker variable of the launching process, as anything a session leaves behind.
const SESSION_MARK: &str = "HM_CONNECT_SESSION_MARK";

/// The alias the runner's catalog knows.
const ALIAS: &str = "h1";

/// What one `connect` did: its exit, stdout and stderr, and what the stand-in client
/// recorded (`None`: the client was never started).
struct Connected {
    success: bool,
    stdout: String,
    stderr: String,
    client: Option<(Vec<String>, Vec<String>, String)>,
}

/// One unattended `heimdall connect h1` on the runner, from a process whose environment
/// holds `extra` beside the runner's own, with the stand-in client first on `PATH`.
fn connect(runner: &Runner, bin_dir: &Path, out: &Path, extra: &[(&str, &str)]) -> Connected {
    for name in ["env.txt", "agent.txt", "args.txt"] {
        let _ = std::fs::remove_file(out.join(name));
    }
    let mut cmd = runner.command();
    cmd.env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()));
    // The launching process has no LANG of its own (the launcher then sets the default).
    cmd.env_remove("LANG");
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let done = cmd
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
    let read = |name: &str| std::fs::read_to_string(out.join(name)).ok();
    let lines = |text: String| text.lines().map(str::to_owned).collect::<Vec<_>>();
    let client = match (read("env.txt"), read("agent.txt"), read("args.txt")) {
        (Some(env), Some(agent), Some(args)) => Some((lines(env), lines(agent), args)),
        _ => None,
    };
    Connected {
        success: done.status.success(),
        stdout: String::from_utf8_lossy(&done.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&done.stderr).into_owned(),
        client,
    }
}

pub(crate) fn journey() {
    let scratch = Scratch::new().unwrap();
    let Ok(mut forwarded) = DisposableSshAgent::start(&scratch, AgentOptions::default()) else {
        blocked(CASE, "no disposable ssh-agent on this host");
        return;
    };
    let key = FixtureKey::generate();
    forwarded.add_key(&key, KeyConstraints::default()).unwrap();
    let socket = forwarded.socket.to_string_lossy().into_owned();
    let stands_for = listed_identities(&socket);
    assert_eq!(stands_for.len(), 1, "the fixture agent holds its one key");

    // The runner: enrolled on a terminal, one existing-access alias in its catalog.
    let mut runner = Runner::named(&scratch, "cr");
    let owner_key = MgmtKey::generate().unwrap().public().unwrap();
    let owner_key = owner_key
        .openssh_line
        .rsplit_once(' ')
        .map(|(k, _)| k.to_owned())
        .unwrap();
    let owner = ClientId::from_random_bytes([0x5c; 16]);
    let init = envelope(&runner.remote_init(&owner, &owner_key, "yes"));
    assert_eq!(init["code"], "OK", "{init}");
    let pair = AccessPairRef {
        destination: heimdall_contract::ids::DestinationId::parse(ALIAS).unwrap(),
        account: heimdall_contract::ids::AccountName::parse("hm-fixture").unwrap(),
    };
    seed_runner_catalog_with(
        &runner.home,
        heimdall_runtime::platform::SystemClock.wall(),
        &[pair],
        4 * HOUR,
    );
    std::fs::create_dir_all(runner.account.join(".ssh")).unwrap();
    let config = runner.account.join(".ssh/config");
    std::fs::write(&config, format!("Host {ALIAS}\n  HostName 127.0.0.1\n")).unwrap();
    runner.start();

    // The stand-in client.
    let bin_dir = scratch.subdir("cr-bin").unwrap();
    let out = scratch.subdir("cr-out").unwrap();
    let client = bin_dir.join("ssh");
    std::fs::write(
        &client,
        format!(
            "#!/bin/sh\n/usr/bin/env > '{0}/env.txt'\n/usr/bin/ssh-add -L > '{0}/agent.txt' 2>/dev/null\n\
             printf '%s\\n' \"$*\" > '{0}/args.txt'\nexit 0\n",
            out.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o700)).unwrap();

    // clean-launch: an SSH session with agent forwarding started the launching process.
    let session: [(&str, &str); 6] = [
        ("SSH_AUTH_SOCK", &socket),
        ("SSH_CONNECTION", "127.0.0.1 50000 127.0.0.1 22"),
        (SESSION_MARK, "1"),
        ("TERM", "xterm-256color"),
        ("TZ", "UTC"),
        ("LC_ALL", "C"),
    ];
    let done = connect(&runner, &bin_dir, &out, &session);
    assert_no_canary(&done.stderr);
    let (env, agent, args) = done.client.unwrap_or_else(|| {
        panic!(
            "the client was not started: {} {}",
            done.stdout, done.stderr
        )
    });
    assert!(done.success, "{} {}", done.stdout, done.stderr);
    assert_eq!(args.trim(), ALIAS, "the client is launched for the alias");
    assert!(
        !agent.iter().any(|l| stands_for.contains(l)),
        "the forwarded agent reached the connected session's environment: its key is offered"
    );
    assert!(
        !env.iter().any(|l| l.contains(&socket)),
        "the forwarded agent's socket reached the connected session's environment"
    );
    let mut names: Vec<&str> = env
        .iter()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k))
        // What `sh` and the platform's launcher add themselves.
        .filter(|k| !["PWD", "SHLVL", "_", "OLDPWD", "__CF_USER_TEXT_ENCODING"].contains(k))
        .collect();
    names.sort_unstable();
    // Of the declared pass-list, exactly the variables the launching process had; and the
    // launcher-set values.
    assert_eq!(
        names,
        [
            "HEIMDALL_HOME",
            "HOME",
            "LANG",
            "LC_ALL",
            "LOGNAME",
            "PATH",
            "SHELL",
            "TERM",
            "TZ",
            "USER"
        ],
        "the connected session's environment is not the clean launch's"
    );
    // HOME is the account database's, never the launching process's (a scratch directory
    // here); USER and LOGNAME are what `id -un` prints.
    let value = |name: &str| {
        env.iter()
            .find_map(|l| l.strip_prefix(&format!("{name}=")))
            .unwrap()
            .to_owned()
    };
    let launching_home = runner.account.to_string_lossy().into_owned();
    assert_ne!(value("HOME"), launching_home);
    assert!(!env.iter().any(|l| l == &format!("HOME={launching_home}")));
    let id = std::process::Command::new("/usr/bin/id")
        .arg("-un")
        .output()
        .unwrap();
    let account_name = String::from_utf8_lossy(&id.stdout).trim().to_owned();
    assert!(id.status.success() && !account_name.is_empty());
    assert_eq!(value("USER"), account_name);
    assert_eq!(value("LOGNAME"), account_name);
    assert!(value("SHELL").starts_with('/'));
    for kept in [
        "LANG=C.UTF-8",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "TERM=xterm-256color",
        "TZ=UTC",
        "LC_ALL=C",
    ] {
        assert!(env.contains(&kept.to_owned()), "{kept}: {names:?}");
    }
    assert!(
        done.stderr.contains(
            "runner work does not get the inherited agent (provenance: controller_dependency"
        ),
        "{}",
        done.stderr
    );
    assert!(!done.stderr.contains(&socket), "a socket path was printed");
    for line in env.iter().chain(&agent) {
        assert_no_canary(line);
    }
    observe(
        CASE,
        "clean-launch",
        "launched_by=heimdall_connect alias=existing_access \
         environment=declared_pass_list_and_launcher_set_values \
         home_user_logname_shell=account_database_not_the_parents lang=default_c_utf8 \
         ssh_auth_sock=absent forwarded_agent=fixture_agent_standing_for_it \
         forwarded_agent_inherited=false forwarded_agent_provenance=controller_dependency",
    );

    // configured-agent: the alias's own configuration names the forwarded socket.
    std::fs::write(
        &config,
        format!("Host {ALIAS}\n  HostName 127.0.0.1\n  IdentityAgent {socket}\n"),
    )
    .unwrap();
    let refused = |extra: &[(&str, &str)], reason: &str| {
        let done = connect(&runner, &bin_dir, &out, extra);
        assert_no_canary(&done.stderr);
        assert!(
            !done.success && done.client.is_none(),
            "an unattended connect on an agent outside the inventory launched: {} {}",
            done.stdout,
            done.stderr
        );
        // A refusal before launch is the envelope on stderr (stdout is the client's).
        let answer: Value = done
            .stderr
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str(l).ok())
            .unwrap_or_else(|| panic!("no envelope: {} {}", done.stdout, done.stderr));
        assert_eq!(answer["code"], "CAPABILITY_UNAVAILABLE", "{answer}");
        assert_eq!(answer["data"]["error"]["reason"], reason, "{answer}");
        assert!(!done.stdout.contains(&socket) && !done.stderr.contains(&socket));
    };
    refused(&session, "controller_dependency");
    observe(
        CASE,
        "configured-agent",
        "alias_identity_agent=the_inherited_session_socket unattended_connect=refused \
         code=CAPABILITY_UNAVAILABLE reason=controller_dependency client_started=false",
    );
    refused(&[(SESSION_MARK, "1")], "dependency_provenance_unknown");
    observe(
        CASE,
        "ordinary-path-agent",
        "alias_identity_agent=ordinary_local_path unattended_connect=refused \
         code=CAPABILITY_UNAVAILABLE reason=dependency_provenance_unknown client_started=false",
    );

    // undetermined-agent: values the static pass cannot determine. ssh would take the agent
    // from its own configuration, which the clean environment does not control.
    let undetermined = |directive: &str, why: &str| {
        std::fs::write(
            &config,
            format!("{directive}\nHost {ALIAS}\n  HostName 127.0.0.1\n"),
        )
        .unwrap();
        let done = connect(&runner, &bin_dir, &out, &[(SESSION_MARK, "1")]);
        assert_no_canary(&done.stderr);
        assert!(
            !done.success && done.client.is_none(),
            "an unattended connect on an undetermined IdentityAgent launched ({directive}): {} {}",
            done.stdout,
            done.stderr
        );
        let answer: Value = done
            .stderr
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str(l).ok())
            .unwrap_or_else(|| panic!("no envelope: {} {}", done.stdout, done.stderr));
        assert_eq!(answer["code"], "CAPABILITY_UNAVAILABLE", "{answer}");
        assert_eq!(
            answer["data"]["error"]["reason"], "dependency_provenance_unknown",
            "{answer}"
        );
        let message = answer["data"]["error"]["message"]
            .as_str()
            .unwrap_or_default();
        assert!(
            message.contains(&format!("alias `{ALIAS}`")) && message.contains(why),
            "the refusal does not name the alias and why ({directive}): {answer}"
        );
    };
    undetermined(
        &format!("Host {ALIAS}\n  IdentityAgent ~/.ssh/agent.sock"),
        "`~` path",
    );
    undetermined(
        &format!("Host {ALIAS}\n  IdentityAgent /tmp/hm-fixture-%u.sock"),
        "`%` token",
    );
    undetermined(
        &format!(
            "Match originalhost {ALIAS} exec \"/usr/bin/true\"\n  IdentityAgent /tmp/hm-fixture-agent.sock"
        ),
        "`Match` block",
    );
    // Determined again (no agent at all): the unattended connect launches.
    std::fs::write(
        &config,
        format!("Host {ALIAS}\n  HostName 127.0.0.1\n  IdentityAgent none\n"),
    )
    .unwrap();
    let done = connect(&runner, &bin_dir, &out, &[(SESSION_MARK, "1")]);
    assert!(
        done.success && done.client.is_some(),
        "{} {}",
        done.stdout,
        done.stderr
    );
    observe(
        CASE,
        "undetermined-agent",
        "alias_identity_agent=tilde_path|percent_token|match_exec_dependent unattended_connect=refused_each \
         code=CAPABILITY_UNAVAILABLE reason=dependency_provenance_unknown names_alias_and_why=true \
         client_started=false identity_agent_none=launched",
    );
    forwarded.stop();
}
