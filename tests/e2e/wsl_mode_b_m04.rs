//! ⟨M04 W2⟩ WSL Mode B through the real binary, end to end, on a host without WSL (ADR-0010 §3;
//! m04-plan U4; I-11). The distribution is a stand-in: the debug-only
//! `HEIMDALL_TEST_WSL_DIRECT` configuration gives the runtime and the CLI one registered
//! distribution whose helper is the binary's own `internal wsl-helper`, started directly with a
//! scratch account home (`heimdall_wsl::DirectLauncher`). Everything else is the product: the
//! M03 exit suite's world (the CLI-started runtime, its real issuer child, a seeded CA, a
//! verified pair on a loopback sshd), `wsl enable --mode-b` and its `AddEnvironment` decision
//! typed on a terminal, `access ensure` in the environment, the real Mode B bridge
//! (`heimdall_wsl::Bridge` under the runtime's supervisor), the helper's Linux endpoint, and
//! the binding's own signer serving each relayed stream.
//!
//! This is the seam the two wave-2 units were built on in parallel (U4a: the transport; U4b:
//! the product wiring), proven with both real halves. It is **mechanism evidence**: the A13
//! rows (a real distribution, another Linux user, `wsl --terminate`) are the Windows suite's
//! `native::mode_b`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::world::{self, Out, World, WorldOptions, run_bounded};

/// The stand-in distribution's registration GUID and name.
const GUID: &str = "0b1c2d3e-2222-4222-8333-abcdef012345";
const NAME: &str = "Ubuntu";
/// The distribution account the helper reports.
const ACCOUNT: &str = "alice";

fn json(o: &Out) -> Value {
    o.json()
}

/// The stand-in distribution: the account home and runtime directory the helper uses, and the
/// `HEIMDALL_TEST_WSL_DIRECT` file describing it.
struct Distribution {
    _dir: tempfile::TempDir,
    home: PathBuf,
    direct: PathBuf,
}

impl Distribution {
    fn new() -> Distribution {
        // Short paths: the endpoint's socket path must stay under the 104-byte `sun_path`.
        let dir = tempfile::Builder::new()
            .prefix("hmb")
            .tempdir_in("/tmp")
            .unwrap();
        // The distribution account's own tree, whatever the umask made the temporary
        // directory: Mode B refuses a run base another principal could replace (M04-W2-R01).
        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let home = dir.path().join("h");
        let run = dir.path().join("r");
        for d in [&home, &run] {
            std::fs::create_dir(d).unwrap();
            std::fs::set_permissions(d, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .unwrap();
        }
        let ssh_exe = dir.path().join("ssh.exe");
        std::fs::write(&ssh_exe, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(
            &ssh_exe,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        let uid = String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_owned();
        let s = |p: &Path| p.to_str().unwrap().to_owned();
        let helper_env = serde_json::json!([
            ["PATH", "/usr/bin:/bin"],
            ["HOME", s(&home)],
            ["XDG_CONFIG_HOME", s(&home.join(".config"))],
            ["XDG_STATE_HOME", s(&home.join(".local").join("state"))],
            ["XDG_RUNTIME_DIR", s(&run)],
            [
                "HEIMDALL_TEST_WSL_HELPER_ID",
                format!("{uid}:{ACCOUNT}:{NAME}")
            ],
            ["HEIMDALL_TEST_WSL_HOME", s(&home)],
            ["HEIMDALL_TEST_WSL_SSH_EXE", s(&ssh_exe)],
        ]);
        let direct = dir.path().join("direct.json");
        std::fs::write(
            &direct,
            serde_json::to_vec(&serde_json::json!({
                "guid": GUID,
                "name": NAME,
                "default_uid": 1000,
                "helper_env": helper_env,
            }))
            .unwrap(),
        )
        .unwrap();
        Distribution {
            _dir: dir,
            home,
            direct,
        }
    }
}

/// The OpenSSH client `program` with exactly `env` (and nothing inherited).
fn openssh(program: &str, args: &[&str], env: &[(&str, &str)], cwd: &Path) -> Out {
    let mut cmd = Command::new(world::openssh(program));
    cmd.args(args).env_clear().current_dir(cwd);
    cmd.env("PATH", "/usr/bin:/bin");
    for (k, v) in env {
        cmd.env(k, v);
    }
    run_bounded(&mut cmd, Duration::from_secs(60))
}

/// ⟨ADR-0010 §3 items 3–8, 11; I-11⟩ Mode B end to end: enable through the decision, `ensure`
/// in the environment, a listing and a real login through the helper's Linux endpoint with
/// the binding's own configuration, and the endpoint withdrawn when the grant ends.
/// 1. `wsl enable --mode-b`, typed `yes`: the `AddEnvironment` decision is approved and the
///    environment is listed as `wsl_distribution` with Mode B and a running-state view.
/// 2. `ensure` in that environment answers the Mode B descriptor: a socket and an
///    `ssh_config` under the helper's run directory, `SSH_AUTH_SOCK` and `GIT_SSH_COMMAND`, no
///    mount and no native endpoint. Nothing is written into the distribution account's
///    `~/.ssh`.
/// 3. Through the endpoint, `ssh-add -l` lists exactly the binding's key, and `ssh -F
///    <config> <alias>` logs in with the grant's certificate (the sshd accepts one certificate
///    whose key ID names the grant). The configuration names the endpoint as its agent and
///    never `ForwardAgent`.
///    A socket deleted inside the distribution is recreated by the runtime's re-check (m04-plan
///    U4, `a13_deleted_socket_recreated`'s mechanism).
/// 4. Revoking the grant withdraws the endpoint: the socket stops listening and the binding's
///    directory goes away. `wsl disable` then removes the environment.
#[test]
fn mode_b_end_to_end_through_the_real_bridge_and_helper() {
    let d = Distribution::new();
    let (w, _ca) = World::start(WorldOptions {
        pairs: 1,
        per_pair_profiles: true,
        extra_env: vec![(
            "HEIMDALL_TEST_WSL_DIRECT".to_owned(),
            d.direct.to_str().unwrap().to_owned(),
        )],
        ..WorldOptions::default()
    });
    let profile = w.profile_of(0);

    // 1. Enable, approving the decision on a terminal.
    let enabled = w.confirm(&["wsl", "enable", NAME, "--account", ACCOUNT, "--mode-b"]);
    assert_eq!(enabled.code, 0, "wsl enable: {}", w.redact(&enabled.stdout));
    let listing = json(&w.cli(&["--json", "inspect", "environments"]));
    let item = listing["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["kind"] == "wsl_distribution")
        .cloned()
        .unwrap_or_else(|| panic!("the Mode B environment is listed: {listing}"));
    assert!(
        item["realization"]["modes"]
            .as_array()
            .is_some_and(|m| m.iter().any(|x| x == "b")),
        "{item}"
    );
    let env_id = item["environment_id"].as_str().unwrap().to_owned();
    // The environment may serve this profile (the policy the owner sets; the approval grants
    // `managed_signing` only), as the container flow does.
    {
        use heimdall_contract::ids::{EnvironmentId, PolicyId};
        let environment = EnvironmentId::parse(&env_id).unwrap();
        w.open_store()
            .transaction(|tx| {
                let mut rec = tx.environment(&environment)?.expect("its record");
                rec.permissions.automatic_activation = true;
                tx.upsert_environment(&rec)?;
                let pid = PolicyId::parse(&format!("{}-1", world::POLICY)).unwrap();
                let mut pol = tx.policy(&pid)?.expect("the pair's policy");
                pol.environments.insert(environment.clone());
                pol.revision = heimdall_domain::policy::PolicyRevision(pol.revision.0 + 1);
                tx.upsert_policy(&pol, false)
            })
            .unwrap();
    }

    // 2. Ensure in the environment.
    let out = w.cli(&[
        "--json",
        "access",
        "ensure",
        "--profile",
        &profile,
        "--environment",
        &env_id,
        "--work-id",
        "b1",
        "--request-id",
        "b1-r1",
    ]);
    assert_eq!(out.code, 0, "ensure: {}", w.redact(&format!("{out:?}")));
    let data = json(&out)["data"].clone();
    let realization = data["consumer"]["realization"].clone();
    assert_eq!(
        realization["environment_kind"], "wsl_distribution",
        "{data}"
    );
    assert!(realization.get("mount").is_none_or(Value::is_null));
    assert!(
        data["consumer"]
            .get("signing_endpoint")
            .is_none_or(Value::is_null),
        "{data}"
    );
    let socket = realization["endpoint"].as_str().unwrap().to_owned();
    let config = realization["config"].as_str().unwrap().to_owned();
    assert!(
        Path::new(&socket).starts_with(&d.home) || socket.starts_with("/tmp/"),
        "the endpoint is the helper's: {socket}"
    );
    let env: Vec<(String, String)> = realization["environment"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p[0].as_str().unwrap().to_owned(),
                p[1].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert!(
        env.contains(&("SSH_AUTH_SOCK".to_owned(), socket.clone())),
        "{env:?}"
    );
    assert!(
        env.contains(&(
            "GIT_SSH_COMMAND".to_owned(),
            format!(
                "ssh -F {}",
                heimdall_app::operations::container_m04::sh_word(&config)
            )
        )),
        "{env:?}"
    );
    assert!(
        !d.home.join(".ssh").exists(),
        "nothing is written into the distribution account's ~/.ssh"
    );
    let rendered = std::fs::read_to_string(&config).unwrap();
    assert!(
        rendered.contains(&socket),
        "IdentityAgent names the endpoint"
    );
    assert!(
        !rendered.to_lowercase().contains("forwardagent"),
        "{rendered}"
    );
    let grant = data["grant_id"].as_str().unwrap().to_owned();

    // 3. A listing and a login through the endpoint.
    let listed = openssh(
        "ssh-add",
        &["-l"],
        &[("SSH_AUTH_SOCK", &socket)],
        &w.home.root,
    );
    assert_eq!(listed.code, 0, "{listed:?}");
    assert_eq!(
        listed.stdout.lines().count(),
        1,
        "the binding's key: {listed:?}"
    );
    let alias = w.pairs[0].alias.clone();
    let mark = w.pairs[0].sshd.log_mark();
    let login = openssh(
        "ssh",
        &[
            "-F",
            &config,
            "-o",
            "BatchMode=yes",
            &alias,
            "echo hm-mode-b",
        ],
        &[("HOME", d.home.to_str().unwrap())],
        &w.home.root,
    );
    assert_eq!(login.code, 0, "login: {}", w.redact(&format!("{login:?}")));
    assert!(login.stdout.contains("hm-mode-b"), "{login:?}");
    let accepted = w.accepted_since(0, mark);
    assert_eq!(accepted.len(), 1, "{accepted:?}");
    assert!(
        accepted[0]
            .key_id
            .starts_with(&format!("heimdall:{}:{grant}:", w.environment.as_str())),
        "{:?}",
        accepted[0]
    );

    // 3b. A deleted socket is recreated by the runtime's re-check (every 10 s), for the same
    // binding: the listing works again through the same path.
    std::fs::remove_file(&socket).unwrap();
    let deadline = Instant::now() + Duration::from_secs(40);
    while !Path::new(&socket).exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
    }
    let relisted = openssh(
        "ssh-add",
        &["-l"],
        &[("SSH_AUTH_SOCK", &socket)],
        &w.home.root,
    );
    assert_eq!(relisted.code, 0, "the endpoint is back: {relisted:?}");
    assert_eq!(relisted.stdout, listed.stdout, "the same binding's key");

    // 4. The grant ends: the endpoint is withdrawn.
    w.revoke(&grant, "b1-revoke");
    let dir = Path::new(&socket).parent().unwrap().to_path_buf();
    let deadline = Instant::now() + Duration::from_secs(30);
    while (dir.exists() || std::os::unix::net::UnixStream::connect(&socket).is_ok())
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        std::os::unix::net::UnixStream::connect(&socket).is_err(),
        "the endpoint stops listening"
    );
    assert!(!dir.exists(), "the binding's directory is removed");
    let disabled = w.cli(&["--json", "--non-interactive", "wsl", "disable", NAME]);
    assert_eq!(disabled.code, 0, "{}", w.redact(&format!("{disabled:?}")));
    let after = json(&w.cli(&["--json", "inspect", "environments"]));
    assert!(
        !after["data"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["environment_id"] == env_id.as_str() && i["state"] != "removed"),
        "{after}"
    );
}

/// ⟨M04 W2 review, M04-W2-R04⟩ The review's probe, inverted: Git runs `GIT_SSH_COMMAND` through
/// `sh`, so the descriptor's command carries a configuration path with a space (and a quote)
/// as one argument. A scratch `ssh` records the arguments Git gives it; the real Git runs it
/// (no network: the scratch `ssh` exits 1). The raw `config` field stays the plain path; the
/// container's fixed path needs no quoting and is unchanged.
#[test]
fn git_ssh_command_carries_a_config_path_with_spaces_as_one_argument() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::Builder::new()
        .prefix("hwg")
        .tempdir_in("/tmp")
        .unwrap();
    let config = root.path().join("with space/it's/ssh_config");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "Host *\n").unwrap();
    let ssh = root.path().join("ssh");
    std::fs::write(
        &ssh,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$HM_ARGS\"\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    let args = root.path().join("args");
    let config_text = config.to_str().unwrap();
    let descriptor = heimdall_app::operations::container_m04::wsl_realization_descriptor(
        "/unused/agent.sock",
        config_text,
    );
    assert_eq!(
        descriptor.config.as_deref(),
        Some(config_text),
        "the raw path field"
    );
    let (_, command) = descriptor
        .environment
        .iter()
        .find(|(k, _)| k == "GIT_SSH_COMMAND")
        .unwrap();
    let git = heimdall_testkit::home::find_program("git").expect("git");
    let out = Command::new(git)
        .args(["ls-remote", "ssh://fixture.invalid/hm"])
        .env_clear()
        .env("HOME", root.path())
        .env("PATH", format!("{}:/usr/bin:/bin", root.path().display()))
        .env("HM_ARGS", &args)
        .env("GIT_SSH_COMMAND", command)
        .env("GIT_SSH_VARIANT", "ssh")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0), "the scratch ssh refuses");
    let seen = std::fs::read_to_string(&args).unwrap();
    let seen: Vec<&str> = seen.lines().collect();
    let at = seen.iter().position(|a| *a == "-F").expect("-F");
    assert_eq!(
        seen.get(at + 1),
        Some(&config_text),
        "one argument: {seen:?}"
    );
    // The container's fixed path needs no quoting: its command is unchanged.
    let container = heimdall_app::operations::container_m04::realization_descriptor("/x");
    assert!(
        container.environment.contains(&(
            "GIT_SSH_COMMAND".to_owned(),
            "ssh -F /run/heimdall/ssh_config".to_owned()
        )),
        "{container:?}"
    );
}
