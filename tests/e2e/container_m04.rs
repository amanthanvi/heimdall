//! ⟨M04 U5⟩ ADR-0010 §4 / review D05 and D08: the container recipe's **mounted flow**, through the
//! real binary (`HEIMDALL_E2E_BIN`, else `CARGO_BIN_EXE_heimdall`) and a **real container engine**.
//!
//! [`a15_container_mounted_flow`] is `cfg(target_os = "linux")` and `platform_only`. It runs only
//! where the harness names an engine, in the PC's disposable WSL distribution (Podman rootless
//! and Docker Engine rootful, installed inside it only):
//!
//! * `HEIMDALL_M04_CONTAINER_ENGINE` = `podman` (rootless) or `docker` (rootful), and
//! * `HEIMDALL_M04_CONTAINER_IMAGE` = a local image that has the OpenSSH client (`ssh`,
//!   `ssh-add`, `ssh-keygen`) and `sh`, `ls`, `cat`, `sleep`.
//!
//! Without them the test prints `SKIPPED a15_container_mounted_flow: …` and passes; a skipped
//! engine row is a **blocked** row in the evidence, never a result. The engine-free cases of the
//! same recipe run everywhere (`heimdall-runtime`, `managed_store::live_tests::container`).
//!
//! **What it proves**, against a loopback `sshd` that trusts a per-run test CA for each pair's
//! principal (`exit_m03/world.rs`, the real runtime and the real issuer child):
//! * the mount instruction of the `ensure` result is the one `heimdall container mount-args`
//!   prints, and one SSH login from **inside the container** through the mount succeeds;
//! * negatives: an unauthorized key is refused, and so is a destination outside the binding (by
//!   the container's own host-key check, and, with that check turned off in the probe, by the
//!   server's principals);
//! * the mounted directory lists exactly the expected entries, the endpoint lists only the
//!   binding's identity, and a control-protocol hello on `agent.sock` fails;
//! * fresh authentication is refused at the original deadline, and after a replacement binding
//!   a login works again at the same mounted path, **in the same running container**;
//! * the UID rule, each negative beside an admitted positive control: Podman with
//!   `--userns=keep-id` is admitted and a sub-uid user is refused; Docker with
//!   `--user <uid>:<gid>` is admitted and root (`--user 0`) is refused.
//!
//! It records `m04 observation: …` lines: the engine and its version, the user-namespace
//! mapping the container saw, and what each refused user observed (the errno family). The
//! **peer uid the listener saw** is the uid map's translation of the container uid, not a
//! listener log: the runtime logs no per-connection peer. The container-side refusal of a
//! sub-uid is first the directory's 0700 mode (EACCES), then the socket's 0600, then the peer
//! check; rootful root passes the modes (`CAP_DAC_OVERRIDE`) and is refused by the peer check
//! alone.
//!
//! **Isolation.** The engine runs only against this world's scratch directory and loopback
//! server; no owner key, agent, keychain or `~/.ssh` is mounted or read. Docker Desktop is
//! `not-tested` by decision and is never driven here.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::too_many_lines,
    dead_code,
    missing_docs
)]

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::world::{self, Out, World, WorldOptions, platform, run_bounded};
use heimdall_contract::Timestamp;
use serde_json::Value;

const ENGINE_ENV: &str = "HEIMDALL_M04_CONTAINER_ENGINE";
const IMAGE_ENV: &str = "HEIMDALL_M04_CONTAINER_IMAGE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Rootless Podman.
    Podman,
    /// Rootful Docker Engine.
    Docker,
}

#[derive(Debug, Clone)]
struct Engine {
    kind: Kind,
    program: PathBuf,
    image: String,
}

impl Engine {
    /// The engine the harness names, `Ok(None)` when none (the skip), `Err` for a malformed
    /// harness.
    fn from_env() -> Result<Option<Engine>, String> {
        let Some(name) = std::env::var_os(ENGINE_ENV).filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        let kind = match name.to_str() {
            Some("podman") => Kind::Podman,
            Some("docker") => Kind::Docker,
            _ => return Err(format!("{ENGINE_ENV}: expected podman or docker")),
        };
        let image = std::env::var(IMAGE_ENV)
            .ok()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("{IMAGE_ENV} names the image with the OpenSSH client"))?;
        let program = heimdall_testkit::home::find_program(match kind {
            Kind::Podman => "podman",
            Kind::Docker => "docker",
        })
        .ok_or_else(|| format!("blocked: no {name:?} program on this host"))?;
        Ok(Some(Engine {
            kind,
            program,
            image,
        }))
    }

    fn run(&self, args: &[String]) -> Out {
        run_bounded(
            Command::new(&self.program)
                .args(args)
                .env_clear()
                .envs(self.env()),
            Duration::from_secs(120),
        )
    }

    /// Only what the engine needs (a cleared environment: no owner variable reaches it).
    fn env(&self) -> Vec<(String, String)> {
        ["PATH", "HOME", "XDG_RUNTIME_DIR", "DOCKER_HOST"]
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| ((*k).to_owned(), v)))
            .collect()
    }

    fn version(&self) -> String {
        let out = self.run(&["--version".to_owned()]);
        out.stdout.lines().next().unwrap_or("?").trim().to_owned()
    }
}

/// One running container (removed when dropped).
struct Container<'a> {
    engine: &'a Engine,
    name: String,
}

impl<'a> Container<'a> {
    /// Start `sleep` with the mount instruction (`source` the host directory, `env` the
    /// instruction's variables) and `user` flags, on the host network (the loopback server).
    fn start(
        engine: &'a Engine,
        tag: &str,
        source: &str,
        env: &[(String, String)],
        user: &[&str],
    ) -> Result<Container<'a>, Out> {
        let name = format!("hm-m04-{tag}-{}", heimdall_testkit::agent::random_hex(4));
        let mut args: Vec<String> = ["run", "-d", "--rm", "--name", &name, "--network", "host"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        args.extend(user.iter().map(|s| (*s).to_owned()));
        if engine.kind == Kind::Docker && user.contains(&"--user") {
            // A rootful container run as a plain uid needs the host's passwd to resolve it
            // (the OpenSSH client looks its user up).
            for f in ["/etc/passwd", "/etc/group"] {
                args.extend([
                    "--mount".to_owned(),
                    format!("type=bind,source={f},target={f},readonly"),
                ]);
            }
        }
        args.extend([
            "--mount".to_owned(),
            format!("type=bind,source={source},target=/run/heimdall,readonly"),
        ]);
        for (k, v) in env {
            args.extend(["-e".to_owned(), format!("{k}={v}")]);
        }
        args.extend([engine.image.clone(), "sleep".to_owned(), "3600".to_owned()]);
        let out = engine.run(&args);
        if out.code != 0 {
            return Err(out);
        }
        Ok(Container { engine, name })
    }

    fn exec(&self, argv: &[&str]) -> Out {
        let mut args = vec!["exec".to_owned(), self.name.clone()];
        args.extend(argv.iter().map(|s| (*s).to_owned()));
        self.engine.run(&args)
    }

    /// `sh -c <script>` inside the container.
    fn sh(&self, script: &str) -> Out {
        self.exec(&["sh", "-c", script])
    }
}

impl Drop for Container<'_> {
    fn drop(&mut self) {
        let _ = self
            .engine
            .run(&["rm".to_owned(), "-f".to_owned(), self.name.clone()]);
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// The files the directory holds for a binding over `certs` (module docs; the generation
/// marker is Heimdall's, hidden, and part of the contract of the directory).
fn expected_entries(certs: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = [
        ".generation",
        "agent.sock",
        "key.pub",
        "known_hosts",
        "ssh_config",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .chain(certs.iter().map(|c| (*c).to_owned()))
    .collect();
    v.sort();
    v
}

fn json(out: &Out) -> Value {
    out.json()
}

fn observe(what: &str) {
    println!("m04 observation: a15 {} {what}", platform());
}

/// One line of an error, for the record: the first line only, no path.
fn first_line(text: &str) -> String {
    text.lines()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect()
}

/// The `ensure` of `profile` in `environment` (exit 0, `ACCESS_READY` asserted): its data.
fn ensure_in(
    w: &World,
    profile: &str,
    environment: &str,
    work: &str,
    request: &str,
    until: Option<&str>,
) -> Value {
    let mut args = vec![
        "--json",
        "access",
        "ensure",
        "--profile",
        profile,
        "--environment",
        environment,
        "--work-id",
        work,
        "--request-id",
        request,
    ];
    if let Some(u) = until {
        args.extend(["--until", u]);
    }
    let out = w.cli(&args);
    assert_eq!(
        out.code,
        0,
        "ensure {work}: {}",
        w.redact(&format!("{out:?}"))
    );
    let env = json(&out);
    assert_eq!(
        env["code"],
        "ACCESS_READY",
        "{}",
        w.redact(&format!("{env}"))
    );
    env["data"].clone()
}

#[test]
fn a15_container_mounted_flow() {
    let engine = match Engine::from_env() {
        Ok(Some(e)) => e,
        Ok(None) => {
            println!(
                "SKIPPED a15_container_mounted_flow: {ENGINE_ENV} is not set (the engine rows are blocked, not passed)"
            );
            return;
        }
        Err(e) => panic!("{e}"),
    };
    observe(&format!(
        "engine={:?} version={:?}",
        engine.kind,
        engine.version()
    ));

    // The world: two pairs on two loopback servers, one profile per pair (the binding covers
    // pair 1; pair 2 is the destination outside it), the real runtime and issuer child.
    let (w, _ca) = World::start(WorldOptions {
        pairs: 2,
        per_pair_profiles: true,
        ..WorldOptions::default()
    });
    let profile = w.profile_of(0);

    // `container add` on a terminal: the owner's typed `yes` approves the AddEnvironment
    // decision. The environment and its directory come from `inspect environments`.
    let added = w.confirm(&["container", "add", "lab"]);
    assert_eq!(added.code, 0, "container add: {}", w.redact(&added.stdout));
    let listing = json(&w.cli(&["--json", "inspect", "environments"]));
    let item = listing["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["kind"] == "container")
        .cloned()
        .expect("the container environment is listed");
    let env_id = item["environment_id"].as_str().unwrap().to_owned();
    let dir = PathBuf::from(item["realization"]["directory"].as_str().unwrap());
    assert!(dir.is_dir(), "the stable directory exists");
    // The environment may serve this profile without a decision (the setup the owner does with
    // a policy; the approval grants `managed_signing` only).
    {
        use heimdall_contract::ids::{EnvironmentId, PolicyId};
        let environment = EnvironmentId::parse(&env_id).unwrap();
        let store = w.open_store();
        store
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

    // ---- ensure, and the instruction `container mount-args` prints -------------------------
    let first = ensure_in(&w, &profile, &env_id, "c1", "c1-r1", None);
    let realization = first["consumer"]["realization"].clone();
    assert_eq!(realization["environment_kind"], "container");
    assert!(
        first["consumer"]
            .get("signing_endpoint")
            .is_none_or(Value::is_null)
    );
    let source = realization["mount"]["source"].as_str().unwrap().to_owned();
    assert_eq!(Path::new(&source), dir);
    let args_out = w.cli(&["--json", "container", "mount-args", &env_id]);
    assert_eq!(args_out.code, 0, "{args_out:?}");
    assert_eq!(
        json(&args_out)["data"]["realization"],
        realization,
        "mount-args prints the instruction of the ensure result"
    );
    let env_pairs: Vec<(String, String)> = realization["environment"]
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
    let grant = first["grant_id"].as_str().unwrap().to_owned();
    let key_prefix = format!("heimdall:{}:{grant}:", w.environment.as_str());
    let alias = w.pairs[0].alias.clone();
    let login = |c: &Container<'_>, marker: &str| {
        c.sh(&format!(
            "ssh -F /run/heimdall/ssh_config -o BatchMode=yes {alias} 'echo {marker}'"
        ))
    };

    // The container the rows share: Podman rootless runs container root as the user (its
    // `--userns=keep-id` positive control is the UID rows' own container); Docker rootful runs
    // as the host uid and gid.
    let (uid, gid) = (
        String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout).unwrap(),
        String::from_utf8(Command::new("id").arg("-g").output().unwrap().stdout).unwrap(),
    );
    let (uid, gid) = (uid.trim().to_owned(), gid.trim().to_owned());
    let admitted_user: Vec<String> = match engine.kind {
        Kind::Podman => vec!["--userns=keep-id".to_owned()],
        Kind::Docker => vec!["--user".to_owned(), format!("{uid}:{gid}")],
    };
    let admitted: Vec<&str> = admitted_user.iter().map(String::as_str).collect();
    let main = Container::start(&engine, "main", &source, &env_pairs, &admitted)
        .unwrap_or_else(|o| panic!("container start: {}", w.redact(&format!("{o:?}"))));
    observe(&format!(
        "uid_map={:?}",
        first_line(&main.exec(&["cat", "/proc/self/uid_map"]).stdout)
    ));

    // ---- positive: one login from inside the container -------------------------------------
    let mark = w.pairs[0].sshd.log_mark();
    let ok = login(&main, "hm-c-pos");
    assert_eq!(ok.code, 0, "login: {}", w.redact(&format!("{ok:?}")));
    assert!(ok.stdout.contains("hm-c-pos"), "{ok:?}");
    let accepted = w.accepted_since(0, mark);
    assert_eq!(accepted.len(), 1, "{accepted:?}");
    assert!(
        accepted[0].key_id.starts_with(&key_prefix),
        "{:?}",
        accepted[0]
    );

    // ---- negatives -------------------------------------------------------------------------
    let mark = w.pairs[0].sshd.log_mark();
    let wrong_key = main.sh(&format!(
        "ssh-keygen -q -t ed25519 -N '' -f /tmp/hm-k && ssh -F /run/heimdall/ssh_config -o BatchMode=yes -o IdentityAgent=none -o IdentitiesOnly=yes -o IdentityFile=/tmp/hm-k {alias} 'echo hm-c-neg'"
    ));
    assert_ne!(
        wrong_key.code, 0,
        "an unauthorized key is refused: {wrong_key:?}"
    );
    assert!(!wrong_key.stdout.contains("hm-c-neg"));
    assert!(w.accepted_since(0, mark).is_empty());
    // A destination outside the binding: pair 2's server. As configured the container's own
    // host-key check refuses it; with that check off in the probe the server's principals do.
    let (host2, port2, account2) = {
        let p = &w.pairs[1];
        (p.sshd.host.clone(), p.sshd.port, p.account.clone())
    };
    let mark2 = w.pairs[1].sshd.log_mark();
    let outside = main.sh(&format!(
        "ssh -F /run/heimdall/ssh_config -o BatchMode=yes -o HostName={host2} -p {port2} -l {account2} outside 'echo hm-c-out'"
    ));
    assert_ne!(outside.code, 0, "{outside:?}");
    assert!(!outside.stdout.contains("hm-c-out"));
    let unchecked = main.sh(&format!(
        "ssh -F /run/heimdall/ssh_config -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o HostName={host2} -p {port2} -l {account2} outside 'echo hm-c-out2'"
    ));
    assert_ne!(
        unchecked.code, 0,
        "the server refuses the binding's principal: {unchecked:?}"
    );
    assert!(
        w.accepted_since(1, mark2).is_empty(),
        "no certificate accepted by pair 2"
    );

    // ---- the directory and the endpoint ----------------------------------------------------
    let cert = format!("cert-{}.pub", w.pairs[0].destination);
    assert_eq!(names(&dir), expected_entries(&[&cert]), "the host's view");
    let inside = main.exec(&["ls", "-A", "/run/heimdall"]);
    let mut seen: Vec<String> = inside.stdout.lines().map(str::to_owned).collect();
    seen.sort();
    assert_eq!(seen, expected_entries(&[&cert]), "the container's view");
    let listing = main.exec(&["ssh-add", "-l"]);
    assert_eq!(listing.code, 0, "{listing:?}");
    assert_eq!(
        listing.stdout.lines().count(),
        1,
        "the endpoint lists only the binding's identity: {listing:?}"
    );
    // A control-protocol hello on the signing endpoint fails: it speaks the SSH agent
    // protocol only.
    {
        use std::io::{Read, Write};
        let mut s = UnixStream::connect(dir.join("agent.sock")).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = s.write_all(br#"{"hello":{"protocol":"heimdall-control/1"}}"#);
        let mut answer = Vec::new();
        let _ = s.read_to_end(&mut answer);
        assert!(
            !answer.starts_with(b"{"),
            "the endpoint answered a control hello"
        );
    }

    // ---- the deadline, and a replacement at the same mounted path --------------------------
    // The first binding ends; a short-lived one is the original deadline.
    let bid = first["binding_id"].as_str().unwrap().to_owned();
    let released = w.cli(&["--json", "access", "release", &bid]);
    assert_eq!(released.code, 0, "{released:?}");
    let deadline = Timestamp::from_second(Timestamp::now().as_second() + 60).unwrap();
    let deadline_text = deadline.to_string();
    let second = ensure_in(&w, &profile, &env_id, "c2", "c2-r1", Some(&deadline_text));
    assert!(second["grant_id"].as_str().is_some(), "{second}");
    let mark = w.pairs[0].sshd.log_mark();
    let before = login(&main, "hm-c-before");
    assert_eq!(
        before.code,
        0,
        "before the deadline: {}",
        w.redact(&format!("{before:?}"))
    );
    assert_eq!(w.accepted_since(0, mark).len(), 1);
    let wait = deadline
        .as_second()
        .saturating_sub(Timestamp::now().as_second())
        .max(0) as u64
        + 3;
    std::thread::sleep(Duration::from_secs(wait));
    let mark = w.pairs[0].sshd.log_mark();
    let after = login(&main, "hm-c-after");
    assert_ne!(
        after.code, 0,
        "fresh authentication at the original deadline: {after:?}"
    );
    assert!(w.accepted_since(0, mark).is_empty());
    observe(&format!(
        "deadline refusal: {:?}",
        first_line(&after.stderr)
    ));
    // A replacement binding: the same running container, the same mounted path.
    let third = ensure_in(&w, &profile, &env_id, "c3", "c3-r1", None);
    assert_eq!(
        third["consumer"]["realization"]["mount"]["source"].as_str(),
        Some(source.as_str()),
        "the replacement is mounted at the same host directory"
    );
    let mut ok = None;
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(30) {
        let mark = w.pairs[0].sshd.log_mark();
        let attempt = login(&main, "hm-c-again");
        if attempt.code == 0 {
            assert_eq!(w.accepted_since(0, mark).len(), 1);
            ok = Some(attempt);
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(
        ok.is_some_and(|o| o.stdout.contains("hm-c-again")),
        "a login works again at the same mounted path after the replacement"
    );
    assert_eq!(names(&dir), expected_entries(&[&cert]));

    // ---- the UID rule: each negative beside an admitted positive control --------------------
    drop(main);
    let uid_rows: Vec<(&str, Vec<String>, bool)> = match engine.kind {
        Kind::Podman => vec![
            (
                "podman keep-id (admitted)",
                vec!["--userns=keep-id".to_owned()],
                true,
            ),
            (
                "podman sub-uid user",
                vec![
                    "--userns=keep-id".to_owned(),
                    "--user".to_owned(),
                    "1".to_owned(),
                ],
                false,
            ),
        ],
        Kind::Docker => vec![
            (
                "docker --user uid:gid (admitted)",
                vec!["--user".to_owned(), format!("{uid}:{gid}")],
                true,
            ),
            (
                "docker root",
                vec!["--user".to_owned(), "0".to_owned()],
                false,
            ),
        ],
    };
    for (label, flags, is_admitted) in uid_rows {
        let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
        let c = Container::start(&engine, "uid", &source, &env_pairs, &flags).unwrap_or_else(|o| {
            panic!("{label}: container start: {}", w.redact(&format!("{o:?}")))
        });
        let map = first_line(&c.exec(&["cat", "/proc/self/uid_map"]).stdout);
        let ids = c.exec(&["ssh-add", "-l"]);
        observe(&format!(
            "uid row {label:?}: uid_map={map:?} exit={} detail={:?}",
            ids.code,
            first_line(&format!("{}{}", ids.stderr, ids.stdout))
        ));
        if is_admitted {
            assert_eq!(ids.code, 0, "{label}: {ids:?}");
        } else {
            assert_ne!(ids.code, 0, "{label}: refused: {ids:?}");
            assert!(
                ids.stdout.trim().is_empty() || !ids.stdout.contains("CERT"),
                "{label}: no identity listed: {ids:?}"
            );
        }
    }
}
