//! ⟨M04 U6⟩ Single-hop `ProxyJump` through catalog destinations, explicit agent forwarding
//! and route-aware verified-scope evidence, through the **real binary** and its **real**
//! `internal issuer` child, against loopback sshds (ADR-0010 §5, §9 items 3, 4 and 8; review
//! findings M04-D03 and M04-D04; A15, A27).
//!
//! The scaffolding is the M03 exit suite's [`world`] (a scratch home, the CLI-started runtime
//! and its issuer child, a seeded CA, one server per pair, `setup apply` and `time confirm`
//! typed on a terminal, fresh logins). Here a world has **two** pairs on a
//! [`heimdall_testkit::bastion::Bastion`]: the jump host (`exit1`, destination `ex1`, which
//! allows TCP forwarding to the final host's port only) and the final host (`exit2`,
//! destination `ex2`, no forwarding). Every managed pair's enrollment is seeded **without
//! evidence** ([`world::WorldOptions::no_seeded_evidence`]): the verified-scope claim exists
//! only after the product's own `enroll verify`, so no pre-verified record bypasses the
//! freshness rules (D04). The enrollment's registry line is the world's seed (the enrollment
//! loop has its own suites).
//!
//! **Platforms.** Everything that needs a forwarding sshd is `cfg(unix)`: a harness sshd (the
//! Windows run's WSL server) cannot honour `AllowTcpForwarding`, so the Windows rows of these
//! cases are `blocked` on a harness server with forwarding settings (the report names the
//! command), never counted as passes. [`route_rules_through_the_real_binary`] needs no sshd
//! and runs everywhere.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::too_many_lines,
    dead_code,
    missing_docs
)]
#![cfg_attr(not(any(unix, windows)), allow(unused_imports))]

#[path = "exit_m03/procs.rs"]
mod procs;
#[path = "exit_m03/worker.rs"]
mod worker;
#[path = "exit_m03/world.rs"]
mod world;

use serde_json::Value;
use world::Out;

/// The jump pair's index in the world (alias `exit1`, destination `ex1`).
const JUMP: usize = 0;
/// The final pair's index (alias `exit2`, destination `ex2`).
const FINAL: usize = 1;

fn text(o: &Out) -> String {
    format!(
        "exit {}\nstdout: {}\nstderr: {}",
        o.code, o.stdout, o.stderr
    )
}

#[cfg(unix)]
mod fx {
    use super::*;
    use heimdall_testkit::bastion::{Bastion, BastionOptions};
    use heimdall_testkit::home::Scratch;
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use world::{World, WorldOptions};

    /// A two-pair world on a bastion (module docs).
    pub struct Route {
        pub w: World,
        /// A directory holding an `ssh` wrapper that adds only `-F <scratch config>`: the
        /// client `connect` resolves from `PATH` (it execs `ssh` with no `-F`, and OpenSSH
        /// finds `~/.ssh/config` through the account database, never `$HOME`).
        pub bin: std::path::PathBuf,
        /// The existing-access agent, when the jump hop uses one.
        pub agent: Option<heimdall_testkit::agent::FakeAgent>,
        /// Meta files of launches whose binding is released before the next launch.
        pending: std::sync::Mutex<Vec<std::path::PathBuf>>,
        /// The servers' scratch: declared after `w`, so it outlives the servers.
        _scratch: Scratch,
    }

    pub fn route_world(agent_forwarding: bool) -> Route {
        route_world_with(agent_forwarding, Vec::new(), None)
    }

    /// [`route_world`], with the jump host also accepting `jump_authorized` (existing access)
    /// and `agent` kept alive for the test.
    pub fn route_world_with(
        agent_forwarding: bool,
        jump_authorized: Vec<heimdall_testkit::agent::FixtureKey>,
        agent: Option<heimdall_testkit::agent::FakeAgent>,
    ) -> Route {
        let scratch = Scratch::new().expect("scratch");
        let Bastion { jump, target } = Bastion::start(
            &scratch,
            BastionOptions {
                agent_forwarding,
                jump_authorized: jump_authorized.iter().map(|k| k.public().clone()).collect(),
            },
        )
        .unwrap_or_else(|e| panic!("blocked: {e}"));
        let (w, ca) = World::start(WorldOptions {
            pairs: 2,
            servers: vec![jump, target],
            ..WorldOptions::default()
        });
        drop(ca);
        // The jump hop's `ssh` is started by the first one with `-F <config>` and no other
        // option, so the trust store of both hops is the user's own configuration (OpenSSH's
        // user-controlled trust, ADR-0010 §9 item 3): the scratch known-hosts files, named
        // by directives before P's include.
        let original = std::fs::read_to_string(&w.home.user_config).unwrap();
        std::fs::write(
            &w.home.user_config,
            format!(
                "{original}\nUserKnownHostsFile {}\nGlobalKnownHostsFile {}\nBatchMode yes\n",
                heimdall_testkit::home::ssh_option_path(&w.home.known_hosts),
                heimdall_testkit::home::ssh_option_path(&w.home.global_known_hosts),
            ),
        )
        .unwrap();
        let bin = w.home.root.join("route-bin");
        std::fs::create_dir(&bin).unwrap();
        let wrapper = bin.join("ssh");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nexec {} -F '{}' \"$@\"\n",
                world::openssh("ssh").display(),
                w.home.user_config.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::create_dir(w.home.root.join("meta")).unwrap();
        Route {
            w,
            bin,
            agent,
            pending: std::sync::Mutex::new(Vec::new()),
            _scratch: scratch,
        }
    }

    impl Route {
        pub fn cli_ok(&self, args: &[&str]) -> Value {
            let out = self.w.cli(args);
            assert_eq!(out.code, 0, "{args:?}: {}", self.w.redact(&text(&out)));
            out.json()
        }

        /// `enroll verify` of every enrollment (a presence re-verification through the real
        /// issuer child): each ends `verified` with fresh evidence.
        pub fn verify_all(&self) {
            let status = self.cli_ok(&["--json", "--non-interactive", "enroll", "status"]);
            let listed = status["data"]["enrollments"].as_array().unwrap().clone();
            assert_eq!(listed.len(), 2, "{status}");
            for e in listed {
                let id = e["enrollment_id"].as_str().unwrap().to_owned();
                let out = self
                    .w
                    .cli(&["--json", "--non-interactive", "enroll", "verify", &id]);
                let env = out.json();
                assert!(
                    out.code == 0 && env["data"]["state"] == "verified",
                    "enroll verify {id}: {}",
                    self.w.redact(&text(&out))
                );
            }
        }

        /// `destination add exit2 … [--jump exit1]` (the final destination, re-defined).
        pub fn define_final(&self, jump: bool) -> Out {
            let p = &self.w.pairs[FINAL];
            let port = p.sshd.port.to_string();
            let mut args = vec![
                "--json",
                "destination",
                "add",
                &p.alias,
                "--hostname",
                &p.sshd.host,
                "--port",
                &port,
                "--account",
                &p.account,
                "--identity",
                &self.w.identity,
                "--id",
                &p.destination,
            ];
            if jump {
                args.extend(["--jump", &self.w.pairs[JUMP].alias]);
            }
            self.w.cli(&args)
        }

        /// `setup apply`, typed on a terminal.
        pub fn apply(&self) {
            let out = self.w.confirm(&["setup", "apply"]);
            assert_eq!(out.code, 0, "setup apply: {}", self.w.redact(&text(&out)));
        }

        /// `access ensure --profile exit` requiring verified server principals.
        pub fn ensure_verified(&self, work: &str, request: &str, extra: &[&str]) -> Out {
            let mut args = vec![
                "--json",
                "access",
                "ensure",
                "--profile",
                "exit",
                "--work-id",
                work,
                "--request-id",
                request,
                "--require-destination-scope",
                "verified_server_principals",
            ];
            args.extend(extra);
            self.w.cli(&args)
        }

        /// The system `ssh` (no binding: for `-G`, which connects to nothing).
        pub fn ssh_g(&self, alias: &str) -> Out {
            let (program, _, env) = self.w.login_command(FINAL, "x");
            let mut args = self.w.home.isolation_args();
            args.push("-G".into());
            args.push(alias.into());
            world::run_bounded(
                Command::new(program)
                    .args(args)
                    .env_clear()
                    .envs(env)
                    .current_dir(&self.w.home.root),
                Duration::from_secs(60),
            )
        }

        /// `heimdall run --profile exit -- ssh <isolation> <extra> <alias> [remote]`: the
        /// binding holds every pair's slot, so the projection alone supplies identity and
        /// route to both hops.
        pub fn run_ssh(
            &self,
            work: &str,
            extra: &[&str],
            alias: &str,
            remote: Option<&str>,
        ) -> Out {
            self.run_ssh_isolated(work, extra, alias, remote, self.w.home.isolation_args())
        }

        /// [`Self::run_ssh`] with the client's isolation arguments `isolation` (its `-F`
        /// configuration and trust files) instead of the scratch home's.
        pub fn run_ssh_isolated(
            &self,
            work: &str,
            extra: &[&str],
            alias: &str,
            remote: Option<&str>,
            isolation: Vec<std::ffi::OsString>,
        ) -> Out {
            let mut last = Out {
                code: -1,
                stdout: String::new(),
                stderr: String::new(),
            };
            for _ in 0..30 {
                let mut cmd =
                    self.run_ssh_command_isolated(work, extra, alias, remote, isolation.clone());
                last = world::run_bounded(&mut cmd, Duration::from_secs(90));
                // An earlier `run`'s binding releases its slots when the runtime notices its
                // holder is gone (every few seconds): retry while that is all that refuses.
                if !last.stderr.contains("managed_slot_held") {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            last
        }

        /// A fresh `--meta-file` path for a launch, remembered so the launch's binding is
        /// released before the next launch (a pair's managed slot has one holder).
        fn meta_path(&self) -> std::path::PathBuf {
            let p = self.w.home.root.join("meta").join(format!(
                "m{}.ndjson",
                heimdall_testkit::agent::random_hex(6)
            ));
            self.pending.lock().unwrap().push(p.clone());
            p
        }

        /// Release the bindings of the launches so far (their holders are gone or going).
        pub fn release_pending(&self) {
            let paths: Vec<_> = std::mem::take(&mut *self.pending.lock().unwrap());
            for p in paths {
                let Ok(text) = std::fs::read_to_string(&p) else {
                    continue;
                };
                let mut rest = text.as_str();
                let mut ids = Vec::new();
                while let Some(i) = rest.find("binding_") {
                    let id: String = rest[i..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    rest = &rest[i + id.len()..];
                    if !ids.contains(&id) {
                        ids.push(id);
                    }
                }
                for id in ids {
                    let _ = self.w.cli(&["--json", "access", "release", &id]);
                }
            }
        }

        pub fn run_ssh_command(
            &self,
            work: &str,
            extra: &[&str],
            alias: &str,
            remote: Option<&str>,
        ) -> Command {
            self.run_ssh_command_isolated(work, extra, alias, remote, self.w.home.isolation_args())
        }

        fn run_ssh_command_isolated(
            &self,
            work: &str,
            extra: &[&str],
            alias: &str,
            remote: Option<&str>,
            isolation: Vec<std::ffi::OsString>,
        ) -> Command {
            self.release_pending();
            let meta = self.meta_path();
            let mut cmd = Command::new(world::bin());
            cmd.args([
                "run",
                "--profile",
                "exit",
                "--work-id",
                work,
                "--request-id",
                &format!("req-{work}"),
                "--meta-file",
            ])
            .arg(&meta)
            .arg("--")
            .arg(world::openssh("ssh"))
            .args(isolation)
            .args(extra)
            .arg(alias);
            if let Some(r) = remote {
                cmd.arg(r);
            }
            cmd.env_clear()
                .envs(self.w.env())
                .current_dir(&self.w.home.root);
            cmd
        }

        /// `heimdall --non-interactive connect <alias>` with `script` on stdin (the remote
        /// login shell reads its commands from it).
        pub fn connect(&self, alias: &str, script: &str) -> Out {
            // A binding of an earlier `run` releases its slot when the runtime notices its
            // holder is gone: retry while that is the only thing refusing.
            let mut last = self.connect_once(alias, script);
            for _ in 0..30 {
                if !last.stderr.contains("managed_slot_held") {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
                last = self.connect_once(alias, script);
            }
            last
        }

        fn connect_once(&self, alias: &str, script: &str) -> Out {
            self.release_pending();
            let meta = self.meta_path();
            let mut child = Command::new(world::bin())
                .args(["connect", alias, "--meta-file"])
                .arg(&meta)
                .env_clear()
                .envs(self.w.env())
                .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
                .current_dir(&self.w.home.root)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn heimdall connect");
            let mut stdin = child.stdin.take().unwrap();
            let out = world::drain(child.stdout.take().unwrap());
            let err = world::drain(child.stderr.take().unwrap());
            stdin.write_all(script.as_bytes()).unwrap();
            drop(stdin);
            let start = std::time::Instant::now();
            let code = loop {
                if let Ok(Some(s)) = child.try_wait() {
                    break s.code().unwrap_or(-1);
                }
                if start.elapsed() > Duration::from_secs(90) {
                    let _ = child.kill();
                    let _ = child.wait();
                    break -1;
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            let o = Out {
                code,
                stdout: String::from_utf8_lossy(&out.join().unwrap_or_default()).into_owned(),
                stderr: String::from_utf8_lossy(&err.join().unwrap_or_default()).into_owned(),
            };
            self.w.record_bytes("connect (stdout)", o.stdout.as_bytes());
            o
        }

        /// The pair `i`'s accepted certificates since `mark`.
        pub fn accepted(&self, i: usize, mark: u64) -> Vec<heimdall_testkit::sshd::AcceptedCert> {
            self.w.accepted_since(i, mark)
        }

        pub fn marks(&self) -> [u64; 2] {
            [
                self.w.pairs[JUMP].sshd.log_mark(),
                self.w.pairs[FINAL].sshd.log_mark(),
            ]
        }
    }

    /// What a `-W` or `-L` forwarding to `target_port` through `alias` came to.
    pub struct Forward {
        /// The first line the forwarded connection returned (the target's SSH banner).
        pub banner: Option<String>,
        /// The client's stderr.
        pub stderr: String,
    }

    impl Route {
        /// A forwarding probe through `alias` to the final host's port: `-W` (stdio) or `-L`
        /// (a local listener the probe connects to).
        pub fn forward(&self, work: &str, alias: &str, kind: &str, target_port: u16) -> Forward {
            // An earlier `run`'s binding releases its slots when the runtime notices its holder
            // is gone: retry while that is the only thing refusing.
            let mut last = self.forward_once(work, alias, kind, target_port);
            for _ in 0..30 {
                if !last.stderr.contains("managed_slot_held") {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
                last = self.forward_once(work, alias, kind, target_port);
            }
            last
        }

        fn forward_once(&self, work: &str, alias: &str, kind: &str, target_port: u16) -> Forward {
            use std::io::Read as _;
            let mut local = None;
            let (extra, remote): (Vec<String>, Option<&str>) = match kind {
                "-W" => (vec!["-W".into(), format!("127.0.0.1:{target_port}")], None),
                _ => {
                    let port = heimdall_testkit::sshd::pick_loopback_port().unwrap();
                    local = Some(port);
                    (
                        vec!["-L".into(), format!("{port}:127.0.0.1:{target_port}")],
                        Some("sleep 6"),
                    )
                }
            };
            let extra_refs: Vec<&str> = extra.iter().map(String::as_str).collect();
            let mut cmd = self.run_ssh_command(work, &extra_refs, alias, remote);
            let mut child = cmd
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn heimdall run");
            let mut stdin = child.stdin.take();
            let out = world::drain(child.stdout.take().unwrap());
            let err = world::drain(child.stderr.take().unwrap());
            std::thread::sleep(Duration::from_millis(4000));
            let mut banner = None;
            if let Some(port) = local {
                if let Ok(mut c) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                    c.set_read_timeout(Some(Duration::from_secs(3))).ok();
                    let mut buf = [0u8; 64];
                    if let Ok(n) = c.read(&mut buf) {
                        banner = Some(String::from_utf8_lossy(&buf[..n]).trim().to_owned())
                            .filter(|b| !b.is_empty());
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            drop(stdin.take());
            let start = std::time::Instant::now();
            loop {
                if let Ok(Some(_)) = child.try_wait() {
                    break;
                }
                if start.elapsed() > Duration::from_secs(15) {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let stdout = String::from_utf8_lossy(&out.join().unwrap_or_default()).into_owned();
            if kind == "-W" {
                banner = stdout
                    .lines()
                    .next()
                    .map(str::to_owned)
                    .filter(|l| l.starts_with("SSH-"));
            }
            Forward {
                banner,
                stderr: String::from_utf8_lossy(&err.join().unwrap_or_default()).into_owned(),
            }
        }

        /// Define profile `profile` over `pairs` (indexes into the world) with `caps`, and a
        /// standing policy `policy` of `window` covering it (seeded as the world seeds
        /// `exit`: the CLI has no capability option, and the runtime is stopped meanwhile).
        pub fn seed_profile(
            &self,
            profile: &str,
            policy: &str,
            pairs: &[usize],
            caps: &[heimdall_contract::request::Capability],
            window: Duration,
        ) {
            use heimdall_contract::ids::{AccountName, DestinationId, PolicyId, ProfileId};
            use heimdall_domain::policy::{
                PauseState, PolicyRevision, PolicySource, StandingPolicy,
            };
            use heimdall_domain::profile::ProfileDefinition;
            use heimdall_domain::scope::{AccessPair, Scope};
            self.w.stop_runtime();
            let scope = Scope {
                pairs: pairs
                    .iter()
                    .map(|i| AccessPair {
                        destination: DestinationId::parse(&self.w.pairs[*i].destination).unwrap(),
                        account: AccountName::parse(&self.w.pairs[*i].account).unwrap(),
                    })
                    .collect(),
                capabilities: caps.iter().copied().collect(),
            };
            let (profile, policy) = (
                ProfileId::parse(profile).unwrap(),
                PolicyId::parse(policy).unwrap(),
            );
            self.w
                .open_store()
                .transaction(|tx| {
                    let env = tx.self_environment()?.expect("environment");
                    tx.upsert_profile(&ProfileDefinition {
                        id: profile.clone(),
                        revision: 1,
                        scope: scope.clone(),
                        label: None,
                    })?;
                    tx.upsert_policy(
                        &StandingPolicy {
                            id: policy.clone(),
                            revision: PolicyRevision(1),
                            profile: profile.clone(),
                            workspace: None,
                            scope: scope.clone(),
                            environments: [env].into_iter().collect(),
                            max_window: window,
                            pause: PauseState::Active,
                            cutoff_at: None,
                            source: PolicySource::SetupDefault,
                            lock_behavior: heimdall_contract::managed::LockBehavior::Continue,
                            connection: heimdall_contract::managed::ConnectionPolicy::default(),
                            default: false,
                        },
                        false,
                    )
                })
                .unwrap();
            self.w.start_runtime();
        }

        /// The extensions of grant `grant`'s published certificate for destination `dest`.
        pub fn extensions(&self, grant: &str, dest: &str) -> Vec<String> {
            let gid = heimdall_contract::ids::GrantId::parse(grant).unwrap();
            let entries = self
                .w
                .open_store()
                .transaction(|tx| tx.issuance_entries(&gid))
                .unwrap();
            let e = entries
                .into_iter()
                .find(|e| {
                    e.pair.destination.as_str() == dest
                        && e.state == heimdall_domain::issuance::IssuanceState::Published
                })
                .unwrap_or_else(|| panic!("no published entry for {dest}"));
            e.bounds.extensions.into_iter().collect()
        }
    }
}

/// A required minimum (here: verified server principals) was not met: `CAPABILITY_UNAVAILABLE`,
/// "the credential mechanism cannot meet the requested capability".
fn unmet(o: &Out) -> bool {
    o.code == 4 && o.stdout.contains("cannot meet the requested capability")
}

fn data(o: &Out) -> Value {
    o.json()["data"].clone()
}

fn reason(o: &Out) -> String {
    let j = o.json();
    j["data"]["error"]["reason"]
        .as_str()
        .or_else(|| j["data"]["reason"].as_str())
        .unwrap_or_default()
        .to_owned()
}

/// The pair `dest` of an ensure result's `consumer.pairs`.
fn pair_of(d: &Value, dest: &str) -> Value {
    d["consumer"]["pairs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["destination"] == dest)
        .unwrap_or_else(|| panic!("no pair {dest}: {d}"))
        .clone()
}

/// ⟨D04; A15⟩ The route-aware evidence sequence through the product's own operations, then a
/// login and `connect` through a **managed** bastion (ADR-0010 §5, §9 item 4):
/// 1. a direct world: `enroll verify` of both pairs, then `ensure` requiring verified server
///    principals holds (the evidence is the product's own);
/// 2. `destination add … --jump` and `setup apply` configure the route (P gets `ProxyJump`);
/// 3. `ensure` requiring verified scope **still holds** through the approved route: no
///    re-verification, the evidence survived; the result reports the route
///    (`jump_access: managed`, the `route_dependency` condition); the jump pair's certificate
///    carries `permit-port-forwarding` and no other pair's does;
/// 4. a fresh login through the jump, and `connect`: both hops authenticate with
///    certificates of one grant;
/// 5. an unauthorized dependency (the profile no longer covers the jump pair) is refused
///    `route_dependency_out_of_scope` by `ensure` and by `connect`;
/// 6. a jump changed outside the catalog (the user's own `ProxyJump` override) and a changed
///    final host key each invalidate the evidence at once; restoring them restores it.
#[cfg(unix)]
#[test]
fn a15_proxyjump_through_managed_bastion() {
    use fx::*;
    let r = route_world(false);
    let final_port = r.w.pairs[FINAL].sshd.port;

    // 1. direct.
    r.verify_all();
    let direct = r.ensure_verified("w-direct", "req-direct", &[]);
    assert_eq!(direct.code, 0, "{}", r.w.redact(&text(&direct)));
    let d = data(&direct);
    assert_eq!(
        d["enforcement"]["destination_scope"],
        "verified_server_principals"
    );
    assert!(
        pair_of(&d, "ex2").get("route").is_none(),
        "no route yet: {d}"
    );
    let g_direct = d["grant_id"].as_str().unwrap().to_owned();
    for dest in ["ex1", "ex2"] {
        assert!(
            !r.extensions(&g_direct, dest)
                .contains(&"permit-port-forwarding".to_owned()),
            "{dest}: no jump pair without a route"
        );
    }
    r.w.revoke(&g_direct, "rev-direct");

    // 2. the route.
    let added = r.define_final(true);
    assert_eq!(added.code, 0, "{}", r.w.redact(&text(&added)));
    r.apply();
    let g = r.ssh_g("exit2");
    assert!(g.stdout.contains("proxyjump exit1"), "{}", text(&g));
    let g1 = r.ssh_g("exit1");
    assert!(
        !g1.stdout.contains("proxyjump"),
        "the jump has no route: {}",
        text(&g1)
    );
    for forbidden in [
        "forwardagent yes",
        "stricthostkeychecking no",
        "stricthostkeychecking accept-new",
    ] {
        assert!(!g.stdout.contains(forbidden), "{forbidden}: {}", text(&g));
    }

    // 3. still verified through the approved route.
    let routed = r.ensure_verified("w-routed", "req-routed", &[]);
    assert_eq!(routed.code, 0, "{}", r.w.redact(&text(&routed)));
    let d = data(&routed);
    assert_eq!(
        d["enforcement"]["destination_scope"], "verified_server_principals",
        "{d}"
    );
    let route = pair_of(&d, "ex2")["route"].clone();
    assert_eq!(
        route,
        serde_json::json!({"jump": "ex1", "jump_alias": "exit1", "jump_access": "managed"}),
        "{d}"
    );
    assert!(pair_of(&d, "ex1").get("route").is_none());
    assert!(
        d["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "route_dependency"),
        "{d}"
    );
    let grant = d["grant_id"].as_str().unwrap().to_owned();
    assert!(
        r.extensions(&grant, "ex1")
            .contains(&"permit-port-forwarding".to_owned())
    );
    assert!(
        !r.extensions(&grant, "ex2")
            .contains(&"permit-port-forwarding".to_owned())
    );
    assert!(
        r.extensions(&grant, "ex2")
            .contains(&"permit-pty".to_owned())
    );
    let inspected = r.w.cli(&["--json", "inspect", "capabilities"]);
    assert_eq!(inspected.code, 0);

    // 4. logins through the jump.
    let marks = r.marks();
    let marker = "hm-route-login";
    let login = r.run_ssh("w-login", &[], "exit2", Some(&format!("echo {marker}")));
    assert!(
        login.code == 0 && login.stdout.contains(marker),
        "{}",
        r.w.redact(&text(&login))
    );
    let (j, f) = (r.accepted(JUMP, marks[0]), r.accepted(FINAL, marks[1]));
    assert_eq!(
        (j.len(), f.len()),
        (1, 1),
        "one certificate at each hop: {j:?} {f:?}"
    );
    let grant_of =
        |c: &heimdall_testkit::sshd::AcceptedCert| c.key_id.split(':').nth(2).unwrap().to_owned();
    assert!(
        j[0].key_id
            .starts_with(&format!("heimdall:{}:grant_", r.w.environment.as_str()))
            && grant_of(&j[0]) == grant_of(&f[0]),
        "one grant's certificates at both hops: {j:?} {f:?}"
    );
    assert_eq!(j[0].ca_fingerprint, r.w.ca_fingerprint.as_str());
    let marks = r.marks();
    let connected = r.connect(
        "exit2",
        &format!(
            "echo {marker}-connect
"
        ),
    );
    assert!(
        connected.code == 0 && connected.stdout.contains(&format!("{marker}-connect")),
        "{}",
        r.w.redact(&text(&connected))
    );
    assert_eq!(r.accepted(JUMP, marks[0]).len(), 1, "connect: the jump hop");
    assert_eq!(
        r.accepted(FINAL, marks[1]).len(),
        1,
        "connect: the final hop"
    );

    // 5. an unauthorized dependency.
    let acct = r.w.pairs[JUMP].account.clone();
    r.cli_ok(&[
        "--json",
        "profile",
        "remove",
        "exit",
        "--pair",
        &format!("ex1:{acct}"),
    ]);
    let refused = r.ensure_verified("w-oos", "req-oos", &[]);
    assert_ne!(refused.code, 0);
    assert_eq!(
        reason(&refused),
        "route_dependency_out_of_scope",
        "{}",
        text(&refused)
    );
    let refused = r.connect(
        "exit2", "echo no
",
    );
    assert_ne!(refused.code, 0, "{}", text(&refused));
    assert!(
        refused.stdout.contains("route_dependency_out_of_scope")
            || refused.stderr.contains("route_dependency_out_of_scope")
            || refused.stderr.contains("bastion"),
        "{}",
        text(&refused)
    );
    r.cli_ok(&[
        "--json",
        "profile",
        "add",
        "exit",
        "--pair",
        &format!("ex1:{acct}"),
    ]);

    // 6. a route change outside the catalog, and a changed final key, each invalidate.
    let still = r.ensure_verified("w-still", "req-still", &[]);
    assert_eq!(still.code, 0, "{}", r.w.redact(&text(&still)));
    let original = std::fs::read(&r.w.home.user_config).unwrap();
    let mut over = b"Host exit2\n    ProxyJump elsewhere\n\n".to_vec();
    over.extend_from_slice(&original);
    std::fs::write(&r.w.home.user_config, &over).unwrap();
    let invalid = r.ensure_verified("w-override", "req-override", &[]);
    assert_ne!(
        invalid.code, 0,
        "an unapproved jump invalidates the evidence"
    );
    assert!(unmet(&invalid), "{}", text(&invalid));
    std::fs::write(&r.w.home.user_config, &original).unwrap();
    let restored = r.ensure_verified("w-restored", "req-restored", &[]);
    assert_eq!(
        restored.code,
        0,
        "the evidence returns with the approved route: {}",
        text(&restored)
    );

    let known = std::fs::read_to_string(&r.w.home.known_hosts).unwrap();
    let wrong = heimdall_testkit::agent::FixtureKey::generate();
    let swapped: String = known
        .lines()
        .map(|l| {
            if l.starts_with(&format!("[127.0.0.1]:{final_port} ")) {
                format!(
                    "[127.0.0.1]:{final_port} {}\n",
                    wrong.public_line_without_comment()
                )
            } else {
                format!("{l}\n")
            }
        })
        .collect();
    std::fs::write(&r.w.home.known_hosts, &swapped).unwrap();
    // ⟨M04-W1-R01⟩ A changed final key through the route is a host-key change: refused at
    // once (the evidence no longer holds), or, once the supervisor's pass has seen it,
    // because the enrollment is held. The hold outlasts the key's return: only an approved
    // target change releases it, as in the direct case.
    let refused = |o: &Out| o.code != 0 && (unmet(o) || o.stdout.contains("pair_not_enrolled"));
    let key_changed = r.ensure_verified("w-key", "req-key", &[]);
    assert!(
        refused(&key_changed),
        "a changed final host key invalidates the evidence: {}",
        text(&key_changed)
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let held = loop {
        let status = r.cli_ok(&["--json", "--non-interactive", "enroll", "status"]);
        let e = status["data"]["enrollments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["destination_id"] == "ex2")
            .cloned()
            .unwrap();
        if e["state"] == "held" || std::time::Instant::now() > deadline {
            break e;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    };
    assert_eq!(held["hold"]["reason"], "host_key_changed", "{held}");
    std::fs::write(&r.w.home.known_hosts, &known).unwrap();
    let back = r.ensure_verified("w-key-back", "req-key-back", &[]);
    assert!(refused(&back), "still held: {}", text(&back));
    let _ = final_port;
}

/// ⟨M04 W1 review, M04-W1-R01; ADR-0010 §5 item 5, §10⟩ A routed enrollment through the real
/// binary: `ex2` is verified directly, then routed through `ex1` (`setup apply`), with an
/// active grant requiring verified server principals.
/// 1. **No verification around the route.** `enroll verify` of `ex2` with the approved keys
///    reaches neither server (its `ssh` would pin the final host directly, around the jump):
///    it ends `verification_inconclusive`, `ex2` stays `verified`, and the grant stays
///    active.
/// 2. **A changed final key is a host-key change through the route.** With the final host's
///    key replaced in `known_hosts`, `enroll verify` (or the supervisor's pass, whichever
///    comes first) holds `ex2` as `host_key_changed` and degrades the grant, again without
///    reaching either server. Before the fix the verification ran a direct session and
///    ended `inconclusive`, `ex2` stayed `verified` and the grant active (the review's
///    probe).
#[cfg(unix)]
#[test]
fn a15_routed_enrollment_never_verified_around_the_jump_and_held_on_a_changed_final_key() {
    use fx::*;
    let r = route_world(false);
    let final_port = r.w.pairs[FINAL].sshd.port;
    r.verify_all();
    let added = r.define_final(true);
    assert_eq!(added.code, 0, "{}", r.w.redact(&text(&added)));
    r.apply();
    let routed = r.ensure_verified("w-r01", "req-r01", &[]);
    assert_eq!(routed.code, 0, "{}", r.w.redact(&text(&routed)));
    let grant = data(&routed)["grant_id"].as_str().unwrap().to_owned();
    assert_eq!(r.w.grant_state(&grant), "active");
    let status_of = |dest: &str| -> Value {
        let status = r.cli_ok(&["--json", "--non-interactive", "enroll", "status"]);
        status["data"]["enrollments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["destination_id"] == dest)
            .cloned()
            .unwrap_or_else(|| panic!("no enrollment of {dest}: {status}"))
    };
    let id = status_of("ex2")["enrollment_id"]
        .as_str()
        .unwrap()
        .to_owned();

    // 1. The approved keys: no session anywhere.
    let marks = r.marks();
    let out =
        r.w.cli(&["--json", "--non-interactive", "enroll", "verify", &id]);
    assert_ne!(out.code, 0, "{}", r.w.redact(&text(&out)));
    assert_eq!(
        reason(&out),
        "verification_inconclusive",
        "{}",
        r.w.redact(&text(&out))
    );
    assert_eq!(status_of("ex2")["state"], "verified");
    assert_eq!(r.w.grant_state(&grant), "active");
    assert!(
        r.accepted(JUMP, marks[0]).is_empty() && r.accepted(FINAL, marks[1]).is_empty(),
        "no verification login at either hop"
    );

    // 2. The final host's key changes.
    let known = std::fs::read_to_string(&r.w.home.known_hosts).unwrap();
    let wrong = heimdall_testkit::agent::FixtureKey::generate();
    let swapped: String = known
        .lines()
        .map(|l| {
            if l.starts_with(&format!("[127.0.0.1]:{final_port} ")) {
                format!(
                    "[127.0.0.1]:{final_port} {}\n",
                    wrong.public_line_without_comment()
                )
            } else {
                format!("{l}\n")
            }
        })
        .collect();
    assert_ne!(swapped, known);
    std::fs::write(&r.w.home.known_hosts, &swapped).unwrap();
    let marks = r.marks();
    // The supervisor's pass may hold it first; the verification then finds it held.
    let out =
        r.w.cli(&["--json", "--non-interactive", "enroll", "verify", &id]);
    assert_ne!(
        reason(&out),
        "verification_inconclusive",
        "{}",
        r.w.redact(&text(&out))
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let held = loop {
        let e = status_of("ex2");
        if e["state"] == "held" || std::time::Instant::now() > deadline {
            break e;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    };
    assert_eq!(held["state"], "held", "{held}");
    assert_eq!(held["hold"]["reason"], "host_key_changed", "{held}");
    assert_eq!(r.w.grant_state(&grant), "degraded");
    assert!(
        r.accepted(JUMP, marks[0]).is_empty() && r.accepted(FINAL, marks[1]).is_empty(),
        "no verification login at either hop"
    );
}

/// ⟨A15; ADR-0010 §5 item 2, §9 item 8⟩ A non-jump pair cannot open forwarding channels; the
/// jump pair can. The jump host's own `sshd` allows forwarding to the final host's port (and
/// its authorized-keys lines do not use `restrict` alone), so the **certificate** is what
/// decides: with no route, the jump host's pair (no `permit-port-forwarding`) gets `-W` and
/// `-L` refused (`administratively prohibited`), as does the final pair on its own host;
/// once the route makes it the jump pair, the same `-W` and `-L` reach the final host's
/// banner (the positive control, on the same server and the same command), while a target
/// outside the jump's `PermitOpen` is still refused by the bastion's own limit (reported,
/// not enforced by Heimdall: ADR-0010 §5 option (d)).
#[cfg(unix)]
#[test]
fn a15_non_jump_pair_cannot_open_forwarding() {
    use fx::*;
    let r = route_world(false);
    r.verify_all();
    let final_port = r.w.pairs[FINAL].sshd.port;
    let jump_port = r.w.pairs[JUMP].sshd.port;
    let prohibited = |f: &Forward| {
        f.banner.is_none()
            && (f.stderr.contains("administratively prohibited")
                || f.stderr.contains("stdio forwarding failed"))
    };

    for (kind, work) in [("-W", "w-nj-w"), ("-L", "w-nj-l")] {
        let f = r.forward(work, "exit1", kind, final_port);
        assert!(
            prohibited(&f),
            "{kind} through a non-jump pair: {} {:?}",
            f.stderr,
            f.banner
        );
    }
    let f = r.forward("w-nj-self", "exit2", "-W", final_port);
    assert!(
        prohibited(&f),
        "the final host allows no forwarding: {} {:?}",
        f.stderr,
        f.banner
    );

    // The route makes exit1 the jump pair: its certificate now carries the extension.
    assert_eq!(r.define_final(true).code, 0);
    r.apply();
    for (kind, work) in [("-W", "w-j-w"), ("-L", "w-j-l")] {
        let f = r.forward(work, "exit1", kind, final_port);
        assert!(
            f.banner.as_deref().is_some_and(|b| b.starts_with("SSH-")),
            "{kind} through the jump pair reaches the final host: {} {:?}",
            f.stderr,
            f.banner
        );
    }
    let f = r.forward("w-j-other", "exit1", "-W", jump_port);
    assert!(
        prohibited(&f),
        "outside the bastion's PermitOpen: {} {:?}",
        f.stderr,
        f.banner
    );
}

/// ⟨D03; ADR-0010 §9 item 3⟩ With the configuration the product generates (P's `ProxyJump
/// exit1` on `exit2`, and the user's own trust files), a substituted host key fails **before
/// authentication to the substituted hop**, at either hop and through an inherited
/// `KnownHostsCommand` as the trust source. No pinning flag is used: the client gets only
/// the isolation arguments and the user configuration. The oracle is the client's `-v` output
/// and the fixture sshds' logs: the substituted hop's server logs no publickey attempt, and
/// (for the final hop) the client never reports authenticating to it.
///
/// ⟨M04-W1-R01⟩ The substitutions go into the **client's** copy of the user configuration
/// and known-hosts file (`-F` and `UserKnownHostsFile` name the copies; the jump hop's `ssh`
/// gets the same `-F`). The runtime keeps evaluating the originals. Otherwise its supervisor
/// sees the changed key within a pass, holds the enrollment of the substituted hop, and the
/// launch is refused before any client runs (a stronger refusal, proven by
/// `a15_routed_enrollment_never_verified_around_the_jump_and_held_on_a_changed_final_key`),
/// so this proof of the client's own lookup would race the pass.
#[cfg(unix)]
#[test]
fn a15_proxyjump_substituted_host_keys_fail_before_authentication() {
    use fx::*;
    let r = route_world(false);
    r.verify_all();
    assert_eq!(r.define_final(true).code, 0);
    r.apply();
    let (jump_port, final_port) = (r.w.pairs[JUMP].sshd.port, r.w.pairs[FINAL].sshd.port);
    let known = std::fs::read_to_string(&r.w.home.known_hosts).unwrap();
    // The client's copies of the user configuration and known-hosts file.
    let client_known = r.w.home.root.join("client_known_hosts");
    let client_config = r.w.home.root.join("client_config");
    let original_config = std::fs::read_to_string(&r.w.home.user_config).unwrap();
    let kh = heimdall_testkit::home::ssh_option_path(&r.w.home.known_hosts);
    let ckh = heimdall_testkit::home::ssh_option_path(&client_known);
    assert!(original_config.contains(&format!("UserKnownHostsFile {kh}")));
    let client_isolation = || -> Vec<std::ffi::OsString> {
        r.w.home
            .isolation_args()
            .into_iter()
            .map(|a| {
                let t = a.to_string_lossy();
                if a == r.w.home.user_config.as_os_str() {
                    client_config.clone().into_os_string()
                } else if t.starts_with("UserKnownHostsFile=") {
                    format!("UserKnownHostsFile={ckh}").into()
                } else {
                    a
                }
            })
            .collect()
    };
    let client_config_with = |extra: &str| {
        std::fs::write(
            &client_config,
            format!(
                "{}{extra}",
                original_config.replace(
                    &format!("UserKnownHostsFile {kh}"),
                    &format!("UserKnownHostsFile {ckh}")
                )
            ),
        )
        .unwrap();
    };
    client_config_with("");
    std::fs::write(&client_known, &known).unwrap();
    let line_of = |port: u16| format!("[127.0.0.1]:{port} ");
    let wrong = || heimdall_testkit::agent::FixtureKey::generate().public_line_without_comment();
    let with = |port: u16, key: Option<String>| -> String {
        known
            .lines()
            .map(|l| match (&key, l.starts_with(&line_of(port))) {
                (Some(k), true) => format!("{}{k}\n", line_of(port)),
                (None, true) => String::new(),
                _ => format!("{l}\n"),
            })
            .collect()
    };
    let attempts = |i: usize, mark: u64| -> usize {
        let sshd = &r.w.pairs[i].sshd;
        [
            "Accepted publickey",
            "Failed publickey",
            "Postponed publickey",
            "Invalid user",
        ]
        .iter()
        .map(|n| sshd.log_lines_since(mark, n).len())
        .sum()
    };

    // The control: the unsubstituted configuration passes (and shows what a pass looks like).
    let marks = r.marks();
    let ok = r.run_ssh_isolated(
        "w-d03-ok",
        &["-v"],
        "exit2",
        Some("echo hm-d03-ok"),
        client_isolation(),
    );
    assert!(
        ok.code == 0 && ok.stdout.contains("hm-d03-ok"),
        "{}",
        text(&ok)
    );
    assert_eq!(
        r.accepted(JUMP, marks[0]).len(),
        1,
        "control: the jump hop authenticated"
    );
    assert_eq!(
        r.accepted(FINAL, marks[1]).len(),
        1,
        "control: the final hop authenticated"
    );
    assert!(ok.stderr.contains("(via proxy) using"), "{}", ok.stderr);

    // A. the bastion's key substituted.
    std::fs::write(&client_known, with(jump_port, Some(wrong()))).unwrap();
    let marks = r.marks();
    let out = r.run_ssh_isolated(
        "w-d03-a",
        &["-v"],
        "exit2",
        Some("echo hm-d03-a"),
        client_isolation(),
    );
    assert_ne!(out.code, 0, "{}", text(&out));
    assert!(
        out.stderr.contains("Host key verification failed"),
        "{}",
        out.stderr
    );
    assert!(!out.stdout.contains("hm-d03-a"));
    assert_eq!(
        attempts(JUMP, marks[0]),
        0,
        "no publickey attempt at the substituted bastion"
    );
    assert!(
        r.w.pairs[FINAL]
            .sshd
            .log_lines_since(marks[1], "Connection from")
            .is_empty(),
        "the final host was never reached"
    );
    assert!(
        !out.stderr.contains("Offering public key"),
        "no key offered anywhere"
    );
    assert!(!out.stderr.contains("Authenticated to"), "{}", out.stderr);

    // B. the final host's key substituted (the bastion's restored).
    std::fs::write(&client_known, with(final_port, Some(wrong()))).unwrap();
    let marks = r.marks();
    let out = r.run_ssh_isolated(
        "w-d03-b",
        &["-v"],
        "exit2",
        Some("echo hm-d03-b"),
        client_isolation(),
    );
    assert_ne!(out.code, 0, "{}", text(&out));
    assert!(
        out.stderr.contains("Host key verification failed"),
        "{}",
        out.stderr
    );
    assert_eq!(
        r.accepted(JUMP, marks[0]).len(),
        1,
        "the bastion hop authenticated and forwarded"
    );
    assert_eq!(
        attempts(FINAL, marks[1]),
        0,
        "no publickey attempt at the substituted final host"
    );
    assert!(
        !out.stderr.contains("(via proxy) using"),
        "the client never authenticated to the final host: {}",
        out.stderr
    );
    assert!(!out.stdout.contains("hm-d03-b"));

    // C. an inherited KnownHostsCommand as the bastion's key source (no file entry for it).
    std::fs::write(&client_known, with(jump_port, None)).unwrap();
    let script = r.w.home.root.join("khc-wrong");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncase \"$1\" in\n  *:{jump_port}) printf '%s\\n' '[127.0.0.1]:{jump_port} {}' ;;\nesac\n",
            wrong()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    client_config_with(&format!("\nKnownHostsCommand {} %H\n", script.display()));
    let marks = r.marks();
    let out = r.run_ssh_isolated(
        "w-d03-c",
        &["-v"],
        "exit2",
        Some("echo hm-d03-c"),
        client_isolation(),
    );
    assert_ne!(out.code, 0, "{}", text(&out));
    assert!(
        out.stderr.contains("Host key verification failed"),
        "{}",
        out.stderr
    );
    assert_eq!(
        attempts(JUMP, marks[0]),
        0,
        "no publickey attempt: the command's key is not the bastion's"
    );
    assert!(!out.stderr.contains("Authenticated to"), "{}", out.stderr);
    // The runtime evaluated the unchanged originals throughout: nothing was held, so every
    // refusal above was the client's own.
    let status = r.cli_ok(&["--json", "--non-interactive", "enroll", "status"]);
    for e in status["data"]["enrollments"].as_array().unwrap() {
        assert_eq!(e["state"], "verified", "{e}");
    }
}

/// ⟨A27⟩ A binary round trip through the jump: 3 MiB of non-text bytes through `ssh exit2 cat`
/// (the bastion forwards the stream to the final host and back) come back byte for byte.
#[cfg(unix)]
#[test]
fn a15_binary_roundtrip_through_jump() {
    use fx::*;
    use std::io::{Read as _, Write as _};
    use std::process::Stdio;
    let r = route_world(false);
    r.verify_all();
    assert_eq!(r.define_final(true).code, 0);
    r.apply();
    let payload: Vec<u8> = (0..3 * 1024 * 1024u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let mut cmd = r.run_ssh_command("w-roundtrip", &[], "exit2", Some("cat"));
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let err = world::drain(child.stderr.take().unwrap());
    let send = payload.clone();
    let writer = std::thread::spawn(move || {
        stdin.write_all(&send).unwrap();
    });
    let mut back = Vec::new();
    stdout.read_to_end(&mut back).unwrap();
    writer.join().unwrap();
    let status = child.wait().unwrap();
    let stderr = String::from_utf8_lossy(&err.join().unwrap_or_default()).into_owned();
    assert!(status.success(), "{stderr}");
    assert_eq!(back.len(), payload.len(), "{stderr}");
    assert!(back == payload, "the bytes differ");
}

/// ⟨A15; ADR-0010 §5 item 3⟩ P never renders `ForwardAgent`, and a managed certificate lacks
/// `permit-agent-forwarding` unless the grant has the `agent-forwarding` capability, so a user's
/// own `ssh -A` (here `-o ForwardAgent=<an agent socket>`, so a request is certainly sent) on a
/// managed alias is refused **by the destination**: both fixture sshds allow agent forwarding
/// administratively (`AllowAgentForwarding yes`), and the remote session still has no
/// `SSH_AUTH_SOCK`.
#[cfg(unix)]
#[test]
fn a15_user_dash_a_refused_without_capability() {
    use fx::*;
    let r = route_world(true);
    r.verify_all();
    let decoy = r.w.home.decoy_agent().endpoint().locator();
    let decoy = decoy.to_string_lossy().into_owned();
    let out = r.run_ssh(
        "w-dash-a",
        &["-o", &format!("ForwardAgent={decoy}")],
        "exit2",
        Some("echo SOCK=${SSH_AUTH_SOCK:-none}"),
    );
    assert!(
        out.code == 0 && out.stdout.contains("SOCK=none"),
        "the destination refuses the forwarding request: {}",
        text(&out)
    );
    let g = r.ssh_g("exit2");
    assert!(
        g.stdout.contains("\nforwardagent no\n"),
        "P never renders ForwardAgent: {}",
        text(&g)
    );
    assert!(
        std::fs::read_to_string(r.w.home.git_home.join(".config/heimdall/ssh_config"))
            .or_else(|_| std::fs::read_to_string(r.w.hh.join("config/ssh_config")))
            .is_ok_and(|p| !p.contains("ForwardAgent")),
        "P carries no ForwardAgent"
    );
}

/// ⟨A15; ADR-0010 §5 item 4⟩ With the grant's `agent-forwarding` capability, `connect` carries
/// `ForwardAgent <that binding's endpoint>` and the destination's certificate permits it. The
/// forwarded endpoint then lists only the binding's identities, a host that does not map the
/// principal refuses the forwarded identity, the final host (which maps it) accepts it, and both
/// stop at the grant's deadline. Unix; on Windows `ForwardAgent` to a named pipe stays
/// `unsupported` (ADR-0010 §9 item 8: no pass is claimed).
#[cfg(unix)]
#[test]
fn a15_forwarded_endpoint_bounded_to_binding() {
    use fx::*;
    use heimdall_contract::request::Capability;
    // ⟨M04 integrator⟩ OpenSSH 10.1 and later place a forwarded agent's listener under the
    // authenticated account's `~/.ssh/agent/`. The fixture sshd runs as this account, so on
    // such a host the case would write into the owner's `~/.ssh` (AGENTS.md: never). It runs
    // where the sshd keeps the socket in `/tmp` (the devbox's 9.6p1), or with an explicit
    // opt-in on a scratch account; elsewhere it reports itself blocked and does nothing.
    // The guard is the testkit's (`heimdall_testkit::sshd`, shared with M06's forwarding
    // steps): it asks the sshd the fixture itself resolves, and fails closed.
    if heimdall_testkit::sshd::agent_forwarding_through_account_sshd_blocked() {
        println!(
            "blocked (B3, no scratch account): {}; run on a host whose sshd uses /tmp (the \
             devbox) or a scratch account ({}=1)",
            heimdall_testkit::sshd::FORWARDED_AGENT_BLOCKED_REASON,
            heimdall_testkit::sshd::FORWARDING_SCRATCH_ACCOUNT_ENV,
        );
        return;
    }
    let r = route_world(true);
    r.verify_all();
    r.seed_profile(
        "fwd",
        "fwd-pol",
        &[FINAL],
        &[Capability::SshAuthentication, Capability::AgentForwarding],
        std::time::Duration::from_secs(60),
    );
    r.cli_ok(&["--json", "profile", "remove", "exit"]);
    let (jump_port, final_port) = (r.w.pairs[JUMP].sshd.port, r.w.pairs[FINAL].sshd.port);
    let scratch = r.w.home.root.join("fwd-probe");
    std::fs::create_dir(&scratch).unwrap();
    let remote_ssh = |port: u16, tag: &str| {
        format!(
            "ssh -n -F /dev/null -o BatchMode=yes -o IdentityFile={d}/none -o IdentitiesOnly=no \
             -o StrictHostKeyChecking=no -o UserKnownHostsFile={d}/kh -o ConnectTimeout=10 \
             -p {port} 127.0.0.1 echo {tag}; echo rc-{tag}=$?",
            d = scratch.display()
        )
    };
    let script = format!(
        "echo SOCK=${{SSH_AUTH_SOCK:-none}}\n\
         echo LIST_BEGIN; ssh-add -l; echo LIST_END\n\
         {}\n{}\n\
         sleep 66\n\
         echo AFTER_BEGIN; ssh-add -l; echo AFTER_END\n{}\n",
        remote_ssh(final_port, "FINAL-BEFORE"),
        remote_ssh(jump_port, "UNMAPPED"),
        remote_ssh(final_port, "FINAL-AFTER"),
    );
    let marks = r.marks();
    let out = r.connect("exit2", &script);
    let stdout = &out.stdout;
    assert_eq!(out.code, 0, "{}", r.w.redact(&text(&out)));
    assert!(
        stdout.contains("SOCK=/"),
        "the binding's endpoint is forwarded: {stdout}"
    );
    let between = |a: &str, b: &str| -> String {
        stdout
            .split(a)
            .nth(1)
            .and_then(|t| t.split(b).next())
            .unwrap_or_default()
            .to_owned()
    };
    let fingerprints = |t: &str| -> Vec<String> {
        t.split_whitespace()
            .filter(|w| w.starts_with("SHA256:"))
            .map(str::to_owned)
            .collect()
    };
    let listed = fingerprints(&between("LIST_BEGIN", "LIST_END"));
    let accepted = r.accepted(FINAL, marks[1]);
    assert!(
        !listed.is_empty() && listed.len() <= 2,
        "the binding's identities only: {stdout}"
    );
    assert!(
        listed
            .iter()
            .all(|fp| accepted.iter().any(|c| &c.fingerprint == fp)),
        "{listed:?} vs {accepted:?}"
    );
    assert!(
        stdout.contains("FINAL-BEFORE") && stdout.contains("rc-FINAL-BEFORE=0"),
        "the mapped host accepts it: {stdout}"
    );
    assert!(
        !stdout.contains("\nUNMAPPED\n") && !stdout.contains("rc-UNMAPPED=0"),
        "an unmapped host refuses the forwarded identity: {stdout}"
    );
    assert!(
        r.w.pairs[JUMP]
            .sshd
            .log_lines_since(marks[0], "Accepted publickey")
            .is_empty(),
        "the unmapped host accepted nothing"
    );
    // The deadline: the endpoint still lists only the binding's identity (it lasts until the
    // binding ends, ADR-0010 §5 item 4), and the mapped host that accepted it before the
    // deadline now refuses it: forwarded use stops at the deadline.
    assert!(
        fingerprints(&between("AFTER_BEGIN", "AFTER_END"))
            .iter()
            .all(|fp| listed.contains(fp)),
        "{stdout}"
    );
    assert!(
        !stdout.contains("\nFINAL-AFTER\n") && !stdout.contains("rc-FINAL-AFTER=0"),
        "signing stops at the deadline: {stdout}"
    );
}

/// ⟨ADR-0010 §5 item 1; reading I-4⟩ The route rules through the real binary and the real
/// runtime, with no sshd (runs on every host): a jump is a managed destination other than the
/// destination, with no jump of its own (`route_chain_unsupported`); an observed or missing jump
/// is refused (`route_dependency_out_of_scope`, `NOT_FOUND`); a destination another uses as its
/// jump cannot become route-bearing or be removed (`route_chain_unsupported`) while that use
/// exists. The domain's rule table is `route_chain_and_out_of_scope_jump_refused`.
#[test]
fn route_rules_through_the_real_binary() {
    use std::process::{Command, Stdio};
    let home = heimdall_testkit::home::ScratchHome::new();
    let hh = home.root.join("hh");
    let env = || -> Vec<(String, std::ffi::OsString)> {
        let lock = home.root.join("lock-state");
        std::fs::write(&lock, "unlocked").unwrap();
        let mut e: Vec<(String, std::ffi::OsString)> = vec![
            ("HEIMDALL_HOME".into(), hh.clone().into_os_string()),
            ("HOME".into(), home.git_home.clone().into_os_string()),
            // Catalog writes need safe time: the test configuration the exit suite uses.
            ("HEIMDALL_TEST_ADAPTER".into(), "prepare".into()),
            ("HEIMDALL_TEST_TIME_SYNC".into(), "synchronized".into()),
            ("HEIMDALL_TEST_SESSION_LOCK".into(), lock.into_os_string()),
            (
                "HEIMDALL_TEST_SSH_HOME".into(),
                home.git_home.clone().into_os_string(),
            ),
        ];
        if !cfg!(windows) {
            e.push(("HEIMDALL_TEST_SECRET_STORE".into(), "scratch".into()));
        }
        if cfg!(windows) {
            for k in [
                "SystemRoot",
                "PATH",
                "TEMP",
                "TMP",
                "USERNAME",
                "USERPROFILE",
            ] {
                if let Some(v) = std::env::var_os(k) {
                    e.push((k.to_owned(), v));
                }
            }
        } else {
            e.push(("PATH".into(), "/usr/bin:/bin".into()));
        }
        e
    };
    let cli = |args: &[&str]| -> Out {
        let o = Command::new(world::bin())
            .args(args)
            .env_clear()
            .envs(env())
            .current_dir(&home.root)
            .stdin(Stdio::null())
            .output()
            .expect("spawn heimdall");
        Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    };
    let key = heimdall_testkit::agent::FixtureKey::generate_many(1);
    let public = home.root.join("k.pub");
    std::fs::write(
        &public,
        format!("{}\n", key[0].public_line_without_comment()),
    )
    .unwrap();
    let adopted = cli(&[
        "--json",
        "identity",
        "adopt",
        "--pub",
        &public.to_string_lossy(),
    ]);
    assert_eq!(adopted.code, 0, "{}", text(&adopted));
    let identity = adopted.json()["data"]["identity_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let add = |alias: &str, extra: &[&str]| -> Out {
        let mut a = vec![
            "--json",
            "destination",
            "add",
            alias,
            "--hostname",
            "10.0.0.9",
            "--account",
            "ops",
            "--identity",
            &identity,
            "--id",
            alias,
        ];
        a.extend(extra);
        cli(&a)
    };
    let reason_of = |o: &Out| reason(o);
    assert_eq!(add("bastion", &[]).code, 0);
    assert_eq!(
        add("lab", &["--jump", "bastion"]).code,
        0,
        "a valid single-hop route"
    );
    let shown = cli(&["--json", "destination", "list"]);
    assert!(
        shown.stdout.contains("\"jump\":\"bastion\""),
        "{}",
        text(&shown)
    );
    // A chain: the jump has a jump of its own.
    let chain = add("far", &["--jump", "lab"]);
    assert_eq!(
        reason_of(&chain),
        "route_chain_unsupported",
        "{}",
        text(&chain)
    );
    // The bastion cannot become route-bearing, or go, while `lab` uses it.
    let nested = add("bastion", &["--jump", "far"]);
    assert_ne!(nested.code, 0, "{}", text(&nested));
    let remove = cli(&["--json", "destination", "remove", "bastion"]);
    assert_eq!(
        reason_of(&remove),
        "route_chain_unsupported",
        "{}",
        text(&remove)
    );
    // Itself, an observed destination, a missing one.
    let own = add("solo", &["--jump", "solo"]);
    assert_ne!(own.code, 0, "{}", text(&own));
    assert_eq!(
        cli(&["--json", "destination", "add", "seen", "--observed"]).code,
        0
    );
    let observed = add("lab2", &["--jump", "seen"]);
    assert_eq!(
        reason_of(&observed),
        "route_dependency_out_of_scope",
        "{}",
        text(&observed)
    );
    let missing = add("lab3", &["--jump", "nowhere"]);
    assert_ne!(missing.code, 0, "{}", text(&missing));
    // Once nothing uses it, the bastion goes.
    assert_eq!(cli(&["--json", "destination", "remove", "lab"]).code, 0);
    assert_eq!(cli(&["--json", "destination", "remove", "bastion"]).code, 0);
    let _ = cli(&["service", "stop"]);
}

/// ⟨D04; A15; ADR-0010 §5 item 2⟩ A route through an **existing-access** bastion: the jump pair
/// prefers existing access (its adopted identity, held by a fixture agent that the jump host
/// authorizes), the grant covers the final pair only, and the result reports `jump_access:
/// existing` with the route dependency and the weaker lock continuity. `ensure` requiring
/// verified scope holds through the route; a login (`run`) and `connect` reach the final host
/// through the bastion, the jump hop authenticating with the adopted key (an `Accepted publickey`
/// by that key, no certificate) and no certificate extension is granted to the bastion.
#[cfg(unix)]
#[test]
fn a15_proxyjump_through_existing_access_bastion() {
    use fx::*;
    use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};
    use std::process::Command;
    let scratch = heimdall_testkit::home::Scratch::new().expect("scratch");
    let key = FixtureKey::generate();
    let agent = FakeAgent::try_start(
        Endpoint::in_scratch(&scratch, "jump-agent").unwrap(),
        FakeAgentConfig {
            keys: vec![key.clone()],
            mode: AgentMode::Normal,
        },
    )
    .expect("fixture agent");
    let socket = agent.endpoint().locator().to_string_lossy().into_owned();
    let r = route_world_with(false, vec![key.clone()], Some(agent));
    let acct = r.w.pairs[JUMP].account.clone();
    r.verify_all();
    // The jump destination is adopted from the fixture agent and prefers existing access.
    let adopted = Command::new(world::bin())
        .args([
            "--json",
            "--non-interactive",
            "identity",
            "adopt",
            "--from-agent",
            "--active-probe",
            "agent",
            "--fingerprint",
            &key.fingerprint(),
        ])
        .env_clear()
        .envs(r.w.env())
        .env("SSH_AUTH_SOCK", &socket)
        .current_dir(&r.w.home.root)
        .output()
        .unwrap();
    assert_eq!(
        adopted.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&adopted.stdout)
    );
    let adopted: Value = serde_json::from_slice(
        String::from_utf8_lossy(&adopted.stdout)
            .lines()
            .rev()
            .find(|l| l.trim_start().starts_with('{'))
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let identity = adopted["data"]["identity_id"].as_str().unwrap().to_owned();
    let p = &r.w.pairs[JUMP];
    let port = p.sshd.port.to_string();
    r.cli_ok(&[
        "--json",
        "destination",
        "add",
        &p.alias,
        "--hostname",
        &p.sshd.host,
        "--port",
        &port,
        "--account",
        &p.account,
        "--identity",
        &identity,
        "--id",
        &p.destination,
    ]);
    r.cli_ok(&["--json", "destination", "prefer", &p.alias, "existing"]);
    // The grant covers the final pair alone; then the route.
    r.cli_ok(&[
        "--json",
        "profile",
        "remove",
        "exit",
        "--pair",
        &format!("ex1:{acct}"),
    ]);
    assert_eq!(r.define_final(true).code, 0);
    r.apply();
    let g = r.ssh_g("exit2");
    assert!(g.stdout.contains("proxyjump exit1"), "{}", text(&g));

    let ensured = r.ensure_verified("w-ex", "req-ex", &[]);
    assert_eq!(ensured.code, 0, "{}", r.w.redact(&text(&ensured)));
    let d = data(&ensured);
    assert_eq!(
        d["enforcement"]["destination_scope"], "verified_server_principals",
        "{d}"
    );
    assert_eq!(
        pair_of(&d, "ex2")["route"],
        serde_json::json!({"jump": "ex1", "jump_alias": "exit1", "jump_access": "existing"}),
        "{d}"
    );
    assert!(
        d["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "route_dependency"),
        "{d}"
    );
    assert_eq!(
        d["lock_continuity"], "not_verified",
        "the weaker hop's: {d}"
    );
    let grant = d["grant_id"].as_str().unwrap().to_owned();
    assert!(
        !r.extensions(&grant, "ex2")
            .contains(&"permit-port-forwarding".to_owned())
    );

    let marks = r.marks();
    let login = r.run_ssh("w-ex-login", &[], "exit2", Some("echo hm-existing-hop"));
    assert!(
        login.code == 0 && login.stdout.contains("hm-existing-hop"),
        "{}",
        r.w.redact(&text(&login))
    );
    let jump_keys = r.w.pairs[JUMP]
        .sshd
        .log_lines_since(marks[0], "Accepted publickey");
    assert_eq!(jump_keys.len(), 1, "{jump_keys:?}");
    assert!(
        jump_keys[0].contains(&key.fingerprint()) && !jump_keys[0].contains("-CERT"),
        "the jump hop used the adopted key: {jump_keys:?}"
    );
    assert_eq!(
        r.accepted(FINAL, marks[1]).len(),
        1,
        "the final hop used a certificate"
    );
    let connected = r.connect("exit2", "echo hm-existing-connect\n");
    assert!(
        connected.code == 0 && connected.stdout.contains("hm-existing-connect"),
        "{}",
        r.w.redact(&text(&connected))
    );
}
