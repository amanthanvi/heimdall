//! M02-U9 end-to-end suite: `heimdall setup|doctor|destination|identity|profile|
//! uninstall` through the **real binary** (`CARGO_BIN_EXE_heimdall`, or
//! `HEIMDALL_E2E_BIN`) against a real runtime (m02-plan U9 "Tests"; ADR-0007 §5, §6,
//! §7; ADR-0006 §3.1).
//!
//! **The runtime is always this test's in-process service** (`Service::start_with`
//! with `ProjectionWiring::Config` over a `ScratchHome`), never one the CLI starts:
//! a runtime the CLI started would wire the account's real `~/.ssh` (the account
//! database's home). [`World::cli`] refuses to run a command that could start one
//! while the service is stopped; only `doctor`, which never starts it, runs then.
//!
//! **Isolation** (m02-plan §0; ADR-0007 §9). Every process gets a cleared environment:
//! `PATH=/usr/bin:/bin`, the scratch `HOME`, `HEIMDALL_HOME` and
//! `HEIMDALL_TEST_SSH_HOME` (the CLI's SSH paths, and the doctor's isolation-only
//! client arguments), `GIT_CONFIG_NOSYSTEM=1`, a scratch `GIT_CONFIG_GLOBAL`, and the
//! decoy counting agent at `SSH_AUTH_SOCK`. Clients get only isolation on their
//! command line (`ScratchHome::isolation_args`), after the default-identity guard.
//! Keys are generated per run. Only processes this test started are stopped, by their
//! own handles.
//!
//! **Canaries.** Every stdout and stderr byte is scanned with `assert_no_canary`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]
// The suite is Unix-hosted (the fixture sshd, agents and the pty); on Windows only the
// usage-error case runs, and the shared helpers are unused there.
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use heimdall_testkit::assert_no_canary;
use serde_json::Value;

/// The binary under test.
fn bin() -> String {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
}

fn os(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

/// One finished invocation.
#[derive(Debug)]
struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Out {
    fn of(out: std::process::Output) -> Out {
        let o = Out {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        };
        assert_no_canary(&o.stdout);
        assert_no_canary(&o.stderr);
        o
    }

    /// The `--json` envelope (the last JSON line on stdout).
    fn json(&self) -> Value {
        self.stdout
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
            .unwrap_or_else(|| panic!("no envelope: {self:?}"))
    }

    fn code_str(&self) -> String {
        self.json()["code"].as_str().unwrap_or_default().to_owned()
    }

    fn reason(&self) -> String {
        self.json()["data"]["error"]["reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
}

/// The checked-in public schema `name`.
fn schema(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/public-api")
        .join(format!("{name}.schema.json"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

/// `value` validates against the public schema `name` (the contract suite's validator).
fn assert_valid(name: &str, value: &Value) {
    if let Err(errors) = jsonschema_lite::validate(&schema(name), value) {
        panic!("{name}: {errors:?}\n{value}");
    }
}

/// An envelope validates against `envelope` (or `envelope.error` for an error).
fn assert_envelope_valid(env: &Value) {
    if env["data"].get("error").is_some() {
        assert_valid("envelope.error", env);
    } else {
        assert_valid("envelope", env);
    }
}

#[cfg(unix)]
mod world {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use heimdall_app::{Attendance, Caller, OpError, Operations};
    use heimdall_contract::catalog::{
        CatalogRequest, DeclaredInteraction, DestinationDefinitionSpec, DestinationSpec,
        IdentitySourceSpec, IdentitySpec, ProfileSpec,
    };
    use heimdall_contract::ids::{
        AccountName, DecisionId, DestinationId, IdentityId, PolicyId, ProfileId, RequestId,
    };
    use heimdall_contract::provider::{EndpointKind, EndpointRef};
    use heimdall_contract::request::{AccessPairRef, DecideRequest, InteractionMode, Verdict};
    use heimdall_contract::setup::{PreviewIntent, SetupPlan, SetupRequest};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_localenv::env::{Env, Platform};
    use heimdall_localenv::paths::SshPaths;
    use heimdall_localenv::projection::{ProjectionConfig, ReplaceHook, ReplacePoint};
    use heimdall_runtime::config::{Config, Paths};
    use heimdall_runtime::service::{ProjectionWiring, Service, ServiceOptions};
    use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};
    use heimdall_testkit::home::ScratchHome;
    use tokio_util::sync::CancellationToken;

    use super::*;

    /// A one-shot hook action: runs at `point` (any step) while it returns `false`, and
    /// is disarmed once it returns `true`.
    type Action = Box<dyn Fn() -> bool + Send + Sync>;

    /// The projection writer's test hook (the U4 `ReplaceHook` seam).
    #[derive(Default)]
    pub(super) struct Hook {
        armed: Mutex<Vec<(ReplacePoint, Action)>>,
    }

    impl Hook {
        pub(super) fn arm(
            &self,
            point: ReplacePoint,
            f: impl Fn() -> bool + Send + Sync + 'static,
        ) {
            self.armed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((point, Box::new(f)));
        }
    }

    impl ReplaceHook for Hook {
        fn at(&self, point: ReplacePoint, _step: u16) {
            let mut armed = self.armed.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(i) = armed.iter().position(|(p, f)| *p == point && f()) {
                drop(armed.remove(i));
            }
        }
    }

    struct Running {
        ops: Operations,
        store: Arc<heimdall_store::Store>,
        token: CancellationToken,
        handle: tokio::runtime::Handle,
        thread: std::thread::JoinHandle<()>,
    }

    /// U7's disposable `ssh-agent` behind a counting proxy (identities adopted at the
    /// proxy, so every agent contact is counted).
    pub(super) struct RealAgent {
        pub(super) agent: heimdall_testkit::agent::DisposableSshAgent,
        pub(super) proxy: heimdall_testkit::agent::CountingProxy,
    }

    pub(super) struct World {
        pub(super) home: ScratchHome,
        service: Option<Running>,
        pub(super) agent: FakeAgent,
        pub(super) real: Option<RealAgent>,
        pub(super) keys: Vec<FixtureKey>,
        pub(super) hook: Arc<Hook>,
        uid: u32,
        n: AtomicU32,
    }

    fn rid(s: &str) -> RequestId {
        RequestId::parse(s).unwrap()
    }

    impl World {
        /// A scratch home, a fake agent holding `keys` keys, the service started.
        pub(super) fn new(keys: usize) -> World {
            World::with_mode(keys, AgentMode::Normal)
        }

        pub(super) fn with_mode(keys: usize, mode: AgentMode) -> World {
            use std::os::unix::fs::MetadataExt as _;
            let home = ScratchHome::new();
            std::fs::create_dir_all(home.root.join("etc-ssh")).unwrap();
            let keys = FixtureKey::generate_many(keys);
            let agent = FakeAgent::start(
                Endpoint::in_scratch(home.scratch(), "agent").unwrap(),
                FakeAgentConfig {
                    keys: keys.clone(),
                    mode,
                },
            );
            let uid = std::fs::metadata(&home.root).unwrap().uid();
            let mut w = World {
                home,
                service: None,
                agent,
                real: None,
                keys,
                hook: Arc::new(Hook::default()),
                uid,
                n: AtomicU32::new(0),
            };
            w.start();
            w
        }

        pub(super) fn projection(&self) -> ProjectionConfig {
            let paths = SshPaths::with_test_override(
                self.home.git_home.clone(),
                self.home.root.join("etc-ssh"),
            );
            let mut c =
                ProjectionConfig::new(paths, Platform::current(), self.home.config_dir.clone());
            c.env = Env::from_vars([
                ("HOME", self.home.git_home.display().to_string()),
                ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
            ]);
            let h: Arc<dyn ReplaceHook> = self.hook.clone();
            c.hook = Some(h);
            c
        }

        pub(super) fn start(&mut self) {
            let projection = self.projection();
            let root = self.home.root.clone();
            let token = CancellationToken::new();
            let service_token = token.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let handle = rt.handle().clone();
                rt.block_on(async move {
                    let clock =
                        Arc::new(heimdall_runtime::platform::SystemClock::try_new().unwrap());
                    let mut o = ServiceOptions::with_clock(
                        clock,
                        heimdall_testkit::ScriptedTimeSync::new(
                            heimdall_domain::time::SyncStatus::Synchronized,
                        ),
                    );
                    o.projection = ProjectionWiring::Config(Box::new(projection));
                    o.existing_access = true;
                    let service = Service::start_with(
                        Paths::under(&root),
                        Config::default(),
                        o,
                        service_token,
                    )
                    .await
                    .unwrap();
                    let _ = tx.send((
                        handle,
                        service.operations().clone(),
                        Arc::clone(service.store()),
                    ));
                    let _ = service.run().await;
                });
            });
            let (handle, ops, store) = rx.recv().expect("the service started");
            self.service = Some(Running {
                ops,
                store,
                token,
                handle,
                thread,
            });
        }

        pub(super) fn stop(&mut self) {
            if let Some(s) = self.service.take() {
                s.token.cancel();
                let _ = s.thread.join();
            }
        }

        /// Whether the service thread still serves (an `uninstall` stops it).
        pub(super) fn serving(&self) -> bool {
            self.service
                .as_ref()
                .is_some_and(|s| !s.thread.is_finished())
                && self.home.root.join("run/instance.json").exists()
        }

        fn on<T: Send + 'static>(
            &self,
            f: impl std::future::Future<Output = T> + Send + 'static,
        ) -> T {
            let (tx, rx) = std::sync::mpsc::channel();
            self.service.as_ref().unwrap().handle.spawn(async move {
                let _ = tx.send(f.await);
            });
            rx.recv().expect("the service task finished")
        }

        fn ops(&self) -> &Operations {
            &self.service.as_ref().unwrap().ops
        }

        pub(super) fn store(&self) -> Arc<heimdall_store::Store> {
            Arc::clone(&self.service.as_ref().unwrap().store)
        }

        fn attended(&self) -> Caller {
            Caller {
                context: CallerContext {
                    principal: PrincipalRef::UnixUser { uid: self.uid },
                    role: ClientRole::Owner,
                },
                attendance: Attendance::Attended {
                    since: heimdall_contract::Timestamp::now(),
                },
                interaction: InteractionMode::Interactive,
            }
        }

        pub(super) fn next_id(&self, what: &str) -> RequestId {
            let n = self.n.fetch_add(1, Ordering::SeqCst);
            rid(&format!("r-{what}-{n}"))
        }

        pub(super) fn catalog(&self, req: CatalogRequest) -> Result<Value, OpError> {
            let caller = self.attended();
            let ops = self.ops().clone();
            self.on(async move { ops.catalog(&caller, req).await.map(|c| c.data) })
        }

        pub(super) fn setup(&self, req: SetupRequest) -> Result<Value, OpError> {
            let caller = self.attended();
            let ops = self.ops().clone();
            self.on(async move { ops.setup(&caller, req).await.map(|c| c.data) })
        }

        pub(super) fn approve(&self, decision: &str) {
            let caller = self.attended();
            let ops = self.ops().clone();
            let d = decision.to_owned();
            self.on(async move {
                ops.decide(
                    &caller,
                    DecideRequest {
                        decision_id: DecisionId::parse(&d).unwrap(),
                        verdict: Verdict::Approve,
                    },
                )
                .await
                .map(|_| ())
            })
            .unwrap();
        }

        pub(super) fn endpoint(&self) -> EndpointRef {
            let locator = match &self.real {
                Some(r) => r.proxy.endpoint().locator(),
                None => self.agent.endpoint().locator(),
            };
            EndpointRef {
                kind: EndpointKind::UnixSocket,
                locator: locator.to_str().unwrap().to_owned(),
            }
        }

        /// Start the disposable agent and its counting proxy, holding `keys` (indices).
        pub(super) fn attach_real(&mut self, keys: &[usize]) {
            use heimdall_testkit::agent::{
                AgentOptions, AskpassAnswer, CountingProxy, DisposableSshAgent, KeyConstraints,
            };
            let scratch = self.home.scratch();
            let agent = DisposableSshAgent::start(
                scratch,
                AgentOptions {
                    askpass_log: Some(self.home.root.join("askpass.log")),
                    askpass_answer: AskpassAnswer::Approve,
                },
            )
            .unwrap_or_else(|e| panic!("the disposable ssh-agent: {e}"));
            for k in keys {
                agent
                    .add_key(
                        &self.keys[*k].with_comment(&format!("hm-fixture-k{k}")),
                        KeyConstraints { confirm: false },
                    )
                    .unwrap();
            }
            let proxy = CountingProxy::start(
                &agent.endpoint(),
                Endpoint::in_scratch(scratch, "proxy").unwrap(),
            );
            self.real = Some(RealAgent { agent, proxy });
        }

        /// Adopt key `k` at the fake agent.
        pub(super) fn adopt(&self, k: usize) -> IdentityId {
            let data = self
                .catalog(CatalogRequest::AdoptIdentity {
                    identity: IdentitySpec {
                        source: IdentitySourceSpec::NativeAgent {
                            endpoint: self.endpoint(),
                        },
                        public_key: self.keys[k].public_line_without_comment(),
                        label: None,
                    },
                    request_id: self.next_id("adopt"),
                })
                .unwrap();
            IdentityId::parse(data["identity_id"].as_str().unwrap()).unwrap()
        }

        /// Managed destination `alias` (`dst-<alias>`) for `identity`.
        pub(super) fn managed(
            &self,
            alias: &str,
            host: &str,
            port: Option<u16>,
            account: &str,
            identity: &IdentityId,
        ) {
            self.catalog(CatalogRequest::UpsertDestination {
                destination: DestinationSpec {
                    id: DestinationId::parse(&format!("dst-{alias}")).unwrap(),
                    alias: alias.to_owned(),
                    definition: DestinationDefinitionSpec::Managed {
                        hostname: host.to_owned(),
                        port,
                        account: AccountName::parse(account).unwrap(),
                        identity: identity.clone(),
                    },
                    label: None,
                },
                request_id: self.next_id("dest"),
            })
            .unwrap();
        }

        /// Profile `work` over `aliases` (as `account`), covered by policy `pol`.
        pub(super) fn profile(&self, aliases: &[&str], account: &str) {
            self.profile_as("work", "pol", aliases, account);
        }

        /// Profile `name` over `aliases` (as `account`), covered by standing policy
        /// `policy`.
        pub(super) fn profile_as(&self, name: &str, policy: &str, aliases: &[&str], account: &str) {
            use heimdall_domain::environment::{
                EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
            };
            use heimdall_domain::policy::{
                PauseState, PolicyRevision, PolicySource, StandingPolicy,
            };
            use heimdall_domain::scope::{AccessPair, Scope};
            let pair = |a: &str| AccessPairRef {
                destination: DestinationId::parse(&format!("dst-{a}")).unwrap(),
                account: AccountName::parse(account).unwrap(),
            };
            self.catalog(CatalogRequest::UpsertProfile {
                profile: ProfileSpec {
                    id: ProfileId::parse(name).unwrap(),
                    pairs: aliases.iter().map(|a| pair(a)).collect(),
                    label: None,
                },
                request_id: self.next_id("profile"),
            })
            .unwrap();
            let env = self.ops().environment().clone();
            let pairs: std::collections::BTreeSet<AccessPair> = aliases
                .iter()
                .map(|a| AccessPair {
                    destination: DestinationId::parse(&format!("dst-{a}")).unwrap(),
                    account: AccountName::parse(account).unwrap(),
                })
                .collect();
            self.store()
                .transaction(|tx| {
                    tx.upsert_environment(&EnvironmentRecord {
                        id: env.clone(),
                        device: heimdall_contract::ids::DeviceId::from_random_bytes([8; 16]),
                        kind: EnvironmentKind::NativeSession,
                        label: None,
                        permissions: EnvironmentPermissions {
                            automatic_activation: true,
                            managed_signing: true,
                            issuer_access: true,
                        },
                    })?;
                    tx.upsert_policy(
                        &StandingPolicy {
                            id: PolicyId::parse(policy).unwrap(),
                            revision: PolicyRevision(1),
                            profile: ProfileId::parse(name).unwrap(),
                            workspace: None,
                            scope: Scope {
                                pairs: pairs.clone(),
                                capabilities: [
                                    heimdall_contract::request::Capability::SshAuthentication,
                                ]
                                .into_iter()
                                .collect(),
                            },
                            environments: [env.clone()].into_iter().collect(),
                            max_window: Duration::from_secs(2 * 3600),
                            pause: PauseState::Active,
                            cutoff_at: None,
                            source: PolicySource::SetupDefault,
                        },
                        false,
                    )
                })
                .unwrap();
        }

        /// Preview and apply (approved), in process.
        pub(super) fn project(&self) {
            let plan: SetupPlan = serde_json::from_value(
                self.setup(SetupRequest::Preview {
                    intent: PreviewIntent::Apply { include_git: false },
                })
                .unwrap(),
            )
            .unwrap();
            let id = self.next_id("apply");
            let apply = |id: RequestId| SetupRequest::Apply {
                plan_digest: plan.plan_digest.clone(),
                request_id: id,
            };
            if let Err(e) = self.setup(apply(id.clone())) {
                self.approve(e.next.decision_ref.as_deref().unwrap());
                self.setup(apply(id)).unwrap();
            }
        }

        /// Declare `identity` `none` (attended, approved), in process.
        pub(super) fn declare(&self, identity: &IdentityId) {
            let id = self.next_id("declare");
            let req = || CatalogRequest::DeclareInteraction {
                identity: identity.clone(),
                interaction: DeclaredInteraction::None,
                request_id: id.clone(),
            };
            let e = self.catalog(req()).unwrap_err();
            self.approve(e.next.decision_ref.as_deref().unwrap());
            self.catalog(req()).unwrap();
        }

        /// The environment every heimdall process gets.
        pub(super) fn env(&self) -> Vec<(OsString, OsString)> {
            let g = &self.home.git_home;
            vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), g.clone().into_os_string()),
                (
                    "HEIMDALL_HOME".into(),
                    self.home.root.clone().into_os_string(),
                ),
                ("HEIMDALL_TEST_SSH_HOME".into(), g.clone().into_os_string()),
                ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
                (
                    "GIT_CONFIG_GLOBAL".into(),
                    g.join(".gitconfig").into_os_string(),
                ),
                (
                    "SSH_AUTH_SOCK".into(),
                    self.home.decoy_agent().endpoint().locator(),
                ),
            ]
        }

        /// `heimdall <args>` with this world's environment and `extra`. A command that
        /// could start a runtime is refused while the service is stopped (module docs).
        pub(super) fn command(&self, args: &[OsString], extra: &[(&str, &OsStr)]) -> Command {
            let doctor_only = args.iter().any(|a| a == "doctor");
            assert!(
                self.serving() || doctor_only,
                "the in-process service is stopped: {args:?} could start a runtime on the account's files"
            );
            let mut cmd = Command::new(bin());
            cmd.args(args).env_clear().current_dir(&self.home.root);
            for (k, v) in self.env() {
                cmd.env(k, v);
            }
            for (k, v) in extra {
                cmd.env(k, v);
            }
            cmd.stdin(Stdio::null());
            cmd
        }

        pub(super) fn cli(&self, args: &[&str]) -> Out {
            Out::of(self.command(&os(args), &[]).output().unwrap())
        }

        pub(super) fn cli_with(&self, args: &[&str], extra: &[(&str, &OsStr)]) -> Out {
            Out::of(self.command(&os(args), extra).output().unwrap())
        }

        /// P's path.
        pub(super) fn p(&self) -> PathBuf {
            self.home.config_dir.join("ssh_config")
        }

        /// Every file under the scratch tree that setup may touch, with its bytes.
        pub(super) fn tree(&self) -> Vec<(PathBuf, Vec<u8>)> {
            let mut out = Vec::new();
            for dir in [
                &self.home.ssh_dir,
                &self.home.config_dir,
                &self.home.git_home,
            ] {
                walk(dir, &mut out);
            }
            out.sort();
            out
        }
    }

    fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(m) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if m.is_dir() {
                walk(&p, out);
            } else if m.is_file() {
                out.push((p.clone(), std::fs::read(&p).unwrap_or_default()));
            }
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            self.stop();
            if let Some(mut r) = self.real.take() {
                r.proxy.stop();
                r.agent.stop();
            }
        }
    }
}

/// The contract suite's JSON Schema validator (`tests/contracts/jsonschema_lite.rs`),
/// copied: no schema-validation crate is pinned, and suites are not `#[path]`-included.
#[allow(dead_code, clippy::all)]
mod jsonschema_lite {
    //! A small JSON Schema (draft 2020-12 subset) validator.
    //!
    //! No schema-validation crate is pinned in the workspace, so this covers exactly the
    //! keywords `schemars` emits for the public contract. An unsupported keyword is a
    //! test failure (never silently ignored), so a schema change that introduces new
    //! constraints cannot weaken the example checks unnoticed.

    use serde_json::Value;

    /// Keywords that carry no validation semantics.
    const ANNOTATIONS: &[&str] = &[
        "$schema",
        "$defs",
        "title",
        "description",
        "default",
        "format",
        "examples",
        "deprecated",
    ];

    /// Validate `instance` against `root` (the whole schema document).
    pub(crate) fn validate(root: &Value, instance: &Value) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        check(root, root, instance, "$", &mut errors);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn type_matches(name: &str, v: &Value) -> bool {
        match name {
            "null" => v.is_null(),
            "boolean" => v.is_boolean(),
            "string" => v.is_string(),
            "array" => v.is_array(),
            "object" => v.is_object(),
            "number" => v.is_number(),
            "integer" => v.is_i64() || v.is_u64(),
            _ => false,
        }
    }

    fn resolve<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
        let pointer = reference.strip_prefix('#')?;
        root.pointer(pointer)
    }

    fn check(root: &Value, schema: &Value, inst: &Value, path: &str, errors: &mut Vec<String>) {
        let obj = match schema {
            Value::Bool(true) => return,
            Value::Bool(false) => {
                errors.push(format!("{path}: schema `false` rejects everything"));
                return;
            }
            Value::Object(map) => map,
            other => {
                errors.push(format!("{path}: schema is not an object: {other}"));
                return;
            }
        };
        for (key, value) in obj {
            match key.as_str() {
                k if ANNOTATIONS.contains(&k) => {}
                "$ref" => match value.as_str().and_then(|r| resolve(root, r)) {
                    Some(target) => check(root, target, inst, path, errors),
                    None => errors.push(format!("{path}: unresolvable $ref {value}")),
                },
                "type" => {
                    let ok = match value {
                        Value::String(t) => type_matches(t, inst),
                        Value::Array(ts) => ts
                            .iter()
                            .any(|t| t.as_str().is_some_and(|t| type_matches(t, inst))),
                        _ => false,
                    };
                    if !ok {
                        errors.push(format!("{path}: expected type {value}, got {inst}"));
                    }
                }
                "const" => {
                    if inst != value {
                        errors.push(format!("{path}: expected const {value}, got {inst}"));
                    }
                }
                "enum" => {
                    let ok = value.as_array().is_some_and(|vs| vs.contains(inst));
                    if !ok {
                        errors.push(format!("{path}: {inst} not in enum"));
                    }
                }
                "minimum" | "maximum" => {
                    if let (Some(bound), Some(n)) = (value.as_f64(), inst.as_f64()) {
                        let bad = if key == "minimum" {
                            n < bound
                        } else {
                            n > bound
                        };
                        if bad {
                            errors.push(format!("{path}: {n} violates {key} {bound}"));
                        }
                    }
                }
                "properties" => {
                    if let (Some(props), Some(map)) = (value.as_object(), inst.as_object()) {
                        for (name, sub) in props {
                            if let Some(child) = map.get(name) {
                                check(root, sub, child, &format!("{path}.{name}"), errors);
                            }
                        }
                    }
                }
                "required" => {
                    if let (Some(names), Some(map)) = (value.as_array(), inst.as_object()) {
                        for name in names.iter().filter_map(Value::as_str) {
                            if !map.contains_key(name) {
                                errors.push(format!("{path}: missing required `{name}`"));
                            }
                        }
                    }
                }
                "additionalProperties" => {
                    // The public schemas tolerate unknown fields; a restriction here
                    // would contradict ADR-0006 section 9, so surface it.
                    errors.push(format!(
                        "{path}: additionalProperties {value} contradicts unknown-field tolerance"
                    ));
                }
                "items" => {
                    if let Some(items) = inst.as_array() {
                        let skip = obj
                            .get("prefixItems")
                            .and_then(Value::as_array)
                            .map_or(0, Vec::len);
                        for (i, item) in items.iter().enumerate().skip(skip) {
                            check(root, value, item, &format!("{path}[{i}]"), errors);
                        }
                    }
                }
                "prefixItems" => {
                    if let (Some(subs), Some(items)) = (value.as_array(), inst.as_array()) {
                        for (i, (sub, item)) in subs.iter().zip(items).enumerate() {
                            check(root, sub, item, &format!("{path}[{i}]"), errors);
                        }
                    }
                }
                "minItems" | "maxItems" => {
                    if let (Some(bound), Some(items)) = (value.as_u64(), inst.as_array()) {
                        let len = items.len() as u64;
                        let bad = if key == "minItems" {
                            len < bound
                        } else {
                            len > bound
                        };
                        if bad {
                            errors.push(format!("{path}: {len} items violates {key} {bound}"));
                        }
                    }
                }
                "uniqueItems" => {
                    if value == &Value::Bool(true)
                        && let Some(items) = inst.as_array()
                    {
                        for (i, a) in items.iter().enumerate() {
                            if items.iter().skip(i + 1).any(|b| a == b) {
                                errors.push(format!("{path}: duplicate items"));
                                break;
                            }
                        }
                    }
                }
                "anyOf" | "oneOf" | "allOf" => {
                    let subs = value.as_array().map_or(&[][..], Vec::as_slice);
                    let matching = subs
                        .iter()
                        .filter(|sub| {
                            let mut scratch = Vec::new();
                            check(root, sub, inst, path, &mut scratch);
                            scratch.is_empty()
                        })
                        .count();
                    let ok = match key.as_str() {
                        "anyOf" => matching >= 1,
                        "oneOf" => matching == 1,
                        _ => matching == subs.len(),
                    };
                    if !ok {
                        errors.push(format!(
                            "{path}: {key} matched {matching} of {} alternatives for {inst}",
                            subs.len()
                        ));
                    }
                }
                other => errors.push(format!("{path}: unsupported schema keyword `{other}`")),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use serde_json::json;

        use super::validate;

        #[test]
        fn accepts_and_rejects_basic_shapes() {
            let schema = json!({
                "type": "object",
                "properties": {
                    "n": {"type": "integer", "minimum": 0},
                    "k": {"oneOf": [{"type": "string", "const": "a"}, {"type": "string", "const": "b"}]},
                    "xs": {"type": "array", "items": {"$ref": "#/$defs/S"}},
                    "t": {"type": "array", "prefixItems": [{"type": "string"}, {"type": "string"}],
                           "minItems": 2, "maxItems": 2},
                    "o": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["n"],
                "$defs": {"S": {"type": "string"}}
            });
            let good =
                json!({"n": 1, "k": "a", "xs": ["x"], "t": ["a", "b"], "o": null, "extra": 1});
            assert!(validate(&schema, &good).is_ok());
            for bad in [
                json!({}),
                json!({"n": -1}),
                json!({"n": 1.5}),
                json!({"n": 1, "k": "c"}),
                json!({"n": 1, "xs": [1]}),
                json!({"n": 1, "t": ["a"]}),
                json!({"n": 1, "o": 3}),
            ] {
                assert!(validate(&schema, &bad).is_err(), "{bad}");
            }
        }

        #[test]
        fn one_of_requires_exactly_one_match() {
            let schema = json!({"oneOf": [{"type": "integer"}, {"type": "number"}]});
            assert!(validate(&schema, &json!(1)).is_err(), "matches both");
            assert!(validate(&schema, &json!(1.5)).is_ok());
        }

        #[test]
        fn unsupported_keywords_fail_loudly() {
            let schema = json!({"type": "string", "pattern": "^a$"});
            let errs = validate(&schema, &json!("a")).unwrap_err();
            assert!(errs[0].contains("unsupported schema keyword"));
        }

        #[test]
        fn unique_items_detects_duplicates() {
            let schema = json!({"type": "array", "uniqueItems": true});
            assert!(validate(&schema, &json!([1, 2])).is_ok());
            assert!(validate(&schema, &json!([1, 1])).is_err());
        }
    }
}

/// A pseudo-terminal for the owner-prompt cases: the CLI runs as the session leader of
/// a new session whose controlling terminal is the pty's slave (the test binary
/// re-executes itself in child mode, then execs heimdall), so its stdin is a TTY.
#[cfg(unix)]
mod terminal {
    use std::io::Read as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::process::CommandExt as _;
    use std::process::Child;
    use std::time::{Duration, Instant};

    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    use super::*;

    const SLAVE: &str = "HM_U9_PTY_SLAVE";
    const ARGS: &str = "HM_U9_PTY_ARGS";

    /// Child-mode entry of the pty cases; does nothing in a normal run.
    #[test]
    #[ignore = "child-mode entry of the pty tests, started by them"]
    fn pty_child() {
        let (Some(slave), Some(args)) = (std::env::var_os(SLAVE), std::env::var(ARGS).ok()) else {
            return;
        };
        rustix::process::setsid().unwrap();
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave)
            .unwrap();
        rustix::process::ioctl_tiocsctty(&tty).unwrap();
        rustix::stdio::dup2_stdin(&tty).unwrap();
        rustix::stdio::dup2_stdout(&tty).unwrap();
        rustix::stdio::dup2_stderr(&tty).unwrap();
        drop(tty);
        let args: Vec<String> = serde_json::from_str(&args).unwrap();
        let err = Command::new(bin()).args(args).exec();
        panic!("exec failed: {err}");
    }

    pub(crate) struct Pty {
        master: OwnedFd,
        slave: PathBuf,
        output: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Pty {
        pub(crate) fn open() -> Pty {
            let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
            grantpt(&master).unwrap();
            unlockpt(&master).unwrap();
            let name = ptsname(&master, Vec::new()).unwrap();
            let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let reader = master.try_clone().unwrap();
            let sink = std::sync::Arc::clone(&output);
            let done = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut f = std::fs::File::from(reader);
                let mut buf = [0u8; 4096];
                while !done.load(std::sync::atomic::Ordering::SeqCst) {
                    match f.read(&mut buf) {
                        Ok(n) if n > 0 => sink.lock().unwrap().extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        _ => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            });
            Pty {
                master,
                slave: PathBuf::from(std::ffi::OsStr::from_bytes(name.as_bytes())),
                output,
                stop,
            }
        }

        pub(crate) fn write(&self, bytes: &[u8]) {
            use std::io::Write as _;
            let mut f = std::fs::File::from(self.master.try_clone().unwrap());
            f.write_all(bytes).unwrap();
        }

        /// `heimdall <args>` on this terminal with exactly `env`, in `cwd`.
        pub(crate) fn start(
            &self,
            env: &[(OsString, OsString)],
            cwd: &Path,
            args: &[&str],
        ) -> Child {
            let json = serde_json::to_string(&args).unwrap();
            let mut cmd = Command::new(std::env::current_exe().unwrap());
            cmd.args([
                "--exact",
                "terminal::pty_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env_clear()
            .current_dir(cwd);
            for (k, v) in env {
                cmd.env(k, v);
            }
            cmd.env(SLAVE, &self.slave)
                .env(ARGS, &json)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        }

        pub(crate) fn transcript(&self) -> String {
            String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
        }
    }

    /// `heimdall <args>` on a fresh pty: whenever a confirmation prompt (`[y/N]`)
    /// appears, type `answer` (bytes) once; return the exit status and the transcript.
    pub(crate) fn answer(
        env: &[(OsString, OsString)],
        cwd: &Path,
        args: &[&str],
        answer: &[u8],
    ) -> (Option<i32>, String) {
        let pty = Pty::open();
        let mut child = pty.start(env, cwd, args);
        let deadline = Instant::now() + Duration::from_secs(90);
        let mut answered = 0;
        let code = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s.code();
            }
            if pty.transcript().matches("[y/N]").count() > answered {
                pty.write(answer);
                answered += 1;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the pty child did not exit in time: {}", pty.transcript());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        std::thread::sleep(Duration::from_millis(150));
        let t = pty.transcript();
        assert_no_canary(&t);
        (code, t)
    }

    /// The last JSON envelope in a pty transcript.
    pub(crate) fn envelope(transcript: &str) -> Value {
        transcript
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
            .unwrap_or_else(|| panic!("no envelope: {transcript}"))
    }
}

/// Cross-platform: a usage error exits 2 with one schema-valid `USAGE_ERROR` envelope,
/// before any runtime contact (the Heimdall home is never created).
#[test]
fn u9_usage_errors_exit_2_before_any_runtime_contact() {
    let scratch = tempfile::tempdir().unwrap();
    for (i, line) in [
        &["setup", "repair", "nonsense", "rerender"][..],
        &["setup", "repair", "--operation", "op_x", "later"],
        &["setup", "repair", "projection_held", "retry_held"],
        &["doctor", "--active-probe", "everything"],
        &["profile", "create", "p", "--pair", "no-colon"],
        &[
            "destination",
            "add",
            "lab",
            "--hostname",
            "h.example.invalid",
        ],
    ]
    .iter()
    .enumerate()
    {
        let home = scratch.path().join(format!("h{i}"));
        let mut cmd = Command::new(bin());
        cmd.arg("--json")
            .arg("--non-interactive")
            .args(*line)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HEIMDALL_HOME", &home)
            .env("HEIMDALL_TEST_SSH_HOME", scratch.path())
            .stdin(Stdio::null());
        let out = Out::of(cmd.output().unwrap());
        assert_eq!(out.code, Some(2), "{line:?}: {out:?}");
        let env = out.json();
        assert_eq!(env["code"], "USAGE_ERROR", "{line:?}");
        assert_envelope_valid(&env);
        assert!(
            !home.join("run").exists(),
            "{line:?} reached for the runtime"
        );
    }
}

#[cfg(unix)]
mod unix {
    use heimdall_contract::ids::IdentityId;
    use heimdall_localenv::projection::ReplacePoint;

    use super::world::World;
    use super::*;

    const ALPHA: &str = "alpha";
    const USER: &str = "Host other\n    HostName other.example.invalid\n    User fixture\n";

    /// Key 0 adopted at the fake agent for `alpha`, profile `work`, the user file
    /// [`USER`], and (with `project`) the projection applied in process.
    fn single(project: bool) -> (World, IdentityId) {
        let w = World::new(1);
        w.home.write_user_config(USER).unwrap();
        let id = w.adopt(0);
        w.managed(ALPHA, "alpha.example.invalid", None, "fixture", &id);
        w.profile(&[ALPHA], "fixture");
        if project {
            w.project();
        }
        (w, id)
    }

    fn user(w: &World) -> String {
        std::fs::read_to_string(&w.home.user_config).unwrap()
    }

    /// The operation of a refusal or result.
    fn op_of(env: &Value) -> String {
        env["operation_id"]
            .as_str()
            .or_else(|| env["next"]["operation_id"].as_str())
            .unwrap_or_else(|| panic!("no operation: {env}"))
            .to_owned()
    }

    /// `heimdall --json --non-interactive <args>`.
    fn ni(w: &World, args: &[&str]) -> Out {
        let mut all = vec!["--json", "--non-interactive"];
        all.extend_from_slice(args);
        w.cli(&all)
    }

    /// `heimdall --json <args>` on a terminal, the owner typing `yes` at every prompt
    /// (the ADR-0006 §3.1 flow); the exit status, the envelope and the transcript.
    fn owner(w: &World, args: &[&str]) -> (Option<i32>, Value, String) {
        let mut all = vec!["--json"];
        all.extend_from_slice(args);
        let (code, t) = terminal::answer(&w.env(), &w.home.root, &all, b"yes\n");
        let env = terminal::envelope(&t);
        assert_envelope_valid(&env);
        (code, env, t)
    }

    // ---- A22: conflicts and repairs ------------------------------------------------------

    /// The Heimdall block made conditional: a `Host` line inserted above it.
    fn make_conditional(w: &World) {
        let text = user(w);
        assert!(text.contains("heimdall managed include"), "{text}");
        w.home
            .write_user_config(&format!("Host zz-conditional\n    User fixture\n{text}"))
            .unwrap();
    }

    /// m02-plan U9 `a22_cli_setup_conflict_then_repair`: the include block is made
    /// conditional after setup; `setup apply` reports the conflict (exit 6, nothing
    /// written); the targeted repair `move_include_to_top` runs through the CLI (preview,
    /// plan digest, the owner's decision), and the projection is unconditional again.
    #[test]
    fn a22_cli_setup_conflict_then_repair() {
        let (w, _) = single(true);
        make_conditional(&w);
        let before = w.tree();
        let out = ni(&w, &["setup", "apply"]);
        assert_eq!(out.code, Some(6), "{out:?}");
        assert_eq!(out.code_str(), "CONFIG_CONFLICT", "{out:?}");
        assert_eq!(out.reason(), "include_conditional", "{out:?}");
        assert_envelope_valid(&out.json());
        let message = out.json()["data"]["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            message.contains("heimdall setup repair include_conditional move_include_to_top"),
            "{message}"
        );
        assert_eq!(w.tree(), before, "nothing written");
        // The targeted repairs, each previewed, shown, confirmed and digest-bound.
        let (code, _, t) = owner(
            &w,
            &[
                "setup",
                "repair",
                "include_conditional",
                "move_include_to_top",
            ],
        );
        assert_eq!(code, Some(0), "{t}");
        let (code, env, t) = owner(
            &w,
            &[
                "setup",
                "repair",
                "marker_duplicated",
                "remove_duplicate_markers",
            ],
        );
        assert_eq!(code, Some(0), "{t}");
        assert_eq!(env["data"]["repair_complete"], true, "{env}");
        assert!(
            user(&w).starts_with("# >>> heimdall managed include"),
            "{}",
            user(&w)
        );
        let out = ni(&w, &["setup", "apply"]);
        assert_eq!(out.code, Some(0), "no conflict left: {out:?}");
        // P edited by the owner: never overwritten. Apply and a re-render are refused
        // (never a no-op reported as success), naming what to do; nothing is written.
        std::fs::write(w.p(), "# edited by the owner\nHost alpha\n").unwrap();
        let before = w.tree();
        let out = ni(&w, &["setup", "apply"]);
        assert_eq!(out.code, Some(6), "{out:?}");
        assert_eq!(out.reason(), "managed_file_edited", "{out:?}");
        assert!(out.stdout.contains("heimdall setup rollback"), "{out:?}");
        let out = ni(&w, &["setup", "repair", "managed_file_edited", "rerender"]);
        assert_eq!(out.code, Some(6), "{out:?}");
        assert_eq!(w.tree(), before, "nothing written");
    }

    /// ADR-0007 §12.19 item 7: `move_include_to_top` leaves the old block, so doctor
    /// reports `marker_duplicated`: the CLI says the repair is not complete and names
    /// the next operation; after `remove_duplicate_markers` doctor reports none left and
    /// the CLI says so.
    #[test]
    fn multi_operation_repair_is_complete_only_when_doctor_reports_none_left() {
        let (w, _) = single(true);
        make_conditional(&w);
        let (code, env, t) = owner(
            &w,
            &[
                "setup",
                "repair",
                "include_conditional",
                "move_include_to_top",
            ],
        );
        assert_eq!(code, Some(0), "{t}");
        assert_eq!(env["data"]["repair_complete"], false, "{env}");
        assert_eq!(
            env["data"]["next_repair"],
            "heimdall setup repair marker_duplicated remove_duplicate_markers"
        );
        assert!(
            env["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w["code"] == "repair_incomplete")
        );
        assert_eq!(
            user(&w).matches("# >>> heimdall managed include").count(),
            2
        );
        let (code, env, t) = owner(
            &w,
            &[
                "setup",
                "repair",
                "marker_duplicated",
                "remove_duplicate_markers",
            ],
        );
        assert_eq!(code, Some(0), "{t}");
        assert_eq!(env["data"]["repair_complete"], true, "{env}");
        assert!(env["data"].get("next_repair").is_none());
        assert_eq!(
            user(&w).matches("# >>> heimdall managed include").count(),
            1
        );
        assert!(
            user(&w).starts_with("# >>> heimdall managed include"),
            "{}",
            user(&w)
        );
        let doctor = ni(&w, &["doctor", "--no-local-exec"]);
        assert!(
            doctor.json()["data"]["projection"]["conflict"].is_null(),
            "{doctor:?}"
        );
    }

    // ---- held operations -----------------------------------------------------------------

    /// A first adoption held for the owner: after the user file's exchange (the commit
    /// point) and before the transaction check, P is rewritten in place (C7a,
    /// `active_entry_modified`). Returns the held operation.
    fn held() -> (World, String) {
        let (w, _) = single(false);
        let p = w.p();
        let user_config = w.home.user_config.clone();
        w.hook
            .arm(ReplacePoint::BeforeReceipt("post_validated"), move || {
                let committed = std::fs::read_to_string(&user_config)
                    .is_ok_and(|t| t.contains("heimdall managed include"));
                if committed {
                    use std::io::Write as _;
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(&p)
                        .unwrap();
                    f.write_all(b"# edited by another writer\nHost edited\n")
                        .unwrap();
                    f.sync_all().unwrap();
                }
                committed
            });
        let (code, env, t) = owner(&w, &["setup", "apply"]);
        assert_eq!(code, Some(7), "{t}");
        assert_eq!(env["code"], "OUTCOME_UNKNOWN", "{env}");
        assert_eq!(env["data"]["error"]["reason"], "projection_held", "{env}");
        let op = op_of(&env);
        let message = env["data"]["error"]["message"].as_str().unwrap();
        assert!(
            message.contains(&format!("heimdall setup repair --operation {op} retry")),
            "{message}"
        );
        assert!(
            message.contains(&format!("heimdall setup repair --operation {op} keep")),
            "{message}"
        );
        (w, op)
    }

    /// m02-plan U9 `a22_cli_held_operation_status_retry_and_keep`, with the uninstall
    /// leg of `held_operation_blocks_setup_except_its_repair` (ADR-0007 §12.22 item 10):
    /// * `setup status` shows the held operation with each held step's role, path and
    ///   reason, what each observed name holds, and both commands; its `--json`
    ///   validates against the envelope schema;
    /// * `setup apply` and `uninstall` print `setup_in_progress` naming it and both
    ///   commands; uninstall stops nothing;
    /// * `retry` is admitted (P still edited: it stays held);
    /// * `keep` without a typed `yes` exits 3 and changes nothing; with `yes` (pty) it
    ///   closes the operation and the scratch tree is unchanged.
    #[test]
    fn a22_cli_held_operation_status_retry_and_keep() {
        let (w, op) = held();
        let status = ni(&w, &["setup", "status"]);
        assert_eq!(status.code, Some(0), "{status:?}");
        let env = status.json();
        assert_envelope_valid(&env);
        let held = &env["data"]["held_operations"];
        assert_eq!(held.as_array().unwrap().len(), 1, "{env}");
        assert_eq!(held[0]["operation_id"], op.as_str());
        let steps = held[0]["steps"].as_array().unwrap();
        assert!(!steps.is_empty(), "{env}");
        assert!(
            steps.iter().any(|s| s["reason"] == "active_entry_modified"
                && s["role"] == "managed_ssh"
                && s["path"].as_str().unwrap().contains("content changed")),
            "{env}"
        );
        let commands: Vec<&str> = held[0]["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["command"].as_str().unwrap())
            .collect();
        assert_eq!(
            commands,
            [
                format!("heimdall setup repair --operation {op} retry"),
                format!("heimdall setup repair --operation {op} keep")
            ]
        );
        // Human status: the same, as text.
        let human = w.cli(&["--non-interactive", "setup", "status"]);
        assert!(
            human.stdout.contains(&format!("Held operation {op}")),
            "{human:?}"
        );
        assert!(human.stdout.contains("keep"), "{human:?}");

        // Every other setup command is refused naming it and both repairs.
        for args in [&["setup", "apply"][..], &["uninstall"]] {
            let out = ni(&w, args);
            assert_eq!(out.code, Some(6), "{args:?}: {out:?}");
            assert_eq!(out.reason(), "setup_in_progress", "{args:?}");
            let env = out.json();
            assert_envelope_valid(&env);
            let message = env["data"]["error"]["message"].as_str().unwrap();
            assert!(message.contains(&op), "{message}");
            assert!(
                message.contains("retry") && message.contains("keep"),
                "{message}"
            );
        }
        assert!(w.serving(), "a refused uninstall stops nothing");

        // `retry` is admitted: P is still edited, so it stays held.
        let retry = ni(&w, &["setup", "repair", "--operation", &op, "retry"]);
        assert_eq!(retry.code, Some(6), "{retry:?}");
        assert_eq!(retry.reason(), "projection_held");
        assert!(
            retry.json()["operation_id"].is_string(),
            "admitted: {retry:?}"
        );
        assert_envelope_valid(&retry.json());

        // `keep` without a typed yes: exit 3, nothing changed, still held.
        let tree = w.tree();
        let keep = ni(&w, &["setup", "repair", "--operation", &op, "keep"]);
        assert_eq!(keep.code, Some(3), "{keep:?}");
        assert_eq!(keep.code_str(), "INTERACTION_REQUIRED");
        assert_envelope_valid(&keep.json());
        assert_eq!(w.tree(), tree);
        let still = ni(&w, &["setup", "status"]);
        assert_eq!(
            still.json()["data"]["held_operations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        // `keep` with a typed yes on a terminal closes it; nothing moves.
        let (code, transcript) = terminal::answer(
            &w.env(),
            &w.home.root,
            &["setup", "repair", "--operation", &op, "keep"],
            b"yes\n",
        );
        assert_eq!(code, Some(0), "{transcript}");
        assert!(transcript.contains("nothing is moved"), "{transcript}");
        assert_eq!(w.tree(), tree, "nothing moved");
        let after = ni(&w, &["setup", "status"]);
        assert!(
            after.json()["data"]["held_operations"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    // ---- the confirmation contract on a terminal ----------------------------------------

    /// m02-plan U9 "pty confirmation cases (EOF, `n`, non-TTY, `yes` exactly once)" for
    /// `setup apply` (a first adoption always needs a decision): `n` and end of input exit
    /// 3 with the decision still pending and nothing written; a non-TTY stdin exits 3
    /// without prompting; `yes` applies exactly once.
    #[test]
    fn pty_setup_apply_confirmation_eof_no_non_tty_yes_exactly_once() {
        let (w, _) = single(false);
        let before = user(&w);
        for (answer, name) in [(&b"n\n"[..], "no"), (&b"\x04"[..], "eof")] {
            let (code, t) = terminal::answer(
                &w.env(),
                &w.home.root,
                &["setup", "apply", "--request-id", &format!("r-pty-{name}")],
                answer,
            );
            assert_eq!(code, Some(3), "{name}: {t}");
            assert!(
                t.contains("Restore column"),
                "{name}: the plan with its restore column: {t}"
            );
            assert!(t.contains("not confirmed"), "{name}: {t}");
            assert_eq!(user(&w), before, "{name}: nothing written");
            // The pending apply blocks other setups until it is decided or expires;
            // deny it in process so the next case starts clean.
            let pending = ni(&w, &["decision", "list"]);
            for d in pending.json()["data"]["decisions"].as_array().unwrap() {
                let id = d["decision_id"].as_str().unwrap();
                deny(&w, id);
            }
        }
        // Non-TTY without --non-interactive: no prompt, exit 3 with the reference.
        let out = w.cli(&["--json", "setup", "apply", "--request-id", "r-pipe"]);
        assert_eq!(out.code, Some(3), "{out:?}");
        assert!(out.json()["next"]["decision_ref"].is_string());
        assert!(!out.stderr.contains("[y/N]"));
        let pending = ni(&w, &["decision", "list"]);
        for d in pending.json()["data"]["decisions"].as_array().unwrap() {
            deny(&w, d["decision_id"].as_str().unwrap());
        }
        // yes: applied exactly once.
        let (code, t) = terminal::answer(
            &w.env(),
            &w.home.root,
            &["setup", "apply", "--request-id", "r-pty-yes"],
            b"yes\n",
        );
        assert_eq!(code, Some(0), "{t}");
        assert_eq!(
            user(&w).matches("# >>> heimdall managed include").count(),
            1
        );
        assert!(w.p().exists());
        // The same request ID again never applies a second time: the CLI previews
        // afresh, so the runtime refuses the reuse (REQUEST_CONFLICT) and writes nothing.
        let tree = w.tree();
        let again = ni(&w, &["setup", "apply", "--request-id", "r-pty-yes"]);
        assert_eq!(again.code, Some(6), "{again:?}");
        assert_eq!(again.code_str(), "REQUEST_CONFLICT");
        // ADR-0007 §12.30 item 12: that is correct, and the CLI says why.
        let message = again.json()["data"]["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(
            message.contains("request ID r-pty-yes was already used for an earlier setup plan")
                && message.contains("new request ID"),
            "{message}"
        );
        assert_envelope_valid(&again.json());
        assert_eq!(w.tree(), tree);
        assert_eq!(
            user(&w).matches("# >>> heimdall managed include").count(),
            1
        );
    }

    /// ADR-0007 §5.1, §5.5 and §12.30 item 7 through the CLI: the first adoption's
    /// preview shows each alias with its restore column; `setup apply` copies the
    /// original user file, before its first edit, to
    /// `<state>/backups/ssh_config.<UTC timestamp>.orig` (0600, the original bytes) and
    /// `setup status` lists it; a later rollback (which edits the file again) adds no
    /// snapshot and leaves the first one as it was.
    #[test]
    fn setup_apply_snapshots_the_original_and_previews_the_restore_column() {
        use std::os::unix::fs::PermissionsExt as _;
        let (w, _) = single(false);
        let original = std::fs::read(&w.home.user_config).unwrap();
        let preview = ni(&w, &["setup", "preview"]);
        assert_eq!(preview.code, Some(0), "{preview:?}");
        let aliases = preview.json()["data"]["aliases"].clone();
        let alpha = aliases
            .as_array()
            .and_then(|a| a.iter().find(|a| a["alias"] == ALPHA))
            .unwrap_or_else(|| panic!("the plan lists alpha: {aliases}"));
        assert_eq!(alpha["kind"], "managed", "{alpha}");
        assert_eq!(
            alpha["restore"]["digest"].as_str().map(str::len),
            Some(64),
            "{alpha}"
        );
        let human = w.cli(&["--non-interactive", "setup", "preview"]);
        assert!(
            human.stdout.contains("Alias alpha (managed)")
                && human.stdout.contains("restore: digest"),
            "{human:?}"
        );
        let backups = w.home.state_dir.join("backups");
        assert!(!backups.exists(), "a preview takes no snapshot");
        let (code, _, t) = owner(&w, &["setup", "apply"]);
        assert_eq!(code, Some(0), "{t}");
        let snapshots = || -> Vec<PathBuf> {
            let mut v: Vec<PathBuf> = std::fs::read_dir(&backups)
                .map(|rd| rd.filter_map(Result::ok).map(|e| e.path()).collect())
                .unwrap_or_default();
            v.sort();
            v
        };
        let taken = snapshots();
        assert_eq!(taken.len(), 1, "{taken:?}");
        let name = taken[0].file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("ssh_config.") && name.ends_with("Z.orig") && name.len() == 32,
            "{name}"
        );
        assert_eq!(
            std::fs::read(&taken[0]).unwrap(),
            original,
            "the original bytes"
        );
        assert_eq!(
            std::fs::metadata(&taken[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_ne!(
            std::fs::read(&w.home.user_config).unwrap(),
            original,
            "the apply edited the user file after the copy"
        );
        let status = ni(&w, &["setup", "status"]);
        let listed = status.json()["data"]["backups"].clone();
        assert_eq!(listed.as_array().map(Vec::len), Some(1), "{listed}");
        assert!(listed[0].as_str().unwrap().ends_with(&name), "{listed}");
        let (code, _, t) = owner(&w, &["setup", "rollback"]);
        assert_eq!(code, Some(0), "{t}");
        assert_eq!(snapshots(), taken, "no second snapshot");
        assert_eq!(std::fs::read(&taken[0]).unwrap(), original);
    }

    /// ADR-0007 §12.30 item 12: with an agent that lists several identities,
    /// `identity adopt --from-agent` (the explicit agent probe) is a usage error naming
    /// their fingerprints and `--fingerprint`; `--fingerprint <fp>` adopts exactly that
    /// listed identity; an unlisted fingerprint is `NOT_FOUND` and adopts nothing.
    #[test]
    fn identity_adopt_from_agent_fingerprint_chooses_one_listed_identity() {
        let w = World::new(2);
        let agent = w.agent.endpoint().locator();
        let at_agent: [(&str, &OsStr); 1] = [("SSH_AUTH_SOCK", agent.as_os_str())];
        let base = [
            "--json",
            "--non-interactive",
            "identity",
            "adopt",
            "--from-agent",
            "--active-probe",
            "agent",
        ];
        let adopted = |w: &World| {
            w.cli(&["--json", "--non-interactive", "identity", "list"])
                .json()["data"]["identities"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        };
        let several = w.cli_with(&base, &at_agent);
        assert_eq!(several.code, Some(2), "{several:?}");
        let message = several.json()["data"]["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        for k in &w.keys {
            assert!(message.contains(&k.fingerprint()), "{message}");
        }
        assert!(message.contains("--fingerprint"), "{message}");
        assert!(adopted(&w).is_empty());
        let unlisted = heimdall_testkit::agent::FixtureKey::generate().fingerprint();
        let mut line = base.to_vec();
        line.extend(["--fingerprint", unlisted.as_str()]);
        let missing = w.cli_with(&line, &at_agent);
        assert_eq!(missing.code_str(), "NOT_FOUND", "{missing:?}");
        assert!(adopted(&w).is_empty(), "nothing adopted");
        let wanted = w.keys[1].fingerprint();
        let mut line = base.to_vec();
        line.extend(["--fingerprint", wanted.as_str()]);
        let chosen = w.cli_with(&line, &at_agent);
        assert_eq!(chosen.code, Some(0), "{chosen:?}");
        let list = adopted(&w);
        assert_eq!(list.len(), 1, "{list:?}");
        assert_eq!(list[0]["fingerprint"], wanted, "{list:?}");
        assert_eq!(
            list[0]["identity_id"],
            chosen.json()["data"]["identity_id"],
            "{chosen:?}"
        );
    }

    fn deny(w: &World, decision: &str) {
        let (code, t) = terminal::answer(
            &w.env(),
            &w.home.root,
            &["decision", "deny", decision],
            b"yes\n",
        );
        assert_eq!(code, Some(0), "{t}");
    }

    // ---- A11: non-interactive exit codes ---------------------------------------------------

    /// m02-plan U9 `a11_noninteractive_errors_exit_codes`: apply gives 3,
    /// `--require-unattended` gives 4, an absent provider endpoint gives 5, a conflict
    /// gives 6, `LAUNCH_FAILED` gives 127, a usage error gives 2; each envelope is
    /// schema-valid.
    #[test]
    fn a11_noninteractive_errors_exit_codes() {
        let (w, id) = single(true);
        w.declare(&id);
        // 4: the native agent's lock continuity is unknown, which never satisfies it.
        let out = ni(
            &w,
            &[
                "run",
                "--profile",
                "work",
                "--require-unattended",
                "--",
                "/usr/bin/true",
            ],
        );
        assert_eq!(out.code, Some(4), "{out:?}");
        // 127: the program cannot be found.
        let out = ni(
            &w,
            &["run", "--profile", "work", "--", "/nonexistent/hm-program"],
        );
        assert_eq!(out.code, Some(127), "{out:?}");
        // 5: an identity adopted at an endpoint that is absent.
        let gone = w.home.root.join("gone.sock");
        let data = w
            .catalog(heimdall_contract::catalog::CatalogRequest::AdoptIdentity {
                identity: heimdall_contract::catalog::IdentitySpec {
                    source: heimdall_contract::catalog::IdentitySourceSpec::NativeAgent {
                        endpoint: heimdall_contract::provider::EndpointRef {
                            kind: heimdall_contract::provider::EndpointKind::UnixSocket,
                            locator: gone.display().to_string(),
                        },
                    },
                    public_key: heimdall_testkit::agent::FixtureKey::generate_many(1)[0]
                        .public_line_without_comment(),
                    label: None,
                },
                request_id: w.next_id("adopt-gone"),
            })
            .unwrap();
        let gone_id = IdentityId::parse(data["identity_id"].as_str().unwrap()).unwrap();
        w.managed("beta", "beta.example.invalid", None, "fixture", &gone_id);
        w.profile_as("gone", "pol-gone", &["beta"], "fixture");
        w.project();
        let out = ni(
            &w,
            &[
                "access",
                "ensure",
                "--profile",
                "gone",
                "--work-id",
                "w5",
                "--request-id",
                "r5",
            ],
        );
        assert_eq!(out.code, Some(5), "{out:?}");
        assert_envelope_valid(&out.json());
        // 3: an apply that needs a decision (a changed managed alias).
        w.managed("beta", "beta2.example.invalid", None, "fixture", &id);
        let out = ni(&w, &["setup", "apply", "--request-id", "r-a3"]);
        assert_eq!(out.code, Some(3), "{out:?}");
        assert_eq!(out.code_str(), "INTERACTION_REQUIRED");
        assert!(out.json()["next"]["decision_ref"].is_string());
        assert_envelope_valid(&out.json());
        // 6: a second setup while that one waits.
        let out = ni(&w, &["setup", "rollback"]);
        assert_eq!(out.code, Some(6), "{out:?}");
        assert_eq!(out.reason(), "setup_in_progress");
        assert_envelope_valid(&out.json());
        // 2: a usage error.
        let out = ni(&w, &["setup", "repair", "nonsense", "rerender"]);
        assert_eq!(out.code, Some(2), "{out:?}");
        assert_envelope_valid(&out.json());
    }

    // ---- A21: doctor -----------------------------------------------------------------------

    /// m02-plan U9 `a21_cli_doctor_json_validates_against_schema`, with ADR-0007 §12.17
    /// item 10 (the CLI fills `LocalContext` from the catalog, read-only) and §12.25
    /// item 2's doctor wiring (`Match localuser` from the account database, never `USER`).
    #[test]
    fn a21_cli_doctor_json_validates_against_schema() {
        let (w, _) = single(true);
        let text = format!(
            "{}Match localuser hm-not-this-account-u9\n    HostName wrong.example.invalid\nHost plain\n    HostName right.example.invalid\n",
            user(&w)
        );
        w.home.write_user_config(&text).unwrap();
        let out = w.cli_with(
            &["--json", "--non-interactive", "doctor", "--no-local-exec"],
            &[
                ("USER", OsStr::new("hm-not-this-account-u9")),
                ("LOGNAME", OsStr::new("hm-not-this-account-u9")),
            ],
        );
        assert_eq!(out.code, Some(0), "{out:?}");
        let env = out.json();
        assert_envelope_valid(&env);
        assert_valid("doctor-report", &env["data"]);
        let aliases = env["data"]["aliases"].as_array().unwrap();
        let alpha = aliases.iter().find(|a| a["alias"] == ALPHA).expect("alpha");
        assert_eq!(
            alpha["definition"], "managed",
            "the catalog filled LocalContext"
        );
        assert_eq!(
            alpha["identity_selection"]["selection"], "exclusive",
            "{alpha}"
        );
        let plain = aliases
            .iter()
            .find(|a| a["alias"] == "plain")
            .expect("plain");
        let hostname = plain["behavior"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["directive"] == "HostName")
            .unwrap();
        assert_eq!(
            hostname["values"],
            serde_json::json!(["right.example.invalid"]),
            "{plain}"
        );
        assert!(!w.home.root.join("run/instance.json").exists() || w.serving());
        // --redact: still schema-valid, no host name.
        let red = ni(&w, &["doctor", "--no-local-exec", "--redact"]);
        assert_valid("doctor-report", &red.json()["data"]);
        assert!(!red.stdout.contains("alpha.example.invalid"), "{red:?}");
    }

    /// The scratch configuration of the `--allow-config-commands` cases: alias `lab`,
    /// and, with `exec`, a `Match exec` that touches `marker` when ssh evaluates it.
    fn lab(w: &World, marker: Option<&Path>) -> u32 {
        let mut text = String::from("Host lab\n    HostName 127.0.0.1\n    Port 9\n");
        let mut line = 0;
        if let Some(m) = marker {
            text.push_str(&format!(
                "Match exec \"/usr/bin/touch {}\"\n    User fixture\n",
                m.display()
            ));
            line = 4;
        }
        w.home.write_user_config(&text).unwrap();
        line
    }

    /// m02-plan U9 `a21_cli_allow_config_commands_prompt_text_and_typed_yes`: on a pty
    /// the prompt says "runs your configuration's commands with whatever effects they
    /// have" and lists the `Match exec` line; `n` exits 3 and nothing ran; `yes` runs the
    /// level (the command ran). Under `--non-interactive` the flag is the authorization
    /// and the record says so; without the flag the level is declined and nothing runs.
    #[test]
    fn a21_cli_allow_config_commands_prompt_text_and_typed_yes() {
        let w = World::new(1);
        let marker = w.home.root.join("match-exec-ran");
        let line = lab(&w, Some(&marker));
        let args = [
            "doctor",
            "--no-local-exec",
            "--active-probe",
            "evaluate",
            "--allow-config-commands",
            "--alias",
            "lab",
        ];
        let (code, t) = terminal::answer(&w.env(), &w.home.root, &args, b"n\n");
        assert_eq!(code, Some(3), "{t}");
        assert!(
            t.contains("runs your configuration's commands with whatever effects they have"),
            "{t}"
        );
        assert!(t.contains(&format!("~/.ssh/config:{line}")), "{t}");
        assert!(!marker.exists(), "nothing ran");
        let (code, t) = terminal::answer(&w.env(), &w.home.root, &args, b"yes\n");
        assert_eq!(code, Some(0), "{t}");
        assert!(
            marker.exists(),
            "the authorized level ran the configuration"
        );
        std::fs::remove_file(&marker).unwrap();
        // --non-interactive: the flag is the authorization, recorded.
        let mut all = vec!["--json", "--non-interactive"];
        all.extend_from_slice(&args);
        let out = w.cli(&all);
        assert_eq!(out.code, Some(0), "{out:?}");
        let probes = out.json()["data"]["probes"].clone();
        let eval = probes
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["level"] == "evaluate")
            .unwrap()
            .clone();
        assert_eq!(
            eval["authorization"],
            serde_json::json!(["allow_config_commands"]),
            "{eval}"
        );
        assert!(marker.exists());
        std::fs::remove_file(&marker).unwrap();
        // Without the flag: declined, nothing ran.
        let out = ni(
            &w,
            &[
                "doctor",
                "--no-local-exec",
                "--active-probe",
                "evaluate",
                "--alias",
                "lab",
            ],
        );
        assert_eq!(out.code, Some(0));
        let eval = out.json()["data"]["probes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["level"] == "evaluate")
            .unwrap()
            .clone();
        assert_eq!(eval["decline_reason"], "config_commands_not_authorized");
        assert!(!marker.exists());
    }

    /// m02-plan U9 `a21_cli_inert_config_still_prompts_for_allow_config_commands`: with
    /// no executing construct the prompt still appears and says "none found now; the
    /// configuration can change before ssh reads it".
    #[test]
    fn a21_cli_inert_config_still_prompts_for_allow_config_commands() {
        let w = World::new(1);
        lab(&w, None);
        for level in ["evaluate", "host_verification", "authentication"] {
            let (code, t) = terminal::answer(
                &w.env(),
                &w.home.root,
                &[
                    "doctor",
                    "--no-local-exec",
                    "--active-probe",
                    level,
                    "--allow-config-commands",
                    "--alias",
                    "lab",
                ],
                b"\n",
            );
            assert_eq!(code, Some(3), "{level}: {t}");
            assert!(
                t.contains("none found now; the configuration can change before ssh reads it"),
                "{level}: {t}"
            );
        }
    }

    /// ADR-0007 §12.31 item 2 (Q02), the reviewer's reproduction through the real binary
    /// on a pty: alias `lab`'s tree has an `Include` the static pass cannot expand (an
    /// unset variable), so the authorization step offers nothing and shows no prompt;
    /// a disposable `ssh` first on `PATH` rewrites the configuration into a readable,
    /// inert one when the doctor's own run queries `ssh -V`, and creates a marker when
    /// anything else runs it (the `evaluate` level's `ssh -G`). The skipped authorization
    /// authorizes nothing: exit 0, no prompt, no marker, and the `evaluate` probe is
    /// declined with the step's reason although the tree is readable by then.
    #[test]
    fn q02_cli_skipped_authorization_runs_no_evaluation_after_the_tree_becomes_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        let w = World::new(1);
        let inert = "Host lab\n    HostName 127.0.0.1\n    Port 9\n";
        w.home
            .write_user_config(&format!(
                "Include ${{HM_FIXTURE_UNSET_VARIABLE}}/x.conf\n{inert}"
            ))
            .unwrap();
        let bin = w.home.root.join("q02-bin");
        std::fs::create_dir_all(&bin).unwrap();
        let marker = w.home.root.join("q02-evaluation-ran");
        let stub = bin.join("ssh");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then\n  printf '{}' > '{}'\n  echo 'OpenSSH_9.9p1, LibreSSL 3.3.6' >&2\n  exit 0\nfi\n: > '{}'\nexit 0\n",
                inert.replace('\n', "\\n"),
                w.home.user_config.display(),
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut env = w.env();
        for (k, v) in &mut env {
            if k == "PATH" {
                *v = format!("{}:/usr/bin:/bin", bin.display()).into();
            }
        }
        let (code, t) = terminal::answer(
            &env,
            &w.home.root,
            &[
                "doctor",
                "--alias",
                "lab",
                "--active-probe",
                "evaluate",
                "--allow-config-commands",
            ],
            b"n\n",
        );
        assert_eq!(
            std::fs::read_to_string(&w.home.user_config).unwrap(),
            inert,
            "the interleaving happened: {t}"
        );
        assert_eq!(code, Some(0), "{t}");
        assert!(!t.contains("[y/N]"), "no prompt was shown: {t}");
        assert!(!marker.exists(), "no evaluation ran: {t}");
        assert!(
            t.contains("Probe evaluate lab: declined (config_not_fully_readable)"),
            "{t}"
        );
        assert!(!t.contains("authorized by"), "{t}");
    }

    /// m02-plan U9 `a21_cli_inventory_wording_never_claims_completeness`: the
    /// configuration changes its own tree while ssh runs it (a `Match exec` adds a new
    /// member of an `Include` glob). The human and `--json` outputs carry "found before
    /// the run", the record lists the difference, and no output calls the list complete.
    #[test]
    fn a21_cli_inventory_wording_never_claims_completeness() {
        let w = World::new(1);
        let confd = w.home.ssh_dir.join("conf.d");
        std::fs::create_dir_all(&confd).unwrap();
        let added = confd.join("added.conf");
        w.home
            .write_user_config(&format!(
                "Include {}/*.conf\nHost lab\n    HostName 127.0.0.1\nMatch exec \"/usr/bin/touch {}\"\n    User fixture\n",
                confd.display(),
                added.display()
            ))
            .unwrap();
        let args = [
            "doctor",
            "--no-local-exec",
            "--active-probe",
            "evaluate",
            "--allow-config-commands",
            "--alias",
            "lab",
        ];
        let mut all = vec!["--json", "--non-interactive"];
        all.extend_from_slice(&args);
        let json = w.cli(&all);
        assert_eq!(json.code, Some(0), "{json:?}");
        let env = json.json();
        assert!(
            env["warnings"].as_array().unwrap().iter().any(|x| x["message"]
                == "configuration commands found before the run; the run may have executed others"),
            "{env}"
        );
        let eval = env["data"]["probes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["level"] == "evaluate")
            .unwrap()
            .clone();
        assert_eq!(eval["config_tree_changed"], true, "{eval}");
        assert!(
            !eval["executed_config_commands"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        std::fs::remove_file(&added).unwrap();
        let mut human_args = vec!["--non-interactive"];
        human_args.extend_from_slice(&args);
        let human = w.cli(&human_args);
        assert_eq!(human.code, Some(0), "{human:?}");
        assert!(
            human
                .stdout
                .contains("found before the run; the run may have executed others"),
            "{human:?}"
        );
        assert!(human.stdout.contains("added"), "{human:?}");
        for text in [&json.stdout, &human.stdout, &human.stderr] {
            assert!(!text.to_ascii_lowercase().contains("complete"), "{text}");
        }
    }

    /// m02-plan U9 `a11_cli_listing_lapse_recorded_only_when_runtime_running`: the
    /// adopted, declared key is not in the agent. With the runtime stopped, `doctor
    /// --active-probe agent` reports the lapse `recorded: false` with the command and
    /// starts nothing; with it running, the lapse is recorded and a later `run
    /// --non-interactive` is refused.
    #[test]
    fn a11_cli_listing_lapse_recorded_only_when_runtime_running() {
        let mut w = World::new(1);
        w.home.write_user_config(USER).unwrap();
        // A key the agent does not hold, adopted at the agent and declared.
        let absent = heimdall_testkit::agent::FixtureKey::generate_many(1).remove(0);
        let data = w
            .catalog(heimdall_contract::catalog::CatalogRequest::AdoptIdentity {
                identity: heimdall_contract::catalog::IdentitySpec {
                    source: heimdall_contract::catalog::IdentitySourceSpec::NativeAgent {
                        endpoint: w.endpoint(),
                    },
                    public_key: absent.public_line_without_comment(),
                    label: None,
                },
                request_id: w.next_id("adopt"),
            })
            .unwrap();
        let id = IdentityId::parse(data["identity_id"].as_str().unwrap()).unwrap();
        w.managed(ALPHA, "alpha.example.invalid", None, "fixture", &id);
        w.profile(&[ALPHA], "fixture");
        w.project();
        w.declare(&id);
        w.stop();
        let args = [
            "--json",
            "--non-interactive",
            "doctor",
            "--no-local-exec",
            "--active-probe",
            "agent",
        ];
        let out = w.cli(&args);
        assert_eq!(out.code, Some(0), "{out:?}");
        let lapse = out.json()["data"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["code"] == "interaction_declaration_lapsed")
            .cloned()
            .unwrap_or_else(|| panic!("{out:?}"));
        assert_eq!(lapse["reason"], "not_recorded");
        let message = lapse["message"].as_str().unwrap();
        assert!(message.contains("recorded: false"), "{message}");
        assert!(
            message.contains(&format!("heimdall identity withdraw-declaration {id}")),
            "{message}"
        );
        assert!(
            !w.home.root.join("run/instance.json").exists(),
            "doctor started nothing"
        );
        w.start();
        let out = w.cli(&args);
        let lapse = out.json()["data"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["code"] == "interaction_declaration_lapsed")
            .cloned()
            .unwrap();
        assert_eq!(lapse["reason"], "recorded", "{out:?}");
        let run = ni(&w, &["run", "--profile", "work", "--", "/usr/bin/true"]);
        assert_eq!(run.code, Some(3), "{run:?}");
    }

    /// The catalog commands through the CLI (m02-plan U9): `profile create|add|remove|
    /// show|list`, `destination show|remove`, `identity list`; and `identity
    /// declare-interaction` follows the confirmation contract (ADR-0007 §7; ADR-0006
    /// §3.1): unattended it exits 3 with `next.decision_ref` and declares nothing; on a
    /// terminal it shows the decision text and a typed `yes` declares; `identity
    /// withdraw-declaration` then withdraws without a decision.
    #[test]
    fn catalog_commands_round_trip_and_declare_interaction_follows_the_confirmation_contract() {
        let (w, id) = single(false);
        let id = id.to_string();
        let out = ni(
            &w,
            &["profile", "create", "extra", "--pair", "dst-alpha:fixture"],
        );
        assert_eq!(out.code, Some(0), "{out:?}");
        let out = ni(
            &w,
            &["profile", "add", "extra", "--pair", "dst-alpha:other"],
        );
        assert_eq!(out.code, Some(0), "{out:?}");
        let shown = ni(&w, &["profile", "show", "extra"]);
        assert_eq!(shown.code, Some(0), "{shown:?}");
        assert!(shown.stdout.contains("other"), "{shown:?}");
        let out = ni(
            &w,
            &["profile", "remove", "extra", "--pair", "dst-alpha:other"],
        );
        assert_eq!(out.code, Some(0), "{out:?}");
        assert!(
            !ni(&w, &["profile", "show", "extra"])
                .stdout
                .contains("\"other\"")
        );
        let out = ni(&w, &["profile", "remove", "extra"]);
        assert_eq!(out.code, Some(0), "{out:?}");
        assert_eq!(
            ni(&w, &["profile", "show", "extra"]).code,
            Some(2),
            "NOT_FOUND exits 2"
        );
        assert!(ni(&w, &["profile", "list"]).stdout.contains("work"));
        let dest = ni(&w, &["destination", "show", ALPHA]);
        assert_eq!(dest.code, Some(0), "{dest:?}");
        assert_envelope_valid(&dest.json());
        assert!(ni(&w, &["identity", "list"]).stdout.contains(&id));
        // declare-interaction: unattended, a decision reference and nothing declared.
        let out = ni(&w, &["identity", "declare-interaction", &id, "none"]);
        assert_eq!(out.code, Some(3), "{out:?}");
        assert!(out.json()["next"]["decision_ref"].is_string(), "{out:?}");
        let listed = ni(&w, &["identity", "list"]).json();
        assert_ne!(
            listed["data"]["identities"][0]["interaction"], "none",
            "{listed}"
        );
        // On a terminal: the decision text, a typed yes, declared.
        let (code, t) = terminal::answer(
            &w.env(),
            &w.home.root,
            &["identity", "declare-interaction", &id, "none"],
            b"yes\n",
        );
        assert_eq!(code, Some(0), "{t}");
        assert!(
            t.contains("Heimdall will treat this key as needing no confirmation"),
            "{t}"
        );
        let listed = ni(&w, &["identity", "list"]).json();
        assert_eq!(
            listed["data"]["identities"][0]["interaction"], "none",
            "{listed}"
        );
        // Withdraw: narrowing, no decision.
        let out = ni(&w, &["identity", "withdraw-declaration", &id]);
        assert_eq!(out.code, Some(0), "{out:?}");
        assert_eq!(out.json()["data"]["withdrawn"], true, "{out:?}");
        let listed = ni(&w, &["identity", "list"]).json();
        assert_ne!(
            listed["data"]["identities"][0]["interaction"], "none",
            "{listed}"
        );
        // destination remove: the projection goes stale, no file changes.
        let tree = w.tree();
        let out = ni(&w, &["destination", "remove", ALPHA]);
        assert_eq!(out.code, Some(0), "{out:?}");
        assert_eq!(w.tree(), tree);
        assert_eq!(ni(&w, &["destination", "show", ALPHA]).code, Some(2));
    }

    // ---- uninstall -------------------------------------------------------------------------

    /// `ssh -G -F <scratch config> <alias>`, isolation only.
    fn ssh_g(w: &World, alias: &str) -> String {
        let ssh = heimdall_testkit::home::find_program("ssh").expect("ssh");
        let out = Command::new(ssh)
            .args(w.home.isolation_args())
            .arg("-G")
            .arg(alias)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &w.home.git_home)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// m02-plan U9 `uninstall_restores_user_bytes_and_effective_config_and_reports_remaining_items`
    /// (A35 T06): the user file is restored byte for byte, `ssh -G` of an unaffected
    /// alias is identical, P and the key files are removed, the runtime stops, and the
    /// report lists the kept state store.
    #[test]
    fn uninstall_restores_user_bytes_and_effective_config_and_reports_remaining_items() {
        let w = World::new(1);
        w.home.write_user_config(USER).unwrap();
        let bytes = std::fs::read(&w.home.user_config).unwrap();
        let effective = ssh_g(&w, "other");
        let id = w.adopt(0);
        w.managed(ALPHA, "alpha.example.invalid", None, "fixture", &id);
        w.project();
        assert_ne!(std::fs::read(&w.home.user_config).unwrap(), bytes);
        let out = ni(&w, &["uninstall"]);
        assert_eq!(out.code, Some(0), "{out:?}");
        let env = out.json();
        assert_envelope_valid(&env);
        assert_eq!(
            std::fs::read(&w.home.user_config).unwrap(),
            bytes,
            "restored byte for byte"
        );
        assert_eq!(ssh_g(&w, "other"), effective);
        assert!(!w.p().exists(), "P removed");
        assert!(
            std::fs::read_dir(w.home.config_dir.join("keys"))
                .map_or(true, |mut d| d.next().is_none()),
            "key files removed"
        );
        assert_eq!(env["data"]["runtime_stopped"], true, "{env}");
        assert!(!w.home.root.join("run/instance.json").exists());
        let kinds: Vec<&str> = env["data"]["remaining"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["kind"].as_str().unwrap())
            .collect();
        assert!(kinds.contains(&"state_store"), "{env}");
        assert!(
            !kinds.contains(&"conflict_file") && !kinds.contains(&"quarantine"),
            "{env}"
        );
        let shown = env["data"]["remaining"].to_string();
        assert!(
            !shown.contains(w.home.git_home.to_str().unwrap()),
            "no absolute home path: {shown}"
        );
    }

    /// m02-plan U9 `uninstall_with_incomplete_rollback_keeps_artifacts_and_purge_refuses`
    /// (Q6 as qualified): P was edited after setup, so the rollback keeps it as a conflict
    /// file; a foreign quarantine entry is kept. Uninstall reports `CONFIG_CONFLICT`
    /// (effect `partial`), keeps and lists the state store, the conflict file and the
    /// quarantine, and `--purge-state` refuses (exit 6) and deletes nothing.
    #[test]
    fn uninstall_with_incomplete_rollback_keeps_artifacts_and_purge_refuses() {
        use std::os::unix::fs::PermissionsExt as _;
        let (w, _) = single(true);
        std::fs::write(w.p(), "# edited by the owner\nHost edited\n").unwrap();
        let q = w.home.config_dir.join(".hm-quarantine");
        std::fs::create_dir_all(&q).unwrap();
        std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(q.join("managed_ssh-9-00ff"), b"foreign bytes\n").unwrap();
        // A purge is confirmed first (ADR-0007 §12.31 item 1), so this runs on a
        // terminal with the owner's typed yes; the incomplete rollback then refuses it.
        let (code, env, t) = owner(&w, &["uninstall", "--purge-state"]);
        assert_eq!(code, Some(6), "{t}");
        assert_eq!(env["data"]["error"]["effect_status"], "partial", "{env}");
        let kinds: Vec<&str> = env["data"]["remaining"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["kind"].as_str().unwrap())
            .collect();
        for k in ["state_store", "quarantine", "recovery_record"] {
            assert!(kinds.contains(&k), "{k}: {env}");
        }
        assert_eq!(env["data"]["purged"], false);
        assert!(
            w.home.state_dir.join("state.db").exists(),
            "the store is kept"
        );
        assert!(
            q.join("managed_ssh-9-00ff").exists(),
            "the foreign entry is kept"
        );
        let quarantine = env["data"]["quarantine"].to_string();
        assert!(quarantine.contains("managed_ssh-9-00ff"), "{quarantine}");
        // The confirmation listed the quarantine as kept before the owner answered.
        assert!(
            t.contains("Conflict and quarantine copies, kept")
                && t.contains(".hm-quarantine")
                && t.find(".hm-quarantine") < t.find("[y/N]"),
            "{t}"
        );
    }

    /// A disposable snapshot in the state directory, as `setup apply` leaves one.
    fn plant_backup(w: &World) -> (PathBuf, &'static [u8]) {
        let dir = w.home.state_dir.join("backups");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("ssh_config.20260101T000000Z.orig");
        let bytes: &'static [u8] = b"Host disposable\n    HostName backup.example.invalid\n";
        std::fs::write(&file, bytes).unwrap();
        (file, bytes)
    }

    /// ADR-0007 §12.31 item 1 (Q01; Q6): `uninstall --purge-state` is refused without a
    /// typed yes, with everything kept, and nothing changed (the runtime still serves,
    /// the projection and the user file are as they were). The reviewer's reproduction
    /// (`--non-interactive`, stdin from /dev/null) and a bare non-TTY stdin exit 3
    /// `INTERACTION_REQUIRED` with no `decision_ref` before anything is read or started;
    /// on a terminal, a no, an unrecognised answer and end of input exit 3 the same way,
    /// after the prompt listed the database with its counts and the backup. A refusal is
    /// final: it is not the incomplete-rollback refusal (exit 6) and purges nothing.
    #[test]
    fn uninstall_purge_state_is_refused_without_a_typed_yes_and_keeps_everything() {
        let (w, _) = single(true);
        let (backup, backup_bytes) = plant_backup(&w);
        let db = w.home.state_dir.join("state.db");
        let tree = w.tree();
        let intact = |what: &str| {
            assert!(db.exists(), "{what}: the state database is kept");
            assert_eq!(
                std::fs::read(&backup).unwrap(),
                backup_bytes,
                "{what}: the backup is kept"
            );
            assert_eq!(w.tree(), tree, "{what}: nothing else changed");
            assert!(w.serving(), "{what}: the runtime was not stopped");
        };
        let refused = |env: &Value, why: &str| {
            assert_envelope_valid(env);
            assert_eq!(env["code"], "INTERACTION_REQUIRED", "{env}");
            assert!(
                env["next"]["decision_ref"].is_null(),
                "client-side: no decision_ref: {env}"
            );
            assert_eq!(env["data"]["error"]["effect_status"], "none", "{env}");
            let message = env["data"]["error"]["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("--purge-state not confirmed")
                    && message.contains("nothing was changed")
                    && message.contains(why),
                "{why}: {message}"
            );
        };
        // Unattended: the flag stands in for nothing here.
        for (args, why) in [
            (
                &["--json", "--non-interactive", "uninstall", "--purge-state"][..],
                "--non-interactive",
            ),
            (
                &["--json", "uninstall", "--purge-state"][..],
                "stdin is not a terminal",
            ),
        ] {
            let out = w.cli(args);
            assert_eq!(out.code, Some(3), "{why}: {out:?}");
            refused(&out.json(), why);
            assert!(
                !out.stdout.contains("State database:") && !out.stderr.contains("State database:"),
                "nothing was listed or asked: {out:?}"
            );
            intact(why);
        }
        // Attended, but not a typed yes.
        for (answer, why) in [
            (&b"no\n"[..], "answered no"),
            (&b"sure\n"[..], "answered no"),
            (&b"\x04"[..], "end of input"),
        ] {
            let (code, t) = terminal::answer(
                &w.env(),
                &w.home.root,
                &["--json", "uninstall", "--purge-state"],
                answer,
            );
            assert_eq!(code, Some(3), "{answer:?}: {t}");
            refused(&terminal::envelope(&t), why);
            // What would have been discarded was shown before the answer.
            let prompt_at = t.find("[y/N]").unwrap_or_else(|| panic!("no prompt: {t}"));
            let shown = &t[..prompt_at];
            for needle in [
                "--purge-state permanently deletes",
                "State database:",
                "operations:",
                "1 identities, 1 destinations, 1 profiles",
                "Backups of your original files (1):",
                "ssh_config.20260101T000000Z.orig",
            ] {
                assert!(shown.contains(needle), "{answer:?}: {needle}: {t}");
            }
            assert_eq!(t.matches("[y/N]").count(), 1, "asked once: {t}");
            intact(why);
        }
    }

    /// ADR-0007 §12.31 item 1: with the attended typed yes the purge is done: the
    /// database and the backups are deleted, the runtime stopped, the report says so, and
    /// what was discarded was listed before the answer. Nothing to roll back here, so the
    /// purge prompt is the only prompt.
    #[test]
    fn uninstall_purge_state_with_a_typed_yes_discards_the_state() {
        let (w, _) = single(false);
        let (backup, _) = plant_backup(&w);
        let db = w.home.state_dir.join("state.db");
        assert!(db.exists());
        let (code, env, t) = owner(&w, &["uninstall", "--purge-state"]);
        assert_eq!(code, Some(0), "{t}");
        assert_eq!(env["code"], "OK", "{env}");
        assert_eq!(env["data"]["purged"], true, "{env}");
        assert_eq!(env["data"]["runtime_stopped"], true, "{env}");
        assert!(!db.exists(), "the state database is deleted");
        assert!(!backup.exists(), "the backup is deleted");
        assert!(!w.home.state_dir.join("backups").exists());
        let kinds: Vec<&str> = env["data"]["remaining"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["kind"].as_str().unwrap())
            .collect();
        assert!(
            !kinds.contains(&"state_store") && !kinds.contains(&"backup"),
            "{env}"
        );
        assert_eq!(t.matches("[y/N]").count(), 1, "one prompt: {t}");
        let shown = &t[..t.find("[y/N]").unwrap()];
        for needle in [
            "State database:",
            "1 identities, 1 destinations, 1 profiles",
            "Backups of your original files (1):",
            "ssh_config.20260101T000000Z.orig",
        ] {
            assert!(shown.contains(needle), "{needle}: {t}");
        }
    }

    /// The full uninstall: after a purge was confirmed, the rollback of an installed
    /// projection runs as usual (the user file is restored byte for byte, P and the
    /// keys are removed) and the state is then purged.
    #[test]
    fn uninstall_purge_state_confirmed_then_rolls_back_and_purges() {
        let (w, _) = single(true);
        let db = w.home.state_dir.join("state.db");
        assert_ne!(user(&w), USER, "the projection is installed");
        let (code, env, t) = owner(&w, &["uninstall", "--purge-state"]);
        assert_eq!(code, Some(0), "{t}");
        assert_eq!(env["data"]["purged"], true, "{env}");
        assert_eq!(user(&w), USER, "restored byte for byte");
        assert!(!w.p().exists(), "P removed");
        assert!(!db.exists(), "the state database is deleted");
        let purge_at = t.find("--purge-state permanently deletes");
        assert!(purge_at.is_some(), "the loss was listed: {t}");
        let first_prompt = t.find("[y/N]").unwrap();
        assert!(
            purge_at.unwrap() < first_prompt,
            "listed before the first answer: {t}"
        );
    }
}

/// The A01 and A35 cases against the loopback fixture sshd (m02-plan U9 "Tests"; U7's
/// `LoopbackSshd`, non-root, `127.0.0.1`, per-run keys). Every client gets only the
/// isolation arguments, after the default-identity guard; `SSH_AUTH_SOCK` is the decoy.
#[cfg(unix)]
mod ssh {
    use heimdall_contract::catalog::CatalogRequest;
    use heimdall_contract::ids::IdentityId;
    use heimdall_testkit::agent::AgentMode;
    use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};

    use super::world::World;
    use super::*;

    const ALPHA: &str = "alpha";

    fn account_name() -> String {
        let out = Command::new("/usr/bin/id")
            .arg("-un")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    struct Fix {
        w: World,
        sshd: LoopbackSshd,
        ssh: PathBuf,
        account: String,
    }

    /// `heimdall --json <args>` on a terminal, `yes` at every prompt.
    fn owner(w: &World, args: &[&str]) -> (Option<i32>, Value, String) {
        let mut all = vec!["--json"];
        all.extend_from_slice(args);
        let (code, t) = terminal::answer(&w.env(), &w.home.root, &all, b"yes\n");
        (code, terminal::envelope(&t), t)
    }

    impl Fix {
        /// The fixture sshd accepting `authorized` (indices into the world's keys) with
        /// `max_auth_tries`; the user file `user` (`{port}` and `{account}` replaced);
        /// key 0 adopted at the world's agent endpoint for `alpha` (127.0.0.1, the
        /// account the non-root sshd authenticates, read at run time); profile `work`.
        fn build(w: World, authorized: &[usize], max_auth_tries: u32, user: &str) -> Fix {
            let sshd = LoopbackSshd::start(
                w.home.scratch(),
                SshdConfig {
                    authorized: authorized
                        .iter()
                        .map(|k| w.keys[*k].public().clone())
                        .collect(),
                    max_auth_tries,
                    ..SshdConfig::default()
                },
            )
            .unwrap_or_else(|e| panic!("{e}"));
            w.home.trust_host_key(&sshd.host_key_line).unwrap();
            let account = account_name();
            let text = user
                .replace("{port}", &sshd.port.to_string())
                .replace("{account}", &account);
            w.home.write_user_config(&text).unwrap();
            let id = w.adopt(0);
            w.managed(ALPHA, &sshd.host, Some(sshd.port), &account, &id);
            w.profile(&[ALPHA], &account);
            let ssh = heimdall_testkit::home::find_program("ssh").expect("an ssh client");
            Fix {
                w,
                sshd,
                ssh,
                account,
            }
        }

        /// Apply through the CLI on a terminal (the owner's typed yes).
        fn apply(&self) {
            let (code, env, t) = owner(&self.w, &["setup", "apply"]);
            assert_eq!(code, Some(0), "{t}");
            assert_eq!(env["code"], "OK", "{env}");
        }

        /// `<client> <isolation> <args>`, the decoy at `SSH_AUTH_SOCK`, in scratch.
        fn client(&self, program: &Path, args: &[OsString]) -> std::process::Output {
            let mut cmd = Command::new(program);
            cmd.args(self.w.home.isolation_args())
                .args(args)
                .env_clear()
                .current_dir(&self.w.home.root);
            for (k, v) in self.w.env() {
                cmd.env(k, v);
            }
            cmd.stdin(Stdio::null()).output().unwrap()
        }

        /// Ordinary `ssh <isolation> <alias> true`, after the guard.
        fn login(&self, alias: &str) -> std::process::Output {
            self.w.home.check_alias(alias).unwrap();
            let ssh = self.ssh.clone();
            self.client(&ssh, &[alias.into(), "true".into()])
        }

        fn accepted(&self) -> Vec<String> {
            self.sshd
                .accepted_log()
                .into_iter()
                .map(|a| a.fingerprint)
                .collect()
        }

        fn fp(&self, k: usize) -> String {
            self.w.keys[k].fingerprint()
        }

        fn decoy(&self) -> usize {
            self.w.home.decoy_agent().contact_count()
        }

        /// The selection of `alias` in a passive doctor report.
        fn doctor_selection(&self, alias: &str) -> String {
            let out = self
                .w
                .cli(&["--json", "--non-interactive", "doctor", "--no-local-exec"]);
            let env = out.json();
            env["data"]["aliases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["alias"] == alias)
                .map(|a| {
                    a["identity_selection"]["selection"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned()
                })
                .unwrap_or_else(|| panic!("{alias}: {env}"))
        }
    }

    /// m02-plan U9 `a01_cli_adopt_observed_and_managed_aliases_then_ordinary_ssh_with_scratch_F`:
    /// through the CLI, the agent's one key is adopted (`identity adopt --from-agent`,
    /// the explicit agent probe), a managed alias and an observed alias are added, and
    /// setup is applied; then ordinary `ssh -F <scratch>` logs in through both, the
    /// provider agent A is contacted and the decoy B never.
    #[test]
    fn a01_cli_adopt_observed_and_managed_aliases_then_ordinary_ssh_with_scratch_f() {
        let w = World::new(1);
        let sshd = LoopbackSshd::start(
            w.home.scratch(),
            SshdConfig {
                authorized: vec![w.keys[0].public().clone()],
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        w.home.trust_host_key(&sshd.host_key_line).unwrap();
        let account = account_name();
        let agent = w.agent.endpoint().locator();
        let pubfile = w.home.root.join("k0.pub");
        w.keys[0].write_public(&pubfile).unwrap();
        w.home
            .write_user_config(&format!(
                "Host obs\n    HostName 127.0.0.1\n    Port {}\n    User {account}\n    IdentityAgent \"{}\"\n    IdentityFile \"{}\"\n    IdentitiesOnly yes\n",
                sshd.port,
                agent.to_str().unwrap(),
                pubfile.display()
            ))
            .unwrap();
        let at_agent: [(&str, &OsStr); 1] = [("SSH_AUTH_SOCK", agent.as_os_str())];
        let adopted = w.cli_with(
            &[
                "--json",
                "--non-interactive",
                "identity",
                "adopt",
                "--from-agent",
                "--active-probe",
                "agent",
            ],
            &at_agent,
        );
        assert_eq!(adopted.code, Some(0), "{adopted:?}");
        let identity = adopted.json()["data"]["identity_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let port = sshd.port.to_string();
        let added = w.cli(&[
            "--json",
            "--non-interactive",
            "destination",
            "add",
            ALPHA,
            "--hostname",
            "127.0.0.1",
            "--port",
            &port,
            "--account",
            &account,
            "--identity",
            &identity,
        ]);
        assert_eq!(added.code, Some(0), "{added:?}");
        let obs = w.cli(&[
            "--json",
            "--non-interactive",
            "destination",
            "add",
            "obs",
            "--observed",
        ]);
        assert_eq!(obs.code, Some(0), "{obs:?}");
        let listed = w.cli(&["--json", "--non-interactive", "destination", "list"]);
        let text = listed.json()["data"].to_string();
        assert!(text.contains(ALPHA) && text.contains("obs"), "{text}");
        let (code, _, t) = owner(&w, &["setup", "apply"]);
        assert_eq!(code, Some(0), "{t}");
        let ssh = heimdall_testkit::home::find_program("ssh").unwrap();
        let before = w.agent.contact_count();
        for alias in [ALPHA, "obs"] {
            w.home.check_alias(alias).unwrap();
            let mut cmd = Command::new(&ssh);
            cmd.args(w.home.isolation_args())
                .arg(alias)
                .arg("true")
                .env_clear();
            for (k, v) in w.env() {
                cmd.env(k, v);
            }
            let out = cmd.stdin(Stdio::null()).output().unwrap();
            assert!(
                out.status.success(),
                "{alias}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        assert!(
            w.agent.contact_count() > before,
            "provider agent A contacted"
        );
        assert_eq!(w.home.decoy_agent().contact_count(), 0, "decoy B never");
        let accepted = sshd.accepted_log();
        assert!(
            accepted.len() >= 2
                && accepted
                    .iter()
                    .all(|a| a.fingerprint == w.keys[0].fingerprint())
        );
    }

    /// m02-plan U9 `a01_unaffected_aliases_effective_config_identical_before_after`:
    /// aliases the projection does not manage keep their effective configuration, both
    /// statically (the doctor's observation) and by `ssh -G -F`.
    #[test]
    fn a01_unaffected_aliases_effective_config_identical_before_after() {
        let w = World::new(1);
        let user = "Host one\n    HostName one.example.invalid\n    Port 2201\n    User u1\nHost two *.example.invalid\n    ForwardAgent no\n    ServerAliveInterval 30\nHost *\n    Compression yes\n";
        w.home.write_user_config(user).unwrap();
        let ssh = heimdall_testkit::home::find_program("ssh").unwrap();
        let g = |alias: &str| {
            let out = Command::new(&ssh)
                .args(w.home.isolation_args())
                .arg("-G")
                .arg(alias)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &w.home.git_home)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(out.status.success());
            String::from_utf8(out.stdout).unwrap()
        };
        let statics = || {
            let out = w.cli(&[
                "--json",
                "--non-interactive",
                "doctor",
                "--no-local-exec",
                "--alias",
                "one",
                "--alias",
                "two",
            ]);
            // Values and certainties: provenance line numbers move by the block's lines,
            // which is not behaviour.
            let mut aliases = out.json()["data"]["aliases"].clone();
            for a in aliases.as_array_mut().unwrap() {
                for d in a["behavior"].as_array_mut().unwrap() {
                    d.as_object_mut().unwrap().remove("provenance");
                }
                if let Some(entries) = a["identity_selection"]["entries"].as_array_mut() {
                    for e in entries {
                        e.as_object_mut().unwrap().remove("provenance");
                    }
                }
            }
            aliases
        };
        let before = (g("one"), g("two"), statics());
        let id = w.adopt(0);
        w.managed(ALPHA, "alpha.example.invalid", None, "fixture", &id);
        let (code, _, t) = owner(&w, &["setup", "apply"]);
        assert_eq!(code, Some(0), "{t}");
        assert!(
            std::fs::read_to_string(&w.home.user_config)
                .unwrap()
                .contains("heimdall managed include")
        );
        let after = (g("one"), g("two"), statics());
        assert_eq!(after.0, before.0, "ssh -G one");
        assert_eq!(after.1, before.1, "ssh -G two");
        assert_eq!(after.2, before.2, "static observation");
    }

    /// m02-plan U9 `a01_no_remote_change`: setup and logins change nothing on the server
    /// (the fixture sshd's authorized-keys digest is unchanged).
    #[test]
    fn a01_no_remote_change() {
        let f = Fix::build(World::new(1), &[0], 6, "");
        let digest = || {
            let mut files = Vec::new();
            walk_named(&f.w.home.root, "authorized_keys", &mut files);
            assert!(!files.is_empty());
            files
        };
        let before = digest();
        f.apply();
        assert!(f.login(ALPHA).status.success());
        assert_eq!(digest(), before);
    }

    fn walk_named(dir: &Path, name: &str, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() && !p.is_symlink() {
                walk_named(&p, name, out);
            } else if p.file_name().is_some_and(|n| n == name) {
                out.push((p.clone(), std::fs::read(&p).unwrap()));
            }
        }
    }

    /// m02-plan U9 `a01_no_key_export`: a private key file holding canary bytes (mode
    /// 000) beside its `.pub`; adopting by `--pub`, setup and a doctor run never read it:
    /// it stays mode 000, and its bytes appear in no output, managed file or store.
    #[test]
    fn a01_no_key_export() {
        use std::os::unix::fs::PermissionsExt as _;
        let w = World::new(1);
        w.home
            .write_user_config("Host other\n    HostName other.example.invalid\n")
            .unwrap();
        let private = w.home.ssh_dir.join("id_canary");
        let canary = format!("{}PRIVATE_KEY_U9", heimdall_testkit::CANARY_PREFIX);
        std::fs::write(
            &private,
            format!("-----BEGIN OPENSSH {} KEY-----\n{canary}\n", "PRIVATE"),
        )
        .unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o000)).unwrap();
        let pubfile = w.home.ssh_dir.join("id_canary.pub");
        w.keys[0].write_public(&pubfile).unwrap();
        let adopted = w.cli(&[
            "--json",
            "--non-interactive",
            "identity",
            "adopt",
            "--pub",
            pubfile.to_str().unwrap(),
        ]);
        assert_eq!(adopted.code, Some(0), "{adopted:?}");
        let id =
            IdentityId::parse(adopted.json()["data"]["identity_id"].as_str().unwrap()).unwrap();
        w.managed(ALPHA, "alpha.example.invalid", None, "fixture", &id);
        let (code, _, t) = owner(&w, &["setup", "apply"]);
        assert_eq!(code, Some(0), "{t}");
        let doctor = w.cli(&["--json", "--non-interactive", "doctor", "--no-local-exec"]);
        assert_eq!(doctor.code, Some(0));
        let mode = std::fs::metadata(&private).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0, "the private key stays mode 000");
        let mut files = Vec::new();
        for dir in [&w.home.config_dir, &w.home.state_dir] {
            for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                if e.path().is_file() {
                    files.push(std::fs::read(e.path()).unwrap());
                }
            }
        }
        files.push(std::fs::read(&w.home.user_config).unwrap());
        for bytes in files {
            assert!(!String::from_utf8_lossy(&bytes).contains(&canary));
        }
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// m02-plan U9 `a01_personal_profile_without_repository` (Q3), in the plan's wording
    /// (ADR-0007 §12.30 item 1): the working directory has no `.git`; the adopted key is
    /// **undeclared** (no interaction declaration, so nothing relies on one); ordinary
    /// ssh and `connect` work; an **interactive** `run --profile personal` (a terminal,
    /// no `--non-interactive`; no standing policy covers `personal`) asks for exactly one
    /// attended owner decision, and after the typed `yes` the launch runs: the server
    /// accepts the adopted key and nothing is left pending.
    #[test]
    fn a01_personal_profile_without_repository() {
        use std::os::unix::fs::PermissionsExt as _;
        let f = Fix::build(World::new(1), &[0], 6, "");
        f.apply();
        let listed =
            f.w.cli(&["--json", "--non-interactive", "identity", "list"]);
        let identity = listed.json()["data"]["identities"][0].clone();
        assert!(identity["identity_id"].is_string(), "{identity}");
        assert!(
            identity["declaration"].is_null() && identity["declared_at"].is_null(),
            "the adopted key is undeclared: {identity}"
        );
        assert_ne!(identity["interaction_basis"], "declared", "{identity}");
        let cwd = f.w.home.root.join("not-a-repo");
        std::fs::create_dir_all(&cwd).unwrap();
        assert!(!cwd.join(".git").exists());
        assert!(f.login(ALPHA).status.success());
        // `connect` through a verified-client wrapper that adds only isolation.
        let dir = f.w.home.root.join("wrapper-bin");
        std::fs::create_dir_all(&dir).unwrap();
        let mut words = vec![f.ssh.clone().into_os_string()];
        words.extend(f.w.home.isolation_args());
        let wrapper = dir.join("ssh");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nexec {} \"$@\" true\n",
                heimdall_testkit::home::sh_join(&words)
            ),
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = OsString::from(format!("{}:/usr/bin:/bin", dir.display()));
        let connected = Out::of(
            f.w.command(&os(&["connect", ALPHA]), &[("PATH", path.as_os_str())])
                .current_dir(&cwd)
                .output()
                .unwrap(),
        );
        assert_eq!(connected.code, Some(0), "{connected:?}");
        // `run --profile personal`: one attended decision, then the launch.
        f.w.catalog(CatalogRequest::UpsertProfile {
            profile: heimdall_contract::catalog::ProfileSpec {
                id: heimdall_contract::ids::ProfileId::parse("personal").unwrap(),
                pairs: [heimdall_contract::request::AccessPairRef {
                    destination: heimdall_contract::ids::DestinationId::parse("dst-alpha").unwrap(),
                    account: heimdall_contract::ids::AccountName::parse(&f.account).unwrap(),
                }]
                .into_iter()
                .collect(),
                label: None,
            },
            request_id: f.w.next_id("personal"),
        })
        .unwrap();
        let mut argv = vec![
            "run".to_owned(),
            "--profile".to_owned(),
            "personal".to_owned(),
            "--".to_owned(),
        ];
        argv.push(f.ssh.to_string_lossy().into_owned());
        argv.extend(
            f.w.home
                .isolation_args()
                .iter()
                .map(|a| a.to_string_lossy().into_owned()),
        );
        argv.extend([ALPHA.to_owned(), "true".to_owned()]);
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        let accepted_before = f.accepted().len();
        let (code, t) = terminal::answer(&f.w.env(), &cwd, &refs, b"yes\n");
        assert_eq!(code, Some(0), "{t}");
        assert_eq!(t.matches("[y/N]").count(), 1, "exactly one decision: {t}");
        assert!(
            !t.contains("INTERACTION_REQUIRED"),
            "the approved interactive run is never refused for interaction: {t}"
        );
        let accepted = f.accepted();
        assert!(
            accepted.len() > accepted_before
                && accepted[accepted_before..].iter().all(|fp| *fp == f.fp(0)),
            "the launch logged in with the adopted key: {accepted:?}"
        );
        let pending =
            f.w.cli(&["--json", "--non-interactive", "decision", "list"]);
        assert_eq!(
            pending.json()["data"]["decisions"].as_array().map(Vec::len),
            Some(0),
            "nothing left pending: {pending:?}"
        );
        // Still undeclared: the one decision was the profile's, not a declaration.
        let after =
            f.w.cli(&["--json", "--non-interactive", "identity", "list"]);
        assert!(
            after.json()["data"]["identities"][0]["declaration"].is_null(),
            "{after:?}"
        );
        assert_eq!(f.decoy(), 0);
    }

    /// m02-plan U9 `host_key_substitution_fails_closed_and_nothing_written_to_known_hosts`
    /// (MANIFEST row 5 pattern; R-SE-04): the trusted entry names another key; the
    /// login fails, through the CLI's `run` too, and known_hosts is byte-identical.
    #[test]
    fn host_key_substitution_fails_closed_and_nothing_written_to_known_hosts() {
        let f = Fix::build(World::new(1), &[0], 6, "");
        f.apply();
        f.w.declare(
            &IdentityId::parse(
                f.w.cli(&["--json", "--non-interactive", "identity", "list"])
                    .json()["data"]["identities"][0]["identity_id"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        );
        let other = heimdall_testkit::agent::FixtureKey::generate_many(1).remove(0);
        let substituted = format!(
            "[{}]:{} {}\n",
            f.sshd.host,
            f.sshd.port,
            other.public_line_without_comment()
        );
        std::fs::write(&f.w.home.known_hosts, &substituted).unwrap();
        let out = f.login(ALPHA);
        assert_eq!(
            out.status.code(),
            Some(255),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut argv = os(&[
            "--json",
            "--non-interactive",
            "run",
            "--profile",
            "work",
            "--",
        ]);
        argv.push(f.ssh.clone().into_os_string());
        argv.extend(f.w.home.isolation_args());
        argv.extend(os(&[ALPHA, "true"]));
        let run = Out::of(f.w.command(&argv, &[]).output().unwrap());
        assert_eq!(run.code, Some(255), "{run:?}");
        assert_eq!(
            std::fs::read_to_string(&f.w.home.known_hosts).unwrap(),
            substituted
        );
        assert!(f.accepted().is_empty());
        assert_eq!(f.decoy(), 0);
    }

    /// m02-plan U9 `a35_matrix_ssh_git_scp_sftp_ordinary_alias_and_run_bound`: a real
    /// disposable agent behind a counting proxy holds the adopted key; ordinary `ssh`,
    /// `scp`, `sftp` and Git over the managed alias, and `run`-bound `ssh`, all log in
    /// with exactly the adopted key; the resolved executable is recorded; proxy count
    /// > 0, decoy 0.
    #[test]
    fn a35_matrix_ssh_git_scp_sftp_ordinary_alias_and_run_bound() {
        let mut w = World::new(1);
        w.attach_real(&[0]);
        let f = Fix::build(w, &[0], 6, "");
        f.apply();
        let id = IdentityId::parse(
            f.w.cli(&["--json", "--non-interactive", "identity", "list"])
                .json()["data"]["identities"][0]["identity_id"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        f.w.declare(&id);
        let base = f.w.real.as_ref().unwrap().proxy.count();
        let root = f.w.home.root.clone();
        let mut record = Vec::new();
        // ssh
        assert!(f.login(ALPHA).status.success());
        record.push(("ssh", f.ssh.clone()));
        // scp
        let scp = heimdall_testkit::home::find_program("scp").unwrap();
        let local = root.join("payload.bin");
        std::fs::write(&local, (0..=255u8).collect::<Vec<u8>>()).unwrap();
        let remote = root.join("copied.bin");
        let out = f.client(
            &scp,
            &[
                local.clone().into(),
                format!("{ALPHA}:{}", remote.display()).into(),
            ],
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            std::fs::read(&remote).unwrap(),
            std::fs::read(&local).unwrap()
        );
        record.push(("scp", scp));
        // sftp
        let sftp = heimdall_testkit::home::find_program("sftp").unwrap();
        let batch = root.join("batch");
        let fetched = root.join("fetched.bin");
        std::fs::write(
            &batch,
            format!("get \"{}\" \"{}\"\n", remote.display(), fetched.display()),
        )
        .unwrap();
        let out = f.client(&sftp, &["-b".into(), batch.into(), ALPHA.into()]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            std::fs::read(&fetched).unwrap(),
            std::fs::read(&local).unwrap()
        );
        record.push(("sftp", sftp));
        // git
        let git = heimdall_testkit::home::find_program("git").unwrap();
        let bare = root.join("repo.git");
        let st = Command::new(&git)
            .args(["init", "-q", "--bare"])
            .arg(&bare)
            .env_clear()
            .env("HOME", &f.w.home.git_home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", f.w.home.git_home.join(".gitconfig"))
            .status()
            .unwrap();
        assert!(st.success());
        let mut words = vec![f.ssh.clone().into_os_string()];
        words.extend(f.w.home.isolation_args());
        let mut cmd = Command::new(&git);
        cmd.args(["ls-remote"])
            .arg(format!("{ALPHA}:{}", bare.display()))
            .env_clear()
            .current_dir(&root);
        for (k, v) in f.w.env() {
            cmd.env(k, v);
        }
        cmd.env("GIT_SSH_COMMAND", heimdall_testkit::home::sh_join(&words))
            .env("GIT_SSH_VARIANT", "ssh");
        f.w.home.check_alias(ALPHA).unwrap();
        let out = cmd.stdin(Stdio::null()).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        record.push(("git", git));
        // run-bound
        let mut argv = os(&[
            "--json",
            "--non-interactive",
            "run",
            "--profile",
            "work",
            "--",
        ]);
        argv.push(f.ssh.clone().into_os_string());
        argv.extend(f.w.home.isolation_args());
        argv.extend(os(&[ALPHA, "true"]));
        let run = Out::of(f.w.command(&argv, &[]).output().unwrap());
        assert_eq!(run.code, Some(0), "{run:?}");
        let accepted = f.accepted();
        assert!(accepted.len() >= 5, "{accepted:?}");
        assert!(
            accepted.iter().all(|a| *a == f.fp(0)),
            "only the adopted key: {accepted:?}"
        );
        assert!(
            f.w.real.as_ref().unwrap().proxy.count() > base,
            "agent A contacted"
        );
        assert_eq!(f.decoy(), 0, "decoy B never");
        for (what, exe) in &record {
            eprintln!("a35 matrix: {what} resolved to {}", exe.display());
        }
    }

    /// m02-plan U9 `a35_wrong_key_exclusive_selection_fails_without_fallback`: the agent
    /// holds the adopted key (rejected by the server) and an accepted key; the
    /// selection is exclusive, so the login fails and the accepted key is never used.
    #[test]
    fn a35_wrong_key_exclusive_selection_fails_without_fallback() {
        let f = Fix::build(World::new(2), &[1], 6, "");
        f.apply();
        assert_eq!(f.doctor_selection(ALPHA), "exclusive");
        let out = f.login(ALPHA);
        assert_eq!(
            out.status.code(),
            Some(255),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(f.accepted().is_empty(), "no fallback to the accepted key");
        assert_eq!(f.decoy(), 0);
    }

    /// The inherited-fallback cases (M2-D01, M2-R05): `Host *` adds `other`, which the
    /// server accepts while rejecting the adopted key.
    fn inherited(file_backed: bool) {
        use std::os::unix::fs::PermissionsExt as _;
        let w = World::new(2);
        let other_pub = w.home.ssh_dir.join("id_other.pub");
        w.keys[1].write_public(&other_pub).unwrap();
        let entry = if file_backed {
            let private = w.home.ssh_dir.join("id_other");
            w.keys[1].write_private(&private).unwrap();
            std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600)).unwrap();
            private
        } else {
            other_pub.clone()
        };
        let user = format!(
            "Host *\n    IdentityFile \"{}\"\n    IdentityAgent \"{}\"\n",
            entry.display(),
            w.agent.endpoint().locator().to_str().unwrap()
        );
        let f = Fix::build(w, &[1], 6, &user);
        f.apply();
        assert_eq!(f.doctor_selection(ALPHA), "not_exclusive");
        let ensure = f.w.cli(&[
            "--json",
            "access",
            "ensure",
            "--profile",
            "work",
            "--work-id",
            "w",
            "--request-id",
            "r-ens",
        ]);
        assert!(
            !ensure.stdout.contains("\"selection\":\"exclusive\""),
            "{ensure:?}"
        );
        // The ordinary interactive login still succeeds with the other key.
        let out = f.login(ALPHA);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            f.accepted().iter().all(|a| *a == f.fp(1)),
            "{:?}",
            f.accepted()
        );
        // Non-interactive `run`: refused before any agent contact.
        let before = f.w.agent.contact_count();
        let mut argv = os(&[
            "--json",
            "--non-interactive",
            "run",
            "--profile",
            "work",
            "--",
        ]);
        argv.push(f.ssh.clone().into_os_string());
        argv.extend(f.w.home.isolation_args());
        argv.extend(os(&[ALPHA, "true"]));
        let run = Out::of(f.w.command(&argv, &[]).output().unwrap());
        assert_eq!(run.code, Some(3), "{run:?}");
        assert_eq!(f.w.agent.contact_count(), before, "agent A delta 0");
        // Narrowed: exclusive, and the login fails (no fallback).
        let text = std::fs::read_to_string(&f.w.home.user_config).unwrap();
        std::fs::write(
            &f.w.home.user_config,
            text.replacen("Host *\n", &format!("Host * !{ALPHA}\n"), 1),
        )
        .unwrap();
        assert_eq!(f.doctor_selection(ALPHA), "exclusive");
        let accepted = f.accepted().len();
        let out = f.login(ALPHA);
        assert_eq!(out.status.code(), Some(255));
        assert_eq!(f.accepted().len(), accepted);
        assert_eq!(f.decoy(), 0);
    }

    /// m02-plan U9 `a35_inherited_identity_fallback_agent_backed_reported_not_exclusive`.
    #[test]
    fn a35_inherited_identity_fallback_agent_backed_reported_not_exclusive() {
        inherited(false);
    }

    /// m02-plan U9 `a35_inherited_identity_fallback_file_backed_reported_not_exclusive`.
    #[test]
    fn a35_inherited_identity_fallback_file_backed_reported_not_exclusive() {
        inherited(true);
    }

    /// m02-plan U9 `a35_too_many_keys_succeeds_for_managed_alias_only`: an agent with
    /// many keys and `MaxAuthTries 3`; the exclusive managed alias logs in, an ordinary
    /// alias offering every agent key fails.
    #[test]
    fn a35_too_many_keys_succeeds_for_managed_alias_only() {
        let w = World::with_mode(1, AgentMode::ManyKeys(10));
        let agent = w.agent.endpoint().locator();
        let user = format!(
            "Host plain\n    HostName 127.0.0.1\n    Port {{port}}\n    User {{account}}\n    IdentityAgent \"{}\"\n",
            agent.to_str().unwrap()
        );
        let f = Fix::build(w, &[0], 3, &user);
        f.apply();
        assert_eq!(f.doctor_selection(ALPHA), "exclusive");
        assert!(f.login(ALPHA).status.success());
        let out = f.client(
            &f.ssh,
            &[
                "-o".into(),
                "IdentityFile=none".into(),
                "plain".into(),
                "true".into(),
            ],
        );
        assert_eq!(
            out.status.code(),
            Some(255),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(f.decoy(), 0);
    }

    /// m02-plan U9 `a35_identity_agent_overriding_ssh_auth_sock_is_reported_and_managed_alias_unaffected`:
    /// a user `Host *` IdentityAgent points at the decoy; the managed alias still uses
    /// the projected agent (P is read first), the decoy is never contacted, and the
    /// doctor reports the override for the aliases it affects.
    #[test]
    fn a35_identity_agent_overriding_ssh_auth_sock_is_reported_and_managed_alias_unaffected() {
        let w = World::new(1);
        let decoy = w.home.decoy_agent().endpoint().locator();
        let user = format!(
            "Host *\n    IdentityAgent \"{}\"\n",
            decoy.to_str().unwrap()
        );
        let f = Fix::build(w, &[0], 6, &user);
        f.apply();
        assert!(f.login(ALPHA).status.success());
        assert!(f.accepted().iter().all(|a| *a == f.fp(0)));
        assert_eq!(f.decoy(), 0, "the projected agent wins");
        let doctor =
            f.w.cli(&["--json", "--non-interactive", "doctor", "--no-local-exec"]);
        assert_eq!(doctor.code, Some(0));
        let alpha = doctor.json()["data"]["aliases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["alias"] == ALPHA)
            .cloned()
            .unwrap();
        let agent = alpha["behavior"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["directive"] == "IdentityAgent")
            .cloned()
            .unwrap();
        assert!(
            agent.to_string().contains("agent.sock"),
            "the projected agent: {agent}"
        );
    }

    /// m02-plan U9 `a35_mutation_broken_identity_agent_is_detected` (M2-D09): the
    /// rendered P's IdentityAgent pointed at the decoy, or removed: the same oracle
    /// reports failure (the decoy contacted, or the login failed).
    #[test]
    fn a35_mutation_broken_identity_agent_is_detected() {
        let f = Fix::build(World::new(1), &[0], 6, "");
        f.apply();
        assert!(f.login(ALPHA).status.success());
        let p = f.w.p();
        let good = std::fs::read_to_string(&p).unwrap();
        let line = good
            .lines()
            .find(|l| l.trim_start().starts_with("IdentityAgent"))
            .unwrap()
            .to_owned();
        let decoy = f.w.home.decoy_agent().endpoint().locator();
        for broken in [
            good.replace(
                &line,
                &format!("    IdentityAgent \"{}\"", decoy.to_str().unwrap()),
            ),
            good.replace(&format!("{line}\n"), ""),
        ] {
            std::fs::write(&p, &broken).unwrap();
            let before = f.decoy();
            let out = f.client(&f.ssh, &[ALPHA.into(), "true".into()]);
            let detected = f.decoy() > before || !out.status.success();
            assert!(detected, "the oracle must report the broken IdentityAgent");
        }
        std::fs::write(&p, &good).unwrap();
    }
}
