//! ⟨M07 U5h⟩ m07-plan §5a: the two independent harnesses run the deterministic tasks against
//! the real binary (`CARGO_BIN_EXE_heimdall`, or `HEIMDALL_E2E_BIN`).
//!
//! H1 (`examples/harnesses/cli`, a script per task) and H2 (`examples/harnesses/goal-loop`, a
//! goal and a typed state machine) are Python programs that call only `heimdall --json`. This
//! file is their fixture driver. Both sources are compiled in and written to the scratch root,
//! so the test binary carries what it runs.
//!
//! | Task (m07-plan §5a) | World | H1 | H2 |
//! |---|---|---|---|
//! | 1 discover | existing access | `discover` | goal `discover` |
//! | 2 use an already-trusted profile | existing access | `covered` | goal `access` |
//! | 3 request only missing access, handing off the approval | fixture adapter | `approval` | goal `access` with `pairs` |
//! | 4 recover from a caller timeout by observing | fixture adapter | `timeout` | goal `access` with `timeout_ms` |
//! | 5 bind work and run a child | existing access | `bind-run` | goal `run` |
//! | 6 stop it | existing access | `release` | goal `stop` |
//! | 7 the operation-level capability refusal | existing access | `capability-refusal` | goal `access` with `require_unattended` |
//!
//! **Two worlds per harness**, each in its own root inside one scratch directory:
//! - *existing access*: an in-process runtime as `cli_m07.rs` builds it (the loopback sshd, a
//!   disposable agent holding a key generated for this run, a saved and approved profile). The
//!   child of task 5 logs in to the fixture sshd twice (see "The login oracle").
//! - *fixture adapter*: `heimdall service run` as a child with the debug test configuration
//!   (`crates/heimdall/src/testcfg.rs`): profile `dev` whose pair `h3:deploy` no policy covers
//!   (task 3), and a delayed prepare so a 1 ms caller timeout always ends first (task 4). Today's
//!   build has no other way to get either.
//!
//! **Request IDs and bindings.** Each harness gives every changing request a request ID of its
//! own. Task 5 follows task 2 for the same profile and work, so today's build may answer its
//! `run` with a second binding for that work. Task 6 has to release every binding the harness
//! holds: for H2 the driver checks one release for each binding H2 reported holding.
//!
//! **Cleanup (M07-W3-R01).** Tasks 3 and 4 each end holding a binding, so each harness releases
//! them in the fixture-adapter world too, after its tasks: H1 with its `release` task, H2 with a
//! `stop` goal. Those records are checked and are not among the seven. Every world of both
//! harnesses ends with no binding active, and H2 reports nothing left to release when it closes.
//!
//! **The login oracle (M07-W3-R02).** `heimdall run` gives the child of task 5 the binding's
//! signing endpoint as `SSH_AUTH_SOCK`. The child first checks that this is the disposable agent
//! of this run and nothing else, then logs in to the fixture sshd through that endpoint, with no
//! key file. Only then does it make the isolated login (every agent off, the generated key by
//! `-i`). A dead endpoint fails the first login, so it fails the task. The driver checks both
//! logins in the sshd's log, the first one's output, and a signature by the fixture agent.
//!
//! **On Windows (M07 W7)** the child of task 5 is the **in-box OpenSSH client**,
//! `%SystemRoot%\System32\OpenSSH\ssh.exe`, started by `heimdall run` itself (the `run -- ssh`
//! form of the AGENTS.md rule): `-F <scratch config>` and the isolated option set (every agent
//! and default identity off, the generated key by `-i`, scratch known hosts) are on its own
//! command line, with no wrapper and no redirect. It makes the isolated login, and the driver
//! checks it in the sshd's log. The login through the binding's endpoint is **not made on
//! Windows**: with `ssh.exe` itself as the child, nothing runs between `heimdall run` and the
//! client that could check that `SSH_AUTH_SOCK` names this run's disposable agent before the
//! client asks it, and an unchecked `IdentityAgent=SSH_AUTH_SOCK` falls back to the account's
//! own agent pipe whenever `SSH_AUTH_SOCK` is unset. So on Windows task 5 proves a launch under
//! the binding (H2 reads the `spawned` record) and an isolated login, not the endpoint.
//! ⟨M07 W7.3; M07-W7-R02⟩ The harnesses add no isolation to a child they did not build: the
//! caller's goal decides which ssh profile the child uses. So
//! `every_windows_goal_starting_the_in_box_client_carries_the_isolation` reads every goal the
//! Windows journeys give H1 and H2 as data, on every platform, and checks that each child
//! starting the in-box client carries its scratch `-F` file and the isolated options.
//!
//! **The human step** of task 3 is this driver: it reads the pending decision, checks that it
//! asks for exactly the missing pair, and approves it through the real CLI on a testkit terminal
//! (`script(1)` on Unix, ConPTY on Windows), typing `yes`.
//!
//! **Environment (m07-plan §0 rule 4).** Every `heimdall` child and every Python child gets a
//! cleared environment holding `HOME`, `HEIMDALL_HOME` and `HEIMDALL_TEST_SSH_HOME`, three
//! separate directories, plus management and transport fixture store paths inside the
//! world's root. All are checked before each launch. No `SSH_AUTH_SOCK` is passed. Every
//! wait is bounded, and every process is stopped by its own handle.
//!
//! **Python.** `HEIMDALL_E2E_PYTHON` names an absolute Python 3.9+ interpreter. The fallback
//! looks for `python3` on Unix and `python.exe` or `python3.exe` on the Windows runner's PATH.
//! All invocations use `-I -B` and set `PYTHONDONTWRITEBYTECODE=1`.
//!
//! **Platforms.** Unix runs both worlds together. Windows has a self-contained adapter test
//! (tasks 3 and 4) and a test using the native runner's disposable loopback sshd (tasks 1, 2,
//! 5, 6 and 7), whose task 5 child is the in-box `ssh.exe` (above).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

/// H1's source, as shipped.
const H1_SOURCE: &str = include_str!("../../examples/harnesses/cli/harness.py");
/// H2's source, as shipped.
const H2_SOURCE: &str = include_str!("../../examples/harnesses/goal-loop/harness.py");

/// Standard-library modules a harness may import. ⟨M07 W8; M07-W7-R03⟩ `ctypes` is H2's means of
/// holding the child Heimdall spawns on Windows by a handle of its own (kernel32).
const STANDARD_LIBRARY: [&str; 14] = [
    "argparse",
    "collections",
    "ctypes",
    "dataclasses",
    "json",
    "os",
    "pathlib",
    "queue",
    "re",
    "subprocess",
    "sys",
    "threading",
    "time",
    "uuid",
];

/// The top-level modules a Python source imports. Any line shaped like an import counts, so a
/// docstring cannot hide one (and one that merely looks like an import fails closed).
fn imported_modules(source: &str) -> Vec<String> {
    let mut modules = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        let named: Vec<&str> = if let Some(rest) = line.strip_prefix("import ") {
            rest.split(',').collect()
        } else if let Some(rest) = line.strip_prefix("from ") {
            match rest.split_once(" import ") {
                Some((module, _)) => vec![module],
                None => continue,
            }
        } else {
            continue;
        };
        for name in named {
            let name = name.split_whitespace().next().unwrap_or_default();
            modules.push(name.split('.').next().unwrap_or_default().to_owned());
        }
    }
    modules
}

#[test]
fn harnesses_are_independent_and_use_only_the_standard_library() {
    // What each harness must never name: the wrapper, the other harness, a way to load code by
    // name, Heimdall's private files, or a decision command.
    let common = [
        "reference-wrapper",
        "reference_wrapper",
        "__import__",
        "importlib",
        "runpy",
        "sys.path",
        "exec(",
        "eval(",
        "instance.json",
        "state.db",
        "sqlite",
        "\"approve\"",
        "\"deny\"",
        "\"decision\"",
        "\"tui\"",
    ];
    for (harness, source, other) in [
        ("H1", H1_SOURCE, ["goal-loop", "goal_loop"]),
        ("H2", H2_SOURCE, ["harnesses/cli", "harnesses.cli"]),
    ] {
        let modules = imported_modules(source);
        assert!(
            modules.len() >= 5,
            "{harness}: found too few imports to trust the scan: {modules:?}"
        );
        for module in &modules {
            assert!(
                STANDARD_LIBRARY.contains(&module.as_str()),
                "{harness} imports {module:?}, which is not an allowed standard-library module"
            );
        }
        for needle in common.iter().chain(other.iter()) {
            assert!(!source.contains(needle), "{harness} names {needle:?}");
        }
        assert!(
            source.contains("subprocess") && source.contains("\"--json\""),
            "{harness} is expected to call `heimdall --json` through subprocess"
        );
    }
    assert_eq!(
        imported_modules("import os, importlib.util as u\nfrom a.b import c\nx = 1\n"),
        ["os", "importlib", "a"]
    );
}

#[cfg(any(unix, windows))]
mod journey {
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::sync::Arc;
    use std::time::Duration;

    use heimdall_app::{Attendance, Caller, OpError, Operations};
    use heimdall_contract::catalog::{
        CatalogRequest, DeclaredInteraction, DestinationDefinitionSpec, DestinationSpec,
        IdentitySourceSpec, IdentitySpec, ProfileSpec,
    };
    use heimdall_contract::ids::{
        AccountName, DecisionId, DestinationId, IdentityId, ProfileId, RequestId,
    };
    use heimdall_contract::provider::{EndpointKind, EndpointRef};
    use heimdall_contract::request::{
        AccessPairRef, DecideRequest, InteractionMode, PolicyAction, Verdict,
    };
    use heimdall_contract::setup::{PreviewIntent, SetupPlan, SetupRequest};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_localenv::env::{Env, Platform};
    use heimdall_localenv::paths::SshPaths;
    use heimdall_localenv::projection::ProjectionConfig;
    use heimdall_runtime::config::{Config, Paths};
    use heimdall_runtime::service::{ProjectionWiring, Service, ServiceOptions};
    use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};
    use heimdall_testkit::console::TerminalCommand;
    use heimdall_testkit::home::ScratchHome;
    use heimdall_testkit::home::ssh_option_path;
    #[cfg(unix)]
    use heimdall_testkit::home::{find_program, sh_join};
    use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};
    use serde_json::{Value, json};
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::process::{Child, Command};
    use tokio_util::sync::CancellationToken;

    use super::{H1_SOURCE, H2_SOURCE};

    /// One CLI call, a runtime start or stop.
    const TIMEOUT: Duration = Duration::from_secs(30);
    /// One harness invocation (several calls, one of them a bounded wait).
    const HARNESS_TIMEOUT: Duration = Duration::from_secs(180);
    /// The fixture adapter's delay before every prepare: a 1 ms caller timeout always ends first.
    const SLOW_PREPARE_MS: &str = "800";
    /// The saved, approved profile of the existing-access world.
    const PROFILE: &str = "lab-access";
    /// The longest Unix socket path every supported platform accepts.
    #[cfg(unix)]
    const SOCKET_PATH_MAX: usize = 103;

    fn python() -> PathBuf {
        let python = std::env::var_os("HEIMDALL_E2E_PYTHON")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        #[cfg(unix)]
        let python = python.or_else(|| find_program("python3"));
        #[cfg(windows)]
        let python = python.or_else(|| {
            // The Store's WindowsApps aliases are not interpreters and can open the Store.
            let path = std::env::var_os("PATH")?;
            std::env::split_paths(&path)
                .filter(|dir| {
                    dir.is_absolute()
                        && !dir
                            .iter()
                            .any(|part| part.eq_ignore_ascii_case("WindowsApps"))
                })
                .flat_map(|dir| ["python.exe", "python3.exe"].map(|name| dir.join(name)))
                .find(|candidate| candidate.is_file())
        });
        let python = python.expect(
            "blocked: journey not run; Python 3.9+ is missing (set HEIMDALL_E2E_PYTHON to the absolute interpreter path)",
        );
        assert!(
            python.is_absolute() && python.is_file(),
            "blocked: journey not run; expected an absolute Python executable (HEIMDALL_E2E_PYTHON)"
        );
        python
    }

    const MGMT_STORE: &str = "HEIMDALL_TEST_MGMT_STORE";
    const IROH_STORE: &str = "HEIMDALL_TEST_IROH_KEY_STORE";

    fn fixture_stores(root: &Path) -> [(&'static str, PathBuf); 2] {
        [
            (MGMT_STORE, root.join("mgmt-store")),
            (IROH_STORE, root.join("iroh-key-store")),
        ]
    }

    fn assert_no_fixture_stores(root: &Path) {
        for (name, path) in fixture_stores(root) {
            assert!(
                path.symlink_metadata()
                    .is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound),
                "unexpected fixture store {name}"
            );
        }
    }

    /// Three separate launch directories and two fixture store paths (m07-plan §0 rule 4).
    fn launch_paths(scratch: &Path, root: &Path) -> Result<Vec<(&'static str, OsString)>, String> {
        let inside = std::fs::canonicalize(scratch).map_err(|e| format!("scratch root: {e}"))?;
        let homes = [
            ("HOME", root.join("home")),
            ("HEIMDALL_HOME", root.join("heimdall-home")),
            ("HEIMDALL_TEST_SSH_HOME", root.join("ssh-home")),
        ];
        let mut real = Vec::new();
        for (name, path) in &homes {
            let resolved = std::fs::canonicalize(path).map_err(|e| format!("{name}: {e}"))?;
            if !resolved.is_dir() || resolved == inside || !resolved.starts_with(&inside) {
                return Err(format!("{name} is not a directory inside the scratch root"));
            }
            real.push(resolved);
        }
        for (i, a) in real.iter().enumerate() {
            for (j, b) in real.iter().enumerate() {
                if i != j && a.starts_with(b) {
                    return Err(format!(
                        "{} and {} are not separate",
                        homes[i].0, homes[j].0
                    ));
                }
            }
        }
        let real_root = root
            .canonicalize()
            .map_err(|e| format!("world root: {e}"))?;
        if !root.is_absolute() || real_root == inside || !real_root.starts_with(&inside) {
            return Err("world root is not inside the scratch root".into());
        }
        let mut env: Vec<_> = homes
            .into_iter()
            .map(|(name, path)| (name, path.into_os_string()))
            .collect();
        for (name, path) in fixture_stores(root) {
            match path.symlink_metadata() {
                Ok(meta) if meta.is_file() => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    return Err(format!(
                        "{name} is not a fixture file path inside the world root"
                    ));
                }
            }
            let mut value = OsString::from(if name == MGMT_STORE {
                "fixture-file:"
            } else {
                ""
            });
            value.push(path);
            env.push((name, value));
        }
        Ok(env)
    }

    #[test]
    fn an_unsafe_home_or_store_fails_before_any_launch() {
        let scratch = heimdall_testkit::home::Scratch::new().unwrap();
        let other = heimdall_testkit::home::Scratch::new().unwrap();
        let root = scratch.path().join("w");
        for dir in ["home", "heimdall-home"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        let missing = launch_paths(scratch.path(), &root).unwrap_err();
        assert!(missing.starts_with("HEIMDALL_TEST_SSH_HOME"), "{missing}");
        std::fs::create_dir(root.join("ssh-home")).unwrap();
        let env = launch_paths(scratch.path(), &root).unwrap();
        for (name, path) in fixture_stores(&root) {
            let mut expected = OsString::from(if name == MGMT_STORE {
                "fixture-file:"
            } else {
                ""
            });
            expected.push(&path);
            assert!(env.contains(&(name, expected)));
            std::fs::create_dir(&path).unwrap();
            let error = launch_paths(scratch.path(), &root).unwrap_err();
            assert!(error.starts_with(name), "{error}");
            std::fs::remove_dir(&path).unwrap();
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(other.path().join("missing"), &path).unwrap();
                let error = launch_paths(scratch.path(), &root).unwrap_err();
                assert!(error.starts_with(name), "{error}");
                std::fs::remove_file(&path).unwrap();
            }
        }
        // The same root is foreign to another test's scratch directory.
        let foreign = launch_paths(other.path(), &root).unwrap_err();
        assert!(foreign.contains("inside the scratch root"), "{foreign}");
        #[cfg(unix)]
        {
            // A home that is a link to another home is not a separate directory.
            std::fs::remove_dir(root.join("ssh-home")).unwrap();
            std::os::unix::fs::symlink(root.join("home"), root.join("ssh-home")).unwrap();
            let shared = launch_paths(scratch.path(), &root).unwrap_err();
            assert!(shared.contains("not separate"), "{shared}");
        }
    }

    /// The test's scratch directory and what every world in it shares.
    struct Suite {
        home: ScratchHome,
        bin: PathBuf,
        python: PathBuf,
        h1: PathBuf,
        h2: PathBuf,
        /// The login name, redacted from diagnostics.
        login: String,
    }

    impl Suite {
        fn new() -> Suite {
            let bin = if cfg!(debug_assertions) {
                std::env::var_os("HEIMDALL_E2E_BIN")
                    .filter(|s| !s.is_empty())
                    .map_or_else(
                        || PathBuf::from(env!("CARGO_BIN_EXE_heimdall")),
                        PathBuf::from,
                    )
            } else {
                panic!("blocked: the journey needs a debug build");
            };
            let python = python();
            assert!(
                bin.is_absolute() && bin.is_file(),
                "expected an absolute debug Heimdall executable (HEIMDALL_E2E_BIN)"
            );
            let home = ScratchHome::new();
            // Scripts live apart from the roots the harnesses work in.
            let sources = home.root.join("src");
            let mut written = Vec::new();
            for (name, text) in [("h1", H1_SOURCE), ("h2", H2_SOURCE)] {
                let dir = sources.join(name);
                std::fs::create_dir_all(&dir).unwrap();
                let file = dir.join("harness.py");
                std::fs::write(&file, text).unwrap();
                written.push(file);
            }
            #[cfg(unix)]
            let login = {
                let out = std::process::Command::new("/usr/bin/id")
                    .arg("-un")
                    .env_clear()
                    .output()
                    .unwrap();
                assert!(out.status.success(), "fixture account lookup");
                String::from_utf8(out.stdout).unwrap().trim().to_owned()
            };
            #[cfg(windows)]
            let login = std::env::var("HM_FIXTURE_SSHD_USER").unwrap_or_default();
            Suite {
                home,
                bin,
                python,
                h2: written.pop().unwrap(),
                h1: written.pop().unwrap(),
                login,
            }
        }

        /// A new root with the layout H1 expects: `home`, `heimdall-home` and `ssh-home` with an
        /// empty `etc-ssh`, all owner-only.
        fn root(&self, name: &str) -> PathBuf {
            let root = self.home.root.join(name);
            for dir in [
                root.clone(),
                root.join("home"),
                root.join("heimdall-home"),
                root.join("ssh-home"),
                root.join("ssh-home/etc-ssh"),
            ] {
                std::fs::create_dir(&dir).unwrap();
                #[cfg(unix)]
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
                #[cfg(windows)]
                heimdall_testkit::win::set_owner_only(&dir).unwrap();
            }
            #[cfg(unix)]
            {
                let socket = root.join("heimdall-home/run/control.sock");
                assert!(
                    socket.as_os_str().len() <= SOCKET_PATH_MAX,
                    "the scratch directory is too deep for the runtime's socket path ({} bytes)",
                    socket.as_os_str().len()
                );
            }
            root
        }

        /// The allowlisted environment for pipes and the attended terminal alike.
        fn environment(&self, root: &Path) -> Vec<(&'static str, OsString)> {
            let paths = launch_paths(&self.home.root, root)
                .unwrap_or_else(|e| panic!("launch environment refused before launch: {e}"));
            let mut env = vec![
                ("LANG", "C".into()),
                ("TERM", "dumb".into()),
                ("HEIMDALL_TEST_SECRET_STORE", "scratch".into()),
            ];
            #[cfg(unix)]
            env.push(("PATH", "/usr/bin:/bin:/usr/sbin:/sbin".into()));
            #[cfg(windows)]
            {
                let windows = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"));
                assert!(windows.is_absolute(), "SystemRoot must be absolute");
                let system = windows.join("System32");
                let path = std::env::join_paths([system.join("OpenSSH"), system, windows.clone()])
                    .unwrap();
                env.extend([("SystemRoot", windows.into()), ("PATH", path)]);
                let home = root.join("home").into_os_string();
                for name in [
                    "USERPROFILE",
                    "ProgramData",
                    "ALLUSERSPROFILE",
                    "APPDATA",
                    "LOCALAPPDATA",
                    "TEMP",
                    "TMP",
                ] {
                    env.push((name, home.clone()));
                }
            }
            env.extend(paths);
            env
        }

        /// `program` in `root`, with the checked launch environment and nothing else.
        fn command(&self, root: &Path, program: &Path) -> Command {
            let mut cmd = Command::new(program);
            cmd.env_clear()
                .envs(self.environment(root))
                .current_dir(root)
                .kill_on_drop(true);
            cmd
        }

        fn heimdall(&self, root: &Path, args: &[&str]) -> Command {
            let mut cmd = self.command(root, &self.bin);
            cmd.args(args);
            cmd
        }

        /// Text for a failure message: no scratch path, no login name, no key material.
        fn redact(&self, bytes: &[u8]) -> String {
            let text = String::from_utf8_lossy(bytes);
            heimdall_testkit::assert_no_canary(&text);
            let scratch = self.home.root.to_string_lossy();
            let real = std::fs::canonicalize(&self.home.root).unwrap();
            let mut text = text
                .replace(&*real.to_string_lossy(), "<scratch>")
                .replace(&*scratch, "<scratch>");
            if !self.login.is_empty() {
                text = text.replace(&self.login, "<login>");
            }
            heimdall_enroll::remote::redact_excerpt(text.as_bytes(), 4096)
        }

        /// One `heimdall --json` call of the driver's own: its exit code and envelope.
        async fn call(&self, root: &Path, args: &[&str]) -> (Option<i32>, Value) {
            let mut all = vec!["--json", "--non-interactive"];
            all.extend_from_slice(args);
            let mut cmd = self.heimdall(root, &all);
            cmd.stdin(Stdio::null());
            let out = tokio::time::timeout(TIMEOUT, cmd.output())
                .await
                .unwrap_or_else(|_| panic!("heimdall {args:?} did not finish"))
                .unwrap();
            let envelope = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
                panic!(
                    "heimdall {args:?}: no envelope; exit {}\nstdout: {}\nstderr: {}",
                    out.status,
                    self.redact(&out.stdout),
                    self.redact(&out.stderr)
                )
            });
            heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stderr));
            (out.status.code(), envelope)
        }

        /// Bindings the runtime of `root` still reports as active.
        async fn active_bindings(&self, root: &Path) -> Vec<Value> {
            let (code, listed) = self.call(root, &["inspect", "bindings"]).await;
            assert_eq!(code, Some(0), "{listed}");
            listed["data"]["bindings"]
                .as_array()
                .expect("a binding list")
                .iter()
                .filter(|binding| binding["state"] == "active")
                .cloned()
                .collect()
        }
    }

    /// The `ssh` client of every fixture login: the one on the `PATH` on Unix, and the in-box
    /// OpenSSH client (`%SystemRoot%\System32\OpenSSH\ssh.exe`) on Windows.
    fn ssh_client() -> PathBuf {
        #[cfg(unix)]
        let ssh = find_program("ssh").expect("ssh client");
        #[cfg(windows)]
        let ssh = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
            .join("System32")
            .join("OpenSSH")
            .join("ssh.exe");
        assert!(
            ssh.is_absolute() && ssh.is_file(),
            "blocked: journey not run; the ssh client is missing"
        );
        ssh
    }

    // ---- the existing-access world (as `cli_m07.rs` builds it) ------------------------------

    fn owner(root: &Path) -> Caller {
        #[cfg(unix)]
        let principal = {
            use std::os::unix::fs::MetadataExt as _;
            PrincipalRef::UnixUser {
                uid: std::fs::metadata(root).unwrap().uid(),
            }
        };
        #[cfg(windows)]
        let principal: PrincipalRef = {
            assert!(root.is_dir());
            heimdall_testkit::win::current_principal().unwrap()
        };
        Caller {
            context: CallerContext {
                principal,
                role: ClientRole::Owner,
                remote_client: None,
            },
            attendance: Attendance::Attended {
                since: heimdall_contract::Timestamp::now(),
            },
            interaction: InteractionMode::Interactive,
        }
    }

    /// Fixture setup only: the saved profile's own decisions are approved in process.
    async fn approve_seed(ops: &Operations, caller: &Caller, pending: OpError) {
        let id = pending.next.decision_ref.expect("pending owner decision");
        ops.decide(
            caller,
            DecideRequest {
                decision_id: DecisionId::parse(&id).unwrap(),
                verdict: Verdict::Approve,
            },
        )
        .await
        .unwrap();
    }

    /// Adopt the fixture key from the disposable agent, add destination `lab` (the loopback
    /// sshd), save profile [`PROFILE`], apply the projection, and approve the profile's policy.
    async fn seed(
        ops: &Operations,
        caller: &Caller,
        sshd: &LoopbackSshd,
        account: &AccountName,
        key: &FixtureKey,
        agent: &FakeAgent,
    ) {
        let rid = |value| RequestId::parse(value).unwrap();
        let adopted = ops
            .catalog(
                caller,
                CatalogRequest::AdoptIdentity {
                    identity: IdentitySpec {
                        source: IdentitySourceSpec::NativeAgent {
                            endpoint: EndpointRef {
                                kind: if cfg!(windows) {
                                    EndpointKind::NamedPipe
                                } else {
                                    EndpointKind::UnixSocket
                                },
                                locator: agent.endpoint().locator().to_str().unwrap().to_owned(),
                            },
                        },
                        public_key: key.public_line_without_comment(),
                        label: None,
                    },
                    request_id: rid("adopt-h"),
                },
            )
            .await
            .unwrap();
        let identity = IdentityId::parse(adopted.data["identity_id"].as_str().unwrap()).unwrap();
        let destination = DestinationId::parse("dst-lab").unwrap();
        ops.catalog(
            caller,
            CatalogRequest::UpsertDestination {
                destination: DestinationSpec {
                    id: destination.clone(),
                    alias: "lab".into(),
                    definition: DestinationDefinitionSpec::Managed {
                        hostname: sshd.host.clone(),
                        port: Some(sshd.port),
                        account: account.clone(),
                        identity: identity.clone(),
                        jump: None,
                    },
                    label: None,
                },
                request_id: rid("destination-h"),
            },
        )
        .await
        .unwrap();
        let profile = ProfileId::parse(PROFILE).unwrap();
        ops.catalog(
            caller,
            CatalogRequest::UpsertProfile {
                profile: ProfileSpec {
                    id: profile.clone(),
                    pairs: [AccessPairRef {
                        destination,
                        account: account.clone(),
                    }]
                    .into_iter()
                    .collect(),
                    label: None,
                },
                request_id: rid("profile-h"),
            },
        )
        .await
        .unwrap();
        let preview = ops
            .setup(
                caller,
                SetupRequest::Preview {
                    intent: PreviewIntent::Apply {
                        include_git: false,
                        items: Default::default(),
                        distribution: None,
                    },
                },
            )
            .await
            .unwrap();
        let plan: SetupPlan = serde_json::from_value(preview.data).unwrap();
        let apply = SetupRequest::Apply {
            plan_digest: plan.plan_digest,
            request_id: rid("apply-h"),
        };
        if let Err(pending) = ops.setup(caller, apply.clone()).await {
            approve_seed(ops, caller, pending).await;
            ops.setup(caller, apply).await.unwrap();
        }
        let declare = CatalogRequest::DeclareInteraction {
            identity,
            interaction: DeclaredInteraction::None,
            request_id: rid("declare-h"),
        };
        approve_seed(
            ops,
            caller,
            ops.catalog(caller, declare.clone()).await.unwrap_err(),
        )
        .await;
        ops.catalog(caller, declare).await.unwrap();
        approve_seed(
            ops,
            caller,
            ops.policy(
                caller,
                PolicyAction::Create {
                    profile,
                    environments: [ops.environment().clone()].into_iter().collect(),
                    max_window: None,
                    default: false,
                },
            )
            .await
            .unwrap_err(),
        )
        .await;
    }

    /// What the existing-access worlds share: one fixture sshd, one disposable agent, one key.
    struct Lab {
        sshd: LoopbackSshd,
        agent: FakeAgent,
        key: FixtureKey,
        account: AccountName,
        /// The fixture key's private half, for the pinned login of the fixture children.
        login_key: PathBuf,
    }

    impl Lab {
        fn start(suite: &Suite) -> Lab {
            let key = FixtureKey::generate().with_comment("m07-harness-fixture");
            let agent = FakeAgent::start(
                Endpoint::in_scratch(suite.home.scratch(), "access").unwrap(),
                FakeAgentConfig {
                    keys: vec![key.clone()],
                    mode: AgentMode::Normal,
                },
            );
            let sshd = LoopbackSshd::start(
                suite.home.scratch(),
                SshdConfig {
                    authorized: vec![key.public().clone()],
                    ..SshdConfig::default()
                },
            )
            .unwrap_or_else(|error| panic!("blocked: existing-access journey not run: {error}"));
            #[cfg(unix)]
            let account = sshd.account().unwrap_or(&suite.login);
            #[cfg(windows)]
            let account = sshd.account().expect(
                "blocked: existing-access journey not run; the loopback sshd needs HM_FIXTURE_SSHD_USER",
            );
            let account = AccountName::parse(account).unwrap();
            let login_key = {
                let path = suite.home.root.join("login-key");
                key.write_private(&path).unwrap();
                // The in-box client refuses a key file that others may read.
                #[cfg(windows)]
                heimdall_testkit::win::set_owner_only(&path).unwrap();
                path
            };
            Lab {
                sshd,
                agent,
                key,
                account,
                login_key,
            }
        }

        /// Logins the fixture sshd accepted so far, each checked to be the generated key's.
        fn logins(&self) -> usize {
            let accepted = self.sshd.accepted_log();
            assert!(
                accepted
                    .iter()
                    .all(|login| login.fingerprint == self.key.fingerprint()),
                "the fixture sshd accepted a key this run did not generate"
            );
            accepted.len()
        }

        /// Signing requests the disposable agent received so far for the generated key.
        #[cfg(unix)]
        fn signatures(&self) -> usize {
            let fingerprint = self.key.fingerprint();
            self.agent
                .log()
                .iter()
                .filter(|contact| contact.key_fp.as_deref() == Some(fingerprint.as_str()))
                .count()
        }

        #[cfg(unix)]
        fn seen(&self) -> Seen {
            Seen {
                logins: self.logins(),
                signatures: self.signatures(),
            }
        }
    }

    /// What the fixture sshd and the disposable agent had seen at one moment.
    #[cfg(unix)]
    struct Seen {
        logins: usize,
        signatures: usize,
    }

    /// One harness's existing-access world: an in-process runtime over its root.
    struct ExistingAccess {
        root: PathBuf,
        shutdown: CancellationToken,
        serving: tokio::task::JoinHandle<Result<(), heimdall_runtime::service::ServiceError>>,
    }

    impl ExistingAccess {
        async fn start(suite: &Suite, lab: &Lab, name: &str) -> ExistingAccess {
            let root = suite.root(name);
            launch_paths(&suite.home.root, &root).expect("launch environment");
            let ssh_home = root.join("ssh-home");
            let ssh_dir = ssh_home.join(".ssh");
            std::fs::create_dir(&ssh_dir).unwrap();
            #[cfg(unix)]
            std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            for (file, text) in [
                ("config", String::new()),
                ("known_hosts", format!("{}\n", lab.sshd.host_key_line)),
            ] {
                let path = ssh_dir.join(file);
                std::fs::write(&path, text).unwrap();
                #[cfg(unix)]
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            // Windows has no /dev/null for the client's global known hosts: an empty file.
            #[cfg(windows)]
            std::fs::write(root.join("global_known_hosts"), "").unwrap();
            let paths = Paths::under(&root.join("heimdall-home"));
            let mut projection = ProjectionConfig::new(
                SshPaths::with_test_override(ssh_home.clone(), ssh_home.join("etc-ssh")),
                Platform::current(),
                paths.config_dir.clone(),
            )
            .with_state_dir(paths.state_dir.clone());
            projection.env = Env::from_vars([("HOME", ssh_home.display().to_string())]);
            let mut options = ServiceOptions::with_clock(
                Arc::new(heimdall_runtime::platform::SystemClock::try_new().unwrap()),
                heimdall_testkit::ScriptedTimeSync::new(
                    heimdall_domain::time::SyncStatus::Synchronized,
                ),
            );
            options.projection = ProjectionWiring::Config(Box::new(projection));
            options.existing_access = true;
            let shutdown = CancellationToken::new();
            let service = Service::start_with(paths, Config::default(), options, shutdown.clone())
                .await
                .unwrap();
            seed(
                service.operations(),
                &owner(&root),
                &lab.sshd,
                &lab.account,
                &lab.key,
                &lab.agent,
            )
            .await;
            ExistingAccess {
                root,
                shutdown,
                serving: tokio::spawn(service.run()),
            }
        }

        /// One pinned login to the fixture sshd (alias `lab`) that runs `remote`
        /// ([`login_words`]), with the `ssh` on the `PATH`: the logins of the Unix child. On
        /// Windows the child of task 5 is [`windows_task5_child`].
        #[cfg(unix)]
        fn login(&self, identity: &[&str], key: Option<&Path>, remote: &str) -> Vec<OsString> {
            login_words(&ssh_client(), &self.root, false, identity, key, remote)
        }

        /// Where the child `name` writes what its login through the binding's endpoint printed.
        #[cfg(unix)]
        fn endpoint_login_output(&self, name: &str) -> PathBuf {
            self.root.join(format!("{name}.endpoint-login"))
        }

        /// A child program inside the root. It makes two pinned logins to the fixture sshd.
        ///
        /// 1. **Through the binding's own signing endpoint (M07-W3-R02).** `heimdall run` sets
        ///    the child's `SSH_AUTH_SOCK` to it. The child goes on only when that names the
        ///    disposable agent of this run (exit 96 otherwise: no other agent is ever asked).
        ///    It then logs in with that agent and no key file, and the login's output goes to
        ///    [`Self::endpoint_login_output`]. A dead endpoint fails here (exit 97).
        /// 2. **Isolated.** Every agent and default identity is switched off; the key is the
        ///    fixture's, by `-i`. This login runs `remote` and is what the harness watches.
        #[cfg(unix)]
        fn child(&self, lab: &Lab, name: &str, remote: &str) -> PathBuf {
            let through_endpoint = self.login(
                &["IdentitiesOnly=no", "IdentityAgent=SSH_AUTH_SOCK"],
                None,
                &format!("echo {name}-endpoint-login"),
            );
            let isolated = self.login(
                &["IdentitiesOnly=yes", "IdentityAgent=none"],
                Some(&lab.login_key),
                remote,
            );
            let script = self.root.join(name);
            let text = format!(
                "#!/bin/sh\n[ \"${{SSH_AUTH_SOCK-}}\" = {expected} ] || exit 96\n\
                 {through_endpoint} </dev/null >{output} || exit 97\nexec {isolated}\n",
                expected = sh_join(&[lab.agent.endpoint().locator()]),
                through_endpoint = sh_join(&through_endpoint),
                output = sh_join(&[self.endpoint_login_output(name).into()]),
                isolated = sh_join(&isolated),
            );
            std::fs::write(&script, text).unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            script
        }

        /// The child of task 5 as `heimdall run` starts it, program first. On Unix it is
        /// [`Self::child`], which makes both logins. On Windows it is the **in-box OpenSSH
        /// client** itself, with `-F <scratch config>` and the isolated option set on its own
        /// command line (the `run -- ssh` form): it makes the isolated login only (see the
        /// module documentation, "On Windows").
        fn task5_child(&self, lab: &Lab, name: &str, remote: &str) -> Vec<OsString> {
            #[cfg(unix)]
            {
                vec![self.child(lab, name, remote).into()]
            }
            #[cfg(windows)]
            {
                let _ = name;
                windows_task5_child(&ssh_client(), &self.root, &lab.login_key, remote)
            }
        }

        async fn stop(self) {
            self.shutdown.cancel();
            tokio::time::timeout(TIMEOUT, self.serving)
                .await
                .expect("the in-process runtime stops")
                .unwrap()
                .unwrap();
        }
    }

    /// One pinned login to the fixture sshd (alias `lab`) that runs `remote`, for the world
    /// whose root is `root`, with `client` on the platform `windows` names: the option set
    /// every fixture login shares, then `identity`, which says where the key comes from. Pure
    /// data, so [`every_windows_goal_starting_the_in_box_client_carries_the_isolation`] reads
    /// the Windows form on every platform.
    fn login_words(
        client: &Path,
        root: &Path,
        windows: bool,
        identity: &[&str],
        key: Option<&Path>,
        remote: &str,
    ) -> Vec<OsString> {
        let ssh_dir = root.join("ssh-home/.ssh");
        let mut words: Vec<OsString> = vec![client.into(), "-T".into(), "-F".into()];
        words.push(ssh_dir.join("config").into());
        let global = if windows {
            format!(
                "GlobalKnownHostsFile={}",
                ssh_option_path(&root.join("global_known_hosts"))
            )
        } else {
            "GlobalKnownHostsFile=/dev/null".to_owned()
        };
        for option in [
            "IdentityFile=none",
            "CertificateFile=none",
            "ControlMaster=no",
            "ControlPath=none",
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            global.as_str(),
        ]
        .iter()
        .chain(identity)
        {
            words.push("-o".into());
            words.push(option.into());
        }
        words.push("-o".into());
        words.push(
            format!(
                "UserKnownHostsFile={}",
                ssh_option_path(&ssh_dir.join("known_hosts"))
            )
            .into(),
        );
        if let Some(key) = key {
            words.push("-i".into());
            words.push(key.into());
        }
        words.push("lab".into());
        words.push(remote.into());
        words
    }

    /// The child of task 5 on Windows (module documentation, "On Windows"): the in-box
    /// `client` itself, with the isolated option set on its own command line. The harnesses
    /// add no isolation to a child they did not build (M07-W7-R02), so this is all the
    /// isolation the client gets.
    fn windows_task5_child(client: &Path, root: &Path, key: &Path, remote: &str) -> Vec<OsString> {
        login_words(
            client,
            root,
            true,
            &["IdentitiesOnly=yes", "IdentityAgent=none"],
            Some(key),
            remote,
        )
    }

    // ---- the fixture-adapter world (the real binary's runtime) ------------------------------

    struct FixtureAdapter {
        root: PathBuf,
        runtime: Child,
    }

    impl FixtureAdapter {
        async fn start(suite: &Suite, name: &str) -> FixtureAdapter {
            let root = suite.root(name);
            let mut cmd = suite.heimdall(&root, &["--non-interactive", "service", "run"]);
            cmd.env("HEIMDALL_TEST_ADAPTER", "prepare")
                .env("HEIMDALL_TEST_SLOW_PREPARE_MS", SLOW_PREPARE_MS)
                .env("HEIMDALL_TEST_TIME_SYNC", "synchronized")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let mut runtime = cmd.spawn().unwrap();
            let deadline = tokio::time::Instant::now() + TIMEOUT;
            loop {
                let mut status = suite.heimdall(&root, &["--json", "--non-interactive", "status"]);
                status.stdin(Stdio::null());
                let out = tokio::time::timeout(TIMEOUT, status.output())
                    .await
                    .expect("status answers")
                    .unwrap();
                if out.status.success() {
                    break;
                }
                assert!(
                    runtime.try_wait().unwrap().is_none(),
                    "the fixture runtime exited during startup"
                );
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the fixture runtime did not start"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            FixtureAdapter { root, runtime }
        }

        async fn stop(mut self, suite: &Suite) {
            let (code, stopped) = suite.call(&self.root, &["service", "stop"]).await;
            assert_eq!(code, Some(0), "service stop: {stopped}");
            let status = tokio::time::timeout(TIMEOUT, self.runtime.wait())
                .await
                .expect("the fixture runtime exits after `service stop`")
                .unwrap();
            assert!(status.success(), "the fixture runtime exited cleanly");
            assert_no_fixture_stores(&self.root);
        }
    }

    // ---- the human step ---------------------------------------------------------------------

    /// What the person at the terminal does for task 3: read the pending decision, check that
    /// it asks for exactly the missing pair of this operation, and approve it through the real
    /// CLI on a pseudo-terminal, typing `yes` at its prompt.
    async fn approve_at_a_terminal(suite: &Suite, root: &Path, handoff: &Value) {
        let decision = handoff["decision_ref"]
            .as_str()
            .expect("a decision reference");
        let operation = handoff["operation_id"].as_str().expect("an operation");
        for (id, prefix) in [(decision, "dec_"), (operation, "op_")] {
            let rest = id.strip_prefix(prefix).unwrap_or_default();
            assert!(
                !rest.is_empty() && rest.len() <= 64 && rest.bytes().all(|b| b.is_ascii_hexdigit()),
                "the handoff names a malformed reference"
            );
        }
        let (code, listed) = suite.call(root, &["decision", "list"]).await;
        assert_eq!(code, Some(0), "{listed}");
        let pending = listed["data"]["decisions"].as_array().expect("decisions");
        assert_eq!(
            pending.len(),
            1,
            "exactly one decision is pending: {listed}"
        );
        assert_eq!(pending[0]["decision_id"], decision);
        assert_eq!(pending[0]["state"], "pending");
        assert_eq!(pending[0]["kind"], "approve_authority");
        assert_eq!(pending[0]["request"]["operation_id"], operation);
        assert_eq!(
            pending[0]["request"]["delta"]["added_scope"]["pairs"],
            json!([{"account": "deploy", "destination": "h3"}]),
            "the request asks for only the missing pair"
        );

        let mut cmd = TerminalCommand::new(&suite.bin)
            .args(["decision", "approve", decision])
            .current_dir(root);
        for (name, value) in suite.environment(root) {
            cmd = cmd.env(name, value);
        }
        let (status, answered, transcript) = tokio::task::spawn_blocking(move || {
            let mut terminal = cmd.spawn().unwrap_or_else(|error| {
                if cfg!(unix) && error.kind() == std::io::ErrorKind::NotFound {
                    panic!("blocked: script(1) is needed for the terminal approval");
                }
                panic!("the approval terminal did not start: {}", error.kind());
            });
            let answered =
                terminal.expect("[y/N]:", TIMEOUT).is_ok() && terminal.send(b"yes\r").is_ok();
            let status = answered.then(|| terminal.wait(TIMEOUT)).flatten();
            (status, answered, terminal.text())
        })
        .await
        .unwrap();
        heimdall_testkit::assert_no_canary(&transcript);
        assert!(
            status == Some(0) && answered && transcript.contains(decision),
            "approve on the terminal: exit {status:?}, typed yes: {answered}: {}",
            suite.redact(transcript.as_bytes())
        );
    }

    // ---- running a harness ------------------------------------------------------------------

    /// Run one harness invocation to its end and return its summary. A handoff line on stderr
    /// (`decision_ref`, `operation_id`) gets the human step, then `continue` on stdin.
    async fn run_harness(
        suite: &Suite,
        root: &Path,
        source: &Path,
        args: Vec<OsString>,
        expect_handoffs: usize,
    ) -> Value {
        let mut cmd = suite.command(root, &suite.python);
        cmd.args(["-I", "-B"])
            .arg(source)
            .arg("--heimdall-bin")
            .arg(&suite.bin)
            .arg("--scratch-root")
            .arg(root)
            .args(args)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let mut stdin = child.stdin.take();
        if expect_handoffs == 0 {
            stdin = None; // closed: a harness that asks for a person gets end-of-file
        }
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = BufReader::new(child.stderr.take().unwrap()).lines();
        let reader = tokio::spawn(async move {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).await.map(|_| bytes)
        });
        let mut diagnostics = String::new();
        let mut handoffs = 0;
        let finished = tokio::time::timeout(HARNESS_TIMEOUT, async {
            while let Some(line) = stderr.next_line().await.unwrap() {
                heimdall_testkit::assert_no_canary(&line);
                match serde_json::from_str::<Value>(&line) {
                    Ok(handoff) if handoff["decision_ref"].is_string() => {
                        handoffs += 1;
                        assert!(handoffs <= expect_handoffs, "an unexpected handoff");
                        approve_at_a_terminal(suite, root, &handoff).await;
                        let terminal = stdin.as_mut().expect("the harness's stdin");
                        terminal.write_all(b"continue\n").await.unwrap();
                        terminal.flush().await.unwrap();
                    }
                    _ => {
                        diagnostics.push_str(&line);
                        diagnostics.push('\n');
                    }
                }
            }
            child.wait().await.unwrap()
        })
        .await;
        let Ok(status) = finished else {
            panic!(
                "the harness did not finish: {}",
                suite.redact(diagnostics.as_bytes())
            );
        };
        let output = tokio::time::timeout(TIMEOUT, reader)
            .await
            .expect("the harness's stdout closes")
            .unwrap()
            .unwrap();
        let text = String::from_utf8_lossy(&output);
        heimdall_testkit::assert_no_canary(&text);
        let summary: Value = serde_json::from_str(text.trim_end()).unwrap_or_else(|_| {
            panic!(
                "the harness printed no summary; exit {status}\nstdout: {}\nstderr: {}",
                suite.redact(&output),
                suite.redact(diagnostics.as_bytes())
            )
        });
        assert!(
            status.success() && handoffs == expect_handoffs,
            "the harness failed: exit {status}, {handoffs} handoffs\nsummary: {}\nstderr: {}",
            suite.redact(&output),
            suite.redact(diagnostics.as_bytes())
        );
        assert_eq!(text.lines().count(), 1, "one summary line");
        assert_no_fixture_stores(root);
        summary
    }

    fn words(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    /// The §5a task a harness's own task name stands for.
    fn task_number(name: &str) -> u64 {
        match name {
            "discover" => 1,
            "covered" => 2,
            "approval" => 3,
            "timeout" => 4,
            "bind-run" => 5,
            "release" | "stop" => 6,
            "capability-refusal" => 7,
            other => panic!("a harness reported an unknown task {other:?}"),
        }
    }

    /// The recorded fields of one task (m07-plan §5a "Recorded per task and harness").
    fn records(harness: &str, world: &str, summary: &Value) -> Vec<Value> {
        assert_eq!(summary["harness"], harness);
        summary["tasks"]
            .as_array()
            .expect("task records")
            .iter()
            .map(|task| {
                json!({
                    "harness": harness,
                    "task": task_number(task["task"].as_str().expect("a task name")),
                    "name": task["task"],
                    "world": world,
                    "success": task["success"],
                    "calls": task["calls"],
                    "round_trips": task["round_trips"],
                    "human_handoffs": task["human_handoffs"],
                    "invalid_retries": task["invalid_retries"],
                    "wall_time_ms": task["wall_time_ms"],
                    "discovery_bytes": task["discovery_bytes"],
                    "detail": task["detail"],
                })
            })
            .collect()
    }

    /// After a harness's existing-access tasks (Unix).
    ///
    /// The child `name` of task 5 logged in twice, each time with the generated key: once
    /// through the signing endpoint its binding gave it, which the disposable agent signed for,
    /// and once isolated, from the key file.
    #[cfg(unix)]
    fn check_logins(lab: &Lab, world: &ExistingAccess, name: &str, before: &Seen) {
        assert_eq!(
            std::fs::read_to_string(world.endpoint_login_output(name)).ok(),
            Some(format!("{name}-endpoint-login\n")),
            "the child of task 5 logged in through the endpoint its binding gave it"
        );
        assert!(
            lab.signatures() > before.signatures,
            "the disposable agent signed for the login through the binding's endpoint"
        );
        assert_eq!(
            lab.logins(),
            before.logins + 2,
            "the child of task 5 logged in to the fixture sshd exactly twice"
        );
    }

    /// After a harness's existing-access tasks (Windows): the child of task 5, the in-box
    /// `ssh.exe`, logged in to the fixture sshd exactly once, isolated, with the generated key.
    #[cfg(windows)]
    fn check_logins(lab: &Lab, before: usize) {
        assert_eq!(
            lab.logins(),
            before + 1,
            "the child of task 5 logged in to the fixture sshd exactly once, with the generated key"
        );
    }

    async fn check_no_active_bindings(suite: &Suite, world: &ExistingAccess) {
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            let active = suite.active_bindings(&world.root).await;
            if active.is_empty() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "bindings are still active after the stop: {}",
                active.len()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// After a harness's fixture-adapter tasks and its cleanup: no decision is left pending and
    /// no binding is left active.
    async fn check_fixture_adapter(suite: &Suite, world: &FixtureAdapter) {
        let (code, listed) = suite.call(&world.root, &["decision", "list"]).await;
        assert_eq!(code, Some(0), "{listed}");
        let pending = listed["data"]["decisions"].as_array().expect("decisions");
        assert!(
            pending.iter().all(|d| d["state"] != "pending"),
            "a decision is still pending: {listed}"
        );
        let active = suite.active_bindings(&world.root).await;
        assert!(
            active.is_empty(),
            "bindings are still active after the harness's tasks: {}",
            active.len()
        );
    }

    /// Take the cleanup that follows a world's tasks off a summary: its last record, named
    /// `name`, which made `releases` calls and succeeded. It is not one of the seven tasks.
    fn take_cleanup(summary: &mut Value, name: &str, releases: u64) -> Value {
        let cleanup = summary["tasks"]
            .as_array_mut()
            .expect("task records")
            .pop()
            .expect("a cleanup record");
        assert_eq!(
            (
                &cleanup["task"],
                &cleanup["success"],
                cleanup["calls"].as_u64()
            ),
            (&json!(name), &json!(true), Some(releases)),
            "the cleanup released each binding once: {cleanup}"
        );
        cleanup
    }

    /// What the child of H1's task 5 runs on the fixture sshd.
    const H1_CHILD_REMOTE: &str = "echo h1-fixture-child";
    /// What the child of H2's task 5 runs: it reports that it is up, then holds its login open
    /// until its input ends.
    const H2_CHILD_REMOTE: &str = "echo h2-fixture-child; cat";

    /// H1's existing-access invocation, `child` (program first) as the child of task 5.
    fn h1_existing_args(child: Vec<OsString>) -> Vec<OsString> {
        let mut args = words(&[
            "--profile",
            PROFILE,
            "--task",
            "discover",
            "--task",
            "covered",
            "--task",
            "bind-run",
            "--task",
            "release",
            "--task",
            "capability-refusal",
            "--child",
        ]);
        args.extend(child);
        args
    }

    /// H1's two fixture-adapter invocations: tasks 3 and 4, each with its cleanup.
    fn h1_adapter_args() -> [Vec<OsString>; 2] {
        [
            words(&[
                "--profile",
                "dev",
                "--approval-pair",
                "h3:deploy",
                "--task",
                "approval",
                "--task",
                "release",
            ]),
            words(&["--profile", "ops", "--task", "timeout", "--task", "release"]),
        ]
    }

    /// H2's existing-access goals, `child` (program first) as the child of task 5.
    fn h2_existing_goals(child: &[String]) -> Vec<Value> {
        let work = "h2-lab-work";
        vec![
            json!({"goal": "discover"}),
            json!({"task": "covered", "goal": "access", "profile": PROFILE, "work_id": work}),
            json!({"task": "bind-run", "goal": "run", "profile": PROFILE, "work_id": work,
                   "argv": child}),
            json!({"goal": "stop"}),
            json!({"task": "capability-refusal", "goal": "access", "profile": PROFILE,
                   "work_id": "h2-unattended-work", "require_unattended": true,
                   "expect_refusal": "CAPABILITY_UNAVAILABLE"}),
        ]
    }

    /// H2's fixture-adapter goals.
    fn h2_adapter_goals() -> Vec<Value> {
        vec![
            json!({"task": "approval", "goal": "access", "profile": "dev",
                   "work_id": "h2-wider-work", "pairs": ["h3:deploy"]}),
            json!({"task": "timeout", "goal": "access", "profile": "ops",
                   "work_id": "h2-slow-work", "timeout_ms": 1}),
            // Tasks 3 and 4 each end holding a binding: release both before the record.
            json!({"task": "cleanup", "goal": "stop"}),
        ]
    }

    async fn run_h1_existing(suite: &Suite, lab: &Lab) -> Vec<Value> {
        let world = ExistingAccess::start(suite, lab, "h1e").await;
        #[cfg(unix)]
        let before = lab.seen();
        #[cfg(windows)]
        let before = lab.logins();
        let args = h1_existing_args(world.task5_child(lab, "h1-child", H1_CHILD_REMOTE));
        let summary = run_harness(suite, &world.root, &suite.h1, args, 0).await;
        #[cfg(unix)]
        check_logins(lab, &world, "h1-child", &before);
        #[cfg(windows)]
        check_logins(lab, before);
        check_no_active_bindings(suite, &world).await;
        world.stop().await;
        records("H1", "existing-access", &summary)
    }

    async fn run_h1_adapter(suite: &Suite) -> Vec<Value> {
        let mut out = Vec::new();
        // Tasks 3 and 4 each end holding a binding. H1 releases it with its `release` task at
        // the end of the same invocation: a cleanup, not a second task 6.
        let world = FixtureAdapter::start(suite, "h1f").await;
        let [approval, timeout] = h1_adapter_args();
        let mut summary = run_harness(suite, &world.root, &suite.h1, approval, 1).await;
        take_cleanup(&mut summary, "release", 1);
        out.extend(records("H1", "fixture-adapter", &summary));
        let mut summary = run_harness(suite, &world.root, &suite.h1, timeout, 0).await;
        take_cleanup(&mut summary, "release", 1);
        out.extend(records("H1", "fixture-adapter", &summary));
        check_fixture_adapter(suite, &world).await;
        world.stop(suite).await;
        out
    }

    fn goals(list: &[Value]) -> Vec<OsString> {
        list.iter()
            .flat_map(|goal| [OsString::from("--goal"), goal.to_string().into()])
            .collect()
    }

    /// H2's own record of how it moved: every step came from its transition table.
    fn check_h2_paths(summary: &Value, expected: &[(&str, &[&str])]) {
        assert!(
            summary["call_set"]
                .as_str()
                .is_some_and(|source| source.contains("held for U4b")),
            "H2 says where its call set came from"
        );
        let tasks = summary["tasks"].as_array().expect("task records");
        assert_eq!(tasks.len(), expected.len());
        for (task, (name, path)) in tasks.iter().zip(expected) {
            assert_eq!(task["task"], *name);
            let steps = task["transitions"].as_array().expect("transitions");
            assert!(
                steps.iter().all(|step| step["by_table"] == true),
                "{name}: a step did not come from the transition table: {task}"
            );
            let states: Vec<&str> = steps.iter().map(|s| s["to"].as_str().unwrap()).collect();
            assert_eq!(states, *path, "{name}: {task}");
        }
    }

    /// The bindings H2 reports holding once the child of task 5 runs: the one task 2 prepared,
    /// and the child's own when the build made another for the same work. Read from H2's typed
    /// records only.
    fn h2_held_for_the_run(tasks: &Value) -> Vec<String> {
        let (covered, running) = (&tasks[1], &tasks[2]);
        let prepared = covered["final_state"]["binding_id"]
            .as_str()
            .expect("task 2 ends holding a binding");
        let bound = running["final_state"]["binding_id"]
            .as_str()
            .expect("task 5 runs its child under a binding");
        assert_eq!(covered["held"], json!([prepared]), "{covered}");
        let held: Vec<String> = running["held"]
            .as_array()
            .expect("H2 reports what it holds")
            .iter()
            .map(|id| id.as_str().expect("a binding ID").to_owned())
            .collect();
        let expected: Vec<&str> = if prepared == bound {
            vec![prepared]
        } else {
            vec![prepared, bound]
        };
        assert_eq!(
            held, expected,
            "H2 holds the prepared binding and the child's: {running}"
        );
        held
    }

    /// H2's existing-access tasks. On Windows the child of task 5 is the in-box `ssh.exe`
    /// itself, which H2 starts through `heimdall run` and reads by its `spawned` run record.
    async fn run_h2_child(suite: &Suite, lab: &Lab, world: &ExistingAccess) -> Value {
        let child: Vec<String> = world
            .task5_child(lab, "h2-child", H2_CHILD_REMOTE)
            .iter()
            .map(|word| word.to_str().expect("a UTF-8 child argument").to_owned())
            .collect();
        #[cfg(unix)]
        let before = lab.seen();
        #[cfg(windows)]
        let before = lab.logins();
        let summary = run_harness(
            suite,
            &world.root,
            &suite.h2,
            goals(&h2_existing_goals(&child)),
            0,
        )
        .await;
        // Task 5 is a request of its own (a new request ID), so the build may bind the child
        // under a second binding for the same work. H2 reports what it holds after each goal;
        // the stop of task 6 is one release for each binding, then `stopped`.
        let held = h2_held_for_the_run(&summary["tasks"]);
        println!(
            "a32 note: H2 held {} binding(s) for one piece of work when task 6 began",
            held.len()
        );
        let mut stop_path = vec!["releasing"; held.len() - 1];
        stop_path.push("stopped");
        check_h2_paths(
            &summary,
            &[
                ("discover", &["discovered"]),
                ("covered", &["ready"]),
                ("bind-run", &["running"]),
                ("stop", &stop_path),
                ("capability-refusal", &["failed"]),
            ],
        );
        let stop = &summary["tasks"][3];
        assert_eq!(
            stop["child_exit_code"], 0,
            "the child of task 5 ended cleanly when task 6 stopped it"
        );
        // ⟨M07 W8; M07-W7-R03⟩ On Windows H2 held the in-box client that heimdall.exe spawned by
        // a handle of its own (it passed the identity checks), and task 6 found it exited at the
        // end of its input.
        #[cfg(windows)]
        {
            let run = &summary["tasks"][2];
            assert_eq!(
                run["spawned_child"]["held"], true,
                "H2 held the child Heimdall spawned: {run}"
            );
            assert_eq!(
                (
                    &stop["spawned_child"]["pid"],
                    &stop["spawned_child"]["ended"],
                    &stop["spawned_child"]["exit_code"]
                ),
                (&run["spawned_child"]["pid"], &json!("exited"), &json!(0)),
                "task 6 found the held child exited: {stop}"
            );
        }
        assert_eq!(
            (stop["calls"].as_u64(), &stop["held"]),
            (Some(held.len() as u64), &json!([])),
            "task 6 released each binding H2 held, once: {stop}"
        );
        assert_eq!(
            summary["close"],
            json!({"released": [], "held": []}),
            "H2 had nothing left to release when it closed"
        );
        #[cfg(unix)]
        check_logins(lab, world, "h2-child", &before);
        #[cfg(windows)]
        check_logins(lab, before);
        summary
    }

    async fn run_h2_existing(suite: &Suite, lab: &Lab) -> Vec<Value> {
        let world = ExistingAccess::start(suite, lab, "h2e").await;
        let summary = run_h2_child(suite, lab, &world).await;
        check_no_active_bindings(suite, &world).await;
        world.stop().await;
        records("H2", "existing-access", &summary)
    }

    async fn run_h2_adapter(suite: &Suite) -> Vec<Value> {
        let world = FixtureAdapter::start(suite, "h2f").await;
        let mut summary =
            run_harness(suite, &world.root, &suite.h2, goals(&h2_adapter_goals()), 1).await;
        check_h2_paths(
            &summary,
            &[
                ("approval", &["pending_approval", "ready"]),
                ("timeout", &["observing", "ready"]),
                ("cleanup", &["releasing", "stopped"]),
            ],
        );
        assert_eq!(
            (
                &summary["tasks"][1]["held"].as_array().map(Vec::len),
                &summary["close"]
            ),
            (&Some(2), &json!({"released": [], "held": []})),
            "H2 held one binding for each of tasks 3 and 4, and its stop left none to close"
        );
        let cleanup = take_cleanup(&mut summary, "cleanup", 2);
        assert_eq!(cleanup["held"], json!([]), "{cleanup}");
        check_fixture_adapter(suite, &world).await;
        world.stop(suite).await;
        records("H2", "fixture-adapter", &summary)
    }

    /// The shape of the composition record (the evidence file itself is the integrator's).
    fn check_composition(composition: &Value, expected: &[u64]) {
        let records = composition["records"].as_array().expect("records");
        assert_eq!(
            records.len(),
            expected.len() * 2,
            "tasks for both harnesses"
        );
        for harness in ["H1", "H2"] {
            let mut tasks: Vec<u64> = records
                .iter()
                .filter(|record| record["harness"] == harness)
                .map(|record| record["task"].as_u64().expect("a task number"))
                .collect();
            tasks.sort_unstable();
            assert_eq!(tasks, expected, "{harness} ran each selected task once");
        }
        for record in records {
            let task = record["task"].as_u64().unwrap();
            let count = |field: &str| {
                record[field]
                    .as_u64()
                    .unwrap_or_else(|| panic!("{field} is a count: {record}"))
            };
            assert_eq!(record["success"], true, "{record}");
            assert!(count("calls") >= 1, "{record}");
            assert_eq!(count("round_trips"), count("calls"), "{record}");
            assert_eq!(
                count("invalid_retries"),
                0,
                "zero invalid retries: {record}"
            );
            assert_eq!(count("human_handoffs"), u64::from(task == 3), "{record}");
            assert_eq!(count("discovery_bytes") > 0, task == 1, "{record}");
            let wall = record["wall_time_ms"].as_f64().expect("wall time");
            assert!((0.0..120_000.0).contains(&wall), "{record}");
            assert!(record["world"].is_string() && record["name"].is_string());
            match task {
                // `ACCESS_READY` in one intent-level request; the refusal is met in one too.
                2 | 7 => assert_eq!(count("calls"), 1, "{record}"),
                // The request, then one observation of the same operation: never a repeat.
                4 => assert_eq!(count("calls"), 2, "{record}"),
                _ => {}
            }
        }
    }

    fn record_composition(suite: &Suite, mut records: Vec<Value>, expected: &[u64], held: &[&str]) {
        records.sort_by_key(|r| (r["harness"].as_str().map(str::to_owned), r["task"].as_u64()));
        let mut held_items = vec![
            "H2 loads its call set from a local table until schema show primitives is served (U4b)",
        ];
        held_items.extend_from_slice(held);
        let composition = json!({
            "case": "A32",
            "tasks": expected,
            "platform": format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            "harnesses": ["H1", "H2"],
            "held": held_items,
            "records": records,
        });
        // Written into the scratch root and read back: what is checked is what was recorded.
        let file = suite.home.root.join("m07-a32-composition.json");
        std::fs::write(&file, serde_json::to_vec_pretty(&composition).unwrap()).unwrap();
        let recorded: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        check_composition(&recorded, expected);
        for record in recorded["records"].as_array().unwrap() {
            println!("a32 record: {record}");
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn both_harnesses_complete_the_deterministic_tasks() {
        let suite = Suite::new();
        let lab = Lab::start(&suite);
        let mut records = run_h1_existing(&suite, &lab).await;
        records.extend(run_h1_adapter(&suite).await);
        records.extend(run_h2_existing(&suite, &lab).await);
        records.extend(run_h2_adapter(&suite).await);
        record_composition(&suite, records, &[1, 2, 3, 4, 5, 6, 7], &[]);
    }

    /// What the Windows run of task 5 does not prove (module documentation, "On Windows"),
    /// and ⟨M07 W8; M07-W7-R03⟩ the Windows check of H2's hold on the child that is still to
    /// run on the PC.
    #[cfg(windows)]
    const WINDOWS_HELD: [&str; 2] = [
        "task 5 on Windows: the child is the in-box ssh.exe with the isolated options, so it makes no login through the binding's signing endpoint (M07-W3-R02 is proven on Unix)",
        "H2 on Windows (M07-W7-R03): H2 holds the child the spawned record names by a handle of its own, opened when the record is read and checked by identity (its parent is the heimdall.exe H2 started, it was created after it, it runs the goal's program), and ends it by that handle; the Windows check of a child that ignores the end of its input (goal-loop PlannerTests.test_windows_the_child_heimdall_spawned_is_ended_by_its_own_handle) is pending the PC run",
    ];

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn both_harnesses_use_the_fixture_adapter_on_windows() {
        let suite = Suite::new();
        let mut records = run_h1_adapter(&suite).await;
        records.extend(run_h2_adapter(&suite).await);
        record_composition(&suite, records, &[3, 4], &[]);
    }

    /// Tasks 1, 2, 5, 6 and 7 on Windows. The child of task 5 is the **in-box OpenSSH client**,
    /// `%SystemRoot%\System32\OpenSSH\ssh.exe`, started by `heimdall run` with
    /// `-F <scratch config>` and the isolated option set on its own command line; it makes the
    /// isolated login, which the driver checks in the fixture sshd's log (see
    /// [`WINDOWS_HELD`]).
    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn both_harnesses_use_existing_access_on_windows() {
        let suite = Suite::new();
        let lab = Lab::start(&suite);
        let mut records = run_h1_existing(&suite, &lab).await;
        records.extend(run_h2_existing(&suite, &lab).await);
        record_composition(&suite, records, &[1, 2, 5, 6, 7], &WINDOWS_HELD);
    }

    // ---- M07-W7-R02: the Windows children, read as data on every platform ------------------

    /// Whether `program` names the in-box OpenSSH client (`…\System32\OpenSSH\ssh.exe`, any
    /// case, either separator).
    fn is_in_box_client(program: &str) -> bool {
        program
            .replace('\\', "/")
            .to_ascii_lowercase()
            .ends_with("/system32/openssh/ssh.exe")
    }

    /// An `ssh_config` value as [`ssh_option_path`] wrote it: one pair of double quotes with
    /// `\` and `"` escaped removed, and `%%` read as `%`.
    fn ssh_value(value: &str) -> String {
        let text = match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            Some(inner) => {
                let mut out = String::new();
                let mut chars = inner.chars();
                while let Some(c) = chars.next() {
                    out.push(if c == '\\' {
                        chars.next().unwrap_or(c)
                    } else {
                        c
                    });
                }
                out
            }
            None => value.to_owned(),
        };
        text.replace("%%", "%")
    }

    /// Whether an `ssh_config` value names a path inside `root`: absolute, no `.` or `..`.
    fn inside(root: &Path, value: &str) -> bool {
        let path = PathBuf::from(ssh_value(value));
        path.is_absolute()
            && !path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            && path.starts_with(root)
    }

    /// Why the in-box client's `argv` (program first) lacks the isolation the harnesses do not
    /// add (M07-W7-R02), if it does: exactly one `-F` naming a file inside `root`, and once
    /// each `IdentityAgent=none`, `IdentitiesOnly=yes`, and `UserKnownHostsFile` and
    /// `GlobalKnownHostsFile` whose every entry is inside `root`.
    fn in_box_isolation(argv: &[String], root: &Path) -> Result<(), String> {
        let mut configs = Vec::new();
        let mut options: Vec<(String, String)> = Vec::new();
        let mut words = argv.iter().skip(1);
        while let Some(word) = words.next() {
            let (flag, rest) = if let Some(rest) = word.strip_prefix("-F") {
                ('F', rest)
            } else if let Some(rest) = word.strip_prefix("-o") {
                ('o', rest)
            } else {
                continue;
            };
            let value = if rest.is_empty() {
                match words.next() {
                    Some(value) => value.clone(),
                    None => return Err(format!("-{flag} has no value")),
                }
            } else {
                rest.to_owned()
            };
            if flag == 'F' {
                configs.push(value);
            } else {
                let (name, value) = value.split_once(['=', ' ']).unwrap_or((&value, ""));
                options.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
            }
        }
        let [config] = configs.as_slice() else {
            return Err("not exactly one -F".to_owned());
        };
        if !inside(root, config) {
            return Err("the -F file is outside the scratch root".to_owned());
        }
        let once = |name: &str| -> Result<String, String> {
            let values: Vec<&String> = options
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, v)| v)
                .collect();
            match values.as_slice() {
                [value] => Ok((*value).clone()),
                _ => Err(format!("{name} is not set once")),
            }
        };
        if once("identityagent")? != "none" {
            return Err("IdentityAgent is not none".to_owned());
        }
        if once("identitiesonly")? != "yes" {
            return Err("IdentitiesOnly is not yes".to_owned());
        }
        for name in ["userknownhostsfile", "globalknownhostsfile"] {
            let value = once(name)?;
            let entries: Vec<&str> = if value.starts_with('"') {
                vec![value.as_str()]
            } else {
                value.split_whitespace().collect()
            };
            if entries.is_empty() || !entries.iter().all(|e| inside(root, e)) {
                return Err(format!("{name} is outside the scratch root"));
            }
        }
        Ok(())
    }

    /// Every `run` child the Windows journeys give H1 (`--child` words) and H2 (a goal's
    /// `argv`), across all their invocations and goals, built by the functions the Windows
    /// runs use, with `client` as the in-box client and `root` as the scratch root.
    fn windows_journey_children(client: &Path, root: &Path) -> Vec<(&'static str, Vec<String>)> {
        let key = root.join("login-key");
        let text = |words: &[OsString]| -> Vec<String> {
            words
                .iter()
                .map(|w| w.to_str().expect("a UTF-8 word").to_owned())
                .collect()
        };
        let mut h1 = vec![h1_existing_args(windows_task5_child(
            client,
            &root.join("h1e"),
            &key,
            H1_CHILD_REMOTE,
        ))];
        h1.extend(h1_adapter_args());
        let h2_child = text(&windows_task5_child(
            client,
            &root.join("h2e"),
            &key,
            H2_CHILD_REMOTE,
        ));
        let h2 = [h2_existing_goals(&h2_child), h2_adapter_goals()];
        let mut children = Vec::new();
        for args in &h1 {
            let args = text(args);
            if let Some(at) = args.iter().position(|a| a == "--child") {
                children.push(("H1", args[at + 1..].to_vec()));
            }
        }
        for goal in h2.iter().flatten() {
            if let Some(argv) = goal.get("argv") {
                let argv = argv.as_array().expect("an argv list");
                children.push((
                    "H2",
                    argv.iter()
                        .map(|w| w.as_str().expect("a word").to_owned())
                        .collect(),
                ));
            }
        }
        children
    }

    /// ⟨M07 W7.3; M07-W7-R02⟩ H1 and H2 accept the in-box `ssh.exe` as a `run` child on
    /// Windows and add no isolation to it: the caller's goal decides which ssh profile it
    /// uses. So across **all** goals the Windows journeys give both harnesses, every child
    /// that starts the in-box client carries exactly one `-F <file inside the scratch root>`,
    /// `IdentityAgent=none`, `IdentitiesOnly=yes`, and `UserKnownHostsFile` and
    /// `GlobalKnownHostsFile` inside the scratch root. Read as data, so it runs on every
    /// platform; each missing or widened item is caught.
    #[test]
    fn every_windows_goal_starting_the_in_box_client_carries_the_isolation() {
        let root = Path::new(if cfg!(windows) {
            r"C:\hm-scratch"
        } else {
            "/hm-scratch"
        });
        let client = Path::new(r"C:\Windows\System32\OpenSSH\ssh.exe");
        let children = windows_journey_children(client, root);
        let in_box: Vec<&(&str, Vec<String>)> = children
            .iter()
            .filter(|(_, argv)| argv.first().is_some_and(|p| is_in_box_client(p)))
            .collect();
        assert_eq!(
            in_box.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
            ["H1", "H2"],
            "each harness's task 5 starts the in-box client: {children:?}"
        );
        for (harness, argv) in &in_box {
            assert_eq!(in_box_isolation(argv, root), Ok(()), "{harness}: {argv:?}");
        }
        // The check has teeth: each item missing, doubled or outside the root is caught.
        let argv = &in_box[1].1;
        let outside = root.parent().unwrap().join("elsewhere").join("config");
        let swap = |from: &str, to: &str| -> Vec<String> {
            argv.iter()
                .map(|w| if w == from { to.to_owned() } else { w.clone() })
                .collect()
        };
        let config = argv[argv.iter().position(|w| w == "-F").unwrap() + 1].clone();
        let without = |word: &str| -> Vec<String> {
            let at = argv.iter().position(|w| w == word).unwrap();
            [&argv[..at - 1], &argv[at + 1..]].concat()
        };
        let global = argv
            .iter()
            .find(|w| w.starts_with("GlobalKnownHostsFile="))
            .unwrap()
            .clone();
        let user = argv
            .iter()
            .find(|w| w.starts_with("UserKnownHostsFile="))
            .unwrap()
            .clone();
        let mutations: Vec<(&str, Vec<String>)> = vec![
            ("no -F", without(&config)),
            ("-F outside", swap(&config, &outside.display().to_string())),
            (
                "two -F",
                [
                    argv.clone(),
                    vec!["-F".into(), outside.display().to_string()],
                ]
                .concat(),
            ),
            (
                "the agent",
                swap("IdentityAgent=none", "IdentityAgent=SSH_AUTH_SOCK"),
            ),
            ("no IdentityAgent", without("IdentityAgent=none")),
            (
                "IdentityAgent twice",
                [argv.clone(), vec!["-o".into(), "IdentityAgent=none".into()]].concat(),
            ),
            (
                "IdentitiesOnly",
                swap("IdentitiesOnly=yes", "IdentitiesOnly=no"),
            ),
            ("no IdentitiesOnly", without("IdentitiesOnly=yes")),
            (
                "global known hosts",
                swap(&global, "GlobalKnownHostsFile=/dev/null"),
            ),
            (
                "user known hosts",
                swap(&user, "UserKnownHostsFile=~/.ssh/known_hosts"),
            ),
            ("no user known hosts", without(&user)),
        ];
        for (what, mutated) in mutations {
            assert_ne!(&mutated, argv, "{what}: the mutation changed nothing");
            assert!(
                in_box_isolation(&mutated, root).is_err(),
                "{what}: {mutated:?}"
            );
        }
    }
}
