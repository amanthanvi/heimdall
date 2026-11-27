//! ⟨M06 U2⟩ The M06 command surface through the real binary (m06-plan U2; the orchestrator's
//! naming ruling for the G08 freeze).
//!
//! * `m06_help_goldens`: the `--help` of every M06 command line equals its golden
//!   (`tests/contracts/golden/cli-help-m06/`; `cli-help/` is the M03 suite's, which refuses
//!   any file it does not own, and holds the updated `top-level.txt`); `HM_UPDATE_GOLDENS=1`
//!   rewrites them. The top level lists `environment`, `device`, `route` and `transport`, and
//!   neither `env` nor `roost`; `route` does not list the frozen `connect`, whose own help
//!   is reachable by name only.
//! * `show_key_creates_k_mgmt_once_and_a_locked_store_refuses`: `environment join
//!   --show-key` with the fixture K_mgmt store (test configuration, test kind: mechanism
//!   evidence, never a product claim) creates K_mgmt once and shows the same key after; with
//!   the store locked it answers `CAPABILITY_UNAVAILABLE` / `mgmt_key_store_locked` (exit 4).
//! * `environment_commands_use_the_controller_records_under_the_instance_lock`: reads
//!   (`status`, `update`'s lookup) open the state read-only and create nothing; a writing
//!   command (`remove`) takes the runtime's instance lock and the read-write store; with a
//!   runtime running it refuses `SERVICE_UNAVAILABLE` with effect `none` (no request form
//!   carries a controller record); `add` without a terminal is refused before any state.
//!   The help goldens also pin that the hidden `remote` command stays out of the top level.
//!
//! **Isolation.** Every process gets a cleared environment: `PATH`, a scratch `HOME`, a
//! scratch Heimdall home, a scratch `HEIMDALL_TEST_SSH_HOME`, no `SSH_AUTH_SOCK`. The help
//! invocations name no home (clap prints an `env` argument's value). Only the runtime this
//! test started is stopped, through `service stop` on its own scratch home. Every output byte
//! is scanned for canaries.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use heimdall_testkit::assert_no_canary;
use heimdall_testkit::workspace::Scratch;
use serde_json::Value;

fn bin() -> String {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
}

#[derive(Debug)]
struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        self.stdout
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
            .unwrap_or_else(|| panic!("no envelope: {self:?}"))
    }
}

/// A scratch installation: its Heimdall home, a scratch account home, the K_mgmt fixture.
struct Rt {
    ws: Scratch,
    home: PathBuf,
    account: PathBuf,
    mgmt: PathBuf,
}

impl Rt {
    fn new() -> Rt {
        let ws = Scratch::new().unwrap();
        let account = ws.path("acct");
        std::fs::create_dir_all(&account).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&account, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Rt {
            home: ws.path("hm"),
            mgmt: ws.path("k_mgmt.fixture"),
            account,
            ws,
        }
    }

    fn run(&self, args: &[&str]) -> Out {
        let mut cmd = Command::new(bin());
        cmd.env_clear();
        if cfg!(windows) {
            for k in ["SystemRoot", "PATH", "TEMP", "TMP", "LOCALAPPDATA"] {
                if let Some(v) = std::env::var_os(k) {
                    cmd.env(k, v);
                }
            }
        } else {
            cmd.env("PATH", "/usr/bin:/bin");
        }
        cmd.env("HEIMDALL_HOME", &self.home)
            .env("HOME", &self.account)
            .env("HEIMDALL_TEST_SSH_HOME", &self.account)
            .env("HEIMDALL_TEST_SECRET_STORE", "scratch")
            .env("HEIMDALL_TEST_IROH_KEY_STORE", &self.account)
            .env("HEIMDALL_TEST_TIME_SYNC", "synchronized")
            .env(
                "HEIMDALL_TEST_MGMT_STORE",
                format!("fixture-file:{}", self.mgmt.display()),
            )
            .args(args)
            .current_dir(self.ws.root())
            .stdin(Stdio::null());
        let out = cmd.output().expect("spawn heimdall");
        let out = Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        };
        assert_no_canary(&out.stdout);
        assert_no_canary(&out.stderr);
        assert!(!out.stderr.contains("panicked"), "{args:?}: {out:?}");
        out
    }
}

impl Drop for Rt {
    fn drop(&mut self) {
        // The runtime this test started, in its own scratch home (a no-op when none ran).
        let _ = self.run(&["--json", "service", "stop"]);
    }
}

/// `heimdall <line> --help` with a cleared environment.
fn help_of(line: &[&str]) -> String {
    let out = Command::new(bin())
        .args(line)
        .arg("--help")
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{line:?} --help");
    assert!(out.stderr.is_empty(), "{line:?}: stderr on --help");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains('\u{1b}'), "{line:?}: no ANSI in piped help");
    text
}

/// Every M06 command line whose `--help` is a golden, and its file stem.
const HELP_LINES: &[(&str, &[&str])] = &[
    ("environment", &["environment"]),
    ("environment-add", &["environment", "add"]),
    ("environment-invite", &["environment", "invite"]),
    ("environment-join", &["environment", "join"]),
    (
        "environment-revoke-client",
        &["environment", "revoke-client"],
    ),
    ("environment-remove", &["environment", "remove"]),
    ("environment-update", &["environment", "update"]),
    (
        "environment-resume-issuance",
        &["environment", "resume-issuance"],
    ),
    ("environment-status", &["environment", "status"]),
    ("device", &["device"]),
    ("device-retire", &["device", "retire"]),
    ("route", &["route"]),
    // ⟨ADR-0006 §18.9 item 9⟩ `route add`'s flags, `--relay` included (frozen surface).
    ("route-add", &["route", "add"]),
    ("transport", &["transport"]),
    ("transport-disable", &["transport", "disable"]),
    ("remote-init", &["remote", "init"]),
];

fn golden(dir: &Path, name: &str, text: &str, mismatches: &mut Vec<String>) {
    let path = dir.join(name);
    if std::env::var_os("HM_UPDATE_GOLDENS").is_some_and(|v| v == "1") {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(&path, text).unwrap();
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(g) if g == text => {}
        Ok(g) => {
            let first = text
                .lines()
                .zip(g.lines())
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| text.lines().count().min(g.lines().count()));
            mismatches.push(format!(
                "{name}: changed at line {} (got {:?}, golden {:?})",
                first + 1,
                text.lines().nth(first).unwrap_or(""),
                g.lines().nth(first).unwrap_or("")
            ));
        }
        Err(e) => mismatches.push(format!(
            "{}: {e} (HM_UPDATE_GOLDENS=1 writes it)",
            path.display()
        )),
    }
}

#[test]
fn m06_help_goldens() {
    let dir = heimdall_testkit::repo::repo_path("tests/contracts/golden/cli-help-m06");
    let mut mismatches = Vec::new();
    for (stem, line) in HELP_LINES {
        let text = help_of(line);
        assert!(
            text.contains(&format!("heimdall {}", line.join(" "))),
            "{stem}: the usage line names the command"
        );
        golden(&dir, &format!("{stem}.txt"), &text, &mut mismatches);
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    if std::env::var_os("HM_UPDATE_GOLDENS").is_none() {
        let mut found: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        found.sort();
        let mut want: Vec<String> = HELP_LINES.iter().map(|(s, _)| format!("{s}.txt")).collect();
        want.sort();
        assert_eq!(found, want, "stale or missing M06 help goldens");
    }
    let top = help_of(&[]);
    let listed = |name: &str| {
        top.lines()
            .any(|l| l.trim_start().starts_with(&format!("{name} ")))
    };
    for name in ["environment", "device", "route", "transport"] {
        assert!(listed(name), "{name} is listed");
    }
    for name in ["env", "roost", "remote"] {
        assert!(!listed(name), "{name} is not listed");
    }
    // ⟨W2 wiring⟩ The hidden, frozen runner commands: reachable by name only.
    assert!(help_of(&["remote", "init"]).contains("heimdall remote init"));
    assert!(help_of(&["remote", "serve"]).contains("heimdall remote serve"));
    let route = help_of(&["route"]);
    assert!(
        !route.contains("connect"),
        "route connect is hidden: {route}"
    );
    assert!(help_of(&["route", "connect"]).contains("heimdall route connect"));
    assert!(help_of(&["transport"]).contains("adopt-roost"));
}

#[test]
fn show_key_creates_k_mgmt_once_and_a_locked_store_refuses() {
    let rt = Rt::new();
    let first = rt.run(&["--json", "environment", "join", "--show-key"]);
    assert_eq!(first.code, 0, "{first:?}");
    let a = first.json();
    assert_eq!(a["code"], "OK");
    let line = a["data"]["public_key"].as_str().unwrap().to_owned();
    assert!(line.starts_with("ssh-ed25519 AAAA") && line.ends_with(" heimdall-mgmt"));
    assert!(
        a["data"]["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("SHA256:")
    );
    assert_eq!(a["data"]["created"], true);
    assert_eq!(a["data"]["store"]["test"], "fixture_test");
    let again = rt
        .run(&["--json", "environment", "join", "--show-key"])
        .json();
    assert_eq!(again["data"]["created"], false);
    assert_eq!(again["data"]["public_key"].as_str(), Some(line.as_str()));

    // Locked: management is unavailable, nothing is created or changed.
    let mut flag = rt.mgmt.clone().into_os_string();
    flag.push(".locked");
    std::fs::write(PathBuf::from(&flag), b"").unwrap();
    let before = std::fs::read(&rt.mgmt).unwrap();
    let locked = rt.run(&["--json", "environment", "join", "--show-key"]);
    assert_eq!(locked.code, 4, "{locked:?}");
    let env = locked.json();
    assert_eq!(env["code"], "CAPABILITY_UNAVAILABLE");
    assert_eq!(env["data"]["error"]["reason"], "mgmt_key_store_locked");
    assert_eq!(std::fs::read(&rt.mgmt).unwrap(), before);
}

#[test]
fn environment_commands_use_the_controller_records_under_the_instance_lock() {
    let rt = Rt::new();
    // Read-only: no state yet, no records, no management key store selectable; nothing is
    // created and no runtime starts.
    let status = rt.run(&["--json", "environment", "status"]);
    assert_eq!(status.code, 0, "{status:?}");
    let env = status.json();
    assert_eq!(env["code"], "OK");
    assert_eq!(env["data"]["environments"], serde_json::json!([]));
    assert_eq!(env["data"]["management"], "mgmt_key_store_unavailable");
    assert!(
        !heimdall_store::layout::db_path(&rt.home.join("state"))
            .unwrap()
            .exists(),
        "status wrote nothing"
    );
    let update = rt.run(&[
        "--json",
        "--non-interactive",
        "environment",
        "update",
        "env_0123",
    ]);
    assert_eq!(update.json()["code"], "NOT_FOUND", "{update:?}");
    // A writing command takes the instance lock and the store (no runtime started).
    let remove = rt.run(&[
        "--json",
        "--non-interactive",
        "environment",
        "remove",
        "env_0123",
    ]);
    assert_eq!(remove.json()["code"], "NOT_FOUND", "{remove:?}");
    assert!(
        heimdall_store::layout::db_path(&rt.home.join("state"))
            .unwrap()
            .exists()
    );
    let not_running = rt.run(&["--json", "service", "status"]);
    assert_ne!(
        not_running.code, 0,
        "no runtime was started: {not_running:?}"
    );
    assert!(!rt.mgmt.exists(), "no management key was created");
    // `environment add` without a terminal is refused before anything happens.
    let add = rt.run(&[
        "--json",
        "environment",
        "add",
        "--destination",
        "lab",
        "--account",
        "runner",
        "--runner-program",
        "/opt/heimdall/bin/heimdall",
        "--runner-home",
        "/srv/runner/heimdall",
    ]);
    assert_eq!(add.code, 3, "{add:?}");
    assert_eq!(add.json()["code"], "INTERACTION_REQUIRED");
    // ⟨M06 W4⟩ So is `environment resume-issuance`: the acknowledgement is attended.
    let resume = rt.run(&["--json", "environment", "resume-issuance", "env_0123"]);
    assert_eq!(resume.code, 3, "{resume:?}");
    assert_eq!(resume.json()["code"], "INTERACTION_REQUIRED");
    assert_eq!(resume.json()["data"]["error"]["effect_status"], "none");
    assert!(!rt.mgmt.exists());
    // ⟨rev6.3; ADR-0006 §18.7 item 6⟩ With the runtime running, a writing command no longer
    // refuses `SERVICE_UNAVAILABLE`: it reads the records and would write them through the
    // runtime (`controller_record.*`), so an unknown runner is `NOT_FOUND` as without one.
    let started = rt.run(&["--json", "access", "default-profile", "--clear"]);
    assert_eq!(started.code, 0, "{started:?}");
    let beside = rt.run(&[
        "--json",
        "--non-interactive",
        "environment",
        "remove",
        "env_0123",
    ]);
    let env = beside.json();
    assert_eq!(env["code"], "NOT_FOUND", "{beside:?}");
    assert_eq!(env["data"]["error"]["effect_status"], "none");
    // Reads still work beside the runtime.
    assert_eq!(rt.run(&["--json", "environment", "status"]).code, 0);
}

#[test]
fn oversized_authority_report_wording_is_shown_by_status_and_doctor() {
    use std::sync::Arc;

    use heimdall_app::remote_status::{REPORT_OVER_LIMIT, REPORT_OVER_LIMIT_NEXT};
    use heimdall_contract::Timestamp;
    use heimdall_contract::controller_record::{
        ManagementHop, ManagementRoute, RemoteEnvironmentPin,
    };
    use heimdall_contract::envelope::reason;
    use heimdall_contract::ids::{
        AccountName, ClientId, DestinationId, EnvironmentId, KeyFingerprint,
    };
    use heimdall_contract::remote::Role;
    use heimdall_store::{NoFaults, Store};

    let rt = Rt::new();
    let state = rt.home.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let store = Store::open(
        &heimdall_store::layout::db_path(&state).unwrap(),
        Arc::new(NoFaults),
    )
    .unwrap();
    let pin = RemoteEnvironmentPin {
        environment: EnvironmentId::from_random_bytes([3; 16]),
        destination: DestinationId::parse("lab").unwrap(),
        route: ManagementRoute {
            runner: ManagementHop {
                hostname: "runner.example.invalid".into(),
                port: None,
                account: AccountName::parse("runner").unwrap(),
                host_keys: vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA".into()],
            },
            jump: None,
        },
        client: ClientId::from_random_bytes([1; 16]),
        role: Role::Owner,
        key_fingerprint: KeyFingerprint::parse(&format!("SHA256:{}", "K".repeat(43))).unwrap(),
        label: None,
        pinned_at: Timestamp::now(),
    };
    store
        .transaction(|tx| {
            tx.put_remote_environment_pin(
                &pin.environment,
                &pin.destination,
                &pin.route.runner.account,
                &pin.key_fingerprint,
                &serde_json::to_string(&pin).unwrap(),
                pin.pinned_at,
            )?;
            tx.note_remote_failure(&pin.environment, pin.pinned_at, reason::RESPONSE_TOO_LARGE)
        })
        .unwrap();

    let mut missing = Vec::new();
    for args in [
        &["environment", "status"][..],
        &["doctor", "--no-local-exec"],
    ] {
        let out = rt.run(args);
        assert_eq!(out.code, 0, "{args:?} did not succeed");
        if !out.stdout.contains(REPORT_OVER_LIMIT) || !out.stdout.contains(REPORT_OVER_LIMIT_NEXT) {
            missing.push(args.join(" "));
        }
    }
    assert!(
        missing.is_empty(),
        "oversized report wording missing from {missing:?}"
    );
}
