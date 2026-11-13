//! M03 end-to-end suite (U0 §5 item 24, U0b rows 16 and 18, U12): the M03 command tree
//! through the **real binary** (`CARGO_BIN_EXE_heimdall`, or `HEIMDALL_E2E_BIN`).
//!
//! This parent file holds the cross-cutting checks (⟨wave 5⟩ rewritten from the wave-0
//! "not available" assertions); the per-command suites are its submodules, one file per
//! owner under `tests/e2e/cli_m03/`:
//!
//! * `enroll` (`enroll_cmd`): the client-executed enrollment loop, previews, decisions;
//! * `issuer` (`issuer_cmd`): ceremonies, status, bundle, retire;
//! * `access` (`m03_cmd`, `connections_cmd`, `output`): lock behaviour, connection
//!   policy, `destination prefer`, `connections`, the help and discovery goldens;
//! * `uninstall_doctor` (`uninstall_cmd`, `doctor_cmd`): remote enrollments at uninstall,
//!   `slot_free`, `managed_dir_unsafe`, the status chore.
//!
//! The parent's own tests:
//!
//! * `m03_cli_commands_answer_without_a_runtime_and_never_panic` (was
//!   `w0_m03_cli_commands_report_not_available_and_never_panic`): every M03 command line
//!   that answers before any runtime contact answers its real exit class and code with
//!   **no runtime** (stdin closed, a Heimdall home that does not exist), never panics,
//!   never creates the home, never starts a runtime and never answers "not available".
//!   The lines that start a runtime on demand (`enroll lab`, `destination prefer`) are
//!   covered by their submodules.
//! * `no_m03_source_contains_the_wave_0_text`: the M03 handler and TUI sources no longer
//!   hold M01's wave-0 text.
//! * `uninstall_refuses_purge_with_live_enrollments`: a state database at schema 6 with a
//!   non-final enrollment makes `uninstall --purge-state` refuse before anything else,
//!   listing marker, destination and state; only final ones leave it alone.
//! * the `HEIMDALL_TEST_*` M03 gates of `enroll` and `service run` in this build (the
//!   release-build half is `tools/validation/release-gate.sh`).
//!
//! **Isolation.** Every process gets a cleared environment: `PATH`, a scratch `HOME` and
//! the scratch Heimdall home (a path that does not exist yet), stdin closed. The
//! fixtures are synthetic (fixture IDs, `example.invalid`, fake public keys); no owner
//! key, agent or keychain is touched. Every stdout and stderr byte is scanned for
//! canaries. A test here never starts a runtime it does not stop: a line that would
//! start one is given an invalid ID (answered first) or is left to a submodule.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{AccountName, CaFingerprint, DestinationId, EnrollmentId, IdentityId};
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentRecord, EnrollmentState,
    ExistingAccessRecord, NoProxy, RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
};
use heimdall_store::{IssuerRecord, NoFaults, Store};
use heimdall_testkit::assert_no_canary;
use serde_json::Value;

/// The binary under test.
fn bin() -> String {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
}

/// M01's wave-0 text, built at run time (as `m03_cmd` builds it).
fn not_available_text() -> String {
    [
        "this command is not available",
        "in this build (planned for M03)",
    ]
    .join(" ")
}

/// One finished invocation.
#[derive(Debug)]
struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    /// The last JSON object on stdout (the envelope).
    fn json(&self) -> Value {
        self.stdout
            .lines()
            .rev()
            .filter_map(|l| l.trim().find('{').map(|i| l.trim()[i..].to_owned()))
            .find_map(|l| serde_json::from_str::<Value>(&l).ok())
            .unwrap_or_else(|| panic!("no envelope: {self:?}"))
    }

    fn message(&self) -> String {
        self.json()["data"]["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
}

/// Run the binary with a cleared environment, stdin closed, both streams scanned.
fn run(home: &Path, account: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Out {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .env_clear()
        .env("HEIMDALL_HOME", home)
        .env("HOME", account)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::null());
    if cfg!(windows) {
        for k in ["SystemRoot", "PATH", "TEMP", "TMP"] {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
    } else {
        cmd.env("PATH", "/usr/bin:/bin");
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
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

/// A line that has no ID of its own to refuse (a policy, a profile) is given this one:
/// it parses as an argument and is refused as an invalid ID before any runtime contact
/// (a valid ID would start the runtime on demand).
const BAD: &str = "BAD ID";

/// The M03 command lines of m03-plan §5 item 24 that answer **before any runtime
/// contact**, each with its real exit code and envelope code (determined by running the
/// binary, ⟨wave 5⟩). Not listed, because they start a detached runtime on demand and are
/// covered by their submodules: `enroll lab` (bare), `destination prefer`, and the
/// `access ensure --strict` / `lock-behavior` / `connection-policy` lines with a valid ID
/// (here they carry [`BAD`]). `internal issuer` and `internal session-lock-state` are
/// below.
const ANSWERS_WITHOUT_A_RUNTIME: &[(&[&str], i32, &str)] = &[
    // The ceremonies need the owner at a terminal: `--non-interactive` -> 3.
    (
        &["issuer", "init", "--backup-out", "b.enc"],
        3,
        "INTERACTION_REQUIRED",
    ),
    (
        &[
            "issuer",
            "init",
            "--backup-out",
            "b",
            "--replace-orphan",
            "fp",
            "--bundle",
            "f",
        ],
        3,
        "INTERACTION_REQUIRED",
    ),
    (
        &[
            "issuer",
            "init",
            "--backup-out",
            "b",
            "--replace-orphan",
            "fp",
            "--no-bundle-available",
        ],
        3,
        "INTERACTION_REQUIRED",
    ),
    (&["issuer", "status"], 5, "SERVICE_UNAVAILABLE"),
    (&["issuer", "unlock"], 3, "INTERACTION_REQUIRED"),
    (
        &["issuer", "rotate", "begin", "--backup-out", "b.enc"],
        3,
        "INTERACTION_REQUIRED",
    ),
    // `SHA256:abc` is not a CA fingerprint.
    (&["issuer", "retire", "SHA256:abc"], 2, "USAGE_ERROR"),
    (
        &["issuer", "restore", "--backup", "b.enc"],
        3,
        "INTERACTION_REQUIRED",
    ),
    (
        &["issuer", "restore", "--backup", "b.enc", "--not-stolen"],
        3,
        "INTERACTION_REQUIRED",
    ),
    (
        &["issuer", "bundle", "--out", "o.json"],
        5,
        "SERVICE_UNAVAILABLE",
    ),
    (
        &[
            "issuer",
            "bundle",
            "--out",
            "o.json",
            "--redact",
            "hostnames",
        ],
        5,
        "SERVICE_UNAVAILABLE",
    ),
    // `enroll`: the fixture ID, CA or bundle does not parse (exit 2 before contact);
    // `status` is a read and never starts a runtime (exit 5).
    (
        &[
            "enroll",
            "lab",
            "--account",
            "deploy",
            "--form",
            "system",
            "--registry-path",
            "p",
            "--ca",
            "fp",
        ],
        2,
        "USAGE_ERROR",
    ),
    (&["enroll", "status"], 5, "SERVICE_UNAVAILABLE"),
    (&["enroll", "verify", "enr-1"], 2, "USAGE_ERROR"),
    (
        &["enroll", "verify", "enr-1", "--absence"],
        2,
        "USAGE_ERROR",
    ),
    (
        &["enroll", "verify", "enr-1", "--approve-target-change"],
        2,
        "USAGE_ERROR",
    ),
    (&["enroll", "remove", "enr-1"], 2, "USAGE_ERROR"),
    (
        &[
            "enroll",
            "remove",
            "--from-bundle",
            "f",
            "--marker",
            "m",
            "--alias",
            "a",
        ],
        2,
        "USAGE_ERROR",
    ),
    (&["enroll", "reconcile", "op-1"], 2, "USAGE_ERROR"),
    (
        &["enroll", "reconcile", "op-1", "--after-manual-recovery"],
        2,
        "USAGE_ERROR",
    ),
    (&["enroll", "abandon", "enr-1"], 2, "USAGE_ERROR"),
    // `access`: an invalid ID is refused before contact.
    (
        &[
            "access",
            "ensure",
            "--profile",
            BAD,
            "--work-id",
            "w",
            "--request-id",
            "r",
            "--strict",
        ],
        2,
        "USAGE_ERROR",
    ),
    (
        &["access", "lock-behavior", "--policy", BAD, "continue"],
        2,
        "USAGE_ERROR",
    ),
    (
        &["access", "lock-behavior", "--policy", BAD, "revoke-on-lock"],
        2,
        "USAGE_ERROR",
    ),
    // Neither `--existing` nor `--multiplexing`: refused first, whatever the policy.
    (
        &["access", "connection-policy", "--policy", "pol"],
        2,
        "USAGE_ERROR",
    ),
    (
        &[
            "access",
            "connection-policy",
            "--policy",
            BAD,
            "--existing",
            "strict",
            "--multiplexing",
            "owned",
        ],
        2,
        "USAGE_ERROR",
    ),
    // `connections` is a read (exit 5); the ID of `close` does not parse.
    (&["connections"], 5, "SERVICE_UNAVAILABLE"),
    (&["connections", "close", "conn-1"], 2, "USAGE_ERROR"),
];

/// Assert that nothing of `home` was created: no home, no runtime directory.
fn assert_no_runtime(home: &Path, what: &str) {
    assert!(!home.exists(), "{what} created the Heimdall home");
    assert!(
        !home.join("run").exists(),
        "{what} started a runtime (a run/ directory exists)"
    );
}

/// `m03_cli_commands_answer_without_a_runtime_and_never_panic` (was
/// `w0_m03_cli_commands_report_not_available_and_never_panic`): every M03 line that
/// answers before runtime contact answers its real exit class and code, `--json` and
/// human, with no runtime (stdin closed, a home that does not exist), never panics, never
/// creates the home or a `run/` directory, and never answers "not available".
#[test]
fn m03_cli_commands_answer_without_a_runtime_and_never_panic() {
    let scratch = tempfile::tempdir().unwrap();
    let account = scratch.path().join("account");
    std::fs::create_dir_all(&account).unwrap();
    let wave_0 = not_available_text();
    for (i, (line, exit, code)) in ANSWERS_WITHOUT_A_RUNTIME.iter().enumerate() {
        let home = scratch.path().join(format!("home-{i}"));
        let mut argv = vec!["--json", "--non-interactive"];
        argv.extend_from_slice(line);
        let out = run(&home, &account, &argv, &[]);
        assert_eq!(out.code, *exit, "{line:?}: {out:?}");
        let env = out.json();
        assert_eq!(env["code"], *code, "{line:?}: {out:?}");
        assert_eq!(env["data"]["error"]["effect_status"], "none", "{line:?}");
        assert_ne!(out.message(), wave_0, "{line:?}: {out:?}");
        assert!(
            !out.stdout.contains("not available in this build"),
            "{line:?}"
        );
        assert!(
            !out.stderr.contains("not available in this build"),
            "{line:?}"
        );
        assert_no_runtime(&home, &format!("{line:?}"));
    }

    // Human mode: the message on stderr (not the wave-0 text), the exit class unchanged.
    let home = scratch.path().join("home-human");
    let out = run(&home, &account, &["issuer", "status"], &[]);
    assert_eq!(out.code, 5, "{out:?}");
    assert!(out.stderr.contains("no runtime is running"), "{out:?}");
    assert!(!out.stderr.contains(&wave_0), "{out:?}");
    assert_no_runtime(&home, "human issuer status");

    // A line the tree refuses is an ordinary usage error.
    for line in [
        &["issuer", "init"][..],
        &["enroll"],
        &["enroll", "remove"],
        &["access", "lock-behavior", "--policy", "pol", "sometimes"],
        &["uninstall", "--purge-state", "--bundle", "f"],
    ] {
        let mut argv = vec!["--json"];
        argv.extend_from_slice(line);
        let home = scratch.path().join("home-usage");
        let out = run(&home, &account, &argv, &[]);
        assert_eq!(out.code, 2, "{line:?}: {out:?}");
        assert_eq!(out.json()["code"], "USAGE_ERROR", "{line:?}");
        assert_ne!(out.message(), wave_0, "{line:?}");
        assert_no_runtime(&home, &format!("{line:?}"));
    }

    // `internal issuer` on a pipe is the issuer child: its stdout is the
    // `heimdall-issuer/1` channel, so it prints no envelope. With no installation (no
    // state database) it cannot serve and exits `unavailable` (5), reading nothing and
    // creating neither the home nor a runtime.
    let home = scratch.path().join("home-issuer");
    let out = run(&home, &account, &["internal", "issuer"], &[]);
    assert_eq!(out.code, 5, "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert_no_runtime(&home, "internal issuer");

    // `internal session-lock-state` is a read-only query (exit 0, `OK`): the platform
    // source's reading of this host, whatever it is (a locked or unknown host answers
    // too), and it writes nothing, not even the home. (The deterministic states are
    // `access.rs`'s, through `HEIMDALL_TEST_SESSION_LOCK`.)
    let home = scratch.path().join("home-lock-state");
    let out = run(
        &home,
        &account,
        &["--json", "internal", "session-lock-state"],
        &[],
    );
    assert_eq!(out.code, 0, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "OK", "{out:?}");
    assert_eq!(env["data"]["source"], "platform", "{out:?}");
    let state = env["data"]["state"].as_str().unwrap_or_default();
    assert!(
        ["unlocked", "locked", "unknown", "unavailable"].contains(&state),
        "{out:?}"
    );
    assert!(env["data"]["signal"].is_string(), "{out:?}");
    assert!(
        !out.stdout.contains("not available in this build"),
        "{out:?}"
    );
    assert_no_runtime(&home, "internal session-lock-state");

    // `internal` is not listed in help; the M03 user commands are.
    let help = run(
        &scratch.path().join("home-help"),
        &account,
        &["--help"],
        &[],
    );
    assert_eq!(help.code, 0, "{help:?}");
    for listed in ["issuer", "enroll", "connections"] {
        assert!(
            help.stdout
                .lines()
                .any(|l| l.trim_start().starts_with(listed)),
            "{listed} missing from help"
        );
    }
    assert!(
        !help
            .stdout
            .lines()
            .any(|l| l.trim_start().starts_with("internal")),
        "internal is hidden"
    );
}

/// The Rust sources of the M03 handlers and the TUI, relative to the `heimdall` crate:
/// the files and (recursively) the directories that hold them.
const M03_SOURCES: &[&str] = &[
    "src/issuer_cmd.rs",
    "src/issuer_cmd",
    "src/enroll_cmd.rs",
    "src/enroll_cmd",
    "src/connections_cmd.rs",
    "src/m03_cmd.rs",
    "src/uninstall_cmd.rs",
    "src/doctor_cmd.rs",
    "src/tui",
];

fn collect_sources(path: &Path, into: &mut Vec<PathBuf>) {
    if path.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for entry in entries {
            collect_sources(&entry, into);
        }
    } else if path.extension().is_some_and(|e| e == "rs") {
        into.push(path.to_path_buf());
    }
}

/// No M03 handler or TUI source holds M01's wave-0 text any more. The text is built here
/// at run time so this file does not hold it (as `cli_m01.rs` does for its own guard); the
/// match ignores comment markers and line breaks, so a wrapped doc comment is caught too.
#[test]
fn no_m03_source_contains_the_wave_0_text() {
    let words = [
        "this",
        "command",
        "is",
        "not",
        "available",
        "in",
        "this",
        "build",
    ];
    // The repository through `HM_REPO_ROOT` (testkit `repo`), never the compile-time root.
    let crate_dir = heimdall_testkit::repo::repo_path("crates/heimdall");
    let mut files = Vec::new();
    for rel in M03_SOURCES {
        let path = crate_dir.join(rel);
        if path.exists() {
            collect_sources(&path, &mut files);
        }
    }
    assert!(
        files.len() >= 8,
        "the guard found only {} source files: {files:?}",
        files.len()
    );
    // The assembling idiom of the wave-0 helpers (a message built from two halves).
    let halves = [
        ["not", "available"].join("_"),
        ["in this build", "(planned for M03)"].join(" "),
    ];
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        // Words only: drop comment markers, quotes, commas and line breaks.
        let flat: Vec<&str> = text
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty())
            .collect();
        let hit = flat.windows(words.len()).any(|w| w == words);
        assert!(
            !hit,
            "{} holds the wave-0 text ({})",
            file.display(),
            words.join(" ")
        );
        for half in &halves {
            assert!(
                !text.contains(half.as_str()),
                "{} holds `{half}` (the wave-0 helpers)",
                file.display()
            );
        }
    }
}

/// `enroll` reads `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` in the CLI process: a relative value
/// is a usage error naming the variable (a release build refuses any value; both exit 2
/// before anything else), and `service run` validates the M03 variables before it starts
/// anything. The release-build half is `tools/validation/release-gate.sh`.
#[test]
fn m03_test_gates_are_validated_before_anything_else() {
    let scratch = tempfile::tempdir().unwrap();
    let account = scratch.path().join("account");
    std::fs::create_dir_all(&account).unwrap();

    let home = scratch.path().join("home-enroll");
    let out = run(
        &home,
        &account,
        &["--json", "enroll", "lab"],
        &[("HEIMDALL_TEST_SCRIPT_PAUSE_DIR", "relative/dir")],
    );
    assert_eq!(out.code, 2, "{out:?}");
    assert!(out.message().contains("HEIMDALL_TEST_"), "{out:?}");
    assert_ne!(out.message(), not_available_text());
    assert!(!home.exists());
    // The CLI's build profile, from its own answer: a release CLI refuses every
    // HEIMDALL_TEST_* variable with its release message. A native harness's copied CLI
    // (`HEIMDALL_E2E_BIN`) comes from the same debug build as this test, so the presence
    // of the variable says nothing about the profile (wave-1 native run, item B5).
    let debug_build = !out.message().contains("not available in release builds");
    if std::env::var_os("HEIMDALL_E2E_BIN").is_none() {
        assert_eq!(debug_build, cfg!(debug_assertions), "{out:?}");
    }

    // An absolute directory. A release build refuses the variable with its release
    // message (exit 2, nothing created; `tools/validation/release-gate.sh` is the
    // release-build half). A debug build only validates it (ADR-0008 §17.25 item 3: the
    // runtime inserts the pause points when it builds a step, from its own test
    // configuration), so `enroll` goes on: `enroll status`, which never starts a
    // runtime, reports that none runs, names no variable and starts nothing.
    let abs = scratch.path().join("pause");
    let abs = abs.to_string_lossy().into_owned();
    if debug_build {
        let out = run(
            &home,
            &account,
            &["--json", "enroll", "status"],
            &[("HEIMDALL_TEST_SCRIPT_PAUSE_DIR", &abs)],
        );
        assert_ne!(out.code, 2, "{out:?}");
        assert_ne!(out.code, 0, "no runtime runs: {out:?}");
        assert!(
            !out.message().contains("HEIMDALL_TEST_SCRIPT_PAUSE_DIR"),
            "{out:?}"
        );
        assert_ne!(out.message(), not_available_text(), "{out:?}");
        assert!(!home.join("run").join("instance.json").exists());
        // A form that the round-1 CLI refused with the variable set (exit 2): a foreign
        // removal from a redacted bundle now reaches its own local check (exit 4,
        // `bundle_redacted`, before any runtime contact).
        let bundle = scratch.path().join("bundle.json");
        let marker = "heimdall:enr_00112233445566778899aabbccddeeff";
        std::fs::write(
            &bundle,
            serde_json::json!({
                "schema": "heimdall-recovery-bundle/1",
                "created_at": "2026-11-01T00:00:00Z",
                "redacted": true,
                "cas": [],
                "enrollments": [{
                    "marker": marker, "destination_id": "dst_lab", "alias": "lab",
                    "hostname": null, "port": null, "account": "deploy",
                    "registry": {"resolved_by": "remote_home"},
                    "registry_path_display": "$HOME/.ssh/authorized_keys",
                    "form": "account", "state": "verified",
                    "ca_fingerprint": format!("SHA256:{}", "A".repeat(43)),
                    "ca_public_key": "ssh-ed25519 AAAA",
                    "line_sha256": "ab".repeat(32),
                }],
                "instructions": [],
            })
            .to_string(),
        )
        .unwrap();
        let bundle = bundle.to_string_lossy().into_owned();
        let out = run(
            &home,
            &account,
            &[
                "--json",
                "enroll",
                "remove",
                "--from-bundle",
                &bundle,
                "--marker",
                marker,
                "--alias",
                "lab",
            ],
            &[("HEIMDALL_TEST_SCRIPT_PAUSE_DIR", &abs)],
        );
        assert_eq!(out.code, 4, "{out:?}");
        assert!(
            !out.message().contains("HEIMDALL_TEST_SCRIPT_PAUSE_DIR"),
            "{out:?}"
        );
        assert!(!home.join("run").join("instance.json").exists());
    } else {
        let out = run(
            &home,
            &account,
            &["--json", "enroll", "lab"],
            &[("HEIMDALL_TEST_SCRIPT_PAUSE_DIR", &abs)],
        );
        assert_eq!(out.code, 2, "{out:?}");
        assert!(out.message().contains("HEIMDALL_TEST_"), "{out:?}");
        assert_ne!(out.message(), not_available_text(), "{out:?}");
        assert!(!home.exists());
    }

    // `service run`: a malformed value of each M03 variable ends the command at once
    // (exit 2, the variable named), before a runtime exists.
    for (name, value) in [
        ("HEIMDALL_TEST_SECRET_STORE", "platform"),
        ("HEIMDALL_TEST_KEY_SEED", "not-hex"),
        ("HEIMDALL_TEST_SESSION_LOCK", "relative/state"),
        ("HEIMDALL_TEST_SCRIPT_PAUSE_DIR", "relative/dir"),
    ] {
        let home = scratch.path().join(format!("home-service-{name}"));
        let out = run(
            &home,
            &account,
            &["--json", "service", "run"],
            &[(name, value)],
        );
        assert_eq!(out.code, 2, "{name}: {out:?}");
        assert!(out.message().contains("HEIMDALL_TEST_"), "{name}: {out:?}");
        if debug_build {
            assert!(out.message().contains(name), "{name}: {out:?}");
        }
        assert!(
            !home.join("run").join("instance.json").exists(),
            "{name}: a runtime started"
        );
    }
}

// --- uninstall (U0b row 18) ---------------------------------------------------------

fn t0() -> Timestamp {
    "2026-11-01T00:00:00Z".parse().unwrap()
}

fn ca() -> CaFingerprint {
    CaFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap()
}

/// A synthetic enrollment `n` of destination `dst-lab<n>` in `state`.
fn enrollment(n: u8, state: EnrollmentState) -> EnrollmentRecord {
    let id = EnrollmentId::from_random_bytes([n; 16]);
    let account = AccountName::parse("deploy").unwrap();
    let at = t0().checked_add(Duration::from_secs(u64::from(n))).unwrap();
    EnrollmentRecord {
        marker: marker_for(&id),
        id,
        destination: DestinationId::parse(&format!("dst-lab{n}")).unwrap(),
        account: account.clone(),
        ca_fingerprint: ca(),
        form: EnrollmentForm::Account,
        registry: RegistryRef {
            path_display: "~/.ssh/authorized_keys".into(),
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        registry_canonical: RegistryCanonical {
            path: None,
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        line_sha256: "ab".repeat(32),
        target: ApprovedTarget {
            hostname: "example.invalid".into(),
            port: 22,
            user: account,
            proxy: NoProxy::None,
            host_key: ApprovedHostKey {
                algorithm: "ssh-ed25519".into(),
                key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                fingerprint: "SHA256:hostfixture".into(),
            },
        },
        existing_access: ExistingAccessRecord {
            identity: IdentityId::from_random_bytes([n; 16]),
            endpoint: None,
            public_key_file: None,
        },
        hold: None,
        removal_origin: None,
        late_write: None,
        state,
        verified_at: None,
        evidence: None,
        created_at: at,
        updated_at: at,
    }
}

/// Create `<home>/state/state.db` at the current schema (6) holding one CA and the
/// enrollments in `states`; returns the database path.
fn seed_state(home: &Path, states: &[EnrollmentState]) -> PathBuf {
    let state_dir = home.join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let db = state_dir.join("state.db");
    let store = Store::open(&db, Arc::new(NoFaults)).unwrap();
    store
        .transaction(|tx| {
            tx.insert_issuer(&IssuerRecord {
                ca_fingerprint: ca(),
                public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture0".into(),
                state: CaState::Active,
                store_kind: StoreKind::LinuxSecretService,
                backup_sha256: "00".repeat(32),
                backup_created_at: t0(),
                restored_without_log: false,
                created_at: t0(),
                retired_at: None,
            })?;
            for (n, state) in (1u8..).zip(states) {
                tx.seed_enrollment(&enrollment(n, *state))?;
            }
            Ok(())
        })
        .unwrap();
    drop(store);
    db
}

/// `uninstall_refuses_purge_with_live_enrollments`: a non-final enrollment refuses
/// `--purge-state` before the confirmation, the rollback or any runtime contact, and
/// lists marker, destination and state; `--keep-remote-enrollments` needs a bundle
/// (`bundle_required`, exit 4) and a `--bundle` this installation never recorded is
/// refused the same way (ADR-0008 §17.25 item 8: content check plus a recorded digest);
/// final enrollments
/// do not refuse. (The plain `uninstall` listing and acknowledgement are
/// `uninstall_doctor`'s.)
#[test]
fn uninstall_refuses_purge_with_live_enrollments() {
    let scratch = tempfile::tempdir().unwrap();
    let account = scratch.path().join("account");
    std::fs::create_dir_all(&account).unwrap();

    // One live (applied, unverified) and one final (withdrawn) enrollment.
    let home = scratch.path().join("live");
    let db = seed_state(
        &home,
        &[
            EnrollmentState::AppliedUnverified,
            EnrollmentState::Withdrawn,
        ],
    );
    let live = enrollment(1, EnrollmentState::AppliedUnverified);
    let final_one = enrollment(2, EnrollmentState::Withdrawn);
    let before = std::fs::read(&db).unwrap();

    let out = run(
        &home,
        &account,
        &["--json", "--non-interactive", "uninstall", "--purge-state"],
        &[],
    );
    assert_eq!(out.code, 6, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "CONFIG_CONFLICT", "{out:?}");
    assert_eq!(env["data"]["error"]["effect_status"], "none", "{out:?}");
    let listed = env["data"]["enrollments"].as_array().unwrap();
    assert_eq!(listed.len(), 1, "{out:?}");
    assert_eq!(listed[0]["marker"], live.marker.as_str());
    assert_eq!(listed[0]["destination_id"], "dst-lab1");
    assert_eq!(listed[0]["state"], "applied_unverified");
    assert!(!out.stdout.contains(&final_one.marker), "{out:?}");
    assert!(out.message().contains("--purge-state refused"), "{out:?}");
    assert!(db.exists(), "the state store is kept");
    assert!(!home.join("run").exists(), "no runtime was contacted");
    assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");

    // Human mode lists the same three fields.
    let out = run(
        &home,
        &account,
        &["--non-interactive", "uninstall", "--purge-state"],
        &[],
    );
    assert_eq!(out.code, 6, "{out:?}");
    for field in [live.marker.as_str(), "dst-lab1", "applied_unverified"] {
        assert!(out.stdout.contains(field), "{field}: {out:?}");
    }

    // Keeping them needs a fresh bundle (bundle_required, exit 4)...
    let out = run(
        &home,
        &account,
        &[
            "--json",
            "--non-interactive",
            "uninstall",
            "--purge-state",
            "--keep-remote-enrollments",
        ],
        &[],
    );
    assert_eq!(out.code, 4, "{out:?}");
    assert_eq!(out.json()["code"], "CAPABILITY_UNAVAILABLE");
    assert_eq!(out.json()["data"]["error"]["reason"], "bundle_required");
    assert_eq!(
        out.json()["data"]["enrollments"].as_array().unwrap().len(),
        1
    );

    // ...and with one whose digest this installation never recorded (§17.25 item 8):
    // refused `bundle_required` (exit 4), the enrollments listed, nothing changed. The
    // accepted case is `uninstall_doctor::uninstall_purge_keeping_enrollments_requires_fresh_bundle`.
    let bundle = scratch.path().join("bundle.json");
    let bundle_arg = bundle.to_string_lossy().into_owned();
    let out = run(
        &home,
        &account,
        &[
            "--json",
            "--non-interactive",
            "uninstall",
            "--purge-state",
            "--keep-remote-enrollments",
            "--bundle",
            &bundle_arg,
        ],
        &[],
    );
    assert_eq!(out.code, 4, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "CAPABILITY_UNAVAILABLE", "{out:?}");
    assert_eq!(env["data"]["error"]["reason"], "bundle_required", "{out:?}");
    assert_eq!(
        env["data"]["enrollments"].as_array().unwrap().len(),
        1,
        "{out:?}"
    );
    assert_ne!(out.message(), not_available_text(), "{out:?}");
    assert!(db.exists(), "the state store is kept");
    assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");
    assert!(!home.join("run").exists(), "no runtime was contacted");

    // Only final enrollments: the new check does not refuse. The purge goes on to its
    // own confirmation, which `--non-interactive` never gives (exit 3, nothing changed).
    let home = scratch.path().join("final");
    let db = seed_state(
        &home,
        &[
            EnrollmentState::Withdrawn,
            EnrollmentState::Removed,
            EnrollmentState::VerificationFailed,
            EnrollmentState::FailedUnwritten,
        ],
    );
    let out = run(
        &home,
        &account,
        &["--json", "--non-interactive", "uninstall", "--purge-state"],
        &[],
    );
    assert_eq!(out.code, 3, "{out:?}");
    assert_eq!(out.json()["code"], "INTERACTION_REQUIRED", "{out:?}");
    assert!(out.json()["data"].get("enrollments").is_none());
    assert!(db.exists());

    // `abandoned` is not final: it refuses.
    let home = scratch.path().join("abandoned");
    seed_state(&home, &[EnrollmentState::Abandoned]);
    let out = run(
        &home,
        &account,
        &["--json", "--non-interactive", "uninstall", "--purge-state"],
        &[],
    );
    assert_eq!(out.code, 6, "{out:?}");
    assert_eq!(out.json()["data"]["enrollments"][0]["state"], "abandoned");
}

// ⟨wave 5⟩ U12 suites, one file per owner (`.m03-wave5-api.md` R1); each reaches the
// helpers above through `super::`.
#[path = "cli_m03/access.rs"]
mod access;
#[path = "cli_m03/enroll.rs"]
mod enroll;
#[path = "cli_m03/issuer.rs"]
mod issuer;
#[path = "cli_m03/uninstall_doctor.rs"]
mod uninstall_doctor;
