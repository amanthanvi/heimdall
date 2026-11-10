//! M03 wave 0 end-to-end suite (U0 §5 item 24, U0b rows 16 and 18): the M03 command tree
//! through the **real binary** (`CARGO_BIN_EXE_heimdall`, or `HEIMDALL_E2E_BIN`).
//!
//! * `w0_m03_cli_commands_report_not_available_and_never_panic`: every M03 command line
//!   answers the wave-0 envelope (M01's: `USAGE_ERROR`, exit 2) with its own handler,
//!   never panics, and never creates the Heimdall home it names (no runtime contact).
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
//! canaries.
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

/// Every M03 command line of m03-plan §5 item 24 (the same set as the in-process
/// `m03_cmd` test: that one cannot be imported from a binary crate).
const M03_LINES: &[&[&str]] = &[
    &["issuer", "init", "--backup-out", "b.enc"],
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
    &[
        "issuer",
        "init",
        "--backup-out",
        "b",
        "--replace-orphan",
        "fp",
        "--no-bundle-available",
    ],
    &["issuer", "status"],
    &["issuer", "unlock"],
    &["issuer", "rotate", "begin", "--backup-out", "b.enc"],
    &["issuer", "retire", "SHA256:abc"],
    &["issuer", "restore", "--backup", "b.enc"],
    &["issuer", "restore", "--backup", "b.enc", "--not-stolen"],
    &["issuer", "bundle", "--out", "o.json"],
    &[
        "issuer",
        "bundle",
        "--out",
        "o.json",
        "--redact",
        "hostnames",
    ],
    &["enroll", "lab"],
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
    &["enroll", "status"],
    &["enroll", "verify", "enr-1"],
    &["enroll", "verify", "enr-1", "--absence"],
    &["enroll", "verify", "enr-1", "--approve-target-change"],
    &["enroll", "remove", "enr-1"],
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
    &["enroll", "reconcile", "op-1"],
    &["enroll", "reconcile", "op-1", "--after-manual-recovery"],
    &["enroll", "abandon", "enr-1"],
    &["destination", "prefer", "lab", "managed"],
    &["destination", "prefer", "lab", "existing"],
    &[
        "access",
        "ensure",
        "--profile",
        "p",
        "--work-id",
        "w",
        "--request-id",
        "r",
        "--strict",
    ],
    &["access", "lock-behavior", "--policy", "pol", "continue"],
    &[
        "access",
        "lock-behavior",
        "--policy",
        "pol",
        "revoke-on-lock",
    ],
    &["access", "connection-policy", "--policy", "pol"],
    &[
        "access",
        "connection-policy",
        "--policy",
        "pol",
        "--existing",
        "strict",
        "--multiplexing",
        "owned",
    ],
    &["connections"],
    &["connections", "close", "conn-1"],
    &["internal", "issuer"],
    &["internal", "session-lock-state"],
];

/// `w0_m03_cli_commands_report_not_available_and_never_panic`: M01's envelope for every
/// M03 command, `--json` and human, with no runtime directory (nor the home) created.
#[test]
fn w0_m03_cli_commands_report_not_available_and_never_panic() {
    let scratch = tempfile::tempdir().unwrap();
    let account = scratch.path().join("account");
    std::fs::create_dir_all(&account).unwrap();
    let expected = not_available_text();
    for (i, line) in M03_LINES.iter().enumerate() {
        let home = scratch.path().join(format!("home-{i}"));
        let mut argv = vec!["--json", "--non-interactive"];
        argv.extend_from_slice(line);
        let out = run(&home, &account, &argv, &[]);
        assert_eq!(out.code, 2, "{line:?}: {out:?}");
        let env = out.json();
        assert_eq!(env["code"], "USAGE_ERROR", "{line:?}: {out:?}");
        assert_eq!(out.message(), expected, "{line:?}: {out:?}");
        assert_eq!(env["data"]["error"]["effect_status"], "none", "{line:?}");
        assert_eq!(env["next"]["action"], "fix_request", "{line:?}: {out:?}");
        assert!(
            !home.exists(),
            "{line:?} created the Heimdall home (runtime contact)"
        );
        assert!(
            !home.join("run").join("instance.json").exists(),
            "{line:?} started a runtime"
        );
    }

    // Human mode: the message on stderr, nothing on stdout but the head line, exit 2.
    let home = scratch.path().join("home-human");
    let out = run(&home, &account, &["issuer", "status"], &[]);
    assert_eq!(out.code, 2, "{out:?}");
    assert!(out.stderr.contains(&expected), "{out:?}");
    assert!(!home.exists());

    // A line the tree refuses is an ordinary usage error, not the wave-0 answer.
    for line in [
        &["issuer", "init"][..],
        &["enroll"],
        &["enroll", "remove"],
        &["access", "lock-behavior", "--policy", "pol", "sometimes"],
        &["uninstall", "--keep-remote-enrollments"],
        &["uninstall", "--purge-state", "--bundle", "f"],
    ] {
        let mut argv = vec!["--json"];
        argv.extend_from_slice(line);
        let out = run(&scratch.path().join("home-usage"), &account, &argv, &[]);
        assert_eq!(out.code, 2, "{line:?}: {out:?}");
        assert_eq!(out.json()["code"], "USAGE_ERROR", "{line:?}");
        assert_ne!(out.message(), expected, "{line:?}");
    }

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

    // An absolute directory: a debug build goes on to the wave-0 answer, a release
    // build refuses the variable.
    let abs = scratch.path().join("pause");
    let abs = abs.to_string_lossy().into_owned();
    let out = run(
        &home,
        &account,
        &["--json", "enroll", "lab"],
        &[("HEIMDALL_TEST_SCRIPT_PAUSE_DIR", &abs)],
    );
    assert_eq!(out.code, 2, "{out:?}");
    if debug_build {
        assert_eq!(out.message(), not_available_text(), "{out:?}");
    } else {
        assert!(out.message().contains("HEIMDALL_TEST_"), "{out:?}");
    }
    assert!(!home.exists());

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
/// (`bundle_required`) and, with one, fails closed; final enrollments do not refuse;
/// a plain `uninstall` is not affected by the new check.
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

    // ...and with one, nothing can verify it yet: fail closed, nothing changed.
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
    assert_eq!(out.code, 2, "{out:?}");
    assert_eq!(out.message(), not_available_text(), "{out:?}");
    assert!(db.exists());
    assert!(!home.join("run").exists());

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
