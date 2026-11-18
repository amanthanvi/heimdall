//! M04 and M05 joint wave 0 (ADR-0010 §9 items 8–9; ADR-0011 §10 items 8–10): every new
//! command and flag refuses as "not available in this build (planned for M04|M05)" through
//! the **real binary** (`CARGO_BIN_EXE_heimdall`, or `HEIMDALL_E2E_BIN`).
//!
//! One table-driven test. Each row is a command line and the milestone that owns it; each
//! must answer, with `--json`: exit 2, `USAGE_ERROR`, effect `none`, `next.action`
//! `fix_request` and the milestone's message, and must neither contact or start a runtime nor
//! create the Heimdall home (the home path does not exist before and after). `run` keeps
//! stdout for the launched program, so its envelope is on stderr (spec §10.4).
//!
//! The same test pins that the forms the new flags extend are unchanged: the policy-ID form of
//! `access pause|resume|cutoff` still reaches its own validation (an invalid ID is an ordinary
//! usage error, not the refusal). Each track deletes the rows of the commands it builds
//! (M04 U1: `service autostart enable|disable|status` and `service run --login`, now
//! `service_login_m04`'s).
//!
//! **Isolation.** A cleared environment, a scratch `HOME` and a Heimdall home that does not
//! exist, stdin closed; synthetic arguments only (no owner key, agent or keychain).
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::path::Path;
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

/// The refusal text for a milestone, built at run time (the M02 and M03 source guards scan
/// for the unassembled text, as `cli_m03.rs` does).
fn refusal(milestone: &str) -> String {
    [
        "this command is not available",
        &format!("in this build (planned for {milestone})"),
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
    /// The last JSON object in `text` (the envelope).
    fn envelope(text: &str) -> Option<Value> {
        text.lines()
            .rev()
            .filter_map(|l| l.trim().find('{').map(|i| l.trim()[i..].to_owned()))
            .find_map(|l| serde_json::from_str::<Value>(&l).ok())
    }
}

/// Run the binary with a cleared environment and stdin closed; both streams are scanned.
fn run(home: &Path, account: &Path, args: &[&str]) -> Out {
    let mut cmd = Command::new(bin());
    cmd.arg("--json")
        .arg("--non-interactive")
        .args(args)
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

/// Every new M04 command line and flag (ADR-0010 §9 item 9; the m04-plan units), with the
/// stream its envelope is on.
const M04: &[&[&str]] = &[];

/// Every new M05 command line and flag (ADR-0011 §10 item 10; the m05-plan units).
const M05: &[&[&str]] = &[
    &["project", "trust"],
    &["project", "status", "--cwd", "."],
    &["project", "untrust", "--cwd", "."],
    &["project", "reconcile"],
    &["access", "allow", "--policy", "pol"],
    &["access", "allow", "--profile", "dev"],
    &["access", "allow", "--workspace", "--cwd", "."],
    &["access", "stop", "--work", "w"],
    &["access", "stop", "--policy", "pol"],
    &["access", "stop", "--profile", "dev"],
    &["access", "stop", "--workspace"],
    &["access", "stop", "--all"],
    &["access", "pause", "--profile", "dev"],
    &["access", "pause", "--workspace"],
    &["access", "pause", "--all"],
    &["access", "resume", "--profile", "dev"],
    &["access", "resume", "--workspace"],
    &["access", "resume", "--all"],
    &[
        "access",
        "cutoff",
        "--profile",
        "dev",
        "--at",
        "2030-01-01T00:00:00Z",
    ],
    &["access", "cutoff", "--workspace", "--clear"],
    &["access", "cutoff", "--all", "--clear"],
    &["activate", "--hook", "--cwd", "."],
    &["shell", "init", "zsh"],
    &["shell", "init", "bash"],
    &["export"],
    &["export", "--redact"],
    &["import", "bundle.json"],
];

/// `run --parent-binding` (M05): the envelope is on stderr.
const M05_RUN: &[&str] = &[
    "run",
    "--profile",
    "dev",
    "--parent-binding",
    "bnd",
    "--",
    "true",
];

fn assert_refused(out: &Out, on_stderr: bool, expected: &str, line: &[&str]) {
    assert_eq!(out.code, 2, "{line:?}: {out:?}");
    let (stream, other) = if on_stderr {
        (&out.stderr, &out.stdout)
    } else {
        (&out.stdout, &out.stderr)
    };
    let env = Out::envelope(stream).unwrap_or_else(|| panic!("{line:?}: no envelope: {out:?}"));
    assert_eq!(env["code"], "USAGE_ERROR", "{line:?}: {out:?}");
    assert_eq!(env["data"]["error"]["message"], expected, "{line:?}");
    assert_eq!(env["data"]["error"]["effect_status"], "none", "{line:?}");
    assert_eq!(env["next"]["action"], "fix_request", "{line:?}: {out:?}");
    // The other stream carries no envelope (`run`'s stdout belongs to the program).
    assert!(Out::envelope(other).is_none(), "{line:?}: {out:?}");
}

/// Every new command or flag refuses with the "not available" envelope, contacts no
/// runtime and creates no home; the forms the flags extend keep their own behaviour.
#[test]
fn m04_m05_new_commands_refuse_as_not_available_without_a_runtime() {
    let scratch = tempfile::tempdir().unwrap();
    let account = scratch.path().join("account");
    std::fs::create_dir_all(&account).unwrap();
    let mut rows: Vec<(&[&str], &str, bool)> = Vec::new();
    rows.extend(M04.iter().map(|l| (*l, "M04", false)));
    rows.extend(M05.iter().map(|l| (*l, "M05", false)));
    rows.push((M05_RUN, "M05", true));
    for (i, (line, milestone, on_stderr)) in rows.iter().enumerate() {
        let home = scratch.path().join(format!("home-{i}"));
        let out = run(&home, &account, line);
        assert_refused(&out, *on_stderr, &refusal(milestone), line);
        assert!(!home.exists(), "{line:?} created the Heimdall home");
    }

    // The forms the new flags extend are unchanged: an invalid policy ID is the existing
    // `USAGE_ERROR` (before any runtime contact), not the refusal; a target and a policy ID
    // together, or neither, is a parse error.
    let home = scratch.path().join("home-existing");
    for line in [
        &["access", "pause", "not a policy id"][..],
        &["access", "resume", "not a policy id"],
        &["access", "cutoff", "not a policy id", "--clear"],
    ] {
        let out = run(&home, &account, line);
        assert_eq!(out.code, 2, "{line:?}: {out:?}");
        let env = Out::envelope(&out.stdout).unwrap();
        assert_eq!(
            env["data"]["error"]["message"], "invalid policy ID",
            "{line:?}"
        );
    }
    for line in [
        &["access", "pause"][..],
        &["access", "pause", "pol", "--all"],
        &["access", "pause", "--profile", "dev", "--workspace"],
        &["access", "stop"],
        &["access", "stop", "--work", "w", "--all"],
        &["wsl", "enable", "Debian", "--mode-a", "--mode-b"],
    ] {
        let out = run(&home, &account, line);
        assert_eq!(out.code, 2, "{line:?}: {out:?}");
        let env = Out::envelope(&out.stdout).unwrap();
        assert_eq!(env["code"], "USAGE_ERROR", "{line:?}");
        for milestone in ["M04", "M05"] {
            assert_ne!(
                env["data"]["error"]["message"],
                refusal(milestone),
                "{line:?}: a parse error is not the refusal"
            );
        }
    }
    assert!(!home.exists(), "an existing-form refusal created the home");
}
