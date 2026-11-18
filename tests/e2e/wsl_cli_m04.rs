//! ⟨M04 U3b⟩ `heimdall wsl enable|disable|status` on a host without WSL (ADR-0010 §2): the real
//! binary answers before it contacts or starts a runtime and before it creates the Heimdall
//! home. One table (ADR-0010 §9 item 8: new command refusals get one table-driven test).
//! The Windows rows (a disposable distribution) are the A12 native suite's.

use std::process::{Command, Stdio};

use heimdall_testkit::assert_no_canary;
use serde_json::Value;

fn bin() -> String {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
}

/// Each line, its exit status and its envelope's `code` and `reason`.
const ROWS: &[(&[&str], i32, &str, Option<&str>)] = &[
    (
        &["wsl", "status"],
        4,
        "CAPABILITY_UNAVAILABLE",
        Some("wsl_unavailable"),
    ),
    (
        &["wsl", "enable", "Debian", "--mode-a", "--account", "dev"],
        4,
        "CAPABILITY_UNAVAILABLE",
        Some("wsl_unavailable"),
    ),
    (&["wsl", "enable", "Debian"], 2, "USAGE_ERROR", None),
    (
        &["wsl", "disable", "Debian", "--start"],
        4,
        "CAPABILITY_UNAVAILABLE",
        Some("wsl_unavailable"),
    ),
];

#[test]
fn wsl_commands_refuse_without_wsl_before_any_runtime_or_home() {
    let scratch = tempfile::tempdir().unwrap();
    let home = scratch.path().join("heimdall-home");
    let account = scratch.path().join("account");
    std::fs::create_dir(&account).unwrap();
    for (args, exit, code, reason) in ROWS {
        let out = Command::new(bin())
            .arg("--json")
            .arg("--non-interactive")
            .args(*args)
            .env_clear()
            .env("HEIMDALL_HOME", &home)
            .env("HOME", &account)
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_no_canary(&stdout);
        assert_no_canary(&stderr);
        assert_eq!(
            out.status.code(),
            Some(*exit),
            "{args:?}: {stdout} {stderr}"
        );
        let env: Value = stdout
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str(l.trim()).ok())
            .unwrap_or_else(|| panic!("{args:?}: no envelope: {stdout}"));
        assert_eq!(env["code"], *code, "{args:?}");
        assert_eq!(env["data"]["error"]["reason"].as_str(), *reason, "{args:?}");
        assert!(
            !home.exists(),
            "{args:?}: no runtime contacted and no Heimdall home created"
        );
    }
}
