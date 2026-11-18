//! The debug-build guard against the account's real home (orchestrator ruling I-15), through
//! the **real binary** (`CARGO_BIN_EXE_heimdall`, or `HEIMDALL_E2E_BIN`).
//!
//! With no `HEIMDALL_HOME` and the process's home set to the account's real home (read from
//! the account database or the token, never the environment), a debug build must refuse
//! before it creates, reads or starts anything: exit 2, `USAGE_ERROR`, effect `none`. With
//! `HEIMDALL_DEV_ALLOW_ACCOUNT_HOME=1` it must not be the guard that stops it.
//!
//! **Safety: a broken guard cannot write to the real home.** `HOME` (Unix) or `USERPROFILE`
//! (Windows) is the real home, which is the point of the test, but every directory the default
//! paths derive from is redirected into a scratch directory: `XDG_STATE_HOME`,
//! `XDG_CONFIG_HOME` and `XDG_RUNTIME_DIR` on Unix (`Paths::platform_defaults` reads them
//! before `HOME`), `LOCALAPPDATA` on Windows (etcetera reads it before the known folder). The
//! escape leg runs only `status`, which never starts a runtime and never creates a directory.
//! The test asserts the scratch tree is still empty after every refusal.
//!
//! **Platforms:** the guard's Windows branch (`USERPROFILE` against
//! `GetUserProfileDirectoryW`) is compiled and covered by this same test on Windows; it is
//! not run on this platform unless this platform is Windows.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]
// Release test builds have no guard (`refusal` is a constant `None`), so this suite is the
// debug-build behaviour only.
#![cfg(debug_assertions)]

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

/// The account's real home, from the account database / process token (the same call the
/// guard makes). Only compared against and exported as `HOME`; nothing is ever written there.
fn account_home() -> PathBuf {
    heimdall_localenv::sys::account_home().expect("the account home")
}

/// A scratch root and the redirected directories under it, all empty.
struct Scratch {
    root: tempfile::TempDir,
}

impl Scratch {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        for d in ["state", "config", "run", "localappdata"] {
            std::fs::create_dir(root.path().join(d)).unwrap();
        }
        Self { root }
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    /// Every entry below the scratch root other than the four pre-created directories.
    fn leftovers(&self) -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                out.push(p.clone());
                if p.is_dir() {
                    walk(&p, out);
                }
            }
        }
        let mut all = Vec::new();
        walk(self.root.path(), &mut all);
        all.retain(|p| {
            !["state", "config", "run", "localappdata"]
                .iter()
                .any(|d| *p == self.dir(d))
        });
        all
    }
}

#[derive(Debug)]
struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Run the binary with a cleared environment: no `HEIMDALL_HOME`, the real home as the
/// process home, every default-directory variable in `scratch`.
fn run(scratch: &Scratch, allow: bool, args: &[&str]) -> Out {
    let mut cmd = Command::new(bin());
    cmd.arg("--json")
        .arg("--non-interactive")
        .args(args)
        .env_clear()
        .env("XDG_STATE_HOME", scratch.dir("state"))
        .env("XDG_CONFIG_HOME", scratch.dir("config"))
        .env("XDG_RUNTIME_DIR", scratch.dir("run"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::null());
    if cfg!(windows) {
        cmd.env("USERPROFILE", account_home())
            .env("LOCALAPPDATA", scratch.dir("localappdata"))
            .env("APPDATA", scratch.dir("config"));
        for k in ["SystemRoot", "PATH", "TEMP", "TMP"] {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
    } else {
        cmd.env("HOME", account_home()).env("PATH", "/usr/bin:/bin");
    }
    if allow {
        cmd.env("HEIMDALL_DEV_ALLOW_ACCOUNT_HOME", "1");
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

fn envelope(text: &str) -> Option<Value> {
    text.lines()
        .rev()
        .filter_map(|l| l.trim().find('{').map(|i| l.trim()[i..].to_owned()))
        .find_map(|l| serde_json::from_str::<Value>(&l).ok())
}

fn is_guard_refusal(out: &Out) -> bool {
    envelope(&out.stdout).is_some_and(|e| {
        e["code"] == "USAGE_ERROR"
            && e["data"]["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("HEIMDALL_DEV_ALLOW_ACCOUNT_HOME"))
    })
}

/// `status` only contacts a runtime; `access release` is effectful, so it starts one on
/// demand. Both are refused before anything happens.
#[test]
fn a_debug_build_refuses_the_account_home_without_touching_anything() {
    let scratch = Scratch::new();
    let release = format!("binding_{}", "0123456789abcdef".repeat(2));
    for line in [&["status"][..], &["access", "release", release.as_str()]] {
        let out = run(&scratch, false, line);
        assert_eq!(out.code, 2, "{line:?}: {out:?}");
        let env = envelope(&out.stdout).unwrap_or_else(|| panic!("{line:?}: no envelope: {out:?}"));
        assert_eq!(env["code"], "USAGE_ERROR", "{line:?}: {out:?}");
        assert_eq!(env["data"]["error"]["effect_status"], "none", "{line:?}");
        let message = env["data"]["error"]["message"].as_str().unwrap();
        assert!(message.contains("HEIMDALL_HOME"), "{message}");
        assert!(
            message.contains("HEIMDALL_DEV_ALLOW_ACCOUNT_HOME"),
            "{message}"
        );
        assert!(
            scratch.leftovers().is_empty(),
            "{line:?} created {:?}",
            scratch.leftovers()
        );
    }
}

/// With the escape the guard lets `status` through: it reaches the runtime lookup and fails
/// for another reason (no runtime running), and it still creates nothing in the scratch
/// redirection.
#[test]
fn the_escape_variable_lets_it_through() {
    let scratch = Scratch::new();
    let out = run(&scratch, true, &["status"]);
    assert!(!is_guard_refusal(&out), "{out:?}");
    assert_ne!(
        out.code, 0,
        "no runtime is running in the scratch home: {out:?}"
    );
    assert!(
        scratch.leftovers().is_empty(),
        "status created {:?}",
        scratch.leftovers()
    );
}
