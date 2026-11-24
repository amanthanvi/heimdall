//! ⟨M06 W5 U7⟩ What every M06 exit journey shares beyond [`super::world`]: the observation
//! line, envelope reads, and the runner-side requests of the journeys.
#![allow(dead_code)] // each of the two targets uses its own part

use std::process::Stdio;

use serde_json::Value;

use super::world::{ControllerRuntime, Journey, Runner};

/// One step's stable result: `m06 observation: <case> <step>: <result>`. The result holds
/// no identifier, path, port or instant, so two platforms' lines can be compared.
#[allow(clippy::print_stdout)] // the observation lines are the suite's output
pub(crate) fn observe(case: &str, step: &str, result: impl std::fmt::Display) {
    println!("m06 observation: {case} {step}: {result}");
}

/// A step this host cannot run, said so in the output (never a result).
#[allow(clippy::print_stdout)]
pub(crate) fn blocked(case: &str, why: &str) {
    println!("m06 observation: {case} journey: blocked ({why})");
}

/// The envelope a `--json` command printed.
pub(crate) fn json_of(out: &std::process::Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
        panic!(
            "no envelope: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// `heimdall --json <args…>` as the runner's local owner, without a terminal.
pub(crate) fn runner_json(runner: &Runner, args: &[&str]) -> Value {
    json_of(
        &runner
            .command()
            .arg("--json")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap(),
    )
}

/// The controller owner's `access ensure --environment <runner>` for `runner-profile`,
/// naming no pair, to its settled answer: a pending `ACCEPTED` (checked: no reason, the
/// controller as refresh dependency, the grant listed) is followed with `operation wait`.
/// Returns the answer and whether it was pending first.
pub(crate) fn forwarded_ensure(
    j: &Journey,
    work: &str,
    request: &str,
    lifetime: &str,
) -> (Value, bool) {
    let args = [
        "access",
        "ensure",
        "--profile",
        "runner-profile",
        "--environment",
        j.environment.as_str(),
        "--work-id",
        work,
        "--for",
        lifetime,
        "--request-id",
        request,
    ];
    let mut answer = j.controller.json(&args);
    let mut pending = false;
    if answer["code"] == "ACCEPTED" {
        pending = true;
        let data = &answer["data"];
        assert!(data["error"].get("reason").is_none(), "{answer}");
        assert_eq!(data["refresh_dependency"], "controller", "{answer}");
        assert_eq!(
            data["remote_pending"][0], data["error"]["resource"]["id"],
            "{answer}"
        );
        let operation = answer["operation_id"]
            .as_str()
            .unwrap_or_else(|| panic!("the pending answer names no operation: {answer}"))
            .to_owned();
        answer = j
            .controller
            .json(&["operation", "wait", &operation, "--timeout-ms", "60000"]);
    }
    (answer, pending)
}

/// Both runtimes' stderr, for a failed step's message.
pub(crate) fn logs(j: &Journey) -> String {
    format!(
        "controller: {}\nrunner: {}",
        j.controller.stderr(),
        runner_stderr(&j.runner)
    )
}

pub(crate) fn runner_stderr(runner: &Runner) -> String {
    std::fs::read_to_string(runner.account.join("runtime.stderr")).unwrap_or_default()
}

/// The process IDs whose parent is `parent` (read-only; IDs only).
pub(crate) fn children_of(parent: u32) -> Vec<u32> {
    let out = std::process::Command::new("ps")
        .args(["-A", "-o", "pid=", "-o", "ppid="])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut w = l.split_ascii_whitespace();
            let pid: u32 = w.next()?.parse().ok()?;
            let ppid: u32 = w.next()?.parse().ok()?;
            (ppid == parent).then_some(pid)
        })
        .collect()
}

/// Whether the process `pid` exists (read-only).
pub(crate) fn alive(pid: u32) -> bool {
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .is_ok_and(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
}

/// The controller runtime's process ID while it runs.
pub(crate) fn runtime_pid(c: &ControllerRuntime) -> Option<u32> {
    c.runtime.as_ref().map(std::process::Child::id)
}
