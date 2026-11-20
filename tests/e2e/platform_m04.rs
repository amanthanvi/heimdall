//! ⟨M04⟩ The M04 platform suite (m04-plan U1, U2): the real binary's login-entry commands on
//! every host, and the native Windows integration on Windows. One target with platform-gated
//! modules, so every host runs at least one of its tests (`tools/validation/check.sh`'s
//! test discovery refuses a target that runs none).
//!
//! * [`service_login`]: `service run --login`, `service autostart`, uninstall's login-entry
//!   seam (U1; every host).
//! * `windows`: inherited-handle lists, the A14 non-takeover inventory and the Git client
//!   finding (U2; Windows only).
//! * `wsl_cli`: `wsl enable|disable|status` on a host without WSL (U3b; every host but
//!   Windows).
//! * `container`: the container recipe's mounted flow (U5; Linux only; its engine rows skip
//!   by name without `HEIMDALL_M04_CONTAINER_ENGINE`).
//! * `wsl_mode_b`: WSL Mode B through the real binary with the helper started directly, as the
//!   distribution's stand-in (U4; Unix; mechanism evidence, the native rows are `windows`').
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    missing_docs
)]

#[path = "service_login_m04.rs"]
mod service_login;

// The M03 exit suite's world (a scratch home, the CLI-started runtime and its issuer child, a
// seeded CA, one server per pair), shared by the modules that drive the product end to end.
// `world.rs` names `crate::procs`.
#[cfg(any(unix, windows))]
#[path = "exit_m03/procs.rs"]
mod procs;
#[cfg(any(unix, windows))]
#[path = "exit_m03/world.rs"]
mod world;

#[cfg(windows)]
#[path = "windows_m04.rs"]
mod windows;

#[cfg(not(windows))]
#[path = "wsl_cli_m04.rs"]
mod wsl_cli;

#[cfg(target_os = "linux")]
#[path = "container_m04.rs"]
mod container;

#[cfg(unix)]
#[path = "wsl_mode_b_m04.rs"]
mod wsl_mode_b;

/// ⟨M04, the Windows readiness failures⟩ The exact-identity runtime guard
/// (`world::stop_started_runtimes`) never kills a process that is not this suite's `heimdall`:
/// a live process recorded with its own PID and start token (here `sleep`), and a record whose
/// PID names no such process, are left alone, and nothing is reported killed.
#[cfg(unix)]
#[test]
fn runtime_guard_never_kills_a_recorded_process_that_is_not_heimdall() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let mut other = std::process::Command::new("/bin/sleep")
        .arg("60")
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let pid = other.id();
    let token = heimdall_runtime::platform::process_start_time(pid).expect("its start token");
    std::fs::write(
        state.join("test-service-starts"),
        format!("{pid} {token}\n{pid} not-its-token\n"),
    )
    .unwrap();
    let env = vec![(
        std::ffi::OsString::from("HEIMDALL_HOME"),
        dir.path().as_os_str().to_owned(),
    )];
    let killed = world::stop_started_runtimes_within(
        &env,
        &state,
        dir.path(),
        std::time::Duration::from_secs(1),
    );
    assert_eq!(killed, 0);
    assert!(
        other.try_wait().unwrap().is_none(),
        "a recorded process whose image is not heimdall is never killed"
    );
    // Only the exact child this test started.
    other.kill().unwrap();
    other.wait().unwrap();
}

/// ⟨M04, the Windows readiness failures⟩ The guard's kill path: a real `heimdall` runtime of a
/// scratch installation, recorded under the test configuration and serving, that `service stop`
/// cannot reach (the guard is given another installation's environment, as for a runtime that
/// never advertised) is killed by exact identity once the grace period ends, and is gone.
#[cfg(unix)]
#[test]
fn runtime_guard_kills_a_recorded_runtime_service_stop_cannot_reach() {
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::create_dir_all(&b).unwrap();
    let bin = std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned());
    let err_path = dir.path().join("runtime.err");
    // As the M01 suite starts one: this process's environment without any Heimdall
    // variable or agent, plus the scratch home and the synchronized test clock.
    let mut cmd = std::process::Command::new(&bin);
    cmd.args(["service", "run"]);
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy().into_owned();
        if k.starts_with("HEIMDALL_") || k.starts_with("SSH_AUTH") || k.starts_with("SSH_AGENT") {
            cmd.env_remove(&k);
        }
    }
    let mut runtime = cmd
        .env("HEIMDALL_HOME", &a)
        .env("HEIMDALL_TEST_TIME_SYNC", "synchronized")
        .current_dir(dir.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(&err_path).unwrap())
        .spawn()
        .unwrap();
    let why = |runtime: &mut std::process::Child| {
        format!(
            "status {:?}, stderr: {}",
            runtime.try_wait().unwrap(),
            std::fs::read_to_string(&err_path).unwrap_or_default()
        )
    };
    // Serving: recorded, and advertised (a runtime that advertised stays until stopped).
    let record = a.join("state").join("test-service-starts");
    let advertised = a.join("run").join("instance.json");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !(std::fs::read_to_string(&record).is_ok_and(|s| s.contains(' ')) && advertised.exists())
    {
        assert!(
            runtime.try_wait().unwrap().is_none(),
            "the runtime runs: {}",
            why(&mut runtime)
        );
        assert!(
            Instant::now() < deadline,
            "the runtime serves: {}",
            why(&mut runtime)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let other = vec![(
        std::ffi::OsString::from("HEIMDALL_HOME"),
        b.as_os_str().to_owned(),
    )];
    let killed = world::stop_started_runtimes_within(
        &other,
        &a.join("state"),
        dir.path(),
        Duration::from_secs(1),
    );
    assert_eq!(
        killed,
        1,
        "the recorded runtime is killed by exact identity: {}",
        why(&mut runtime)
    );
    let gone_by = Instant::now() + Duration::from_secs(10);
    while runtime.try_wait().unwrap().is_none() {
        assert!(Instant::now() < gone_by, "the killed runtime is gone");
        std::thread::sleep(Duration::from_millis(50));
    }
}
