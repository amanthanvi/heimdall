//! ⟨M04 U2⟩ Native Windows integration (ADR-0010 §1 items 4–6; m04-plan U2; A14, A13
//! channel privacy). Every test here is `#[cfg(windows)]` and runs natively on the PC; on any
//! other host this suite is empty (the pure classifier and the argument, environment and
//! quoting rules are unit-tested in `heimdall_localenv`, `sys::spawn` and `doctor`).
//!
//! * `runtime_child_inherits_only_listed_handles` (A14, A13): a nonsecret marker file handle,
//!   inheritable and open while the child starts, is absent in a child started through
//!   `spawn_with_handle_list` and in the issuer child path (the spawner the runtime injects
//!   into the issuer client), and **present** in a child of a plain inheritable `Command`
//!   spawn (the positive control, so the assertion can fail).
//! * `a14_no_global_agent_takeover_inventory_identical` (A14): the real binary's product
//!   steps, run on a scratch installation, leave the owner's global agent pipe, `ssh-agent`
//!   service (configuration, state and SDDL, read with `sc.exe`, read-only), `HKCU\Environment`
//!   (`reg.exe query`), Git global and system configuration and `%USERPROFILE%\.ssh` exactly
//!   as they were. **A product step is one line in [`STEPS`]**: the login entry (U1,
//!   into a scratch registry root, never the account's Run key) is there; WSL Mode A enable
//!   and disable (U3b) join with a disposable distribution.
//! * `a14_git_bundled_client_reported_not_claimed` (A14): with Git for Windows' bundled `ssh`
//!   as Git's effective client the doctor reports `git_client_cannot_reach_pipe`; once an
//!   override names the in-box `ssh.exe` (the M02 Git item's result) it does not.
//! * `inherited_state_dir_then_setup_rollback_and_uninstall` (M04-W1-R02; ADR-0010 §10
//!   item 5): a state directory with the inherited list of a build before M04 is narrowed
//!   once, and `setup rollback` and `uninstall` both run on it.
//!
//! * `a13_*` and `a03_mode_b_fresh_logins_while_windows_locked` (⟨M04 U4b⟩, WSL Mode B, ADR-0010
//!   §3): the native A13 rows through the real binary, the real runtime and its Linux helper
//!   in disposable distributions, over the exit suite's [`world::World`] (the real issuer
//!   child, a verified enrollment, the harness's sshd). `#[ignore]`d, and each needs
//!   `HM_WSL_TEST_DISTRO`, `HM_WSL_TEST_ACCOUNT` and `HM_WSL_TEST_HELPER` as the A12 rows do
//!   (the row for two distributions: also `HM_WSL_TEST_DISTRO2`, and optionally
//!   `HM_WSL_TEST_ACCOUNT2`); an unset variable panics, it never reads as a pass. The Linux
//!   `ssh` and Git inside the distribution reach the harness's sshd at the host and port the
//!   catalog names (WSL2 distributions share one network namespace, so a loopback server of
//!   the harness's own distribution is reachable from the disposable one).
//!
//! **Not added here:** `a14_managed_alias_never_contacts_inherited_ssh_auth_sock` is already
//! asserted on Windows by `e2e_enroll_m03`'s
//! `enroll_preview_apply_verify_setup_apply_ensure_ssh` (a decoy pipe at `SSH_AUTH_SOCK` for the
//! real `ssh`, whose contact count is unchanged across setup apply, ensure and ssh).
//!
//! **Isolation.** Disposable fixtures only: a scratch installation (`HEIMDALL_HOME`,
//! `HEIMDALL_TEST_SSH_HOME`, scratch secret store) and a scratch Git home. The owner's
//! material is read only by the inventory: names and digests, never content, and no pipe is
//! opened, no service is started, stopped or changed.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::too_many_lines,
    dead_code,
    missing_docs
)]

// ⟨M04 U4b⟩ The A13 rows use the exit suite's world, declared at the suite's root
// (`platform_m04.rs`).

#[cfg(windows)]
mod native {
    use std::collections::BTreeSet;
    use std::ffi::OsString;
    use std::fs::File;
    use std::hash::{Hash, Hasher};
    use std::io::Read;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use heimdall_localenv::clients::ClientsConfig;
    use heimdall_localenv::doctor::{DoctorRequest, LocalContext, run};
    use heimdall_localenv::env::{Env, Platform};
    use heimdall_localenv::paths::SshPaths;
    use heimdall_localenv::sys::spawn::spawn_with_handle_list;
    use heimdall_sshconf::limits::Limits;
    use heimdall_testkit::home::{Scratch, find_program};
    use heimdall_testkit::installation::SecondInstallation;
    use heimdall_testkit::owner_digest::OwnerDigest;

    fn bin() -> String {
        std::env::var("HEIMDALL_E2E_BIN")
            .ok()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
    }

    // --- the handle probe (re-executed by the handle test) -------------------------------

    const PROBE_HANDLE: &str = "HM_U2_PROBE_HANDLE";
    const PROBE_MARKER: &str = "HM_U2_PROBE_MARKER";
    const PROBE_PREFIX: &str = "HM_U2_PROBE=";

    /// The tiny FFI the native tests need. `unsafe_code` is denied workspace-wide and listed in
    /// the overview §9 inventory for production modules; this test-only module opts in for
    /// three read or flag-setting calls on handles this test owns.
    #[allow(unsafe_code)]
    mod ffi {
        use std::os::windows::io::RawHandle;

        use windows_sys::Win32::Foundation::{
            GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation,
        };
        use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

        /// Make `handle` inheritable.
        pub fn make_inheritable(handle: RawHandle) {
            // SAFETY: `handle` is an open handle owned by the caller's `File`.
            let ok = unsafe {
                SetHandleInformation(handle as HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
            };
            assert!(ok != 0, "SetHandleInformation failed");
        }

        /// Whether `handle` is inheritable (`None`: not a valid handle).
        pub fn is_inheritable(handle: RawHandle) -> Option<bool> {
            let mut flags = 0u32;
            // SAFETY: `flags` is a valid out-pointer; an invalid handle only makes the call
            // fail.
            let ok = unsafe { GetHandleInformation(handle as HANDLE, &raw mut flags) };
            (ok != 0).then_some(flags & HANDLE_FLAG_INHERIT != 0)
        }

        /// Whether the numeric `handle` names a file whose final path ends with `marker`
        /// (identifying the object, not the value: another handle with the same number is
        /// not the marker).
        pub fn names_marker(handle: usize, marker: &str) -> bool {
            let mut buf = vec![0u16; 4096];
            // SAFETY: `buf` holds `len` UTF-16 units for the call; an invalid or non-file
            // handle makes it return 0.
            let n = unsafe {
                GetFinalPathNameByHandleW(
                    handle as HANDLE,
                    buf.as_mut_ptr(),
                    u32::try_from(buf.len()).unwrap(),
                    0,
                )
            } as usize;
            n > 0
                && n < buf.len()
                && String::from_utf16_lossy(&buf[..n])
                    .to_lowercase()
                    .ends_with(&marker.to_lowercase())
        }
    }

    /// The probe: re-executed with `--exact <its name> --nocapture` ([`probe_name`]), it reports
    /// whether the handle number in `HM_U2_PROBE_HANDLE` names the marker file. A no-op unless
    /// the variables are set.
    #[test]
    fn handle_probe_child() {
        let (Some(handle), Some(marker)) = (
            std::env::var(PROBE_HANDLE).ok(),
            std::env::var(PROBE_MARKER).ok(),
        ) else {
            return;
        };
        let present = ffi::names_marker(handle.parse().unwrap(), &marker);
        println!(
            "{PROBE_PREFIX}{}",
            if present { "present" } else { "absent" }
        );
    }

    /// The probe's libtest name in this test binary. ⟨M04 Windows fix round⟩ Derived from the
    /// module path, not written out: since this file became the `windows` module of
    /// `e2e_platform_m04` the name is `windows::native::handle_probe_child`, and the literal
    /// `native::handle_probe_child` matched no test, so the probe printed nothing ("no verdict").
    fn probe_name() -> String {
        let path = module_path!();
        let inside = path.split_once("::").map_or(path, |(_, rest)| rest);
        format!("{inside}::handle_probe_child")
    }

    fn probe_args() -> Vec<String> {
        vec![
            "--exact".to_owned(),
            probe_name(),
            "--nocapture".to_owned(),
            "--test-threads=1".to_owned(),
        ]
    }

    fn probe_env(handle: usize, marker: &str) -> [(&'static str, OsString); 2] {
        [
            (PROBE_HANDLE, handle.to_string().into()),
            (PROBE_MARKER, marker.into()),
        ]
    }

    fn verdict(output: &str) -> &str {
        output
            .lines()
            .find_map(|l| l.trim().strip_prefix(PROBE_PREFIX))
            .unwrap_or_else(|| panic!("the probe printed no verdict: {output}"))
    }

    /// ADR-0010 §1 item 6 (closing ADR-0006 §13.9): a handle this process holds as inheritable
    /// reaches a child of a plain spawn (the positive control) but not a child of
    /// `spawn_with_handle_list` nor the issuer child path.
    #[test]
    fn runtime_child_inherits_only_listed_handles() {
        let dir = tempfile::tempdir().unwrap();
        let marker_name = format!(
            "hm-u2-marker-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let marker = File::create(dir.path().join(&marker_name)).unwrap();
        ffi::make_inheritable(marker.as_raw_handle());
        let number = marker.as_raw_handle() as usize;
        let exe = std::env::current_exe().unwrap();

        // Positive control: a plain std spawn inherits every inheritable handle.
        let mut plain = Command::new(&exe);
        plain.args(probe_args());
        for (k, v) in probe_env(number, &marker_name) {
            plain.env(k, v);
        }
        let out = plain.output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert_eq!(
            verdict(&text),
            "present",
            "the control must inherit the marker handle, or the test proves nothing: {text}"
        );

        // `spawn_with_handle_list`: the marker is absent, the three streams and the
        // environment still work, and the parent's ends are not inheritable.
        let mut cmd = Command::new(&exe);
        cmd.args(probe_args());
        for (k, v) in probe_env(number, &marker_name) {
            cmd.env(k, v);
        }
        let mut child = spawn_with_handle_list(&cmd).unwrap();
        for file in [&child.stdin, &child.stdout, &child.stderr]
            .into_iter()
            .flatten()
        {
            assert_eq!(
                ffi::is_inheritable(file.as_raw_handle()),
                Some(false),
                "the parent's pipe end is never inheritable"
            );
        }
        drop(child.stdin.take());
        let mut text = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(child.wait().unwrap(), 0, "{text}");
        assert_eq!(verdict(&text), "absent", "{text}");

        // The issuer child path: the spawner the runtime injects into the issuer client.
        let command = heimdall_issuer::client::ChildCommand {
            program: exe.clone(),
            args: probe_args().into_iter().map(OsString::from).collect(),
            env: probe_env(number, &marker_name)
                .into_iter()
                .map(|(k, v)| (OsString::from(k), v))
                .collect(),
        };
        let spawn = heimdall_runtime::service::listed_issuer_spawner();
        let mut spawned = spawn(&command).unwrap();
        drop(spawned.stdin);
        let mut text = String::new();
        spawned.stdout.read_to_string(&mut text).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while !spawned.process.try_wait().unwrap() {
            assert!(
                Instant::now() < deadline,
                "the issuer-path child did not exit"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(verdict(&text), "absent", "{text}");
        drop(marker);
    }

    // --- the A14 inventory ---------------------------------------------------------------

    /// A stable digest (equality only; never printed with a value).
    fn digest(bytes: &[u8]) -> String {
        let mut h = std::hash::DefaultHasher::new();
        bytes.hash(&mut h);
        format!("{:016x}", h.finish())
    }

    fn system32(program: &str) -> PathBuf {
        PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
            .join("System32")
            .join(program)
    }

    /// One read-only query: exit code and a digest of its output (the output is the
    /// owner's configuration and is never printed).
    fn read_only(program: &str, args: &[&str]) -> String {
        let out = Command::new(system32(program))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        format!(
            "exit={} stdout={} stderr={}",
            out.status.code().unwrap_or(-1),
            digest(&out.stdout),
            digest(&out.stderr)
        )
    }

    /// Everything A14 says a product step must leave alone. Reads only.
    #[derive(Debug, PartialEq, Eq)]
    struct Inventory {
        /// The names under `\\.\pipe\` that are, or look like, the global OpenSSH agent's.
        agent_pipes: BTreeSet<String>,
        /// Heimdall's own pipes (`heimdall-…`), which a finished step list leaves as it found
        /// them.
        heimdall_pipes: BTreeSet<String>,
        /// `sc.exe qc ssh-agent`, `sdshow ssh-agent` and `query ssh-agent`.
        agent_service: [String; 3],
        /// `reg.exe query HKCU\Environment`.
        user_environment: String,
        /// Whether `SSH_AUTH_SOCK` is a persistent user variable.
        persistent_ssh_auth_sock: bool,
        /// The system-wide Git configuration files that exist, with their digests.
        git_system: Vec<(String, String)>,
    }

    /// The `\\.\pipe\` names, listed by directory enumeration (no pipe is opened).
    fn pipe_names() -> BTreeSet<String> {
        std::fs::read_dir(r"\\.\pipe\")
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_lowercase())
            .collect()
    }

    fn inventory() -> Inventory {
        let pipes = pipe_names();
        let agent_pipes = pipes
            .iter()
            .filter(|n| n.contains("ssh-agent") || n.starts_with("openssh"))
            .cloned()
            .collect();
        let heimdall_pipes = pipes
            .iter()
            .filter(|n| n.starts_with("heimdall-"))
            .cloned()
            .collect();
        let env_query = Command::new(system32("reg.exe"))
            .args(["query", r"HKCU\Environment"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let env_text = String::from_utf8_lossy(&env_query.stdout).to_lowercase();
        let mut git_system = Vec::new();
        for (var, rel) in [
            ("ProgramFiles", r"Git\etc\gitconfig"),
            ("ProgramFiles(x86)", r"Git\etc\gitconfig"),
            ("ProgramData", r"Git\config"),
        ] {
            if let Some(base) = std::env::var_os(var) {
                let file = Path::new(&base).join(rel);
                if let Ok(bytes) = std::fs::read(&file) {
                    git_system.push((var.to_owned(), digest(&bytes)));
                }
            }
        }
        Inventory {
            agent_pipes,
            heimdall_pipes,
            agent_service: [
                read_only("sc.exe", &["qc", "ssh-agent"]),
                read_only("sc.exe", &["sdshow", "ssh-agent"]),
                read_only("sc.exe", &["query", "ssh-agent"]),
            ],
            user_environment: format!(
                "exit={} stdout={}",
                env_query.status.code().unwrap_or(-1),
                digest(env_text.as_bytes())
            ),
            persistent_ssh_auth_sock: env_text.contains("ssh_auth_sock"),
            git_system,
        }
    }

    /// How a step runs.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        /// A plain process with null stdin.
        Plain,
        /// On a pseudoconsole; the owner's prompt is answered `yes`.
        Attended,
    }

    /// The product steps the A14 inventory brackets: (name, arguments, mode, the envelope's
    /// `code`). **One line per step.** WSL Mode A enable and disable (U3b) join when a
    /// disposable distribution is part of this run.
    const STEPS: &[(&str, &[&str], Mode, &str)] = &[
        ("time confirm", &["time", "confirm"], Mode::Attended, "OK"),
        ("setup apply", &["setup", "apply"], Mode::Attended, "OK"),
        // ⟨M04 U1⟩ The login entry, into the scratch registry root `product_env` names
        // (`HEIMDALL_TEST_LOGIN_ROOT`), never the account's Run key (m04-plan §0).
        (
            "login entry enable",
            &["service", "autostart", "enable"],
            Mode::Attended,
            "OK",
        ),
        (
            "login entry disable",
            &["service", "autostart", "disable"],
            Mode::Plain,
            "OK",
        ),
        (
            "runtime start on demand",
            &["destination", "prefer", "nosuch", "managed"],
            Mode::Plain,
            "NOT_FOUND",
        ),
        ("service status", &["service", "status"], Mode::Plain, "OK"),
        ("uninstall", &["uninstall"], Mode::Plain, "OK"),
    ];

    /// The environment of the binary under test: the scratch installation, a scratch `HOME`,
    /// no system Git configuration, and the machine-wide variables Windows needs.
    fn product_env(inst: &SecondInstallation) -> Vec<(OsString, OsString)> {
        let mut env = inst.env();
        env.push(("HOME".into(), inst.ssh_home().as_os_str().to_owned()));
        env.push((LOGIN_ROOT_ENV.into(), login_root(inst).into()));
        env.push(("GIT_CONFIG_NOSYSTEM".into(), "1".into()));
        for k in ["SystemRoot", "PATH", "TEMP", "TMP"] {
            if let Some(v) = std::env::var_os(k) {
                env.push((k.into(), v));
            }
        }
        env
    }

    /// ⟨M04 U1⟩ The debug-only scratch root of the login entry (`service_cmd::LOGIN_ROOT_ENV`).
    const LOGIN_ROOT_ENV: &str = "HEIMDALL_TEST_LOGIN_ROOT";

    /// The scratch registry subkey this installation's login entry goes to: under
    /// `HKCU\Software\HeimdallTest\`, unique per scratch installation, deleted by
    /// [`DeleteLoginRoot`].
    fn login_root(inst: &SecondInstallation) -> String {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        inst.env().iter().for_each(|(k, v)| (k, v).hash(&mut h));
        format!("Software\\HeimdallTest\\a14-{:016x}", h.finish())
    }

    /// Deletes the scratch login root when the test ends (absent is fine).
    struct DeleteLoginRoot(String);

    impl Drop for DeleteLoginRoot {
        fn drop(&mut self) {
            let _ = Command::new("reg.exe")
                .args(["delete", &format!("HKCU\\{}", self.0), "/f"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }

    /// Stops the scratch installation's runtime when a test ends (a no-op when none runs).
    struct StopRuntime(Vec<(OsString, OsString)>);

    impl Drop for StopRuntime {
        fn drop(&mut self) {
            let _ = Command::new(bin())
                .args(["--json", "service", "stop"])
                .env_clear()
                .envs(self.0.iter().map(|(k, v)| (k, v)))
                .stdin(Stdio::null())
                .output();
        }
    }

    /// Run one step; its envelope's `code` and the exit code.
    fn run_step(env: &[(OsString, OsString)], args: &[&str], mode: Mode) -> (String, i32) {
        match mode {
            Mode::Plain => {
                let out = Command::new(bin())
                    .args(["--json", "--non-interactive"])
                    .args(args)
                    .env_clear()
                    .envs(env.iter().map(|(k, v)| (k, v)))
                    .stdin(Stdio::null())
                    .output()
                    .unwrap();
                let text = String::from_utf8_lossy(&out.stdout).into_owned();
                heimdall_testkit::assert_no_canary(&text);
                (envelope_code(&text), out.status.code().unwrap_or(-1))
            }
            Mode::Attended => {
                let mut cmd = heimdall_testkit::console::TerminalCommand::new(bin())
                    .args(["--json"])
                    .args(args)
                    .size(400, 50);
                for (k, v) in env {
                    cmd = cmd.env(k, v);
                }
                let mut t = cmd.spawn().expect("the pseudoconsole starts");
                t.expect("[y/N]:", Duration::from_secs(60))
                    .unwrap_or_else(|e| panic!("{args:?}: no prompt: {e}"));
                std::thread::sleep(Duration::from_millis(300));
                t.send(b"yes\r").unwrap();
                let code = t.wait(Duration::from_secs(120));
                let text = t.text().replace('\n', "");
                heimdall_testkit::assert_no_canary(&text);
                let code = code.unwrap_or_else(|| panic!("{args:?}: did not exit: {text}"));
                (envelope_code(&text), code)
            }
        }
    }

    /// The `code` of the last envelope in `text` (`""` when there is none).
    fn envelope_code(text: &str) -> String {
        text.lines()
            .rev()
            .filter_map(|l| l.find("{\"schema_version\"").map(|i| &l[i..]))
            .find_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .and_then(|v| v["code"].as_str().map(str::to_owned))
            .unwrap_or_default()
    }

    /// ⟨M04 Windows fix round; M03 `eccab7d6`⟩ A plan that changes no item is applied as
    /// previewed, with no question (ADR-0007 §5.2), so a fresh home's first `setup apply` asks
    /// nothing. The first adoption of an alias always needs the owner's decision: this adopts
    /// a scratch public key (generated per run, never the owner's) and adds a destination for
    /// it, so the next `setup apply` asks its typed `yes`. Both are plain product steps.
    fn add_alias_needing_a_decision(env: &[(OsString, OsString)], inst: &SecondInstallation) {
        let run = |args: Vec<OsString>| -> serde_json::Value {
            let out = Command::new(bin())
                .args(["--json", "--non-interactive"])
                .args(&args)
                .env_clear()
                .envs(env.iter().map(|(k, v)| (k, v)))
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            heimdall_testkit::assert_no_canary(&text);
            let envelope = text
                .lines()
                .rev()
                .filter_map(|l| l.find("{\"schema_version\"").map(|i| &l[i..]))
                .find_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .unwrap_or_default();
            assert_eq!(
                envelope["code"],
                "OK",
                "{args:?} (exit {:?})",
                out.status.code()
            );
            envelope
        };
        let key = heimdall_testkit::agent::FixtureKey::generate_many(1);
        let path = inst.root().join("fixture.pub");
        std::fs::write(&path, format!("{}\n", key[0].public_line_without_comment())).unwrap();
        let adopted = run(vec![
            "identity".into(),
            "adopt".into(),
            "--pub".into(),
            path.clone().into_os_string(),
        ]);
        let identity = adopted["data"]["identity_id"].as_str().unwrap().to_owned();
        let destination = inst.destination_id();
        run(SecondInstallation::destination_add_args(
            "hm-a14",
            &destination,
            "127.0.0.1",
            22,
            "deploy",
            &identity,
        ));
    }

    /// ADR-0010 §1 item 4 (A14): no takeover. Before and after every product step, the global
    /// agent pipe, the `ssh-agent` service (configuration, state and SDDL), the persistent user
    /// environment, Git's global and system configuration and `%USERPROFILE%\.ssh` are the same,
    /// and the step list leaves no Heimdall pipe behind.
    #[test]
    fn a14_no_global_agent_takeover_inventory_identical() {
        let profile = PathBuf::from(std::env::var_os("USERPROFILE").expect("USERPROFILE"));
        let owner = OwnerDigest::capture_tree(&profile);
        let before = inventory();
        let scratch = Scratch::new().unwrap();
        let inst = SecondInstallation::new(&scratch).unwrap();
        let env = product_env(&inst);
        let _login_root = DeleteLoginRoot(login_root(&inst));
        let _stop = StopRuntime(env.clone());
        // The alias `setup apply` must decide on (M03 `eccab7d6`), itself product steps.
        add_alias_needing_a_decision(&env, &inst);
        let after = inventory();
        assert_eq!(after.agent_pipes, before.agent_pipes, "after adopt and add");
        assert_eq!(
            after.user_environment, before.user_environment,
            "after adopt and add"
        );
        owner.assert_unchanged();
        for (name, args, mode, expected) in STEPS {
            let (code, exit) = run_step(&env, args, *mode);
            assert_eq!(code, *expected, "step `{name}` (exit {exit})");
            let after = inventory();
            assert_eq!(after.agent_pipes, before.agent_pipes, "after `{name}`");
            assert_eq!(after.agent_service, before.agent_service, "after `{name}`");
            assert_eq!(
                after.user_environment, before.user_environment,
                "after `{name}`"
            );
            assert_eq!(
                after.persistent_ssh_auth_sock, before.persistent_ssh_auth_sock,
                "after `{name}`"
            );
            assert_eq!(after.git_system, before.git_system, "after `{name}`");
            owner.assert_unchanged();
        }
        let after = inventory();
        assert_eq!(
            after.heimdall_pipes, before.heimdall_pipes,
            "the finished step list leaves no Heimdall pipe behind"
        );
        assert_eq!(after, before);
    }

    // --- ⟨M04 W1 review, M04-W1-R02⟩ the state directory a build before M04 left ----------

    /// Whether the scratch login root holds a `Heimdall-…` value (read with `reg.exe`).
    fn login_value_present(inst: &SecondInstallation) -> bool {
        let out = Command::new(system32("reg.exe"))
            .args(["query", &format!("HKCU\\{}", login_root(inst))])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).contains("Heimdall-")
    }

    /// ⟨M04 Windows fix round⟩ Give `dir` (a directory of this test's installation) the stock
    /// profile list, protected: full control, inherited by files and subdirectories, for the
    /// user, SYSTEM and Administrators only, so what is created inside has a stock profile's
    /// inherited list whatever the host profile carries.
    fn stock_profile_list(dir: &Path) {
        let me = heimdall_ipc::windows::current_user_sid().unwrap();
        let set = Command::new(system32("icacls.exe"))
            .arg(dir)
            .args([
                "/inheritance:r",
                "/grant:r",
                &format!("*{me}:(OI)(CI)F"),
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(set.status.success(), "{set:?}");
    }

    /// `std::fs::rename`, retried for a while: the stopped runtime's last handles close
    /// asynchronously.
    fn rename_settled(from: &Path, to: &Path) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match std::fs::rename(from, to) {
                Ok(()) => return,
                Err(e) if Instant::now() < deadline => {
                    let _ = e;
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) => panic!("rename {}: {e}", from.display()),
            }
        }
    }

    /// ⟨ADR-0010 §10 item 5⟩ An installation whose state directory has the inherited list a
    /// build before M04 left can still undo what it changed. After `setup apply` and the
    /// login entry, the state directory is given that list again (its content moved into a
    /// directory `create_dir_all` made, as M01–M03 did). `setup rollback` and `uninstall`
    /// then both run: the first command narrows the directory once to the protected
    /// owner-only list, the rollback removes the managed include from the user file, and
    /// uninstall removes the login entry. Before the fix both answered a reasonless
    /// `SERVICE_UNAVAILABLE` and changed nothing.
    #[test]
    fn inherited_state_dir_then_setup_rollback_and_uninstall() {
        use heimdall_runtime::platform::state_dir_acl::{Verdict, check_owner_only};
        let scratch = Scratch::new().unwrap();
        let inst = SecondInstallation::new(&scratch).unwrap();
        let env = product_env(&inst);
        let _login_root = DeleteLoginRoot(login_root(&inst));
        let _stop = StopRuntime(env.clone());
        let config = inst.ssh_home().join(".ssh").join("config");
        let managed = |p: &Path| {
            std::fs::read_to_string(p)
                .unwrap_or_default()
                .contains("# >>> heimdall managed include")
        };
        add_alias_needing_a_decision(&env, &inst);
        for (args, mode) in [
            (&["time", "confirm"][..], Mode::Attended),
            (&["setup", "apply"][..], Mode::Attended),
            (&["service", "autostart", "enable"][..], Mode::Attended),
            (&["service", "stop"][..], Mode::Plain),
        ] {
            let (code, exit) = run_step(&env, args, mode);
            assert_eq!(code, "OK", "{args:?} (exit {exit})");
        }
        assert!(managed(&config), "setup apply wrote the managed include");
        assert!(login_value_present(&inst), "the login entry is installed");
        // The list a build before M04 left on a stock profile: the content moved into a plain
        // directory under a parent given the stock list here (⟨M04 Windows fix round⟩ never
        // assumed from the host profile, which sandboxing tools change; ADR-0010 §11).
        let state = inst.state_dir();
        assert_eq!(check_owner_only(&state).unwrap(), Verdict::OwnerOnly);
        let aside = inst.root().join("state-aside");
        rename_settled(&state, &aside);
        stock_profile_list(inst.heimdall_home());
        std::fs::create_dir_all(&state).unwrap();
        for e in std::fs::read_dir(&aside).unwrap() {
            let e = e.unwrap();
            rename_settled(&e.path(), &state.join(e.file_name()));
        }
        std::fs::remove_dir(&aside).unwrap();
        assert_eq!(
            check_owner_only(&state).unwrap(),
            Verdict::LegacyInherited,
            "the inherited list of an installation from before M04"
        );
        let (code, exit) = run_step(&env, &["setup", "rollback"], Mode::Attended);
        assert_eq!(code, "OK", "setup rollback (exit {exit})");
        assert_eq!(
            check_owner_only(&state).unwrap(),
            Verdict::OwnerOnly,
            "narrowed once, at the first command"
        );
        assert!(
            !managed(&config),
            "the rollback removed the managed include"
        );
        let (code, exit) = run_step(&env, &["uninstall"], Mode::Plain);
        assert_eq!(code, "OK", "uninstall (exit {exit})");
        assert!(
            !login_value_present(&inst),
            "uninstall removed the login entry"
        );
    }

    // --- ⟨M04 U3b⟩ WSL Mode A in a disposable distribution (A12) ---------------------------

    /// The disposable distribution the harness created (`tests/native/m0x/run-wsl-distro.sh`),
    /// its non-root account, and the Windows path of the cross-built Linux helper; `None`
    /// unless all three are set (the tests are `#[ignore]`d: an unset environment never
    /// reads as a pass).
    fn disposable() -> Option<(String, String, String)> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Some((
            get("HM_WSL_TEST_DISTRO")?,
            get("HM_WSL_TEST_ACCOUNT")?,
            get("HM_WSL_TEST_HELPER")?,
        ))
    }

    /// Run `argv` inside the distribution as `account` (`wsl.exe -d -u --exec`); its stdout.
    fn in_distro(distro: &str, account: &str, argv: &[&str]) -> (i32, String) {
        let system_root = std::env::var("SystemRoot").unwrap();
        let out = Command::new(Path::new(&system_root).join("System32").join("wsl.exe"))
            .args(["-d", distro, "-u", account, "--exec"])
            .args(argv)
            .env("WSL_UTF8", "1")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    /// Like [`run_step`] in [`Mode::Attended`], for a command that may ask zero, one or
    /// several typed confirmations (a WSL rollback asks only when its plan needs one): every
    /// new `[y/N]:` prompt is answered `yes` until the program exits.
    fn run_attended_all(env: &[(OsString, OsString)], args: &[&str]) -> (String, i32) {
        let mut cmd = heimdall_testkit::console::TerminalCommand::new(bin())
            .args(["--json"])
            .args(args)
            .size(400, 50);
        for (k, v) in env {
            cmd = cmd.env(k, v);
        }
        let mut t = cmd.spawn().expect("the pseudoconsole starts");
        let start = Instant::now();
        let mut answered = 0;
        let code = loop {
            if let Some(code) = t.try_wait() {
                break Some(code);
            }
            let prompts = t.text().matches("[y/N]:").count();
            if prompts > answered {
                std::thread::sleep(Duration::from_millis(300));
                t.send(b"yes\r").unwrap();
                answered = prompts;
            }
            if start.elapsed() > Duration::from_secs(300) {
                break t.wait(Duration::from_secs(1));
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        let text = t.text().replace('\n', "");
        heimdall_testkit::assert_no_canary(&text);
        let code = code.unwrap_or_else(|| panic!("{args:?}: did not exit: {text}"));
        (envelope_code(&text), code)
    }

    /// ADR-0010 §2 item 2 (A12, A31): `wsl enable --mode-a` points the distribution user's Git
    /// at the in-box `ssh.exe` (through the helper and the setup flow, attended), and `wsl
    /// disable` rolls it back, leaving the distribution's global Git configuration
    /// byte-identical and Linux `ssh`'s configuration untouched throughout.
    #[test]
    #[ignore = "needs a disposable WSL distribution (HM_WSL_TEST_DISTRO, _ACCOUNT, _HELPER)"]
    fn a12_enable_disable_leaves_distribution_git_config_identical() {
        let Some((distro, account, helper)) = disposable() else {
            panic!("HM_WSL_TEST_DISTRO, HM_WSL_TEST_ACCOUNT and HM_WSL_TEST_HELPER must be set");
        };
        let read = |path: &str| {
            in_distro(
                &distro,
                &account,
                &[
                    "/bin/sh",
                    "-c",
                    &format!("cat {path} 2>/dev/null | sha256sum"),
                ],
            )
            .1
        };
        let git_before = read("$HOME/.gitconfig");
        let ssh_before = read("$HOME/.ssh/config");
        let scratch = Scratch::new().unwrap();
        let inst = SecondInstallation::new(&scratch).unwrap();
        let mut env = product_env(&inst);
        env.push(("HEIMDALL_WSL_HELPER".into(), helper.clone().into()));
        let _stop = StopRuntime(env.clone());
        let enable = [
            "wsl",
            "enable",
            distro.as_str(),
            "--account",
            account.as_str(),
            "--mode-a",
        ];
        let (code, exit) = run_attended_all(&env, &enable);
        assert_eq!(code, "OK", "wsl enable (exit {exit})");
        let (status, selected) = in_distro(
            &distro,
            &account,
            &[
                "git",
                "config",
                "--global",
                "--includes",
                "--get",
                "core.sshCommand",
            ],
        );
        assert_eq!(status, 0, "core.sshCommand is set");
        assert!(
            selected
                .to_ascii_lowercase()
                .contains("/windows/system32/openssh/ssh.exe"),
            "Git uses the in-box ssh.exe at its distribution-visible path: {selected}"
        );
        assert_eq!(
            read("$HOME/.ssh/config"),
            ssh_before,
            "Linux ssh stays Linux"
        );
        let disable = ["wsl", "disable", distro.as_str()];
        let (code, exit) = run_attended_all(&env, &disable);
        assert_eq!(code, "OK", "wsl disable (exit {exit})");
        assert_eq!(
            read("$HOME/.gitconfig"),
            git_before,
            "the global Git file is as before"
        );
        assert_eq!(read("$HOME/.ssh/config"), ssh_before);
        let (status, _) = in_distro(
            &distro,
            &account,
            &[
                "git",
                "config",
                "--global",
                "--includes",
                "--get",
                "core.sshCommand",
            ],
        );
        assert_ne!(status, 0, "no core.sshCommand is left");
    }

    /// A12, A14 (P-A06): a Windows program started through interop from the distribution runs
    /// at Medium integrity. That no UAC prompt appears needs an operator (B5).
    #[test]
    #[ignore = "needs a disposable WSL distribution (HM_WSL_TEST_DISTRO, _ACCOUNT)"]
    fn a12_interop_child_medium_integrity() {
        let Some((distro, account, _)) = disposable() else {
            panic!("HM_WSL_TEST_DISTRO and HM_WSL_TEST_ACCOUNT must be set");
        };
        let (status, groups) = in_distro(
            &distro,
            &account,
            &["/mnt/c/Windows/System32/whoami.exe", "/groups"],
        );
        assert_eq!(status, 0, "whoami.exe ran through interop");
        assert!(
            groups.contains("S-1-16-8192"),
            "Medium Mandatory Level (S-1-16-8192)"
        );
        assert!(!groups.contains("S-1-16-12288"), "never High");
    }

    // --- the Git client finding ----------------------------------------------------------

    /// A scratch Git home and an environment that finds the real Git for Windows and the in-box
    /// `ssh.exe`, as `git_observe`'s fixture does.
    struct GitWorld {
        _scratch: Scratch,
        home: PathBuf,
        root: PathBuf,
        git: PathBuf,
        in_box: PathBuf,
    }

    impl GitWorld {
        fn new() -> GitWorld {
            let scratch = Scratch::new().unwrap();
            let root = scratch.path().to_path_buf();
            let home = root.join("home");
            std::fs::create_dir_all(&home).unwrap();
            let git = find_program("git").expect("Git for Windows on PATH (blocked without it)");
            let in_box = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                .join(r"System32\OpenSSH\ssh.exe");
            assert!(in_box.is_file(), "the in-box OpenSSH client");
            GitWorld {
                _scratch: scratch,
                home,
                root,
                git,
                in_box,
            }
        }

        fn env(&self, extra: &[(&str, String)]) -> Env {
            let path = std::env::join_paths([
                self.git.parent().unwrap().to_path_buf(),
                self.in_box.parent().unwrap().to_path_buf(),
            ])
            .unwrap();
            let mut vars: Vec<(OsString, OsString)> = vec![
                ("PATH".into(), path),
                ("HOME".into(), self.home.clone().into_os_string()),
                ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
                (
                    "XDG_CONFIG_HOME".into(),
                    self.home.join(".config").into_os_string(),
                ),
                ("SystemRoot".into(), std::env::var_os("SystemRoot").unwrap()),
            ];
            vars.extend(extra.iter().map(|(k, v)| ((*k).into(), v.into())));
            Env::from_vars(vars)
        }

        fn report(&self, extra: &[(&str, String)]) -> heimdall_contract::doctor::DoctorReport {
            let paths = SshPaths::with_test_override(self.home.clone(), self.root.join("etc-ssh"));
            let ctx = LocalContext::new(
                paths,
                self.env(extra),
                Platform::Windows,
                ClientsConfig::default(),
                Limits::default(),
            );
            run(&ctx, &DoctorRequest::passive())
        }

        /// The in-box client as a Git command: `/` separators, single-quoted (as Heimdall's
        /// Git item renders it).
        fn in_box_command(&self) -> String {
            format!("'{}'", self.in_box.to_string_lossy().replace('\\', "/"))
        }
    }

    fn reported(report: &heimdall_contract::doctor::DoctorReport) -> bool {
        report
            .findings
            .iter()
            .any(|f| f.code == heimdall_contract::envelope::reason::GIT_CLIENT_CANNOT_REACH_PIPE)
    }

    /// ADR-0010 §1 item 5 (P-W03): Git for Windows' bundled MSYS `ssh` cannot reach a named
    /// pipe, so the doctor reports `git_client_cannot_reach_pipe` and makes no Git claim; once
    /// `GIT_SSH_COMMAND` or a global `core.sshCommand` names the in-box `ssh.exe` (what the M02
    /// Git item writes) it does not.
    #[test]
    fn a14_git_bundled_client_reported_not_claimed() {
        use heimdall_contract::doctor::GitSshClassification;
        let w = GitWorld::new();
        let selection = |r: &heimdall_contract::doctor::DoctorReport| {
            r.git
                .as_ref()
                .expect("a Git observation")
                .selection
                .classification
        };

        // No override: Git runs its bundled client (when Git for Windows bundles one).
        let report = w.report(&[]);
        assert_eq!(
            selection(&report),
            GitSshClassification::BundledMsys,
            "this host's Git for Windows must bundle its MSYS ssh (blocked without it)"
        );
        assert!(reported(&report), "{:?}", report.findings);
        assert!(
            report.git.as_ref().unwrap().values.is_empty(),
            "no core.sshCommand is claimed"
        );

        // An environment override naming the in-box client.
        let report = w.report(&[("GIT_SSH_COMMAND", w.in_box_command())]);
        assert_eq!(selection(&report), GitSshClassification::VerifiedClient);
        assert!(!reported(&report), "{:?}", report.findings);

        // A global core.sshCommand naming it (the M02 Git item's value).
        std::fs::write(
            w.home.join(".gitconfig"),
            format!("[core]\n\tsshCommand = \"{}\"\n", w.in_box_command()),
        )
        .unwrap();
        let report = w.report(&[]);
        assert_eq!(selection(&report), GitSshClassification::VerifiedClient);
        assert!(!reported(&report), "{:?}", report.findings);
    }
    // --- ⟨M04 U4b⟩ WSL Mode B in disposable distributions (A13, A03) ------------------------

    /// The A13 rows (ADR-0010 §3; module docs): one scratch installation with the real runtime,
    /// the real Linux helper and a verified enrollment, the distribution enabled in Mode B
    /// through the product's own attended `wsl enable --mode-b`, an `ensure` in its environment,
    /// and Linux `ssh`, `ssh-add` and Git run **inside** the distribution through the
    /// descriptor the `ensure` returned. Every Linux-side probe is a single `wsl.exe -d <name>
    /// -u <account> --exec` call.
    mod mode_b {
        use std::io::Write as _;

        use serde_json::Value;

        use super::{Command, Duration, Instant, Path, Stdio, disposable, in_distro};
        use crate::world::{self, World, WorldOptions};

        /// The first and, for the two-distribution rows, second disposable distribution.
        struct Distro {
            name: String,
            account: String,
        }

        fn first() -> (Distro, String) {
            let Some((name, account, helper)) = disposable() else {
                panic!(
                    "HM_WSL_TEST_DISTRO, HM_WSL_TEST_ACCOUNT and HM_WSL_TEST_HELPER must be set"
                );
            };
            (Distro { name, account }, helper)
        }

        fn second() -> Distro {
            let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
            let Some(name) = get("HM_WSL_TEST_DISTRO2") else {
                panic!("HM_WSL_TEST_DISTRO2 must name the second disposable distribution");
            };
            let account = get("HM_WSL_TEST_ACCOUNT2")
                .or_else(|| get("HM_WSL_TEST_ACCOUNT"))
                .expect("HM_WSL_TEST_ACCOUNT");
            Distro { name, account }
        }

        /// A scratch installation whose runtime uses the Linux helper at `helper`.
        fn world(helper: &str) -> World {
            let (w, _ca) = World::start(WorldOptions {
                pairs: 1,
                per_pair_profiles: true,
                extra_env: vec![("HEIMDALL_WSL_HELPER".to_owned(), helper.to_owned())],
                ..WorldOptions::default()
            });
            w
        }

        /// Ends Mode B for `distro` when the test ends (the bindings end, the helper stops),
        /// whatever the test did; a failure here is not the test's.
        struct Disable<'w>(&'w World, String);

        impl Drop for Disable<'_> {
            fn drop(&mut self) {
                let _ = self.0.cli(&["--json", "wsl", "disable", &self.1]);
            }
        }

        /// `wsl enable <distro> --account <account> --mode-b`, the typed `yes` of the
        /// `AddEnvironment` decision, and the policy that lets the environment serve the
        /// profile without a further decision. Returns the environment's ID.
        fn enable(w: &World, d: &Distro) -> String {
            let out = w.confirm(&[
                "wsl",
                "enable",
                &d.name,
                "--account",
                &d.account,
                "--mode-b",
            ]);
            assert_eq!(
                out.code,
                0,
                "wsl enable --mode-b: {}",
                w.redact(&out.stdout)
            );
            let item = environment(w, &d.name).expect("the Mode B environment is listed");
            assert_eq!(item["state"], "active", "{item}");
            let id = item["environment_id"].as_str().unwrap().to_owned();
            permit(w, &id);
            id
        }

        /// The `inspect environments` item of the Mode B distribution `name`.
        fn environment(w: &World, name: &str) -> Option<Value> {
            let listing = w.cli(&["--json", "inspect", "environments"]).json();
            listing["data"]["items"]
                .as_array()?
                .iter()
                .find(|i| i["kind"] == "wsl_distribution" && i["realization"]["name"] == name)
                .cloned()
        }

        /// Let `environment` serve the first pair's profile without a decision (the approval
        /// grants `managed_signing` only), as the container row does.
        fn permit(w: &World, environment: &str) {
            use heimdall_contract::ids::{EnvironmentId, PolicyId};
            let environment = EnvironmentId::parse(environment).unwrap();
            w.open_store()
                .transaction(|tx| {
                    let mut rec = tx.environment(&environment)?.expect("its record");
                    rec.permissions.automatic_activation = true;
                    tx.upsert_environment(&rec)?;
                    let pid = PolicyId::parse(&format!("{}-1", world::POLICY)).unwrap();
                    let mut pol = tx.policy(&pid)?.expect("the pair's policy");
                    pol.environments.insert(environment.clone());
                    pol.revision = heimdall_domain::policy::PolicyRevision(pol.revision.0 + 1);
                    tx.upsert_policy(&pol, false)
                })
                .unwrap();
        }

        /// `access ensure` of the first pair's profile in `environment` (exit 0 and
        /// `ACCESS_READY` asserted): its data.
        fn ensure(w: &World, environment: &str, work: &str, request: &str) -> Value {
            let out = w.cli(&[
                "--json",
                "access",
                "ensure",
                "--profile",
                &w.profile_of(0),
                "--environment",
                environment,
                "--work-id",
                work,
                "--request-id",
                request,
            ]);
            assert_eq!(out.code, 0, "ensure: {}", w.redact(&format!("{out:?}")));
            let env = out.json();
            assert_eq!(
                env["code"],
                "ACCESS_READY",
                "{}",
                w.redact(&env.to_string())
            );
            env["data"].clone()
        }

        /// The Linux socket and OpenSSH configuration of an `ensure` result's descriptor.
        fn descriptor(data: &Value) -> (String, String) {
            let r = &data["consumer"]["realization"];
            assert_eq!(r["environment_kind"], "wsl_distribution", "{r}");
            assert!(r.get("mount").is_none_or(Value::is_null), "no mount: {r}");
            (
                r["endpoint"].as_str().unwrap().to_owned(),
                r["config"].as_str().unwrap().to_owned(),
            )
        }

        /// A shell script inside the distribution as `account`; its exit code and stdout.
        fn sh(d: &Distro, script: &str) -> (i32, String) {
            in_distro(&d.name, &d.account, &["/bin/sh", "-c", script])
        }

        /// A shell script inside the distribution as root (the disposable distribution's own).
        fn root(d: &Distro, script: &str) -> (i32, String) {
            in_distro(&d.name, "root", &["/bin/sh", "-c", script])
        }

        /// `wsl.exe` with `args` (UTF-8 output); its exit code and stdout.
        fn wsl(args: &[&str]) -> (i32, String) {
            let system_root = std::env::var("SystemRoot").unwrap();
            let out = Command::new(Path::new(&system_root).join("System32").join("wsl.exe"))
                .args(args)
                .env("WSL_UTF8", "1")
                .stdin(Stdio::null())
                .output()
                .unwrap();
            (
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stdout).into_owned(),
            )
        }

        /// Whether `name` is in `wsl.exe --list --running --quiet` (which starts nothing).
        fn running(name: &str) -> bool {
            wsl(&["--list", "--running", "--quiet"])
                .1
                .lines()
                .any(|l| l.trim().eq_ignore_ascii_case(name))
        }

        fn eventually(what: &str, within: Duration, mut f: impl FnMut() -> bool) {
            let deadline = Instant::now() + within;
            while !f() {
                assert!(Instant::now() < deadline, "not within {within:?}: {what}");
                std::thread::sleep(Duration::from_millis(500));
            }
        }

        /// `ssh-add -l` against `socket`, as the account: its exit code and lines.
        fn list(d: &Distro, socket: &str) -> (i32, usize) {
            let (code, out) = sh(d, &format!("SSH_AUTH_SOCK={socket} ssh-add -l 2>&1"));
            (code, out.lines().filter(|l| l.contains("SHA256:")).count())
        }

        /// One login to the pair's alias through the binding's `ssh_config`.
        fn login(w: &World, d: &Distro, config: &str, marker: &str) -> (i32, String) {
            let alias = &w.pairs[0].alias;
            sh(
                d,
                &format!("ssh -F {config} -o BatchMode=yes {alias} 'echo {marker}' 2>&1"),
            )
        }

        /// A13: through the bridge the account sees exactly the binding's identity and logs in
        /// (attributed to the binding's certificate); a key that is not listed is refused by
        /// the server, an identity cannot be added through the endpoint, and nothing else is
        /// listed afterwards.
        #[test]
        #[ignore = "needs a disposable WSL distribution (HM_WSL_TEST_DISTRO, _ACCOUNT, _HELPER) and the harness sshd"]
        fn a13_lists_only_binding_identities_and_refuses_unlisted_key() {
            let (d, helper) = first();
            let w = world(&helper);
            let _end = Disable(&w, d.name.clone());
            let env = enable(&w, &d);
            let data = ensure(&w, &env, "a13-l", "a13-l-r1");
            let (socket, config) = descriptor(&data);
            let key_prefix = format!(
                "heimdall:{}:{}:",
                w.environment.as_str(),
                data["grant_id"].as_str().unwrap()
            );
            assert_eq!(list(&d, &socket), (0, 1), "exactly the binding's identity");

            let mark = w.pairs[0].sshd.log_mark();
            let (code, out) = login(&w, &d, &config, "hm-b-pos");
            assert_eq!(code, 0, "login: {}", w.redact(&out));
            assert!(out.contains("hm-b-pos"), "{out}");
            let accepted = w.accepted_since(0, mark);
            assert_eq!(accepted.len(), 1, "{accepted:?}");
            assert!(
                accepted[0].key_id.starts_with(&key_prefix),
                "{:?}",
                accepted[0]
            );

            // An unlisted key (never offered to the server by the agent) is refused.
            let mark = w.pairs[0].sshd.log_mark();
            let alias = &w.pairs[0].alias;
            let (code, out) = sh(
                &d,
                &format!(
                    "rm -f /tmp/hm-a13-k /tmp/hm-a13-k.pub; ssh-keygen -q -t ed25519 -N '' -f /tmp/hm-a13-k && ssh -F {config} -o BatchMode=yes -o IdentityAgent=none -o IdentitiesOnly=yes -o IdentityFile=/tmp/hm-a13-k {alias} 'echo hm-b-neg' 2>&1"
                ),
            );
            assert_ne!(code, 0, "an unlisted key is refused: {}", w.redact(&out));
            assert!(!out.contains("hm-b-neg"));
            assert!(w.accepted_since(0, mark).is_empty());

            // An add-identity message is not on the allow-list: refused at the endpoint, and the
            // listing is unchanged.
            let (code, _) = sh(
                &d,
                &format!("SSH_AUTH_SOCK={socket} ssh-add /tmp/hm-a13-k 2>&1"),
            );
            assert_ne!(code, 0, "the endpoint does not add identities");
            assert_eq!(list(&d, &socket), (0, 1));
            let _ = sh(&d, "rm -f /tmp/hm-a13-k /tmp/hm-a13-k.pub");
        }

        /// A13, A27: Git over the Linux `ssh` through the bridge: the descriptor's own
        /// `GIT_SSH_COMMAND` and `SSH_AUTH_SOCK`, a bare repository made on the server, a commit
        /// pushed and read back byte for byte.
        #[test]
        #[ignore = "needs a disposable WSL distribution (HM_WSL_TEST_DISTRO, _ACCOUNT, _HELPER), git in it and on the harness sshd"]
        fn a13_git_over_linux_ssh_through_bridge() {
            let (d, helper) = first();
            let w = world(&helper);
            let _end = Disable(&w, d.name.clone());
            let env = enable(&w, &d);
            let data = ensure(&w, &env, "a13-g", "a13-g-r1");
            let (socket, config) = descriptor(&data);
            let alias = &w.pairs[0].alias;
            let git_ssh = format!("ssh -F {config}");
            let remote = format!("/tmp/hm-a13-{}.git", std::process::id());
            let mark = w.pairs[0].sshd.log_mark();
            let (code, out) = sh(
                &d,
                &format!(
                    "ssh -F {config} -o BatchMode=yes {alias} 'git init -q --bare {remote}' 2>&1"
                ),
            );
            assert_eq!(code, 0, "git init on the server: {}", w.redact(&out));
            let work = "/tmp/hm-a13-work";
            let script = format!(
                "rm -rf {work} && git init -q {work} && cd {work} && git -c user.name=hm -c user.email=hm@example.invalid commit -q --allow-empty -m a13 && printf 'payload-%s\\n' 0123456789abcdef > f && git add f && git -c user.name=hm -c user.email=hm@example.invalid commit -q -m a13b && export SSH_AUTH_SOCK={socket} GIT_SSH_COMMAND='{git_ssh}' && git push -q {alias}:{remote} HEAD:refs/heads/main 2>&1 && git rev-parse HEAD && git ls-remote {alias}:{remote} refs/heads/main 2>&1"
            );
            let (code, out) = sh(&d, &script);
            assert_eq!(code, 0, "git over the bridge: {}", w.redact(&out));
            let lines: Vec<&str> = out.lines().collect();
            let head = lines
                .iter()
                .find(|l| l.len() == 40 && l.bytes().all(|b| b.is_ascii_hexdigit()))
                .expect("the pushed commit id");
            assert!(
                lines
                    .iter()
                    .any(|l| l.starts_with(head) && l.ends_with("refs/heads/main")),
                "the server holds the pushed commit: {out}"
            );
            assert!(!w.accepted_since(0, mark).is_empty());
            let _ = ssh_cleanup(&w, &d, &config, &remote, work);
        }

        fn ssh_cleanup(w: &World, d: &Distro, config: &str, remote: &str, work: &str) -> i32 {
            let alias = &w.pairs[0].alias;
            sh(
                d,
                &format!(
                    "rm -rf {work}; ssh -F {config} -o BatchMode=yes {alias} 'rm -rf {remote}' 2>&1"
                ),
            )
            .0
        }

        /// A13 (the M04 exit's "no management API" clause): the bridge socket speaks the SSH
        /// agent protocol only. A control-protocol hello on it is not answered with a control
        /// envelope, and the agent protocol still works on a fresh connection afterwards.
        #[test]
        #[ignore = "needs a disposable WSL distribution (HM_WSL_TEST_DISTRO, _ACCOUNT, _HELPER) with python3"]
        fn a13_control_hello_on_bridge_socket_fails() {
            let (d, helper) = first();
            let w = world(&helper);
            let _end = Disable(&w, d.name.clone());
            let env = enable(&w, &d);
            let (socket, _) = descriptor(&ensure(&w, &env, "a13-h", "a13-h-r1"));
            let script = format!(
                "python3 - <<'PY'\nimport socket\ns = socket.socket(socket.AF_UNIX)\ns.settimeout(5)\ns.connect('{socket}')\ns.sendall(b'{{\"hello\":{{\"protocol\":\"heimdall-control/1\"}}}}')\ntry:\n    got = s.recv(4096)\nexcept Exception:\n    got = b''\nprint('answered-json' if got.startswith(b'{{') else 'no-control-answer')\nPY"
            );
            let (code, out) = sh(&d, &script);
            assert_eq!(code, 0, "{out}");
            assert!(out.contains("no-control-answer"), "{out}");
            assert_eq!(list(&d, &socket), (0, 1), "the agent protocol still works");
        }

        /// A13: a second distribution sees nothing of the first one's endpoint (the second
        /// disposable distribution is the observer): no path, no abstract or `/mnt/wsl`
        /// socket, and no new TCP listener anywhere in the shared network namespace, before
        /// and after a binding exists.
        #[test]
        #[ignore = "needs two disposable WSL distributions (HM_WSL_TEST_DISTRO, _ACCOUNT, _HELPER, _DISTRO2)"]
        fn a13_other_distribution_sees_no_endpoint() {
            let (d, helper) = first();
            let observer = second();
            assert_ne!(d.name, observer.name, "two distinct distributions");
            let probe = |o: &Distro| {
                let (_, listeners) = root(
                    o,
                    "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '$4==\"0A\"{print $2}' | sort",
                );
                let (_, unix) = root(
                    o,
                    "awk '{print $NF}' /proc/net/unix | grep -E 'heimdall|agent.sock' | sort",
                );
                let (_, mnt) = root(
                    o,
                    "find /mnt/wsl -maxdepth 6 \\( -name 'agent.sock' -o -path '*heimdall*' \\) 2>/dev/null | sort",
                );
                (listeners, unix, mnt)
            };
            let before = probe(&observer);
            let w = world(&helper);
            let _end = Disable(&w, d.name.clone());
            let env = enable(&w, &d);
            let (socket, _) = descriptor(&ensure(&w, &env, "a13-o", "a13-o-r1"));
            assert_eq!(
                list(&d, &socket),
                (0, 1),
                "the enabled distribution serves it"
            );
            let (listeners, unix, mnt) = probe(&observer);
            assert_eq!(listeners, before.0, "no new TCP listener");
            assert!(
                !unix.contains("heimdall") && !unix.contains("agent.sock"),
                "no abstract or path socket of the first is visible: {unix}"
            );
            assert_eq!(mnt, before.2, "nothing under /mnt/wsl");
            let (code, _) = sh(&observer, &format!("test -e {socket}"));
            assert_ne!(code, 0, "the path does not exist in the observer");
            let (code, out) = sh(
                &observer,
                &format!("SSH_AUTH_SOCK={socket} ssh-add -l 2>&1"),
            );
            assert_ne!(code, 0, "the observer cannot use the path: {out}");
        }

        /// A13: two enabled distributions get disjoint endpoints: different paths, each served
        /// in its own distribution only, each listing exactly its own binding's identity.
        #[test]
        #[ignore = "needs two disposable WSL distributions (HM_WSL_TEST_DISTRO, _ACCOUNT, _HELPER, _DISTRO2)"]
        fn a13_two_enabled_distributions_get_disjoint_endpoints() {
            let (d1, helper) = first();
            let d2 = second();
            assert_ne!(d1.name, d2.name, "two distinct distributions");
            let w = world(&helper);
            let _e1 = Disable(&w, d1.name.clone());
            let _e2 = Disable(&w, d2.name.clone());
            let env1 = enable(&w, &d1);
            let env2 = enable(&w, &d2);
            assert_ne!(env1, env2, "two environments");
            let (s1, _) = descriptor(&ensure(&w, &env1, "a13-t1", "a13-t1-r1"));
            let (s2, _) = descriptor(&ensure(&w, &env2, "a13-t2", "a13-t2-r1"));
            assert_ne!(s1, s2, "disjoint endpoints");
            assert_eq!(list(&d1, &s1), (0, 1));
            assert_eq!(list(&d2, &s2), (0, 1));
            assert_ne!(
                sh(&d1, &format!("test -S {s2}")).0,
                0,
                "the second's socket is not in the first"
            );
            assert_ne!(
                sh(&d2, &format!("test -S {s1}")).0,
                0,
                "the first's socket is not in the second"
            );
        }

        /// A13: another Linux user of the distribution is refused by the file modes and the peer
        /// check. The `wsl.exe -u <account>` bypass (any process of the same Windows user can
        /// become the owning account) is probed and recorded as the residual, not claimed.
        #[test]
        #[ignore = "needs a disposable WSL distribution (HM_WSL_TEST_DISTRO, _ACCOUNT, _HELPER); it creates and removes a user in it"]
        fn a13_other_linux_user_refused() {
            let (d, helper) = first();
            let w = world(&helper);
            let _end = Disable(&w, d.name.clone());
            let env = enable(&w, &d);
            let (socket, _) = descriptor(&ensure(&w, &env, "a13-u", "a13-u-r1"));
            let other = "hmother";
            let _ = root(&d, &format!("userdel -r {other} 2>/dev/null; true"));
            let (code, out) = root(&d, &format!("useradd -m -s /bin/sh {other} 2>&1"));
            assert_eq!(code, 0, "a second user: {out}");
            let outcome = std::panic::catch_unwind(|| {
                let (code, out) = in_distro(
                    &d.name,
                    other,
                    &[
                        "/bin/sh",
                        "-c",
                        &format!("SSH_AUTH_SOCK={socket} ssh-add -l 2>&1"),
                    ],
                );
                assert_ne!(code, 0, "another Linux user is refused: {out}");
                assert!(
                    !out.contains("SHA256:"),
                    "no identity is listed to it: {out}"
                );
                let (code, _) = in_distro(
                    &d.name,
                    other,
                    &["/bin/sh", "-c", &format!("ls {socket} >/dev/null 2>&1")],
                );
                assert_ne!(code, 0, "the 0700 directory hides the socket from it");
            });
            let _ = root(&d, &format!("userdel -r {other} 2>/dev/null; true"));
            outcome.unwrap_or_else(|e| std::panic::resume_unwind(e));
            // The residual, recorded: the owning account is reachable through `wsl.exe -u`.
            let (code, listed) = (list(&d, &socket).0, list(&d, &socket).1);
            println!(
                "m04 observation: a13 windows wsl.exe -u bypass: owner account lists {listed} identity (exit {code}); a documented non-claim"
            );
        }

        /// A13: `wsl --terminate` kills the helper with the distribution; the runtime reports it
        /// and starts **nothing** in the background (the distribution stays stopped across two
        /// re-check periods); after a user restart the helper is not relaunched in the
        /// background either, and the owner's next `ensure` brings the endpoint back at the
        /// same path (M04-W2-R03).
        #[test]
        #[ignore = "needs a disposable WSL distribution (HM_WSL_TEST_DISTRO, _ACCOUNT, _HELPER)"]
        fn a13_terminate_then_user_restart_recreates_endpoint_without_background_start() {
            let (d, helper) = first();
            let w = world(&helper);
            let _end = Disable(&w, d.name.clone());
            let env = enable(&w, &d);
            let (socket, _) = descriptor(&ensure(&w, &env, "a13-r", "a13-r-r1"));
            assert_eq!(list(&d, &socket), (0, 1));
            let (code, _) = wsl(&["--terminate", &d.name]);
            assert_eq!(code, 0, "wsl --terminate");
            eventually(
                "the distribution is stopped",
                Duration::from_secs(30),
                || !running(&d.name),
            );
            // Two re-check periods (10 s each) and a margin: nothing starts it.
            std::thread::sleep(Duration::from_secs(25));
            assert!(!running(&d.name), "no background start");
            let item = environment(&w, &d.name).expect("still listed");
            assert_eq!(item["state"], "not_running", "{item}");
            // A user restart. ⟨M04-W2-R03; ADR-0010 §11 item 1⟩ A listing showed it stopped, so
            // nothing relaunches the helper in the background: the endpoint stays away over
            // two re-check periods, until the owner's next `ensure` naming the environment,
            // which is the explicit start and brings it back at the same path.
            let (code, _) = sh(&d, "true");
            assert_eq!(code, 0, "the user restarts the distribution");
            std::thread::sleep(Duration::from_secs(25));
            assert_ne!(list(&d, &socket), (0, 1), "no background relaunch");
            ensure(&w, &env, "a13-r2", "a13-r2-r1");
            eventually("the endpoint is back", Duration::from_secs(60), || {
                list(&d, &socket) == (0, 1)
            });
            let item = environment(&w, &d.name).expect("listed");
            assert_eq!(item["state"], "active", "{item}");
        }

        /// A13: a socket deleted by hand is recreated at the same path, still serving only the
        /// binding's identity: the runtime's 10 s re-check realizes the current generation
        /// again, which the helper answers by recreating a missing socket (ADR-0010 §11 item 2).
        #[test]
        #[ignore = "needs a disposable WSL distribution (HM_WSL_TEST_DISTRO, _ACCOUNT, _HELPER)"]
        fn a13_deleted_socket_recreated() {
            let (d, helper) = first();
            let w = world(&helper);
            let _end = Disable(&w, d.name.clone());
            let env = enable(&w, &d);
            let (socket, _) = descriptor(&ensure(&w, &env, "a13-d", "a13-d-r1"));
            assert_eq!(list(&d, &socket), (0, 1));
            let (code, out) = sh(&d, &format!("rm -f {socket} && ! test -e {socket}"));
            assert_eq!(code, 0, "{out}");
            eventually("the socket is recreated", Duration::from_secs(60), || {
                list(&d, &socket) == (0, 1)
            });
        }

        /// A13: when the binding ends the endpoint stops listing at once (the signer refuses),
        /// then the endpoint and its files are withdrawn, and the helper ends with the last
        /// binding.
        #[test]
        #[ignore = "needs a disposable WSL distribution (HM_WSL_TEST_DISTRO, _ACCOUNT, _HELPER)"]
        fn a13_binding_end_refuses_then_withdraws_endpoint() {
            let (d, helper) = first();
            let w = world(&helper);
            let _end = Disable(&w, d.name.clone());
            let env = enable(&w, &d);
            let data = ensure(&w, &env, "a13-b", "a13-b-r1");
            let (socket, config) = descriptor(&data);
            assert_eq!(list(&d, &socket), (0, 1));
            let dir = socket.rsplit_once('/').unwrap().0.to_owned();
            let released = w.cli(&[
                "--json",
                "access",
                "release",
                data["binding_id"].as_str().unwrap(),
            ]);
            assert_eq!(released.code, 0, "{released:?}");
            // Refuses at once: no identity is listed (or the endpoint is already gone).
            assert_eq!(
                list(&d, &socket).1,
                0,
                "no identity after the binding ended"
            );
            eventually("the endpoint is withdrawn", Duration::from_secs(30), || {
                sh(&d, &format!("test ! -e {socket} && test ! -e {config}")).0 == 0
            });
            let (_, left) = sh(&d, &format!("ls -A {dir} 2>/dev/null | wc -l"));
            assert_eq!(left.trim(), "0", "the binding directory is empty or gone");
            eventually(
                "the helper ends with the last binding",
                Duration::from_secs(30),
                || helper_pids(&d).is_empty(),
            );
        }

        /// The helper processes of the distribution (`heimdall internal wsl-helper`).
        fn helper_pids(d: &Distro) -> Vec<String> {
            let (_, out) = sh(
                d,
                "ps -eo pid=,args= | grep -F 'internal wsl-helper' | grep -v grep | awk '{print $1}'",
            );
            out.split_whitespace().map(str::to_owned).collect()
        }

        /// A13: when the runtime stops the helper sees EOF, removes its endpoints and exits.
        #[test]
        #[ignore = "needs a disposable WSL distribution (HM_WSL_TEST_DISTRO, _ACCOUNT, _HELPER)"]
        fn a13_runtime_stop_helper_exits_and_removes_endpoints() {
            let (d, helper) = first();
            let w = world(&helper);
            let _end = Disable(&w, d.name.clone());
            let env = enable(&w, &d);
            let (socket, _) = descriptor(&ensure(&w, &env, "a13-s", "a13-s-r1"));
            assert_eq!(list(&d, &socket), (0, 1));
            assert!(!helper_pids(&d).is_empty(), "the helper runs");
            w.stop_runtime();
            eventually("the helper exits", Duration::from_secs(30), || {
                helper_pids(&d).is_empty()
            });
            eventually("its endpoints are removed", Duration::from_secs(30), || {
                sh(&d, &format!("test ! -e {socket}")).0 == 0
            });
        }

        /// A13: an unregistered distribution releases its bindings: the environment becomes
        /// `gone`, the grant ends, and the environment is refused as a target. **It unregisters
        /// `HM_WSL_TEST_DISTRO2`**, so it needs the explicit `HM_WSL_TEST_ALLOW_UNREGISTER=1`
        /// and the distribution is gone afterwards: run it last, alone.
        #[test]
        #[ignore = "destroys HM_WSL_TEST_DISTRO2 (needs HM_WSL_TEST_ALLOW_UNREGISTER=1): run it alone, last"]
        fn a13_unregistered_distribution_releases_bindings() {
            assert_eq!(
                std::env::var("HM_WSL_TEST_ALLOW_UNREGISTER").as_deref(),
                Ok("1"),
                "HM_WSL_TEST_ALLOW_UNREGISTER=1 acknowledges that HM_WSL_TEST_DISTRO2 is unregistered"
            );
            let (_, helper) = first();
            let d2 = second();
            let w = world(&helper);
            let env = enable(&w, &d2);
            let data = ensure(&w, &env, "a13-x", "a13-x-r1");
            let (socket, _) = descriptor(&data);
            assert_eq!(list(&d2, &socket), (0, 1));
            let grant = data["grant_id"].as_str().unwrap().to_owned();
            let (code, out) = wsl(&["--unregister", &d2.name]);
            assert_eq!(code, 0, "wsl --unregister: {out}");
            eventually("the environment is gone", Duration::from_secs(60), || {
                w.cli(&["--json", "inspect", "environments"]).json()["data"]["items"]
                    .as_array()
                    .is_some_and(|items| {
                        items.iter().any(|i| {
                            i["environment_id"].as_str() == Some(env.as_str())
                                && i["state"] == "gone"
                        })
                    })
            });
            eventually("the grant ends", Duration::from_secs(60), || {
                w.grant_state(&grant) != "active"
            });
            let again = w.cli(&[
                "--json",
                "access",
                "ensure",
                "--profile",
                &w.profile_of(0),
                "--environment",
                &env,
                "--work-id",
                "a13-x2",
                "--request-id",
                "a13-x2-r1",
            ]);
            assert_ne!(again.code, 0, "a gone environment is not a target");
            assert_eq!(
                again.json()["data"]["reason"]
                    .as_str()
                    .or(again.json()["reason"].as_str()),
                Some("environment_removed"),
                "{again:?}"
            );
        }

        /// A03 (WSL Mode B, ADR-0004 §2 idle rule, P-B07): while the Windows session is locked,
        /// fresh logins from the distribution through the bridge keep working under a standing
        /// policy, because the signer runs on the Windows side. The lock itself is the
        /// harness's (`tests/native/m03/lock-windows.ps1`): this driver prepares, waits for
        /// `locked` in `HM_LOCK_STATE_DIR`, does its checks, answers `locked-done` and waits for
        /// `unlocked`, with the same handshake files as the M03 lock driver (module docs of
        /// `exit_m03/lock.rs`). Its world is the debug configuration here; the release-profile
        /// DPAPI product configuration is the M03 driver's `WorldOptions::product`.
        #[test]
        #[ignore = "run by the lock harness (tests/native/m03/lock-windows.ps1) with HM_LOCK_STATE_DIR, and the A13 variables"]
        fn a03_mode_b_fresh_logins_while_windows_locked() {
            let state = std::path::PathBuf::from(
                std::env::var_os("HM_LOCK_STATE_DIR")
                    .expect("HM_LOCK_STATE_DIR (the lock harness)"),
            );
            let write = |name: &str, text: &str| {
                let tmp = state.join(format!("{name}.tmp"));
                let mut f = std::fs::File::create(&tmp).unwrap();
                f.write_all(text.as_bytes()).unwrap();
                std::fs::rename(&tmp, state.join(name)).unwrap();
            };
            let wait_for = |name: &str, within: Duration| -> String {
                let deadline = Instant::now() + within;
                loop {
                    if let Ok(text) = std::fs::read_to_string(state.join(name)) {
                        return text;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "the harness never wrote `{name}`"
                    );
                    std::thread::sleep(Duration::from_millis(500));
                }
            };
            let (d, helper) = first();
            let w = world(&helper);
            let _end = Disable(&w, d.name.clone());
            let env = enable(&w, &d);
            let data = ensure(&w, &env, "a03-b", "a03-b-r1");
            let (socket, config) = descriptor(&data);
            let key_prefix = format!(
                "heimdall:{}:{}:",
                w.environment.as_str(),
                data["grant_id"].as_str().unwrap()
            );
            let (code, out) = login(&w, &d, &config, "hm-a03-unlocked");
            assert_eq!(code, 0, "baseline login: {}", w.redact(&out));
            write("ready", "ready\n");
            let locked = wait_for("locked", Duration::from_secs(12 * 3600));
            assert!(!locked.starts_with("abort"), "aborted: {locked}");
            // Locked: three fresh logins about 60 s apart, each accepted with exactly the
            // binding's certificate.
            for n in 0..3 {
                if n > 0 {
                    std::thread::sleep(Duration::from_secs(60));
                }
                let mark = w.pairs[0].sshd.log_mark();
                let (code, out) = login(&w, &d, &config, &format!("hm-a03-locked-{n}"));
                assert_eq!(code, 0, "fresh login {n} while locked: {}", w.redact(&out));
                let accepted = w.accepted_since(0, mark);
                assert_eq!(accepted.len(), 1, "{accepted:?}");
                assert!(
                    accepted[0].key_id.starts_with(&key_prefix),
                    "{:?}",
                    accepted[0]
                );
            }
            assert_eq!(
                list(&d, &socket),
                (0, 1),
                "the endpoint still lists the binding"
            );
            write("locked-done", "done\n");
            let _ = wait_for("unlocked", Duration::from_secs(12 * 3600 + 600));
            write("done", "done\n");
        }
    }
}
