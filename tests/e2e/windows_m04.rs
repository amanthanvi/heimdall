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
    missing_docs
)]

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

    /// The probe: re-executed with `--exact native::handle_probe_child --nocapture`, it reports
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

    fn probe_args() -> Vec<&'static str> {
        vec![
            "--exact",
            "native::handle_probe_child",
            "--nocapture",
            "--test-threads=1",
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
        // The list a build before M04 left: the content moved into a plain directory.
        let state = inst.state_dir();
        assert_eq!(check_owner_only(&state).unwrap(), Verdict::OwnerOnly);
        let aside = inst.root().join("state-aside");
        rename_settled(&state, &aside);
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
}
