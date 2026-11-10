//! M03 U5-scripts: the remote registry scripts of `heimdall_registry::script` run on
//! every target shell (m03-plan U5 "Tests"; ADR-0008 D5 §6.3, §6.7, §6.8, D13).
//! Hosted by heimdall-enroll.
//!
//! **How a script runs here.** Directly under the target shell, with the script on
//! stdin (`/bin/sh -s`) and the shell leading its own process group (as under sshd):
//! * `native_sh`: this host's `/bin/sh` (macOS: bash 3.2.57 in POSIX mode), spawned
//!   with its own process group, `HOME` and every registry in the test's scratch;
//! * `native_sshd`: the same shell through a [`LoopbackSshd`] with the fixed remote
//!   command `printf 'HM1 ready\n'; exec /bin/sh -s`; the script is written only after
//!   the ready line is read. The session's `HOME` is the account's, so these rows use
//!   **explicit scratch registry paths only** (the guard refuses the remote home);
//! * `docker_dash`: the M00-T03 Debian 13 `enrollable` container (`up.sh` / `down.sh`;
//!   dash 0.5.12 as `/bin/sh`), `docker exec -u enroll … setsid -w /bin/sh -s`, with a
//!   scratch directory in `/tmp` and a scratch `HOME`;
//! * `docker_bash_sh`, `docker_busybox`, `docker_debian_dash`: disposable containers
//!   this suite starts (`--network none --init`, label `heimdall.fixture=u5-scripts`,
//!   removed by exact name), from the round-4 images (`debian@sha256:4c25…` with
//!   procps and acl added at build time, `/bin/sh` pointed at bash for bash-as-`sh`;
//!   `alpine@sha256:be26…`). U11's `shells::ShellContainers` was not in the tree when
//!   this suite was written; this local equivalent follows its plan text.
//!
//! **Every output** is checked against the frozen HM1 grammar
//! (`heimdall_registry::hm1`: first line `HM1 v=1`, known keys, each value of its
//! shape), which is wave-0 index row N4 confirmed as the scripts emit it.
//!
//! **Docker rows** are `#[ignore = "docker: …"]` and assert `HM_DOCKER_TESTS=1` first:
//! `HM_DOCKER_TESTS=1 cargo test -p heimdall-enroll --test integration_enroll_registry
//! -- --ignored docker_`. The `docker_dash` rows need the M00-T03 fixtures up.
//!
//! **The registry guard.** Every registry is under the test's scratch root (native),
//! or under a scratch directory inside a container labelled `heimdall.fixture`
//! ([`Target::location`] refuses anything else); the remote home is used only with a
//! scratch `HOME`, never through sshd.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::too_many_lines
)]

/// The targets, the runs, the pause hooks and the HM1 checks.
#[cfg(all(unix, debug_assertions))]
mod harness {
    use std::io::{Read, Write};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, ChildStdin, Command, Output, Stdio};
    use std::sync::Mutex;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use heimdall_registry::hm1::{self, Hm1Key};
    use heimdall_registry::script::{
        self, AppendParams, BootstrapParams, FenceParams, InspectParams, Marker, NotAfter, Payload,
        RegistryLine, RegistryLocation, RemoteScript, RemoveParams, StepToken,
    };
    use heimdall_testkit::agent::{FakeAgent, FakeAgentConfig, FixtureKey, random_hex};
    use heimdall_testkit::home::{ClientKind, Scratch, ScratchHome};
    use heimdall_testkit::registry::{RegistryGuard, RegistryTarget};
    use heimdall_testkit::shells::{ShellContainer, ShellKind};
    use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};

    /// The `PATH` of every native run (as a non-interactive sshd session has it;
    /// `sysctl` is in `/usr/sbin` on macOS).
    pub const NATIVE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

    /// The fixed remote command (ADR-0008 D5 §6.3).
    pub const REMOTE_COMMAND: &str = "printf 'HM1 ready\\n'; exec /bin/sh -s";

    /// The label every container this suite starts carries.
    pub const LABEL: &str = "heimdall.fixture=u5-scripts";

    /// The round-4 images (ADR-0008 D5 §6.3 shell table).
    pub const DEBIAN_BASE: &str =
        "debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308";
    pub const ALPINE_BASE: &str =
        "alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a";
    /// This suite's Debian image with procps **and acl** (for `setfacl`) added at
    /// build time, for the dash rows that need them (U11's image has procps only).
    pub const DEBIAN_IMAGE: &str = "heimdall-u5s-debian-acl:local";

    /// The M00-T03 enrollable container and its account.
    pub const M00_ENROLL: &str = "hm-m00t03-enroll";

    /// A Docker row asserts the opt-in first, so a stray `--ignored` fails loudly.
    pub fn docker_gate() {
        assert_eq!(
            std::env::var("HM_DOCKER_TESTS").as_deref(),
            Ok("1"),
            "docker rows need HM_DOCKER_TESTS=1 (and Docker; docker_dash needs the M00-T03 fixtures up)"
        );
    }

    /// Wall-clock seconds.
    pub fn now() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    /// Lowercase hex.
    pub fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Decode lowercase hex.
    pub fn unhex(text: &str) -> Vec<u8> {
        assert!(text.len().is_multiple_of(2), "odd hex {text:?}");
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A fresh marker, `heimdall:enr_<32 hex>`.
    pub fn marker() -> Marker {
        Marker::parse(&format!("heimdall:enr_{}", random_hex(16))).unwrap()
    }

    /// A fresh step token.
    pub fn token() -> StepToken {
        StepToken::parse(&random_hex(16)).unwrap()
    }

    /// The registry line for `m` (synthetic key text, in the line character set).
    pub fn line(m: &Marker) -> RegistryLine {
        RegistryLine::parse(
            &format!(
                "cert-authority,principals=\"hm:dst_u5s:acct\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIu5sSyntheticTestKeyTextNotAKey0000000 {}",
                m.as_str()
            ),
            m,
        )
        .unwrap()
    }

    /// A not-after an hour away.
    pub fn far() -> NotAfter {
        NotAfter::new(now() + 3600).unwrap()
    }

    /// A not-after `secs` from now.
    pub fn soon(secs: i64) -> NotAfter {
        NotAfter::new(now() + secs).unwrap()
    }

    /// Wait until the local clock is past `na` (plus a second for the remote reading).
    pub fn wait_past(na: NotAfter) {
        while now() <= na.seconds() + 1 {
            thread::sleep(Duration::from_millis(200));
        }
    }

    // ---------------------------------------------------------------------------
    // HM1 output, checked against the frozen grammar (N4).
    // ---------------------------------------------------------------------------

    /// One finished run.
    #[derive(Debug)]
    pub struct Out {
        /// The exit code (`None`: ended by a signal).
        pub code: Option<i32>,
        /// Raw stdout (after the ready line, for sshd runs).
        pub stdout: Vec<u8>,
        /// Raw stderr.
        pub stderr: Vec<u8>,
        /// The HM1 pairs after `HM1 v=1`.
        pub kv: Vec<(String, String)>,
    }

    impl Out {
        pub fn new(code: Option<i32>, stdout: Vec<u8>, stderr: Vec<u8>) -> Out {
            let kv = parse_hm1(&stdout, &stderr);
            Out {
                code,
                stdout,
                stderr,
                kv,
            }
        }

        /// An unchecked run (a truncated script, a shim shell).
        pub fn raw(code: Option<i32>, stdout: Vec<u8>, stderr: Vec<u8>) -> Out {
            Out {
                code,
                stdout,
                stderr,
                kv: Vec::new(),
            }
        }

        pub fn get(&self, key: &str) -> Option<&str> {
            self.kv
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        }

        pub fn last(&self, key: &str) -> Option<&str> {
            self.kv
                .iter()
                .rev()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        }

        pub fn all(&self, key: &str) -> Vec<&str> {
            self.kv
                .iter()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
                .collect()
        }

        /// The last `content_hex`, decoded.
        pub fn content(&self) -> Vec<u8> {
            unhex(
                self.last("content_hex")
                    .unwrap_or_else(|| panic!("no content_hex: {self}")),
            )
        }

        /// Assert the exit code and the status word.
        pub fn expect(&self, code: i32, status: &str) -> &Out {
            assert!(
                self.code == Some(code) && self.last("status") == Some(status),
                "expected exit {code} status={status}: {self}"
            );
            self
        }

        /// Assert a refusal (30) with `reason`.
        pub fn refused(&self, reason: &str) -> &Out {
            self.expect(30, "refused");
            assert_eq!(self.last("reason"), Some(reason), "{self}");
            self
        }
    }

    impl std::fmt::Display for Out {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let cut = |b: &[u8]| {
                let t = String::from_utf8_lossy(b).into_owned();
                if t.len() > 3000 {
                    format!("{}…", &t[..3000])
                } else {
                    t
                }
            };
            write!(
                f,
                "exit={:?}\n--- stdout\n{}--- stderr\n{}",
                self.code,
                cut(&self.stdout),
                cut(&self.stderr)
            )
        }
    }

    /// The HM1 pairs of a script's stdout: the first line is `HM1 v=1`, every later
    /// line is `HM1 <known key>=<value of its shape>`.
    fn parse_hm1(stdout: &[u8], stderr: &[u8]) -> Vec<(String, String)> {
        if stdout.is_empty() {
            return Vec::new();
        }
        let ctx = || {
            format!(
                "stdout={:?} stderr={:?}",
                String::from_utf8_lossy(&stdout[..stdout.len().min(2000)]),
                String::from_utf8_lossy(stderr)
            )
        };
        let text =
            std::str::from_utf8(stdout).unwrap_or_else(|_| panic!("non-UTF-8 HM1: {}", ctx()));
        assert!(
            text.ends_with('\n'),
            "HM1 output does not end a line: {}",
            ctx()
        );
        assert!(
            stdout.len() <= hm1::MAX_STDOUT_BYTES,
            "HM1 output over the bound"
        );
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some(hm1::VERSION_LINE),
            "first line: {}",
            ctx()
        );
        lines
            .map(|line| {
                let rest = line
                    .strip_prefix(hm1::LINE_PREFIX)
                    .unwrap_or_else(|| panic!("not an HM1 line {line:?}: {}", ctx()));
                let (k, v) = rest
                    .split_once('=')
                    .unwrap_or_else(|| panic!("no '=' in {line:?}: {}", ctx()));
                let key = Hm1Key::from_wire(k)
                    .unwrap_or_else(|| panic!("unknown HM1 key {k:?}: {}", ctx()));
                assert!(
                    key.shape().accepts(v),
                    "HM1 {k}={v:?} is not of the frozen shape {:?}: {}",
                    key.shape(),
                    ctx()
                );
                (k.to_owned(), v.to_owned())
            })
            .collect()
    }

    // ---------------------------------------------------------------------------
    // Targets.
    // ---------------------------------------------------------------------------

    /// Which shell runs the scripts.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Shell {
        /// This host's `/bin/sh`.
        Native,
        /// dash (Debian 13).
        Dash,
        /// bash 5.2 as `/bin/sh` (Debian 13).
        BashSh,
        /// BusyBox `ash` (Alpine).
        BusyBox,
    }

    impl Shell {
        /// Whether the group proof can agree on this shell (ADR-0008 D5 §6.3 table):
        /// every shell but BusyBox `ash`, whose `kill` rejects `--`.
        pub fn automatic_recovery(self) -> bool {
            self != Shell::BusyBox
        }
    }

    /// How a target runs things.
    pub enum Runner {
        /// `/bin/sh -s` on this host, own process group.
        Direct,
        /// Through a loopback sshd.
        Sshd(Box<SshdLogin>),
        /// `docker exec` into a container.
        Docker {
            /// The exact container name.
            container: String,
            /// The account the scripts run as.
            user: String,
        },
    }

    /// A target shell with a scratch root.
    pub struct Target {
        pub shell: Shell,
        pub runner: Runner,
        /// The scratch root in the target (absolute).
        pub root: String,
        /// The scratch `HOME` in the target.
        pub home: String,
        /// Processes and groups to end on drop (exact PIDs).
        cleanup: Mutex<Vec<Cleanup>>,
        /// U11's registry guard for this target's scratch.
        guard: RegistryGuard,
        /// U11's owner digest (host targets): the owner's `~/.ssh`, Git global files
        /// and keychain list must be unchanged when the target drops.
        owner: Option<heimdall_testkit::owner_digest::OwnerDigest>,
        /// A container this target started (removed on drop, after the scratch).
        container: Option<Owned>,
        /// The native scratch (kept alive until the target drops; removed last).
        _native: Option<Scratch>,
    }

    /// A container a target owns.
    enum Owned {
        /// U11's shell container (bash as `sh`, BusyBox `ash`).
        Shell(ShellContainer),
        /// This suite's acl container.
        Own(Container),
    }

    enum Cleanup {
        Child(Child),
        /// A PID and the account that owns it.
        Pid(u32, String),
        Group(u32),
    }

    impl Drop for Target {
        fn drop(&mut self) {
            let items: Vec<Cleanup> = std::mem::take(&mut *self.cleanup.lock().unwrap());
            for item in items {
                match item {
                    Cleanup::Child(mut c) => {
                        let _ = c.kill();
                        let _ = c.wait();
                    }
                    Cleanup::Pid(p, user) => {
                        let _ = self.sh_as(&user, "kill -9 \"$1\" 2>/dev/null", &[&p.to_string()]);
                    }
                    Cleanup::Group(g) => {
                        let _ = self.kill_group("KILL", g);
                    }
                }
            }
            if let Some(owner) = &self.owner
                && !thread::panicking()
            {
                owner.assert_unchanged();
            }
            if let Runner::Docker { container, .. } = &self.runner
                && self.container.is_none()
            {
                // A shared fixture container: remove only this test's scratch (root
                // first for what other accounts made, then its owner).
                for user in ["0", self.user()] {
                    let _ = Command::new("docker")
                        .args(["exec", "-u", user, container, "rm", "-rf", &self.root])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
            }
        }
    }

    impl Target {
        fn new(shell: Shell, runner: Runner, root: String, native: Option<Scratch>) -> Target {
            let home = format!("{root}/home");
            let guard = match (&runner, &native) {
                (Runner::Sshd(login), _) => RegistryGuard::new(login.home.scratch()).unwrap(),
                (_, Some(scratch)) => RegistryGuard::new(scratch).unwrap(),
                // A container target's registries are checked as container paths.
                (_, None) => RegistryGuard::new(&Scratch::new().unwrap()).unwrap(),
            };
            let owner = match runner {
                Runner::Docker { .. } => None,
                _ => Some(heimdall_testkit::owner_digest::OwnerDigest::capture().unwrap()),
            };
            Target {
                shell,
                runner,
                root,
                home,
                cleanup: Mutex::new(Vec::new()),
                guard,
                owner,
                container: None,
                _native: native,
            }
        }

        /// The account the scripts run as (Docker), or `""` (native).
        pub fn user(&self) -> &str {
            match &self.runner {
                Runner::Docker { user, .. } => user,
                _ => "",
            }
        }

        /// This host's `/bin/sh`, direct.
        pub fn native() -> Target {
            let scratch = Scratch::new().unwrap();
            let root = scratch.path().to_str().unwrap().to_owned();
            let t = Target::new(Shell::Native, Runner::Direct, root, Some(scratch));
            t.mkdir(&t.home.clone(), "700");
            t
        }

        /// This host's `/bin/sh` through a loopback sshd.
        pub fn sshd() -> Target {
            let login = SshdLogin::new();
            let root = login
                .home
                .scratch()
                .subdir("t")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let t = Target::new(Shell::Native, Runner::Sshd(Box::new(login)), root, None);
            t.mkdir(&t.home.clone(), "700");
            t
        }

        /// The M00-T03 `enrollable` container (dash), as its account `enroll`.
        pub fn m00_enrollable() -> Target {
            let label = docker(&[
                "inspect",
                "-f",
                "{{index .Config.Labels \"heimdall.fixture\"}}",
                M00_ENROLL,
            ]);
            assert!(
                label.status.success()
                    && String::from_utf8_lossy(&label.stdout).trim() == "m00-t03",
                "the M00-T03 fixtures are not up (run tests/fixtures/ssh/up.sh): {}",
                String::from_utf8_lossy(&label.stderr)
            );
            let root = format!("/tmp/hm-u5s-{}", random_hex(6));
            let t = Target::new(
                Shell::Dash,
                Runner::Docker {
                    container: M00_ENROLL.to_owned(),
                    user: "enroll".to_owned(),
                },
                root.clone(),
                None,
            );
            let out = t.sh("mkdir -m 700 \"$1\" && mkdir -m 700 \"$1/home\"", &[&root]);
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            t
        }

        /// A disposable shell container: U11's `ShellContainer` for bash as `sh` and
        /// BusyBox `ash` (`--network none --cap-drop ALL --init`, labelled
        /// `heimdall.fixture=m03-shells`), or this suite's acl container for dash.
        /// Scripts run as uid 1000.
        pub fn container(shell: Shell) -> Target {
            let owned = match shell {
                Shell::BashSh | Shell::BusyBox => {
                    heimdall_testkit::shells::ensure_images().unwrap_or_else(|e| panic!("{e}"));
                    let kind = if shell == Shell::BashSh {
                        ShellKind::BashAsSh
                    } else {
                        ShellKind::BusyBoxAsh
                    };
                    Owned::Shell(ShellContainer::start(kind).unwrap_or_else(|e| panic!("{e}")))
                }
                _ => Owned::Own(Container::start(shell)),
            };
            let name = match &owned {
                Owned::Shell(c) => c.name().to_owned(),
                Owned::Own(c) => c.name.clone(),
            };
            let root = format!("/tmp/hm-u5s-{}", random_hex(6));
            let mut t = Target::new(
                shell,
                Runner::Docker {
                    container: name,
                    user: "1000:1000".to_owned(),
                },
                root.clone(),
                None,
            );
            t.container = Some(owned);
            let out = t.sh("mkdir -m 700 \"$1\" \"$1/home\"", &[&root]);
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            t
        }

        /// Whether this target is Linux (procfs identities).
        pub fn is_linux(&self) -> bool {
            matches!(self.runner, Runner::Docker { .. }) || cfg!(target_os = "linux")
        }

        /// Whether this target runs scripts through sshd.
        pub fn via_sshd(&self) -> bool {
            matches!(self.runner, Runner::Sshd(_))
        }

        /// Whether [`sh_as`](Self::sh_as) really is another account (Docker).
        pub fn has_root(&self) -> bool {
            matches!(self.runner, Runner::Docker { .. })
        }

        /// `<root>/<rel>`.
        pub fn path(&self, rel: &str) -> String {
            format!("{}/{rel}", self.root)
        }

        /// The registry guard (m03-plan §0.2): an explicit path under this target's
        /// scratch root. Anything else is refused before any script runs.
        pub fn location(&self, path: &str) -> RegistryLocation {
            assert!(
                path.starts_with(&format!("{}/", self.root)) && !path.contains("/../"),
                "registry guard: {path} is not under the scratch root"
            );
            let target = match &self.runner {
                Runner::Docker { container, .. } => RegistryTarget::Container {
                    name: container,
                    path,
                },
                _ => RegistryTarget::Path(std::path::Path::new(path)),
            };
            self.guard
                .check(&target)
                .unwrap_or_else(|e| panic!("registry guard (U11) refused {path}: {e:?}"));
            RegistryLocation::from_plan(Some(path)).unwrap()
        }

        /// The remote home, only where `HOME` is this target's scratch home.
        pub fn remote_home(&self) -> RegistryLocation {
            assert!(
                !self.via_sshd(),
                "registry guard: through sshd the remote home is the account's real home"
            );
            RegistryLocation::RemoteHome
        }

        // --- helper commands (not scripts) ---

        fn helper(
            &self,
            as_user: Option<&str>,
            cmd: &str,
            args: &[&str],
            stdin: Option<&[u8]>,
        ) -> Output {
            let mut c = match &self.runner {
                Runner::Docker { container, user } => {
                    let mut c = Command::new("docker");
                    c.arg("exec");
                    if stdin.is_some() {
                        c.arg("-i");
                    }
                    c.args(["-u", as_user.unwrap_or(user)])
                        .args(["-e", &format!("HOME={}", self.home)])
                        .args(["-e", "LC_ALL=C"])
                        .arg(container)
                        .args(["/bin/sh", "-c", cmd, "sh"])
                        .args(args);
                    c
                }
                _ => {
                    let mut c = Command::new("/bin/sh");
                    c.args(["-c", cmd, "sh"])
                        .args(args)
                        .env_clear()
                        .env("PATH", NATIVE_PATH)
                        .env("HOME", &self.home)
                        .env("LC_ALL", "C")
                        .current_dir(&self.root);
                    c
                }
            };
            c.stdout(Stdio::piped()).stderr(Stdio::piped());
            match stdin {
                None => {
                    c.stdin(Stdio::null());
                    c.output().unwrap()
                }
                Some(input) => {
                    c.stdin(Stdio::piped());
                    let mut child = c.spawn().unwrap();
                    let mut w = child.stdin.take().unwrap();
                    let data = input.to_vec();
                    let writer = thread::spawn(move || {
                        let _ = w.write_all(&data);
                    });
                    let out = child.wait_with_output().unwrap();
                    writer.join().unwrap();
                    out
                }
            }
        }

        /// A helper command as the scripts' account.
        pub fn sh(&self, cmd: &str, args: &[&str]) -> Output {
            self.helper(None, cmd, args, None)
        }

        /// A helper command as another account (Docker `-u`; no capability is
        /// needed, so it works in U11's `--cap-drop ALL` containers), or as this
        /// account (native).
        pub fn sh_as(&self, user: &str, cmd: &str, args: &[&str]) -> Output {
            if user.is_empty() {
                return self.sh(cmd, args);
            }
            self.helper(Some(user), cmd, args, None)
        }

        /// As [`sh_as`](Self::sh_as), and it must succeed; its stdout.
        pub fn as_ok(&self, user: &str, cmd: &str, args: &[&str]) -> String {
            let out = self.sh_as(user, cmd, args);
            assert!(
                out.status.success(),
                "helper as {user} {cmd:?} {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        /// A helper that must succeed; its stdout.
        pub fn sh_ok(&self, cmd: &str, args: &[&str]) -> String {
            let out = self.sh(cmd, args);
            assert!(
                out.status.success(),
                "helper {cmd:?} {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        pub fn put(&self, path: &str, bytes: &[u8]) {
            let out = self.helper(None, "cat > \"$1\"", &[path], Some(bytes));
            assert!(
                out.status.success(),
                "put {path}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        pub fn get(&self, path: &str) -> Option<Vec<u8>> {
            let out = self.sh("[ -f \"$1\" ] && cat \"$1\"", &[path]);
            out.status.success().then_some(out.stdout)
        }

        pub fn exists(&self, path: &str) -> bool {
            self.sh("[ -e \"$1\" ] || [ -L \"$1\" ]", &[path])
                .status
                .success()
        }

        pub fn mkdir(&self, path: &str, mode: &str) {
            self.sh_ok("mkdir -m \"$2\" \"$1\"", &[path, mode]);
        }

        pub fn chmod(&self, mode: &str, path: &str) {
            self.sh_ok("chmod \"$1\" \"$2\"", &[mode, path]);
        }

        /// The `ls -ldn` mode string.
        pub fn mode(&self, path: &str) -> String {
            self.sh_ok("ls -ldn \"$1\"", &[path])
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned()
        }

        /// A symlink's contents.
        pub fn link(&self, path: &str) -> Option<String> {
            let out = self.sh("[ -L \"$1\" ] && ls -ld \"$1\"", &[path]);
            if !out.status.success() {
                return None;
            }
            let text = String::from_utf8_lossy(&out.stdout).trim_end().to_owned();
            text.rsplit_once(" -> ").map(|(_, t)| t.to_owned())
        }

        /// The names in a directory (with dot files, without `.` and `..`).
        pub fn names(&self, dir: &str) -> Vec<String> {
            let mut v: Vec<String> = self
                .sh_ok("ls -a \"$1\"", &[dir])
                .lines()
                .filter(|l| *l != "." && *l != "..")
                .map(str::to_owned)
                .collect();
            v.sort();
            v
        }

        pub fn mkfifo(&self, path: &str) {
            self.sh_ok("mkfifo -m 600 \"$1\"", &[path]);
        }

        /// Send `sig` to the process group `pgid` (as the scripts' account).
        pub fn kill_group(&self, sig: &str, pgid: u32) -> bool {
            self.kill_group_as("", sig, pgid)
        }

        /// As [`kill_group`](Self::kill_group), as `user`.
        pub fn kill_group_as(&self, user: &str, sig: &str, pgid: u32) -> bool {
            let cmd = if self.shell == Shell::BusyBox {
                // BusyBox's kill rejects `--`.
                "kill -\"$1\" -\"$2\""
            } else {
                "kill -s \"$1\" -- -\"$2\""
            };
            self.sh_as(user, cmd, &[sig, &pgid.to_string()])
                .status
                .success()
        }

        /// Send `sig` to one process (as the scripts' account).
        pub fn kill_pid(&self, sig: &str, pid: u32) -> bool {
            self.sh("kill -s \"$1\" \"$2\"", &[sig, &pid.to_string()])
                .status
                .success()
        }

        /// Whether `pid` exists (a zombie included), whoever owns it.
        pub fn alive(&self, pid: u32) -> bool {
            let cmd = if self.is_linux() {
                "[ -e \"/proc/$1\" ]"
            } else {
                "ps -o pid= -p \"$1\" >/dev/null 2>&1"
            };
            self.sh(cmd, &[&pid.to_string()]).status.success()
        }

        /// Whether any process is in group `pgid`.
        pub fn group_has_members(&self, pgid: u32) -> bool {
            let out = self.sh_ok("ps -A -o pgid=", &[]);
            out.lines().any(|l| l.trim() == pgid.to_string())
        }

        /// Wait (bounded) until `pred`.
        pub fn wait_until(&self, what: &str, secs: u64, pred: impl Fn() -> bool) {
            let end = Instant::now() + Duration::from_secs(secs);
            while !pred() {
                assert!(Instant::now() < end, "timed out waiting for {what}");
                thread::sleep(Duration::from_millis(50));
            }
        }

        /// A `sleep` the test owns: in its own process group (`own_group`), or not.
        /// Ended by exact PID on drop.
        pub fn start_sleeper(&self, own_group: bool) -> u32 {
            match &self.runner {
                Runner::Docker { .. } => {
                    let cmd = if own_group {
                        "setsid sleep 300 >/dev/null 2>&1 < /dev/null & echo $!"
                    } else {
                        "sleep 300 >/dev/null 2>&1 < /dev/null & echo $!"
                    };
                    let pid: u32 = self.sh_ok(cmd, &[]).trim().parse().unwrap();
                    self.cleanup
                        .lock()
                        .unwrap()
                        .push(Cleanup::Pid(pid, self.user().to_owned()));
                    pid
                }
                _ => {
                    let mut c = Command::new("/bin/sleep");
                    c.arg("300")
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null());
                    if own_group {
                        c.process_group(0);
                    }
                    let child = c.spawn().unwrap();
                    let pid = child.id();
                    self.cleanup.lock().unwrap().push(Cleanup::Child(child));
                    pid
                }
            }
        }

        /// A `sleep` leading its own group, run by another account (uid 2000; Docker).
        pub fn start_foreign_sleeper(&self) -> u32 {
            assert!(self.has_root());
            let pid: u32 = self
                .as_ok(
                    "2000:2000",
                    "setsid sleep 300 >/dev/null 2>&1 < /dev/null & echo $!",
                    &[],
                )
                .trim()
                .parse()
                .unwrap();
            self.cleanup
                .lock()
                .unwrap()
                .push(Cleanup::Pid(pid, "2000:2000".to_owned()));
            pid
        }

        /// A process group whose leader has exited and whose one member (a `sleep`)
        /// lives on: the "live child, leader gone" case. Returns the group.
        pub fn start_orphan_group(&self) -> u32 {
            let pgid: u32 = match &self.runner {
                Runner::Docker { .. } => self
                    .sh_ok(
                        "setsid sh -c 'sleep 300 >/dev/null 2>&1 < /dev/null & echo $$' < /dev/null",
                        &[],
                    )
                    .trim()
                    .parse()
                    .unwrap(),
                _ => {
                    let out = Command::new("/bin/sh")
                        .args(["-c", "sleep 300 >/dev/null 2>&1 < /dev/null & echo $$"])
                        .env_clear()
                        .env("PATH", NATIVE_PATH)
                        .process_group(0)
                        .stdin(Stdio::null())
                        .output()
                        .unwrap();
                    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
                }
            };
            self.cleanup.lock().unwrap().push(Cleanup::Group(pgid));
            self.wait_until("the orphan group's leader to exit", 10, || {
                !self.alive(pgid)
            });
            assert!(
                self.group_has_members(pgid),
                "the orphan group has no member"
            );
            pgid
        }

        /// A PID that no process has (a just-ended `sleep`), and that is no group.
        pub fn dead_pid(&self) -> u32 {
            let pid: u32 = self
                .sh_ok("sleep 0 & p=$!; wait $p; echo $p", &[])
                .trim()
                .parse()
                .unwrap();
            assert!(!self.alive(pid) && !self.group_has_members(pid));
            pid
        }

        /// The start identity and boot identity of `pid` as the scripts compute them
        /// (hex), read independently by a helper.
        pub fn identity_of(&self, pid: u32) -> (String, String) {
            let raw = |cmd: &str| {
                let s = self.sh_ok(cmd, &[&pid.to_string()]);
                s.trim_end_matches('\n').to_owned()
            };
            if self.is_linux() {
                let stat = self
                    .get(&format!("/proc/{pid}/stat"))
                    .unwrap_or_else(|| panic!("no /proc/{pid}/stat"));
                let p = heimdall_domain::procstat::parse(&stat).unwrap();
                let boot = raw("cat /proc/sys/kernel/random/boot_id");
                (
                    hex(p.start_time.to_string().as_bytes()),
                    hex(boot.as_bytes()),
                )
            } else {
                let start = raw("TZ=UTC0 ps -o lstart= -p \"$1\" | awk '{ $1 = $1; print }'");
                let boot = raw(Self::bsd_boot_command());
                (hex(start.as_bytes()), hex(boot.as_bytes()))
            }
        }

        /// The boot-identity command of a non-Linux (host) target: macOS
        /// `kern.bootsessionuuid`, the BSDs `kern.boottime` up to its first `}`
        /// (ADR-0008 §17.17 item 2).
        fn bsd_boot_command() -> &'static str {
            if cfg!(target_os = "macos") {
                "sysctl -n kern.bootsessionuuid"
            } else {
                "sysctl -n kern.boottime | awk '{ i = index($0, \"}\"); if (i > 0) { print substr($0, 1, i); exit } }'"
            }
        }

        /// The boot identity of this target (hex).
        pub fn boot_hex(&self) -> String {
            if self.is_linux() {
                hex(self
                    .sh_ok("cat /proc/sys/kernel/random/boot_id", &[])
                    .trim_end()
                    .as_bytes())
            } else {
                hex(self
                    .sh_ok(Self::bsd_boot_command(), &[])
                    .trim_end()
                    .as_bytes())
            }
        }

        // --- scripts ---

        /// Run `script` under the target shell (group leader) and wait.
        pub fn run(&self, script: &str) -> Out {
            self.spawn(script).wait()
        }

        /// As [`run`](Self::run), without the HM1 check (truncated or shimmed runs).
        pub fn run_raw(&self, script: &str) -> Out {
            self.spawn_with(script, true, true).wait()
        }

        /// Run `script` in the background (its output collected and its process reaped
        /// by a thread, so a killed shell never lingers as a zombie).
        pub fn spawn(&self, script: &str) -> Running {
            self.spawn_with(script, true, false)
        }

        /// As [`spawn`](Self::spawn), without making the shell a group leader (direct
        /// and Docker only).
        pub fn spawn_not_leader(&self, script: &str) -> Running {
            self.spawn_with(script, false, false)
        }

        /// As [`spawn_not_leader`](Self::spawn_not_leader), without the HM1 check.
        pub fn spawn_not_leader_raw(&self, script: &str) -> Running {
            self.spawn_with(script, false, true)
        }

        fn spawn_with(&self, script: &str, leader: bool, raw: bool) -> Running {
            let mut cmd = match &self.runner {
                Runner::Direct => {
                    let mut c = Command::new("/bin/sh");
                    c.arg("-s")
                        .env_clear()
                        .env("PATH", NATIVE_PATH)
                        .env("HOME", &self.home)
                        .current_dir(&self.root);
                    if leader {
                        c.process_group(0);
                    }
                    c
                }
                Runner::Sshd(login) => {
                    assert!(leader, "an sshd session always leads its group");
                    login.command()
                }
                Runner::Docker { container, user } => {
                    let mut c = Command::new("docker");
                    c.args(["exec", "-i", "-u", user])
                        .args(["-e", &format!("HOME={}", self.home)])
                        .args(["-w", &self.root])
                        .arg(container);
                    if leader {
                        // As U11's `ShellContainer::run_script`: `setsid` in the
                        // background of a wrapper that is not a group leader, waited
                        // for, so the exit status is kept (BusyBox `setsid` has no `-w`).
                        c.args([
                            "/bin/sh",
                            "-c",
                            "exec 3<&0; setsid /bin/sh -s <&3 3<&- & wait \"$!\"",
                        ]);
                    } else {
                        c.args(["/bin/sh", "-s"]);
                    }
                    c
                }
            };
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = cmd.spawn().unwrap();
            let pid = child.id();
            let ready = self.via_sshd();
            let stdin = child.stdin.take().unwrap();
            let mut stdout = child.stdout.take().unwrap();
            let mut stderr = child.stderr.take().unwrap();
            let text = script.as_bytes().to_vec();
            let handle = thread::spawn(move || {
                let err = thread::spawn(move || {
                    let mut b = Vec::new();
                    let _ = stderr.read_to_end(&mut b);
                    b
                });
                let mut head = Vec::new();
                let mut send = true;
                if ready {
                    // The ready handshake: the script is written only after the line.
                    let mut byte = [0u8; 1];
                    while stdout.read(&mut byte).unwrap_or(0) == 1 {
                        head.push(byte[0]);
                        if byte[0] == b'\n' {
                            break;
                        }
                    }
                    if head == b"HM1 ready\n" {
                        head.clear();
                    } else {
                        send = false;
                    }
                }
                if send {
                    let mut w = stdin;
                    let _ = w.write_all(&text);
                } else {
                    drop(stdin);
                }
                let reader = thread::spawn(move || {
                    let mut b = Vec::new();
                    let _ = stdout.read_to_end(&mut b);
                    b
                });
                // Reap as soon as the shell exits (a child it leaves behind may keep
                // stdout open; the shell must not linger as a zombie meanwhile).
                let deadline = Instant::now() + Duration::from_secs(300);
                let status = loop {
                    if let Some(s) = child.try_wait().unwrap() {
                        break s;
                    }
                    if Instant::now() > deadline {
                        let _ = child.kill();
                        break child.wait().unwrap();
                    }
                    thread::sleep(Duration::from_millis(5));
                };
                head.extend(reader.join().unwrap());
                let err = err.join().unwrap();
                if raw {
                    Out::raw(status.code(), head, err)
                } else {
                    Out::new(status.code(), head, err)
                }
            });
            Running {
                pid,
                handle: Some(handle),
            }
        }

        // --- registries ---

        /// A registry in a fresh directory (mode 0700).
        pub fn reg(&self) -> Reg<'_> {
            let dir = self.path(&format!("r{}", random_hex(3)));
            self.mkdir(&dir, "700");
            Reg::at(self, &dir)
        }

        /// A registry whose directory does not exist yet (its parent does).
        pub fn reg_absent(&self) -> Reg<'_> {
            let parent = self.path(&format!("p{}", random_hex(3)));
            self.mkdir(&parent, "700");
            Reg::at(self, &format!("{parent}/.ssh"))
        }
    }

    /// A background run.
    pub struct Running {
        /// The host PID of the spawned process (the shell itself for direct runs).
        pub pid: u32,
        handle: Option<JoinHandle<Out>>,
    }

    impl Running {
        pub fn wait(mut self) -> Out {
            self.handle.take().unwrap().join().unwrap()
        }

        /// Whether the run has ended.
        pub fn finished(&self) -> bool {
            self.handle.as_ref().is_none_or(JoinHandle::is_finished)
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            if let Some(h) = self.handle.take() {
                if !h.is_finished() {
                    // Never block a failing test on a stuck script: end it by exact
                    // PID, and give up on its output if a child keeps it open.
                    let _ = Command::new("kill")
                        .args(["-9", &self.pid.to_string()])
                        .stderr(Stdio::null())
                        .status();
                    let end = Instant::now() + Duration::from_secs(5);
                    while !h.is_finished() && Instant::now() < end {
                        thread::sleep(Duration::from_millis(20));
                    }
                }
                if h.is_finished() {
                    let _ = h.join();
                }
            }
        }
    }

    /// One registry under test.
    pub struct Reg<'t> {
        pub t: &'t Target,
        pub dir: String,
        pub path: String,
        pub loc: RegistryLocation,
    }

    impl<'t> Reg<'t> {
        pub fn at(t: &'t Target, dir: &str) -> Reg<'t> {
            let path = format!("{dir}/authorized_keys");
            let loc = t.location(&path);
            Reg {
                t,
                dir: dir.to_owned(),
                path,
                loc,
            }
        }

        pub fn seed(&self, bytes: &[u8]) {
            self.t.put(&self.path, bytes);
            self.t.chmod("600", &self.path);
        }

        pub fn bytes(&self) -> Option<Vec<u8>> {
            self.t.get(&self.path)
        }

        pub fn lock_path(&self) -> String {
            format!("{}/.hm-lock.authorized_keys", self.dir)
        }

        pub fn lock(&self) -> Option<String> {
            self.t.link(&self.lock_path())
        }

        /// Plant a lock record (as another script would have).
        pub fn plant_lock(&self, record: &str) {
            self.t
                .sh_ok("ln -s \"$1\" \"$2\"", &[record, &self.lock_path()]);
        }

        /// The names in the registry's directory other than the registry itself.
        pub fn others(&self) -> Vec<String> {
            self.t
                .names(&self.dir)
                .into_iter()
                .filter(|n| n != "authorized_keys")
                .collect()
        }

        pub fn inspect_script(&self, m: &Marker) -> RemoteScript {
            script::inspect(&InspectParams {
                registry: self.loc.clone(),
                marker: m.clone(),
            })
        }

        pub fn inspect(&self, m: &Marker) -> Out {
            self.t.run(self.inspect_script(m).text())
        }

        pub fn bootstrap_script(&self) -> RemoteScript {
            script::bootstrap(&BootstrapParams {
                registry: self.loc.clone(),
            })
        }

        pub fn bootstrap(&self) -> Out {
            self.t.run(self.bootstrap_script().text())
        }

        pub fn append_script(
            &self,
            m: &Marker,
            l: &RegistryLine,
            tok: &StepToken,
            na: NotAfter,
        ) -> RemoteScript {
            script::append(&AppendParams {
                registry: self.loc.clone(),
                marker: m.clone(),
                line: l.clone(),
                token: tok.clone(),
                not_after_remote: na,
            })
        }

        pub fn append(&self, m: &Marker, l: &RegistryLine, na: NotAfter) -> Out {
            self.t.run(self.append_script(m, l, &token(), na).text())
        }

        pub fn remove_script(
            &self,
            m: &Marker,
            tok: &StepToken,
            na: NotAfter,
            pre: &[u8],
            post: &[u8],
        ) -> RemoteScript {
            script::remove(&RemoveParams {
                registry: self.loc.clone(),
                marker: m.clone(),
                token: tok.clone(),
                not_after_remote: na,
                preimage: Payload::new(pre).unwrap(),
                post_image: Payload::new(post).unwrap(),
            })
        }

        pub fn remove(&self, m: &Marker, na: NotAfter, pre: &[u8], post: &[u8]) -> Out {
            self.t
                .run(self.remove_script(m, &token(), na, pre, post).text())
        }

        pub fn fence_script(&self, tok: &StepToken, terminate: bool) -> RemoteScript {
            script::fence(&FenceParams {
                registry: self.loc.clone(),
                token: tok.clone(),
                terminate,
            })
        }

        pub fn fence(&self, tok: &StepToken, terminate: bool) -> Out {
            self.t.run(self.fence_script(tok, terminate).text())
        }
    }

    // ---------------------------------------------------------------------------
    // Pause hooks (the script side is `script::test_form`; this follows U11's
    // `PauseHooks` plan text: FIFOs in scratch, wait_at, release, stop/continue).
    // ---------------------------------------------------------------------------

    /// A pause directory in a target.
    pub struct Pauses<'t> {
        t: &'t Target,
        pub dir: String,
    }

    impl<'t> Pauses<'t> {
        pub fn new(t: &'t Target) -> Pauses<'t> {
            let dir = t.path(&format!("pause{}", random_hex(3)));
            t.mkdir(&dir, "700");
            Pauses { t, dir }
        }

        /// The test form of `s` for this directory.
        pub fn form(&self, s: &RemoteScript) -> String {
            use heimdall_registry::script::test_form::{PauseDir, with_pause_points};
            with_pause_points(s, &PauseDir::parse(&self.dir).unwrap())
                .unwrap()
                .into_text()
        }

        /// Make `name` a pause point for the next script that reaches it.
        pub fn arm(&self, name: &str) -> Gate<'t> {
            let fifo = format!("{}/{name}", self.dir);
            let _ = self.t.sh("rm -f \"$1\" \"$1.pid\"", &[&fifo]);
            self.t.mkfifo(&fifo);
            Gate {
                t: self.t,
                fifo,
                writer: None,
            }
        }
    }

    /// One armed pause point.
    pub struct Gate<'t> {
        t: &'t Target,
        fifo: String,
        writer: Option<(Child, Option<ChildStdin>)>,
    }

    impl Gate<'_> {
        /// Wait until a script is paused here; its PID (its process group).
        pub fn wait(&mut self) -> u32 {
            self.wait_for(None)
        }

        /// As [`wait`](Self::wait), failing at once (with its output) when `run`
        /// ends before reaching the point.
        pub fn wait_on(&mut self, run: &mut Option<Running>) -> u32 {
            self.wait_for(Some(run))
        }

        fn wait_for(&mut self, mut run: Option<&mut Option<Running>>) -> u32 {
            let mut c = match &self.t.runner {
                Runner::Docker { container, user } => {
                    let mut c = Command::new("docker");
                    c.args(["exec", "-i", "-u", user, container]).args([
                        "/bin/sh",
                        "-c",
                        "exec cat > \"$1\"",
                        "sh",
                        &self.fifo,
                    ]);
                    c
                }
                _ => {
                    let mut c = Command::new("/bin/sh");
                    c.args(["-c", "exec cat > \"$1\"", "sh", &self.fifo]);
                    c
                }
            };
            let mut child = c
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let stdin = child.stdin.take();
            self.writer = Some((child, stdin));
            let pidfile = format!("{}.pid", self.fifo);
            let end = Instant::now() + Duration::from_secs(60);
            loop {
                if let Some(b) = self.t.get(&pidfile)
                    && let Ok(pid) = String::from_utf8_lossy(&b).trim().parse::<u32>()
                {
                    return pid;
                }
                if let Some(slot) = run.as_deref_mut()
                    && slot.as_ref().is_some_and(Running::finished)
                {
                    let out = slot.take().unwrap().wait();
                    panic!("the script ended before pause {}: {out}", self.fifo);
                }
                assert!(
                    Instant::now() < end,
                    "no script reached pause {}",
                    self.fifo
                );
                thread::sleep(Duration::from_millis(25));
            }
        }

        /// Release the paused script.
        pub fn release(&mut self) {
            if let Some((mut child, stdin)) = self.writer.take() {
                drop(stdin);
                let end = Instant::now() + Duration::from_secs(10);
                loop {
                    if child.try_wait().unwrap().is_some() {
                        break;
                    }
                    if Instant::now() > end {
                        // The script never opened the FIFO: open it ourselves.
                        let _ = self.t.sh(": < \"$1\"", &[&self.fifo]);
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    impl Drop for Gate<'_> {
        fn drop(&mut self) {
            self.release();
        }
    }

    // ---------------------------------------------------------------------------
    // Containers.
    // ---------------------------------------------------------------------------

    /// A disposable container, removed by exact name on drop.
    pub struct Container {
        pub name: String,
    }

    pub fn docker(args: &[&str]) -> Output {
        Command::new("docker")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    static IMAGE: Mutex<bool> = Mutex::new(false);

    /// Build the Debian image with procps and acl once (the network is attached only
    /// for this build step; every container runs with `--network none`).
    fn debian_image() {
        let mut built = IMAGE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *built || docker(&["image", "inspect", DEBIAN_IMAGE]).status.success() {
            *built = true;
            return;
        }
        let dockerfile = format!(
            "FROM {DEBIAN_BASE}\nRUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends procps acl && rm -rf /var/lib/apt/lists/*\n"
        );
        let mut child = Command::new("docker")
            .args(["build", "--label", LABEL, "-t", DEBIAN_IMAGE, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(dockerfile.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "docker build: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        *built = true;
    }

    impl Container {
        pub fn start(shell: Shell) -> Container {
            let image = match shell {
                Shell::BusyBox => ALPINE_BASE.to_owned(),
                _ => {
                    debian_image();
                    DEBIAN_IMAGE.to_owned()
                }
            };
            let name = format!("hm-u5s-{}-{}", std::process::id(), random_hex(4));
            let out = docker(&[
                "run",
                "-d",
                "--network",
                "none",
                "--init",
                "--label",
                LABEL,
                "--name",
                &name,
                &image,
                "sleep",
                "infinity",
            ]);
            assert!(
                out.status.success(),
                "docker run: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let c = Container { name };
            if shell == Shell::BashSh {
                let out = docker(&["exec", "-u", "0", &c.name, "ln", "-sf", "bash", "/bin/sh"]);
                assert!(out.status.success());
            }
            c
        }
    }

    impl Drop for Container {
        fn drop(&mut self) {
            let _ = docker(&["rm", "-f", &self.name]);
        }
    }

    // ---------------------------------------------------------------------------
    // The loopback sshd login.
    // ---------------------------------------------------------------------------

    /// A loopback sshd that authorizes a fixture key held by a fake agent; the
    /// scratch user configuration names them (the configuration under test), the
    /// command line carries only the isolation arguments.
    pub struct SshdLogin {
        _agent: FakeAgent,
        _sshd: LoopbackSshd,
        pub home: ScratchHome,
    }

    impl SshdLogin {
        fn new() -> SshdLogin {
            let home = ScratchHome::new();
            let key = FixtureKey::generate();
            let sshd = LoopbackSshd::start(
                home.scratch(),
                SshdConfig {
                    authorized: vec![key.public().clone()],
                    ..SshdConfig::default()
                },
            )
            .unwrap_or_else(|e| panic!("{e}"));
            home.trust_host_key(&sshd.host_key_line).unwrap();
            let identity = home.ssh_dir.join("u5s_fixture.pub");
            key.write_public(&identity).unwrap();
            let agent = FakeAgent::start(
                heimdall_testkit::agent::Endpoint::in_scratch(home.scratch(), "a").unwrap(),
                FakeAgentConfig {
                    keys: vec![key],
                    mode: heimdall_testkit::agent::AgentMode::Normal,
                },
            );
            let agent_path = agent.endpoint().locator();
            home.write_user_config(&format!(
                "Host hm-u5s\n  HostName 127.0.0.1\n  Port {}\n  IdentityAgent {}\n  IdentityFile {}\n  IdentitiesOnly yes\n",
                sshd.port,
                heimdall_testkit::home::ssh_option_path(std::path::Path::new(&agent_path)),
                heimdall_testkit::home::ssh_option_path(&identity),
            ))
            .unwrap();
            SshdLogin {
                _agent: agent,
                _sshd: sshd,
                home,
            }
        }

        fn command(&self) -> Command {
            let mut cmd = self
                .home
                .client_command(ClientKind::Ssh, "hm-u5s")
                .unwrap_or_else(|e| panic!("{e:?}"));
            cmd.arg(REMOTE_COMMAND);
            cmd
        }
    }
}

/// The rows, each a body shared by every target it runs on.
#[cfg(all(unix, debug_assertions))]
mod rows {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use heimdall_registry::script::{self, Marker, NotAfter, RegistryLine, StepToken};

    use crate::harness::{
        NATIVE_PATH, Out, Pauses, Reg, Runner, Shell, Target, far, hex, line, marker, now, soon,
        token, unhex, wait_past,
    };

    fn nl(l: &RegistryLine) -> Vec<u8> {
        let mut v = l.as_str().as_bytes().to_vec();
        v.push(b'\n');
        v
    }

    fn count(hay: &[u8], needle: &str) -> usize {
        hay.windows(needle.len())
            .filter(|w| *w == needle.as_bytes())
            .count()
    }

    /// The lines of `bytes` that contain `m`.
    fn marker_lines(bytes: &[u8], m: &Marker) -> Vec<Vec<u8>> {
        bytes
            .split(|b| *b == b'\n')
            .filter(|l| count(l, m.as_str()) > 0)
            .map(<[u8]>::to_vec)
            .collect()
    }

    /// `bytes` without the lines equal to `l`.
    fn without_line(bytes: &[u8], l: &RegistryLine) -> Vec<u8> {
        let mut out = Vec::new();
        for piece in bytes.split_inclusive(|b| *b == b'\n') {
            let body = piece.strip_suffix(b"\n").unwrap_or(piece);
            if body != l.as_str().as_bytes() {
                out.extend_from_slice(piece);
            }
        }
        out
    }

    /// Nothing of ours is left in the registry's directory (no lock, no temp file).
    fn clean(r: &Reg<'_>) {
        let left: Vec<String> = r
            .others()
            .into_iter()
            .filter(|n| n.starts_with(".hm-"))
            .collect();
        assert!(left.is_empty(), "left behind: {left:?}");
    }

    /// Whether a run ended by a signal (directly: no exit code; through `docker exec`
    /// and the `wait` wrapper: 128 + the signal).
    fn killed(o: &Out) -> bool {
        matches!(o.code, None | Some(137 | 143))
    }

    fn record(tok: &StepToken, pid: u32, start: &str, boot: &str, na: i64) -> String {
        format!("hm1-{}-{pid}-{start}-{boot}-{na}", tok.as_str())
    }

    fn rec_parts(rec: &str) -> Vec<String> {
        rec.split('-').map(str::to_owned).collect()
    }

    /// Prefix shell functions (the injected faults of U11's `ProbeShim`): a `kill`
    /// that rejects the probe's syntax.
    const SHIM_KILL_SYNTAX: &str = "kill() {\n  if [ \"$1\" = -s ] && [ \"$3\" = -- ]; then\n    printf '%s\\n' 'sh: kill: Illegal number: -' >&2\n    return 2\n  fi\n  command kill \"$@\"\n}\n";

    /// A `ps` whose listing drops the group `pgid` (when `when` names an existing file,
    /// or always).
    fn shim_ps_drop(pgid: &str, when: Option<&str>) -> String {
        let cond = when.map_or_else(|| "true".to_owned(), |f| format!("[ -f '{f}' ]"));
        format!(
            "ps() {{\n  if [ \"$1\" = -A ] && {cond}; then\n    command ps \"$@\" | awk -v t='{pgid}' '{{ if ($1 != t) print }}'\n  else\n    command ps \"$@\"\n  fi\n}}\n"
        )
    }

    /// A `ps` whose listing adds the group `pgid`.
    fn shim_ps_add(pgid: &str) -> String {
        format!(
            "ps() {{\n  if [ \"$1\" = -A ]; then\n    command ps \"$@\"\n    printf '%s\\n' '{pgid}'\n  else\n    command ps \"$@\"\n  fi\n}}\n"
        )
    }

    /// A `ps` whose listing drops the fence shell's own group.
    const SHIM_PS_DROP_OWN: &str = "ps() {\n  if [ \"$1\" = -A ]; then\n    command ps \"$@\" | awk -v t=\"$$\" '{ if ($1 != t) print }'\n  else\n    command ps \"$@\"\n  fi\n}\n";

    /// `kill` and `ps` that print diagnostics (to stderr, which the scripts discard,
    /// and to `seen` so the test knows they ran) but keep their real exit status.
    fn shim_noisy(seen: &str) -> String {
        format!(
            "kill() {{\n  printf '%s\\n' 'kill: bad argument (diagnostic only)' >&2\n  printf 'kill\\n' >> '{seen}'\n  command kill \"$@\"\n}}\nps() {{\n  printf '%s\\n' 'ps: warning: diagnostic only' >&2\n  printf 'ps\\n' >> '{seen}'\n  command ps \"$@\"\n}}\n"
        )
    }

    /// A `kill` that prints an error yet exits 0 for the probe of `pgid` (bash as `sh`
    /// printing argument errors with exit 0).
    fn shim_kill_lies_ok(pgid: &str) -> String {
        format!(
            "kill() {{\n  if [ \"$1\" = -s ] && [ \"$2\" = 0 ] && [ \"$4\" = '-{pgid}' ]; then\n    printf '%s\\n' 'kill: ({pgid}) - No such process' >&2\n    return 0\n  fi\n  command kill \"$@\"\n}}\n"
        )
    }

    /// A holder: an `append` paused at `point`, its lock taken unless the point is
    /// before it. Returns the run, the gate, the token, the PID and the line.
    struct Holder<'t> {
        // The gate is released before the run is dropped (a failing test never waits
        // on a paused script).
        gate: crate::harness::Gate<'t>,
        run: Option<crate::harness::Running>,
        tok: StepToken,
        pid: u32,
        m: Marker,
        l: RegistryLine,
        _pauses: Pauses<'t>,
    }

    fn holder<'t>(t: &'t Target, r: &Reg<'t>, point: &str, na: NotAfter) -> Holder<'t> {
        let p = Pauses::new(t);
        let m = marker();
        let l = line(&m);
        let tok = token();
        let mut gate = p.arm(point);
        let mut run = Some(t.spawn(&p.form(&r.append_script(&m, &l, &tok, na))));
        let pid = gate.wait_on(&mut run);
        Holder {
            gate,
            run,
            tok,
            pid,
            m,
            l,
            _pauses: p,
        }
    }

    impl Holder<'_> {
        fn finish(&mut self) -> Out {
            self.gate.release();
            self.run.take().unwrap().wait()
        }
    }

    fn fence_with(r: &Reg<'_>, prefix: &str, tok: &StepToken, terminate: bool) -> Out {
        let s = r.fence_script(tok, terminate);
        r.t.run(&format!("{prefix}{}", s.text()))
    }

    /// The expected fence outcome on this shell: `(exit, status)` for a case the
    /// group proof decides `want` on an automatic shell; BusyBox is always unproven.
    fn fence_expect(t: &Target, o: &Out, code: i32, status: &str) {
        if t.shell.automatic_recovery() {
            o.expect(code, status);
        } else {
            o.expect(44, "unproven");
            assert_eq!(o.last("fence_signals"), Some(""), "{o}");
            assert_eq!(o.get("group_control"), Some("1"), "{o}");
        }
    }

    // =========================================================================
    // Protocol (registry_protocol_on_target_shell and its sub-rows).
    // =========================================================================

    /// The whole protocol in order on this target: inspect, bootstrap, append,
    /// inspect, remove, inspect; and the remote-home path where `HOME` is scratch.
    pub fn registry_protocol_on_target_shell(t: &Target) {
        let r = t.reg_absent();
        let m = marker();
        let l = line(&m);
        let o = r.inspect(&m);
        o.expect(0, "ok");
        assert_eq!(unhex(o.get("path_hex").unwrap()), r.path.as_bytes());
        assert_eq!(
            (o.get("dir"), o.get("file"), o.get("lock")),
            (Some("absent"), Some("absent"), Some("none"))
        );
        r.bootstrap().expect(0, "created");
        assert_eq!(t.mode(&r.dir), "drwx------");
        let o = r.append(&m, &l, far());
        o.expect(0, "written");
        assert_eq!(o.content(), nl(&l));
        assert_eq!(t.mode(&r.path), "-rw-------");
        let o = r.inspect(&m);
        o.expect(0, "ok");
        assert_eq!(o.get("marker_lines"), Some("1"));
        assert_eq!(o.content(), nl(&l));
        let o = r.remove(&m, far(), &nl(&l), b"");
        o.expect(0, "renamed");
        assert_eq!(o.get("marker_lines"), Some("0"));
        assert_eq!(r.bytes().unwrap(), b"");
        let o = r.inspect(&m);
        o.expect(0, "ok");
        assert_eq!((o.get("size"), o.get("lock")), (Some("0"), Some("none")));
        clean(&r);

        if !t.via_sshd() {
            // The default path: `$HOME/.ssh/authorized_keys`, `HOME` being scratch.
            let loc = t.remote_home();
            let home_reg = format!("{}/.ssh/authorized_keys", t.home);
            let ins = script::inspect(&script::InspectParams {
                registry: loc.clone(),
                marker: m.clone(),
            });
            let o = t.run(ins.text());
            o.expect(0, "ok");
            assert_eq!(unhex(o.get("path_hex").unwrap()), home_reg.as_bytes());
            assert_eq!(o.get("dir"), Some("absent"));
            t.run(
                script::bootstrap(&script::BootstrapParams {
                    registry: loc.clone(),
                })
                .text(),
            )
            .expect(0, "created");
            let app = script::append(&script::AppendParams {
                registry: loc,
                marker: m.clone(),
                line: l.clone(),
                token: token(),
                not_after_remote: far(),
            });
            t.run(app.text()).expect(0, "written");
            assert_eq!(t.get(&home_reg).unwrap(), nl(&l));
        }
    }

    pub fn append_creates_registry_exclusively_mode_0600(t: &Target) {
        let r = t.reg();
        let m = marker();
        let l = line(&m);
        let o = r.append(&m, &l, far());
        o.expect(0, "written");
        assert_eq!(o.get("file"), Some("absent"));
        assert_eq!(t.mode(&r.path), "-rw-------");
        assert_eq!(r.bytes().unwrap(), nl(&l));
        clean(&r);

        // Exclusive: a file that appears between the check and the create is never
        // overwritten (`set -C`); the script refuses and writes nothing.
        let r = t.reg();
        let p = Pauses::new(t);
        let mut g = p.arm("before_write");
        let run = t.spawn(&p.form(&r.append_script(&m, &l, &token(), far())));
        g.wait();
        t.put(&r.path, b"admin created this\n");
        g.release();
        let o = run.wait();
        o.refused("write_failed");
        assert_eq!(r.bytes().unwrap(), b"admin created this\n");
        clean(&r);
    }

    /// The script part: inspect shows the directory absent, append refuses 32 and
    /// creates nothing, bootstrap creates it 0700 (11 on a rerun), then the append
    /// takes the lock and writes. Showing the step in the plan and journaling it is
    /// U5-pure's and U10's.
    pub fn registry_dir_bootstrap_journaled_shown_in_plan_then_locked(t: &Target) {
        let r = t.reg_absent();
        let m = marker();
        let l = line(&m);
        assert_eq!(r.inspect(&m).expect(0, "ok").get("dir"), Some("absent"));
        r.append(&m, &l, far()).expect(32, "dir_absent");
        assert!(!t.exists(&r.dir), "append created the directory");
        let o = r.bootstrap();
        o.expect(0, "created");
        assert_eq!(
            (o.get("dir_mode"), o.get("dir_owner_self")),
            (Some("drwx------"), Some("yes"))
        );
        r.bootstrap().expect(11, "already_present");
        let o = r.append(&m, &l, far());
        o.expect(0, "written");
        assert!(o.get("pgid").is_some());
        assert_eq!(r.bytes().unwrap(), nl(&l));
        clean(&r);
    }

    pub fn missing_registry_dir_is_exit_32_not_busy(t: &Target) {
        let r = t.reg_absent();
        let m = marker();
        let o = r.append(&m, &line(&m), far());
        o.expect(32, "dir_absent");
        assert_eq!(o.get("dir"), Some("absent"));
        assert!(o.get("lock").is_none());
        r.remove(&m, far(), b"x\n", b"").expect(32, "dir_absent");
        assert!(!t.exists(&r.dir));
    }

    pub fn bootstrap_missing_parent_exit_33_refused(t: &Target) {
        let parent = t.path(&format!("missing{}", now()));
        let r = Reg::at(t, &format!("{parent}/.ssh"));
        let o = r.bootstrap();
        o.expect(33, "parent_absent");
        assert_eq!(o.get("dir"), Some("absent"));
        assert!(!t.exists(&parent));
    }

    pub fn bootstrap_refuses_symlink_or_foreign_owner(t: &Target) {
        // The directory is a symlink (to a private directory).
        let real = t.path("real");
        t.mkdir(&real, "700");
        let pa = t.path("pa");
        t.mkdir(&pa, "700");
        t.sh_ok("ln -s \"$1\" \"$2\"", &[&real, &format!("{pa}/.ssh")]);
        Reg::at(t, &format!("{pa}/.ssh"))
            .bootstrap()
            .refused("dir_symlink");
        // The parent is a symlink.
        let pb = t.path("pb");
        t.sh_ok("ln -s \"$1\" \"$2\"", &[&real, &pb]);
        Reg::at(t, &format!("{pb}/.ssh"))
            .bootstrap()
            .refused("parent_symlink");
        assert!(!t.exists(&format!("{real}/.ssh")));
        // A parent writable by others.
        for mode in ["770", "703"] {
            let pc = t.path(&format!("pc{mode}"));
            t.mkdir(&pc, "700");
            t.chmod(mode, &pc);
            Reg::at(t, &format!("{pc}/.ssh"))
                .bootstrap()
                .refused("parent_writable_by_others");
            assert!(!t.exists(&format!("{pc}/.ssh")));
        }
        // An existing directory that is not private.
        let pd = t.path("pd");
        t.mkdir(&pd, "700");
        t.mkdir(&format!("{pd}/.ssh"), "755");
        Reg::at(t, &format!("{pd}/.ssh"))
            .bootstrap()
            .refused("dir_not_private");
        if t.has_root() {
            // Other accounts' directories (made by those accounts through `docker exec
            // -u`, so no capability is needed). The scratch root is opened meanwhile.
            t.chmod("777", &t.root);
            // A parent owned by another (non-root) account.
            let pe = t.path("pe");
            t.as_ok("2000:2000", "mkdir -m 755 \"$1\"", &[&pe]);
            Reg::at(t, &format!("{pe}/.ssh"))
                .bootstrap()
                .refused("parent_owner_foreign");
            // A directory owned by root.
            let pf = t.path("pf");
            t.mkdir(&pf, "777");
            t.as_ok("0", "mkdir -m 700 \"$1/.ssh\"", &[&pf]);
            t.chmod("700", &pf);
            let o = Reg::at(t, &format!("{pf}/.ssh")).bootstrap();
            o.refused("dir_owner_foreign");
            assert_eq!(o.get("dir_owner_self"), Some("no"));
            // A root-owned parent is allowed (`/home`).
            let pg = t.path("pg");
            t.as_ok("0", "mkdir -m 777 \"$1\"", &[&pg]);
            t.mkdir(&format!("{pg}/u"), "755");
            t.as_ok("0", "chmod 755 \"$1\"", &[&pg]);
            t.chmod("700", &t.root);
            Reg::at(t, &format!("{pg}/u/.ssh"))
                .bootstrap()
                .expect(0, "created");
        }
    }

    pub fn append_newline_decided_at_append_time(t: &Target) {
        let m = marker();
        let l = line(&m);
        // No final newline: one is written first, in the same append.
        let r = t.reg();
        r.seed(b"x");
        r.append(&m, &l, far()).expect(0, "written");
        assert_eq!(r.bytes().unwrap(), [b"x\n", &nl(&l)[..]].concat());
        // Decided at append time, not from an earlier inspect: the newline the
        // inspect did not see is not doubled, and one the inspect saw but that is gone
        // is written.
        let r = t.reg();
        r.seed(b"y");
        assert_eq!(r.inspect(&m).get("last_byte_newline"), Some("no"));
        t.put(&r.path, b"y\n");
        r.append(&m, &l, far()).expect(0, "written");
        assert_eq!(r.bytes().unwrap(), [b"y\n", &nl(&l)[..]].concat());
        let r = t.reg();
        r.seed(b"z\n");
        assert_eq!(r.inspect(&m).get("last_byte_newline"), Some("yes"));
        t.put(&r.path, b"z");
        r.append(&m, &l, far()).expect(0, "written");
        assert_eq!(r.bytes().unwrap(), [b"z\n", &nl(&l)[..]].concat());
        // Inside the lock window: the newline is read at the write, after the lock.
        let r = t.reg();
        r.seed(b"w\n");
        let p = Pauses::new(t);
        let mut g = p.arm("after_lock");
        let run = t.spawn(&p.form(&r.append_script(&m, &l, &token(), far())));
        g.wait();
        t.put(&r.path, b"w");
        g.release();
        run.wait().expect(0, "written");
        assert_eq!(r.bytes().unwrap(), [b"w\n", &nl(&l)[..]].concat());
    }

    pub fn append_idempotent_by_marker_exit_10(t: &Target) {
        let m = marker();
        let l = line(&m);
        let r = t.reg();
        r.seed(b"# a\n");
        r.append(&m, &l, far()).expect(0, "written");
        let after = r.bytes().unwrap();
        let o = r.append(&m, &l, far());
        o.expect(10, "already_present");
        assert_eq!(o.get("marker_lines"), Some("1"));
        assert_eq!(o.content(), after);
        assert_eq!(r.bytes().unwrap(), after);
        clean(&r);
        // Any line containing the marker stops it, even a damaged one.
        let r = t.reg();
        let damaged = format!("garbage {}\n", m.as_str());
        r.seed(damaged.as_bytes());
        r.append(&m, &l, far()).expect(10, "already_present");
        assert_eq!(r.bytes().unwrap(), damaged.as_bytes());
        clean(&r);
    }

    pub fn inspect_reports_metadata_and_content(t: &Target) {
        let m = marker();
        let l = line(&m);
        let r = t.reg();
        let seed = [b"# admin\n", &nl(&l)[..], b"tail-without-newline"].concat();
        r.seed(&seed);
        t.chmod("640", &r.path);
        let before = now();
        let o = r.inspect(&m);
        o.expect(0, "ok");
        assert_eq!(unhex(o.get("path_hex").unwrap()), r.path.as_bytes());
        let want = [
            ("dir", "present"),
            ("dir_mode", "drwx------"),
            ("dir_owner_self", "yes"),
            ("file", "regular"),
            ("links", "1"),
            ("mode", "-rw-r-----"),
            ("owner_self", "yes"),
            ("last_byte_newline", "no"),
            ("marker_lines", "1"),
            ("lock", "none"),
        ];
        for (k, v) in want {
            assert_eq!(o.get(k), Some(v), "{k}: {o}");
        }
        assert_eq!(o.get("size"), Some(seed.len().to_string().as_str()));
        assert_eq!(o.content(), seed);
        let remote: i64 = o.get("remote_now").unwrap().parse().unwrap();
        assert!(
            (remote - before).abs() <= 30,
            "remote_now {remote} vs {before}"
        );
        // A held lock: its holder record.
        let rec = record(&token(), 4242, "3132", "6162", now() + 60);
        r.plant_lock(&rec);
        let o = r.inspect(&m);
        o.expect(0, "ok");
        assert_eq!(
            (o.get("lock"), o.get("lock_holder")),
            (Some("held"), Some(rec.as_str()))
        );
        // A lock that is not a holder record: held, without a holder.
        t.sh_ok(
            "rm -f \"$1\" && ln -s 'not a record' \"$1\"",
            &[&r.lock_path()],
        );
        let o = r.inspect(&m);
        assert_eq!((o.get("lock"), o.get("lock_holder")), (Some("held"), None));
        // An empty registry.
        let r = t.reg();
        r.seed(b"");
        let o = r.inspect(&m);
        assert_eq!(
            (
                o.get("size"),
                o.get("last_byte_newline"),
                o.get("marker_lines")
            ),
            (Some("0"), Some("no"), Some("0"))
        );
        assert_eq!(o.content(), b"");
    }

    pub fn remove_compare_then_rename_preserves_unrelated_bytes(t: &Target) {
        let m = marker();
        let l = line(&m);
        let r = t.reg();
        let a: &[u8] = b"\xef\xbb\xbf# BOM, comment, CRLF\r\ncommand=\"/bin/echo x\",no-pty ssh-ed25519 AAAAunrelated1 one\r\n\n";
        let b: &[u8] = b"from=\"192.0.2.0/24\" ssh-ed25519 AAAAunrelated2 two\ncert-authority,principals=\"ops\" ssh-ed25519 AAAAunrelated3\n# caf\xc3\xa9 \xff\xfe raw\nlast-line-without-newline";
        let near = format!(
            "{} heimdall:enr_neardup\n",
            l.as_str().strip_suffix(m.as_str()).unwrap().trim_end()
        );
        let pre = [a, &nl(&l)[..], near.as_bytes(), b].concat();
        let post = [a, near.as_bytes(), b].concat();
        r.seed(&pre);
        t.chmod("644", &r.path);
        // A stale preimage: exit 20, nothing renamed.
        r.remove(&m, far(), b"stale\n", &post)
            .expect(20, "changed_since_read");
        assert_eq!(r.bytes().unwrap(), pre);
        clean(&r);
        // The inspected preimage: renamed; every other byte and the mode preserved.
        let o = r.remove(&m, far(), &pre, &post);
        o.expect(0, "renamed");
        assert_eq!(o.content(), post);
        assert_eq!(r.bytes().unwrap(), post);
        assert_eq!(t.mode(&r.path), "-rw-r--r--");
        clean(&r);
    }

    pub fn remote_clock_reading_per_target(t: &Target) {
        let r = t.reg();
        let before = now();
        let o = r.inspect(&marker());
        let after = now();
        let remote: i64 = o.get("remote_now").unwrap().parse().unwrap();
        // Containers share the host kernel's clock (through Docker's VM on macOS).
        assert!(
            remote >= before - 10 && remote <= after + 10,
            "remote_now {remote} outside [{before}, {after}] ± 10 s"
        );
        let srand = t.sh_ok("awk 'BEGIN { srand(); print srand() }'", &[]);
        eprintln!(
            "remote_clock_reading_per_target: shell={:?} remote_now={remote} local=[{before},{after}] awk_srand_raw={} (M-F23 reading; U5S-Q1)",
            t.shell,
            srand.trim()
        );
    }

    pub fn lock_symlink_is_exclusive_per_target(t: &Target) {
        let r = t.reg();
        r.seed(b"# base\n");
        let (m1, m2) = (marker(), marker());
        let (p1, p2) = (Pauses::new(t), Pauses::new(t));
        let (mut g1, mut held, mut g2) = (
            p1.arm("before_ln"),
            p1.arm("after_lock"),
            p2.arm("before_ln"),
        );
        let a = t.spawn(&p1.form(&r.append_script(&m1, &line(&m1), &token(), far())));
        g1.wait();
        let b = t.spawn(&p2.form(&r.append_script(&m2, &line(&m2), &token(), far())));
        g2.wait();
        // Both passed the "no lock" check. The first `ln -s` takes the lock and holds
        // it; the second `ln -s` then fails on the existing link.
        g1.release();
        held.wait();
        let rec = r.lock().unwrap();
        g2.release();
        let ob = b.wait();
        ob.expect(40, "busy");
        assert_eq!(ob.get("lock_holder"), Some(rec.as_str()), "{ob}");
        held.release();
        a.wait().expect(0, "written");
        let bytes = r.bytes().unwrap();
        assert_eq!(
            (count(&bytes, m1.as_str()), count(&bytes, m2.as_str())),
            (1, 0)
        );
        clean(&r);
        // An existing lock: 40, nothing written, the lock untouched.
        let rec = record(&token(), 1, "30", "30", 1);
        r.plant_lock(&rec);
        let m3 = marker();
        r.append(&m3, &line(&m3), far()).expect(40, "busy");
        assert_eq!(r.lock().as_deref(), Some(rec.as_str()));
        assert_eq!(r.bytes().unwrap(), bytes);
        // A directory at the lock name: 30, nothing created inside it.
        t.sh_ok("rm -f \"$1\" && mkdir \"$1\"", &[&r.lock_path()]);
        r.append(&m3, &line(&m3), far())
            .refused("lock_is_directory");
        assert!(t.names(&r.lock_path()).is_empty());
        assert_eq!(r.bytes().unwrap(), bytes);
    }

    pub fn start_identity_per_target_shell(t: &Target) {
        let r = t.reg();
        let mut h = holder(t, &r, "after_lock", far());
        let rec = r.lock().unwrap();
        let parts = rec_parts(&rec);
        assert_eq!(parts.len(), 6, "{rec}");
        assert_eq!(
            parts[2],
            h.pid.to_string(),
            "the record's PID is the holder shell"
        );
        // Read independently while the holder is alive.
        let (start, boot) = t.identity_of(h.pid);
        assert_eq!(parts[3], start, "start identity");
        assert_eq!(parts[4], boot, "boot identity");
        let o = h.finish();
        o.expect(0, "written");
        assert_eq!(o.get("start_identity"), Some(start.as_str()));
        assert_eq!(o.get("boot_identity"), Some(boot.as_str()));
        assert_eq!(o.get("pgid"), Some(h.pid.to_string().as_str()));
        let start_text = String::from_utf8(unhex(&start)).unwrap();
        let boot_text = String::from_utf8(unhex(&boot)).unwrap();
        if t.is_linux() {
            assert!(
                start_text.bytes().all(|b| b.is_ascii_digit()),
                "{start_text:?}"
            );
            assert_eq!(boot_text.len(), 36, "boot_id {boot_text:?}");
        } else {
            // `ps -o lstart=`, blanks collapsed: `Tue Nov 10 11:03:36 2026`.
            assert_eq!(start_text.split(' ').count(), 5, "lstart {start_text:?}");
            if cfg!(target_os = "macos") {
                // ADR-0008 §17.17 item 2: `kern.bootsessionuuid`, a UUID that a clock
                // step does not move (never the `kern.boottime` timestamp).
                assert_eq!(boot_text.len(), 36, "bootsessionuuid {boot_text:?}");
                assert_eq!(boot_text.matches('-').count(), 4, "{boot_text:?}");
                assert!(!boot_text.contains("sec ="), "{boot_text:?}");
            } else {
                assert!(
                    boot_text.starts_with("{ sec = ") && boot_text.ends_with('}'),
                    "{boot_text:?}"
                );
            }
        }
        eprintln!(
            "start_identity_per_target_shell: shell={:?} start={start_text:?} ({}) boot={boot_text:?} ({})",
            t.shell,
            if t.is_linux() {
                "token 20 after the last ')' of /proc/$$/stat, clock ticks since boot"
            } else {
                "ps -o lstart= -p $$, 1 s resolution, TZ=UTC0"
            },
            if t.is_linux() {
                "/proc/sys/kernel/random/boot_id"
            } else if cfg!(target_os = "macos") {
                "sysctl -n kern.bootsessionuuid"
            } else {
                "sysctl -n kern.boottime, up to the first '}'"
            }
        );
    }

    pub fn holder_is_process_group_leader_per_target(t: &Target) {
        // As the session's (or setsid's) group leader: the holder record's PID is the
        // script's own group.
        let r = t.reg();
        let mut h = holder(t, &r, "after_lock", far());
        let rec = rec_parts(&r.lock().unwrap());
        assert_eq!(rec[2], h.pid.to_string());
        let o = h.finish();
        o.expect(0, "written");
        assert_eq!(o.get("pgid"), Some(h.pid.to_string().as_str()));
        if t.via_sshd() {
            return;
        }
        // Not a group leader: exit 33 before the lock, nothing written (where the run
        // really is not one).
        let probe = format!(
            "awk '{}' /proc/$$/stat 2>/dev/null || ps -o pgid= -p $$; echo \"pid=$$\"\n",
            script::PROCSTAT_AWK
        );
        let p = t.spawn_not_leader_raw(&probe).wait();
        let text = String::from_utf8_lossy(&p.stdout).into_owned();
        let pid = text
            .lines()
            .find_map(|l| l.strip_prefix("pid="))
            .unwrap()
            .to_owned();
        let pgid = text.split_whitespace().next().unwrap().to_owned();
        let leads = pgid == pid;
        let r = t.reg();
        let m = marker();
        let script = r.append_script(&m, &line(&m), &token(), far());
        let o = t.spawn_not_leader(script.text()).wait();
        if leads {
            eprintln!(
                "holder_is_process_group_leader_per_target: shell={:?}: this runner's shell leads its group without setsid",
                t.shell
            );
            o.expect(0, "written");
        } else {
            o.expect(33, "no_process_group");
            assert!(r.bytes().is_none());
            clean(&r);
        }
    }

    pub fn non_ascii_registry_bytes_per_target_shell(t: &Target) {
        let m = marker();
        let l = line(&m);
        let every: Vec<u8> = (1u8..=255).collect();
        let seed = [b"# every byte but NUL follows\n", &every[..], b"\n"].concat();
        let r = t.reg();
        r.seed(&seed);
        let o = r.inspect(&m);
        o.expect(0, "ok");
        assert_eq!(o.content(), seed);
        let o = r.append(&m, &l, far());
        o.expect(0, "written");
        let with = [&seed[..], &nl(&l)].concat();
        assert_eq!(o.content(), with);
        let o = r.remove(&m, far(), &with, &seed);
        o.expect(0, "renamed");
        assert_eq!(r.bytes().unwrap(), seed, "awk printf %c under LC_ALL=C");
        // A NUL in the preimage refuses; nothing renamed.
        r.remove(&m, far(), b"a\0b\n", b"").refused("decode_failed");
        assert_eq!(r.bytes().unwrap(), seed);
        clean(&r);
    }

    // =========================================================================
    // Negative.
    // =========================================================================

    pub fn symlinked_registry_refused(t: &Target) {
        let m = marker();
        let r = t.reg();
        let real = format!("{}/real", r.dir);
        t.put(&real, b"# real\n");
        t.sh_ok("ln -s real \"$1\"", &[&r.path]);
        let o = r.inspect(&m);
        o.refused("registry_symlink");
        assert_eq!(o.get("file"), Some("symlink"));
        assert!(o.get("content_hex").is_none());
        r.append(&m, &line(&m), far()).refused("registry_symlink");
        r.remove(&m, far(), b"# real\n", b"")
            .refused("registry_symlink");
        assert_eq!(t.get(&real).unwrap(), b"# real\n");
        assert_eq!(t.link(&r.path).as_deref(), Some("real"));
        clean(&r);
    }

    pub fn hardlinked_registry_refused(t: &Target) {
        let m = marker();
        let r = t.reg();
        r.seed(b"# linked\n");
        t.sh_ok("ln \"$1\" \"$1.second\"", &[&r.path]);
        let o = r.inspect(&m);
        o.refused("registry_hardlinked");
        assert_eq!(o.get("links"), Some("2"));
        assert_eq!(o.content(), b"# linked\n");
        r.append(&m, &line(&m), far())
            .refused("registry_hardlinked");
        r.remove(&m, far(), b"# linked\n", b"")
            .refused("registry_hardlinked");
        assert_eq!(r.bytes().unwrap(), b"# linked\n");
        clean(&r);
    }

    pub fn acl_indicator_refused(t: &Target) {
        let m = marker();
        let r = t.reg();
        r.seed(b"# acl\n");
        if t.is_linux() {
            t.sh_ok("setfacl -m u:2000:r \"$1\"", &[&r.path]);
        } else {
            t.sh_ok("chmod +a 'everyone deny delete' \"$1\"", &[&r.path]);
        }
        let mode = t.mode(&r.path);
        assert!(mode.ends_with('+'), "no ACL indicator: {mode}");
        let o = r.inspect(&m);
        o.refused("registry_acl_or_label");
        assert_eq!(o.get("mode"), Some(mode.as_str()));
        r.append(&m, &line(&m), far())
            .refused("registry_acl_or_label");
        r.remove(&m, far(), b"# acl\n", b"")
            .refused("registry_acl_or_label");
        assert_eq!(r.bytes().unwrap(), b"# acl\n");
        clean(&r);
        // Drop the ACL, so the scratch can be removed ("deny delete" binds the owner).
        if !t.is_linux() {
            t.sh_ok("chmod -N \"$1\"", &[&r.path]);
        }
    }

    pub fn foreign_owned_registry_refused(t: &Target) {
        assert!(
            t.has_root(),
            "a root-owned file needs the container's root account"
        );
        let m = marker();
        let r = t.reg();
        // Root writes it (through `docker exec -u 0`) into the account's directory.
        t.chmod("777", &t.root);
        t.chmod("777", &r.dir);
        t.as_ok(
            "0",
            "printf '# root\\047s\\n' > \"$1\" && chmod 644 \"$1\"",
            &[&r.path],
        );
        t.chmod("700", &r.dir);
        t.chmod("700", &t.root);
        let o = r.inspect(&m);
        o.refused("registry_owner_foreign");
        assert_eq!(o.get("owner_self"), Some("no"));
        r.append(&m, &line(&m), far())
            .refused("registry_owner_foreign");
        r.remove(&m, far(), b"# root's\n", b"")
            .refused("registry_owner_foreign");
        assert_eq!(r.bytes().unwrap(), b"# root's\n");
        clean(&r);
    }

    pub fn group_writable_dir_refused(t: &Target) {
        let m = marker();
        for mode in ["770", "703"] {
            let r = t.reg();
            r.seed(b"# dir\n");
            t.chmod(mode, &r.dir);
            r.inspect(&m).refused("dir_writable_by_others");
            r.append(&m, &line(&m), far())
                .refused("dir_writable_by_others");
            r.remove(&m, far(), b"# dir\n", b"")
                .refused("dir_writable_by_others");
            assert_eq!(r.bytes().unwrap(), b"# dir\n");
            clean(&r);
            t.chmod("700", &r.dir);
        }
    }

    pub fn registry_too_large_refused(t: &Target) {
        let m = marker();
        let r = t.reg();
        let big = vec![b'#'; 131_073];
        r.seed(&big);
        let o = r.inspect(&m);
        o.expect(31, "too_large");
        assert!(o.get("content_hex").is_none());
        r.append(&m, &line(&m), far()).expect(31, "too_large");
        r.remove(&m, far(), b"x", b"").expect(31, "too_large");
        assert_eq!(r.bytes().unwrap().len(), 131_073);
        clean(&r);
        let r = t.reg();
        let max = vec![b'#'; 131_072];
        r.seed(&max);
        assert_eq!(r.inspect(&m).expect(0, "ok").content().len(), 131_072);
    }

    /// The script part: every script's first output line is `HM1 v=1`, so anything
    /// printed before it (a noisy login) is not the script's, and a non-POSIX shell
    /// prints no `HM1 v=1` and writes nothing. That no script is sent before `HM1
    /// ready` is the step runner's (U5-io, `SshStepRunner`); the sshd row here sends
    /// only after reading the ready line.
    pub fn non_posix_or_noisy_login_refused_as_registry_unsupported(t: &Target) {
        let m = marker();
        let l = line(&m);
        let r = t.reg();
        r.seed(b"# base\n");
        let tok = token();
        let scripts = [
            r.inspect_script(&m),
            r.bootstrap_script(),
            r.append_script(&m, &l, &tok, far()),
            r.remove_script(&m, &token(), far(), b"other\n", b""),
            r.fence_script(&tok, false),
        ];
        for s in &scripts {
            let o = t.run(s.text());
            assert!(o.stdout.starts_with(b"HM1 v=1\n"), "{o}");
        }
        assert_eq!(r.bytes().unwrap(), [b"# base\n", &nl(&l)[..]].concat());
        if matches!(t.runner, Runner::Direct) && std::path::Path::new("/bin/csh").exists() {
            let r = t.reg();
            r.seed(b"# base\n");
            let s = r.append_script(&m, &l, &token(), far());
            let mut child = Command::new("/bin/csh")
                .arg("-s")
                .env_clear()
                .env("PATH", NATIVE_PATH)
                .env("HOME", &t.home)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            {
                use std::io::Write;
                let mut w = child.stdin.take().unwrap();
                let _ = w.write_all(s.text().as_bytes());
            }
            let out = child.wait_with_output().unwrap();
            assert!(
                !String::from_utf8_lossy(&out.stdout).contains("HM1 v=1"),
                "csh ran the script"
            );
            assert_eq!(r.bytes().unwrap(), b"# base\n");
            clean(&r);
        }
    }

    // =========================================================================
    // Interleaving (pause hooks).
    // =========================================================================

    pub fn admin_append_between_inspect_and_append_preserved(t: &Target) {
        let m = marker();
        let l = line(&m);
        let r = t.reg();
        r.seed(b"# base\n");
        let pre = r.inspect(&m).content();
        t.sh_ok("printf 'admin-line\\n' >> \"$1\"", &[&r.path]);
        let o = r.append(&m, &l, far());
        o.expect(0, "written");
        let post = o.content();
        assert_eq!(post, [&pre[..], b"admin-line\n", &nl(&l)].concat());
        // The post-write rule: one marker line equal to ours, and the rest starts with
        // the preimage.
        assert_eq!(marker_lines(&post, &m), [l.as_str().as_bytes().to_vec()]);
        assert!(without_line(&post, &l).starts_with(&pre));
    }

    pub fn admin_append_without_newline_in_append_window_detected_damaged(t: &Target) {
        let m = marker();
        let l = line(&m);
        let r = t.reg();
        r.seed(b"# base\n");
        let p = Pauses::new(t);
        let mut g = p.arm("before_write");
        let run = t.spawn(&p.form(&r.append_script(&m, &l, &token(), far())));
        g.wait();
        // After the newline decision and before the write.
        t.sh_ok("printf 'admin-partial' >> \"$1\"", &[&r.path]);
        g.release();
        let o = run.wait();
        o.expect(0, "written");
        let post = o.content();
        let lines = marker_lines(&post, &m);
        assert_eq!(lines.len(), 1, "{o}");
        assert_ne!(lines[0], l.as_str().as_bytes(), "the join must be visible");
        assert_eq!(
            lines[0],
            [b"admin-partial", l.as_str().as_bytes()].concat(),
            "the administrator's line joined ours: the post-write check reads damage"
        );
    }

    pub fn admin_edit_before_final_check_remove_restarts(t: &Target) {
        let m = marker();
        let l = line(&m);
        let r = t.reg();
        let pre = [b"# base\n", &nl(&l)[..], b"# tail\n"].concat();
        let post = without_line(&pre, &l);
        r.seed(&pre);
        let p = Pauses::new(t);
        let mut g = p.arm("after_lock");
        let run = t.spawn(&p.form(&r.remove_script(&m, &token(), far(), &pre, &post)));
        g.wait();
        t.sh_ok("printf 'admin-edit\\n' >> \"$1\"", &[&r.path]);
        g.release();
        run.wait().expect(20, "changed_since_read");
        let edited = [&pre[..], b"admin-edit\n"].concat();
        assert_eq!(r.bytes().unwrap(), edited);
        clean(&r);
        // Start again from inspect: the edit is kept.
        let pre2 = r.inspect(&m).content();
        let post2 = without_line(&pre2, &l);
        r.remove(&m, far(), &pre2, &post2).expect(0, "renamed");
        assert_eq!(r.bytes().unwrap(), post2);
        assert!(count(&post2, "admin-edit") == 1 && count(&post2, m.as_str()) == 0);
        clean(&r);
    }

    /// The script part: three compare failures in a row each exit 20 and rename
    /// nothing. Turning the third into `CONFIG_CONFLICT registry_changed` and `held`
    /// is the runtime's (U10, with U5-pure's classification).
    pub fn three_compare_failures_give_registry_changed(t: &Target) {
        let m = marker();
        let l = line(&m);
        let r = t.reg();
        r.seed(&[b"# base\n", &nl(&l)[..]].concat());
        for attempt in 1..=3 {
            let pre = r.inspect(&m).content();
            let post = without_line(&pre, &l);
            let p = Pauses::new(t);
            let mut g = p.arm("after_lock");
            let run = t.spawn(&p.form(&r.remove_script(&m, &token(), far(), &pre, &post)));
            g.wait();
            t.sh_ok(
                "printf 'edit-%s\\n' \"$2\" >> \"$1\"",
                &[&r.path, &attempt.to_string()],
            );
            g.release();
            run.wait().expect(20, "changed_since_read");
            clean(&r);
        }
        let now_bytes = r.bytes().unwrap();
        assert_eq!(marker_lines(&now_bytes, &m).len(), 1, "nothing renamed");
        assert_eq!(count(&now_bytes, "edit-"), 3);
    }

    pub fn rotation_add_preserves_admin_edit(t: &Target) {
        let (ma, mb) = (marker(), marker());
        let (la, lb) = (line(&ma), line(&mb));
        let r = t.reg();
        r.seed(&[b"# base\n", &nl(&la)[..]].concat());
        // The rotation's add, with an administrator edit inside its lock window.
        let p = Pauses::new(t);
        let mut g = p.arm("after_lock");
        let run = t.spawn(&p.form(&r.append_script(&mb, &lb, &token(), far())));
        g.wait();
        t.sh_ok("printf 'admin-edit\\n' >> \"$1\"", &[&r.path]);
        g.release();
        run.wait().expect(0, "written");
        let both = [b"# base\n", &nl(&la)[..], b"admin-edit\n", &nl(&lb)].concat();
        assert_eq!(r.bytes().unwrap(), both);
        // Then the old line's removal keeps the edit and the new line.
        let pre = r.inspect(&ma).content();
        let post = without_line(&pre, &la);
        r.remove(&ma, far(), &pre, &post).expect(0, "renamed");
        assert_eq!(
            r.bytes().unwrap(),
            [&b"# base\n"[..], b"admin-edit\n", &nl(&lb)].concat()
        );
        clean(&r);
    }

    /// **The disclosed limitation** (ADR-0008 D5 §6.3 "Disclosed windows"): an
    /// administrator write between `remove`'s compare and its rename is lost and
    /// cannot be detected afterwards. This asserts the loss as it is; it is never a
    /// pass of a preservation property.
    pub fn admin_edit_inside_remove_window_is_lost(t: &Target) {
        let m = marker();
        let l = line(&m);
        let r = t.reg();
        let pre = [b"# base\n", &nl(&l)[..]].concat();
        let post = without_line(&pre, &l);
        r.seed(&pre);
        let p = Pauses::new(t);
        let mut g = p.arm("before_write");
        let run = t.spawn(&p.form(&r.remove_script(&m, &token(), far(), &pre, &post)));
        g.wait();
        t.sh_ok("printf 'admin-lost\\n' >> \"$1\"", &[&r.path]);
        g.release();
        run.wait().expect(0, "renamed");
        let after = r.bytes().unwrap();
        assert_eq!(after, post);
        assert_eq!(
            count(&after, "admin-lost"),
            0,
            "LIMITATION: the administrator's write is lost"
        );
        eprintln!(
            "admin_edit_inside_remove_window_is_lost: shell={:?}: DISCLOSED LIMITATION reproduced (the write between cmp and mv is lost)",
            t.shell
        );
    }

    // =========================================================================
    // Fencing.
    // =========================================================================

    pub fn busy_lock_changes_nothing_exit_40(t: &Target) {
        let m = marker();
        let r = t.reg();
        r.seed(b"# base\n");
        let rec = record(&token(), 4242, "31", &t.boot_hex(), now() + 600);
        r.plant_lock(&rec);
        let o = r.append(&m, &line(&m), far());
        o.expect(40, "busy");
        assert_eq!(o.get("lock_holder"), Some(rec.as_str()));
        r.remove(&m, far(), b"# base\n", b"").expect(40, "busy");
        assert_eq!(r.bytes().unwrap(), b"# base\n");
        assert_eq!(r.lock().as_deref(), Some(rec.as_str()));
    }

    pub fn not_after_passed_changes_nothing_exit_41(t: &Target) {
        let m = marker();
        let l = line(&m);
        let r = t.reg();
        r.seed(b"# base\n");
        let past = NotAfter::new(now() - 10).unwrap();
        r.append(&m, &l, past).expect(41, "not_after_passed");
        r.remove(&m, past, b"# base\n", b"")
            .expect(41, "not_after_passed");
        assert!(r.lock().is_none());
        // Passing inside the lock window: the re-check before the write refuses, and
        // the lock is released.
        let na = soon(3);
        let mut h = holder(t, &r, "after_lock", na);
        assert!(r.lock().is_some());
        wait_past(na);
        h.finish().expect(41, "not_after_passed");
        assert_eq!(r.bytes().unwrap(), b"# base\n");
        clean(&r);
    }

    pub fn lock_lost_changes_nothing_exit_42(t: &Target) {
        let r = t.reg();
        r.seed(b"# base\n");
        let mut h = holder(t, &r, "after_lock", far());
        let other = record(&token(), 7, "37", &t.boot_hex(), now() + 600);
        t.sh_ok(
            "rm -f \"$1\" && ln -s \"$2\" \"$1\"",
            &[&r.lock_path(), &other],
        );
        h.finish().expect(42, "lock_lost");
        assert_eq!(r.bytes().unwrap(), b"# base\n");
        assert_eq!(
            r.lock().as_deref(),
            Some(other.as_str()),
            "another's lock untouched"
        );
    }

    pub fn lock_records_holder_pid_start_and_boot_identity(t: &Target) {
        let r = t.reg();
        let na = soon(600);
        let mut h = holder(t, &r, "after_lock", na);
        let rec = r.lock().unwrap();
        let parts = rec_parts(&rec);
        let (start, boot) = t.identity_of(h.pid);
        assert_eq!(
            parts,
            [
                "hm1".to_owned(),
                h.tok.as_str().to_owned(),
                h.pid.to_string(),
                start,
                boot,
                na.seconds().to_string()
            ]
        );
        h.finish().expect(0, "written");
        assert!(r.lock().is_none(), "released by its owning contents");
    }

    /// The script part (ADR-0008 D5 §6.7): the first script is paused after taking
    /// its lock and its step "times out" (nothing reads its result). Reconcile's
    /// `fence` sees it alive, after the not-after terminates it, proves it gone, and
    /// the redispatch writes the one line. The runtime's reconcile driving these
    /// steps is U10's.
    pub fn first_script_survives_timeout_resumes_after_reconcile_no_duplicate_no_loss(t: &Target) {
        let r = t.reg();
        r.seed(b"# base\n");
        let na = soon(3);
        let mut h = holder(t, &r, "after_lock", na);
        let o = r.inspect(&h.m);
        assert_eq!(o.get("lock"), Some("held"));
        assert_eq!(rec_parts(o.get("lock_holder").unwrap())[1], h.tok.as_str());
        let o = r.fence(&h.tok, false);
        fence_expect(t, &o, 43, "alive");
        wait_past(na);
        let o = r.fence(&h.tok, true);
        if !t.shell.automatic_recovery() {
            fence_expect(t, &o, 0, "gone");
            assert!(r.lock().is_some(), "never unlocked on BusyBox");
            let m2 = marker();
            r.append(&m2, &line(&m2), far()).expect(40, "busy");
            t.kill_group("KILL", h.pid);
            let _ = h.finish();
            return;
        }
        o.expect(0, "gone");
        assert_eq!(o.last("fence_signals"), Some("TERM"));
        assert!(r.lock().is_none());
        let first = h.finish();
        assert_ne!(
            first.code,
            Some(0),
            "the first script never resumes: {first}"
        );
        r.append(&h.m, &h.l, far()).expect(0, "written");
        assert_eq!(r.bytes().unwrap(), [b"# base\n", &nl(&h.l)[..]].concat());
    }

    pub fn writer_paused_just_before_write_no_duplicate_no_loss(t: &Target) {
        let r = t.reg();
        r.seed(b"# base\n");
        let na = soon(3);
        let mut h = holder(t, &r, "before_write", na);
        assert!(t.kill_group("STOP", h.pid));
        let o = r.fence(&h.tok, false);
        fence_expect(t, &o, 43, "alive");
        wait_past(na);
        let o = r.fence(&h.tok, true);
        fence_expect(t, &o, 0, "gone");
        if !t.shell.automatic_recovery() {
            assert!(r.lock().is_some());
            t.kill_group("KILL", h.pid);
            let _ = h.finish();
            assert_eq!(r.bytes().unwrap(), b"# base\n");
            return;
        }
        assert_eq!(o.last("fence_signals"), Some("TERM,KILL"), "{o}");
        assert!(r.lock().is_none());
        assert!(!t.group_has_members(h.pid));
        let first = h.finish();
        assert!(killed(&first), "the stopped writer was killed: {first}");
        r.append(&h.m, &h.l, far()).expect(0, "written");
        assert_eq!(r.bytes().unwrap(), [b"# base\n", &nl(&h.l)[..]].concat());
        clean(&r);
    }

    pub fn stale_lock_broken_only_after_holder_proven_gone(t: &Target) {
        let r = t.reg();
        r.seed(b"# base\n");
        let mut h = holder(t, &r, "after_lock", far());
        // Alive: never broken, however old.
        let o = r.fence(&h.tok, false);
        fence_expect(t, &o, 43, "alive");
        assert!(r.lock().is_some());
        // The holder's whole group dies (a crash): the lock is stale.
        t.kill_group("KILL", h.pid);
        let _ = h.finish();
        t.wait_until("the holder group to empty", 10, || {
            !t.group_has_members(h.pid)
        });
        let o = r.fence(&h.tok, false);
        fence_expect(t, &o, 0, "gone");
        if t.shell.automatic_recovery() {
            assert_eq!(o.last("fence_signals"), Some(""));
            assert_eq!(o.last("group_listed"), Some("no"));
            assert!(r.lock().is_none());
            r.inspect(&h.m).expect(0, "ok");
        } else {
            assert!(r.lock().is_some());
        }
    }

    pub fn holder_alive_past_not_after_terminated_term_then_kill_then_proven_gone(t: &Target) {
        // A holder that ends on TERM.
        let r = t.reg();
        let na = soon(3);
        let mut h = holder(t, &r, "after_lock", na);
        wait_past(na);
        let o = r.fence(&h.tok, true);
        fence_expect(t, &o, 0, "gone");
        if !t.shell.automatic_recovery() {
            t.kill_group("KILL", h.pid);
            let _ = h.finish();
            return;
        }
        assert_eq!(o.last("fence_signals"), Some("TERM"));
        assert_eq!(o.all("fence").first().copied(), Some("alive"));
        let _ = h.finish();
        assert!(r.lock().is_none());
        // A holder that survives TERM (its shell stopped, its child not): the decision
        // is re-made, then KILL, then proven gone.
        let r = t.reg();
        let na = soon(3);
        let mut h = holder(t, &r, "after_lock", na);
        assert!(t.kill_pid("STOP", h.pid));
        wait_past(na);
        let o = r.fence(&h.tok, true);
        o.expect(0, "gone");
        assert_eq!(o.last("fence_signals"), Some("TERM,KILL"), "{o}");
        let decisions = o.all("fence");
        assert_eq!(decisions.first().copied(), Some("alive"));
        assert_eq!(decisions.last().copied(), Some("gone"));
        assert!(
            decisions.iter().filter(|d| **d == "alive").count() >= 2,
            "{decisions:?}"
        );
        let _ = h.finish();
        assert!(r.lock().is_none());
    }

    pub fn stopped_holder_ended_by_kill(t: &Target) {
        let r = t.reg();
        let na = soon(3);
        let mut h = holder(t, &r, "after_lock", na);
        assert!(t.kill_group("STOP", h.pid));
        wait_past(na);
        let o = r.fence(&h.tok, true);
        fence_expect(t, &o, 0, "gone");
        if !t.shell.automatic_recovery() {
            t.kill_group("KILL", h.pid);
            let _ = h.finish();
            return;
        }
        assert_eq!(o.last("fence_signals"), Some("TERM,KILL"), "{o}");
        assert!(killed(&h.finish()));
        assert!(r.lock().is_none());
    }

    pub fn reused_pid_with_live_foreign_group_is_unproven_never_signalled(t: &Target) {
        let r = t.reg();
        let pid = t.start_sleeper(true);
        let tok = token();
        let rec = record(
            &tok,
            pid,
            &hex(b"not-its-start"),
            &t.boot_hex(),
            now() - 100,
        );
        r.plant_lock(&rec);
        let o = r.fence(&tok, true);
        o.expect(44, "unproven");
        assert_eq!(o.last("fence_signals"), Some(""));
        assert!(t.alive(pid), "the foreign group was signalled");
        assert_eq!(r.lock().as_deref(), Some(rec.as_str()));
    }

    pub fn reused_pid_with_empty_group_is_gone_by_agreement(t: &Target) {
        for alive in [true, false] {
            let r = t.reg();
            let pid = if alive {
                t.start_sleeper(false)
            } else {
                t.dead_pid()
            };
            let tok = token();
            r.plant_lock(&record(
                &tok,
                pid,
                &hex(b"not-its-start"),
                &t.boot_hex(),
                now() - 100,
            ));
            let o = r.fence(&tok, true);
            fence_expect(t, &o, 0, "gone");
            if t.shell.automatic_recovery() {
                assert_eq!(o.last("group_probe").map(|v| v != "0"), Some(true));
                assert_eq!(o.last("group_listed"), Some("no"));
                assert_eq!(o.last("fence_signals"), Some(""));
                assert!(r.lock().is_none());
            }
            if alive {
                assert!(
                    t.alive(pid),
                    "a process that is not the holder was signalled"
                );
            }
        }
    }

    pub fn leader_absent_live_mutation_child_never_gone_per_shell(t: &Target) {
        let r = t.reg();
        r.seed(b"# base\n");
        let na = soon(4);
        let mut h = holder(t, &r, "before_write", na);
        // Kill and reap the holder shell only; its child (the paused `cat`) lives on.
        assert!(t.kill_pid("KILL", h.pid));
        t.wait_until("the holder shell to be reaped", 10, || !t.alive(h.pid));
        assert!(t.group_has_members(h.pid), "the mutation child is gone");
        let o = r.fence(&h.tok, false);
        fence_expect(t, &o, 43, "alive");
        if !t.shell.automatic_recovery() {
            wait_past(na);
            for _ in 0..3 {
                let o = r.fence(&h.tok, true);
                fence_expect(t, &o, 43, "alive");
            }
            assert!(r.lock().is_some(), "nothing unlocked");
            let m2 = marker();
            r.append(&m2, &line(&m2), far()).expect(40, "busy");
            t.kill_group("KILL", h.pid);
            let _ = h.finish();
            assert_eq!(
                r.bytes().unwrap(),
                b"# base\n",
                "nothing lost, nothing written"
            );
            return;
        }
        assert!(
            o.get("start_identity").is_none(),
            "the leader PID is absent"
        );
        assert_eq!(
            r.fence(&h.tok, true).expect(43, "alive").last("reason"),
            Some("not_after_not_passed")
        );
        wait_past(na);
        let o = r.fence(&h.tok, true);
        o.expect(0, "gone");
        assert_eq!(
            o.all("fence").first().copied(),
            Some("alive"),
            "never gone first"
        );
        assert!(!t.group_has_members(h.pid));
        let _ = h.finish();
        r.append(&h.m, &h.l, far()).expect(0, "written");
        assert_eq!(r.bytes().unwrap(), [b"# base\n", &nl(&h.l)[..]].concat());
        clean(&r);
    }

    pub fn group_probe_and_listing_per_target_shell(t: &Target) {
        let r = t.reg();
        let mut h = holder(t, &r, "after_lock", far());
        let live = r.fence(&h.tok, false);
        t.kill_group("KILL", h.pid);
        let _ = h.finish();
        t.wait_until("the group to empty", 10, || !t.group_has_members(h.pid));
        let empty = r.fence(&h.tok, false);
        let row = |o: &Out| {
            format!(
                "C={} K={} listed={} fence={}",
                o.last("group_control").unwrap_or("-"),
                o.last("group_probe").unwrap_or("-"),
                o.last("group_listed").unwrap_or("-"),
                o.last("fence").unwrap_or("-")
            )
        };
        eprintln!(
            "group_probe_and_listing_per_target_shell: shell={:?} live: {} | empty: {}",
            t.shell,
            row(&live),
            row(&empty)
        );
        if t.shell.automatic_recovery() {
            assert_eq!(row(&live), "C=0 K=0 listed=yes fence=alive");
            assert_eq!(empty.last("group_control"), Some("0"));
            assert_ne!(empty.last("group_probe"), Some("0"));
            assert_eq!(empty.last("group_listed"), Some("no"));
            assert_eq!(empty.last("fence"), Some("gone"));
        } else {
            assert_eq!(live.last("fence"), Some("unproven"));
            assert_eq!(empty.last("fence"), Some("unproven"));
        }
    }

    /// ADR-0008 §17.17 item 2: on a row whose boot identity is a timestamp (the BSDs'
    /// `kern.boottime`, which a clock step moves), a boot-identity difference alone
    /// never proves `gone`: the group proof still runs, and a live holder stays
    /// `alive`. A `uname` shim makes this macOS host take the BSD row (its `ps -o
    /// lstart=` and `sysctl -n kern.boottime` behave as the BSDs'). Without the shim,
    /// the Darwin row's `kern.bootsessionuuid` is stable, and a difference is a reboot.
    #[cfg(target_os = "macos")]
    pub fn timestamp_boot_identity_difference_alone_never_proves_gone(t: &Target) {
        const SHIM_UNAME_BSD: &str = "uname() {\n  printf '%s\\n' FreeBSD\n}\n";
        // A live holder: its record carries the Darwin boot UUID, and the BSD row
        // reads a `kern.boottime` timestamp, so the identities differ.
        let r = t.reg();
        let mut h = holder(t, &r, "after_lock", far());
        let rec = r.lock().unwrap();
        let o = fence_with(&r, SHIM_UNAME_BSD, &h.tok, false);
        let recorded_boot = rec_parts(&rec)[4].clone();
        assert_ne!(o.last("boot_identity"), Some(recorded_boot.as_str()), "{o}");
        assert!(o.get("group_control").is_some(), "the group proof ran: {o}");
        o.expect(43, "alive");
        assert!(t.alive(h.pid), "nothing signalled");
        assert_eq!(r.lock().as_deref(), Some(rec.as_str()), "nothing unlocked");
        h.finish().expect(0, "written");
        // A dead holder on the timestamp row: `gone` only by the group proof.
        let r = t.reg();
        let tok = token();
        let dead = t.dead_pid();
        r.plant_lock(&record(
            &tok,
            dead,
            &hex(b"not-its-start"),
            &t.boot_hex(),
            now() - 100,
        ));
        let o = fence_with(&r, SHIM_UNAME_BSD, &tok, false);
        o.expect(0, "gone");
        assert_eq!(o.last("group_listed"), Some("no"), "{o}");
        assert!(r.lock().is_none());
        // The control, the Darwin row: another boot-session UUID is a reboot, `gone`
        // without the group proof.
        let r = t.reg();
        let tok = token();
        r.plant_lock(&record(
            &tok,
            dead,
            &hex(b"not-its-start"),
            &hex(b"00000000-0000-0000-0000-000000000000"),
            now() - 100,
        ));
        let o = r.fence(&tok, false);
        o.expect(0, "gone");
        assert!(
            o.get("group_control").is_none(),
            "the stable identity sufficed: {o}"
        );
    }

    pub fn group_probe_syntax_error_is_unproven(t: &Target) {
        let r = t.reg();
        let na = soon(3);
        let mut h = holder(t, &r, "after_lock", na);
        wait_past(na);
        let o = fence_with(&r, SHIM_KILL_SYNTAX, &h.tok, true);
        o.expect(44, "unproven");
        assert_eq!(o.last("group_control"), Some("2"));
        assert_eq!(o.last("fence_signals"), Some(""));
        assert!(t.alive(h.pid), "nothing signalled");
        assert!(r.lock().is_some(), "nothing unlocked");
        h.finish().expect(41, "not_after_passed");
    }

    pub fn group_probe_and_listing_disagreement_is_unproven(t: &Target) {
        // A live group the listing hides.
        let r = t.reg();
        let na = soon(3);
        let mut h = holder(t, &r, "after_lock", na);
        wait_past(na);
        let o = fence_with(&r, &shim_ps_drop(&h.pid.to_string(), None), &h.tok, true);
        o.expect(44, "unproven");
        assert_eq!(o.last("fence_signals"), Some(""));
        assert!(t.alive(h.pid) && r.lock().is_some());
        let _ = h.finish();
        // An empty group the listing shows.
        let r = t.reg();
        let tok = token();
        let dead = t.dead_pid();
        r.plant_lock(&record(&tok, dead, "3030", &t.boot_hex(), 1));
        let o = fence_with(&r, &shim_ps_add(&dead.to_string()), &tok, true);
        o.expect(44, "unproven");
        assert!(r.lock().is_some());
    }

    pub fn group_probe_permission_failure_is_unproven(t: &Target) {
        assert!(
            t.has_root(),
            "another account's group needs the container's root"
        );
        let pid = t.start_foreign_sleeper();
        t.wait_until("the foreign sleeper", 10, || t.alive(pid));
        thread::sleep(Duration::from_millis(300));
        let r = t.reg();
        let tok = token();
        let (start, boot) = t.identity_of(pid);
        r.plant_lock(&record(&tok, pid, &start, &boot, 1));
        let o = r.fence(&tok, true);
        o.expect(44, "unproven");
        if t.shell.automatic_recovery() {
            assert_ne!(o.last("group_probe"), Some("0"), "{o}");
            assert_eq!(o.last("group_listed"), Some("yes"), "{o}");
        }
        assert_eq!(o.last("fence_signals"), Some(""));
        assert!(t.alive(pid));
        assert!(r.lock().is_some());
        t.kill_group_as("2000:2000", "KILL", pid);
        eprintln!(
            "group_probe_permission_failure_is_unproven: shell={:?}: a group owned by uid 2000 probed by uid 1000 (genuine EPERM in a disposable container)",
            t.shell
        );
    }

    pub fn listing_without_own_group_is_unproven(t: &Target) {
        let r = t.reg();
        let mut h = holder(t, &r, "after_lock", far());
        let o = fence_with(&r, SHIM_PS_DROP_OWN, &h.tok, false);
        o.expect(44, "unproven");
        assert!(
            o.get("group_listed").is_none(),
            "an invalid listing reports no flag"
        );
        assert!(r.lock().is_some());
        h.finish().expect(0, "written");
    }

    pub fn terminate_then_unproven_reports_signals_sent_exit_44(t: &Target) {
        let r = t.reg();
        let na = soon(3);
        let mut h = holder(t, &r, "after_lock", na);
        assert!(t.kill_group("STOP", h.pid));
        wait_past(na);
        if !t.shell.automatic_recovery() {
            let o = r.fence(&h.tok, true);
            fence_expect(t, &o, 0, "gone");
            t.kill_group("KILL", h.pid);
            let _ = h.finish();
            return;
        }
        // fence --terminate finds alive and sends TERM; then the proof breaks.
        let pf = Pauses::new(t);
        let lie = t.path("lie");
        let s = pf.form(&r.fence_script(&h.tok, true));
        let mut g = pf.arm("after_term");
        let run = t.spawn(&format!(
            "{}{s}",
            shim_ps_drop(&h.pid.to_string(), Some(&lie))
        ));
        g.wait();
        t.put(&lie, b"1");
        g.release();
        let o = run.wait();
        o.expect(44, "unproven");
        assert_eq!(o.last("fence_signals"), Some("TERM"), "{o}");
        assert_eq!(o.all("fence").first().copied(), Some("alive"));
        assert!(t.alive(h.pid), "no further signal (KILL) after unproven");
        assert!(r.lock().is_some(), "no unlock");
        t.kill_group("KILL", h.pid);
        let _ = h.finish();
    }

    pub fn shell_table_matches_round4_observed_rows(t: &Target) {
        let probe = |pgid: &str| {
            format!(
                "kill -s 0 -- -$$ 2>/dev/null; c=$?; kill -s 0 -- -{pgid} 2>/dev/null; k=$?; ps -A -o pgid= >/dev/null 2>&1; l=$?; echo \"$c/$k/$l\"\n"
            )
        };
        // "Invalid syntax": a non-numeric argument, `kill -s 0 -x`, in the control and
        // the probe positions; it reproduces every round-4 row. (With `--` before it,
        // BusyBox counts two failed arguments and exits 2: recorded below.)
        let invalid = "kill -s 0 -x 2>/dev/null; c=$?; kill -s 0 -x 2>/dev/null; k=$?; ps -A -o pgid= >/dev/null 2>&1; l=$?; echo \"$c/$k/$l\"\n";
        let invalid_dashdash = "kill -s 0 -- -x 2>/dev/null; c=$?; kill -s 0 -- -x 2>/dev/null; k=$?; ps -A -o pgid= >/dev/null 2>&1; l=$?; echo \"$c/$k/$l\"\n";
        let cell = |s: &str| {
            String::from_utf8_lossy(&t.run_raw(s).stdout)
                .trim()
                .to_owned()
        };
        let orphan = t.start_orphan_group();
        let live = cell(&probe(&orphan.to_string()));
        let empty = cell(&probe(&t.dead_pid().to_string()));
        let bad = cell(invalid);
        let bad_dashdash = cell(invalid_dashdash);
        let (name, version) = match t.shell {
            Shell::Dash => ("dash", t.sh_ok("dpkg-query -W -f '${Version}' dash", &[])),
            Shell::BashSh => ("bash", t.sh_ok("bash --version | head -1", &[])),
            Shell::BusyBox => ("busybox", t.sh_ok("busybox 2>&1 | head -1", &[])),
            Shell::Native => {
                if cfg!(target_os = "macos") {
                    ("macos-sh", t.sh_ok("/bin/sh --version | head -1", &[]))
                } else {
                    let target = t.sh_ok("readlink -f /bin/sh", &[]);
                    if target.contains("dash") {
                        (
                            "dash",
                            t.sh_ok(
                                "dpkg-query -W -f '${Version}' dash 2>/dev/null || echo unknown",
                                &[],
                            ),
                        )
                    } else if target.contains("bash") {
                        ("bash", t.sh_ok("bash --version | head -1", &[]))
                    } else {
                        ("busybox", t.sh_ok("busybox 2>&1 | head -1", &[]))
                    }
                }
            }
        };
        eprintln!(
            "shell_table_matches_round4_observed_rows: {name} [{}]: live child {live}, empty group {empty}, invalid syntax {bad} (with `--`: {bad_dashdash})",
            version.trim()
        );
        let (want_version, want) = match name {
            "dash" => ("0.5.12-12", ["0/0/0", "0/1/0", "2/2/0"]),
            "bash" => ("5.2.37", ["0/0/0", "0/1/0", "1/1/0"]),
            "busybox" => ("v1.37.0", ["1/1/0", "1/2/0", "1/1/0"]),
            _ => ("3.2.57", ["0/0/0", "0/1/0", "1/1/0"]),
        };
        assert!(
            version.contains(want_version),
            "{name}: version {version:?} is not the round-4 row's {want_version}"
        );
        assert_eq!(
            [live.as_str(), empty.as_str(), bad.as_str()],
            want,
            "{name}"
        );
        // The injected disagreements (three branches) are unproven.
        let r = t.reg();
        let mut h = holder(t, &r, "after_lock", far());
        let hp = h.pid.to_string();
        for (what, shim) in [
            ("listing hides a live group", shim_ps_drop(&hp, None)),
            ("listing lacks the own group", SHIM_PS_DROP_OWN.to_owned()),
        ] {
            let o = fence_with(&r, &shim, &h.tok, false);
            assert_eq!(o.code, Some(44), "{what}: {o}");
        }
        h.finish().expect(0, "written");
        let tok = token();
        let dead = t.dead_pid();
        r.plant_lock(&record(&tok, dead, "3030", &t.boot_hex(), 1));
        let o = fence_with(&r, &shim_ps_add(&dead.to_string()), &tok, false);
        assert_eq!(o.code, Some(44), "listing shows an empty group: {o}");
    }

    pub fn fence_decision_ignores_diagnostics_uses_exit_status(t: &Target) {
        let r = t.reg();
        let mut h = holder(t, &r, "after_lock", far());
        let seen = t.path("noisy-seen");
        let plain = r.fence(&h.tok, false);
        let noisy = fence_with(&r, &shim_noisy(&seen), &h.tok, false);
        assert_eq!(plain.code, noisy.code, "{plain}\n{noisy}");
        assert_eq!(plain.last("fence"), noisy.last("fence"));
        let ran = String::from_utf8(t.get(&seen).unwrap()).unwrap();
        assert!(
            ran.contains("kill") && ran.contains("ps"),
            "the noisy shims ran: {ran:?}"
        );
        h.finish().expect(0, "written");
        // A stale lock: the same decision with and without diagnostics; and a probe
        // that prints an error yet exits 0 is read by its status, which the listing
        // contradicts: unproven, never alive and never gone.
        let tok = token();
        let dead = t.dead_pid();
        r.plant_lock(&record(&tok, dead, "3030", &t.boot_hex(), 1));
        let noisy = fence_with(&r, &shim_noisy(&seen), &tok, false);
        fence_expect(t, &noisy, 0, "gone");
        let r = t.reg();
        r.plant_lock(&record(&tok, dead, "3030", &t.boot_hex(), 1));
        let lying = fence_with(&r, &shim_kill_lies_ok(&dead.to_string()), &tok, false);
        lying.expect(44, "unproven");
        assert!(r.lock().is_some());
    }

    /// The script part: a holder whose termination cannot be proven is never
    /// unlocked by `fence` (three attempts), and a redispatch finds the lock and
    /// writes nothing. `held` (`lock_holder_unresolved`) with manual instructions is
    /// the runtime's (U10).
    pub fn unprovable_holder_held_for_manual_recovery_never_redispatched(t: &Target) {
        let r = t.reg();
        r.seed(b"# base\n");
        let na = soon(3);
        let mut h = holder(t, &r, "after_lock", na);
        assert!(t.kill_group("STOP", h.pid));
        wait_past(na);
        let shim = shim_ps_drop(&h.pid.to_string(), None);
        for attempt in 1..=3 {
            let o = fence_with(&r, &shim, &h.tok, true);
            o.expect(44, "unproven");
            assert_eq!(o.last("fence_signals"), Some(""), "attempt {attempt}");
            assert!(r.lock().is_some());
        }
        let m2 = marker();
        r.append(&m2, &line(&m2), far()).expect(40, "busy");
        assert_eq!(r.bytes().unwrap(), b"# base\n");
        // Manual recovery: the owner ends the process and removes the link by hand.
        t.kill_group("KILL", h.pid);
        let _ = h.finish();
        t.sh_ok("rm -f \"$1\"", &[&r.lock_path()]);
        let o = r.inspect(&h.m);
        assert_eq!(
            (o.get("marker_lines"), o.get("lock")),
            (Some("0"), Some("none"))
        );
    }

    pub fn other_enrollments_lock_is_busy_never_broken(t: &Target) {
        let r = t.reg();
        let na = soon(3);
        let mut h = holder(t, &r, "after_lock", na);
        let rec = r.lock().unwrap();
        wait_past(na);
        let other = token();
        for terminate in [false, true] {
            let o = r.fence(&other, terminate);
            o.expect(40, "busy");
            assert_eq!(o.last("reason"), Some("lock_other_token"));
            assert_eq!(o.last("fence_signals"), Some(""));
            assert!(t.alive(h.pid));
        }
        // Even once its holder is gone, another enrollment never breaks it.
        t.kill_group("KILL", h.pid);
        let _ = h.finish();
        r.fence(&other, true).expect(40, "busy");
        let m2 = marker();
        r.append(&m2, &line(&m2), far()).expect(40, "busy");
        assert_eq!(r.lock().as_deref(), Some(rec.as_str()));
    }

    pub fn script_started_after_not_after_writes_nothing_exit_41(t: &Target) {
        let m = marker();
        let l = line(&m);
        let r = t.reg();
        let pre = [b"# base\n", &nl(&l)[..]].concat();
        r.seed(&pre);
        let past = NotAfter::new(now() - 1).unwrap();
        let m2 = marker();
        let o = r.append(&m2, &line(&m2), past);
        o.expect(41, "not_after_passed");
        assert!(o.get("lock").is_none(), "refused before the lock");
        r.remove(&m, past, &pre, b"# base\n")
            .expect(41, "not_after_passed");
        assert_eq!(r.bytes().unwrap(), pre);
        clean(&r);
        // A not-after equal to the remote clock reading has passed (writes happen
        // strictly before it).
        let at = NotAfter::new(now()).unwrap();
        let o = r.append(&m2, &line(&m2), at);
        assert!(o.code == Some(41) || o.code == Some(0), "{o}");
    }

    /// The script part (ADR-0008 D5 §6.7 "The late_write residual"): a script that had
    /// not taken the lock fails its own not-after check, and one that had keeps the
    /// lock, so only an inspect whose remote clock is past the not-after, showing no
    /// marker and no lock with the token, can clear it. `late_write_cleared` is
    /// U5-pure's; the residual's bookkeeping is U10's.
    pub fn late_write_residual_cleared_only_by_inspect_after_not_after(t: &Target) {
        let r = t.reg();
        r.seed(b"# base\n");
        let na = soon(3);
        let mut h = holder(t, &r, "before_ln", na);
        let o = r.inspect(&h.m);
        let early: i64 = o.get("remote_now").unwrap().parse().unwrap();
        assert!(
            early < na.seconds(),
            "not yet clearable: the clock is before the not-after"
        );
        assert_eq!(
            (o.get("marker_lines"), o.get("lock")),
            (Some("0"), Some("none"))
        );
        wait_past(na);
        h.finish().expect(41, "not_after_passed");
        let o = r.inspect(&h.m);
        let late: i64 = o.get("remote_now").unwrap().parse().unwrap();
        assert!(late > na.seconds());
        assert_eq!(
            (o.get("marker_lines"), o.get("lock")),
            (Some("0"), Some("none"))
        );
        // A holder past its not-after keeps its lock: an inspect then sees the token.
        let na2 = soon(3);
        let mut h2 = holder(t, &r, "after_lock", na2);
        wait_past(na2);
        let o = r.inspect(&h2.m);
        assert!(o.get("remote_now").unwrap().parse::<i64>().unwrap() > na2.seconds());
        assert_eq!(rec_parts(o.get("lock_holder").unwrap())[1], h2.tok.as_str());
        h2.finish().expect(41, "not_after_passed");
        assert_eq!(r.bytes().unwrap(), b"# base\n");
    }

    /// The script part: a retry after a lost reply carries the same marker, and the
    /// script refuses a second line by marker (exit 10), whatever the local state
    /// says. The lost reply itself is U5-io's runner and U10's runtime.
    pub fn retry_after_lost_reply_never_appends_twice(t: &Target) {
        let m = marker();
        let l = line(&m);
        let r = t.reg();
        r.seed(b"# base\n");
        let _lost = r.append(&m, &l, far()).expect(0, "written");
        r.append(&m, &l, far()).expect(10, "already_present");
        let bytes = r.bytes().unwrap();
        assert_eq!(count(&bytes, m.as_str()), 1);
    }

    /// The script part: a session killed before the lock (paused at `before_ln`)
    /// leaves no line and no lock, so the reconcile inspect reads not-applied. The
    /// ssh process, its kill and the reconcile are U5-io's and U10's.
    pub fn ssh_killed_before_append_reconciled_not_applied(t: &Target) {
        let r = t.reg();
        r.seed(b"# base\n");
        let mut h = holder(t, &r, "before_ln", far());
        t.kill_group("KILL", h.pid);
        let _ = h.finish();
        let o = r.inspect(&h.m);
        assert_eq!(
            (o.get("marker_lines"), o.get("lock")),
            (Some("0"), Some("none"))
        );
        assert_eq!(r.bytes().unwrap(), b"# base\n");
    }

    pub fn truncated_script_does_nothing_at_every_truncation_point(t: &Target) {
        let m = marker();
        let l = line(&m);
        let ri = t.reg();
        ri.seed(b"# base\n");
        let rb = t.reg_absent();
        let ra = t.reg();
        ra.seed(b"# base\n");
        let rr = t.reg();
        let pre = [b"# base\n", &nl(&l)[..]].concat();
        rr.seed(&pre);
        let rf = t.reg();
        let tok = token();
        let dead = t.dead_pid();
        let rec = record(&tok, dead, "3030", &t.boot_hex(), 1);
        rf.plant_lock(&rec);
        let cases = [
            ("inspect", ri.inspect_script(&m)),
            ("bootstrap", rb.bootstrap_script()),
            ("append", ra.append_script(&m, &l, &token(), far())),
            (
                "remove",
                rr.remove_script(&m, &token(), far(), &pre, b"# base\n"),
            ),
            ("fence", rf.fence_script(&tok, false)),
        ];
        let mut total = 0usize;
        for (name, s) in &cases {
            let text = s.text().as_bytes();
            let ran = prefixes_that_ran(t, name, text, 1, text.len() - 2);
            assert!(ran.is_empty(), "{name}: prefixes that ran: {ran:?}");
            total += text.len() - 2;
            // Nothing changed.
            assert_eq!(ri.bytes().unwrap(), b"# base\n");
            assert!(!t.exists(&rb.dir), "bootstrap prefix created the directory");
            assert_eq!(ra.bytes().unwrap(), b"# base\n");
            assert_eq!(rr.bytes().unwrap(), pre);
            assert_eq!(rf.lock().as_deref(), Some(rec.as_str()));
            for r in [&ri, &ra, &rr] {
                clean(r);
            }
        }
        // The positive control, through the same driver: the full script without
        // only its final newline is complete, runs, and does what the script does.
        for (name, s) in &cases {
            let n = s.text().len() - 1;
            let ran = prefixes_that_ran(t, name, s.text().as_bytes(), n, n);
            assert_eq!(ran, [n], "{name}: the complete script did not run");
        }
        assert!(t.exists(&rb.dir), "bootstrap");
        assert_eq!(
            ra.bytes().unwrap(),
            [b"# base\n", &nl(&l)[..]].concat(),
            "append"
        );
        assert_eq!(rr.bytes().unwrap(), b"# base\n", "remove");
        assert_eq!(rf.lock().is_none(), t.shell.automatic_recovery(), "fence");
        eprintln!(
            "truncated_script_does_nothing_at_every_truncation_point: shell={:?}: {total} prefixes, none ran",
            t.shell
        );
    }

    /// Every prefix of `text` of length `first..=last`, each run as a group leader;
    /// the lengths whose run printed anything (a script prints `HM1 v=1` first).
    fn prefixes_that_ran(
        t: &Target,
        name: &str,
        text: &[u8],
        first: usize,
        last: usize,
    ) -> Vec<usize> {
        match &t.runner {
            Runner::Docker { .. } => {
                let file = t.path(&format!("trunc-{name}.sh"));
                t.put(&file, text);
                let driver = t.path("trunc-driver.sh");
                t.put(
                    &driver,
                    b"s=$1; i=$2; hi=$3; w=$4\nwhile [ \"$i\" -le \"$hi\" ]; do\n  head -c \"$i\" \"$s\" > \"$s.p$w\"\n  setsid /bin/sh -s < \"$s.p$w\" > \"$s.o$w\" 2>/dev/null &\n  wait \"$!\"\n  if [ -s \"$s.o$w\" ]; then echo \"RAN $i\"; fi\n  i=$((i + 1))\ndone\nrm -f \"$s.p$w\" \"$s.o$w\"\n",
                );
                let workers = 8usize;
                let chunk = (last + 1 - first).div_ceil(workers);
                let handles: Vec<_> = (0..workers)
                    .map(|w| {
                        let lo = first + w * chunk;
                        let hi = (first + (w + 1) * chunk - 1).min(last);
                        let (file, driver) = (file.clone(), driver.clone());
                        let (container, user) = match &t.runner {
                            Runner::Docker { container, user } => (container.clone(), user.clone()),
                            _ => unreachable!(),
                        };
                        let home = t.home.clone();
                        thread::spawn(move || {
                            if lo > hi {
                                return String::new();
                            }
                            let out = Command::new("docker")
                                .args([
                                    "exec",
                                    "-u",
                                    &user,
                                    "-e",
                                    &format!("HOME={home}"),
                                    &container,
                                ])
                                .args([
                                    "/bin/sh",
                                    &driver,
                                    &file,
                                    &lo.to_string(),
                                    &hi.to_string(),
                                    &w.to_string(),
                                ])
                                .stdin(Stdio::null())
                                .output()
                                .unwrap();
                            assert!(
                                out.status.success(),
                                "{}",
                                String::from_utf8_lossy(&out.stderr)
                            );
                            String::from_utf8_lossy(&out.stdout).into_owned()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|h| {
                        h.join()
                            .unwrap()
                            .lines()
                            .filter_map(|l| l.strip_prefix("RAN ").and_then(|n| n.parse().ok()))
                            .collect::<Vec<usize>>()
                    })
                    .collect()
            }
            _ => {
                let next = Arc::new(AtomicUsize::new(first));
                let ran = Arc::new(Mutex::new(Vec::new()));
                let text = Arc::new(text.to_vec());
                let workers: Vec<_> = (0..8)
                    .map(|_| {
                        let (next, ran, text) = (next.clone(), ran.clone(), text.clone());
                        let (home, root) = (t.home.clone(), t.root.clone());
                        thread::spawn(move || {
                            loop {
                                let n = next.fetch_add(1, Ordering::Relaxed);
                                if n > last {
                                    break;
                                }
                                let mut child = Command::new("/bin/sh")
                                    .arg("-s")
                                    .env_clear()
                                    .env("PATH", NATIVE_PATH)
                                    .env("HOME", &home)
                                    .current_dir(&root)
                                    .process_group(0)
                                    .stdin(Stdio::piped())
                                    .stdout(Stdio::piped())
                                    .stderr(Stdio::null())
                                    .spawn()
                                    .unwrap();
                                {
                                    use std::io::Write;
                                    let mut w = child.stdin.take().unwrap();
                                    let _ = w.write_all(&text[..n]);
                                }
                                let out = child.wait_with_output().unwrap();
                                if !out.stdout.is_empty() {
                                    ran.lock().unwrap().push(n);
                                }
                            }
                        })
                    })
                    .collect();
                for w in workers {
                    w.join().unwrap();
                }
                let mut v = ran.lock().unwrap().clone();
                v.sort_unstable();
                v
            }
        }
    }

    // =========================================================================
    // BusyBox and the shared /proc parser.
    // =========================================================================

    pub fn busybox_fence_always_unproven_manual_recovery(t: &Target) {
        assert_eq!(t.shell, Shell::BusyBox);
        let check = |o: &Out| {
            o.expect(44, "unproven");
            assert_eq!(o.last("fence_signals"), Some(""), "{o}");
            assert_eq!(o.last("group_control"), Some("1"), "{o}");
        };
        // A live holder past its not-after.
        let r = t.reg();
        let na = soon(3);
        let mut h = holder(t, &r, "after_lock", na);
        wait_past(na);
        check(&r.fence(&h.tok, true));
        // Stopped.
        assert!(t.kill_group("STOP", h.pid));
        check(&r.fence(&h.tok, true));
        // Leader absent, child alive.
        assert!(t.kill_pid("KILL", h.pid));
        t.wait_until("the shell reaped", 10, || !t.alive(h.pid));
        check(&r.fence(&h.tok, true));
        // Stale: the whole group gone.
        t.kill_group("KILL", h.pid);
        let _ = h.finish();
        t.wait_until("the group to empty", 10, || !t.group_has_members(h.pid));
        check(&r.fence(&h.tok, true));
        assert!(r.lock().is_some(), "never unlocked automatically");
        // Manual recovery: the owner removes the link; inspect then reads none.
        t.sh_ok("rm -f \"$1\"", &[&r.lock_path()]);
        assert_eq!(r.inspect(&h.m).get("lock"), Some("none"));
        // Reused PIDs: never gone, never signalled.
        let pid = t.start_sleeper(false);
        let tok = token();
        let r = t.reg();
        r.plant_lock(&record(&tok, pid, "3030", &t.boot_hex(), 1));
        check(&r.fence(&tok, true));
        assert!(t.alive(pid));
    }

    pub fn busybox_append_and_remove_run_with_proc_process_group(t: &Target) {
        assert_eq!(t.shell, Shell::BusyBox);
        // `ps -p` is unsupported here (why Q29 reads /proc).
        let ps = t.sh("ps -o pgid= -p $$", &[]);
        eprintln!(
            "busybox_append_and_remove_run_with_proc_process_group: `ps -o pgid= -p $$` exit {:?}",
            ps.status.code()
        );
        assert!(!ps.status.success());
        let m = marker();
        let l = line(&m);
        let r = t.reg();
        r.seed(b"# base\n");
        let o = r.append(&m, &l, far());
        o.expect(0, "written");
        assert!(o.get("pgid").is_some());
        let pre = r.bytes().unwrap();
        r.remove(&m, far(), &pre, b"# base\n").expect(0, "renamed");
        assert_eq!(r.bytes().unwrap(), b"# base\n");
        clean(&r);
    }

    /// U11's synthetic `/proc/<pid>/stat` fixtures (its plan text; `procstat::Fixtures`
    /// was not in the tree): the `comm` values, a 15-byte name, a newline, and the
    /// malformed lines.
    fn stat_fixtures() -> Vec<Vec<u8>> {
        let line = |comm: &str, state: &str, pgrp: &str, start: &str| {
            format!(
                "4242 ({comm}) {state} 1 {pgrp} 4242 0 -1 4194304 10 0 0 0 1 2 0 0 20 0 1 0 {start} 1000 200 18446744073709551615\n"
            )
            .into_bytes()
        };
        let mut v = Vec::new();
        for comm in [
            "plain",
            "has space",
            "a ) b ( c",
            ")(",
            "fifteen_bytes__",
            "nl\nname",
        ] {
            v.push(line(comm, "S", "77", "123456"));
        }
        v.push(line("zombie", "Z", "1", "0"));
        v.push(b"4242 sh S 1 77 4242 0 -1 4194304\n".to_vec());
        v.push(b"4242 (sh) S 1 77 4242\n".to_vec());
        for bad in ["0", "x", "-1", "+7"] {
            v.push(line("sh", "S", bad, "1"));
        }
        for bad in ["1.5", "abc", "-1"] {
            v.push(line("sh", "S", "7", bad));
        }
        v.push(line("sh", "SS", "7", "1"));
        v.push(line("sh", "1", "7", "1"));
        v
    }

    pub fn procstat_fixtures_rust_and_awk_agree(t: &Target) {
        for (i, fixture) in stat_fixtures().iter().enumerate() {
            let f = t.path(&format!("stat{i}"));
            t.put(&f, fixture);
            let out = t.sh("awk \"$1\" \"$2\"", &[script::PROCSTAT_AWK, &f]);
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            match heimdall_domain::procstat::parse(fixture) {
                Ok(p) => {
                    assert!(out.status.success(), "{i}: awk refused {fixture:?}");
                    assert_eq!(
                        stdout.trim(),
                        format!("{} {}", p.process_group, p.start_time),
                        "{i}: {fixture:?}"
                    );
                }
                Err(e) => {
                    assert_eq!(
                        out.status.code(),
                        Some(2),
                        "{i}: awk accepted {fixture:?} ({e})"
                    );
                    assert!(stdout.is_empty());
                }
            }
        }
    }

    pub fn procstat_live_comm_fixtures_per_linux_shell(t: &Target) {
        assert!(t.is_linux());
        for (i, name) in ["plain", "has space", "a ) b ( c", ")(", "nl\nname"]
            .iter()
            .enumerate()
        {
            let dir = t.path(&format!("comm{i}"));
            t.mkdir(&dir, "700");
            let prog = format!("{dir}/{name}");
            t.put(&prog, b"#!/bin/sh\nsleep 300\n");
            t.chmod("700", &prog);
            let pid: u32 = t
                .sh_ok(
                    "setsid \"$1\" >/dev/null 2>&1 < /dev/null & echo $!",
                    &[&prog],
                )
                .trim()
                .parse()
                .unwrap();
            t.wait_until("the comm to be set", 10, || {
                t.get(&format!("/proc/{pid}/comm"))
                    .is_some_and(|c| c == format!("{name}\n").as_bytes())
            });
            let stat = t.get(&format!("/proc/{pid}/stat")).unwrap();
            let rust = heimdall_domain::procstat::parse(&stat).unwrap();
            let awk = t.sh_ok(
                "awk \"$1\" \"/proc/$2/stat\"",
                &[script::PROCSTAT_AWK, &pid.to_string()],
            );
            assert_eq!(awk.trim(), format!("{pid} {}", rust.start_time), "{name:?}");
            assert_eq!(
                rust.process_group, pid,
                "{name:?}: setsid makes it a leader"
            );
            let naive = t.sh_ok("awk '{print $5}' \"/proc/$1/stat\"", &[&pid.to_string()]);
            if matches!(*name, "has space" | "a ) b ( c") {
                assert_ne!(
                    naive.trim(),
                    pid.to_string(),
                    "{name:?}: the naive read was right?"
                );
            }
            eprintln!(
                "procstat_live_comm_fixtures_per_linux_shell: shell={:?} comm={name:?} pid={pid} parser={} naive_$5={:?}",
                t.shell,
                awk.trim(),
                naive.trim()
            );
            t.kill_group("KILL", pid);
        }
    }
}

/// The goldens: the release scripts, rendered from fixed parameters, byte for byte,
/// with no pause point; the test form differs only by its `HM_PAUSE` lines. Runs on
/// every host (no shell needed).
mod golden {
    use heimdall_contract::enrollment::RemoteStage;
    use heimdall_registry::script::{
        self, AppendParams, BootstrapParams, FenceParams, InspectParams, Marker, NotAfter, Payload,
        RegistryLine, RegistryLocation, RemoteScript, RemoveParams, StepToken,
    };

    /// The fixed golden parameters. The line's key text is synthetic (not a key).
    pub fn golden_scripts() -> Vec<(&'static str, RemoteScript)> {
        let marker = Marker::parse("heimdall:enr_0123456789abcdef0123456789abcdef").unwrap();
        let line = RegistryLine::parse(
            "cert-authority,principals=\"hm:dst_golden:enroll\" ssh-ed25519 AAAAgoldenSyntheticNotAKey heimdall:enr_0123456789abcdef0123456789abcdef",
            &marker,
        )
        .unwrap();
        let token = StepToken::parse("00112233445566778899aabbccddeeff").unwrap();
        let not_after = NotAfter::new(1_800_000_000).unwrap();
        let pre = format!("# admin line\n{}\n", line.as_str());
        vec![
            (
                "inspect",
                script::inspect(&InspectParams {
                    registry: RegistryLocation::RemoteHome,
                    marker: marker.clone(),
                }),
            ),
            (
                "bootstrap",
                script::bootstrap(&BootstrapParams {
                    registry: RegistryLocation::RemoteHome,
                }),
            ),
            (
                "append",
                script::append(&AppendParams {
                    registry: RegistryLocation::RemoteHome,
                    marker: marker.clone(),
                    line,
                    token: token.clone(),
                    not_after_remote: not_after,
                }),
            ),
            (
                "remove",
                script::remove(&RemoveParams {
                    registry: RegistryLocation::RemoteHome,
                    marker,
                    token: token.clone(),
                    not_after_remote: not_after,
                    preimage: Payload::new(pre.as_bytes()).unwrap(),
                    post_image: Payload::new(b"# admin line\n").unwrap(),
                }),
            ),
            (
                "fence",
                script::fence(&FenceParams {
                    registry: RegistryLocation::RemoteHome,
                    token,
                    terminate: true,
                }),
            ),
        ]
    }

    #[test]
    fn release_scripts_match_golden_and_have_no_pause_points() {
        let dir = heimdall_testkit::repo::repo_path("tests/contracts/golden/enroll-scripts");
        let update = std::env::var_os("HM_UPDATE_GOLDENS").is_some_and(|v| v == "1");
        let stages = [
            RemoteStage::Inspect,
            RemoteStage::Bootstrap,
            RemoteStage::Append,
            RemoteStage::Remove,
            RemoteStage::Fence,
        ];
        let scripts = golden_scripts();
        assert_eq!(scripts.len(), stages.len());
        for ((name, s), stage) in scripts.iter().zip(stages) {
            assert_eq!(s.stage(), stage);
            let path = dir.join(format!("{name}.sh"));
            if update {
                std::fs::write(&path, s.text()).unwrap();
            }
            let golden = std::fs::read(&path).unwrap_or_else(|e| {
                panic!("{}: {e} (HM_UPDATE_GOLDENS=1 writes it)", path.display())
            });
            assert!(
                golden == s.text().as_bytes(),
                "{name}.sh differs from the release rendering"
            );
            // No pause point, no placeholder, one function called on the last line.
            let text = s.text();
            assert!(
                !text.contains("HM_PAUSE"),
                "{name}: a pause point in a release script"
            );
            assert!(!text.contains("@@"), "{name}: an unexpanded placeholder");
            assert!(
                text.ends_with("}\nhm_main\n"),
                "{name}: not called on the last line"
            );
            assert!(
                text.contains("\nhm_main() {\n  export LC_ALL=C\n  umask 077\n"),
                "{name}: LC_ALL=C and umask 077 are not the first statements"
            );
            assert!(text.is_ascii() && !text.contains('\r'));
            #[cfg(debug_assertions)]
            {
                // The test form adds only the pause function and its points.
                use heimdall_registry::script::test_form::{PauseDir, with_pause_points};
                let dir = PauseDir::parse("/scratch/pause").unwrap();
                let test = with_pause_points(s, &dir).unwrap();
                let added: Vec<&str> = {
                    let release: std::collections::BTreeSet<&str> = text.lines().collect();
                    test.text()
                        .lines()
                        .filter(|l| !release.contains(l))
                        .collect()
                };
                let points: Vec<String> = script::pause_points(stage)
                    .iter()
                    .map(|p| format!("HM_PAUSE {p}"))
                    .collect();
                for line in &added {
                    let t = line.trim_start();
                    assert!(
                        t.starts_with("HM_PAUSE")
                            || points.iter().any(|p| t == p)
                            || matches!(
                                t,
                                "if [ -p \"$HM_PAUSE_DIR/$1\" ]; then"
                                    | "printf '%s\\n' \"$$\" >| \"$HM_PAUSE_DIR/$1.pid\""
                                    | "cat \"$HM_PAUSE_DIR/$1\" > /dev/null"
                                    | "fi"
                                    | "}"
                            ),
                        "{name}: unexpected test-form line {line:?}"
                    );
                }
            }
        }
        // Only the five goldens and the README live there.
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "README.md",
                "append.sh",
                "bootstrap.sh",
                "fence.sh",
                "inspect.sh",
                "remove.sh"
            ]
        );
    }
}

/// Stamp one test per row for a target: `$make` builds the target, each row is the
/// shared body in [`rows`].
#[cfg(all(unix, debug_assertions))]
macro_rules! rows_for {
    (native $make:path; $($row:ident),* $(,)?) => {
        $(
            #[test]
            fn $row() {
                let t = $make();
                crate::rows::$row(&t);
            }
        )*
    };
    (docker $make:path; $($row:ident),* $(,)?) => {
        $(
            #[test]
            #[ignore = "docker: run with HM_DOCKER_TESTS=1 cargo test -p heimdall-enroll --test integration_enroll_registry -- --ignored"]
            fn $row() {
                crate::harness::docker_gate();
                let t = $make();
                crate::rows::$row(&t);
            }
        )*
    };
}

/// The protocol rows of `registry_protocol_on_target_shell`, plus the negative rows,
/// that run on every target.
#[cfg(all(unix, debug_assertions))]
macro_rules! protocol_rows {
    ($kind:ident $make:path) => {
        rows_for!($kind $make;
            registry_protocol_on_target_shell,
            append_creates_registry_exclusively_mode_0600,
            registry_dir_bootstrap_journaled_shown_in_plan_then_locked,
            missing_registry_dir_is_exit_32_not_busy,
            bootstrap_missing_parent_exit_33_refused,
            bootstrap_refuses_symlink_or_foreign_owner,
            append_newline_decided_at_append_time,
            append_idempotent_by_marker_exit_10,
            inspect_reports_metadata_and_content,
            remove_compare_then_rename_preserves_unrelated_bytes,
            remote_clock_reading_per_target,
            lock_symlink_is_exclusive_per_target,
            start_identity_per_target_shell,
            holder_is_process_group_leader_per_target,
            non_ascii_registry_bytes_per_target_shell,
            symlinked_registry_refused,
            hardlinked_registry_refused,
            group_writable_dir_refused,
            registry_too_large_refused,
            non_posix_or_noisy_login_refused_as_registry_unsupported,
        );
    };
}

/// The interleaving and fencing rows (direct runs, pause hooks).
#[cfg(all(unix, debug_assertions))]
macro_rules! fencing_rows {
    ($kind:ident $make:path) => {
        rows_for!($kind $make;
            admin_append_between_inspect_and_append_preserved,
            admin_append_without_newline_in_append_window_detected_damaged,
            admin_edit_before_final_check_remove_restarts,
            three_compare_failures_give_registry_changed,
            rotation_add_preserves_admin_edit,
            admin_edit_inside_remove_window_is_lost,
            busy_lock_changes_nothing_exit_40,
            not_after_passed_changes_nothing_exit_41,
            lock_lost_changes_nothing_exit_42,
            lock_records_holder_pid_start_and_boot_identity,
            first_script_survives_timeout_resumes_after_reconcile_no_duplicate_no_loss,
            writer_paused_just_before_write_no_duplicate_no_loss,
            stale_lock_broken_only_after_holder_proven_gone,
            holder_alive_past_not_after_terminated_term_then_kill_then_proven_gone,
            stopped_holder_ended_by_kill,
            reused_pid_with_live_foreign_group_is_unproven_never_signalled,
            reused_pid_with_empty_group_is_gone_by_agreement,
            leader_absent_live_mutation_child_never_gone_per_shell,
            group_probe_and_listing_per_target_shell,
            group_probe_syntax_error_is_unproven,
            group_probe_and_listing_disagreement_is_unproven,
            listing_without_own_group_is_unproven,
            terminate_then_unproven_reports_signals_sent_exit_44,
            shell_table_matches_round4_observed_rows,
            fence_decision_ignores_diagnostics_uses_exit_status,
            unprovable_holder_held_for_manual_recovery_never_redispatched,
            other_enrollments_lock_is_busy_never_broken,
            script_started_after_not_after_writes_nothing_exit_41,
            late_write_residual_cleared_only_by_inspect_after_not_after,
            retry_after_lost_reply_never_appends_twice,
            ssh_killed_before_append_reconciled_not_applied,
            truncated_script_does_nothing_at_every_truncation_point,
        );
    };
}

/// This host's `/bin/sh`, run directly as its own process-group leader.
#[cfg(all(unix, debug_assertions))]
mod native_sh {
    use crate::harness::Target;
    fn make() -> Target {
        Target::native()
    }
    protocol_rows!(native make);
    fencing_rows!(native make);
    rows_for!(native make; procstat_fixtures_rust_and_awk_agree);
    #[cfg(target_os = "macos")]
    rows_for!(native make; acl_indicator_refused);
    #[cfg(target_os = "macos")]
    rows_for!(native make; timestamp_boot_identity_difference_alone_never_proves_gone);
    #[cfg(target_os = "linux")]
    rows_for!(native make; procstat_live_comm_fixtures_per_linux_shell);
}

/// This host's `/bin/sh` through a loopback sshd (`printf 'HM1 ready\n'; exec /bin/sh
/// -s`), where the process-group-leader property under sshd matters.
#[cfg(all(unix, debug_assertions))]
mod native_sshd {
    use crate::harness::Target;
    fn make() -> Target {
        Target::sshd()
    }
    protocol_rows!(native make);
}

/// dash 0.5.12 on the M00-T03 Debian 13 `enrollable` container (`up.sh` first).
#[cfg(all(unix, debug_assertions))]
mod docker_dash {
    use crate::harness::Target;
    fn make() -> Target {
        Target::m00_enrollable()
    }
    protocol_rows!(docker make);
    fencing_rows!(docker make);
    rows_for!(docker make;
        foreign_owned_registry_refused,
        group_probe_permission_failure_is_unproven,
        procstat_fixtures_rust_and_awk_agree,
        procstat_live_comm_fixtures_per_linux_shell,
    );
}

/// dash on the round-4 Debian 13 image with procps and acl (for `setfacl`).
#[cfg(all(unix, debug_assertions))]
mod docker_debian_dash {
    use crate::harness::{Shell, Target};
    fn make() -> Target {
        Target::container(Shell::Dash)
    }
    rows_for!(docker make; acl_indicator_refused, foreign_owned_registry_refused);
}

/// bash 5.2 as `/bin/sh` (U11's shell-container row, built locally).
#[cfg(all(unix, debug_assertions))]
mod docker_bash_sh {
    use crate::harness::{Shell, Target};
    fn make() -> Target {
        Target::container(Shell::BashSh)
    }
    protocol_rows!(docker make);
    fencing_rows!(docker make);
    rows_for!(docker make;
        foreign_owned_registry_refused,
        group_probe_permission_failure_is_unproven,
        procstat_fixtures_rust_and_awk_agree,
        procstat_live_comm_fixtures_per_linux_shell,
    );
}

/// BusyBox 1.37.0 `ash` with BusyBox `ps` (U11's shell-container row, built locally).
#[cfg(all(unix, debug_assertions))]
mod docker_busybox {
    use crate::harness::{Shell, Target};
    fn make() -> Target {
        Target::container(Shell::BusyBox)
    }
    protocol_rows!(docker make);
    fencing_rows!(docker make);
    rows_for!(docker make;
        foreign_owned_registry_refused,
        group_probe_permission_failure_is_unproven,
        procstat_fixtures_rust_and_awk_agree,
        procstat_live_comm_fixtures_per_linux_shell,
        busybox_fence_always_unproven_manual_recovery,
        busybox_append_and_remove_run_with_proc_process_group,
    );
}
