//! Disposable shell containers and probe shims (m03-plan U11 `shells`; ADR-0008 D13
//! item 2 ⟨r4⟩, §17.7 item 1, §17.9 item 5). Feature `fixtures`.
//!
//! [`ShellContainers`] are two disposable Docker containers on the build host, for the
//! per-shell fencing rows no sshd target covers:
//! * **bash as `sh`**: [`DEBIAN_BASE`] with `procps` added at build time (the network
//!   is attached only to that `docker build` step) and `/bin/sh` pointed at bash
//!   (image [`DEBIAN_IMAGE`], labelled `heimdall.fixture=m03-shells`);
//! * **BusyBox `ash`**: [`ALPINE_BASE`] as is (BusyBox `ash`, `ps`, `kill`).
//!
//! Each container runs with `--network none` (no listener, no egress), `--cap-drop
//! ALL` (so root inside cannot signal another account's processes: the permission
//! failure case), `no-new-privileges`, pid and memory limits, `--init` (which reaps a
//! killed holder), the label `heimdall.fixture=m03-shells`, and a per-run name; it is
//! removed by that exact name on drop (`docker rm -f <name>`). `down.sh` removes any
//! leftover container and the built image by label.
//!
//! A script runs **directly under the shell, in a session made with `setsid`**
//! ([`ShellContainer::run_script`]): a wrapper `sh -c` (not a group leader) starts
//! `setsid /bin/sh -s` in the background with the original stdin and waits for it, so
//! the script's shell leads its own session and process group (`$$` is its group, as
//! under sshd) and its exit status is kept (BusyBox `setsid` has no `-w`).
//!
//! [`ProbeShim`] (⟨r4⟩): a wrapper shell whose `kill` rejects the POSIX group probe
//! `kill -s 0 -- -PGID` (a syntax error, so the control fails), and a `ps` shim whose
//! `ps -A -o pgid=` listing disagrees with the probe (a group hidden or added).

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use crate::agent::random_hex;
use crate::home::{Scratch, find_program};
use crate::registry::{
    Finished, PauseHooks, PrefixRun, docker_exec_run, docker_exec_spawn, finish, is_container_name,
    is_plain_absolute,
};

/// The Debian 13 base the round-4 re-check used (pinned by digest; MANIFEST row 21).
pub const DEBIAN_BASE: &str =
    "debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308";
/// The Alpine base the round-4 re-check used (pinned by digest; MANIFEST row 22).
pub const ALPINE_BASE: &str =
    "alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a";
/// The image built from [`DEBIAN_BASE`] (procps added, `/bin/sh` → bash).
pub const DEBIAN_IMAGE: &str = "heimdall-m03-shell-debian:local";
/// The value of the `heimdall.fixture` label on the shell image and containers.
pub const LABEL_VALUE: &str = "m03-shells";
/// The name prefix of every shell container.
pub const NAME_PREFIX: &str = "hm-m03-shell-";

/// The Dockerfile of [`DEBIAN_IMAGE`]: the only step with a network.
pub const DEBIAN_DOCKERFILE: &str = "\
# Heimdall M03 shell fixture (m03-plan U11 ShellContainers): bash as sh, procps ps.
FROM debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308
LABEL heimdall.fixture=\"m03-shells\"
RUN apt-get update \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends procps \\
 && rm -rf /var/lib/apt/lists/* \\
 && ln -sf bash /bin/sh
";

/// The wrapper that gives a script its own session (see the module documentation).
const SETSID_WRAPPER: &str = "exec 3<&0; setsid /bin/sh -s <&3 3<&- & wait \"$!\"";

/// Which shell a container runs as `/bin/sh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShellKind {
    /// bash 5.2 as `sh` on Debian 13 (procps `ps`).
    BashAsSh,
    /// BusyBox 1.37 `ash` on Alpine (BusyBox `ps`).
    BusyBoxAsh,
}

impl ShellKind {
    /// Both kinds.
    pub const ALL: [ShellKind; 2] = [ShellKind::BashAsSh, ShellKind::BusyBoxAsh];

    /// A short name (`bash-as-sh`, `busybox-ash`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ShellKind::BashAsSh => "bash-as-sh",
            ShellKind::BusyBoxAsh => "busybox-ash",
        }
    }

    fn image(self) -> &'static str {
        match self {
            ShellKind::BashAsSh => DEBIAN_IMAGE,
            ShellKind::BusyBoxAsh => ALPINE_BASE,
        }
    }
}

/// The shell containers cannot run here (no Docker, or the image cannot be built).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellsUnavailable {
    /// Why (no path or user name).
    pub reason: String,
}

impl fmt::Display for ShellsUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shell containers unavailable: {}", self.reason)
    }
}

impl std::error::Error for ShellsUnavailable {}

fn unavailable(reason: impl Into<String>) -> ShellsUnavailable {
    ShellsUnavailable {
        reason: reason.into(),
    }
}

/// One disposable shell container. Removed by its exact name on drop.
#[derive(Debug)]
pub struct ShellContainer {
    kind: ShellKind,
    name: String,
}

/// The two shell containers of a run.
#[derive(Debug)]
pub struct ShellContainers {
    /// bash as `sh` (Debian 13).
    pub bash: ShellContainer,
    /// BusyBox `ash` (Alpine).
    pub busybox: ShellContainer,
}

/// Serializes image builds within this process.
static BUILD: Mutex<()> = Mutex::new(());

fn docker() -> Result<PathBuf, ShellsUnavailable> {
    find_program("docker").ok_or_else(|| unavailable("docker is not installed"))
}

fn quiet(cmd: &mut Command) -> io::Result<bool> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
}

/// Build [`DEBIAN_IMAGE`] unless it exists (the network is attached only to this
/// build; the context is a fresh scratch directory holding only the Dockerfile).
///
/// # Errors
/// [`ShellsUnavailable`].
pub fn ensure_images() -> Result<(), ShellsUnavailable> {
    let docker = docker()?;
    let _build = BUILD.lock().unwrap_or_else(|e| e.into_inner());
    if !quiet(Command::new(&docker).args(["info"])).unwrap_or(false) {
        return Err(unavailable("the docker daemon is unavailable"));
    }
    for base in [DEBIAN_BASE, ALPINE_BASE] {
        let present =
            quiet(Command::new(&docker).args(["image", "inspect", base])).unwrap_or(false);
        if !present && !quiet(Command::new(&docker).args(["pull", base])).unwrap_or(false) {
            return Err(unavailable("a pinned base image cannot be pulled"));
        }
    }
    if quiet(Command::new(&docker).args(["image", "inspect", DEBIAN_IMAGE])).unwrap_or(false) {
        return Ok(());
    }
    let ctx = Scratch::new().map_err(|e| unavailable(format!("build context: {:?}", e.kind())))?;
    fs::write(ctx.path().join("Dockerfile"), DEBIAN_DOCKERFILE)
        .map_err(|e| unavailable(format!("build context: {:?}", e.kind())))?;
    let built = quiet(
        Command::new(&docker)
            .args([
                "build",
                "-q",
                "--label",
                &format!("heimdall.fixture={LABEL_VALUE}"),
                "-t",
                DEBIAN_IMAGE,
            ])
            .arg(ctx.path()),
    )
    .unwrap_or(false);
    if built {
        Ok(())
    } else {
        Err(unavailable("docker build of the bash-as-sh image failed"))
    }
}

impl ShellContainers {
    /// Ensure the images and start both containers.
    ///
    /// # Errors
    /// [`ShellsUnavailable`].
    pub fn start() -> Result<ShellContainers, ShellsUnavailable> {
        ensure_images()?;
        let bash = ShellContainer::start(ShellKind::BashAsSh)?;
        let busybox = ShellContainer::start(ShellKind::BusyBoxAsh)?;
        Ok(ShellContainers { bash, busybox })
    }

    /// Both containers, bash first.
    #[must_use]
    pub fn each(&self) -> [&ShellContainer; 2] {
        [&self.bash, &self.busybox]
    }
}

impl ShellContainer {
    /// Start one container of `kind` (its image must exist: [`ensure_images`]).
    ///
    /// # Errors
    /// [`ShellsUnavailable`].
    pub fn start(kind: ShellKind) -> Result<ShellContainer, ShellsUnavailable> {
        let docker = docker()?;
        let name = format!("{NAME_PREFIX}{}-{}", kind.name(), random_hex(6));
        let started = quiet(Command::new(&docker).args([
            "run",
            "-d",
            "--name",
            &name,
            "--label",
            &format!("heimdall.fixture={LABEL_VALUE}"),
            "--label",
            &format!("heimdall.fixture.role=shell-{}", kind.name()),
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "256",
            "--memory",
            "256m",
            "--init",
            kind.image(),
            "tail",
            "-f",
            "/dev/null",
        ]))
        .unwrap_or(false);
        let container = ShellContainer { kind, name };
        if started {
            Ok(container)
        } else {
            // Drop removes a half-created container by its exact name.
            Err(unavailable("docker run of a shell container failed"))
        }
    }

    /// The shell kind.
    #[must_use]
    pub fn kind(&self) -> ShellKind {
        self.kind
    }

    /// The container's exact name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `docker exec <name> <args>` (no stdin), bounded by `timeout`.
    ///
    /// # Errors
    /// The docker client cannot start.
    pub fn exec(&self, args: &[&str], timeout: Duration) -> io::Result<Finished> {
        docker_exec_run(&self.name, args, None, &[], timeout)
    }

    /// `docker exec -u <user> <name> <args>`, bounded by `timeout`.
    ///
    /// # Errors
    /// The docker client cannot start.
    pub fn exec_as(&self, user: &str, args: &[&str], timeout: Duration) -> io::Result<Finished> {
        let child = docker_exec_spawn(&self.name, args, false, Some(user), &[])?;
        finish(child, None, timeout)
    }

    /// Run `script` as `setsid /bin/sh -s` (see the module documentation) with `env`,
    /// bounded by `timeout`.
    ///
    /// # Errors
    /// The docker client cannot start.
    pub fn run_script(
        &self,
        script: &[u8],
        env: &[(&str, &str)],
        timeout: Duration,
    ) -> io::Result<Finished> {
        docker_exec_run(
            &self.name,
            &["/bin/sh", "-c", SETSID_WRAPPER],
            Some(script),
            env,
            timeout,
        )
    }

    /// [`Self::run_script`] in the background (for a paused holder); `user` runs it as
    /// another account (the permission-failure case).
    ///
    /// # Errors
    /// The docker client cannot start.
    pub fn spawn_script(
        &self,
        script: &[u8],
        env: &[(&str, &str)],
        user: Option<&str>,
    ) -> io::Result<RunningScript> {
        let mut child = docker_exec_spawn(
            &self.name,
            &["/bin/sh", "-c", SETSID_WRAPPER],
            true,
            user,
            env,
        )?;
        if let Some(mut pipe) = child.stdin.take() {
            use std::io::Write;
            let bytes = script.to_vec();
            std::thread::spawn(move || {
                let _ = pipe.write_all(&bytes);
            });
        }
        Ok(RunningScript { child: Some(child) })
    }

    /// Write `bytes` to `path` inside the container (`cat > path`), then `chmod mode`.
    ///
    /// # Errors
    /// A bad path, or the write failed.
    pub fn write_file(&self, path: &str, bytes: &[u8], mode: &str) -> io::Result<()> {
        if !is_plain_absolute(path) || !mode.bytes().all(|b| b.is_ascii_digit()) {
            return Err(io::Error::other("bad path or mode"));
        }
        let run = docker_exec_run(
            &self.name,
            &[
                "/bin/sh",
                "-c",
                "cat > \"$1\" && chmod \"$2\" \"$1\"",
                "sh",
                path,
                mode,
            ],
            Some(bytes),
            &[],
            Duration::from_secs(60),
        )?;
        if run.status == Some(0) {
            Ok(())
        } else {
            Err(io::Error::other("writing a file in the container failed"))
        }
    }

    /// Read `path` inside the container.
    ///
    /// # Errors
    /// A bad path, or the read failed.
    pub fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
        if !is_plain_absolute(path) {
            return Err(io::Error::other("bad path"));
        }
        let run = self.exec(&["cat", path], Duration::from_secs(60))?;
        if run.status == Some(0) {
            Ok(run.stdout)
        } else {
            Err(io::Error::other("reading a file in the container failed"))
        }
    }

    /// Send `signal` (`STOP`, `CONT`, `TERM`, `KILL`) to process group `group` inside the
    /// container, with the shell's `kill -s <SIG> -<group>` (which BusyBox accepts; it
    /// rejects `--`).
    ///
    /// # Errors
    /// As [`signal_container_group`].
    pub fn signal_group(&self, group: u32, signal: &str) -> io::Result<()> {
        signal_container_group(&self.name, group, signal)
    }

    /// Pause hooks whose directory is `dir` inside this container.
    ///
    /// # Errors
    /// As [`PauseHooks::in_container`].
    pub fn pause_hooks(&self, dir: &str) -> io::Result<PauseHooks> {
        PauseHooks::in_container(&self.name, dir)
    }

    /// Feed every prefix of `script` (`0..=len` bytes) to `setsid /bin/sh -s` inside
    /// the container, in one `docker exec` (the loop runs in the container), with
    /// `env`. Each prefix's stdout comes back hex-encoded; its stderr is not kept.
    ///
    /// # Errors
    /// The docker client failed, or the loop's report is malformed.
    pub fn run_prefixes(
        &self,
        script: &[u8],
        env: &[(&str, &str)],
        timeout: Duration,
    ) -> io::Result<Vec<PrefixRun>> {
        let dir = format!("/tmp/hm-trunc-{}", random_hex(6));
        let file = format!("{dir}/script");
        let mk = self.exec(&["mkdir", "-p", &dir], Duration::from_secs(30))?;
        if mk.status != Some(0) {
            return Err(io::Error::other("mkdir in the container failed"));
        }
        self.write_file(&file, script, "600")?;
        let len = script.len().to_string();
        // For each n: the first n bytes into a prefix file, run under its own session,
        // report `HMT <n> <exit> <stdout hex>`.
        let looped = "\
            n=0; while [ \"$n\" -le \"$2\" ]; do \
              head -c \"$n\" \"$1\" > \"$1.p\"; \
              ( exec 3<\"$1.p\"; setsid /bin/sh -s <&3 3<&- > \"$1.o\" 2>/dev/null & wait \"$!\" ); s=$?; \
              printf 'HMT %s %s ' \"$n\" \"$s\"; od -An -v -tx1 \"$1.o\" | tr -d ' \\n'; printf '\\n'; \
              n=$((n + 1)); \
            done";
        let run = docker_exec_run(
            &self.name,
            &["/bin/sh", "-c", looped, "sh", &file, &len],
            None,
            env,
            timeout,
        )?;
        let _ = self.exec(&["rm", "-rf", &dir], Duration::from_secs(30));
        if run.status != Some(0) {
            return Err(io::Error::other("the prefix loop failed"));
        }
        parse_prefix_report(&run.stdout, script.len())
    }
}

/// Parse `HMT <n> <exit> <hex>` lines (one per prefix, in order).
fn parse_prefix_report(stdout: &[u8], len: usize) -> io::Result<Vec<PrefixRun>> {
    let bad = || io::Error::other("malformed prefix report");
    let text = String::from_utf8_lossy(stdout);
    let mut runs = Vec::new();
    for line in text.lines() {
        let mut f = line.split(' ');
        if f.next() != Some("HMT") {
            continue;
        }
        let n: usize = f.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
        let status: i32 = f.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
        let hex = f.next().unwrap_or("");
        let stdout = decode_hex(hex).ok_or_else(bad)?;
        runs.push(PrefixRun {
            len: n,
            status: Some(status),
            stdout,
            stderr: Vec::new(),
        });
    }
    if runs.len() != len + 1 || runs.iter().enumerate().any(|(i, r)| r.len != i) {
        return Err(bad());
    }
    Ok(runs)
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

impl Drop for ShellContainer {
    fn drop(&mut self) {
        if let Some(docker) = find_program("docker")
            && is_container_name(&self.name)
        {
            let _ = quiet(Command::new(docker).args(["rm", "-f", "--", &self.name]));
        }
    }
}

/// `kill -s <SIG> -<group>` inside `container` (group ≥ 2; `SIG` one of `STOP`,
/// `CONT`, `TERM`, `KILL`, `0`).
///
/// # Errors
/// A refused group or signal, or the kill failed.
pub fn signal_container_group(container: &str, group: u32, signal: &str) -> io::Result<()> {
    if group < 2 || !matches!(signal, "STOP" | "CONT" | "TERM" | "KILL" | "0") {
        return Err(io::Error::other("refused group or signal"));
    }
    let run = docker_exec_run(
        container,
        &[
            "/bin/sh",
            "-c",
            "kill -s \"$1\" -\"$2\"",
            "sh",
            signal,
            &group.to_string(),
        ],
        None,
        &[],
        Duration::from_secs(30),
    )?;
    if run.status == Some(0) {
        Ok(())
    } else {
        Err(io::Error::other("kill in the container failed"))
    }
}

/// A script started with [`ShellContainer::spawn_script`]. Dropping it kills the
/// docker client by its exact handle (the in-container processes go with the
/// container).
#[derive(Debug)]
pub struct RunningScript {
    child: Option<Child>,
}

impl RunningScript {
    /// Wait up to `timeout` for the script's docker client.
    ///
    /// # Errors
    /// The wait failed.
    pub fn wait(mut self, timeout: Duration) -> io::Result<Finished> {
        let child = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("already waited"))?;
        finish(child, None, timeout)
    }
}

impl Drop for RunningScript {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take()
            && !matches!(child.try_wait(), Ok(Some(_)))
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// --- probe shims --------------------------------------------------------------------------------

/// What the `ps` shim's `ps -A -o pgid=` listing does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listing {
    /// The real listing.
    PassThrough,
    /// The real listing without the group (the probe says live, the listing empty).
    Hide(u32),
    /// The real listing plus the group (the probe says empty, the listing live).
    Add(u32),
}

/// The rejecting wrapper shell: it reads the whole script, defines a `kill` function
/// that rejects `kill -s 0 -- -<n>` like dash's `kill -0 -- -<n>` ("Illegal number"),
/// and evaluates the script in the same process (so `$$` is unchanged).
fn rejecting_shell_text(real_sh: &str) -> String {
    format!(
        "#!{real_sh}\n\
         # Heimdall fixture ProbeShim (m03-plan U11): a shell whose kill rejects the\n\
         # POSIX group probe syntax, so the control fails (unproven).\n\
         hm_shim_script=$(cat; printf x); hm_shim_script=${{hm_shim_script%x}}\n\
         kill() {{\n\
         \x20 case \"$*\" in\n\
         \x20   '-s 0 -- -'*) printf '%s\\n' 'kill: Illegal number: -' >&2; return 2 ;;\n\
         \x20 esac\n\
         \x20 command kill \"$@\"\n\
         }}\n\
         eval \"$hm_shim_script\"\n"
    )
}

/// The `ps` shim: `ps -A -o pgid=` is post-processed per the mode file next to it;
/// every other invocation is the real `ps`.
fn ps_shim_text(real_ps: &str, mode_file: &str) -> String {
    format!(
        "#!/bin/sh\n\
         # Heimdall fixture ProbeShim (m03-plan U11): a ps whose group listing disagrees.\n\
         if [ \"$*\" = '-A -o pgid=' ] && [ -f '{mode_file}' ]; then\n\
         \x20 read hm_mode hm_group < '{mode_file}'\n\
         \x20 '{real_ps}' -A -o pgid= > \"${{TMPDIR:-/tmp}}/hm-ps-shim.$$\"; hm_s=$?\n\
         \x20 case \"$hm_mode\" in\n\
         \x20   hide) awk -v g=\"$hm_group\" '{{ v = $1 }} v != g {{ print }}' \"${{TMPDIR:-/tmp}}/hm-ps-shim.$$\" ;;\n\
         \x20   add) cat \"${{TMPDIR:-/tmp}}/hm-ps-shim.$$\"; printf '%s\\n' \"$hm_group\" ;;\n\
         \x20   *) cat \"${{TMPDIR:-/tmp}}/hm-ps-shim.$$\" ;;\n\
         \x20 esac\n\
         \x20 rm -f \"${{TMPDIR:-/tmp}}/hm-ps-shim.$$\"\n\
         \x20 exit \"$hm_s\"\n\
         fi\n\
         exec '{real_ps}' \"$@\"\n"
    )
}

#[derive(Debug)]
enum ShimHost {
    Local,
    Container(String),
}

/// The probe shims of one run (see the module documentation). Paths are plain
/// (no quote characters), so they can be single-quoted in the shims.
#[derive(Debug)]
pub struct ProbeShim {
    host: ShimHost,
    dir: String,
}

impl ProbeShim {
    /// Shims in a fresh scratch directory on this host (`<dir>/shell/sh` and
    /// `<dir>/bin/ps`; `/bin/sh` and the host's `ps` are the real programs).
    ///
    /// # Errors
    /// The scratch path holds a quote, `ps` is not found, or a write failed.
    pub fn local(scratch: &Scratch) -> io::Result<ProbeShim> {
        let dir = scratch.subdir("shim")?;
        let text = dir
            .to_str()
            .filter(|t| !t.contains('\'') && !t.contains('"'))
            .ok_or_else(|| io::Error::other("the scratch path cannot be quoted"))?
            .to_owned();
        let real_ps = find_program("ps").ok_or_else(|| io::Error::other("ps not found"))?;
        let shim = ProbeShim {
            host: ShimHost::Local,
            dir: text,
        };
        fs::create_dir(dir.join("shell"))?;
        fs::create_dir(dir.join("bin"))?;
        write_executable(&dir.join("shell/sh"), &rejecting_shell_text("/bin/sh"))?;
        write_executable(
            &dir.join("bin/ps"),
            &ps_shim_text(&real_ps.to_string_lossy(), &shim.mode_file()),
        )?;
        shim.set_listing(Listing::PassThrough)?;
        Ok(shim)
    }

    /// Shims in `dir` inside a shell container (a plain absolute path, created).
    ///
    /// # Errors
    /// A bad path, or a write in the container failed.
    pub fn in_container(container: &ShellContainer, dir: &str) -> io::Result<ProbeShim> {
        if !is_plain_absolute(dir) || dir.contains('\'') || dir.contains('"') {
            return Err(io::Error::other("bad shim directory"));
        }
        let mk = container.exec(
            &[
                "mkdir",
                "-p",
                &format!("{dir}/shell"),
                &format!("{dir}/bin"),
            ],
            Duration::from_secs(30),
        )?;
        if mk.status != Some(0) {
            return Err(io::Error::other("mkdir in the container failed"));
        }
        let found = container.exec(&["/bin/sh", "-c", "command -v ps"], Duration::from_secs(30))?;
        let real_ps = String::from_utf8_lossy(&found.stdout).trim().to_owned();
        if found.status != Some(0) || !is_plain_absolute(&real_ps) {
            return Err(io::Error::other("ps not found in the container"));
        }
        let shim = ProbeShim {
            host: ShimHost::Container(container.name().to_owned()),
            dir: dir.to_owned(),
        };
        container.write_file(
            &format!("{dir}/shell/sh"),
            rejecting_shell_text("/bin/sh").as_bytes(),
            "755",
        )?;
        container.write_file(
            &format!("{dir}/bin/ps"),
            ps_shim_text(&real_ps, &shim.mode_file()).as_bytes(),
            "755",
        )?;
        shim.set_listing(Listing::PassThrough)?;
        Ok(shim)
    }

    fn mode_file(&self) -> String {
        format!("{}/bin/ps.mode", self.dir)
    }

    /// The rejecting wrapper shell (run a script as `<it> -s`, or feed it stdin).
    #[must_use]
    pub fn shell(&self) -> String {
        format!("{}/shell/sh", self.dir)
    }

    /// The directory holding the `ps` shim (put it first on `PATH`).
    #[must_use]
    pub fn ps_dir(&self) -> String {
        format!("{}/bin", self.dir)
    }

    /// `<ps_dir>:/usr/bin:/bin:/usr/sbin:/sbin`.
    #[must_use]
    pub fn path_env(&self) -> String {
        format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", self.ps_dir())
    }

    /// Set what the listing does from now on.
    ///
    /// # Errors
    /// The mode file cannot be written.
    pub fn set_listing(&self, listing: Listing) -> io::Result<()> {
        let text = match listing {
            Listing::PassThrough => "pass 0\n".to_owned(),
            Listing::Hide(g) => format!("hide {g}\n"),
            Listing::Add(g) => format!("add {g}\n"),
        };
        match &self.host {
            ShimHost::Local => fs::write(self.mode_file(), text),
            ShimHost::Container(name) => {
                let run = docker_exec_run(
                    name,
                    &["/bin/sh", "-c", "cat > \"$1\"", "sh", &self.mode_file()],
                    Some(text.as_bytes()),
                    &[],
                    Duration::from_secs(30),
                )?;
                if run.status == Some(0) {
                    Ok(())
                } else {
                    Err(io::Error::other("writing the ps mode failed"))
                }
            }
        }
    }
}

fn write_executable(path: &Path, text: &str) -> io::Result<()> {
    fs::write(path, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_report_parses_and_checks_order() {
        let out = b"HMT 0 0 \nHMT 1 2 6869\n";
        let runs = parse_prefix_report(out, 1).unwrap();
        assert_eq!(runs[1].stdout, b"hi");
        assert_eq!(runs[1].status, Some(2));
        assert!(parse_prefix_report(b"HMT 1 0 \n", 0).is_err());
        assert!(parse_prefix_report(b"HMT 0 0 zz\n", 0).is_err());
    }

    #[test]
    fn shim_texts_name_the_real_programs() {
        let sh = rejecting_shell_text("/bin/sh");
        assert!(sh.starts_with("#!/bin/sh\n"));
        assert!(sh.contains("'-s 0 -- -'*"));
        let ps = ps_shim_text("/bin/ps", "/s/bin/ps.mode");
        assert!(ps.contains("exec '/bin/ps' \"$@\""));
        assert!(DEBIAN_DOCKERFILE.contains(DEBIAN_BASE));
    }
}
