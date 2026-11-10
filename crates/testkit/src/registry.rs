//! Registry fixtures (m03-plan U11 `registry`; ADR-0008 D13 items 3 and 4, D5 §6.3).
//! Feature `fixtures`.
//!
//! * [`RegistryGuard`]: every enrollment a test runs must target a registry under the
//!   run's scratch directory, inside a disposable Docker container labelled
//!   `heimdall.fixture`, or inside the disposable WSL distribution. Anything else is
//!   [`FixtureUnsafe`] **before any `ssh` runs** (m03-plan §0.2).
//! * [`PauseHooks`]: the concurrent-writer pause points of the test configuration
//!   (`HM_PAUSE <name>`; ADR-0008 D13 item 3): FIFOs in a scratch directory (or inside a
//!   shell container), [`PauseHooks::wait_at`], [`PauseHooks::release`], and
//!   [`PauseHooks::stop_holder`] / [`PauseHooks::continue_holder`] (SIGSTOP / SIGCONT of
//!   the paused script's exact process group).
//! * [`Truncation`]: feeds every prefix of a script to a target shell (ADR-0008 D5
//!   §6.3 "A truncated script does nothing").
//!
//! # The pause protocol (U5-scripts' test form; the verifier's `nonce_known` likewise)
//!
//! The pause directory `D` is `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` (absolute; test
//! configuration only). A test **arms** a hook `N` by creating the FIFO `D/N`
//! ([`PauseHooks::arm`]). At an armed point (`HM_PAUSE N`; `heimdall_registry::script::
//! test_form`) the paused party:
//!
//! 1. writes its report: scripts write `$$` and a newline to `D/N.pid` (`>|`); the
//!    verifier's `nonce_known` writes the 32-hex nonce to `D/N.nonce`;
//! 2. opens `D/N` for reading and reads to end-of-file (`cat D/N > /dev/null`, a child
//!    in the script's process group);
//! 3. continues.
//!
//! [`PauseHooks::wait_at`] opens the FIFO's write end (which succeeds once the reader is
//! there), holds it and reads the report files; [`PauseHooks::release`] closes it. A
//! point whose `D/N` is not a FIFO is a no-op, so a test arms only the hooks it needs.
//! [`pause_snippet`] is an equivalent POSIX `sh` point for fixture scripts that are not
//! U5's. A point may be reached more than once; each reach needs one `wait_at` and one
//! `release`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::home::{GuardScope, Scratch, find_program};

/// The label every disposable fixture container carries (M00-T03, m03-plan §0.2).
pub const FIXTURE_LABEL: &str = "heimdall.fixture";

/// The variable a harness sets to the disposable WSL distribution's name (outside it).
/// Inside it, WSL itself sets `WSL_DISTRO_NAME`.
pub const WSL_DISTRO_ENV: &str = "HM_FIXTURE_WSL_DISTRO";

/// The test-configuration variable naming the pause directory
/// (`heimdall::testcfg::SCRIPT_PAUSE_DIR_ENV`).
pub const PAUSE_DIR_ENV: &str = "HEIMDALL_TEST_SCRIPT_PAUSE_DIR";

/// The default bound of [`PauseHooks::wait_at`] and [`PauseHooks::release`].
pub const PAUSE_WAIT: Duration = Duration::from_secs(30);

/// The pause points of ADR-0008 D5 §6.3 and D13 item 3.
pub mod hook {
    /// After the lock link is taken.
    pub const AFTER_LOCK: &str = "after_lock";
    /// Between the final re-check and the write.
    pub const BEFORE_WRITE: &str = "before_write";
    /// Before `ln -s` takes the lock.
    pub const BEFORE_LN: &str = "before_ln";
    /// Once a verification's negative nonce exists (the verifier, not a script).
    pub const NONCE_KNOWN: &str = "nonce_known";
    /// `bootstrap`: before its `mkdir` (U5-scripts' test form).
    pub const BEFORE_MKDIR: &str = "before_mkdir";
    /// `fence --terminate`: after TERM (U5-scripts' test form).
    pub const AFTER_TERM: &str = "after_term";
    /// `fence --terminate`: after KILL (U5-scripts' test form).
    pub const AFTER_KILL: &str = "after_kill";
    /// Every named point.
    pub const ALL: [&str; 7] = [
        AFTER_LOCK,
        BEFORE_WRITE,
        BEFORE_LN,
        NONCE_KNOWN,
        BEFORE_MKDIR,
        AFTER_TERM,
        AFTER_KILL,
    ];
}

// --- the registry guard ------------------------------------------------------------------

/// Why the registry guard refused a target. Messages carry no path. (Distinct from
/// [`crate::home::FixtureUnsafe`], the M02 default-identity guard's refusal.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureUnsafe {
    /// The path is not lexically and canonically under the run's scratch directory.
    NotScratch,
    /// The path is not absolute UTF-8 without `.`/`..` components.
    BadPath,
    /// The container name is not a plain token.
    BadContainerName,
    /// The container does not exist, is not running, or lacks the `heimdall.fixture`
    /// label.
    ContainerNotFixture,
    /// The distribution is not the run's disposable WSL distribution.
    WslNotDisposable,
}

impl fmt::Display for FixtureUnsafe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FixtureUnsafe::NotScratch => {
                "fixture unsafe: the registry is not under the run's scratch directory"
            }
            FixtureUnsafe::BadPath => {
                "fixture unsafe: the registry path is not a plain absolute path"
            }
            FixtureUnsafe::BadContainerName => "fixture unsafe: the container name is not a token",
            FixtureUnsafe::ContainerNotFixture => {
                "fixture unsafe: the container is not a running, labelled fixture container"
            }
            FixtureUnsafe::WslNotDisposable => {
                "fixture unsafe: the distribution is not the disposable WSL distribution"
            }
        })
    }
}

impl std::error::Error for FixtureUnsafe {}

/// Where an enrollment under test writes its registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryTarget<'a> {
    /// A registry on this host (loopback sshd, explicit `--registry-path`).
    Path(&'a Path),
    /// A registry inside a Docker container (an in-container absolute path).
    Container {
        /// The container's exact name.
        name: &'a str,
        /// The registry path inside it.
        path: &'a str,
    },
    /// A registry inside a WSL distribution (a path inside it).
    Wsl {
        /// The distribution's name.
        distribution: &'a str,
        /// The registry path inside it.
        path: &'a str,
    },
}

/// The registry guard (ADR-0008 D13 item 4). See the module documentation.
#[derive(Debug, Clone)]
pub struct RegistryGuard {
    scope: GuardScope,
    wsl: Vec<String>,
}

/// `hm-m0<digit>-<lowercase alphanumerics and dashes>`: the disposable distributions'
/// names (`tests/native/m02/run-wsl-distro.sh`).
fn is_disposable_distro_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("hm-m0") else {
        return false;
    };
    let mut chars = rest.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_digit()) || chars.next() != Some('-') {
        return false;
    }
    let tail: String = chars.collect();
    !tail.is_empty()
        && tail.len() <= 48
        && tail
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A container name Docker accepts and that needs no quoting.
pub(crate) fn is_container_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// An absolute path text without `.`/`..` components or control characters.
pub(crate) fn is_plain_absolute(path: &str) -> bool {
    path.starts_with('/')
        && !path.chars().any(char::is_control)
        && !Path::new(path)
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
}

impl RegistryGuard {
    /// The guard of one run: its scratch root, plus the disposable WSL distribution
    /// the harness names ([`WSL_DISTRO_ENV`]) or WSL reports from inside it
    /// (`WSL_DISTRO_NAME`), when that name is a disposable one.
    ///
    /// # Errors
    /// The scratch root cannot be canonicalized.
    pub fn new(scratch: &Scratch) -> io::Result<RegistryGuard> {
        let mut wsl = Vec::new();
        for var in [WSL_DISTRO_ENV, "WSL_DISTRO_NAME"] {
            if let Ok(name) = std::env::var(var)
                && is_disposable_distro_name(&name)
                && !wsl.contains(&name)
            {
                wsl.push(name);
            }
        }
        Ok(RegistryGuard {
            scope: GuardScope::new(scratch.path())?,
            wsl,
        })
    }

    /// Check `target` before any `ssh` runs.
    ///
    /// * a path must be absolute UTF-8 without `.`/`..`, lexically under the scratch
    ///   root, and (where it or an ancestor exists) canonically under it (no symlink
    ///   out);
    /// * a container must be a plain name of a **running** container carrying the
    ///   `heimdall.fixture` label (read with `docker inspect`; nothing else runs), and
    ///   the path a plain absolute path;
    /// * a WSL distribution must be the run's disposable distribution.
    ///
    /// # Errors
    /// [`FixtureUnsafe`].
    pub fn check(&self, target: &RegistryTarget<'_>) -> Result<(), FixtureUnsafe> {
        match *target {
            RegistryTarget::Path(path) => {
                let text = path.to_str().ok_or(FixtureUnsafe::BadPath)?;
                if !is_plain_absolute(text) {
                    return Err(FixtureUnsafe::BadPath);
                }
                if self.scope.is_scratch_path(text) {
                    Ok(())
                } else {
                    Err(FixtureUnsafe::NotScratch)
                }
            }
            RegistryTarget::Container { name, path } => {
                if !is_container_name(name) {
                    return Err(FixtureUnsafe::BadContainerName);
                }
                if !is_plain_absolute(path) {
                    return Err(FixtureUnsafe::BadPath);
                }
                if container_is_running_fixture(name) {
                    Ok(())
                } else {
                    Err(FixtureUnsafe::ContainerNotFixture)
                }
            }
            RegistryTarget::Wsl { distribution, path } => {
                if !is_plain_absolute(path) {
                    return Err(FixtureUnsafe::BadPath);
                }
                if is_disposable_distro_name(distribution)
                    && self.wsl.iter().any(|d| d == distribution)
                {
                    Ok(())
                } else {
                    Err(FixtureUnsafe::WslNotDisposable)
                }
            }
        }
    }
}

/// `docker inspect` of exactly `name`: running and labelled `heimdall.fixture`.
fn container_is_running_fixture(name: &str) -> bool {
    let Some(docker) = find_program("docker") else {
        return false;
    };
    let format = format!("{{{{.State.Running}}}} {{{{index .Config.Labels \"{FIXTURE_LABEL}\"}}}}");
    let Ok(out) = Command::new(docker)
        .args([
            "inspect",
            "--type",
            "container",
            "--format",
            &format,
            "--",
            name,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut f = text.split_whitespace();
    out.status.success() && f.next() == Some("true") && f.next().is_some_and(|l| !l.is_empty())
}

// --- pause hooks -------------------------------------------------------------------------

/// A POSIX `sh` pause point equivalent to U5's test-form `HM_PAUSE <name>` (see the module
/// documentation), for fixture scripts that are not U5's.
#[must_use]
pub fn pause_snippet(dir: &str, name: &str) -> String {
    let base = format!("{dir}/{name}");
    format!(
        "if [ -p '{base}' ]; then printf '%s\\n' \"$$\" >| '{base}.pid'; cat '{base}' > /dev/null; fi"
    )
}

/// What a paused party reported on arrival.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reached {
    /// The hook.
    pub name: String,
    /// The report files' contents, by suffix: `pid` (`<dir>/<name>.pid`, a script's
    /// `$$`) and `nonce` (`<dir>/<name>.nonce`, the verifier's `nonce_known`).
    pub fields: BTreeMap<String, String>,
    /// `pid` parsed (never 0 or 1).
    pub pid: Option<u32>,
    /// The process group of `pid`, read when the arrival was seen (local: `getpgid`;
    /// container: field 5 of `/proc/<pid>/stat` through the shared parser).
    pub process_group: Option<u32>,
}

/// The process group a [`PauseHooks`] signals: the last arrival's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HolderGroup {
    /// The script's `$$`.
    pub pid: u32,
    /// Its process group (equal to `pid` for a group leader).
    pub process_group: u32,
}

#[derive(Debug, Clone)]
enum Backend {
    Local(PathBuf),
    Container { name: String, dir: String },
}

/// The write end the test holds while a party is paused.
#[derive(Debug)]
enum Held {
    Local(fs::File),
    Container(Child),
}

/// The pause points of one run (see the module documentation).
#[derive(Debug)]
pub struct PauseHooks {
    backend: Backend,
    holder: Mutex<Option<HolderGroup>>,
    held: Mutex<BTreeMap<String, Held>>,
}

fn check_name(name: &str) -> io::Result<()> {
    if !name.is_empty()
        && name.len() <= 32
        && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
    {
        Ok(())
    } else {
        Err(io::Error::other("pause hook names are [a-z_]+"))
    }
}

/// The report file suffixes read on arrival.
const REPORTS: [&str; 2] = ["pid", "nonce"];

fn reached_from(name: &str, fields: BTreeMap<String, String>) -> Reached {
    let pid = fields
        .get("pid")
        .and_then(|p| p.parse::<u32>().ok())
        .filter(|&p| p > 1);
    Reached {
        name: name.to_owned(),
        fields,
        pid,
        process_group: None,
    }
}

impl PauseHooks {
    fn with(backend: Backend) -> PauseHooks {
        PauseHooks {
            backend,
            holder: Mutex::new(None),
            held: Mutex::new(BTreeMap::new()),
        }
    }

    /// A fresh pause directory `<scratch>/pause<n>` on this host.
    ///
    /// # Errors
    /// The directory cannot be created.
    pub fn new(scratch: &Scratch) -> io::Result<PauseHooks> {
        Ok(PauseHooks::with(Backend::Local(scratch.subdir("pause")?)))
    }

    /// A pause directory inside a running fixture container (created with `mkdir -p`;
    /// a plain absolute path), for scripts run in [`crate::shells::ShellContainers`].
    ///
    /// # Errors
    /// A bad name or path, or `docker exec` failed.
    pub fn in_container(container: &str, dir: &str) -> io::Result<PauseHooks> {
        if !is_container_name(container) || !is_plain_absolute(dir) {
            return Err(io::Error::other("bad container name or pause directory"));
        }
        docker_exec_ok(container, &["mkdir", "-p", dir])?;
        Ok(PauseHooks::with(Backend::Container {
            name: container.to_owned(),
            dir: dir.to_owned(),
        }))
    }

    /// The pause directory (for a container, its in-container path).
    #[must_use]
    pub fn dir(&self) -> PathBuf {
        match &self.backend {
            Backend::Local(d) => d.clone(),
            Backend::Container { dir, .. } => PathBuf::from(dir),
        }
    }

    /// `(HEIMDALL_TEST_SCRIPT_PAUSE_DIR, <dir>)`, for the environment of the code under
    /// test.
    #[must_use]
    pub fn env(&self) -> (&'static str, OsString) {
        (PAUSE_DIR_ENV, self.dir().into_os_string())
    }

    /// [`pause_snippet`] for this directory.
    #[must_use]
    pub fn snippet(&self, name: &str) -> String {
        pause_snippet(&self.dir().to_string_lossy(), name)
    }

    /// Arm `name`: create the FIFO `<dir>/<name>` (owner-only, with `mkfifo`).
    ///
    /// # Errors
    /// A bad name, or `mkfifo` failed (for example, the hook is already armed).
    pub fn arm(&self, name: &str) -> io::Result<()> {
        check_name(name)?;
        match &self.backend {
            Backend::Local(dir) => {
                let mkfifo =
                    find_program("mkfifo").ok_or_else(|| io::Error::other("mkfifo not found"))?;
                let status = Command::new(mkfifo)
                    .arg("-m")
                    .arg("600")
                    .arg(dir.join(name))
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()?;
                if status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other("mkfifo failed"))
                }
            }
            Backend::Container { name: c, dir } => {
                docker_exec_ok(c, &["mkfifo", "-m", "600", &format!("{dir}/{name}")])
            }
        }
    }

    /// Arm every point of [`hook::ALL`].
    ///
    /// # Errors
    /// As [`Self::arm`].
    pub fn arm_all(&self) -> io::Result<()> {
        hook::ALL.iter().try_for_each(|n| self.arm(n))
    }

    /// Disarm `name` (remove its FIFO and report files); a later reach is a no-op.
    ///
    /// # Errors
    /// A bad name, or the removal failed.
    pub fn disarm(&self, name: &str) -> io::Result<()> {
        check_name(name)?;
        match &self.backend {
            Backend::Local(dir) => {
                let mut files = vec![dir.join(name)];
                files.extend(REPORTS.iter().map(|r| dir.join(format!("{name}.{r}"))));
                for f in files {
                    match fs::remove_file(f) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e),
                    }
                }
                Ok(())
            }
            Backend::Container { name: c, dir } => {
                let mut args = vec!["rm".to_owned(), "-f".to_owned(), format!("{dir}/{name}")];
                args.extend(REPORTS.iter().map(|r| format!("{dir}/{name}.{r}")));
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                docker_exec_ok(c, &args)
            }
        }
    }

    /// [`Self::wait_at_for`] with [`PAUSE_WAIT`].
    ///
    /// # Errors
    /// As [`Self::wait_at_for`].
    pub fn wait_at(&self, name: &str) -> io::Result<Reached> {
        self.wait_at_for(name, PAUSE_WAIT)
    }

    /// Block until a party is paused at `name` (its reader has opened the FIFO **and** its
    /// report file exists) or `timeout` passes; hold the FIFO's write end (the party
    /// stays paused until [`Self::release`]); read the report files; and record the
    /// reported PID's process group as the holder for [`Self::stop_holder`]. A reader
    /// with no report is a released party's reader that has not yet seen end-of-file:
    /// the write end is closed again at once (it then ends) and the wait goes on.
    ///
    /// # Errors
    /// `TimedOut`, a bad name, the hook already held, or a read failed.
    pub fn wait_at_for(&self, name: &str, timeout: Duration) -> io::Result<Reached> {
        check_name(name)?;
        if self.held_map().contains_key(name) {
            return Err(io::Error::other("this pause point is already held"));
        }
        let (held, mut reached) = match &self.backend {
            Backend::Local(dir) => {
                let (file, fields) = local_arrival(dir, name, timeout)?;
                let mut reached = reached_from(name, fields);
                reached.process_group = reached.pid.and_then(local_process_group);
                (Held::Local(file), reached)
            }
            Backend::Container { name: c, dir } => {
                let (child, fields) = container_arrival(c, dir, name, timeout)?;
                let mut reached = reached_from(name, fields);
                reached.process_group = reached
                    .pid
                    .and_then(|pid| container_process_group(c, pid).ok());
                (Held::Container(child), reached)
            }
        };
        if reached.pid.is_some() {
            // A reported PID whose group cannot be read is never signalled.
            *self.holder.lock().unwrap_or_else(|e| e.into_inner()) = reached
                .pid
                .zip(reached.process_group)
                .map(|(pid, g)| HolderGroup {
                    pid,
                    process_group: g,
                });
        }
        reached.name = name.to_owned();
        self.held_map().insert(name.to_owned(), held);
        Ok(reached)
    }

    fn held_map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Held>> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// [`Self::release_for`] with [`PAUSE_WAIT`].
    ///
    /// # Errors
    /// As [`Self::release_for`].
    pub fn release(&self, name: &str) -> io::Result<()> {
        self.release_for(name, PAUSE_WAIT)
    }

    /// Let the party paused at `name` continue: remove its report files, then close the
    /// held write end (its `cat` reads end-of-file), so a following [`Self::wait_at`]
    /// sees only the **next** arrival.
    ///
    /// # Errors
    /// The point is not held, or the container's writer did not finish in time.
    pub fn release_for(&self, name: &str, timeout: Duration) -> io::Result<()> {
        check_name(name)?;
        let held = self
            .held_map()
            .remove(name)
            .ok_or_else(|| io::Error::other("this pause point is not held"))?;
        // The reports go first, while the party is still held: a report present at a
        // later `wait_at` is then always the next arrival's.
        match &self.backend {
            Backend::Local(dir) => {
                for r in REPORTS {
                    let _ = fs::remove_file(dir.join(format!("{name}.{r}")));
                }
            }
            Backend::Container { name: c, dir } => {
                let files: Vec<String> = REPORTS
                    .iter()
                    .map(|r| format!("{dir}/{name}.{r}"))
                    .collect();
                let mut args = vec!["rm", "-f"];
                args.extend(files.iter().map(String::as_str));
                let _ = docker_exec_ok(c, &args);
            }
        }
        match held {
            Held::Local(file) => {
                drop(file);
                Ok(())
            }
            Held::Container(mut child) => {
                drop(child.stdin.take());
                let end = Instant::now() + timeout;
                loop {
                    if child.try_wait()?.is_some() {
                        return Ok(());
                    }
                    if Instant::now() >= end {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "the container's pause writer did not close in time",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }

    /// The holder group recorded by the last arrival that reported a PID.
    #[must_use]
    pub fn holder(&self) -> Option<HolderGroup> {
        *self.holder.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// SIGSTOP the holder's exact process group (the last arrival's).
    ///
    /// # Errors
    /// No holder recorded, group 0 or 1 or this process's own group (never signalled),
    /// or the signal failed.
    pub fn stop_holder(&self) -> io::Result<()> {
        self.signal_holder(GroupSignal::Stop)
    }

    /// SIGCONT the holder's exact process group.
    ///
    /// # Errors
    /// As [`Self::stop_holder`].
    pub fn continue_holder(&self) -> io::Result<()> {
        self.signal_holder(GroupSignal::Cont)
    }

    fn signal_holder(&self, sig: GroupSignal) -> io::Result<()> {
        let holder = self
            .holder()
            .ok_or_else(|| io::Error::other("no paused holder group is recorded"))?;
        match &self.backend {
            Backend::Local(_) => signal_local_group(holder.process_group, sig),
            Backend::Container { name, .. } => {
                crate::shells::signal_container_group(name, holder.process_group, sig.name())
            }
        }
    }
}

impl Drop for PauseHooks {
    fn drop(&mut self) {
        // Closing every held writer releases every paused party.
        let held = std::mem::take(&mut *self.held_map());
        for (_, h) in held {
            if let Held::Container(mut child) = h {
                drop(child.stdin.take());
                let end = Instant::now() + Duration::from_secs(5);
                while Instant::now() < end && !matches!(child.try_wait(), Ok(Some(_))) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

/// A group signal [`PauseHooks`] sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupSignal {
    Stop,
    Cont,
}

impl GroupSignal {
    fn name(self) -> &'static str {
        match self {
            GroupSignal::Stop => "STOP",
            GroupSignal::Cont => "CONT",
        }
    }
}

#[cfg(unix)]
fn local_process_group(pid: u32) -> Option<u32> {
    let pid = rustix::process::Pid::from_raw(i32::try_from(pid).ok()?)?;
    let group = rustix::process::getpgid(Some(pid)).ok()?;
    u32::try_from(group.as_raw_nonzero().get()).ok()
}

#[cfg(not(unix))]
fn local_process_group(_pid: u32) -> Option<u32> {
    None
}

#[cfg(unix)]
fn signal_local_group(group: u32, sig: GroupSignal) -> io::Result<()> {
    use rustix::process::{Pid, Signal, getpgrp, kill_process_group};
    let raw = i32::try_from(group).map_err(|_| io::Error::other("group out of range"))?;
    let pid = Pid::from_raw(raw)
        .filter(|p| p.as_raw_nonzero().get() > 1)
        .ok_or_else(|| io::Error::other("refusing to signal group 0 or 1"))?;
    if pid == getpgrp() {
        return Err(io::Error::other(
            "refusing to signal this process's own group",
        ));
    }
    let signal = match sig {
        GroupSignal::Stop => Signal::STOP,
        GroupSignal::Cont => Signal::CONT,
    };
    kill_process_group(pid, signal).map_err(io::Error::from)
}

#[cfg(not(unix))]
fn signal_local_group(_group: u32, _sig: GroupSignal) -> io::Result<()> {
    Err(io::Error::other("process groups are Unix only"))
}

/// The report files of `name` in `dir` that exist, by suffix.
#[cfg(unix)]
fn local_reports(dir: &Path, name: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for r in REPORTS {
        if let Ok(text) = fs::read_to_string(dir.join(format!("{name}.{r}"))) {
            fields.insert(r.to_owned(), text.trim().to_owned());
        }
    }
    fields
}

/// Wait for an arrival at `dir/name`: a non-blocking write open (which fails with `ENXIO`
/// while no reader has the FIFO open) that succeeds while a report file exists. The
/// returned file is held (never written); closing it gives the reader end-of-file.
#[cfg(unix)]
fn local_arrival(
    dir: &Path,
    name: &str,
    timeout: Duration,
) -> io::Result<(fs::File, BTreeMap<String, String>)> {
    use rustix::fs::{Mode, OFlags};
    let path = dir.join(name);
    let end = Instant::now() + timeout;
    loop {
        match rustix::fs::open(
            &path,
            OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => {
                let file = fs::File::from(fd);
                let fields = local_reports(dir, name);
                if !fields.is_empty() {
                    return Ok((file, fields));
                }
                // A stale reader: let it see end-of-file.
                drop(file);
            }
            Err(e) if e == rustix::io::Errno::NXIO || e == rustix::io::Errno::INTR => {}
            Err(e) => return Err(e.into()),
        }
        if Instant::now() >= end {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no party reached the pause point in time",
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(not(unix))]
fn local_arrival(
    _dir: &Path,
    _name: &str,
    _timeout: Duration,
) -> io::Result<(fs::File, BTreeMap<String, String>)> {
    Err(io::Error::other("FIFOs are Unix only"))
}

/// In a container: `docker exec -i <c> sh -c 'exec 3>"$1" && echo opened && read x'`
/// (the open blocks until a reader is there), then the report files; a reader with no
/// report is stale (the writer is closed again and the wait goes on). Keeps the client,
/// whose closed stdin later closes the writer.
fn container_arrival(
    container: &str,
    dir: &str,
    name: &str,
    timeout: Duration,
) -> io::Result<(Child, BTreeMap<String, String>)> {
    let end = Instant::now() + timeout;
    loop {
        let left = end.saturating_duration_since(Instant::now());
        let mut child = container_writer_when_read(container, &format!("{dir}/{name}"), left)?;
        let mut fields = BTreeMap::new();
        for r in REPORTS {
            let path = format!("{dir}/{name}.{r}");
            if let Ok(run) = docker_exec_run(
                container,
                &["/bin/sh", "-c", "[ -f \"$1\" ] && cat \"$1\"", "sh", &path],
                None,
                &[],
                Duration::from_secs(30),
            ) && run.status == Some(0)
            {
                fields.insert(
                    r.to_owned(),
                    String::from_utf8_lossy(&run.stdout).trim().to_owned(),
                );
            }
        }
        if !fields.is_empty() {
            return Ok((child, fields));
        }
        drop(child.stdin.take());
        let _ = child.wait();
        if Instant::now() >= end {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no party reached the pause point in time",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The container side of one write-end hold (see [`container_arrival`]).
fn container_writer_when_read(container: &str, fifo: &str, timeout: Duration) -> io::Result<Child> {
    let mut child = docker_exec_spawn(
        container,
        &[
            "/bin/sh",
            "-c",
            "exec 3>\"$1\" && echo opened && read hm_x; exec 3>&-",
            "sh",
            fifo,
        ],
        true,
        None,
        &[],
    )?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("no stdout"))?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut stdout = stdout;
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        while let Ok(1) = stdout.read(&mut b) {
            line.push(b[0]);
            if b[0] == b'\n' {
                break;
            }
        }
        let _ = tx.send(line);
    });
    match rx.recv_timeout(timeout) {
        Ok(line) if line == b"opened\n" => Ok(child),
        _ => {
            let _ = child.kill();
            let _ = child.wait();
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no party reached the pause point in time",
            ))
        }
    }
}

// --- docker helpers (shared with `shells` and `procstat`) ------------------------------------

/// `docker exec <c> <args>`: success or an error naming no path.
pub(crate) fn docker_exec_ok(container: &str, args: &[&str]) -> io::Result<()> {
    docker_exec_output(container, args, None, Duration::from_secs(60)).map(|_| ())
}

/// `docker exec [-i] <c> <args>` with `stdin` written (when given), bounded by `timeout`
/// (the docker client is killed on timeout). Returns stdout on exit 0.
pub(crate) fn docker_exec_output(
    container: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let run = docker_exec_run(container, args, stdin, &[], timeout)?;
    if run.status == Some(0) {
        Ok(run.stdout)
    } else {
        Err(io::Error::other(format!(
            "docker exec exited {:?}",
            run.status
        )))
    }
}

/// One finished command: exit status (`None` when killed by a signal or the bound),
/// stdout and stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// The exit status.
    pub status: Option<i32>,
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: Vec<u8>,
}

/// `docker exec [-i] [-u U] -e K=V … <c> <args>`, bounded.
pub(crate) fn docker_exec_run(
    container: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    env: &[(&str, &str)],
    timeout: Duration,
) -> io::Result<Finished> {
    docker_exec_spawn(container, args, stdin.is_some(), None, env)
        .and_then(|child| finish(child, stdin, timeout))
}

/// Start `docker exec [-i] [-u <user>] -e K=V … <c> <args>` (stdout and stderr piped).
pub(crate) fn docker_exec_spawn(
    container: &str,
    args: &[&str],
    with_stdin: bool,
    user: Option<&str>,
    env: &[(&str, &str)],
) -> io::Result<Child> {
    if !is_container_name(container) {
        return Err(io::Error::other("bad container name"));
    }
    let docker = find_program("docker").ok_or_else(|| io::Error::other("docker not found"))?;
    let mut cmd = Command::new(docker);
    cmd.arg("exec");
    if with_stdin {
        cmd.arg("-i");
    }
    if let Some(user) = user {
        cmd.arg("-u").arg(user);
    }
    for (k, v) in env {
        cmd.arg("-e").arg(format!("{k}={v}"));
    }
    cmd.arg(container).args(args);
    cmd.stdin(if with_stdin {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
}

/// Feed `stdin`, collect both outputs concurrently, and wait with a bound (kill by
/// the exact child handle on timeout).
pub(crate) fn finish(
    mut child: Child,
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<Finished> {
    let feeder = match (child.stdin.take(), stdin) {
        (Some(mut pipe), Some(bytes)) => {
            let bytes = bytes.to_vec();
            Some(std::thread::spawn(move || {
                let _ = pipe.write_all(&bytes);
            }))
        }
        _ => None,
    };
    let out_t = spawn_reader(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err_t = spawn_reader(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let end = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status.code();
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if let Some(f) = feeder {
        let _ = f.join();
    }
    let stdout = out_t.join().unwrap_or_default();
    let stderr = err_t.join().unwrap_or_default();
    Ok(Finished {
        status,
        stdout,
        stderr,
    })
}

fn spawn_reader(pipe: Option<Box<dyn Read + Send>>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        if let Some(mut p) = pipe {
            let _ = p.read_to_end(&mut out);
        }
        out
    })
}

/// The process group of `pid` inside a container: field 5 of `/proc/<pid>/stat`,
/// read through the shared parser (`heimdall_domain::procstat::parse`).
pub(crate) fn container_process_group(container: &str, pid: u32) -> io::Result<u32> {
    let stat = docker_exec_output(
        container,
        &["cat", &format!("/proc/{pid}/stat")],
        None,
        Duration::from_secs(30),
    )?;
    heimdall_domain::procstat::parse(&stat)
        .map(|s| s.process_group)
        .map_err(|e| io::Error::other(e.to_string()))
}

// --- local scripts -----------------------------------------------------------------------------

/// A script running locally under a shell, in a **new process group** it leads
/// (`process_group(0)`, so its `$$` is its group, as under sshd).
#[derive(Debug)]
pub struct LocalScript {
    child: Option<Child>,
    stdout: Option<std::thread::JoinHandle<Vec<u8>>>,
    stderr: Option<std::thread::JoinHandle<Vec<u8>>>,
}

impl LocalScript {
    /// Run `script` as `<shell> -s` with exactly `env` (after `PATH` set to the
    /// standard directories, which `env` may replace), in `cwd`; its stdin is closed
    /// after the script.
    ///
    /// # Errors
    /// The shell cannot be started.
    pub fn spawn(
        shell: &Path,
        script: &[u8],
        env: &[(OsString, OsString)],
        cwd: &Path,
    ) -> io::Result<LocalScript> {
        let mut cmd = Command::new(shell);
        cmd.arg("-s")
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let mut child = cmd.spawn()?;
        if let Some(mut pipe) = child.stdin.take() {
            let bytes = script.to_vec();
            std::thread::spawn(move || {
                let _ = pipe.write_all(&bytes);
            });
        }
        let stdout = Some(spawn_reader(
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ));
        let stderr = Some(spawn_reader(
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ));
        Ok(LocalScript {
            child: Some(child),
            stdout,
            stderr,
        })
    }

    /// The shell's PID (its process group).
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Whether it has exited (reaping it if so).
    #[must_use]
    pub fn has_exited(&mut self) -> bool {
        self.child
            .as_mut()
            .is_none_or(|c| matches!(c.try_wait(), Ok(Some(_))))
    }

    /// Wait up to `timeout`; on timeout kill the shell by its exact handle.
    ///
    /// # Errors
    /// The wait failed.
    pub fn wait(mut self, timeout: Duration) -> io::Result<Finished> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("already waited"))?;
        let end = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status.code();
            }
            if Instant::now() >= end {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let stdout = self
            .stdout
            .take()
            .and_then(|t| t.join().ok())
            .unwrap_or_default();
        let stderr = self
            .stderr
            .take()
            .and_then(|t| t.join().ok())
            .unwrap_or_default();
        Ok(Finished {
            status,
            stdout,
            stderr,
        })
    }
}

impl Drop for LocalScript {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take()
            && !matches!(child.try_wait(), Ok(Some(_)))
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// --- truncation ----------------------------------------------------------------------------------

/// One prefix run of a [`Truncation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixRun {
    /// The prefix length in bytes.
    pub len: usize,
    /// The shell's exit status (`None`: killed by a signal or the bound).
    pub status: Option<i32>,
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: Vec<u8>,
}

/// Feeds every prefix of a script to a target shell (ADR-0008 D13 item 3): the cut
/// points are `0..=len`, so the last run is the whole script (which is expected to
/// run, as is the whole script without only its final newline; m03-plan U5 ⟨r4⟩).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Truncation {
    script: Vec<u8>,
}

impl Truncation {
    /// The truncation harness of `script`.
    #[must_use]
    pub fn new(script: impl Into<Vec<u8>>) -> Truncation {
        Truncation {
            script: script.into(),
        }
    }

    /// The script.
    #[must_use]
    pub fn script(&self) -> &[u8] {
        &self.script
    }

    /// Every cut point, `0..=len`.
    #[must_use]
    pub fn cut_points(&self) -> std::ops::RangeInclusive<usize> {
        0..=self.script.len()
    }

    /// The prefix of `len` bytes (clamped to the script).
    #[must_use]
    pub fn prefix(&self, len: usize) -> &[u8] {
        &self.script[..len.min(self.script.len())]
    }

    /// Run every prefix through `feed`, in order.
    ///
    /// # Errors
    /// The first error `feed` returns.
    pub fn run_with(
        &self,
        mut feed: impl FnMut(usize, &[u8]) -> io::Result<Finished>,
    ) -> io::Result<Vec<PrefixRun>> {
        self.cut_points()
            .map(|len| {
                feed(len, self.prefix(len)).map(|f| PrefixRun {
                    len,
                    status: f.status,
                    stdout: f.stdout,
                    stderr: f.stderr,
                })
            })
            .collect()
    }

    /// Run every prefix locally as `<shell> -s` ([`LocalScript`]: its own process
    /// group, exactly `env`, in `cwd`), each bounded by `each`.
    ///
    /// # Errors
    /// A shell could not be started.
    pub fn run_local(
        &self,
        shell: &Path,
        env: &[(OsString, OsString)],
        cwd: &Path,
        each: Duration,
    ) -> io::Result<Vec<PrefixRun>> {
        self.run_with(|_, prefix| LocalScript::spawn(shell, prefix, env, cwd)?.wait(each))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposable_distribution_names() {
        for ok in ["hm-m03-abc123", "hm-m02-x", "hm-m09-a-b"] {
            assert!(is_disposable_distro_name(ok), "{ok}");
        }
        for bad in [
            "Ubuntu",
            "hm-m03-",
            "hm-m3-x",
            "hm-m03-ABC",
            "hm-m03-a b",
            "",
        ] {
            assert!(!is_disposable_distro_name(bad), "{bad}");
        }
    }

    #[test]
    fn reports_parse() {
        let mut f = BTreeMap::new();
        f.insert("pid".to_owned(), "4242".to_owned());
        assert_eq!(reached_from("before_write", f).pid, Some(4242));
        let mut n = BTreeMap::new();
        n.insert("nonce".to_owned(), "00ff".to_owned());
        assert_eq!(reached_from("nonce_known", n).pid, None);
        let mut one = BTreeMap::new();
        one.insert("pid".to_owned(), "1".to_owned());
        assert_eq!(reached_from("x", one).pid, None, "never group 1");
    }

    #[test]
    fn snippet_is_single_quoted_and_names_the_fifo_and_pid_file() {
        let s = pause_snippet("/s/p", "before_write");
        assert!(s.contains("[ -p '/s/p/before_write' ]"));
        assert!(s.contains(">| '/s/p/before_write.pid'"));
        assert!(check_name("before_write").is_ok());
        assert!(check_name("../x").is_err());
        assert!(is_container_name("hm-m03-shell-debian-1"));
        assert!(!is_container_name("-x"));
        assert!(is_plain_absolute("/tmp/x"));
        assert!(!is_plain_absolute("/tmp/../x"));
    }

    #[test]
    fn truncation_cut_points_cover_every_prefix() {
        let t = Truncation::new(b"ab\n".to_vec());
        assert_eq!(t.cut_points().collect::<Vec<_>>(), [0, 1, 2, 3]);
        assert_eq!(t.prefix(2), b"ab");
        let runs = t
            .run_with(|len, p| {
                Ok(Finished {
                    status: Some(i32::try_from(len).unwrap()),
                    stdout: p.to_vec(),
                    stderr: Vec::new(),
                })
            })
            .unwrap();
        assert_eq!(runs.len(), 4);
        assert_eq!(runs[3].stdout, b"ab\n");
    }
}
