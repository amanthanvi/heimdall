//! ⟨M03 wave 6, U13⟩ The **A03 lock driver** (m03-plan §4.4 and §3 row A03; ADR-0004 §2
//! lock rule; ADR-0008 D9 and §17.1 item 17, F09): the product-level checks that run
//! while the desktop is really locked. It never locks anything itself: the harness
//! (`tests/native/m03/lock-macos.sh`, `tests/native/m03/lock-windows.ps1`) enforces the
//! 15-minute idle rule, locks, verifies the lock through the product's own query and
//! waits for the owner's unlock; this driver prepares, checks and cleans up.
//!
//! **One driver process.** [`World`] lives in this process (its fixtures and scratch
//! directories last as long as the process), so the whole procedure runs in one
//! invocation: `e2e_exit_m03 --ignored --test-threads=16 --show-output lock::`. The first
//! test to ask starts the procedure ([`procedure`], a `OnceLock`) on its own thread; each
//! `#[test]` waits (bounded) for its own step's result and asserts it, so libtest prints
//! one genuine result per check:
//!
//! | Test | Step |
//! |---|---|
//! | `a03_lock_prepare` | unlocked: the world, the grants, the stand-in agent, the baselines |
//! | `a03_fresh_logins_while_locked_continue` | locked: fresh logins to host 1, about 60 s apart, each attributed to grant C |
//! | `a03_new_grant_while_locked_under_standing_policy` | locked: a non-interactive `access ensure`, then grant N (a `run`'s own ensure) and its fresh logins to host 3 |
//! | `a03_issuer_restart_dpapi_unprotect_while_locked` (Windows) | locked: a forced runtime restart (its new issuer child unprotects K_ca under lock), the re-issue of C's dropped key, a fresh login attributed to C's new certificate |
//! | `a03_lock_revokes_ends_grant_and_fresh_login_fails` | locked: R's revocation (cause `session_locked`) and its refused fresh login |
//! | `a03_vault_stand_in_locked_agent_does_not_matter` | locked: the stand-in agent lists nothing while a managed login succeeds; no credential prompt process |
//! | `a03_post_unlock_follows_remaining_deadline` | unlocked again: R terminal; C and N by the harness's expectation |
//! | `a03_lock_cleanup` | the workers, the stand-in, the runtime, the fixtures and the scratch |
//!
//! **Handshake** (files in `HM_LOCK_STATE_DIR`, each written whole with a rename): the
//! driver writes `ready` after preparing, or `prepare-failed` (one line: `blocked: …` or
//! `failed: …`); the harness writes `locked` after verifying the lock, or `abort` (one
//! line, the reason) when the run is blocked, and the driver then skips the locked steps
//! (each fails `aborted: <reason>`) but still cleans up; the driver writes `locked-done`;
//! the harness waits for the unlock, writes `expect` (`C=usable R=terminal N=expired`)
//! and then `unlocked`; the driver runs the post-unlock step and the cleanup, writes
//! `done` and ends. Every wait is bounded (the unlock wait 12 h and a margin), and with
//! `HM_LOCK_HARNESS_PID` the driver also stops waiting when the harness is gone, so it
//! never outlives it.
//!
//! **Records** the driver appends there: `grants.tsv` (role, grant ID, host 1..3, deadline
//! in epoch seconds), `logins.tsv` (epoch, phase `prepare|locked|post`, host, role, the
//! accepted certificate key ID or `-`, `accepted|refused`; one row per accepted
//! certificate), `events.tsv` (epoch, event, role: `revoked R` at the commit of R's
//! `session_locked` revocation, `ensured N` for the explicit ensure under lock),
//! `store-kind.txt` (the registered CA's store kind as `issuer status` reports it) and
//! `runtime-home.txt` (the scratch Heimdall home, for the harness's fallback `service
//! stop` should this process be killed).
//!
//! **Per platform.** macOS (`HM_LOCK_PLATFORM=macos`): the debug test configuration with
//! the scratch test store (mechanism evidence only, F03) and the **platform**
//! session-lock source (no `HEIMDALL_TEST_SESSION_LOCK`), [`ThreeHosts`] in the account
//! form, a disposable `ssh-agent` locked with `ssh-add -x` as the stand-in. Windows
//! (`HM_LOCK_PLATFORM=windows`): the release-profile product binary with no
//! `HEIMDALL_TEST_*` variable at all ([`WorldOptions::product`]), K_ca seeded through the
//! product's own DPAPI store code where the release issuer child reads it, the three
//! harness sshds (`HM_LOCK_SSHD_<1..3>_*`, [`LoopbackSshd::external`]) and testkit's
//! `FakeAgent` in its `Locked` mode as the stand-in. A release runtime projects into the
//! **account's own** SSH configuration, so on Windows the driver refuses (`blocked:
//! owner_ssh_in_scope`) unless the account's `.ssh` is absent or empty, that is, unless it
//! runs as a disposable account (AGENTS.md: the owner's `~/.ssh` is never edited).
//!
//! Nothing printed names a path, a user or a secret: grants and environments appear only
//! inside certificate key IDs.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use heimdall_testkit::agent::{AgentConnection, Endpoint, FixtureKey};
use heimdall_testkit::home::Scratch;
use heimdall_testkit::sshd::{AcceptedCert, LoopbackSshd, SshdConfig, ThreeHosts};
use serde_json::Value;

use crate::worker;
use crate::world::{Worker, World, WorldOptions, platform};

// ---- the tests ------------------------------------------------------------------------------

/// Unlocked: the runtime from this build (Windows: the release product binary) with the
/// platform session-lock source, `time confirm` and `setup apply` typed on a terminal, the
/// issuer (macOS the scratch test store; Windows the product DPAPI store kind, reported
/// by `issuer status`), three hosts with disjoint pairs, grant C (`continue`, ≥ 13 h
/// left) on host 1, grant R under a policy narrowed to `revoke-on-lock` on host 2, the
/// standing policy for N on host 3, the stand-in agent started and locked, one baseline
/// fresh login per grant attributed by key ID.
#[test]
#[ignore = "run once by tests/native/m03/lock-macos.sh or lock-windows.ps1 (m03-plan §4.4)"]
fn a03_lock_prepare() {
    check(Step::Prepare);
}

/// Locked: three fresh logins to host 1 about 60 s apart, each accepted with exactly one
/// certificate whose key ID names grant C, under the world's CA.
#[test]
#[ignore = "run once by tests/native/m03/lock-macos.sh or lock-windows.ps1 (m03-plan §4.4)"]
fn a03_fresh_logins_while_locked_continue() {
    check(Step::FreshLogins);
}

/// Locked: one non-interactive `access ensure` under the standing policy of host 3
/// activates a new grant whose certificate the issuer signs under lock; then a worker's
/// `run` (its own non-interactive ensure) activates grant N, and two fresh logins to
/// host 3 are attributed to N by key ID (ADR-0005 D1: new grants under lock).
#[test]
#[ignore = "run once by tests/native/m03/lock-macos.sh or lock-windows.ps1 (m03-plan §4.4)"]
fn a03_new_grant_while_locked_under_standing_policy() {
    check(Step::NewGrant);
}

/// Windows, locked: the runtime is restarted (its K_env dropped), the new issuer child
/// unprotects K_ca from DPAPI under lock (`issuer status` ready), C and N are re-issued,
/// and C's held worker logs in fresh with C's new certificate (same grant, new serial).
#[cfg(windows)]
#[test]
#[ignore = "run once by tests/native/m03/lock-macos.sh or lock-windows.ps1 (m03-plan §4.4)"]
fn a03_issuer_restart_dpapi_unprotect_while_locked() {
    check(Step::IssuerRestart);
}

/// Locked: grant R (`revoke_on_lock`) has a tombstone with cause `session_locked` and is
/// `revoked`; its worker's fresh login to host 2 is refused, and host 2 accepted no
/// certificate of R after its baseline.
#[test]
#[ignore = "run once by tests/native/m03/lock-macos.sh or lock-windows.ps1 (m03-plan §4.4)"]
fn a03_lock_revokes_ends_grant_and_fresh_login_fails() {
    check(Step::LockRevokes);
}

/// Locked: the source-provider stand-in agent lists nothing (and refuses an add) before
/// and after a managed fresh login to host 1 that runs with it as `SSH_AUTH_SOCK` and is
/// attributed to C; no keychain or credential prompt process appeared since the baseline
/// (exact names).
#[test]
#[ignore = "run once by tests/native/m03/lock-macos.sh or lock-windows.ps1 (m03-plan §4.4)"]
fn a03_vault_stand_in_locked_agent_does_not_matter() {
    check(Step::StandIn);
}

/// After the unlock: R is still terminal (its tombstone unchanged) and its fresh login is
/// refused; C and N each follow the harness's expectation from the remaining deadline:
/// `usable`, a fresh login attributed to it; `expired`, the grant reads `expired` and its
/// fresh login is refused.
#[test]
#[ignore = "run once by tests/native/m03/lock-macos.sh or lock-windows.ps1 (m03-plan §4.4)"]
fn a03_post_unlock_follows_remaining_deadline() {
    check(Step::PostUnlock);
}

/// The workers end (or are killed through their handles), the stand-in agent stops, the
/// runtime is stopped with `service stop` in its own home, the fixtures stop through their
/// handles and both scratch directories are gone.
#[test]
#[ignore = "run once by tests/native/m03/lock-macos.sh or lock-windows.ps1 (m03-plan §4.4)"]
fn a03_lock_cleanup() {
    check(Step::Cleanup);
}

fn check(step: Step) {
    match procedure().wait(step) {
        Ok(text) => print!("{text}"),
        Err(why) => panic!("{}: {why}", step.name()),
    }
}

// ---- the shared procedure ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Step {
    Prepare,
    FreshLogins,
    NewGrant,
    IssuerRestart,
    LockRevokes,
    StandIn,
    PostUnlock,
    Cleanup,
}

const ALL_STEPS: [Step; 8] = [
    Step::Prepare,
    Step::FreshLogins,
    Step::NewGrant,
    Step::IssuerRestart,
    Step::LockRevokes,
    Step::StandIn,
    Step::PostUnlock,
    Step::Cleanup,
];

impl Step {
    fn name(self) -> &'static str {
        match self {
            Step::Prepare => "a03_lock_prepare",
            Step::FreshLogins => "a03_fresh_logins_while_locked_continue",
            Step::NewGrant => "a03_new_grant_while_locked_under_standing_policy",
            Step::IssuerRestart => "a03_issuer_restart_dpapi_unprotect_while_locked",
            Step::LockRevokes => "a03_lock_revokes_ends_grant_and_fresh_login_fails",
            Step::StandIn => "a03_vault_stand_in_locked_agent_does_not_matter",
            Step::PostUnlock => "a03_post_unlock_follows_remaining_deadline",
            Step::Cleanup => "a03_lock_cleanup",
        }
    }

    /// How long its test waits for the result (beyond every wait of the procedure that
    /// comes before it, so a result always arrives first).
    fn bound(self) -> Duration {
        match self {
            Step::Prepare => H / 2,
            Step::FreshLogins
            | Step::NewGrant
            | Step::IssuerRestart
            | Step::LockRevokes
            | Step::StandIn => 4 * H,
            Step::PostUnlock => UNLOCK_WAIT + 5 * H,
            Step::Cleanup => UNLOCK_WAIT + 6 * H,
        }
    }

    /// Whether this platform runs it.
    fn runs_here(self) -> bool {
        self != Step::IssuerRestart || cfg!(windows)
    }
}

const H: Duration = Duration::from_secs(3600);
/// The harness's `locked` (or `abort`) arrives within this of `ready` (an idle check, the
/// lock and its 30 s verification).
const LOCK_WAIT: Duration = Duration::from_secs(3600);
/// The harness's `locked-done` → `unlocked` wait: the owner's unlock, bounded to 12 h
/// (m03-plan §4.4 step 6), plus a margin for the harness's own steps.
const UNLOCK_WAIT: Duration = Duration::from_secs(12 * 3600 + 1800);
/// A worker's wait for its next login before the post-unlock one (the worker never logs
/// in at a wrong time: the driver kills it through its handle first).
const WORKER_POST_WAIT: Duration = Duration::from_secs(13 * 3600);
/// A worker's wait for its next login while locked.
const WORKER_WAIT: Duration = Duration::from_secs(3 * 3600);
/// The interval of grant C's locked logins (m03-plan §4.4 step 5: sampled every 60 s).
const SAMPLE_INTERVAL: Duration = Duration::from_secs(60);
/// Grant C's policy window and the configuration's `session.max_window`: ≥ 13 h after
/// the planned lock (m03-plan §4.4 step 2).
const C_WINDOW: Duration = Duration::from_secs(16 * 3600);
/// The least C may have left when prepared (the lock follows within minutes).
const C_MIN_LEFT: Duration = Duration::from_secs(13 * 3600 + 1800);
/// Grant R's policy window.
const R_WINDOW: Duration = Duration::from_secs(2 * 3600);
/// Grant N's policy window: short, so an unlock more than an hour later exercises the
/// `expired` case and C the `usable` one (F09).
const N_WINDOW: Duration = Duration::from_secs(3600);

#[derive(Default)]
struct Shared {
    results: Mutex<BTreeMap<Step, Result<String, String>>>,
    cv: Condvar,
}

impl Shared {
    /// Record `step`'s result (the first one wins).
    fn put(&self, step: Step, result: Result<String, String>) {
        let mut g = self
            .results
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.entry(step).or_insert(result);
        self.cv.notify_all();
    }

    /// Wait (bounded by [`Step::bound`]) for `step`'s result.
    fn wait(&self, step: Step) -> Result<String, String> {
        let deadline = Instant::now() + step.bound();
        let mut g = self
            .results
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(r) = g.get(&step) {
                return r.clone();
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "no result within {} s (the procedure is stuck)",
                    step.bound().as_secs()
                ));
            }
            g = self
                .cv
                .wait_timeout(g, deadline - now)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }
}

/// Every step still without a result fails with this, when the procedure thread ends.
struct FailRemaining(&'static Shared);

impl Drop for FailRemaining {
    fn drop(&mut self) {
        for s in ALL_STEPS {
            self.0.put(
                s,
                Err("the lock procedure ended before this step ran".to_owned()),
            );
        }
    }
}

static SHARED: OnceLock<Shared> = OnceLock::new();

/// The procedure, started by the first test that asks.
fn procedure() -> &'static Shared {
    let mut first = false;
    let shared = SHARED.get_or_init(|| {
        first = true;
        Shared::default()
    });
    if first {
        std::thread::Builder::new()
            .name("a03-lock-procedure".to_owned())
            .spawn(move || {
                let _guard = FailRemaining(shared);
                run(shared);
            })
            .expect("start the lock procedure");
    }
    shared
}

/// Run `f`, its panic message as the error.
fn guarded<F: FnOnce() -> String>(f: F) -> Result<String, String> {
    std::panic::catch_unwind(AssertUnwindSafe(f)).map_err(|p| {
        p.downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_else(|| "panicked".to_owned())
    })
}

/// The whole procedure (module docs).
fn run(shared: &'static Shared) {
    let hs = match Handshake::from_env() {
        Ok(h) => h,
        Err(why) => {
            for s in ALL_STEPS {
                shared.put(s, Err(why.clone()));
            }
            return;
        }
    };
    // Unlocked: prepare.
    let mut slot: Option<Run> = None;
    let prepared = guarded(|| {
        let (run, text) = Run::prepare(&hs);
        slot = Some(run);
        text
    });
    match &prepared {
        Ok(_) => hs.write("ready", ""),
        Err(why) => {
            let line = one_line(why);
            let text = if line.starts_with("blocked: ") {
                line
            } else {
                format!("failed: {line}")
            };
            hs.write("prepare-failed", &text);
        }
    }
    shared.put(Step::Prepare, prepared.clone());
    let skip = |why: &str| {
        for s in [
            Step::FreshLogins,
            Step::NewGrant,
            Step::IssuerRestart,
            Step::LockRevokes,
            Step::StandIn,
            Step::PostUnlock,
        ] {
            shared.put(s, Err(why.to_owned()));
        }
    };
    let Some(mut run) = slot else {
        skip(&match &prepared {
            Err(e) if one_line(e).starts_with("blocked: ") => {
                format!("aborted: the preparation is {}", one_line(e))
            }
            _ => "not run: the preparation failed".to_owned(),
        });
        // ⟨W6-R01⟩ A world dropped while the preparation unwound ran its owned projection
        // rollback: report it, and fail the cleanup when it could not be completed (its
        // recovery state is then kept, never deleted).
        let cleanups = crate::world::take_projection_cleanups();
        let failed: Vec<&str> = cleanups
            .iter()
            .filter_map(|c| c.result.as_ref().err().map(String::as_str))
            .collect();
        let mut text = String::from(
            "cleanup: the preparation failed; what it had started stopped through its handles as it unwound\n",
        );
        for c in &cleanups {
            text.push_str(&format!(
                "cleanup: {}\n",
                c.result
                    .as_ref()
                    .map_or_else(|e| e.as_str(), |t| t.as_str())
            ));
        }
        shared.put(
            Step::Cleanup,
            if failed.is_empty() {
                Ok(text)
            } else {
                Err(format!("cleanup failed: {}", failed.join("; ")))
            },
        );
        hs.write("done", "");
        return;
    };

    // Locked.
    match hs.await_flag(&["abort", "locked"], LOCK_WAIT) {
        Ok((flag, text)) if flag == "locked" => {
            run.locked_at = epoch();
            let _ = text;
            for step in [
                Step::FreshLogins,
                Step::NewGrant,
                Step::IssuerRestart,
                Step::LockRevokes,
                Step::StandIn,
            ] {
                if step.runs_here() {
                    let r = guarded(|| run.locked_step(step));
                    shared.put(step, r);
                }
            }
            hs.write("locked-done", "");
            // After the unlock.
            match hs.await_flag(&["abort", "unlocked"], UNLOCK_WAIT) {
                Ok((flag, _)) if flag == "unlocked" => {
                    let expect = hs.read("expect").unwrap_or_default();
                    let r = guarded(|| run.post_unlock(&expect));
                    shared.put(Step::PostUnlock, r);
                }
                Ok((_, why)) => shared.put(
                    Step::PostUnlock,
                    Err(format!("aborted: {}", one_line(&why))),
                ),
                Err(why) => shared.put(Step::PostUnlock, Err(format!("aborted: {why}"))),
            }
        }
        Ok((_, why)) => skip(&format!("aborted: {}", one_line(&why))),
        Err(why) => skip(&format!("aborted: {why}")),
    }
    let r = guarded(|| run.cleanup());
    shared.put(Step::Cleanup, r);
    hs.write("done", "");
}

fn one_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or("").trim();
    line.chars().take(400).collect()
}

fn epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---- the handshake ------------------------------------------------------------------------------

struct Handshake {
    /// `HM_LOCK_STATE_DIR`.
    dir: PathBuf,
    /// `HM_LOCK_HARNESS_PID`: the harness, checked alive while waiting.
    harness: Option<u32>,
}

impl Handshake {
    fn from_env() -> Result<Handshake, String> {
        let dir = std::env::var_os("HM_LOCK_STATE_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute() && p.is_dir())
            .ok_or_else(|| {
                "not run by the lock harness: HM_LOCK_STATE_DIR is not an existing absolute \
                 directory (tests/native/m03/lock-macos.sh, lock-windows.ps1)"
                    .to_owned()
            })?;
        let want = std::env::var("HM_LOCK_PLATFORM").unwrap_or_default();
        if want != platform() || !(cfg!(target_os = "macos") || cfg!(windows)) {
            return Err(format!(
                "HM_LOCK_PLATFORM must name this platform ({}); the lock procedure runs on \
                 macOS and Windows only (m03-plan §4.2: no desktop lock on a headless host)",
                platform()
            ));
        }
        let harness = match std::env::var("HM_LOCK_HARNESS_PID") {
            Ok(v) => Some(
                v.trim()
                    .parse::<u32>()
                    .map_err(|_| "HM_LOCK_HARNESS_PID is not a PID".to_owned())?,
            ),
            Err(_) => None,
        };
        Ok(Handshake { dir, harness })
    }

    /// Write the flag `name` whole (a temporary file, then a rename).
    fn write(&self, name: &str, text: &str) {
        let tmp = self.dir.join(format!(".{name}.tmp"));
        let _ = std::fs::write(&tmp, format!("{text}\n"));
        let _ = std::fs::rename(&tmp, self.dir.join(name));
    }

    fn read(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.join(name))
            .ok()
            .map(|t| t.trim().to_owned())
    }

    /// Wait for the first of `flags` to exist, bounded, and while the harness lives:
    /// `(flag, its text)`.
    fn await_flag(&self, flags: &[&str], bound: Duration) -> Result<(String, String), String> {
        let start = Instant::now();
        let mut checked = Instant::now();
        loop {
            for f in flags {
                if let Some(text) = self.read(f) {
                    return Ok(((*f).to_owned(), text));
                }
            }
            if start.elapsed() > bound {
                return Err(format!(
                    "no {} from the harness within {} s",
                    flags.join(" or "),
                    bound.as_secs()
                ));
            }
            if let Some(pid) = self.harness
                && checked.elapsed() > Duration::from_secs(30)
            {
                checked = Instant::now();
                if !crate::procs::alive(pid) {
                    return Err("the harness ended (its process is gone)".to_owned());
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    fn append(&self, file: &str, line: &str) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(file))
            .expect("append to the lock state directory");
        writeln!(f, "{line}").expect("append to the lock state directory");
    }
}

// ---- the run ----------------------------------------------------------------------------------

/// A grant's role in §4.4: C on host 1, R on host 2, N on host 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    C,
    R,
    N,
}

impl Role {
    fn letter(self) -> &'static str {
        match self {
            Role::C => "C",
            Role::R => "R",
            Role::N => "N",
        }
    }

    /// The pair index (host = index + 1).
    fn pair(self) -> usize {
        match self {
            Role::C => 0,
            Role::R => 1,
            Role::N => 2,
        }
    }
}

/// One login a lane's worker makes: its label and, for the stand-in login, the
/// `SSH_AUTH_SOCK` it runs with instead of the decoy.
struct Planned {
    label: &'static str,
    auth_sock: Option<OsString>,
}

/// A worker under `heimdall run` on one role's profile, logging in when told
/// (`login`, `signal s<k>`, `wait g<k>`, …).
struct Lane {
    role: Role,
    work: &'static str,
    plan: Vec<Planned>,
    dir: PathBuf,
    worker: Option<Worker>,
    next: usize,
}

impl Lane {
    fn signal(&self, k: usize) -> PathBuf {
        self.dir.join(format!("s{k}"))
    }
    fn go(&self, k: usize) -> PathBuf {
        self.dir.join(format!("g{k}"))
    }
}

/// One fresh login's outcome.
#[derive(Debug)]
struct Login {
    ok: bool,
    certs: Vec<AcceptedCert>,
    stderr: String,
}

/// Everything the procedure started. Fields drop in declaration order: the workers
/// first, the stand-in agent, then the world (`service stop`, its servers, its scratch),
/// then the servers' scratch.
struct Run {
    lanes: [Lane; 3],
    standin: Option<StandIn>,
    w: Option<World>,
    servers_scratch: Option<Scratch>,
    hs: Handshake,
    grants: BTreeMap<&'static str, String>,
    /// Host 2's log position after R's baseline login.
    r_mark: u64,
    /// When the harness's `locked` arrived (epoch seconds).
    locked_at: u64,
    /// C's last accepted serial.
    c_serial: u64,
    /// Credential-prompt processes present at the baseline, and those seen since.
    ui_baseline: BTreeSet<u32>,
    ui_new: BTreeSet<(u32, String)>,
}

impl Run {
    fn w(&self) -> &World {
        self.w.as_ref().expect("the world")
    }

    fn lane(&mut self, role: Role) -> &mut Lane {
        &mut self.lanes[role.pair()]
    }

    fn grant(&self, role: Role) -> String {
        self.grants
            .get(role.letter())
            .cloned()
            .unwrap_or_else(|| panic!("grant {} is not known", role.letter()))
    }

    fn key_prefix(&self, grant: &str) -> String {
        format!("heimdall:{}:{grant}:", self.w().environment.as_str())
    }

    // ---- prepare ---------------------------------------------------------------------------

    fn prepare(hs: &Handshake) -> (Run, String) {
        let mut out = String::new();
        let os = platform();
        let hs = Handshake {
            dir: hs.dir.clone(),
            harness: hs.harness,
        };
        let product = cfg!(windows);
        if product {
            release_probe();
            owner_ssh_guard();
        }
        let servers_scratch = Scratch::new().expect("a scratch directory for the servers");
        let servers = servers(&servers_scratch);
        let (w, ca) = World::start(WorldOptions {
            pairs: 3,
            servers,
            per_pair_profiles: true,
            platform_session_lock: true,
            product,
            pair_policy_windows: vec![C_WINDOW, R_WINDOW, N_WINDOW],
            config_toml: Some(format!(
                "schema_version = 1\n\n[session]\nmax_window = \"{}s\"\n",
                C_WINDOW.as_secs()
            )),
            ..WorldOptions::default()
        });
        drop(ca);
        hs.write("runtime-home.txt", &w.hh.to_string_lossy());
        let _ = writeln!(
            out,
            "m03 observation: a03 {os} world three hosts with disjoint pairs (exit-1..3 on hosts 1..3), {} configuration, session-lock source platform",
            if product {
                "product (no HEIMDALL_TEST_* variable)"
            } else {
                "debug test"
            }
        );
        // The platform source answers (the harness checked the same query reads
        // `unlocked`); `revoke-on-lock` needs it.
        let ls = w.cli(&["--json", "internal", "session-lock-state"]);
        let ls = ls.json();
        assert_eq!(ls["data"]["source"], "platform", "{ls}");
        assert_eq!(ls["data"]["state"], "unlocked", "{ls}");

        // The issuer's store kind as the product reports it.
        let status = w.cli(&["--json", "issuer", "status"]).json();
        assert_eq!(status["data"]["state"], "ready", "{status}");
        let kind = status["data"]["cas"][0]["store"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        hs.write("store-kind.txt", &kind);
        if product {
            assert_eq!(kind, "windows_dpapi", "the product DPAPI store kind");
            assert!(
                product_blob_exists(&w),
                "the K_ca blob is at the product location under the scratch home"
            );
            let _ = writeln!(
                out,
                "m03 observation: a03 {os} issuer store windows_dpapi (release product binary; K_ca read by the issuer child from the product DPAPI location under the scratch Heimdall home)"
            );
        } else {
            let _ = writeln!(
                out,
                "m03 observation: a03 {os} issuer store scratch_test (HEIMDALL_TEST_SECRET_STORE=scratch; the CA record's label reads {kind}); mechanism evidence only (F03)"
            );
        }

        // R's policy narrowed to `revoke-on-lock` (narrowing: no owner decision is asked).
        let lb = w.cli(&[
            "--json",
            "access",
            "lock-behavior",
            "--policy",
            "exit-pol-2",
            "revoke-on-lock",
        ]);
        assert_eq!(lb.code, 0, "{}", w.redact(&format!("{lb:?}")));
        let pol = heimdall_contract::ids::PolicyId::parse("exit-pol-2").unwrap();
        let stored = w
            .open_store()
            .transaction(|tx| tx.policy(&pol))
            .unwrap()
            .expect("policy exit-pol-2");
        assert_eq!(
            stored.lock_behavior,
            heimdall_contract::managed::LockBehavior::RevokeOnLock,
            "exit-pol-2 is revoke-on-lock"
        );
        for name in ["exit-pol-1", "exit-pol-3"] {
            let id = heimdall_contract::ids::PolicyId::parse(name).unwrap();
            let p = w
                .open_store()
                .transaction(|tx| tx.policy(&id))
                .unwrap()
                .expect("policy");
            assert_eq!(
                p.lock_behavior,
                heimdall_contract::managed::LockBehavior::Continue,
                "{name} continues"
            );
        }
        let _ = writeln!(
            out,
            "m03 observation: a03 {os} policies exit-pol-1 continue (window {} s), exit-pol-2 revoke_on_lock (`access lock-behavior`, narrowing), exit-pol-3 continue (window {} s; the standing policy for N)",
            C_WINDOW.as_secs(),
            N_WINDOW.as_secs()
        );

        // The stand-in agent, started and locked.
        let standin = StandIn::start(&w);
        let _ = writeln!(
            out,
            "m03 observation: a03 {os} stand_in {}",
            standin.label()
        );

        let sig = w.subdir("lanes");
        let lane = |role: Role, work: &'static str, plan: Vec<Planned>| {
            let dir = sig.join(role.letter());
            std::fs::create_dir(&dir).unwrap();
            Lane {
                role,
                work,
                plan,
                dir,
                worker: None,
                next: 0,
            }
        };
        let plain = |label| Planned {
            label,
            auth_sock: None,
        };
        let mut c_plan = vec![
            plain("c-baseline"),
            plain("c-locked-1"),
            plain("c-locked-2"),
            plain("c-locked-3"),
        ];
        if cfg!(windows) {
            c_plan.push(plain("c-after-restart"));
        }
        c_plan.push(Planned {
            label: "c-stand-in",
            auth_sock: Some(standin.locator()),
        });
        c_plan.push(plain("c-post"));
        let lanes = [
            lane(Role::C, "lock-c", c_plan),
            lane(
                Role::R,
                "lock-r",
                vec![plain("r-baseline"), plain("r-locked"), plain("r-post")],
            ),
            lane(
                Role::N,
                "lock-n",
                vec![plain("n-locked-1"), plain("n-locked-2"), plain("n-post")],
            ),
        ];
        let mut run = Run {
            lanes,
            standin: Some(standin),
            w: Some(w),
            servers_scratch: Some(servers_scratch),
            hs,
            grants: BTreeMap::new(),
            r_mark: 0,
            locked_at: 0,
            c_serial: 0,
            ui_baseline: prompt_ui().into_iter().map(|(p, _)| p).collect(),
            ui_new: BTreeSet::new(),
        };

        // The baselines: C, then R (after its policy's narrowing).
        for role in [Role::C, Role::R] {
            let login = run.drive(role, "prepare");
            let cert = run.attributed_any(&login, role, "the baseline login");
            let grant = grant_of(&cert.key_id);
            let deadline = run.deadline(&grant);
            run.hs.append(
                "grants.tsv",
                &format!(
                    "{}\t{grant}\t{}\t{deadline}",
                    role.letter(),
                    role.pair() + 1
                ),
            );
            run.grants.insert(role.letter(), grant.clone());
            if role == Role::C {
                run.c_serial = cert.serial;
                let left = deadline.saturating_sub(epoch());
                assert!(
                    left >= C_MIN_LEFT.as_secs(),
                    "grant C has {left} s left; at least {} s are needed (≥ 13 h after the lock)",
                    C_MIN_LEFT.as_secs()
                );
                let _ = writeln!(
                    out,
                    "m03 observation: a03 {os} grant C {grant} host 1 continue, {left} s left at the baseline; baseline login accepted, key ID {}",
                    cert.key_id
                );
            } else {
                run.r_mark = run.w().pairs[1].sshd.log_mark();
                let _ = writeln!(
                    out,
                    "m03 observation: a03 {os} grant R {grant} host 2 revoke_on_lock; baseline login accepted, key ID {}",
                    cert.key_id
                );
            }
        }
        assert_ne!(run.grant(Role::C), run.grant(Role::R), "disjoint grants");
        let _ = writeln!(
            out,
            "m03 observation: a03 {os} credential_prompt_processes_at_baseline {} (names: {})",
            run.ui_baseline.len(),
            PROMPT_UI.join(", ")
        );
        (run, out)
    }

    // ---- logins ----------------------------------------------------------------------------

    /// Make `role`'s next planned login (spawning its worker for the first one), record
    /// it in `logins.tsv` and return it.
    fn drive(&mut self, role: Role, phase: &str) -> Login {
        let pair = role.pair();
        let mark = self.w().pairs[pair].sshd.log_mark();
        let at = epoch();
        let k = self.lane(role).next;
        assert!(k < self.lane(role).plan.len(), "no planned login left");
        if k == 0 {
            let worker = self.spawn_lane(role);
            self.lane(role).worker = Some(worker);
        } else {
            let go = self.lane(role).go(k - 1);
            std::fs::write(go, b"").unwrap();
        }
        let signal = self.lane(role).signal(k);
        let label = self.lane(role).plan[k].label;
        let results = self
            .lane(role)
            .worker
            .as_mut()
            .unwrap()
            .wait_signal(&signal, Duration::from_secs(240));
        self.lane(role).next = k + 1;
        let r = worker::result(&results, "login", Some(label));
        let ok = r["exit"] == 0 && r["marker_seen"] == true;
        let stderr = self.w().redact(r["stderr"].as_str().unwrap_or_default());
        let certs = self.w().accepted_since(pair, mark);
        let host = pair + 1;
        if certs.is_empty() {
            self.hs.append(
                "logins.tsv",
                &format!(
                    "{at}\t{phase}\t{host}\t{}\t-\t{}",
                    role.letter(),
                    if ok { "accepted" } else { "refused" }
                ),
            );
        }
        for c in &certs {
            self.hs.append(
                "logins.tsv",
                &format!(
                    "{at}\t{phase}\t{host}\t{}\t{}\taccepted",
                    role.letter(),
                    c.key_id
                ),
            );
        }
        Login { ok, certs, stderr }
    }

    fn spawn_lane(&self, role: Role) -> Worker {
        let w = self.w();
        let lane = &self.lanes[role.pair()];
        let n = lane.plan.len();
        let mut tasks: Vec<Value> = Vec::new();
        for (k, p) in lane.plan.iter().enumerate() {
            let marker = format!(
                "hm-lock-{}-{}",
                p.label,
                heimdall_testkit::agent::random_hex(6)
            );
            let (program, args, mut env) = w.login_command(role.pair(), &marker);
            if let Some(sock) = &p.auth_sock {
                for (key, value) in &mut env {
                    if key.as_os_str() == "SSH_AUTH_SOCK" {
                        value.clone_from(sock);
                    }
                }
            }
            tasks.push(worker::login(p.label, &(program, args, env), &marker));
            tasks.push(worker::signal(&lane.signal(k)));
            if k + 1 < n {
                let wait = if k + 2 == n {
                    WORKER_POST_WAIT
                } else {
                    WORKER_WAIT
                };
                tasks.push(worker::wait(&lane.go(k), wait));
            }
        }
        let profile = w.profile_of(role.pair());
        w.spawn_worker_on(&profile, lane.work, &format!("{}-run", lane.work), tasks)
    }

    /// The login was accepted with exactly one certificate under the world's CA: that
    /// certificate (its key ID's grant is the caller's to check).
    fn attributed_any(&self, login: &Login, role: Role, what: &str) -> AcceptedCert {
        assert!(
            login.ok,
            "{what} ({}): the client did not log in: {}",
            role.letter(),
            login.stderr
        );
        assert_eq!(
            login.certs.len(),
            1,
            "{what} ({}): exactly one accepted certificate on host {}: {:?}",
            role.letter(),
            role.pair() + 1,
            login.certs
        );
        let c = login.certs[0].clone();
        assert_eq!(
            c.ca_fingerprint,
            self.w().ca_fingerprint.as_str(),
            "{what}: the world's CA"
        );
        assert!(
            c.key_id
                .starts_with(&format!("heimdall:{}:", self.w().environment.as_str())),
            "{what}: a managed key ID: {}",
            c.key_id
        );
        c
    }

    /// The login was accepted with exactly one certificate whose key ID names `role`'s
    /// grant (F09).
    fn attributed(&self, login: &Login, role: Role, what: &str) -> AcceptedCert {
        let c = self.attributed_any(login, role, what);
        let grant = self.grant(role);
        assert!(
            c.key_id.starts_with(&self.key_prefix(&grant)),
            "{what}: the key ID {} names grant {} ({grant})",
            c.key_id,
            role.letter()
        );
        c
    }

    /// The login was refused and the host accepted nothing.
    fn refused(&self, login: &Login, role: Role, what: &str) {
        assert!(!login.ok, "{what} ({}): the login succeeded", role.letter());
        assert!(
            login.certs.is_empty(),
            "{what} ({}): host {} accepted {:?}",
            role.letter(),
            role.pair() + 1,
            login.certs
        );
    }

    fn snapshot(&self, grant: &str) -> heimdall_domain::grant::GrantSnapshot {
        let id = heimdall_contract::ids::GrantId::parse(grant).unwrap();
        self.w()
            .open_store()
            .transaction(|tx| tx.grant(&id))
            .unwrap()
            .unwrap_or_else(|| panic!("grant {grant} is stored"))
    }

    /// The grant's effective deadline, epoch seconds.
    fn deadline(&self, grant: &str) -> u64 {
        u64::try_from(self.snapshot(grant).deadline.effective.as_second()).unwrap_or(0)
    }

    fn note_prompts(&mut self) {
        for (pid, name) in prompt_ui() {
            if !self.ui_baseline.contains(&pid) {
                self.ui_new.insert((pid, name));
            }
        }
    }

    // ---- locked ----------------------------------------------------------------------------

    fn locked_step(&mut self, step: Step) -> String {
        let r = match step {
            Step::FreshLogins => self.fresh_logins(),
            Step::NewGrant => self.new_grant(),
            Step::IssuerRestart => self.issuer_restart(),
            Step::LockRevokes => self.lock_revokes(),
            Step::StandIn => self.stand_in(),
            _ => unreachable!("not a locked step"),
        };
        self.note_prompts();
        r
    }

    fn fresh_logins(&mut self) -> String {
        let os = platform();
        let mut out = String::new();
        let mut last: Option<Instant> = None;
        for n in 1..=3 {
            if let Some(t) = last {
                let left = SAMPLE_INTERVAL.saturating_sub(t.elapsed());
                std::thread::sleep(left);
            }
            last = Some(Instant::now());
            self.note_prompts();
            let login = self.drive(Role::C, "locked");
            let cert = self.attributed(&login, Role::C, &format!("locked login {n} to host 1"));
            self.c_serial = cert.serial;
            let _ = writeln!(
                out,
                "m03 observation: a03 {os} locked_login {n} host 1 accepted key_id {} serial {} (grant C)",
                cert.key_id, cert.serial
            );
        }
        out
    }

    fn new_grant(&mut self) -> String {
        let os = platform();
        let mut out = String::new();
        // The explicit non-interactive `access ensure` under the standing policy.
        let profile = self.w().profile_of(Role::N.pair());
        let data = self
            .w()
            .ensure_on(&profile, "lock-n-ensure", "lock-n-ensure-1");
        let ensured = data["grant_id"].as_str().unwrap().to_owned();
        let published = self.w().published(&ensured);
        assert_eq!(
            published.len(),
            1,
            "the issuer signed the ensured grant's certificate under lock"
        );
        let starts = self.snapshot(&ensured).starts_at.as_second();
        assert!(
            u64::try_from(starts).unwrap_or(0) + 1 >= self.locked_at,
            "the ensured grant was created under lock"
        );
        self.hs
            .append("events.tsv", &format!("{}\tensured\tN", epoch()));
        let _ = writeln!(
            out,
            "m03 observation: a03 {os} ensure_under_lock profile exit-3 ACCESS_READY grant {ensured} (one certificate signed under lock, key ID {})",
            published[0].1
        );
        // Grant N: a worker's `run` on host 3's profile (its own non-interactive ensure).
        let login = self.drive(Role::N, "locked");
        let cert = self.attributed_any(&login, Role::N, "N's first locked login");
        let n = grant_of(&cert.key_id);
        assert_ne!(n, self.grant(Role::C), "N is not C");
        assert_ne!(n, self.grant(Role::R), "N is not R");
        let starts = self.snapshot(&n).starts_at.as_second();
        assert!(
            u64::try_from(starts).unwrap_or(0) + 1 >= self.locked_at,
            "grant N was created under lock"
        );
        assert!(
            self.w().published(&n).iter().any(|e| e.0 == cert.serial),
            "the login used N's certificate, signed under lock"
        );
        let deadline = self.deadline(&n);
        self.hs
            .append("grants.tsv", &format!("N\t{n}\t3\t{deadline}"));
        self.grants.insert("N", n.clone());
        let _ = writeln!(
            out,
            "m03 observation: a03 {os} grant N {n} host 3 created under lock by run's ensure, {} s left; locked_login 1 host 3 accepted key_id {} (grant N){}",
            deadline.saturating_sub(epoch()),
            cert.key_id,
            if n == ensured {
                " (the same grant as the explicit ensure)"
            } else {
                " (a grant of its own; the explicit ensure's grant has no binding)"
            }
        );
        let login = self.drive(Role::N, "locked");
        let cert = self.attributed(&login, Role::N, "N's second locked login");
        let _ = writeln!(
            out,
            "m03 observation: a03 {os} locked_login 2 host 3 accepted key_id {} (grant N)",
            cert.key_id
        );
        out
    }

    fn issuer_restart(&mut self) -> String {
        let os = platform();
        let c = self.grant(Role::C);
        let n = self.grant(Role::N);
        let (pc, pn) = (self.w().published(&c).len(), self.w().published(&n).len());
        let before = self.c_serial;
        // A forced runtime restart under lock: K_env lived only in the old process; the
        // new one starts its issuer child, which unprotects K_ca from DPAPI now.
        self.w().restart_runtime();
        self.w().wait_reissued(&[&c], pc + 1);
        self.w().wait_reissued(&[&n], pn + 1);
        let login = self.drive(Role::C, "locked");
        let cert = self.attributed(&login, Role::C, "C's login after the restart");
        assert_ne!(cert.serial, before, "a new certificate (serial)");
        assert!(
            self.w().published(&c).iter().any(|e| e.0 == cert.serial),
            "the login used C's re-issued certificate"
        );
        self.c_serial = cert.serial;
        format!(
            "m03 observation: a03 {os} issuer_restart_under_lock issuer status ready (K_ca unprotected under lock); C and N re-issued; host 1 accepted key_id {} serial {} (was {before})\n",
            cert.key_id, cert.serial
        )
    }

    fn lock_revokes(&mut self) -> String {
        let os = platform();
        let r = self.grant(Role::R);
        let id = heimdall_contract::ids::GrantId::parse(&r).unwrap();
        let start = Instant::now();
        let tomb = loop {
            let t = self
                .w()
                .open_store()
                .transaction(|tx| tx.tombstone(&id))
                .unwrap();
            if let Some(t) = t {
                break t;
            }
            assert!(
                start.elapsed() < Duration::from_secs(120),
                "no revocation of R within 120 s (state {})",
                self.w().grant_state(&r)
            );
            std::thread::sleep(Duration::from_millis(500));
        };
        assert_eq!(
            tomb.cause,
            heimdall_domain::revocation::RevocationCause::SessionLocked,
            "R's revocation cause"
        );
        let revoked_at = u64::try_from(tomb.revoked_at.as_second()).unwrap_or(0);
        self.hs
            .append("events.tsv", &format!("{revoked_at}\trevoked\tR"));
        assert_eq!(self.w().grant_state(&r), "revoked", "R is revoked");
        let login = self.drive(Role::R, "locked");
        self.refused(&login, Role::R, "R's fresh login after its revocation");
        let prefix = self.key_prefix(&r);
        let after: Vec<String> = self
            .w()
            .accepted_since(Role::R.pair(), self.r_mark)
            .into_iter()
            .map(|c| c.key_id)
            .collect();
        assert!(
            after.iter().all(|k| !k.starts_with(&prefix)),
            "no accepted line for any key ID of R after its baseline: {after:?}"
        );
        let offset =
            i64::try_from(revoked_at).unwrap_or(0) - i64::try_from(self.locked_at).unwrap_or(0);
        format!(
            "m03 observation: a03 {os} lock_revokes R revoked cause session_locked at {offset:+} s from the harness's verified-lock flag; fresh login to host 2 refused; host 2 accepted none of R's key IDs since its baseline\n"
        )
    }

    fn stand_in(&mut self) -> String {
        let os = platform();
        let before = self.standin.as_ref().unwrap().probe();
        assert_eq!(
            before,
            Ok(0),
            "the stand-in agent lists nothing while locked"
        );
        let contacts = self.standin.as_ref().unwrap().contacts();
        let login = self.drive(Role::C, "locked");
        let cert = self.attributed(
            &login,
            Role::C,
            "the managed login with the locked stand-in as SSH_AUTH_SOCK",
        );
        let after = self.standin.as_ref().unwrap().probe();
        assert_eq!(after, Ok(0), "the stand-in agent is still locked");
        let used = self
            .standin
            .as_ref()
            .unwrap()
            .contacts()
            .map(|n| n.saturating_sub(contacts.unwrap_or(0)));
        self.note_prompts();
        let prompts: Vec<String> = self.ui_new.iter().map(|(_, n)| n.clone()).collect();
        assert!(
            prompts.is_empty(),
            "a keychain or credential prompt process appeared while locked: {prompts:?}"
        );
        format!(
            "m03 observation: a03 {os} stand_in_locked lists 0 before and after; managed login host 1 accepted key_id {} (grant C); stand-in contacts during the login {}; new credential prompt processes 0 (names: {})\n",
            cert.key_id,
            used.map_or_else(
                || "unobservable (a real ssh-agent)".to_owned(),
                |n| n.to_string()
            ),
            PROMPT_UI.join(", ")
        )
    }

    // ---- after the unlock ------------------------------------------------------------------

    fn post_unlock(&mut self, expect: &str) -> String {
        let cases: BTreeMap<String, String> = expect
            .split_whitespace()
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        // Each grant is checked on its own, so one failure never hides another's result.
        let mut out = String::new();
        let mut failures = Vec::new();
        for role in [Role::R, Role::C, Role::N] {
            let case = cases.get(role.letter()).cloned().unwrap_or_default();
            match guarded(|| self.post_one(role, &case)) {
                Ok(text) => out.push_str(&text),
                Err(why) => failures.push(format!("{}: {why}", role.letter())),
            }
        }
        assert!(
            failures.is_empty(),
            "{} (expectation {expect:?}; passed: {})",
            failures.join("; "),
            out.trim_end().replace('\n', " | ")
        );
        out
    }

    /// One grant after the unlock: R terminal; C or N by `case` (`usable`, `expired`).
    fn post_one(&mut self, role: Role, case: &str) -> String {
        let os = platform();
        let grant = self.grant(role);
        if role == Role::R {
            assert_eq!(case, "terminal", "the expectation names R terminal");
            // Terminal, never reactivated.
            assert_eq!(
                self.w().grant_state(&grant),
                "revoked",
                "R is still revoked"
            );
            let id = heimdall_contract::ids::GrantId::parse(&grant).unwrap();
            let tomb = self
                .w()
                .open_store()
                .transaction(|tx| tx.tombstone(&id))
                .unwrap()
                .expect("R's tombstone");
            assert_eq!(
                tomb.cause,
                heimdall_domain::revocation::RevocationCause::SessionLocked
            );
            let login = self.drive(Role::R, "post");
            self.refused(&login, Role::R, "R's fresh login after the unlock");
            let prefix = self.key_prefix(&grant);
            assert!(
                self.w()
                    .accepted_since(Role::R.pair(), self.r_mark)
                    .iter()
                    .all(|c| !c.key_id.starts_with(&prefix)),
                "nothing of R accepted since its baseline"
            );
            return format!(
                "m03 observation: a03 {os} post_unlock R terminal (revoked, cause session_locked, not reactivated; fresh login refused)\n"
            );
        }
        match case {
            "usable" => {
                let login = self.drive(role, "post");
                let cert = self.attributed(
                    &login,
                    role,
                    &format!("{}'s fresh login after the unlock", role.letter()),
                );
                format!(
                    "m03 observation: a03 {os} post_unlock {} usable (deadline not passed): host {} accepted key_id {}\n",
                    role.letter(),
                    role.pair() + 1,
                    cert.key_id
                )
            }
            "expired" => {
                let start = Instant::now();
                while self.w().grant_state(&grant) != "expired" {
                    assert!(
                        start.elapsed() < Duration::from_secs(180),
                        "{} past its deadline reads {}, not expired",
                        role.letter(),
                        self.w().grant_state(&grant)
                    );
                    std::thread::sleep(Duration::from_secs(1));
                }
                let mark = self.w().pairs[role.pair()].sshd.log_mark();
                let login = self.drive(role, "post");
                self.refused(
                    &login,
                    role,
                    &format!("{}'s fresh login past its deadline", role.letter()),
                );
                let prefix = self.key_prefix(&grant);
                assert!(
                    self.w()
                        .accepted_since(role.pair(), mark)
                        .iter()
                        .all(|c| !c.key_id.starts_with(&prefix)),
                    "nothing of {} accepted past its deadline",
                    role.letter()
                );
                format!(
                    "m03 observation: a03 {os} post_unlock {} expired (deadline passed): state expired, fresh login refused\n",
                    role.letter()
                )
            }
            other => panic!(
                "no usable or expired expectation for {}: {other:?}",
                role.letter()
            ),
        }
    }

    // ---- cleanup ---------------------------------------------------------------------------

    fn cleanup(&mut self) -> String {
        let mut out = String::new();
        // The workers: each ends after its last login, else it is killed through its
        // handle (a worker still waiting for a login that will not come).
        let mut ended = 0;
        let mut killed = 0;
        for lane in &mut self.lanes {
            if let Some(wk) = lane.worker.take() {
                let done = lane.next >= lane.plan.len();
                let o = wk.finish(Duration::from_secs(if done { 60 } else { 1 }));
                if done && o.code == 0 {
                    ended += 1;
                } else {
                    killed += 1;
                }
            }
        }
        let _ = writeln!(
            out,
            "cleanup: workers ended {ended}, stopped through their handles {killed}"
        );
        if let Some(s) = self.standin.take() {
            let _ = writeln!(out, "cleanup: stand-in agent {}", s.stop());
        }
        let mut w = self.w.take().expect("the world");
        // ⟨W6-R01⟩ The world owns the projection's rollback (the product configuration
        // wrote the disposable account's configuration): a nonzero exit, a timeout, a
        // panic or a failed restoration check keeps its scratch home for recovery and
        // fails this cleanup.
        let rollback = w.rollback_projection();
        let _ = writeln!(
            out,
            "cleanup: {}",
            rollback
                .as_ref()
                .map_or_else(|e| e.as_str(), |t| t.as_str())
        );
        let stop = w.cli(&["--json", "service", "stop"]);
        assert!(
            matches!(stop.code, 0 | 5),
            "service stop: {}",
            w.redact(&format!("{stop:?}"))
        );
        let _ = writeln!(out, "cleanup: service stop exit {}", stop.code);
        let root = w.home.root.clone();
        let kept = rollback.is_err();
        drop(w);
        if kept {
            assert!(root.exists(), "the recovery state is kept");
        } else {
            assert!(!root.exists(), "the world's scratch directory is removed");
        }
        if let Some(s) = self.servers_scratch.take() {
            let p = s.path().to_path_buf();
            drop(s);
            assert!(!p.exists(), "the servers' scratch directory is removed");
        }
        let _ = writeln!(
            out,
            "cleanup: fixtures stopped through their handles; both scratch directories removed"
        );
        let _ = std::fs::remove_file(self.hs.dir.join("runtime-home.txt"));
        if let Err(why) = rollback {
            panic!("cleanup failed: {why}\n{out}");
        }
        out
    }
}

/// The grant a key ID names (`heimdall:<environment>:<grant>:<n>`).
fn grant_of(key_id: &str) -> String {
    key_id.split(':').nth(2).unwrap_or_default().to_owned()
}

// ---- platform pieces -------------------------------------------------------------------------

/// The keychain and credential prompt processes, by exact executable name (m03-plan §4.4
/// step 5: no prompt observed).
const PROMPT_UI: &[&str] = if cfg!(windows) {
    &["CredentialUIBroker", "consent"]
} else {
    &["SecurityAgent", "coreautha"]
};

fn prompt_ui() -> Vec<(u32, String)> {
    crate::procs::processes()
        .into_iter()
        .filter(|p| PROMPT_UI.contains(&p.name.as_str()))
        .map(|p| (p.pid, p.name))
        .collect()
}

/// The three servers: macOS [`ThreeHosts`] (account form); Windows the harness's WSL
/// sshds (`HM_LOCK_SSHD_<1..3>_{PORT,HOST_KEY,AUTHORIZED_KEYS,LOG,REGISTRY,REGISTRY_REMOTE,USER}`).
fn servers(scratch: &Scratch) -> Vec<LoopbackSshd> {
    if cfg!(windows) {
        (1..=3)
            .map(|i| {
                let ext = external_from_env(i);
                LoopbackSshd::external(
                    scratch,
                    &ext,
                    &SshdConfig {
                        registry_seed: Some(Vec::new()),
                        ..SshdConfig::default()
                    },
                )
                .unwrap_or_else(|e| panic!("harness sshd {i}: {e}"))
            })
            .collect()
    } else {
        ThreeHosts::start(
            scratch,
            heimdall_contract::enrollment::EnrollmentForm::Account,
        )
        .unwrap_or_else(|e| panic!("blocked: three loopback sshds: {e}"))
        .hosts
        .into_iter()
        .collect()
    }
}

fn external_from_env(i: usize) -> heimdall_testkit::sshd::ExternalSshd {
    let var = |k: &str| std::env::var(format!("HM_LOCK_SSHD_{i}_{k}")).ok();
    let path = |k: &str| var(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    heimdall_testkit::sshd::ExternalSshd {
        host: "127.0.0.1".to_owned(),
        port: var("PORT")
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or_else(|| panic!("HM_LOCK_SSHD_{i}_PORT is not a port")),
        host_key: var("HOST_KEY").unwrap_or_else(|| panic!("HM_LOCK_SSHD_{i}_HOST_KEY is not set")),
        authorized_keys: path("AUTHORIZED_KEYS"),
        log: path("LOG"),
        registry: path("REGISTRY"),
        registry_remote: var("REGISTRY_REMOTE").filter(|v| !v.is_empty()),
        account: var("USER").filter(|v| !v.is_empty()),
    }
}

/// The product binary is a release build: it refuses a test variable with exit 2
/// (`release_build_refuses_m03_test_gates`). Only such a run is claim-eligible (F03).
fn release_probe() {
    let dir = Scratch::new().expect("a scratch directory for the probe");
    let file = dir.path().join("lock-state");
    std::fs::write(&file, "locked").unwrap();
    let mut cmd = std::process::Command::new(crate::world::bin());
    cmd.args(["--json", "internal", "session-lock-state"])
        .env_clear()
        .env("HEIMDALL_TEST_SESSION_LOCK", &file)
        .current_dir(dir.path());
    for k in ["SystemRoot", "PATH", "TEMP", "TMP"] {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    let out = crate::world::run_bounded(&mut cmd, Duration::from_secs(60));
    assert!(
        out.code == 2,
        "blocked: not_release_profile: the product binary answered with a test variable set (exit {}); only a release-profile build is claim-eligible (F03)",
        out.code
    );
}

/// A release runtime projects into the account's own SSH configuration
/// (`ProjectionWiring::Account`, the account home from the account database, not from a
/// variable) and its existing-access adapters read the account's agents; `setup apply`
/// would edit `~/.ssh/config`. The owner's `~/.ssh` is never touched (AGENTS.md;
/// m03-plan §0.2), so the product configuration runs only for an account whose `.ssh` is
/// absent or empty (a disposable account).
fn owner_ssh_guard() {
    let home = heimdall_localenv::sys::account_home()
        .unwrap_or_else(|_| panic!("blocked: owner_ssh_in_scope: the account home is unreadable"));
    // ⟨W6-R01⟩ An absent or empty `.ssh` does not prove the account is disposable: the
    // B2 account's setup creates this marker, and only an account carrying it is used.
    let marker = home.join(DISPOSABLE_ACCOUNT_MARKER);
    let opted_in = std::fs::symlink_metadata(&marker).is_ok_and(|m| m.file_type().is_file());
    assert!(
        opted_in,
        "blocked: owner_ssh_in_scope: this account carries no {DISPOSABLE_ACCOUNT_MARKER} marker; the Windows lock procedure runs only in the disposable second Windows account (B2), whose setup creates that marker (a release-profile runtime projects into the account's own .ssh, ProjectionWiring::Account)"
    );
    let ssh = home.join(".ssh");
    let empty = match std::fs::read_dir(&ssh) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Ok(mut entries) => entries.next().is_none(),
        Err(_) => false,
    };
    assert!(
        empty,
        "blocked: owner_ssh_in_scope: this account's .ssh directory is not empty, and a release-profile runtime would read it and setup apply would edit its config (ProjectionWiring::Account); the disposable account (B2) starts with none (AGENTS.md: the owner's ~/.ssh is never edited)"
    );
}

/// ⟨W6-R01⟩ The opt-in a disposable Windows account carries in its profile directory
/// (created by the B2 account setup, never by this suite).
const DISPOSABLE_ACCOUNT_MARKER: &str = ".heimdall-disposable-account";

/// Windows: the K_ca blob exists where the release issuer child reads it.
fn product_blob_exists(w: &World) -> bool {
    #[cfg(windows)]
    {
        heimdall_issuer::store::WindowsDpapi::in_dir(w.store.dir(), &w.environment)
            .blob_path(&w.ca_fingerprint)
            .is_file()
    }
    #[cfg(not(windows))]
    {
        let _ = w;
        false
    }
}

/// The source-provider stand-in (m03-plan §4.4 step 2): macOS a disposable `ssh-agent`
/// holding a disposable key, locked with `ssh-add -x` through a scratch askpass (the
/// password stays in an owner-only scratch file, never in argv); Windows testkit's
/// `FakeAgent` in its `Locked` mode (labelled a stand-in). Never a system agent.
struct StandIn {
    endpoint: Endpoint,
    dir: PathBuf,
    #[cfg(unix)]
    agent: Option<std::process::Child>,
    #[cfg(windows)]
    fake: Option<heimdall_testkit::agent::FakeAgent>,
}

impl StandIn {
    fn start(w: &World) -> StandIn {
        let dir = w.subdir("standin");
        #[cfg(unix)]
        {
            let sock = dir.join("a.sock");
            let agent = std::process::Command::new(crate::world::openssh("ssh-agent"))
                .arg("-D")
                .arg("-a")
                .arg(&sock)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .current_dir(&dir)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("blocked: a disposable ssh-agent");
            let s = StandIn {
                endpoint: Endpoint::UnixSocket(sock.clone()),
                dir: dir.clone(),
                agent: Some(agent),
            };
            let start = Instant::now();
            while !sock.exists() {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "the stand-in agent did not listen"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            let key = FixtureKey::generate().with_comment("hm-stand-in");
            key.write_private(&dir.join("k1")).unwrap();
            assert_eq!(s.ssh_add(&[dir.join("k1").as_os_str()]), 0, "ssh-add k1");
            assert_eq!(s.probe(), Ok(1), "the stand-in holds its key");
            // Lock it: `ssh-add -x` reads the password twice through the askpass.
            let pw = dir.join("pw");
            write_private_file(&pw, heimdall_testkit::agent::random_hex(16).as_bytes());
            let askpass = dir.join("askpass.sh");
            write_private_file(
                &askpass,
                format!(
                    "#!/bin/sh\nexec /bin/cat {}\n",
                    heimdall_testkit::home::sh_quote(pw.as_os_str())
                )
                .as_bytes(),
            );
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            assert_eq!(s.ssh_add(&[std::ffi::OsStr::new("-x")]), 0, "ssh-add -x");
            assert_eq!(s.probe(), Ok(0), "the locked stand-in lists nothing");
            s
        }
        #[cfg(windows)]
        {
            let endpoint = Endpoint::in_scratch(w.home.scratch(), "standin").unwrap();
            let fake = heimdall_testkit::agent::FakeAgent::start(
                endpoint.clone(),
                heimdall_testkit::agent::FakeAgentConfig {
                    keys: vec![FixtureKey::generate().with_comment("hm-stand-in")],
                    mode: heimdall_testkit::agent::AgentMode::Locked,
                },
            );
            let s = StandIn {
                endpoint,
                dir,
                fake: Some(fake),
            };
            assert_eq!(s.probe(), Ok(0), "the locked stand-in lists nothing");
            s
        }
    }

    fn label(&self) -> &'static str {
        if cfg!(windows) {
            "FakeAgent in its Locked mode (a stand-in for a locked vault agent) lists 0 identities"
        } else {
            "disposable ssh-agent with one disposable key, locked with ssh-add -x (scratch askpass): lists 0 identities, refuses an add"
        }
    }

    fn locator(&self) -> OsString {
        self.endpoint.locator()
    }

    /// How many identities it lists; on Unix also that it refuses an add (a locked
    /// agent does; an empty unlocked one would not), else `Err`.
    fn probe(&self) -> Result<usize, String> {
        let n = AgentConnection::connect(&self.endpoint, Duration::from_secs(10))
            .and_then(|mut c| c.list())
            .map(|l| l.len())
            .map_err(|e| format!("cannot list the stand-in: {:?}", e.kind()))?;
        #[cfg(unix)]
        if n == 0 {
            let k2 = self.dir.join("k2");
            if !k2.exists() {
                FixtureKey::generate()
                    .with_comment("hm-stand-in-2")
                    .write_private(&k2)
                    .unwrap();
            }
            if self.ssh_add(&[k2.as_os_str()]) == 0 {
                return Err("the stand-in accepted an add: it is not locked".to_owned());
            }
        }
        Ok(n)
    }

    /// Signing and listing requests it received (Windows `FakeAgent`); `None` for a real
    /// `ssh-agent`.
    fn contacts(&self) -> Option<usize> {
        #[cfg(windows)]
        {
            self.fake.as_ref().map(|f| f.contact_count())
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    #[cfg(unix)]
    fn ssh_add(&self, args: &[&std::ffi::OsStr]) -> i32 {
        let mut cmd = std::process::Command::new(crate::world::openssh("ssh-add"));
        cmd.args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("SSH_AUTH_SOCK", self.endpoint.locator())
            .env("SSH_ASKPASS", self.dir.join("askpass.sh"))
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", ":0")
            .current_dir(&self.dir);
        crate::world::run_bounded(&mut cmd, Duration::from_secs(30)).code
    }

    /// Stop it through its handle.
    fn stop(mut self) -> &'static str {
        #[cfg(unix)]
        if let Some(mut c) = self.agent.take() {
            let _ = c.kill();
            let _ = c.wait();
            return "stopped through its handle";
        }
        #[cfg(windows)]
        if let Some(f) = self.fake.take() {
            drop(f);
            return "stopped through its handle";
        }
        "already stopped"
    }
}

impl Drop for StandIn {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(mut c) = self.agent.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        f.write_all(bytes).unwrap();
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes).unwrap();
}
