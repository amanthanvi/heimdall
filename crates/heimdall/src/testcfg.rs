//! Env-gated test configuration for `heimdall service run` (m01-plan U9 "test
//! adapter wiring"; never a production path).
//!
//! The runtime ships with no credential adapter in M01. The end-to-end suite
//! (`tests/e2e/cli_m01.rs`) needs a runtime that can actually prepare access, so a
//! **debug build** (`cfg(debug_assertions)`) accepts these variables in
//! `service run`:
//!
//! | Variable | Meaning |
//! |---|---|
//! | `HEIMDALL_TEST_ADAPTER` | Fake adapter script, comma-separated steps: `prepare`, `lose_reply` (apply the effect, lose the reply), `unavailable` (fail with `AdapterError::Unavailable`). Setting it enables the configuration. |
//! | `HEIMDALL_TEST_LEDGER` | Absolute path of the fake adapter's durable effect ledger (`FakeCredentialAdapter::with_ledger`). |
//! | `HEIMDALL_TEST_HANG_AFTER_EFFECT` | Absolute marker path: after the first applied `prepare` the adapter writes the marker and never returns (the effect is in the ledger, its receipt is not), so a test can kill the service by exact PID at that point. |
//! | `HEIMDALL_TEST_SLOW_PREPARE_MS` | Delay before every `prepare` (bounded waits end with `ACCEPTED`). |
//! | `HEIMDALL_TEST_TIME_SYNC` | `synchronized`, `not_synchronized` or `unknown` (default `unknown`, the production stub's answer). |
//! | `HEIMDALL_TEST_STAGE_FAIL` | One-shot pipeline fault through the production `StageHook`: `before:<stage>:<CODE>` or `after:<stage>:<CODE>`. |
//! | `HEIMDALL_TEST_CLOCK_OFFSET_S` | ⟨M02⟩ m02-plan U8 (ADR-0007 §12.14 item 8): shifts the **wall** clock of the runtime and of `run`/`connect` by a signed number of seconds. The value is the number itself, or an absolute path of a file holding it, read at every clock reading, so a test can move the clock during a pause (write it with a rename; an unreadable or malformed file reads as 0). The continuous clock and the boot ID are not shifted. |
//!
//! When any of them is set the configuration also requires an explicit
//! `HEIMDALL_HOME` (it never touches the per-user default directories), seeds a
//! fixture environment record, profile `dev` (`h1`, `h2`, `h3` as `deploy`) and
//! policy `pol` (covers `h1` and `h2`; `h3` is added authority), and profile `ops`
//! (`h1`) fully covered by policy `pol-ops`, once per store,
//! and appends this process's PID to `<state>/test-service-starts` before the
//! instance lock is taken (the single-child launcher test counts the lines). On
//! Windows its pipes carry the `hmtest-` prefix before the random token.
//!
//! **Release builds refuse it.** Without `debug_assertions` nothing in this
//! module references `heimdall-testkit`, so none of it is linked, and
//! [`refusal`] makes `service run` exit 2 (`USAGE_ERROR`) when any of the
//! variables is set: a release runtime never silently ignores a request to run
//! with a fake adapter, and never honours one.
//!
//! **⟨M02⟩ `run` and `connect`** (m02-plan U8). The CLI process reads these
//! ([`launch_hooks`]); a release build refuses `run` and `connect` (exit 2) when one
//! is set, and never honours them:
//!
//! | Variable | Meaning |
//! |---|---|
//! | `HEIMDALL_TEST_PRE_EXEC_PAUSE` | Absolute FIFO path: after `launching` is written, the CLI opens it for reading and blocks until a writer opens it (or the test stops the process by exact PID). |
//! | `HEIMDALL_TEST_PRE_CHECK_PAUSE` | Absolute FIFO path: after `bind` and Git resolution, before the pre-launch eligibility check, the CLI opens it for reading and reads until the writer closes it (so the test's own open returns once the CLI is paused, and closing releases it). |
//! | `HEIMDALL_TEST_FORCE_EXEC_FAILURE` | `1`: the exec (Unix) fails after `launching` (`heimdall_launch::unix::TestHooks`). |
//! | `HEIMDALL_TEST_SSH_HOME` | Absolute scratch account home for the CLI's static selection pass (`SshPaths::with_test_override`, system directory `<home>/etc-ssh`), so a test never reads the account's real `~/.ssh` or `/etc/ssh`. ⟨M02⟩ W4: a runtime started under any test variable wires its projection over this scratch home, or none without it, never the account's (`isolate_projection`). |
//! | `HEIMDALL_TEST_CLOCK_OFFSET_S` | As above: the CLI's wall clock for the pre-launch check. |
//!
//! **⟨M03⟩ managed credentials** (m03-plan U0b row 16; ADR-0008 §18). Four more
//! variables, debug builds only. `service run` reads the first three (U10 wires them
//! into the runtime); the `enroll` CLI process reads the fourth (the client-executed
//! remote steps pause there, U5). A release build that finds **any** of them set
//! refuses at that command (exit 2, `USAGE_ERROR`) before anything else happens:
//! [`requested`] covers all four for `service run`, and [`enroll_hooks`] covers the
//! pause directory for `enroll`.
//!
//! | Variable | Meaning |
//! |---|---|
//! | `HEIMDALL_TEST_SECRET_STORE` | `scratch`: select testkit's `ScratchSecretStore` for the CA key instead of the platform secret store. ⟨ADR-0008 §17.25 item 7 (b)⟩ `product-file:<abs path>`: a disposable store of a **product** kind the test created in its scratch home (macOS: a file keychain outside the search list; Windows: a DPAPI directory; refused on Linux), checked by `heimdall_issuer::store::test_product::refusal` against the explicit `HEIMDALL_HOME` ([`test_store`]). |
//! | `HEIMDALL_TEST_KEY_SEED` | Hex seed (1 to 64 bytes) of the deterministic test key material. |
//! | `HEIMDALL_TEST_SESSION_LOCK` | Absolute path of the state file testkit's `FakeSessionLockSource` reads. |
//! | `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` | Absolute directory in which an enrollment script pauses. |
//!
//! The fake adapter's credential reference carries a synthetic
//! `HEIMDALL_CANARY_*` value built at runtime; it must never reach an envelope,
//! event or log line (the e2e suite scans every byte the binary prints).

/// ⟨M02⟩ U8: FIFO opened after `launching`, before exec.
pub const PRE_EXEC_PAUSE_ENV: &str = "HEIMDALL_TEST_PRE_EXEC_PAUSE";
/// ⟨M02⟩ U8: FIFO opened after `bind` and Git resolution, before the check.
pub const PRE_CHECK_PAUSE_ENV: &str = "HEIMDALL_TEST_PRE_CHECK_PAUSE";
/// ⟨M02⟩ U8: make the exec fail after `launching`.
pub const FORCE_EXEC_FAILURE_ENV: &str = "HEIMDALL_TEST_FORCE_EXEC_FAILURE";
/// ⟨M02⟩ U8: scratch account home for the CLI's static selection pass.
pub const SSH_HOME_ENV: &str = "HEIMDALL_TEST_SSH_HOME";

/// ⟨M02⟩ Every variable `run` and `connect` read.
pub const LAUNCH_ENV: [&str; 5] = [
    PRE_EXEC_PAUSE_ENV,
    PRE_CHECK_PAUSE_ENV,
    FORCE_EXEC_FAILURE_ENV,
    SSH_HOME_ENV,
    CLOCK_OFFSET_ENV,
];

/// ⟨M02⟩ A wall-clock offset (module docs): fixed, or read from a file at every use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockOffset {
    /// A fixed number of seconds.
    Fixed(i64),
    /// An absolute file holding the number of seconds.
    File(std::path::PathBuf),
}

impl ClockOffset {
    /// Parse the variable's value: a signed integer, or an absolute path.
    ///
    /// # Errors
    /// Anything else (a usage error of the test harness).
    pub fn parse(value: &std::ffi::OsStr) -> Result<ClockOffset, String> {
        if let Some(n) = value.to_str().and_then(|v| v.trim().parse::<i64>().ok()) {
            return Ok(ClockOffset::Fixed(n));
        }
        let path = std::path::PathBuf::from(value);
        if path.is_absolute() {
            Ok(ClockOffset::File(path))
        } else {
            Err(format!(
                "{CLOCK_OFFSET_ENV}: expected seconds or an absolute file path"
            ))
        }
    }

    /// The offset now, in seconds (an unreadable or malformed file reads as 0).
    #[must_use]
    pub fn seconds(&self) -> i64 {
        match self {
            ClockOffset::Fixed(n) => *n,
            ClockOffset::File(path) => std::fs::read_to_string(path)
                .ok()
                .and_then(|t| t.trim().parse::<i64>().ok())
                .unwrap_or(0),
        }
    }

    /// `wall` shifted by the offset (saturating at the representable range).
    #[must_use]
    pub fn shift(&self, wall: heimdall_contract::Timestamp) -> heimdall_contract::Timestamp {
        let secs = self.seconds();
        let span = std::time::Duration::from_secs(secs.unsigned_abs());
        if secs >= 0 {
            wall.checked_add(span).unwrap_or(wall)
        } else {
            wall.checked_sub(span).unwrap_or(wall)
        }
    }
}

/// ⟨M02⟩ What `run` and `connect` take from the test configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchHooks {
    /// [`PRE_EXEC_PAUSE_ENV`].
    pub pre_exec_pause: Option<std::path::PathBuf>,
    /// [`PRE_CHECK_PAUSE_ENV`].
    pub pre_check_pause: Option<std::path::PathBuf>,
    /// [`FORCE_EXEC_FAILURE_ENV`].
    pub force_exec_failure: bool,
    /// [`SSH_HOME_ENV`].
    pub ssh_home: Option<std::path::PathBuf>,
    /// [`CLOCK_OFFSET_ENV`].
    pub clock_offset: Option<ClockOffset>,
}

impl LaunchHooks {
    /// The CLI's wall clock (the production clock, shifted by the offset).
    #[must_use]
    pub fn now(&self) -> heimdall_contract::Timestamp {
        let now = heimdall_contract::Timestamp::now();
        self.clock_offset.as_ref().map_or(now, |o| o.shift(now))
    }
}

/// ⟨M02⟩ The `run`/`connect` hooks from `env` (module docs). A build without the test
/// configuration refuses any of them; a debug build parses them.
///
/// # Errors
/// A refusal or a malformed value (usage errors, exit 2).
pub fn launch_hooks(
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<LaunchHooks, String> {
    let any = LAUNCH_ENV.iter().any(|name| env(name).is_some());
    if let Some(msg) = refusal(AVAILABLE, any) {
        return Err(msg.to_owned());
    }
    if !any {
        return Ok(LaunchHooks::default());
    }
    let absolute = |name: &str| -> Result<Option<std::path::PathBuf>, String> {
        env(name)
            .map(|v| {
                let p = std::path::PathBuf::from(v);
                if p.is_absolute() {
                    Ok(p)
                } else {
                    Err(format!("{name} must be an absolute path"))
                }
            })
            .transpose()
    };
    Ok(LaunchHooks {
        pre_exec_pause: absolute(PRE_EXEC_PAUSE_ENV)?,
        pre_check_pause: absolute(PRE_CHECK_PAUSE_ENV)?,
        force_exec_failure: match env(FORCE_EXEC_FAILURE_ENV) {
            None => false,
            Some(v) if v == "1" => true,
            Some(_) => return Err(format!("{FORCE_EXEC_FAILURE_ENV}: expected 1")),
        },
        ssh_home: absolute(SSH_HOME_ENV)?,
        clock_offset: env(CLOCK_OFFSET_ENV)
            .map(|v| ClockOffset::parse(&v))
            .transpose()?,
    })
}

/// Enables the configuration (fake adapter script).
pub const ADAPTER_ENV: &str = "HEIMDALL_TEST_ADAPTER";
/// Durable fake effect ledger path.
pub const LEDGER_ENV: &str = "HEIMDALL_TEST_LEDGER";
/// Hang-after-effect marker path.
pub const HANG_ENV: &str = "HEIMDALL_TEST_HANG_AFTER_EFFECT";
/// Delay before every prepare, in milliseconds.
pub const SLOW_ENV: &str = "HEIMDALL_TEST_SLOW_PREPARE_MS";
/// Scripted time synchronization report.
pub const SYNC_ENV: &str = "HEIMDALL_TEST_TIME_SYNC";
/// One-shot pipeline stage fault.
pub const STAGE_FAIL_ENV: &str = "HEIMDALL_TEST_STAGE_FAIL";
/// ⟨M02⟩ U8: wall-clock offset of the runtime and the CLI (module docs).
pub const CLOCK_OFFSET_ENV: &str = "HEIMDALL_TEST_CLOCK_OFFSET_S";

/// Every variable of the test configuration.
pub const ALL_ENV: [&str; 7] = [
    ADAPTER_ENV,
    LEDGER_ENV,
    HANG_ENV,
    SLOW_ENV,
    SYNC_ENV,
    STAGE_FAIL_ENV,
    CLOCK_OFFSET_ENV,
];

/// ⟨M03⟩ `scratch`: select testkit's `ScratchSecretStore`; ⟨§17.25 item 7 (b)⟩
/// `product-file:<abs path>`: the test's disposable product-kind store ([`test_store`]).
pub const SECRET_STORE_ENV: &str = "HEIMDALL_TEST_SECRET_STORE";
/// ⟨M03⟩ Hex seed of the deterministic test key material.
pub const KEY_SEED_ENV: &str = "HEIMDALL_TEST_KEY_SEED";
/// ⟨M03⟩ Absolute path of the `FakeSessionLockSource` state file.
pub const SESSION_LOCK_ENV: &str = "HEIMDALL_TEST_SESSION_LOCK";
/// ⟨M03⟩ Absolute directory in which an enrollment script pauses.
pub const SCRIPT_PAUSE_DIR_ENV: &str = "HEIMDALL_TEST_SCRIPT_PAUSE_DIR";

/// ⟨M03⟩ Every variable the M03 test configuration adds (module docs). `ALL_ENV`
/// keeps its M01/M02 contents; [`requested_by`] covers both lists.
pub const M03_ENV: [&str; 4] = [
    SECRET_STORE_ENV,
    KEY_SEED_ENV,
    SESSION_LOCK_ENV,
    SCRIPT_PAUSE_DIR_ENV,
];

/// ⟨M03⟩ The longest key seed accepted, in bytes.
const KEY_SEED_MAX_BYTES: usize = 64;

/// ⟨M03⟩ A test key seed. Its `Debug` form shows only the length.
#[derive(Clone, PartialEq, Eq)]
pub struct KeySeed(Vec<u8>);

impl KeySeed {
    /// The seed bytes.
    #[must_use]
    #[allow(dead_code)] // read by the debug build's runtime wiring only
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for KeySeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeySeed({} bytes)", self.0.len())
    }
}

/// ⟨M03⟩ What the M03 test variables select, validated (nothing consumes it in wave 0
/// except tests and `service run`'s validation; U10 wires the runtime).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(dead_code)] // consumed by U10's runtime wiring; validated and tested now
pub struct M03Config {
    /// [`SECRET_STORE_ENV`] was `scratch`.
    pub scratch_secret_store: bool,
    /// ⟨ADR-0008 §17.25 item 7 (b)⟩ [`SECRET_STORE_ENV`] was `product-file:<abs path>`:
    /// the path (absolute; its location is checked by [`test_store`]).
    pub product_file_store: Option<std::path::PathBuf>,
    /// [`KEY_SEED_ENV`].
    pub key_seed: Option<KeySeed>,
    /// [`SESSION_LOCK_ENV`].
    pub session_lock: Option<std::path::PathBuf>,
    /// [`SCRIPT_PAUSE_DIR_ENV`].
    pub script_pause_dir: Option<std::path::PathBuf>,
}

/// An absolute path from `name`'s value, or the harness error.
fn absolute_path(name: &str, value: std::ffi::OsString) -> Result<std::path::PathBuf, String> {
    let p = std::path::PathBuf::from(value);
    if p.is_absolute() {
        Ok(p)
    } else {
        Err(format!("{name} must be an absolute path"))
    }
}

/// Hex digits to bytes (either case); `None` for an odd length or a non-digit.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digit = |b: u8| char::from(b).to_digit(16);
            let (hi, lo) = (digit(pair[0])?, digit(pair[1])?);
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

/// ⟨M03⟩ The M03 test configuration from `env` for a build that is (`available`) or is
/// not able to honour it. A build that cannot honour it refuses when any variable is
/// set, before any value is read; otherwise each value is validated.
///
/// # Errors
/// The release refusal, or a malformed value (usage errors, exit 2).
pub fn m03_config_in(
    available: bool,
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<M03Config, String> {
    let any = M03_ENV.iter().any(|name| env(name).is_some());
    if let Some(msg) = refusal(available, any) {
        return Err(msg.to_owned());
    }
    if !any {
        return Ok(M03Config::default());
    }
    let (scratch_secret_store, product_file_store) = match env(SECRET_STORE_ENV) {
        None => (false, None),
        Some(v) if v == "scratch" => (true, None),
        Some(v) => match v.to_str().and_then(|t| t.strip_prefix(PRODUCT_FILE_PREFIX)) {
            Some(_) if !PRODUCT_FILE_AVAILABLE => {
                return Err(format!(
                    "{SECRET_STORE_ENV}: {PRODUCT_FILE_PREFIX} has no store on this platform (Linux has no disposable Secret Service)"
                ));
            }
            Some(path) => (false, Some(absolute_path(SECRET_STORE_ENV, path.into())?)),
            None => {
                return Err(format!(
                    "{SECRET_STORE_ENV}: expected scratch or {PRODUCT_FILE_PREFIX}<absolute path>"
                ));
            }
        },
    };
    let key_seed = match env(KEY_SEED_ENV) {
        None => None,
        Some(v) => {
            let bytes = v
                .to_str()
                .and_then(decode_hex)
                .filter(|b| (1..=KEY_SEED_MAX_BYTES).contains(&b.len()))
                .ok_or_else(|| format!("{KEY_SEED_ENV}: expected 1 to 64 bytes of hex"))?;
            Some(KeySeed(bytes))
        }
    };
    Ok(M03Config {
        scratch_secret_store,
        product_file_store,
        key_seed,
        session_lock: env(SESSION_LOCK_ENV)
            .map(|v| absolute_path(SESSION_LOCK_ENV, v))
            .transpose()?,
        script_pause_dir: env(SCRIPT_PAUSE_DIR_ENV)
            .map(|v| absolute_path(SCRIPT_PAUSE_DIR_ENV, v))
            .transpose()?,
    })
}

/// ⟨M03⟩ [`m03_config_in`] for this build.
///
/// # Errors
/// As [`m03_config_in`].
#[allow(dead_code)] // `service run`'s debug-build `prepare` calls it; a release build has no caller
pub fn m03_config(env: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> Result<M03Config, String> {
    m03_config_in(AVAILABLE, env)
}

/// ⟨ADR-0008 §17.25 item 7 (b)⟩ The prefix of [`SECRET_STORE_ENV`]'s product-file value.
pub const PRODUCT_FILE_PREFIX: &str = "product-file:";

/// ⟨ADR-0008 §17.25 item 7 (b)⟩ Whether this platform has a disposable product store
/// (macOS: a file keychain; Windows: a DPAPI directory). Linux has none: the value is
/// refused.
pub const PRODUCT_FILE_AVAILABLE: bool = cfg!(any(target_os = "macos", windows));

/// ⟨M03; ADR-0008 §17.25 item 7 (b)⟩ The CA key store the test configuration selects
/// (`m03_cmd::issuer_store`): the platform's product store, testkit's scratch store, or
/// the test's disposable product-kind store at a checked path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TestStore {
    /// No test store: the platform's product store.
    #[default]
    Platform,
    /// `scratch`: testkit's `ScratchSecretStore` (a test kind).
    Scratch,
    /// `product-file:<path>`: the disposable product-kind store at `path`, accepted by
    /// `heimdall_issuer::store::test_product::refusal`. Never constructed in a release
    /// build ([`test_store`] refuses it there).
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    ProductFile(std::path::PathBuf),
}

/// ⟨ADR-0008 §17.25 item 7 (b)⟩ The store `m03` selects, its product-file path checked
/// against the test's scratch home `home` (the explicit `HEIMDALL_HOME`; a test
/// configuration needs one) and the account's home (`localenv::sys::account_home`).
///
/// # Errors
/// The refusal (a usage error, exit 2): a product-file store without an explicit home, or
/// one `test_product::refusal` refuses; a release build has no product-file store.
pub fn test_store(m03: &M03Config, home: Option<&std::path::Path>) -> Result<TestStore, String> {
    let Some(path) = &m03.product_file_store else {
        return Ok(if m03.scratch_secret_store {
            TestStore::Scratch
        } else {
            TestStore::Platform
        });
    };
    #[cfg(debug_assertions)]
    {
        let Some(home) = home else {
            return Err(format!(
                "{SECRET_STORE_ENV}: {PRODUCT_FILE_PREFIX} needs an explicit HEIMDALL_HOME (the test's scratch home)"
            ));
        };
        let account = heimdall_localenv::sys::account_home().ok();
        match heimdall_issuer::store::test_product::refusal(path, home, account.as_deref()) {
            None => Ok(TestStore::ProductFile(path.clone())),
            Some(why) => Err(format!("{SECRET_STORE_ENV}: {why}")),
        }
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = (path, home);
        Err(refusal(false, true).unwrap_or_default().to_owned())
    }
}

/// ⟨M03⟩ What the `enroll` CLI process takes from the test configuration: the script
/// pause directory, for a build that is (`available`) or is not able to honour it.
///
/// # Errors
/// The release refusal, or a relative directory (usage errors, exit 2).
pub fn enroll_hooks_in(
    available: bool,
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<Option<std::path::PathBuf>, String> {
    let dir = env(SCRIPT_PAUSE_DIR_ENV);
    if let Some(msg) = refusal(available, dir.is_some()) {
        return Err(msg.to_owned());
    }
    dir.map(|v| absolute_path(SCRIPT_PAUSE_DIR_ENV, v))
        .transpose()
}

/// ⟨M03⟩ [`enroll_hooks_in`] for this build.
///
/// # Errors
/// As [`enroll_hooks_in`].
pub fn enroll_hooks(
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<Option<std::path::PathBuf>, String> {
    enroll_hooks_in(AVAILABLE, env)
}

/// ⟨ADR-0008 §17.33 item 14⟩ Absolute directory from which `uninstall --purge-state`'s
/// secure-path check starts instead of `/` (Linux test hosts keep scratch directories
/// under the sticky `/tmp`, which the rule refuses). Debug builds only; the purge accepts
/// it only when it is this user's owner-only directory and a strict ancestor of both
/// purge roots, and still checks every component below it by the full rule.
pub const PURGE_TRUSTED_TOP_ENV: &str = "HEIMDALL_TEST_PURGE_TRUSTED_TOP";

/// ⟨ADR-0008 §17.33 item 14⟩ The purge's trusted top from `env`, for a build that can
/// (`available`) or cannot honour the test configuration.
///
/// # Errors
/// A refusal (a build without the test configuration) or a value that is not absolute.
pub fn purge_trusted_top_in(
    available: bool,
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<Option<std::path::PathBuf>, String> {
    let top = env(PURGE_TRUSTED_TOP_ENV);
    if let Some(msg) = refusal(available, top.is_some()) {
        return Err(msg.to_owned());
    }
    top.map(|v| absolute_path(PURGE_TRUSTED_TOP_ENV, v))
        .transpose()
}

/// ⟨ADR-0008 §17.33 item 14⟩ [`purge_trusted_top_in`] for this build.
///
/// # Errors
/// As [`purge_trusted_top_in`].
pub fn purge_trusted_top(
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<Option<std::path::PathBuf>, String> {
    purge_trusted_top_in(AVAILABLE, env)
}

/// File (in the state directory) that records one line per `service run` start.
#[cfg(debug_assertions)]
pub const STARTS_FILE: &str = "test-service-starts";

/// Whether this build can honour the test configuration at all.
pub const AVAILABLE: bool = cfg!(debug_assertions);

/// Whether any test-configuration variable is set (by the injected lookup): the M01/M02
/// `ALL_ENV` set and, from M03, `M03_ENV`.
#[must_use]
pub fn requested_by(env: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    ALL_ENV
        .iter()
        .chain(M03_ENV.iter())
        .any(|name| env(name).is_some())
}

/// Whether any test-configuration variable is set in this process.
#[must_use]
pub fn requested() -> bool {
    requested_by(&|name| std::env::var_os(name))
}

/// The refusal a build that cannot honour the configuration gives, if one is due.
#[must_use]
pub fn refusal(available: bool, requested: bool) -> Option<&'static str> {
    (requested && !available)
        .then_some("the HEIMDALL_TEST_* test configuration is not available in release builds")
}

/// The refusal for a requested configuration without an explicit home, checked
/// before any directory is created (the per-user default directories are never
/// touched by a test configuration).
#[must_use]
pub fn home_refusal(requested: bool, home_explicit: bool) -> Option<&'static str> {
    (requested && !home_explicit)
        .then_some("the HEIMDALL_TEST_* configuration needs an explicit HEIMDALL_HOME")
}

#[cfg(debug_assertions)]
pub use enabled::{isolate_projection, prepare};

#[cfg(debug_assertions)]
mod enabled {
    use std::collections::BTreeSet;
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use heimdall_app::ensure::EnsureStage;
    use heimdall_app::ports::SessionLockSource;
    use heimdall_app::ports::{
        AdapterDescriptor, AdapterError, CredentialAdapter, IntegrationSnapshot,
        InteractionRequirement, LockContinuity, PrepareOutcome, PreparePair, PrepareRequest,
        ReconcileOutcome, RevokeOutcome,
    };
    use heimdall_contract::Code;
    use heimdall_contract::Timestamp;
    use heimdall_contract::ids::{
        AccountName, DestinationId, DeviceId, EnvironmentId, GrantId, PolicyId, ProfileId,
    };
    use heimdall_contract::request::{
        Capability, DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy,
        NewAuthenticationExpiry, RefreshDependency, RevocationStatus, WorkloadIsolation,
    };
    use heimdall_domain::environment::{
        EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
    };
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::operation::AdapterIdentity;
    use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
    use heimdall_domain::profile::ProfileDefinition;
    use heimdall_domain::scope::{AccessPair, Scope};
    use heimdall_domain::time::SyncStatus;
    use heimdall_localenv::clients::{ClientsConfig, resolve_clients};
    use heimdall_localenv::env::{Env, Platform};
    use heimdall_localenv::local_query::LocalQueries;
    use heimdall_localenv::paths::SshPaths;
    use heimdall_localenv::projection::ProjectionConfig;
    use heimdall_runtime::Paths;
    use heimdall_runtime::service::{ProjectionWiring, ServiceOptions, SessionLockWiring};
    use heimdall_testkit::session_lock::FakeSessionLockSource;
    use heimdall_testkit::{
        CANARY_PREFIX, FakeCredentialAdapter, FakeStep, ScriptedStageHook, ScriptedTimeSync,
    };

    use super::{
        ADAPTER_ENV, CLOCK_OFFSET_ENV, HANG_ENV, LEDGER_ENV, SLOW_ENV, STAGE_FAIL_ENV, SYNC_ENV,
    };

    /// ⟨M02⟩ U8: the production clock with its wall reading shifted.
    struct OffsetClock {
        inner: Arc<dyn heimdall_domain::time::Clock>,
        offset: super::ClockOffset,
    }

    impl heimdall_domain::time::Clock for OffsetClock {
        fn wall(&self) -> Timestamp {
            self.offset.shift(self.inner.wall())
        }
        fn continuous(&self) -> Duration {
            self.inner.continuous()
        }
        fn boot_id(&self) -> heimdall_domain::time::BootId {
            self.inner.boot_id()
        }
    }

    /// What `service run` does after `Service::start_with` when the test
    /// configuration is active.
    #[derive(Debug)]
    pub struct TestSetup {
        _private: (),
    }

    impl TestSetup {
        /// Seed the fixture environment record, profile and policy once per store
        /// (a restarted service keeps a paused policy paused).
        pub fn seed(&self, service: &heimdall_runtime::Service) -> Result<(), String> {
            let env = service.environment().clone();
            let profile = ProfileId::parse("dev").map_err(|e| e.to_string())?;
            let policy = PolicyId::parse("pol").map_err(|e| e.to_string())?;
            let pairs = |names: &[&str]| -> Result<BTreeSet<AccessPair>, String> {
                names
                    .iter()
                    .map(|d| {
                        Ok(AccessPair {
                            destination: DestinationId::parse(d).map_err(|e| e.to_string())?,
                            account: AccountName::parse("deploy").map_err(|e| e.to_string())?,
                        })
                    })
                    .collect()
            };
            let ssh: BTreeSet<Capability> = [Capability::SshAuthentication].into_iter().collect();
            let profile_def = ProfileDefinition {
                id: profile.clone(),
                revision: 1,
                scope: Scope {
                    pairs: pairs(&["h1", "h2", "h3"])?,
                    capabilities: ssh.clone(),
                },
                label: None,
            };
            let policy_def = StandingPolicy {
                id: policy,
                revision: PolicyRevision(1),
                profile: profile.clone(),
                workspace: None,
                scope: Scope {
                    pairs: pairs(&["h1", "h2"])?,
                    capabilities: ssh,
                },
                environments: [env.clone()].into_iter().collect(),
                max_window: Duration::from_secs(2 * 3600),
                pause: PauseState::Active,
                cutoff_at: None,
                source: PolicySource::SetupDefault,
                // M03 wave 0 (A1): fail closed until U0b
                lock_behavior: Default::default(),
                connection: Default::default(),
            };
            // `ops` (h1 only) is fully covered by its policy `pol-ops`, so a
            // preview of it is `allowed` (gap G17 e2e cases).
            let ops = ProfileId::parse("ops").map_err(|e| e.to_string())?;
            let ops_def = ProfileDefinition {
                id: ops.clone(),
                revision: 1,
                scope: Scope {
                    pairs: pairs(&["h1"])?,
                    capabilities: policy_def.scope.capabilities.clone(),
                },
                label: None,
            };
            let ops_policy = StandingPolicy {
                id: PolicyId::parse("pol-ops").map_err(|e| e.to_string())?,
                profile: ops.clone(),
                scope: ops_def.scope.clone(),
                ..policy_def.clone()
            };
            let record = EnvironmentRecord {
                id: env.clone(),
                device: device_for(&env),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                },
            };
            service
                .store()
                .transaction(|tx| {
                    if tx.environment(&env)?.is_none() {
                        tx.upsert_environment(&record)?;
                    }
                    if tx.profile(&profile)?.is_none() {
                        tx.upsert_profile(&profile_def)?;
                        tx.upsert_policy(&policy_def, false)?;
                    }
                    if tx.profile(&ops)?.is_none() {
                        tx.upsert_profile(&ops_def)?;
                        tx.upsert_policy(&ops_policy, false)?;
                    }
                    Ok(())
                })
                .map_err(|e| format!("fixture seeding failed: {e}"))
        }
    }

    /// A stable fixture device ID derived from the environment ID (no secret).
    fn device_for(env: &EnvironmentId) -> DeviceId {
        let mut bytes = [0u8; 16];
        for (i, b) in env.as_str().bytes().rev().take(16).enumerate() {
            bytes[i] = b;
        }
        DeviceId::from_random_bytes(bytes)
    }

    fn enforcement() -> EnforcementEvidence {
        EnforcementEvidence {
            report: Enforcement {
                destination_scope: DestinationScopeEnforcement::ClientRouting,
                new_authentication_expiry: NewAuthenticationExpiry::SignerOnly,
                workload_isolation: WorkloadIsolation::SharedOsUser,
                existing_connections: ExistingConnectionsPolicy::GracefulDedicatedConnections,
                revocation: RevocationStatus::LocalApplied,
                // M03 wave 0 (A1): fail closed until U0b
                identity_selection: None,
                new_signing_expiry: None,
                owned_multiplexing: None,
                remote_processes: None,
                unmanaged_connections: None,
                issuer_isolation: None,
            },
            evidence: Vec::new(),
        }
    }

    fn descriptor() -> AdapterDescriptor {
        AdapterDescriptor {
            identity: AdapterIdentity {
                mechanism: "fake_agent".into(),
                instance: "cli-fixture".into(),
            },
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
            external_side_effects: true,
            interaction: InteractionRequirement::None,
            enforcement: enforcement(),
            lock_continuity: LockContinuity::Unknown,
            remote_credential_effect: false, // M03 wave 0 (A2)
        }
    }

    fn outcome(now: Timestamp) -> Result<PrepareOutcome, String> {
        let plus = |secs: u64| {
            now.checked_add(Duration::from_secs(secs))
                .map_err(|_| "fixture time out of range".to_owned())
        };
        Ok(PrepareOutcome {
            usable_until: plus(12 * 3600)?,
            offline_until: plus(3600)?,
            refresh_dependency: RefreshDependency::None,
            enforcement: enforcement(),
            // Synthetic canary built at runtime: it must never be printed.
            credential_ref: format!("{CANARY_PREFIX}cli_fixture_{}", std::process::id()),
            // ⟨M02⟩ U0b row 15: the new outcome fields at their M01-equivalent values.
            availability: Default::default(),
            provider: None,
            integration: Default::default(),
            managed: None,
        })
    }

    fn absolute(var: &str, value: std::ffi::OsString) -> Result<PathBuf, String> {
        let p = PathBuf::from(value);
        if p.is_absolute() {
            Ok(p)
        } else {
            Err(format!("{var} must be an absolute path"))
        }
    }

    fn script(text: &str, now: Timestamp) -> Result<Vec<FakeStep>, String> {
        text.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|step| match step {
                "prepare" => Ok(FakeStep::Prepare(outcome(now)?)),
                "lose_reply" => Ok(FakeStep::ApplyButLoseReply(outcome(now)?)),
                "unavailable" => Ok(FakeStep::Fail(AdapterError::Unavailable(
                    "fixture dependency unavailable".into(),
                ))),
                _ => Err(format!("{ADAPTER_ENV}: unknown step")),
            })
            .collect()
    }

    fn stage_fail(text: &str) -> Result<Arc<ScriptedStageHook>, String> {
        let mut parts = text.splitn(3, ':');
        let (Some(when), Some(stage), Some(code)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(format!(
                "{STAGE_FAIL_ENV}: expected <before|after>:<stage>:<CODE>"
            ));
        };
        let stage: EnsureStage = serde_json::from_value(serde_json::Value::String(stage.into()))
            .map_err(|_| format!("{STAGE_FAIL_ENV}: unknown stage"))?;
        let code = Code::parse(code);
        if matches!(code, Code::Unknown(_)) {
            return Err(format!("{STAGE_FAIL_ENV}: unknown code"));
        }
        match when {
            "before" => Ok(ScriptedStageHook::new([(stage, code)], [])),
            "after" => Ok(ScriptedStageHook::new([], [(stage, code)])),
            _ => Err(format!("{STAGE_FAIL_ENV}: expected before or after")),
        }
    }

    /// Apply the test configuration to `options`, if requested. Errors are usage
    /// errors of the test harness (exit 2); `Ok(None)` when no variable is set.
    pub fn prepare(
        options: &mut ServiceOptions,
        paths: &Paths,
        home_explicit: bool,
        env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
    ) -> Result<Option<TestSetup>, String> {
        if !super::requested_by(env) {
            return Ok(None);
        }
        if let Some(msg) = super::home_refusal(true, home_explicit) {
            return Err(msg.into());
        }
        // ⟨M03⟩ wave 4 (m03-plan U0b row 16; U10): the M03 variables, validated, wired
        // into the managed runtime (a runtime without the managed wiring ignores them):
        // the key seed (`KeyVault::with_test_seed`), the fake session-lock source over
        // its state file, the verifier's script pause directory. `scratch` secret store:
        // the issuer child (`internal issuer`, which inherits this environment) selects
        // testkit's `ScratchSecretStore` itself (`m03_cmd::issuer_store`).
        let m03 = super::m03_config(env)?;
        if let Some(managed) = options.managed.as_mut() {
            managed.test_key_seed = m03.key_seed.as_ref().map(|k| k.as_bytes().to_vec());
            if let Some(path) = &m03.session_lock {
                managed.session_lock = SessionLockWiring::Source(fake_session_lock(path));
            }
            managed.script_pause_dir = m03.script_pause_dir.clone();
        }
        // Count starts before the instance lock (single-child launcher test).
        record_start(paths).map_err(|e| format!("cannot record the start: {}", e.kind()))?;

        let now = options.clock.wall();
        let steps = match env(ADAPTER_ENV) {
            Some(v) => script(&v.to_string_lossy(), now)?,
            None => vec![FakeStep::Prepare(outcome(now)?)],
        };
        let fake = match env(LEDGER_ENV) {
            Some(v) => {
                FakeCredentialAdapter::with_ledger(descriptor(), steps, absolute(LEDGER_ENV, v)?)
                    .map_err(|e| format!("{LEDGER_ENV}: {}", e.kind()))?
            }
            None => FakeCredentialAdapter::new(descriptor(), steps),
        };
        let hang = env(HANG_ENV).map(|v| absolute(HANG_ENV, v)).transpose()?;
        let slow = env(SLOW_ENV)
            .map(|v| {
                v.to_string_lossy()
                    .parse::<u64>()
                    .map(Duration::from_millis)
                    .map_err(|_| format!("{SLOW_ENV}: expected milliseconds"))
            })
            .transpose()?;
        options.adapters = vec![Arc::new(TestAdapter {
            inner: fake,
            hang,
            hung: AtomicBool::new(false),
            slow,
        })];
        if let Some(v) = env(SYNC_ENV) {
            let status = match v.to_string_lossy().as_ref() {
                "synchronized" => SyncStatus::Synchronized,
                "not_synchronized" => SyncStatus::NotSynchronized,
                "unknown" => SyncStatus::Unknown,
                _ => return Err(format!("{SYNC_ENV}: unknown status")),
            };
            options.time_sync = ScriptedTimeSync::new(status);
        }
        if let Some(v) = env(STAGE_FAIL_ENV) {
            options.stage_hook = stage_fail(&v.to_string_lossy())?;
        }
        // ⟨M02⟩ U8: the runtime's wall clock, shifted (ADR-0007 §12.14 item 8).
        if let Some(v) = env(CLOCK_OFFSET_ENV) {
            options.clock = Arc::new(OffsetClock {
                inner: Arc::clone(&options.clock),
                offset: super::ClockOffset::parse(&v)?,
            });
        }
        // Windows: test runtimes' pipes are recognizable (`heimdall-hmtest-<random>`).
        options.endpoint_prefix = TEST_PIPE_PREFIX.to_owned();
        Ok(Some(TestSetup { _private: () }))
    }

    /// ⟨M03⟩ `HEIMDALL_TEST_SESSION_LOCK`: testkit's `FakeSessionLockSource` over the
    /// state file, re-read every [`SESSION_LOCK_POLL`] by a task that ends with the
    /// source (the test writes the file to lock and unlock).
    fn fake_session_lock(path: &std::path::Path) -> Arc<dyn SessionLockSource> {
        let source = Arc::new(FakeSessionLockSource::from_state_file(path));
        let weak = Arc::downgrade(&source);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SESSION_LOCK_POLL).await;
                let Some(s) = weak.upgrade() else { break };
                s.refresh_from_file();
            }
        });
        source
    }

    /// How often the fake session-lock source re-reads its state file.
    const SESSION_LOCK_POLL: Duration = Duration::from_millis(100);

    /// ⟨M02⟩ W4 integration: a runtime started while any test variable is set
    /// (the [`ALL_ENV`](super::ALL_ENV) set, or one of
    /// [`LAUNCH_ENV`](super::LAUNCH_ENV), `HEIMDALL_TEST_SSH_HOME` included) never
    /// wires the account's real SSH configuration (AGENTS.md: tests never use the
    /// owner's `~/.ssh`). With `HEIMDALL_TEST_SSH_HOME` the projection uses that
    /// scratch home (system directory `<home>/etc-ssh`), as the CLI's own static pass
    /// does; without it no projection is wired, so setup answers
    /// `driver_unavailable` and the existing-access adapters observe nothing (fail
    /// closed). With no test variable set, `options` is left as given.
    ///
    /// # Errors
    ///
    /// A relative `HEIMDALL_TEST_SSH_HOME` (a usage error of the test harness).
    pub fn isolate_projection(
        options: &mut ServiceOptions,
        paths: &Paths,
        env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
    ) -> Result<(), String> {
        let any_launch = super::LAUNCH_ENV.iter().any(|n| env(n).is_some());
        if !(super::requested_by(env) || any_launch) {
            return Ok(());
        }
        options.projection = projection_wiring(paths, env)?;
        Ok(())
    }

    /// The projection wiring of a test runtime (see [`isolate_projection`]): a
    /// scratch configuration under `HEIMDALL_TEST_SSH_HOME`, or none. Never the
    /// account's.
    fn projection_wiring(
        paths: &Paths,
        env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
    ) -> Result<ProjectionWiring, String> {
        let Some(home) = env(super::SSH_HOME_ENV) else {
            return Ok(ProjectionWiring::Disabled);
        };
        let home = absolute(super::SSH_HOME_ENV, home)?;
        let ssh = SshPaths::with_test_override(home.clone(), home.join("etc-ssh"));
        let captured = Env::capture();
        let clients = resolve_clients(
            &captured,
            &ssh,
            &ClientsConfig::default(),
            LocalQueries::Enabled,
        );
        let mut config = ProjectionConfig::new(ssh, Platform::current(), paths.config_dir.clone())
            .with_state_dir(paths.state_dir.clone());
        config.env = captured;
        config.clients = clients;
        config.queries = LocalQueries::Enabled;
        Ok(ProjectionWiring::Config(Box::new(config)))
    }

    fn record_start(paths: &Paths) -> std::io::Result<()> {
        use std::io::Write as _;
        paths.ensure().map_err(|e| match e {
            heimdall_runtime::config::ConfigError::Io(io) => io,
            other => std::io::Error::other(other.to_string()),
        })?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(paths.state_dir.join(super::STARTS_FILE))?;
        writeln!(f, "{}", std::process::id())?;
        f.sync_all()
    }

    /// The fake adapter behind the production port, plus the two test-only
    /// behaviours the process-level cases need (delay, hang after the effect).
    struct TestAdapter {
        inner: Arc<FakeCredentialAdapter>,
        hang: Option<PathBuf>,
        hung: AtomicBool,
        slow: Option<Duration>,
    }

    /// Windows pipe-name prefix of a runtime under the test configuration.
    const TEST_PIPE_PREFIX: &str = "hmtest-";

    /// Bound on the hang, so an abandoned test service still ends its call.
    const HANG_BOUND: Duration = Duration::from_secs(300);

    type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

    // `CredentialAdapter` is declared with `#[async_trait]`; these are the same
    // signatures written out, so this crate needs no macro dependency.
    impl CredentialAdapter for TestAdapter {
        fn descriptor(&self) -> &AdapterDescriptor {
            self.inner.descriptor()
        }

        fn prepare<'life0, 'life1, 'async_trait>(
            &'life0 self,
            req: PrepareRequest<'life1>,
        ) -> BoxFuture<'async_trait, Result<PrepareOutcome, AdapterError>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                if let Some(d) = self.slow {
                    tokio::time::sleep(d).await;
                }
                let r = self.inner.prepare(req).await;
                if let Some(marker) = &self.hang
                    && !self.hung.swap(true, Ordering::SeqCst)
                {
                    // The effect is in the ledger; its receipt is not written
                    // while this call does not return.
                    let _ = std::fs::write(marker, b"effect applied\n");
                    tokio::time::sleep(HANG_BOUND).await;
                }
                r
            })
        }

        // ⟨M02⟩ ADR-0007 §12.26 item 2: the fake reads no source, and the bounded
        // call is this adapter's own `prepare`, with its delay and hang.
        fn read_sources(&self, _pairs: &[PreparePair]) -> IntegrationSnapshot {
            IntegrationSnapshot::default()
        }

        fn prepare_from<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            req: PrepareRequest<'life1>,
            _sources: &'life2 IntegrationSnapshot,
        ) -> BoxFuture<'async_trait, Result<PrepareOutcome, AdapterError>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            self.prepare(req)
        }

        fn renew<'life0, 'life1, 'async_trait>(
            &'life0 self,
            req: PrepareRequest<'life1>,
        ) -> BoxFuture<'async_trait, Result<PrepareOutcome, AdapterError>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.renew(req)
        }

        fn reconcile<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            grant: &'life1 GrantId,
            effect_token: &'life2 str,
        ) -> BoxFuture<'async_trait, Result<ReconcileOutcome, AdapterError>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.reconcile(grant, effect_token)
        }

        fn revoke<'life0, 'life1, 'async_trait>(
            &'life0 self,
            grant: &'life1 GrantId,
            now: Timestamp,
        ) -> BoxFuture<'async_trait, Result<RevokeOutcome, AdapterError>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.revoke(grant, now)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// ⟨M02⟩ W4 integration: a runtime started under the test configuration
        /// never wires the account's real SSH configuration. With a scratch SSH home
        /// its projection reads only that home; without one, no projection is wired.
        #[test]
        #[allow(clippy::unwrap_used)]
        fn a_test_runtime_never_wires_the_accounts_ssh_configuration() {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths::under(&dir.path().join("heimdall"));
            let scratch = dir.path().join("account");
            let scratch_os = scratch.clone().into_os_string();
            let home_only = |n: &str| (n == super::super::SSH_HOME_ENV).then(|| scratch_os.clone());
            // `HEIMDALL_TEST_SSH_HOME` alone is not in `ALL_ENV`, so `prepare` does
            // nothing for it; the isolation must still apply.
            assert!(!super::super::requested_by(&home_only));
            let mut options = ServiceOptions::production().unwrap();
            assert_eq!(format!("{:?}", options.projection), "Account");
            isolate_projection(&mut options, &paths, &home_only).unwrap();
            match &options.projection {
                ProjectionWiring::Config(c) => {
                    assert_eq!(c.paths.account_home, scratch);
                    assert_eq!(c.paths.user_config, scratch.join(".ssh").join("config"));
                    assert_eq!(c.paths.system_dir, scratch.join("etc-ssh"));
                }
                other => panic!("expected the scratch configuration, got {other:?}"),
            }

            for name in super::super::ALL_ENV
                .iter()
                .chain(super::super::LAUNCH_ENV.iter())
                .filter(|n| **n != super::super::SSH_HOME_ENV)
            {
                let one = |n: &str| (n == *name).then(|| "x".into());
                let mut options = ServiceOptions::production().unwrap();
                isolate_projection(&mut options, &paths, &one).unwrap();
                assert_eq!(format!("{:?}", options.projection), "Disabled", "{name}");
            }

            let mut options = ServiceOptions::production().unwrap();
            isolate_projection(&mut options, &paths, &|_| None).unwrap();
            assert_eq!(
                format!("{:?}", options.projection),
                "Account",
                "no test variable"
            );

            let relative = |n: &str| (n == super::super::SSH_HOME_ENV).then(|| "rel".into());
            let mut options = ServiceOptions::production().unwrap();
            assert!(isolate_projection(&mut options, &paths, &relative).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_sees_every_variable_and_nothing_else() {
        assert!(!requested_by(&|_| None));
        for name in ALL_ENV {
            assert!(requested_by(&|n| (n == name).then(|| "x".into())));
        }
        assert!(!requested_by(
            &|n| (n == "HEIMDALL_HOME").then(|| "/x".into())
        ));
    }

    #[test]
    fn detection_covers_the_m03_variables_and_all_env_keeps_its_m01_m02_set() {
        assert_eq!(ALL_ENV.len(), 7, "ALL_ENV is the M01/M02 set");
        for name in M03_ENV {
            assert!(!ALL_ENV.contains(&name), "{name}");
            assert!(requested_by(&|n| (n == name).then(|| "x".into())));
        }
    }

    /// Debug-build half of `release_build_refuses_m03_test_gates`: the refusal
    /// function covers every M03 variable, for the config and for `enroll`'s hook
    /// (the pause directory), and refuses before it reads a value.
    #[test]
    fn the_m03_refusal_covers_every_m03_variable() {
        for name in M03_ENV {
            let one = |n: &str| (n == name).then(|| std::ffi::OsString::from("x"));
            let Err(msg) = m03_config_in(false, &one) else {
                panic!("{name} was not refused");
            };
            assert!(msg.contains("HEIMDALL_TEST_"), "{name}: {msg}");
            assert_eq!(Some(msg.as_str()), refusal(false, true), "{name}");
            // Even a well-formed value is refused, and the value is never read.
            let good = |n: &str| (n == name).then(|| std::ffi::OsString::from("/abs"));
            assert!(m03_config_in(false, &good).is_err(), "{name}");
        }
        // ⟨§17.25 item 7 (b)⟩ The product-file selector too, well-formed or not.
        for value in ["product-file:/abs/t.keychain-db", "product-file:rel"] {
            let one = |n: &str| (n == SECRET_STORE_ENV).then(|| std::ffi::OsString::from(value));
            assert_eq!(
                m03_config_in(false, &one).err().as_deref(),
                refusal(false, true),
                "{value}"
            );
        }
        let pause = |n: &str| (n == SCRIPT_PAUSE_DIR_ENV).then(|| std::ffi::OsString::from("/p"));
        assert!(enroll_hooks_in(false, &pause).is_err());
        // The other three variables are not `enroll`'s.
        let other = |n: &str| (n == KEY_SEED_ENV).then(|| std::ffi::OsString::from("00"));
        assert_eq!(enroll_hooks_in(false, &other), Ok(None));
        // Nothing set: a release build is fine.
        assert_eq!(m03_config_in(false, &|_| None), Ok(M03Config::default()));
        assert_eq!(enroll_hooks_in(false, &|_| None), Ok(None));
    }

    /// `purge_trusted_top_is_refused_in_a_release_build` (ADR-0008 §17.33 item 14): a
    /// build without the test configuration refuses `HEIMDALL_TEST_PURGE_TRUSTED_TOP`;
    /// a debug build takes an absolute value and refuses a relative one.
    #[test]
    fn purge_trusted_top_is_refused_in_a_release_build() {
        let top = |v: &'static str| {
            move |n: &str| (n == PURGE_TRUSTED_TOP_ENV).then(|| std::ffi::OsString::from(v))
        };
        assert_eq!(
            purge_trusted_top_in(false, &top("/abs")).err().as_deref(),
            refusal(false, true)
        );
        assert_eq!(purge_trusted_top_in(false, &|_| None), Ok(None));
        assert_eq!(
            purge_trusted_top_in(true, &top("/abs")),
            Ok(Some(std::path::PathBuf::from("/abs")))
        );
        assert!(purge_trusted_top_in(true, &top("rel")).is_err());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn m03_values_are_parsed_and_validated() {
        let set = |pairs: &'static [(&'static str, &'static str)]| {
            move |n: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == n)
                    .map(|(_, v)| std::ffi::OsString::from(*v))
            }
        };
        const ABS: &str = if cfg!(windows) {
            "C:\\scratch\\x"
        } else {
            "/scratch/x"
        };
        let cfg = m03_config_in(
            true,
            &set(&[
                (SECRET_STORE_ENV, "scratch"),
                (KEY_SEED_ENV, "00fF"),
                (SESSION_LOCK_ENV, ABS),
                (SCRIPT_PAUSE_DIR_ENV, ABS),
            ]),
        )
        .unwrap();
        assert!(cfg.scratch_secret_store);
        assert_eq!(cfg.key_seed.as_ref().unwrap().as_bytes(), &[0x00, 0xff]);
        assert_eq!(cfg.session_lock.as_deref(), Some(std::path::Path::new(ABS)));
        assert_eq!(
            cfg.script_pause_dir.as_deref(),
            Some(std::path::Path::new(ABS))
        );
        assert_eq!(format!("{:?}", cfg.key_seed.unwrap()), "KeySeed(2 bytes)");
        assert_eq!(
            m03_config_in(true, &|_| None).unwrap(),
            M03Config::default()
        );
        let bad: [(&str, &str); 8] = [
            (SECRET_STORE_ENV, "real"),
            (SECRET_STORE_ENV, ""),
            (KEY_SEED_ENV, ""),
            (KEY_SEED_ENV, "0"),
            (KEY_SEED_ENV, "zz"),
            (KEY_SEED_ENV, "+1"),
            (SESSION_LOCK_ENV, "relative"),
            (SCRIPT_PAUSE_DIR_ENV, "relative"),
        ];
        for (name, value) in bad {
            let one = |n: &str| (n == name).then(|| std::ffi::OsString::from(value));
            assert!(m03_config_in(true, &one).is_err(), "{name}={value}");
        }
        let too_long = "ab".repeat(65);
        let long = |n: &str| (n == KEY_SEED_ENV).then(|| std::ffi::OsString::from(&too_long));
        assert!(m03_config_in(true, &long).is_err());
        let max = "ab".repeat(64);
        let longest = |n: &str| (n == KEY_SEED_ENV).then(|| std::ffi::OsString::from(&max));
        assert!(m03_config_in(true, &longest).is_ok());
        assert_eq!(
            enroll_hooks_in(true, &set(&[(SCRIPT_PAUSE_DIR_ENV, ABS)])).unwrap(),
            Some(std::path::PathBuf::from(ABS))
        );
        assert!(enroll_hooks_in(true, &set(&[(SCRIPT_PAUSE_DIR_ENV, "rel")])).is_err());
    }

    /// ⟨ADR-0008 §17.25 item 7 (b)⟩ `product-file:<abs path>` parses on macOS and Windows
    /// (refused on Linux), needs an absolute path, and selects a store only through
    /// [`test_store`]: never without an explicit home, never a path the location check
    /// refuses; `scratch` and nothing select as before. (Debug builds: the release half is
    /// `release_build_refuses_m03_test_gates`.)
    #[cfg(debug_assertions)]
    #[test]
    #[allow(clippy::unwrap_used)]
    fn product_file_selector_parses_and_is_checked_against_the_home() {
        const ABS: &str = if cfg!(windows) {
            "product-file:C:\\scratch\\t"
        } else {
            "product-file:/scratch/t.keychain-db"
        };
        let one = |v: &'static str| {
            move |n: &str| (n == SECRET_STORE_ENV).then(|| std::ffi::OsString::from(v))
        };
        let parsed = m03_config_in(true, &one(ABS));
        if PRODUCT_FILE_AVAILABLE {
            let cfg = parsed.unwrap();
            assert!(!cfg.scratch_secret_store);
            assert_eq!(
                cfg.product_file_store.as_deref(),
                Some(std::path::Path::new(&ABS[PRODUCT_FILE_PREFIX.len()..]))
            );
            assert!(
                test_store(&cfg, None)
                    .unwrap_err()
                    .contains("HEIMDALL_HOME")
            );
            let home = std::env::temp_dir();
            let refused = test_store(&cfg, Some(&home));
            assert!(refused.is_err(), "outside the scratch home: {refused:?}");
        } else {
            assert!(parsed.unwrap_err().contains("Linux"));
        }
        for bad in [
            "product-file:rel",
            "product-file:",
            "product-file",
            "file:/x",
        ] {
            assert!(m03_config_in(true, &one(bad)).is_err(), "{bad}");
        }
        let scratch = m03_config_in(true, &one("scratch")).unwrap();
        assert_eq!(test_store(&scratch, None), Ok(TestStore::Scratch));
        assert_eq!(
            test_store(&M03Config::default(), None),
            Ok(TestStore::Platform)
        );
    }

    #[test]
    fn a_build_without_the_configuration_refuses_a_request_for_it() {
        assert!(refusal(false, true).is_some());
        assert!(refusal(false, false).is_none());
        assert!(refusal(true, true).is_none());
        assert_eq!(AVAILABLE, cfg!(debug_assertions));
        assert!(home_refusal(true, false).is_some());
        assert!(home_refusal(true, true).is_none());
        assert!(home_refusal(false, false).is_none());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn launch_hooks_parse_and_need_absolute_paths() {
        let none = launch_hooks(&|_| None).unwrap();
        assert_eq!(none, LaunchHooks::default());
        let set = |pairs: &'static [(&'static str, &'static str)]| {
            move |n: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == n)
                    .map(|(_, v)| std::ffi::OsString::from(*v))
            }
        };
        // An absolute path on the host (a Unix path has no drive on Windows).
        const FIFO: &str = if cfg!(windows) {
            "C:\\scratch\\fifo"
        } else {
            "/scratch/fifo"
        };
        if AVAILABLE {
            let h = launch_hooks(&set(&[
                (PRE_EXEC_PAUSE_ENV, FIFO),
                (FORCE_EXEC_FAILURE_ENV, "1"),
                (CLOCK_OFFSET_ENV, "-90"),
            ]))
            .unwrap();
            assert_eq!(
                h.pre_exec_pause.as_deref(),
                Some(std::path::Path::new(FIFO))
            );
            assert!(h.force_exec_failure);
            assert_eq!(h.clock_offset, Some(ClockOffset::Fixed(-90)));
            assert!(launch_hooks(&set(&[(PRE_CHECK_PAUSE_ENV, "relative")])).is_err());
            assert!(launch_hooks(&set(&[(FORCE_EXEC_FAILURE_ENV, "yes")])).is_err());
            assert!(launch_hooks(&set(&[(CLOCK_OFFSET_ENV, "soon")])).is_err());
        } else {
            assert!(launch_hooks(&set(&[(SSH_HOME_ENV, "/scratch/home")])).is_err());
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn clock_offset_is_fixed_or_read_from_its_file_at_every_use() {
        let at: heimdall_contract::Timestamp = "2026-11-03T12:00:00Z".parse().unwrap();
        let fixed = ClockOffset::parse(std::ffi::OsStr::new("3600")).unwrap();
        assert_eq!(fixed.shift(at), "2026-11-03T13:00:00Z".parse().unwrap());
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("offset");
        let offset = ClockOffset::parse(file.as_os_str()).unwrap();
        assert_eq!(offset.seconds(), 0, "a missing file reads as 0");
        std::fs::write(&file, "86400\n").unwrap();
        assert_eq!(offset.shift(at), "2026-11-04T12:00:00Z".parse().unwrap());
        std::fs::write(&file, "-60").unwrap();
        assert_eq!(offset.seconds(), -60, "re-read at every use");
        std::fs::write(&file, "garbage").unwrap();
        assert_eq!(offset.seconds(), 0);
    }

    /// Runs only under a release-profile test build (`cargo test --release`):
    /// the build itself cannot honour the configuration.
    #[cfg(not(debug_assertions))]
    #[test]
    fn release_profile_build_refuses_the_test_configuration() {
        assert!(!AVAILABLE);
        assert!(refusal(AVAILABLE, true).is_some());
    }

    /// ⟨M03⟩ Release-profile half of `release_build_refuses_m03_test_gates` (the binary
    /// half is `tools/validation/release-gate.sh`): every M03 variable makes the
    /// build's own functions refuse, `requested` sees it, and nothing is parsed.
    #[cfg(not(debug_assertions))]
    #[test]
    fn release_build_refuses_m03_test_gates() {
        assert!(!AVAILABLE);
        for name in M03_ENV {
            let one = |n: &str| (n == name).then(|| std::ffi::OsString::from("scratch"));
            assert!(requested_by(&one), "{name}");
            assert!(m03_config(&one).is_err(), "{name}");
        }
        let pause = |n: &str| (n == SCRIPT_PAUSE_DIR_ENV).then(|| std::ffi::OsString::from("/p"));
        assert!(enroll_hooks(&pause).is_err());
        // ⟨§17.25 item 7 (b)⟩ The product-file selector: refused before it is parsed, and
        // `test_store` selects no product-file store in this build.
        let product = |n: &str| {
            (n == SECRET_STORE_ENV).then(|| std::ffi::OsString::from("product-file:/abs/t"))
        };
        assert!(m03_config(&product).is_err());
        let forced = M03Config {
            product_file_store: Some(std::path::PathBuf::from("/abs/t")),
            ..M03Config::default()
        };
        assert!(test_store(&forced, Some(std::path::Path::new("/abs"))).is_err());
    }
}
