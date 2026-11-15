//! M03 command surface (m03-plan U0, U12, §5 item 24).
//!
//! The clap tree of every M03 command is in `cli.rs`; this module holds the handlers of
//! the commands that extend M02's `access` and `destination` trees
//! (`access lock-behavior|connection-policy`, `access ensure --strict`,
//! `destination prefer`) and of the hidden `internal` commands. `issuer_cmd`,
//! `enroll_cmd`, `connections_cmd` and `uninstall_cmd` hold the per-group handlers.
//!
//! **Wave 5 (U12): every M03 command is wired.** No command answers the wave-0 text
//! ("not available in this build"): the tests in `tests/e2e/cli_m03.rs` and the
//! `no_m03_source_contains_the_wave_0_text` guard pin that. A command refused before
//! its runtime contact (an invalid ID, `--non-interactive` where an owner is needed)
//! answers its own `USAGE_ERROR` / `INTERACTION_REQUIRED` with effect `none` and never
//! creates the Heimdall home.

use heimdall_contract::envelope::Envelope;
use heimdall_contract::{Code, ExitCode};

use heimdall_contract::catalog::CatalogRequest;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{AccountName, DestinationId, PolicyId};
use heimdall_contract::managed::{
    ConnectionRequest, ExistingConnectionsMode, LockBehavior, MultiplexingMode, PreferredMechanism,
};
use heimdall_contract::request::{InspectSubject, PolicyAction, Request};

use crate::cli::{
    ConnectionPolicyArgs, DestinationPreferArgs, Done, ExistingArg, InternalCommand,
    LockBehaviorArg, LockBehaviorArgs, MechanismArg, MultiplexingArg, parse,
};
use crate::client::{Ctx, error};
use crate::output;
use crate::setup_cmd::{self, Outcome};

/// The pair a destination (alias or ID) names, from `inspect destinations` data: its
/// catalog ID and its account. Only a **managed** destination has an account and a
/// mechanism to choose; an observed one is refused (`observed_alias_unmanaged`, exit
/// 4), an unknown one is `NOT_FOUND`.
pub(crate) fn managed_pair(
    listing: &serde_json::Value,
    wanted: &str,
) -> Result<(DestinationId, AccountName), Outcome> {
    let text =
        |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_owned);
    let items = listing
        .get("items")
        .or_else(|| listing.get("destinations"))
        .and_then(|i| i.as_array())
        .map_or(&[][..], Vec::as_slice);
    let Some(found) = items.iter().find(|d| {
        text(d, "alias").as_deref() == Some(wanted)
            || text(d, "destination_id").as_deref() == Some(wanted)
    }) else {
        return Err(Outcome::of(setup_cmd::failure(
            Code::NotFound,
            "no such destination",
            None,
        )));
    };
    let unmanaged = || {
        Outcome::of(setup_cmd::failure(
            Code::CapabilityUnavailable,
            "only a managed destination has a mechanism to choose; this alias is observed from your own ssh configuration",
            Some(reason::OBSERVED_ALIAS_UNMANAGED),
        ))
    };
    let (Some(id), Some(account)) = (text(found, "destination_id"), text(found, "account")) else {
        return Err(unmanaged());
    };
    let bad = || {
        Outcome::of(setup_cmd::failure(
            Code::InternalError,
            "the runtime listed an invalid destination",
            None,
        ))
    };
    Ok((
        DestinationId::parse(&id).map_err(|_| bad())?,
        AccountName::parse(&account).map_err(|_| bad())?,
    ))
}

/// The human rendering of a `SetPreference` answer for `alias`: what is chosen and
/// whether it changed, that it reaches `ssh` only through `setup apply` (D5 §6.6),
/// and, for a refusal because no verified enrollment exists, the command that makes one.
pub(crate) fn prefer_outcome(
    env: Envelope<serde_json::Value>,
    alias: &str,
    account: &AccountName,
) -> Outcome {
    let text =
        |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_owned);
    let mut human = String::new();
    if env.code.is_success() {
        let changed = env.data.get("changed").and_then(|c| c.as_bool());
        human.push_str(&format!(
            "{alias}: preference is {} ({}).\n",
            text(&env.data, "mechanism").unwrap_or_default(),
            if changed == Some(true) {
                "changed"
            } else {
                "unchanged"
            }
        ));
        match env.data.get("projection").filter(|p| !p.is_null()) {
            Some(p) if text(p, "state").as_deref() == Some("pending") => human.push_str(
                "It reaches ssh only after `heimdall setup apply`; until then ssh keeps its current behaviour.\n",
            ),
            Some(p) if text(p, "state").as_deref() == Some("applied") => {
                human.push_str("It is applied in Heimdall's ssh configuration.\n");
            }
            _ => {}
        }
    } else if env
        .data
        .get("error")
        .and_then(|e| text(e, "reason"))
        .as_deref()
        == Some(reason::PAIR_NOT_ENROLLED)
    {
        human.push_str(&format!(
            "This pair has no verified enrollment. Enroll it first: `heimdall enroll {alias} --account {account}`.\n"
        ));
    }
    Outcome::of(env).with_human(human)
}

/// `destination prefer <alias> managed|existing` (m03-plan §5 items 4b and 24): the
/// alias is resolved to its catalog destination and account through `inspect
/// destinations` (read-only), then the journaled catalog `SetPreference` is sent. The
/// runtime refuses `managed` for a pair without a verified enrollment
/// (`pair_not_enrolled`, exit 4); a change reaches `ssh` only through `setup apply`.
pub(crate) async fn destination_prefer(ctx: &Ctx, args: DestinationPreferArgs) -> Outcome {
    let mut client = match setup_cmd::session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let listing = match setup_cmd::inspect(&mut client, InspectSubject::Destinations).await {
        Ok(d) => d,
        Err(o) => return o,
    };
    let (destination, account) = match managed_pair(&listing, &args.alias) {
        Ok(p) => p,
        Err(o) => return o,
    };
    let request_id = match setup_cmd::request_id(None) {
        Ok(r) => r,
        Err(o) => return o,
    };
    let env = client
        .request(Request::Catalog(CatalogRequest::SetPreference {
            destination,
            account: account.clone(),
            mechanism: match args.mechanism {
                MechanismArg::Managed => PreferredMechanism::ManagedCertificate,
                MechanismArg::Existing => PreferredMechanism::Existing,
            },
            request_id,
        }))
        .await;
    prefer_outcome(env, &args.alias, &account)
}

/// `access lock-behavior --policy P continue|revoke-on-lock` as its policy action
/// (wave 5, U12). `cli::access` runs it through the M01 policy flow: `revoke-on-lock` is
/// narrowing and applies at once; `continue` widens and needs the owner's typed `yes`.
/// Where no lock signal is usable the runtime refuses before anything is written
/// (`lock_signal_unavailable`); a Linux `revoke_on_lock` result carries the
/// `signal_unverified` warning (U9-Q3 (a)).
pub(crate) fn lock_behavior_action(a: &LockBehaviorArgs) -> Result<PolicyAction, Done> {
    Ok(PolicyAction::SetLockBehavior {
        policy_id: parse("policy", PolicyId::parse, &a.policy)?,
        behavior: match a.behavior {
            LockBehaviorArg::Continue => LockBehavior::Continue,
            LockBehaviorArg::RevokeOnLock => LockBehavior::RevokeOnLock,
        },
    })
}

/// `access connection-policy --policy P [--existing ..] [--multiplexing ..]` as its
/// policy action (wave 5, U12). Neither flag given is a usage error: nothing to set.
pub(crate) fn connection_policy_action(a: &ConnectionPolicyArgs) -> Result<PolicyAction, Done> {
    if a.existing.is_none() && a.multiplexing.is_none() {
        return Err(Done::of(output::error_value(error(
            Code::UsageError,
            "connection-policy needs --existing or --multiplexing",
        ))));
    }
    Ok(PolicyAction::SetConnectionPolicy {
        policy_id: parse("policy", PolicyId::parse, &a.policy)?,
        existing: a.existing.map(|e| match e {
            ExistingArg::Graceful => ExistingConnectionsMode::Graceful,
            ExistingArg::Strict => ExistingConnectionsMode::Strict,
        }),
        multiplexing: a.multiplexing.map(|m| match m {
            MultiplexingArg::Disabled => MultiplexingMode::Disabled,
            MultiplexingArg::Owned => MultiplexingMode::OwnedMasters,
        }),
    })
}

/// `access ensure ... --strict`: `EnsureRequest.connection` asks for strict owned
/// connections (m03-plan §5 item 7). Without `--strict` the request is M02's.
pub(crate) fn strict_connection() -> ConnectionRequest {
    ConnectionRequest {
        existing: Some(ExistingConnectionsMode::Strict),
    }
}

/// The refusal of `internal issuer` run by a person: the issuer child is started by the
/// runtime on a pipe, never from a terminal (ADR-0008 D3). With a terminal on stdin the
/// message names the terminal; without one (not reachable from [`internal`], which runs
/// the child on a pipe) it is the plain usage line.
pub(crate) fn internal_issuer_envelope(stdin_tty: bool) -> Envelope<serde_json::Value> {
    let message = if stdin_tty {
        "internal issuer is started by the runtime and refuses a terminal on stdin"
    } else {
        "internal issuer runs only as the runtime's child"
    };
    output::error_value(error(Code::UsageError, message))
}

/// The hidden `internal` commands. `issuer` refuses a terminal on stdin first (the
/// envelope); on a pipe it **is** the issuer child (M03-U3, [`internal_issuer`]),
/// which writes nothing on stdout but protocol frames. `session-lock-state` is the
/// read-only query of [`session_lock_state_envelope`].
pub(crate) fn internal(ctx: &Ctx, command: InternalCommand) -> ExitCode {
    let env = match command {
        InternalCommand::Issuer if !ctx.stdin_tty => return internal_issuer(ctx),
        InternalCommand::Issuer => internal_issuer_envelope(true),
        InternalCommand::SessionLockState => {
            session_lock_state_envelope(&|name| std::env::var_os(name))
        }
    };
    output::emit(&env, ctx.json);
    output::exit_code_for(env.code, false)
}

/// ⟨M03 wave 5⟩ `heimdall internal session-lock-state` (m03-plan §4.4 step 4, §5 item
/// 24): the hidden, **read-only** query the native lock procedure verifies `locked`
/// with, in test configuration and release alike. One envelope, `OK`, whose data is
/// `{state, source, signal}`:
/// * `state`: the contract's `SessionLockState` (`unlocked`, `locked`, `unknown`,
///   `unavailable`), exactly what the source the runtime uses reads first;
/// * `source`: `platform` (`heimdall_runtime::session_lock::PlatformSessionLockSource`,
///   started for this one reading and joined), or `test_configuration` (a debug build
///   with `HEIMDALL_TEST_SESSION_LOCK`: testkit's `FakeSessionLockSource` over that
///   state file, as `service run` wires it);
/// * `signal`: the platform signal (`macos_screen_lock`, `windows_session`,
///   `linux_logind`, `none` where the source reads `unavailable`) or `test_state_file`.
///
/// It starts no runtime, opens no store and writes nothing (not even the Heimdall home).
/// A source that cannot be read answers what the source answers for it, `unknown` (a
/// platform source with no first reading in time; an unreadable state file), never a
/// guess. A release build that sees a test variable, or a malformed M03 test value, is
/// refused (`USAGE_ERROR`, exit 2) before anything is read.
pub(crate) fn session_lock_state_envelope(
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Envelope<serde_json::Value> {
    if let Some(msg) =
        crate::testcfg::refusal(crate::testcfg::AVAILABLE, crate::testcfg::requested_by(env))
    {
        return output::error_value(error(Code::UsageError, msg));
    }
    let m03 = match crate::testcfg::m03_config(env) {
        Ok(c) => c,
        Err(msg) => return output::error_value(error(Code::UsageError, &msg)),
    };
    let (state, source, signal) = match test_session_lock_state(&m03) {
        Some(state) => (state, "test_configuration", "test_state_file"),
        None => {
            let src = heimdall_runtime::session_lock::PlatformSessionLockSource::start();
            let snapshot = src.snapshot();
            src.shutdown();
            (
                snapshot.state,
                "platform",
                lock_signal_name(snapshot.signal),
            )
        }
    };
    Envelope::ok(serde_json::json!({
        "state": state,
        "source": source,
        "signal": signal,
    }))
}

/// The state of the test configuration's fake source (debug builds; `None` without
/// `HEIMDALL_TEST_SESSION_LOCK`).
#[cfg(debug_assertions)]
fn test_session_lock_state(
    m03: &crate::testcfg::M03Config,
) -> Option<heimdall_contract::managed::SessionLockState> {
    use heimdall_app::ports::SessionLockSource as _;
    m03.session_lock
        .as_ref()
        .map(|p| heimdall_testkit::session_lock::FakeSessionLockSource::from_state_file(p).state())
}

/// A release build has no test source (its test variables were refused above).
#[cfg(not(debug_assertions))]
fn test_session_lock_state(
    _: &crate::testcfg::M03Config,
) -> Option<heimdall_contract::managed::SessionLockState> {
    None
}

/// The wire name of a platform signal (ADR-0008 D9 item 3's table).
fn lock_signal_name(signal: heimdall_app::lock::LockSignal) -> &'static str {
    use heimdall_app::lock::LockSignal;
    match signal {
        LockSignal::MacosScreenLock => "macos_screen_lock",
        LockSignal::WindowsSession => "windows_session",
        LockSignal::LinuxLogind => "linux_logind",
        _ => "none",
    }
}

/// ⟨M03-U3⟩ The directory of the scratch test store under the state directory (D1
/// "Test K_ca": under the scratch state directory). U10's runtime wiring and U12's
/// ceremony select the same directory.
/// (Read by [`issuer_store`]'s debug-only scratch branch.)
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub(crate) const SCRATCH_STORE_DIR: &str = "scratch-secret-store";

/// ⟨M03-U3⟩ `heimdall internal issuer` on a pipe (ADR-0008 D3 item 1): the child the
/// runtime spawns. Its stdout is the `heimdall-issuer/1` channel, so it never prints
/// an envelope; the status is the child's ([`heimdall_issuer::child::run`]): 0 →
/// success, a refused configuration → usage (2), anything else → unavailable (5),
/// which the supervisor reads as `crashed`.
fn internal_issuer(ctx: &Ctx) -> ExitCode {
    match issuer_child_status(ctx) {
        0 => ExitCode::Success,
        heimdall_issuer::child::EXIT_USAGE => ExitCode::Usage,
        _ => ExitCode::Unavailable,
    }
}

/// The issuer child's status (see [`internal_issuer`]).
fn issuer_child_status(ctx: &Ctx) -> i32 {
    use heimdall_issuer::child::{EXIT_UNAVAILABLE, EXIT_USAGE};
    let env = |name: &str| std::env::var_os(name);
    // A release build refuses every test variable before anything is read (U0b's
    // `release_build_refuses_m03_test_gates`); the M03 values are validated here.
    if crate::testcfg::refusal(
        crate::testcfg::AVAILABLE,
        crate::testcfg::requested_by(&env),
    )
    .is_some()
    {
        return EXIT_USAGE;
    }
    let Ok(m03) = crate::testcfg::m03_config(&env) else {
        return EXIT_USAGE;
    };
    let Ok(paths) = ctx.paths() else {
        return EXIT_UNAVAILABLE;
    };
    let db = paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    // The installation's environment, which scopes the product store's items.
    let environment =
        heimdall_store::Store::open_read_only(&db, std::sync::Arc::new(heimdall_store::NoFaults))
            .and_then(|s| s.transaction(|tx| tx.self_environment()));
    let Ok(Some(environment)) = environment else {
        return EXIT_UNAVAILABLE;
    };
    // ⟨ADR-0008 §17.25 item 7 (b)⟩ The same selection as the CLI's (`issuer_cmd`): a
    // refused product-file store is a refused configuration.
    let Ok(test) = crate::testcfg::test_store(&m03, ctx.home.as_deref()) else {
        return EXIT_USAGE;
    };
    let Some(store) = issuer_store(ctx, &paths, &environment, &test) else {
        return EXIT_UNAVAILABLE;
    };
    heimdall_issuer::child::run(
        std::io::stdin(),
        std::io::stdout(),
        store,
        &db,
        issuer_clock(&env),
    )
}

/// ⟨M03-U3⟩ The issuer child's K_ca store (ADR-0008 D1): the platform's product
/// store, scoped to `environment` (§17.18 item 1). `None` where there is none
/// (headless Linux answers through the Secret Service's own availability; other
/// platforms have no store): fail closed, never a plaintext fallback. On Windows an
/// explicit Heimdall home keeps the DPAPI blobs under `<state>/issuer/<environment>`
/// (D1: a scratch `HEIMDALL_HOME` is the product kind at a scratch path); otherwise
/// `%LOCALAPPDATA%\Heimdall\issuer\<environment>` (§17.18 item 1). Either way the
/// directory is this environment's own: `WindowsDpapi::in_dir` reads and writes only
/// the blobs in it, so a blob outside it (the pre-release shared path) is never read or
/// adopted (§17.18 item 5).
///
/// ⟨M03 wave 4 (U3-Q4, §17.19 item 6)⟩ The scratch test store
/// (`HEIMDALL_TEST_SECRET_STORE=scratch`) is `heimdall_testkit::scratch_store::
/// ScratchSecretStore` under `<state>/scratch-secret-store`, in a **debug** build only:
/// a release build refuses every `HEIMDALL_TEST_*` variable before this runs (U0b row
/// 16), and its `scratch` flag is then never set; this branch is compiled out of it
/// regardless. Its kind is the testkit's `scratch_test`, never a product kind (F23).
///
/// ⟨ADR-0008 §17.25 item 7 (b)⟩ The product-file test store
/// (`HEIMDALL_TEST_SECRET_STORE=product-file:<abs path>`, [`crate::testcfg::TestStore`])
/// is the platform's product implementation at the test's path
/// (`heimdall_issuer::store::test_product::open`: a file keychain outside the search
/// list on macOS, a DPAPI directory on Windows, none on Linux), in a **debug** build
/// only, re-checked here (`test_product::refusal`) against the explicit home. A release
/// build refuses the variable first, and this branch answers `None` there.
pub(crate) fn issuer_store(
    ctx: &Ctx,
    paths: &heimdall_runtime::paths::Paths,
    environment: &heimdall_contract::ids::EnvironmentId,
    test: &crate::testcfg::TestStore,
) -> Option<Box<dyn heimdall_issuer::store::SecretStore>> {
    use crate::testcfg::TestStore;
    match test {
        TestStore::Platform => {}
        #[cfg(debug_assertions)]
        TestStore::Scratch => {
            return Some(Box::new(
                heimdall_testkit::scratch_store::ScratchSecretStore::new(
                    paths.state_dir.join(SCRATCH_STORE_DIR),
                ),
            ));
        }
        #[cfg(debug_assertions)]
        TestStore::ProductFile(path) => {
            let home = ctx.home.as_deref()?;
            let account = heimdall_localenv::sys::account_home().ok();
            if heimdall_issuer::store::test_product::refusal(path, home, account.as_deref())
                .is_some()
            {
                return None;
            }
            return heimdall_issuer::store::test_product::open(path, environment);
        }
        #[cfg(not(debug_assertions))]
        TestStore::Scratch | TestStore::ProductFile(_) => return None,
    }
    let _ = (ctx, paths, environment);
    #[cfg(target_os = "macos")]
    {
        let home = heimdall_localenv::sys::account_home().ok()?;
        Some(Box::new(heimdall_issuer::store::MacosLoginKeychain::login(
            &home,
            environment,
        )))
    }
    #[cfg(windows)]
    {
        let dir = if ctx.home.is_some() {
            paths.state_dir.join("issuer").join(environment.as_str())
        } else {
            heimdall_issuer::store::WindowsDpapi::default_dir(environment).ok()?
        };
        Some(Box::new(heimdall_issuer::store::WindowsDpapi::in_dir(
            dir,
            environment,
        )))
    }
    #[cfg(target_os = "linux")]
    {
        Some(Box::new(heimdall_issuer::store::LinuxSecretService::new(
            environment,
        )))
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    {
        None
    }
}

/// ⟨M03-U3⟩ The issuer child's clock: the system clock, shifted like the runtime's
/// by `HEIMDALL_TEST_CLOCK_OFFSET_S` in a test-configured build, so the child's
/// read-only time gate sees the wall time the runtime anchored.
fn issuer_clock(
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> std::sync::Arc<dyn heimdall_domain::time::Clock> {
    use heimdall_domain::time::Clock;
    struct Shifted(crate::testcfg::ClockOffset);
    impl Clock for Shifted {
        fn wall(&self) -> heimdall_contract::Timestamp {
            self.0.shift(heimdall_runtime::platform::SystemClock.wall())
        }
        fn continuous(&self) -> std::time::Duration {
            heimdall_runtime::platform::SystemClock.continuous()
        }
        fn boot_id(&self) -> heimdall_domain::time::BootId {
            heimdall_runtime::platform::SystemClock.boot_id()
        }
    }
    match env(crate::testcfg::CLOCK_OFFSET_ENV)
        .filter(|_| crate::testcfg::AVAILABLE)
        .and_then(|v| crate::testcfg::ClockOffset::parse(&v).ok())
    {
        Some(offset) => std::sync::Arc::new(Shifted(offset)),
        None => std::sync::Arc::new(heimdall_runtime::platform::SystemClock),
    }
}

// --- the runtime's conditional lock text (ADR-0008 §17.27 item 4; D9 item 1) ---------

/// ⟨§17.27 item 4; wave 5 round 3 api R2⟩ The runtime's conditional lock text from an
/// `inspect capabilities` answer: `data.lock.disclosure`, sanitized for the terminal
/// with the ordinary renderers' sanitizer ([`output::sanitize_for_terminal`]). `None`
/// when the answer is a refusal, carries no `lock` (the runtime could not read it), or
/// its text is absent, not a string, or empty once sanitized: a caller whose decision
/// carries `lock_continuity_once` then refuses to approve (exit 3), so the once-only
/// acknowledgement is recorded only for a decision whose conditional text was shown.
#[must_use]
pub(crate) fn lock_disclosure_text(capabilities: &Envelope<serde_json::Value>) -> Option<String> {
    if !capabilities.code.is_success() {
        return None;
    }
    let raw = capabilities.data.get("lock")?.get("disclosure")?.as_str()?;
    let text = output::sanitize_for_terminal(raw);
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// [`lock_disclosure_text`] of a fresh `inspect capabilities` on `s` (read-only).
pub(crate) async fn fetch_lock_disclosure_text<S: crate::cli::Session>(
    s: &mut S,
) -> Option<String> {
    let env = s
        .request(Request::Inspect(
            heimdall_contract::request::InspectRequest {
                subject: InspectSubject::Capabilities,
                preview: None,
            },
        ))
        .await;
    lock_disclosure_text(&env)
}

/// ⟨§17.27 item 4⟩ The refusal to approve a decision carrying `lock_continuity_once`
/// whose conditional lock text could not be obtained or rendered: nothing was sent, the
/// decision stays pending (exit 3, `INTERACTION_REQUIRED`).
pub(crate) fn lock_text_unavailable(
    decision: Option<&str>,
    operation: Option<heimdall_contract::ids::OperationId>,
) -> Envelope<serde_json::Value> {
    setup_cmd::not_confirmed(
        decision,
        operation,
        "the runtime's lock disclosure could not be read, so it cannot be shown; approval is refused until it can be",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(env: &Envelope<serde_json::Value>) -> String {
        env.data
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .map(str::to_owned)
            .unwrap_or_default()
    }

    /// (was `the_wave_0_envelope_is_m01s`.) Neither `internal issuer` refusal carries the
    /// wave-0 text: both are ordinary usage errors (exit 2, effect `none`) that name why.
    #[test]
    fn m03_internal_issuer_envelopes_carry_no_wave_0_text() {
        for tty in [true, false] {
            let env = internal_issuer_envelope(tty);
            assert_eq!(env.code, Code::UsageError, "tty={tty}");
            assert_eq!(
                output::exit_code_for(env.code.clone(), false),
                ExitCode::Usage,
                "tty={tty}"
            );
            assert!(
                !message(&env).contains("not available"),
                "tty={tty}: {}",
                message(&env)
            );
            assert!(
                !message(&env).contains("planned for M03"),
                "tty={tty}: {}",
                message(&env)
            );
            assert_eq!(
                env.data["error"]["effect_status"], "none",
                "tty={tty}: {env:?}"
            );
        }
    }

    /// `internal issuer_refuses_tty_stdin`: a terminal on stdin is refused first, with
    /// its own message; the line without a terminal is the plain "runs only as the
    /// runtime's child" usage error (not the wave-0 text).
    #[test]
    fn internal_issuer_refuses_tty_stdin() {
        let tty = internal_issuer_envelope(true);
        assert_eq!(tty.code, Code::UsageError);
        assert!(message(&tty).contains("refuses a terminal on stdin"));
        assert!(!message(&tty).contains("not available"));
        let pipe = internal_issuer_envelope(false);
        assert_eq!(pipe.code, Code::UsageError);
        assert!(message(&pipe).contains("runs only as the runtime's child"));
        assert_ne!(message(&pipe), message(&tty));
        assert!(!message(&pipe).contains("not available"));
    }

    /// Every M03 command line of m03-plan §5 item 24, as a list of arguments.
    pub(crate) const M03_LINES: &[&[&str]] = &[
        &["issuer", "init", "--backup-out", "b.enc"],
        &[
            "issuer",
            "init",
            "--backup-out",
            "b",
            "--replace-orphan",
            "fp",
            "--bundle",
            "f",
        ],
        &[
            "issuer",
            "init",
            "--backup-out",
            "b",
            "--replace-orphan",
            "fp",
            "--no-bundle-available",
        ],
        &["issuer", "status"],
        &["issuer", "unlock"],
        &["issuer", "rotate", "begin", "--backup-out", "b.enc"],
        &["issuer", "retire", "SHA256:abc"],
        &["issuer", "restore", "--backup", "b.enc"],
        &["issuer", "restore", "--backup", "b.enc", "--not-stolen"],
        &["issuer", "bundle", "--out", "o.json"],
        &[
            "issuer",
            "bundle",
            "--out",
            "o.json",
            "--redact",
            "hostnames",
        ],
        &["enroll", "lab"],
        &[
            "enroll",
            "lab",
            "--account",
            "deploy",
            "--form",
            "system",
            "--registry-path",
            "p",
            "--ca",
            "fp",
        ],
        &["enroll", "status"],
        &["enroll", "verify", "enr-1"],
        &["enroll", "verify", "enr-1", "--absence"],
        &["enroll", "verify", "enr-1", "--approve-target-change"],
        &["enroll", "remove", "enr-1"],
        &[
            "enroll",
            "remove",
            "--from-bundle",
            "f",
            "--marker",
            "m",
            "--alias",
            "a",
        ],
        &["enroll", "reconcile", "op-1"],
        &["enroll", "reconcile", "op-1", "--after-manual-recovery"],
        &["enroll", "abandon", "enr-1"],
        &["destination", "prefer", "lab", "managed"],
        &["destination", "prefer", "lab", "existing"],
        &[
            "access",
            "ensure",
            "--profile",
            "p",
            "--work-id",
            "w",
            "--request-id",
            "r",
            "--strict",
        ],
        &["access", "lock-behavior", "--policy", "pol", "continue"],
        &[
            "access",
            "lock-behavior",
            "--policy",
            "pol",
            "revoke-on-lock",
        ],
        &["access", "connection-policy", "--policy", "pol"],
        &[
            "access",
            "connection-policy",
            "--policy",
            "pol",
            "--existing",
            "strict",
            "--multiplexing",
            "owned",
        ],
        &[
            "access",
            "connection-policy",
            "--policy",
            "pol",
            "--existing",
            "graceful",
            "--multiplexing",
            "disabled",
        ],
        &["connections"],
        &["connections", "close", "conn-1"],
        &["internal", "issuer"],
        &["internal", "session-lock-state"],
    ];

    /// Lines the tree must refuse at parse time (exit 2 `USAGE_ERROR`).
    const REFUSED_LINES: &[&[&str]] = &[
        &["issuer", "init"],
        &[
            "issuer",
            "init",
            "--backup-out",
            "b",
            "--replace-orphan",
            "fp",
        ],
        &["issuer", "init", "--backup-out", "b", "--bundle", "f"],
        &[
            "issuer",
            "init",
            "--backup-out",
            "b",
            "--replace-orphan",
            "fp",
            "--bundle",
            "f",
            "--no-bundle-available",
        ],
        &["issuer", "rotate"],
        &["issuer", "restore"],
        &["issuer", "bundle", "--out", "o", "--redact", "everything"],
        &["enroll"],
        &["enroll", "lab", "status"],
        &[
            "enroll",
            "verify",
            "enr-1",
            "--absence",
            "--approve-target-change",
        ],
        &["enroll", "remove"],
        &["enroll", "remove", "--from-bundle", "f"],
        &[
            "enroll",
            "remove",
            "enr-1",
            "--from-bundle",
            "f",
            "--marker",
            "m",
            "--alias",
            "a",
        ],
        &["destination", "prefer", "lab", "other"],
        &["access", "lock-behavior", "continue"],
        &["access", "lock-behavior", "--policy", "pol", "sometimes"],
        &["access", "connection-policy"],
        &[
            "access",
            "connection-policy",
            "--policy",
            "pol",
            "--multiplexing",
            "owned_masters",
        ],
        &["connections", "close"],
        // ⟨§17.25 item 11⟩ `--keep-remote-enrollments` alone is accepted (it acknowledges a
        // plain uninstall); `--bundle` still needs both flags.
        &["uninstall", "--keep-remote-enrollments", "--bundle", "f"],
        &["uninstall", "--purge-state", "--bundle", "f"],
    ];

    /// The tree takes exactly the commands of the plan's table and refuses the rest,
    /// and every accepted line is an M03 command that no M02 handler owns.
    #[test]
    fn the_m03_command_tree_matches_the_plan_table() {
        use clap::Parser as _;
        for line in M03_LINES {
            let argv: Vec<&str> = std::iter::once("heimdall")
                .chain(line.iter().copied())
                .collect();
            if let Err(e) = crate::cli::Cli::try_parse_from(&argv) {
                panic!("{line:?} must parse: {:?}", e.kind());
            }
        }
        for line in REFUSED_LINES {
            let argv: Vec<&str> = std::iter::once("heimdall")
                .chain(line.iter().copied())
                .collect();
            assert!(
                crate::cli::Cli::try_parse_from(&argv).is_err(),
                "{line:?} must be refused"
            );
        }
        let uninstall = crate::cli::Cli::try_parse_from([
            "heimdall",
            "uninstall",
            "--purge-state",
            "--keep-remote-enrollments",
            "--bundle",
            "f",
        ]);
        assert!(uninstall.is_ok());
    }

    /// `internal` is hidden from help; the user commands are not.
    #[test]
    fn internal_is_hidden_and_the_rest_are_listed() {
        use clap::CommandFactory as _;
        let cmd = crate::cli::Cli::command();
        for (name, hidden) in [
            ("internal", true),
            ("issuer", false),
            ("enroll", false),
            ("connections", false),
        ] {
            let Some(sub) = cmd.get_subcommands().find(|c| c.get_name() == name) else {
                panic!("no {name} command");
            };
            assert_eq!(sub.is_hide_set(), hidden, "{name}");
        }
    }

    /// The M03 lines that answer **before any runtime contact**, with each line's real exit
    /// class (wave 5; each was determined by running the real binary). Lines of
    /// [`M03_LINES`] that are missing here contact the runtime and start it on demand
    /// (`enroll lab`, `destination prefer`), or are the hidden `internal` commands
    /// (below); the policy and `ensure --strict` lines are given an invalid ID so they
    /// are refused as usage errors first.
    const BAD: &str = "BAD ID";
    const ANSWERS_WITHOUT_A_RUNTIME: &[(&[&str], ExitCode)] = &[
        // Ceremonies need the owner at a terminal: `--non-interactive` -> 3.
        (
            &["issuer", "init", "--backup-out", "b.enc"],
            ExitCode::InteractionRequired,
        ),
        (
            &[
                "issuer",
                "init",
                "--backup-out",
                "b",
                "--replace-orphan",
                "fp",
                "--bundle",
                "f",
            ],
            ExitCode::InteractionRequired,
        ),
        (
            &[
                "issuer",
                "init",
                "--backup-out",
                "b",
                "--replace-orphan",
                "fp",
                "--no-bundle-available",
            ],
            ExitCode::InteractionRequired,
        ),
        (&["issuer", "status"], ExitCode::Unavailable),
        (&["issuer", "unlock"], ExitCode::InteractionRequired),
        (
            &["issuer", "rotate", "begin", "--backup-out", "b.enc"],
            ExitCode::InteractionRequired,
        ),
        (&["issuer", "retire", "SHA256:abc"], ExitCode::Usage),
        (
            &["issuer", "restore", "--backup", "b.enc"],
            ExitCode::InteractionRequired,
        ),
        (
            &["issuer", "restore", "--backup", "b.enc", "--not-stolen"],
            ExitCode::InteractionRequired,
        ),
        (
            &["issuer", "bundle", "--out", "o.json"],
            ExitCode::Unavailable,
        ),
        (
            &[
                "issuer",
                "bundle",
                "--out",
                "o.json",
                "--redact",
                "hostnames",
            ],
            ExitCode::Unavailable,
        ),
        // `enroll`: a fixture ID or CA that does not parse is refused first.
        (
            &[
                "enroll",
                "lab",
                "--account",
                "deploy",
                "--form",
                "system",
                "--registry-path",
                "p",
                "--ca",
                "fp",
            ],
            ExitCode::Usage,
        ),
        (&["enroll", "status"], ExitCode::Unavailable),
        (&["enroll", "verify", "enr-1"], ExitCode::Usage),
        (&["enroll", "verify", "enr-1", "--absence"], ExitCode::Usage),
        (
            &["enroll", "verify", "enr-1", "--approve-target-change"],
            ExitCode::Usage,
        ),
        (&["enroll", "remove", "enr-1"], ExitCode::Usage),
        (
            &[
                "enroll",
                "remove",
                "--from-bundle",
                "f",
                "--marker",
                "m",
                "--alias",
                "a",
            ],
            ExitCode::Usage,
        ),
        (&["enroll", "reconcile", "op-1"], ExitCode::Usage),
        (
            &["enroll", "reconcile", "op-1", "--after-manual-recovery"],
            ExitCode::Usage,
        ),
        (&["enroll", "abandon", "enr-1"], ExitCode::Usage),
        // `access`: an invalid ID (a valid one would start the runtime).
        (
            &[
                "access",
                "ensure",
                "--profile",
                BAD,
                "--work-id",
                "w",
                "--request-id",
                "r",
                "--strict",
            ],
            ExitCode::Usage,
        ),
        (
            &["access", "lock-behavior", "--policy", BAD, "continue"],
            ExitCode::Usage,
        ),
        (
            &["access", "lock-behavior", "--policy", BAD, "revoke-on-lock"],
            ExitCode::Usage,
        ),
        (
            &["access", "connection-policy", "--policy", "pol"],
            ExitCode::Usage,
        ),
        (
            &[
                "access",
                "connection-policy",
                "--policy",
                BAD,
                "--existing",
                "strict",
                "--multiplexing",
                "owned",
            ],
            ExitCode::Usage,
        ),
        (&["connections"], ExitCode::Unavailable),
        (&["connections", "close", "conn-1"], ExitCode::Usage),
    ];

    /// Dispatch `line` in-process against a Heimdall home that does not exist; returns the
    /// exit status and whether the home exists afterwards.
    fn dispatch_in_process(line: &[&str], home: &std::path::Path) -> (ExitCode, bool) {
        use clap::Parser as _;
        let home_arg = home.to_string_lossy().into_owned();
        let argv: Vec<&str> = ["heimdall", "--json", "--non-interactive", "--home"]
            .into_iter()
            .chain(std::iter::once(home_arg.as_str()))
            .chain(line.iter().copied())
            .collect();
        let cli = crate::cli::Cli::try_parse_from(&argv)
            .unwrap_or_else(|e| panic!("{line:?} must parse: {:?}", e.kind()));
        let code = crate::cli::dispatch(cli);
        (code, home.exists())
    }

    /// Every M03 line that answers before runtime contact, dispatched in-process, answers
    /// its **real** exit class (3 for a ceremony under `--non-interactive`, 5 for a read
    /// with no runtime, 2 for an invalid ID) and creates nothing under the Heimdall home
    /// it names. Each of those lines parses, and is a line of the plan's table or its
    /// invalid-ID form.
    #[test]
    fn m03_lines_answer_without_touching_the_home() {
        use clap::Parser as _;
        let scratch = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        for (i, (line, expected)) in ANSWERS_WITHOUT_A_RUNTIME.iter().enumerate() {
            let home = scratch.path().join(format!("home-{i}"));
            let (code, created) = dispatch_in_process(line, &home);
            assert_eq!(code, *expected, "{line:?}");
            assert!(!created, "{line:?} touched the home");
            assert!(!home.join("run").exists(), "{line:?} started a runtime");
            let argv: Vec<&str> = std::iter::once("heimdall")
                .chain(line.iter().copied())
                .collect();
            assert!(crate::cli::Cli::try_parse_from(&argv).is_ok(), "{line:?}");
        }
        // `internal issuer` is the issuer child on a pipe (no state database in the home:
        // it cannot serve, exits unavailable); with a terminal on stdin it is the usage
        // refusal. Neither touches the home.
        let home = scratch.path().join("home-internal-issuer");
        let (code, created) = dispatch_in_process(&["internal", "issuer"], &home);
        let expected = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            ExitCode::Usage
        } else {
            ExitCode::Unavailable
        };
        assert_eq!(code, expected);
        assert!(!created, "internal issuer touched the home");
    }
}

/// ⟨M03⟩ wave 5 (U12), worker A's unit tests: the `destination prefer` resolution and
/// rendering, the classification of the two M03 policy actions, and the exit codes of
/// every M03 reason. (The integrator's `mod tests` above is separate.)
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod wave5_tests {
    use super::*;
    use crate::cli::{ConnectionPolicyArgs, ExistingArg, LockBehaviorArg, MultiplexingArg};

    fn lock(behavior: LockBehaviorArg) -> PolicyAction {
        lock_behavior_action(&LockBehaviorArgs {
            policy: "pol".to_owned(),
            behavior,
        })
        .unwrap_or_else(|_| unreachable!())
    }

    fn conn(existing: Option<ExistingArg>, multiplexing: Option<MultiplexingArg>) -> PolicyAction {
        connection_policy_action(&ConnectionPolicyArgs {
            policy: "pol".to_owned(),
            existing,
            multiplexing,
        })
        .unwrap_or_else(|_| unreachable!())
    }

    /// The widening M03 actions are the ones that need the owner's typed `yes` (and
    /// `Attend` first); the narrowing ones apply at once and never attend
    /// (`policy_flow` asks `PolicyAction::is_widening`). The classification is the
    /// contract's, against the plan's table (§5 item 6).
    #[test]
    fn m03_policy_actions_classify_as_widening_or_narrowing() {
        assert!(lock(LockBehaviorArg::Continue).is_widening());
        assert!(!lock(LockBehaviorArg::RevokeOnLock).is_widening());
        assert!(conn(Some(ExistingArg::Graceful), None).is_widening());
        assert!(conn(None, Some(MultiplexingArg::Owned)).is_widening());
        assert!(!conn(Some(ExistingArg::Strict), None).is_widening());
        assert!(!conn(None, Some(MultiplexingArg::Disabled)).is_widening());
        // Both flags: one widening part makes the whole action widening.
        assert!(conn(Some(ExistingArg::Strict), Some(MultiplexingArg::Owned)).is_widening());
        assert!(!conn(Some(ExistingArg::Strict), Some(MultiplexingArg::Disabled)).is_widening());
    }

    /// `connection-policy` with neither flag is a usage error, sent nowhere.
    #[test]
    fn connection_policy_needs_a_flag() {
        let refused = connection_policy_action(&ConnectionPolicyArgs {
            policy: "pol".to_owned(),
            existing: None,
            multiplexing: None,
        });
        let Err(done) = refused else {
            panic!("a no-op connection-policy was accepted");
        };
        assert_eq!(done.env.code, Code::UsageError);
    }

    /// `access ensure --strict` asks to narrow `existing` to `strict` and nothing more.
    #[test]
    fn strict_connection_narrows_existing_only() {
        let c = strict_connection();
        assert_eq!(c.existing, Some(ExistingConnectionsMode::Strict));
    }

    fn listing() -> serde_json::Value {
        serde_json::json!({"items": [
            {"destination_id": "dst-lab", "alias": "lab", "definition": "managed",
             "account": "deploy", "hostname": "lab.example.invalid"},
            {"destination_id": "dst-seen", "alias": "seen", "definition": "observed"},
        ]})
    }

    fn code_of(o: &Outcome) -> (Code, Option<String>) {
        (
            o.env.code.clone(),
            o.env
                .data
                .get("error")
                .and_then(|e| e.get("reason"))
                .and_then(|r| r.as_str())
                .map(str::to_owned),
        )
    }

    /// The alias (or the ID) resolves to the managed destination's ID and account; an
    /// observed alias is `observed_alias_unmanaged` (exit 4), an unknown one `NOT_FOUND`.
    #[test]
    fn destination_prefer_resolves_the_managed_pair() {
        for wanted in ["lab", "dst-lab"] {
            let (d, a) =
                managed_pair(&listing(), wanted).unwrap_or_else(|_| panic!("{wanted} resolves"));
            assert_eq!((d.as_str(), a.as_str()), ("dst-lab", "deploy"));
        }
        let observed = match managed_pair(&listing(), "seen") {
            Err(o) => o,
            Ok(_) => panic!("an observed alias resolved"),
        };
        assert_eq!(
            code_of(&observed),
            (
                Code::CapabilityUnavailable,
                Some(reason::OBSERVED_ALIAS_UNMANAGED.to_owned())
            )
        );
        assert_eq!(observed.exit, ExitCode::Denied);
        let missing = match managed_pair(&listing(), "nope") {
            Err(o) => o,
            Ok(_) => panic!("an unknown alias resolved"),
        };
        assert_eq!(code_of(&missing).0, Code::NotFound);
        assert_eq!(missing.exit, ExitCode::Usage);
        // A listing without items is an unknown destination, never a panic.
        assert!(managed_pair(&serde_json::json!({}), "lab").is_err());
    }

    fn answered(data: serde_json::Value) -> Envelope<serde_json::Value> {
        Envelope::ok(data)
    }

    /// The answer is rendered with what is chosen, whether it changed, and that the
    /// change reaches `ssh` only through `setup apply`; the refusal for a pair without
    /// a verified enrollment names the enrollment command; the envelope is untouched.
    #[test]
    fn destination_prefer_renders_the_answer() {
        let account = AccountName::parse("deploy").unwrap();
        let pending = prefer_outcome(
            answered(serde_json::json!({
                "destination_id": "dst-lab", "account": "deploy",
                "mechanism": "managed_certificate",
                "projection": {"state": "pending"}, "changed": true,
            })),
            "lab",
            &account,
        );
        assert_eq!(pending.exit, ExitCode::Success);
        assert!(
            pending
                .human
                .contains("lab: preference is managed_certificate (changed).")
        );
        assert!(
            pending.human.contains("heimdall setup apply"),
            "{}",
            pending.human
        );
        let same = prefer_outcome(
            answered(serde_json::json!({
                "mechanism": "existing", "projection": null, "changed": false,
            })),
            "lab",
            &account,
        );
        assert!(same.human.contains("preference is existing (unchanged)."));
        assert!(!same.human.contains("setup apply"));
        let refused = crate::setup_cmd::failure(
            Code::CapabilityUnavailable,
            "this pair has no verified enrollment",
            Some(reason::PAIR_NOT_ENROLLED),
        );
        let refused = prefer_outcome(refused, "lab", &account);
        assert_eq!(refused.exit, ExitCode::Denied);
        assert!(
            refused
                .human
                .contains("heimdall enroll lab --account deploy"),
            "{}",
            refused.human
        );
    }

    /// ADR-0006 §5, transcribed: the exit class of each code an M03 reason is used with.
    const EXIT_BY_CODE: &[(&str, i32)] = &[
        ("CAPABILITY_UNAVAILABLE", 4),
        ("CONFIG_CONFLICT", 6),
        ("USAGE_ERROR", 2),
        ("LAUNCH_FAILED", 127),
        ("REQUEST_CONFLICT", 6),
        ("OUTCOME_UNKNOWN", 7),
        ("DECISION_STALE", 6),
        ("HOST_TRUST_CHANGED", 4),
        ("SERVICE_UNAVAILABLE", 5),
        ("BACKPRESSURE", 5),
        ("CREDENTIAL_EXPIRED", 4),
    ];

    /// m03-plan U12 "exit codes per the ADR-0006 §5 table for each new reason": every
    /// reason in `reason::M03` exits as its code's row of the table, through the CLI's
    /// own mapping (`output::exit_code_for`, and the reason-aware form `run`/`connect`
    /// use), and agrees with the frozen golden.
    #[test]
    fn m03_reasons_exit_codes_follow_adr_0006_table() {
        let golden: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(heimdall_testkit::repo::repo_path(
                "tests/contracts/golden/m03-reasons.golden.json",
            ))
            .expect("the reasons golden"),
        )
        .expect("the golden is JSON");
        let golden_rows: Vec<(String, String)> = golden["new"]
            .as_array()
            .expect("new reasons")
            .iter()
            .map(|r| {
                (
                    r["reason"].as_str().unwrap().to_owned(),
                    r["code"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert!(!reason::M03.is_empty());
        for (name, code) in reason::M03 {
            let (_, expected) = EXIT_BY_CODE
                .iter()
                .find(|(c, _)| *c == code.as_str())
                .unwrap_or_else(|| panic!("{name}: {code:?} is not in the table above"));
            assert_eq!(
                output::exit_code_for(code.clone(), false).as_i32(),
                *expected,
                "{name} ({code:?})"
            );
            assert_eq!(
                output::exit_code_for(code.clone(), true).as_i32(),
                *expected,
                "{name} (async)"
            );
            assert_eq!(
                code.exit_code_for_reason(Some(name)).as_i32(),
                *expected,
                "{name} (reason-aware)"
            );
            assert!(
                golden_rows
                    .iter()
                    .any(|(r, c)| r == name && c == code.as_str()),
                "{name} -> {code:?} is not in the golden"
            );
        }
        // Nothing in the golden is missing from the registry the CLI maps through.
        for (name, code) in &golden_rows {
            assert!(
                reason::M03
                    .iter()
                    .any(|(r, c)| r == name && c.as_str() == code),
                "{name} -> {code} is in the golden but not in reason::M03"
            );
        }
        // The reasons this unit's commands answer with, by name.
        for (name, exit) in [
            (reason::LOCK_SIGNAL_UNAVAILABLE, 4),
            (reason::PAIR_NOT_ENROLLED, 4),
            (reason::OBSERVED_ALIAS_UNMANAGED, 4),
            (reason::DESCRIPTOR_MISMATCH, 4),
            (reason::REGISTRY_PATH_INVALID, 2),
            (reason::OWNED_CONNECTION_OPTION_CONFLICT, 6),
            (reason::CONNECTION_REGISTRATION_REFUSED, 127),
        ] {
            let (_, code) = reason::M03
                .iter()
                .find(|(r, _)| *r == name)
                .unwrap_or_else(|| panic!("{name} is not an M03 reason"));
            assert_eq!(
                output::exit_code_for(code.clone(), false).as_i32(),
                exit,
                "{name}"
            );
        }
    }
}
