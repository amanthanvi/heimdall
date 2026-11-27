//! `heimdall service run|status|stop` (spec §13.1; overview §3 "service mode").
//!
//! * `run` hosts the per-user runtime in this process on the service's
//!   current-thread executor (`Service::runtime`, overview §4). SIGINT/SIGTERM
//!   (Ctrl-C on Windows) cancel the service token; `Service::run` then drains,
//!   closes the endpoints, removes `instance.json` and releases the lock last.
//!   `--detach` (used by on-demand start, which already spawned this process with
//!   null stdio in its own process group) logs to the bounded file sink instead
//!   of stderr and ignores SIGHUP. Before anything else it closes every
//!   descriptor above 2 it inherited (Unix; ADR-0006 §13.8 item 7), and refuses
//!   to start (fixed stderr message, exit 5) when that cannot be established.
//! * ⟨M04 U1; ADR-0010 §1 item 2, §6⟩ `run --login` is `run` as the login entry starts it:
//!   it exits 0, with no output and no side effect, when another instance holds the
//!   runtime lock (read from the existing lock file before any directory, log or store is
//!   touched, and again by the lock the runtime takes itself), and otherwise runs like
//!   `run --detach` (the log goes to the bounded file sink: a login entry has no
//!   terminal).
//! * ⟨M04 U1⟩ `autostart enable|disable|status` manage the login entry (module
//!   [`heimdall_runtime::autostart`]): `status` and `disable` are local and read or
//!   remove only Heimdall's own entry by its exact data (a foreign entry at the name is
//!   `CONFIG_CONFLICT`, reason `login_entry_conflict`, untouched); `enable` is the
//!   attended setup step: it previews the entry through the runtime's setup item, shows
//!   its exact data, and writes it only after a typed `yes` on a terminal
//!   ([`enable_flow`]); `--non-interactive` or no terminal ends it with exit 3 and
//!   nothing written. A relocated Heimdall home (`--home`) never writes the account's
//!   login entry: `enable` is refused there unless the debug-only test root
//!   `HEIMDALL_TEST_LOGIN_ROOT` names a scratch root (a directory, or on Windows a
//!   registry subkey under `Software\HeimdallTest\`), and a release build refuses the
//!   variable.
//! * `status` validates the advertisement (pid + OS start time + owner-only
//!   endpoints), connects to the advertised endpoint, verifies it and performs a hello;
//!   it never starts a runtime. ⟨M07 S2-07; ADR-0013 §8 D12, ADR-0014 H14⟩ It answers
//!   three states (`runtime_not_running`, the verified status, `runtime_unreachable`)
//!   and reports only what the verified connection gives or checks ([`status`]).
//! * `stop` (every platform, ADR-0006 §13.6 item 8) connects to the owner's
//!   control endpoint requiring `service-control/1` and sends `Request::Shutdown`;
//!   on `OK` the runtime drains gracefully and this command waits, bounded, for
//!   the **validated** advertised process (pid + OS start time) to end
//!   (`via: "control"`). An explicit refusal by the runtime is reported as is,
//!   never bypassed. Only when the control endpoint cannot be used (connect or
//!   hello failure, an older runtime without the capability, a lost connection)
//!   does Unix fall back to SIGTERM to the validated advertised PID only (the
//!   advertisement is re-validated immediately before the signal, which goes
//!   through `/bin/kill` or `/usr/bin/kill` by absolute path: no shell, no `PATH`
//!   lookup, no `unsafe` in this crate; `via: "signal"`); Windows then reports
//!   `SERVICE_UNAVAILABLE`. Nothing running is success (`stopped: false`):
//!   repeated stops are idempotent.

use std::time::Duration;

use heimdall_app::ports::{LoginEntryFailure, LoginEntryPort, LoginEntryState};
use heimdall_contract::envelope::EffectStatus;
use heimdall_contract::envelope::{Envelope, ErrorData};
use heimdall_contract::{Code, ExitCode};
use heimdall_runtime::autostart::port::HostLoginPort;
use heimdall_runtime::config::{Config, MAX_CONFIG_BYTES};
use heimdall_runtime::instance::{Advertised, InstanceInfo};
use heimdall_runtime::service::{Service, ServiceError, ServiceOptions};
use heimdall_runtime::telemetry::{self, LogSink};
use heimdall_runtime::{Paths, config::ConfigError};
use tokio_util::sync::CancellationToken;

use crate::cli::{AutostartCommand, Prompter, Session, TerminalPrompt};
use crate::client::{Ctx, error};
use crate::output;

/// Bound on waiting for a stopped runtime to exit.
const STOP_WAIT: Duration = Duration::from_secs(20);

fn finish(ctx: &Ctx, env: Envelope<serde_json::Value>) -> ExitCode {
    output::emit(&env, ctx.json);
    output::exit_code_for(env.code, false)
}

fn fail(ctx: &Ctx, env: Envelope<ErrorData>) -> ExitCode {
    finish(ctx, output::error_value(env))
}

fn service_error(e: &ServiceError) -> Envelope<ErrorData> {
    use heimdall_runtime::instance::InstanceError;
    let (code, msg) = match e {
        ServiceError::Instance(InstanceError::AlreadyRunning) => (
            Code::ServiceUnavailable,
            "another runtime instance is already running for these directories".to_owned(),
        ),
        ServiceError::Instance(InstanceError::Io(io)) => (
            Code::StateUnavailable,
            format!("the instance lock is unavailable: {}", io.kind()),
        ),
        ServiceError::Config(c) if heimdall_runtime::paths::is_state_dir_unsafe(c) => {
            return state_dir_unsafe(c);
        }
        ServiceError::Config(c) => (Code::ConfigConflict, c.to_string()),
        ServiceError::Store(s) => (Code::StateUnavailable, format!("state store: {s}")),
        ServiceError::App(app) => return app.clone().into_envelope(),
        ServiceError::Bind(io) => (
            Code::ServiceUnavailable,
            format!("endpoint bind failed: {}", io.kind()),
        ),
        ServiceError::Clock(io) => (
            Code::TimeUncertain,
            format!("platform clock sources unavailable: {}", io.kind()),
        ),
        ServiceError::Advertise(io) => (
            Code::ServiceUnavailable,
            format!("instance advertisement failed: {}", io.kind()),
        ),
    };
    error(code, &msg)
}

/// `STATE_UNAVAILABLE`, reason `state_dir_unsafe` (ADR-0010 §1 item 7): the Windows state
/// directory is not protected owner-only. Refused, never repaired.
pub(crate) fn state_dir_unsafe(e: &ConfigError) -> Envelope<ErrorData> {
    // ⟨M04 review-fix round⟩ A pre-M04 directory never reaches this: it is narrowed to
    // owner-only at start (`heimdall_runtime::paths`). What does is a directory that grants
    // someone else, which Heimdall never changes: the message says how to fix it without
    // losing the state.
    heimdall_app::OpError::new(
        Code::StateUnavailable,
        format!(
            "{e}; Heimdall never changes a state directory that grants access to anyone but \
             you, SYSTEM and Administrators: give it a list that names only those, with \
             inheritance from its parent turned off (your state is kept), or move the \
             directory aside to start a new installation, then run the command again"
        ),
    )
    .with_reason(heimdall_contract::envelope::reason::STATE_DIR_UNSAFE)
    .with_effect(EffectStatus::None)
    .into_envelope()
}

fn load_config(paths: &Paths) -> Result<Config, ConfigError> {
    use std::io::Read as _;
    let path = paths.config_dir.join("config.toml");
    // ⟨M05; review M05-W4-R02⟩ A regular file only, opened without waiting (a FIFO refuses).
    let file = match crate::input_file::open_regular(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(e.into()),
    };
    let mut text = String::new();
    file.take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_string(&mut text)?;
    Config::parse(&text)
}

/// Whether another instance holds `<state>/service.lock`, read from the existing file
/// without creating anything (the login entry's yield; module docs). A lock this call can
/// take is released again at once.
fn instance_holds_lock(state_dir: &std::path::Path) -> bool {
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .open(state_dir.join("service.lock"))
    else {
        return false;
    };
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            false
        }
        Err(std::fs::TryLockError::WouldBlock) => true,
        Err(std::fs::TryLockError::Error(_)) => false,
    }
}

/// `service run [--detach] [--login]`.
pub fn run(ctx: &Ctx, detach: bool, login: bool, runner: bool) -> ExitCode {
    // ⟨M04, the Windows readiness failures⟩ The start's own clock, for the runtime log's
    // start-up timings (`serve`, `Service::start_with`).
    let begun = std::time::Instant::now();
    // M04 U1: the login entry yields to a running instance before it touches anything.
    if login
        && let Ok(paths) = ctx.paths()
        && instance_holds_lock(&paths.state_dir)
    {
        return ExitCode::Success;
    }
    // A login entry has no terminal: it logs like the detached on-demand runtime. On
    // Windows the `Run` value starts it in a console window of its own, which it lets go
    // of at once (a no-op elsewhere).
    if login {
        heimdall_runtime::platform::detach_console();
    }
    let detach = detach || login;
    // First, before this process opens anything: the long-lived runtime keeps no
    // descriptor above 2 inherited from whatever started it (a client's or a
    // caller's pipe would otherwise never reach end of file; ADR-0006 §13.8
    // item 7). Unix only; a no-op on Windows. When that cannot be established
    // (no close_range, no descriptor listing, no usable hard limit) the runtime
    // refuses to start: a fixed message on stderr, nothing else opened.
    if heimdall_runtime::platform::close_inherited_descriptors().is_err() {
        output::diagnostic(
            "heimdall: the runtime refuses to start: inherited descriptors above 2 cannot be closed on this host",
        );
        return output::exit_code_for(Code::ServiceUnavailable, false);
    }
    let requested = crate::testcfg::requested();
    if let Some(msg) = crate::testcfg::refusal(crate::testcfg::AVAILABLE, requested)
        .or_else(|| crate::testcfg::home_refusal(requested, ctx.home.is_some()))
    {
        return fail(ctx, error(Code::UsageError, msg));
    }
    let paths = match ctx.paths() {
        Ok(p) => p,
        Err(e) => return fail(ctx, *e),
    };
    if let Err(e) = paths.ensure() {
        if heimdall_runtime::paths::is_state_dir_unsafe(&e) {
            return fail(ctx, state_dir_unsafe(&e));
        }
        return fail(
            ctx,
            error(
                Code::StateUnavailable,
                &format!("cannot prepare the runtime directories: {e}"),
            ),
        );
    }
    let sink = if detach {
        LogSink::File
    } else {
        LogSink::Stderr
    };
    if let Err(e) = telemetry::init(sink, Some(&paths.log_dir)) {
        output::diagnostic(&format!("logging unavailable: {}", e.kind()));
    }
    let config = match load_config(&paths) {
        Ok(c) => c,
        Err(e) => return fail(ctx, error(Code::ConfigConflict, &e.to_string())),
    };
    let rt = match Service::runtime() {
        Ok(rt) => rt,
        Err(e) => {
            return fail(
                ctx,
                error(
                    Code::InternalError,
                    &format!("cannot build the executor: {}", e.kind()),
                ),
            );
        }
    };
    // ⟨M06⟩ `--runner`: the forced command's paths need this executable and an explicit,
    // absolute home (the management line names both).
    let runner_command = if runner {
        match runner_serve_command(ctx) {
            Ok(c) => Some(c),
            Err(env) => return fail(ctx, env),
        }
    } else {
        None
    };
    match rt.block_on(serve(
        ctx,
        paths,
        config,
        detach,
        login,
        runner_command,
        begun,
    )) {
        Ok(()) => ExitCode::Success,
        Err(env) => fail(ctx, *env),
    }
}

/// ⟨M06⟩ The forced command's paths for `service run --runner` (ADR-0012 §3.2
/// "Rendering"): this executable and the explicit home, both absolute and validated.
fn runner_serve_command(
    ctx: &Ctx,
) -> Result<heimdall_runtime::paired::RunnerServeCommand, Envelope<ErrorData>> {
    let usage = |m: &str| error(Code::UsageError, m);
    let home = ctx
        .home
        .as_ref()
        .filter(|h| h.is_absolute())
        .ok_or_else(|| usage("service run --runner needs an explicit, absolute --home"))?;
    let exe = std::env::current_exe()
        .map_err(|_| usage("cannot locate this executable for the runner's forced command"))?;
    let (Some(exe), Some(home)) = (exe.to_str(), home.to_str()) else {
        return Err(usage("the runner's forced command needs UTF-8 paths"));
    };
    heimdall_runtime::paired::RunnerServeCommand::new(exe, home).map_err(|_| {
        usage("the runner's forced command paths are not from the permitted character set")
    })
}

#[allow(clippy::too_many_arguments)]
async fn serve(
    ctx: &Ctx,
    paths: Paths,
    config: Config,
    detach: bool,
    login: bool,
    runner_command: Option<heimdall_runtime::paired::RunnerServeCommand>,
    begun: std::time::Instant,
) -> Result<(), Box<Envelope<ErrorData>>> {
    #[allow(unused_mut)]
    let mut options = ServiceOptions::production().map_err(|e| {
        Box::new(error(
            Code::TimeUncertain,
            &format!("platform clock sources unavailable: {}", e.kind()),
        ))
    })?;
    // ⟨M06⟩ A runner's paired-session ports (used only when the home is runner-initialized;
    // no file-backed management-line writer exists in this build, so `lines` stays `None`).
    if let Some(command) = runner_command {
        options.runner.command = Some(command);
    }
    // ⟨rev6.3; ADR-0006 §18.7 item 10⟩ `transport.rotate` tells this device's recorded
    // runners the new endpoint over their management sessions (the CLI's own wiring).
    if let Some(t) = options.transport.as_mut() {
        t.announcer = Some(std::sync::Arc::new(
            crate::m06_cmd::ManagementAnnouncer::new(ctx, &paths),
        ));
    }
    // ⟨M06 W3 host⟩ The controller's hosted driver opens its management sessions through
    // the CLI's own wiring (K_mgmt, the recorded pins, never a prompt). A runner hosts none.
    options.controller = Some(heimdall_runtime::controller_host::ControllerHostWiring {
        sessions: std::sync::Arc::new(crate::m06_cmd::DriverSessions::new(ctx, &paths)),
        interval: heimdall_runtime::controller_host::DEFAULT_INTERVAL,
    });
    #[cfg(debug_assertions)]
    let setup = crate::testcfg::prepare(&mut options, &paths, ctx.home.is_some(), &|n| {
        std::env::var_os(n)
    })
    .map_err(|m| Box::new(error(Code::UsageError, &m)))?;
    // ⟨M02⟩ W4 integration: a test runtime never wires the account's SSH files.
    #[cfg(debug_assertions)]
    crate::testcfg::isolate_projection(&mut options, &paths, &|n| std::env::var_os(n))
        .map_err(|m| Box::new(error(Code::UsageError, &m)))?;
    #[cfg(not(debug_assertions))]
    let _ = ctx;

    // ⟨M04 U1⟩ The login entry's port (setup item, `inspect capabilities`): the host's
    // own, or a scratch root under test; none under a relocated home.
    options.login_entry = login_port(ctx, &paths).ok().flatten().map(|p| {
        let p: std::sync::Arc<dyn LoginEntryPort> = std::sync::Arc::new(p);
        p
    });
    // ⟨M04 U3b⟩ The Linux helper's Windows path, when the debug-only test configuration
    // names one (`HEIMDALL_WSL_HELPER`); a release build refuses the variable earlier.
    #[cfg(debug_assertions)]
    {
        options.wsl_helper =
            std::env::var_os(crate::testcfg::WSL_HELPER_ENV).map(std::path::PathBuf::from);
        // ⟨M04 W2⟩ The directly started stand-in distribution (`HEIMDALL_TEST_WSL_DIRECT`):
        // its host, and the Mode B helper sessions through the same launcher.
        if let Some(host) = crate::testcfg::wsl_direct_host(&|n| std::env::var_os(n))
            .map_err(|m| Box::new(error(Code::UsageError, &m)))?
        {
            options.wsl_bridge = Some(std::sync::Arc::new(
                heimdall_runtime::wsl_bridge::LauncherBridgeFactory::new(host.launcher()),
            ));
            options.wsl_host = Some(std::sync::Arc::new(host));
        }
    }
    let token = CancellationToken::new();
    // ⟨M04, the Windows readiness failures⟩ What ran before the runtime's own start (the
    // test configuration's client probes included), in milliseconds.
    tracing::info!(
        prestart_ms = u64::try_from(begun.elapsed().as_millis()).unwrap_or(u64::MAX),
        "the runtime starts"
    );
    let service = match Service::start_with(paths, config, options, token.clone()).await {
        Ok(service) => service,
        // The login entry yields when another instance won the lock in between.
        Err(ServiceError::Instance(heimdall_runtime::instance::InstanceError::AlreadyRunning))
            if login =>
        {
            return Ok(());
        }
        Err(e) => return Err(Box::new(service_error(&e))),
    };
    #[cfg(debug_assertions)]
    if let Some(setup) = setup {
        setup
            .seed(&service)
            .map_err(|m| Box::new(error(Code::StateUnavailable, &m)))?;
    }
    tokio::spawn(stop_on_signal(token, detach));
    service.run().await.map_err(|e| Box::new(service_error(&e)))
}

#[cfg(unix)]
async fn stop_on_signal(token: CancellationToken, detach: bool) {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        tracing::warn!("signal handlers unavailable; stop the runtime with its process");
        return;
    };
    let mut hup = if detach {
        signal(SignalKind::hangup()).ok()
    } else {
        None
    };
    loop {
        tokio::select! {
            _ = term.recv() => break,
            _ = int.recv() => break,
            Some(()) = async {
                match hup.as_mut() {
                    Some(h) => h.recv().await,
                    None => std::future::pending().await,
                }
            } => {}
        }
    }
    tracing::info!("stop requested by signal");
    token.cancel();
}

#[cfg(not(unix))]
async fn stop_on_signal(token: CancellationToken, _detach: bool) {
    if tokio::signal::ctrl_c().await.is_ok() {
        token.cancel();
    }
}

/// `service status`: never starts a runtime (ADR-0013 §8 "Discovery", D12; ADR-0014 H14).
///
/// Three states, from [`InstanceInfo::read_advertised`]: nothing advertised is
/// `SERVICE_UNAVAILABLE` / `runtime_not_running`; advertised with an endpoint that does
/// not answer is `runtime_unreachable`; otherwise it connects, verifies (the advertised
/// environment ID present, the endpoint's platform checks and a known server PID, Windows'
/// exact control pipe name and server-process SID) and completes the hello, which must name
/// the advertised environment. Every reported field comes from that verified connection or
/// is checked against it: `control_endpoint` is the endpoint connected to; `environment_id`,
/// `protocol`, `capabilities`, `principal` and `version` are the hello's; `pid` is the
/// verified peer's and must equal the advertisement's. Any failed check is
/// `endpoint_untrusted`. `time_sync_observation` is this host's diagnostic, not the
/// runtime's.
pub fn status(ctx: &Ctx) -> ExitCode {
    let paths = match ctx.paths() {
        Ok(p) => p,
        Err(e) => return fail(ctx, *e),
    };
    let info = match InstanceInfo::read_advertised(&paths.runtime_dir) {
        Ok(Advertised::Live(info)) => info,
        Ok(advertised) => return fail(ctx, *crate::client::not_live(&advertised)),
        Err(e) => return fail(ctx, *crate::client::advertisement_untrusted(&e)),
    };
    let rt = match current_thread() {
        Ok(rt) => rt,
        Err(env) => return fail(ctx, env),
    };
    let verified = rt.block_on(async {
        let client = crate::client::connect_advertised(
            ctx,
            &paths,
            &info,
            &[],
            ctx.interaction(),
            crate::client::Expect::Required,
        )
        .await?;
        verified_status(&client, &info)
    });
    match verified {
        Ok(data) => finish(ctx, Envelope::ok(data)),
        Err(env) => fail(ctx, *env),
    }
}

/// ⟨M07 S2-07; D12⟩ `service status`'s data from a verified session: the verified peer's PID
/// must equal the advertisement's (`endpoint_untrusted` otherwise); every other runtime
/// field is the session's.
fn verified_status(
    client: &crate::client::Client,
    info: &InstanceInfo,
) -> Result<serde_json::Value, Box<Envelope<ErrorData>>> {
    if client.server_pid() != info.pid {
        return Err(crate::client::untrusted(
            "the process serving the runtime's endpoint is not the advertised runtime process",
        ));
    }
    let h = client.server();
    Ok(serde_json::json!({
        "running": true,
        "pid": client.server_pid(),
        "version": h.server.version,
        "environment_id": h.environment_id,
        "capabilities": h.capabilities,
        "principal": h.principal,
        "protocol": h.protocol,
        "control_endpoint": client.control_endpoint(),
        "time_sync_observation": time_sync_observation(),
    }))
}

/// A current-thread executor for client commands.
pub fn current_thread() -> Result<tokio::runtime::Runtime, Envelope<ErrorData>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            error(
                Code::InternalError,
                &format!("cannot build the executor: {}", e.kind()),
            )
        })
}

/// `service stop`.
pub fn stop(ctx: &Ctx) -> ExitCode {
    let paths = match ctx.paths() {
        Ok(p) => p,
        Err(e) => return fail(ctx, *e),
    };
    let info = match InstanceInfo::read_valid(&paths.runtime_dir) {
        Ok(None) => {
            return finish(
                ctx,
                Envelope::ok(serde_json::json!({ "running": false, "stopped": false })),
            );
        }
        Err(e) => {
            return fail(
                ctx,
                error(
                    Code::ServiceUnavailable,
                    &format!("the runtime advertisement is not trusted: {}", e.kind()),
                ),
            );
        }
        Ok(Some(info)) => info,
    };
    let rt = match current_thread() {
        Ok(rt) => rt,
        Err(env) => return fail(ctx, env),
    };
    let stopped = |via: &str| {
        Envelope::ok(serde_json::json!({
            "running": false,
            "stopped": true,
            "pid": info.pid,
            "via": via,
        }))
    };
    match rt.block_on(request_shutdown(ctx, &paths, &info)) {
        Ok(()) => match wait_for_exit(&info) {
            Ok(()) => finish(ctx, stopped("control")),
            Err(env) => fail(ctx, env),
        },
        Err(StopFailure::Refused(env)) => fail(ctx, env),
        Err(StopFailure::Unreachable(env)) => match fallback(&paths, &info, env) {
            Ok(via) => finish(ctx, stopped(via)),
            Err(env) => fail(ctx, env),
        },
    }
}

/// Why `Request::Shutdown` did not start a drain.
enum StopFailure {
    /// The runtime answered with an error: reported as is, never bypassed.
    Refused(Envelope<ErrorData>),
    /// The control endpoint could not be used (connect, hello, transport).
    Unreachable(Envelope<ErrorData>),
}

/// Send `Request::Shutdown` on a session that requires `service-control/1`, to the runtime
/// `info` advertises. ⟨M07 S2-07⟩ The session is verified as every connect's
/// (`client::connect_advertised`); an advertisement from an earlier build, without the
/// environment ID, is still stopped, on a connection whose verified server PID is the
/// advertised one (`client::Expect::StopLegacy`): `heimdall service stop` is the restart
/// guidance for such a runtime.
async fn request_shutdown(
    ctx: &Ctx,
    paths: &Paths,
    info: &InstanceInfo,
) -> Result<(), StopFailure> {
    use heimdall_contract::ipc::capability::SERVICE_CONTROL_V1;
    use heimdall_contract::request::{Request, ShutdownRequest};
    let mut client = crate::client::connect_advertised(
        ctx,
        paths,
        info,
        &[SERVICE_CONTROL_V1],
        ctx.interaction(),
        crate::client::Expect::StopLegacy,
    )
    .await
    .map_err(|e| StopFailure::Unreachable(*e))?;
    let env = client.request(Request::Shutdown(ShutdownRequest {})).await;
    if env.code == Code::Ok {
        return Ok(());
    }
    let refused =
        env.data.get("error").cloned().and_then(|e| {
            serde_json::from_value::<heimdall_contract::envelope::ErrorDetail>(e).ok()
        });
    let rendered = heimdall_app::OpError::new(
        env.code.clone(),
        refused.as_ref().map_or_else(
            || "the runtime refused to stop".to_owned(),
            |d| d.message.clone(),
        ),
    )
    .with_effect(
        refused
            .as_ref()
            .map_or(EffectStatus::None, |d| d.effect_status),
    )
    .into_envelope();
    if env.code == Code::ServiceUnavailable {
        // Transport loss after sending: the runtime may or may not be stopping.
        Err(StopFailure::Unreachable(rendered))
    } else {
        Err(StopFailure::Refused(rendered))
    }
}

/// Wait, bounded, until the exact advertised process (pid + start time) is gone.
fn wait_for_exit(info: &InstanceInfo) -> Result<(), Envelope<ErrorData>> {
    let deadline = std::time::Instant::now() + STOP_WAIT;
    loop {
        let alive = heimdall_runtime::platform::process_start_time(info.pid)
            .is_some_and(|s| s == info.started_at);
        if !alive {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(heimdall_app::OpError::new(
                Code::ServiceUnavailable,
                "the runtime did not stop in time",
            )
            .with_effect(EffectStatus::Unknown)
            .into_envelope());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Unix: the signal fallback to the validated advertised PID (`via: "signal"`).
/// Elsewhere there is no fallback: a runtime that was asked over its endpoint
/// may still be stopping, so wait for it (bounded; `via: "exited"`); otherwise
/// report why the endpoint could not be used.
#[cfg(unix)]
fn fallback(
    paths: &Paths,
    info: &InstanceInfo,
    _why: Envelope<ErrorData>,
) -> Result<&'static str, Envelope<ErrorData>> {
    tracing::debug!("control endpoint unavailable for stop; falling back to a signal");
    terminate(paths, info).map(|()| "signal")
}

#[cfg(not(unix))]
fn fallback(
    _paths: &Paths,
    info: &InstanceInfo,
    why: Envelope<ErrorData>,
) -> Result<&'static str, Envelope<ErrorData>> {
    wait_for_exit(info).map(|()| "exited").map_err(|_| why)
}

#[cfg(unix)]
fn terminate(paths: &Paths, info: &InstanceInfo) -> Result<(), Envelope<ErrorData>> {
    // Re-validate right before signalling: same pid, same OS start time.
    match InstanceInfo::read_valid(&paths.runtime_dir) {
        Ok(Some(now)) if now.pid == info.pid && now.started_at == info.started_at => {}
        _ => return Ok(()),
    }
    let kill = ["/bin/kill", "/usr/bin/kill"]
        .into_iter()
        .map(std::path::Path::new)
        .find(|p| p.is_file())
        .ok_or_else(|| {
            error(
                Code::ServiceUnavailable,
                "no kill utility found at /bin/kill or /usr/bin/kill",
            )
        })?;
    let status = std::process::Command::new(kill)
        .args(["-s", "TERM", &info.pid.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| {
            error(
                Code::ServiceUnavailable,
                &format!("cannot signal the runtime: {}", e.kind()),
            )
        })?;
    if !status.success() {
        // It may have exited in between; the wait below decides.
        tracing::debug!("kill utility reported failure");
    }
    wait_for_exit(info)
}

// --- ⟨M04 U1⟩ time observation ----------------------------------------------------------------

/// The host's read-only synchronization observation (ADR-0010 §9 item 6): a diagnostic
/// field only. The time gate does not read it: every platform keeps `unknown` and the
/// attended time confirmation until native negative evidence exists.
fn time_sync_observation() -> serde_json::Value {
    use heimdall_runtime::platform::{SyncObservation, observe_time_sync};
    let obs = observe_time_sync();
    let mut v = serde_json::json!({
        "interface": obs.interface,
        "reading": obs.reading.word(),
        "used_by_time_gate": false,
    });
    if let serde_json::Value::Object(map) = &mut v {
        match &obs.reading {
            SyncObservation::Synchronized {
                max_error_us,
                sta_unsync,
            }
            | SyncObservation::NotSynchronized {
                max_error_us,
                sta_unsync,
            } => {
                map.insert("max_error_us".to_owned(), (*max_error_us).into());
                map.insert("sta_unsync".to_owned(), (*sta_unsync).into());
            }
            SyncObservation::Unavailable { why } => {
                map.insert("why".to_owned(), why.clone().into());
            }
            SyncObservation::NoInterface => {}
        }
    }
    v
}

// --- ⟨M04 U1⟩ service autostart -----------------------------------------------------------------

/// Debug-only test root of the login entry: a scratch directory (a registry subkey under
/// `Software\HeimdallTest\` on Windows). A release build refuses the variable.
pub const LOGIN_ROOT_ENV: &str = "HEIMDALL_TEST_LOGIN_ROOT";

/// The scratch root named by [`LOGIN_ROOT_ENV`], if any.
///
/// # Errors
/// A release build with the variable set, or a value that is not an absolute directory
/// (a `Software\HeimdallTest\…` subkey on Windows).
fn login_root() -> Result<Option<std::path::PathBuf>, String> {
    let Some(value) = std::env::var_os(LOGIN_ROOT_ENV) else {
        return Ok(None);
    };
    if !cfg!(debug_assertions) {
        return Err(format!(
            "{LOGIN_ROOT_ENV} is a test configuration that a release build refuses"
        ));
    }
    let root = std::path::PathBuf::from(value);
    let ok = if cfg!(windows) {
        root.to_string_lossy()
            .to_ascii_lowercase()
            .starts_with(&"Software\\HeimdallTest\\".to_ascii_lowercase())
    } else {
        root.is_absolute()
    };
    if ok {
        Ok(Some(root))
    } else {
        Err(format!(
            "{LOGIN_ROOT_ENV} must be an absolute directory (on Windows a Software\\HeimdallTest\\ subkey)"
        ))
    }
}

/// The login entry's port for this installation: the host's, or the scratch root's.
/// `Ok(None)` under a relocated home with no scratch root: such a home (fixtures and
/// tests) never reaches the account's login location.
pub(crate) fn login_port(ctx: &Ctx, paths: &Paths) -> Result<Option<HostLoginPort>, String> {
    let root = login_root()?;
    if root.is_none() && ctx.home.is_some() {
        return Ok(None);
    }
    Ok(Some(HostLoginPort::system(
        &paths.state_dir,
        root.as_deref(),
    )))
}

fn state_word(s: LoginEntryState) -> &'static str {
    match s {
        LoginEntryState::Absent => "absent",
        LoginEntryState::Owned => "owned",
        LoginEntryState::Foreign => "conflict",
    }
}

fn kind_word(k: heimdall_contract::environment::LoginStartKind) -> &'static str {
    use heimdall_contract::environment::LoginStartKind as K;
    match k {
        K::RunValue => "run_value",
        K::LaunchAgent => "launch_agent",
        K::SystemdUser => "systemd_user",
        _ => "none",
    }
}

/// A failed login-entry operation as its envelope: a conflict is `CONFIG_CONFLICT` with
/// reason `login_entry_conflict` (exit 6, nothing touched).
fn login_failure(f: &LoginEntryFailure) -> Envelope<ErrorData> {
    use heimdall_contract::envelope::reason;
    match f {
        LoginEntryFailure::Conflict => heimdall_app::OpError::new(
            Code::ConfigConflict,
            "another entry is at Heimdall's login entry name; it was left untouched",
        )
        .with_reason(reason::LOGIN_ENTRY_CONFLICT)
        .with_effect(EffectStatus::None)
        .into_envelope(),
        LoginEntryFailure::NoUserManager => error(
            Code::CapabilityUnavailable,
            "this host has no user session manager: there is no login entry, and the runtime starts on demand",
        ),
        LoginEntryFailure::Failed(msg) => {
            heimdall_app::OpError::new(Code::StateUnavailable, msg.clone())
                .with_effect(EffectStatus::Unknown)
                .into_envelope()
        }
    }
}

/// `service autostart enable|disable|status` (module docs).
pub fn autostart(ctx: &Ctx, command: AutostartCommand) -> ExitCode {
    let paths = match ctx.paths() {
        Ok(p) => p,
        Err(e) => return fail(ctx, *e),
    };
    let port = match login_port(ctx, &paths) {
        Ok(p) => p,
        Err(m) => return fail(ctx, error(Code::UsageError, &m)),
    };
    match command {
        AutostartCommand::Status => {
            let Some(port) = port else {
                // A relocated home has no login entry of its own to report.
                return finish(
                    ctx,
                    Envelope::ok(serde_json::json!({
                        "kind": "none", "installed": false, "state": "absent", "on_demand": true,
                    })),
                );
            };
            match port.observe() {
                Ok(state) => finish(
                    ctx,
                    Envelope::ok(serde_json::json!({
                        "kind": kind_word(port.kind()),
                        "installed": state == LoginEntryState::Owned,
                        "state": state_word(state),
                        "location": port.location(),
                        "on_demand": port.kind() == heimdall_contract::environment::LoginStartKind::None,
                    })),
                ),
                Err(f) => fail(ctx, login_failure(&f)),
            }
        }
        AutostartCommand::Disable => {
            let Some(port) = port else {
                return finish(
                    ctx,
                    Envelope::ok(serde_json::json!({"removed": false, "kind": "none"})),
                );
            };
            match port.remove() {
                Ok(effect) => finish(
                    ctx,
                    Envelope::ok(serde_json::json!({
                        "removed": effect == heimdall_app::ports::LoginEntryEffect::Removed,
                        "kind": kind_word(port.kind()),
                        "location": port.location(),
                    })),
                ),
                // A host with no user manager has no entry to remove.
                Err(LoginEntryFailure::NoUserManager) => finish(
                    ctx,
                    Envelope::ok(serde_json::json!({"removed": false, "kind": "none"})),
                ),
                Err(f) => fail(ctx, login_failure(&f)),
            }
        }
        AutostartCommand::Enable => {
            if port.is_none() {
                return fail(
                    ctx,
                    error(
                        Code::UsageError,
                        "a relocated Heimdall home never writes the account's login entry",
                    ),
                );
            }
            crate::setup_cmd::block(ctx, enable_via_runtime(ctx))
        }
    }
}

async fn enable_via_runtime(ctx: &Ctx) -> crate::setup_cmd::Outcome {
    use heimdall_contract::ipc::capability::{ENVIRONMENTS_V1, SETUP_V1};
    let rid = match crate::setup_cmd::request_id(None) {
        Ok(r) => r,
        Err(o) => return o,
    };
    let mut client =
        match crate::client::connect_requiring(ctx, true, &[SETUP_V1, ENVIRONMENTS_V1]).await {
            Ok(c) => c,
            Err(e) => return crate::setup_cmd::Outcome::of(output::error_value(*e)),
        };
    enable_flow(&mut client, &mut TerminalPrompt, ctx, rid).await
}

/// The attended setup step (module docs): preview the entry through the runtime, show its
/// exact data, require a typed `yes`, then apply the plan's digest. Generic over the
/// session and the prompt so the unit test drives it with scripted ones.
pub(crate) async fn enable_flow<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    rid: heimdall_contract::ids::RequestId,
) -> crate::setup_cmd::Outcome {
    use crate::setup_cmd::{Outcome, attend_first, failure, non_interactive_reason, not_confirmed};
    use heimdall_contract::request::Request;
    use heimdall_contract::setup::{PlanDigest, PreviewIntent, ProjectionItem, SetupRequest};
    let intent = PreviewIntent::Apply {
        include_git: false,
        items: [ProjectionItem::LoginEntry].into_iter().collect(),
        distribution: None,
    };
    let preview = s
        .request(Request::Setup(SetupRequest::Preview {
            intent: intent.clone(),
        }))
        .await;
    if !preview.code.is_success() {
        return crate::setup_cmd::result_outcome(preview);
    }
    let Some(digest) = preview
        .data
        .get("plan_digest")
        .and_then(|d| d.as_str())
        .and_then(|d| PlanDigest::parse(d).ok())
    else {
        return Outcome::of(failure(
            Code::InternalError,
            "the runtime's plan carries no valid digest",
            None,
        ));
    };
    let finding = preview
        .data
        .get("findings")
        .and_then(|f| f.as_array())
        .and_then(|f| f.first())
        .cloned()
        .unwrap_or_default();
    let message = finding
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_owned();
    match finding.get("reason").and_then(|r| r.as_str()) {
        Some("login_entry_conflict") => {
            return Outcome::of(failure(
                Code::ConfigConflict,
                &message,
                Some(heimdall_contract::envelope::reason::LOGIN_ENTRY_CONFLICT),
            ))
            .with_human(format!("{message}\n"));
        }
        Some("on_demand") => {
            return Outcome::of(failure(Code::CapabilityUnavailable, &message, None))
                .with_human(format!("{message}\n"));
        }
        _ => {}
    }
    if !ctx.interactive() {
        return Outcome::of(not_confirmed(None, None, non_interactive_reason(ctx)))
            .with_human(format!("{message}\n"));
    }
    if let Err(refused) = attend_first(s, ctx).await {
        return Outcome::of(refused);
    }
    let answer = p
        .ask(&format!(
            "Login entry (written only because you confirm it here):\n  {message}\nWrite exactly this?\n"
        ))
        .await;
    if answer != crate::prompt::Answer::Yes {
        return Outcome::of(not_confirmed(None, None, answer.reason()));
    }
    let env = s
        .request(Request::Setup(SetupRequest::Apply {
            plan_digest: digest,
            request_id: rid,
        }))
        .await;
    let human = env
        .data
        .get("login_entry")
        .map(|l| {
            format!(
                "Login entry {}: {} at {}\n",
                l.get("effect").and_then(|v| v.as_str()).unwrap_or("done"),
                l.get("kind").and_then(|v| v.as_str()).unwrap_or(""),
                l.get("location").and_then(|v| v.as_str()).unwrap_or(""),
            )
        })
        .unwrap_or_default();
    let mut out = crate::setup_cmd::result_outcome(env);
    if out.env.code.is_success() {
        out.human = human;
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::prompt::Answer;

    /// Records the kind of every request and answers from a script.
    struct Session1 {
        sent: Vec<String>,
        preview: Envelope<serde_json::Value>,
        applied: Option<serde_json::Value>,
    }

    impl Session for Session1 {
        async fn request(
            &mut self,
            request: heimdall_contract::request::Request,
        ) -> Envelope<serde_json::Value> {
            use heimdall_contract::request::Request;
            use heimdall_contract::setup::SetupRequest;
            match request {
                Request::Setup(SetupRequest::Preview { .. }) => {
                    self.sent.push("preview".to_owned());
                    self.preview.clone()
                }
                Request::Setup(SetupRequest::Apply { plan_digest, .. }) => {
                    self.sent.push(format!("apply {plan_digest}"));
                    Envelope::ok(self.applied.clone().unwrap_or_default())
                }
                other => {
                    self.sent.push(other.kind().to_owned());
                    Envelope::ok(serde_json::json!({}))
                }
            }
        }
        async fn attend(&mut self) -> Envelope<serde_json::Value> {
            self.sent.push("attend".to_owned());
            Envelope::ok(serde_json::json!({"attended": true}))
        }
    }

    struct Answers {
        next: Answer,
        shown: Vec<String>,
    }

    impl Prompter for Answers {
        async fn ask(&mut self, text: &str) -> Answer {
            self.shown.push(text.to_owned());
            self.next
        }
    }

    fn plan(reason: Option<&str>, message: &str) -> Envelope<serde_json::Value> {
        let mut finding = serde_json::json!({
            "code": "login_entry", "severity": "info", "message": message,
        });
        if let Some(r) = reason {
            finding["reason"] = r.into();
        }
        Envelope::ok(serde_json::json!({
            "plan_digest": "ab".repeat(32),
            "intent": {"kind": "apply", "items": ["login_entry"]},
            "mode": "automatic",
            "consent": {"decision_required": false},
            "findings": [finding],
        }))
    }

    fn ctx(tty: bool, non_interactive: bool) -> Ctx {
        Ctx {
            json: true,
            non_interactive,
            home: None,
            stdin_tty: tty,
            request_epoch: None,
        }
    }

    /// ADR-0010 §6 item 1 ("Setup offers it... never silently"): `service autostart
    /// enable` previews the entry, shows its exact data, attends the session and applies
    /// the preview's digest only after a typed `yes` on a terminal. Any other answer, no
    /// terminal, a conflict and a host without a user manager each end before anything is
    /// applied.
    #[test]
    fn autostart_enable_is_previewed_attended_and_applied_only_after_a_typed_yes() {
        let digest = "ab".repeat(32);
        let applied = serde_json::json!({"login_entry": {
            "kind": "systemd_user", "location": "/u/heimdall.service", "effect": "created",
        }});
        // (preview, tty, non_interactive, answer, requests sent, exit code, prompts)
        type Row = (
            Envelope<serde_json::Value>,
            bool,
            bool,
            Answer,
            Vec<String>,
            Code,
            usize,
        );
        let rows: Vec<Row> = vec![
            (
                plan(None, "ExecStart=\"/x/heimdall\" service run --login"),
                true,
                false,
                Answer::Yes,
                vec!["preview".into(), "attend".into(), format!("apply {digest}")],
                Code::Ok,
                1,
            ),
            (
                plan(None, "data"),
                true,
                false,
                Answer::No,
                vec!["preview".into(), "attend".into()],
                Code::InteractionRequired,
                1,
            ),
            (
                plan(None, "data"),
                true,
                false,
                Answer::Eof,
                vec!["preview".into(), "attend".into()],
                Code::InteractionRequired,
                1,
            ),
            (
                plan(None, "data"),
                false,
                false,
                Answer::Yes,
                vec!["preview".into()],
                Code::InteractionRequired,
                0,
            ),
            (
                plan(None, "data"),
                true,
                true,
                Answer::Yes,
                vec!["preview".into()],
                Code::InteractionRequired,
                0,
            ),
            (
                plan(Some("login_entry_conflict"), "another entry is at the name"),
                true,
                false,
                Answer::Yes,
                vec!["preview".into()],
                Code::ConfigConflict,
                0,
            ),
            (
                plan(Some("on_demand"), "no user session manager"),
                true,
                false,
                Answer::Yes,
                vec!["preview".into()],
                Code::CapabilityUnavailable,
                0,
            ),
        ];
        for (i, (preview, tty, non_interactive, answer, sent, code, prompts)) in
            rows.into_iter().enumerate()
        {
            let mut s = Session1 {
                sent: Vec::new(),
                preview,
                applied: Some(applied.clone()),
            };
            let mut p = Answers {
                next: answer,
                shown: Vec::new(),
            };
            let out = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(enable_flow(
                    &mut s,
                    &mut p,
                    &ctx(tty, non_interactive),
                    heimdall_contract::ids::RequestId::parse("r-1").unwrap(),
                ));
            assert_eq!(s.sent, sent, "row {i}");
            assert_eq!(out.env.code, code, "row {i}: {:?}", out.env.data);
            assert_eq!(p.shown.len(), prompts, "row {i}");
            if i == 0 {
                assert!(
                    p.shown[0].contains("ExecStart=\"/x/heimdall\" service run --login"),
                    "the prompt shows the exact data: {:?}",
                    p.shown
                );
                assert!(out.human.contains("created"), "{}", out.human);
            }
        }
    }
}
