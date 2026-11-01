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
//! * `status` validates the advertisement (pid + OS start time + owner-only
//!   endpoints) and performs a hello; it never starts a runtime.
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

use heimdall_contract::envelope::EffectStatus;
use heimdall_contract::envelope::{Envelope, ErrorData};
use heimdall_contract::{Code, ExitCode};
use heimdall_runtime::config::{Config, MAX_CONFIG_BYTES};
use heimdall_runtime::instance::InstanceInfo;
use heimdall_runtime::service::{Service, ServiceError, ServiceOptions};
use heimdall_runtime::telemetry::{self, LogSink};
use heimdall_runtime::{Paths, config::ConfigError};
use tokio_util::sync::CancellationToken;

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

fn load_config(paths: &Paths) -> Result<Config, ConfigError> {
    use std::io::Read as _;
    let path = paths.config_dir.join("config.toml");
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(e.into()),
    };
    let mut text = String::new();
    file.take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_string(&mut text)?;
    Config::parse(&text)
}

/// `service run [--detach]`.
pub fn run(ctx: &Ctx, detach: bool) -> ExitCode {
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
    match rt.block_on(serve(ctx, paths, config, detach)) {
        Ok(()) => ExitCode::Success,
        Err(env) => fail(ctx, *env),
    }
}

async fn serve(
    ctx: &Ctx,
    paths: Paths,
    config: Config,
    detach: bool,
) -> Result<(), Box<Envelope<ErrorData>>> {
    #[allow(unused_mut)]
    let mut options = ServiceOptions::production().map_err(|e| {
        Box::new(error(
            Code::TimeUncertain,
            &format!("platform clock sources unavailable: {}", e.kind()),
        ))
    })?;
    #[cfg(debug_assertions)]
    let setup = crate::testcfg::prepare(&mut options, &paths, ctx.home.is_some(), &|n| {
        std::env::var_os(n)
    })
    .map_err(|m| Box::new(error(Code::UsageError, &m)))?;
    #[cfg(not(debug_assertions))]
    let _ = ctx;

    let token = CancellationToken::new();
    let service = Service::start_with(paths, config, options, token.clone())
        .await
        .map_err(|e| Box::new(service_error(&e)))?;
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

/// `service status`: never starts a runtime.
pub fn status(ctx: &Ctx) -> ExitCode {
    let paths = match ctx.paths() {
        Ok(p) => p,
        Err(e) => return fail(ctx, *e),
    };
    let info = match InstanceInfo::read_valid(&paths.runtime_dir) {
        Ok(Some(info)) => info,
        Ok(None) => {
            return fail(
                ctx,
                error(Code::ServiceUnavailable, "no runtime is running"),
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
    };
    let rt = match current_thread() {
        Ok(rt) => rt,
        Err(env) => return fail(ctx, env),
    };
    let hello = rt.block_on(async {
        crate::client::connect(ctx, false)
            .await
            .map(|c| c.server().clone())
    });
    match hello {
        Ok(h) => finish(
            ctx,
            Envelope::ok(serde_json::json!({
                "running": true,
                "pid": info.pid,
                "version": info.version,
                "environment_id": h.environment_id,
                "capabilities": h.capabilities,
                "principal": h.principal,
            })),
        ),
        Err(env) => fail(ctx, *env),
    }
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
    match rt.block_on(request_shutdown(ctx)) {
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

/// Send `Request::Shutdown` on a session that requires `service-control/1`.
async fn request_shutdown(ctx: &Ctx) -> Result<(), StopFailure> {
    use heimdall_contract::ipc::capability::SERVICE_CONTROL_V1;
    use heimdall_contract::request::{Request, ShutdownRequest};
    let mut client = crate::client::connect_requiring(ctx, false, &[SERVICE_CONTROL_V1])
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
