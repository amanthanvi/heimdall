//! Control-endpoint client for the CLI (overview §3 "client mode"; ADR-0006 §2).
//!
//! Resolve the per-user paths (honouring `--home` / `HEIMDALL_HOME`), make sure a
//! runtime is serving (effectful commands may start one on demand through
//! `runtime::launcher`; pure inspection never does, spec §13.1), connect to the
//! owner-only control endpoint, and perform the hello. Every failure becomes an
//! error envelope with a stable code; nothing here authorizes anything.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use heimdall_contract::Code;
use heimdall_contract::envelope::{EffectStatus, Envelope, ErrorData};
use heimdall_contract::ipc::{PeerInfo, capability};
use heimdall_contract::request::{InteractionMode, Request};
use heimdall_ipc::session::{ControlClient, transport_failure_envelope};
use heimdall_runtime::Paths;
use heimdall_runtime::launcher::{self, LaunchError, LauncherConfig};
use heimdall_runtime::paths::HOME_ENV;

/// Name the CLI reports in its hello (metadata only, never authority).
pub const CLIENT_NAME: &str = "heimdall-cli";

/// Global invocation context shared by every command.
#[derive(Debug, Clone)]
pub struct Ctx {
    /// `--json`.
    pub json: bool,
    /// `--non-interactive`.
    pub non_interactive: bool,
    /// `--home` / `HEIMDALL_HOME`.
    pub home: Option<PathBuf>,
    /// Whether stdin is a terminal.
    pub stdin_tty: bool,
}

impl Ctx {
    /// The interactive flow is available: stdin is a TTY and
    /// `--non-interactive` is absent (m01-plan U9).
    #[must_use]
    pub fn interactive(&self) -> bool {
        self.stdin_tty && !self.non_interactive
    }

    /// The hello's interaction mode.
    #[must_use]
    pub fn interaction(&self) -> InteractionMode {
        if self.interactive() {
            InteractionMode::Interactive
        } else {
            InteractionMode::NonInteractive
        }
    }

    /// Resolve the directories without creating them.
    pub fn paths(&self) -> Result<Paths, Box<Envelope<ErrorData>>> {
        let home = self.home.clone();
        Paths::resolve(&|name| {
            if name == HOME_ENV {
                home.clone().map(OsString::from)
            } else {
                std::env::var_os(name)
            }
        })
        .map_err(|e| {
            Box::new(error(
                Code::UsageError,
                &format!("cannot resolve the Heimdall directories: {e}"),
            ))
        })
    }
}

/// An error envelope with no effect.
#[must_use]
pub fn error(code: Code, message: &str) -> Envelope<ErrorData> {
    heimdall_app::OpError::new(code, message.to_owned())
        .with_effect(EffectStatus::None)
        .into_envelope()
}

#[cfg(unix)]
type Stream = tokio::net::UnixStream;
#[cfg(windows)]
type Stream = tokio::net::windows::named_pipe::NamedPipeClient;

/// A connected, negotiated control session.
pub struct Client {
    inner: ControlClient<Stream>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl Client {
    /// Send a request; a transport failure after sending is `SERVICE_UNAVAILABLE`
    /// with effect `unknown` (the journal decides; a same-ID retry replays).
    pub async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
        match self.inner.request(request).await {
            Ok(env) => env,
            Err(e) => crate::output::error_value(transport_failure_envelope(&e, true)),
        }
    }

    /// Mark the session attended. Sent only on an interactive TTY session, first,
    /// before an owner-present action whose decision this session then shows
    /// and confirms (ADR-0006 §3.1, §13.6 item 7); attendance authorizes nothing
    /// by itself.
    pub async fn attend(&mut self) -> Envelope<serde_json::Value> {
        match self.inner.attend().await {
            Ok(env) => env,
            Err(e) => crate::output::error_value(transport_failure_envelope(&e, false)),
        }
    }

    /// The negotiated server hello.
    #[must_use]
    pub fn server(&self) -> &heimdall_contract::ipc::ServerHello {
        self.inner.server()
    }

    /// The underlying session (subscriptions).
    pub fn raw(&mut self) -> &mut ControlClient<Stream> {
        &mut self.inner
    }
}

fn launch_error(e: &LaunchError) -> Envelope<ErrorData> {
    let message = match e {
        LaunchError::NotRunning => {
            "no runtime is running; read-only commands do not start one (effectful commands start it on demand)".to_owned()
        }
        LaunchError::Timeout => "the runtime did not become ready in time".to_owned(),
        LaunchError::Insecure(_) => {
            "the runtime advertisement is not a private file of this user; nothing was started"
                .to_owned()
        }
        LaunchError::Spawn(io) | LaunchError::Io(io) => {
            format!("the runtime could not be started: {}", io.kind())
        }
        LaunchError::Config(c) => format!("the runtime could not be started: {c}"),
    };
    heimdall_app::OpError::new(Code::ServiceUnavailable, message)
        .with_effect(EffectStatus::None)
        .with_resource("endpoint", None)
        .into_envelope()
}

/// Connect to the runtime, starting it first when `allow_start` (effectful
/// commands only) and none is serving.
pub async fn connect(ctx: &Ctx, allow_start: bool) -> Result<Client, Box<Envelope<ErrorData>>> {
    connect_requiring(ctx, allow_start, &[]).await
}

/// [`connect`], also requiring `extra` capabilities in the hello (a runtime that
/// lacks one rejects the hello with `SCHEMA_UNSUPPORTED`; `service stop` requires
/// `service-control/1`).
pub async fn connect_requiring(
    ctx: &Ctx,
    allow_start: bool,
    extra: &[&str],
) -> Result<Client, Box<Envelope<ErrorData>>> {
    let paths = ctx.paths()?;
    if allow_start {
        paths.ensure().map_err(|e| {
            Box::new(error(
                Code::ServiceUnavailable,
                &format!("cannot prepare the runtime directories: {e}"),
            ))
        })?;
    }
    let exe = std::env::current_exe().map_err(|e| {
        Box::new(error(
            Code::ServiceUnavailable,
            &format!("cannot locate this executable: {}", e.kind()),
        ))
    })?;
    let home = ctx.home.clone();
    // Same executable path (never a PATH lookup), no shell; an explicit `--home`
    // is passed on so the runtime uses the same directories.
    let spawn = move || {
        let mut args: Vec<&OsStr> = Vec::new();
        if let Some(h) = &home {
            args.push(OsStr::new("--home"));
            args.push(h.as_os_str());
        }
        args.extend(launcher::SERVICE_ARGS.iter().map(OsStr::new));
        launcher::spawn_detached(&exe, &args).map(drop)
    };
    launcher::ensure_running_with(
        &paths.runtime_dir,
        allow_start,
        LauncherConfig::default(),
        &spawn,
    )
    .await
    .map_err(|e| Box::new(launch_error(&e)))?;

    let stream = open_stream(&paths).await?;
    let required: BTreeSet<String> = std::iter::once(capability::OPERATIONS_V1)
        .chain(extra.iter().copied())
        .map(str::to_owned)
        .collect();
    let inner = ControlClient::handshake(
        stream,
        PeerInfo {
            name: CLIENT_NAME.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        required,
        ctx.interaction(),
    )
    .await
    .map_err(|e| Box::new(transport_failure_envelope(&e, false)))?;
    Ok(Client { inner })
}

#[cfg(unix)]
async fn open_stream(paths: &Paths) -> Result<Stream, Box<Envelope<ErrorData>>> {
    let endpoints = heimdall_ipc::EndpointPaths::for_runtime(&paths.runtime_dir, "");
    heimdall_ipc::unix::connect(&endpoints.control)
        .await
        .map_err(|e| {
            Box::new(
                heimdall_app::OpError::new(
                    Code::ServiceUnavailable,
                    format!("cannot connect to the runtime: {e}"),
                )
                .with_effect(EffectStatus::None)
                .with_resource("endpoint", None)
                .into_envelope(),
            )
        })
}

#[cfg(windows)]
async fn open_stream(paths: &Paths) -> Result<Stream, Box<Envelope<ErrorData>>> {
    let unavailable = |msg: String| {
        Box::new(
            heimdall_app::OpError::new(Code::ServiceUnavailable, msg)
                .with_effect(EffectStatus::None)
                .with_resource("endpoint", None)
                .into_envelope(),
        )
    };
    let info = heimdall_runtime::instance::InstanceInfo::read_valid(&paths.runtime_dir)
        .map_err(|e| {
            unavailable(format!(
                "cannot read the runtime advertisement: {}",
                e.kind()
            ))
        })?
        .ok_or_else(|| unavailable("no runtime is running".to_owned()))?;
    heimdall_ipc::windows::connect_with_owner(
        std::path::Path::new(&info.control_endpoint),
        heimdall_ipc::windows::ServerOwner::CurrentUser,
    )
    .await
    .map_err(|e| unavailable(format!("cannot connect to the runtime: {}", e.kind())))
}
