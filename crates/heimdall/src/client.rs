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
use heimdall_contract::page::{PageRequest, PageToken, Select};
use heimdall_contract::request::{InspectRequest, InspectSubject, InteractionMode, Request};
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
    /// ⟨M08 U2b-2; ADR-0014 §3.6 step 3⟩ `--request-epoch`: the restore epoch a retried
    /// request ID was first bound to. Every mutating request of this invocation carries it,
    /// and a runtime that does not offer `request-epoch/1` gets nothing (`SCHEMA_UNSUPPORTED`).
    /// `None`: each mutating request carries the epoch of this session's hello, bound at send.
    pub request_epoch: Option<heimdall_contract::lifecycle::RestoreEpoch>,
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

    /// Resolve the directories without creating them. A debug build first refuses the
    /// account's real home when no explicit home was given (`dev_home_guard`; release
    /// builds have no guard): `USAGE_ERROR`, before anything is created, read or started.
    pub fn paths(&self) -> Result<Paths, Box<Envelope<ErrorData>>> {
        if let Some(message) = crate::dev_home_guard::refusal(self.home.is_some()) {
            return Err(Box::new(error(Code::UsageError, &message)));
        }
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
    /// ⟨M08 U2b-2⟩ This invocation's kept epoch ([`Ctx::request_epoch`]).
    kept: Option<heimdall_contract::lifecycle::RestoreEpoch>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl Client {
    /// Send a request; a transport failure after sending is `SERVICE_UNAVAILABLE`
    /// with effect `unknown` (the journal decides; a same-ID retry replays).
    ///
    /// ⟨M08 U2b-2; ADR-0014 §3.6 step 3⟩ A mutating request carries the kept epoch
    /// (`--request-epoch`) or, without one, this session's hello epoch, bound at send; a kept
    /// epoch the runtime cannot check is answered `SCHEMA_UNSUPPORTED` with nothing sent
    /// (`heimdall_ipc::session::ControlClient::request`).
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

    /// ⟨M08 U2b-2⟩ Send `request` carrying `kept`, the epoch a retried request ID was first
    /// bound to, instead of this invocation's (the TUI's resend of a request it keeps). `None`:
    /// [`Self::request`]'s choice for a fresh request.
    pub async fn request_kept(
        &mut self,
        request: Request,
        kept: Option<heimdall_contract::lifecycle::RestoreEpoch>,
    ) -> Envelope<serde_json::Value> {
        let invocation = self.kept;
        self.inner.keep_epoch(kept.or(invocation));
        let env = self.request(request).await;
        self.inner.keep_epoch(invocation);
        env
    }

    /// ⟨M08 U2b-2⟩ The epoch a mutating request sent now carries: the kept one, else the
    /// hello's where the runtime offers `request-epoch/1`; `None` where neither applies.
    #[must_use]
    pub fn bound_epoch(&self) -> Option<heimdall_contract::lifecycle::RestoreEpoch> {
        self.kept.or_else(|| self.inner.fresh_epoch())
    }

    /// The underlying session (subscriptions).
    pub fn raw(&mut self) -> &mut ControlClient<Stream> {
        &mut self.inner
    }

    /// ⟨rev7⟩ Whether this session negotiated `pages/1` (`select` and `page` are sent only
    /// then; [`lookup`] refuses locally otherwise).
    #[must_use]
    pub fn serves_pages(&self) -> bool {
        self.inner
            .server()
            .capabilities
            .contains(capability::PAGES_V1)
    }

    /// ⟨rev7⟩ An enumeration ([`traverse_on`]).
    ///
    /// # Errors
    ///
    /// The first refused page's envelope, as [`traverse_on`].
    // ⟨U3-1b⟩ No CLI enumeration traverses yet: every list output keeps its whole read, whose
    // answer (order, wrapper key, the extra fields some subjects carry) its goldens fix; the
    // traversal is for enumeration only (ADR-0013 §6.3), never for a resolution.
    #[allow(dead_code)]
    pub async fn traverse(
        &mut self,
        subject: InspectSubject,
        limit: Option<u32>,
    ) -> Result<Vec<serde_json::Value>, Box<Envelope<serde_json::Value>>> {
        traverse_on(&mut self.inner, subject, limit).await
    }
}

/// ⟨rev7⟩ `pages/1`'s request for `subject`: no preview, `cwd` or `redact`.
fn pages_request(
    subject: InspectSubject,
    select: Option<Select>,
    page: Option<PageRequest>,
) -> Request {
    Request::Inspect(InspectRequest {
        subject,
        preview: None,
        cwd: None,
        redact: false,
        select,
        page,
    })
}

/// ⟨rev7⟩ `SCHEMA_UNSUPPORTED` without sending anything, for a session that did not
/// negotiate `pages/1` (an older runtime): the forms are never sent where they would be
/// refused, and nothing falls back to a whole read.
fn pages_unsupported<S>(client: &ControlClient<S>) -> Option<Envelope<serde_json::Value>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    (!client.server().capabilities.contains(capability::PAGES_V1)).then(|| {
        crate::output::error_value(error(
            Code::SchemaUnsupported,
            "the runtime does not serve select or page (pages/1)",
        ))
    })
}

/// ⟨rev7⟩ Every control session is a [`crate::cli::Session`]: the CLI's [`Client`] wraps
/// one, and the point lookup ([`lookup`]) runs on either.
impl<S> crate::cli::Session for ControlClient<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
        match ControlClient::request(self, request).await {
            Ok(env) => env,
            Err(e) => crate::output::error_value(transport_failure_envelope(&e, true)),
        }
    }

    async fn attend(&mut self) -> Envelope<serde_json::Value> {
        match ControlClient::attend(self).await {
            Ok(env) => env,
            Err(e) => crate::output::error_value(transport_failure_envelope(&e, false)),
        }
    }

    fn serves_pages(&self) -> bool {
        pages_unsupported(self).is_none()
    }
}

/// ⟨rev7⟩ m07-plan U3 (ADR-0013 §6.1): every item of `subject` this caller may read, page by
/// page (`limit` per page, the runtime's default when `None`), until the first page with
/// `more: false`, which may be empty. On a session without `pages/1`, `SCHEMA_UNSUPPORTED`,
/// sent nowhere.
///
/// # Errors
///
/// The first page refused (its envelope, unchanged), a transport failure, or a page that
/// breaks the form (`next_page_token` present exactly when `more`; a token never repeats):
/// `INTERNAL_ERROR`.
pub async fn traverse_on<S>(
    client: &mut ControlClient<S>,
    subject: InspectSubject,
    limit: Option<u32>,
) -> Result<Vec<serde_json::Value>, Box<Envelope<serde_json::Value>>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    if let Some(refused) = pages_unsupported(client) {
        return Err(Box::new(refused));
    }
    let malformed = || {
        Box::new(crate::output::error_value(error(
            Code::InternalError,
            "the runtime answered a page that breaks the page form",
        )))
    };
    let mut items = Vec::new();
    let mut token: Option<PageToken> = None;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    loop {
        let page = PageRequest {
            limit,
            token: token.clone(),
        };
        let env = client
            .request(pages_request(subject, None, Some(page)))
            .await
            .map_err(|e| {
                Box::new(crate::output::error_value(transport_failure_envelope(
                    &e, false,
                )))
            })?;
        if !env.code.is_success() {
            return Err(Box::new(env));
        }
        let more = env.data["more"].as_bool().ok_or_else(malformed)?;
        let next = match env.data.get("next_page_token") {
            None => None,
            Some(t) => {
                Some(serde_json::from_value::<PageToken>(t.clone()).map_err(|_| malformed())?)
            }
        };
        let serde_json::Value::Array(page_items) = env.data["items"].clone() else {
            return Err(malformed());
        };
        items.extend(page_items);
        match (more, next) {
            (false, None) => return Ok(items),
            (true, Some(next)) if seen.insert(next.as_str().to_owned()) => token = Some(next),
            _ => return Err(malformed()),
        }
    }
}

/// ⟨rev7⟩ m07-plan U3 build step 1 (ADR-0013 §6.3, S3): the answer of a point lookup, the one
/// way internal resolution reads the records it needs (routes, hops, aliases, profiles,
/// identities, bindings, decisions, environments by ID). `missing` names the entries that
/// matched nothing this caller may read.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Selection {
    pub(crate) items: Vec<serde_json::Value>,
    pub(crate) missing: Vec<String>,
}

impl Selection {
    /// The selected item whose string field `field` is `value`.
    pub(crate) fn item(&self, field: &str, value: &str) -> Option<&serde_json::Value> {
        self.items
            .iter()
            .find(|i| i.get(field).and_then(serde_json::Value::as_str) == Some(value))
    }

    /// A `select` answer read as `{items, missing}`: a refusal is returned unchanged; an
    /// answer of another form is `INTERNAL_ERROR` (unreadable: never read as "absent").
    pub(crate) fn of(
        env: Envelope<serde_json::Value>,
    ) -> Result<Self, Box<Envelope<serde_json::Value>>> {
        if !env.code.is_success() {
            return Err(Box::new(env));
        }
        let malformed = || {
            Box::new(crate::output::error_value(error(
                Code::InternalError,
                "the runtime answered a point lookup that breaks the select form",
            )))
        };
        let serde_json::Value::Array(items) = env.data["items"].clone() else {
            return Err(malformed());
        };
        let missing = match env.data.get("missing") {
            None => Vec::new(),
            Some(m) => serde_json::from_value(m.clone()).map_err(|_| malformed())?,
        };
        Ok(Self { items, missing })
    }
}

/// ⟨rev7⟩ The `select` request of `ids` and `aliases` in `subject` (no preview, `cwd` or
/// `redact`).
pub(crate) fn select_request(
    subject: InspectSubject,
    ids: Vec<String>,
    aliases: Vec<String>,
) -> Request {
    pages_request(subject, Some(Select { ids, aliases }), None)
}

/// ⟨rev7⟩ m07-plan U3 build step 1 (ADR-0013 §6.3): the point lookup of `ids` and `aliases`
/// in `subject` on any control session, sent as one `select` per [`SELECT_MAX`] entries.
/// On a session that did not negotiate `pages/1`, `SCHEMA_UNSUPPORTED`, sent nowhere: never a
/// whole read instead.
///
/// # Errors
///
/// The first refusal (unchanged), or `INTERNAL_ERROR` for an answer that breaks the form.
pub(crate) async fn lookup<S: crate::cli::Session>(
    s: &mut S,
    subject: InspectSubject,
    ids: &[String],
    aliases: &[String],
) -> Result<Selection, Box<Envelope<serde_json::Value>>> {
    use heimdall_contract::page::SELECT_MAX;
    if !s.serves_pages() {
        return Err(Box::new(crate::output::error_value(error(
            Code::SchemaUnsupported,
            "the runtime does not serve select or page (pages/1)",
        ))));
    }
    let mut out = Selection::default();
    let entries: Vec<(bool, &String)> = ids
        .iter()
        .map(|i| (true, i))
        .chain(aliases.iter().map(|a| (false, a)))
        .collect();
    for chunk in entries.chunks(SELECT_MAX) {
        let (ids, aliases): (Vec<_>, Vec<_>) = chunk.iter().partition(|(id, _)| *id);
        let request = select_request(
            subject,
            ids.into_iter().map(|(_, i)| (*i).clone()).collect(),
            aliases.into_iter().map(|(_, a)| (*a).clone()).collect(),
        );
        let part = Selection::of(s.request(request).await)?;
        out.items.extend(part.items);
        out.missing.extend(part.missing);
    }
    Ok(out)
}

/// ⟨rev7⟩ Test seam: the answer a runtime gives `request` when a fake holds the whole read
/// `whole` of its subject. A `select` answers `{items, missing}` from `whole`'s list (by the
/// subject's ID field, and by `alias` for destinations); any other request gets `whole`.
#[cfg(test)]
pub(crate) fn answered(request: &Request, whole: serde_json::Value) -> serde_json::Value {
    let Request::Inspect(InspectRequest {
        subject,
        select: Some(select),
        ..
    }) = request
    else {
        return whole;
    };
    let (key, id) = match subject {
        InspectSubject::Environments => ("items", "environment_id"),
        InspectSubject::Profiles => ("items", "profile_id"),
        InspectSubject::Destinations => ("items", "destination_id"),
        InspectSubject::Grants => ("grants", "grant_id"),
        InspectSubject::Bindings => ("bindings", "binding_id"),
        InspectSubject::Operations => ("operations", "operation_id"),
        InspectSubject::Decisions => ("decisions", "decision_id"),
        InspectSubject::Identities => ("identities", "identity_id"),
        InspectSubject::Enrollments => ("enrollments", "enrollment_id"),
        InspectSubject::Policies => ("items", "policy_id"),
        _ => ("items", "id"),
    };
    let list = whole[key].as_array().cloned().unwrap_or_default();
    let mut items = Vec::new();
    let mut missing = Vec::new();
    let found = |field: &str, wanted: &str| {
        list.iter()
            .find(|i| i.get(field).and_then(serde_json::Value::as_str) == Some(wanted))
            .cloned()
    };
    for wanted in &select.ids {
        match found(id, wanted) {
            Some(i) => items.push(i),
            None => missing.push(wanted.clone()),
        }
    }
    for wanted in &select.aliases {
        match found("alias", wanted) {
            Some(i) => items.push(i),
            None => missing.push(wanted.clone()),
        }
    }
    serde_json::json!({ "items": items, "missing": missing })
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
    connect_as(ctx, allow_start, extra, ctx.interaction()).await
}

/// [`connect_requiring`] with an explicit hello interaction mode. `run` and `connect`
/// declare `interactive` whenever the provider may interact (`--non-interactive`
/// absent, or `--allow-provider-interaction`), so the runtime's no-interaction path
/// is exactly ADR-0007 §7's; attendance still needs the terminal flow, which only an
/// interactive TTY session sends (m02-plan U8).
pub async fn connect_as(
    ctx: &Ctx,
    allow_start: bool,
    extra: &[&str],
    interaction: InteractionMode,
) -> Result<Client, Box<Envelope<ErrorData>>> {
    let paths = ctx.paths()?;
    if allow_start {
        paths.ensure().map_err(|e| {
            // ⟨M04 review-fix round⟩ An unsafe state directory is named as such, with how
            // to fix it, never as a generic start failure.
            if heimdall_runtime::paths::is_state_dir_unsafe(&e) {
                return Box::new(crate::service_cmd::state_dir_unsafe(&e));
            }
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
        interaction,
    )
    .await
    .map_err(|e| Box::new(transport_failure_envelope(&e, false)))?;
    let mut inner = inner;
    // ⟨M08 U2b-2⟩ A retry's kept epoch travels with every mutating request it sends.
    inner.keep_epoch(ctx.request_epoch);
    Ok(Client {
        inner,
        kept: ctx.request_epoch,
    })
}

/// ⟨M06 W2⟩ A raw connection to the control endpoint of the runtime serving `home` (an
/// absolute Heimdall home named by `remote serve`'s argv, never the environment), with no
/// hello sent: the bridge originates the only hello (ADR-0012 §3.6). Never starts a runtime:
/// a runner's runtime is its user service (or the operator's), and one started from an sshd
/// session would inherit that session's environment.
///
/// # Errors
/// `USAGE_ERROR` when the directories cannot be resolved; `SERVICE_UNAVAILABLE` when no
/// runtime serves the home.
pub async fn control_stream_for_home(
    home: &std::path::Path,
) -> Result<Stream, Box<Envelope<ErrorData>>> {
    let home = home.as_os_str().to_owned();
    let paths = Paths::resolve(&|name| {
        if name == HOME_ENV {
            Some(home.clone())
        } else {
            None
        }
    })
    .map_err(|e| {
        Box::new(error(
            Code::UsageError,
            &format!("cannot resolve the Heimdall directories: {e}"),
        ))
    })?;
    open_stream(&paths).await
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod pages_tests {
    //! ⟨rev7⟩ m07-plan U3: `pages/1` over a real session (the IPC gate, then the client's
    //! point lookup and traversal) with a dispatcher that counts what reaches it.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use heimdall_contract::event::{Cursor, EventFilter};
    use heimdall_contract::ids::EnvironmentId;
    use heimdall_contract::ipc::{ClientHello, PrincipalInfo};
    use heimdall_contract::{PROTOCOL_VERSION, SchemaVersion};
    use heimdall_ipc::session::{
        ConnectionLimits, ControlConnection, Dispatcher, SessionInfo, SubscriptionStart,
        server_capabilities,
    };
    use tokio_util::sync::CancellationToken;

    use super::*;

    /// Answers `page` with two pages (`[1, 2]` then `[3]`) and `select` with every entry
    /// missing; counts every dispatched request.
    #[derive(Clone, Default)]
    struct Pages {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Dispatcher for Pages {
        async fn dispatch(
            &self,
            _session: &SessionInfo,
            request: Request,
        ) -> Envelope<serde_json::Value> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let Request::Inspect(r) = request else {
                return crate::output::error_value(error(Code::UsageError, "inspect only"));
            };
            let data = match (&r.select, &r.page) {
                (Some(s), None) => serde_json::json!({ "items": [], "missing": s.ids }),
                (None, Some(p)) if p.token.is_none() => {
                    serde_json::json!({ "items": [1, 2], "more": true, "next_page_token": "AAAA" })
                }
                (None, Some(_)) => serde_json::json!({ "items": [3], "more": false }),
                _ => serde_json::json!({ "items": [] }),
            };
            Envelope::ok(data)
        }

        async fn subscribe(
            &self,
            _session: &SessionInfo,
            _filter: EventFilter,
            _from: Option<Cursor>,
        ) -> Result<SubscriptionStart, Box<Envelope<ErrorData>>> {
            Err(Box::new(error(Code::UsageError, "no subscriptions")))
        }
    }

    /// A session whose hello offers `offer`, served by `dispatcher`.
    async fn session(
        offer: BTreeSet<String>,
        dispatcher: Pages,
    ) -> ControlClient<tokio::io::DuplexStream> {
        let (server, stream) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let _ = ControlConnection::new(server, ConnectionLimits::default())
                .with_server_identity(
                    EnvironmentId::from_random_bytes([9; 16]),
                    PeerInfo {
                        name: "heimdall".into(),
                        version: "test".into(),
                    },
                )
                .serve(
                    PrincipalInfo::OsUserUnix { uid: 501 },
                    dispatcher,
                    CancellationToken::new(),
                )
                .await;
        });
        ControlClient::handshake_hello(
            stream,
            ClientHello {
                protocol: PROTOCOL_VERSION,
                schema_version: SchemaVersion::current(),
                client: PeerInfo {
                    name: "pages-test".into(),
                    version: "0".into(),
                },
                capabilities: offer,
                required: std::iter::once(capability::OPERATIONS_V1.to_owned()).collect(),
                interaction: InteractionMode::NonInteractive,
                remote_client: None,
            },
        )
        .await
        .unwrap()
    }

    fn a() -> Vec<String> {
        vec!["dst-a".into()]
    }

    fn select_one() -> Select {
        Select {
            ids: vec!["dst-a".into()],
            aliases: Vec::new(),
        }
    }

    /// `select_or_page_without_the_capability_is_schema_unsupported`: a session that did not
    /// negotiate `pages/1` sending `select` or `page` is answered `SCHEMA_UNSUPPORTED` by the
    /// session gate and never dispatched; the client's own helpers refuse it without sending.
    /// The same session still dispatches a whole read.
    #[tokio::test]
    async fn select_or_page_without_the_capability_is_schema_unsupported() {
        let mut offer = server_capabilities();
        assert!(
            offer.remove(capability::PAGES_V1),
            "the server offers pages/1"
        );
        let dispatcher = Pages::default();
        let mut client = session(offer, dispatcher.clone()).await;
        assert!(!client.server().capabilities.contains(capability::PAGES_V1));
        let forms = [
            pages_request(InspectSubject::Destinations, Some(select_one()), None),
            pages_request(
                InspectSubject::Destinations,
                None,
                Some(PageRequest::default()),
            ),
            pages_request(InspectSubject::Capabilities, Some(Select::default()), None),
        ];
        for request in forms {
            let env = client.request(request).await.unwrap();
            assert_eq!(env.code, Code::SchemaUnsupported, "{env:?}");
        }
        assert_eq!(
            dispatcher.calls.load(Ordering::SeqCst),
            0,
            "never dispatched"
        );
        let err = lookup(&mut client, InspectSubject::Destinations, &a(), &[])
            .await
            .unwrap_err();
        assert_eq!(err.code, Code::SchemaUnsupported);
        let err = traverse_on(&mut client, InspectSubject::Destinations, None)
            .await
            .unwrap_err();
        assert_eq!(err.code, Code::SchemaUnsupported);
        assert_eq!(dispatcher.calls.load(Ordering::SeqCst), 0, "nothing sent");
        let env = client
            .request(pages_request(InspectSubject::Destinations, None, None))
            .await
            .unwrap();
        assert_eq!(env.code, Code::Ok);
        assert_eq!(dispatcher.calls.load(Ordering::SeqCst), 1);
    }

    /// The CLI's and the TUI's hello (`ControlClient::handshake`, the server's set) offers
    /// `pages/1`, so their sessions negotiate it; the traversal follows `next_page_token`
    /// until the first page with `more: false`, and `select` answers `missing`.
    #[tokio::test]
    async fn traversal_follows_tokens_to_the_last_page() {
        let dispatcher = Pages::default();
        let mut client = session(server_capabilities(), dispatcher.clone()).await;
        assert!(client.server().capabilities.contains(capability::PAGES_V1));
        let items = traverse_on(&mut client, InspectSubject::Destinations, Some(2))
            .await
            .unwrap();
        assert_eq!(items, [1, 2, 3].map(serde_json::Value::from));
        assert_eq!(dispatcher.calls.load(Ordering::SeqCst), 2);
        let selected = lookup(&mut client, InspectSubject::Destinations, &a(), &[])
            .await
            .unwrap();
        assert_eq!(selected.missing, ["dst-a"]);
    }
}

#[cfg(test)]
#[path = "client_resolution_tests.rs"]
mod resolution_tests;
