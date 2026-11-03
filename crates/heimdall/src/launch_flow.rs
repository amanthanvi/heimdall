//! What `run` and `connect` share (m02-plan U8; ADR-0007 §7, §8; spec §10.4).
//!
//! * **Side channel.** `--meta-fd` (Unix) is adopted through
//!   [`SideChannel::from_fd`] and `--meta-file` created through
//!   [`SideChannel::create_exclusive`] **before** anything else: an unusable
//!   descriptor or an existing file is a `USAGE_ERROR` (exit 2) before `ensure`, with
//!   no record (there is no channel to write one to). Every later failure before launch
//!   writes `prelaunch_failed` with its code, exit status and reason ([`Failure`]).
//! * **Output.** Nothing Heimdall prints reaches stdout: the child owns it. A failure is
//!   reported on stderr, as one JSON envelope with `--json` or as human lines
//!   otherwise; so are the consumer overrides that stay in force.
//! * **Interaction.** The no-interaction path is `--non-interactive` without
//!   `--allow-provider-interaction` (ADR-0007 §7). Only then is the session's hello
//!   `non_interactive` and the pre-launch eligibility check run; otherwise the hello is
//!   `interactive`, so the runtime's readiness lets the provider (never Heimdall)
//!   interact. Attendance and Heimdall's own prompts still need an interactive TTY
//!   ([`Ctx::interactive`]).
//! * **The fresh views** of the pre-launch check: a new `inspect identities` (owner
//!   role, ADR-0007 §12.14 item 5) and, per pair, a static `sshconf` pass in this
//!   process over the user's configuration with P as the managed root
//!   (`heimdall_localenv::projection::observe::observe`; passive: nothing executes and
//!   no local query runs).
//! * **Argument privacy.** `argv` never crosses IPC and never appears in a record,
//!   envelope, diagnostic or log: refusals name an argument by index only.

use std::ffi::OsString;
use std::path::Path;

use heimdall_contract::envelope::{EffectStatus, Envelope, NextAction};
use heimdall_contract::ids::{BindingId, OperationId};
use heimdall_contract::provider::{
    DeclarationRef, EndpointKind, EndpointRef, IdentitiesOnly, IdentitySelection,
    IdentitySelectionReport, InteractionKind, ProviderInteractionRef, ProviderKind,
};
use heimdall_contract::request::{
    ConsumerOverride, InspectRequest, InspectSubject, InteractionMode, OverrideSource, Request,
};
use heimdall_contract::{Code, ExitCode};
use heimdall_domain::projection::ProjectionRecord;
use heimdall_launch::LaunchFailure;
use heimdall_launch::eligibility::{
    FreshSelection, IdentitiesView, IdentityView, PrelaunchReason, PrelaunchRefusal,
};
use heimdall_launch::env::EnvDelta;
use heimdall_launch::meta::{MetaError, SideChannel};
use heimdall_launch::resolve::{LaunchRefusal, ResolvedProgram};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::paths::SshPaths;
use heimdall_localenv::projection::ProjectionConfig;

use crate::cli::LaunchArgs;
use crate::client::{Client, Ctx};
use crate::output;
use crate::testcfg::LaunchHooks;

/// A failure before launch: the envelope reported on stderr and the exit status (also
/// the `prelaunch_failed` record's).
pub(crate) struct Failure {
    /// The error envelope.
    pub(crate) env: Envelope<serde_json::Value>,
    /// The exit status.
    pub(crate) exit: ExitCode,
}

impl Failure {
    /// From an error envelope, exiting with its code's class.
    pub(crate) fn of(env: Envelope<serde_json::Value>) -> Failure {
        let reason = reason_of(&env);
        let exit = env.code.exit_code_for_reason(reason.as_deref());
        Failure { env, exit }
    }

    /// A new error.
    pub(crate) fn new(code: Code, message: &str, reason: Option<&str>) -> Failure {
        let mut e =
            heimdall_app::OpError::new(code, message.to_owned()).with_effect(EffectStatus::None);
        if let Some(r) = reason {
            e = e.with_reason(r);
        }
        Failure::of(output::error_value(e.into_envelope()))
    }

    /// `USAGE_ERROR`, exit 2.
    pub(crate) fn usage(message: &str) -> Failure {
        Failure::new(Code::UsageError, message, None)
    }

    /// `LAUNCH_FAILED` for a refusal (127, or 126 for `not_executable`).
    pub(crate) fn refused(refusal: LaunchRefusal) -> Failure {
        let mut f = Failure::new(
            Code::LaunchFailed,
            &refusal.to_string(),
            Some(refusal.reason()),
        );
        f.exit = exit_of(refusal.exit_code());
        f
    }

    /// The pre-launch eligibility refusal: `INTERACTION_REQUIRED`, exit 3, `next:
    /// interact` with the provider's interaction, never a `decision_ref` (spec §5.5),
    /// naming each uncleared entry's file and line.
    pub(crate) fn ineligible(
        refusal: &PrelaunchRefusal,
        provider: ProviderKind,
        kind: InteractionKind,
    ) -> Failure {
        let mut message = match refusal.reason {
            PrelaunchReason::InteractionUnknown => {
                "an identity of this launch may need interaction (its declaration is no longer the one the binding relied on, or none counts)".to_owned()
            }
            PrelaunchReason::ProviderInteraction => {
                "the provider may ask for approval, unlock or presence".to_owned()
            }
            PrelaunchReason::FallbackIdentityInteraction => {
                "an identity ssh may also try is not cleared for use without interaction".to_owned()
            }
        };
        if !refusal.entries.is_empty() {
            let lines: Vec<String> = refusal
                .entries
                .iter()
                .map(|p| format!("{}:{}", p.path_display, p.line))
                .collect();
            message.push_str(&format!(" ({})", lines.join(", ")));
        }
        message.push_str(
            "; nothing was launched (pass --allow-provider-interaction to let the provider prompt)",
        );
        let e = heimdall_app::OpError::new(Code::InteractionRequired, message)
            .with_effect(EffectStatus::None)
            .with_reason(refusal.reason.as_str())
            .with_next(NextAction {
                provider_interaction: Some(ProviderInteractionRef { provider, kind }),
                ..NextAction::for_code(Code::InteractionRequired)
            });
        Failure {
            env: output::error_value(e.into_envelope()),
            exit: ExitCode::InteractionRequired,
        }
    }
}

/// `data.error.reason` of an error envelope.
fn reason_of(env: &Envelope<serde_json::Value>) -> Option<String> {
    env.data
        .get("error")
        .and_then(|e| e.get("reason"))
        .and_then(|r| r.as_str())
        .map(str::to_owned)
}

/// The exit status of a launch refusal as the exit enum.
fn exit_of(code: i32) -> ExitCode {
    if code == ExitCode::NotExecutable.as_i32() {
        ExitCode::NotExecutable
    } else {
        ExitCode::LaunchFailed
    }
}

/// Report an envelope on stderr (module docs).
pub(crate) fn report(ctx: &Ctx, env: &Envelope<serde_json::Value>) {
    if ctx.json {
        if let Ok(text) = serde_json::to_string(env) {
            output::diagnostic(&text);
        }
        return;
    }
    let error = env.data.get("error");
    let field = |k: &str| {
        error
            .and_then(|e| e.get(k))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    let mut line = format!("heimdall: {}", env.code.as_str());
    let reason = field("reason");
    if !reason.is_empty() {
        line.push_str(&format!(" ({reason})"));
    }
    let message = field("message");
    if !message.is_empty() {
        line.push_str(": ");
        line.push_str(&message);
    }
    output::diagnostic(&line);
    if let Some(next) = env.next.as_ref() {
        let mut line = format!("heimdall: next: {}", next.action);
        if let Some(op) = &next.operation_id {
            line.push_str(&format!(" operation_id={op}"));
        }
        if let Some(d) = &next.decision_ref {
            line.push_str(&format!(" decision_ref={d}"));
        }
        output::diagnostic(&line);
    }
}

/// Record and report `failure`, and return its exit status.
pub(crate) fn fail(ctx: &Ctx, meta: &mut Option<SideChannel>, failure: Failure) -> ExitCode {
    if let Some(channel) = meta.as_mut() {
        let reason = reason_of(&failure.env);
        let _ = channel.write_prelaunch_failed(
            failure.env.code.clone(),
            failure.exit.as_i32(),
            reason.as_deref(),
        );
    }
    report(ctx, &failure.env);
    failure.exit
}

/// Open the side channel the options name (module docs). `Err` is a usage error with
/// no record.
pub(crate) fn open_side_channel(launch: &LaunchArgs) -> Result<Option<SideChannel>, Failure> {
    if let Some(fd) = launch.meta_fd {
        if cfg!(not(unix)) {
            return Err(Failure::usage(
                "--meta-fd is available on Unix only; use --meta-file",
            ));
        }
        return SideChannel::from_fd(fd).map(Some).map_err(|_| {
            Failure::usage(
                "--meta-fd must be an open, writable pipe, socket or regular file above 2",
            )
        });
    }
    if let Some(path) = &launch.meta_file {
        return SideChannel::create_exclusive(path)
            .map(Some)
            .map_err(|e| match e {
                MetaError::Exists => {
                    Failure::usage("--meta-file already exists; it is created new")
                }
                _ => Failure::usage("--meta-file cannot be created"),
            });
    }
    Ok(None)
}

/// The no-interaction path (module docs).
pub(crate) fn no_interaction_path(ctx: &Ctx, launch: &LaunchArgs) -> bool {
    ctx.non_interactive && !launch.allow_provider_interaction
}

/// The hello and request interaction mode of `run` and `connect` (module docs).
pub(crate) fn interaction(ctx: &Ctx, launch: &LaunchArgs) -> InteractionMode {
    if no_interaction_path(ctx, launch) {
        InteractionMode::NonInteractive
    } else {
        InteractionMode::Interactive
    }
}

/// Block on the pre-check pause FIFO (debug builds' test configuration only): open it
/// for reading, which waits for a writer, then read until that writer closes it. So a
/// test knows the CLI is paused once its own open returns, acts, and releases the CLI
/// by closing its end.
pub(crate) fn pause(path: Option<&Path>) {
    if let Some(p) = path
        && let Ok(mut f) = std::fs::File::open(p)
    {
        use std::io::Read as _;
        let mut sink = Vec::new();
        let _ = f.read_to_end(&mut sink);
    }
}

/// One `inspect` request; a refusal is a failure.
async fn inspect(
    client: &mut Client,
    subject: InspectSubject,
) -> Result<serde_json::Value, Failure> {
    let env = client
        .request(Request::Inspect(InspectRequest {
            subject,
            preview: None,
        }))
        .await;
    if env.code.is_success() {
        Ok(env.data)
    } else {
        Err(Failure::of(env))
    }
}

/// A fresh `inspect identities` as the check's view. An entry that cannot be read is
/// left out, so its identity is `unknown` (fail closed).
pub(crate) async fn fresh_identities(client: &mut Client) -> Result<IdentitiesView, Failure> {
    let data = inspect(client, InspectSubject::Identities).await?;
    let items = data
        .get("identities")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut identities = Vec::with_capacity(items.len());
    for item in items {
        let get = |k: &str| item.get(k).cloned().unwrap_or(serde_json::Value::Null);
        let (Ok(identity), Ok(fingerprint), Ok(interaction)) = (
            serde_json::from_value(get("identity_id")),
            serde_json::from_value::<String>(get("fingerprint")),
            serde_json::from_value::<InteractionKind>(get("interaction")),
        ) else {
            continue;
        };
        let endpoint =
            serde_json::from_value::<Option<EndpointRef>>(get("endpoint")).unwrap_or(None);
        let declaration =
            serde_json::from_value::<Option<DeclarationRef>>(get("declaration")).unwrap_or(None);
        identities.push(IdentityView {
            identity,
            fingerprint,
            endpoint,
            interaction,
            declaration,
        });
    }
    Ok(IdentitiesView { identities })
}

/// The environment's projection record (`inspect projections`), or an empty one.
pub(crate) async fn projection_record(client: &mut Client) -> Result<ProjectionRecord, Failure> {
    let environment = client.server().environment_id.clone();
    let data = inspect(client, InspectSubject::Projections).await?;
    Ok(data
        .get("record")
        .cloned()
        .and_then(|r| serde_json::from_value::<ProjectionRecord>(r).ok())
        .unwrap_or(ProjectionRecord {
            environment,
            items: Default::default(),
        }))
}

/// The SSH configuration locations of the static pass: the account's, or the test
/// configuration's scratch home.
pub(crate) fn ssh_paths(hooks: &LaunchHooks) -> Result<SshPaths, Failure> {
    match &hooks.ssh_home {
        Some(home) => Ok(SshPaths::with_test_override(home.clone(), home.join("etc-ssh"))),
        None => SshPaths::resolve().map_err(|_| {
            Failure::new(
                Code::InteractionRequired,
                "the account home cannot be resolved, so the identity selection cannot be checked; nothing was launched",
                Some(PrelaunchReason::FallbackIdentityInteraction.as_str()),
            )
        }),
    }
}

/// The static pass's configuration: passive (no local query), P under Heimdall's
/// configuration directory, this process's environment.
pub(crate) fn static_config(ctx: &Ctx, hooks: &LaunchHooks) -> Result<ProjectionConfig, Failure> {
    let paths = ctx
        .paths()
        .map_err(|e| Failure::of(output::error_value(*e)))?;
    let mut config =
        ProjectionConfig::new(ssh_paths(hooks)?, Platform::current(), paths.config_dir);
    config.env = Env::capture();
    Ok(config)
}

/// The undetermined selection (no observation).
fn undetermined() -> IdentitySelectionReport {
    IdentitySelectionReport {
        selection: IdentitySelection::Undetermined,
        entries: Vec::new(),
        identities_only: IdentitiesOnly::Undetermined,
    }
}

/// The alias's effective `IdentityAgent`, when the static pass determined one explicit
/// endpoint (the default agent and `~` paths are not endpoints the check can compare).
fn identity_agent(
    observation: &heimdall_contract::doctor::AliasObservation,
) -> Option<EndpointRef> {
    let directive = observation
        .behavior
        .iter()
        .find(|d| d.directive.eq_ignore_ascii_case("IdentityAgent"))?;
    if directive.certainty != heimdall_contract::doctor::DirectiveCertainty::Determined {
        return None;
    }
    let [value] = directive.values.as_slice() else {
        return None;
    };
    let value = value.trim().trim_matches('"');
    if value.is_empty()
        || value == "none"
        || value == "SSH_AUTH_SOCK"
        || value.starts_with('$')
        || value.starts_with('~')
    {
        return None;
    }
    Some(EndpointRef {
        kind: if Platform::current().is_windows() {
            EndpointKind::NamedPipe
        } else {
            EndpointKind::UnixSocket
        },
        locator: value.to_owned(),
    })
}

/// The fresh static selection of `alias` (module docs). No alias, or an alias the
/// pass cannot evaluate, is undetermined with no endpoint, which clears nothing.
pub(crate) fn fresh_selection(
    config: &ProjectionConfig,
    record: &ProjectionRecord,
    alias: Option<&str>,
) -> FreshSelection {
    let Some(alias) = alias else {
        return FreshSelection {
            alias: String::new(),
            report: undetermined(),
            endpoint: None,
        };
    };
    let observation =
        heimdall_localenv::projection::observe::observe(config, record, &[alias.to_owned()])
            .into_iter()
            .next();
    let mut report = observation
        .as_ref()
        .and_then(|o| o.identity_selection.clone())
        .unwrap_or_else(undetermined);
    for entry in &mut report.entries {
        entry.cleared = None;
    }
    FreshSelection {
        alias: alias.to_owned(),
        report,
        endpoint: observation.as_ref().and_then(identity_agent),
    }
}

/// The provider and interaction a refusal names (`next.provider_interaction`).
pub(crate) fn refusal_provider(
    mechanism: Option<&str>,
    fresh: &IdentitiesView,
    identity: Option<&heimdall_contract::ids::IdentityId>,
) -> (ProviderKind, InteractionKind) {
    let provider = match mechanism {
        Some(heimdall_domain::catalog::MECHANISM_ONEPASSWORD) => ProviderKind::OnePassword,
        Some(heimdall_domain::catalog::MECHANISM_NATIVE_AGENT) => ProviderKind::NativeAgent,
        _ => ProviderKind::Unknown,
    };
    let kind = identity
        .and_then(|i| fresh.get(i))
        .map(|v| v.interaction)
        .filter(|k| *k != InteractionKind::None)
        .unwrap_or(InteractionKind::Unknown);
    (provider, kind)
}

/// Report the consumer settings another source keeps in force (names and sources,
/// never values) on stderr.
pub(crate) fn report_overrides(ctx: &Ctx, overrides: &[ConsumerOverride]) {
    if ctx.json {
        return;
    }
    for o in overrides {
        let consumer = serde_json::to_value(o.consumer)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let source = match &o.source {
            OverrideSource::SshConfig(p) => format!("{}:{}", p.path_display, p.line),
            OverrideSource::GitScope { scope } => format!(
                "git {} scope",
                serde_json::to_value(scope)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default()
            ),
            OverrideSource::Environment => "the environment".to_owned(),
            _ => "another source".to_owned(),
        };
        output::diagnostic(&format!(
            "heimdall: {consumer} keeps {} from {source} (consumer override)",
            o.setting
        ));
    }
}

/// Everything a launch needs once every check passed.
pub(crate) struct Launch {
    /// The program.
    pub(crate) program: ResolvedProgram,
    /// `argv[1..]`.
    pub(crate) args: Vec<OsString>,
    /// The environment delta.
    pub(crate) delta: EnvDelta,
    /// The side channel, naming the operation and binding.
    pub(crate) meta: Option<SideChannel>,
    /// The test hooks (debug builds).
    pub(crate) hooks: LaunchHooks,
}

/// The side channel with the operation and binding the records name.
pub(crate) fn with_ids(
    meta: Option<SideChannel>,
    operation: Option<OperationId>,
    binding: Option<BindingId>,
) -> Option<SideChannel> {
    meta.map(|m| m.with_ids(operation, binding))
}

/// Report a launch call that failed and return its exit status (127, or 126/127 for a
/// refusal by the pre-flight checks).
fn launch_failure(ctx: &Ctx, failure: &LaunchFailure) -> ExitCode {
    let f = match failure {
        LaunchFailure::Refused(r) => Failure::refused(*r),
        LaunchFailure::MetaUnavailable => Failure::new(
            Code::LaunchFailed,
            "the run record could not be written; nothing was launched",
            Some(heimdall_contract::envelope::reason::META_UNAVAILABLE),
        ),
        // `exec_error`, and any failure a newer launch crate adds.
        _ => Failure::new(
            Code::LaunchFailed,
            "the program could not be started",
            Some(heimdall_contract::envelope::reason::EXEC_ERROR),
        ),
    };
    report(ctx, &f.env);
    f.exit
}

/// Launch (ADR-0007 §8). Unix: `exec` (returns only on failure). Windows: spawn, wait,
/// and exit with the child's exact 32-bit code.
pub(crate) fn launch(ctx: &Ctx, launch: Launch) -> ExitCode {
    let Launch {
        program,
        args,
        delta,
        meta,
        hooks,
    } = launch;
    #[cfg(unix)]
    {
        let failure = exec(&program, &args, &delta, meta, &hooks);
        launch_failure(ctx, &failure)
    }
    #[cfg(windows)]
    {
        let _ = hooks;
        match heimdall_launch::windows::spawn_and_wait(&program, &args, &delta, meta) {
            Ok(code) => {
                // The child's exact status, not an exit class.
                #[allow(clippy::cast_possible_wrap, clippy::exit)]
                std::process::exit(code as i32)
            }
            Err(failure) => launch_failure(ctx, &failure),
        }
    }
}

#[cfg(all(unix, debug_assertions))]
fn exec(
    program: &ResolvedProgram,
    args: &[OsString],
    delta: &EnvDelta,
    meta: Option<SideChannel>,
    hooks: &LaunchHooks,
) -> LaunchFailure {
    if hooks.pre_exec_pause.is_some() || hooks.force_exec_failure {
        return heimdall_launch::unix::exec_replace_with_test_hooks(
            program,
            args,
            delta,
            meta,
            &heimdall_launch::unix::TestHooks {
                pre_exec_pause: hooks.pre_exec_pause.clone(),
                force_exec_failure: hooks.force_exec_failure,
            },
        );
    }
    heimdall_launch::unix::exec_replace(program, args, delta, meta)
}

#[cfg(all(unix, not(debug_assertions)))]
fn exec(
    program: &ResolvedProgram,
    args: &[OsString],
    delta: &EnvDelta,
    meta: Option<SideChannel>,
    _hooks: &LaunchHooks,
) -> LaunchFailure {
    heimdall_launch::unix::exec_replace(program, args, delta, meta)
}
