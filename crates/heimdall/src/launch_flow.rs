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
//!   (`heimdall_localenv::projection::observe::observe_profiles`; passive: nothing
//!   executes and no local query runs). The pass covers every invocation profile the
//!   launched work can use, `Shell`, `Exec(None)` and `Subsystem("sftp")` (ADR-0007
//!   §12.25 item 1), takes the local account from the account database, never `USER`
//!   or `USERNAME` (item 2), and shows each entry's file through the canonicalized
//!   account home, so the home's absolute path never appears (§12.26 item 7).
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
    ProfileSelection,
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
    /// naming each uncleared entry's file and line in the message and, as data, in
    /// `data.error.entries` (ADR-0007 §12.24 item 4; empty, so omitted, for the other
    /// reasons).
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
        // ADR-0007 §12.24 item 4: the refused entries' file and line, as data.
        let mut env = e.into_envelope();
        env.data.error.entries = refusal.entries.clone();
        Failure {
            env: output::error_value(env),
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
            cwd: None,
            redact: false,
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

/// ADR-0007 §12.24 item 2: immediately before `launching`, one `inspect bindings`
/// confirms that `binding` is still `active`. A replayed `bind` returns its stored
/// result verbatim, so a binding the holder pass released since (its first holder
/// exited) still reads `ACCESS_READY`; it is refused here ([`binding_released`]), and
/// nothing is launched. A binding the listing does not show (released bindings hold no
/// reference, so they are not listed) is refused the same way (fail closed). A listing
/// that cannot be read is refused with the `inspect` failure itself.
pub(crate) async fn confirm_binding_active(
    client: &mut Client,
    binding: &BindingId,
) -> Result<(), Failure> {
    let data = inspect(client, InspectSubject::Bindings).await?;
    let active = data
        .get("bindings")
        .and_then(|v| v.as_array())
        .is_some_and(|items| {
            items.iter().any(|b| {
                b.get("binding_id").and_then(|v| v.as_str()) == Some(binding.as_str())
                    && b.get("state").and_then(|v| v.as_str()) == Some("active")
            })
        });
    if active {
        return Ok(());
    }
    Err(binding_released(binding))
}

/// ADR-0007 §12.26 item 3(a), §12.28 item 7: the refusal of a binding that is no
/// longer active, made where the re-check finds it: the code a `bind` of a released
/// binding settles with, `CREDENTIAL_EXPIRED` (exit 4), `next: new_work`, effect `none`,
/// the binding as the resource, reason `binding_released`.
pub(crate) fn binding_released(binding: &BindingId) -> Failure {
    let e = heimdall_app::OpError::new(
        Code::CredentialExpired,
        "the binding was released (its holder exited); nothing was launched, start new work",
    )
    .with_effect(EffectStatus::None)
    .with_reason(heimdall_contract::envelope::reason::BINDING_RELEASED)
    .with_resource("binding", Some(binding.to_string()));
    Failure::of(output::error_value(e.into_envelope()))
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
/// endpoint (the default agent, `~` paths and values with a `%` token are not endpoints
/// the check can compare: ssh expands them).
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
        || value.contains('%')
    {
        return None;
    }
    // Windows: P renders a pipe `//./pipe/<name>` (`RenderPath::pipe`), the same pipe as
    // the `\\.\pipe\<name>` an identity is adopted at; compare one spelling.
    let locator = match heimdall_localenv::agents::locator_for(value, Platform::current()) {
        Some(heimdall_localenv::agents::EndpointLocator::NamedPipe(name))
            if Platform::current().is_windows() =>
        {
            name
        }
        _ => value.to_owned(),
    };
    Some(EndpointRef {
        kind: if Platform::current().is_windows() {
            EndpointKind::NamedPipe
        } else {
            EndpointKind::UnixSocket
        },
        locator,
    })
}

/// The fresh static selection of `alias` (module docs), under every invocation
/// profile (ADR-0007 §12.25 item 1). No alias, or an alias the pass cannot evaluate,
/// is undetermined with no endpoint, which clears nothing.
pub(crate) fn fresh_selection(
    config: &ProjectionConfig,
    record: &ProjectionRecord,
    alias: Option<&str>,
) -> FreshSelection {
    let Some(alias) = alias else {
        return selection_of("", Vec::new(), &config.paths.account_home);
    };
    selection_of(
        alias,
        managed_observations(config, record, alias),
        &config.paths.account_home,
    )
}

/// `alias`'s static observation under each invocation profile (`None`: the pass reported
/// nothing for that profile).
pub(crate) type ProfileObservations =
    Vec<(String, Option<heimdall_contract::doctor::AliasObservation>)>;

/// The observations [`fresh_selection`] reads: a managed alias (one P renders).
pub(crate) fn managed_observations(
    config: &ProjectionConfig,
    record: &ProjectionRecord,
    alias: &str,
) -> ProfileObservations {
    heimdall_localenv::projection::observe::observe_profiles(config, record, alias)
}

/// A selection from observations already made ([`managed_observations`],
/// [`observed_observations`]).
pub(crate) fn selection_from(
    config: &ProjectionConfig,
    alias: &str,
    profiles: ProfileObservations,
) -> FreshSelection {
    selection_of(alias, profiles, &config.paths.account_home)
}

/// ⟨M06 W5; ADR-0012 §4 item 5 "An undetermined `IdentityAgent`" ⟨2026-11-22⟩⟩ Why the
/// static pass cannot determine the agent `alias` would use, under the first invocation
/// profile where it cannot; `None` when it is determined under every profile: unset,
/// `none`, the default agent's variable (which the clean launch of runner work never
/// passes), or one explicit endpoint.
///
/// Undetermined: a profile the pass reported nothing for; a value that depends on a
/// `Match` block or has several candidates; a `~` path or a value with a `%` token (ssh
/// expands them, the pass does not); a value read from another environment variable.
pub(crate) fn undetermined_identity_agent(profiles: &ProfileObservations) -> Option<String> {
    for profile in heimdall_launch::eligibility::required_profiles() {
        let observation = profiles
            .iter()
            .find(|(name, _)| *name == profile)
            .and_then(|(_, o)| o.as_ref());
        let why = match observation {
            None => Some("its configuration could not be evaluated"),
            Some(o) => identity_agent_undetermined(o),
        };
        if let Some(why) = why {
            return Some(format!("{why} (invocation profile `{profile}`)"));
        }
    }
    None
}

/// Why one observation's `IdentityAgent` is undetermined
/// ([`undetermined_identity_agent`]).
fn identity_agent_undetermined(
    observation: &heimdall_contract::doctor::AliasObservation,
) -> Option<&'static str> {
    use heimdall_contract::doctor::DirectiveCertainty;
    let directive = observation
        .behavior
        .iter()
        .find(|d| d.directive.eq_ignore_ascii_case("IdentityAgent"))?;
    match directive.certainty {
        DirectiveCertainty::Unset => return None,
        DirectiveCertainty::Determined => {}
        _ => {
            return Some(
                "its value depends on a `Match` block or has several candidates the static pass cannot choose between",
            );
        }
    }
    let value = match directive.values.as_slice() {
        [] => return None,
        [value] => value.trim().trim_matches('"'),
        _ => return Some("it has several values"),
    };
    if value.starts_with('~') {
        Some("its value is a `~` path, which ssh expands")
    } else if value.contains('%') {
        Some("its value has a `%` token, which ssh expands")
    } else if value.starts_with('$') {
        Some("its value is read from an environment variable")
    } else {
        None
    }
}

/// The fresh static selection of an **observed** alias, one the user's own
/// configuration defines (ADR-0007 §12.24 item 1). `projection::observe` reports an
/// identity selection only for P's aliases (it needs the adopted key file), so the
/// alias is evaluated by the doctor's static level instead, as an observed catalog
/// alias: passive, with local queries off, so nothing executes, no agent is contacted
/// and only configuration and `.pub` files are read (the same evaluator, roots and
/// managed root P as `observe`), under every invocation profile (§12.25 item 1,
/// `doctor::alias_profiles`). Its placeholder identity names no key file, so every
/// entry is reported with its own source, fingerprint, backing and provenance, and the
/// check reads each one as an alternative the domain rule must clear.
pub(crate) fn fresh_observed_selection(config: &ProjectionConfig, alias: &str) -> FreshSelection {
    selection_of(
        alias,
        observed_observations(config, alias),
        &config.paths.account_home,
    )
}

/// The observations [`fresh_observed_selection`] reads.
pub(crate) fn observed_observations(config: &ProjectionConfig, alias: &str) -> ProfileObservations {
    use heimdall_localenv::doctor::{CatalogAlias, CatalogIdentity, LocalContext};
    let mut ctx = LocalContext::new(
        config.paths.clone(),
        config.env.clone(),
        config.platform,
        heimdall_localenv::clients::ClientsConfig::default(),
        Default::default(),
    );
    ctx.managed_file = Some(config.managed_ssh_path());
    ctx.catalog = vec![CatalogAlias {
        alias: alias.to_owned(),
        definition: heimdall_contract::doctor::AliasDefinition::Observed,
        identity: Some(CatalogIdentity {
            public_key_path: std::path::PathBuf::new(),
            fingerprint: None,
            interaction: InteractionKind::Unknown,
            endpoint: None,
        }),
    }];
    heimdall_localenv::doctor::alias_profiles(&ctx, alias)
        .into_iter()
        .map(|(name, observation)| (name, (observation.alias == alias).then_some(observation)))
        .collect()
}

/// A fresh selection from `alias`'s static observation under each profile
/// (`(name, observation)`). A profile with no observation, or one `profiles` lacks, is
/// undetermined with no endpoint, which clears nothing. A stored clearance is never
/// what the check reads. Each entry's file is shown through the canonicalized account
/// `home` (ADR-0007 §12.26 item 7).
fn selection_of(
    alias: &str,
    profiles: Vec<(String, Option<heimdall_contract::doctor::AliasObservation>)>,
    home: &Path,
) -> FreshSelection {
    let mut by_name: Vec<ProfileSelection> = heimdall_launch::eligibility::required_profiles()
        .into_iter()
        .map(|profile| {
            let observation = profiles
                .iter()
                .find(|(name, _)| *name == profile)
                .and_then(|(_, o)| o.as_ref());
            let mut report = observation
                .and_then(|o| o.identity_selection.clone())
                .unwrap_or_else(undetermined);
            for entry in &mut report.entries {
                entry.cleared = None;
                if let Some(p) = entry.provenance.as_mut() {
                    heimdall_localenv::doctor::redisplay(p, home);
                }
            }
            ProfileSelection {
                profile,
                report,
                endpoint: observation.and_then(identity_agent),
            }
        })
        .collect();
    // `shell` is the first required profile: the selection's own report and agent.
    let shell = if by_name.is_empty() {
        ProfileSelection {
            profile: "shell".to_owned(),
            report: undetermined(),
            endpoint: None,
        }
    } else {
        by_name.remove(0)
    };
    FreshSelection {
        alias: alias.to_owned(),
        report: shell.report,
        endpoint: shell.endpoint,
        profiles: by_name,
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

// --- ⟨M06 W5⟩ runner work (ADR-0012 §4 item 5; A24) ---------------------------------------

/// Whether this installation is a remote runner, read from its own state (read-only: its
/// environment record's kind, `heimdall_runtime::paired::is_runner`). An installation with
/// no state database is not one.
///
/// # Errors
/// The state exists and cannot be read: the kind is unknown, so the caller launches
/// nothing (a runner's work must never start with the launching process's environment).
pub(crate) fn installation_is_runner(
    ctx: &Ctx,
) -> Result<Option<heimdall_runtime::Paths>, Failure> {
    let unreadable = || {
        Failure::new(
            Code::StateUnavailable,
            "this installation's kind cannot be read; nothing was launched",
            None,
        )
    };
    let paths = ctx.paths().map_err(|_| unreadable())?;
    let db = paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    if !db.exists() {
        return Ok(None);
    }
    let store =
        heimdall_store::Store::open_read_only(&db, std::sync::Arc::new(heimdall_store::NoFaults))
            .map_err(|_| unreadable())?;
    let runner = store
        .transaction(heimdall_runtime::paired::is_runner)
        .map_err(|_| unreadable())?;
    Ok(runner.then_some(paths))
}

/// ⟨M06 W5; ADR-0012 §4 item 5 "Dependencies by construction"; A24⟩ The launch of **runner
/// work**: on an installation of kind `remote_runner`, `delta` becomes the clean launch
/// `heimdall_runtime::runner::launch::plan_launch` plans, and on any other installation it
/// is returned unchanged (nothing else is read or printed).
///
/// On a runner:
/// * every variable of this process's environment is removed from the child's, and the
///   child gets exactly the planned environment: the declared pass-list
///   (`heimdall_runtime::runner::launch::PASS_LIST`, ADR-0012 §4 item 5 ⟨2026-11-22⟩, less
///   any variable `delta` already keeps out), a fixed `PATH`, and `SSH_AUTH_SOCK` only
///   when it is the runner signer's endpoint of this binding (`consumer`'s signing
///   endpoint, `managed` saying the binding's mechanism is the managed certificate, or the
///   one endpoint every pair shares). An agent this process inherited (a forwarded one
///   above all) never reaches the work;
/// * each agent that is not passed is named on stderr with its provenance
///   (`controller_dependency`, or `unknown` for any other, an ordinary local path included),
///   never with its path;
/// * an override that said the caller's `SSH_AUTH_SOCK` stays in force is dropped: it does
///   not.
///
/// # Errors
/// The installation's kind cannot be read (`STATE_UNAVAILABLE`); or nobody is present
/// ([`Ctx::interactive`] is false) and the binding depends on an agent that is neither
/// runner-managed nor independently managed: `CAPABILITY_UNAVAILABLE`, reason
/// `controller_dependency` or `dependency_provenance_unknown`. Nothing is launched.
pub(crate) fn runner_work(
    ctx: &Ctx,
    consumer: &heimdall_contract::request::ConsumerIntegration,
    managed: bool,
    delta: EnvDelta,
    env: &Env,
) -> Result<EnvDelta, Failure> {
    use heimdall_runtime::runner::launch::{BoundAgent, SSH_AUTH_SOCK};
    let Some(paths) = installation_is_runner(ctx)? else {
        return Ok(delta);
    };
    let mut bound: Vec<BoundAgent> = consumer
        .pairs
        .iter()
        .filter_map(|p| {
            let endpoint = p.endpoint.as_ref()?;
            (endpoint.kind == EndpointKind::UnixSocket).then(|| BoundAgent {
                socket: std::path::PathBuf::from(&endpoint.locator),
                managed: p.mechanism == MANAGED_CERTIFICATE,
            })
        })
        .collect();
    // A runner's managed binding names its endpoint as the integration's signing endpoint
    // and no pair (`heimdall_runtime::runner::adapter`): that endpoint is the work's signer
    // when no pair names another.
    let signing = consumer
        .signing_endpoint
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);
    let from_pairs = !bound.is_empty();
    if let Some(socket) = &signing {
        bound.push(BoundAgent {
            socket: socket.clone(),
            managed,
        });
    }
    let selected = delta
        .set
        .iter()
        .find(|(name, _)| name == SSH_AUTH_SOCK)
        .map(|(_, value)| std::path::PathBuf::from(value))
        .or_else(|| signing.filter(|_| !from_pairs));
    clean_launch(ctx, &paths, &bound, selected.as_deref(), delta, env)
}

/// ⟨M06 W5⟩ [`runner_work`] for a launch that has no binding: `connect` to an
/// existing-access alias on a runner. `agents` are the agent endpoints the alias's own
/// configuration names (never runner-managed: the runner signer's endpoints belong to
/// bindings), so none is passed, each is reported, and an unattended launch that depends on
/// one is refused. Not a runner (`runner` is `None`): the launch is unchanged.
///
/// ⟨ADR-0012 §4 item 5 "An undetermined `IdentityAgent`" ⟨2026-11-22⟩⟩ `undetermined`
/// names the alias and why the static pass cannot determine its `IdentityAgent`
/// ([`undetermined_identity_agent`]): an unattended launch is then refused, because ssh
/// would take the agent from its own configuration, which the clean environment does not
/// control. An attended launch is unchanged.
///
/// # Errors
/// [`runner_work`]'s; and, unattended with `undetermined` set, `CAPABILITY_UNAVAILABLE`,
/// reason `dependency_provenance_unknown`, naming the alias and why. Nothing is launched.
pub(crate) fn runner_work_unbound(
    ctx: &Ctx,
    runner: Option<&heimdall_runtime::Paths>,
    agents: &[std::path::PathBuf],
    undetermined: Option<&UndeterminedAgent>,
    env: &Env,
) -> Result<EnvDelta, Failure> {
    let Some(paths) = runner else {
        return Ok(EnvDelta::default());
    };
    if let Some(refusal) = undetermined.and_then(|u| u.refusal(!ctx.interactive())) {
        return Err(refusal);
    }
    let bound: Vec<heimdall_runtime::runner::launch::BoundAgent> = agents
        .iter()
        .map(|socket| heimdall_runtime::runner::launch::BoundAgent {
            socket: socket.clone(),
            managed: false,
        })
        .collect();
    clean_launch(ctx, paths, &bound, None, EnvDelta::default(), env)
}

/// ⟨M06 W5 `w5n`; ADR-0012 §4 item 5 "An undetermined `IdentityAgent`" ⟨2026-11-22⟩⟩ The
/// first existing-access pair of a binding whose alias's `IdentityAgent` the static pass
/// cannot determine, with why: `run` and `run --parent-binding` on a runner, the same rule
/// and the same helper as `connect` ([`runner_work_unbound`]). A managed-certificate pair's
/// alias is not asked (its endpoint is the runner signer's, named by the binding), nor is
/// a pair without an alias. `observe` gives one alias's observations.
pub(crate) fn undetermined_among(
    pairs: &[heimdall_contract::request::PairIntegration],
    observe: &dyn Fn(&str) -> ProfileObservations,
) -> Option<UndeterminedAgent> {
    pairs
        .iter()
        .filter(|p| p.mechanism != MANAGED_CERTIFICATE)
        .filter_map(|p| p.alias.as_deref())
        .find_map(|alias| {
            undetermined_identity_agent(&observe(alias)).map(|why| UndeterminedAgent {
                alias: alias.to_owned(),
                why,
            })
        })
}

/// ⟨M06 W5 `w5n`⟩ [`undetermined_among`] for the pairs of a binding about to be launched
/// by `run`, on a runner only (`Ok(None)` on every other installation, where the pass is
/// not run for this): each alias's fresh static observation, as [`fresh_selection`] reads
/// it (P's aliases through the projection record, any other through the doctor's static
/// level; nothing executes).
///
/// # Errors
/// [`installation_is_runner`]'s, [`static_config`]'s and [`projection_record`]'s.
pub(crate) async fn runner_undetermined_agent(
    ctx: &Ctx,
    client: &mut Client,
    hooks: &LaunchHooks,
    pairs: &[heimdall_contract::request::PairIntegration],
) -> Result<Option<UndeterminedAgent>, Failure> {
    if installation_is_runner(ctx)?.is_none()
        || !pairs
            .iter()
            .any(|p| p.mechanism != MANAGED_CERTIFICATE && p.alias.is_some())
    {
        return Ok(None);
    }
    let config = static_config(ctx, hooks)?;
    let record = projection_record(client).await?;
    let projected = |alias: &str| {
        record
            .items
            .get(&heimdall_contract::setup::ProjectionItem::Ssh)
            .is_some_and(|r| r.aliases.iter().any(|a| a == alias))
    };
    Ok(undetermined_among(pairs, &|alias| {
        if projected(alias) {
            managed_observations(&config, &record, alias)
        } else {
            observed_observations(&config, alias)
        }
    }))
}

/// An existing-access alias whose `IdentityAgent` the static pass cannot determine
/// ([`undetermined_identity_agent`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UndeterminedAgent {
    /// The alias.
    pub(crate) alias: String,
    /// Why.
    pub(crate) why: String,
}

impl UndeterminedAgent {
    /// The refusal of an unattended launch on a runner; `None` when somebody is present.
    pub(crate) fn refusal(&self, unattended: bool) -> Option<Failure> {
        unattended.then(|| {
            Failure::new(
                Code::CapabilityUnavailable,
                &format!(
                    "the static pass cannot determine the IdentityAgent of alias `{}`: {}; runner work is not launched unattended on an agent whose custody is not established",
                    self.alias, self.why
                ),
                Some(heimdall_contract::envelope::reason::DEPENDENCY_PROVENANCE_UNKNOWN),
            )
        })
    }
}

/// The clean launch of runner work over the agents the launch names ([`runner_work`]).
fn clean_launch(
    ctx: &Ctx,
    paths: &heimdall_runtime::Paths,
    bound: &[heimdall_runtime::runner::launch::BoundAgent],
    selected: Option<&Path>,
    delta: EnvDelta,
    env: &Env,
) -> Result<EnvDelta, Failure> {
    use heimdall_runtime::runner::launch::{AgentSource, SSH_AUTH_SOCK, plan_launch};
    let plan = plan_launch(
        &paths.runtime_dir,
        bound,
        selected,
        |name| env.get(name).map(std::ffi::OsStr::to_os_string),
        !ctx.interactive(),
    )
    .map_err(|e| {
        Failure::of(output::error_value(
            e.with_effect(EffectStatus::None).into_envelope(),
        ))
    })?;
    for agent in plan.agents.iter().filter(|a| !a.passed) {
        let source = match agent.source {
            AgentSource::Binding => "an agent of this binding",
            AgentSource::Inherited => "the inherited agent",
        };
        let looks = agent
            .diagnostic
            .map(|d| format!("; {d}"))
            .unwrap_or_default();
        output::diagnostic(&format!(
            "heimdall: runner work does not get {source} (provenance: {}{looks})",
            agent.provenance.as_str()
        ));
    }
    let kept_out = delta.unset;
    Ok(EnvDelta {
        set: plan
            .environment
            .into_iter()
            .filter(|(name, _)| !kept_out.contains(name))
            .collect(),
        unset: env.iter().map(|(name, _)| name.to_os_string()).collect(),
        overrides: delta
            .overrides
            .into_iter()
            .filter(|o| !(o.setting == SSH_AUTH_SOCK && o.source == OverrideSource::Environment))
            .collect(),
    })
}

// --- ⟨M03⟩ managed launches (ADR-0008 D8 item 2, D10 items 4-5) --------------------------

/// The mechanism name of a managed pair (`PairIntegration.mechanism`).
pub(crate) const MANAGED_CERTIFICATE: &str = "managed_certificate";

/// Whether a binding's integration names a managed pair. Such a launch is **owned**
/// when its program is the verified `ssh` client (ADR-0008 D8 item 2).
pub(crate) fn is_managed(pairs: &[heimdall_contract::request::PairIntegration]) -> bool {
    pairs.iter().any(|p| p.mechanism == MANAGED_CERTIFICATE)
}

/// Whether `program` is the verified `ssh` client of the client inventory (D8 item 2:
/// only a launch of that client is an owned connection). Paths are compared after
/// canonicalization; a path that cannot be canonicalized compares as written.
pub(crate) fn is_verified_ssh(program: &ResolvedProgram, env: &Env) -> bool {
    use heimdall_localenv::clients::{ClientKind, ClientsConfig, selected_path};
    let Some(verified) = selected_path(env, &ClientsConfig::default(), ClientKind::Ssh) else {
        return false;
    };
    let canonical = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    canonical(&program.path) == canonical(&verified)
}

/// D8 item 2: an argument that would move an owned connection out of the launched
/// process, refused before launch: `CONFIG_CONFLICT`, reason
/// `owned_connection_option_conflict`, `prelaunch_failed`. The argument is named by
/// index only.
pub(crate) fn owned_option_conflict(
    conflict: &heimdall_sshconf::render::OwnedOptionConflict,
) -> Failure {
    Failure::new(
        Code::ConfigConflict,
        &format!(
            "{conflict}; Heimdall keeps the connections it owns in the launched process, so nothing was launched"
        ),
        Some(heimdall_contract::envelope::reason::OWNED_CONNECTION_OPTION_CONFLICT),
    )
}

/// The arguments of an owned `ssh` launch: the foreground pins right after the program
/// name, then `args` (D8 item 2), or the refusal of a conflicting argument.
pub(crate) fn owned_ssh_args(args: &[OsString]) -> Result<Vec<OsString>, Failure> {
    heimdall_sshconf::render::owned_ssh_arguments(args).map_err(|c| owned_option_conflict(&c))
}

/// D10 item 5: another binding holds a managed pair's slot: `CONFIG_CONFLICT`, reason
/// `managed_slot_held`, next `release_binding`, `prelaunch_failed`.
pub(crate) fn managed_slot_held(binding: &BindingId) -> Failure {
    let e = heimdall_app::OpError::new(
        Code::ConfigConflict,
        "another binding holds this pair's managed slot; release it, or use `heimdall connect`, which needs no slot; nothing was launched",
    )
    .with_effect(EffectStatus::None)
    .with_reason(heimdall_contract::envelope::reason::MANAGED_SLOT_HELD)
    .with_resource("binding", Some(binding.to_string()))
    .with_next(NextAction {
        action: "release_binding".to_owned(),
        ..NextAction::default()
    });
    Failure::of(output::error_value(e.into_envelope()))
}

/// What a later wave supplies and this build does not have yet: refused
/// `CAPABILITY_UNAVAILABLE`, `driver_unavailable`, before launch (fail closed). The text
/// names the missing part; it is never the retired wave-0 envelope text, which no M02
/// command answers (`cli::tests`).
pub(crate) fn managed_unavailable(what: &str) -> Failure {
    Failure::of(output::error_value(
        heimdall_app::OpError::driver_unavailable(&format!(
            "the managed launch needs {what}, which this runtime does not provide yet; nothing was launched"
        ))
        .into_envelope(),
    ))
}

/// ⟨M03⟩ D8 item 6: the deadline notice of a managed launch on stderr (human output
/// only), worded by the pairs' identity selection: the unqualified text only when every
/// managed pair's selection is `exclusive`.
pub(crate) fn report_deadline(ctx: &Ctx, data: &heimdall_contract::request::EnsureData) {
    use heimdall_contract::managed::ExistingConnectionsMode;
    if ctx.json || !is_managed(&data.consumer.pairs) {
        return;
    }
    let selection = if data
        .consumer
        .pairs
        .iter()
        .filter(|p| p.mechanism == MANAGED_CERTIFICATE)
        .all(|p| p.identity_selection == IdentitySelection::Exclusive)
    {
        IdentitySelection::Exclusive
    } else {
        IdentitySelection::NotExclusive
    };
    let existing = data
        .connection_policy
        .as_ref()
        .map_or(ExistingConnectionsMode::Graceful, |p| p.existing);
    output::diagnostic(&format!(
        "heimdall: {}",
        heimdall_localenv::projection::plan::deadline_wording(selection, existing)
    ));
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use heimdall_contract::doctor::ConfigProvenance;

    /// ⟨M06 W5; ADR-0012 §4 item 5 "An undetermined `IdentityAgent`" ⟨2026-11-22⟩⟩ Which
    /// values of an alias's `IdentityAgent` the static pass cannot determine, and that
    /// only an unattended launch is refused for one, naming the alias and why.
    #[test]
    fn an_undetermined_identity_agent_is_named_and_refused_only_unattended() {
        use heimdall_contract::doctor::{
            AliasDefinition, AliasObservation, DirectiveCertainty, DirectiveObservation,
        };
        let observation = |certainty: DirectiveCertainty, values: &[&str]| AliasObservation {
            alias: "h1".to_owned(),
            definition: AliasDefinition::Observed,
            behavior: vec![DirectiveObservation {
                directive: "IdentityAgent".to_owned(),
                values: values.iter().map(|v| (*v).to_owned()).collect(),
                certainty,
                provenance: Vec::new(),
            }],
            identity_selection: None,
        };
        let every = |o: Option<AliasObservation>| -> ProfileObservations {
            heimdall_launch::eligibility::required_profiles()
                .into_iter()
                .map(|p| (p, o.clone()))
                .collect()
        };
        let why = |certainty, values: &[&str]| {
            undetermined_identity_agent(&every(Some(observation(certainty, values))))
        };
        use DirectiveCertainty::{Determined, Undetermined, Unset};
        // Determined: unset, no agent, the default agent's variable, one explicit endpoint.
        assert_eq!(why(Unset, &[]), None);
        assert_eq!(why(Determined, &[]), None);
        assert_eq!(why(Determined, &["none"]), None);
        assert_eq!(why(Determined, &["SSH_AUTH_SOCK"]), None);
        assert_eq!(why(Determined, &["/run/user/1000/agent.sock"]), None);
        // Undetermined, each with its reason and the profile.
        for (certainty, values, text) in [
            (Determined, &["~/.ssh/agent.sock"][..], "`~` path"),
            (Determined, &["\"~/.ssh/agent.sock\""][..], "`~` path"),
            (Determined, &["/run/%u/agent.sock"][..], "`%` token"),
            (Determined, &["$OTHER_SOCK"][..], "environment variable"),
            (Determined, &["/a.sock", "/b.sock"][..], "several values"),
            (Undetermined, &["/a.sock", "/b.sock"][..], "`Match` block"),
            (Undetermined, &[][..], "`Match` block"),
        ] {
            let got = why(certainty, values).unwrap_or_else(|| panic!("{values:?}"));
            assert!(got.contains(text), "{values:?}: {got}");
            assert!(got.contains("invocation profile `shell`"), "{got}");
        }
        // A profile the pass reported nothing for; and one undetermined profile is enough.
        let nothing = undetermined_identity_agent(&every(None)).unwrap();
        assert!(nothing.contains("could not be evaluated"), "{nothing}");
        assert!(undetermined_identity_agent(&Vec::new()).is_some());
        let mut mixed = every(Some(observation(Determined, &["none"])));
        mixed[1].1 = Some(observation(Determined, &["~/x.sock"]));
        let got = undetermined_identity_agent(&mixed).unwrap();
        assert!(got.contains(&format!("`{}`", mixed[1].0)), "{got}");
        // Only an unattended launch is refused.
        let agent = UndeterminedAgent {
            alias: "h1".to_owned(),
            why: got,
        };
        assert!(agent.refusal(false).is_none());
        let refusal = agent.refusal(true).unwrap();
        assert_eq!(refusal.env.code, Code::CapabilityUnavailable);
        assert_eq!(
            reason_of(&refusal.env).as_deref(),
            Some(heimdall_contract::envelope::reason::DEPENDENCY_PROVENANCE_UNKNOWN)
        );
        let message = refusal.env.data["error"]["message"]
            .as_str()
            .unwrap_or_default();
        assert!(message.contains("alias `h1`"), "{message}");
        assert!(message.contains("`~` path"), "{message}");
    }

    /// ADR-0007 §12.24 item 4: the fallback refusal carries the refused entries' file
    /// and line in `data.error.entries`, in order; a refusal without entries omits the
    /// field.
    #[test]
    fn the_fallback_refusal_fills_error_entries() {
        let at = |line: u32| ConfigProvenance {
            path_display: "~/.ssh/config".to_owned(),
            line,
        };
        let refusal = PrelaunchRefusal {
            reason: PrelaunchReason::FallbackIdentityInteraction,
            pair: 0,
            entries: vec![at(5), at(9)],
        };
        let f = Failure::ineligible(
            &refusal,
            ProviderKind::NativeAgent,
            InteractionKind::Unknown,
        );
        assert_eq!(f.exit, ExitCode::InteractionRequired);
        let error = &f.env.data["error"];
        assert_eq!(error["reason"], "fallback_identity_interaction");
        assert_eq!(
            error["entries"],
            serde_json::json!([
                {"path_display": "~/.ssh/config", "line": 5},
                {"path_display": "~/.ssh/config", "line": 9},
            ])
        );
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("~/.ssh/config:5, ~/.ssh/config:9")
        );
        let none = PrelaunchRefusal {
            reason: PrelaunchReason::InteractionUnknown,
            pair: 0,
            entries: Vec::new(),
        };
        let f = Failure::ineligible(&none, ProviderKind::NativeAgent, InteractionKind::Unknown);
        assert!(f.env.data["error"].get("entries").is_none());
    }

    /// ADR-0007 §12.28 item 7: the re-check's refusal of a binding that is no longer
    /// active is made in `launch_flow` (`confirm_binding_active` returns it): exit 4,
    /// `CREDENTIAL_EXPIRED`, `next: new_work`, effect `none`, the binding as the
    /// resource, reason `binding_released`.
    #[test]
    fn a_binding_that_is_no_longer_active_is_refused_as_binding_released() {
        let binding = BindingId::from_random_bytes([7; 16]);
        let f = binding_released(&binding);
        assert_eq!(f.exit.as_i32(), 4);
        assert_eq!(f.env.code, Code::CredentialExpired);
        let error = &f.env.data["error"];
        assert_eq!(error["reason"], "binding_released");
        assert_eq!(error["effect_status"], "none");
        assert_eq!(error["resource"]["kind"], "binding");
        assert_eq!(error["resource"]["id"], binding.to_string());
        assert_eq!(f.env.next.as_ref().unwrap().action, "new_work");
    }

    /// A scratch layout for the static pass: the account's real home holds a segment
    /// that stands for the account name, and the configured home reaches it through a
    /// symlink (as `/var` reaches `/private/var` on macOS). P names the adopted key for
    /// `alpha` under `IdentitiesOnly yes`; the user file includes P and appends
    /// `extra`.
    #[cfg(unix)]
    struct Layout {
        _dir: tempfile::TempDir,
        real: std::path::PathBuf,
        link: std::path::PathBuf,
        config: ProjectionConfig,
        record: ProjectionRecord,
    }

    #[cfg(unix)]
    const NAME_SEGMENT: &str = "hm-fixture-account-name";

    #[cfg(unix)]
    impl Layout {
        fn new(extra: &str) -> Layout {
            use heimdall_contract::setup::ProjectionItem;
            use heimdall_domain::projection::{
                FileIdentity, FileRole, ItemRecord, ProjectionLocator, Sha256Hex,
            };
            let dir = tempfile::tempdir().unwrap();
            let real = dir.path().join("real").join(NAME_SEGMENT);
            std::fs::create_dir_all(real.join(".ssh")).unwrap();
            let link = dir.path().join("home");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            let config_dir = dir.path().join("config");
            std::fs::create_dir_all(&config_dir).unwrap();
            let key = config_dir.join("alpha.pub");
            std::fs::write(&key, "ssh-ed25519 AAAA fixture\n").unwrap();
            std::fs::write(
                config_dir.join("ssh_config"),
                format!(
                    "Host alpha\n  IdentityFile \"{}\"\n  IdentitiesOnly yes\n",
                    key.display()
                ),
            )
            .unwrap();
            std::fs::write(
                link.join(".ssh").join("config"),
                format!(
                    "Include \"{}\"\n{extra}",
                    config_dir.join("ssh_config").display()
                ),
            )
            .unwrap();
            let paths = SshPaths::with_test_override(link.clone(), dir.path().join("etc-ssh"));
            let mut config = ProjectionConfig::new(paths, Platform::current(), config_dir);
            // ADR-0007 §12.32 item 11: an unknown client version takes the strictest
            // reading (no `Match sessiontype`), so the layout names an observed client
            // that evaluates every invocation profile (OpenSSH 10.5p1).
            config.clients = heimdall_localenv::clients::ClientInventory {
                candidates: vec![heimdall_localenv::clients::ClientCandidate {
                    kind: heimdall_localenv::clients::ClientKind::Ssh,
                    path: dir.path().join("bin").join("ssh"),
                    source: heimdall_localenv::clients::ClientSource::Path,
                    version: Some(heimdall_sshconf::eval::OpenSshVersion {
                        major: 10,
                        minor: 5,
                        portable: Some(1),
                    }),
                    sha256: None,
                    identity: None,
                    selected: true,
                }],
            };
            let environment = heimdall_contract::ids::EnvironmentId::from_random_bytes([4; 16]);
            let record = ProjectionRecord {
                environment,
                items: [(
                    ProjectionItem::Ssh,
                    ItemRecord {
                        generation: 1,
                        files: vec![ProjectionLocator {
                            role: FileRole::Key,
                            path: key.display().to_string(),
                            identity: FileIdentity::Unix {
                                dev: 1,
                                ino: 2,
                                birth: None,
                            },
                            sha256: Sha256Hex::of(b"fixture"),
                        }],
                        aliases: vec!["alpha".to_owned()],
                        include_file: None,
                        operation: OperationId::from_random_bytes([3; 16]),
                        committed_at: heimdall_contract::Timestamp::now(),
                    },
                )]
                .into_iter()
                .collect(),
            };
            Layout {
                _dir: dir,
                real,
                link,
                config,
                record,
            }
        }

        fn selection(&self) -> FreshSelection {
            fresh_selection(&self.config, &self.record, Some("alpha"))
        }
    }

    /// The user-sourced entries' provenance of one report.
    #[cfg(unix)]
    fn user_entries(report: &IdentitySelectionReport) -> Vec<ConfigProvenance> {
        report
            .entries
            .iter()
            .filter(|e| e.source == heimdall_contract::provider::IdentityEntrySource::User)
            .filter_map(|e| e.provenance.clone())
            .collect()
    }

    /// ADR-0007 §12.25 item 1 (T01): the fresh selection carries every invocation
    /// profile, `shell` in its own report and `exec` and `subsystem:sftp` in
    /// `profiles`, each evaluated under its own invocation: an `IdentityFile` behind
    /// `Match sessiontype exec` is in the `exec` profile's report only, one behind
    /// `Match sessiontype subsystem` in the `subsystem:sftp` profile's only.
    #[cfg(unix)]
    #[test]
    fn the_fresh_selection_evaluates_every_invocation_profile() {
        let names = |s: &FreshSelection| -> Vec<String> {
            s.profiles.iter().map(|p| p.profile.clone()).collect()
        };
        let at = |line: u32| ConfigProvenance {
            path_display: "~/.ssh/config".to_owned(),
            line,
        };
        let l = Layout::new(
            "Match sessiontype exec\n  IdentityFile \"~/k2.pub\"\nMatch sessiontype subsystem\n  IdentityFile \"~/k3.pub\"\n",
        );
        let s = l.selection();
        assert_eq!(names(&s), ["exec", "subsystem:sftp"]);
        assert_eq!(
            s.report.selection,
            IdentitySelection::Exclusive,
            "{:?}",
            s.report
        );
        assert!(user_entries(&s.report).is_empty());
        assert_eq!(user_entries(&s.profiles[0].report), [at(3)]);
        assert_ne!(s.profiles[0].report.selection, IdentitySelection::Exclusive);
        assert_eq!(user_entries(&s.profiles[1].report), [at(5)]);
        assert_ne!(s.profiles[1].report.selection, IdentitySelection::Exclusive);
        // No alias: every profile undetermined.
        let none = fresh_selection(&l.config, &l.record, None);
        assert_eq!(names(&none), ["exec", "subsystem:sftp"]);
        assert!(
            std::iter::once(&none.report)
                .chain(none.profiles.iter().map(|p| &p.report))
                .all(|r| r.selection == IdentitySelection::Undetermined)
        );
    }

    /// ADR-0007 §12.26 item 7: with the account home reached through a symlink, every
    /// entry of the pre-launch check's fresh selection is shown as `~/.ssh/config`, so
    /// the refusal's `data.error.entries` and message never show the home's absolute
    /// path nor the account-name segment it holds. A path outside the home is shown as
    /// written.
    #[cfg(unix)]
    #[test]
    fn refusal_entries_show_a_home_behind_a_symlink_as_tilde() {
        let l = Layout::new(
            "Host *\n  IdentityFile \"~/k2.pub\"\n  IdentityFile \"/hm-fixture-outside/k4.pub\"\n",
        );
        let s = l.selection();
        let expected = [
            ConfigProvenance {
                path_display: "~/.ssh/config".to_owned(),
                line: 3,
            },
            ConfigProvenance {
                path_display: "~/.ssh/config".to_owned(),
                line: 4,
            },
        ];
        assert_eq!(user_entries(&s.report), expected);
        for p in &s.profiles {
            assert_eq!(user_entries(&p.report), expected, "{}", p.profile);
        }
        let refusal = PrelaunchRefusal {
            reason: PrelaunchReason::FallbackIdentityInteraction,
            pair: 0,
            entries: user_entries(&s.report),
        };
        let f = Failure::ineligible(
            &refusal,
            ProviderKind::NativeAgent,
            InteractionKind::Unknown,
        );
        let text = serde_json::to_string(&f.env).unwrap();
        for absent in [
            NAME_SEGMENT.to_owned(),
            l.real.display().to_string(),
            l.link.display().to_string(),
            std::fs::canonicalize(&l.real)
                .unwrap()
                .display()
                .to_string(),
        ] {
            assert!(!text.contains(&absent), "{text}");
        }
        assert!(
            f.env.data["error"]["message"]
                .as_str()
                .unwrap()
                .contains("~/.ssh/config:3, ~/.ssh/config:4")
        );
        // Outside the home: shown as written.
        assert_eq!(
            heimdall_localenv::doctor::path_display(
                std::path::Path::new("/hm-fixture-outside/x"),
                &l.link
            ),
            "/hm-fixture-outside/x"
        );
    }

    /// ADR-0007 §12.28 item 6: a file outside the account home is shown in the
    /// pre-launch check's entries as the configuration names it, never in its canonical
    /// form. An `Include` of a file reached through a symlinked directory shows the
    /// link's path, in every profile, and the refusal's entries and message carry it;
    /// P, under Heimdall's configuration directory, shows its configured path (on macOS
    /// the scratch directory lies under `/var`, whose canonical form is `/private/var`).
    #[cfg(unix)]
    #[test]
    fn a_path_outside_the_home_is_shown_as_written_not_canonicalized() {
        let outside = tempfile::tempdir().unwrap();
        let real = outside.path().join("hm-fixture-real-dir");
        std::fs::create_dir_all(&real).unwrap();
        let link = outside.path().join("hm-fixture-link-dir");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        std::fs::write(
            real.join("extra.conf"),
            "Host *\n  IdentityFile \"/hm-fixture-outside/k4.pub\"\n",
        )
        .unwrap();
        let written = link.join("extra.conf");
        let canonical = std::fs::canonicalize(&written).unwrap();
        assert_ne!(
            written, canonical,
            "the fixture reaches the file through a link"
        );
        let l = Layout::new(&format!("Include \"{}\"\n", written.display()));
        let s = l.selection();
        let expected = [ConfigProvenance {
            path_display: written.display().to_string(),
            line: 2,
        }];
        assert_eq!(user_entries(&s.report), expected);
        for p in &s.profiles {
            assert_eq!(user_entries(&p.report), expected, "{}", p.profile);
        }
        // P's own entry: its configured path, not the canonical one.
        let managed: Vec<String> = s
            .report
            .entries
            .iter()
            .filter(|e| e.source == heimdall_contract::provider::IdentityEntrySource::Managed)
            .filter_map(|e| e.provenance.as_ref().map(|p| p.path_display.clone()))
            .collect();
        assert_eq!(
            managed,
            [l.config.managed_ssh_path().display().to_string()],
            "P as configured"
        );
        let refusal = PrelaunchRefusal {
            reason: PrelaunchReason::FallbackIdentityInteraction,
            pair: 0,
            entries: user_entries(&s.report),
        };
        let f = Failure::ineligible(
            &refusal,
            ProviderKind::NativeAgent,
            InteractionKind::Unknown,
        );
        let text = serde_json::to_string(&f.env).unwrap();
        assert!(text.contains(&format!("{}:2", written.display())), "{text}");
        assert!(!text.contains(&canonical.display().to_string()), "{text}");
        assert!(!text.contains("hm-fixture-real-dir"), "{text}");
    }
}
