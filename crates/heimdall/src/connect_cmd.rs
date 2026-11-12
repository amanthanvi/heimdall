//! `heimdall connect <alias>` (m02-plan U8; ADR-0007 §8).
//!
//! `run` without a profile binding, for an ordinary alias: the projection already
//! supplies the configuration (spec §10.3). In order:
//! 1. the side channel (as `run`);
//! 2. the alias is checked: a known destination (managed or observed); a word that
//!    `ssh` would read as an option (a leading `-`), or one with whitespace or a
//!    control character, is a usage error;
//! 3. the verified client: Unix `ssh` from `PATH`; Windows the in-box
//!    `%WINDIR%\System32\OpenSSH\ssh.exe` (ADR-0004 E6), resolved without a shell; its
//!    path and SHA-256 are reported on stderr (R-SS-03);
//! 4. under `--non-interactive` without `--allow-provider-interaction`, the pre-launch
//!    eligibility check for the alias's identity, from the command's first `inspect
//!    identities` to a fresh one taken immediately before launch;
//! 5. `exec` (Unix) or spawn and wait (Windows) of `ssh <alias>`, with no environment
//!    addition.
//!
//! **Observed aliases (ADR-0007 §12.24 item 1).** `inspect destinations` lists the
//! catalog: each destination with its alias and definition (`managed`, `observed`).
//! A destination is known when the listing names its alias, whatever its definition;
//! a runtime that does not list the catalog yet (`NOT_LISTED`, an empty listing) falls
//! back to the stored projection record's managed aliases. An observed alias then goes
//! through the same pre-launch check as a managed one; its fresh static selection is
//! taken over the user's own configuration (`launch_flow::fresh_observed_selection`,
//! the doctor's passive static level: nothing executes, no agent is contacted), since
//! P has no section for it.
//!
//! **The alias's identity (fail closed).** The check needs the identity the launch
//! relies on. For a managed alias it is the adopted key its managed entry carries. An
//! observed alias has no managed entry; its identity is the adopted key named by
//! fingerprint in the first of its own entries (in ssh's order) that names one. The
//! check reads an observed alias's entries as alternatives, each cleared only by the
//! one domain rule like any fallback, so it launches only when every entry is an
//! agent-backed adopted key declared `none` at the alias's agent, under `IdentitiesOnly
//! yes`. An alias whose entries name no adopted identity is refused
//! (`interaction_unknown`): which key ssh would use is not known.
//!
//! `connect` binds nothing (its records name no operation or binding), so the
//! binding re-check `run` does before `launching` (§12.24 item 2) has nothing to
//! confirm here.
//!
//! **⟨M03⟩ A managed pair** (ADR-0008 D8 item 2, D10 item 4; m03-plan U8). When the
//! listing names the alias's pair preference `managed_certificate` with its projection
//! `applied` (`"preference": {"mechanism", "projection": {"state"}}`; a listing without
//! it reads as existing access, so the M02 flow above is unchanged):
//! 1. the pair is resolved from the listing (`destination_id`, `account`);
//! 2. `ensure` for that single pair under the one profile of the environment whose scope
//!    contains it; none (or more than one: no default can be chosen, U8-Q5) is
//!    `CAPABILITY_UNAVAILABLE`, `no_profile_covers_destination`. The request ID is
//!    fresh (random), so it is never a replay;
//! 3. `bind` with `Launch { executable, holder }`, this process holding the reference
//!    (as `run`; on Unix the exec makes the client the holder);
//! 4. under `--non-interactive`, `run`'s pre-launch check over the bound pairs;
//! 5. the launch of the verified client, in the foreground: the pins right after the
//!    program name, then the **binding's** endpoint and files on the command line
//!    (`-o IdentityAgent=…`, `-o IdentitiesOnly=yes` and the identity options of the
//!    one form selector, `heimdall_sshconf::render::managed_identity_options`), then the
//!    alias. The binding endpoint is the bind result's `consumer.signing_endpoint`, and
//!    its files are `key.pub` and `cert-<destination-id>.pub` in the binding's
//!    directory `<runtime_dir>/b/<16 hex>/` (ADR-0008 D6 item 1 step 6; reading R6).
//!
//! ⟨M03 wave 4, round 3 (ADR-0008 §17.22 item 13; R2C-Q2)⟩ The runtime names the binding
//! endpoint in the `bind` result from its endpoint registry, for that exact live binding
//! (`OperationsDispatcher::with_binding_endpoints`); a result that names none (the
//! endpoint is not live) refuses before launch, `driver_unavailable`
//! ([`managed_launch_args`]). On Windows the launch needs U7's contained spawn, so it is
//! refused there (fail closed).

use heimdall_contract::ids::{ProfileId, WorkId};
use heimdall_contract::provider::IdentityEntrySource;
use heimdall_contract::request::{
    AccessPairRef, BindForm, BindRequest, EnsureData, EnsureRequest, InspectRequest,
    InspectSubject, LaunchBinding, ProcessHolder, Request, WaitMode,
};
use heimdall_contract::setup::ProjectionItem;
use heimdall_contract::{Code, ExitCode};
use heimdall_launch::eligibility::{
    BoundPair, IdentitiesView, IdentityView, PrelaunchReason, PrelaunchRefusal,
    check_noninteractive, check_pairs,
};
use heimdall_launch::env::EnvDelta;
use heimdall_launch::resolve::resolve_program;
use heimdall_localenv::clients::{ClientKind, ClientsConfig, selected_path, sha256_file};
use heimdall_localenv::env::{Env, Platform};

use crate::cli::{ConnectArgs, TerminalPrompt, ensure_flow, fresh_request_id};
use crate::client::{Client, Ctx, connect_as};
use crate::launch_flow::{self, Failure, Launch};
use crate::output;
use crate::testcfg;

/// The longest alias `connect` passes to `ssh`.
const MAX_ALIAS_BYTES: usize = 255;

/// The bounded wait for a managed pair's `ensure` (as `run`'s).
const ENSURE_TIMEOUT_MS: u64 = 30_000;

/// Handle `connect`.
pub(crate) fn run(ctx: &Ctx, args: ConnectArgs) -> ExitCode {
    let ConnectArgs {
        destination: alias,
        launch,
    } = args;
    let hooks = match testcfg::launch_hooks(&|n| std::env::var_os(n)) {
        Ok(h) => h,
        Err(m) => return launch_flow::fail(ctx, &mut None, Failure::usage(&m)),
    };
    let mut meta = match launch_flow::open_side_channel(&launch) {
        Ok(m) => m,
        Err(f) => return launch_flow::fail(ctx, &mut None, f),
    };
    if alias.is_empty()
        || alias.len() > MAX_ALIAS_BYTES
        || alias.starts_with('-')
        || alias.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return launch_flow::fail(
            ctx,
            &mut meta,
            Failure::usage("the destination must be an alias (no leading '-', no spaces)"),
        );
    }
    let env = Env::capture();
    let platform = Platform::current();
    let Some(client_path) = selected_path(&env, &ClientsConfig::default(), ClientKind::Ssh) else {
        return launch_flow::fail(
            ctx,
            &mut meta,
            Failure::refused(heimdall_launch::resolve::LaunchRefusal::NotFound),
        );
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"));
    let program = match resolve_program(client_path.as_os_str(), &env, &cwd, platform) {
        Ok(p) => p,
        Err(r) => return launch_flow::fail(ctx, &mut meta, Failure::refused(r)),
    };
    let rt = match crate::service_cmd::current_thread() {
        Ok(rt) => rt,
        Err(e) => {
            return launch_flow::fail(ctx, &mut meta, Failure::of(output::error_value(e)));
        }
    };
    let interaction = launch_flow::interaction(ctx, &launch);
    let check = launch_flow::no_interaction_path(ctx, &launch);
    let checked = rt.block_on(async {
        let mut client = connect_as(ctx, true, &[], interaction)
            .await
            .map_err(|e| Failure::of(output::error_value(*e)))?;
        let Some(known) = known_destination(&mut client, &alias).await? else {
            return Err(Failure::new(
                Code::NotFound,
                "unknown destination: the alias is not a managed or observed destination",
                None,
            ));
        };
        if let Some(pair) = known.managed.clone() {
            let flow = ManagedConnect {
                alias: &alias,
                pair,
                program: &program,
                interaction,
                check,
            };
            return flow.run(ctx, &mut client, &hooks).await.map(Some);
        }
        if check {
            eligible(ctx, &mut client, &alias, known.definition, &hooks).await?;
        }
        Ok(None)
    });
    rt.shutdown_background();
    let managed = match checked {
        Ok(m) => m,
        Err(f) => return launch_flow::fail(ctx, &mut meta, f),
    };
    let (args, meta) = match managed {
        None => (vec![std::ffi::OsString::from(&alias)], meta),
        Some(m) => (
            m.args,
            launch_flow::with_ids(meta, m.operation, Some(m.binding)),
        ),
    };
    if !ctx.json {
        let digest = sha256_file(&program.path).unwrap_or_else(|| "unknown".to_owned());
        output::diagnostic(&format!(
            "heimdall: verified client {} (sha256 {digest})",
            program.path.display()
        ));
    }
    launch_flow::launch(
        ctx,
        Launch {
            program,
            args,
            delta: EnvDelta::default(),
            meta,
            hooks,
        },
    )
}

/// A known destination: its definition and, for a managed pair whose projection is
/// applied, the pair (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Known {
    definition: Definition,
    managed: Option<AccessPairRef>,
}

/// The pair of a listed destination whose preference is `managed_certificate` with its
/// projection `applied` (module docs), `None` otherwise: no `preference`, another
/// mechanism, a pending projection, or a pair that cannot be read (all M02's flow).
fn managed_pair_of(item: &serde_json::Value) -> Option<AccessPairRef> {
    let preference = item.get("preference")?;
    if preference.get("mechanism").and_then(|m| m.as_str())
        != Some(launch_flow::MANAGED_CERTIFICATE)
    {
        return None;
    }
    let projection = preference.get("projection")?;
    let state = projection
        .as_str()
        .or_else(|| projection.get("state").and_then(|s| s.as_str()));
    if state != Some("applied") {
        return None;
    }
    Some(AccessPairRef {
        destination: serde_json::from_value(item.get("destination_id")?.clone()).ok()?,
        account: serde_json::from_value(item.get("account")?.clone()).ok()?,
    })
}

/// What the managed flow hands to the launch.
struct ManagedLaunch {
    args: Vec<std::ffi::OsString>,
    operation: Option<heimdall_contract::ids::OperationId>,
    binding: heimdall_contract::ids::BindingId,
}

/// ⟨M03⟩ `connect` for a managed pair (module docs; ADR-0008 D8 item 2).
struct ManagedConnect<'a> {
    alias: &'a str,
    pair: AccessPairRef,
    program: &'a heimdall_launch::resolve::ResolvedProgram,
    interaction: heimdall_contract::request::InteractionMode,
    check: bool,
}

impl ManagedConnect<'_> {
    async fn run(
        self,
        ctx: &Ctx,
        client: &mut Client,
        hooks: &testcfg::LaunchHooks,
    ) -> Result<ManagedLaunch, Failure> {
        // 2. The covering profile, then `ensure` for the single pair.
        let profile = covering_profile(client, &self.pair).await?;
        let request_id = fresh_request_id().map_err(|d| Failure::of(d.env))?;
        let work_id =
            WorkId::parse(request_id.as_str()).map_err(|_| Failure::usage("invalid work ID"))?;
        let request = EnsureRequest {
            profile,
            profile_revision: None,
            scope: std::iter::once(self.pair.clone()).collect(),
            environment: None,
            work_id,
            until: None,
            required_capabilities: Default::default(),
            request_id: request_id.clone(),
            interaction: self.interaction,
            wait: WaitMode::Sync {
                timeout_ms: ENSURE_TIMEOUT_MS,
            },
            connection: None,
        };
        let ensured = ensure_flow(client, &mut TerminalPrompt, ctx, request, false).await;
        if ensured.env.code != Code::AccessReady {
            return Err(Failure::of(ensured.env));
        }
        let data: EnsureData = serde_json::from_value(ensured.env.data.clone()).map_err(|_| {
            Failure::new(
                Code::InternalError,
                "the ensure result cannot be read",
                None,
            )
        })?;
        // 3. bind(launch), this process holding the reference.
        let executable = self
            .program
            .path
            .to_str()
            .ok_or_else(|| {
                Failure::refused(heimdall_launch::resolve::LaunchRefusal::PathNotUnicode)
            })?
            .to_owned();
        let holder =
            heimdall_runtime::platform::process_start_time(std::process::id()).map(|started_at| {
                ProcessHolder {
                    pid: std::process::id(),
                    started_at,
                }
            });
        let bound = client
            .request(Request::Bind(BindRequest {
                binding_id: data.binding_id.clone(),
                form: BindForm::Launch(LaunchBinding { executable, holder }),
                request_id,
            }))
            .await;
        let operation = bound.operation_id.clone();
        if bound.code != Code::AccessReady {
            return Err(Failure::of(bound));
        }
        let bound_data: EnsureData = serde_json::from_value(bound.data.clone()).map_err(|_| {
            Failure::new(Code::InternalError, "the bind result cannot be read", None)
        })?;
        // 4. The pre-launch check over the bound pairs, on fresh views.
        if self.check {
            let fresh = launch_flow::fresh_identities(client).await?;
            let record = launch_flow::projection_record(client).await?;
            let config = launch_flow::static_config(ctx, hooks)?;
            let pairs = &bound_data.consumer.pairs;
            let selections: Vec<_> = pairs
                .iter()
                .map(|p| launch_flow::fresh_selection(&config, &record, p.alias.as_deref()))
                .collect();
            if let Err(refusal) = check_noninteractive(pairs, &fresh, &selections, hooks.now()) {
                let (provider, kind) = launch_flow::refusal_provider(None, &fresh, None);
                return Err(Failure::ineligible(&refusal, provider, kind));
            }
        }
        launch_flow::confirm_binding_active(client, &data.binding_id).await?;
        // 5. The binding's endpoint and files on the command line, in the foreground.
        let args = managed_connect_args(ctx, self.alias, &self.pair, &bound_data)?;
        launch_flow::report_deadline(ctx, &bound_data);
        Ok(ManagedLaunch {
            args,
            operation,
            binding: data.binding_id,
        })
    }
}

/// The one profile of the environment whose scope contains `pair` (module docs).
async fn covering_profile(client: &mut Client, pair: &AccessPairRef) -> Result<ProfileId, Failure> {
    let listed = client
        .request(Request::Inspect(InspectRequest {
            subject: InspectSubject::Profiles,
            preview: None,
        }))
        .await;
    if !listed.code.is_success() {
        return Err(Failure::of(listed));
    }
    choose_covering(&listed_items(&listed.data), pair)
}

/// The one profile among `profiles` (an `inspect profiles` listing) whose scope pairs
/// contain `pair`: none, or more than one (no default can be chosen, U8-Q5), is
/// `CAPABILITY_UNAVAILABLE`, `no_profile_covers_destination` (ADR-0008 D8 item 2).
fn choose_covering(
    profiles: &[serde_json::Value],
    pair: &AccessPairRef,
) -> Result<ProfileId, Failure> {
    let covering: Vec<ProfileId> = profiles
        .iter()
        .filter(|p| {
            p.get("pairs")
                .and_then(|v| serde_json::from_value::<Vec<AccessPairRef>>(v.clone()).ok())
                .is_some_and(|pairs| pairs.contains(pair))
        })
        .filter_map(|p| serde_json::from_value(p.get("profile_id")?.clone()).ok())
        .collect();
    match covering.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(Failure::new(
            Code::CapabilityUnavailable,
            if covering.is_empty() {
                "no profile of this environment covers the destination; add it to a profile, or use `heimdall run --profile`"
            } else {
                "more than one profile covers the destination, so connect cannot choose one; use `heimdall run --profile`"
            },
            Some(heimdall_contract::envelope::reason::NO_PROFILE_COVERS_DESTINATION),
        )),
    }
}

/// The arguments of a managed `connect` (module docs, step 5): the foreground pins, the
/// binding's identity options, then the alias.
fn managed_connect_args(
    ctx: &Ctx,
    alias: &str,
    pair: &AccessPairRef,
    bound: &EnsureData,
) -> Result<Vec<std::ffi::OsString>, Failure> {
    managed_launch_args(
        || {
            ctx.paths()
                .map(|p| p.runtime_dir)
                .map_err(|e| Failure::of(output::error_value(*e)))
        },
        alias,
        pair,
        bound,
    )
}

/// [`managed_connect_args`] over the runtime directory `runtime_dir` yields. ⟨ADR-0008
/// §17.22 item 13 (R2C-Q2)⟩ The binding endpoint is only ever the bind result's
/// `consumer.signing_endpoint`, which the runtime reads from its registry for that exact
/// live binding: a managed result that names none (the endpoint is not live), or names
/// one that is not a binding endpoint of this runtime, refuses here, before launch
/// (`CAPABILITY_UNAVAILABLE`, `driver_unavailable`), never falling back to the alias or
/// the environment endpoint.
fn managed_launch_args(
    runtime_dir: impl FnOnce() -> Result<std::path::PathBuf, Failure>,
    alias: &str,
    pair: &AccessPairRef,
    bound: &EnsureData,
) -> Result<Vec<std::ffi::OsString>, Failure> {
    if !launch_flow::is_managed(&bound.consumer.pairs) {
        // Resolution changed since the listing (a pending projection, ADR-0008 D5
        // §6.6): the existing mechanism's binding, launched as M02 launches an alias.
        return Ok(vec![std::ffi::OsString::from(alias)]);
    }
    if cfg!(windows) {
        return Err(launch_flow::managed_unavailable(
            "the contained launch of the verified ssh client (Windows)",
        ));
    }
    let runtime_dir = runtime_dir()?;
    let files = bound
        .consumer
        .signing_endpoint
        .as_deref()
        .and_then(|e| binding_files(e, &runtime_dir, &pair.destination, Platform::current()));
    let Some(files) = files else {
        return Err(launch_flow::managed_unavailable(
            "the binding endpoint of this managed binding",
        ));
    };
    let options = heimdall_sshconf::render::managed_identity_options(
        &files.endpoint,
        &files.key_pub,
        &files.cert,
        files.style,
        heimdall_sshconf::render::ManagedIdentityForm::select(None),
    )
    .map_err(|_| {
        launch_flow::managed_unavailable("a binding endpoint Heimdall can name on the command line")
    })?;
    let mut args: Vec<std::ffi::OsString> = heimdall_sshconf::render::OWNED_LAUNCH_PINS
        .iter()
        .map(std::ffi::OsString::from)
        .collect();
    args.extend(options.into_iter().map(std::ffi::OsString::from));
    args.push(std::ffi::OsString::from(alias));
    Ok(args)
}

/// A binding's endpoint and files, as the command line names them.
struct BindingFiles {
    endpoint: heimdall_sshconf::render::RenderPath,
    key_pub: heimdall_sshconf::render::RenderPath,
    cert: heimdall_sshconf::render::RenderPath,
    style: heimdall_sshconf::render::PathStyle,
}

/// The binding's files beside its endpoint (ADR-0008 D6 item 1 step 6; reading R6):
/// Unix `<runtime_dir>/b/<16 hex>/agent.sock` gives `<runtime_dir>/b/<16 hex>/key.pub`
/// and `cert-<destination-id>.pub`; Windows `\\.\pipe\heimdall-<token>-b<16 hex>`
/// gives the same directory under the runtime directory. Anything else is `None` (the
/// endpoint is not a binding endpoint of this runtime: fail closed).
fn binding_files(
    endpoint: &str,
    runtime_dir: &std::path::Path,
    destination: &heimdall_contract::ids::DestinationId,
    platform: Platform,
) -> Option<BindingFiles> {
    use heimdall_sshconf::render::{PathStyle, RenderPath};
    let hex16 =
        |s: &str| s.len() == 16 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
    let component = heimdall_localenv::projection::content::slot_component(destination).ok()?;
    let cert_name = format!("cert-{component}.pub");
    if platform.is_windows() {
        let name = endpoint.strip_prefix(r"\\.\pipe\")?;
        let (_, hex) = name.strip_prefix("heimdall-")?.rsplit_once("-b")?;
        if !hex16(hex) {
            return None;
        }
        let dir = runtime_dir.join("b").join(hex);
        return Some(BindingFiles {
            endpoint: RenderPath::pipe(endpoint).ok()?,
            key_pub: RenderPath::windows(&dir.join("key.pub")).ok()?,
            cert: RenderPath::windows(&dir.join(cert_name)).ok()?,
            style: PathStyle::Windows,
        });
    }
    let socket = std::path::Path::new(endpoint);
    if socket.file_name()? != "agent.sock" {
        return None;
    }
    let dir = socket.parent()?;
    let hex = dir.file_name()?.to_str()?;
    if !hex16(hex) || dir.parent()? != runtime_dir.join("b") {
        return None;
    }
    Some(BindingFiles {
        endpoint: RenderPath::unix(socket).ok()?,
        key_pub: RenderPath::unix(&dir.join("key.pub")).ok()?,
        cert: RenderPath::unix(&dir.join(cert_name)).ok()?,
        style: PathStyle::Unix,
    })
}

/// How the catalog defines a known destination (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Definition {
    /// Rendered into P (or a listing that names no definition: read strictly).
    Managed,
    /// Defined in the user's own configuration.
    Observed,
}

/// The definition a listed destination names: `"definition": "observed"` or
/// `"definition": {"kind": "observed", …}`. Anything else is read as managed, the
/// stricter identity rule.
fn definition_of(item: &serde_json::Value) -> Definition {
    let definition = item.get("definition");
    let kind = definition.and_then(|d| d.as_str()).or_else(|| {
        definition
            .and_then(|d| d.get("kind"))
            .and_then(|k| k.as_str())
    });
    if kind == Some("observed") {
        Definition::Observed
    } else {
        Definition::Managed
    }
}

/// The destinations an `inspect destinations` answer lists (`destinations`, or
/// `items` as an answer without the catalog has it).
fn listed_items(data: &serde_json::Value) -> Vec<serde_json::Value> {
    ["destinations", "items"]
        .iter()
        .find_map(|k| data.get(*k).and_then(|v| v.as_array()))
        .cloned()
        .unwrap_or_default()
}

/// `alias`'s definition when it is a known destination, `None` otherwise (module
/// docs).
async fn known_destination(client: &mut Client, alias: &str) -> Result<Option<Known>, Failure> {
    let listed = client
        .request(Request::Inspect(InspectRequest {
            subject: InspectSubject::Destinations,
            preview: None,
        }))
        .await;
    if !listed.code.is_success() {
        return Err(Failure::of(listed));
    }
    if let Some(item) = listed_items(&listed.data)
        .iter()
        .find(|d| d.get("alias").and_then(|a| a.as_str()) == Some(alias))
    {
        return Ok(Some(Known {
            definition: definition_of(item),
            managed: managed_pair_of(item),
        }));
    }
    let record = launch_flow::projection_record(client).await?;
    Ok(record
        .items
        .get(&ProjectionItem::Ssh)
        .is_some_and(|r| r.aliases.iter().any(|a| a == alias))
        .then_some(Known {
            definition: Definition::Managed,
            managed: None,
        }))
}

/// The adopted identity the launch relies on (module docs): for a managed alias the
/// one a managed entry carries; for an observed alias the first one its entries name.
fn alias_identity<'v>(
    identities: &'v IdentitiesView,
    entries: &[heimdall_contract::provider::IdentityEntry],
    definition: Definition,
) -> Option<&'v IdentityView> {
    entries
        .iter()
        .filter(|e| match definition {
            Definition::Managed => e.source == IdentityEntrySource::Managed,
            Definition::Observed => true,
        })
        .find_map(|e| {
            let fingerprint = e.fingerprint.as_deref()?;
            identities
                .identities
                .iter()
                .find(|v| v.fingerprint == fingerprint)
        })
}

/// The alias's fresh static selection: over P for a managed alias, over the user's own
/// configuration for an observed one (`launch_flow::fresh_observed_selection`).
async fn alias_selection(
    client: &mut Client,
    config: &heimdall_localenv::projection::ProjectionConfig,
    alias: &str,
    definition: Definition,
) -> Result<heimdall_launch::eligibility::FreshSelection, Failure> {
    Ok(match definition {
        Definition::Managed => {
            let record = launch_flow::projection_record(client).await?;
            launch_flow::fresh_selection(config, &record, Some(alias))
        }
        Definition::Observed => launch_flow::fresh_observed_selection(config, alias),
    })
}

/// The pre-launch check for the alias's identity (module docs).
async fn eligible(
    ctx: &Ctx,
    client: &mut Client,
    alias: &str,
    definition: Definition,
    hooks: &testcfg::LaunchHooks,
) -> Result<(), Failure> {
    let config = launch_flow::static_config(ctx, hooks)?;
    let first = launch_flow::fresh_identities(client).await?;
    let selection = alias_selection(client, &config, alias, definition).await?;
    let adopted = alias_identity(&first, &selection.report.entries, definition);
    let Some(view) = adopted else {
        let refusal = PrelaunchRefusal {
            reason: PrelaunchReason::InteractionUnknown,
            pair: 0,
            entries: Vec::new(),
        };
        let (provider, kind) = launch_flow::refusal_provider(None, &first, None);
        return Err(Failure::ineligible(&refusal, provider, kind));
    };
    let bound = BoundPair::from_view(view, alias);
    launch_flow::pause(hooks.pre_check_pause.as_deref());
    let fresh = launch_flow::fresh_identities(client).await?;
    let selection = alias_selection(client, &config, alias, definition).await?;
    check_pairs(
        std::slice::from_ref(&bound),
        &fresh,
        std::slice::from_ref(&selection),
        hooks.now(),
    )
    .map_err(|refusal| {
        let (provider, kind) = launch_flow::refusal_provider(None, &fresh, Some(&bound.identity));
        Failure::ineligible(&refusal, provider, kind)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use heimdall_contract::ids::IdentityId;
    use heimdall_contract::provider::{
        Certainty, IdentityBacking, IdentityEntry, IdentityEntryKind, InteractionKind,
    };

    #[test]
    fn a_listed_destination_names_its_definition_and_anything_else_reads_managed() {
        let v = |j: &str| serde_json::from_str::<serde_json::Value>(j).unwrap();
        for (item, expected) in [
            (
                r#"{"alias":"a","definition":"observed"}"#,
                Definition::Observed,
            ),
            (
                r#"{"alias":"a","definition":{"kind":"observed"}}"#,
                Definition::Observed,
            ),
            (
                r#"{"alias":"a","definition":"managed"}"#,
                Definition::Managed,
            ),
            (
                r#"{"alias":"a","definition":{"kind":"managed","hostname":"h"}}"#,
                Definition::Managed,
            ),
            (r#"{"alias":"a"}"#, Definition::Managed),
            (
                r#"{"alias":"a","definition":{"kind":"new"}}"#,
                Definition::Managed,
            ),
        ] {
            assert_eq!(definition_of(&v(item)), expected, "{item}");
        }
        assert_eq!(
            listed_items(&v(r#"{"destinations":[{"alias":"a"}],"items":[]}"#)).len(),
            1
        );
        assert_eq!(listed_items(&v(r#"{"items":[{"alias":"a"}]}"#)).len(), 1);
        assert!(listed_items(&v(r#"{"profiles":[]}"#)).is_empty());
    }

    /// ⟨M03⟩ Only a listed pair whose preference is `managed_certificate` with its
    /// projection `applied` takes the managed flow; anything else is M02's.
    #[test]
    fn only_an_applied_managed_preference_takes_the_managed_flow() {
        let v = |j: &str| serde_json::from_str::<serde_json::Value>(j).unwrap();
        let item = |pref: &str| {
            v(&format!(
                r#"{{"alias":"w","destination_id":"dst-w","account":"deploy","definition":"managed"{pref}}}"#
            ))
        };
        let pair = managed_pair_of(&item(
            r#","preference":{"mechanism":"managed_certificate","projection":{"state":"applied","generation":3}}"#,
        ))
        .unwrap();
        assert_eq!(pair.destination.as_str(), "dst-w");
        assert_eq!(pair.account.as_str(), "deploy");
        assert!(
            managed_pair_of(&item(
                r#","preference":{"mechanism":"managed_certificate","projection":"applied"}"#
            ))
            .is_some()
        );
        for other in [
            "",
            r#","preference":{"mechanism":"existing","projection":{"state":"applied"}}"#,
            r#","preference":{"mechanism":"managed_certificate","projection":{"state":"pending"}}"#,
            r#","preference":{"mechanism":"managed_certificate"}"#,
        ] {
            assert_eq!(managed_pair_of(&item(other)), None, "{other}");
        }
    }

    /// ⟨M03⟩ ADR-0008 D8 item 2: `connect` for a managed pair uses the one profile
    /// covering it; none (or several) is `no_profile_covers_destination`.
    #[test]
    fn connect_managed_pair_covering_profile_is_the_one_listed_or_refused() {
        let v = |j: &str| serde_json::from_str::<serde_json::Value>(j).unwrap();
        let pair = AccessPairRef {
            destination: heimdall_contract::ids::DestinationId::parse("dst-w").unwrap(),
            account: heimdall_contract::ids::AccountName::parse("deploy").unwrap(),
        };
        let covers =
            v(r#"{"profile_id":"ops","pairs":[{"destination":"dst-w","account":"deploy"}]}"#);
        let other =
            v(r#"{"profile_id":"web","pairs":[{"destination":"dst-x","account":"deploy"}]}"#);
        let also =
            v(r#"{"profile_id":"dev","pairs":[{"destination":"dst-w","account":"deploy"}]}"#);
        assert_eq!(
            choose_covering(&[other.clone(), covers.clone()], &pair)
                .ok()
                .map(|p| p.as_str().to_owned()),
            Some("ops".to_owned())
        );
        for refused in [vec![other.clone()], vec![], vec![covers, also]] {
            let Err(f) = choose_covering(&refused, &pair) else {
                panic!("refused: {refused:?}");
            };
            assert_eq!(f.env.code, Code::CapabilityUnavailable);
            assert_eq!(
                f.env.data["error"]["reason"],
                "no_profile_covers_destination"
            );
        }
    }

    /// ⟨M03⟩ The binding's files sit beside its endpoint, under `<runtime_dir>/b/<16
    /// hex>/`; an endpoint of any other shape names no files (fail closed).
    #[test]
    fn binding_files_follow_the_binding_endpoint_or_refuse() {
        let rd = std::path::Path::new("/run/user/1000/heimdall");
        let dest = heimdall_contract::ids::DestinationId::parse("dst-w").unwrap();
        let unix = binding_files(
            "/run/user/1000/heimdall/b/0123456789abcdef/agent.sock",
            rd,
            &dest,
            Platform::Linux,
        );
        // ⟨wave-2 Windows native run⟩ The Unix layout is only ever read on a Unix host:
        // on Windows, `Path::join` writes `\` into the Unix path, which `RenderPath::unix`
        // refuses (fail closed), as the Windows half's positive case is Windows-only.
        if cfg!(unix) {
            let unix = unix.unwrap();
            assert_eq!(
                unix.key_pub.as_str(),
                "/run/user/1000/heimdall/b/0123456789abcdef/key.pub"
            );
            assert_eq!(
                unix.cert.as_str(),
                "/run/user/1000/heimdall/b/0123456789abcdef/cert-dst-w.pub"
            );
        } else {
            assert!(unix.is_none(), "never a Unix path built on Windows");
        }
        for bad in [
            "/run/user/1000/heimdall/signing.sock",
            "/run/user/1000/heimdall/b/0123456789ABCDEF/agent.sock",
            "/elsewhere/b/0123456789abcdef/agent.sock",
            "/run/user/1000/heimdall/b/0123456789abcdef/other.sock",
            "/run/user/1000/heimdall/v/0123456789abcdef/agent.sock",
        ] {
            assert!(
                binding_files(bad, rd, &dest, Platform::Linux).is_none(),
                "{bad}"
            );
        }
        let unsafe_dest = heimdall_contract::ids::DestinationId::parse("a:b").unwrap();
        assert!(
            binding_files(
                "/run/user/1000/heimdall/b/0123456789abcdef/agent.sock",
                rd,
                &unsafe_dest,
                Platform::Linux
            )
            .is_none()
        );
        let wrd = std::path::Path::new(r"C:\Users\fx\AppData\Local\heimdall\run");
        let windows = binding_files(
            r"\\.\pipe\heimdall-tok-b0123456789abcdef",
            wrd,
            &dest,
            Platform::Windows,
        );
        if cfg!(windows) {
            let w = windows.unwrap();
            assert_eq!(
                w.endpoint.as_str(),
                "//./pipe/heimdall-tok-b0123456789abcdef"
            );
            assert!(
                w.cert
                    .as_str()
                    .ends_with("/run/b/0123456789abcdef/cert-dst-w.pub")
            );
        }
        assert!(
            binding_files(
                r"\\.\pipe\heimdall-tok-signing",
                wrd,
                &dest,
                Platform::Windows
            )
            .is_none()
        );
    }

    /// ⟨§17.22 item 13 (R2C-Q2)⟩ A managed bind result: the launch names the binding
    /// endpoint the result carries (and its files), and a result naming none refuses
    /// before launch (`driver_unavailable`), never `ssh <alias>`; an existing-access
    /// result keeps M02's `ssh <alias>`.
    #[cfg(unix)]
    #[test]
    fn managed_connect_refuses_without_a_live_binding_endpoint() {
        use heimdall_contract::provider::{
            EvidenceBasis, IdentitySelection, InteractionKind, NoninteractiveEligibility,
        };
        let now = heimdall_contract::Timestamp::now();
        let pair_ref = AccessPairRef {
            destination: heimdall_contract::ids::DestinationId::parse("dst-w").unwrap(),
            account: heimdall_contract::ids::AccountName::parse("deploy").unwrap(),
        };
        let integration = |mechanism: &str| heimdall_contract::request::PairIntegration {
            destination: pair_ref.destination.clone(),
            account: pair_ref.account.clone(),
            identity: IdentityId::from_random_bytes([3; 16]),
            mechanism: mechanism.to_owned(),
            endpoint: None,
            alias: Some("w".to_owned()),
            interaction: InteractionKind::None,
            interaction_basis: EvidenceBasis::Observed,
            declared_at: None,
            identity_selection: IdentitySelection::Exclusive,
            selection_observed_at: now,
            declaration: None,
            noninteractive: NoninteractiveEligibility {
                eligible: true,
                reason: None,
            },
            eligibility_checked_at: now,
            identity_selection_report: None,
        };
        let bound = |mechanism: &str, endpoint: Option<&str>| -> EnsureData {
            let mut d: EnsureData = serde_json::from_value(serde_json::json!({
                "binding_id": heimdall_contract::ids::BindingId::from_random_bytes([1; 16]),
                "environment_id": "env_07070707070707070707070707070707",
                "profile_revision": 1,
                "grant_id": heimdall_contract::ids::GrantId::from_random_bytes([2; 16]),
                "expires_at": "2026-11-02T11:00:00Z",
                "usable_until": "2026-11-02T11:00:00Z",
                "offline_until": "2026-11-02T11:00:00Z",
                "refresh_dependency": "none",
                "credential_mechanism": mechanism,
                "enforcement": {
                    "destination_scope": "unknown",
                    "new_authentication_expiry": "unknown",
                    "workload_isolation": "shared_os_user",
                    "existing_connections": "unknown",
                    "revocation": "unknown"
                },
                "consumer": {},
                "credential_availability": "unknown"
            }))
            .unwrap();
            d.consumer.pairs = vec![integration(mechanism)];
            d.consumer.signing_endpoint = endpoint.map(str::to_owned);
            d
        };
        let rd = std::path::PathBuf::from("/run/user/1000/heimdall");
        let dir = || Ok(rd.clone());
        let live = "/run/user/1000/heimdall/b/0123456789abcdef/agent.sock";
        // A live binding endpoint: the binding's endpoint and files, then the alias.
        let Ok(args) = managed_launch_args(
            dir,
            "w",
            &pair_ref,
            &bound(launch_flow::MANAGED_CERTIFICATE, Some(live)),
        ) else {
            panic!("a live binding endpoint launches");
        };
        let text: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(text.last().map(String::as_str), Some("w"));
        assert!(
            text.iter().any(|a| a.contains(live)),
            "the binding endpoint is on the command line: {text:?}"
        );
        // None named (not live in the registry), or one that is not a binding
        // endpoint: refused before launch.
        for endpoint in [None, Some("/run/user/1000/heimdall/signing.sock")] {
            let Err(f) = managed_launch_args(
                dir,
                "w",
                &pair_ref,
                &bound(launch_flow::MANAGED_CERTIFICATE, endpoint),
            ) else {
                panic!("refused before launch: {endpoint:?}");
            };
            assert_eq!(f.env.code, Code::CapabilityUnavailable, "{endpoint:?}");
            assert_eq!(f.env.data["error"]["reason"], "driver_unavailable");
        }
        // Existing access: M02's launch, `ssh <alias>`.
        let Ok(existing) = managed_launch_args(dir, "w", &pair_ref, &bound("native_agent", None))
        else {
            panic!("existing access launches");
        };
        assert_eq!(existing, vec![std::ffi::OsString::from("w")]);
    }

    fn entry(source: IdentityEntrySource, fp: &str) -> IdentityEntry {
        IdentityEntry {
            kind: IdentityEntryKind::IdentityFile,
            source,
            provenance: None,
            certainty: Certainty::Determined,
            fingerprint: Some(fp.to_owned()),
            backing: IdentityBacking::Agent,
            cleared: None,
        }
    }

    fn view(n: u8) -> IdentityView {
        IdentityView {
            identity: IdentityId::from_random_bytes([n; 16]),
            fingerprint: format!("SHA256:fixture-{n}"),
            endpoint: None,
            interaction: InteractionKind::None,
            declaration: None,
        }
    }

    /// ADR-0007 §12.24 item 1: a managed alias relies on the adopted key its managed
    /// entry carries; an observed alias on the first adopted key its own entries name.
    #[test]
    fn the_alias_identity_follows_the_definition() {
        let identities = IdentitiesView {
            identities: vec![view(1), view(2)],
        };
        let user = |n: u8| entry(IdentityEntrySource::User, &format!("SHA256:fixture-{n}"));
        let managed = |n: u8| entry(IdentityEntrySource::Managed, &format!("SHA256:fixture-{n}"));
        let id = |v: Option<&IdentityView>| v.map(|v| v.identity.clone());
        // Managed: only a managed entry counts.
        assert_eq!(
            id(alias_identity(&identities, &[user(1)], Definition::Managed)),
            None
        );
        assert_eq!(
            id(alias_identity(
                &identities,
                &[user(1), managed(2)],
                Definition::Managed
            )),
            Some(view(2).identity)
        );
        // Observed: the first entry that names an adopted key.
        assert_eq!(
            id(alias_identity(
                &identities,
                &[user(9), user(2), user(1)],
                Definition::Observed
            )),
            Some(view(2).identity)
        );
        assert_eq!(
            id(alias_identity(
                &identities,
                &[user(9)],
                Definition::Observed
            )),
            None
        );
    }
}
