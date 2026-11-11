//! `heimdall run --profile P -- <argv>` (m02-plan U8; ADR-0007 §7, §8; spec §10.4).
//!
//! In order:
//! 1. the side channel (`--meta-fd`/`--meta-file`; a usage error before anything
//!    else) and the argument bound (`MAX_ARGV_BYTES`, enforced here before `ensure`,
//!    ADR-0007 §12.15 item 7);
//! 2. the program, resolved by Heimdall without a shell (a refusal is
//!    `LAUNCH_FAILED`, 127 or 126, before any request: no operation is created for a
//!    program that cannot run);
//! 3. `ensure` of the profile (the owner-present flow on an interactive TTY);
//! 4. `bind(Launch { executable, holder })`, the holder being this process (Unix: it
//!    becomes the child; Windows: the launcher that waits). A binding another live
//!    process holds is refused by the runtime (`REQUEST_CONFLICT`, reason
//!    `binding_in_use`, `next: new_request_id`, a `prelaunch_failed` record; ADR-0007
//!    §12.25 item 4), so of two overlapping invocations of one binding only one
//!    launches and the first holder is kept;
//! 5. Git's SSH selection, resolved in the child's working directory with the child's
//!    environment (`localenv::git::resolve_run_selection`; a bounded local query);
//! 6. under `--non-interactive` without `--allow-provider-interaction`, the pre-launch
//!    eligibility check (`heimdall_launch::eligibility::check_noninteractive`) over a
//!    fresh `inspect identities` and a fresh static selection; a refusal is
//!    `INTERACTION_REQUIRED`, exit 3, with a `prelaunch_failed` record, naming the
//!    uncleared entries' file and line in `data.error.entries`;
//! 7. one `inspect bindings` confirming the binding is still `active` (ADR-0007
//!    §12.24 item 2, `launch_flow::confirm_binding_active`): a replayed `bind` returns
//!    its stored result, so a binding the holder pass released since is refused there
//!    (`CREDENTIAL_EXPIRED`, reason `binding_released`, `next: new_work`, a
//!    `prelaunch_failed` record; §12.26 item 3(a), §12.28 item 7) and never launched;
//! 8. the launch: Unix `exec` after `launching`, Windows spawn and wait.
//!
//! **⟨M03⟩ A managed binding** (ADR-0008 D8 item 2, D10 item 5; m03-plan U8), after
//! step 4:
//! * **the slot check:** the binding must hold the slot of every managed pair. A free
//!   slot is claimed (auto-materialize); a slot another binding holds (or that is still
//!   clearing) is refused before launch, `CONFIG_CONFLICT` `managed_slot_held`
//!   ([`require_slots`]). The slot table is the runtime's (U6's files, U10's wiring);
//!   this build has no request for it, so the production [`ManagedSlots`] refuses
//!   `driver_unavailable` (fail closed). Today a managed pair never gets this far:
//!   `ensure` refuses it `driver_unavailable` until the managed adapter is registered;
//! * **an owned launch** (the program is the verified `ssh` client): the foreground pins
//!   right after the program name, and the refusal of `-f`, `-M`, `-S`, `-O` and the
//!   `-o` forms of `ForkAfterAuthentication`, `ControlMaster`, `ControlPath` and
//!   `ControlPersist` (`owned_connection_option_conflict`). ⟨M03 U7, reading R9⟩ On
//!   Windows an owned launch (`heimdall_launch::windows::launch_uses_kill_on_close_job`)
//!   is the contained one: the child is created suspended in a kill-on-close job,
//!   registered while suspended through `Request::Connections(Register)`, and resumed
//!   only after a successful reply. Until the runtime accepts that request (U10) every
//!   registration fails, so the job is closed, the child dies never having run, and
//!   `prelaunch_failed` is written with `connection_registration_failed` (or
//!   `connection_registration_refused`) (fail closed);
//! * the deadline notice follows the pairs' identity selection (D8 item 6).
//!
//! The control session is closed and the async runtime shut down before step 8, so
//! the child inherits neither. Every failure before launch writes `prelaunch_failed`
//! (when a side channel is open) and is reported on stderr; stdout is the child's.
//!
//! Readings applied: `--profile` is required (`run` without a profile has nothing to
//! ensure; `connect` is the profile-free command); a request ID is minted and reported
//! on stderr when absent; `--work-id` defaults to the request ID, so a retry with the
//! same request ID replays the same `ensure` and `bind` (and the launch is the
//! caller's explicit act: nothing relaunches on its own, R-RT-05). `argv` is read
//! only to resolve the program and to pass it to the child; it never crosses IPC.

use std::ffi::OsString;

use heimdall_contract::ids::{ProfileId, RequestId, WorkId};
use heimdall_contract::request::{
    BindForm, BindRequest, EnsureData, EnsureRequest, LaunchBinding, ProcessHolder, Request,
    WaitMode,
};
use heimdall_contract::{Code, ExitCode};
use heimdall_launch::eligibility::check_noninteractive;
use heimdall_launch::env::EnvDelta;
use heimdall_launch::resolve::{check_arguments, resolve_program};
use heimdall_localenv::clients::{ClientsConfig, resolve_clients};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::local_query::LocalQueries;
use heimdall_localenv::paths::SshPaths;

use crate::cli::{RunArgs, TerminalPrompt, ensure_flow, fresh_request_id};
use crate::client::{Ctx, connect_as};
use crate::launch_flow::{self, Failure, Launch};
use crate::output;
use crate::testcfg::{self, LaunchHooks};

/// The bounded wait for `ensure` (the same default as `access ensure`).
const ENSURE_TIMEOUT_MS: u64 = 30_000;

/// Handle `run`.
pub(crate) fn run(ctx: &Ctx, args: RunArgs) -> ExitCode {
    let hooks = match testcfg::launch_hooks(&|n| std::env::var_os(n)) {
        Ok(h) => h,
        Err(m) => return launch_flow::fail(ctx, &mut None, Failure::usage(&m)),
    };
    let meta = match launch_flow::open_side_channel(&args.launch) {
        Ok(m) => m,
        Err(f) => return launch_flow::fail(ctx, &mut None, f),
    };
    match prepare(ctx, &args, &hooks) {
        #[cfg(windows)]
        Ok(prepared) if prepared.contained => contained::launch(ctx, &args, prepared, meta),
        Ok(prepared) => launch_flow::launch(
            ctx,
            Launch {
                program: prepared.program,
                args: prepared.args.unwrap_or_else(|| {
                    args.argv
                        .get(1..)
                        .map(<[OsString]>::to_vec)
                        .unwrap_or_default()
                }),
                delta: prepared.delta,
                meta: launch_flow::with_ids(meta, prepared.operation, prepared.binding),
                hooks,
            },
        ),
        Err((failure, ids)) => {
            let mut meta = match ids {
                Some((op, b)) => launch_flow::with_ids(meta, op, b),
                None => meta,
            };
            launch_flow::fail(ctx, &mut meta, failure)
        }
    }
}

/// What a successful preparation hands to the launch.
struct Prepared {
    program: heimdall_launch::resolve::ResolvedProgram,
    /// ⟨M03⟩ An owned launch's arguments (the pins, then the user's); `None`: the
    /// user's arguments unchanged.
    args: Option<Vec<OsString>>,
    delta: EnvDelta,
    operation: Option<heimdall_contract::ids::OperationId>,
    binding: Option<heimdall_contract::ids::BindingId>,
    /// ⟨M03⟩ Windows: the contained launch of the verified `ssh` (module docs).
    #[cfg_attr(not(windows), allow(dead_code))]
    contained: bool,
}

type Ids = (
    Option<heimdall_contract::ids::OperationId>,
    Option<heimdall_contract::ids::BindingId>,
);

/// A failure, with the operation and binding its record names (once known).
type Refused = (Failure, Option<Ids>);

/// The total argument size `MAX_ARGV_BYTES` bounds: each argument's bytes and its
/// terminating NUL, the program included.
fn argv_size(argv: &[OsString]) -> usize {
    argv.iter()
        .map(|a| a.as_encoded_bytes().len().saturating_add(1))
        .fold(0, usize::saturating_add)
}

/// ADR-0007 §12.15 item 7: the argument bound, checked before anything else (so
/// before `ensure`).
fn check_argv_bound(argv: &[OsString]) -> Result<(), Failure> {
    if argv_size(argv) > heimdall_launch::MAX_ARGV_BYTES {
        return Err(Failure::usage(
            "the argument vector is larger than 1 MiB; nothing was launched",
        ));
    }
    Ok(())
}

fn prepare(ctx: &Ctx, args: &RunArgs, hooks: &LaunchHooks) -> Result<Prepared, Refused> {
    let none = |f: Failure| (f, None);
    check_argv_bound(&args.argv).map_err(none)?;
    let Some(program_name) = args.argv.first() else {
        return Err(none(Failure::usage("run needs a program after --")));
    };
    let env = Env::capture();
    let cwd = std::env::current_dir().map_err(|e| {
        none(Failure::new(
            Code::LaunchFailed,
            &format!("the working directory cannot be read: {}", e.kind()),
            Some(heimdall_contract::envelope::reason::NOT_FOUND),
        ))
    })?;
    let platform = Platform::current();
    let program = resolve_program(program_name, &env, &cwd, platform)
        .map_err(|r| none(Failure::refused(r)))?;
    check_arguments(program.kind, &args.argv[1..]).map_err(|r| none(Failure::refused(r)))?;
    let executable = program
        .path
        .to_str()
        .ok_or_else(|| {
            none(Failure::refused(
                heimdall_launch::resolve::LaunchRefusal::PathNotUnicode,
            ))
        })?
        .to_owned();
    let Some(profile) = args.profile.as_deref() else {
        return Err(none(Failure::usage(
            "run needs --profile (use `heimdall connect <alias>` without a profile)",
        )));
    };
    let profile = ProfileId::parse(profile).map_err(|_| none(Failure::usage("invalid profile")))?;
    let request_id = match args.request_id.as_deref() {
        Some(r) => RequestId::parse(r).map_err(|_| none(Failure::usage("invalid request ID")))?,
        None => {
            let minted = fresh_request_id().map_err(|d| none(Failure::of(d.env)))?;
            output::diagnostic(&format!("heimdall: request ID {minted}"));
            minted
        }
    };
    let work_id = WorkId::parse(args.work_id.as_deref().unwrap_or(request_id.as_str()))
        .map_err(|_| none(Failure::usage("invalid work ID")))?;
    let required = args
        .require
        .to_request()
        .map_err(|d| none(Failure::of(d.env)))?;
    let interaction = launch_flow::interaction(ctx, &args.launch);
    let request = EnsureRequest {
        profile,
        profile_revision: None,
        scope: Default::default(),
        environment: None,
        work_id,
        until: None,
        required_capabilities: required,
        request_id: request_id.clone(),
        interaction,
        wait: WaitMode::Sync {
            timeout_ms: ENSURE_TIMEOUT_MS,
        },
        // M03 wave 0 (A1): fail closed until U0b
        connection: None,
    };
    let rt = crate::service_cmd::current_thread()
        .map_err(|e| none(Failure::of(output::error_value(e))))?;
    let check = launch_flow::no_interaction_path(ctx, &args.launch);
    let result = rt.block_on(async {
        let mut client = connect_as(ctx, true, &[], interaction)
            .await
            .map_err(|e| none(Failure::of(output::error_value(*e))))?;
        // 3. ensure.
        let ensured = ensure_flow(&mut client, &mut TerminalPrompt, ctx, request, false).await;
        if ensured.env.code != Code::AccessReady {
            let ids = (ensured.env.operation_id.clone(), None);
            return Err((Failure::of(ensured.env), Some(ids)));
        }
        let data: EnsureData = serde_json::from_value(ensured.env.data.clone()).map_err(|_| {
            none(Failure::new(
                Code::InternalError,
                "the ensure result cannot be read",
                None,
            ))
        })?;
        // 4. bind(launch), this process holding the reference.
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
        let ids = (bound.operation_id.clone(), Some(data.binding_id.clone()));
        if bound.code != Code::AccessReady {
            return Err((Failure::of(bound), Some(ids)));
        }
        let bound_data: EnsureData = serde_json::from_value(bound.data.clone()).map_err(|_| {
            (
                Failure::new(Code::InternalError, "the bind result cannot be read", None),
                Some(ids.clone()),
            )
        })?;
        // ⟨M03⟩ 4b. A managed binding: the slot of every managed pair, and an owned
        // launch's foreground pins and refusals (module docs).
        let owned_args = managed_checks(
            &program,
            &env,
            &args.argv,
            &data.binding_id,
            &bound_data.consumer.pairs,
            &mut UnavailableSlots,
        )
        .map_err(|f| (f, Some(ids.clone())))?;
        // 5. Git's selection in the child's directory, with the child's environment.
        let ssh_paths = launch_flow::ssh_paths(hooks)
            .unwrap_or_else(|_| SshPaths::with_test_override(cwd.clone(), cwd.clone()));
        let clients = resolve_clients(
            &env,
            &ssh_paths,
            &ClientsConfig::default(),
            LocalQueries::Disabled,
        );
        let git = heimdall_localenv::git::resolve_run_selection(
            &cwd,
            &env,
            &clients,
            LocalQueries::Enabled,
        );
        launch_flow::pause(hooks.pre_check_pause.as_deref());
        // 6. The pre-launch eligibility check, on fresh views.
        if check {
            let fresh = launch_flow::fresh_identities(&mut client)
                .await
                .map_err(|f| (f, Some(ids.clone())))?;
            let record = launch_flow::projection_record(&mut client)
                .await
                .map_err(|f| (f, Some(ids.clone())))?;
            let config =
                launch_flow::static_config(ctx, hooks).map_err(|f| (f, Some(ids.clone())))?;
            let pairs = &bound_data.consumer.pairs;
            let selections: Vec<_> = pairs
                .iter()
                .map(|p| launch_flow::fresh_selection(&config, &record, p.alias.as_deref()))
                .collect();
            if let Err(refusal) = check_noninteractive(pairs, &fresh, &selections, hooks.now()) {
                let pair = pairs.get(refusal.pair);
                let (provider, kind) = launch_flow::refusal_provider(
                    pair.map(|p| p.mechanism.as_str()),
                    &fresh,
                    pair.map(|p| &p.identity),
                );
                return Err((Failure::ineligible(&refusal, provider, kind), Some(ids)));
            }
        }
        // 7. The binding is still active (a replayed bind may name a released one;
        // `confirm_binding_active` refuses it as `binding_released`).
        launch_flow::confirm_binding_active(&mut client, &data.binding_id)
            .await
            .map_err(|f| (f, Some(ids.clone())))?;
        drop(client);
        launch_flow::report_deadline(ctx, &bound_data);
        #[cfg(windows)]
        let contained = heimdall_launch::windows::launch_uses_kill_on_close_job(
            launch_flow::is_managed(&bound_data.consumer.pairs),
            launch_flow::is_verified_ssh(&program, &env),
        );
        #[cfg(not(windows))]
        let contained = false;
        let delta = EnvDelta::from_integration(&bound_data.consumer, &env, &git, platform);
        Ok(Prepared {
            program,
            args: owned_args,
            delta,
            operation: ids.0,
            binding: ids.1,
            contained,
        })
    });
    rt.shutdown_background();
    let prepared = result?;
    launch_flow::report_overrides(ctx, &prepared.delta.overrides);
    Ok(prepared)
}

// --- ⟨M03⟩ the managed checks (ADR-0008 D8 item 2, D10 item 5) ---------------------------

/// The slot table of the managed pairs, as `run` needs it (D10 item 2). The runtime owns
/// it (U6's files, U10's wiring); the CLI reaches it only through a request, which this
/// build does not have ([`UnavailableSlots`]).
pub(crate) trait ManagedSlots {
    /// The slot's state for `pair`.
    fn state(
        &mut self,
        pair: &heimdall_contract::request::PairIntegration,
    ) -> Result<heimdall_domain::managed::SlotState, Failure>;
    /// Claim the free slot of `pair` for `binding` (auto-materialize: the files are
    /// written, then the environment endpoint lists the key).
    fn claim(
        &mut self,
        binding: &heimdall_contract::ids::BindingId,
        pair: &heimdall_contract::request::PairIntegration,
    ) -> Result<(), Failure>;
}

/// The production slot table of this build: none (fail closed).
pub(crate) struct UnavailableSlots;

impl ManagedSlots for UnavailableSlots {
    fn state(
        &mut self,
        _pair: &heimdall_contract::request::PairIntegration,
    ) -> Result<heimdall_domain::managed::SlotState, Failure> {
        Err(launch_flow::managed_unavailable("the managed slot table"))
    }

    fn claim(
        &mut self,
        _binding: &heimdall_contract::ids::BindingId,
        _pair: &heimdall_contract::request::PairIntegration,
    ) -> Result<(), Failure> {
        Err(launch_flow::managed_unavailable("the managed slot table"))
    }
}

/// D10 item 5: `binding` must hold the slot of every managed pair of `pairs`. Every
/// slot is read first; any slot another binding holds, or one still clearing, refuses
/// the launch (`managed_slot_held`) before anything is claimed. Then each free slot is
/// claimed (the domain's `slot_transition` decides each case). Returns how many slots
/// were claimed.
pub(crate) fn require_slots(
    slots: &mut dyn ManagedSlots,
    binding: &heimdall_contract::ids::BindingId,
    pairs: &[heimdall_contract::request::PairIntegration],
) -> Result<usize, Failure> {
    use heimdall_domain::managed::{SlotEvent, SlotState, slot_transition};
    let claim = SlotEvent::Claim {
        binding: binding.clone(),
    };
    let mut free = Vec::new();
    for pair in pairs
        .iter()
        .filter(|p| p.mechanism == launch_flow::MANAGED_CERTIFICATE)
    {
        let state = slots.state(pair)?;
        match slot_transition(&state, &claim) {
            Ok(next) if next == state => {}
            Ok(_) if matches!(state, SlotState::Free { .. }) => free.push(pair),
            // Held by another binding, clearing, or anything this build cannot claim.
            _ => return Err(launch_flow::managed_slot_held(binding)),
        }
    }
    for pair in &free {
        slots.claim(binding, pair)?;
    }
    Ok(free.len())
}

/// ⟨M03⟩ The checks of a managed binding (module docs): `None` for a binding with no
/// managed pair (M02, unchanged); otherwise the slot check, and for an owned launch the
/// pinned arguments. On Windows an owned launch then goes through the contained spawn
/// ([`Prepared::contained`]).
fn managed_checks(
    program: &heimdall_launch::resolve::ResolvedProgram,
    env: &Env,
    argv: &[OsString],
    binding: &heimdall_contract::ids::BindingId,
    pairs: &[heimdall_contract::request::PairIntegration],
    slots: &mut dyn ManagedSlots,
) -> Result<Option<Vec<OsString>>, Failure> {
    if !launch_flow::is_managed(pairs) {
        return Ok(None);
    }
    let owned = launch_flow::is_verified_ssh(program, env);
    let pinned = if owned {
        Some(launch_flow::owned_ssh_args(
            argv.get(1..).unwrap_or_default(),
        )?)
    } else {
        None
    };
    require_slots(slots, binding, pairs)?;
    Ok(pinned)
}

/// ⟨M03 U7, reading R9⟩ The Windows contained launch of the verified `ssh` (ADR-0008 D8
/// item 2): the production registrar sends `Request::Connections(Register)` over a fresh
/// control session; any answer but `OK` fails closed.
#[cfg(windows)]
mod contained {
    use std::ffi::OsString;
    use std::path::Path;

    use heimdall_contract::envelope::reason;
    use heimdall_contract::ids::BindingId;
    use heimdall_contract::managed::ConnectionsRequest;
    use heimdall_contract::request::{InteractionMode, Request};
    use heimdall_contract::{Code, ExitCode, Timestamp};
    use heimdall_launch::LaunchFailure;
    use heimdall_launch::windows::{ContainedFailure, Registration, spawn_contained_and_wait};

    use super::Prepared;
    use crate::cli::RunArgs;
    use crate::client::{Ctx, connect_as};
    use crate::launch_flow::{self, Failure};

    /// One registration over a fresh session (the launch's own was closed before it).
    fn register(
        ctx: &Ctx,
        interaction: InteractionMode,
        binding: &BindingId,
        pid: u32,
        created_at: Timestamp,
        image: &Path,
    ) -> Registration {
        let Some(image) = image.to_str() else {
            return Registration::Failed;
        };
        let Ok(rt) = crate::service_cmd::current_thread() else {
            return Registration::Failed;
        };
        let answer = rt.block_on(async {
            let mut client = connect_as(ctx, false, &[], interaction).await.ok()?;
            Some(
                client
                    .request(Request::Connections(ConnectionsRequest::Register {
                        binding_id: binding.clone(),
                        pid,
                        created_at,
                        image: image.to_owned(),
                    }))
                    .await,
            )
        });
        rt.shutdown_background();
        match answer {
            Some(env) if env.code == Code::Ok => Registration::Registered,
            Some(env)
                if env.data["error"]["reason"].as_str()
                    == Some(reason::CONNECTION_REGISTRATION_REFUSED) =>
            {
                Registration::Refused
            }
            _ => Registration::Failed,
        }
    }

    pub(super) fn launch(
        ctx: &Ctx,
        args: &RunArgs,
        prepared: Prepared,
        meta: Option<heimdall_launch::meta::SideChannel>,
    ) -> ExitCode {
        let meta =
            launch_flow::with_ids(meta, prepared.operation.clone(), prepared.binding.clone());
        let Some(binding) = prepared.binding.clone() else {
            let mut meta = meta;
            return launch_flow::fail(
                ctx,
                &mut meta,
                Failure::new(
                    Code::LaunchFailed,
                    "the contained launch has no binding to register; nothing was launched",
                    Some(reason::CONNECTION_REGISTRATION_FAILED),
                ),
            );
        };
        let interaction = launch_flow::interaction(ctx, &args.launch);
        let user_args: Vec<OsString> = args
            .argv
            .get(1..)
            .map(<[OsString]>::to_vec)
            .unwrap_or_default();
        let child_args = prepared.args.clone().unwrap_or(user_args);
        let mut registrar = |pid: u32, created_at: Timestamp, image: &Path| {
            register(ctx, interaction, &binding, pid, created_at, image)
        };
        match spawn_contained_and_wait(
            &prepared.program,
            &child_args,
            &prepared.delta,
            meta,
            &mut registrar,
        ) {
            Ok(code) => {
                // The child's exact status, not an exit class.
                #[allow(clippy::cast_possible_wrap, clippy::exit)]
                std::process::exit(code as i32)
            }
            Err(failure) => {
                let why = failure.reason();
                match failure {
                    ContainedFailure::Registration { refused, mut meta } => {
                        let message = if refused {
                            "the runtime refused to register the ssh client for this grant; the client was never resumed and nothing ran"
                        } else {
                            "the ssh client could not be registered with the runtime; the client was never resumed and nothing ran"
                        };
                        launch_flow::fail(
                            ctx,
                            &mut meta,
                            Failure::new(Code::LaunchFailed, message, why),
                        )
                    }
                    // The record is already written; report only.
                    ContainedFailure::Launch(f) => {
                        let failure = match f {
                            LaunchFailure::Refused(r) => Failure::refused(r),
                            LaunchFailure::MetaUnavailable => Failure::new(
                                Code::LaunchFailed,
                                "the run record could not be written; nothing was launched",
                                Some(reason::META_UNAVAILABLE),
                            ),
                            _ => Failure::new(
                                Code::LaunchFailed,
                                "the program could not be started",
                                Some(reason::EXEC_ERROR),
                            ),
                        };
                        launch_flow::fail(ctx, &mut None, failure)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use heimdall_contract::ids::{AccountName, BindingId, DestinationId, IdentityId};
    use heimdall_contract::provider::{
        EvidenceBasis, IdentitySelection, InteractionKind, NoninteractiveEligibility,
    };
    use heimdall_contract::request::PairIntegration;
    use heimdall_domain::managed::SlotState;

    fn pair(n: u8, mechanism: &str) -> PairIntegration {
        PairIntegration {
            destination: DestinationId::parse(&format!("host-{n}"))
                .unwrap_or_else(|_| unreachable!()),
            account: AccountName::parse("deploy").unwrap_or_else(|_| unreachable!()),
            identity: IdentityId::from_random_bytes([n; 16]),
            mechanism: mechanism.to_owned(),
            endpoint: None,
            alias: Some(format!("host{n}")),
            interaction: InteractionKind::None,
            interaction_basis: EvidenceBasis::Observed,
            declared_at: None,
            identity_selection: IdentitySelection::Exclusive,
            selection_observed_at: heimdall_contract::Timestamp::now(),
            declaration: None,
            noninteractive: NoninteractiveEligibility {
                eligible: true,
                reason: None,
            },
            eligibility_checked_at: heimdall_contract::Timestamp::now(),
            identity_selection_report: None,
        }
    }

    /// A fake slot table: each pair's state by destination, and the claims made.
    struct FakeSlots {
        states: Vec<(DestinationId, SlotState)>,
        claims: Vec<DestinationId>,
    }

    impl ManagedSlots for FakeSlots {
        fn state(&mut self, pair: &PairIntegration) -> Result<SlotState, Failure> {
            Ok(self
                .states
                .iter()
                .find(|(d, _)| *d == pair.destination)
                .map_or(SlotState::Free { generation: 0 }, |(_, s)| s.clone()))
        }
        fn claim(&mut self, _binding: &BindingId, pair: &PairIntegration) -> Result<(), Failure> {
            self.claims.push(pair.destination.clone());
            Ok(())
        }
    }

    /// ADR-0008 D10 item 5, against a fake slot table: free slots are claimed, a slot
    /// the binding holds is kept, a slot another binding holds (or one still clearing)
    /// refuses before any claim (`CONFIG_CONFLICT`, `managed_slot_held`, next
    /// `release_binding`), and existing-access pairs need no slot.
    #[test]
    fn the_slot_check_claims_free_slots_and_refuses_a_held_one_before_any_claim() {
        let me = BindingId::from_random_bytes([1; 16]);
        let other = BindingId::from_random_bytes([2; 16]);
        let pairs = [
            pair(1, launch_flow::MANAGED_CERTIFICATE),
            pair(2, launch_flow::MANAGED_CERTIFICATE),
            pair(3, "native_agent"),
        ];
        let mut slots = FakeSlots {
            states: vec![(
                pairs[1].destination.clone(),
                SlotState::Held {
                    binding: me.clone(),
                    generation: 4,
                },
            )],
            claims: Vec::new(),
        };
        assert_eq!(require_slots(&mut slots, &me, &pairs).ok(), Some(1));
        assert_eq!(slots.claims, [pairs[0].destination.clone()]);

        for blocking in [
            SlotState::Held {
                binding: other.clone(),
                generation: 7,
            },
            SlotState::Clearing { generation: 7 },
        ] {
            let mut slots = FakeSlots {
                states: vec![(pairs[1].destination.clone(), blocking)],
                claims: Vec::new(),
            };
            let Err(f) = require_slots(&mut slots, &me, &pairs) else {
                panic!("a held slot must refuse");
            };
            assert!(
                slots.claims.is_empty(),
                "nothing is claimed before the refusal"
            );
            assert_eq!(f.env.code, heimdall_contract::Code::ConfigConflict);
            assert_eq!(f.env.data["error"]["reason"], "managed_slot_held");
            assert_eq!(
                f.env.next.as_ref().map(|n| n.action.as_str()),
                Some("release_binding")
            );
        }
        // No managed pair: no slot is read.
        let mut none = FakeSlots {
            states: Vec::new(),
            claims: Vec::new(),
        };
        assert_eq!(require_slots(&mut none, &me, &pairs[2..]).ok(), Some(0));
        // The production table of this build refuses, fail closed.
        let Err(f) = require_slots(&mut UnavailableSlots, &me, &pairs) else {
            panic!("no slot table in this build");
        };
        assert_eq!(f.env.data["error"]["reason"], "driver_unavailable");
    }

    #[test]
    fn the_argument_bound_counts_every_byte_and_terminator() {
        assert_eq!(argv_size(&[]), 0);
        assert_eq!(argv_size(&[OsString::from("ab"), OsString::from("")]), 4);
        let just = vec![OsString::from(
            "x".repeat(heimdall_launch::MAX_ARGV_BYTES - 1),
        )];
        assert_eq!(argv_size(&just), heimdall_launch::MAX_ARGV_BYTES);
    }

    /// ADR-0007 §12.15 item 7: exactly `MAX_ARGV_BYTES` passes; one byte more is a
    /// usage error (the wiring runs this first, before `ensure`). An oversized vector
    /// cannot reach the binary through `exec` on this host (the OS argument limit is
    /// of the same size), so the end-to-end refusal is not tested.
    #[test]
    fn the_argument_bound_refuses_one_byte_over() {
        let at = vec![
            OsString::from("prog"),
            OsString::from("x".repeat(heimdall_launch::MAX_ARGV_BYTES - 6)),
        ];
        assert_eq!(argv_size(&at), heimdall_launch::MAX_ARGV_BYTES);
        assert!(check_argv_bound(&at).is_ok());
        let over = vec![
            OsString::from("prog"),
            OsString::from("x".repeat(heimdall_launch::MAX_ARGV_BYTES - 5)),
        ];
        assert!(check_argv_bound(&over).is_err());
    }
}
