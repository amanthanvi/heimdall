//! `heimdall run --parent-binding <binding> [--scope DEST:ACCOUNT]... [--until T] -- <argv>`
//! (m05-plan U8; ADR-0011 §6; spec §14.3, §14.4).
//!
//! Delegates a child of `<binding>`, binds it for the launch and starts the program with
//! **only the child's signing endpoint** in its environment. In order, after the shared
//! argument and program checks (as `run`):
//!
//! 1. `delegate` of the parent binding over `--scope` (default: all the parent's pairs) until
//!    `--until` (default: the parent's deadline). The enforced recipe is the M03 child key
//!    and certificate (ADR-0005 §3.10): principals a subset of the parent's, `valid_before`
//!    no later than the parent's. A wider scope or a later deadline is refused by the runtime,
//!    `DELEGATION_EXCEEDS_PARENT`, before any key exists; nothing is launched and no record
//!    but `prelaunch_failed` is written;
//! 2. `bind(Launch)` of the **child** binding with this process as the holder, the slot
//!    check and an owned launch's pins, Git's selection, the pre-launch eligibility check
//!    under `--non-interactive` and the active confirmation: exactly `run`'s steps 4 to 7
//!    ([`crate::run_cmd`]);
//! 3. the environment: `SSH_AUTH_SOCK` is the child's endpoint (the pairs' one endpoint, as
//!    `run` sets it) or, when the child has no single endpoint, **removed**, so a worker never
//!    inherits the owner's agent; and every `HEIMDALL_*` variable is removed
//!    ([`control_locators`]): no locator of the runtime's control endpoint or home reaches the
//!    worker (ADR-0011 §6.2).
//!
//! **What this does not claim** (ADR-0011 §6.2, spec §14.4): a same-user worker can still
//! derive the owner's default control endpoint path and open it itself. The child's result
//! says so: `owner_functions: not_delegated`, `workload_isolation: shared_os_user`. A key
//! filter is convenience, not isolation. Nothing the child holds (its binding ID, its
//! endpoint) can `decide`, change a policy or delegate wider: the endpoint refuses control
//! frames and issuance requests (R-RT-03), binding IDs are references, and an approval needs
//! an attended owner `Decide`.
//!
//! Readings applied: `--profile` with `--parent-binding` is a usage error (the child's profile is
//! its parent's; checked here, because clap drops a `requires` whose target conflicts with a
//! present argument); `--work-id` defaults to the request ID as for `run`, so a retry with the same
//! request ID replays the same `delegate` and `bind`; a delegation needing an owner decision
//! (not the case for a narrower child) is reported as the runtime answers it, never prompted.

use std::ffi::{OsStr, OsString};

use heimdall_contract::ids::{AccountName, BindingId, DestinationId, RequestId, WorkId};
use heimdall_contract::request::{
    AccessPairRef, BindForm, BindRequest, DeadlineIntent, DelegateRequest, EnsureData,
    LaunchBinding, ProcessHolder, Request,
};
use heimdall_contract::{Code, ExitCode};
use heimdall_launch::eligibility::check_noninteractive;
use heimdall_launch::env::EnvDelta;
use heimdall_launch::resolve::{check_arguments, resolve_program};
use heimdall_localenv::clients::{ClientsConfig, resolve_clients};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::local_query::LocalQueries;
use heimdall_localenv::paths::SshPaths;

use crate::cli::{RunArgs, fresh_request_id};
use crate::client::{Ctx, connect_as};
use crate::launch_flow::{self, Failure};
use crate::output;
use crate::run_cmd::{self, BoundSlots, Prepared, Refused};
use crate::testcfg::LaunchHooks;

/// Handle `run --parent-binding`.
pub(crate) fn run(ctx: &Ctx, args: RunArgs) -> ExitCode {
    run_cmd::run_with(ctx, args, prepare)
}

/// `SSH_AUTH_SOCK`: the one variable that points a worker at an agent.
const SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";

/// The prefix of every variable of Heimdall's own (`HEIMDALL_HOME`, the test configuration):
/// none of them is passed to a delegated worker.
const CONTROL_PREFIX: &str = "HEIMDALL_";

/// The variables of `names` that must not reach a delegated worker: every `HEIMDALL_*`
/// variable (on Windows the name compares ASCII case-insensitively). Names only.
pub(crate) fn control_locators<'a>(
    names: impl IntoIterator<Item = &'a OsStr>,
    platform: Platform,
) -> Vec<OsString> {
    names
        .into_iter()
        .filter(|name| {
            let Some(text) = name.to_str() else {
                return false;
            };
            if platform.is_windows() {
                text.len() >= CONTROL_PREFIX.len()
                    && text.is_char_boundary(CONTROL_PREFIX.len())
                    && text[..CONTROL_PREFIX.len()].eq_ignore_ascii_case(CONTROL_PREFIX)
            } else {
                text.starts_with(CONTROL_PREFIX)
            }
        })
        .map(OsStr::to_os_string)
        .collect()
}

/// `DEST:ACCOUNT` as a scope pair.
fn scope_pair(text: &str) -> Result<AccessPairRef, Failure> {
    let Some((destination, account)) = text.split_once(':') else {
        return Err(Failure::usage("a scope pair is DEST:ACCOUNT"));
    };
    Ok(AccessPairRef {
        destination: DestinationId::parse(destination)
            .map_err(|_| Failure::usage("invalid destination"))?,
        account: AccountName::parse(account).map_err(|_| Failure::usage("invalid account"))?,
    })
}

/// The preparation of `run --parent-binding` (module docs): `run`'s steps with `delegate` of
/// the parent binding in place of `ensure`.
fn prepare(ctx: &Ctx, args: &RunArgs, hooks: &LaunchHooks) -> Result<Prepared, Refused> {
    let none = |f: Failure| (f, None);
    if args.profile.is_some() {
        return Err(none(Failure::usage(
            "--parent-binding takes no --profile: the child's profile is its parent's",
        )));
    }
    run_cmd::check_argv_bound(&args.argv).map_err(none)?;
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
    let Some(parent) = args.parent_binding.as_deref() else {
        return Err(none(Failure::usage("run needs --parent-binding here")));
    };
    let parent = BindingId::parse(parent).map_err(|_| none(Failure::usage("invalid binding")))?;
    let scope = args
        .scope
        .iter()
        .map(|p| scope_pair(p))
        .collect::<Result<_, _>>()
        .map_err(none)?;
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
    let request = DelegateRequest {
        parent_binding_id: parent,
        scope,
        until: args.until.clone().map(DeadlineIntent::Absolute),
        work_id,
        request_id: request_id.clone(),
        required_capabilities: required,
    };
    let rt = crate::service_cmd::current_thread()
        .map_err(|e| none(Failure::of(output::error_value(e))))?;
    let check = launch_flow::no_interaction_path(ctx, &args.launch);
    let result = rt.block_on(async {
        let mut client = connect_as(ctx, true, &[], interaction)
            .await
            .map_err(|e| none(Failure::of(output::error_value(*e))))?;
        // 1. delegate: the child key and certificate, or `DELEGATION_EXCEEDS_PARENT`.
        let delegated = client.request(Request::Delegate(request)).await;
        if delegated.code != Code::AccessReady {
            let ids = (delegated.operation_id.clone(), None);
            return Err((Failure::of(delegated), Some(ids)));
        }
        let data: EnsureData = serde_json::from_value(delegated.data.clone()).map_err(|_| {
            none(Failure::new(
                Code::InternalError,
                "the delegate result cannot be read",
                None,
            ))
        })?;
        // 2. bind(launch) of the child, this process holding the reference.
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
        let owned_args = run_cmd::managed_checks(
            &program,
            &env,
            &args.argv,
            &data.binding_id,
            &bound_data.consumer.pairs,
            &mut BoundSlots::of(&bound),
        )
        .map_err(|f| (f, Some(ids.clone())))?;
        // 3. Git's selection in the worker's directory, with the worker's environment.
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
        // 4. The pre-launch eligibility check, on fresh views.
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
        // 5. The child binding is still active.
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
        let mut delta = EnvDelta::from_integration(&bound_data.consumer, &env, &git, platform);
        confine(&mut delta, &env, platform);
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

/// The worker's environment (module docs, item 3): no `HEIMDALL_*` variable, and an agent
/// endpoint only if the delta names the child's.
fn confine(delta: &mut EnvDelta, env: &Env, platform: Platform) {
    delta.unset = control_locators(env.iter().map(|(name, _)| name), platform);
    let sets_agent = delta.set.iter().any(|(name, _)| {
        if platform.is_windows() {
            name.to_str()
                .is_some_and(|n| n.eq_ignore_ascii_case(SSH_AUTH_SOCK))
        } else {
            name == SSH_AUTH_SOCK
        }
    });
    if !sets_agent {
        delta.unset.push(OsString::from(SSH_AUTH_SOCK));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `HEIMDALL_*` variable is removed from a worker's environment, and nothing
    /// else; the agent variable goes too unless the child names an endpoint.
    #[test]
    fn worker_environment_loses_every_locator_and_a_foreign_agent() {
        let env = Env::from_vars([
            ("HEIMDALL_HOME", "/h"),
            ("HEIMDALL_TEST_ADAPTER", "prepare"),
            ("HEIMDALLX", "kept"),
            ("PATH", "/usr/bin"),
            ("SSH_AUTH_SOCK", "/owner/agent"),
        ]);
        let mut delta = EnvDelta::default();
        confine(&mut delta, &env, Platform::Linux);
        let mut gone: Vec<_> = delta
            .unset
            .iter()
            .map(|n| n.to_string_lossy().into_owned())
            .collect();
        gone.sort();
        assert_eq!(
            gone,
            ["HEIMDALL_HOME", "HEIMDALL_TEST_ADAPTER", "SSH_AUTH_SOCK"]
        );
        // The child's endpoint is set (by the integration), so the agent variable stays.
        let mut delta = EnvDelta::default();
        delta
            .set
            .push((OsString::from("SSH_AUTH_SOCK"), OsString::from("/child")));
        confine(&mut delta, &env, Platform::Linux);
        assert!(!delta.unset.contains(&OsString::from("SSH_AUTH_SOCK")));
        assert!(delta.unset.contains(&OsString::from("HEIMDALL_HOME")));
        // Windows names compare case-insensitively.
        let env = Env::from_vars([("Heimdall_Home", "C:\\h"), ("Path", "C:\\w")]);
        assert_eq!(
            control_locators(env.iter().map(|(n, _)| n), Platform::Windows),
            [OsString::from("Heimdall_Home")]
        );
    }

    /// A scope pair is `DEST:ACCOUNT`; anything else is a usage error before any request.
    #[test]
    fn scope_pair_needs_destination_and_account() {
        assert!(scope_pair("h1:deploy").is_ok());
        for bad in ["h1", ":deploy", "h1:", "a b:c"] {
            assert!(scope_pair(bad).is_err(), "{bad}");
        }
    }
}
