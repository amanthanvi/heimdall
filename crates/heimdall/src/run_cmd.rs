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
//!    becomes the child; Windows: the launcher that waits);
//! 5. Git's SSH selection, resolved in the child's working directory with the child's
//!    environment (`localenv::git::resolve_run_selection`; a bounded local query);
//! 6. under `--non-interactive` without `--allow-provider-interaction`, the pre-launch
//!    eligibility check (`heimdall_launch::eligibility::check_noninteractive`) over a
//!    fresh `inspect identities` and a fresh static selection; a refusal is
//!    `INTERACTION_REQUIRED`, exit 3, with a `prelaunch_failed` record;
//! 7. the launch: Unix `exec` after `launching`, Windows spawn and wait.
//!
//! The control session is closed and the async runtime shut down before step 7, so
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
        Ok(prepared) => launch_flow::launch(
            ctx,
            Launch {
                program: prepared.program,
                args: args
                    .argv
                    .get(1..)
                    .map(<[OsString]>::to_vec)
                    .unwrap_or_default(),
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
    delta: EnvDelta,
    operation: Option<heimdall_contract::ids::OperationId>,
    binding: Option<heimdall_contract::ids::BindingId>,
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
        drop(client);
        let delta = EnvDelta::from_integration(&bound_data.consumer, &env, &git, platform);
        Ok(Prepared {
            program,
            delta,
            operation: ids.0,
            binding: ids.1,
        })
    });
    rt.shutdown_background();
    let prepared = result?;
    launch_flow::report_overrides(ctx, &prepared.delta.overrides);
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::*;

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
