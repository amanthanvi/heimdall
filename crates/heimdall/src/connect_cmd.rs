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
//!    eligibility check for the alias's identity (the adopted key the alias's managed
//!    entry carries), from the command's first `inspect identities` to a fresh one
//!    taken immediately before launch;
//! 5. `exec` (Unix) or spawn and wait (Windows) of `ssh <alias>`, with no environment
//!    addition.
//!
//! **Readings applied (fail closed).** The runtime answers `inspect destinations` with
//! `NOT_LISTED` in this build (it does not list the catalog yet), so a destination is
//! known when the listing names its alias, or, failing a listing, when the stored
//! projection record lists it as a managed alias. An observed alias is therefore
//! refused (`NOT_FOUND`) until the runtime lists destinations (escalated). On the
//! no-interaction path an alias whose managed entry names no adopted identity is
//! refused (`interaction_unknown`): which key ssh would use is not known.

use heimdall_contract::provider::IdentityEntrySource;
use heimdall_contract::request::{InspectRequest, InspectSubject, Request};
use heimdall_contract::setup::ProjectionItem;
use heimdall_contract::{Code, ExitCode};
use heimdall_launch::eligibility::{BoundPair, PrelaunchReason, PrelaunchRefusal, check_pairs};
use heimdall_launch::env::EnvDelta;
use heimdall_launch::resolve::resolve_program;
use heimdall_localenv::clients::{ClientKind, ClientsConfig, selected_path, sha256_file};
use heimdall_localenv::env::{Env, Platform};

use crate::cli::ConnectArgs;
use crate::client::{Client, Ctx, connect_as};
use crate::launch_flow::{self, Failure, Launch};
use crate::output;
use crate::testcfg;

/// The longest alias `connect` passes to `ssh`.
const MAX_ALIAS_BYTES: usize = 255;

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
        if !known_destination(&mut client, &alias).await? {
            return Err(Failure::new(
                Code::NotFound,
                "unknown destination: the alias is not a managed or observed destination",
                None,
            ));
        }
        if check {
            eligible(ctx, &mut client, &alias, &hooks).await?;
        }
        Ok(())
    });
    rt.shutdown_background();
    if let Err(f) = checked {
        return launch_flow::fail(ctx, &mut meta, f);
    }
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
            args: vec![std::ffi::OsString::from(&alias)],
            delta: EnvDelta::default(),
            meta,
            hooks,
        },
    )
}

/// Whether `alias` is a known destination (module docs).
async fn known_destination(client: &mut Client, alias: &str) -> Result<bool, Failure> {
    let listed = client
        .request(Request::Inspect(InspectRequest {
            subject: InspectSubject::Destinations,
            preview: None,
        }))
        .await;
    if !listed.code.is_success() {
        return Err(Failure::of(listed));
    }
    let items = listed
        .data
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if items
        .iter()
        .any(|d| d.get("alias").and_then(|a| a.as_str()) == Some(alias))
    {
        return Ok(true);
    }
    let record = launch_flow::projection_record(client).await?;
    Ok(record
        .items
        .get(&ProjectionItem::Ssh)
        .is_some_and(|r| r.aliases.iter().any(|a| a == alias)))
}

/// The pre-launch check for the alias's identity (module docs).
async fn eligible(
    ctx: &Ctx,
    client: &mut Client,
    alias: &str,
    hooks: &testcfg::LaunchHooks,
) -> Result<(), Failure> {
    let config = launch_flow::static_config(ctx, hooks)?;
    let first = launch_flow::fresh_identities(client).await?;
    let record = launch_flow::projection_record(client).await?;
    let selection = launch_flow::fresh_selection(&config, &record, Some(alias));
    let adopted = first.identities.iter().find(|v| {
        selection.report.entries.iter().any(|e| {
            e.source == IdentityEntrySource::Managed
                && e.fingerprint.as_deref() == Some(v.fingerprint.as_str())
        })
    });
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
    let record = launch_flow::projection_record(client).await?;
    let selection = launch_flow::fresh_selection(&config, &record, Some(alias));
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
