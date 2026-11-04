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

use heimdall_contract::provider::IdentityEntrySource;
use heimdall_contract::request::{InspectRequest, InspectSubject, Request};
use heimdall_contract::setup::ProjectionItem;
use heimdall_contract::{Code, ExitCode};
use heimdall_launch::eligibility::{
    BoundPair, IdentitiesView, IdentityView, PrelaunchReason, PrelaunchRefusal, check_pairs,
};
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
        let Some(definition) = known_destination(&mut client, &alias).await? else {
            return Err(Failure::new(
                Code::NotFound,
                "unknown destination: the alias is not a managed or observed destination",
                None,
            ));
        };
        if check {
            eligible(ctx, &mut client, &alias, definition, &hooks).await?;
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
async fn known_destination(
    client: &mut Client,
    alias: &str,
) -> Result<Option<Definition>, Failure> {
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
        return Ok(Some(definition_of(item)));
    }
    let record = launch_flow::projection_record(client).await?;
    Ok(record
        .items
        .get(&ProjectionItem::Ssh)
        .is_some_and(|r| r.aliases.iter().any(|a| a == alias))
        .then_some(Definition::Managed))
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
