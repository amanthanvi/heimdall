//! `heimdall doctor` (m02-plan U9; ADR-0007 §6; spec §10.2).
//!
//! The doctor runs **in this process** (`heimdall_localenv::doctor::run`): it never
//! starts the runtime and reads the store **read-only** (`Store::open_read_only`, which
//! never creates, migrates or repairs). Its [`LocalContext`] is filled here (ADR-0007
//! §12.17 item 10): the account's SSH paths (or, in a debug build's test
//! configuration, `HEIMDALL_TEST_SSH_HOME`, with the isolation-only client arguments
//! `-F`, the two known-hosts files and `BatchMode`, ADR-0007 §9), this process's
//! environment, the platform, the default `[clients]`, the default bounds, the catalog
//! read from the store (each managed alias with its adopted key file, fingerprint,
//! fresh interaction through `heimdall_domain::catalog::eligibility`, and endpoint;
//! observed aliases without an identity), and P's path. The local account for `%u`
//! and `Match localuser` comes from the account database (§12.25 item 2), through
//! `LocalContext::local_user`.
//!
//! * `--active-probe LEVEL[,…]` names the explicit levels; `static` always runs.
//! * `--allow-config-commands` authorizes the levels that run the real configuration
//!   tree (`evaluate`, `host_verification`, `authentication`), and is required for each
//!   of them even when the static pass lists nothing (M2-R06). On an interactive TTY it
//!   shows "runs your configuration's commands with whatever effects they have" and the
//!   file:line list the static pass found (or "none found now; the configuration can
//!   change before ssh reads it"), and needs a typed `yes`; anything else exits 3 and
//!   runs nothing. Under `--non-interactive` the flag itself is the authorization, and
//!   each probe record says so (`authorization: ["allow_config_commands"]`). A non-TTY
//!   stdin without `--non-interactive` cannot confirm: exit 3, nothing runs. An alias
//!   whose tree the static pass cannot fully read is declined
//!   (`config_not_fully_readable`) and is not offered in the prompt.
//! * `--active-probe agent` records a lapse (`WithdrawDeclaration { revision, reason:
//!   listing_missing }`) for each declared identity the listing lacked, only when the
//!   runtime is already running; otherwise the finding `interaction_declaration_lapsed`
//!   says `recorded: false` and names the exact command (ADR-0007 §7; QR9).
//! * Every probe that ran the real tree lists its configuration commands under the
//!   heading "configuration commands found before the run; the run may have executed
//!   others" (human), and the `--json` envelope carries the same text as the warning
//!   `config_commands_inventory`; no output calls the list complete (M2-S04).
//! * The doctor exits 0 when it completes, whatever its findings.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;

use heimdall_contract::Timestamp;
use heimdall_contract::catalog::{CatalogRequest, WithdrawReason};
use heimdall_contract::doctor::{
    AliasDefinition, DoctorReport, Finding, FindingSeverity, ProbeOutcome, finding,
};
use heimdall_contract::envelope::{Envelope, NextAction, ResourceRef, Warning};
use heimdall_contract::ids::IdentityId;
use heimdall_contract::provider::{InteractionKind, ProbeLevel};
use heimdall_contract::request::Request;
use heimdall_contract::setup::ConflictKind;
use heimdall_contract::{Code, ExitCode};
use heimdall_domain::catalog::{DestinationDefinition, IdentityRecord, InteractionDeclaration};
use heimdall_localenv::agents::EndpointLocator;
use heimdall_localenv::doctor::{CatalogAlias, CatalogIdentity, DoctorRequest, LocalContext};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::local_query::LocalQueries;
use heimdall_localenv::paths::SshPaths;
use heimdall_store::Store;

use crate::cli::{DoctorArgs, Prompter, TerminalPrompt};
use crate::client::Ctx;
use crate::output;
use crate::prompt::Answer;
use crate::setup_cmd::{Outcome, failure, non_interactive_reason, not_confirmed, usage};

/// The authorization text (ADR-0007 §6).
pub(crate) const AUTHORIZATION_TEXT: &str =
    "runs your configuration's commands with whatever effects they have";

/// The text when the static pass found no configuration command (ADR-0007 §6, M2-R06).
pub(crate) const NONE_FOUND_TEXT: &str =
    "none found now; the configuration can change before ssh reads it";

/// The levels that run the real configuration tree.
const REAL_TREE: [ProbeLevel; 3] = [
    ProbeLevel::Evaluate,
    ProbeLevel::HostVerification,
    ProbeLevel::Authentication,
];

/// Handle `doctor` (module docs).
pub(crate) fn run(ctx: &Ctx, args: DoctorArgs) -> ExitCode {
    let mut levels = BTreeSet::from([ProbeLevel::Static]);
    for l in &args.active_probe {
        match serde_json::from_value::<ProbeLevel>(serde_json::Value::String(l.trim().to_owned())) {
            Ok(level) => {
                levels.insert(level);
            }
            Err(_) => return usage("unknown probe level").emit(ctx),
        }
    }
    let local = match local_context(ctx) {
        Ok(l) => l,
        Err(o) => return o.emit(ctx),
    };
    let request = DoctorRequest {
        levels,
        allow_config_commands: args.allow_config_commands,
        aliases: (!args.aliases.is_empty()).then(|| args.aliases.clone()),
        interactive: ctx.interactive(),
        local_queries: if args.no_local_exec {
            LocalQueries::Disabled
        } else {
            LocalQueries::Enabled
        },
        redact: args.redact,
    };
    let mut prompt = TerminalPrompt;
    crate::setup_cmd::block(ctx, doctor(ctx, &local, request, &mut prompt))
}

/// Authorize, run, record lapses, render.
pub(crate) async fn doctor<P: Prompter>(
    ctx: &Ctx,
    local: &LocalContext,
    request: DoctorRequest,
    p: &mut P,
) -> Outcome {
    let wants_real_tree = REAL_TREE.iter().any(|l| request.levels.contains(l));
    if wants_real_tree
        && request.allow_config_commands
        && let Err(o) = authorize(ctx, local, &request, p).await
    {
        return o;
    }
    let local2 = local.clone();
    let req2 = request.clone();
    let report =
        match tokio::task::spawn_blocking(move || heimdall_localenv::doctor::run(&local2, &req2))
            .await
        {
            Ok(r) => r,
            Err(_) => {
                return Outcome::of(failure(Code::InternalError, "the doctor stopped", None));
            }
        };
    let mut report = report;
    if request.levels.contains(&ProbeLevel::Agent) {
        record_lapses(ctx, &mut report).await;
    }
    let value = serde_json::to_value(&report).unwrap_or_default();
    let human = output::render_doctor(&value);
    let mut env = Envelope::ok(value);
    if report
        .probes
        .iter()
        .any(|r| r.config_tree_changed.is_some())
    {
        env.warnings.push(Warning {
            code: output::INVENTORY_WARNING.to_owned(),
            message: output::INVENTORY_HEADING.to_owned(),
        });
    }
    Outcome::of(env).with_human(human)
}

/// The prompt text for `--allow-config-commands` over `aliases` (module docs). `None`
/// when no alias can run (each is declined `config_not_fully_readable`): then no prompt
/// is shown.
pub(crate) fn authorization_text(local: &LocalContext, aliases: &[String]) -> Option<String> {
    let mut found: Vec<String> = Vec::new();
    let mut runnable = false;
    for alias in aliases {
        if !heimdall_localenv::probe::alias_is_usable(alias) {
            continue;
        }
        let pass = heimdall_localenv::probe::static_pass(local, alias, None);
        if pass.not_fully_readable {
            continue;
        }
        runnable = true;
        for p in pass.executed {
            let line = format!("{}:{}", p.path_display, p.line);
            if !found.contains(&line) {
                found.push(line);
            }
        }
    }
    if !runnable {
        return None;
    }
    let list = if found.is_empty() {
        format!("  {NONE_FOUND_TEXT}")
    } else {
        found
            .iter()
            .map(|l| format!("  {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    Some(format!(
        "--allow-config-commands {AUTHORIZATION_TEXT}.\nConfiguration commands the static pass found for {}:\n{list}\nAllow the probes to run your configuration?\n",
        aliases.join(", ")
    ))
}

/// The typed `yes` for `--allow-config-commands` on an interactive TTY (module docs).
async fn authorize<P: Prompter>(
    ctx: &Ctx,
    local: &LocalContext,
    request: &DoctorRequest,
    p: &mut P,
) -> Result<(), Outcome> {
    if ctx.non_interactive {
        // The flag itself is the authorization; every probe record says so.
        return Ok(());
    }
    if !ctx.interactive() {
        return Err(Outcome::of(not_confirmed(
            None,
            None,
            &format!(
                "{}; --allow-config-commands needs a typed yes, or --non-interactive to authorize with the flag alone",
                non_interactive_reason(ctx)
            ),
        )));
    }
    let aliases = match &request.aliases {
        Some(a) => a.clone(),
        None => {
            // The aliases the doctor will check: its own passive static pass.
            let mut passive = DoctorRequest::passive();
            passive.local_queries = LocalQueries::Disabled;
            let l = local.clone();
            tokio::task::spawn_blocking(move || heimdall_localenv::doctor::run(&l, &passive))
                .await
                .map(|r| r.aliases.into_iter().map(|a| a.alias).collect())
                .unwrap_or_default()
        }
    };
    let Some(text) = authorization_text(local, &aliases) else {
        return Ok(());
    };
    let answer = p.ask(&text).await;
    if answer == Answer::Yes {
        Ok(())
    } else {
        Err(Outcome::of(not_confirmed(None, None, answer.reason())))
    }
}

/// For each `identity_not_listed` finding whose identity has a declaration in force,
/// record the lapse when the runtime is already running (never starting it), and add
/// `interaction_declaration_lapsed` with `recorded: true|false` (module docs).
async fn record_lapses(ctx: &Ctx, report: &mut DoctorReport) {
    let lapsed: Vec<(String, IdentityId, u64)> = {
        let Ok(store) = open_store(ctx) else {
            return;
        };
        let now = Timestamp::now();
        let read = store.transaction(|tx| {
            let mut out = Vec::new();
            for d in tx.destinations()? {
                if let DestinationDefinition::Managed { identity, .. } = d.definition
                    && let Some(i) = tx.identity(&identity)?
                    && let Some(decl) = tx.interaction_declaration(&identity)?
                    && let Some(endpoint) = i.source.endpoint()
                    && decl.counts_for(&i, endpoint, now)
                {
                    out.push((d.alias, identity, decl.revision));
                }
            }
            Ok(out)
        });
        let declared = read.unwrap_or_default();
        report
            .findings
            .iter()
            .filter(|f| f.code == finding::IDENTITY_NOT_LISTED)
            .filter_map(|f| f.subject.id.clone())
            .filter_map(|alias| declared.iter().find(|(a, _, _)| *a == alias).cloned())
            .collect()
    };
    if lapsed.is_empty() {
        return;
    }
    let mut client = crate::client::connect(ctx, false).await.ok();
    for (alias, identity, revision) in lapsed {
        let mut recorded = false;
        if let Some(c) = client.as_mut()
            && let Ok(rid) = crate::setup_cmd::request_id(None)
        {
            let env = c
                .request(Request::Catalog(CatalogRequest::WithdrawDeclaration {
                    identity: identity.clone(),
                    revision: Some(revision),
                    reason: WithdrawReason::ListingMissing,
                    request_id: rid,
                }))
                .await;
            recorded = env.code.is_success();
        }
        let command = format!("heimdall identity withdraw-declaration {identity}");
        report.findings.push(Finding {
            code: finding::INTERACTION_DECLARATION_LAPSED.to_owned(),
            severity: FindingSeverity::Warning,
            subject: ResourceRef {
                kind: "identity".to_owned(),
                id: Some(identity.to_string()),
            },
            level: ProbeLevel::Agent,
            provenance: None,
            message: if recorded {
                format!(
                    "the agent no longer lists the declared identity of {alias}; the declaration lapsed (recorded: true)"
                )
            } else {
                format!(
                    "the agent no longer lists the declared identity of {alias}; the lapse is not recorded because the runtime is not running (recorded: false); record it with `{command}`"
                )
            },
            next: NextAction {
                action: "interact".to_owned(),
                ..NextAction::default()
            },
            reason: Some(if recorded { "recorded" } else { "not_recorded" }.to_owned()),
        });
    }
}

/// The SSH paths: the account's, or the test configuration's scratch home.
fn ssh_paths(hooks: &crate::testcfg::LaunchHooks) -> Result<SshPaths, Outcome> {
    match &hooks.ssh_home {
        Some(home) => Ok(SshPaths::with_test_override(
            home.clone(),
            home.join("etc-ssh"),
        )),
        None => SshPaths::resolve().map_err(|_| {
            Outcome::of(failure(
                Code::StateUnavailable,
                "the account home cannot be resolved",
                None,
            ))
        }),
    }
}

/// The isolation-only client arguments of the test configuration (ADR-0007 §9): `-F`
/// the scratch user file, the scratch known-hosts files and `BatchMode`. Never set in
/// production, where ssh reads the real tree.
fn isolation(paths: &SshPaths) -> Vec<OsString> {
    vec![
        "-F".into(),
        paths.user_config.clone().into_os_string(),
        "-o".into(),
        format!(
            "UserKnownHostsFile={}",
            paths.user_dir.join("known_hosts").display()
        )
        .into(),
        "-o".into(),
        format!(
            "GlobalKnownHostsFile={}",
            paths.system_dir.join("ssh_known_hosts").display()
        )
        .into(),
        "-o".into(),
        "BatchMode=yes".into(),
    ]
}

/// The state store, opened read-only (never created, migrated or repaired).
pub(crate) fn open_store(ctx: &Ctx) -> Result<Store, String> {
    let paths = ctx.paths().map_err(|_| "paths".to_owned())?;
    let db = paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    Store::open_read_only(&db, std::sync::Arc::new(heimdall_store::NoFaults))
        .map_err(|e| e.to_string())
}

/// The endpoint locator of a recorded endpoint.
fn locator(e: &heimdall_contract::provider::EndpointRef) -> EndpointLocator {
    use heimdall_contract::provider::EndpointKind;
    match e.kind {
        EndpointKind::NamedPipe => EndpointLocator::NamedPipe(e.locator.clone()),
        _ => EndpointLocator::UnixSocket(PathBuf::from(&e.locator)),
    }
}

/// The catalog as the doctor reads it (module docs); empty when the store cannot be
/// read (no state yet, or another schema), which the report then simply lacks.
pub(crate) fn catalog(ctx: &Ctx, config_dir: &std::path::Path) -> Vec<CatalogAlias> {
    let Ok(store) = open_store(ctx) else {
        return Vec::new();
    };
    let now = Timestamp::now();
    let read = store.transaction(|tx| {
        let identities: Vec<IdentityRecord> = tx.identities()?;
        let mut declarations: Vec<(IdentityId, Option<InteractionDeclaration>)> = Vec::new();
        for i in &identities {
            declarations.push((i.id.clone(), tx.interaction_declaration(&i.id)?));
        }
        Ok((tx.destinations()?, identities, declarations))
    });
    let Ok((destinations, identities, declarations)) = read else {
        return Vec::new();
    };
    destinations
        .into_iter()
        .map(|d| match d.definition {
            DestinationDefinition::Managed { identity, .. } => {
                let record = identities.iter().find(|i| i.id == identity);
                let identity = record.map(|i| {
                    let declaration = declarations
                        .iter()
                        .find(|(id, _)| *id == i.id)
                        .and_then(|(_, d)| d.as_ref());
                    let interaction = match i.source.endpoint() {
                        Some(e) => {
                            heimdall_domain::catalog::eligibility(i, declaration, e, now)
                                .interaction
                        }
                        None => InteractionKind::Unknown,
                    };
                    CatalogIdentity {
                        public_key_path: config_dir.join(
                            heimdall_localenv::materialize::key_file_path(&i.fingerprint),
                        ),
                        fingerprint: Some(i.fingerprint.clone()),
                        interaction,
                        endpoint: i.source.endpoint().map(locator),
                    }
                });
                CatalogAlias {
                    alias: d.alias,
                    definition: AliasDefinition::Managed,
                    identity,
                }
            }
            _ => CatalogAlias {
                alias: d.alias,
                definition: AliasDefinition::Observed,
                identity: None,
            },
        })
        .collect()
}

/// The doctor's [`LocalContext`] (module docs; ADR-0007 §12.17 item 10).
pub(crate) fn local_context(ctx: &Ctx) -> Result<LocalContext, Outcome> {
    let hooks = crate::testcfg::launch_hooks(&|n| std::env::var_os(n))
        .map_err(|m| crate::setup_cmd::usage(&m))?;
    let paths = ssh_paths(&hooks)?;
    let heimdall = ctx
        .paths()
        .map_err(|e| Outcome::of(output::error_value(*e)))?;
    let isolation = hooks.ssh_home.as_ref().map(|_| isolation(&paths));
    let mut local = LocalContext::new(
        paths,
        Env::capture(),
        Platform::current(),
        heimdall_localenv::clients::ClientsConfig::default(),
        Default::default(),
    );
    local.client_isolation = isolation;
    local.managed_file = Some(heimdall.config_dir.join("ssh_config"));
    local.catalog = catalog(ctx, &heimdall.config_dir);
    Ok(local)
}

/// The projection conflict the passive doctor reports now (ADR-0007 §12.19 item 7):
/// `None` when there is none. Static only, no local query, no alias evaluation.
pub(crate) fn projection_conflict(ctx: &Ctx) -> Result<Option<ConflictKind>, String> {
    let local = local_context(ctx).map_err(|_| "doctor_unavailable".to_owned())?;
    let mut request = DoctorRequest::passive();
    request.local_queries = LocalQueries::Disabled;
    request.aliases = Some(Vec::new());
    let report = heimdall_localenv::doctor::run(&local, &request);
    let conflict = report.projection.and_then(|p| p.conflict);
    if conflict.is_none()
        && report
            .findings
            .iter()
            .any(|f| f.code == finding::INCLUDE_NOT_FIRST)
    {
        return Ok(Some(ConflictKind::IncludeConditional));
    }
    Ok(conflict)
}

/// Whether every requested real-tree level was declined (for the tests).
#[allow(dead_code)]
pub(crate) fn declined_everywhere(report: &DoctorReport, level: ProbeLevel) -> bool {
    report
        .probes
        .iter()
        .filter(|r| r.level == level)
        .all(|r| r.outcome == ProbeOutcome::Declined)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Script {
        answers: Vec<Answer>,
        shown: Vec<String>,
    }

    impl Prompter for Script {
        async fn ask(&mut self, text: &str) -> Answer {
            self.shown.push(text.to_owned());
            if self.answers.is_empty() {
                Answer::Eof
            } else {
                self.answers.remove(0)
            }
        }
    }

    fn scratch_context(user_config: &str) -> (tempfile::TempDir, LocalContext) {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir_all(home.join("etc-ssh")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(home.join(".ssh/config"), user_config).unwrap_or_else(|e| panic!("{e}"));
        let paths = SshPaths::with_test_override(home.clone(), home.join("etc-ssh"));
        let mut local = LocalContext::new(
            paths.clone(),
            Env::from_vars([("HOME", home.display().to_string())]),
            Platform::current(),
            heimdall_localenv::clients::ClientsConfig::default(),
            Default::default(),
        );
        local.client_isolation = Some(isolation(&paths));
        (dir, local)
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| unreachable!())
            .block_on(f)
    }

    fn request(levels: &[ProbeLevel], allow: bool) -> DoctorRequest {
        let mut r = DoctorRequest::passive();
        r.levels.extend(levels.iter().copied());
        r.allow_config_commands = allow;
        r.aliases = Some(vec!["lab".to_owned()]);
        r.local_queries = LocalQueries::Disabled;
        r
    }

    fn tty() -> Ctx {
        Ctx {
            json: true,
            non_interactive: false,
            home: None,
            stdin_tty: true,
        }
    }

    /// ADR-0007 §6 (M2-R06): the prompt shows the authorization sentence and the
    /// file:line list; with nothing found it still prompts, saying so.
    #[test]
    fn authorization_text_lists_found_commands_or_says_none_found_now() {
        let (_d, local) = scratch_context(
            "Host lab\n    HostName lab.example.invalid\n    ProxyCommand nc %h %p\n",
        );
        let text = authorization_text(&local, &["lab".to_owned()]).unwrap_or_default();
        assert!(text.contains(AUTHORIZATION_TEXT), "{text}");
        assert!(text.contains("~/.ssh/config:3"), "{text}");
        let (_d, inert) = scratch_context("Host lab\n    HostName lab.example.invalid\n");
        let text = authorization_text(&inert, &["lab".to_owned()]).unwrap_or_default();
        assert!(text.contains(NONE_FOUND_TEXT), "{text}");
    }

    /// A tree the static pass cannot fully read is declined, and no prompt is shown.
    #[test]
    fn an_unreadable_tree_shows_no_prompt() {
        let (_d, local) = scratch_context("");
        // An included file over the 1 MiB file bound: the static pass cannot fully read
        // the tree, so the level is declined and nothing is offered.
        let big = local.paths.user_dir.join("big.conf");
        std::fs::write(&big, "# x\n".repeat(400_000)).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(
            &local.paths.user_config,
            format!(
                "Include {}\nHost lab\n    HostName lab.example.invalid\n",
                big.display()
            ),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(authorization_text(&local, &["lab".to_owned()]), None);
    }

    /// Interactive: anything but `yes` exits 3 and runs nothing (no level performed);
    /// `yes` runs the level with the authorization recorded.
    #[test]
    fn interactive_authorization_needs_a_typed_yes() {
        let (_d, local) = scratch_context("Host lab\n    HostName 127.0.0.1\n    Port 9\n");
        let mut p = Script {
            answers: vec![Answer::No],
            shown: Vec::new(),
        };
        let out = block_on(doctor(
            &tty(),
            &local,
            request(&[ProbeLevel::Evaluate], true),
            &mut p,
        ));
        assert_eq!(out.exit, ExitCode::InteractionRequired);
        assert_eq!(p.shown.len(), 1);
        assert!(p.shown[0].contains(AUTHORIZATION_TEXT));
        // Without the flag nothing is asked and the level is declined.
        let mut p = Script {
            answers: vec![],
            shown: Vec::new(),
        };
        let out = block_on(doctor(
            &tty(),
            &local,
            request(&[ProbeLevel::Evaluate], false),
            &mut p,
        ));
        assert!(p.shown.is_empty());
        assert_eq!(out.exit, ExitCode::Success);
        assert_eq!(
            out.env.data["probes"]
                .as_array()
                .and_then(|p| p.iter().find(|r| r["level"] == "evaluate"))
                .map(|r| r["decline_reason"].clone()),
            Some(serde_json::json!("config_commands_not_authorized"))
        );
    }

    /// `--non-interactive`: the flag is the authorization (no prompt), and a non-TTY
    /// stdin without it cannot confirm (exit 3, nothing runs).
    #[test]
    fn non_interactive_flag_is_the_authorization_and_a_bare_pipe_is_refused() {
        let (_d, local) = scratch_context("Host lab\n    HostName lab.example.invalid\n");
        let mut p = Script {
            answers: vec![],
            shown: Vec::new(),
        };
        let pipe = Ctx {
            stdin_tty: false,
            ..tty()
        };
        let out = block_on(doctor(
            &pipe,
            &local,
            request(&[ProbeLevel::Evaluate], true),
            &mut p,
        ));
        assert_eq!(out.exit, ExitCode::InteractionRequired);
        assert!(p.shown.is_empty());
        let ni = Ctx {
            non_interactive: true,
            ..tty()
        };
        assert!(
            block_on(authorize(
                &ni,
                &local,
                &request(&[ProbeLevel::Evaluate], true),
                &mut p
            ))
            .is_ok()
        );
        assert!(p.shown.is_empty());
    }
}
