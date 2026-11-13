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
//! * **The authorization step has exactly two outcomes** (ADR-0007 §12.31 item 2, Q02):
//!   authorized (a typed `yes`, or `--non-interactive` with the flag) or not authorized.
//!   When no alias can be offered, nothing is asked and nothing is authorized: "nothing
//!   runnable" (no usable alias) and "the configuration could not be read" (no alias
//!   whose tree the static pass could fully read, or the alias listing itself could not
//!   be read). The run is then given no authorization, so no real-tree level can run
//!   whatever a later pass sees, and every real-tree record of the invocation is
//!   `declined` with the step's reason (`config_not_fully_readable`, or
//!   `config_commands_not_authorized` when nothing was runnable).
//! * `--active-probe agent` records a lapse (`WithdrawDeclaration { revision, reason:
//!   listing_missing }`) for each declared identity the listing lacked, only when the
//!   runtime is already running; otherwise the finding `interaction_declaration_lapsed`
//!   says `recorded: false` and names the exact command (ADR-0007 §7; QR9).
//! * Every probe that ran the real tree lists its configuration commands under the
//!   heading "configuration commands found before the run; the run may have executed
//!   others" (human), and the `--json` envelope carries the same text as the warning
//!   `config_commands_inventory`; no output calls the list complete (M2-S04).
//! * The doctor exits 0 when it completes, whatever its findings.
//! * ⟨M03⟩ (m03-plan U12, §5 item 14) The static level also reports, from facts this
//!   module reads read-only ([`managed_facts`]; the runtime is never started):
//!   `slot_free` for each managed alias whose pair prefers managed certificates, whose
//!   projection is applied and whose slot no binding holds, with the command that holds
//!   one (ADR-0008 D10 item 2, §17.4 item 12); and `managed_dir_unsafe` for each managed
//!   directory under `<runtime_dir>/b/` or `<state_dir>/managed/` that is not owner-only
//!   (§17.20 item 15), reported only, never repaired.
//! * ⟨M03⟩ (ADR-0008 §17.25 item 13) From the store, read-only: `enrollment_evidence_stale`
//!   for each `verified` enrollment whose evidence is no longer fresh, and
//!   `reverification_inconclusive` for each whose last re-verification ended
//!   inconclusive ([`enrollment_facts`]); and, where an issuer CA is registered,
//!   `client_trace_family_unrecorded` when the selected `ssh`'s family and version have
//!   no row in `heimdall_enroll::trace::RECORDED` ([`client_trace_finding`]).
//! * ⟨M03⟩ [`pending_chores`] is the store-backed reader of the chores the CLI and the
//!   TUI show: `time_confirmation_after_reboot` with its one command,
//!   `heimdall time confirm`, pending exactly when the time gate would refuse an
//!   issuance for lack of a time reference for this boot and an issuer CA is
//!   registered (ADR-0008 D9 item 5, §17.25 item 12; [`time_confirmation_pending`]).
//!   [`with_status_chores`] adds them to the bare `heimdall` status.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;

use heimdall_contract::Timestamp;
use heimdall_contract::catalog::{CatalogRequest, WithdrawReason};
use heimdall_contract::doctor::{AliasDefinition, DoctorReport, Finding, FindingSeverity, finding};
use heimdall_contract::envelope::{Envelope, NextAction, ResourceRef, Warning};
use heimdall_contract::ids::IdentityId;
use heimdall_contract::provider::{InteractionKind, ProbeLevel};
use heimdall_contract::request::Request;
use heimdall_contract::setup::ConflictKind;
use heimdall_contract::{Code, ExitCode};
use heimdall_domain::catalog::{DestinationDefinition, IdentityRecord, InteractionDeclaration};
use heimdall_localenv::agents::EndpointLocator;
use heimdall_localenv::doctor::{
    CatalogAlias, CatalogIdentity, DoctorRequest, FreeSlot, LocalContext, ManagedFacts,
};
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
    let mut local = local;
    local.managed = managed_facts(ctx);
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
    // ADR-0007 §12.31 item 2 (Q02): a skipped authorization never authorizes. The run is
    // given the flag only when the step authorized; otherwise it runs without it (so no
    // real-tree level can run, whatever its own pass sees) and every real-tree record is
    // declined with the step's reason.
    let mut run_request = request.clone();
    let mut not_authorized = None;
    if wants_real_tree && request.allow_config_commands {
        match authorize(ctx, local, &request, p).await {
            Ok(Authorization::Authorized) => {}
            Ok(Authorization::NotAuthorized(reason)) => {
                run_request.allow_config_commands = false;
                not_authorized = Some(reason);
            }
            Err(o) => return o,
        }
    }
    let local2 = local.clone();
    let req2 = run_request;
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
    if let Some(reason) = not_authorized {
        decline_real_tree(&mut report, reason);
    }
    if request.levels.contains(&ProbeLevel::Agent) {
        record_lapses(ctx, &mut report).await;
    }
    // ⟨ADR-0008 §17.25 item 13⟩ Only where managed certificates are set up (an issuer CA
    // is registered) does the trace row matter: enrollment verification reads it.
    if let Some(f) = client_trace_finding(&report, local.platform.is_windows())
        && ca_registered(ctx)
    {
        report.findings.push(f);
    }
    // ⟨ADR-0008 §17.28 item 6⟩ The issuer's access-list denial, as the running runtime's
    // `issuer.status` reports it (never starting one; the doctor never reads a CA key).
    if ca_registered(ctx)
        && let Some(f) = issuer_store_finding(ctx).await
    {
        report.findings.push(f);
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
            reason: None,
        });
    }
    Outcome::of(env).with_human(human)
}

/// What the `--allow-config-commands` authorization step gave (ADR-0007 §12.31 item 2,
/// Q02): exactly one of two outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Authorization {
    /// A typed `yes` on an interactive TTY, or `--non-interactive` with the flag (the
    /// flag itself is the authorization, as documented; every probe record says so).
    Authorized,
    /// Nothing was asked, so nothing was authorized: no alias could be offered. The
    /// reason is a `decline_reason`: `config_not_fully_readable` when the configuration
    /// could not be read (an alias's tree, or the alias listing), otherwise
    /// `config_commands_not_authorized` (nothing runnable). Every real-tree level of the
    /// invocation is declined with it ([`decline_real_tree`]).
    NotAuthorized(&'static str),
}

/// The prompt text for `--allow-config-commands` over `aliases` (module docs). When no
/// alias can run, no prompt is shown and the error is the reason nothing was offered
/// ([`Authorization::NotAuthorized`]): `config_not_fully_readable` when an alias was left
/// out because the static pass could not fully read its tree, otherwise
/// `config_commands_not_authorized` (no alias, or none usable on a command line).
pub(crate) fn authorization_text(
    local: &LocalContext,
    aliases: &[String],
) -> Result<String, &'static str> {
    let mut found: Vec<String> = Vec::new();
    let mut runnable = false;
    let mut unreadable = false;
    for alias in aliases {
        if !heimdall_localenv::probe::alias_is_usable(alias) {
            continue;
        }
        let pass = heimdall_localenv::probe::static_pass(local, alias, None);
        if pass.not_fully_readable {
            unreadable = true;
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
        return Err(if unreadable {
            heimdall_contract::doctor::decline_reason::CONFIG_NOT_FULLY_READABLE
        } else {
            heimdall_contract::doctor::decline_reason::CONFIG_COMMANDS_NOT_AUTHORIZED
        });
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
    Ok(format!(
        "--allow-config-commands {AUTHORIZATION_TEXT}.\nConfiguration commands the static pass found for {}:\n{list}\nAllow the probes to run your configuration?\n",
        aliases.join(", ")
    ))
}

/// The authorization step for `--allow-config-commands` (module docs; ADR-0007 §12.31
/// item 2): the typed `yes` on an interactive TTY, or the flag itself under
/// `--non-interactive`. When no alias can be offered nothing is asked and the step is
/// [`Authorization::NotAuthorized`], never an authorization. A refusal (anything but
/// `yes`, or a non-TTY stdin without `--non-interactive`) is the `Err` outcome: exit 3,
/// nothing runs.
async fn authorize<P: Prompter>(
    ctx: &Ctx,
    local: &LocalContext,
    request: &DoctorRequest,
    p: &mut P,
) -> Result<Authorization, Outcome> {
    if ctx.non_interactive {
        // The flag itself is the authorization; every probe record says so.
        return Ok(Authorization::Authorized);
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
            match tokio::task::spawn_blocking(move || heimdall_localenv::doctor::run(&l, &passive))
                .await
            {
                Ok(r) => r.aliases.into_iter().map(|a| a.alias).collect(),
                // The listing could not be read: nothing is offered, nothing authorized.
                Err(_) => {
                    return Ok(Authorization::NotAuthorized(
                        heimdall_contract::doctor::decline_reason::CONFIG_NOT_FULLY_READABLE,
                    ));
                }
            }
        }
    };
    let text = match authorization_text(local, &aliases) {
        Ok(text) => text,
        Err(reason) => return Ok(Authorization::NotAuthorized(reason)),
    };
    let answer = p.ask(&text).await;
    if answer == Answer::Yes {
        Ok(Authorization::Authorized)
    } else {
        Err(Outcome::of(not_confirmed(None, None, answer.reason())))
    }
}

/// ADR-0007 §12.31 item 2 (Q02): after a run whose authorization step did not authorize
/// (so the run itself had no `allow_config_commands`, and none of its real-tree levels
/// ran anything), every real-tree record becomes `declined` with the step's `reason`,
/// whatever that run's own pass saw: a usable or an unusable alias, a tree readable now
/// or not, or no alias at all (the level's `*` record). Those levels are then declined,
/// never performed.
fn decline_real_tree(report: &mut DoctorReport, reason: &'static str) {
    for r in report
        .probes
        .iter_mut()
        .filter(|r| REAL_TREE.contains(&r.level))
    {
        *r = heimdall_localenv::probe::declined(r.level, &r.target, reason);
        report.levels_performed.remove(&r.level);
        report.levels_declined.insert(r.level);
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

/// The SSH paths this invocation uses ([`ssh_paths`] under its own test configuration):
/// the account's, or the debug build's scratch home.
pub(crate) fn account_ssh_paths() -> Result<SshPaths, Outcome> {
    let hooks = crate::testcfg::launch_hooks(&|n| std::env::var_os(n))
        .map_err(|m| crate::setup_cmd::usage(&m))?;
    ssh_paths(&hooks)
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

// --- ⟨M03⟩ managed facts and pending chores (m03-plan U12) ------------------------------

/// The doctor's M03 facts (module docs), read-only: the managed aliases whose slot is
/// free, and the managed directory trees to check. Empty when the store cannot be read.
pub(crate) fn managed_facts(ctx: &Ctx) -> ManagedFacts {
    let mut facts = ManagedFacts::default();
    if let Ok(paths) = ctx.paths() {
        // `heimdall_credential::endpoints::BINDING_DIR` and the slot level of
        // `heimdall_localenv::projection::content::managed_slot_paths`.
        facts.dirs = vec![
            (paths.runtime_dir.clone(), "b".to_owned()),
            (paths.state_dir.clone(), "managed".to_owned()),
        ];
    }
    facts.free_slots = free_slots(ctx);
    let (stale, inconclusive) = enrollment_facts(ctx, Timestamp::now());
    facts.stale_evidence = stale;
    facts.inconclusive_reverifications = inconclusive;
    facts
}

/// The error reasons a re-verification that ended inconclusive settles with
/// (`enrollment_m03::verify::verdict_error` for an `Inconclusive` verdict).
const INCONCLUSIVE_REASONS: [&str; 3] = [
    heimdall_contract::envelope::reason::VERIFICATION_INCONCLUSIVE,
    heimdall_contract::envelope::reason::DESTINATION_CLOCK_SKEW,
    heimdall_contract::envelope::reason::CA_NOT_HELD,
];

/// ⟨ADR-0008 §17.25 item 13⟩ The `verified` enrollments the doctor reports, read from
/// the store read-only, at wall time `now`:
/// * **stale evidence** (`enrollment_evidence_stale`): the record's evidence is fresh
///   until `now` or earlier, or none is recorded;
/// * **an inconclusive re-verification** (`reverification_inconclusive`): its last two
///   enrollment events are `reverifying` then `verified`, both by one operation, and
///   the record's evidence is not that operation's. A re-verification that passed
///   records its own evidence; one that ended inconclusive returns to `verified` with
///   the earlier evidence unchanged (D5 §6.5). The reason is the operation's error
///   reason, while the operation is still recorded. Events trimmed by retention leave
///   nothing to report.
///
/// Both lists are empty when the store cannot be read.
fn enrollment_facts(
    ctx: &Ctx,
    now: Timestamp,
) -> (
    Vec<heimdall_localenv::doctor::EnrollmentFact>,
    Vec<heimdall_localenv::doctor::EnrollmentFact>,
) {
    let Ok(store) = open_store(ctx) else {
        return (Vec::new(), Vec::new());
    };
    store
        .transaction(|tx| enrollment_facts_in(tx, now))
        .unwrap_or_default()
}

/// [`enrollment_facts`] inside one read transaction.
#[allow(clippy::type_complexity)]
fn enrollment_facts_in(
    tx: &mut heimdall_store::Txn<'_>,
    now: Timestamp,
) -> heimdall_store::Result<(
    Vec<heimdall_localenv::doctor::EnrollmentFact>,
    Vec<heimdall_localenv::doctor::EnrollmentFact>,
)> {
    use heimdall_contract::enrollment::EnrollmentState;
    use heimdall_contract::event::{EventFilter, EventType};
    use heimdall_contract::ids::{EnrollmentId, OperationId};
    use heimdall_contract::managed::EnrollmentEventPayload;
    use heimdall_localenv::doctor::EnrollmentFact;
    use std::collections::BTreeMap;

    let mut verified = Vec::new();
    for issuer in tx.issuers()? {
        for r in tx.enrollments_for_ca(&issuer.ca_fingerprint)? {
            if r.state == EnrollmentState::Verified {
                verified.push(r);
            }
        }
    }
    if verified.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    // The last two (state, operation) events of each enrollment, oldest first.
    type Step = (EnrollmentState, Option<OperationId>);
    let mut last: BTreeMap<EnrollmentId, (Option<Step>, Option<Step>)> = BTreeMap::new();
    if let Some(environment) = tx.self_environment()? {
        let filter = EventFilter {
            operation_id: None,
            types: vec![EventType::Enrollment],
        };
        let mut after = 0;
        loop {
            let page = tx.stored_events_after(&environment, after, &filter, 500)?;
            let Some(tail) = page.events.last() else {
                break;
            };
            after = tail.seq;
            for e in page.events {
                if let Ok(p) = serde_json::from_value::<EnrollmentEventPayload>(e.event.payload) {
                    let entry = last.entry(p.enrollment_id).or_default();
                    *entry = (entry.1.take(), Some((p.state, p.operation_id)));
                }
            }
        }
    }
    let mut stale = Vec::new();
    let mut inconclusive = Vec::new();
    for r in verified {
        let fresh_until = r.evidence.as_ref().map(|e| e.fresh_until);
        let fact = |operation: Option<OperationId>, reason: Option<String>| EnrollmentFact {
            enrollment: r.id.clone(),
            marker: r.marker.clone(),
            destination: r.destination.clone(),
            fresh_until,
            operation,
            reason,
        };
        if fresh_until.is_none_or(|t| t <= now) {
            stale.push(fact(None, None));
        }
        if let Some((
            Some((EnrollmentState::Reverifying, Some(started))),
            Some((EnrollmentState::Verified, Some(ended))),
        )) = last.get(&r.id)
            && started == ended
            && r.evidence.as_ref().is_none_or(|e| e.operation != *ended)
        {
            let reason = tx
                .operation(ended)?
                .and_then(|o| o.result)
                .and_then(|v| v["error"]["reason"].as_str().map(str::to_owned))
                .filter(|r| INCONCLUSIVE_REASONS.contains(&r.as_str()));
            inconclusive.push(fact(Some(ended.clone()), reason));
        }
    }
    Ok((stale, inconclusive))
}

/// Every managed alias whose pair prefers managed certificates, whose projection is
/// applied, and whose slot in this installation's environment is not held (ADR-0008
/// D10 item 2: ordinary `ssh <alias>` then fails closed). Read-only; none when the
/// store cannot be read or no environment was created yet.
fn free_slots(ctx: &Ctx) -> Vec<FreeSlot> {
    use heimdall_domain::enrollment::{PreferredMechanism, ProjectionStatus};
    use heimdall_domain::managed::SlotState;
    let Ok(store) = open_store(ctx) else {
        return Vec::new();
    };
    store
        .transaction(|tx| {
            let Some(environment) = tx.self_environment()? else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            for d in tx.destinations()? {
                let DestinationDefinition::Managed { account, .. } = &d.definition else {
                    continue;
                };
                let pair = heimdall_domain::scope::AccessPair {
                    destination: d.id.clone(),
                    account: account.clone(),
                };
                let Some(preference) = tx.pair_preference(&pair)? else {
                    continue;
                };
                if preference.mechanism != PreferredMechanism::ManagedCertificate
                    || !matches!(preference.projection, ProjectionStatus::Applied { .. })
                {
                    continue;
                }
                if !matches!(tx.slot(&environment, &pair)?, SlotState::Held { .. }) {
                    out.push(FreeSlot {
                        alias: d.alias.clone(),
                        destination: d.id.clone(),
                    });
                }
            }
            Ok(out)
        })
        .unwrap_or_default()
}

/// The chore's name: `ReadinessCondition::TimeConfirmationAfterReboot` on the wire.
pub(crate) const TIME_CONFIRMATION_CHORE: &str = "time_confirmation_after_reboot";

/// The chore's one command.
pub(crate) const TIME_CONFIRM_COMMAND: &str = "heimdall time confirm";

/// A chore the owner has to do before Heimdall can go on (m03-plan U12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingChore {
    /// Its stable name.
    pub(crate) chore: &'static str,
    /// Its one command.
    pub(crate) command: &'static str,
    /// Human text naming the command.
    pub(crate) message: String,
}

/// ⟨ADR-0008 §17.25 item 13⟩ `client_trace_family_unrecorded`: the selected `ssh`'s
/// version (the static level's local query; none under `--no-local-exec`), in the
/// release family the runtime's Verifier gives it (Win32-OpenSSH on Windows, portable
/// elsewhere), has no recorded row in `heimdall_enroll::trace::RECORDED`
/// (`patterns_for`), so every verification with it ends inconclusive. Names the family
/// and the version; it carries no path or host name, so `--redact` changes nothing.
pub(crate) fn client_trace_finding(report: &DoctorReport, windows: bool) -> Option<Finding> {
    use heimdall_contract::request::ConsumerKind;
    use heimdall_enroll::trace::{ClientFamily, ClientVersion, RECORDED, patterns_for};
    let ssh = report
        .clients
        .iter()
        .find(|c| c.consumer == ConsumerKind::Ssh && c.selected)?;
    let parsed = ClientVersion::parse(ssh.version.as_deref()?)?;
    let family = if windows {
        ClientFamily::Win32
    } else {
        ClientFamily::Portable
    };
    let unrecorded = patterns_for(family, ClientVersion { family, ..parsed }).err()?;
    let recorded: Vec<String> = RECORDED
        .iter()
        .map(|p| {
            if p.from == p.to {
                format!("{} {}", p.family.as_str(), p.from)
            } else {
                format!("{} {} to {}", p.family.as_str(), p.from, p.to)
            }
        })
        .collect();
    Some(Finding {
        code: finding::CLIENT_TRACE_FAMILY_UNRECORDED.to_owned(),
        severity: FindingSeverity::Problem,
        subject: ResourceRef {
            kind: "executable".to_owned(),
            id: Some("ssh".to_owned()),
        },
        level: ProbeLevel::Static,
        provenance: None,
        message: format!(
            "the selected ssh is {}: no client trace is recorded for that family and version, so every enrollment verification with it ends inconclusive; recorded: {}",
            unrecorded.detail(),
            recorded.join(", ")
        ),
        next: NextAction {
            action: "change_client".to_owned(),
            ..NextAction::default()
        },
        reason: None,
    })
}

/// Whether `time_confirmation_after_reboot` is pending (ADR-0008 §17.25 item 12): the
/// time gate's verdict `status` refuses for lack of a time reference for this boot
/// (`Unsynchronized`: no same-boot runtime anchor or attended confirmation, and time
/// synchronization is not trusted in M03, Q13), **and** an issuer CA is registered. A
/// never-confirmed store is therefore included; a store with no CA, a clock below the
/// high-water mark (a rollback that no confirmation clears) and a same-boot skew are
/// not this chore.
pub(crate) fn time_confirmation_pending(
    status: &heimdall_domain::time::TimeStatus,
    ca_registered: bool,
) -> bool {
    use heimdall_domain::time::{TimeStatus, TimeUncertainty};
    ca_registered
        && matches!(
            status,
            TimeStatus::Uncertain(TimeUncertainty::Unsynchronized { .. })
        )
}

/// ⟨ADR-0008 §17.28 item 6⟩ `issuer_store_access_denied` when a runtime is already running
/// (never started here) and its `issuer.status` reports that the CA key store's access
/// list denied the issuer a read (on macOS, an ad-hoc-signed build after an update). Only
/// the issuer child and the owner-present ceremony ever read a CA key (ADR-0008 D1), so
/// with no runtime running nothing is reported. `None` otherwise.
async fn issuer_store_finding(ctx: &Ctx) -> Option<Finding> {
    use heimdall_contract::envelope::reason;
    use heimdall_contract::issuer::{IssuerRequest, IssuerStatus};
    let mut client = crate::client::connect(ctx, false).await.ok()?;
    let env = client.request(Request::Issuer(IssuerRequest::Status)).await;
    if !env.code.is_success() {
        return None;
    }
    let status: IssuerStatus = serde_json::from_value(env.data).ok()?;
    issuer_store_finding_of(&status, reason::ISSUER_STORE_ACCESS_DENIED)
}

/// The finding for an `issuer.status` whose reason is `denied` (module docs).
fn issuer_store_finding_of(
    status: &heimdall_contract::issuer::IssuerStatus,
    denied: &str,
) -> Option<Finding> {
    if status.reason.as_deref() != Some(denied) {
        return None;
    }
    Some(Finding {
        code: finding::ISSUER_STORE_ACCESS_DENIED.to_owned(),
        severity: FindingSeverity::Problem,
        subject: ResourceRef {
            kind: "issuer".to_owned(),
            id: None,
        },
        level: ProbeLevel::Static,
        provenance: None,
        message: format!(
            "the issuer cannot read its CA key, so no certificate can be issued (issuer_store_access_denied): {}",
            heimdall_app::issuer::STORE_ACCESS_DENIED_GUIDANCE
        ),
        next: NextAction {
            action: "owner_decision".to_owned(),
            ..NextAction::default()
        },
        reason: Some(denied.to_owned()),
    })
}

/// Whether an issuer CA is registered: one that is neither `deleted` nor `retired`.
fn ca_registered_in(tx: &mut heimdall_store::Txn<'_>) -> heimdall_store::Result<bool> {
    use heimdall_contract::issuer::CaState;
    Ok(tx
        .issuers()?
        .iter()
        .any(|i| !matches!(i.state, CaState::Deleted | CaState::Retired)))
}

/// Whether an issuer CA is registered in the store, read read-only (`false` when the
/// store cannot be read).
fn ca_registered(ctx: &Ctx) -> bool {
    open_store(ctx)
        .and_then(|s| s.transaction(ca_registered_in).map_err(|e| e.to_string()))
        .unwrap_or(false)
}

/// The pending chores, read from the store read-only (the runtime is never started).
/// The time chore asks the time gate itself (`heimdall_app::TimeGate`'s read-only
/// assessment, the one an issuance uses) over this process's clock: nothing is
/// persisted. Empty when the store cannot be read.
pub(crate) fn pending_chores(ctx: &Ctx) -> Vec<PendingChore> {
    use std::sync::Arc;
    let Ok(store) = open_store(ctx) else {
        return Vec::new();
    };
    let store = Arc::new(store);
    let gate = heimdall_app::TimeGate::new(
        Arc::clone(&store),
        Arc::new(heimdall_runtime::platform::SystemClock::new()),
        Arc::new(heimdall_runtime::platform::SystemTimeSync),
        heimdall_domain::time::TimePolicy::default(),
    );
    let Ok((status, ca)) = store.transaction(|tx| {
        let (_, status) = gate.assess_read_only_in(tx)?;
        Ok((status, ca_registered_in(tx)?))
    }) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if time_confirmation_pending(&status, ca) {
        out.push(PendingChore {
            chore: TIME_CONFIRMATION_CHORE,
            command: TIME_CONFIRM_COMMAND,
            message: format!(
                "this machine's time has no trusted reference for this boot (it restarted, or the time was never confirmed); managed issuance waits until you confirm the time once, attended: run `{TIME_CONFIRM_COMMAND}`"
            ),
        });
    }
    out
}

/// Add `chores` to `env`'s data (only when some are pending, so an envelope without one
/// is unchanged); an error envelope's message also names them.
pub(crate) fn add_chores(env: &mut Envelope<serde_json::Value>, chores: &[PendingChore]) {
    if chores.is_empty() {
        return;
    }
    let listed: Vec<serde_json::Value> = chores
        .iter()
        .map(|c| {
            serde_json::json!({
                "chore": c.chore,
                "command": c.command,
                "message": c.message,
            })
        })
        .collect();
    if let serde_json::Value::Object(map) = &mut env.data {
        if let Some(serde_json::Value::Object(error)) = map.get_mut("error")
            && let Some(serde_json::Value::String(message)) = error.get_mut("message")
        {
            for c in chores {
                message.push_str(&format!(
                    "; pending chore: run `{}` ({})",
                    c.command, c.chore
                ));
            }
        }
        map.insert("chores".to_owned(), serde_json::Value::Array(listed));
    }
}

/// The bare `heimdall` status (`cli::status`, either outcome) with the pending chores
/// added ([`add_chores`]). ⟨U-R1⟩ `cli.rs` (the integrator's) calls it from the
/// `Command::Status` arm; the TUI reuses [`pending_chores`].
pub(crate) fn with_status_chores(ctx: &Ctx, mut done: crate::cli::Done) -> crate::cli::Done {
    add_chores(&mut done.env, &pending_chores(ctx));
    done
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether every record of `level` was declined.
    #[cfg(unix)]
    fn declined_everywhere(report: &DoctorReport, level: ProbeLevel) -> bool {
        report
            .probes
            .iter()
            .filter(|r| r.level == level)
            .all(|r| r.outcome == heimdall_contract::doctor::ProbeOutcome::Declined)
    }

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
        assert_eq!(
            authorization_text(&local, &["lab".to_owned()]),
            Err(heimdall_contract::doctor::decline_reason::CONFIG_NOT_FULLY_READABLE)
        );
        // Nothing runnable for another reason (no alias, none usable): not authorized,
        // with its own reason.
        for aliases in [&[][..], &["-oProxyCommand=x".to_owned()][..]] {
            assert_eq!(
                authorization_text(&local, aliases),
                Err(heimdall_contract::doctor::decline_reason::CONFIG_COMMANDS_NOT_AUTHORIZED),
                "{aliases:?}"
            );
        }
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
        assert!(matches!(
            block_on(authorize(
                &ni,
                &local,
                &request(&[ProbeLevel::Evaluate], true),
                &mut p
            )),
            Ok(Authorization::Authorized)
        ));
        assert!(p.shown.is_empty());
    }

    /// The reviewer's interleaving (ADR-0007 §12.31 item 2, Q02), deterministic: a
    /// disposable `ssh` on the scratch `PATH` whose `-V` query (a local query of the
    /// doctor's own run, after the authorization step) rewrites the user configuration
    /// into `inert`, and whose every other invocation (the `evaluate` level's `ssh -G`)
    /// creates the marker. Returns the scratch directory, the context and the marker.
    #[cfg(unix)]
    fn rewriting_ssh(initial: &str, inert: &str) -> (tempfile::TempDir, LocalContext, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let (dir, mut local) = scratch_context(initial);
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap_or_else(|e| panic!("{e}"));
        let marker = dir.path().join("evaluation-ran");
        let stub = bin.join("ssh");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then\n  printf '{}' > '{}'\n  echo 'OpenSSH_9.9p1, LibreSSL 3.3.6' >&2\n  exit 0\nfi\n: > '{}'\nexit 0\n",
                inert.replace('\n', "\\n"),
                local.paths.user_config.display(),
                marker.display()
            ),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("{e}"));
        local.env = Env::from_vars([
            ("HOME", local.paths.account_home.display().to_string()),
            ("PATH", bin.display().to_string()),
        ]);
        (dir, local, marker)
    }

    /// The `level` records of `out`'s report.
    #[cfg(unix)]
    fn records(out: &Outcome, level: &str) -> Vec<serde_json::Value> {
        out.env.data["probes"]
            .as_array()
            .map(|p| p.iter().filter(|r| r["level"] == level).cloned().collect())
            .unwrap_or_default()
    }

    /// ADR-0007 §12.31 item 2 (Q02), the reviewer's reproduction: the alias's tree has an
    /// `Include` the static pass cannot expand, so the authorization step offers nothing
    /// and asks nothing (a TTY that would answer no `yes`). Before the doctor's own run
    /// evaluates anything, its `ssh -V` query makes the tree readable and inert. A skipped
    /// authorization is not authorized: no evaluation runs (no marker), and the
    /// `evaluate` record is declined with the step's reason, `config_not_fully_readable`,
    /// although the run's own pass could read the tree. Exit 0, as for any completed
    /// doctor.
    #[cfg(unix)]
    #[test]
    fn q02_unreadable_then_readable_tree_runs_no_evaluation() {
        let inert = "Host lab\n    HostName 127.0.0.1\n    Port 9\n";
        let (_d, local, marker) = rewriting_ssh(
            &format!("Include ${{HM_FIXTURE_UNSET_VARIABLE}}/x.conf\n{inert}"),
            inert,
        );
        assert_eq!(
            authorization_text(&local, &["lab".to_owned()]),
            Err(heimdall_contract::doctor::decline_reason::CONFIG_NOT_FULLY_READABLE),
            "the step offers nothing"
        );
        let mut request = request(&[ProbeLevel::Evaluate], true);
        request.local_queries = LocalQueries::Enabled;
        let mut p = Script {
            answers: vec![Answer::No],
            shown: Vec::new(),
        };
        let out = block_on(doctor(&tty(), &local, request, &mut p));
        assert_eq!(
            std::fs::read_to_string(&local.paths.user_config)
                .ok()
                .as_deref(),
            Some(inert),
            "the interleaving happened: the run's own query made the tree readable"
        );
        assert!(p.shown.is_empty(), "nothing was asked: {:?}", p.shown);
        assert!(!marker.exists(), "no evaluation ran");
        assert_eq!(out.exit, ExitCode::Success);
        let eval = records(&out, "evaluate");
        assert_eq!(eval.len(), 1, "{eval:?}");
        assert_eq!(eval[0]["outcome"], "declined", "{eval:?}");
        assert_eq!(
            eval[0]["decline_reason"], "config_not_fully_readable",
            "{eval:?}"
        );
        assert_eq!(eval[0]["authorization"], serde_json::json!([]), "{eval:?}");
        let data = &out.env.data;
        assert!(
            data["levels_declined"]
                .as_array()
                .is_some_and(|l| l.contains(&serde_json::json!("evaluate"))),
            "{data}"
        );
        assert!(
            !data["levels_performed"]
                .as_array()
                .is_some_and(|l| l.contains(&serde_json::json!("evaluate"))),
            "{data}"
        );
    }

    /// ADR-0007 §12.31 item 2 (Q02), "nothing runnable": with no `--alias` and no alias
    /// in the configuration, the step offers nothing and asks nothing. The doctor's own
    /// `ssh -V` query then adds alias `lab` to the tree, so the run's own alias list
    /// names it; still no level of the real tree runs for it (no marker), and each of the
    /// three real-tree levels is declined with `config_commands_not_authorized`.
    #[cfg(unix)]
    #[test]
    fn q02_nothing_runnable_then_an_alias_appears_runs_nothing() {
        let (_d, local, marker) =
            rewriting_ssh("", "Host lab\n    HostName 127.0.0.1\n    Port 9\n");
        let mut request = request(
            &[
                ProbeLevel::Evaluate,
                ProbeLevel::HostVerification,
                ProbeLevel::Authentication,
            ],
            true,
        );
        request.aliases = None;
        request.local_queries = LocalQueries::Enabled;
        let mut p = Script {
            answers: vec![Answer::Yes],
            shown: Vec::new(),
        };
        let out = block_on(doctor(&tty(), &local, request, &mut p));
        assert!(p.shown.is_empty(), "nothing was asked: {:?}", p.shown);
        assert!(!marker.exists(), "nothing of the real tree ran");
        assert_eq!(out.exit, ExitCode::Success);
        assert!(
            out.env.data["aliases"]
                .as_array()
                .is_some_and(|a| a.iter().any(|a| a["alias"] == "lab")),
            "the run's own pass found the alias: {}",
            out.env.data
        );
        let report: DoctorReport = serde_json::from_value(out.env.data.clone())
            .unwrap_or_else(|e| panic!("the report: {e}"));
        for level in REAL_TREE {
            assert!(declined_everywhere(&report, level), "{level:?}");
            assert!(report.levels_declined.contains(&level), "{level:?}");
            assert!(!report.levels_performed.contains(&level), "{level:?}");
        }
        for level in ["evaluate", "host_verification", "authentication"] {
            let r = records(&out, level);
            assert!(!r.is_empty(), "{level}");
            for record in &r {
                assert_eq!(record["outcome"], "declined", "{level}: {record}");
                assert_eq!(
                    record["decline_reason"], "config_commands_not_authorized",
                    "{level}: {record}"
                );
            }
        }
    }

    /// ADR-0008 §17.25 item 12: the chore follows the time gate's verdict. Pending only
    /// for `Unsynchronized` (no time reference for this boot) with a CA registered;
    /// never for a safe time, a rollback below the mark, a skew, or without a CA. The
    /// verdicts come from the gate itself.
    #[test]
    fn time_confirmation_is_pending_exactly_when_the_gate_lacks_a_reference() {
        use heimdall_domain::time::{
            AttendedTimeConfirmation, BootId, GateInput, SyncStatus, TimeAnchor, TimePolicy, gate,
        };
        let wall: Timestamp = "2026-11-01T00:00:00Z".parse().unwrap_or_else(|_| panic!());
        let later: Timestamp = "2026-11-01T01:00:00Z".parse().unwrap_or_else(|_| panic!());
        let now = TimeAnchor {
            boot_id: BootId("boot-now".into()),
            continuous: std::time::Duration::from_secs(10),
            wall,
        };
        let policy = TimePolicy::default();
        let input = |previous, high_water, confirmation| GateInput {
            previous,
            high_water,
            now: &now,
            sync: SyncStatus::Unknown,
            confirmation,
            policy: &policy,
        };
        let before = TimeAnchor {
            boot_id: BootId("boot-before".into()),
            ..now.clone()
        };
        let confirmed = AttendedTimeConfirmation {
            boot_id: now.boot_id.clone(),
            continuous: now.continuous,
            wall,
            decision: heimdall_contract::ids::DecisionId::from_random_bytes([1; 16]),
        };
        let skewed = TimeAnchor {
            continuous: std::time::Duration::from_secs(9),
            wall: later,
            ..now.clone()
        };
        // Never confirmed, and after a reboot: no reference for this boot.
        for status in [
            gate(&input(None, None, None)),
            gate(&input(Some(&before), None, None)),
        ] {
            assert!(time_confirmation_pending(&status, true), "{status:?}");
            assert!(
                !time_confirmation_pending(&status, false),
                "no CA: {status:?}"
            );
        }
        // Confirmed in this boot, a rollback below the mark, a same-boot skew: not it.
        for status in [
            gate(&input(None, None, Some(&confirmed))),
            gate(&input(Some(&before), Some(later), None)),
            gate(&input(Some(&skewed), None, None)),
        ] {
            assert!(!time_confirmation_pending(&status, true), "{status:?}");
        }
    }

    /// ⟨ADR-0008 §17.28 item 6⟩ The finding only for an `issuer.status` reporting the
    /// access-list denial (never the lock, another store reason, or none).
    #[test]
    fn issuer_store_finding_only_for_the_access_denial() {
        use heimdall_contract::envelope::reason;
        use heimdall_contract::issuer::{IssuerState, IssuerStatus};
        use heimdall_contract::managed::IssuerIsolation;
        let status = |r: Option<&str>| IssuerStatus {
            state: IssuerState::StoreUnavailable,
            reason: r.map(str::to_owned),
            cas: Vec::new(),
            orphan_store_items: Vec::new(),
            issuer_isolation: IssuerIsolation::SameUserProcess,
            bundle_stale: false,
        };
        let denied = reason::ISSUER_STORE_ACCESS_DENIED;
        let found = issuer_store_finding_of(&status(Some(denied)), denied);
        assert!(found.is_some(), "the access denial is reported");
        let Some(f) = found else { return };
        assert_eq!(f.code, finding::ISSUER_STORE_ACCESS_DENIED);
        assert_eq!(f.reason.as_deref(), Some(denied));
        assert!(
            f.message
                .contains("heimdall issuer restore --backup <file>"),
            "{}",
            f.message
        );
        assert!(f.message.contains("unlocking cannot help"));
        for other in [
            Some(reason::ISSUER_STORE_LOCKED),
            Some(reason::ISSUER_STORE_UNAVAILABLE),
            None,
        ] {
            assert!(
                issuer_store_finding_of(&status(other), denied).is_none(),
                "{other:?}"
            );
        }
    }

    /// §17.25 item 13: an unrecorded family or version is named; a recorded one, no
    /// local query (no version) and no selected ssh give nothing.
    #[test]
    fn client_trace_finding_names_an_unrecorded_family_and_version() {
        use heimdall_contract::doctor::{ClientObservation, ClientSource};
        use heimdall_contract::request::ConsumerKind;
        let report = |version: Option<&str>, selected: bool| DoctorReport {
            levels_performed: BTreeSet::new(),
            levels_declined: BTreeSet::new(),
            clients: vec![ClientObservation {
                consumer: ConsumerKind::Ssh,
                path_display: "/usr/bin/ssh".into(),
                source: ClientSource::Path,
                version: version.map(str::to_owned),
                sha256: None,
                selected,
            }],
            config_files: Vec::new(),
            aliases: Vec::new(),
            providers: Vec::new(),
            projection: None,
            git: None,
            findings: Vec::new(),
            probes: Vec::new(),
        };
        let f = client_trace_finding(&report(Some("OpenSSH_9.9p1"), true), false)
            .unwrap_or_else(|| panic!("unrecorded"));
        assert_eq!(f.code, finding::CLIENT_TRACE_FAMILY_UNRECORDED);
        assert_eq!(f.severity, FindingSeverity::Problem);
        assert_eq!(f.subject.id.as_deref(), Some("ssh"));
        assert_eq!(f.next.action, "change_client");
        assert!(f.message.contains("portable 9.9p1"), "{}", f.message);
        assert!(!f.message.contains("/usr/bin"), "{}", f.message);
        // The same version on Windows is the Win32 family.
        let w = client_trace_finding(&report(Some("OpenSSH_9.9p1"), true), true)
            .unwrap_or_else(|| panic!("unrecorded"));
        assert!(w.message.contains("win32 9.9p1"), "{}", w.message);
        // Recorded rows: portable 10.5p1 and 9.6p1, win32 9.5p2.
        assert!(client_trace_finding(&report(Some("OpenSSH_10.5p1"), true), false).is_none());
        assert!(client_trace_finding(&report(Some("OpenSSH_9.5p2"), true), true).is_none());
        assert!(client_trace_finding(&report(None, true), false).is_none());
        assert!(client_trace_finding(&report(Some("OpenSSH_9.9p1"), false), false).is_none());
    }

    /// The chores are added only when pending; an error envelope's message names the
    /// command too.
    #[test]
    fn chores_are_added_to_status_only_when_pending() {
        let chore = PendingChore {
            chore: TIME_CONFIRMATION_CHORE,
            command: TIME_CONFIRM_COMMAND,
            message: "m".into(),
        };
        let mut ok = Envelope::ok(serde_json::json!({"running": true}));
        add_chores(&mut ok, &[]);
        assert!(ok.data.get("chores").is_none());
        add_chores(&mut ok, std::slice::from_ref(&chore));
        assert_eq!(
            ok.data["chores"][0]["chore"],
            "time_confirmation_after_reboot"
        );
        assert_eq!(ok.data["chores"][0]["command"], "heimdall time confirm");
        let mut err = failure(Code::ServiceUnavailable, "no runtime is running", None);
        add_chores(&mut err, &[chore]);
        assert_eq!(err.data["chores"][0]["command"], "heimdall time confirm");
        let message = err.data["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.ends_with(
                "; pending chore: run `heimdall time confirm` (time_confirmation_after_reboot)"
            ),
            "{message}"
        );
    }
}
