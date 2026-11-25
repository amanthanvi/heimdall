//! `heimdall setup [preview|apply|rollback|repair|status]` (m02-plan U9; ADR-0007 §5).
//!
//! * **Preview first.** `apply`, `rollback` and `repair` first ask the runtime for the
//!   plan (`SetupRequest::Preview`), show it (files and diffs, each affected alias with
//!   its before, after and **restore** columns, the consent need), and only then submit
//!   the effect request carrying that plan's `plan_digest`. There is no `--evaluate`.
//! * **Confirmation contract** (ADR-0006 §3.1, binding on this CLI). On an interactive
//!   TTY the session is attended first, so a plan that needs the owner's decision is
//!   answered `APPROVAL_REQUIRED` with `next.decision_ref`; the CLI then fetches and
//!   shows the exact recorded plan (its digest must be the one shown), requires a typed
//!   `y`/`yes` (default No), and only then sends `Decide approve` and the same request
//!   again (same request ID: the runtime replays the approved operation). Any other
//!   answer, end of input, Ctrl-C, the prompt timeout, a non-TTY stdin or
//!   `--non-interactive` sends nothing more and exits 3 `INTERACTION_REQUIRED` with
//!   `next.decision_ref`. A plan that needs no decision (ADR-0007 §5.2) is applied as
//!   previewed.
//! * **Held operations** (ADR-0007 §5.7). `repair --operation <id> keep` shows its plan
//!   (which moves nothing and lists what stays in place) and needs a typed `yes`
//!   client-side (QR12: no decision record); without one it exits 3 and sends nothing.
//!   `retry` continues the recorded plan. Every other setup command refused with
//!   `setup_in_progress` (or answered `projection_held`) names the held operation and
//!   both repair commands.
//! * **Multi-operation repairs** (ADR-0007 §12.19 item 7). A repair is presented as
//!   complete only when the passive doctor reports no projection conflict left;
//!   otherwise the result says `repair_complete: false` and names the next operation.
//! * **`status`** lists the projection record and resources, each held operation with
//!   each held step's role, path and reason and what each observed name holds, both
//!   repair commands, every non-empty quarantine directory with its entries, and the
//!   snapshots under `<state>/backups` (ADR-0007 §5.5).
//! * **Snapshots** (ADR-0007 §5.5, §12.32 item 2) are the writer's, not this CLI's: the
//!   projection writer copies an original user file (the SSH configuration, the global Git
//!   file) to `<state>/backups` before its first edit of it, whoever submitted the
//!   operation. This module only lists them in `status`.
//! * **A replayed request ID** whose plan changed stays `REQUEST_CONFLICT` (exit 6); the
//!   message says why (ADR-0007 §12.30 item 12).
//!
//! The helpers of the owner-present flow ([`attend_first`], [`approve_request`],
//! [`decided_request`]) are shared with `catalog_cmd` and `uninstall_cmd`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use heimdall_contract::envelope::{EffectStatus, Envelope, NextAction, Warning, reason};
use heimdall_contract::ids::{DecisionId, EnvironmentId, OperationId, ProfileId, RequestId};
use heimdall_contract::managed::LockBehavior;
use heimdall_contract::request::{
    DecideRequest, InspectRequest, InspectSubject, ObserveRequest, PolicyAction, Request, Verdict,
};
use heimdall_contract::setup::{
    ConflictKind, PlanDigest, PreviewIntent, ProjectionItem, RepairResolution, SetupRequest,
};
use heimdall_contract::trust::DecisionScope;
use heimdall_contract::{Code, ExitCode};

use crate::cli::{Prompter, RepairArgs, Session, SetupArgs, SetupCommand, TerminalPrompt};
use crate::client::{Client, Ctx};
use crate::output;
use crate::prompt::Answer;

// --- a finished M02 command -------------------------------------------------------------

/// A finished M02 command: the envelope, its exit status and its human rendering.
pub(crate) struct Outcome {
    /// The envelope printed with `--json`.
    pub(crate) env: Envelope<serde_json::Value>,
    /// The process exit status.
    pub(crate) exit: ExitCode,
    /// The human rendering of the data (stdout in human mode).
    pub(crate) human: String,
}

impl Outcome {
    /// From an envelope, exiting with its code's class (ADR-0006 §6).
    pub(crate) fn of(env: Envelope<serde_json::Value>) -> Outcome {
        let exit = output::exit_code_for(env.code.clone(), false);
        Outcome {
            env,
            exit,
            human: String::new(),
        }
    }

    /// With a human rendering.
    pub(crate) fn with_human(mut self, human: String) -> Outcome {
        self.human = human;
        self
    }

    /// Print it and return its exit status.
    pub(crate) fn emit(self, ctx: &Ctx) -> ExitCode {
        output::emit_rendered(&self.env, ctx.json, &self.human);
        self.exit
    }
}

/// An error envelope with effect `none`.
pub(crate) fn failure(code: Code, message: &str, why: Option<&str>) -> Envelope<serde_json::Value> {
    let mut e =
        heimdall_app::OpError::new(code, message.to_owned()).with_effect(EffectStatus::None);
    if let Some(r) = why {
        e = e.with_reason(r);
    }
    output::error_value(e.into_envelope())
}

/// `USAGE_ERROR`, effect `none` (exit 2).
pub(crate) fn usage(message: &str) -> Outcome {
    Outcome::of(failure(Code::UsageError, message, None))
}

/// Run `f` on a current-thread executor, print its outcome and return its exit status.
pub(crate) fn block<F: std::future::Future<Output = Outcome>>(ctx: &Ctx, f: F) -> ExitCode {
    match crate::service_cmd::current_thread() {
        Ok(rt) => rt.block_on(f).emit(ctx),
        Err(env) => Outcome::of(output::error_value(env)).emit(ctx),
    }
}

/// A connected control session (`allow_start`: effectful commands start the runtime on
/// demand; read-only ones never do).
pub(crate) async fn session(ctx: &Ctx, allow_start: bool) -> Result<Client, Outcome> {
    crate::client::connect(ctx, allow_start)
        .await
        .map_err(|e| Outcome::of(output::error_value(*e)))
}

/// The given idempotency request ID, or a fresh one.
pub(crate) fn request_id(given: Option<&str>) -> Result<RequestId, Outcome> {
    match given {
        Some(r) => RequestId::parse(r).map_err(|_| usage("invalid request ID")),
        None => crate::cli::fresh_request_id().map_err(|d| Outcome::of(d.env)),
    }
}

/// One `inspect` request's data, or its refusal.
pub(crate) async fn inspect<S: Session>(
    s: &mut S,
    subject: InspectSubject,
) -> Result<serde_json::Value, Outcome> {
    let env = s
        .request(Request::Inspect(InspectRequest {
            subject,
            preview: None,
            cwd: None,
            redact: false,
            select: None,
            page: None,
        }))
        .await;
    if env.code.is_success() {
        Ok(env.data)
    } else {
        Err(Outcome::of(env))
    }
}

/// ⟨rev7⟩ The point lookup of the destination named `wanted` (its alias or its ID; ADR-0013
/// §6.3), answered as a listing of what it found (`{"items": [..]}`): an absent destination
/// is an empty listing, a refused lookup its own refusal.
pub(crate) async fn destination_named<S: Session>(
    s: &mut S,
    wanted: &str,
) -> Result<serde_json::Value, Outcome> {
    let found = crate::client::lookup(
        s,
        InspectSubject::Destinations,
        &[wanted.to_owned()],
        &[wanted.to_owned()],
    )
    .await
    .map_err(|e| Outcome::of(*e))?;
    Ok(serde_json::json!({ "items": found.items }))
}

// --- the owner-present flow (ADR-0006 §3.1) ----------------------------------------------

/// The pending decision a result asks for, if any.
pub(crate) fn pending_decision(env: &Envelope<serde_json::Value>) -> Option<String> {
    if !matches!(env.code, Code::InteractionRequired | Code::ApprovalRequired) {
        return None;
    }
    env.next.as_ref().and_then(|n| n.decision_ref.clone())
}

/// Why no prompt can be shown.
pub(crate) fn non_interactive_reason(ctx: &Ctx) -> &'static str {
    if ctx.non_interactive {
        "--non-interactive"
    } else {
        "stdin is not a terminal"
    }
}

/// "Not confirmed": nothing was sent; a pending decision stays pending (exit 3).
pub(crate) fn not_confirmed(
    decision: Option<&str>,
    operation: Option<OperationId>,
    why: &str,
) -> Envelope<serde_json::Value> {
    let mut e = heimdall_app::OpError::new(
        Code::InteractionRequired,
        format!(
            "not confirmed ({why}): nothing was sent; a pending decision stays pending until it expires"
        ),
    )
    .with_effect(EffectStatus::None);
    if let Some(d) = decision {
        e = e
            .with_decision(d.to_owned())
            .with_resource("decision", Some(d.to_owned()));
    }
    if let Some(op) = operation {
        e = e.with_operation(op);
    }
    output::error_value(e.into_envelope())
}

/// Mark the session attended first, on an interactive TTY only (ADR-0006 §13.6 item 7).
pub(crate) async fn attend_first<S: Session>(
    s: &mut S,
    ctx: &Ctx,
) -> Result<(), Envelope<serde_json::Value>> {
    if !ctx.interactive() {
        return Ok(());
    }
    let attended = s.attend().await;
    if attended.code.is_success() {
        Ok(())
    } else {
        Err(attended)
    }
}

/// Show and confirm the current record for an attended request. The preface is
/// built from that same record, including after a stale retry.
pub(crate) async fn approve_request<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    request: &Request,
    env: Envelope<serde_json::Value>,
    preface: impl Fn(&serde_json::Value) -> Result<String, String>,
    expect_digest: Option<&str>,
) -> Result<Envelope<serde_json::Value>, Envelope<serde_json::Value>> {
    if !ctx.interactive() {
        return Err(env);
    }
    crate::cli::retry_stale_decision(
        s,
        p,
        ctx,
        request,
        env,
        &mut 2,
        async |s, p, decision, pending| {
            confirm_recorded(
                s,
                p,
                ctx,
                decision,
                &preface,
                expect_digest,
                pending.operation_id.clone(),
            )
            .await
        },
    )
    .await
}

/// Show the exact recorded request and require a typed `yes` before `Decide approve`.
/// A preface refusal, a changed plan digest or any other answer sends no decision.
async fn confirm_recorded<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    decision: &str,
    preface: impl FnOnce(&serde_json::Value) -> Result<String, String>,
    expect_digest: Option<&str>,
    operation: Option<OperationId>,
) -> Envelope<serde_json::Value> {
    if !ctx.interactive() {
        return not_confirmed(Some(decision), operation, non_interactive_reason(ctx));
    }
    let Ok(decision_id) = DecisionId::parse(decision) else {
        return failure(Code::UsageError, "invalid decision reference", None);
    };
    // ⟨rev7⟩ The decision by a point lookup of exactly its ID (ADR-0013 §6.3).
    let record = match crate::client::lookup(
        s,
        InspectSubject::Decisions,
        &[decision.to_owned()],
        &[],
    )
    .await
    {
        Ok(found) => found.item("decision_id", decision).cloned(),
        Err(e) => return *e,
    };
    let Some(record) = record else {
        return not_confirmed(
            Some(decision),
            operation,
            "the decision is not pending in this runtime",
        );
    };
    let preface = match preface(&record) {
        Ok(text) => text,
        Err(why) => return not_confirmed(Some(decision), operation, &why),
    };
    let request = record
        .get("request")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if let Some(expected) = expect_digest
        && request.get("plan_digest").and_then(|v| v.as_str()) != Some(expected)
    {
        return failure(
            Code::ConfigConflict,
            "the recorded plan is not the plan shown; nothing was approved (preview again)",
            None,
        );
    }
    let field = |k: &str| {
        record
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_owned()
    };
    // The restore column of a recorded projection plan (ADR-0007 §5.2): what each
    // item's behaviour would be if its section were removed now.
    let restore = request
        .get("restore")
        .and_then(|r| r.as_array())
        .filter(|r| !r.is_empty())
        .map(|items| {
            let rows: Vec<String> = items
                .iter()
                .map(|i| {
                    let digest = i.get("digest").and_then(|d| d.as_str()).unwrap_or("");
                    format!(
                        "  {}: restore state {}",
                        i.get("item").and_then(|v| v.as_str()).unwrap_or("?"),
                        digest.get(..12).unwrap_or(digest)
                    )
                })
                .collect();
            format!(
                "Restore column (each item's behaviour if its section were removed now):\n{}\n",
                rows.join("\n")
            )
        })
        .unwrap_or_default();
    // ⟨ADR-0008 §17.27 items 3 and 4⟩ Every disclosure the recorded request carries is
    // shown in words, in every output mode (the prompt is on stderr). One that discloses
    // lock continuity needs the runtime's conditional lock text: without it the approval
    // is refused (exit 3) and nothing is sent, so the once-only acknowledgement is only
    // ever recorded for a decision whose conditional text was shown.
    let lock = if crate::enroll_cmd::carries_lock_disclosure(&request) {
        match crate::m03_cmd::fetch_lock_disclosure_text(s).await {
            Some(t) => Some(t),
            None => return crate::m03_cmd::lock_text_unavailable(Some(decision), operation),
        }
    } else {
        None
    };
    let disclosures = crate::enroll_cmd::recorded_disclosure_prose(&request, lock.as_deref());
    let text = format!(
        "{preface}\n{restore}Owner decision {decision}\n  kind: {}\n  expires: {}\n  recorded request (exactly what approve applies to):\n{}\n\
         {disclosures}\
         Heimdall cannot verify that this prompt was shown: a program running as your user could imitate it.\n\
         Approve exactly this request?\n",
        field("kind"),
        field("expires_at"),
        crate::output::human_json(&request)
            .lines()
            .map(|l| format!("    {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let answer = p.ask(&text).await;
    if answer != Answer::Yes {
        return not_confirmed(Some(decision), operation, answer.reason());
    }
    let request = s.request(Request::Decide(DecideRequest {
        decision_id,
        verdict: Verdict::Approve,
    }));
    output::explain_wait(
        !ctx.json && operation.is_some(),
        "the approved change",
        operation.as_ref(),
        request,
    )
    .await
}

/// An owner-present request (ADR-0006 §3.1): attend first (interactive TTY only), send
/// `request`; when it waits on an owner decision and a prompt can be shown, run
/// [`approve_request`] and send the same request again. Otherwise the runtime's
/// answer stands (`INTERACTION_REQUIRED` with `next.decision_ref` when unattended).
pub(crate) async fn decided_request<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    request: Request,
    preface: &str,
    expect_digest: Option<&str>,
) -> Envelope<serde_json::Value> {
    if let Err(refused) = attend_first(s, ctx).await {
        return refused;
    }
    let env = s.request_with_wait(ctx, request.clone(), None).await;
    let env = match approve_request(
        s,
        p,
        ctx,
        &request,
        env,
        |_| Ok(preface.to_owned()),
        expect_digest,
    )
    .await
    {
        Ok(decided) => {
            s.request_with_wait(ctx, request.clone(), decided.operation_id.as_ref())
                .await
        }
        Err(env) => env,
    };
    settle(s, ctx, request, env).await
}

/// While the answer is `ACCEPTED` with an operation, wait for it (bounded) and replay the
/// same request (same request ID), so the caller sees the settled result.
async fn settle<S: Session>(
    s: &mut S,
    ctx: &Ctx,
    request: Request,
    mut env: Envelope<serde_json::Value>,
) -> Envelope<serde_json::Value> {
    let operation = env.operation_id.clone();
    output::explain_wait(!ctx.json, "setup to finish", operation.as_ref(), async {
        for _ in 0..4 {
            let Some(op) = env
                .operation_id
                .clone()
                .filter(|_| env.code == Code::Accepted)
            else {
                break;
            };
            let _ = s
                .request(Request::Observe(ObserveRequest::Operation {
                    operation_id: op,
                    wait_ms: Some(30_000),
                }))
                .await;
            env = s.request(request.clone()).await;
        }
        env
    })
    .await
}

// --- ⟨M05⟩ U5: the personal-default offer ----------------------------------------------

/// ⟨M05⟩ U5: the disclosure of a personal default (spec §5.2's first-trust message, for
/// ordinary `ssh`; ADR-0011 §3.3's re-entry sentence; the scope it covers), shown before
/// the owner approves the `create {default: true}` decision. It is built **only from the
/// scope the runtime recorded for that decision** (its `inspect decisions` entry's `scope`,
/// ADR-0006 §17.10 item 22; review M05-W3-R01): the pairs and capabilities of the profile
/// revision the record pinned, its environments and the lock behaviour approval applies.
/// The offer's own catalog reads never reach it, so a profile edited between them and the
/// decision can neither add an unshown destination nor show one approval would not add.
pub(crate) fn personal_default_disclosure(scope: &DecisionScope, own: &EnvironmentId) -> String {
    fn list(items: Vec<String>) -> String {
        if items.is_empty() {
            "none".to_owned()
        } else {
            items.join(", ")
        }
    }
    let profile = scope.profile_id.as_str();
    let pairs = list(
        scope
            .pairs
            .iter()
            .map(|p| format!("{}:{}", p.destination.as_str(), p.account.as_str()))
            .collect(),
    );
    let capabilities = list(
        scope
            .capabilities
            .iter()
            .map(|c| {
                serde_json::to_value(c)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_else(|| "?".to_owned())
            })
            .collect(),
    );
    let environments = if scope.environments.len() == 1 && scope.environments.contains(own) {
        "this one only".to_owned()
    } else {
        list(
            scope
                .environments
                .iter()
                .map(|e| {
                    if e == own {
                        format!("{} (this one)", e.as_str())
                    } else {
                        e.as_str().to_owned()
                    }
                })
                .collect(),
        )
    };
    let lock = match scope.lock_behavior {
        LockBehavior::Continue => {
            "Work can continue while your desktop and password manager are locked, using your saved session limits"
        }
        _ => "A session lock ends this access; it works within your saved session limits",
    };
    format!(
        "Use {profile} access automatically for ordinary ssh in this environment?\n\
         {lock} (each use gets one bounded session window, 12 hours at most).\n\
         Access starts again automatically when you next use it, within your saved limits; pause or set a stop time to end it.\n\
         You can pause or remove access at any time.\n\
         Destinations and accounts: {pairs}\n\
         Capabilities: {capabilities}\n\
         Environment: {environments}\n\
         Profile: {profile} at revision {revision}, as the runtime recorded this decision (what approval applies)\n",
        revision = scope.profile_revision,
    )
}

/// The `error.message` of a refused envelope, else its code.
pub(crate) fn refusal_text(env: &Envelope<serde_json::Value>) -> String {
    env.data
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .map_or_else(|| env.code.to_string(), str::to_owned)
}

/// ⟨M05⟩ Why a `create` record without a recorded scope is never approved (review
/// M05-W3-R01): the setup offer, the CLI's review and the TUI refuse it with this.
pub(crate) const SCOPE_NOT_RECORDED: &str =
    "the runtime did not record the scope this approval would apply, so it cannot be shown";

/// ⟨M05⟩ The scope an `inspect decisions` entry records for a `create` (ADR-0006 §17.10
/// item 22), if it carries a well-formed one. A missing or malformed `scope` is `None`,
/// never a guess.
pub(crate) fn recorded_scope(record: &serde_json::Value) -> Option<DecisionScope> {
    serde_json::from_value(record.get("scope")?.clone()).ok()
}

/// ⟨M05⟩ U5 (ADR-0011 §3.1, §3.3, §3.4 "personal default at setup: 1 decision"; spec
/// §5.2; m05-plan U5): after a successful `setup apply`, **on an interactive TTY only**,
/// offer this environment a personal default: the owner `create {profile, environments:
/// [this one], default: true}` decision, confirmed (as [`approve_request`] does) with
/// [`personal_default_disclosure`] of the scope the runtime recorded for that decision and
/// the exact recorded request, both from the same `inspect decisions` entry (ADR-0006 §3.1,
/// §17.10 item 22; review M05-W3-R01). The profile listing only chooses the profile; it is
/// never what the owner is shown. A record without a `scope` is refused before anything is
/// asked (fail closed). Nothing is sent unattended or without a TTY, and nothing is offered
/// when:
/// * the runtime does not serve the trusted-work forms (`inspect policies` refused);
/// * this environment already has a personal default;
/// * no profile is evident: this environment's default-profile preference, else the
///   catalog's only profile;
/// * a personal policy for that profile already applies here (`create` would refuse it).
///
/// The setup result and its exit status are never changed: the returned note (for stderr)
/// says what happened, `None` when nothing was offered. A refusal or anything but a typed
/// `yes` creates nothing (the pending decision expires on its own).
pub(crate) async fn offer_personal_default<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
) -> Option<String> {
    if !ctx.interactive() {
        return None;
    }
    let policies = inspect(s, InspectSubject::Policies).await.ok()?;
    let own = inspect(s, InspectSubject::Environments)
        .await
        .ok()?
        .get("environment_id")
        .and_then(|v| v.as_str())
        .and_then(|v| EnvironmentId::parse(v).ok())?;
    let items = policies
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let personal_here = |q: &serde_json::Value| {
        q.get("workspace_id").is_none_or(serde_json::Value::is_null)
            && q.get("environments")
                .and_then(|e| e.as_array())
                .is_some_and(|e| e.iter().any(|x| x.as_str() == Some(own.as_str())))
    };
    if items.iter().any(|q| {
        personal_here(q) && q.get("default").and_then(serde_json::Value::as_bool) == Some(true)
    }) {
        return None;
    }
    let preferred = policies
        .get("default_profiles")
        .and_then(|v| v.as_array())
        .and_then(|d| {
            d.iter()
                .find(|x| x.get("environment_id").and_then(|e| e.as_str()) == Some(own.as_str()))
        })
        .and_then(|x| x.get("profile_id"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let listed = inspect(s, InspectSubject::Profiles)
        .await
        .ok()?
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let chosen = match &preferred {
        Some(id) => listed
            .iter()
            .find(|x| x.get("profile_id").and_then(|v| v.as_str()) == Some(id.as_str())),
        None if listed.len() == 1 => listed.first(),
        None => None,
    };
    let Some(chosen) = chosen else {
        return (!listed.is_empty()).then(|| {
            "No personal default was offered: choose this environment's default profile first, then run setup again.".to_owned()
        });
    };
    let profile = chosen
        .get("profile_id")
        .and_then(|v| v.as_str())
        .and_then(|v| ProfileId::parse(v).ok())?;
    if items.iter().any(|q| {
        personal_here(q) && q.get("profile").and_then(|v| v.as_str()) == Some(profile.as_str())
    }) {
        return Some(format!(
            "No personal default was offered: a personal policy for {profile} already applies in this environment."
        ));
    }
    if let Err(refused) = attend_first(s, ctx).await {
        return Some(format!(
            "No personal default was offered: {}",
            refusal_text(&refused)
        ));
    }
    let request = Request::Policy(PolicyAction::Create {
        profile: profile.clone(),
        environments: [own.clone()].into_iter().collect(),
        max_window: None,
        default: true,
    });
    let env = s.request(request.clone()).await;
    // Review M05-W3-R01: the disclosure is the scope the runtime pinned for this record,
    // read with the record itself; without it nothing is asked or approved (fail closed).
    let decided = approve_request(
        s,
        p,
        ctx,
        &request,
        env,
        |record| match recorded_scope(record) {
            Some(scope) if scope.profile_id == profile => {
                Ok(personal_default_disclosure(&scope, &own))
            }
            Some(_) => Err("the recorded decision names another profile".to_owned()),
            None => Err(SCOPE_NOT_RECORDED.to_owned()),
        },
        None,
    )
    .await;
    Some(if let Err(env) = decided {
        format!("No personal default was created: {}", refusal_text(&env))
    } else {
        // ⟨M05; rulings I-13 and I-17⟩ The note claims no more than the exit record: the first
        // ordinary `ssh` after a free-slot period activates the default and may fail once.
        format!(
            "Personal default created: ordinary ssh in this environment uses {profile} access automatically, within its saved limits. \
             After a time without access, the first ssh starts it and may fail once; the next one logs in. \
             With the shell integration (bash or zsh) access is started before you need it."
        )
    })
}

// --- setup ------------------------------------------------------------------------------

/// Handle `setup` (module docs). Without an action, `apply`.
pub(crate) fn run(ctx: &Ctx, args: SetupArgs) -> ExitCode {
    let action = args.action.unwrap_or(SetupCommand::Apply {
        include_git: false,
        allow_config_commands: false,
        request_id: None,
    });
    match action {
        SetupCommand::Preview { include_git } => block(
            ctx,
            preview(
                ctx,
                PreviewIntent::Apply {
                    include_git,
                    distribution: None,
                    items: Default::default(),
                },
            ),
        ),
        SetupCommand::Apply {
            include_git,
            allow_config_commands,
            request_id,
        } => block(
            ctx,
            effect(
                ctx,
                PreviewIntent::Apply {
                    include_git,
                    distribution: None,
                    items: Default::default(),
                },
                request_id,
                allow_config_commands,
            ),
        ),
        SetupCommand::Rollback {
            keep_key_files,
            request_id,
        } => block(
            ctx,
            effect(ctx, rollback_intent(keep_key_files), request_id, false),
        ),
        SetupCommand::Repair(r) => match repair_intent(&r) {
            Ok(intent) => block(ctx, effect(ctx, intent, r.request_id, false)),
            Err(o) => o.emit(ctx),
        },
        SetupCommand::Status => block(ctx, status(ctx)),
    }
}

/// The rollback of every item.
pub(crate) fn rollback_intent(keep_key_files: bool) -> PreviewIntent {
    PreviewIntent::Rollback {
        keep_key_files,
        items: [ProjectionItem::Ssh, ProjectionItem::Git]
            .into_iter()
            .collect(),
        distribution: None,
    }
}

/// A snake_case wire name as its enum.
fn wire<T: serde::de::DeserializeOwned>(text: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(text.to_owned())).ok()
}

/// `repair <conflict> <resolution>` or `repair --operation <id> retry|keep`.
pub(crate) fn repair_intent(r: &RepairArgs) -> Result<PreviewIntent, Outcome> {
    let intent = match (&r.operation, r.args.as_slice()) {
        (Some(op), [what]) => {
            let operation = OperationId::parse(op).map_err(|_| usage("invalid operation ID"))?;
            let resolution = match what.as_str() {
                "retry" => RepairResolution::RetryHeld,
                "keep" => RepairResolution::KeepHeld,
                _ => return Err(usage("with --operation, repair takes retry or keep")),
            };
            PreviewIntent::Repair {
                conflict: ConflictKind::ProjectionHeld,
                resolution,
                operation: Some(operation),
            }
        }
        (None, [conflict, resolution]) => PreviewIntent::Repair {
            conflict: wire(conflict).ok_or_else(|| usage("unknown conflict"))?,
            resolution: wire(resolution).ok_or_else(|| usage("unknown resolution"))?,
            operation: None,
        },
        (Some(_), _) => return Err(usage("with --operation, repair takes retry or keep")),
        (None, _) => return Err(usage("repair takes <conflict> <resolution>")),
    };
    intent.validate().map_err(|e| usage(&e.to_string()))?;
    Ok(intent)
}

/// `setup preview`: the plan, read-only (the runtime journals nothing).
async fn preview(ctx: &Ctx, intent: PreviewIntent) -> Outcome {
    let mut client = match session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let env = client
        .request(Request::Setup(SetupRequest::Preview { intent }))
        .await;
    if env.code.is_success() {
        let human = output::render_plan(&env.data);
        Outcome::of(env).with_human(human)
    } else {
        result_outcome(env)
    }
}

/// `apply`, `rollback`, `repair` on a new session. `allow_config_commands` (`setup apply
/// --allow-config-commands`) authorizes the `ssh -G` check of the helper aliases after an
/// apply, which runs the configuration's own commands.
async fn effect(
    ctx: &Ctx,
    intent: PreviewIntent,
    given: Option<String>,
    allow_config_commands: bool,
) -> Outcome {
    let rid = match request_id(given.as_deref()) {
        Ok(r) => r,
        Err(o) => return o,
    };
    let mut client = match session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let out = setup_flow(&mut client, &mut TerminalPrompt, ctx, &intent, rid).await;
    // ⟨M05⟩ U5: the one personal-default offer step, after a successful apply.
    if matches!(intent, PreviewIntent::Apply { .. })
        && out.exit == ExitCode::Success
        && let Some(note) = offer_personal_default(&mut client, &mut TerminalPrompt, ctx).await
    {
        output::diagnostic(&note);
    }
    // ⟨M06 W5 `w5n`, `w5o`; ADR-0012 §5.2 and §5 ⟨2026-11-22⟩ "the pin check"⟩ At projection
    // time the plan's STATIC check decides what is rendered (nothing of the configuration
    // runs). The `ssh -G` verification of every alias P renders through the route helper
    // runs the configuration's commands, so it runs only with `--allow-config-commands`.
    // A defeated pin is reported; with or without the flag, the helper itself checks with
    // `ssh -G` before it tries any route and refuses such an alias.
    let mut out = out;
    if allow_config_commands
        && matches!(intent, PreviewIntent::Apply { .. })
        && out.exit == ExitCode::Success
    {
        for (alias, setting) in crate::m06_cmd::verify_projected_helper_aliases(ctx).await {
            let message = format!(
                "`{alias}` does not hold its destination's catalog host-key pin: the SSH \
                 configuration decides `{setting}` outside Heimdall's own section \
                 (host_pin_defeated: {setting}). `ssh {alias}` is refused by Heimdall's \
                 route helper until that setting no longer applies; `heimdall doctor` \
                 names it"
            );
            if !ctx.json {
                output::diagnostic(&message);
            }
            out.env.warnings.push(Warning {
                code: "HOST_PIN_DEFEATED".to_owned(),
                message,
                reason: Some(reason::HOST_PIN_DEFEATED.to_owned()),
            });
        }
    }
    finish_repair(ctx, &intent, out)
}

/// The held operation a held repair names.
fn held_target(intent: &PreviewIntent) -> Option<(RepairResolution, &OperationId)> {
    match intent {
        PreviewIntent::Repair {
            resolution,
            operation: Some(op),
            ..
        } if resolution.is_held_resolution() => Some((*resolution, op)),
        _ => None,
    }
}

/// The effect request carrying `digest`.
fn effect_request(
    intent: &PreviewIntent,
    digest: PlanDigest,
    request_id: RequestId,
) -> SetupRequest {
    match intent {
        PreviewIntent::Rollback { .. } => SetupRequest::Rollback {
            plan_digest: digest,
            request_id,
        },
        PreviewIntent::Repair { .. } => SetupRequest::Repair {
            plan_digest: digest,
            request_id,
        },
        _ => SetupRequest::Apply {
            plan_digest: digest,
            request_id,
        },
    }
}

/// Preview, show, (confirm), submit the digest (module docs). Generic over the session
/// and the prompt so the unit tests drive it with scripted ones.
pub(crate) async fn setup_flow<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    intent: &PreviewIntent,
    rid: RequestId,
) -> Outcome {
    let preview = s
        .request(Request::Setup(SetupRequest::Preview {
            intent: intent.clone(),
        }))
        .await;
    setup_from_preview(s, p, ctx, intent, rid, preview).await
}

/// Submit exactly the preview shown, including when enrollment offered it first.
pub(crate) async fn setup_from_preview<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    intent: &PreviewIntent,
    rid: RequestId,
    preview: Envelope<serde_json::Value>,
) -> Outcome {
    if !preview.code.is_success() {
        return result_outcome(preview);
    }
    let plan_text = output::render_plan(&preview.data);
    let Some(digest) = preview
        .data
        .get("plan_digest")
        .and_then(|d| d.as_str())
        .and_then(|d| PlanDigest::parse(d).ok())
    else {
        return Outcome::of(failure(
            Code::InternalError,
            "the runtime's plan carries no valid digest",
            None,
        ));
    };
    if !ctx.json && !ctx.interactive() {
        output::diagnostic(&plan_text);
    }
    if held_target(intent).is_none()
        && !matches!(intent, PreviewIntent::Rollback { .. })
        && let Some((conflict, message)) = plan_conflict(&preview.data)
    {
        return conflict_refusal(conflict, &message).with_human(plan_text);
    }
    let held = held_target(intent);
    if let Some((RepairResolution::KeepHeld, op)) = held {
        // QR12: a client-side confirmation, never a decision record.
        if !ctx.interactive() {
            return Outcome::of(not_confirmed(
                None,
                Some(op.clone()),
                non_interactive_reason(ctx),
            ));
        }
        let staying: Vec<String> = preview
            .data
            .get("findings")
            .and_then(|f| f.as_array())
            .map(|f| {
                f.iter()
                    .filter_map(|x| x.get("message").and_then(|m| m.as_str()))
                    .map(|m| format!("  {m}"))
                    .collect()
            })
            .unwrap_or_default();
        let text = format!(
            "{plan_text}\nKeeping closes operation {op} with every file as it is now: nothing is moved or deleted.\nWhat stays in place:\n{}\nKeep exactly this?\n",
            staying.join("\n")
        );
        let answer = p.ask(&text).await;
        if answer != Answer::Yes {
            return Outcome::of(not_confirmed(None, Some(op.clone()), answer.reason()));
        }
        let env = s
            .request_with_wait(
                ctx,
                Request::Setup(effect_request(intent, digest, rid)),
                Some(op),
            )
            .await;
        return result_outcome(env);
    }
    if let Some((_, op)) = held {
        // `retry` continues exactly the recorded plan; no decision (QR12).
        let request = Request::Setup(effect_request(intent, digest, rid));
        let env = s.request_with_wait(ctx, request.clone(), Some(op)).await;
        return result_outcome(settle(s, ctx, request, env).await);
    }
    let request = Request::Setup(effect_request(intent, digest.clone(), rid.clone()));
    let env = decided_request(s, p, ctx, request, &plan_text, Some(digest.as_str())).await;
    result_outcome(request_conflict_explained(env, &rid))
}

/// ⟨M02⟩ ADR-0007 §12.30 item 12: a setup request ID names exactly one plan, so
/// replaying `--request-id` after the projection (or the catalog, or the consent)
/// changed previews a new plan with another digest, which the runtime refuses as
/// `REQUEST_CONFLICT`. That is correct; the message says why and what to do.
fn request_conflict_explained(
    mut env: Envelope<serde_json::Value>,
    rid: &RequestId,
) -> Envelope<serde_json::Value> {
    if env.code != Code::RequestConflict {
        return env;
    }
    if let Some(message) = env.data.get_mut("error").and_then(|e| e.get_mut("message")) {
        *message = serde_json::Value::String(format!(
            "request ID {rid} was already used for an earlier setup plan; the projection, the catalog or the consent changed since, so the plan previewed now has another digest, and a request ID never applies a different plan. Nothing was written. Run the command again with a new request ID (or without --request-id)"
        ));
    }
    env
}

/// A conflict an `apply` or a (non-held) `repair` plan reports instead of changing
/// anything: no file changes, and a `problem` finding whose reason is a
/// [`ConflictKind`] (for example P edited by another writer, which is never
/// overwritten). The request cannot make the catalog effective or resolve the
/// conflict, so it is refused rather than reported as success.
fn plan_conflict(plan: &serde_json::Value) -> Option<(ConflictKind, String)> {
    let no_files = plan
        .get("files")
        .and_then(|f| f.as_array())
        .is_none_or(Vec::is_empty);
    if !no_files {
        return None;
    }
    plan.get("findings")?.as_array()?.iter().find_map(|f| {
        if f.get("severity").and_then(|v| v.as_str()) != Some("problem") {
            return None;
        }
        let conflict: ConflictKind = wire(f.get("reason")?.as_str()?)?;
        let message = f
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or_default()
            .to_owned();
        Some((conflict, message))
    })
}

/// `CONFIG_CONFLICT` for a plan's conflict, naming the targeted repair; nothing was
/// submitted, so nothing was written.
fn conflict_refusal(conflict: ConflictKind, message: &str) -> Outcome {
    let name = wire_name(&conflict);
    let repair = match next_resolution(conflict) {
        Some(r) => format!(
            "; repair it with `heimdall setup repair {name} {}`",
            wire_name(&r)
        ),
        None => "; restore or move your edits, or roll back with `heimdall setup rollback` (an edited file is kept as a conflict file)".to_owned(),
    };
    Outcome::of(failure(
        Code::ConfigConflict,
        &format!("setup cannot proceed: {message} ({name}); nothing was written{repair}"),
        Some(&name),
    ))
}

/// The result of a setup request: its rendering, and for a held operation (or a
/// `setup_in_progress` refusal naming one) both repair commands in the message and the
/// human text.
pub(crate) fn result_outcome(mut env: Envelope<serde_json::Value>) -> Outcome {
    let mut human = String::new();
    if env.code.is_success() {
        human = output::render_setup_result(&env.data);
    } else if let Some(setup) = env.data.get("setup") {
        human = output::render_setup_result(setup);
    }
    let why = env
        .data
        .get("error")
        .and_then(|e| e.get("reason"))
        .and_then(|r| r.as_str())
        .map(str::to_owned);
    let held_message = env
        .data
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .is_some_and(|m| m.contains("held"));
    let blocker = env.next.as_ref().and_then(|n| n.operation_id.clone());
    if let (Some(op), Some(r)) = (blocker, why.as_deref())
        && (r == reason::PROJECTION_HELD || (r == reason::SETUP_IN_PROGRESS && held_message))
    {
        let commands = output::held_repair_commands(op.as_str());
        if let Some(message) = env.data.get_mut("error").and_then(|e| e.get_mut("message"))
            && let Some(text) = message.as_str()
        {
            *message = serde_json::Value::String(format!(
                "{text}. Repair it with `heimdall setup repair --operation {op} retry` or `heimdall setup repair --operation {op} keep`"
            ));
        }
        human.push_str(&format!(
            "Held operation {op}. Repair it with one of:\n{commands}"
        ));
    }
    Outcome::of(env).with_human(human)
}

/// The resolution that addresses `conflict` next (ADR-0007 §5.5, §12.19 item 7).
fn next_resolution(conflict: ConflictKind) -> Option<RepairResolution> {
    match conflict {
        ConflictKind::MarkerDuplicated => Some(RepairResolution::RemoveDuplicateMarkers),
        ConflictKind::IncludeConditional => Some(RepairResolution::MoveIncludeToTop),
        ConflictKind::MarkerEdited | ConflictKind::UserConfigChanged => {
            Some(RepairResolution::ManualMode)
        }
        _ => None,
    }
}

fn wire_name<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// ADR-0007 §12.19 item 7: a non-held repair that succeeded is complete only when the
/// passive doctor reports no projection conflict left; until then the result names
/// the next operation (`repair_complete: false`, `next_repair`, warning
/// `repair_incomplete`).
fn finish_repair(ctx: &Ctx, intent: &PreviewIntent, mut out: Outcome) -> Outcome {
    let PreviewIntent::Repair { resolution, .. } = intent else {
        return out;
    };
    if resolution.is_held_resolution() || !out.env.code.is_success() {
        return out;
    }
    let left = crate::doctor_cmd::projection_conflict(ctx);
    complete_repair(&mut out, left);
    out
}

/// Mark `out` complete, or name the next operation for the conflict `left`.
pub(crate) fn complete_repair(out: &mut Outcome, left: Result<Option<ConflictKind>, String>) {
    let (complete, next) = match left {
        Ok(None) => (true, None),
        Ok(Some(conflict)) => {
            let next = next_resolution(conflict).map(|r| {
                format!(
                    "heimdall setup repair {} {}",
                    wire_name(&conflict),
                    wire_name(&r)
                )
            });
            (false, Some((wire_name(&conflict), next)))
        }
        // The doctor could not tell: never claim completeness.
        Err(why) => (false, Some((why, None))),
    };
    if let serde_json::Value::Object(map) = &mut out.env.data {
        map.insert(
            "repair_complete".to_owned(),
            serde_json::Value::Bool(complete),
        );
        if let Some((_, Some(cmd))) = &next {
            map.insert(
                "next_repair".to_owned(),
                serde_json::Value::String(cmd.clone()),
            );
        }
    }
    if let Some((conflict, cmd)) = next {
        let message = match &cmd {
            Some(c) => {
                format!("the repair is not complete: doctor still reports {conflict}; next: {c}")
            }
            None => format!("the repair is not complete: doctor reports {conflict}"),
        };
        out.human.push_str(&format!("{message}\n"));
        out.env.warnings.push(Warning {
            code: "repair_incomplete".to_owned(),
            message,
            reason: None,
        });
    } else {
        out.human
            .push_str("The repair is complete: doctor reports no projection conflict left.\n");
    }
}

// --- status ------------------------------------------------------------------------------

/// `setup status` (module docs).
async fn status(ctx: &Ctx) -> Outcome {
    let mut client = match session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let projections = match inspect(&mut client, InspectSubject::Projections).await {
        Ok(d) => d,
        Err(o) => return o,
    };
    let operations = match inspect(&mut client, InspectSubject::Operations).await {
        Ok(d) => d,
        Err(o) => return o,
    };
    let held: Vec<OperationId> = operations
        .get("operations")
        .and_then(|o| o.as_array())
        .map(|ops| {
            ops.iter()
                .filter(|o| {
                    o.get("kind")
                        .and_then(|k| k.as_str())
                        .is_some_and(|k| k.starts_with("setup."))
                        && o.get("state").and_then(|s| s.as_str()) == Some("outcome_unknown")
                })
                .filter_map(|o| o.get("operation_id").and_then(|i| i.as_str()))
                .filter_map(|i| OperationId::parse(i).ok())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        })
        .unwrap_or_default();
    let observed = held_steps(ctx, &held);
    let mut held_out = Vec::new();
    let mut human = String::new();
    for op in &held {
        let steps = observed
            .iter()
            .find(|(o, _)| o == op)
            .map(|(_, s)| s.clone())
            .unwrap_or_else(|| serde_json::json!([]));
        human.push_str(&format!("Held operation {op}:\n"));
        for s in steps.as_array().map_or(&[][..], Vec::as_slice) {
            human.push_str(&format!(
                "    step {} {} {}: {}; path holds {}, aside holds {}, slot holds {}\n",
                s["step"],
                s["role"].as_str().unwrap_or(""),
                s["path_display"].as_str().unwrap_or(""),
                s["reason"].as_str().unwrap_or(""),
                s["path"].as_str().unwrap_or(""),
                s["aside"].as_str().unwrap_or(""),
                s["slot"].as_str().unwrap_or(""),
            ));
        }
        human.push_str(&output::held_repair_commands(op.as_str()));
        held_out.push(serde_json::json!({
            "operation_id": op,
            "steps": steps,
            "commands": [
                {"command": format!("heimdall setup repair --operation {op} retry"),
                 "effect": "runs the held operation's recovery again, after you put the file it names back; it continues exactly the recorded plan"},
                {"command": format!("heimdall setup repair --operation {op} keep"),
                 "effect": "closes the operation keeping every file as it is now; nothing is moved, and what stays in place is listed"},
            ],
        }));
    }
    let quarantine = match crate::uninstall_cmd::artifact_dirs(ctx) {
        Ok(dirs) => crate::uninstall_cmd::quarantine_listing(&dirs, false),
        Err(_) => Vec::new(),
    };
    for q in &quarantine {
        human.push_str(&format!(
            "Quarantine {}:\n",
            q["path_display"].as_str().unwrap_or("")
        ));
        for e in q["entries"].as_array().map_or(&[][..], Vec::as_slice) {
            human.push_str(&format!(
                "    {} (from {}): {}\n",
                e["name"].as_str().unwrap_or(""),
                e["from"].as_str().unwrap_or(""),
                e["reason"].as_str().unwrap_or("")
            ));
        }
    }
    // ADR-0007 §5.5 "Snapshots": `setup status` lists them (they exist for manual
    // recovery; Heimdall never restores one).
    let backups = snapshots(ctx);
    for b in &backups {
        human.push_str(&format!(
            "Snapshot {} (the original, for manual recovery)\n",
            b.as_str().unwrap_or("")
        ));
    }
    let record_items = projections
        .get("record")
        .and_then(|r| r.get("items"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    human.insert_str(
        0,
        &format!(
            "Projection items: {}\n",
            record_items.as_object().map_or_else(
                || "none".to_owned(),
                |m| m.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        ),
    );
    let mut env = Envelope::ok(serde_json::json!({
        "projection": projections,
        "held_operations": held_out,
        "quarantine": quarantine,
        "backups": backups,
    }));
    if !held.is_empty() {
        env.next = Some(NextAction {
            action: "reconcile".to_owned(),
            operation_id: held.first().cloned(),
            ..NextAction::default()
        });
    }
    Outcome::of(env).with_human(human)
}

/// Every snapshot under `<state_dir>/backups` (ADR-0007 §5.5), shown under the account
/// home; a dot-named staging file is not a snapshot.
fn snapshots(ctx: &Ctx) -> Vec<serde_json::Value> {
    let Ok(paths) = ctx.paths() else {
        return Vec::new();
    };
    let home = crate::doctor_cmd::account_ssh_paths()
        .map(|p| p.account_home)
        .unwrap_or_default();
    entries(&paths.state_dir.join("backups"))
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| !n.starts_with('.') && n.ends_with(".orig"))
        })
        .map(|p| serde_json::Value::String(shown(&p, &home)))
        .collect()
}

/// What one observed name holds, for the owner.
fn entry_text(e: heimdall_domain::projection::EntryObs) -> String {
    use heimdall_domain::projection::{ContentState, EntryObs};
    match e {
        EntryObs::Absent => "nothing".to_owned(),
        EntryObs::Recorded { which, content } => format!(
            "Heimdall's entry ({}), content {}",
            wire_name(&which).to_ascii_uppercase(),
            if content == ContentState::Unchanged {
                "matches"
            } else {
                "changed"
            }
        ),
        EntryObs::Foreign => "a foreign entry".to_owned(),
        EntryObs::Unobservable => "an entry that could not be observed".to_owned(),
    }
}

/// Each held operation's held steps, observed passively in this process from the
/// store (read-only) and the files (`ProjectionWriter::observe_held`): role, path,
/// reason, and what the path, aside and slot names hold. An operation whose steps
/// cannot be read is left out (its two repair commands are still shown).
fn held_steps(ctx: &Ctx, held: &[OperationId]) -> Vec<(OperationId, serde_json::Value)> {
    use heimdall_app::ports::ProjectionWriter as _;
    use heimdall_domain::operation::LocalIntent;
    if held.is_empty() {
        return Vec::new();
    }
    let Ok(hooks) = crate::testcfg::launch_hooks(&|n| std::env::var_os(n)) else {
        return Vec::new();
    };
    let Ok(config) = crate::launch_flow::static_config(ctx, &hooks) else {
        return Vec::new();
    };
    let Ok(store) = crate::doctor_cmd::open_store(ctx) else {
        return Vec::new();
    };
    let writer = heimdall_localenv::projection::LocalProjection::new(config);
    let mut out = Vec::new();
    for op in held {
        let read = store.transaction(|tx| {
            let intent = tx.recovery_intent(op)?;
            let receipts = tx.stage_receipts(op)?;
            Ok((intent, receipts))
        });
        let Ok((Some(intent), receipts)) = read else {
            continue;
        };
        let Some(LocalIntent::Setup(intent)) = intent.local else {
            continue;
        };
        let local: Vec<_> = receipts.into_iter().filter(|r| r.local.is_some()).collect();
        let Ok(steps) = writer.observe_held(&intent, &local) else {
            continue;
        };
        let steps: Vec<serde_json::Value> = steps
            .iter()
            .map(|h| {
                serde_json::json!({
                    "step": h.step,
                    "role": wire_name(&h.role),
                    "path_display": h.path_display,
                    "reason": wire_name(&h.reason),
                    "path": entry_text(h.observed.path()),
                    "aside": entry_text(h.observed.aside()),
                    "slot": entry_text(h.observed.slot()),
                })
            })
            .collect();
        out.push((op.clone(), serde_json::Value::Array(steps)));
    }
    out
}

/// `path` for display, `~/…` under the account home.
pub(crate) fn shown(path: &Path, home: &Path) -> String {
    heimdall_localenv::doctor::path_display(path, home)
}

/// Every regular entry name of `dir` (sorted), or none.
pub(crate) fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| rd.filter_map(Result::ok).map(|e| e.path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Prompter, Session};

    /// A recording control session with scripted answers per request kind.
    struct Recorder {
        sent: Vec<String>,
        answers: std::collections::HashMap<&'static str, Vec<Envelope<serde_json::Value>>>,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                sent: Vec::new(),
                answers: std::collections::HashMap::new(),
            }
        }
        fn answer(mut self, kind: &'static str, env: Envelope<serde_json::Value>) -> Self {
            self.answers.entry(kind).or_default().push(env);
            self
        }
    }

    fn kind_of(r: &Request) -> String {
        match r {
            Request::Setup(s) => s.kind().to_owned(),
            other => other.kind().to_owned(),
        }
    }

    impl Session for Recorder {
        async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
            let probe = request.clone();
            #[allow(clippy::needless_return)]
            let mut env: Envelope<serde_json::Value> = async {
                let k = kind_of(&request);
                self.sent.push(k.clone());
                let key: &'static str = match k.as_str() {
                    "setup.preview" => "setup.preview",
                    "setup.apply" => "setup.apply",
                    "setup.rollback" => "setup.rollback",
                    "setup.repair" => "setup.repair",
                    "inspect" => "inspect",
                    "decide" => "decide",
                    _ => "other",
                };
                let queue = self.answers.entry(key).or_default();
                if queue.is_empty() {
                    Envelope::ok(serde_json::json!({}))
                } else {
                    queue.remove(0)
                }
            }
            .await;
            // ⟨rev7⟩ A point lookup reads the scripted listing as the runtime answers `select`.
            if env.code.is_success() {
                env.data = crate::client::answered(&probe, env.data);
            }
            env
        }
        async fn attend(&mut self) -> Envelope<serde_json::Value> {
            self.sent.push("attend".to_owned());
            Envelope::ok(serde_json::json!({"attended": true}))
        }
    }

    struct Script {
        answers: Vec<Answer>,
        shown: Vec<String>,
    }

    impl Prompter for Script {
        async fn ask(&mut self, text: &str) -> Answer {
            self.shown.push(text.to_owned());
            assert!(!self.answers.is_empty(), "unexpected prompt: {text}");
            self.answers.remove(0)
        }
    }

    fn script(a: &[Answer]) -> Script {
        Script {
            answers: a.to_vec(),
            shown: Vec::new(),
        }
    }

    const DEC: &str = "dec_00112233445566778899aabbccddeeff";
    const OP: &str = "op_00112233445566778899aabbccddeeff";

    fn digest() -> String {
        "ab".repeat(32)
    }

    fn plan() -> Envelope<serde_json::Value> {
        Envelope::ok(serde_json::json!({
            "plan_digest": digest(),
            "intent": {"kind": "apply", "include_git": false},
            "mode": "automatic",
            "files": [{"role": "user_ssh", "path_display": "~/.ssh/config", "diff": "+Include x\n"}],
            "aliases": [{"alias": "alpha", "kind": "managed",
                "before": {"digest": "11".repeat(32), "directives": []},
                "after": {"digest": "22".repeat(32), "directives": [{"directive": "HostName", "values": ["alpha.example.invalid"], "certainty": "determined"}]},
                "restore": {"digest": "33".repeat(32), "directives": []}}],
            "consent": {"decision_required": true, "reasons": [{"item": "alpha", "kind": "new_state"}]},
            "unaffected_names_checked": 0,
        }))
    }

    fn approval(code: Code) -> Envelope<serde_json::Value> {
        output::error_value(
            heimdall_app::OpError::new(code, "owner approval required")
                .with_decision(DEC.to_owned())
                .into_envelope(),
        )
    }

    fn listing(digest: &str) -> Envelope<serde_json::Value> {
        Envelope::ok(serde_json::json!({"decisions": [{
            "decision_id": DEC, "kind": "apply_projection", "state": "pending",
            "expires_at": "2026-11-03T00:15:00Z",
            "request": {"plan_digest": digest, "restore": [{"item": "alpha"}], "diff_text": "+Include x\n"},
        }]}))
    }

    fn tty() -> Ctx {
        Ctx {
            json: true,
            non_interactive: false,
            home: None,
            stdin_tty: true,
        }
    }

    fn rid() -> RequestId {
        RequestId::parse("r-1").unwrap_or_else(|_| unreachable!())
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| unreachable!())
            .block_on(f)
    }

    fn apply() -> PreviewIntent {
        PreviewIntent::Apply {
            include_git: false,
            distribution: None,
            items: Default::default(),
        }
    }

    /// m02-plan U9: preview first, attend, submit the digest; on `APPROVAL_REQUIRED` the
    /// prompt shows the plan with its restore column and the exact recorded request;
    /// `yes` sends `Decide` and the same request again, exactly once each.
    #[test]
    fn apply_previews_attends_shows_restore_and_decides_only_on_yes() {
        let mut s = Recorder::new()
            .answer("setup.preview", plan())
            .answer("setup.apply", approval(Code::ApprovalRequired))
            .answer("inspect", listing(&digest()));
        let mut p = script(&[Answer::Yes]);
        let out = block_on(setup_flow(&mut s, &mut p, &tty(), &apply(), rid()));
        assert_eq!(
            s.sent,
            [
                "setup.preview",
                "attend",
                "setup.apply",
                "inspect",
                "decide",
                "setup.apply"
            ]
        );
        assert_eq!(out.exit, ExitCode::Success);
        assert_eq!(p.shown.len(), 1);
        let shown = &p.shown[0];
        assert!(shown.contains("restore:"), "{shown}");
        assert!(shown.contains(&digest()), "{shown}");
        assert!(shown.contains("recorded request"), "{shown}");
    }

    /// ADR-0007 §12.34 item 7: the owner who is asked to approve a rollback (or an
    /// uninstall, which is the same flow) is shown the removal of each of Heimdall's own
    /// files as a removal with its name, line count and SHA-256, and the owner's file
    /// change whole; not the raw writer line, not the removed content.
    #[test]
    fn a_rollback_prompt_shows_heimdalls_own_files_as_removals() {
        let sha = "cd".repeat(32);
        let rollback = Envelope::ok(serde_json::json!({
            "plan_digest": digest(),
            "intent": {"kind": "rollback", "keep_key_files": false, "items": ["ssh"]},
            "mode": "automatic",
            "files": [
                {"role": "user_ssh", "path_display": "~/.ssh/config",
                 "before_sha256": "11".repeat(32), "after_sha256": "22".repeat(32),
                 "diff": "-# >>> heimdall managed include\n-Include ~/.config/heimdall/ssh_config\n"},
                {"role": "managed_ssh", "path_display": "~/.config/heimdall/ssh_config",
                 "before_sha256": sha, "diff": format!("~ removed ssh_config: 4321 lines, sha256 {sha}\n")},
            ],
            "aliases": [],
            "consent": {"decision_required": true, "reasons": [{"item": "alpha", "kind": "exposes_inherited"}]},
            "unaffected_names_checked": 0,
        }));
        let mut s = Recorder::new()
            .answer("setup.preview", rollback)
            .answer("setup.rollback", approval(Code::ApprovalRequired))
            .answer("inspect", listing(&digest()));
        let mut p = script(&[Answer::No]);
        let out = block_on(setup_flow(
            &mut s,
            &mut p,
            &tty(),
            &rollback_intent(false),
            rid(),
        ));
        assert_eq!(out.exit, ExitCode::InteractionRequired);
        assert_eq!(p.shown.len(), 1);
        let shown = &p.shown[0];
        assert!(
            shown.contains(&format!(
                "    removes Heimdall's own file ssh_config: 4321 lines, sha256 {sha}\n"
            )),
            "{shown}"
        );
        assert!(
            shown.contains("    -Include ~/.config/heimdall/ssh_config\n"),
            "{shown}"
        );
        assert!(!shown.contains("\n    ~ removed"), "{shown}");
    }

    /// Any answer but `yes` (no, end of input, Ctrl-C, timeout, unreadable) sends
    /// nothing more and exits 3 `INTERACTION_REQUIRED` with the decision reference.
    #[test]
    fn apply_sends_nothing_more_unless_confirmed() {
        for answer in [
            Answer::No,
            Answer::Eof,
            Answer::Interrupted,
            Answer::TimedOut,
            Answer::Unreadable,
        ] {
            let mut s = Recorder::new()
                .answer("setup.preview", plan())
                .answer("setup.apply", approval(Code::ApprovalRequired))
                .answer("inspect", listing(&digest()));
            let mut p = script(&[answer]);
            let out = block_on(setup_flow(&mut s, &mut p, &tty(), &apply(), rid()));
            assert_eq!(
                s.sent,
                ["setup.preview", "attend", "setup.apply", "inspect"],
                "{answer:?}"
            );
            assert_eq!(out.exit, ExitCode::InteractionRequired);
            assert_eq!(
                out.env
                    .next
                    .as_ref()
                    .and_then(|n| n.decision_ref.as_deref()),
                Some(DEC)
            );
        }
    }

    /// A recorded plan that is not the plan shown is never approved.
    #[test]
    fn a_recorded_plan_other_than_the_one_shown_is_refused() {
        let mut s = Recorder::new()
            .answer("setup.preview", plan())
            .answer("setup.apply", approval(Code::ApprovalRequired))
            .answer("inspect", listing(&"cd".repeat(32)));
        let mut p = script(&[]);
        let out = block_on(setup_flow(&mut s, &mut p, &tty(), &apply(), rid()));
        assert_eq!(
            s.sent,
            ["setup.preview", "attend", "setup.apply", "inspect"]
        );
        assert_eq!(out.env.code, Code::ConfigConflict);
        assert!(p.shown.is_empty());
    }

    /// Non-TTY or `--non-interactive`: no attendance, no prompt; the runtime's
    /// `INTERACTION_REQUIRED` with `next.decision_ref` stands (exit 3).
    #[test]
    fn non_interactive_apply_never_attends_or_prompts() {
        for ctx in [
            Ctx {
                non_interactive: true,
                ..tty()
            },
            Ctx {
                stdin_tty: false,
                ..tty()
            },
        ] {
            let mut s = Recorder::new()
                .answer("setup.preview", plan())
                .answer("setup.apply", approval(Code::InteractionRequired));
            let mut p = script(&[]);
            let out = block_on(setup_flow(&mut s, &mut p, &ctx, &apply(), rid()));
            assert_eq!(s.sent, ["setup.preview", "setup.apply"]);
            assert_eq!(out.exit, ExitCode::InteractionRequired);
            assert_eq!(
                out.env
                    .next
                    .as_ref()
                    .and_then(|n| n.decision_ref.as_deref()),
                Some(DEC)
            );
            assert!(p.shown.is_empty());
        }
    }

    fn keep() -> PreviewIntent {
        PreviewIntent::Repair {
            conflict: ConflictKind::ProjectionHeld,
            resolution: RepairResolution::KeepHeld,
            operation: Some(OperationId::parse(OP).unwrap_or_else(|_| unreachable!())),
        }
    }

    /// QR12: `keep` needs a typed `yes` client-side; without one nothing is sent after
    /// the preview (exit 3), and it never attends or creates a decision.
    #[test]
    fn keep_needs_a_typed_yes_and_sends_nothing_without_one() {
        for (ctx, answers, sent, exit) in [
            (
                tty(),
                vec![Answer::Yes],
                vec!["setup.preview", "setup.repair"],
                ExitCode::Success,
            ),
            (
                tty(),
                vec![Answer::No],
                vec!["setup.preview"],
                ExitCode::InteractionRequired,
            ),
            (
                tty(),
                vec![Answer::Eof],
                vec!["setup.preview"],
                ExitCode::InteractionRequired,
            ),
            (
                Ctx {
                    non_interactive: true,
                    ..tty()
                },
                vec![],
                vec!["setup.preview"],
                ExitCode::InteractionRequired,
            ),
        ] {
            let mut held_plan = plan();
            held_plan.data["findings"] = serde_json::json!([{"code": "projection_held", "message": "step 0 (~/.ssh/config) is held"}]);
            let mut s = Recorder::new().answer("setup.preview", held_plan);
            let mut p = script(&answers);
            let out = block_on(setup_flow(&mut s, &mut p, &ctx, &keep(), rid()));
            assert_eq!(s.sent, sent);
            assert_eq!(out.exit, exit);
            if let Some(text) = p.shown.first() {
                assert!(text.contains("nothing is moved"), "{text}");
                assert!(text.contains("step 0 (~/.ssh/config) is held"), "{text}");
            }
        }
    }

    /// `setup_in_progress` naming a held operation names both repair commands.
    #[test]
    fn setup_in_progress_names_both_repair_commands() {
        let op = OperationId::parse(OP).unwrap_or_else(|_| unreachable!());
        let refused = output::error_value(
            heimdall_app::OpError::new(
                Code::ConfigConflict,
                format!("setup operation {op} is held for the owner and blocks every other setup operation"),
            )
            .with_reason(reason::SETUP_IN_PROGRESS)
            .with_operation(op.clone())
            .with_next(NextAction {
                action: "reconcile".to_owned(),
                operation_id: Some(op.clone()),
                ..NextAction::default()
            })
            .into_envelope(),
        );
        let out = result_outcome(refused);
        let message = out.env.data["error"]["message"]
            .as_str()
            .unwrap_or_default();
        assert!(
            message.contains(&format!("setup repair --operation {op} retry")),
            "{message}"
        );
        assert!(
            message.contains(&format!("setup repair --operation {op} keep")),
            "{message}"
        );
        assert!(out.human.contains("retry") && out.human.contains("keep"));
        assert_eq!(out.exit, ExitCode::Conflict);
    }

    /// ADR-0007 §12.19 item 7: a repair is complete only when doctor reports no
    /// conflict left; otherwise the result names the next operation.
    #[test]
    fn a_repair_is_complete_only_when_doctor_reports_none_left() {
        let mut out = Outcome::of(Envelope::ok(serde_json::json!({"generation": 2})));
        complete_repair(&mut out, Ok(Some(ConflictKind::MarkerDuplicated)));
        assert_eq!(out.env.data["repair_complete"], false);
        assert_eq!(
            out.env.data["next_repair"],
            "heimdall setup repair marker_duplicated remove_duplicate_markers"
        );
        assert!(
            out.env
                .warnings
                .iter()
                .any(|w| w.code == "repair_incomplete")
        );
        let mut out = Outcome::of(Envelope::ok(serde_json::json!({"generation": 3})));
        complete_repair(&mut out, Ok(None));
        assert_eq!(out.env.data["repair_complete"], true);
        assert!(out.env.warnings.is_empty());
        let mut out = Outcome::of(Envelope::ok(serde_json::json!({"generation": 3})));
        complete_repair(&mut out, Err("doctor_unavailable".to_owned()));
        assert_eq!(
            out.env.data["repair_complete"], false,
            "never claimed blind"
        );
    }

    /// Every U9 command line of the clap tree parses into its command (the lines the
    /// wave-0 `not available` tests carried before W4-U9 wired them).
    #[test]
    fn u9_command_lines_parse() {
        use clap::Parser as _;
        let lines: &[&[&str]] = &[
            &["setup"],
            &["setup", "preview", "--include-git"],
            &["setup", "apply", "--include-git", "--request-id", "r1"],
            &["setup", "rollback", "--keep-key-files"],
            &["setup", "repair", "user_config_changed", "rerender"],
            &["setup", "repair", "--operation", "op_x", "retry"],
            &["setup", "repair", "--operation", "op_x", "keep"],
            &["setup", "status"],
            &["doctor"],
            &[
                "doctor",
                "--active-probe",
                "agent,network",
                "--allow-config-commands",
                "--alias",
                "a",
                "--no-local-exec",
                "--redact",
            ],
            &[
                "destination",
                "add",
                "lab",
                "--hostname",
                "h.example",
                "--port",
                "22",
            ],
            &["destination", "add", "lab", "--observed"],
            &["destination", "list"],
            &["destination", "show", "lab"],
            &["destination", "remove", "lab"],
            &["identity", "list"],
            &["identity", "adopt", "--pub", "k.pub"],
            &[
                "identity",
                "adopt",
                "--from-agent",
                "--active-probe",
                "agent",
            ],
            &[
                "identity",
                "adopt",
                "--from-agent",
                "--fingerprint",
                "SHA256:fixture",
            ],
            &["identity", "declare-interaction", "idn_x", "none"],
            &["identity", "withdraw-declaration", "idn_x"],
            &["identity", "remove", "idn_x"],
            &["profile", "create", "p", "--pair", "d:a"],
            &["profile", "show", "p"],
            &["profile", "add", "p", "--pair", "d:a"],
            &["profile", "remove", "p"],
            &["profile", "list"],
            &["uninstall"],
            &["uninstall", "--purge-state"],
        ];
        for line in lines {
            let argv: Vec<&str> = std::iter::once("heimdall")
                .chain(line.iter().copied())
                .collect();
            let cli = crate::cli::Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("{line:?}: {:?}", e.kind()));
            assert!(
                matches!(
                    cli.command,
                    Some(
                        crate::cli::Command::Setup(_)
                            | crate::cli::Command::Doctor(_)
                            | crate::cli::Command::Destination(_)
                            | crate::cli::Command::Identity(_)
                            | crate::cli::Command::Profile(_)
                            | crate::cli::Command::Uninstall(_)
                    )
                ),
                "{line:?}"
            );
        }
    }

    #[test]
    fn repair_arguments_parse_or_are_usage_errors() {
        let args = |op: Option<&str>, a: &[&str]| RepairArgs {
            operation: op.map(str::to_owned),
            args: a.iter().map(|s| (*s).to_owned()).collect(),
            request_id: None,
        };
        assert!(matches!(
            repair_intent(&args(Some(OP), &["keep"])),
            Ok(PreviewIntent::Repair {
                resolution: RepairResolution::KeepHeld,
                ..
            })
        ));
        assert!(matches!(
            repair_intent(&args(
                None,
                &["marker_duplicated", "remove_duplicate_markers"]
            )),
            Ok(PreviewIntent::Repair {
                resolution: RepairResolution::RemoveDuplicateMarkers,
                operation: None,
                ..
            })
        ));
        for bad in [
            args(Some(OP), &["later"]),
            args(Some("bad id"), &["keep"]),
            args(None, &["keep"]),
            args(None, &["projection_held", "rerender"]),
            args(None, &["nonsense", "rerender"]),
        ] {
            assert!(repair_intent(&bad).is_err(), "{:?}", bad.args);
        }
    }

    /// ADR-0007 §12.30 item 12: replaying `setup apply --request-id` after the plan
    /// changed stays the runtime's `REQUEST_CONFLICT` (exit 6, nothing written); the CLI
    /// says why and what to do. Any other result is passed through unchanged.
    #[test]
    fn a_replayed_request_id_after_the_plan_changed_says_why() {
        let conflict = || {
            output::error_value(
                heimdall_app::OpError::new(
                    Code::RequestConflict,
                    "this request ID was already used with different parameters",
                )
                .into_envelope(),
            )
        };
        for ctx in [
            tty(),
            Ctx {
                non_interactive: true,
                stdin_tty: false,
                ..tty()
            },
        ] {
            let mut s = Recorder::new()
                .answer("setup.preview", plan())
                .answer("setup.apply", conflict());
            let mut p = script(&[]);
            let out = block_on(setup_flow(&mut s, &mut p, &ctx, &apply(), rid()));
            assert_eq!(out.env.code, Code::RequestConflict);
            assert_eq!(out.exit, ExitCode::Conflict);
            let message = out.env.data["error"]["message"].as_str().unwrap_or("");
            assert!(
                message.contains("request ID r-1 was already used for an earlier setup plan")
                    && message.contains("another digest")
                    && message.contains("Nothing was written")
                    && message.contains("new request ID"),
                "{message}"
            );
            assert!(p.shown.is_empty(), "nothing is asked");
        }
        // Not a conflict: unchanged.
        let ok = Envelope::ok(serde_json::json!({"generation": 1}));
        assert_eq!(
            serde_json::to_value(request_conflict_explained(ok.clone(), &rid())).ok(),
            serde_json::to_value(ok).ok()
        );
    }

    // --- ⟨M05⟩ U5: the personal-default offer ---------------------------------------------

    const ENV: &str = "env_00112233445566778899aabbccddeeff";

    fn no_policies() -> Envelope<serde_json::Value> {
        Envelope::ok(serde_json::json!({"items": []}))
    }

    fn own_environment() -> Envelope<serde_json::Value> {
        Envelope::ok(serde_json::json!({"environment_id": ENV, "enrolled": true}))
    }

    fn one_profile() -> Envelope<serde_json::Value> {
        Envelope::ok(serde_json::json!({"items": [{
            "profile_id": "dev", "revision": 1, "label": null,
            "pairs": [{"destination": "lab", "account": "deploy"}],
            "capabilities": ["ssh-authentication"],
        }]}))
    }

    /// The scope the runtime records for the `create` (ADR-0006 §17.10 item 22), pinned at
    /// revision 2 of `dev`.
    fn recorded(pairs: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "profile_id": "dev", "profile_revision": 2,
            "pairs": pairs.iter().map(|d| serde_json::json!({"destination": d, "account": "deploy"}))
                .collect::<Vec<_>>(),
            "environments": [ENV], "capabilities": ["ssh-authentication"],
            "lock_behavior": "continue",
        })
    }

    fn create_listing(scope: Option<serde_json::Value>) -> Envelope<serde_json::Value> {
        let mut record = serde_json::json!({
            "decision_id": DEC, "kind": "widen_policy", "state": "pending",
            "expires_at": "2026-11-18T00:15:00Z",
            "request": {"action": {"action": "create", "profile": "dev", "environments": [ENV], "default": true}},
        });
        if let Some(scope) = scope {
            record["scope"] = scope;
        }
        Envelope::ok(serde_json::json!({ "decisions": [record] }))
    }

    fn offer(s: &mut Recorder, p: &mut Script, ctx: &Ctx) -> Option<String> {
        block_on(offer_personal_default(s, p, ctx))
    }

    /// ⟨M05⟩ U5 (ADR-0011 §3.1, §3.3; spec §5.2): on an attended TTY, with no personal default
    /// and one evident profile, setup sends one `create {profile, environments: [this one],
    /// default: true}` and shows the disclosure — including "access starts again automatically
    /// when you next use it, within your saved limits; pause or set a stop time to end it" —
    /// with the exact recorded request; only a typed `yes` sends `Decide`, exactly once. The
    /// destinations shown are the record's `scope` (review M05-W3-R01), not the profile
    /// listing the offer read (`lab` only), which a catalog edit may have outrun.
    #[test]
    fn personal_default_offer_shows_the_disclosure_and_creates_only_on_yes() {
        let mut s = Recorder::new()
            .answer("inspect", no_policies())
            .answer("inspect", own_environment())
            .answer("inspect", one_profile())
            .answer("other", approval(Code::ApprovalRequired))
            .answer(
                "inspect",
                create_listing(Some(recorded(&["lab", "lab-new"]))),
            );
        let mut p = script(&[Answer::Yes]);
        let note = offer(&mut s, &mut p, &tty()).unwrap_or_default();
        assert_eq!(
            s.sent,
            [
                "inspect", "inspect", "inspect", "attend", "policy", "inspect", "decide"
            ]
        );
        assert!(note.starts_with("Personal default created"), "{note}");
        assert_eq!(p.shown.len(), 1);
        let shown = &p.shown[0];
        for needle in [
            "Use dev access automatically for ordinary ssh in this environment?",
            "Access starts again automatically when you next use it, within your saved limits; pause or set a stop time to end it.",
            "Destinations and accounts: lab:deploy, lab-new:deploy\n",
            "Capabilities: ssh-authentication\n",
            "Environment: this one only\n",
            "Profile: dev at revision 2",
            "\"default\": true",
            "Approve exactly this request?",
        ] {
            assert!(shown.contains(needle), "missing {needle:?} in {shown}");
        }
        // Anything but `yes`: no `Decide`; nothing is created.
        let mut s = Recorder::new()
            .answer("inspect", no_policies())
            .answer("inspect", own_environment())
            .answer("inspect", one_profile())
            .answer("other", approval(Code::ApprovalRequired))
            .answer("inspect", create_listing(Some(recorded(&["lab"]))));
        let mut p = script(&[Answer::No]);
        let note = offer(&mut s, &mut p, &tty()).unwrap_or_default();
        assert!(!s.sent.iter().any(|k| k == "decide"), "{:?}", s.sent);
        assert!(
            note.starts_with("No personal default was created"),
            "{note}"
        );
    }

    /// ⟨M05⟩ U5: attended only, and never twice: without a TTY (or with `--non-interactive`)
    /// nothing is sent at all; with a personal default already in this environment, or a
    /// runtime that does not serve the trusted-work forms, only the reads are sent, with no
    /// `Attend`, no `create` and no prompt.
    #[test]
    fn personal_default_offer_is_never_made_unattended_or_twice() {
        for ctx in [
            Ctx {
                stdin_tty: false,
                ..tty()
            },
            Ctx {
                non_interactive: true,
                ..tty()
            },
        ] {
            let mut s = Recorder::new();
            let mut p = script(&[]);
            assert_eq!(offer(&mut s, &mut p, &ctx), None);
            assert!(s.sent.is_empty(), "{:?}", s.sent);
        }
        let existing = Envelope::ok(serde_json::json!({"items": [{
            "policy_id": "pol-default", "revision": 1, "profile": "dev",
            "environments": [ENV], "default": true,
        }]}));
        let mut s = Recorder::new()
            .answer("inspect", existing)
            .answer("inspect", own_environment());
        let mut p = script(&[]);
        assert_eq!(offer(&mut s, &mut p, &tty()), None);
        assert_eq!(s.sent, ["inspect", "inspect"]);
        let refused = output::error_value(
            heimdall_app::OpError::new(Code::SchemaUnsupported, "trusted-work/1 is not offered")
                .into_envelope(),
        );
        let mut s = Recorder::new().answer("inspect", refused);
        let mut p = script(&[]);
        assert_eq!(offer(&mut s, &mut p, &tty()), None);
        assert_eq!(s.sent, ["inspect"]);
    }

    /// ⟨M05⟩ Review M05-W3-R01, fail closed: a `create` record without a well-formed
    /// recorded `scope` (a runtime without ADR-0006 §17.10 item 22, or a basis that is gone)
    /// is never approved: nothing is asked and no `Decide` is sent, and the note says why.
    #[test]
    fn personal_default_offer_without_a_recorded_scope_approves_nothing() {
        let malformed = serde_json::json!({"profile_id": "dev", "pairs": []});
        for scope in [None, Some(malformed)] {
            let mut s = Recorder::new()
                .answer("inspect", no_policies())
                .answer("inspect", own_environment())
                .answer("inspect", one_profile())
                .answer("other", approval(Code::ApprovalRequired))
                .answer("inspect", create_listing(scope));
            let mut p = script(&[]);
            let note = offer(&mut s, &mut p, &tty()).unwrap_or_default();
            assert_eq!(
                s.sent,
                [
                    "inspect", "inspect", "inspect", "attend", "policy", "inspect"
                ]
            );
            assert!(p.shown.is_empty(), "nothing is asked: {:?}", p.shown);
            assert!(
                note.starts_with("No personal default was created")
                    && note.contains("did not record the scope"),
                "{note}"
            );
        }
    }

    /// ⟨M05⟩ Review M05-W3-R01, the reviewer's probe inverted (ADR-0006 §17.10 item 22).
    /// A **real runtime**: the production `Service` in this process on its real control
    /// endpoint in a scratch home, with the debug build's test configuration (fixture
    /// environment, profiles `dev` = h1, h2, h3 and `ops`, policies `pol` = h1, h2 and
    /// `pol-ops`); the offer runs over a real `Client`. The owner's profile `review` is h1
    /// and this environment's default profile. A production `UpsertProfile` (h1, h2, h3)
    /// commits after the offer read the profile and before its `create` reaches the
    /// runtime, which pins the newer revision. The prompt's destination line is exactly the
    /// scope the runtime recorded for that decision (h3 included), and approval creates a
    /// default with exactly that scope. The `extend_scope` record raised afterwards carries
    /// no `scope`.
    #[cfg(debug_assertions)]
    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]
    fn personal_default_offer_shows_the_scope_recorded_after_a_catalog_edit() {
        use heimdall_contract::catalog::{CatalogRequest, ProfileSpec};
        use heimdall_contract::request::AccessPairRef;

        struct Interleaved {
            client: Client,
            edit: Option<Request>,
            decisions: Vec<serde_json::Value>,
        }
        impl Session for Interleaved {
            async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
                if matches!(request, Request::Policy(PolicyAction::Create { .. }))
                    && let Some(edit) = self.edit.take()
                {
                    let edited = self.client.request(edit).await;
                    assert!(edited.code.is_success(), "the catalog edit: {edited:?}");
                }
                let listing = matches!(
                    &request,
                    Request::Inspect(i) if i.subject == InspectSubject::Decisions
                );
                let env = self.client.request(request).await;
                if listing {
                    self.decisions.push(env.data.clone());
                }
                env
            }
            async fn attend(&mut self) -> Envelope<serde_json::Value> {
                self.client.attend().await
            }
        }
        struct Capture(String);
        impl Prompter for Capture {
            async fn ask(&mut self, text: &str) -> Answer {
                self.0.push_str(text);
                Answer::Yes
            }
        }
        let pairs = |names: &[&str]| -> BTreeSet<AccessPairRef> {
            names
                .iter()
                .map(|d| AccessPairRef {
                    destination: heimdall_contract::ids::DestinationId::parse(d).unwrap(),
                    account: heimdall_contract::ids::AccountName::parse("deploy").unwrap(),
                })
                .collect()
        };
        let review = ProfileId::parse("review").unwrap();
        let upsert = |names: &[&str], rid: &str| {
            Request::Catalog(CatalogRequest::UpsertProfile {
                profile: ProfileSpec {
                    id: review.clone(),
                    pairs: pairs(names),
                    label: None,
                },
                request_id: RequestId::parse(rid).unwrap(),
            })
        };

        let scratch = tempfile::tempdir().unwrap();
        let ctx = Ctx {
            json: false,
            non_interactive: false,
            home: Some(scratch.path().join("hm")),
            stdin_tty: true,
        };
        let runtime = InProcessRuntime::start(&ctx);
        let (note, shown, recorded, created) = block_on(async {
            let mut client = crate::client::connect(&ctx, false).await.unwrap();
            for request in [
                upsert(&["h1"], "r01-review-1"),
                Request::Catalog(CatalogRequest::SetDefaultProfile {
                    environment: None,
                    profile: Some(review.clone()),
                    request_id: RequestId::parse("r01-default").unwrap(),
                }),
            ] {
                let env = client.request(request).await;
                assert!(env.code.is_success(), "{env:?}");
            }
            let mut session = Interleaved {
                client,
                edit: Some(upsert(&["h1", "h2", "h3"], "r01-review-2")),
                decisions: Vec::new(),
            };
            let mut capture = Capture(String::new());
            let note = offer_personal_default(&mut session, &mut capture, &ctx).await;
            assert!(session.edit.is_none(), "the edit ran before the create");
            let recorded: Vec<DecisionScope> = session
                .decisions
                .iter()
                // ⟨rev7⟩ The offer reads its decision by a point lookup (`items`).
                .flat_map(|l| l["items"].as_array().cloned().unwrap_or_default())
                .filter_map(|d| recorded_scope(&d))
                .collect();
            let created = runtime
                .store
                .transaction(|tx| {
                    Ok(tx
                        .policies()?
                        .into_iter()
                        .find(|p| p.profile == review && p.default))
                })
                .unwrap();
            // Another `WidenPolicy` record: `pol` gains h3 (its profile's third pair).
            let extend = session
                .client
                .request(Request::Policy(PolicyAction::ExtendScope {
                    policy_id: heimdall_contract::ids::PolicyId::parse("pol").unwrap(),
                    pairs: pairs(&["h3"]),
                    capabilities: BTreeSet::new(),
                    environments: BTreeSet::new(),
                    background_work: None,
                }))
                .await;
            let extension = pending_decision(&extend).expect("an extend_scope record");
            let listing = session
                .client
                .request(Request::Inspect(InspectRequest {
                    subject: InspectSubject::Decisions,
                    preview: None,
                    cwd: None,
                    redact: false,
                    select: None,
                    page: None,
                }))
                .await;
            let entry = listing.data["decisions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|d| d["decision_id"] == extension.as_str())
                .cloned()
                .unwrap();
            assert_eq!(entry["request"]["action"]["action"], "extend_scope");
            assert!(entry.get("scope").is_none(), "no scope key: {entry}");
            (note, capture.0, recorded, created)
        });
        runtime.stop();
        assert!(
            note.as_deref()
                .is_some_and(|n| n.starts_with("Personal default created")),
            "{note:?}"
        );
        let [scope] = recorded.as_slice() else {
            panic!("one recorded create scope: {recorded:?}");
        };
        assert_eq!(
            scope.pairs,
            pairs(&["h1", "h2", "h3"]),
            "the newer revision"
        );
        assert_eq!(scope.profile_revision, 2);
        assert!(
            shown.contains("Destinations and accounts: h1:deploy, h2:deploy, h3:deploy\n"),
            "the disclosure is the recorded scope, h3 included: {shown}"
        );
        assert!(shown.contains("Profile: review at revision 2"), "{shown}");
        let created = created.expect("the default was created");
        assert_eq!(
            created.scope.pairs, scope.pairs,
            "approval applied what was shown"
        );
        assert_eq!(created.scope.capabilities, scope.capabilities);
        assert_eq!(created.environments, scope.environments);
        assert_eq!(created.lock_behavior, scope.lock_behavior);
    }

    /// The production runtime `Service` on its own thread and executor, in the scratch
    /// Heimdall home of a [`Ctx`], with the debug build's test configuration (the fake
    /// adapter, synchronized time, the fixture catalog) and no managed wiring (this process
    /// is the test harness, never an issuer child). Stopped by its cancellation token when
    /// dropped (a failing assertion included), before the scratch home goes.
    #[cfg(debug_assertions)]
    struct InProcessRuntime {
        store: std::sync::Arc<heimdall_store::Store>,
        token: tokio_util::sync::CancellationToken,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(debug_assertions)]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    impl InProcessRuntime {
        fn start(ctx: &Ctx) -> Self {
            use heimdall_runtime::service::{Service, ServiceOptions};
            let paths = ctx.paths().unwrap();
            let token = tokio_util::sync::CancellationToken::new();
            let stop = token.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let rt = Service::runtime().unwrap();
                rt.block_on(async move {
                    let clock = std::sync::Arc::new(
                        heimdall_runtime::platform::SystemClock::try_new().unwrap(),
                    );
                    let mut options = ServiceOptions::with_clock(
                        clock,
                        std::sync::Arc::new(heimdall_runtime::platform::SystemTimeSync),
                    );
                    let env = |name: &str| match name {
                        "HEIMDALL_TEST_ADAPTER" => Some("prepare".into()),
                        "HEIMDALL_TEST_TIME_SYNC" => Some("synchronized".into()),
                        _ => None,
                    };
                    let setup = crate::testcfg::prepare(&mut options, &paths, true, &env)
                        .unwrap()
                        .unwrap();
                    let service = Service::start_with(
                        paths,
                        heimdall_runtime::config::Config::default(),
                        options,
                        stop,
                    )
                    .await
                    .unwrap();
                    setup.seed(&service).unwrap();
                    let _ = tx.send(std::sync::Arc::clone(service.store()));
                    let _ = service.run().await;
                });
            });
            let store = rx.recv().expect("the runtime started");
            Self {
                store,
                token,
                thread: Some(thread),
            }
        }

        fn stop(mut self) {
            self.token.cancel();
            if let Some(t) = self.thread.take() {
                t.join().unwrap();
            }
        }
    }

    #[cfg(debug_assertions)]
    impl Drop for InProcessRuntime {
        fn drop(&mut self) {
            self.token.cancel();
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }
}
