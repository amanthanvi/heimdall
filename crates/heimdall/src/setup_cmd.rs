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
//!   repair commands, and every non-empty quarantine directory with its entries.
//!
//! The helpers of the owner-present flow ([`attend_first`], [`confirm_and_decide`],
//! [`decided_request`]) are shared with `catalog_cmd` and `uninstall_cmd`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use heimdall_contract::envelope::{EffectStatus, Envelope, NextAction, Warning, reason};
use heimdall_contract::ids::{DecisionId, OperationId, RequestId};
use heimdall_contract::request::{
    DecideRequest, InspectRequest, InspectSubject, ObserveRequest, Request, Verdict,
};
use heimdall_contract::setup::{
    ConflictKind, PlanDigest, PreviewIntent, ProjectionItem, RepairResolution, SetupRequest,
};
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
        }))
        .await;
    if env.code.is_success() {
        Ok(env.data)
    } else {
        Err(Outcome::of(env))
    }
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

/// Show `preface` and the exact recorded request of `decision`, require a typed `yes`,
/// and only then send `Decide approve` (ADR-0006 §3.1). With `expect_digest`, a recorded
/// `ApplyProjection` whose plan digest differs from the plan shown is refused and
/// nothing is sent. Anything but `yes` sends nothing: exit 3 "not confirmed".
pub(crate) async fn confirm_and_decide<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    decision: &str,
    preface: &str,
    expect_digest: Option<&str>,
    operation: Option<OperationId>,
) -> Envelope<serde_json::Value> {
    if !ctx.interactive() {
        return not_confirmed(Some(decision), operation, non_interactive_reason(ctx));
    }
    let Ok(decision_id) = DecisionId::parse(decision) else {
        return failure(Code::UsageError, "invalid decision reference", None);
    };
    let listing = match inspect(s, InspectSubject::Decisions).await {
        Ok(d) => d,
        Err(o) => return o.env,
    };
    let record = listing
        .get("decisions")
        .and_then(|d| d.as_array())
        .and_then(|l| {
            l.iter()
                .find(|d| d.get("decision_id").and_then(|v| v.as_str()) == Some(decision))
                .cloned()
        });
    let Some(record) = record else {
        return not_confirmed(
            Some(decision),
            operation,
            "the decision is not pending in this runtime",
        );
    };
    let request = record
        .get("request")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if let Some(expected) = expect_digest
        && let Some(recorded) = request.get("plan_digest").and_then(|v| v.as_str())
        && recorded != expected
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
    let text = format!(
        "{preface}\n{restore}Owner decision {decision}\n  kind: {}\n  expires: {}\n  recorded request (exactly what approve applies to):\n{}\n\
         Heimdall cannot verify that this prompt was shown: a program running as your user could imitate it.\n\
         Approve exactly this request?\n",
        field("kind"),
        field("expires_at"),
        serde_json::to_string_pretty(&request)
            .unwrap_or_default()
            .lines()
            .map(|l| format!("    {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let answer = p.ask(&text).await;
    if answer != Answer::Yes {
        return not_confirmed(Some(decision), operation, answer.reason());
    }
    s.request(Request::Decide(DecideRequest {
        decision_id,
        verdict: Verdict::Approve,
    }))
    .await
}

/// An owner-present request (ADR-0006 §3.1): attend first (interactive TTY only), send
/// `request`; when it waits on an owner decision and a prompt can be shown, run
/// [`confirm_and_decide`] and send the same request again. Otherwise the runtime's
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
    let env = s.request(request.clone()).await;
    let Some(decision) = pending_decision(&env) else {
        return settle(s, request, env).await;
    };
    if !ctx.interactive() {
        return env;
    }
    let decided = confirm_and_decide(
        s,
        p,
        ctx,
        &decision,
        preface,
        expect_digest,
        env.operation_id.clone(),
    )
    .await;
    if decided.code != Code::Ok {
        return decided;
    }
    let again = s.request(request.clone()).await;
    settle(s, request, again).await
}

/// While the answer is `ACCEPTED` with an operation, wait for it (bounded) and replay the
/// same request (same request ID), so the caller sees the settled result.
async fn settle<S: Session>(
    s: &mut S,
    request: Request,
    mut env: Envelope<serde_json::Value>,
) -> Envelope<serde_json::Value> {
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
}

// --- setup ------------------------------------------------------------------------------

/// Handle `setup` (module docs). Without an action, `apply`.
pub(crate) fn run(ctx: &Ctx, args: SetupArgs) -> ExitCode {
    let action = args.action.unwrap_or(SetupCommand::Apply {
        include_git: false,
        request_id: None,
    });
    match action {
        SetupCommand::Preview { include_git } => {
            block(ctx, preview(ctx, PreviewIntent::Apply { include_git }))
        }
        SetupCommand::Apply {
            include_git,
            request_id,
        } => block(
            ctx,
            effect(ctx, PreviewIntent::Apply { include_git }, request_id),
        ),
        SetupCommand::Rollback {
            keep_key_files,
            request_id,
        } => block(
            ctx,
            effect(ctx, rollback_intent(keep_key_files), request_id),
        ),
        SetupCommand::Repair(r) => match repair_intent(&r) {
            Ok(intent) => block(ctx, effect(ctx, intent, r.request_id)),
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

/// `apply`, `rollback`, `repair` on a new session.
async fn effect(ctx: &Ctx, intent: PreviewIntent, given: Option<String>) -> Outcome {
    let rid = match request_id(given.as_deref()) {
        Ok(r) => r,
        Err(o) => return o,
    };
    let mut client = match session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let out = setup_flow(&mut client, &mut TerminalPrompt, ctx, &intent, rid).await;
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
            .request(Request::Setup(effect_request(intent, digest, rid)))
            .await;
        return result_outcome(env);
    }
    if held.is_some() {
        // `retry` continues exactly the recorded plan; no decision (QR12).
        let request = Request::Setup(effect_request(intent, digest, rid));
        let env = s.request(request.clone()).await;
        return result_outcome(settle(s, request, env).await);
    }
    let request = Request::Setup(effect_request(intent, digest.clone(), rid));
    let env = decided_request(s, p, ctx, request, &plan_text, Some(digest.as_str())).await;
    result_outcome(env)
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
        PreviewIntent::Apply { include_git: false }
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
}
