//! `heimdall enroll <destination>` and `enroll status|verify|remove|reconcile|abandon`
//! (m03-plan U12, §5 item 24; ADR-0008 D5).
//!
//! * **`enroll <destination>`**: `Enrollment::Preview`, shown in full (the exact line
//!   to be written, or the system form's lines the owner installs, and every
//!   disclosure); then `Apply` with that plan's digest, on a session attended first;
//!   the owner's typed `yes` on the recorded `EnrollAccount` / `EnrollSystemForm`
//!   decision (`setup_cmd::confirm_and_decide`, which refuses a recorded digest other
//!   than the one shown); then the **client-executed loop** of [`drive`]. End of input,
//!   Ctrl-C, the prompt timeout, a non-TTY stdin and `--non-interactive` send nothing
//!   more and exit 3 with `next.decision_ref`. Nothing skips the decision.
//! * **`enroll status`**: `inspect enrollments` (read-only; never starts a runtime),
//!   with each record's state and marker, a verified record's `slot_free` command, the
//!   `late_write` residual (`possible_late_write`), and a held record's reason and next
//!   step.
//! * **`enroll verify <e> [--absence | --approve-target-change]`**: `Enrollment::Verify`.
//!   A target change shows the new host key as a diff against the approved one and
//!   needs the `ApproveTargetChange` decision.
//! * **`enroll remove <e>`**: account form, the `RemoveEnrollment` decision (a held
//!   host-key change shows the freshly evaluated target as a diff), then the loop. The
//!   system form changes nothing remote: a typed confirmation, then the lines to delete;
//!   it is never called removed before `enroll verify <e> --absence` passes.
//! * **`enroll remove --from-bundle <file> --marker <m> --alias <a>`**: the bundle is
//!   read locally; a redacted one is refused (`bundle_redacted`, exit 4) before any
//!   runtime contact.
//! * **`enroll reconcile <op> [--after-manual-recovery]`**: classification; the same loop
//!   (a manual-recovery reconcile only ever runs `inspect`).
//! * **`enroll abandon <e>`**: a typed confirmation, then `Enrollment::Abandon`.
//!
//! `--json` prints exactly one envelope; prompts, the preview and step progress go to
//! stderr. When the flow stops before the operation runs (a pending decision, a refusal
//! of the prompt), the envelope's `data.plan` carries the previewed plan.
//!
//! **Test configuration.** The CLI is the only reader of
//! `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` (`testcfg::enroll_hooks`: a release build refuses
//! it, a debug build validates it). Inserting the pause points needs
//! `heimdall_registry::script::test_form`, and `heimdall-registry` is not a dependency
//! of this crate (escalated): until [`SCRIPT_PAUSE_POINTS_CONSUMED`], a set pause
//! directory refuses every form but `status` (exit 2, nothing sent).

mod drive;
mod render;

/// The enrollment plan's disclosure wording (one set for the CLI and the TUI).
#[allow(unused_imports)] // offered to the TUI (T-R1); the preview uses it in place
pub(crate) use render::disclosure_text;

use std::path::Path;

use heimdall_contract::enrollment::{
    EnrollmentForm, EnrollmentPlan, EnrollmentRequest, EnrollmentResult, EnrollmentSpec,
    ForeignRemovalTarget, RemovalTarget, TargetSummary, VerifyMode,
};
use heimdall_contract::envelope::{Envelope, reason};
use heimdall_contract::ids::{
    AccountName, CaFingerprint, DestinationId, EnrollmentId, OperationId, RequestId,
};
use heimdall_contract::ipc::capability;
use heimdall_contract::issuer::{RECOVERY_BUNDLE_SCHEMA, RecoveryBundle};
use heimdall_contract::request::{InspectSubject, Request, WaitMode};
use heimdall_contract::{Code, ExitCode};

use crate::cli::{
    EnrollArgs, EnrollCommand, EnrollStartArgs, FormArg, Prompter, Session, TerminalPrompt,
};
use crate::client::{Client, Ctx, error};
use crate::output;
use crate::prompt::Answer;
use crate::setup_cmd::{self, Outcome};
use crate::testcfg;

/// **Switch (escalated; `.m03-wave5-questions.md` heading E).** Whether this CLI inserts
/// the test form's pause points into the scripts it runs
/// (`HEIMDALL_TEST_SCRIPT_PAUSE_DIR`). `false`: the `heimdall-registry` edge it needs is
/// not in the crate graph, so a set pause directory is refused (fail closed: a test that
/// expects pauses never runs unpaused).
pub(crate) const SCRIPT_PAUSE_POINTS_CONSUMED: bool = false;

/// **Switch (Q-I1 option (c); U5IO-Q3).** While
/// `heimdall_enroll::remote::INTERACTIVE_FOREGROUND_HANDOFF` is `false`, refuse up front
/// an interactive step (and an interactive enrollment's plan) whose existing access is
/// not an agent-held identity: a terminal prompt could not be answered and the step
/// would only stall until its bound.
pub(crate) const REFUSE_UNHELD_INTERACTIVE_IDENTITY: bool = true;

/// The longest recovery bundle read (bytes).
const BUNDLE_MAX: u64 = 8 * 1024 * 1024;

/// Handle `enroll`.
pub(crate) fn run(ctx: &Ctx, args: EnrollArgs) -> ExitCode {
    let pause = match testcfg::enroll_hooks(&|n| std::env::var_os(n)) {
        Ok(p) => p,
        Err(msg) => {
            return Outcome::of(output::error_value(error(Code::UsageError, &msg))).emit(ctx);
        }
    };
    // `enroll` alone names neither a destination nor a subcommand.
    if args.command.is_none() && args.start.destination.is_none() {
        return setup_cmd::usage("enroll needs a destination or a subcommand").emit(ctx);
    }
    if pause.is_some()
        && !SCRIPT_PAUSE_POINTS_CONSUMED
        && !matches!(args.command, Some(EnrollCommand::Status))
    {
        return setup_cmd::usage(&format!(
            "{} is set, but this CLI cannot insert the script pause points yet (the heimdall-registry edge is pending); nothing was sent",
            testcfg::SCRIPT_PAUSE_DIR_ENV
        ))
        .emit(ctx);
    }
    let mut p = TerminalPrompt;
    setup_cmd::block(ctx, async move {
        match args.command {
            None => start(ctx, &mut p, args.start).await,
            Some(EnrollCommand::Status) => status(ctx).await,
            Some(EnrollCommand::Verify {
                enrollment,
                absence,
                approve_target_change,
            }) => {
                let mode = if absence {
                    VerifyMode::Absence
                } else if approve_target_change {
                    VerifyMode::TargetChange
                } else {
                    VerifyMode::Presence
                };
                verify(ctx, &mut p, &enrollment, mode).await
            }
            Some(EnrollCommand::Remove {
                enrollment,
                from_bundle,
                marker,
                alias,
            }) => match (enrollment, from_bundle, marker, alias) {
                (_, Some(file), Some(marker), Some(alias)) => {
                    remove_foreign(ctx, &mut p, &file, &marker, &alias).await
                }
                (Some(e), None, _, _) => remove(ctx, &mut p, &e).await,
                _ => setup_cmd::usage(
                    "remove needs an enrollment, or --from-bundle with --marker and --alias",
                ),
            },
            Some(EnrollCommand::Reconcile {
                operation,
                after_manual_recovery,
            }) => reconcile(ctx, &operation, after_manual_recovery).await,
            Some(EnrollCommand::Abandon { enrollment }) => abandon(ctx, &mut p, &enrollment).await,
        }
    })
}

// --- shared --------------------------------------------------------------------------

/// A session that negotiated `enrollment/1` (effectful commands start the runtime on
/// demand).
async fn session(ctx: &Ctx, allow_start: bool) -> Result<Client, Outcome> {
    crate::client::connect_requiring(ctx, allow_start, &[capability::ENROLLMENT_V1])
        .await
        .map_err(|e| Outcome::of(output::error_value(*e)))
}

/// `value` parsed as `what`, or a usage error naming it.
fn parsed<T, E>(what: &str, f: impl FnOnce(&str) -> Result<T, E>, s: &str) -> Result<T, Outcome> {
    f(s).map_err(|_| setup_cmd::usage(&format!("invalid {what}")))
}

/// `env` with `key` set in its data object (an envelope the CLI completes, as uninstall
/// adds `data.enrollments`).
fn with_data(
    mut env: Envelope<serde_json::Value>,
    key: &str,
    value: serde_json::Value,
) -> Envelope<serde_json::Value> {
    if let serde_json::Value::Object(map) = &mut env.data {
        map.insert(key.to_owned(), value);
    } else if env.data.is_null() {
        env.data = serde_json::json!({ key: value });
    }
    env
}

/// The pending decision's recorded request (`inspect decisions`), if listed.
async fn decision_request<S: Session>(s: &mut S, decision: &str) -> Option<serde_json::Value> {
    let listing = setup_cmd::inspect(s, InspectSubject::Decisions)
        .await
        .ok()?;
    listing
        .get("decisions")?
        .as_array()?
        .iter()
        .find(|d| d.get("decision_id").and_then(|v| v.as_str()) == Some(decision))
        .and_then(|d| d.get("request").cloned())
}

/// A typed confirmation that has no decision record (the system form's removal, an
/// abandonment): anything but `yes`, or no terminal, sends nothing (exit 3).
async fn typed_confirmation<P: Prompter>(p: &mut P, ctx: &Ctx, text: &str) -> Result<(), Outcome> {
    if !ctx.interactive() {
        return Err(Outcome::of(setup_cmd::not_confirmed(
            None,
            None,
            setup_cmd::non_interactive_reason(ctx),
        )));
    }
    let answer = p.ask(text).await;
    if answer == Answer::Yes {
        Ok(())
    } else {
        Err(Outcome::of(setup_cmd::not_confirmed(
            None,
            None,
            answer.reason(),
        )))
    }
}

/// A preface shown in human mode (stderr; the prompt's context).
fn show(ctx: &Ctx, text: &str) {
    if !ctx.json && !text.trim().is_empty() {
        output::diagnostic(text.trim_end());
    }
}

/// The answer after a decision-bearing request: on a pending decision, the owner's
/// typed `yes` on its recorded request (`preface` first, `expect_digest` checked), then
/// the same request again; otherwise the answer stands. `Err` is the outcome to report
/// (not confirmed, a pending decision without a terminal, a refusal).
async fn decided<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    request: &Request,
    env: Envelope<serde_json::Value>,
    preface: &dyn Fn(Option<&serde_json::Value>) -> String,
    expect_digest: Option<&str>,
) -> Result<Envelope<serde_json::Value>, Envelope<serde_json::Value>> {
    let Some(decision) = setup_cmd::pending_decision(&env) else {
        return Ok(env);
    };
    let recorded = decision_request(s, &decision).await;
    let text = preface(recorded.as_ref());
    if !ctx.interactive() {
        show(ctx, &text);
        let env = match recorded {
            Some(r) => with_data(env, "decision_request", r),
            None => env,
        };
        return Err(env);
    }
    let answer = setup_cmd::confirm_and_decide(
        s,
        p,
        ctx,
        &decision,
        &text,
        expect_digest,
        env.operation_id.clone(),
    )
    .await;
    if answer.code != Code::Ok {
        return Err(answer);
    }
    Ok(s.request(request.clone()).await)
}

/// After the (decided) request: drive the operation when it waits on client steps,
/// render a result, or report the answer.
async fn settle<S: Session>(
    s: &mut S,
    env: Envelope<serde_json::Value>,
    mode: drive::DriveMode,
) -> Outcome {
    let wants_steps = env.code == Code::Accepted
        && (env.next.as_ref().is_some_and(|n| n.action == "step")
            || env.data.get("next").and_then(|v| v.as_str()) == Some("step"));
    if wants_steps && let Some(op) = env.operation_id.clone() {
        return drive::drive(s, &op, mode).await;
    }
    if env.code.is_success()
        && let Ok(result) = serde_json::from_value::<EnrollmentResult>(env.data.clone())
    {
        return Outcome::of(env.clone()).with_human(render::result(&result, mode.form));
    }
    Outcome::of(env)
}

// --- enroll <destination> ------------------------------------------------------------

/// The catalog destination named by `wanted` (ID or alias): its ID and alias.
fn find_destination(listing: &serde_json::Value, wanted: &str) -> Option<(String, String)> {
    let text =
        |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_owned);
    listing
        .get("items")
        .and_then(|i| i.as_array())?
        .iter()
        .find(|d| {
            text(d, "alias").as_deref() == Some(wanted)
                || text(d, "destination_id").as_deref() == Some(wanted)
        })
        .and_then(|d| Some((text(d, "destination_id")?, text(d, "alias")?)))
}

async fn start<P: Prompter>(ctx: &Ctx, p: &mut P, a: EnrollStartArgs) -> Outcome {
    let Some(wanted) = a.destination else {
        return setup_cmd::usage("enroll needs a destination");
    };
    let account = match a
        .account
        .as_deref()
        .map(|s| parsed("account", AccountName::parse, s))
    {
        Some(Err(o)) => return o,
        Some(Ok(v)) => Some(v),
        None => None,
    };
    let ca = match a
        .ca
        .as_deref()
        .map(|s| parsed("CA fingerprint", CaFingerprint::parse, s))
    {
        Some(Err(o)) => return o,
        Some(Ok(v)) => Some(v),
        None => None,
    };
    let form = match a.form {
        Some(FormArg::System) => EnrollmentForm::System,
        _ => EnrollmentForm::Account,
    };
    let mut s = match session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let listing = match setup_cmd::inspect(&mut s, InspectSubject::Destinations).await {
        Ok(d) => d,
        Err(o) => return o,
    };
    let id = match find_destination(&listing, &wanted) {
        Some((id, _)) => id,
        None => wanted.clone(),
    };
    let Ok(destination) = DestinationId::parse(&id) else {
        return Outcome::of(setup_cmd::failure(
            Code::NotFound,
            "no such destination",
            None,
        ));
    };
    let spec = EnrollmentSpec {
        destination,
        account,
        form,
        registry_path: a.registry_path,
        ca_fingerprint: ca,
    };
    enroll_flow(&mut s, p, ctx, spec).await
}

/// Preview, apply, decide, drive (module docs).
pub(crate) async fn enroll_flow<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    spec: EnrollmentSpec,
) -> Outcome {
    let preview = s
        .request(Request::Enrollment(EnrollmentRequest::Preview {
            spec: spec.clone(),
        }))
        .await;
    if !preview.code.is_success() {
        return Outcome::of(preview);
    }
    let Ok(plan) = serde_json::from_value::<EnrollmentPlan>(preview.data.clone()) else {
        return Outcome::of(setup_cmd::failure(
            Code::InternalError,
            "the runtime's enrollment plan cannot be read; nothing was applied",
            None,
        ));
    };
    let plan_value = preview.data.clone();
    let shown = render::preview(&plan);
    show(ctx, &shown);
    if REFUSE_UNHELD_INTERACTIVE_IDENTITY
        && !heimdall_enroll::remote::INTERACTIVE_FOREGROUND_HANDOFF
        && ctx.interactive()
        && !drive::invocation_agent_held(&plan.existing_access.invocation)
    {
        let env = setup_cmd::failure(
            Code::InteractionRequired,
            "the existing access is not an agent-held identity, and a prompt on this terminal cannot be answered while a remote step runs; nothing was applied. Add the key to an agent and enroll again",
            None,
        );
        return Outcome::of(with_data(env, "plan", plan_value));
    }
    let request_id = match setup_cmd::request_id(None) {
        Ok(r) => r,
        Err(o) => return o,
    };
    let request = Request::Enrollment(EnrollmentRequest::Apply {
        spec,
        plan_digest: plan.plan_digest.clone(),
        request_id,
        interaction: ctx.interaction(),
        wait: WaitMode::default(),
    });
    if let Err(refused) = setup_cmd::attend_first(s, ctx).await {
        return Outcome::of(refused);
    }
    let env = s.request(request.clone()).await;
    let digest = plan.plan_digest.to_string();
    let form = plan.form;
    let preface = |recorded: Option<&serde_json::Value>| {
        let mut t =
            format!("You are deciding the enrollment previewed above (plan digest {digest}).\n");
        if form == EnrollmentForm::System {
            let lines = recorded
                .and_then(|r| r.get("sshd_lines"))
                .and_then(|l| {
                    serde_json::from_value::<heimdall_domain::decision::SystemFormLines>(l.clone())
                        .ok()
                })
                .unwrap_or_else(|| render::system_lines(&plan));
            t.push_str("Approving lets Heimdall issue verification certificates for this pair once you have installed, yourself:\n");
            t.push_str(&format!(
                "  TrustedUserCAKeys file line: {}\n",
                lines.trusted_user_ca_keys_line
            ));
            t.push_str(&format!(
                "  AuthorizedPrincipalsFile line: {}\n",
                lines.principals_line
            ));
            for d in &lines.sshd_directives {
                t.push_str(&format!("  sshd_config: {d}\n"));
            }
        } else {
            t.push_str(&format!(
                "Approving writes exactly this line to {}:\n  {}\n",
                plan.registry.path_display, plan.line
            ));
        }
        t
    };
    let env = match decided(s, p, ctx, &request, env, &preface, Some(&digest)).await {
        Ok(env) => env,
        Err(stopped) => return Outcome::of(with_data(stopped, "plan", plan_value)),
    };
    settle(
        s,
        env,
        drive::DriveMode {
            form: Some(form),
            json: ctx.json,
            ..drive::DriveMode::default()
        },
    )
    .await
}

// --- enroll status -------------------------------------------------------------------

async fn status(ctx: &Ctx) -> Outcome {
    let mut s = match session(ctx, false).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let view = match setup_cmd::inspect(&mut s, InspectSubject::Enrollments).await {
        Ok(v) => v,
        Err(o) => return o,
    };
    let listing = setup_cmd::inspect(&mut s, InspectSubject::Destinations)
        .await
        .unwrap_or(serde_json::Value::Null);
    let alias_of = |dest: &str| {
        listing
            .get("items")
            .and_then(|i| i.as_array())
            .and_then(|items| {
                items
                    .iter()
                    .find(|d| d.get("destination_id").and_then(|v| v.as_str()) == Some(dest))
            })
            .and_then(|d| d.get("alias").and_then(|v| v.as_str()).map(str::to_owned))
    };
    let human = render::status(&view, &alias_of);
    // The machine form: the runtime's view, and per record what the human form adds
    // (the alias, the `slot_free` command, a held record's next commands).
    let guidance: Vec<serde_json::Value> = view
        .get("enrollments")
        .and_then(|e| e.as_array())
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .map(|e| {
            let text = |k: &str| e.get(k).and_then(|v| v.as_str()).unwrap_or("").to_owned();
            let id = text("enrollment_id");
            let alias = alias_of(&text("destination_id"));
            let state = text("state");
            let mut g = serde_json::json!({ "enrollment_id": id, "alias": alias });
            if state == "verified"
                && let Some(a) = &alias
            {
                g["slot_free_command"] =
                    serde_json::json!(heimdall_localenv::projection::plan::slot_free_command(a));
            }
            if state == "held" {
                let reason = e
                    .get("hold")
                    .and_then(|h| h.get("reason"))
                    .and_then(|v| v.as_str());
                g["next_commands"] = serde_json::json!(render::held_next(
                    reason,
                    &id,
                    e.get("open_operation_id").and_then(|v| v.as_str())
                ));
            }
            g
        })
        .collect();
    let mut env = Envelope::ok(view);
    env = with_data(env, "guidance", serde_json::Value::Array(guidance));
    Outcome::of(env).with_human(human)
}

// --- enroll verify -------------------------------------------------------------------

async fn verify<P: Prompter>(ctx: &Ctx, p: &mut P, enrollment: &str, mode: VerifyMode) -> Outcome {
    let id = match parsed("enrollment ID", EnrollmentId::parse, enrollment) {
        Ok(v) => v,
        Err(o) => return o,
    };
    let request_id = match setup_cmd::request_id(None) {
        Ok(r) => r,
        Err(o) => return o,
    };
    let mut s = match session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    verify_flow(&mut s, p, ctx, id, request_id, mode).await
}

/// `enroll verify` on a session.
pub(crate) async fn verify_flow<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    id: EnrollmentId,
    request_id: RequestId,
    mode: VerifyMode,
) -> Outcome {
    let request = Request::Enrollment(EnrollmentRequest::Verify {
        enrollment_id: id,
        request_id,
        mode,
        wait: WaitMode::default(),
    });
    if let Err(refused) = setup_cmd::attend_first(s, ctx).await {
        return Outcome::of(refused);
    }
    let env = s.request(request.clone()).await;
    let preface = |recorded: Option<&serde_json::Value>| {
        let target = |k: &str| {
            recorded.and_then(|r| r.get(k)).and_then(|t| {
                serde_json::from_value::<heimdall_contract::enrollment::ApprovedTarget>(t.clone())
                    .ok()
            })
        };
        match (target("approved"), target("proposed")) {
            (Some(a), Some(n)) => format!(
                "{}Approving re-verifies the enrollment against the new key; the approved target is replaced only if that verification passes.\n",
                render::key_diff(&a, &n)
            ),
            _ => {
                "The recorded target change could not be read; review the recorded request below.\n"
                    .to_owned()
            }
        }
    };
    let env = match decided(s, p, ctx, &request, env, &preface, None).await {
        Ok(env) => env,
        Err(stopped) => return Outcome::of(stopped),
    };
    let form = (mode == VerifyMode::Absence).then_some(EnrollmentForm::System);
    settle(
        s,
        env,
        drive::DriveMode {
            form,
            json: ctx.json,
            ..drive::DriveMode::default()
        },
    )
    .await
}

// --- enroll remove -------------------------------------------------------------------

/// The listed record of `id` (`inspect enrollments`), if any.
async fn listed<S: Session>(
    s: &mut S,
    id: &EnrollmentId,
) -> Result<Option<serde_json::Value>, Outcome> {
    let view = setup_cmd::inspect(s, InspectSubject::Enrollments).await?;
    Ok(view
        .get("enrollments")
        .and_then(|e| e.as_array())
        .and_then(|l| {
            l.iter()
                .find(|e| e.get("enrollment_id").and_then(|v| v.as_str()) == Some(id.as_str()))
                .cloned()
        }))
}

fn system_removal_text(what: &str, verify: &str) -> String {
    format!(
        "Remove {what} (system form). Heimdall changes nothing on the destination: you delete the \
         TrustedUserCAKeys line and the principals-file line yourself (they are shown next). It is \
         recorded removed only after `heimdall enroll verify {verify} --absence` passes.\n\
         Begin the manual removal?\n"
    )
}

async fn remove<P: Prompter>(ctx: &Ctx, p: &mut P, enrollment: &str) -> Outcome {
    let id = match parsed("enrollment ID", EnrollmentId::parse, enrollment) {
        Ok(v) => v,
        Err(o) => return o,
    };
    let request_id = match setup_cmd::request_id(None) {
        Ok(r) => r,
        Err(o) => return o,
    };
    let mut s = match session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let record = match listed(&mut s, &id).await {
        Ok(r) => r,
        Err(o) => return o,
    };
    let form = record
        .as_ref()
        .and_then(|r| r.get("form"))
        .and_then(|f| serde_json::from_value::<EnrollmentForm>(f.clone()).ok());
    let approved = record
        .as_ref()
        .and_then(|r| r.get("approved_target"))
        .and_then(|t| serde_json::from_value::<TargetSummary>(t.clone()).ok());
    remove_flow(
        &mut s,
        p,
        ctx,
        RemovalTarget::Enrollment {
            enrollment_id: id.clone(),
        },
        request_id,
        form,
        approved.as_ref(),
        &format!("enrollment {id}"),
    )
    .await
}

/// `enroll remove` on a session, for a target of `form` (when known).
// The removal's facts are the request's fields plus what the listing showed; a struct
// would only rename them.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn remove_flow<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    target: RemovalTarget,
    request_id: RequestId,
    form: Option<EnrollmentForm>,
    approved: Option<&TargetSummary>,
    what: &str,
) -> Outcome {
    let request = Request::Enrollment(EnrollmentRequest::Remove {
        target: target.clone(),
        request_id,
        interaction: ctx.interaction(),
        wait: WaitMode::default(),
    });
    if form == Some(EnrollmentForm::System) {
        // D5 §6.9: no decision; the request itself is the owner's typed confirmation.
        let verify = match &target {
            RemovalTarget::Enrollment { enrollment_id } => enrollment_id.to_string(),
            _ => "<enrollment>".to_owned(),
        };
        if let Err(o) = typed_confirmation(p, ctx, &system_removal_text(what, &verify)).await {
            return o;
        }
    }
    if let Err(refused) = setup_cmd::attend_first(s, ctx).await {
        return Outcome::of(refused);
    }
    let env = s.request(request.clone()).await;
    let preface = |recorded: Option<&serde_json::Value>| {
        let mut t = format!("You are deciding the removal of {what}.\n");
        let Some(r) = recorded else {
            return t;
        };
        if let Some(inv) = r.get("invocation").and_then(|v| v.as_array()) {
            let args: Vec<&str> = inv.iter().filter_map(|a| a.as_str()).collect();
            t.push_str(&format!("Every remote step runs: ssh {}\n", args.join(" ")));
        }
        if let Some(g) = r.get("affected_grants").and_then(|v| v.as_array()) {
            t.push_str(&format!(
                "Live grants under this CA for the pair, degraded on approval: {}\n",
                if g.is_empty() {
                    "none".to_owned()
                } else {
                    g.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ));
        }
        if let Some(until) = r.get("pair_residual_until").and_then(|v| v.as_str()) {
            t.push_str(&format!(
                "Certificates already issued stay valid until {until} (the pair residual).\n"
            ));
        }
        if let Some(fresh) = r
            .get("fresh_target")
            .filter(|v| !v.is_null())
            .and_then(|v| {
                serde_json::from_value::<heimdall_contract::enrollment::ApprovedTarget>(v.clone())
                    .ok()
            })
        {
            t.push_str("The enrollment is held for a host-key change: the removal runs against the freshly evaluated target.\n");
            t.push_str(&render::summary_diff(approved, &fresh));
        }
        t
    };
    let env = match decided(s, p, ctx, &request, env, &preface, None).await {
        Ok(env) => env,
        Err(stopped) => return Outcome::of(stopped),
    };
    settle(
        s,
        env,
        drive::DriveMode {
            form,
            json: ctx.json,
            ..drive::DriveMode::default()
        },
    )
    .await
}

/// The bundle at `file`, refused when unreadable, oversized or not a recovery bundle.
fn read_bundle(file: &Path) -> Result<RecoveryBundle, Outcome> {
    let shown = std::env::var_os("HOME")
        .map(|h| heimdall_localenv::paths::display_path(Path::new(&h), file))
        .unwrap_or_else(|| file.display().to_string());
    let bad =
        |why: &str| setup_cmd::usage(&format!("cannot use the recovery bundle {shown}: {why}"));
    let meta = std::fs::metadata(file).map_err(|e| bad(&format!("{:?}", e.kind())))?;
    if !meta.is_file() || meta.len() > BUNDLE_MAX {
        return Err(bad("not a regular file of at most 8 MiB"));
    }
    let bytes = std::fs::read(file).map_err(|e| bad(&format!("{:?}", e.kind())))?;
    let bundle: RecoveryBundle =
        serde_json::from_slice(&bytes).map_err(|_| bad("not a recovery bundle"))?;
    if bundle.schema != RECOVERY_BUNDLE_SCHEMA {
        return Err(bad("an unsupported bundle schema"));
    }
    Ok(bundle)
}

/// The removal descriptor of `marker` in `bundle` for `alias` (ADR-0008 D4 item 5): a
/// redacted bundle (or an entry without host and port) is refused `bundle_redacted`.
pub(crate) fn foreign_target(
    bundle: &RecoveryBundle,
    marker: &str,
    alias: &str,
) -> Result<ForeignRemovalTarget, Outcome> {
    let Some(e) = bundle.enrollments.iter().find(|e| e.marker == marker) else {
        return Err(Outcome::of(setup_cmd::failure(
            Code::NotFound,
            "the recovery bundle lists no enrollment with this marker",
            None,
        )));
    };
    let (Some(host), Some(port), false) = (e.hostname.clone(), e.port, bundle.redacted) else {
        return Err(Outcome::of(setup_cmd::failure(
            Code::CapabilityUnavailable,
            "the recovery bundle is redacted (no host name or port): a foreign removal needs an unredacted bundle; nothing was sent",
            Some(reason::BUNDLE_REDACTED),
        )));
    };
    Ok(ForeignRemovalTarget {
        local_alias: alias.to_owned(),
        bundle_destination_id: e.destination_id.clone(),
        bundle_hostname: host,
        bundle_port: port,
        account: e.account.clone(),
        marker: e.marker.clone(),
        ca_public_key: e.ca_public_key.clone(),
        line_sha256: e.line_sha256.clone(),
        registry: e.registry.clone(),
        form: e.form,
    })
}

async fn remove_foreign<P: Prompter>(
    ctx: &Ctx,
    p: &mut P,
    file: &Path,
    marker: &str,
    alias: &str,
) -> Outcome {
    // Local checks first: nothing reaches the runtime for a bundle that cannot serve.
    let bundle = match read_bundle(file) {
        Ok(b) => b,
        Err(o) => return o,
    };
    let target = match foreign_target(&bundle, marker, alias) {
        Ok(t) => t,
        Err(o) => return o,
    };
    let request_id = match setup_cmd::request_id(None) {
        Ok(r) => r,
        Err(o) => return o,
    };
    let form = target.form;
    let what = format!(
        "the foreign enrollment {} ({}@{}:{}) through {}",
        target.marker,
        target.account,
        target.bundle_hostname,
        target.bundle_port,
        target.local_alias
    );
    let mut s = match session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    remove_flow(
        &mut s,
        p,
        ctx,
        RemovalTarget::Foreign(target),
        request_id,
        Some(form),
        None,
        &what,
    )
    .await
}

// --- enroll reconcile ----------------------------------------------------------------

async fn reconcile(ctx: &Ctx, operation: &str, after_manual_recovery: bool) -> Outcome {
    let op = match parsed("operation ID", OperationId::parse, operation) {
        Ok(v) => v,
        Err(o) => return o,
    };
    let mut s = match session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    reconcile_flow(&mut s, ctx, op, after_manual_recovery).await
}

/// `enroll reconcile` on a session: the runtime classifies; the loop runs what it asks
/// (a redispatch needs an attended session, which only an interactive terminal gives).
pub(crate) async fn reconcile_flow<S: Session>(
    s: &mut S,
    ctx: &Ctx,
    op: OperationId,
    after_manual_recovery: bool,
) -> Outcome {
    if let Err(refused) = setup_cmd::attend_first(s, ctx).await {
        return Outcome::of(refused);
    }
    if after_manual_recovery {
        show(
            ctx,
            "Manual-recovery reconcile: the registry is read and classified; nothing is redispatched.",
        );
    }
    let env = s
        .request(Request::Enrollment(EnrollmentRequest::Reconcile {
            operation_id: op,
            interaction: ctx.interaction(),
            after_manual_recovery,
        }))
        .await;
    settle(
        s,
        env,
        drive::DriveMode {
            after_manual_recovery,
            json: ctx.json,
            ..drive::DriveMode::default()
        },
    )
    .await
}

// --- enroll abandon ------------------------------------------------------------------

async fn abandon<P: Prompter>(ctx: &Ctx, p: &mut P, enrollment: &str) -> Outcome {
    let id = match parsed("enrollment ID", EnrollmentId::parse, enrollment) {
        Ok(v) => v,
        Err(o) => return o,
    };
    let text = format!(
        "Abandon enrollment {id}. Heimdall stops managing it; its trust may remain on the destination \
         (reported pending_until_line_removed, listed by uninstall and the recovery bundle).\nAbandon it?\n"
    );
    if let Err(o) = typed_confirmation(p, ctx, &text).await {
        return o;
    }
    let mut s = match session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let env = s
        .request(Request::Enrollment(EnrollmentRequest::Abandon {
            enrollment_id: id,
        }))
        .await;
    settle(
        &mut s,
        env,
        drive::DriveMode {
            json: ctx.json,
            ..drive::DriveMode::default()
        },
    )
    .await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn bundle(redacted: bool, host: Option<&str>) -> RecoveryBundle {
        serde_json::from_value(serde_json::json!({
            "schema": RECOVERY_BUNDLE_SCHEMA,
            "created_at": "2026-11-01T00:00:00Z",
            "redacted": redacted,
            "cas": [],
            "enrollments": [{
                "marker": "heimdall:enr_00112233445566778899aabbccddeeff",
                "destination_id": "dst_lab",
                "alias": "lab",
                "hostname": host,
                "port": host.map(|_| 22),
                "account": "deploy",
                "registry": {"resolved_by": "remote_home"},
                "registry_path_display": "$HOME/.ssh/authorized_keys",
                "form": "account",
                "state": "verified",
                "ca_fingerprint": format!("SHA256:{}", "A".repeat(43)),
                "ca_public_key": "ssh-ed25519 AAAA",
                "line_sha256": "ab".repeat(32),
            }],
            "instructions": [],
        }))
        .unwrap()
    }

    #[test]
    fn a_redacted_bundle_is_refused_bundle_redacted() {
        let m = "heimdall:enr_00112233445566778899aabbccddeeff";
        for b in [
            bundle(true, None),
            bundle(false, None),
            bundle(true, Some("h.example.invalid")),
        ] {
            let o = foreign_target(&b, m, "lab").unwrap_err();
            assert_eq!(o.env.code, Code::CapabilityUnavailable);
            assert_eq!(o.env.data["error"]["reason"], reason::BUNDLE_REDACTED);
        }
        let Ok(t) = foreign_target(&bundle(false, Some("h.example.invalid")), m, "lab") else {
            panic!("an unredacted bundle gives a descriptor");
        };
        assert_eq!(t.bundle_hostname, "h.example.invalid");
        assert_eq!(t.local_alias, "lab");
        assert_eq!(
            foreign_target(&bundle(false, Some("h")), "heimdall:enr_other", "lab")
                .unwrap_err()
                .env
                .code,
            Code::NotFound
        );
    }

    #[test]
    fn the_switches_fail_closed() {
        const {
            assert!(!SCRIPT_PAUSE_POINTS_CONSUMED);
            assert!(REFUSE_UNHELD_INTERACTIVE_IDENTITY);
            assert!(!heimdall_enroll::remote::INTERACTIVE_FOREGROUND_HANDOFF);
        }
    }
}
