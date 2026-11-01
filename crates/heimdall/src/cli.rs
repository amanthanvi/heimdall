//! Command surface (spec §11.1; names are v0.1 proposals, semantics normative).
//!
//! M01 wires `access ensure|release|revoke|delegate|pause|resume|cutoff`,
//! `operation show|wait|cancel|events`, `decision list|approve|deny`,
//! `time confirm`, `service run|status|stop`, `inspect`, `status` and
//! `schema export|show`. `setup`, `connect`, `run`, `doctor` and `tui` are
//! declared so help is complete and answer `USAGE_ERROR` until their milestone.
//!
//! Every command except `service run` and `schema` is a client of the runtime's
//! control endpoint (overview §3); nothing here authorizes access. Effectful
//! commands start the runtime on demand; read-only ones never do (spec §13.1).
//!
//! **Output.** `--json`: one envelope on stdout (NDJSON for `operation events
//! --follow`); otherwise a short human summary on stdout and messages on stderr.
//! **Exit codes** follow ADR-0006 §6 through [`crate::output::exit_code_for`]:
//! `ACCEPTED` exits 0 only with `--async`; an unknown code exits 1.
//!
//! **Interactive flow** (ADR-0006 §3.1 ⟨r2.1⟩ N04). When stdin is a terminal and
//! `--non-interactive` is absent, the hello declares `interactive`. A result
//! carrying `next.decision_ref` (added authority, `resume`, `cutoff --clear`, a
//! later cutoff) and `decision approve|deny` lead to the owner prompt: the CLI
//! fetches and shows the exact recorded request, requires a typed `y`/`yes`
//! (default No), and only then sends `Attend` followed by `Decide` on that same
//! session. Anything else sends nothing and exits 3 `INTERACTION_REQUIRED` with
//! `next.decision_ref` ("not confirmed"). `time confirm` works the same way with
//! the clock reading it shows. The runtime cannot verify that a client prompted:
//! a same-user program can imitate this flow (disclosed limit, spec §14.2).

use std::ffi::OsString;
use std::io::IsTerminal as _;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use heimdall_contract::envelope::{Envelope, NextAction};
use heimdall_contract::event::{Cursor, EventFilter, EventType};
use heimdall_contract::ids::{
    AccountName, BindingId, DecisionId, DestinationId, EnvironmentId, GrantId, OperationId,
    PolicyId, ProfileId, RequestId, WorkId,
};
use heimdall_contract::request::{
    AccessPairRef, CancelRequest, ConfirmTimeRequest, DeadlineIntent, DecideRequest,
    DelegateRequest, EnsureRequest, InspectRequest, InspectSubject, ObserveRequest, PolicyAction,
    ReleaseRequest, Request, RequiredCapabilities, RevokeRequest, Verdict, WaitMode,
};
use heimdall_contract::{Code, ExitCode, OperationState, Timestamp};
use heimdall_ipc::session::{SubscribeOutcome, transport_failure_envelope};

use crate::client::{Client, Ctx, connect, error};
use crate::output::{self, error_value};
use crate::prompt::{self, Answer};
use crate::service_cmd;

/// Heimdall: set up access once; your terminals, tools, and agents work across
/// environments.
#[derive(Debug, Parser)]
#[command(name = "heimdall", version, disable_colored_help = true)]
pub struct Cli {
    /// Machine output: one JSON envelope on stdout (NDJSON for event streams).
    #[arg(long, global = true)]
    pub json: bool,
    /// Never open a browser, dialog, or terminal prompt (spec §11.3). Owner
    /// decisions then exit 3 with `next.decision_ref` and nothing is sent.
    #[arg(long, global = true)]
    pub non_interactive: bool,
    /// Override the Heimdall home directory (fixtures and tests).
    #[arg(long, global = true, env = "HEIMDALL_HOME", value_name = "DIR")]
    pub home: Option<PathBuf>,
    /// Subcommand; with none, the runtime status.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Adopt supported local access (M02).
    Setup,
    /// Convenience connect; ordinary ssh also works (M02).
    Connect {
        /// Destination alias.
        destination: String,
    },
    /// Ensure access then launch argv without a shell (spec §10.4) (M02).
    Run(RunArgs),
    /// Summary of the runtime, open work, and pending owner decisions. Never
    /// starts the runtime.
    Status,
    /// Passive diagnostics by default (spec §10.2) (M02).
    Doctor {
        /// Explicit probe level; never default.
        #[arg(long, value_name = "LEVEL")]
        active_probe: Option<String>,
    },
    /// Terminal UI (M02).
    Tui,
    /// Read-only inspection of runtime state. Never starts the runtime.
    Inspect {
        /// Subject: capabilities|environments|profiles|destinations|bindings|grants|operations|decisions.
        subject: String,
        /// Dry-run authority preview for this profile: the resolved snapshot and
        /// the outcome (`allowed`, `approval_required` with the exact delta, or
        /// `denied`) without any effect, record or prompt.
        #[arg(long, value_name = "PROFILE")]
        preview: Option<String>,
        /// Preview: environment (default the caller's).
        #[arg(long, requires = "preview")]
        environment: Option<String>,
        /// Preview: absolute RFC 3339 deadline with offset.
        #[arg(long, requires = "preview", conflicts_with = "for_duration")]
        until: Option<String>,
        /// Preview: duration deadline (`2h`, `PT2H`).
        #[arg(long = "for", requires = "preview", conflicts_with = "until")]
        for_duration: Option<String>,
        /// Preview: caller minimums.
        #[command(flatten)]
        require: RequireArgs,
    },
    /// Access primitives.
    #[command(subcommand)]
    Access(AccessCommand),
    /// Operation observation and control.
    #[command(subcommand)]
    Operation(OperationCommand),
    /// Pending owner decisions. Approving or denying needs a terminal and a typed
    /// `yes`; the runtime cannot verify that this client prompted (a same-user
    /// program can imitate the owner flow).
    #[command(subcommand)]
    Decision(DecisionCommand),
    /// Owner time confirmation.
    #[command(subcommand)]
    Time(TimeCommand),
    /// Per-user runtime control.
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Public schemas and code table (R-AP-08).
    #[command(subcommand)]
    Schema(SchemaCommand),
}

/// `run` arguments.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Profile to ensure.
    #[arg(long)]
    pub profile: Option<String>,
    /// Work ID.
    #[arg(long)]
    pub work_id: Option<String>,
    /// Argument vector after `--`, passed byte-exact.
    #[arg(last = true, required = true, value_name = "ARGV")]
    pub argv: Vec<OsString>,
}

/// `access` subcommands.
#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// Idempotent access preparation (spec §11.3).
    Ensure(EnsureArgs),
    /// Drop this consumer's reference to a binding.
    Release {
        /// Binding ID.
        binding_id: String,
    },
    /// Revoke a grant and its descendants (spec §6.7).
    Revoke {
        /// Grant ID.
        grant_id: String,
        /// Idempotency request ID (a fresh one is minted and reported when absent).
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Narrower child binding (M05 demo; model in M01).
    Delegate(DelegateArgs),
    /// Pause automatic activation for a policy (owner channel; narrowing).
    Pause {
        /// Policy ID.
        policy_id: String,
    },
    /// Resume automatic activation (widening: needs an owner decision).
    Resume {
        /// Policy ID.
        policy_id: String,
    },
    /// Schedule (or clear) a hard stop for a policy (spec §6.1). An earlier cutoff
    /// applies at once; a later one or `--clear` needs an owner decision.
    Cutoff {
        /// Policy ID.
        policy_id: String,
        /// RFC 3339 instant with explicit offset.
        #[arg(long, required_unless_present = "clear", conflicts_with = "clear")]
        at: Option<String>,
        /// Clear the cutoff deliberately.
        #[arg(long)]
        clear: bool,
    },
}

/// Caller minimums (spec §4.3, §11.3 `required_capabilities`): never satisfied by
/// `unknown`; an unmet minimum is `CAPABILITY_UNAVAILABLE` (exit 4), never a
/// silently weaker mechanism.
#[derive(Debug, Args, Default)]
pub struct RequireArgs {
    /// Required credential capability (repeatable): ssh-authentication,
    /// git-signing, agent-forwarding.
    #[arg(long = "require-capability", value_name = "CAPABILITY")]
    pub capabilities: Vec<String>,
    /// Minimum destination-scope enforcement: unenforced_intent, client_routing,
    /// authenticated_agent_restriction, verified_server_principals,
    /// isolated_execution_boundary.
    #[arg(long = "require-destination-scope", value_name = "LEVEL")]
    pub destination_scope: Option<String>,
    /// Credentials must stay usable offline until this RFC 3339 instant.
    #[arg(long = "require-offline-until", value_name = "INSTANT")]
    pub offline_until: Option<String>,
}

impl RequireArgs {
    fn to_request(&self) -> Result<RequiredCapabilities, Done> {
        let mut out = RequiredCapabilities::default();
        for c in &self.capabilities {
            let cap = serde_json::from_value(serde_json::Value::String(c.clone()))
                .map_err(|_| Done::of(usage("unknown capability")))?;
            out.capabilities.insert(cap);
        }
        if let Some(level) = &self.destination_scope {
            out.destination_scope_at_least = Some(
                serde_json::from_value(serde_json::Value::String(level.clone()))
                    .map_err(|_| Done::of(usage("unknown destination-scope level")))?,
            );
        }
        if let Some(t) = &self.offline_until {
            out.offline_until = Some(t.parse::<Timestamp>().map_err(|_| {
                Done::of(usage("--require-offline-until needs an RFC 3339 instant"))
            })?);
        }
        Ok(out)
    }
}

/// `access ensure` arguments (spec §11.3 example).
#[derive(Debug, Args)]
pub struct EnsureArgs {
    /// Profile.
    #[arg(long)]
    pub profile: String,
    /// `destination:account` pairs (a subset of the profile; default all).
    #[arg(long = "pair", value_name = "DEST:ACCOUNT")]
    pub pairs: Vec<String>,
    /// Environment; default the caller's.
    #[arg(long)]
    pub environment: Option<String>,
    /// Work ID.
    #[arg(long)]
    pub work_id: String,
    /// Absolute RFC 3339 deadline with offset.
    #[arg(long, conflicts_with = "for_duration")]
    pub until: Option<String>,
    /// Duration deadline (`2h`, `PT2H`).
    #[arg(long = "for", conflicts_with = "until")]
    pub for_duration: Option<String>,
    /// Idempotency request ID.
    #[arg(long)]
    pub request_id: String,
    /// Return immediately with the operation to observe (`ACCEPTED`, exit 0).
    #[arg(long = "async")]
    pub r#async: bool,
    /// Bounded synchronous wait in milliseconds (timeout is not cancel; a
    /// still-pending operation exits 5 with `next.observe`).
    #[arg(long, default_value_t = 30_000)]
    pub timeout_ms: u64,
    /// Caller minimums.
    #[command(flatten)]
    pub require: RequireArgs,
}

/// `access delegate` arguments.
#[derive(Debug, Args)]
pub struct DelegateArgs {
    /// Parent binding.
    #[arg(long)]
    pub parent: String,
    /// `destination:account` pairs (subset of the parent).
    #[arg(long = "pair", value_name = "DEST:ACCOUNT")]
    pub pairs: Vec<String>,
    /// Deadline (≤ parent).
    #[arg(long)]
    pub until: Option<String>,
    /// Work ID.
    #[arg(long)]
    pub work_id: String,
    /// Request ID.
    #[arg(long)]
    pub request_id: String,
}

/// `operation` subcommands.
#[derive(Debug, Subcommand)]
pub enum OperationCommand {
    /// Show an operation (read-only).
    Show {
        /// Operation ID.
        operation_id: String,
    },
    /// Wait (bounded) for the operation to stop; the exit code reflects the
    /// operation (5 while still active, 7 for an uncertain outcome, else the
    /// class of its recorded code).
    Wait {
        /// Operation ID.
        operation_id: String,
        /// Timeout in milliseconds.
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
    },
    /// Explicit, idempotent cancellation.
    Cancel {
        /// Operation ID.
        operation_id: String,
    },
    /// Events: a snapshot (no cursor) or the page after `--cursor`; with
    /// `--follow`, a live NDJSON stream (first line: the subscription envelope;
    /// then one event per line, each carrying its resume cursor).
    Events {
        /// Resume cursor.
        #[arg(long)]
        cursor: Option<String>,
        /// Follow live events.
        #[arg(long)]
        follow: bool,
        /// Restrict to one operation.
        #[arg(long)]
        operation: Option<String>,
        /// With `--follow`: stop after this many events.
        #[arg(long, requires = "follow")]
        max_events: Option<u64>,
        /// Without `--follow`: page size (bounded by the runtime).
        #[arg(long, conflicts_with = "follow")]
        limit: Option<u32>,
    },
}

/// `decision` subcommands.
#[derive(Debug, Subcommand)]
pub enum DecisionCommand {
    /// Pending decisions with their exact recorded requests (read-only).
    List,
    /// Approve exactly the recorded request (terminal and typed `yes` required).
    Approve {
        /// Decision reference (`next.decision_ref`).
        decision_id: String,
    },
    /// Deny the recorded request (terminal and typed `yes` required).
    Deny {
        /// Decision reference (`next.decision_ref`).
        decision_id: String,
    },
}

/// `time` subcommands.
#[derive(Debug, Subcommand)]
pub enum TimeCommand {
    /// Confirm this machine's clock for the current boot after `TIME_UNCERTAIN`
    /// (terminal and typed `yes` required). Never moves a deadline. The runtime
    /// cannot verify that this client prompted.
    Confirm,
}

/// `service` subcommands.
#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    /// Run the per-user runtime in the foreground (or detached).
    Run {
        /// Detach from the terminal (used by on-demand start).
        #[arg(long)]
        detach: bool,
    },
    /// Report whether a runtime is serving (exit 5 when none is).
    Status,
    /// Ask the runtime to drain and stop.
    Stop,
}

/// `schema` subcommands.
#[derive(Debug, Subcommand)]
pub enum SchemaCommand {
    /// Write every public schema, and the configuration schema, into directories.
    Export {
        /// Output directory for the public API schemas and the code table (default
        /// `schemas/public-api`).
        #[arg(long, default_value = "schemas/public-api")]
        out: PathBuf,
        /// Output directory for `config.schema.json` (default
        /// `schemas/configuration`).
        #[arg(long, default_value = "schemas/configuration")]
        config_out: PathBuf,
    },
    /// Print one schema or the code table to stdout.
    Show {
        /// Schema name, or `codes`.
        name: String,
    },
}

/// A finished command: the envelope to print and the exit code.
struct Done {
    env: Envelope<serde_json::Value>,
    exit: ExitCode,
}

impl Done {
    fn of(env: Envelope<serde_json::Value>) -> Self {
        let exit = output::exit_code_for(env.code.clone(), false);
        Self { env, exit }
    }
}

fn usage(message: &str) -> Envelope<serde_json::Value> {
    error_value(error(Code::UsageError, message))
}

/// Dispatch a parsed command and return the process exit code.
pub fn dispatch(cli: Cli) -> ExitCode {
    let ctx = Ctx {
        json: cli.json,
        non_interactive: cli.non_interactive,
        home: cli.home,
        stdin_tty: std::io::stdin().is_terminal(),
    };
    let command = match cli.command {
        Some(Command::Schema(SchemaCommand::Show { name })) => return schema_show(&name),
        Some(Command::Schema(SchemaCommand::Export { out, config_out })) => {
            return schema_export(&out, &config_out, ctx.json);
        }
        Some(Command::Service(ServiceCommand::Run { detach })) => {
            return service_cmd::run(&ctx, detach);
        }
        Some(Command::Service(ServiceCommand::Status)) => return service_cmd::status(&ctx),
        Some(Command::Service(ServiceCommand::Stop)) => return service_cmd::stop(&ctx),
        Some(
            Command::Setup
            | Command::Connect { .. }
            | Command::Run(_)
            | Command::Doctor { .. }
            | Command::Tui,
        ) => {
            let env = usage("this command is not available in this build (planned for M02)");
            output::emit(&env, ctx.json);
            return output::exit_code_for(env.code, false);
        }
        None => Command::Status,
        Some(c) => c,
    };
    let rt = match service_cmd::current_thread() {
        Ok(rt) => rt,
        Err(env) => {
            let env = error_value(env);
            output::emit(&env, ctx.json);
            return output::exit_code_for(env.code, false);
        }
    };
    let done = match command {
        // The stream prints as it goes.
        Command::Operation(OperationCommand::Events {
            cursor,
            follow: true,
            operation,
            max_events,
            ..
        }) => return rt.block_on(follow_events(&ctx, cursor, operation, max_events)),
        other => rt.block_on(client_command(&ctx, other)),
    };
    output::emit(&done.env, ctx.json);
    done.exit
}

/// Parse a bounded token into a contract ID, or a usage error naming the flag.
fn parse<T, E>(what: &str, f: impl FnOnce(&str) -> Result<T, E>, s: &str) -> Result<T, Done> {
    f(s).map_err(|_| Done::of(usage(&format!("invalid {what}"))))
}

fn pair(s: &str) -> Result<AccessPairRef, Done> {
    let Some((d, a)) = s.split_once(':') else {
        return Err(Done::of(usage("a pair is DEST:ACCOUNT")));
    };
    Ok(AccessPairRef {
        destination: parse("destination", DestinationId::parse, d)?,
        account: parse("account", AccountName::parse, a)?,
    })
}

fn fresh_request_id() -> Result<RequestId, Done> {
    let a = heimdall_app::ids::random_u64();
    let b = heimdall_app::ids::random_u64();
    match (a, b) {
        (Ok(a), Ok(b)) => parse(
            "request ID",
            RequestId::parse,
            &format!("req-{a:016x}{b:016x}"),
        ),
        _ => Err(Done::of(error_value(error(
            Code::InternalError,
            "randomness unavailable",
        )))),
    }
}

/// The pending decision a result asks for, if any.
fn pending_decision(env: &Envelope<serde_json::Value>) -> Option<String> {
    if !matches!(env.code, Code::InteractionRequired | Code::ApprovalRequired) {
        return None;
    }
    env.next.as_ref().and_then(|n| n.decision_ref.clone())
}

async fn client_command(ctx: &Ctx, command: Command) -> Done {
    match run_client(ctx, command).await {
        Ok(d) | Err(d) => d,
    }
}

async fn session(ctx: &Ctx, allow_start: bool) -> Result<Client, Done> {
    connect(ctx, allow_start)
        .await
        .map_err(|e| Done::of(error_value(*e)))
}

async fn one(ctx: &Ctx, allow_start: bool, request: Request) -> Result<Done, Done> {
    let mut client = session(ctx, allow_start).await?;
    Ok(Done::of(client.request(request).await))
}

async fn run_client(ctx: &Ctx, command: Command) -> Result<Done, Done> {
    match command {
        Command::Status => status(ctx).await,
        Command::Inspect {
            subject,
            preview,
            environment,
            until,
            for_duration,
            require,
        } => {
            let subject: InspectSubject =
                serde_json::from_value(serde_json::Value::String(subject))
                    .map_err(|_| Done::of(usage("unknown inspect subject")))?;
            let preview = match preview {
                None => {
                    if !require.capabilities.is_empty()
                        || require.destination_scope.is_some()
                        || require.offline_until.is_some()
                    {
                        return Err(Done::of(usage("minimums need --preview")));
                    }
                    None
                }
                Some(profile) => Some(heimdall_contract::request::EnsurePreview {
                    profile: parse("profile", ProfileId::parse, &profile)?,
                    environment: environment
                        .as_deref()
                        .map(|e| parse("environment", EnvironmentId::parse, e))
                        .transpose()?,
                    until: match (until, for_duration) {
                        (Some(u), _) => Some(DeadlineIntent::Absolute(u)),
                        (None, Some(d)) => Some(DeadlineIntent::Duration(d)),
                        (None, None) => None,
                    },
                    required_capabilities: require.to_request()?,
                }),
            };
            one(
                ctx,
                false,
                Request::Inspect(InspectRequest { subject, preview }),
            )
            .await
        }
        Command::Access(a) => access(ctx, a).await,
        Command::Operation(o) => operation(ctx, o).await,
        Command::Decision(DecisionCommand::List) => {
            one(
                ctx,
                false,
                Request::Inspect(InspectRequest {
                    subject: InspectSubject::Decisions,
                    preview: None,
                }),
            )
            .await
        }
        Command::Decision(DecisionCommand::Approve { decision_id }) => {
            decide_command(ctx, &decision_id, Verdict::Approve).await
        }
        Command::Decision(DecisionCommand::Deny { decision_id }) => {
            decide_command(ctx, &decision_id, Verdict::Deny).await
        }
        Command::Time(TimeCommand::Confirm) => confirm_time(ctx).await,
        // Handled before the executor starts.
        _ => Err(Done::of(usage("unsupported command"))),
    }
}

async fn status(ctx: &Ctx) -> Result<Done, Done> {
    let mut client = session(ctx, false).await?;
    let inspect = |subject| {
        Request::Inspect(InspectRequest {
            subject,
            preview: None,
        })
    };
    let ops = client.request(inspect(InspectSubject::Operations)).await;
    if !ops.code.is_success() {
        return Ok(Done::of(ops));
    }
    let decisions = client.request(inspect(InspectSubject::Decisions)).await;
    if !decisions.code.is_success() {
        return Ok(Done::of(decisions));
    }
    let count =
        |v: &serde_json::Value, k: &str| v.get(k).and_then(|a| a.as_array()).map_or(0, Vec::len);
    let mut env = Envelope::ok(serde_json::json!({
        "running": true,
        "environment_id": client.server().environment_id,
        "operation_counts": ops.data.get("counts").cloned().unwrap_or_default(),
        "open_operations": count(&ops.data, "operations"),
        "pending_decisions": count(&decisions.data, "decisions"),
    }));
    env.warnings = ops.warnings;
    Ok(Done::of(env))
}

async fn access(ctx: &Ctx, command: AccessCommand) -> Result<Done, Done> {
    match command {
        AccessCommand::Ensure(a) => ensure(ctx, a).await,
        AccessCommand::Release { binding_id } => {
            let binding_id = parse("binding ID", BindingId::parse, &binding_id)?;
            one(ctx, true, Request::Release(ReleaseRequest { binding_id })).await
        }
        AccessCommand::Revoke {
            grant_id,
            request_id,
        } => {
            let grant_id = parse("grant ID", GrantId::parse, &grant_id)?;
            let request_id = match request_id {
                Some(r) => parse("request ID", RequestId::parse, &r)?,
                None => fresh_request_id()?,
            };
            one(
                ctx,
                true,
                Request::Revoke(RevokeRequest {
                    grant_id,
                    request_id,
                }),
            )
            .await
        }
        AccessCommand::Delegate(a) => {
            let request = DelegateRequest {
                parent_binding_id: parse("parent binding", BindingId::parse, &a.parent)?,
                scope: a.pairs.iter().map(|p| pair(p)).collect::<Result<_, _>>()?,
                until: a.until.map(DeadlineIntent::Absolute),
                work_id: parse("work ID", WorkId::parse, &a.work_id)?,
                request_id: parse("request ID", RequestId::parse, &a.request_id)?,
                required_capabilities: RequiredCapabilities::default(),
            };
            one(ctx, true, Request::Delegate(request)).await
        }
        AccessCommand::Pause { policy_id } => {
            let policy_id = parse("policy ID", PolicyId::parse, &policy_id)?;
            policy(ctx, PolicyAction::Pause { policy_id }).await
        }
        AccessCommand::Resume { policy_id } => {
            let policy_id = parse("policy ID", PolicyId::parse, &policy_id)?;
            policy(ctx, PolicyAction::Resume { policy_id }).await
        }
        AccessCommand::Cutoff {
            policy_id,
            at,
            clear,
        } => {
            let policy_id = parse("policy ID", PolicyId::parse, &policy_id)?;
            let action = if clear {
                PolicyAction::ClearCutoff { policy_id }
            } else {
                let at = at.unwrap_or_default();
                let at: Timestamp = at.parse().map_err(|_| {
                    Done::of(usage(
                        "--at must be an RFC 3339 instant with an explicit offset",
                    ))
                })?;
                PolicyAction::Cutoff { policy_id, at }
            };
            policy(ctx, action).await
        }
    }
}

async fn ensure(ctx: &Ctx, a: EnsureArgs) -> Result<Done, Done> {
    let until = match (a.until, a.for_duration) {
        (Some(u), _) => Some(DeadlineIntent::Absolute(u)),
        (None, Some(d)) => Some(DeadlineIntent::Duration(d)),
        (None, None) => None,
    };
    let request = EnsureRequest {
        profile: parse("profile", ProfileId::parse, &a.profile)?,
        profile_revision: None,
        scope: a.pairs.iter().map(|p| pair(p)).collect::<Result<_, _>>()?,
        environment: a
            .environment
            .as_deref()
            .map(|e| parse("environment", EnvironmentId::parse, e))
            .transpose()?,
        work_id: parse("work ID", WorkId::parse, &a.work_id)?,
        until,
        required_capabilities: a.require.to_request()?,
        request_id: parse("request ID", RequestId::parse, &a.request_id)?,
        interaction: ctx.interaction(),
        wait: if a.r#async {
            WaitMode::Async
        } else {
            WaitMode::Sync {
                timeout_ms: a.timeout_ms,
            }
        },
    };
    let is_async = a.r#async;
    let mut client = session(ctx, true).await?;
    let env = client.request(Request::Ensure(request.clone())).await;
    if let Some(decision) = pending_decision(&env)
        && ctx.interactive()
    {
        let decided = confirm_and_decide(
            &mut client,
            ctx,
            &decision,
            Verdict::Approve,
            env.operation_id.clone(),
        )
        .await;
        if decided.code != Code::Ok {
            return Ok(Done::of(decided));
        }
        // Same request ID: the runtime replays the (now approved) operation.
        let again = client.request(Request::Ensure(request)).await;
        let exit = output::exit_code_for(again.code.clone(), is_async);
        return Ok(Done { env: again, exit });
    }
    let exit = output::exit_code_for(env.code.clone(), is_async);
    Ok(Done { env, exit })
}

async fn policy(ctx: &Ctx, action: PolicyAction) -> Result<Done, Done> {
    let mut client = session(ctx, true).await?;
    let env = client.request(Request::Policy(action)).await;
    if let Some(decision) = pending_decision(&env)
        && ctx.interactive()
    {
        return Ok(Done::of(
            confirm_and_decide(&mut client, ctx, &decision, Verdict::Approve, None).await,
        ));
    }
    Ok(Done::of(env))
}

async fn operation(ctx: &Ctx, command: OperationCommand) -> Result<Done, Done> {
    match command {
        OperationCommand::Show { operation_id } => {
            let operation_id = parse("operation ID", OperationId::parse, &operation_id)?;
            one(
                ctx,
                false,
                Request::Observe(ObserveRequest::Operation {
                    operation_id,
                    wait_ms: None,
                }),
            )
            .await
        }
        OperationCommand::Wait {
            operation_id,
            timeout_ms,
        } => {
            let operation_id = parse("operation ID", OperationId::parse, &operation_id)?;
            let Done { env, .. } = one(
                ctx,
                false,
                Request::Observe(ObserveRequest::Operation {
                    operation_id,
                    wait_ms: Some(timeout_ms),
                }),
            )
            .await?;
            let op_code = env
                .data
                .get("code")
                .and_then(|c| serde_json::from_value::<Code>(c.clone()).ok());
            let exit = output::exit_code_after_wait(env.code.clone(), env.state, op_code);
            Ok(Done { env, exit })
        }
        OperationCommand::Cancel { operation_id } => {
            let operation_id = parse("operation ID", OperationId::parse, &operation_id)?;
            one(ctx, true, Request::Cancel(CancelRequest { operation_id })).await
        }
        OperationCommand::Events {
            cursor,
            operation,
            limit,
            ..
        } => {
            let filter = EventFilter {
                operation_id: operation
                    .as_deref()
                    .map(|o| parse("operation ID", OperationId::parse, o))
                    .transpose()?,
                types: Vec::new(),
            };
            one(
                ctx,
                false,
                Request::Observe(ObserveRequest::Events {
                    cursor: cursor.map(Cursor),
                    filter,
                    limit,
                }),
            )
            .await
        }
    }
}

/// "Not confirmed": nothing was sent, the decision stays pending (exit 3).
fn not_confirmed(
    decision: Option<&str>,
    operation: Option<OperationId>,
    reason: &str,
) -> Envelope<serde_json::Value> {
    let mut e = heimdall_app::OpError::new(
        Code::InteractionRequired,
        format!(
            "not confirmed ({reason}): nothing was sent; a pending decision stays pending until it expires"
        ),
    );
    if let Some(d) = decision {
        e = e
            .with_decision(d.to_owned())
            .with_resource("decision", Some(d.to_owned()));
    }
    if let Some(op) = operation {
        e = e.with_operation(op);
    }
    error_value(e.into_envelope())
}

/// Show the exact recorded request of `decision`, ask for a typed `yes`, and
/// only then send `Attend` + `Decide` on this session (ADR-0006 §3.1 N04).
async fn confirm_and_decide(
    client: &mut Client,
    ctx: &Ctx,
    decision: &str,
    verdict: Verdict,
    operation: Option<OperationId>,
) -> Envelope<serde_json::Value> {
    if !ctx.interactive() {
        let reason = if ctx.non_interactive {
            "--non-interactive"
        } else {
            "stdin is not a terminal"
        };
        return not_confirmed(Some(decision), operation, reason);
    }
    let Ok(decision_id) = DecisionId::parse(decision) else {
        return usage("invalid decision reference");
    };
    let listing = client
        .request(Request::Inspect(InspectRequest {
            subject: InspectSubject::Decisions,
            preview: None,
        }))
        .await;
    if !listing.code.is_success() {
        return listing;
    }
    let record = listing
        .data
        .get("decisions")
        .and_then(|d| d.as_array())
        .and_then(|list| {
            list.iter()
                .find(|d| d.get("decision_id").and_then(|v| v.as_str()) == Some(decision))
                .cloned()
        });
    let verb = match verdict {
        Verdict::Approve => "Approve",
        Verdict::Deny => "Deny",
    };
    let text = match &record {
        Some(r) => {
            let request =
                serde_json::to_string_pretty(r.get("request").unwrap_or(&serde_json::Value::Null))
                    .unwrap_or_default();
            let field = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("?").to_owned();
            let expired = r.get("expired").and_then(serde_json::Value::as_bool) == Some(true);
            format!(
                "Owner decision {decision}\n  kind: {}\n  expires: {}{}\n  recorded request (exactly what {} applies to):\n{}\n\
                 Heimdall cannot verify that this prompt was shown: a program running as your user could imitate it.\n\
                 {verb} exactly this request?\n",
                field("kind"),
                field("expires_at"),
                if expired {
                    " (expired: the runtime will refuse it)"
                } else {
                    ""
                },
                verb.to_ascii_lowercase(),
                indent(&request),
            )
        }
        None => format!(
            "Owner decision {decision} is not pending in this runtime (completed, expired and replaced, or unknown).\n\
             There is no recorded request to show; the runtime will refuse to {}.\n\
             {verb} it anyway?\n",
            verb.to_ascii_lowercase()
        ),
    };
    let answer = prompt::ask(&text).await;
    if answer != Answer::Yes {
        return not_confirmed(Some(decision), operation, answer.reason());
    }
    let attended = client.attend().await;
    if !attended.code.is_success() {
        return attended;
    }
    client
        .request(Request::Decide(DecideRequest {
            decision_id,
            verdict,
        }))
        .await
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|l| format!("    {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

async fn decide_command(ctx: &Ctx, decision: &str, verdict: Verdict) -> Result<Done, Done> {
    if DecisionId::parse(decision).is_err() {
        return Err(Done::of(usage("invalid decision reference")));
    }
    if !ctx.interactive() {
        // Nothing is sent, not even a connection is made.
        return Ok(Done::of(not_confirmed(
            Some(decision),
            None,
            if ctx.non_interactive {
                "--non-interactive"
            } else {
                "stdin is not a terminal"
            },
        )));
    }
    let mut client = session(ctx, true).await?;
    Ok(Done::of(
        confirm_and_decide(&mut client, ctx, decision, verdict, None).await,
    ))
}

async fn confirm_time(ctx: &Ctx) -> Result<Done, Done> {
    if !ctx.interactive() {
        let reason = if ctx.non_interactive {
            "--non-interactive"
        } else {
            "stdin is not a terminal"
        };
        return Ok(Done::of(not_confirmed(None, None, reason)));
    }
    let mut client = session(ctx, true).await?;
    // Same host, same clock: this is the wall time the runtime observes. The
    // runtime still checks agreement with its own reading within tolerance.
    let observed_wall = Timestamp::now();
    let text = format!(
        "This machine's clock reads {observed_wall} (UTC); the runtime reads the same clock.\n\
         Confirming vouches that this is the correct current time for this boot. It never moves a deadline or extends access.\n\
         Heimdall cannot verify that this prompt was shown: a program running as your user could imitate it.\n\
         Confirm this time?\n"
    );
    let answer = prompt::ask(&text).await;
    if answer != Answer::Yes {
        return Ok(Done::of(not_confirmed(None, None, answer.reason())));
    }
    let attended = client.attend().await;
    if !attended.code.is_success() {
        return Ok(Done::of(attended));
    }
    Ok(Done::of(
        client
            .request(Request::ConfirmTime(ConfirmTimeRequest { observed_wall }))
            .await,
    ))
}

/// `operation events --follow`: the subscription envelope, then one event per
/// line until `--max-events`, Ctrl-C (exit 0), the runtime going away (exit 5,
/// `SERVICE_UNAVAILABLE`) or a subscription-ending resync (exit 6).
async fn follow_events(
    ctx: &Ctx,
    cursor: Option<String>,
    operation: Option<String>,
    max_events: Option<u64>,
) -> ExitCode {
    let fail = |env: Envelope<serde_json::Value>| {
        output::emit(&env, ctx.json);
        output::exit_code_for(env.code, false)
    };
    let operation_id = match operation.as_deref().map(OperationId::parse).transpose() {
        Ok(o) => o,
        Err(_) => return fail(usage("invalid operation ID")),
    };
    let mut client = match connect(ctx, false).await {
        Ok(c) => c,
        Err(e) => return fail(error_value(*e)),
    };
    let filter = EventFilter {
        operation_id,
        types: Vec::new(),
    };
    let start = match client.raw().subscribe(filter, cursor.map(Cursor)).await {
        Ok(s) => s,
        Err(e) => return fail(error_value(transport_failure_envelope(&e, false))),
    };
    let (subscription, boundary, snapshot) = match start {
        SubscribeOutcome::Refused(env) => return fail(*env),
        SubscribeOutcome::Subscribed {
            subscription,
            cursor,
            snapshot,
        } => (subscription, cursor, snapshot),
    };
    let mut head = Envelope::ok(serde_json::json!({
        "subscription": subscription,
        "cursor": boundary,
        "snapshot": snapshot,
    }));
    head.state = OperationState::Running;
    head.next = Some(NextAction {
        action: "observe".to_owned(),
        cursor: Some(boundary.clone()),
        ..NextAction::default()
    });
    output::emit(&head, ctx.json);
    let mut printed: u64 = 0;
    loop {
        if max_events.is_some_and(|m| printed >= m) {
            return ExitCode::Success;
        }
        let next = tokio::select! {
            r = client.raw().next_event() => r,
            _ = tokio::signal::ctrl_c() => return ExitCode::Success,
        };
        let event = match next {
            Ok((_, event)) => event,
            Err(e) => return fail(error_value(transport_failure_envelope(&e, false))),
        };
        let value = serde_json::to_value(&event).unwrap_or_default();
        let kind = value.get("type").and_then(|t| t.as_str()).unwrap_or("?");
        let human = format!(
            "{} {} {} cursor={}",
            event.timestamp,
            kind,
            event
                .operation_id
                .as_ref()
                .map_or_else(String::new, |o| format!("operation={o}")),
            event.cursor.0
        );
        output::emit_line(&value, &human, ctx.json);
        printed += 1;
        if event.event_type == EventType::ResyncRequired
            && event.payload.get("subscription_ended") == Some(&serde_json::Value::Bool(true))
        {
            return Code::ResyncRequired.exit_code();
        }
    }
}

fn schema_show(name: &str) -> ExitCode {
    let doc = if name == "codes" {
        Some(heimdall_contract::schema::code_table())
    } else {
        heimdall_contract::schema::public_schemas()
            .into_iter()
            .find(|s| s.name == name)
            .and_then(|s| serde_json::to_value(&s.schema).ok())
    };
    match doc {
        Some(v) => {
            let env = heimdall_contract::Envelope::ok(v);
            output::emit(&env, true);
            ExitCode::Success
        }
        None => {
            let env = heimdall_app::OpError::new(Code::NotFound, "unknown schema name")
                .with_resource("schema", Some(name.to_owned()))
                .into_envelope();
            output::emit(&env, true);
            output::exit_code_for(env.code, false)
        }
    }
}

fn schema_export(out: &std::path::Path, config_out: &std::path::Path, json: bool) -> ExitCode {
    let result = (|| -> std::io::Result<Vec<String>> {
        std::fs::create_dir_all(out)?;
        std::fs::create_dir_all(config_out)?;
        let mut written = Vec::new();
        for s in heimdall_contract::schema::public_schemas() {
            let path = out.join(format!("{}.schema.json", s.name));
            let mut text =
                serde_json::to_string_pretty(&s.schema).map_err(std::io::Error::other)?;
            text.push('\n');
            std::fs::write(&path, text)?;
            written.push(path.display().to_string());
        }
        let codes = out.join("codes.json");
        let mut text = serde_json::to_string_pretty(&heimdall_contract::schema::code_table())
            .map_err(std::io::Error::other)?;
        text.push('\n');
        std::fs::write(&codes, text)?;
        written.push(codes.display().to_string());
        // The configuration schema (gap G18), same rendering.
        let config = config_out.join("config.schema.json");
        let text =
            heimdall_runtime::config::Config::json_schema_text().map_err(std::io::Error::other)?;
        std::fs::write(&config, text)?;
        written.push(config.display().to_string());
        Ok(written)
    })();
    match result {
        Ok(written) => {
            let env = heimdall_contract::Envelope::ok(serde_json::json!({ "written": written }));
            output::emit(&env, json);
            ExitCode::Success
        }
        Err(e) => {
            let env = heimdall_app::OpError::new(
                Code::InternalError,
                format!("schema export failed: {}", e.kind()),
            )
            .into_envelope();
            output::emit(&env, json);
            output::exit_code_for(env.code, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn command_tree_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn pending_decision_needs_an_interaction_code_and_a_reference() {
        let mut env: Envelope<serde_json::Value> = Envelope::ok(serde_json::Value::Null);
        env.code = Code::InteractionRequired;
        assert_eq!(pending_decision(&env), None);
        env.next = Some(NextAction {
            action: "interact".into(),
            decision_ref: Some("dec_x".into()),
            ..NextAction::default()
        });
        assert_eq!(pending_decision(&env).as_deref(), Some("dec_x"));
        env.code = Code::ApprovalRequired;
        assert_eq!(pending_decision(&env).as_deref(), Some("dec_x"));
        env.code = Code::PolicyPaused;
        assert_eq!(pending_decision(&env), None);
    }

    #[test]
    fn not_confirmed_is_interaction_required_with_the_decision_ref() {
        let env = not_confirmed(Some("dec_abc"), None, "end of input");
        assert_eq!(env.code, Code::InteractionRequired);
        assert_eq!(
            output::exit_code_for(env.code.clone(), false),
            ExitCode::InteractionRequired
        );
        assert_eq!(
            env.next.as_ref().and_then(|n| n.decision_ref.as_deref()),
            Some("dec_abc")
        );
        assert_eq!(env.state, OperationState::AwaitingApproval);
        let msg = env.data["error"]["message"].as_str().unwrap_or_default();
        assert!(msg.starts_with("not confirmed"));
    }

    #[test]
    fn interactive_needs_a_terminal_and_no_opt_out() {
        let ctx = |tty, ni| Ctx {
            json: false,
            non_interactive: ni,
            home: None,
            stdin_tty: tty,
        };
        assert!(ctx(true, false).interactive());
        assert!(!ctx(true, true).interactive());
        assert!(!ctx(false, false).interactive());
        assert_eq!(
            ctx(false, false).interaction(),
            heimdall_contract::request::InteractionMode::NonInteractive
        );
    }
}
