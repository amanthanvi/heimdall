//! Command surface (spec §11.1; names are v0.1 proposals, semantics normative).
//!
//! M01 wires `access ensure|release|revoke|delegate|pause|resume|cutoff`,
//! `operation show|wait|cancel|events`, `decision list|approve|deny`,
//! `time confirm`, `service run|status|stop`, `inspect`, `status` and
//! `schema export|show`.
//!
//! **M02 commands (m02-plan U0, U8, U9, U10).** `setup`, `connect`, `run`,
//! `doctor`, `tui`, `destination`, `identity`, `profile` and `uninstall` carry
//! their full M02 argument trees, each handled in its own file (`setup_cmd`,
//! `connect_cmd`, `run_cmd`, `doctor_cmd`, `tui`, `catalog_cmd`, `uninstall_cmd`).
//! Until the unit that owns a handler lands, the handler answers M01's "not
//! available in this build" envelope ([`not_available`]: `USAGE_ERROR`, exit 2,
//! effect `none`) without building an async runtime, reading the store or
//! contacting the runtime (§5 item 4, fail-closed landing).
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
//! **Interactive flow** (ADR-0006 §3.1 ⟨r2.1⟩ N04, §13.6 item 7). When stdin is a
//! terminal and `--non-interactive` is absent, the hello declares `interactive`
//! and, before an owner-present action (`access ensure`, `access resume`,
//! `access cutoff`, `decision approve|deny`, `time confirm`), the CLI sends
//! `Attend` **first**, so a request that needs an owner decision is answered
//! `APPROVAL_REQUIRED` with `next.decision_ref`. The CLI then fetches and shows
//! the exact recorded request (and the runtime's answer), requires a typed
//! `y`/`yes` (default No), and only then sends `Decide` on that same session.
//! Anything else (an explicit no, end of input, Ctrl-C, the prompt timeout) sends
//! nothing more and exits 3 `INTERACTION_REQUIRED` with `next.decision_ref` ("not
//! confirmed"). `time confirm` works the same way with the clock reading it
//! shows. `--non-interactive` or a non-TTY stdin never prompts and never attends.
//! Attendance authorizes nothing by itself. The runtime cannot verify that a
//! client prompted: a same-user program can imitate this flow (disclosed limit,
//! spec §14.2).

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
use crate::{
    catalog_cmd, connect_cmd, doctor_cmd, run_cmd, service_cmd, setup_cmd, tui, uninstall_cmd,
};

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
    /// Adopt supported local access: preview, apply, roll back or repair the
    /// managed OpenSSH projection (M02; ADR-0007 §5). Without an action, `apply`.
    Setup(SetupArgs),
    /// Convenience connect through the verified client; ordinary ssh also works
    /// (M02; ADR-0007 §8).
    Connect(ConnectArgs),
    /// Ensure access then launch argv without a shell (spec §10.4) (M02).
    Run(RunArgs),
    /// Summary of the runtime, open work, and pending owner decisions. Never
    /// starts the runtime.
    Status,
    /// Passive diagnostics by default (spec §10.2); explicit probes only by named
    /// level (M02; ADR-0007 §6). Never starts the runtime.
    Doctor(DoctorArgs),
    /// Terminal UI (M02).
    Tui,
    /// Destination catalog: managed and observed aliases (M02).
    #[command(subcommand)]
    Destination(DestinationCommand),
    /// Adopted identities and their interaction declarations (M02; ADR-0007 §7).
    #[command(subcommand)]
    Identity(IdentityCommand),
    /// Profiles: named sets of destination/account pairs (M02).
    #[command(subcommand)]
    Profile(ProfileCommand),
    /// Remove the projection, restore your files, and report what remains (M02).
    Uninstall(UninstallArgs),
    /// Read-only inspection of runtime state. Never starts the runtime.
    Inspect {
        /// Subject: capabilities|environments|profiles|destinations|bindings|grants|operations|decisions
        /// (M02 adds identities|projections).
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

/// `run` arguments (ADR-0007 §8; m02-plan U8).
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Profile to ensure.
    #[arg(long)]
    pub profile: Option<String>,
    /// Work ID.
    #[arg(long)]
    pub work_id: Option<String>,
    /// Idempotency request ID for the ensure and bind (a fresh one is minted and
    /// reported when absent). A retry with the same ID never relaunches by itself.
    #[arg(long)]
    pub request_id: Option<String>,
    /// Caller minimums.
    #[command(flatten)]
    pub require: RequireArgs,
    /// Launch options.
    #[command(flatten)]
    pub launch: LaunchArgs,
    /// Argument vector after `--`, passed byte-exact. Never sent to the runtime,
    /// journaled or logged.
    #[arg(last = true, required = true, value_name = "ARGV")]
    pub argv: Vec<OsString>,
}

/// Launch options shared by `run` and `connect` (ADR-0007 §7, §8).
#[derive(Debug, Args, Default)]
pub struct LaunchArgs {
    /// Under `--non-interactive`, accept that the provider (not Heimdall) may show
    /// its own approval or unlock dialog; without it, an identity that may need
    /// interaction is refused before launch (exit 3).
    #[arg(long)]
    pub allow_provider_interaction: bool,
    /// Write NDJSON run records to this open descriptor (Unix only; must be a
    /// pipe, socket or regular file; set close-on-exec).
    #[arg(long, value_name = "FD", conflicts_with = "meta_file")]
    pub meta_fd: Option<i32>,
    /// Write NDJSON run records to this new file (created exclusively, owner-only).
    #[arg(long, value_name = "PATH")]
    pub meta_file: Option<PathBuf>,
}

/// `connect` arguments (ADR-0007 §8).
#[derive(Debug, Args)]
pub struct ConnectArgs {
    /// Destination alias (managed or observed).
    pub destination: String,
    /// Launch options.
    #[command(flatten)]
    pub launch: LaunchArgs,
}

/// `setup` arguments (ADR-0007 §5; m02-plan U9).
#[derive(Debug, Args)]
pub struct SetupArgs {
    /// Action; without one, `apply`.
    #[command(subcommand)]
    pub action: Option<SetupCommand>,
}

/// `setup` actions. Every effectful action previews first, shows the exact plan
/// (with the restore column) and submits its plan digest.
#[derive(Debug, Subcommand)]
pub enum SetupCommand {
    /// Show what apply would change. Read-only; runs nothing from your
    /// configuration.
    Preview {
        /// Also plan the global Git include (`core.sshCommand`, ADR-0007 §5.6).
        #[arg(long)]
        include_git: bool,
    },
    /// Preview, confirm, then apply exactly the previewed plan.
    Apply {
        /// Also apply the global Git include.
        #[arg(long)]
        include_git: bool,
        /// Idempotency request ID (a fresh one is minted and reported when absent).
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Remove the projection and restore your files to the consented state.
    Rollback {
        /// Keep the materialized public-key files.
        #[arg(long)]
        keep_key_files: bool,
        /// Idempotency request ID.
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Repair a reported conflict (`repair <conflict> <resolution>`), or a held
    /// operation (`repair --operation <id> retry|keep`).
    Repair(RepairArgs),
    /// Projection state, held operations and kept quarantine entries (read-only).
    Status,
}

/// `setup repair` arguments.
#[derive(Debug, Args)]
pub struct RepairArgs {
    /// The held operation to repair; then the only argument is `retry` or `keep`.
    #[arg(long, value_name = "OPERATION_ID")]
    pub operation: Option<String>,
    /// `<conflict> <resolution>`, or `retry`|`keep` with `--operation`.
    #[arg(required = true, num_args = 1..=2, value_name = "ARG")]
    pub args: Vec<String>,
    /// Idempotency request ID.
    #[arg(long)]
    pub request_id: Option<String>,
}

/// `doctor` arguments (ADR-0007 §6; m02-plan U9).
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Explicit probe levels, comma-separated or repeated: evaluate, agent,
    /// network, host_verification, authentication. Never on by default.
    #[arg(long = "active-probe", value_name = "LEVEL", value_delimiter = ',')]
    pub active_probe: Vec<String>,
    /// Authorize the evaluate, host_verification and authentication levels to run
    /// your configuration's commands with whatever effects they have.
    #[arg(long)]
    pub allow_config_commands: bool,
    /// Restrict the report to these aliases (repeatable).
    #[arg(long = "alias", value_name = "ALIAS")]
    pub aliases: Vec<String>,
    /// Run no local version or Git queries.
    #[arg(long)]
    pub no_local_exec: bool,
    /// Redact paths and host names in the report.
    #[arg(long)]
    pub redact: bool,
}

/// `destination` subcommands (m02-plan U9; §5 item 3).
#[derive(Debug, Subcommand)]
pub enum DestinationCommand {
    /// Add or update a destination.
    Add(DestinationAddArgs),
    /// List destinations (read-only).
    List,
    /// Show one destination (read-only).
    Show {
        /// Destination ID or alias.
        destination: String,
    },
    /// Remove a destination. The projection is marked stale; no file changes.
    Remove {
        /// Destination ID or alias.
        destination: String,
        /// Idempotency request ID.
        #[arg(long)]
        request_id: Option<String>,
    },
}

/// `destination add` arguments.
#[derive(Debug, Args)]
pub struct DestinationAddArgs {
    /// The alias used with ssh.
    pub alias: String,
    /// Managed definition: the host name Heimdall renders.
    #[arg(
        long,
        required_unless_present = "observed",
        conflicts_with = "observed"
    )]
    pub hostname: Option<String>,
    /// Managed definition: port.
    #[arg(long, requires = "hostname")]
    pub port: Option<u16>,
    /// Managed definition: remote account.
    #[arg(long, requires = "hostname")]
    pub account: Option<String>,
    /// Managed definition: adopted identity (`idn_…`).
    #[arg(long, requires = "hostname")]
    pub identity: Option<String>,
    /// Observed: an alias your own configuration already defines.
    #[arg(long)]
    pub observed: bool,
    /// Stable destination ID to update (kept when the alias changes).
    #[arg(long)]
    pub id: Option<String>,
    /// Label.
    #[arg(long)]
    pub label: Option<String>,
    /// Idempotency request ID.
    #[arg(long)]
    pub request_id: Option<String>,
}

/// `identity` subcommands (ADR-0007 §7; m02-plan U9).
#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// List adopted identities with their interaction basis (read-only).
    List,
    /// Adopt an identity by its public key, from a `.pub` file or from an agent
    /// listing (the explicit `agent` probe). Private keys are never read.
    Adopt(IdentityAdoptArgs),
    /// Declare that an identity needs no interaction (an owner decision: terminal
    /// and typed `yes`).
    DeclareInteraction {
        /// Identity ID.
        identity: String,
        /// The declared interaction.
        #[arg(value_parser = ["none"])]
        interaction: String,
        /// Idempotency request ID.
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Withdraw an interaction declaration (narrowing; no decision).
    WithdrawDeclaration {
        /// Identity ID.
        identity: String,
        /// Idempotency request ID.
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Remove an adopted identity.
    Remove {
        /// Identity ID.
        identity: String,
        /// Idempotency request ID.
        #[arg(long)]
        request_id: Option<String>,
    },
}

/// `identity adopt` arguments.
#[derive(Debug, Args)]
pub struct IdentityAdoptArgs {
    /// Choose from an agent listing (asks first on a terminal; needs
    /// `--active-probe agent` under `--non-interactive`).
    #[arg(long, conflicts_with = "pub_file")]
    pub from_agent: bool,
    /// The identity's OpenSSH public-key file.
    #[arg(
        long = "pub",
        value_name = "FILE",
        required_unless_present = "from_agent"
    )]
    pub pub_file: Option<PathBuf>,
    /// Explicit probe level authorizing the agent listing (`agent`).
    #[arg(long = "active-probe", value_name = "LEVEL", requires = "from_agent")]
    pub active_probe: Option<String>,
    /// Label.
    #[arg(long)]
    pub label: Option<String>,
    /// Idempotency request ID.
    #[arg(long)]
    pub request_id: Option<String>,
}

/// `profile` subcommands (m02-plan U9).
#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// Create a profile.
    Create {
        /// Profile ID.
        profile: String,
        /// `destination:account` pairs (repeatable).
        #[arg(long = "pair", value_name = "DEST:ACCOUNT")]
        pairs: Vec<String>,
        /// Label.
        #[arg(long)]
        label: Option<String>,
        /// Idempotency request ID.
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Show a profile (read-only).
    Show {
        /// Profile ID.
        profile: String,
    },
    /// Add pairs to a profile (bumps its revision; existing grants keep theirs).
    Add {
        /// Profile ID.
        profile: String,
        /// `destination:account` pairs (repeatable).
        #[arg(long = "pair", value_name = "DEST:ACCOUNT", required = true)]
        pairs: Vec<String>,
        /// Idempotency request ID.
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Remove pairs from a profile; without `--pair`, remove the profile.
    Remove {
        /// Profile ID.
        profile: String,
        /// `destination:account` pairs (repeatable).
        #[arg(long = "pair", value_name = "DEST:ACCOUNT")]
        pairs: Vec<String>,
        /// Idempotency request ID.
        #[arg(long)]
        request_id: Option<String>,
    },
    /// List profiles (read-only).
    List,
}

/// `uninstall` arguments (Q6; m02-plan U9).
#[derive(Debug, Args)]
pub struct UninstallArgs {
    /// Also delete Heimdall's state store once every rollback completed.
    #[arg(long)]
    pub purge_state: bool,
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
    /// New authentications must need no human interaction until the deadline,
    /// including through desktop and vault lock (M02, §5 item 6). `unknown` never
    /// satisfies it.
    #[arg(long = "require-unattended")]
    pub unattended: bool,
}

impl RequireArgs {
    /// Whether any minimum was given.
    fn any(&self) -> bool {
        !self.capabilities.is_empty()
            || self.destination_scope.is_some()
            || self.offline_until.is_some()
            || self.unattended
    }

    pub(crate) fn to_request(&self) -> Result<RequiredCapabilities, Done> {
        let mut out = RequiredCapabilities {
            unattended: self.unattended,
            ..RequiredCapabilities::default()
        };
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
pub(crate) struct Done {
    pub(crate) env: Envelope<serde_json::Value>,
    pub(crate) exit: ExitCode,
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

/// M01's "not available in this build" text, unchanged (m02-plan §5 item 4).
pub(crate) const NOT_AVAILABLE_MESSAGE: &str =
    "this command is not available in this build (planned for M02)";

/// The envelope a command answers until its unit lands: `USAGE_ERROR`, effect
/// `none`, next `fix_request` (M01's envelope for `setup`, `connect`, `run`,
/// `doctor` and `tui`).
pub(crate) fn not_available_envelope() -> Envelope<serde_json::Value> {
    usage(NOT_AVAILABLE_MESSAGE)
}

/// Print [`not_available_envelope`] and return its exit code (2). Builds no async
/// runtime, opens no store and never contacts the runtime.
pub(crate) fn not_available(ctx: &Ctx) -> ExitCode {
    let env = not_available_envelope();
    output::emit(&env, ctx.json);
    output::exit_code_for(env.code, false)
}

/// Whether the raw argument list requests machine output: an exact `--json`
/// token before the first bare `--` (after `--`, tokens are the launched argv
/// of `heimdall run`, never Heimdall flags). Used only when clap could not parse
/// the line, so that a usage failure still honours `--json` wherever the global
/// flag was placed (review C01).
pub fn json_requested<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    args.into_iter()
        .skip(1)
        .map(|a| a.as_ref().to_owned())
        .take_while(|a| a != "--")
        .any(|a| a == "--json" || a.to_str().is_some_and(|a| a.starts_with("--json=")))
}

/// A fixed, value-free message for a clap failure. The offending token is never
/// echoed into the machine envelope: it may be a secret pasted in the wrong
/// place or carry terminal escapes (spec §11.2, §14.3).
fn usage_message(kind: clap::error::ErrorKind) -> &'static str {
    use clap::error::ErrorKind as K;
    match kind {
        K::UnknownArgument => "unknown argument",
        K::InvalidSubcommand => "unknown command",
        K::MissingRequiredArgument => "missing required argument",
        K::MissingSubcommand | K::DisplayHelpOnMissingArgumentOrSubcommand => "missing subcommand",
        K::InvalidValue | K::ValueValidation | K::InvalidUtf8 | K::NoEquals => {
            "invalid argument value"
        }
        K::ArgumentConflict => "conflicting arguments",
        _ => "invalid arguments",
    }
}

/// Render a command-line parse failure (spec §11.2, §11.6; ADR-0006 §6).
///
/// Help and version are successes: clap's human text on stdout, exit 0, also
/// with `--json`. Every other failure is a usage error, exit 2: with `--json`
/// exactly one `USAGE_ERROR` envelope (effect `none`, `next.action`
/// `fix_request`) on stdout; in both modes clap's diagnostic goes to stderr,
/// sanitized for the terminal.
pub fn parse_failure(err: &clap::Error, json: bool) -> ExitCode {
    if !err.use_stderr() {
        let _ = err.print();
        return ExitCode::Success;
    }
    output::diagnostic(err.render().to_string().trim_end());
    if json {
        output::emit(&usage(usage_message(err.kind())), true);
    }
    ExitCode::Usage
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
        // M02 commands: each handler owns its command and, until its unit lands,
        // answers `not_available` before any runtime contact.
        Some(Command::Setup(args)) => return setup_cmd::run(&ctx, args),
        Some(Command::Connect(args)) => return connect_cmd::run(&ctx, args),
        Some(Command::Run(args)) => return run_cmd::run(&ctx, args),
        Some(Command::Doctor(args)) => return doctor_cmd::run(&ctx, args),
        Some(Command::Tui) => return tui::run(&ctx),
        Some(Command::Destination(c)) => return catalog_cmd::destination(&ctx, c),
        Some(Command::Identity(c)) => return catalog_cmd::identity(&ctx, c),
        Some(Command::Profile(c)) => return catalog_cmd::profile(&ctx, c),
        Some(Command::Uninstall(args)) => return uninstall_cmd::run(&ctx, args),
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

pub(crate) fn fresh_request_id() -> Result<RequestId, Done> {
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
                    if require.any() {
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
    Ok(ensure_flow(&mut client, &mut TerminalPrompt, ctx, request, is_async).await)
}

/// What the owner-present flows need from a control session: [`Client`] in
/// production; the unit tests drive the flows through a recording fake (the test
/// seam for ADR-0006 §13.6 item 7).
pub(crate) trait Session {
    /// Send one request; a transport failure is an error envelope.
    async fn request(&mut self, request: Request) -> Envelope<serde_json::Value>;
    /// Send `Attend` for this session.
    async fn attend(&mut self) -> Envelope<serde_json::Value>;
}

impl Session for Client {
    async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
        Client::request(self, request).await
    }
    async fn attend(&mut self) -> Envelope<serde_json::Value> {
        Client::attend(self).await
    }
}

/// The owner confirmation prompt: the terminal in production, scripted answers in
/// the unit tests.
pub(crate) trait Prompter {
    /// Show `text` and ask for a typed `yes` (default No).
    async fn ask(&mut self, text: &str) -> Answer;
}

/// The terminal prompt ([`prompt::ask`]).
pub(crate) struct TerminalPrompt;

impl Prompter for TerminalPrompt {
    async fn ask(&mut self, text: &str) -> Answer {
        prompt::ask(text).await
    }
}

/// Before an owner-present action on an interactive TTY session, mark the session
/// attended **first** (ADR-0006 §13.6 item 7), so the runtime answers a request
/// that needs an owner decision with `APPROVAL_REQUIRED` and `next.decision_ref`.
/// Attendance authorizes nothing by itself (N04). `--non-interactive` or a
/// non-TTY stdin never attends. `Err` carries the runtime's refusal.
async fn attend_first<S: Session>(s: &mut S, ctx: &Ctx) -> Result<(), Done> {
    if !ctx.interactive() {
        return Ok(());
    }
    let attended = s.attend().await;
    if attended.code.is_success() {
        Ok(())
    } else {
        Err(Done::of(attended))
    }
}

/// `access ensure` on a connected session: `Attend` first when interactive, the
/// request, and on a pending decision the owner prompt, `Decide` on `yes`, then
/// the same request again (same request ID: the runtime replays the approved
/// operation).
pub(crate) async fn ensure_flow<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    request: EnsureRequest,
    is_async: bool,
) -> Done {
    if let Err(refused) = attend_first(s, ctx).await {
        return refused;
    }
    let env = s.request(Request::Ensure(request.clone())).await;
    if let Some(decision) = pending_decision(&env)
        && ctx.interactive()
    {
        let decided = confirm_and_decide(
            s,
            p,
            ctx,
            &decision,
            Verdict::Approve,
            env.operation_id.clone(),
            Some(&env.code),
        )
        .await;
        if decided.code != Code::Ok {
            return Done::of(decided);
        }
        let again = s.request(Request::Ensure(request)).await;
        let exit = output::exit_code_for(again.code.clone(), is_async);
        return Done { env: again, exit };
    }
    let exit = output::exit_code_for(env.code.clone(), is_async);
    Done { env, exit }
}

async fn policy(ctx: &Ctx, action: PolicyAction) -> Result<Done, Done> {
    let mut client = session(ctx, true).await?;
    Ok(policy_flow(&mut client, &mut TerminalPrompt, ctx, action).await)
}

/// A policy action on a connected session. `resume` and `cutoff` (a later or
/// cleared cutoff is widening, §13.6 item 6) are owner-present: `Attend` first
/// when interactive, then the request, the prompt and `Decide` on `yes`. `pause`
/// is narrowing and never attends.
async fn policy_flow<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    action: PolicyAction,
) -> Done {
    let owner_present = !matches!(action, PolicyAction::Pause { .. });
    if owner_present && let Err(refused) = attend_first(s, ctx).await {
        return refused;
    }
    let env = s.request(Request::Policy(action)).await;
    if owner_present
        && let Some(decision) = pending_decision(&env)
        && ctx.interactive()
    {
        return Done::of(
            confirm_and_decide(
                s,
                p,
                ctx,
                &decision,
                Verdict::Approve,
                None,
                Some(&env.code),
            )
            .await,
        );
    }
    Done::of(env)
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

/// Show the exact recorded request of `decision` (and the runtime's answer that
/// referred to it), ask for a typed `yes`, and only then send `Decide` on this
/// session, which the caller already attended (ADR-0006 §3.1 N04, §13.6 item 7).
/// Anything but `yes` sends nothing more: exit 3 `INTERACTION_REQUIRED` "not
/// confirmed" with the reference.
async fn confirm_and_decide<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    decision: &str,
    verdict: Verdict,
    operation: Option<OperationId>,
    answered: Option<&Code>,
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
    let listing = s
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
    let answer_line = answered.map_or_else(String::new, |code| {
        format!("The runtime answered {code} with this decision reference.\n")
    });
    let text = match &record {
        Some(r) => {
            let request =
                serde_json::to_string_pretty(r.get("request").unwrap_or(&serde_json::Value::Null))
                    .unwrap_or_default();
            let field = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("?").to_owned();
            let expired = r.get("expired").and_then(serde_json::Value::as_bool) == Some(true);
            format!(
                "{answer_line}Owner decision {decision}\n  kind: {}\n  expires: {}{}\n  recorded request (exactly what {} applies to):\n{}\n\
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
            "{answer_line}Owner decision {decision} is not pending in this runtime (completed, expired and replaced, or unknown).\n\
             There is no recorded request to show; the runtime will refuse to {}.\n\
             {verb} it anyway?\n",
            verb.to_ascii_lowercase()
        ),
    };
    let answer = p.ask(&text).await;
    if answer != Answer::Yes {
        return not_confirmed(Some(decision), operation, answer.reason());
    }
    s.request(Request::Decide(DecideRequest {
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
        return Ok(decide_without_session(ctx, decision));
    }
    let mut client = session(ctx, true).await?;
    Ok(decide_flow(&mut client, &mut TerminalPrompt, ctx, decision, verdict).await)
}

fn non_interactive_reason(ctx: &Ctx) -> &'static str {
    if ctx.non_interactive {
        "--non-interactive"
    } else {
        "stdin is not a terminal"
    }
}

fn decide_without_session(ctx: &Ctx, decision: &str) -> Done {
    Done::of(not_confirmed(
        Some(decision),
        None,
        non_interactive_reason(ctx),
    ))
}

/// `decision approve|deny` on a connected session: `Attend` first, the listing
/// with the exact recorded request, the prompt, `Decide` on `yes`. Without a
/// terminal (or with `--non-interactive`) nothing is sent.
async fn decide_flow<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    decision: &str,
    verdict: Verdict,
) -> Done {
    if !ctx.interactive() {
        return decide_without_session(ctx, decision);
    }
    if let Err(refused) = attend_first(s, ctx).await {
        return refused;
    }
    Done::of(confirm_and_decide(s, p, ctx, decision, verdict, None, None).await)
}

async fn confirm_time(ctx: &Ctx) -> Result<Done, Done> {
    if !ctx.interactive() {
        return Ok(Done::of(not_confirmed(
            None,
            None,
            non_interactive_reason(ctx),
        )));
    }
    let mut client = session(ctx, true).await?;
    Ok(confirm_time_flow(&mut client, &mut TerminalPrompt, ctx).await)
}

/// `time confirm` on a connected session: `Attend` first, the prompt with this
/// machine's clock reading, `ConfirmTime` on `yes`; otherwise nothing more.
async fn confirm_time_flow<S: Session, P: Prompter>(s: &mut S, p: &mut P, ctx: &Ctx) -> Done {
    if !ctx.interactive() {
        return Done::of(not_confirmed(None, None, non_interactive_reason(ctx)));
    }
    if let Err(refused) = attend_first(s, ctx).await {
        return refused;
    }
    // Same host, same clock: this is the wall time the runtime observes. The
    // runtime still checks agreement with its own reading within tolerance.
    let observed_wall = Timestamp::now();
    let text = format!(
        "This machine's clock reads {observed_wall} (UTC); the runtime reads the same clock.\n\
         Confirming vouches that this is the correct current time for this boot. It never moves a deadline or extends access.\n\
         Heimdall cannot verify that this prompt was shown: a program running as your user could imitate it.\n\
         Confirm this time?\n"
    );
    let answer = p.ask(&text).await;
    if answer != Answer::Yes {
        return Done::of(not_confirmed(None, None, answer.reason()));
    }
    Done::of(
        s.request(Request::ConfirmTime(ConfirmTimeRequest { observed_wall }))
            .await,
    )
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

    /// One command line per M02 command and action of the U0 clap tree (m02-plan
    /// U9 command list, U8 `run`/`connect`, U10 `tui`).
    const M02_COMMAND_LINES: &[&[&str]] = &[
        &["setup"],
        &["setup", "preview"],
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
            "--alias",
            "b",
            "--no-local-exec",
            "--redact",
        ],
        &["tui"],
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

    /// `w0_m02_cli_commands_report_not_available_and_never_panic`, in-process form
    /// (⟨M02⟩ wave 3b: `run` and `connect` are wired by U8 and leave this list; their
    /// argument trees and their refusals before any runtime contact are checked by
    /// `run_and_connect_parse_and_refuse_before_the_runtime`)
    /// (m02-plan U0b, §5 item 4; the binary-level form is hosted by a `heimdall`
    /// package target, wave-0 verify E6). Every M02 command parses, answers M01's
    /// "not available in this build" envelope with exit 2, and never contacts the
    /// runtime: the Heimdall home it names is never created (an on-demand start or
    /// a client connection would create or read it).
    #[test]
    fn w0_m02_commands_answer_not_available_and_never_contact_the_runtime() {
        let scratch = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        for (i, line) in M02_COMMAND_LINES.iter().enumerate() {
            let home = scratch.path().join(format!("home-{i}"));
            let home_arg = home.to_string_lossy().into_owned();
            let argv: Vec<&str> = ["heimdall", "--json", "--non-interactive", "--home"]
                .into_iter()
                .chain(std::iter::once(home_arg.as_str()))
                .chain(line.iter().copied())
                .collect();
            let cli = Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("{line:?} must parse: {:?}", e.kind()));
            assert!(
                matches!(
                    cli.command,
                    Some(
                        Command::Setup(_)
                            | Command::Doctor(_)
                            | Command::Tui
                            | Command::Destination(_)
                            | Command::Identity(_)
                            | Command::Profile(_)
                            | Command::Uninstall(_)
                    )
                ),
                "{line:?} is an M02 command"
            );
            let exit = dispatch(cli);
            assert_eq!(exit, ExitCode::Usage, "{line:?}");
            assert!(
                !home.exists(),
                "{line:?} touched the Heimdall home, so it reached for the runtime"
            );
        }
        assert_eq!(
            std::fs::read_dir(scratch.path()).map(Iterator::count).ok(),
            Some(0),
            "nothing was created anywhere under the scratch directory"
        );
    }

    /// ⟨M02⟩ U8 (wave 3b): `run` and `connect` keep their argument trees, and every
    /// refusal that needs no runtime (an existing `--meta-file`, a descriptor that is
    /// not open, a program that cannot run, a missing `--profile`, an option-like
    /// alias) answers before any runtime contact: the Heimdall home is never created.
    #[test]
    fn run_and_connect_parse_and_refuse_before_the_runtime() {
        let scratch = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let existing = scratch.path().join("existing.ndjson");
        std::fs::write(&existing, b"owner bytes").unwrap_or_else(|e| panic!("write: {e}"));
        let existing = existing.to_string_lossy().into_owned();
        let missing = scratch
            .path()
            .join("no-such-program")
            .to_string_lossy()
            .into_owned();
        let lines: Vec<(Vec<&str>, ExitCode)> = vec![
            (
                vec!["connect", "lab", "--meta-file", &existing],
                ExitCode::Usage,
            ),
            (
                vec![
                    "run",
                    "--meta-file",
                    &existing,
                    "--profile",
                    "p",
                    "--",
                    "tool",
                ],
                ExitCode::Usage,
            ),
            (
                vec!["run", "--meta-fd", "987", "--profile", "p", "--", "tool"],
                ExitCode::Usage,
            ),
            (
                vec!["run", "--profile", "p", "--", &missing],
                ExitCode::LaunchFailed,
            ),
            (vec!["run", "--", "/bin/sh"], ExitCode::Usage),
            (vec!["connect", "--", "-oProxyCommand=x"], ExitCode::Usage),
        ];
        for (i, line) in lines.iter().enumerate() {
            let home = scratch.path().join(format!("home-{i}"));
            let home_arg = home.to_string_lossy().into_owned();
            let mut argv = vec![
                "heimdall",
                "--json",
                "--non-interactive",
                "--home",
                &home_arg,
            ];
            argv.extend(line.0.iter().copied());
            let cli = Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("{:?} must parse: {:?}", line.0, e.kind()));
            assert!(matches!(
                cli.command,
                Some(Command::Run(_) | Command::Connect(_))
            ));
            assert_eq!(dispatch(cli), line.1, "{:?}", line.0);
            assert!(!home.exists(), "{:?} reached for the runtime", line.0);
        }
        assert_eq!(
            std::fs::read(scratch.path().join("existing.ndjson")).ok(),
            Some(b"owner bytes".to_vec()),
            "an existing --meta-file is never written"
        );
    }

    #[test]
    fn not_available_envelope_is_m01s_usage_error_with_no_effect() {
        let env = not_available_envelope();
        assert_eq!(env.code, Code::UsageError);
        let value = serde_json::to_value(&env).unwrap_or_else(|e| panic!("serialize: {e}"));
        let error = &value["data"]["error"];
        assert_eq!(error["code"], "USAGE_ERROR", "{value}");
        assert_eq!(error["effect_status"], "none", "{value}");
        assert_eq!(error["message"], NOT_AVAILABLE_MESSAGE, "{value}");
        assert_eq!(
            output::exit_code_for(env.code.clone(), false),
            ExitCode::Usage
        );
        // The envelope is fixed text: no argument of any command can reach it.
        assert!(!value.to_string().contains("HEIMDALL_CANARY"), "{value}");
    }

    #[test]
    fn m02_argument_trees_refuse_malformed_lines() {
        for line in [
            &["setup", "repair"][..],
            &["setup", "repair", "a", "b", "c"],
            &["setup", "bogus"],
            &["connect"],
            &["connect", "lab", "--meta-fd", "3", "--meta-file", "m"],
            &["run", "--profile", "p"],
            &["destination", "add", "lab"],
            &["destination", "add", "lab", "--observed", "--hostname", "h"],
            &["identity", "adopt"],
            &["identity", "adopt", "--from-agent", "--pub", "k.pub"],
            &[
                "identity",
                "declare-interaction",
                "idn_x",
                "provider_approval",
            ],
            &["profile", "add", "p"],
        ] {
            let argv: Vec<&str> = std::iter::once("heimdall")
                .chain(line.iter().copied())
                .collect();
            let Err(e) = Cli::try_parse_from(&argv) else {
                panic!("{line:?} must not parse");
            };
            assert!(e.use_stderr(), "{line:?} is a usage error, not help");
        }
    }

    #[test]
    fn require_unattended_is_carried_into_the_request_never_dropped() {
        let args = RequireArgs {
            unattended: true,
            ..RequireArgs::default()
        };
        assert!(args.any());
        let Ok(required) = args.to_request() else {
            panic!("--require-unattended alone is a valid minimum");
        };
        assert!(required.unattended, "the minimum is never dropped silently");
        assert!(!RequireArgs::default().any());
        let Ok(none) = RequireArgs::default().to_request() else {
            panic!("no minimum is valid");
        };
        assert!(!none.unattended);
        // Parsed from the command line as well.
        let cli = Cli::try_parse_from([
            "heimdall",
            "access",
            "ensure",
            "--profile",
            "p",
            "--work-id",
            "w",
            "--request-id",
            "r",
            "--require-unattended",
        ])
        .unwrap_or_else(|e| panic!("parse: {:?}", e.kind()));
        let Some(Command::Access(AccessCommand::Ensure(a))) = cli.command else {
            panic!("access ensure");
        };
        assert!(a.require.unattended);
    }

    #[test]
    fn json_is_requested_anywhere_before_the_argv_terminator() {
        let req = |a: &[&str]| json_requested(std::iter::once("heimdall").chain(a.iter().copied()));
        assert!(req(&["--json", "access", "ensure", "--bad"]));
        assert!(req(&["access", "ensure", "--bad", "--json"]));
        assert!(req(&["access", "--json", "ensure"]));
        assert!(req(&["--json=yes", "status"]));
        assert!(!req(&["access", "ensure", "--bad"]));
        assert!(!req(&["run", "--bad", "--", "tool", "--json"]));
        assert!(!req(&["--work-id=--json", "x"]), "a value is not the flag");
        assert!(!req(&["--jsonl"]));
        // The program name is never a flag.
        assert!(!json_requested(["--json"]));
    }

    #[test]
    fn usage_messages_never_echo_the_offending_token() {
        for args in [
            vec!["heimdall", "access", "ensure", "--secret-looking-token"],
            vec!["heimdall", "secret-looking-token"],
            vec![
                "heimdall",
                "operation",
                "wait",
                "x",
                "--timeout-ms",
                "secret-looking-token",
            ],
            vec!["heimdall", "operation", "show"],
            vec!["heimdall", "access"],
        ] {
            let Err(e) = Cli::try_parse_from(&args) else {
                panic!("{args:?} must not parse");
            };
            let message = usage_message(e.kind());
            assert!(!message.contains("secret"), "{args:?}: {message}");
            assert_ne!(message, "invalid arguments", "{args:?}: {:?}", e.kind());
        }
        let Err(help) = Cli::try_parse_from(["heimdall", "--json", "--help"]) else {
            panic!("help is an Err from clap");
        };
        assert!(!help.use_stderr(), "help stays a success");
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

    // ---- ADR-0006 §13.6 item 7: attendance order (test seam) -------------------

    /// A recording control session: every message the flow sends, in order, and a
    /// scripted answer per request kind.
    struct Recorder {
        sent: Vec<String>,
        answers: std::collections::HashMap<&'static str, Vec<Envelope<serde_json::Value>>>,
        attended: bool,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                sent: Vec::new(),
                answers: std::collections::HashMap::new(),
                attended: false,
            }
        }
        fn answer(mut self, kind: &'static str, env: Envelope<serde_json::Value>) -> Self {
            self.answers.entry(kind).or_default().push(env);
            self
        }
    }

    impl Session for Recorder {
        async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
            self.sent.push(request.kind().to_owned());
            let queue = self.answers.entry(request.kind()).or_default();
            if queue.is_empty() {
                Envelope::ok(serde_json::json!({}))
            } else {
                queue.remove(0)
            }
        }
        async fn attend(&mut self) -> Envelope<serde_json::Value> {
            self.sent.push("attend".to_owned());
            self.attended = true;
            Envelope::ok(serde_json::json!({"attended": true}))
        }
    }

    /// Scripted prompt answers; records the texts it was shown.
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

    fn script(answers: &[Answer]) -> Script {
        Script {
            answers: answers.to_vec(),
            shown: Vec::new(),
        }
    }

    const DEC: &str = "dec_00112233445566778899aabbccddeeff";

    /// What the runtime answers on an attended session (N04): a decision record.
    fn approval_required() -> Envelope<serde_json::Value> {
        error_value(
            heimdall_app::OpError::new(Code::ApprovalRequired, "owner approval required")
                .with_decision(DEC.to_owned())
                .into_envelope(),
        )
    }

    fn listing() -> Envelope<serde_json::Value> {
        Envelope::ok(serde_json::json!({"decisions": [{
            "decision_id": DEC,
            "kind": "approve_authority",
            "state": "pending",
            "expires_at": "2026-11-01T00:15:00Z",
            "request": {"added_scope": {"pairs": [{"destination": "h3", "account": "deploy"}]}},
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

    fn ensure_request() -> EnsureRequest {
        EnsureRequest {
            profile: ProfileId::parse("dev").unwrap_or_else(|_| unreachable!()),
            profile_revision: None,
            scope: std::collections::BTreeSet::new(),
            environment: None,
            work_id: WorkId::parse("w").unwrap_or_else(|_| unreachable!()),
            until: None,
            required_capabilities: RequiredCapabilities::default(),
            request_id: RequestId::parse("r").unwrap_or_else(|_| unreachable!()),
            interaction: heimdall_contract::request::InteractionMode::Interactive,
            wait: WaitMode::default(),
        }
    }

    fn block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| unreachable!())
            .block_on(f)
    }

    /// On an interactive TTY the CLI sends `Attend` **before** the request, so the
    /// runtime answers `APPROVAL_REQUIRED` with `next.decision_ref`; the prompt
    /// shows the exact recorded delta and the runtime's answer; `yes` sends
    /// `Decide` and the original request replays.
    #[test]
    fn interactive_ensure_attends_before_the_request_and_decides_only_on_yes() {
        let mut s = Recorder::new()
            .answer("ensure", approval_required())
            .answer("inspect", listing());
        let mut p = script(&[Answer::Yes]);
        let done = block(ensure_flow(&mut s, &mut p, &tty(), ensure_request(), false));
        assert_eq!(s.sent, ["attend", "ensure", "inspect", "decide", "ensure"]);
        assert_eq!(done.env.code, Code::Ok);
        assert_eq!(p.shown.len(), 1);
        assert!(p.shown[0].contains("APPROVAL_REQUIRED"), "{}", p.shown[0]);
        assert!(
            p.shown[0].contains("\"destination\": \"h3\""),
            "{}",
            p.shown[0]
        );
    }

    /// Anything but `y`/`yes` (an explicit no, end of input, Ctrl-C, the prompt
    /// timeout, unreadable input) sends nothing more after the decision listing
    /// and exits 3 `INTERACTION_REQUIRED` "not confirmed" with the reference.
    #[test]
    fn interactive_ensure_sends_nothing_more_unless_confirmed() {
        for answer in [
            Answer::No,
            Answer::Eof,
            Answer::Interrupted,
            Answer::TimedOut,
            Answer::Unreadable,
        ] {
            let mut s = Recorder::new()
                .answer("ensure", approval_required())
                .answer("inspect", listing());
            let mut p = script(&[answer]);
            let done = block(ensure_flow(&mut s, &mut p, &tty(), ensure_request(), false));
            assert_eq!(s.sent, ["attend", "ensure", "inspect"], "{answer:?}");
            assert_eq!(done.env.code, Code::InteractionRequired, "{answer:?}");
            assert_eq!(done.exit, ExitCode::InteractionRequired);
            assert_eq!(
                done.env
                    .next
                    .as_ref()
                    .and_then(|n| n.decision_ref.as_deref()),
                Some(DEC)
            );
            let msg = done.env.data["error"]["message"]
                .as_str()
                .unwrap_or_default();
            assert!(msg.starts_with("not confirmed"), "{msg}");
        }
    }

    /// `--non-interactive` or a non-TTY stdin never attends and never prompts.
    #[test]
    fn non_interactive_or_non_tty_never_attends_or_prompts() {
        let unattended = || {
            error_value(
                heimdall_app::OpError::new(Code::InteractionRequired, "owner approval required")
                    .with_decision(DEC.to_owned())
                    .into_envelope(),
            )
        };
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
            let mut s = Recorder::new().answer("ensure", unattended());
            let mut p = script(&[]);
            let done = block(ensure_flow(&mut s, &mut p, &ctx, ensure_request(), false));
            assert_eq!(s.sent, ["ensure"]);
            assert!(!s.attended);
            assert_eq!(done.exit, ExitCode::InteractionRequired);
            assert!(p.shown.is_empty());
            for action in [
                PolicyAction::Resume {
                    policy_id: PolicyId::parse("pol").unwrap_or_else(|_| unreachable!()),
                },
                PolicyAction::ClearCutoff {
                    policy_id: PolicyId::parse("pol").unwrap_or_else(|_| unreachable!()),
                },
            ] {
                let mut s = Recorder::new().answer("policy", unattended());
                let done = block(policy_flow(&mut s, &mut p, &ctx, action));
                assert_eq!(s.sent, ["policy"]);
                assert_eq!(done.exit, ExitCode::InteractionRequired);
            }
            let mut s = Recorder::new();
            let done = block(decide_flow(&mut s, &mut p, &ctx, DEC, Verdict::Approve));
            assert!(s.sent.is_empty(), "nothing sent: {:?}", s.sent);
            assert_eq!(done.exit, ExitCode::InteractionRequired);
            let mut s = Recorder::new();
            let done = block(confirm_time_flow(&mut s, &mut p, &ctx));
            assert!(s.sent.is_empty());
            assert_eq!(done.exit, ExitCode::InteractionRequired);
            assert!(p.shown.is_empty());
        }
    }

    /// Widening policy actions and decision commands follow the same order:
    /// `Attend`, the request (or the listing), the prompt, then `Decide` on yes.
    /// A narrowing pause never attends.
    #[test]
    fn owner_present_policy_and_decision_flows_attend_first() {
        let pol = || PolicyId::parse("pol").unwrap_or_else(|_| unreachable!());
        for action in [
            PolicyAction::Resume { policy_id: pol() },
            PolicyAction::ClearCutoff { policy_id: pol() },
        ] {
            let mut s = Recorder::new()
                .answer("policy", approval_required())
                .answer("inspect", listing());
            let mut p = script(&[Answer::Yes]);
            let done = block(policy_flow(&mut s, &mut p, &tty(), action.clone()));
            assert_eq!(
                s.sent,
                ["attend", "policy", "inspect", "decide"],
                "{action:?}"
            );
            assert_eq!(done.env.code, Code::Ok);
            let mut s = Recorder::new()
                .answer("policy", approval_required())
                .answer("inspect", listing());
            let mut p = script(&[Answer::No]);
            let done = block(policy_flow(&mut s, &mut p, &tty(), action));
            assert_eq!(s.sent, ["attend", "policy", "inspect"]);
            assert_eq!(done.exit, ExitCode::InteractionRequired);
        }
        let mut s = Recorder::new();
        let mut p = script(&[]);
        let done = block(policy_flow(
            &mut s,
            &mut p,
            &tty(),
            PolicyAction::Pause { policy_id: pol() },
        ));
        assert_eq!(s.sent, ["policy"], "narrowing: no attendance");
        assert_eq!(done.env.code, Code::Ok);
        // decision approve|deny: attend, listing, prompt, decide.
        for verdict in [Verdict::Approve, Verdict::Deny] {
            let mut s = Recorder::new().answer("inspect", listing());
            let mut p = script(&[Answer::Yes]);
            let _ = block(decide_flow(&mut s, &mut p, &tty(), DEC, verdict));
            assert_eq!(s.sent, ["attend", "inspect", "decide"]);
            let mut s = Recorder::new().answer("inspect", listing());
            let mut p = script(&[Answer::Eof]);
            let done = block(decide_flow(&mut s, &mut p, &tty(), DEC, verdict));
            assert_eq!(s.sent, ["attend", "inspect"]);
            assert_eq!(done.exit, ExitCode::InteractionRequired);
        }
        // time confirm: attend, prompt, confirm_time.
        let mut s = Recorder::new();
        let mut p = script(&[Answer::Yes]);
        let _ = block(confirm_time_flow(&mut s, &mut p, &tty()));
        assert_eq!(s.sent, ["attend", "confirm_time"]);
        let mut s = Recorder::new();
        let mut p = script(&[Answer::Interrupted]);
        let done = block(confirm_time_flow(&mut s, &mut p, &tty()));
        assert_eq!(s.sent, ["attend"]);
        assert_eq!(done.exit, ExitCode::InteractionRequired);
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
