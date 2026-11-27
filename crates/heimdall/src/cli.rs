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
//! Every handler is wired (⟨M02⟩ wave 4). M01's "not available in this build"
//! envelope and its helpers are retired (ADR-0007 §12.30 item 4); the two wave-0 tests
//! now assert that no M02 command answers that text.
//!
//! **M03 commands (m03-plan U0, §5 item 24).** `issuer`, `enroll`, `connections`, the
//! hidden `internal`, `destination prefer`, `access lock-behavior|connection-policy`,
//! `access ensure --strict` and the `uninstall` additions carry their full argument
//! trees (⟨wave 5, U12⟩ all are wired). Each is answered by its own handler in
//! `issuer_cmd`, `enroll_cmd`, `connections_cmd`, `uninstall_cmd` or `m03_cmd`; a
//! command refused before runtime contact (an invalid ID, `--non-interactive` where the
//! owner is needed) answers its own usage or interaction error. None answers M01's
//! wave-0 "not available" text (`tests/e2e/cli_m03.rs` guards the sources against it).
//!
//! **⟨M05⟩ M05 commands (m05-plan U9; ADR-0011 §2–§7).** `project`, `activate`, `shell
//! init`, `export`, `import`, `access allow|stop|default-profile`, the `--profile`,
//! `--workspace` and `--all` targets of `access pause|resume|cutoff`, and `run` without
//! `--profile` are answered by `m05_cmd`, `activate_cmd`, `portable_cmd` and `run_m05`.
//! The shell hook (`activate --hook`) never attends, prompts or decides (ADR-0011 §10
//! item 3).
//!
//! **⟨M06⟩ M06 commands (m06-plan U0, U2; ADR-0006 §18; the G08 naming ruling).**
//! `environment` (op `remote_environment`; no `env` alias) and `device` are answered by
//! `m06_cmd` through the controller operations (`heimdall_app::remote_env`); ⟨M06 W3⟩ `route
//! add|remove|prefer` and `transport enable|disable|adopt-roost` are sent to the runtime
//! (`route.*`, `transport.*`), and `transport rotate` rotates K_iroh and announces it to the
//! recorded runners. `route connect` (the `ProxyCommand` helper rendered configuration
//! names) and `transport serve` (the supervised serve child) are hidden and frozen. There is
//! no top-level `roost`.
//!
//! **A bare `heimdall`** (no subcommand) opens the TUI when stdin and stdout are
//! terminals and neither `--json` nor `--non-interactive` is given (overview §3; ADR-0007
//! §12.30 item 5); otherwise it is `status`, which never starts the runtime.
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

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
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
    activate_cmd, catalog_cmd, connect_cmd, connections_cmd, container_cmd, delegate_cmd,
    doctor_cmd, enroll_cmd, issuer_cmd, m03_cmd, m05_cmd, m06_cmd, portable_cmd, run_cmd,
    service_cmd, setup_cmd, tui, uninstall_cmd, wsl_cmd,
};

/// Heimdall: set up access once; your terminals, tools, and agents work across
/// environments.
#[derive(Debug, Parser)]
// `bin_name`: the usage text names `heimdall` on every platform, never the invoked file name
// (`heimdall.exe` on Windows); the help goldens and the owner see the same command.
#[command(
    name = "heimdall",
    bin_name = "heimdall",
    version,
    disable_colored_help = true
)]
pub struct Cli {
    /// Machine output: one JSON envelope on stdout (NDJSON for event streams).
    #[arg(long, global = true)]
    pub json: bool,
    // spec §11.3.
    /// Never open a browser, dialog, or terminal prompt. Owner decisions then exit 3
    /// with `next.decision_ref` and nothing is sent.
    #[arg(long, global = true)]
    pub non_interactive: bool,
    /// Use this Heimdall home directory instead of the default.
    #[arg(long, global = true, env = "HEIMDALL_HOME", value_name = "DIR")]
    pub home: Option<PathBuf>,
    /// Subcommand; with none, the TUI on a terminal, otherwise the runtime status.
    #[command(subcommand)]
    pub command: Option<Command>,
    /// ⟨M08 U2b-2⟩ The `--request-epoch` of whichever command was given (every command that
    /// takes `--request-id` takes it), read by [`parse_args`]; not an argument of its own.
    #[arg(skip)]
    pub request_epoch: Option<heimdall_contract::lifecycle::RestoreEpoch>,
}

/// The arg ID every command's `--request-epoch` has ([`parse_args`] finds it by this ID).
pub(crate) const REQUEST_EPOCH_ARG: &str = "request_epoch";

/// ⟨M08 U2b-2; ADR-0014 §3.6 step 3; U0-Q5⟩ Parse `argv` as [`Cli::try_parse_from`] does,
/// and keep the given command's `--request-epoch` in [`Cli::request_epoch`], whichever
/// command it is: the kept epoch every mutating request of the invocation then carries.
///
/// # Errors
/// clap's refusal, as [`Cli::try_parse_from`].
pub fn parse_args<I, T>(argv: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    use clap::{CommandFactory as _, FromArgMatches as _};
    let mut matches = Cli::command().try_get_matches_from(argv)?;
    let epoch = kept_request_epoch(&matches);
    // As `Cli::try_parse_from` does: a matching error is formatted with the command.
    let mut cli =
        Cli::from_arg_matches_mut(&mut matches).map_err(|e| e.format(&mut Cli::command()))?;
    cli.request_epoch = epoch;
    Ok(cli)
}

/// The `--request-epoch` of the innermost command given, if any.
fn kept_request_epoch(
    matches: &clap::ArgMatches,
) -> Option<heimdall_contract::lifecycle::RestoreEpoch> {
    let mut at = matches;
    loop {
        if let Ok(Some(epoch)) = at.try_get_one::<u64>(REQUEST_EPOCH_ARG) {
            return Some(heimdall_contract::lifecycle::RestoreEpoch(*epoch));
        }
        at = at.subcommand()?.1;
    }
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    // ADR-0007 §5.
    /// Adopt supported local access: preview, apply, roll back or repair the
    /// managed OpenSSH projection. Without an action, `apply`.
    Setup(SetupArgs),
    // ADR-0007 §8.
    /// Convenience connect through the verified client; ordinary ssh also works.
    Connect(ConnectArgs),
    // spec §10.4.
    /// Ensure access then launch argv without a shell.
    Run(RunArgs),
    /// Summary of the runtime, open work, and pending owner decisions. Never
    /// starts the runtime.
    Status,
    // spec §10.2; ADR-0007 §6.
    /// Passive diagnostics by default; explicit probes only by named level. Never
    /// starts the runtime.
    Doctor(DoctorArgs),
    /// Terminal UI.
    Tui,
    /// Destination catalog: managed and observed aliases.
    #[command(subcommand)]
    Destination(DestinationCommand),
    // ADR-0007 §7.
    /// Adopted identities and their interaction declarations.
    #[command(subcommand)]
    Identity(IdentityCommand),
    /// Profiles: named sets of destination/account pairs.
    #[command(subcommand)]
    Profile(ProfileCommand),
    /// Remove the projection, restore your files, and report what remains.
    Uninstall(UninstallArgs),
    // ADR-0008 D3, D4.
    /// The local issuer: its CA key, status, recovery bundle.
    // ⟨ADR-0008 §17.28 item 6⟩ The ad-hoc-signed macOS update caveat and its recovery.
    #[command(subcommand, after_help = ISSUER_UPDATE_HELP)]
    Issuer(IssuerCommand),
    // ADR-0008 D5.
    /// Enroll a destination for managed credentials and manage its enrollments.
    Enroll(EnrollArgs),
    // ADR-0008 D8.
    /// Owned connections and their owner-side close.
    Connections(ConnectionsArgs),
    /// Helpers the runtime starts itself; not a user surface.
    #[command(subcommand, hide = true)]
    Internal(InternalCommand),
    // ADR-0010 §2, §3.
    /// WSL distributions Heimdall serves: enable, disable, status.
    #[command(subcommand)]
    Wsl(WslCommand),
    // ADR-0010 §4.
    /// Local Linux-container environments and their binding recipe.
    #[command(subcommand)]
    Container(ContainerCommand),
    // ADR-0011 §2.
    /// Project trust: the trust record of the workspace you are in.
    #[command(subcommand)]
    Project(ProjectCommand),
    // ADR-0011 §3.2.
    /// Activate the profile the working directory's workspace names; the shell hook.
    Activate(ActivateArgs),
    // ADR-0011 §3.2.
    /// Shell integration.
    #[command(subcommand)]
    Shell(ShellCommand),
    // ADR-0011 §2.4.
    /// Export your portable intent: profiles and destinations, never authority.
    Export(ExportArgs),
    // ADR-0011 §2.4.
    /// Import portable intent from an exported bundle; it grants no access.
    Import(ImportArgs),
    // ADR-0012 §3, §7.
    /// Remote runner environments: add, invite, join, revoke-client, remove, update,
    /// status.
    #[command(subcommand)]
    Environment(m06_cmd::EnvironmentCommand),
    // ADR-0012 §3.4.
    /// This controller device: retire.
    #[command(subcommand)]
    Device(m06_cmd::DeviceCommand),
    // ADR-0012 §5.
    /// A destination's approved routes: add, remove, prefer.
    #[command(subcommand)]
    Route(m06_cmd::RouteCommand),
    // ADR-0012 §1, §2, §2.8.
    /// The Iroh transport: enable, disable, adopt-roost.
    #[command(subcommand)]
    Transport(m06_cmd::TransportCommand),
    // ADR-0012 §3.3, §3.6.
    /// The runner's side of a paired environment: `init` (the bootstrap's runner-local
    /// enrollment) and `serve` (the forced command's bridge). Hidden and frozen: the
    /// bootstrap session and rendered management lines name them.
    #[command(subcommand, hide = true)]
    Remote(m06_cmd::RemoteCommand),
    // ⟨rev7⟩ ADR-0014 H1: a skeleton until its unit lands (`rev7_cmd`).
    /// Diagnostics for a support request: a bundle of codes and counts, never secrets or
    /// free text, previewed before it is written.
    #[command(subcommand)]
    Support(SupportCommand),
    // ⟨rev7⟩ ADR-0014 H3, U0-Q8: skeletons until their unit lands (`rev7_cmd`).
    /// The local state store: its status, and the attended restore, reset and repair.
    #[command(subcommand)]
    State(StateCommand),
    /// Read-only inspection of runtime state. Never starts the runtime.
    Inspect {
        /// Subject: capabilities|environments|profiles|destinations|bindings|grants|operations|decisions
        /// (also identities|projections), or `request` with a request ID.
        subject: String,
        // ⟨rev7⟩ U0-Q7: `inspect request <REQUEST_ID>` (a skeleton until its unit lands).
        /// With `request`: the request ID whose state to show.
        #[arg(value_name = "REQUEST_ID")]
        id: Option<String>,
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
    // R-AP-08.
    /// Public schemas, the code table, the error reasons and the agent primitives.
    #[command(subcommand)]
    Schema(SchemaCommand),
}

/// `run` arguments (ADR-0007 §8; m02-plan U8).
#[derive(Debug, Args)]
pub struct RunArgs {
    // ADR-0011 §3.1.
    /// Profile to ensure. Without it, the working directory's workspace, else this
    /// environment's default profile; a trust decision is asked on a terminal.
    #[arg(long)]
    pub profile: Option<String>,
    /// Work ID.
    #[arg(long)]
    pub work_id: Option<String>,
    /// Idempotency request ID for the ensure and bind (a fresh one is minted and
    /// reported when absent). A retry with the same ID never relaunches by itself.
    #[arg(long)]
    pub request_id: Option<String>,
    /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
    /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
    /// is used.
    #[arg(long, value_name = "N", requires = "request_id")]
    pub request_epoch: Option<u64>,
    // ADR-0011 §6.
    /// Run the program with a narrower child binding of this parent binding: the program
    /// gets only the child's signing endpoint and no `HEIMDALL_*` variable. A wider scope
    /// or a later deadline is refused (`DELEGATION_EXCEEDS_PARENT`) and nothing is
    /// launched.
    #[arg(long, value_name = "BINDING")]
    pub parent_binding: Option<String>,
    /// With `--parent-binding`: the child's `destination:account` pairs (repeatable; a
    /// subset of the parent's; default all of them).
    #[arg(
        long = "scope",
        value_name = "DEST:ACCOUNT",
        requires = "parent_binding"
    )]
    pub scope: Vec<String>,
    /// With `--parent-binding`: the child's deadline, an absolute RFC 3339 instant not
    /// later than the parent's (default the parent's).
    #[arg(long, value_name = "INSTANT", requires = "parent_binding")]
    pub until: Option<String>,
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
        // ADR-0007 §5.6.
        /// Also plan the global Git include (`core.sshCommand`).
        #[arg(long)]
        include_git: bool,
    },
    /// Preview, confirm, then apply exactly the previewed plan.
    Apply {
        /// Also apply the global Git include.
        #[arg(long)]
        include_git: bool,
        /// After the apply, also check with `ssh -G` that every alias connected through
        /// Heimdall's routes holds its host-key pin. This runs your configuration's
        /// commands (a `Match exec`, for example) with whatever effects they have.
        /// Without it only the static check runs.
        #[arg(long)]
        allow_config_commands: bool,
        /// Idempotency request ID (a fresh one is minted and reported when absent).
        #[arg(long)]
        request_id: Option<String>,
        /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
        /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
        /// is used.
        #[arg(long, value_name = "N", requires = "request_id")]
        request_epoch: Option<u64>,
    },
    /// Remove the projection and restore your files to the consented state.
    Rollback {
        /// Keep the materialized public-key files.
        #[arg(long)]
        keep_key_files: bool,
        /// Idempotency request ID.
        #[arg(long)]
        request_id: Option<String>,
        /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
        /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
        /// is used.
        #[arg(long, value_name = "N", requires = "request_id")]
        request_epoch: Option<u64>,
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
    /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
    /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
    /// is used.
    #[arg(long, value_name = "N", requires = "request_id")]
    pub request_epoch: Option<u64>,
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
        /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
        /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
        /// is used.
        #[arg(long, value_name = "N", requires = "request_id")]
        request_epoch: Option<u64>,
    },
    /// Choose which mechanism serves an alias: the managed definition or the existing
    /// access (takes effect with `setup apply`).
    Prefer(DestinationPreferArgs),
}

/// `destination prefer` arguments (m03-plan §5 items 4b and 24).
#[derive(Debug, Args)]
pub struct DestinationPreferArgs {
    /// The alias.
    pub alias: String,
    /// The mechanism that serves it.
    #[arg(value_enum)]
    pub mechanism: MechanismArg,
}

/// The mechanism `destination prefer` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MechanismArg {
    /// The managed credential (a short-lived certificate).
    Managed,
    /// The existing access.
    Existing,
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
    // ADR-0010 §5.
    /// Reach the destination through this destination as a bastion.
    #[arg(long, value_name = "DESTINATION", requires = "hostname")]
    pub jump: Option<String>,
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
    /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
    /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
    /// is used.
    #[arg(long, value_name = "N", requires = "request_id")]
    pub request_epoch: Option<u64>,
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
        /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
        /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
        /// is used.
        #[arg(long, value_name = "N", requires = "request_id")]
        request_epoch: Option<u64>,
    },
    /// Withdraw an interaction declaration (narrowing; no decision).
    WithdrawDeclaration {
        /// Identity ID.
        identity: String,
        /// Idempotency request ID.
        #[arg(long)]
        request_id: Option<String>,
        /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
        /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
        /// is used.
        #[arg(long, value_name = "N", requires = "request_id")]
        request_epoch: Option<u64>,
    },
    /// Remove an adopted identity.
    Remove {
        /// Identity ID.
        identity: String,
        /// Idempotency request ID.
        #[arg(long)]
        request_id: Option<String>,
        /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
        /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
        /// is used.
        #[arg(long, value_name = "N", requires = "request_id")]
        request_epoch: Option<u64>,
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
    /// With `--from-agent`: adopt the listed identity with this fingerprint
    /// (`SHA256:…`); needed when the agent lists several. (`requires` alone does not
    /// hold for a flag, which always has a value; refusing `--pub` makes `--from-agent`
    /// the only way to parse it.)
    #[arg(
        long,
        value_name = "FINGERPRINT",
        requires = "from_agent",
        conflicts_with = "pub_file"
    )]
    pub fingerprint: Option<String>,
    /// Label.
    #[arg(long)]
    pub label: Option<String>,
    /// Idempotency request ID.
    #[arg(long)]
    pub request_id: Option<String>,
    /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
    /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
    /// is used.
    #[arg(long, value_name = "N", requires = "request_id")]
    pub request_epoch: Option<u64>,
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
        /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
        /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
        /// is used.
        #[arg(long, value_name = "N", requires = "request_id")]
        request_epoch: Option<u64>,
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
        /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
        /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
        /// is used.
        #[arg(long, value_name = "N", requires = "request_id")]
        request_epoch: Option<u64>,
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
        /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
        /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
        /// is used.
        #[arg(long, value_name = "N", requires = "request_id")]
        request_epoch: Option<u64>,
    },
    /// List profiles (read-only).
    List,
}

/// `uninstall` arguments (Q6; m02-plan U9).
#[derive(Debug, Args)]
pub struct UninstallArgs {
    /// Also delete Heimdall's state store once every rollback completed. Refused while
    /// any remote enrollment is not final, unless `--keep-remote-enrollments` is given.
    #[arg(long)]
    pub purge_state: bool,
    // ADR-0008 D4 item 6, §17.25 items 8 and 11.
    /// Leave the remote enrollments that are not final in place. Alone, it is the
    /// explicit acknowledgement a plain uninstall needs while any remain (the state is
    /// kept); with `--purge-state` it needs a fresh recovery bundle (`--bundle`).
    #[arg(long)]
    pub keep_remote_enrollments: bool,
    /// The fresh recovery bundle that records what stays enrolled when the state is
    /// purged (written by this installation's `heimdall issuer bundle`).
    #[arg(
        long,
        value_name = "FILE",
        requires_all = ["keep_remote_enrollments", "purge_state"]
    )]
    pub bundle: Option<PathBuf>,
}

/// `access` subcommands.
#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    // spec §11.3.
    /// Idempotent access preparation.
    Ensure(EnsureArgs),
    /// Drop this consumer's reference to a binding.
    Release {
        /// Binding ID.
        binding_id: String,
        /// Idempotency request ID: a retry with the same one is checked as the same request.
        /// Without it the release has none (releasing a binding again changes nothing).
        #[arg(long)]
        request_id: Option<String>,
        /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
        /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
        /// is used.
        #[arg(long, value_name = "N", requires = "request_id")]
        request_epoch: Option<u64>,
    },
    // spec §6.7.
    /// Revoke a grant and its descendants.
    Revoke {
        /// Grant ID.
        grant_id: String,
        /// Idempotency request ID (a fresh one is minted and reported when absent).
        #[arg(long)]
        request_id: Option<String>,
        /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
        /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
        /// is used.
        #[arg(long, value_name = "N", requires = "request_id")]
        request_epoch: Option<u64>,
    },
    /// Narrower child binding.
    Delegate(DelegateArgs),
    /// Pause automatic activation for a policy, a profile, a workspace or all (owner
    /// channel; narrowing).
    Pause {
        /// What to pause: a policy ID, or one target.
        #[command(flatten)]
        target: AccessTarget,
    },
    /// Resume automatic activation (widening: needs an owner decision).
    Resume {
        /// What to resume: a policy ID, or one target.
        #[command(flatten)]
        target: AccessTarget,
    },
    // spec §6.1.
    /// Schedule (or clear) a hard stop for a policy, a profile, a workspace or all. An
    /// earlier cutoff applies at once; a later one or `--clear` needs an owner decision.
    Cutoff {
        /// What to cut off: a policy ID, or one target.
        #[command(flatten)]
        target: AccessTarget,
        /// RFC 3339 instant with explicit offset.
        #[arg(long, required_unless_present = "clear", conflicts_with = "clear")]
        at: Option<String>,
        /// Clear the cutoff deliberately.
        #[arg(long)]
        clear: bool,
    },
    /// Choose what a session lock does to a policy's managed grants (narrowing is
    /// immediate, widening needs an owner decision).
    LockBehavior(LockBehaviorArgs),
    /// Choose what happens to owned connections at the deadline, and whether Heimdall
    /// owns a multiplex master.
    ConnectionPolicy(ConnectionPolicyArgs),
    // ADR-0011 §4.3.
    /// Owner-initiated review that may widen a workspace's, profile's or policy's
    /// standing scope; always creates its own decision.
    Allow(AccessAllowArgs),
    // ADR-0011 §7.
    /// Stop now: end one work's access, or a policy's, a profile's, a workspace's or all.
    Stop(AccessStopArgs),
    // ADR-0011 §5.1.
    /// The profile a new request without one uses: show, set or clear this environment's
    /// preference; never authority.
    DefaultProfile(AccessDefaultProfileArgs),
}

/// The target of `access pause|resume|cutoff`: exactly one of a policy ID (the existing
/// form), `--profile`, `--workspace` or `--all` (M05; ADR-0011 §7.3).
#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("access_target")
        .required(true)
        .multiple(false)
        .args(["policy_id", "profile", "workspace", "all"])
))]
pub struct AccessTarget {
    /// Policy ID.
    pub policy_id: Option<String>,
    /// Every policy for this profile.
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<String>,
    /// The policy of the workspace you are in.
    #[arg(long)]
    pub workspace: bool,
    /// Every policy.
    #[arg(long)]
    pub all: bool,
    /// With `--workspace`: the directory whose workspace is meant (default the working
    /// directory).
    #[arg(long, value_name = "PATH", requires = "workspace")]
    pub cwd: Option<PathBuf>,
}

impl AccessTarget {
    /// The policy ID of the existing form, or `None` when an M05 target was given.
    pub(crate) fn policy_id(&self) -> Option<&str> {
        self.policy_id.as_deref()
    }
}

/// `access allow` arguments (M05; ADR-0011 §4.3): what the review is for, exactly one.
#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("allow_target")
        .required(true)
        .multiple(false)
        .args(["policy", "profile", "workspace"])
))]
pub struct AccessAllowArgs {
    /// Review this policy.
    #[arg(long, value_name = "POLICY")]
    pub policy: Option<String>,
    /// Review the policies of this profile.
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<String>,
    /// Review the workspace you are in (or the one `--cwd` names).
    #[arg(long)]
    pub workspace: bool,
    /// The directory whose workspace `--workspace` names (default the working directory).
    #[arg(long, value_name = "PATH", requires = "workspace")]
    pub cwd: Option<PathBuf>,
    /// With `--profile`: review a new policy that names this paired runner
    /// environment. It only lets this controller issue for grants that runner admits for
    /// the profile; it activates nothing on this device.
    #[arg(long, value_name = "ENVIRONMENT", requires = "profile")]
    pub environment: Option<String>,
}

/// `access stop` arguments (M05; ADR-0011 §7): exactly one of a work ID or a policy-level
/// target.
#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("stop_target")
        .required(true)
        .multiple(false)
        .args(["work", "policy", "profile", "workspace", "all"])
))]
pub struct AccessStopArgs {
    /// Stop this work: its unshared grants are revoked, other work is unaffected.
    #[arg(long, value_name = "WORK")]
    pub work: Option<String>,
    /// Stop this policy (pause and end now).
    #[arg(long, value_name = "POLICY")]
    pub policy: Option<String>,
    /// Stop every policy for this profile.
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<String>,
    /// Stop the policy of the workspace you are in.
    #[arg(long)]
    pub workspace: bool,
    /// Stop every policy.
    #[arg(long)]
    pub all: bool,
    /// With `--workspace`: the directory whose workspace is meant (default the working
    /// directory).
    #[arg(long, value_name = "PATH", requires = "workspace")]
    pub cwd: Option<PathBuf>,
    /// With `--work`: the idempotency request ID (a fresh one is minted and reported when
    /// absent).
    #[arg(long, requires = "work")]
    pub request_id: Option<String>,
    /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
    /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
    /// is used.
    #[arg(long, value_name = "N", requires = "request_id")]
    pub request_epoch: Option<u64>,
}

/// `access default-profile` arguments (M05; ADR-0011 §5.1; ADR-0006 §17.9 item 13).
#[derive(Debug, Args)]
pub struct AccessDefaultProfileArgs {
    /// The profile to set; without it (and without `--clear`), show the current one.
    #[arg(value_name = "PROFILE", conflicts_with = "clear")]
    pub profile: Option<String>,
    /// Clear the preference.
    #[arg(long)]
    pub clear: bool,
    /// Idempotency request ID (a fresh one is minted and reported when absent).
    #[arg(long)]
    pub request_id: Option<String>,
    /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
    /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
    /// is used.
    #[arg(long, value_name = "N", requires = "request_id")]
    pub request_epoch: Option<u64>,
}

/// `access lock-behavior` arguments (m03-plan §5 item 24).
#[derive(Debug, Args)]
pub struct LockBehaviorArgs {
    /// Policy ID.
    #[arg(long, value_name = "POLICY")]
    pub policy: String,
    /// `continue` (a lock does not end managed grants) or `revoke-on-lock`.
    #[arg(value_enum)]
    pub behavior: LockBehaviorArg,
}

/// The lock behaviors the CLI names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LockBehaviorArg {
    /// A lock does not end managed grants.
    Continue,
    /// A lock revokes the grant.
    RevokeOnLock,
}

/// `access connection-policy` arguments (m03-plan §5 item 24).
#[derive(Debug, Args)]
pub struct ConnectionPolicyArgs {
    /// Policy ID.
    #[arg(long, value_name = "POLICY")]
    pub policy: String,
    /// What happens to existing owned connections at the deadline.
    #[arg(long, value_enum)]
    pub existing: Option<ExistingArg>,
    /// Whether Heimdall owns a multiplex master per pair.
    #[arg(long, value_enum)]
    pub multiplexing: Option<MultiplexingArg>,
}

/// `--existing` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExistingArg {
    /// Existing dedicated sessions may stay connected.
    Graceful,
    /// Owned connections are closed at the deadline.
    Strict,
}

/// `--multiplexing` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MultiplexingArg {
    /// No master.
    Disabled,
    /// One owned master per pair.
    Owned,
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
    // m02-plan §5 item 6.
    /// New authentications must need no human interaction until the deadline,
    /// including through desktop and vault lock. `unknown` never satisfies it.
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
    /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
    /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
    /// is used.
    #[arg(long, value_name = "N", requires = "request_id")]
    pub request_epoch: Option<u64>,
    /// Return immediately with the operation to observe (`ACCEPTED`, exit 0).
    #[arg(long = "async")]
    pub r#async: bool,
    /// Bounded synchronous wait in milliseconds (timeout is not cancel; a
    /// still-pending operation exits 5 with `next.observe`).
    #[arg(long, default_value_t = 30_000)]
    pub timeout_ms: u64,
    /// Close owned connections at the deadline (`EnsureRequest.connection` strict).
    #[arg(long)]
    pub strict: bool,
    /// Caller minimums.
    #[command(flatten)]
    pub require: RequireArgs,
    // M06 W5; ADR-0012 §4 item 2 (2026-11-21).
    /// On a runner, for its local owner at a terminal: the CA every named pair waits for
    /// (`EnsureRequest.pair_issuers`). Only a CA already in the runner's `issuer_trust` is
    /// admitted, and only as a pending grant: the runner never issues. Hidden: it is the
    /// runner owner's path to record source (b), not an agent's.
    #[arg(
        long = "issuer-ca",
        value_name = "FINGERPRINT",
        hide = true,
        conflicts_with = "environment"
    )]
    pub issuer_ca: Option<String>,
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
    /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
    /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
    /// is used.
    #[arg(long, value_name = "N", requires = "request_id")]
    pub request_epoch: Option<u64>,
}

/// ⟨ADR-0008 §17.28 item 6⟩ `issuer --help`'s note: an ad-hoc-signed macOS build may lose
/// access to its CA key after an update, and the recovery. No K_ca continuity across
/// updates is claimed.
const ISSUER_UPDATE_HELP: &str = "On macOS, a build without a Developer ID signature (ad-hoc-signed) may lose access to its CA key after an update: the key store item trusts the exact build that created it. The issuer then reports `issuer_store_access_denied`. Run `heimdall issuer restore --backup <file>`: it restores the CA to a new store item, then lists the old item under orphan store items; delete that one in Keychain Access (Heimdall never deletes it).";

/// ⟨ADR-0008 §17.28 item 6⟩ `issuer restore --help`'s note on that recovery.
const ISSUER_RESTORE_HELP: &str = "Also the recovery when the issuer reports `issuer_store_access_denied` (on macOS, an ad-hoc-signed build after an update): the CA is restored to a new store item, recorded after a typed `yes`; the old item is kept and listed under orphan store items, to be deleted in Keychain Access (Heimdall never deletes it).";

/// `issuer` subcommands (m03-plan §5 item 24; ADR-0008 D3, D4).
#[derive(Debug, Subcommand)]
pub enum IssuerCommand {
    /// Create the CA key and its offline backup (terminal only).
    #[command(group(
        ArgGroup::new("orphan_bundle")
            .args(["bundle", "no_bundle_available"])
            .requires("replace_orphan")
    ))]
    Init {
        /// Where the encrypted backup is written.
        #[arg(long, value_name = "PATH")]
        backup_out: PathBuf,
        // ADR-0008 D4 item 1.
        /// Replace the kept CA key with this fingerprint.
        #[arg(long, value_name = "FINGERPRINT", requires = "orphan_bundle")]
        replace_orphan: Option<String>,
        /// The recovery bundle that is cross-checked against the orphan.
        #[arg(long, value_name = "FILE")]
        bundle: Option<PathBuf>,
        /// No bundle exists for the orphan.
        #[arg(long)]
        no_bundle_available: bool,
    },
    /// Show the issuer's state, CAs and enrollment counts (read-only).
    Status,
    /// Unlock the CA key store (attended).
    Unlock,
    /// Rotate the CA key.
    #[command(subcommand)]
    Rotate(IssuerRotateCommand),
    /// Retire a CA by fingerprint.
    Retire {
        /// The CA fingerprint.
        fingerprint: String,
    },
    /// Restore the CA key from a backup (the passphrase is typed on the terminal).
    #[command(after_help = ISSUER_RESTORE_HELP)]
    Restore {
        /// The encrypted backup file.
        #[arg(long, value_name = "FILE")]
        backup: PathBuf,
        /// The backup is not believed stolen.
        #[arg(long)]
        not_stolen: bool,
    },
    /// Write a recovery bundle.
    Bundle {
        /// Where the bundle is written.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        /// Redact a class of detail.
        #[arg(long, value_enum)]
        redact: Option<RedactArg>,
    },
}

/// `issuer rotate` subcommands.
#[derive(Debug, Subcommand)]
pub enum IssuerRotateCommand {
    /// Begin a rotation: a new CA key and a new offline backup.
    Begin {
        /// Where the new encrypted backup is written.
        #[arg(long, value_name = "PATH")]
        backup_out: PathBuf,
    },
}

/// What `issuer bundle --redact` hides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RedactArg {
    /// Destination host names.
    Hostnames,
}

/// `enroll` arguments: `enroll <destination>` or one subcommand (m03-plan §5 item 24).
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub struct EnrollArgs {
    /// Manage existing enrollments.
    #[command(subcommand)]
    pub command: Option<EnrollCommand>,
    /// Enroll a destination (the preview is shown first).
    #[command(flatten)]
    pub start: EnrollStartArgs,
}

/// `enroll <destination>` arguments.
#[derive(Debug, Args)]
pub struct EnrollStartArgs {
    /// The destination (ID or alias).
    #[arg(required = true)]
    pub destination: Option<String>,
    /// The account; it must equal the catalog's.
    #[arg(long, value_name = "ACCOUNT")]
    pub account: Option<String>,
    /// `account` (the default) or `system`.
    #[arg(long, value_enum)]
    pub form: Option<FormArg>,
    /// The registry path on the destination.
    #[arg(long, value_name = "PATH")]
    pub registry_path: Option<String>,
    /// The CA fingerprint to enroll under.
    #[arg(long, value_name = "FINGERPRINT")]
    pub ca: Option<String>,
}

/// `--form` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FormArg {
    /// The account's own registry.
    Account,
    /// The system registry (manual removal).
    System,
}

/// `enroll` subcommands.
#[derive(Debug, Subcommand)]
pub enum EnrollCommand {
    /// List enrollments (read-only).
    Status,
    /// Verify an enrollment.
    Verify {
        /// Enrollment ID.
        enrollment: String,
        /// The system form's absence check.
        #[arg(long, conflicts_with = "approve_target_change")]
        absence: bool,
        /// Approve the destination's new host key (shown as a diff).
        #[arg(long)]
        approve_target_change: bool,
    },
    /// Remove an enrollment, or a foreign one from a bundle.
    #[command(group(
        ArgGroup::new("removal")
            .required(true)
            .args(["enrollment", "from_bundle"])
    ))]
    Remove {
        /// Enrollment ID.
        enrollment: Option<String>,
        /// Remove an enrollment recorded only in this bundle.
        #[arg(long, value_name = "FILE", requires_all = ["marker", "alias"])]
        from_bundle: Option<PathBuf>,
        /// The marker of the bundle's enrollment.
        #[arg(long, requires = "from_bundle")]
        marker: Option<String>,
        /// The local alias that reaches the destination.
        #[arg(long, requires = "from_bundle")]
        alias: Option<String>,
    },
    /// Classify an operation that stopped between steps; never redispatches.
    Reconcile {
        /// Operation ID.
        operation: String,
        /// The owner removed a lock by hand.
        #[arg(long)]
        after_manual_recovery: bool,
    },
    /// Give an account up while it is unreachable, held or uncertain.
    Abandon {
        /// Enrollment ID.
        enrollment: String,
    },
}

/// `connections` arguments: no subcommand lists (m03-plan §5 item 24).
#[derive(Debug, Args)]
pub struct ConnectionsArgs {
    /// Act on a connection.
    #[command(subcommand)]
    pub command: Option<ConnectionsCommand>,
}

/// `connections` subcommands.
#[derive(Debug, Subcommand)]
pub enum ConnectionsCommand {
    /// Close an owned connection (never signals an unverified process).
    Close {
        /// Connection ID.
        id: String,
    },
}

/// `internal` subcommands (hidden; m03-plan §5 item 24).
#[derive(Debug, Subcommand)]
pub enum InternalCommand {
    /// The issuer child: refuses a terminal on stdin.
    Issuer,
    /// The session-lock state, read-only.
    SessionLockState,
    // ADR-0010 §2.
    /// The WSL helper the Windows runtime starts inside a distribution.
    WslHelper,
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
        // ADR-0010 §1, §6.
        /// Started by the login entry; yields to a running instance.
        #[arg(long)]
        login: bool,
        // ADR-0012 §3.2, §4.
        /// Serve as a remote runner with the forced command's paths (this executable and
        /// the explicit home): `ServiceOptions::runner`. Hidden: started by the runner's
        /// own wiring.
        #[arg(long, hide = true)]
        runner: bool,
    },
    /// Report whether a runtime is serving (exit 5 when none is).
    Status,
    /// Ask the runtime to drain and stop.
    Stop {
        // ⟨M08 U2b-4⟩ ADR-0014 H2 (`service_cmd::stop_preview`).
        /// Only list what stopping would interrupt; change nothing.
        #[arg(long)]
        preview: bool,
    },
    // ADR-0010 §1, §6.
    /// Start the runtime at login: enable, disable, status.
    #[command(subcommand)]
    Autostart(AutostartCommand),
}

/// `service autostart` subcommands (M04; ADR-0010 §1, §6).
#[derive(Debug, Subcommand)]
pub enum AutostartCommand {
    /// Register the login entry.
    Enable,
    /// Remove the login entry Heimdall registered.
    Disable,
    /// Show whether the login entry is registered (read-only).
    Status,
}

/// `wsl` subcommands (M04; ADR-0010 §2, §3).
#[derive(Debug, Subcommand)]
pub enum WslCommand {
    /// Serve a WSL distribution: Mode A (Windows SSH authority) or Mode B (a Linux-native
    /// scoped endpoint).
    Enable(WslEnableArgs),
    /// Stop serving a distribution and clean up what Heimdall placed in it.
    Disable(WslDisableArgs),
    /// Show the discovered distributions and which ones Heimdall serves (read-only).
    Status,
}

/// `wsl enable` arguments (ADR-0010 §2, §3).
#[derive(Debug, Args)]
pub struct WslEnableArgs {
    /// The distribution name.
    pub distribution: String,
    /// The Linux account inside the distribution (default its default user).
    #[arg(long, value_name = "NAME")]
    pub account: Option<String>,
    /// Mode A: the distribution uses Windows SSH authority.
    #[arg(long, conflicts_with = "mode_b")]
    pub mode_a: bool,
    /// Mode B: a Linux-native scoped endpoint inside the distribution.
    #[arg(long)]
    pub mode_b: bool,
}

/// `wsl disable` arguments (ADR-0010 §9 item 2).
#[derive(Debug, Args)]
pub struct WslDisableArgs {
    /// The distribution name.
    pub distribution: String,
    /// Start a stopped distribution to finish its cleanup (an explicit, authorized
    /// start; a distribution is never started in the background).
    #[arg(long)]
    pub start: bool,
}

/// `container` subcommands (M04; ADR-0010 §4).
#[derive(Debug, Subcommand)]
pub enum ContainerCommand {
    /// Register a local Linux-container environment.
    Add {
        /// The environment's label.
        label: String,
    },
    /// Remove a container environment.
    Remove {
        /// The environment ID.
        environment: String,
    },
    /// Print the mount arguments that bind the container to its environment endpoint.
    MountArgs {
        /// The environment ID.
        environment: String,
    },
}

/// `project` subcommands (M05; ADR-0011 §2).
#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
    /// Trust the workspace's manifest: an owner decision that shows the exact scope.
    Trust(ProjectTrustArgs),
    /// Show the workspace, its trust state and its policy (read-only).
    Status(ProjectCwdArgs),
    /// Withdraw the workspace's trust.
    Untrust(ProjectCwdArgs),
    /// Resolve an ambiguous workspace match (for example a re-clone at the same path).
    Reconcile(ProjectCwdArgs),
}

/// The directory a `project` command reads its workspace from.
#[derive(Debug, Args)]
pub struct ProjectCwdArgs {
    /// The directory (default the working directory).
    #[arg(long, value_name = "PATH")]
    pub cwd: Option<PathBuf>,
}

/// `project trust` arguments (M05; ADR-0011 §2.1, §2.2 "Discovery").
#[derive(Debug, Args)]
pub struct ProjectTrustArgs {
    /// The directory (default the working directory).
    #[arg(long, value_name = "PATH")]
    pub cwd: Option<PathBuf>,
    /// For a workspace without `.heimdall.toml`: the profile to trust it with (default
    /// this environment's default profile). With a manifest, it must be the manifest's.
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<String>,
}

/// ⟨M06⟩ The arguments of a registered M06 subcommand not built yet (`m06_cmd`): accepted
/// and ignored, the command is refused before anything else happens.
#[derive(Debug, Args)]
pub struct PlannedArgs {
    /// The command's arguments (defined by the unit that builds it).
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        hide = true,
        value_name = "ARGS"
    )]
    pub args: Vec<OsString>,
}

/// `activate` arguments (M05; ADR-0011 §3.2, §10 item 3).
#[derive(Debug, Args)]
pub struct ActivateArgs {
    /// Run as the shell hook: noninteractive, never prompts, activates only what is
    /// already covered.
    // ⟨rev7⟩ ADR-0013 §2.3: an integration endpoint, frozen and hidden from help.
    #[arg(long, hide = true)]
    pub hook: bool,
    /// The directory the shell is in.
    #[arg(long, value_name = "PATH")]
    pub cwd: PathBuf,
    /// With `--hook`: the shell that holds the activation (default the parent process).
    #[arg(long, value_name = "PID", requires = "hook", hide = true)]
    pub shell_pid: Option<u32>,
    /// With `--hook`: the shell's work sequence number (the shell integration keeps it).
    #[arg(
        long,
        value_name = "N",
        requires = "hook",
        hide = true,
        default_value_t = 0
    )]
    pub seq: u64,
    /// With `--hook`: the state the shell last showed (a status line is printed only when
    /// the state changes).
    #[arg(long, value_name = "STATE", requires = "hook", hide = true)]
    pub last: Option<String>,
}

/// `shell` subcommands (M05; ADR-0011 §3.2).
#[derive(Debug, Subcommand)]
pub enum ShellCommand {
    /// Print the shell integration script for `zsh`, `bash` or `powershell`.
    Init {
        /// The shell.
        #[arg(value_enum)]
        shell: ShellArg,
    },
}

/// The shells `shell init` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ShellArg {
    /// Zsh.
    Zsh,
    /// Bash.
    Bash,
    /// PowerShell (Windows PowerShell 5.1 and PowerShell 7).
    Powershell,
}

/// `export` arguments (M05; ADR-0011 §2.4).
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Redact host names, addresses and labels.
    #[arg(long)]
    pub redact: bool,
    /// Write the bundle to this new file (created exclusively, owner-only) instead of
    /// stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

/// `import` arguments (M05; ADR-0011 §2.4).
#[derive(Debug, Args)]
pub struct ImportArgs {
    /// The exported bundle.
    #[arg(value_name = "BUNDLE")]
    pub bundle: PathBuf,
    /// Apply the previewed plan without asking (needed without a terminal).
    #[arg(long)]
    pub yes: bool,
    /// Idempotency request ID (a fresh one is minted and reported when absent).
    #[arg(long)]
    pub request_id: Option<String>,
    /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
    /// give it with the same `--request-id` to retry. Without it, the runtime's current epoch
    /// is used.
    #[arg(long, value_name = "N", requires = "request_id")]
    pub request_epoch: Option<u64>,
}

/// ⟨rev7⟩ `support` subcommands (ADR-0014 H1): a skeleton answering "not available in this
/// build" until its unit lands.
#[derive(Debug, Subcommand)]
pub enum SupportCommand {
    /// Write a support bundle: codes, counts and pseudonyms only, never secrets or free
    /// text. The preview shows the exact bytes that would be written.
    Bundle {
        /// Show the bundle and write nothing.
        #[arg(long)]
        preview: bool,
        /// The file to write (created new, owner-only).
        #[arg(long, value_name = "FILE", required_unless_present = "preview")]
        out: Option<PathBuf>,
        /// Write identifiers typed as public (aliases, host names) instead of pseudonyms.
        #[arg(long)]
        include_identifiers: bool,
    },
}

/// ⟨rev7⟩ `state` subcommands (ADR-0014 H3, U0-Q8). ⟨M08 U2b-3b⟩ Status, restore, reset
/// and repair are built (`state_cmd`): status is read-only; restore, reset and repair are
/// attended, with a typed confirmation, and never run under `--non-interactive`.
#[derive(Debug, Subcommand)]
pub enum StateCommand {
    /// The state store's health, its current generation, earlier generations and backups
    /// (read-only).
    Status,
    /// Restore identity and configuration from a backup of this installation. It recovers
    /// no access: grants end, policies pause, paired clients need reauthorization.
    Restore {
        /// The backup file.
        #[arg(long, value_name = "FILE")]
        backup: PathBuf,
    },
    /// Start over with a new identity. The old state is kept, never deleted, and what it
    /// leaves behind on remote hosts is listed first.
    Reset,
    /// Repair a damaged request ledger: fence every readable request after the damage,
    /// raise the restore epoch, then drop the damaged records.
    Repair,
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
        /// Output directory for the trusted-work file formats
        /// (`manifest.schema.json`, `portable.schema.json`; default `schemas/project`).
        #[arg(long, default_value = "schemas/project")]
        project_out: PathBuf,
    },
    /// Print one schema or the code table to stdout.
    Show {
        /// Schema name, or `codes`, `reasons` or `primitives`.
        name: String,
    },
}

/// A finished command: the envelope to print and the exit code.
pub(crate) struct Done {
    pub(crate) env: Envelope<serde_json::Value>,
    pub(crate) exit: ExitCode,
}

impl Done {
    pub(crate) fn of(env: Envelope<serde_json::Value>) -> Self {
        let exit = output::exit_code_for(env.code.clone(), false);
        Self { env, exit }
    }
}

fn usage(message: &str) -> Envelope<serde_json::Value> {
    error_value(error(Code::UsageError, message))
}

/// What a bare `heimdall` (no subcommand) runs (module docs; ADR-0007 §12.30 item 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Bare {
    /// The TUI: stdin and stdout are terminals, no `--json`, no `--non-interactive`.
    Tui,
    /// `status`: anything else (no terminal, machine output, or no prompts allowed).
    Status,
}

/// The reading of a bare `heimdall` for these flags and terminals.
pub(crate) fn bare(json: bool, non_interactive: bool, stdin_tty: bool, stdout_tty: bool) -> Bare {
    if !json && !non_interactive && stdin_tty && stdout_tty {
        Bare::Tui
    } else {
        Bare::Status
    }
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
        request_epoch: cli.request_epoch,
    };
    let command = match cli.command {
        Some(Command::Schema(SchemaCommand::Show { name })) => return schema_show(&name),
        Some(Command::Schema(SchemaCommand::Export {
            out,
            config_out,
            project_out,
        })) => {
            return schema_export(&out, &config_out, &project_out, ctx.json);
        }
        // M04 U1: `--login` and `autostart` are service_cmd's.
        Some(Command::Service(ServiceCommand::Autostart(c))) => {
            return service_cmd::autostart(&ctx, c);
        }
        Some(Command::Service(ServiceCommand::Run {
            detach,
            login,
            runner,
        })) => {
            return service_cmd::run(&ctx, detach, login, runner);
        }
        Some(Command::Service(ServiceCommand::Status)) => return service_cmd::status(&ctx),
        // ⟨M08 U2b-4⟩ ADR-0014 H2: read-only stop preview; changes nothing.
        Some(Command::Service(ServiceCommand::Stop { preview: true })) => {
            return service_cmd::stop_preview(&ctx);
        }
        Some(Command::Service(ServiceCommand::Stop { preview: false })) => {
            return service_cmd::stop(&ctx);
        }
        // ⟨M08 U2b-3b⟩ ADR-0014 H3, U0-Q8: the attended restore, reset and repair
        // (`state_cmd`), before any runtime contact.
        Some(Command::State(StateCommand::Restore { backup })) => {
            return crate::state_cmd::restore(&ctx, &backup);
        }
        Some(Command::State(StateCommand::Reset)) => return crate::state_cmd::reset(&ctx),
        Some(Command::State(StateCommand::Repair)) => return crate::state_cmd::repair(&ctx),
        Some(Command::State(StateCommand::Status)) => return crate::state_cmd::status(&ctx),
        // ⟨rev7⟩ ADR-0014 H1, H3, U0-Q7: skeletons, whatever their flags (the ruling on
        // ASK-H3), before any runtime contact, home creation or file read.
        Some(Command::Support(_)) => {
            return crate::rev7_cmd::not_available(&ctx);
        }
        Some(Command::Inspect { ref subject, .. }) if subject == "request" => {
            return crate::rev7_cmd::not_available(&ctx);
        }
        // M02 commands: each handler owns its command (all wired in wave 4).
        Some(Command::Setup(args)) => return setup_cmd::run(&ctx, args),
        Some(Command::Connect(args)) => return connect_cmd::run(&ctx, args),
        // M05 (U8): `--parent-binding` delegates a child, then launches as `run` does.
        Some(Command::Run(args)) if args.parent_binding.is_some() => {
            return delegate_cmd::run(&ctx, args);
        }
        Some(Command::Run(args)) => return run_cmd::run(&ctx, args),
        Some(Command::Doctor(args)) => return doctor_cmd::run(&ctx, args),
        Some(Command::Tui) => return tui::run(tui::TuiConfig::from_ctx(&ctx)),
        // M03 commands (wave 5, U12): each group has its own handler module.
        Some(Command::Issuer(c)) => return issuer_cmd::run(&ctx, c),
        Some(Command::Enroll(a)) => return enroll_cmd::run(&ctx, a),
        Some(Command::Connections(a)) => return connections_cmd::run(&ctx, a),
        // ⟨M04 U3a⟩ the helper itself (`wsl_cmd::helper`).
        Some(Command::Internal(InternalCommand::WslHelper)) => {
            return wsl_cmd::helper(&ctx);
        }
        Some(Command::Internal(c)) => return m03_cmd::internal(&ctx, c),
        // M04/M05 (ADR-0010 §9 item 9; ADR-0011 §10 item 10): each new command is answered by
        // its owner's handler before any runtime contact.
        // ⟨M04 U3b, U4b⟩ WSL Mode A (ADR-0010 §2) and Mode B (§3, decision-recorded).
        Some(Command::Wsl(WslCommand::Enable(a))) => return wsl_cmd::enable(&ctx, a),
        Some(Command::Wsl(WslCommand::Disable(a))) => return wsl_cmd::disable(&ctx, a),
        Some(Command::Wsl(WslCommand::Status)) => return wsl_cmd::status(&ctx),
        Some(Command::Container(c)) => return container_cmd::run(&ctx, c),
        // ⟨M05⟩ U9a (ADR-0011 §2–§7): each M05 command has its own handler and executor.
        Some(Command::Project(c)) => return m05_cmd::project(&ctx, c),
        Some(Command::Activate(a)) => return activate_cmd::activate(&ctx, &a),
        Some(Command::Shell(ShellCommand::Init { shell })) => {
            return activate_cmd::shell_init(&ctx, shell);
        }
        Some(Command::Export(a)) => return portable_cmd::export(&ctx, &a),
        Some(Command::Import(a)) => return portable_cmd::import(&ctx, &a),
        Some(Command::Access(AccessCommand::Allow(a))) => return m05_cmd::allow(&ctx, &a),
        Some(Command::Access(AccessCommand::Stop(a))) => return m05_cmd::stop(&ctx, &a),
        Some(Command::Access(AccessCommand::DefaultProfile(a))) => {
            return m05_cmd::default_profile(&ctx, &a);
        }
        Some(Command::Access(
            command @ (AccessCommand::Pause { .. }
            | AccessCommand::Resume { .. }
            | AccessCommand::Cutoff { .. }),
        )) if m05_cmd::is_targeted(&command) => return m05_cmd::targeted(&ctx, command),
        // ⟨M06⟩ U2 (ADR-0012 §3): the controller's environment management; `route` and
        // `transport` stay refused before any runtime contact until U56 lands.
        Some(Command::Environment(c)) => return m06_cmd::environment(&ctx, c),
        Some(Command::Device(c)) => return m06_cmd::device(&ctx, c),
        Some(Command::Route(c)) => return m06_cmd::route(&ctx, c),
        Some(Command::Transport(c)) => return m06_cmd::transport(&ctx, c),
        Some(Command::Remote(c)) => return m06_cmd::remote(&ctx, c),
        Some(Command::Destination(c)) => return catalog_cmd::destination(&ctx, c),
        Some(Command::Identity(c)) => return catalog_cmd::identity(&ctx, c),
        Some(Command::Profile(c)) => return catalog_cmd::profile(&ctx, c),
        Some(Command::Uninstall(args)) => return uninstall_cmd::run(&ctx, args),
        // ADR-0007 §12.30 item 5: a bare `heimdall` on a terminal opens the TUI;
        // without one, or with `--json` or `--non-interactive`, it is `status`.
        None => match bare(
            ctx.json,
            ctx.non_interactive,
            ctx.stdin_tty,
            std::io::stdout().is_terminal(),
        ) {
            Bare::Tui => return tui::run(tui::TuiConfig::from_ctx(&ctx)),
            Bare::Status => Command::Status,
        },
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
pub(crate) fn parse<T, E>(
    what: &str,
    f: impl FnOnce(&str) -> Result<T, E>,
    s: &str,
) -> Result<T, Done> {
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

/// ⟨M08 U2b-2 follow-up B; ADR-0014 §3.6 step 3⟩ The arguments that retry a request, as a
/// person or an agent passes them back: its request ID and, beside it, the restore epoch the
/// ID was first sent with, when that is known (a runtime that does not check the epoch reports
/// none, and a kept epoch could not be sent to it).
pub(crate) fn retry_args(
    request_id: &RequestId,
    epoch: Option<heimdall_contract::lifecycle::RestoreEpoch>,
) -> String {
    match epoch {
        Some(epoch) => format!(
            "--request-id {} --request-epoch {}",
            request_id.as_str(),
            epoch.0
        ),
        None => format!("--request-id {}", request_id.as_str()),
    }
}

/// The pending decision a result asks for, if any. ⟨M05⟩ A `decision_cooldown` answer
/// names the **denied** record (ADR-0011 §4.3), which is not pending: nothing is shown or
/// decided for it.
pub(crate) fn pending_decision(env: &Envelope<serde_json::Value>) -> Option<String> {
    if !matches!(env.code, Code::InteractionRequired | Code::ApprovalRequired) {
        return None;
    }
    if env.data["error"]["reason"].as_str()
        == Some(heimdall_contract::envelope::reason::DECISION_COOLDOWN)
    {
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
        // ⟨M03⟩ wave 5 (U12, F14; U-R1): pending chores (`time_confirmation_after_reboot`
        // with `heimdall time confirm`) on the status answer, success or refusal.
        Command::Status => status(ctx)
            .await
            .map(|d| crate::doctor_cmd::with_status_chores(ctx, d))
            .map_err(|d| crate::doctor_cmd::with_status_chores(ctx, d)),
        Command::Inspect {
            subject,
            id,
            preview,
            environment,
            until,
            for_duration,
            require,
        } => {
            // ⟨rev7⟩ Only `inspect request` takes an ID (answered before this, in `dispatch`).
            if id.is_some() {
                return Err(Done::of(usage("only `inspect request` takes an ID")));
            }
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
                Request::Inspect(InspectRequest {
                    subject,
                    preview,
                    cwd: None,
                    redact: false,
                }),
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
                    cwd: None,
                    redact: false,
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
            cwd: None,
            redact: false,
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
    if !ctx.json {
        // Use the expiry flag computed by the runtime.
        env.data["pending_decisions"] = decisions.data["decisions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|decision| decision["state"] == "pending" && decision["expired"] == false)
            .count()
            .into();
        let mut listings = serde_json::Map::new();
        for (key, subject) in [
            ("environments", InspectSubject::Environments),
            ("bindings", InspectSubject::Bindings),
            ("grants", InspectSubject::Grants),
            ("capabilities", InspectSubject::Capabilities),
            ("policies", InspectSubject::Policies),
        ] {
            let request = inspect(subject);
            if request
                .required_capability()
                .is_some_and(|needed| !client.server().capabilities.contains(needed))
            {
                continue;
            }
            let answer = client.request(request).await;
            if answer.code.is_success() {
                listings.insert(key.to_owned(), answer.data);
            }
        }
        env.data[output::STATUS_LISTINGS] = listings.into();
    }
    Ok(Done::of(env))
}

async fn access(ctx: &Ctx, command: AccessCommand) -> Result<Done, Done> {
    match command {
        AccessCommand::Ensure(a) => ensure(ctx, a).await,
        // ⟨M03⟩ wave 5 (U12): the policy flow; narrowing applies at once, widening
        // needs the owner's typed `yes` (m03-plan §5 item 6).
        AccessCommand::LockBehavior(a) => policy(ctx, m03_cmd::lock_behavior_action(&a)?).await,
        AccessCommand::ConnectionPolicy(a) => {
            policy(ctx, m03_cmd::connection_policy_action(&a)?).await
        }
        // ⟨M05⟩ Answered in `dispatch` by `m05_cmd` before the executor starts.
        AccessCommand::Allow(_) | AccessCommand::Stop(_) | AccessCommand::DefaultProfile(_) => {
            Err(Done::of(usage("unsupported command")))
        }
        // ⟨M08 W4 U2b-3a; U0-Q7(a)⟩ `--request-id` is optional, and minted by no one: a
        // release without it is sent as before. `--request-epoch` travels as every command's
        // (`Ctx::request_epoch`).
        AccessCommand::Release {
            binding_id,
            request_id,
            request_epoch: _,
        } => {
            let binding_id = parse("binding ID", BindingId::parse, &binding_id)?;
            let request_id = request_id
                .map(|r| parse("request ID", RequestId::parse, &r))
                .transpose()?;
            one(
                ctx,
                true,
                Request::Release(ReleaseRequest {
                    binding_id,
                    request_id,
                }),
            )
            .await
        }
        AccessCommand::Revoke {
            grant_id,
            request_id,
            request_epoch: _,
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
                    grant_id: Some(grant_id),
                    request_id,
                    target: None,
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
        AccessCommand::Pause { target } => {
            let policy_id = parse("policy ID", PolicyId::parse, policy_of(&target)?)?;
            policy(
                ctx,
                PolicyAction::Pause {
                    policy_id: Some(policy_id),
                    target: None,
                },
            )
            .await
        }
        AccessCommand::Resume { target } => {
            let policy_id = parse("policy ID", PolicyId::parse, policy_of(&target)?)?;
            policy(
                ctx,
                PolicyAction::Resume {
                    policy_id: Some(policy_id),
                    target: None,
                },
            )
            .await
        }
        AccessCommand::Cutoff { target, at, clear } => {
            let policy_id = parse("policy ID", PolicyId::parse, policy_of(&target)?)?;
            let action = if clear {
                PolicyAction::ClearCutoff {
                    policy_id: Some(policy_id),
                    target: None,
                }
            } else {
                let at = at.unwrap_or_default();
                let at: Timestamp = at.parse().map_err(|_| {
                    Done::of(usage(
                        "--at must be an RFC 3339 instant with an explicit offset",
                    ))
                })?;
                PolicyAction::Cutoff {
                    policy_id: Some(policy_id),
                    at,
                    target: None,
                }
            };
            policy(ctx, action).await
        }
    }
}

/// The policy ID of an `access pause|resume|cutoff` target. `dispatch` hands every M05
/// target (`--profile`, `--workspace`, `--all`) to `m05_cmd::targeted` before this runs,
/// so only the policy-ID form arrives; anything else is a usage error here too.
fn policy_of(target: &AccessTarget) -> Result<&str, Done> {
    target
        .policy_id()
        .ok_or_else(|| Done::of(usage("unsupported command")))
}

/// `--issuer-ca`: the same CA for every pair the request names. Refused before anything
/// is sent unless the owner is at this terminal, and unless the pairs are named.
fn named_issuers(
    ctx: &Ctx,
    ca: Option<&str>,
    scope: &std::collections::BTreeSet<AccessPairRef>,
) -> Result<Vec<heimdall_contract::request::PairIssuer>, Done> {
    let Some(ca) = ca else {
        return Ok(Vec::new());
    };
    let ca_fingerprint = parse(
        "issuer CA fingerprint",
        heimdall_contract::ids::CaFingerprint::parse,
        ca,
    )?;
    if scope.is_empty() {
        return Err(Done::of(usage(
            "--issuer-ca names the CA of the pairs given with --pair",
        )));
    }
    if !ctx.interactive() {
        return Err(Done::of(error_value(error(
            Code::InteractionRequired,
            "naming the issuing CA needs the runner's owner at this terminal: nothing was sent",
        ))));
    }
    Ok(scope
        .iter()
        .map(|pair| heimdall_contract::request::PairIssuer {
            pair: pair.clone(),
            ca_fingerprint: ca_fingerprint.clone(),
        })
        .collect())
}

async fn ensure(ctx: &Ctx, a: EnsureArgs) -> Result<Done, Done> {
    let scope: std::collections::BTreeSet<AccessPairRef> =
        a.pairs.iter().map(|p| pair(p)).collect::<Result<_, _>>()?;
    let pair_issuers = named_issuers(ctx, a.issuer_ca.as_deref(), &scope)?;
    let until = match (a.until, a.for_duration) {
        (Some(u), _) => Some(DeadlineIntent::Absolute(u)),
        (None, Some(d)) => Some(DeadlineIntent::Duration(d)),
        (None, None) => None,
    };
    let request = EnsureRequest {
        profile: Some(parse("profile", ProfileId::parse, &a.profile)?),
        profile_revision: None,
        scope,
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
        // ⟨M03⟩ wave 5 (U12): `--strict` asks for strict owned connections; absent,
        // the request is M02's byte for byte (`connection` is skipped when `None`).
        connection: a.strict.then(m03_cmd::strict_connection),
        context: None,
        covered_only: false,
        pair_issuers,
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
    /// Explain a wait without changing the request or polling the runtime separately.
    async fn request_with_wait(
        &mut self,
        ctx: &Ctx,
        request: Request,
        operation: Option<&OperationId>,
    ) -> Envelope<serde_json::Value> {
        use heimdall_contract::enrollment::EnrollmentRequest;

        let (what, operation) = match &request {
            Request::Ensure(EnsureRequest {
                wait: WaitMode::Sync { .. },
                ..
            }) => ("access to be ready", operation),
            Request::Observe(ObserveRequest::Operation {
                operation_id,
                wait_ms: Some(_),
            }) => ("the operation to finish", Some(operation_id)),
            Request::Setup(setup) if setup.request_id().is_some() => ("setup to finish", operation),
            Request::Enrollment(EnrollmentRequest::Reconcile { operation_id, .. }) => {
                ("enrollment recovery", Some(operation_id))
            }
            Request::Enrollment(
                EnrollmentRequest::Apply { .. }
                | EnrollmentRequest::Verify { .. }
                | EnrollmentRequest::Remove { .. },
            ) => ("the enrollment change", operation),
            _ => return self.request(request).await,
        };
        let operation = operation.cloned();
        output::explain_wait(!ctx.json, what, operation.as_ref(), self.request(request)).await
    }
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
pub(crate) async fn attend_first<S: Session>(s: &mut S, ctx: &Ctx) -> Result<(), Done> {
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

/// Complete a pending approval, or return the request's latest answer. Each stale
/// decision needs the original request and a fresh confirmation of its replacement.
pub(crate) async fn retry_stale_decision<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    request: &Request,
    mut env: Envelope<serde_json::Value>,
    stale_retries: &mut usize,
    mut confirm: impl AsyncFnMut(
        &mut S,
        &mut P,
        &str,
        &Envelope<serde_json::Value>,
    ) -> Envelope<serde_json::Value>,
) -> Result<Envelope<serde_json::Value>, Envelope<serde_json::Value>> {
    loop {
        let Some(decision) = pending_decision(&env) else {
            return Err(env);
        };
        let decided = confirm(s, p, &decision, &env).await;
        match decided.code {
            Code::Ok => return Ok(decided),
            Code::DecisionStale if *stale_retries > 0 => {
                *stale_retries -= 1;
                env = s.request_with_wait(ctx, request.clone(), None).await;
                if pending_decision(&env).as_deref() == Some(decision.as_str()) {
                    return Err(decided);
                }
            }
            _ => return Err(decided),
        }
    }
}

pub(crate) async fn approve_request<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    request: &Request,
    env: Envelope<serde_json::Value>,
    stale_retries: &mut usize,
) -> Result<Envelope<serde_json::Value>, Envelope<serde_json::Value>> {
    if !ctx.interactive() {
        return Err(env);
    }
    retry_stale_decision(
        s,
        p,
        ctx,
        request,
        env,
        stale_retries,
        async |s, p, decision, pending| {
            confirm_and_decide(
                s,
                p,
                ctx,
                decision,
                Verdict::Approve,
                pending.operation_id.clone(),
                Some(&pending.code),
            )
            .await
        },
    )
    .await
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
    let request = Request::Ensure(request);
    let env = s.request_with_wait(ctx, request.clone(), None).await;
    let env = match approve_request(s, p, ctx, &request, env, &mut 2).await {
        Ok(decided) => {
            s.request_with_wait(ctx, request, decided.operation_id.as_ref())
                .await
        }
        Err(env) => env,
    };
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
pub(crate) async fn policy_flow<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    action: PolicyAction,
) -> Done {
    // M01's actions keep M01's rule; the M03 actions attend only when widening
    // (`PolicyAction::is_widening`), so a narrowing never sends `Attend`. ⟨M05⟩ So do the
    // M05 narrowing actions (`stop`, `remove`, `narrow_scope`).
    let owner_present = match &action {
        PolicyAction::Pause { .. }
        | PolicyAction::Stop { .. }
        | PolicyAction::Remove { .. }
        | PolicyAction::NarrowScope { .. } => false,
        PolicyAction::SetLockBehavior { .. } | PolicyAction::SetConnectionPolicy { .. } => {
            action.is_widening()
        }
        _ => true,
    };
    if owner_present && let Err(refused) = attend_first(s, ctx).await {
        return refused;
    }
    let request = Request::Policy(action);
    let env = s.request(request.clone()).await;
    let env = if owner_present {
        approve_request(s, p, ctx, &request, env, &mut 2)
            .await
            .unwrap_or_else(|env| env)
    } else {
        env
    };
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
            let mut client = session(ctx, false).await?;
            let env = client
                .request_with_wait(
                    ctx,
                    Request::Observe(ObserveRequest::Operation {
                        operation_id,
                        wait_ms: Some(timeout_ms),
                    }),
                    None,
                )
                .await;
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
pub(crate) async fn confirm_and_decide<S: Session, P: Prompter>(
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
            cwd: None,
            redact: false,
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
    if answered.is_some()
        && record
            .as_ref()
            .and_then(|r| r.get("request"))
            .is_none_or(serde_json::Value::is_null)
    {
        return not_confirmed(
            Some(decision),
            operation,
            "the recorded request could not be read",
        );
    }
    // ⟨M05⟩ Review M05-W3-R01: a `create` whose recorded scope is missing cannot show what
    // approval applies, so it is never approved here (it can still be denied).
    if verdict == Verdict::Approve
        && let Some(why) = record.as_ref().and_then(crate::m05_cmd::approve_block)
    {
        return not_confirmed(Some(decision), operation, why);
    }
    let verb = match verdict {
        Verdict::Approve => "Approve",
        Verdict::Deny => "Deny",
    };
    let answer_line = answered.map_or_else(String::new, |code| {
        format!("The runtime answered {code} with this decision reference.\n")
    });
    // ⟨ADR-0008 §17.27 items 3 and 4⟩ Generic completion has no preview of its own: the
    // recorded request's human form and every disclosure in words are shown before the
    // prompt, in every output mode (stderr). Approving one that discloses lock
    // continuity needs the runtime's conditional lock text; without it the approval is
    // refused (exit 3) and nothing is sent.
    let recorded = record
        .as_ref()
        .and_then(|r| r.get("request"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    // ⟨M05⟩ A `trust_workspace` record whose approval also acknowledges the M03 lock
    // disclosure (`lock_disclosure: true`) needs the same conditional text.
    let lock = if crate::enroll_cmd::carries_lock_disclosure(&recorded)
        || crate::m05_cmd::acknowledges_lock(&recorded)
    {
        let text = crate::m03_cmd::fetch_lock_disclosure_text(s).await;
        if text.is_none() && verdict == Verdict::Approve {
            return crate::m03_cmd::lock_text_unavailable(Some(decision), operation);
        }
        text
    } else {
        None
    };
    let text = match &record {
        Some(r) => {
            // ⟨M05⟩ Review M05-W3-RC01: the recorded request's human copy is inert JSON.
            let request =
                crate::output::human_json(r.get("request").unwrap_or(&serde_json::Value::Null));
            let field = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("?").to_owned();
            let expired = r.get("expired").and_then(serde_json::Value::as_bool) == Some(true);
            let human = format!(
                "{}{}",
                crate::enroll_cmd::recorded_preview(&field("kind"), &recorded),
                // ⟨M05⟩ The first-trust, reconcile and policy-review texts (spec §5.2).
                crate::m05_cmd::recorded_preview(r, lock.as_deref())
            );
            let disclosures =
                crate::enroll_cmd::recorded_disclosure_prose(&recorded, lock.as_deref());
            format!(
                "{answer_line}{human}Owner decision {decision}\n  kind: {}\n  expires: {}{}\n  recorded request (exactly what {} applies to):\n{}\n\
                 {disclosures}\
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
    let request = s.request(Request::Decide(DecideRequest {
        decision_id,
        verdict,
    }));
    output::explain_wait(
        !ctx.json && verdict == Verdict::Approve && operation.is_some(),
        "the approved request",
        operation.as_ref(),
        request,
    )
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
pub(crate) async fn decide_flow<S: Session, P: Prompter>(
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
    let mut env = confirm_and_decide(s, p, ctx, decision, verdict, None, None).await;
    if verdict == Verdict::Approve
        && env.code == Code::DecisionStale
        && !ctx.json
        && let Some(serde_json::Value::String(message)) = env.data.pointer_mut("/error/message")
    {
        message.push_str(
            ". This request changed. Ask the requester to retry it for a fresh approval.",
        );
    }
    Done::of(env)
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
    } else if name == "primitives" {
        // ⟨rev7⟩ ADR-0013 §9, D7.
        Some(heimdall_contract::primitives::index())
    } else if name == "reasons" {
        // ⟨rev7⟩ ADR-0013 D8.
        Some(heimdall_contract::reasons::table())
    } else {
        heimdall_contract::schema::public_schemas()
            .into_iter()
            // ⟨rev7⟩ The declared schemas are shown by name too.
            .chain(heimdall_contract::schema::declared_schemas())
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

fn schema_export(
    out: &std::path::Path,
    config_out: &std::path::Path,
    project_out: &std::path::Path,
    json: bool,
) -> ExitCode {
    let result = (|| -> std::io::Result<Vec<String>> {
        std::fs::create_dir_all(out)?;
        std::fs::create_dir_all(config_out)?;
        std::fs::create_dir_all(project_out)?;
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
        // ⟨rev7⟩ ADR-0013 D7, D8: the primitive index and the reason table, same rendering.
        for (name, doc) in [
            ("primitives.json", heimdall_contract::primitives::index()),
            ("reasons.json", heimdall_contract::reasons::table()),
        ] {
            let path = out.join(name);
            let mut text = serde_json::to_string_pretty(&doc).map_err(std::io::Error::other)?;
            text.push('\n');
            std::fs::write(&path, text)?;
            written.push(path.display().to_string());
        }
        // ⟨rev7⟩ The declared schemas (no live document carries them yet), in their own
        // directory.
        let declared = out.join(heimdall_contract::schema::DECLARED_DIR);
        std::fs::create_dir_all(&declared)?;
        for s in heimdall_contract::schema::declared_schemas() {
            let path = declared.join(format!("{}.schema.json", s.name));
            let mut text =
                serde_json::to_string_pretty(&s.schema).map_err(std::io::Error::other)?;
            text.push('\n');
            std::fs::write(&path, text)?;
            written.push(path.display().to_string());
        }
        // ⟨rev5⟩ The trusted-work file formats (ADR-0006 §17), same rendering.
        for s in heimdall_contract::schema::project_schemas() {
            let path = project_out.join(format!("{}.schema.json", s.name));
            let mut text =
                serde_json::to_string_pretty(&s.schema).map_err(std::io::Error::other)?;
            text.push('\n');
            std::fs::write(&path, text)?;
            written.push(path.display().to_string());
        }
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

/// ⟨rev7⟩ The command-tree golden and the help lint (ADR-0013 D3, D14).
#[cfg(test)]
#[path = "cli_tree_tests.rs"]
mod tree_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// ⟨M08 U2b-2; ASK-FLAGS⟩ Every command that takes `--request-id` takes `--request-epoch`,
    /// which needs `--request-id`, and the given command's epoch is the invocation's kept one
    /// ([`parse_args`]), whichever command it is.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn every_request_id_command_takes_its_request_epoch() {
        use clap::CommandFactory as _;
        fn walk(cmd: &clap::Command, path: &mut Vec<String>, found: &mut Vec<String>) {
            let ids: Vec<&str> = cmd.get_arguments().map(|a| a.get_id().as_str()).collect();
            if ids.contains(&"request_id") {
                found.push(path.join(" "));
                assert!(
                    ids.contains(&REQUEST_EPOCH_ARG),
                    "{path:?} has no --request-epoch"
                );
                let epoch = cmd
                    .get_arguments()
                    .find(|a| a.get_id().as_str() == REQUEST_EPOCH_ARG)
                    .unwrap();
                assert_eq!(epoch.get_long(), Some("request-epoch"), "{path:?}");
            } else {
                assert!(
                    !ids.contains(&REQUEST_EPOCH_ARG),
                    "{path:?}: an epoch with no ID"
                );
            }
            for sub in cmd.get_subcommands() {
                path.push(sub.get_name().to_owned());
                walk(sub, path, found);
                path.pop();
            }
        }
        let mut found = Vec::new();
        walk(&Cli::command(), &mut Vec::new(), &mut found);
        // ⟨M08 W4 U2b-3a; U0-Q7(a)⟩ `access release` is the 21st.
        assert_eq!(found.len(), 21, "{found:?}");
        assert!(found.iter().any(|p| p == "access release"), "{found:?}");
        let epoch = |argv: &[&str]| {
            parse_args(std::iter::once("heimdall").chain(argv.iter().copied()))
                .map(|c| c.request_epoch)
        };
        use heimdall_contract::lifecycle::RestoreEpoch;
        assert_eq!(
            epoch(&[
                "access",
                "revoke",
                "grant_x",
                "--request-id",
                "r",
                "--request-epoch",
                "7"
            ])
            .unwrap(),
            Some(RestoreEpoch(7))
        );
        assert_eq!(
            epoch(&[
                "setup",
                "apply",
                "--request-id",
                "r",
                "--request-epoch",
                "3"
            ])
            .unwrap(),
            Some(RestoreEpoch(3))
        );
        assert_eq!(
            epoch(&[
                "access",
                "release",
                "binding_x",
                "--request-id",
                "r",
                "--request-epoch",
                "5"
            ])
            .unwrap(),
            Some(RestoreEpoch(5))
        );
        assert_eq!(
            epoch(&[
                "environment",
                "invite",
                "env_x",
                "--role",
                "viewer",
                "--public-key",
                "k",
                "--request-id",
                "r",
                "--request-epoch",
                "2",
            ])
            .unwrap(),
            Some(RestoreEpoch(2))
        );
        assert_eq!(
            epoch(&["access", "revoke", "grant_x", "--request-id", "r"]).unwrap(),
            None
        );
        // Without the request ID it names, the epoch is a usage error.
        assert!(epoch(&["access", "revoke", "grant_x", "--request-epoch", "7"]).is_err());
        assert!(
            epoch(&[
                "access",
                "revoke",
                "grant_x",
                "--request-id",
                "r",
                "--request-epoch",
                "-1"
            ])
            .is_err()
        );
    }

    /// ⟨M08 U2b-2 follow-up B⟩ The retry arguments `run` and `environment invite` report are
    /// the ones they take back: the request ID with the epoch beside it, or the ID alone when
    /// the runtime reported no epoch.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn retry_args_are_taken_back_as_reported() {
        use heimdall_contract::lifecycle::RestoreEpoch;
        let id = RequestId::parse("req-0123456789abcdef").unwrap();
        let reported = retry_args(&id, Some(RestoreEpoch(4)));
        assert_eq!(
            reported,
            "--request-id req-0123456789abcdef --request-epoch 4"
        );
        assert_eq!(retry_args(&id, None), "--request-id req-0123456789abcdef");
        for command in [
            &["run", "--profile", "dev"][..],
            &[
                "environment",
                "invite",
                "env_x",
                "--role",
                "viewer",
                "--public-key",
                "k",
            ][..],
        ] {
            let program: &[&str] = if command[0] == "run" {
                &["--", "ssh"]
            } else {
                &[]
            };
            let argv = std::iter::once("heimdall")
                .chain(command.iter().copied())
                .chain(reported.split(' '))
                .chain(program.iter().copied());
            let cli = parse_args(argv).unwrap();
            assert_eq!(cli.request_epoch, Some(RestoreEpoch(4)), "{command:?}");
            let given = match cli.command {
                Some(Command::Run(a)) => a.request_id,
                Some(Command::Environment(m06_cmd::EnvironmentCommand::Invite(a))) => a.request_id,
                _ => None,
            };
            assert_eq!(given.as_deref(), Some(id.as_str()), "{command:?}");
        }
    }

    use clap::CommandFactory as _;

    #[test]
    fn command_tree_is_consistent() {
        Cli::command().debug_assert();
    }

    /// M01's retired "not available" text (ADR-0007 §12.30 item 4), built at run time
    /// so that the source scan below never finds this test's own needle.
    fn retired_text() -> String {
        ["not available", "in this build"].join(" ")
    }

    /// The source of every module that answers an M02 command (m02-plan U8, U9, U10),
    /// and of the dispatch and output shared by all of them.
    const M02_SOURCES: &[(&str, &str)] = &[
        ("cli.rs", include_str!("cli.rs")),
        ("output.rs", include_str!("output.rs")),
        ("setup_cmd.rs", include_str!("setup_cmd.rs")),
        ("connect_cmd.rs", include_str!("connect_cmd.rs")),
        ("run_cmd.rs", include_str!("run_cmd.rs")),
        ("launch_flow.rs", include_str!("launch_flow.rs")),
        ("doctor_cmd.rs", include_str!("doctor_cmd.rs")),
        ("catalog_cmd.rs", include_str!("catalog_cmd.rs")),
        ("uninstall_cmd.rs", include_str!("uninstall_cmd.rs")),
        ("tui/mod.rs", include_str!("tui/mod.rs")),
        ("tui/model.rs", include_str!("tui/model.rs")),
        ("tui/view.rs", include_str!("tui/view.rs")),
        ("tui/worker.rs", include_str!("tui/worker.rs")),
    ];

    /// Stands for [`resolvable_program`] in [`M02_COMMAND_LINES`].
    const PROGRAM: &str = "<resolvable program>";

    /// An absolute path of a program that resolves (`run` resolves its program before
    /// it looks at its IDs, so a line meant to be refused for an invalid work ID needs
    /// one): `/bin/sh` on Unix, and on Windows, where it does not exist, this test binary.
    /// ⟨M05⟩ `run` without `--profile` is no longer refused: it activates by the working
    /// directory (ADR-0011 §3.2), so it contacts the runtime.
    fn resolvable_program() -> String {
        if cfg!(windows) {
            std::env::current_exe()
                .unwrap_or_else(|e| panic!("current_exe: {e}"))
                .to_string_lossy()
                .into_owned()
        } else {
            "/bin/sh".to_owned()
        }
    }

    /// One command line per M02 command whose own handler refuses it before any
    /// runtime, terminal or account-file contact, with the handler's exit status.
    /// (`uninstall` and `identity adopt --from-agent` read the account's SSH directory
    /// or agent first, so their through-the-binary check, with a scratch SSH home, is
    /// `e2e_cli_m01::w0_m02_cli_commands_report_not_available_and_never_panic`.)
    const M02_COMMAND_LINES: &[(&[&str], ExitCode)] = &[
        (
            &["setup", "repair", "nonsense", "rerender"],
            ExitCode::Usage,
        ),
        (&["connect", "--", "-oProxyCommand=x"], ExitCode::Usage),
        (
            &["run", "--work-id", "not a work id", "--", PROGRAM],
            ExitCode::Usage,
        ),
        (&["doctor", "--active-probe", "everything"], ExitCode::Usage),
        (&["tui"], ExitCode::Usage),
        (
            &[
                "destination",
                "add",
                "lab",
                "--hostname",
                "h.example.invalid",
            ],
            ExitCode::Usage,
        ),
        (&["identity", "remove", "not an identity"], ExitCode::Usage),
        (
            &["profile", "create", "p", "--pair", "no-colon"],
            ExitCode::Usage,
        ),
    ];

    /// `w0_m02_cli_commands_report_not_available_and_never_panic`, in-process form,
    /// repurposed (ADR-0007 §12.30 item 4; m02-plan U0b, §5 item 4; the binary-level
    /// form is hosted by a `heimdall` package target, wave-0 verify E6). The wave-0
    /// envelope is retired, so **no** M02 command may answer its text:
    ///
    /// * no line of code (comments aside) of any module answering an M02 command
    ///   carries the retired text, so no handler can print it;
    /// * every M02 command parses and is answered by its own handler: each line of
    ///   [`M02_COMMAND_LINES`] gets its handler's refusal and exit status, and never
    ///   reaches for the runtime (no runtime directory is created under the scratch
    ///   Heimdall home it names).
    #[test]
    fn w0_m02_commands_answer_not_available_and_never_contact_the_runtime() {
        let needle = retired_text();
        for (name, source) in M02_SOURCES {
            for (n, line) in source.lines().enumerate() {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                assert!(
                    !code.contains(&needle),
                    "{name}:{}: an M02 command still answers the retired text",
                    n + 1
                );
            }
        }
        let scratch = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let program = resolvable_program();
        for (i, (line, expected)) in M02_COMMAND_LINES.iter().enumerate() {
            let home = scratch.path().join(format!("home-{i}"));
            let home_arg = home.to_string_lossy().into_owned();
            let argv: Vec<&str> = ["heimdall", "--json", "--non-interactive", "--home"]
                .into_iter()
                .chain(std::iter::once(home_arg.as_str()))
                .chain(line.iter().map(|arg| {
                    if *arg == PROGRAM {
                        program.as_str()
                    } else {
                        *arg
                    }
                }))
                .collect();
            let cli = Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("{line:?} must parse: {:?}", e.kind()));
            assert!(
                matches!(
                    cli.command,
                    Some(
                        Command::Setup(_)
                            | Command::Connect(_)
                            | Command::Run(_)
                            | Command::Doctor(_)
                            | Command::Tui
                            | Command::Destination(_)
                            | Command::Identity(_)
                            | Command::Profile(_)
                    )
                ),
                "{line:?} is an M02 command"
            );
            assert_eq!(dispatch(cli), *expected, "{line:?}");
            assert!(
                !home.join("run").exists(),
                "{line:?} reached for the runtime"
            );
        }
    }

    /// ADR-0007 §12.30 item 5: a bare `heimdall` opens the TUI only with a terminal on
    /// stdin and stdout and neither `--json` nor `--non-interactive`; every other
    /// combination is `status`.
    #[test]
    fn bare_heimdall_is_the_tui_only_on_a_terminal_without_json() {
        for json in [false, true] {
            for non_interactive in [false, true] {
                for stdin_tty in [false, true] {
                    for stdout_tty in [false, true] {
                        let expected = if !json && !non_interactive && stdin_tty && stdout_tty {
                            Bare::Tui
                        } else {
                            Bare::Status
                        };
                        assert_eq!(
                            bare(json, non_interactive, stdin_tty, stdout_tty),
                            expected,
                            "json {json}, non-interactive {non_interactive}, stdin {stdin_tty}, stdout {stdout_tty}"
                        );
                    }
                }
            }
        }
        // A bare line parses with no subcommand.
        let cli = Cli::try_parse_from(["heimdall"]).unwrap_or_else(|e| panic!("{:?}", e.kind()));
        assert!(cli.command.is_none());
    }

    /// ⟨M02⟩ U8 (wave 3b): `run` and `connect` keep their argument trees, and every
    /// refusal that needs no runtime (an existing `--meta-file`, a descriptor that is
    /// not open, a program that cannot run, an invalid work ID, an option-like alias)
    /// answers before any runtime contact: the Heimdall home is never created.
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
        let program = resolvable_program();
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
            (
                vec!["run", "--work-id", "not a work id", "--", &program],
                ExitCode::Usage,
            ),
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
        requests: Vec<Request>,
        answers: std::collections::HashMap<&'static str, Vec<Envelope<serde_json::Value>>>,
        attended: bool,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                sent: Vec::new(),
                requests: Vec::new(),
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
            self.requests.push(request);
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

    #[test]
    fn decision_stale_retries_with_the_same_key_and_resets_the_confirmation() {
        const FRESH: &str = "dec_10112233445566778899aabbccddeeff";
        const LAST: &str = "dec_20112233445566778899aabbccddeeff";
        let pending = |id: &str| {
            let mut env = approval_required();
            if let Some(next) = &mut env.next {
                next.decision_ref = Some(id.to_owned());
            }
            env
        };
        let listed = |id: &str| {
            let mut env = listing();
            env.data["decisions"][0]["decision_id"] = id.into();
            env.data["decisions"][0]["request"]["current_scope"] = id.into();
            env
        };
        for second in [
            Answer::Yes,
            Answer::No,
            Answer::Eof,
            Answer::TimedOut,
            Answer::Interrupted,
        ] {
            let request = ensure_request();
            let mut s = Recorder::new()
                .answer("ensure", pending(DEC))
                .answer("ensure", pending(FRESH))
                .answer("inspect", listed(DEC))
                .answer("inspect", listed(FRESH))
                .answer("decide", error_value(error(Code::DecisionStale, "moved")));
            let mut p = script(&[Answer::Yes, second]);
            let done = block(ensure_flow(&mut s, &mut p, &tty(), request.clone(), false));
            assert_eq!(p.shown.len(), 2);
            assert!(p.shown[1].contains(FRESH));
            assert!(p.shown[1].contains("current_scope"));
            let decided: Vec<_> = s
                .requests
                .iter()
                .filter_map(|r| match r {
                    Request::Decide(d) => Some(d.decision_id.as_str()),
                    _ => None,
                })
                .collect();
            let ensured: Vec<_> = s
                .requests
                .iter()
                .filter_map(|r| match r {
                    Request::Ensure(r) => Some(r),
                    _ => None,
                })
                .collect();
            if second == Answer::Yes {
                assert_eq!(decided, [DEC, FRESH]);
                assert_eq!(ensured, [&request; 3]);
                assert_eq!(done.env.code, Code::Ok);
            } else {
                assert_eq!(decided, [DEC]);
                assert_eq!(ensured, [&request; 2]);
                assert_eq!(done.env.code, Code::InteractionRequired);
            }
        }

        let mut s = Recorder::new();
        for id in [DEC, FRESH, LAST] {
            s = s
                .answer("ensure", pending(id))
                .answer("inspect", listed(id))
                .answer("decide", error_value(error(Code::DecisionStale, id)));
        }
        let done = block(ensure_flow(
            &mut s,
            &mut script(&[Answer::Yes; 3]),
            &tty(),
            ensure_request(),
            false,
        ));
        assert_eq!(done.env.code, Code::DecisionStale);
        assert_eq!(done.env.data["error"]["message"], LAST);
        assert_eq!(
            s.sent
                .iter()
                .filter(|kind| kind.as_str() == "ensure")
                .count(),
            3
        );
    }

    #[test]
    fn decision_approve_by_reference_reports_stale_plainly() {
        let stale = error_value(error(Code::DecisionStale, "moved"));
        for json in [true, false] {
            let ctx = Ctx { json, ..tty() };
            let mut s = Recorder::new()
                .answer("inspect", listing())
                .answer("decide", stale.clone());
            let done = block(decide_flow(
                &mut s,
                &mut script(&[Answer::Yes]),
                &ctx,
                DEC,
                Verdict::Approve,
            ));
            assert_eq!(s.sent, ["attend", "inspect", "decide"]);
            assert_eq!(done.env.code, Code::DecisionStale);
            if json {
                assert_eq!(done.env.data, stale.data);
            } else {
                let message = done.env.data["error"]["message"]
                    .as_str()
                    .unwrap_or_default();
                assert!(message.contains("This request changed"));
                assert!(message.contains("requester to retry"));
            }
        }
    }

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
            request_epoch: None,
        }
    }

    /// ⟨M06 W5⟩ `--issuer-ca` names the CA of every `--pair`, only for the owner at a
    /// terminal; without the pairs, without a terminal, or with a malformed fingerprint
    /// nothing is built to send.
    #[test]
    fn the_hidden_issuer_ca_needs_named_pairs_and_a_terminal() {
        let ca = format!("SHA256:{}", "A".repeat(43));
        let scope: std::collections::BTreeSet<AccessPairRef> =
            [pair("h1:deploy").unwrap_or_else(|_| unreachable!())]
                .into_iter()
                .collect();
        let none = std::collections::BTreeSet::new();
        assert!(matches!(named_issuers(&tty(), None, &scope), Ok(v) if v.is_empty()));
        let named = named_issuers(&tty(), Some(&ca), &scope).unwrap_or_else(|_| unreachable!());
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].ca_fingerprint.as_str(), ca);
        let code = |r: Result<Vec<heimdall_contract::request::PairIssuer>, Done>| match r {
            Err(d) => d.env.code,
            Ok(_) => Code::Ok,
        };
        assert_eq!(
            code(named_issuers(&tty(), Some(&ca), &none)),
            Code::UsageError
        );
        assert_eq!(
            code(named_issuers(&tty(), Some("not-a-fingerprint"), &scope)),
            Code::UsageError
        );
        let piped = Ctx {
            stdin_tty: false,
            ..tty()
        };
        assert_eq!(
            code(named_issuers(&piped, Some(&ca), &scope)),
            Code::InteractionRequired
        );
        let forbidden = Ctx {
            non_interactive: true,
            ..tty()
        };
        assert_eq!(
            code(named_issuers(&forbidden, Some(&ca), &scope)),
            Code::InteractionRequired
        );
        // Never with `--environment`: a forwarded request's CA is the controller's own.
        assert!(
            Cli::try_parse_from([
                "heimdall",
                "access",
                "ensure",
                "--profile",
                "dev",
                "--work-id",
                "w",
                "--request-id",
                "r",
                "--environment",
                "env_00000000000000000000000000000000",
                "--issuer-ca",
                &ca,
            ])
            .is_err()
        );
    }

    fn ensure_request() -> EnsureRequest {
        EnsureRequest {
            profile: Some(ProfileId::parse("dev").unwrap_or_else(|_| unreachable!())),
            profile_revision: None,
            scope: std::collections::BTreeSet::new(),
            environment: None,
            work_id: WorkId::parse("w").unwrap_or_else(|_| unreachable!()),
            until: None,
            required_capabilities: RequiredCapabilities::default(),
            request_id: RequestId::parse("r").unwrap_or_else(|_| unreachable!()),
            interaction: heimdall_contract::request::InteractionMode::Interactive,
            wait: WaitMode::default(),
            // not strict (M02's request)
            connection: None,
            context: None,
            covered_only: false,
            pair_issuers: Vec::new(),
        }
    }

    /// ⟨M03⟩ wave 5 (U12; m03-plan §5 item 6): the M03 policy actions attend only when
    /// widening. A narrowing (`revoke-on-lock`, `--existing strict`, `--multiplexing
    /// disabled`) sends the request alone, never `Attend`, never a prompt; a widening
    /// (`continue`, `--existing graceful`, `--multiplexing owned`) attends first and sends
    /// `decide` only on a typed `yes`.
    #[test]
    fn m03_policy_actions_attend_only_when_widening() {
        use heimdall_contract::managed::{ExistingConnectionsMode, LockBehavior, MultiplexingMode};
        let pol = || PolicyId::parse("pol").unwrap_or_else(|_| unreachable!());
        let narrowing = [
            PolicyAction::SetLockBehavior {
                policy_id: pol(),
                behavior: LockBehavior::RevokeOnLock,
            },
            PolicyAction::SetConnectionPolicy {
                policy_id: pol(),
                existing: Some(ExistingConnectionsMode::Strict),
                multiplexing: Some(MultiplexingMode::Disabled),
            },
        ];
        for action in narrowing {
            let mut s = Recorder::new();
            let mut p = script(&[]);
            let done = block(policy_flow(&mut s, &mut p, &tty(), action.clone()));
            assert_eq!(s.sent, ["policy"], "narrowing never attends: {action:?}");
            assert_eq!(done.env.code, Code::Ok);
        }
        let widening = [
            PolicyAction::SetLockBehavior {
                policy_id: pol(),
                behavior: LockBehavior::Continue,
            },
            PolicyAction::SetConnectionPolicy {
                policy_id: pol(),
                existing: Some(ExistingConnectionsMode::Graceful),
                multiplexing: None,
            },
            PolicyAction::SetConnectionPolicy {
                policy_id: pol(),
                existing: None,
                multiplexing: Some(MultiplexingMode::OwnedMasters),
            },
        ];
        for action in widening {
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
            let mut p = script(&[Answer::Eof]);
            let done = block(policy_flow(&mut s, &mut p, &tty(), action));
            assert_eq!(s.sent, ["attend", "policy", "inspect"]);
            assert_eq!(done.exit, ExitCode::InteractionRequired);
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
                    policy_id: Some(PolicyId::parse("pol").unwrap_or_else(|_| unreachable!())),
                    target: None,
                },
                PolicyAction::ClearCutoff {
                    policy_id: Some(PolicyId::parse("pol").unwrap_or_else(|_| unreachable!())),
                    target: None,
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
            PolicyAction::Resume {
                policy_id: Some(pol()),
                target: None,
            },
            PolicyAction::ClearCutoff {
                policy_id: Some(pol()),
                target: None,
            },
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
            PolicyAction::Pause {
                policy_id: Some(pol()),
                target: None,
            },
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
            request_epoch: None,
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
