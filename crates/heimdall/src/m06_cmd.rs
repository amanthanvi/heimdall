//! M06 command surface (ADR-0012 §2–§5, §9 item 6; ADR-0006 §18; m06-plan U0, U2; the
//! orchestrator's naming ruling for the G08 freeze).
//!
//! * **`environment`** (op `remote_environment`; no `env` alias): `add`, `invite`, `join`,
//!   `revoke-client`, `remove`, `update`, `status`, answered by the controller operations
//!   (`heimdall_app::remote_env`) with this binary's ports: K_mgmt in the platform store
//!   (`heimdall_credential::mgmt`), the catalog's verified access read from the state
//!   database (the M03 enrollment's approved target: the owner-approved host key), the
//!   bootstrap's interactive ssh session, management sessions (the isolated `-F`
//!   configuration from `heimdall_sshconf::mgmt`, the per-session K_mgmt agent, and the IPC
//!   client over `ssh`'s standard streams), and the owner's typed `yes` on this terminal.
//!   **The controller's environment records** (`remote_environment_pins`): read read-only;
//!   ⟨rev6.3; ADR-0006 §18.7 item 6⟩ written directly under the instance lock when no runtime
//!   runs, or through the running runtime's `Request::ControllerRecord` (the runtime is its
//!   store's single writer), so `add`, `join`, `remove` and `device retire` work beside a
//!   running runtime. The TTY confirmations and the ssh bootstrap stay here.
//! * **`device retire`**: the locally attended decision (a terminal and a typed `yes`;
//!   `--non-interactive` or a non-terminal stdin is refused `INTERACTION_REQUIRED` before
//!   anything is read).
//! * ⟨M06 W3⟩ **`route add|remove|prefer`** and **`transport enable|disable|adopt-roost`**:
//!   typed inputs checked here (a malformed one is `USAGE_ERROR` before the runtime is
//!   contacted or the home created), then the `route.*` / `transport.*` form sent to the
//!   runtime (started on demand: they are effectful), which runs `heimdall_app::routes::ops`
//!   and `heimdall_app::transport`. ⟨M06 W5; ADR-0006 §18.9 item 8⟩ A widening (a route or
//!   endpoint that adds exposure, a roost) from an interactive terminal is sent on an
//!   attended session and answers `APPROVAL_REQUIRED` with the reference of its local
//!   decision record; `heimdall decision approve <ref>` on a terminal at this host shows
//!   the exact request and delta, asks for the typed confirmation and applies it. From a
//!   non-interactive session it is answered `INTERACTION_REQUIRED`, the detail naming what
//!   it would add (⟨ADR-0006 §18.9 item 10⟩), and nothing is recorded.
//!   `roost adopt` is `transport adopt-roost`.
//! * **`transport rotate`** (⟨rev6.3⟩ ADR-0006 §18.7 item 10): `transport.rotate` sent to the
//!   runtime when one runs (it rotates K_iroh and tells every recorded runner through
//!   [`ManagementAnnouncer`], which `service run` wires in); with no runtime, the same
//!   rotation under the instance lock. Retry-safe: a runner that fails stays pending and is
//!   named, a re-run mints no further key, the old key goes once nobody is pending.
//! * **`route connect`**: the `ProxyCommand` helper that rendered SSH configuration names
//!   (`heimdall_sshconf::routes`). **Hidden from help and frozen**: its words and arguments
//!   are a compatibility surface of every rendered alias. It runs `heimdall_app::routes::
//!   route_connect` over its standard streams with the runtime's `route.resolve_binding`.
//! * **`transport serve --environment <id>`**: hidden; the supervised serve child.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Subcommand, ValueEnum};
use heimdall_app::OpError;
use heimdall_app::remote_env::{
    AccessCatalog, AddInput, Confirmation, ControllerPorts, EnvironmentRegistry, InvitationBundle,
    InviteInput, InviteOutcome, LocalConfirm, ManagementCall, ManagementHop, ManagementRoute,
    ManagementSession, ManagementSessions, MgmtKeyInfo, MgmtKeyPort, MgmtKeyUnavailable,
    RemoteEnvController, RemoteEnvironmentRecord, SessionHello, SessionName, SessionTarget,
    VerifiedAccess, controller_fault, on_this_controller, ssh as env_ssh,
};
use heimdall_contract::envelope::{EffectStatus, Envelope, NextAction, reason};
use heimdall_contract::ids::{
    AccountName, ClientId, DestinationId, EnvironmentId, IrohEndpointId, KeyFingerprint, RequestId,
};
use heimdall_contract::remote::Role;
use heimdall_contract::request::InteractionMode;
use heimdall_contract::{Code, ExitCode};
use heimdall_credential::mgmt::{
    self, MgmtKeyStore, MgmtSigner, MgmtStoreAvailability, MgmtStoreError, SessionAgent,
};

use crate::client::{CLIENT_NAME, Ctx};
use crate::output;

// --- the command trees -------------------------------------------------------------------

/// `environment` subcommands (ADR-0012 §3; ADR-0006 §18 `remote_environment`).
#[derive(Debug, Subcommand)]
pub enum EnvironmentCommand {
    /// Bootstrap a runner over your existing, host-verified access: one interactive ssh
    /// session in which the runner's `heimdall remote init` enrolls this device's
    /// management key as owner, confirmed at the runner. Also repairs a lost pin or key.
    Add(EnvAddArgs),
    /// Invite another device's management key to a runner. You confirm its fingerprint
    /// here; the runner holds the invitation until it is confirmed there.
    Invite(EnvInviteArgs),
    /// On the invited device: join from the owner's invitation bundle after confirming the
    /// runner's host key and environment ID. `--show-key` prints this device's management
    /// key for the owner first.
    Join(EnvJoinArgs),
    /// Revoke one client on a runner (narrowing; no decision).
    RevokeClient(EnvRevokeArgs),
    /// Revoke this device on a runner, then forget the runner. The management key is kept.
    Remove(EnvTargetArgs),
    /// Ask a runner for its explicit, checksum-verified binary update.
    Update(EnvTargetArgs),
    /// Recheck a runner that went owner-only: probe a real management session to it and
    /// send the runner what the probes observed. Owner only. Nothing is lifted here: the
    /// runner's owner lifts the downgrade at the runner, within 15 minutes.
    Recheck(EnvTargetArgs),
    /// Confirm, on this controller, that the pauses and cutoffs it delivered to a runner
    /// were lifted there. Lists each one awaiting this and acknowledges only those listed;
    /// one delivered later needs its own. Needs a terminal and a typed yes. Issuance for the
    /// runner resumes only when its report shows each lift as well; neither alone reopens it.
    ResumeIssuance(EnvTargetArgs),
    /// This controller's view of its runners. Opens no connection.
    Status(EnvStatusArgs),
}

/// `environment add` arguments.
#[derive(Debug, Args)]
pub struct EnvAddArgs {
    /// The catalog destination whose verified access reaches the runner account.
    #[arg(long, value_name = "DESTINATION")]
    pub destination: String,
    /// The runner account.
    #[arg(long, value_name = "ACCOUNT")]
    pub account: String,
    /// The runner's Heimdall executable (an absolute path on the runner).
    #[arg(long, value_name = "PATH")]
    pub runner_program: String,
    /// The runner's Heimdall home (an absolute path on the runner; the management line's
    /// forced command names it).
    #[arg(long, value_name = "PATH")]
    pub runner_home: String,
    /// The expected SHA-256 of the runner's Heimdall executable (64 lowercase hex), checked
    /// on the runner before anything is written.
    #[arg(long, value_name = "HEX")]
    pub runner_sha256: Option<String>,
    /// A label for the runner.
    #[arg(long, value_name = "TEXT")]
    pub label: Option<String>,
}

/// A runner role (ADR-0012 §3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RoleArg {
    /// Every permission.
    Owner,
    /// View and request.
    Requester,
    /// View only.
    Viewer,
}

impl From<RoleArg> for Role {
    fn from(r: RoleArg) -> Role {
        match r {
            RoleArg::Owner => Role::Owner,
            RoleArg::Requester => Role::Requester,
            RoleArg::Viewer => Role::Viewer,
        }
    }
}

/// `environment invite` arguments.
#[derive(Debug, Args)]
pub struct EnvInviteArgs {
    /// The runner environment.
    #[arg(value_name = "ENVIRONMENT")]
    pub environment: String,
    /// The role to offer.
    #[arg(long, value_enum)]
    pub role: RoleArg,
    /// The invited device's management key (the line its `environment join --show-key`
    /// printed).
    #[arg(long, value_name = "KEY")]
    pub public_key: String,
    /// Reuse the request ID the pending answer named, after confirming at the runner.
    #[arg(long, value_name = "ID")]
    pub request_id: Option<String>,
    /// The restore epoch the request ID was first sent with (the answer's `request_epoch`):
    /// give it with the same `--request-id` to retry. Without it, the runner's current epoch
    /// is used.
    #[arg(long, value_name = "N", requires = "request_id")]
    pub request_epoch: Option<u64>,
    /// Let the invited device reach the runner over Iroh: it sends its own endpoint ID when
    /// it joins (confirmed at the runner with the invitation).
    #[arg(long)]
    pub iroh: bool,
}

/// `environment join` arguments.
#[derive(Debug, Args)]
pub struct EnvJoinArgs {
    /// The invitation bundle file (`-`: standard input).
    #[arg(
        value_name = "BUNDLE",
        conflicts_with = "show_key",
        required_unless_present = "show_key"
    )]
    pub bundle: Option<PathBuf>,
    /// Print this device's management key and fingerprint (created when absent), for the
    /// owner's `environment invite`.
    #[arg(long)]
    pub show_key: bool,
}

/// `environment revoke-client` arguments.
#[derive(Debug, Args)]
pub struct EnvRevokeArgs {
    /// The runner environment.
    #[arg(value_name = "ENVIRONMENT")]
    pub environment: String,
    /// The client to revoke.
    #[arg(value_name = "CLIENT")]
    pub client: String,
}

/// An environment argument.
#[derive(Debug, Args)]
pub struct EnvTargetArgs {
    /// The runner environment.
    #[arg(value_name = "ENVIRONMENT")]
    pub environment: String,
}

/// `environment status` arguments.
#[derive(Debug, Args)]
pub struct EnvStatusArgs {
    /// One runner environment; every one when absent.
    #[arg(value_name = "ENVIRONMENT")]
    pub environment: Option<String>,
}

/// `device` subcommands (ADR-0012 §3.4).
#[derive(Debug, Subcommand)]
pub enum DeviceCommand {
    /// Retire this controller device: revoke it on every runner, then destroy its
    /// management key. Needs a terminal and a typed `yes`.
    Retire,
}

/// `route` subcommands (ADR-0012 §5; ADR-0006 §18 `route.*`).
#[derive(Debug, Subcommand)]
pub enum RouteCommand {
    /// Approve a route for a destination.
    ///
    /// A route that adds exposure (an Iroh route beyond the minimal policy) needs a decision
    /// at this host.
    Add(RouteAddArgs),
    /// Remove an approved route.
    ///
    /// Narrowing: no decision is needed.
    Remove(RouteTargetArgs),
    /// Prefer one approved route.
    ///
    /// A preference among already-approved routes needs no new decision.
    Prefer(RouteTargetArgs),
    /// The ProxyCommand helper rendered SSH configuration names (frozen; not a user
    /// surface).
    #[command(hide = true)]
    Connect(crate::cli::PlannedArgs),
}

/// `route add` arguments: exactly one of `--direct`, `--jump`, `--iroh`.
#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("kind").required(true).args(["direct", "jump", "iroh"])))]
pub struct RouteAddArgs {
    /// The catalog destination.
    #[arg(value_name = "DESTINATION")]
    pub destination: String,
    /// A direct TCP route: `host` or `host:port` (`[v6]:port` for an IPv6 literal).
    #[arg(long, value_name = "HOST[:PORT]")]
    pub direct: Option<String>,
    /// A single-hop jump through another catalog destination.
    #[arg(long, value_name = "DESTINATION")]
    pub jump: Option<String>,
    /// An Iroh route to a serving endpoint ID (under the minimal exposure policy).
    #[arg(long, value_name = "ENDPOINT")]
    pub iroh: Option<String>,
    /// The Iroh endpoint's direct address (`ip:port`), repeatable.
    #[arg(long = "address", value_name = "IP:PORT")]
    pub addresses: Vec<String>,
    /// A relay this Iroh route may use (`https://…` or `http://…`), repeatable. Each relay
    /// adds exposure: the route then needs a decision approved on a terminal at this host,
    /// which names every relay. A URL with a user name or password, a query string or a
    /// fragment is refused. A relay URL must not carry a credential anywhere, its path
    /// included: Heimdall stores it as given and shows only its scheme, host, port and a
    /// short digest.
    #[arg(long = "relay", value_name = "URL")]
    pub relays: Vec<String>,
}

/// A destination and one of its routes.
#[derive(Debug, Args)]
pub struct RouteTargetArgs {
    /// The catalog destination.
    #[arg(value_name = "DESTINATION")]
    pub destination: String,
    /// The route.
    #[arg(value_name = "ROUTE")]
    pub route: String,
}

/// `transport` subcommands (ADR-0012 §1, §2, §2.8; ADR-0006 §18 `transport.*`).
#[derive(Debug, Subcommand)]
pub enum TransportCommand {
    /// Enable the Iroh transport.
    ///
    /// Generates this device's endpoint key in a verified platform store. `--serve` (a
    /// widening, decided at this host) also serves this host's sshd to enrolled clients.
    Enable(TransportEnableArgs),
    /// Disable the Iroh transport.
    ///
    /// Stops serving, destroys the endpoint key and removes every route that names it. It
    /// forgets the enrolled clients' endpoints but does not revoke any client: a later
    /// enable serves the clients still enrolled. To remove one client's Iroh access
    /// permanently, revoke that client.
    Disable,
    /// Adopt an existing Pigeons roost as a route (a widening, confirmed locally).
    AdoptRoost(TransportAdoptArgs),
    /// Rotate this device's endpoint key.
    ///
    /// The new endpoint ID is announced to every recorded runner.
    Rotate,
    /// The supervised serve child `service run` starts (internal; not a user surface).
    #[command(hide = true)]
    Serve(crate::cli::PlannedArgs),
}

/// `transport enable` arguments.
#[derive(Debug, Args)]
pub struct TransportEnableArgs {
    /// Also serve this host's sshd to enrolled clients.
    #[arg(long)]
    pub serve: bool,
    /// The serve port (1-65535); without it the first successful bind's port is recorded
    /// and reused. Change it with `disable` then `enable`.
    #[arg(long, value_name = "PORT", requires = "serve", value_parser = clap::value_parser!(u16).range(1..))]
    pub port: Option<u16>,
    /// The local sshd port served to enrolled clients (1-65535; default 22), always on
    /// 127.0.0.1. Change it with `disable` then `enable`.
    #[arg(long, value_name = "PORT", requires = "serve", value_parser = clap::value_parser!(u16).range(1..))]
    pub sshd_port: Option<u16>,
}

/// `transport adopt-roost` arguments.
#[derive(Debug, Args)]
pub struct TransportAdoptArgs {
    /// The catalog destination the roost reaches.
    #[arg(value_name = "DESTINATION")]
    pub destination: String,
    /// The roost's endpoint ID.
    #[arg(long, value_name = "ENDPOINT")]
    pub endpoint: String,
}

// ADR-0012 §3.3, §3.6.
/// `remote` subcommands: the runner's side. Hidden and frozen.
#[derive(Debug, Subcommand)]
pub enum RemoteCommand {
    /// On the runner, in the bootstrap's interactive ssh session: mark this installation a
    /// remote runner and enroll the controller's management key as owner, after the owner
    /// confirms its fingerprint on this terminal.
    Init(RemoteInitArgs),
    /// The forced command of a management line: bridge one paired session to this
    /// installation's runtime. Takes exactly `--client <client> --home <absolute path>`.
    Serve(crate::cli::PlannedArgs),
    // ⟨M06 W3⟩
    /// This runner's trusted issuers (`issuer_trust`): add a controller's CA (a widening,
    /// typed `yes` on this terminal), remove one (narrowing), or list them.
    #[command(subcommand)]
    IssuerTrust(IssuerTrustCommand),
    // ⟨M06 W3⟩
    /// This runner's designated time source: set an owner client (a widening, typed `yes` on
    /// this terminal), clear it (narrowing), or show it.
    #[command(subcommand)]
    TimeSource(TimeSourceCommand),
    // ⟨M06 W3; ADR-0006 §18.7 item 19⟩
    /// This runner's sshd-policy downgrade.
    #[command(subcommand)]
    Policy(RemotePolicyCommand),
}

// ⟨M06 W3; ADR-0006 §18.7 item 19⟩
/// `remote policy` subcommands, run at the runner (an interactive ssh TTY counts).
#[derive(Debug, Subcommand)]
pub enum RemotePolicyCommand {
    /// Lift this runner's owner-only downgrade on the recheck an owner's controller left
    /// (`heimdall environment recheck`): shows that evidence, then needs a terminal and a
    /// typed `yes`. Refused without evidence, with evidence older than 15 minutes, or with
    /// evidence from before a later downgrade.
    Recheck,
}

// ⟨M06 W3; ADR-0006 §18.7 item 7⟩
/// `remote issuer-trust` subcommands, run at the runner (an interactive ssh TTY counts).
#[derive(Debug, Subcommand)]
pub enum IssuerTrustCommand {
    /// Trust the CA in FILE (one OpenSSH public key line) as the issuer of a paired owner
    /// controller. Needs a terminal and a typed `yes`.
    Add(IssuerTrustAddArgs),
    /// Stop trusting the CA with this fingerprint.
    Remove(IssuerTrustRemoveArgs),
    /// List the trusted CAs.
    List,
}

/// `remote issuer-trust add` arguments.
#[derive(Debug, Args)]
pub struct IssuerTrustAddArgs {
    /// A file holding the CA's OpenSSH public key line.
    pub file: PathBuf,
    /// The paired owner client whose issuer holds the CA (default: this runner's only active
    /// owner client).
    #[arg(long, value_name = "CLIENT")]
    pub controller: Option<String>,
}

/// `remote issuer-trust remove` arguments.
#[derive(Debug, Args)]
pub struct IssuerTrustRemoveArgs {
    /// The CA's fingerprint (`SHA256:…`).
    pub fingerprint: String,
}

// ⟨M06 W3; ADR-0006 §18.7 item 7⟩
/// `remote time-source` subcommands, run at the runner.
#[derive(Debug, Subcommand)]
pub enum TimeSourceCommand {
    /// Designate a paired owner client as this runner's time source. Needs a terminal and a
    /// typed `yes`.
    Set(TimeSourceSetArgs),
    /// Clear the designation.
    Clear,
    /// Show the designation.
    Show,
}

/// `remote time-source set` arguments.
#[derive(Debug, Args)]
pub struct TimeSourceSetArgs {
    /// The paired owner client.
    pub client: String,
}

/// `remote init` arguments (the bootstrap's remote command, `heimdall_app::remote_env::ssh::
/// remote_init_command`).
#[derive(Debug, Args)]
pub struct RemoteInitArgs {
    /// The client ID the controller records for itself.
    #[arg(long, value_name = "CLIENT")]
    pub owner_client: String,
    /// The controller's management key (`ssh-ed25519 <base64>`).
    #[arg(long, value_name = "KEY")]
    pub owner_key: String,
    /// The expected SHA-256 of this runner's Heimdall executable (64 lowercase hex): the
    /// bootstrap's checksum step; refused before anything is written when it differs.
    #[arg(long, value_name = "HEX")]
    pub expect_sha256: Option<String>,
    // ⟨M06 W3⟩
    /// The controller's CA public key (`ssh-ed25519 <base64>`): trusted for the owner client
    /// being enrolled, which also becomes this runner's time source, in the same
    /// confirmation. Absent when the controller has no issuer.
    #[arg(long, value_name = "KEY")]
    pub issuer_ca: Option<String>,
    // ⟨M06 W3⟩
    /// The controller device's Iroh endpoint ID (64 lowercase hex): the owner client is
    /// admitted to this runner over Iroh with it, in the same confirmation. Absent when the
    /// controller has no Iroh key. An endpoint already recorded is never replaced.
    #[arg(long, value_name = "ENDPOINT")]
    pub iroh_endpoint: Option<String>,
    // ⟨M06 W5; ADR-0012 §2.6, the 2026-11-22 bullets⟩
    /// Passed by a controller's bootstrap (`environment add`): after the enrollment, say
    /// plainly whether this runner's runtime is running and, when it is not, offer to start it
    /// in this same attended terminal session with a typed `yes` (`service run --runner`,
    /// detached). Declined, it prints the next step. Without the flag nothing is offered or
    /// started.
    #[arg(long)]
    pub offer_runtime_start: bool,
}

// --- route and transport ----------------------------------------------------------------

/// Parse `host`, `host:port` or `[v6]:port` (a bare IPv6 literal is a host).
fn parse_direct(text: &str) -> Result<heimdall_contract::route::RouteSpec, OpError> {
    let bad = || usage("--direct takes host, host:port or [v6]:port");
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').ok_or_else(bad)?;
        match tail {
            "" => (h.to_owned(), None),
            t => (
                h.to_owned(),
                Some(
                    t.strip_prefix(':')
                        .ok_or_else(bad)?
                        .parse::<u16>()
                        .map_err(|_| bad())?,
                ),
            ),
        }
    } else if text.matches(':').count() == 1 {
        let (h, p) = text.split_once(':').ok_or_else(bad)?;
        (h.to_owned(), Some(p.parse::<u16>().map_err(|_| bad())?))
    } else {
        (text.to_owned(), None)
    };
    if host.is_empty()
        || port == Some(0)
        || host
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || "\"'`$;&|<>\\".contains(c))
    {
        return Err(bad());
    }
    Ok(heimdall_contract::route::RouteSpec::Direct { host, port })
}

fn parse_destination(text: &str) -> Result<DestinationId, OpError> {
    DestinationId::parse(text).map_err(|_| usage("the destination ID is malformed"))
}

fn parse_endpoint(text: &str) -> Result<heimdall_contract::ids::IrohEndpointId, OpError> {
    heimdall_contract::ids::IrohEndpointId::parse(text)
        .map_err(|_| usage("the endpoint ID is malformed (64 lowercase hexadecimal characters)"))
}

/// ⟨rev6.5; ADR-0006 §18.9 item 9⟩ The exposure policy `--relay` names: each URL validated
/// and in its one spelling (`ExposurePolicy::with_normalized_relays`: sorted, each once),
/// checked here so a refused one is a usage error before the runtime is contacted. The
/// runtime runs the same check before it records anything. The message names the flag's
/// position and the class, never the URL (a refused one may hold a credential).
fn relay_policy(relays: &[String]) -> Result<heimdall_contract::route::ExposurePolicy, OpError> {
    let given = heimdall_contract::route::ExposurePolicy {
        infrastructure: heimdall_contract::route::InfrastructureProfile::Custom {
            relays: relays.to_vec(),
        },
        ..heimdall_contract::route::ExposurePolicy::default()
    };
    // ⟨rev7; D20⟩ An over-long URL is `item_too_large`, as the runtime answers it.
    if relays
        .iter()
        .any(|r| r.len() > heimdall_contract::route::RELAY_URL_MAX_BYTES)
    {
        return heimdall_app::routes::ops::canonical_exposure(&given);
    }
    let policy = given
        .with_normalized_relays()
        .map_err(|(i, why)| usage(&format!("--relay {} is refused: {}", i + 1, why.message())))?;
    // ⟨rev7; D20⟩ At most 8 distinct relays per route (`item_too_large`).
    heimdall_app::routes::ops::canonical_exposure(&policy)
}

/// Send `request` to the runtime (started when none runs: these are effectful), requiring
/// `capability`; the answer is printed as is. ⟨M06 W5; ADR-0006 §18.9 item 8⟩ With
/// `may_widen`, an interactive terminal's session is marked attended first (attendance
/// authorizes nothing by itself), so a widening is recorded as a local decision and
/// answered `APPROVAL_REQUIRED`; the human line then names the command that approves it.
fn send_to_runtime(
    ctx: &Ctx,
    capability: &str,
    request: heimdall_contract::request::Request,
    may_widen: bool,
    human: impl FnOnce(&serde_json::Value) -> String,
) -> ExitCode {
    let rt = match crate::service_cmd::current_thread() {
        Ok(rt) => rt,
        Err(env) => {
            let env = output::error_value(env);
            output::emit(&env, ctx.json);
            return output::exit_code_for(env.code, false);
        }
    };
    let env = rt.block_on(async {
        match crate::client::connect_requiring(ctx, true, &[capability]).await {
            Ok(mut client) => {
                if may_widen && ctx.interactive() {
                    let attended = client.attend().await;
                    if !attended.code.is_success() {
                        return attended;
                    }
                }
                client.request(request).await
            }
            Err(e) => output::error_value(*e),
        }
    });
    if env.code.is_success() {
        let text = human(&env.data);
        emit_ok(ctx, env.data, &text)
    } else {
        output::emit(&env, ctx.json);
        if !ctx.json
            && env.code == Code::ApprovalRequired
            && let Some(decision) = env.next.as_ref().and_then(|n| n.decision_ref.as_deref())
        {
            output::diagnostic(&format!(
                "nothing was changed. To review and approve it, run on a terminal at this \
                 host: heimdall decision approve {decision}"
            ));
        }
        output::exit_code_for(env.code, false)
    }
}

fn route_request(command: RouteCommand) -> Result<heimdall_contract::route::RouteRequest, OpError> {
    use heimdall_contract::route::{RouteRequest, RouteSpec};
    let route_id = |t: &str| {
        heimdall_contract::ids::RouteId::parse(t).map_err(|_| usage("the route ID is malformed"))
    };
    Ok(match command {
        RouteCommand::Add(a) => {
            if !a.addresses.is_empty() && a.iroh.is_none() {
                return Err(usage("--address belongs to an --iroh route"));
            }
            if !a.relays.is_empty() && a.iroh.is_none() {
                return Err(usage("--relay belongs to an --iroh route"));
            }
            let route = match (a.direct, a.jump, a.iroh) {
                (Some(d), None, None) => parse_direct(&d)?,
                (None, Some(j), None) => RouteSpec::Jump {
                    via: parse_destination(&j)?,
                },
                (None, None, Some(e)) => {
                    // ⟨rev7; D20, ruling R-A⟩ Each `--address` in its one spelling, within
                    // its bounds, as the runtime checks it (`item_too_large` over a bound).
                    let direct_addresses =
                        heimdall_app::routes::ops::canonical_direct_addresses(&a.addresses)?;
                    RouteSpec::Iroh {
                        endpoint: parse_endpoint(&e)?,
                        direct_addresses,
                        external_roost: false,
                    }
                }
                _ => return Err(usage("give exactly one of --direct, --jump, --iroh")),
            };
            // Without `--relay` the request is as before: no policy, the minimal one.
            let exposure = if a.relays.is_empty() {
                None
            } else {
                Some(relay_policy(&a.relays)?)
            };
            RouteRequest::Add {
                destination: parse_destination(&a.destination)?,
                route,
                exposure,
                request_id: heimdall_app::remote_env::new_request_id()?,
            }
        }
        RouteCommand::Remove(a) => RouteRequest::Remove {
            destination: parse_destination(&a.destination)?,
            route: route_id(&a.route)?,
        },
        RouteCommand::Prefer(a) => RouteRequest::Prefer {
            destination: parse_destination(&a.destination)?,
            route: route_id(&a.route)?,
            request_id: None,
        },
        RouteCommand::Connect(_) => return Err(usage("route connect is the helper")),
    })
}

/// `route …`.
pub(crate) fn route(ctx: &Ctx, command: RouteCommand) -> ExitCode {
    if let RouteCommand::Connect(a) = command {
        return route_connect(ctx, &a);
    }
    let verb = match &command {
        RouteCommand::Add(_) => "added",
        RouteCommand::Remove(_) => "removed",
        _ => "preferred",
    };
    let request = match route_request(command) {
        Ok(r) => r,
        Err(e) => return emit_error(ctx, e),
    };
    let may_widen = matches!(request, heimdall_contract::route::RouteRequest::Add { .. });
    send_to_runtime(
        ctx,
        heimdall_contract::ipc::capability::ROUTES_V1,
        heimdall_contract::request::Request::Route(request),
        may_widen,
        |data| {
            format!(
                "route {} {verb}; approved routes of {}, most preferred first: {}",
                data["route"].as_str().unwrap_or_default(),
                data["destination"].as_str().unwrap_or_default(),
                data["routes"]
                    .as_array()
                    .map(|r| r
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" "))
                    .unwrap_or_default()
            )
        },
    )
}

/// The exposure policy `transport enable`'s flags name: `None` (the minimal policy, as
/// before) unless a serve port or a non-default sshd port is named, so `--sshd-port 22` is
/// the same request as no flag (ADR-0006 §18.9 item 1: omitted when 22).
fn enable_exposure(
    port: Option<u16>,
    sshd_port: Option<u16>,
) -> Option<heimdall_contract::route::ExposurePolicy> {
    use heimdall_contract::route::{DEFAULT_SSHD_PORT, ExposurePolicy};
    let sshd_port = sshd_port.unwrap_or(DEFAULT_SSHD_PORT);
    (port.is_some() || sshd_port != DEFAULT_SSHD_PORT).then(|| ExposurePolicy {
        port,
        sshd_port,
        ..ExposurePolicy::default()
    })
}

/// `transport …`.
pub(crate) fn transport(ctx: &Ctx, command: TransportCommand) -> ExitCode {
    use heimdall_contract::route::TransportRequest;
    let request = match command {
        TransportCommand::Serve(a) => return transport_serve(&a),
        TransportCommand::Rotate => return transport_rotate(ctx),
        TransportCommand::Enable(a) => (|| {
            Ok(TransportRequest::Enable {
                serve: a.serve,
                exposure: enable_exposure(a.port, a.sshd_port),
                request_id: heimdall_app::remote_env::new_request_id()?,
            })
        })(),
        TransportCommand::Disable => Ok(TransportRequest::Disable),
        TransportCommand::AdoptRoost(a) => (|| {
            Ok(TransportRequest::AdoptRoost {
                destination: parse_destination(&a.destination)?,
                endpoint: parse_endpoint(&a.endpoint)?,
                exposure: None,
                request_id: heimdall_app::remote_env::new_request_id()?,
            })
        })(),
    };
    let request: TransportRequest = match request {
        Ok(r) => r,
        Err(e) => return emit_error(ctx, e),
    };
    let may_widen = matches!(
        request,
        TransportRequest::Enable { .. } | TransportRequest::AdoptRoost { .. }
    );
    send_to_runtime(
        ctx,
        heimdall_contract::ipc::capability::TRANSPORT_IROH_V1,
        heimdall_contract::request::Request::Transport(request),
        may_widen,
        |data| serde_json::to_string_pretty(data).unwrap_or_default(),
    )
}

/// The ports of the route helper (`route connect`): the runtime's `route.resolve_binding`
/// (a running runtime only: the binding the alias names is served by it), the catalog's
/// route facts read read-only, the jump leg's pin and access ([`jump_hop_for`]), and the
/// route-health report (`route.record_health`).
struct HelperPorts<'a> {
    ctx: &'a Ctx,
    db: PathBuf,
    paths: heimdall_runtime::paths::Paths,
    /// The alias's own rendered endpoint (`--endpoint`).
    endpoint: String,
    /// The projected pin file's text (`None`: absent or unreadable).
    pin_text: Option<String>,
}

/// A path as OpenSSH takes it on the command line: `/` separators on Windows.
fn ssh_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.into_owned()
    }
}

/// The keys the pin file `text` holds under `host_key_alias`, as `<type> <base64>`, sorted.
/// A line naming several hosts, a marker (`@cert-authority`, `@revoked`) or a hashed name
/// is not a pin and is not counted for this name.
fn pinned_keys(text: &str, host_key_alias: &str) -> Vec<String> {
    let mut keys: Vec<String> = text
        .lines()
        .filter_map(|line| {
            let mut words = line.split_ascii_whitespace();
            let (name, key_type, blob) = (words.next()?, words.next()?, words.next()?);
            (name == host_key_alias).then(|| format!("{key_type} {blob}"))
        })
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Whether the projected pin file holds **exactly** the catalog's pins for `host_key_alias`
/// (catalog-only trust, ADR-0012 §5.2): a destination with no catalog pin, or a pin file
/// that lags the catalog either way (a key the catalog no longer approves, or one it has
/// approved since), does not hold.
fn pins_hold(pin_text: Option<&str>, host_key_alias: &str, catalog: &[String]) -> bool {
    !catalog.is_empty() && pin_text.is_some_and(|t| pinned_keys(t, host_key_alias) == catalog)
}

/// The `ProxyCommand` text P renders for the helper, from this process's own program path
/// (`heimdall_sshconf::routes::helper_command`'s form; a unit test holds the two equal).
fn rendered_helper_command(program: &str, args: &heimdall_app::routes::HelperArgs) -> String {
    format!(
        "\"{program}\" route connect --destination {} --account {} --endpoint \"{}\"",
        args.destination, args.account, args.endpoint
    )
}

/// What a jump hop is built from, read from the catalog in one transaction.
struct JumpFacts {
    hostname: String,
    port: Option<u16>,
    account: AccountName,
    /// The jump pair's catalog pins.
    pins: Vec<String>,
    /// Existing access: the jump identity's endpoint and fingerprint.
    identity: Option<(Option<String>, String)>,
}

/// The jump leg's catalog pin and access (ADR-0012 §5.4; ADR-0010 §5 items 1–2).
///
/// * **The pin:** `hm-dest-<jump>` in the projected pin file, which must hold exactly the
///   catalog's pins for the jump (`pins_hold`); otherwise the route is not attempted.
/// * **A managed jump** (`same_grant`): the binding the alias's endpoint serves for the
///   **jump pair** must be the very binding resolved for the final pair. `same_grant` is
///   that answer, asked of the runtime for every jump attempted; anything else is
///   `route_dependency_out_of_scope`. Its identity is the jump pair's slot certificate at
///   the alias's own endpoint.
/// * **Existing access:** the jump identity's own endpoint and its materialized public key
///   file, outside the grant.
#[allow(clippy::too_many_arguments)]
fn jump_hop_for(
    route: &heimdall_domain::catalog::ApprovedRoute,
    access: heimdall_contract::environment::JumpAccess,
    facts: &JumpFacts,
    same_grant: bool,
    endpoint: &str,
    pin_file: &Path,
    pin_text: Option<&str>,
    paths: &heimdall_runtime::paths::Paths,
) -> Result<heimdall_app::routes::JumpHop, heimdall_app::routes::RouteHelperError> {
    use heimdall_app::routes::RouteHelperError;
    use heimdall_contract::environment::JumpAccess;
    let out_of_scope = || RouteHelperError::NoUsableRoute(reason::ROUTE_DEPENDENCY_OUT_OF_SCOPE);
    let host_key_alias = heimdall_domain::routes::host_key_alias(&route.jump)
        .ok_or(RouteHelperError::NoUsableRoute(reason::HOST_PIN_DEFEATED))?;
    if !pins_hold(pin_text, &host_key_alias, &facts.pins) {
        return Err(RouteHelperError::NoUsableRoute(reason::HOST_PIN_DEFEATED));
    }
    let (identity_agent, identity_file) = match access {
        JumpAccess::Managed => {
            if !same_grant {
                return Err(out_of_scope());
            }
            let slot = heimdall_localenv::projection::content::managed_slot_paths(
                &paths.state_dir,
                &route.jump,
            )
            .map_err(|_| out_of_scope())?;
            (endpoint.to_owned(), slot.cert_pub)
        }
        JumpAccess::Existing => {
            let Some((Some(agent), fingerprint)) = &facts.identity else {
                return Err(out_of_scope());
            };
            (
                agent.clone(),
                paths
                    .config_dir
                    .join(heimdall_localenv::materialize::key_file_path(fingerprint)),
            )
        }
        _ => return Err(out_of_scope()),
    };
    if !identity_file.is_file() {
        return Err(out_of_scope());
    }
    let mut algorithms: Vec<&str> = facts
        .pins
        .iter()
        .filter_map(|k| k.split(' ').next())
        .collect();
    algorithms.dedup();
    Ok(heimdall_app::routes::JumpHop {
        alias: route.jump_alias.clone(),
        hostname: facts.hostname.clone(),
        port: facts.port,
        user: facts.account.as_str().to_owned(),
        host_key_alias,
        pin_file: ssh_path(pin_file),
        host_key_algorithms: Some(algorithms.join(",")),
        identity_agent,
        identity_file: ssh_path(&identity_file),
        certificate_file: None,
    })
}

impl HelperPorts<'_> {
    fn pin_file(&self) -> PathBuf {
        self.paths
            .config_dir
            .join("keys")
            .join(heimdall_localenv::projection::HOST_PINS_FILE)
    }

    /// One `Request::Route` form to the running runtime, bounded.
    async fn ask(
        &self,
        request: heimdall_contract::route::RouteRequest,
    ) -> Result<Envelope<serde_json::Value>, heimdall_app::routes::RouteHelperError> {
        use heimdall_app::routes::RouteHelperError;
        let ask = async {
            let mut client = crate::client::connect_requiring(
                self.ctx,
                false,
                &[heimdall_contract::ipc::capability::ROUTES_V1],
            )
            .await
            .map_err(|_| RouteHelperError::Unavailable)?;
            Ok(client
                .request(heimdall_contract::request::Request::Route(request))
                .await)
        };
        tokio::time::timeout(HELPER_RUNTIME_BOUND, ask)
            .await
            .map_err(|_| RouteHelperError::Unavailable)?
    }

    /// `route.record_health` (best effort: a lost report costs only the report).
    async fn report(
        &self,
        result: heimdall_contract::route::RouteHealthPayload,
        host_pin_defeated: Option<String>,
    ) {
        let _ = self
            .ask(heimdall_contract::route::RouteRequest::RecordHealth {
                endpoint: self.endpoint.clone(),
                result,
                host_pin_defeated,
            })
            .await;
    }

    /// The catalog facts of the jump destination of `route`, by point lookups of exactly
    /// that destination and its identity in one read-only transaction; `None` when the
    /// destination is absent or not managed, or the read failed.
    fn jump_facts(&self, route: &heimdall_domain::catalog::ApprovedRoute) -> Option<JumpFacts> {
        let state =
            heimdall_store::Store::open_read_only(&self.db, Arc::new(heimdall_store::NoFaults))
                .ok()?;
        state
            .transaction(|tx| {
                let Some(heimdall_domain::catalog::DestinationDefinition::Managed {
                    hostname,
                    port,
                    account,
                    identity,
                    ..
                }) = tx.destination(&route.jump)?.map(|d| d.definition)
                else {
                    return Ok(None);
                };
                let pins = heimdall_app::routes::catalog_pins(tx, &route.jump_pair)?;
                let identity = tx.identity(&identity)?.map(|i| {
                    (
                        i.source.endpoint().map(|e| e.locator.clone()),
                        i.fingerprint,
                    )
                });
                Ok(Some(JumpFacts {
                    hostname,
                    port,
                    account,
                    pins,
                    identity,
                }))
            })
            .ok()
            .flatten()
    }
}

/// How long the helper waits for one answer of the runtime.
const HELPER_RUNTIME_BOUND: Duration = Duration::from_secs(15);

#[async_trait::async_trait]
impl heimdall_app::routes::RouteHelperPorts for HelperPorts<'_> {
    async fn resolve_route_binding(
        &self,
        destination: &DestinationId,
        account: &AccountName,
        endpoint: &str,
    ) -> Result<heimdall_app::routes::RouteBinding, heimdall_app::routes::RouteHelperError> {
        use heimdall_app::routes::{ResolvedRouteBinding, RouteHelperError};
        let env = self
            .ask(heimdall_contract::route::RouteRequest::ResolveBinding {
                destination: destination.clone(),
                account: account.clone(),
                endpoint: endpoint.to_owned(),
            })
            .await?;
        if !env.code.is_success() {
            return Err(
                if env.data["error"]["reason"] == reason::ROUTE_BINDING_AMBIGUOUS {
                    RouteHelperError::BindingAmbiguous
                } else {
                    RouteHelperError::Unavailable
                },
            );
        }
        serde_json::from_value::<ResolvedRouteBinding>(env.data)
            .map(Into::into)
            .map_err(|_| RouteHelperError::Unavailable)
    }

    async fn route_view(
        &self,
    ) -> Result<heimdall_domain::catalog::RouteCatalogView, heimdall_app::routes::RouteHelperError>
    {
        heimdall_store::Store::open_read_only(&self.db, Arc::new(heimdall_store::NoFaults))
            .and_then(|s| heimdall_app::routes::route_catalog_view(&s))
            .map_err(|_| heimdall_app::routes::RouteHelperError::Unavailable)
    }

    /// ⟨rev7; ruled 2026-11-25⟩ The pair's route facts by key, never the whole catalog.
    async fn route_view_of(
        &self,
        pair: &heimdall_domain::scope::AccessPair,
    ) -> Result<heimdall_domain::catalog::RouteCatalogView, heimdall_app::routes::RouteHelperError>
    {
        heimdall_store::Store::open_read_only(&self.db, Arc::new(heimdall_store::NoFaults))
            .and_then(|s| heimdall_app::routes::route_catalog_view_of(&s, &pair.destination))
            .map_err(|_| heimdall_app::routes::RouteHelperError::Unavailable)
    }

    async fn jump_hop(
        &self,
        route: &heimdall_domain::catalog::ApprovedRoute,
        access: heimdall_contract::environment::JumpAccess,
        binding: &heimdall_app::routes::RouteBinding,
    ) -> Result<heimdall_app::routes::JumpHop, heimdall_app::routes::RouteHelperError> {
        use heimdall_app::routes::RouteHelperError;
        // ⟨rev7⟩ ADR-0013 §6.3 (D21): a hop that is absent or malformed (no managed catalog
        // destination), or unreadable (the read failed), leaves this route undetermined; the
        // route is not attempted, as any route refused here.
        let facts = self
            .jump_facts(route)
            .ok_or(RouteHelperError::NoUsableRoute(reason::ROUTE_UNDETERMINED))?;
        // ⟨ADR-0012 §5.4; ADR-0010 §5 item 2⟩ The same-grant check, on every jump attempted:
        // the binding the alias's endpoint serves for the jump pair is the binding resolved
        // for the final pair (so its grant, and the certificate the endpoint lists for the
        // jump, are that grant's). Asked of the runtime now, not inferred from the plan.
        let same_grant = match access {
            heimdall_contract::environment::JumpAccess::Managed => self
                .resolve_route_binding(
                    &route.jump_pair.destination,
                    &route.jump_pair.account,
                    &self.endpoint,
                )
                .await
                .is_ok_and(|jump| jump.binding == binding.binding && jump.grant == binding.grant),
            _ => false,
        };
        jump_hop_for(
            route,
            access,
            &facts,
            same_grant,
            &self.endpoint,
            &self.pin_file(),
            self.pin_text.as_deref(),
            &self.paths,
        )
    }

    async fn record_health(&self, payload: heimdall_contract::route::RouteHealthPayload) {
        self.report(payload, None).await;
    }
}

/// ⟨M06 W5 `w5n`; ADR-0012 §5.2⟩ The helper's own check before it tries any route: when it
/// runs as the proxy of the destination's projected alias, that alias must hold the
/// destination's catalog pin **effectively**.
///
/// 1. `ssh -G <alias>` is read (the user's configuration as the client that started the
///    helper reads it). **When the alias's effective `ProxyCommand` is not this very helper
///    invocation, the helper is not acting for the projected alias** (it was named by hand,
///    by another host entry, or with other arguments). ⟨`w5o` item 8⟩ Where P renders the
///    alias through the helper, such an invocation is refused (`proxycommand`); only where
///    P renders no helper section for it (in V1, a runner) does nothing below apply
///    ([`not_the_projected_proxy`]).
/// 2. Otherwise the projected pin file must hold exactly the catalog's pins for
///    `hm-dest-<id>`, and for the jump destination of each approved jump route the catalog
///    pins (`userknownhostsfile` otherwise: the file `ssh` trusts is not the catalog's);
/// 3. and the effective configuration must meet
///    `heimdall_registry::routes::verify_effective`: strict checking, the expected
///    `HostKeyAlias`, the pin file as the only trust source, no multiplexing but the
///    slot's own path, and this helper as the proxy.
///
/// Returns the setting that does not hold, named as `ssh -G` prints it (`unreadable` when
/// the effective configuration could not be read: fail closed). A refusal here means no
/// route is tried, so a projected alias whose pin a user setting defeats never connects
/// through the helper. Command-line options of the client that started the helper are not
/// visible here and are not covered (ADR-0012 §5.2 names the configuration).
async fn alias_pin_defeat(
    ports: &HelperPorts<'_>,
    args: &heimdall_app::routes::HelperArgs,
    ssh: &Path,
    config: Option<&Path>,
    program: &str,
) -> Option<String> {
    let pair = args.pair();
    // The destination's alias and pins, and the pins of the jump destination of each of
    // its approved jump routes that the catalog pins at all.
    let catalog =
        heimdall_store::Store::open_read_only(&ports.db, Arc::new(heimdall_store::NoFaults))
            .and_then(|s| {
                s.transaction(|tx| {
                    let alias = tx.destination(&pair.destination)?.map(|d| d.alias);
                    let pins = heimdall_app::routes::catalog_pins(tx, &pair)?;
                    let all = heimdall_app::routes::helper_pins(tx, &pair.destination)?
                        .unwrap_or_default();
                    Ok((alias, pins, all))
                })
            });
    let Ok((Some(alias), pins, all)) = catalog else {
        return Some("unreadable".to_owned());
    };
    // ⟨M08 U1b; M06-F6⟩ With the OpenSSH environment fill, as every M06 launch.
    let Some(effective) =
        heimdall_app::routes::verify::effective_alias_config(ssh, config, &alias, OPENSSH_FILL)
            .await
    else {
        return Some("unreadable".to_owned());
    };
    let command = rendered_helper_command(program, args);
    if !alias_proxy_is(&effective, &command) {
        // ⟨M06 W5 `w5o` item 8⟩ Not the alias's own proxy. Fail closed wherever this
        // installation projects the destination's alias through the helper: there the only
        // invocation that may connect is the one P renders for that alias.
        let p = std::fs::read_to_string(ports.paths.config_dir.join("ssh_config")).ok();
        return not_the_projected_proxy(p.as_deref(), &alias);
    }
    let Some(host_key_alias) = heimdall_domain::routes::host_key_alias(&args.destination) else {
        return Some("hostkeyalias".to_owned());
    };
    if !pins_hold(ports.pin_text.as_deref(), &host_key_alias, &pins) {
        return Some("userknownhostsfile".to_owned());
    }
    // A jump hop's pin that differs from the catalog's is a trust defect of the pin file,
    // not an unreachable route: nothing is tried (never failed over to another route).
    let mut jumps: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for (destination, key) in all {
        if destination != pair.destination.as_str() {
            jumps.entry(destination).or_default().push(key);
        }
    }
    for (jump, mut keys) in jumps {
        keys.sort();
        keys.dedup();
        let name = format!("{}{jump}", heimdall_domain::routes::HOST_KEY_ALIAS_PREFIX);
        if !pins_hold(ports.pin_text.as_deref(), &name, &keys) {
            return Some("userknownhostsfile".to_owned());
        }
    }
    let expect = heimdall_app::routes::PinExpectation {
        host_key_alias,
        pin_file: ssh_path(&ports.pin_file()),
        owned_control_path: heimdall_localenv::projection::content::checked_mux_path(
            &ports.paths.runtime_dir,
            &args.destination,
        )
        .ok()
        .map(|p| ssh_path(&p)),
        proxy: heimdall_app::routes::ExpectedProxy::Helper(command),
    };
    heimdall_app::routes::verify_effective(&effective, &expect)
        .err()
        .map(|defeated| defeated.setting.to_owned())
}

/// ⟨M06 W5 `w5o` item 8; the ruling on `w5n` Q2⟩ The verdict for a helper invocation that
/// is **not** the effective `ProxyCommand` of the destination's alias (it was named by hand,
/// by another `Host` entry, or with other arguments), from P's text `p`:
///
/// * P renders `alias` through the route helper: **refused** (`proxycommand`). On such an
///   installation only the invocation P renders may connect, and it is verified against
///   the catalog pin; anything else would run the routes under trust the catalog does not
///   control;
/// * P renders no helper section for `alias` (or there is no P): `None`, the check does not
///   apply. This is an installation that projects no helper alias for the destination, in
///   V1 a **runner** (ADR-0012 §5, ruling of 2026-11-22: a runner has no catalog pin and no
///   alias projection of its grants). There the client that names the helper states its
///   own host trust; A26's runner-as-dialer steps are that mechanism.
fn not_the_projected_proxy(p: Option<&str>, alias: &str) -> Option<String> {
    p.is_some_and(|p| projected_helper_aliases(p).iter().any(|a| a.alias == alias))
        .then(|| "proxycommand".to_owned())
}

/// Whether the effective configuration `ssh -G` printed names exactly `command` as its
/// `ProxyCommand` (one line, the whole value).
fn alias_proxy_is(effective: &str, command: &str) -> bool {
    let mut proxies = effective
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter_map(|l| l.split_once(' '))
        .filter(|(k, _)| k.eq_ignore_ascii_case("proxycommand"))
        .map(|(_, v)| v);
    matches!((proxies.next(), proxies.next()), (Some(v), None) if v == command)
}

/// The `-F` argument of an `ssh -G` under a debug build's test configuration (never in a
/// release build, where `ssh` reads the account's own tree and this is `None`): the scratch
/// SSH home's user configuration, or `none` when that home has no configuration file (as
/// an account without `~/.ssh/config` has none: `ssh -F <missing file>` would fail, where
/// the account's own missing file does not).
fn seam_ssh_config(hooks: &crate::testcfg::LaunchHooks) -> Option<PathBuf> {
    hooks.ssh_home.as_ref().map(|home| {
        let config = home.join(".ssh").join("config");
        if config.is_file() {
            config
        } else {
            PathBuf::from("none")
        }
    })
}

/// One helper alias of P, as P's own section states it (what must hold effectively).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectedHelperAlias {
    pub(crate) alias: String,
    pub(crate) expect: heimdall_app::routes::PinExpectation,
}

/// The aliases P renders through the route helper, each with the expectation its own
/// section states: its `ProxyCommand` text, `HostKeyAlias`, pin file and `ControlPath`.
pub(crate) fn projected_helper_aliases(p: &str) -> Vec<ProjectedHelperAlias> {
    fn unquoted(v: &str) -> String {
        v.trim().trim_matches('"').replace("%%", "%")
    }
    let mut out = Vec::new();
    let mut current: Option<(String, Vec<(String, String)>)> = None;
    let mut flush = |section: Option<(String, Vec<(String, String)>)>| {
        let Some((alias, lines)) = section else {
            return;
        };
        let get = |k: &str| lines.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let (Some(proxy), Some(host_key_alias), Some(pin_file)) = (
            get("ProxyCommand"),
            get("HostKeyAlias"),
            get("UserKnownHostsFile"),
        ) else {
            return;
        };
        let control = get("ControlPath").map(|v| unquoted(&v));
        out.push(ProjectedHelperAlias {
            alias,
            expect: heimdall_app::routes::PinExpectation {
                host_key_alias,
                pin_file: unquoted(&pin_file),
                owned_control_path: control.filter(|c| !c.eq_ignore_ascii_case("none")),
                proxy: heimdall_app::routes::ExpectedProxy::Helper(proxy),
            },
        });
    };
    for line in p.lines() {
        if let Some(name) = line.strip_prefix("Host ") {
            flush(current.take());
            current = Some((name.trim().to_owned(), Vec::new()));
        } else if let Some((_, lines)) = &mut current
            && let Some((k, v)) = line.trim_start().split_once(' ')
        {
            lines.push((k.to_owned(), v.to_owned()));
        }
    }
    flush(current.take());
    out
}

/// ⟨M06 W5 `w5n`; ADR-0012 §5.2 "at projection time"⟩ After an apply: `ssh -G` each alias P
/// renders through the route helper and require what its own section states to hold
/// effectively (`heimdall_registry::routes::verify_effective`). Returns each alias that
/// does not verify with the setting (`unreadable` when its effective configuration could
/// not be read). Nothing is changed here: the route helper refuses such an alias before it
/// tries any route, so it is never left connecting under that trust.
pub(crate) async fn verify_projected_helper_aliases(ctx: &Ctx) -> Vec<(String, String)> {
    use heimdall_app::routes::verify::{RouteVerifyError, verify_projected_alias};
    let Ok(paths) = ctx.paths() else {
        return Vec::new();
    };
    let Ok(p) = std::fs::read_to_string(paths.config_dir.join("ssh_config")) else {
        return Vec::new();
    };
    let aliases = projected_helper_aliases(&p);
    if aliases.is_empty() {
        return Vec::new();
    }
    let config = crate::testcfg::launch_hooks(&|n| std::env::var_os(n))
        .ok()
        .and_then(|h| seam_ssh_config(&h));
    let ssh = ssh_client().unwrap_or_default();
    let mut defeated = Vec::new();
    for a in aliases {
        // ⟨M08 U1b; M06-F6⟩ With the OpenSSH environment fill, as every M06 launch.
        match verify_projected_alias(&ssh, config.as_deref(), &a.alias, &a.expect, OPENSSH_FILL)
            .await
        {
            Ok(()) => {}
            Err(RouteVerifyError::Defeated { defeated: d, .. }) => {
                defeated.push((a.alias, d.setting.to_owned()));
            }
            Err(_) => defeated.push((a.alias, "unreadable".to_owned())),
        }
    }
    defeated
}

/// `route connect --destination <id> --account <a> --endpoint <path>` (ADR-0012 §5.3–§5.5):
/// the typed inputs only (`heimdall_app::routes::HelperArgs`), the alias's pin check
/// ([`alias_pin_defeat`]), then the helper core over this process's standard streams
/// (standard output carries SSH bytes only; diagnostics go to standard error). Its exit
/// codes are internal (ADR-0012 §1.5).
fn route_connect(ctx: &Ctx, args: &crate::cli::PlannedArgs) -> ExitCode {
    let parsed = match heimdall_app::routes::HelperArgs::parse(
        args.args.iter().map(std::ffi::OsString::from),
    ) {
        Ok(p) => p,
        Err(e) => {
            output::diagnostic(&format!("heimdall route connect: {e}"));
            return ExitCode::Usage;
        }
    };
    let Ok(paths) = ctx.paths() else {
        output::diagnostic("heimdall route connect: cannot resolve the Heimdall directories");
        return ExitCode::Usage;
    };
    // The scratch SSH home of a debug build's test configuration (never in a release
    // build): the effective configuration is then read with `-F <home>/.ssh/config`.
    let ssh_config = match crate::testcfg::launch_hooks(&|n| std::env::var_os(n)) {
        Ok(hooks) => seam_ssh_config(&hooks),
        Err(m) => {
            output::diagnostic(&format!("heimdall route connect: {m}"));
            return ExitCode::Usage;
        }
    };
    // ⟨M08 U2b-1⟩ The store the pointer names. A corrupt layout names none: an empty path,
    // which every read-only open refuses.
    let db = heimdall_store::layout::db_path(&paths.state_dir).unwrap_or_default();
    let rt = match crate::service_cmd::current_thread() {
        Ok(rt) => rt,
        Err(_) => return ExitCode::Unavailable,
    };
    let iroh = heimdall_store::Store::open_read_only(&db, Arc::new(heimdall_store::NoFaults))
        .ok()
        .and_then(|state| {
            let environment = state.transaction(|tx| tx.self_environment()).ok()??;
            heimdall_runtime::supervise_transport::route_iroh_leg(
                &state,
                iroh_store(ctx, &environment),
            )
        });
    let ssh = ssh_client().unwrap_or_default();
    let dialer = heimdall_app::routes::legs::RouteLegDialer {
        base: heimdall_app::routes::legs::TokioLegDialer {
            ssh_client: ssh.clone(),
            relay_jump_stderr: true,
            // ⟨M08 U1b; M06-F6⟩ The jump leg's `ssh` gets the fill, as every M06 launch.
            fill: OPENSSH_FILL,
        },
        iroh,
        iroh_in_build: heimdall_runtime::supervise_transport::ROUTE_IROH_IN_BUILD,
    };
    let pin_file = paths
        .config_dir
        .join("keys")
        .join(heimdall_localenv::projection::HOST_PINS_FILE);
    let ports = HelperPorts {
        ctx,
        db,
        endpoint: parsed.endpoint.clone(),
        pin_text: std::fs::read_to_string(pin_file).ok(),
        paths,
    };
    // The program as the alias names it: the shell `exec`s the rendered, quoted path.
    let program = std::env::args_os()
        .next()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Some(setting) = rt.block_on(alias_pin_defeat(
        &ports,
        &parsed,
        &ssh,
        ssh_config.as_deref(),
        &program,
    )) {
        output::diagnostic(&format!(
            "heimdall route connect: the SSH configuration does not hold this destination's \
             catalog host-key pin ({}: {setting}); no route was tried. `heimdall doctor` \
             names the setting; `heimdall setup apply` writes the alias and its pins again",
            reason::HOST_PIN_DEFEATED
        ));
        rt.block_on(ports.report(
            heimdall_contract::route::RouteHealthPayload {
                kind: heimdall_contract::route::RouteEventKind::Health,
                destination: parsed.destination.clone(),
                account: parsed.account.clone(),
                attempts: Vec::new(),
                final_route: None,
            },
            Some(setting),
        ));
        rt.shutdown_background();
        return ExitCode::Unavailable;
    }
    let ended = rt.block_on(heimdall_app::routes::route_connect(
        &parsed,
        &ports,
        &dialer,
        tokio::io::stdin(),
        tokio::io::stdout(),
        &heimdall_app::routes::FailoverConfig::default(),
        &mut std::io::stderr(),
    ));
    // The standard-input reader must never hold the exit (G06 S03).
    rt.shutdown_background();
    match ended {
        Ok(outcome) if outcome.succeeded() => ExitCode::Success,
        Ok(_) => ExitCode::Unavailable,
        Err(e) => {
            output::diagnostic(&format!("heimdall route connect: {e}"));
            ExitCode::Unavailable
        }
    }
}

/// `transport serve --environment <id>` (hidden): the supervised serve child
/// (`heimdall_runtime::supervise_transport::serve_child_stdio`), with K_iroh from this
/// installation's verified platform store. Its standard streams are the supervision
/// channel; it reads no state and no environment variable. Its exit code is internal.
fn transport_serve(args: &crate::cli::PlannedArgs) -> ExitCode {
    let environment = match args.args.as_slice() {
        [flag, value] if flag == "--environment" => {
            value.to_str().and_then(|v| EnvironmentId::parse(v).ok())
        }
        _ => None,
    };
    let Some(environment) = environment else {
        output::diagnostic("heimdall transport serve: takes exactly --environment <id>");
        return ExitCode::Usage;
    };
    let keys = heimdall_runtime::supervise_transport::product_iroh_store(&environment);
    let factory = heimdall_runtime::supervise_transport::serve_key_factory(keys);
    match heimdall_runtime::supervise_transport::serve_child_stdio(&factory) {
        0 => ExitCode::Success,
        _ => ExitCode::Unavailable,
    }
}

/// No serve child runs while no runtime does: [`transport_rotate`]'s direct path.
struct NoServe;

#[async_trait::async_trait]
impl heimdall_app::transport::ServeControl for NoServe {
    fn check_policy(
        &self,
        _policy: &heimdall_contract::route::ExposurePolicy,
    ) -> Result<(), &'static str> {
        Ok(())
    }
    async fn start(&self) -> Result<(), OpError> {
        Ok(())
    }
    async fn apply_narrowing(&self) -> heimdall_app::transport::AdmissionReport {
        heimdall_app::transport::AdmissionReport::NotServing
    }
    async fn stop(&self) -> heimdall_app::transport::AdmissionReport {
        heimdall_app::transport::AdmissionReport::NotServing
    }
}

/// ⟨rev6.3; ADR-0006 §18.7 item 10⟩ `transport.rotate`'s management channel
/// (`heimdall_app::transport::EndpointAnnouncer`): `remote_environment.rotate_endpoint` to
/// one recorded runner over its own management session, with this installation's K_mgmt and
/// its recorded pins, exactly as every other management call. The records and the catalog
/// are read read-only from the state database (the caller holds its single writer: the
/// runtime, or the CLI under the instance lock), and nothing is ever confirmed here (no
/// terminal: a management call to a recorded runner asks nothing).
pub(crate) struct ManagementAnnouncer {
    ctx: Ctx,
    paths: heimdall_runtime::Paths,
}

impl ManagementAnnouncer {
    /// The channel for the installation at `paths`.
    pub(crate) fn new(ctx: &Ctx, paths: &heimdall_runtime::Paths) -> Self {
        Self {
            ctx: Ctx {
                // Never a prompt from here, whatever the command's own terminal is.
                non_interactive: true,
                ..ctx.clone()
            },
            paths: paths.clone(),
        }
    }
}

#[async_trait::async_trait]
impl heimdall_app::transport::EndpointAnnouncer for ManagementAnnouncer {
    async fn announce(
        &self,
        environment: &EnvironmentId,
        endpoint: &heimdall_contract::ids::IrohEndpointId,
    ) -> Result<(), OpError> {
        let db = heimdall_store::layout::db_path(&self.paths.state_dir)
            .map_err(|_| state_refusal("the installation's environment cannot be read"))?;
        let own = heimdall_store::Store::open_read_only(&db, Arc::new(heimdall_store::NoFaults))
            .and_then(|s| s.transaction(|tx| tx.self_environment()))
            .ok()
            .flatten()
            .ok_or_else(|| state_refusal("the installation's environment cannot be read"))?;
        let key = Arc::new(StoreKey {
            store: Some(Arc::<dyn MgmtKeyStore>::from(mgmt_store(&self.ctx, &own)?)),
        });
        let registry = StoreRegistry {
            db: db.clone(),
            writes: None,
        };
        let ssh = ssh_client();
        let root = self.paths.runtime_dir.join("mgmt");
        let catalog = StateCatalog { db };
        // The announcement bootstraps nothing: no CA and no endpoint are passed.
        let bootstrap = env_ssh::BootstrapSsh {
            ssh_client: ssh.clone().unwrap_or_default(),
            scratch_dir: root.clone(),
            config: None,
            extra_options: Vec::new(),
            stderr_file: None,
            issuer_ca: None,
            iroh_endpoint: None,
            fill: OPENSSH_FILL,
        };
        let sessions = SshSessions {
            ssh_client: ssh,
            root,
            key: key.clone(),
            fill: OPENSSH_FILL,
            kept_epoch: None,
        };
        let confirm = TerminalConfirm { interactive: false };
        RemoteEnvController::new(ControllerPorts {
            key: key.as_ref(),
            registry: &registry,
            catalog: &catalog,
            bootstrap: &bootstrap,
            sessions: &sessions,
            confirm: &confirm,
            now: now(),
        })
        .announce_endpoint_to(environment, endpoint)
        .await
        .map(drop)
    }
}

/// ⟨M06 W3 host⟩ The hosted controller driver's session opener
/// (`heimdall_runtime::controller_host`): management sessions to this installation's
/// recorded runners over `ssh -F <isolated configuration>` with its K_mgmt, exactly as every
/// other management call. The key store is selected at each open, so a runtime with no
/// recorded runner never touches it; nothing is ever confirmed here (no terminal).
pub(crate) struct DriverSessions {
    ctx: Ctx,
    paths: heimdall_runtime::Paths,
}

impl DriverSessions {
    /// The opener for the installation at `paths`.
    pub(crate) fn new(ctx: &Ctx, paths: &heimdall_runtime::Paths) -> Self {
        Self {
            ctx: Ctx {
                non_interactive: true,
                ..ctx.clone()
            },
            paths: paths.clone(),
        }
    }
}

#[async_trait::async_trait]
impl ManagementSessions for DriverSessions {
    async fn open(&self, target: &SessionTarget) -> Result<Box<dyn ManagementSession>, OpError> {
        let db = heimdall_store::layout::db_path(&self.paths.state_dir)
            .map_err(|_| state_refusal("the installation's environment cannot be read"))?;
        let own = heimdall_store::Store::open_read_only(&db, Arc::new(heimdall_store::NoFaults))
            .and_then(|s| s.transaction(|tx| tx.self_environment()))
            .ok()
            .flatten()
            .ok_or_else(|| state_refusal("the installation's environment cannot be read"))?;
        let sessions = SshSessions {
            ssh_client: ssh_client(),
            root: self.paths.runtime_dir.join("mgmt"),
            key: Arc::new(StoreKey {
                store: Some(Arc::<dyn MgmtKeyStore>::from(mgmt_store(&self.ctx, &own)?)),
            }),
            fill: OPENSSH_FILL,
            kept_epoch: None,
        };
        sessions.open(target).await
    }
}

/// The human line of a rotation's result (`heimdall_app::transport::RotateResult` as JSON):
/// the endpoints, and the runners still pending by name.
fn rotation_text(data: &serde_json::Value) -> String {
    let text = |k: &str| data[k].as_str().unwrap_or("?").to_owned();
    let pending: Vec<&str> = data["pending"]
        .as_array()
        .map(|p| p.iter().filter_map(serde_json::Value::as_str).collect())
        .unwrap_or_default();
    let told = data["runners"].as_array().map_or(0, Vec::len);
    let head = if data["resumed"] == serde_json::json!(true) {
        format!(
            "rotation continued: endpoint {} (was {}); no new key was made",
            text("endpoint"),
            text("previous")
        )
    } else {
        format!(
            "rotated: endpoint {} (was {})",
            text("endpoint"),
            text("previous")
        )
    };
    if pending.is_empty() {
        format!("{head}; {told} runner(s) told, none pending; the old key is destroyed")
    } else {
        format!(
            "{head}; {told} runner(s) told, still pending: {}. The old key is kept until they \
             acknowledge or are removed: run `heimdall transport rotate` again",
            pending.join(", ")
        )
    }
}

/// `transport rotate` (ADR-0012 §2.4 item 4; ADR-0006 §18.7 items 4 and 10): rotate this
/// device's K_iroh and tell every recorded runner the new endpoint ID
/// (`heimdall_app::transport::TransportOps::rotate`: retry-safe; a runner that fails stays
/// pending and is named; a re-run finishes it and mints no further key; the old key goes
/// only once nobody is pending). When a runtime runs it rotates (`transport.rotate`, the
/// runtime being its store's single writer and the serve child's supervisor); when none
/// does, the same rotation runs here under the instance lock.
fn transport_rotate(ctx: &Ctx) -> ExitCode {
    let rt = match crate::service_cmd::current_thread() {
        Ok(rt) => rt,
        Err(env) => {
            let env = output::error_value(env);
            output::emit(&env, ctx.json);
            return output::exit_code_for(env.code, false);
        }
    };
    let direct = rt.block_on(async {
        let paths = ctx
            .paths()
            .map_err(|_| usage("cannot resolve the Heimdall directories"))?;
        // A running runtime holds the lock: it rotates.
        let Some(w) = try_writer(&paths)? else {
            return Ok(None);
        };
        let environment = w
            .store
            .transaction(|tx| tx.self_environment())
            .ok()
            .flatten()
            .ok_or_else(|| state_refusal("the installation's environment cannot be read"))?;
        let keys =
            heimdall_runtime::supervise_transport::CredentialKeys(iroh_store(ctx, &environment));
        let announcer = ManagementAnnouncer::new(ctx, &paths);
        let rotated = heimdall_app::transport::TransportOps {
            store: &w.store,
            keys: &keys,
            serve: &NoServe,
            peers: &heimdall_app::transport::StorePeerEnrollments,
        }
        .rotate(Some(&announcer), now())
        .await?;
        let data = serde_json::to_value(&rotated).map_err(|_| {
            OpError::new(
                Code::InternalError,
                "the rotation's result cannot be rendered",
            )
        })?;
        Ok::<_, OpError>(Some(data))
    });
    match direct {
        Ok(Some(data)) => {
            let human = rotation_text(&data);
            emit_ok(ctx, data, &human)
        }
        Ok(None) => send_to_runtime(
            ctx,
            heimdall_contract::ipc::capability::TRANSPORT_IROH_V1,
            heimdall_contract::request::Request::Transport(
                heimdall_contract::route::TransportRequest::Rotate,
            ),
            false,
            rotation_text,
        ),
        Err(e) => emit_error(ctx, e),
    }
}

// --- output ------------------------------------------------------------------------------

fn emit_error(ctx: &Ctx, e: OpError) -> ExitCode {
    let env = output::error_value(e.into_envelope());
    output::emit(&env, ctx.json);
    output::exit_code_for(env.code, false)
}

fn emit_ok(ctx: &Ctx, data: serde_json::Value, human: &str) -> ExitCode {
    let env = Envelope::ok(data);
    if ctx.json {
        output::emit(&env, true);
    } else {
        output::emit_rendered(&env, false, human);
    }
    ExitCode::Success
}

fn usage(message: &str) -> OpError {
    OpError::new(Code::UsageError, message).with_effect(EffectStatus::None)
}

fn parse_environment(text: &str) -> Result<EnvironmentId, OpError> {
    EnvironmentId::parse(text).map_err(|_| usage("the environment ID is malformed"))
}

// --- K_mgmt ------------------------------------------------------------------------------

/// The debug-build test configuration of the K_mgmt store:
/// `HEIMDALL_TEST_MGMT_STORE=fixture-file:<absolute path>` selects the fixture store (test
/// kind, never a product claim), with an explicit `HEIMDALL_HOME` only. ⟨M06 W5 `w5m`⟩ A
/// release build refuses the variable (exit 2, `testcfg::mgmt_store_refusal`): it never
/// honours it and never silently ignores it.
#[cfg(debug_assertions)]
pub(crate) const TEST_MGMT_STORE_ENV: &str = crate::testcfg::MGMT_STORE_ENV;

/// The fixture store prefix of [`TEST_MGMT_STORE_ENV`].
#[cfg(debug_assertions)]
const FIXTURE_FILE_PREFIX: &str = "fixture-file:";

/// ⟨M06 W5, the 2026-11-22 incident⟩ The debug-build guard for K_mgmt
/// (`heimdall_credential::scratch_guard`): the refusal when the Heimdall home (`home`, or
/// `HEIMDALL_HOME` through `var`) is a temporary or scratch directory and
/// `HEIMDALL_TEST_MGMT_STORE` is not set. The platform store is then never selected, so
/// nothing is created or read in the account's keychain, DPAPI directory or Secret
/// Service. `None` in a release build, always.
#[cfg_attr(windows, allow(dead_code))]
fn mgmt_scratch_refusal(
    home: Option<&Path>,
    var: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<OpError> {
    use heimdall_credential::scratch_guard;
    scratch_guard::home_is_scratch(home, scratch_guard::MGMT_FIXTURE_ENV, var).then(|| {
        OpError::new(Code::CapabilityUnavailable, scratch_guard::MGMT_REFUSAL)
            .with_reason(reason::MGMT_KEY_STORE_UNAVAILABLE)
            .with_effect(EffectStatus::None)
    })
}

/// ⟨M06 W5⟩ This installation's K_iroh store for the commands that run without the
/// runtime: `heimdall_runtime::supervise_transport::product_iroh_store`, after the
/// debug-build guard over the home this command resolved (`--home` as well as
/// `HEIMDALL_HOME`; `heimdall_credential::iroh::scratch_home_refusal`).
fn iroh_store(
    ctx: &Ctx,
    environment: &EnvironmentId,
) -> Arc<dyn heimdall_credential::iroh::IrohKeyStore> {
    if let Some(refusing) =
        heimdall_credential::iroh::scratch_home_refusal(ctx.home.as_deref(), &|n| {
            std::env::var_os(n)
        })
    {
        return Arc::from(refusing);
    }
    heimdall_runtime::supervise_transport::product_iroh_store(environment)
}

/// This installation's K_mgmt store (module docs). `environment` scopes the item.
fn mgmt_store(ctx: &Ctx, environment: &EnvironmentId) -> Result<Box<dyn MgmtKeyStore>, OpError> {
    // A release build with the test variable set selects no store at all (the commands'
    // entry points refused it already; this is the same refusal at the selection itself).
    if let Some(message) = crate::testcfg::mgmt_store_refusal(&|n| std::env::var_os(n)) {
        return Err(usage(message));
    }
    #[cfg(debug_assertions)]
    if let Some(value) = std::env::var_os(TEST_MGMT_STORE_ENV) {
        let path = value
            .to_str()
            .and_then(|v| v.strip_prefix(FIXTURE_FILE_PREFIX))
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or_else(|| {
                usage("HEIMDALL_TEST_MGMT_STORE: expected fixture-file:<absolute path>")
            })?;
        if ctx.home.is_none() {
            return Err(usage(
                "HEIMDALL_TEST_MGMT_STORE needs an explicit HEIMDALL_HOME (the test's scratch home)",
            ));
        }
        return Ok(Box::new(mgmt::fixture::FixtureMgmtStore::file(path)));
    }
    // (Not on Windows: with an explicit Heimdall home the DPAPI store below lives inside
    // that home, so a scratch installation's K_mgmt never reaches the account's own
    // directory there, and the native journeys prove that store under a scratch home.)
    #[cfg(not(windows))]
    if let Some(refused) = mgmt_scratch_refusal(ctx.home.as_deref(), &|n| std::env::var_os(n)) {
        return Err(refused);
    }
    let _ = (ctx, environment);
    #[cfg(target_os = "macos")]
    {
        let home = heimdall_localenv::sys::account_home().map_err(|_| {
            OpError::new(
                Code::CapabilityUnavailable,
                "the account's home cannot be read, so its keychain cannot be selected",
            )
            .with_reason(reason::MGMT_KEY_STORE_UNAVAILABLE)
        })?;
        Ok(Box::new(mgmt::macos::MacosLoginKeychainMgmt::login(
            &home,
            environment,
        )))
    }
    #[cfg(windows)]
    {
        let dir = if ctx.home.is_some() {
            ctx.paths()
                .map_err(|_| usage("cannot resolve the Heimdall directories"))?
                .state_dir
                .join("mgmt")
                .join(environment.as_str())
        } else {
            mgmt::windows::WindowsDpapiMgmt::default_dir(environment)
                .map_err(|_| MgmtKeyUnavailable::StoreUnavailable.to_error())?
        };
        Ok(Box::new(mgmt::windows::WindowsDpapiMgmt::in_dir(
            dir,
            environment,
        )))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(mgmt::linux::LinuxSecretServiceMgmt::new(
            environment,
        )))
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    {
        Ok(Box::new(mgmt::UnsupportedStore))
    }
}

fn unavailable(e: MgmtStoreError) -> MgmtKeyUnavailable {
    match e {
        MgmtStoreError::Unavailable(
            MgmtStoreAvailability::Locked | MgmtStoreAvailability::InteractionNotAllowed,
        ) => MgmtKeyUnavailable::Locked,
        MgmtStoreError::Unavailable(_) | MgmtStoreError::Corrupt => {
            MgmtKeyUnavailable::StoreUnavailable
        }
        MgmtStoreError::NotFound => MgmtKeyUnavailable::NotFound,
        _ => MgmtKeyUnavailable::Failed,
    }
}

/// [`MgmtKeyPort`] over the installation's store (absent: the installation's state could not
/// be read, so no store can be selected).
struct StoreKey {
    store: Option<Arc<dyn MgmtKeyStore>>,
}

impl StoreKey {
    fn store(&self) -> Result<&Arc<dyn MgmtKeyStore>, MgmtKeyUnavailable> {
        self.store
            .as_ref()
            .ok_or(MgmtKeyUnavailable::StoreUnavailable)
    }
}

impl MgmtKeyPort for StoreKey {
    fn check(&self) -> Result<(), MgmtKeyUnavailable> {
        match self.store()?.availability() {
            MgmtStoreAvailability::Available => Ok(()),
            other => Err(unavailable(MgmtStoreError::Unavailable(other))),
        }
    }

    fn public_key(&self, create: bool) -> Result<MgmtKeyInfo, MgmtKeyUnavailable> {
        let store = self.store()?;
        let key = if create {
            mgmt::load_or_create(store.as_ref()).map(|(k, _)| k)
        } else {
            store.load()
        }
        .map_err(unavailable)?;
        let public = key.public().map_err(|_| MgmtKeyUnavailable::Failed)?;
        Ok(MgmtKeyInfo {
            openssh_line: public.openssh_line,
            fingerprint: public.fingerprint,
        })
    }

    fn destroy(&self) -> Result<(), MgmtKeyUnavailable> {
        self.store()?.destroy().map_err(unavailable)
    }

    fn fingerprint_of(&self, openssh_line: &str) -> Option<KeyFingerprint> {
        mgmt::openssh_fingerprint(openssh_line)
    }
}

// --- the records, the catalog, the confirmation ------------------------------------------

/// The instance lock and the read-write store held by a command that writes the
/// controller's records when no runtime runs (the CLI's direct-write pattern: `uninstall`'s
/// purge and `remote init` take the runtime's instance lock, then open the store
/// read-write). Held for the whole command, so no runtime starts while a bootstrap or
/// retirement runs and every write lands. ⟨rev6.3; ADR-0006 §18.7 item 6⟩ When a runtime
/// runs (it holds the lock), the records are written through it instead
/// (`Request::ControllerRecord`, [`RecordWrites::Runtime`]).
struct Writer {
    _lock: heimdall_runtime::InstanceLock,
    store: heimdall_store::Store,
}

fn state_refusal(message: &str) -> OpError {
    OpError::new(Code::StateUnavailable, message).with_effect(EffectStatus::None)
}

/// Take the instance lock of `paths` and open its store read-write (creating it at first
/// use), with this installation's environment ID recorded (as `remote init`'s
/// `init_runner` and the runtime's first start do). A running runtime holds the lock:
/// `SERVICE_UNAVAILABLE` (effect `none`); [`record_writes`] then writes through it.
fn writer(paths: &heimdall_runtime::Paths) -> Result<Writer, OpError> {
    match try_writer(paths)? {
        Some(w) => Ok(w),
        None => Err(OpError::new(
            Code::ServiceUnavailable,
            "the runtime is running on this installation: this command needs the instance \
             lock, so stop the runtime (`heimdall service stop`) and run it again; nothing \
             was changed",
        )
        .with_effect(EffectStatus::None)),
    }
}

/// [`writer`], answering `None` when a running runtime holds the instance lock.
fn try_writer(paths: &heimdall_runtime::Paths) -> Result<Option<Writer>, OpError> {
    paths
        .ensure()
        .map_err(|_| state_refusal("the Heimdall directories cannot be prepared"))?;
    let lock = match heimdall_runtime::InstanceLock::try_acquire(&paths.state_dir) {
        Ok(lock) => lock,
        Err(heimdall_runtime::instance::InstanceError::AlreadyRunning) => return Ok(None),
        Err(_) => return Err(state_refusal("the instance lock cannot be taken")),
    };
    // ⟨M08 U2b-1⟩ Through the generation layout, under the lock just taken: the generation the
    // pointer names, the flat store adopted, or a first install.
    let store = open_locked_store(paths)?.store;
    let fresh = heimdall_app::ids::new_environment_id().map_err(|_| {
        OpError::new(
            Code::InternalError,
            "operating system randomness unavailable",
        )
    })?;
    store
        .transaction(|tx| {
            if tx.self_environment()?.is_none() {
                tx.init_self_environment(&fresh)?;
            }
            Ok(())
        })
        .map_err(|_| state_refusal("the installation's environment cannot be recorded"))?;
    Ok(Some(Writer { _lock: lock, store }))
}

/// ⟨M08 U2b-1; ADR-0014 §3.6⟩ The store of `paths`, read-write, through the generation layout
/// (`heimdall_runtime::state_store::open_locked`), **under the instance lock the caller holds**.
fn open_locked_store(
    paths: &heimdall_runtime::Paths,
) -> Result<heimdall_store::layout::Opened, OpError> {
    heimdall_runtime::state_store::open_locked(
        &paths.state_dir,
        Arc::new(heimdall_store::NoFaults),
        heimdall_contract::Timestamp::now(),
    )
    .map_err(|_| state_refusal("the state database cannot be opened"))
}

/// ⟨rev6.3; ADR-0006 §18.7 item 6⟩ How a command that writes the controller's records writes
/// them: directly under the instance lock when no runtime runs, or through the running
/// runtime's `Request::ControllerRecord` (the runtime is its store's single writer).
enum RecordWrites {
    /// No runtime: the lock and the read-write store, held for the whole command.
    Direct(Writer),
    /// A runtime answers: its control session.
    /// Boxed: the client is far larger than the direct writer.
    Runtime(Box<tokio::sync::Mutex<crate::client::Client>>),
}

/// The writes of one command ([`RecordWrites`]): the instance lock when it can be taken,
/// otherwise a session to the runtime that holds it (never starting one). A runtime that
/// stopped in between is retried once with the lock.
async fn record_writes(
    ctx: &Ctx,
    paths: &heimdall_runtime::Paths,
) -> Result<RecordWrites, OpError> {
    for _ in 0..2 {
        if let Some(w) = try_writer(paths)? {
            return Ok(RecordWrites::Direct(w));
        }
        match crate::client::connect(ctx, false).await {
            Ok(client) => {
                return Ok(RecordWrites::Runtime(Box::new(tokio::sync::Mutex::new(
                    client,
                ))));
            }
            Err(_) => continue,
        }
    }
    Err(OpError::new(
        Code::ServiceUnavailable,
        "the runtime holds the instance lock but does not answer; nothing was changed",
    )
    .with_effect(EffectStatus::None))
}

/// The controller's records over `remote_environment_pins` (`Txn::remote_environment_pins`
/// and friends). Reads go through the held writer, or a read-only open (no state yet: no
/// records); writes go through [`RecordWrites`] (`heimdall_app::remote_env::
/// apply_controller_record` directly, or the same form sent to the running runtime).
struct StoreRegistry {
    db: PathBuf,
    writes: Option<RecordWrites>,
}

fn records_unreadable() -> OpError {
    state_refusal("the controller's remote environment records cannot be read")
}

impl StoreRegistry {
    fn decode(rows: Vec<(EnvironmentId, String)>) -> Result<Vec<RemoteEnvironmentRecord>, OpError> {
        rows.into_iter()
            .map(|(id, json)| {
                let record: RemoteEnvironmentRecord =
                    serde_json::from_str(&json).map_err(|_| records_unreadable())?;
                if record.environment == id {
                    Ok(record)
                } else {
                    Err(records_unreadable())
                }
            })
            .collect()
    }

    /// Send one controller-record form ([`RecordWrites`]).
    async fn send(
        &self,
        form: heimdall_contract::controller_record::ControllerRecordRequest,
    ) -> Result<serde_json::Value, OpError> {
        match &self.writes {
            Some(RecordWrites::Direct(w)) => heimdall_app::remote_env::apply_controller_record(
                &w.store,
                &form,
                &mgmt::openssh_fingerprint,
                heimdall_contract::Timestamp::now(),
            ),
            Some(RecordWrites::Runtime(client)) => {
                let env = client
                    .lock()
                    .await
                    .request(heimdall_contract::request::Request::ControllerRecord(form))
                    .await;
                if env.code.is_success() {
                    return Ok(env.data);
                }
                let operation_id = env.operation_id.clone();
                Err(
                    match serde_json::from_value::<heimdall_contract::envelope::ErrorData>(env.data)
                    {
                        Ok(d) => OpError::from_detail(d.error, operation_id),
                        Err(_) => OpError::new(
                            Code::OutcomeUnknown,
                            "the runtime's answer could not be read",
                        ),
                    },
                )
            }
            None => Err(OpError::new(
                Code::InternalError,
                "the controller's records were opened read-only",
            )),
        }
    }
}

#[async_trait::async_trait]
impl EnvironmentRegistry for StoreRegistry {
    fn list(&self) -> Result<Vec<RemoteEnvironmentRecord>, OpError> {
        let rows = match &self.writes {
            Some(RecordWrites::Direct(w)) => w.store.transaction(|tx| tx.remote_environment_pins()),
            _ if !self.db.exists() => return Ok(Vec::new()),
            _ => {
                heimdall_store::Store::open_read_only(&self.db, Arc::new(heimdall_store::NoFaults))
                    .and_then(|s| s.transaction(|tx| tx.remote_environment_pins()))
            }
        }
        .map_err(|_| records_unreadable())?;
        Self::decode(rows)
    }

    async fn put(&self, record: &RemoteEnvironmentRecord) -> Result<(), OpError> {
        self.send(
            heimdall_contract::controller_record::ControllerRecordRequest::PutEnvironment {
                record: record.clone(),
            },
        )
        .await
        .map(drop)
    }

    async fn remove(&self, environment: &EnvironmentId) -> Result<bool, OpError> {
        let done = self
            .send(
                heimdall_contract::controller_record::ControllerRecordRequest::RemoveEnvironment {
                    environment: environment.clone(),
                },
            )
            .await?;
        Ok(done["removed"] == serde_json::json!(true))
    }
}

/// The catalog's verified access, read from the state database (read-only): the
/// destination's alias, and the owner-approved target of the pair's verified M03 enrollment
/// (host name, port, account and host key). A pair with no verified enrollment has no pinned
/// key, which `add` refuses (`host_trust_undetermined`).
struct StateCatalog {
    db: PathBuf,
}

impl AccessCatalog for StateCatalog {
    fn verified_access(
        &self,
        destination: &DestinationId,
        account: &AccountName,
    ) -> Result<Option<VerifiedAccess>, OpError> {
        use heimdall_contract::enrollment::EnrollmentState;
        let unreadable = || {
            OpError::new(
                Code::StateUnavailable,
                "the installation's catalog cannot be read",
            )
        };
        let store =
            heimdall_store::Store::open_read_only(&self.db, Arc::new(heimdall_store::NoFaults))
                .map_err(|_| unreadable())?;
        let pair = heimdall_contract::request::AccessPairRef {
            destination: destination.clone(),
            account: account.clone(),
        };
        let (record, enrollments) = store
            .transaction(|tx| {
                Ok((
                    tx.destination(destination)?,
                    tx.enrollments_for_pair(&pair)?,
                ))
            })
            .map_err(|_| unreadable())?;
        let Some(record) = record else {
            return Ok(None);
        };
        let target = enrollments
            .into_iter()
            .find(|e| e.state == EnrollmentState::Verified)
            .map(|e| e.target);
        let (hostname, port, host_keys) = match target {
            Some(t) => (
                t.hostname,
                Some(t.port),
                vec![format!("{} {}", t.host_key.algorithm, t.host_key.key)],
            ),
            None => (String::new(), None, Vec::new()),
        };
        Ok(Some(VerifiedAccess {
            destination: destination.clone(),
            alias: record.alias,
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname,
                    port,
                    account: account.clone(),
                    host_keys,
                },
                jump: None,
            },
        }))
    }
}

/// The owner's typed `yes` on this terminal (ADR-0006 §3.1's prompt rules; never on a
/// non-interactive or non-terminal invocation).
struct TerminalConfirm {
    interactive: bool,
}

fn confirmation_text(what: &Confirmation) -> String {
    match what {
        Confirmation::InviteKey {
            environment,
            role,
            fingerprint,
        } => format!(
            "Invite a device to runner {} as {role:?}.\nIts management key's fingerprint is\n    {}\nConfirm that the invited device shows exactly this fingerprint.\nType yes to continue: ",
            environment.as_str(),
            fingerprint.as_str()
        ),
        Confirmation::JoinRunner {
            environment,
            host_fingerprints,
            role,
        } => format!(
            "Join runner {} as {role:?}.\nIts host key fingerprints:\n    {}\nConfirm that the owner's controller shows exactly this environment ID and these fingerprints.\nType yes to continue: ",
            environment.as_str(),
            host_fingerprints.join("\n    ")
        ),
        Confirmation::RetireDevice {
            environments,
            forgotten_only,
            fingerprint,
        } => {
            // ⟨M06 W5 `w5m` L3⟩ What is revoked and what is only forgotten, before the yes.
            let revoked = environments.len().saturating_sub(forgotten_only.len());
            let mut text = format!(
                "Retire this device: revoke it on {revoked} runner(s), then destroy its management key {}.\n",
                fingerprint.as_str()
            );
            if !forgotten_only.is_empty() {
                text.push_str(&format!(
                    "On {} more runner(s) this device holds a limited role, which cannot revoke a client: their records are ONLY FORGOTTEN on this device, and its client stays enrolled there until an owner revokes it. An owner must run, on an owner controller, for each:\n",
                    forgotten_only.len()
                ));
                for s in forgotten_only {
                    text.push_str(&format!(
                        "    heimdall environment revoke-client {} {}\n",
                        s.environment.as_str(),
                        s.client.as_str()
                    ));
                }
            }
            text.push_str(
                "The key cannot be recovered; this device can only rejoin by a new invitation or bootstrap.\nType yes to continue: ",
            );
            text
        }
    }
}

impl TerminalConfirm {
    /// Show `text` and read a typed `yes` (default No, 120 s; never when not interactive).
    fn ask(&self, text: &str) -> bool {
        if !self.interactive {
            return false;
        }
        output::prompt(&output::sanitize_for_terminal(text));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let read = std::io::stdin().read_line(&mut line);
            let _ = tx.send(read.map(|n| (n, line)));
        });
        match rx.recv_timeout(crate::prompt::PROMPT_TIMEOUT) {
            Ok(Ok((0, _))) | Ok(Err(_)) | Err(_) => false,
            Ok(Ok((_, line))) => crate::prompt::classify(Some(&line)) == crate::prompt::Answer::Yes,
        }
    }
}

impl LocalConfirm for TerminalConfirm {
    fn confirm(&self, what: &Confirmation) -> bool {
        self.ask(&confirmation_text(what))
    }
}

// --- management sessions -----------------------------------------------------------------

/// How long a management session's hello may take (connect, authenticate, negotiate).
const SESSION_HELLO_BOUND: Duration = Duration::from_secs(30);

/// Management sessions over `ssh -F <isolated configuration>` (module docs).
struct SshSessions {
    ssh_client: Option<PathBuf>,
    /// A private directory for per-session configuration. ⟨M06 W5 `w5r`⟩ The agent sockets
    /// are not here: each session's are in its own short
    /// `heimdall_credential::mgmt::agent::AgentDir` (Unix).
    root: PathBuf,
    key: Arc<StoreKey>,
    /// ⟨M06 exit⟩ The management `ssh`'s and the probes' environment fill ([`OPENSSH_FILL`]).
    fill: env_ssh::OpensshEnvFill,
    /// ⟨M08 U2b-2; ADR-0014 §3.6 step 3⟩ `environment invite --request-epoch`: the runner's
    /// epoch the retried request ID was first sent with. The session then offers
    /// `request-epoch/1` and every mutating request carries this epoch; a runner that does not
    /// offer it gets nothing (`SCHEMA_UNSUPPORTED`). `None`: no epoch is sent, and the runner
    /// binds each request to its current epoch at receipt, as before.
    kept_epoch: Option<heimdall_contract::lifecycle::RestoreEpoch>,
}

/// ⟨M06 exit; ADR-0006 §18.9 item 13⟩ The fill every M06 launch of `ssh` applies (the
/// preflight, the bootstrap session, the management session and the probes): the variables
/// OpenSSH for Windows needs, from the operating system, as every other product launch of
/// `ssh` (`heimdall_localenv::sys::openssh_env`). The guard behind it stays the backstop.
const OPENSSH_FILL: env_ssh::OpensshEnvFill =
    heimdall_localenv::sys::openssh_env::fill_openssh_environment;

type SessionStream = tokio::io::Join<tokio::process::ChildStdout, tokio::process::ChildStdin>;

/// One open management session; its scratch directory is removed when it ends.
struct SshSession {
    client: heimdall_ipc::session::ControlClient<SessionStream>,
    hello: SessionHello,
    _child: tokio::process::Child,
    agent: Option<SessionAgent>,
    /// ⟨M06 W5 `w5r`⟩ The short owner-only directory of the agent's and the probes'
    /// sockets; removed after the agent stops.
    #[cfg(unix)]
    agent_dir: Option<heimdall_credential::mgmt::agent::AgentDir>,
    dir: PathBuf,
    /// What the confirming probes run with: the session's own client, configuration and
    /// alias (so its key, pins and route).
    ssh_client: PathBuf,
    config_file: PathBuf,
    alias: String,
    fill: env_ssh::OpensshEnvFill,
}

impl Drop for SshSession {
    fn drop(&mut self) {
        drop(self.agent.take());
        #[cfg(unix)]
        drop(self.agent_dir.take());
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[async_trait::async_trait]
impl ManagementSession for SshSession {
    fn hello(&self) -> &SessionHello {
        &self.hello
    }

    fn runner_negotiated(&self) -> bool {
        self.client
            .server()
            .capabilities
            .contains(heimdall_contract::ipc::capability::RUNNER_V1)
    }

    /// ⟨ADR-0006 §18.7 item 16⟩ The four confirming probes, each its own `ssh` run through
    /// this session's configuration while its K_mgmt agent is up. The agent offered for
    /// forwarding is a disposable one that holds nothing.
    async fn probe(&mut self) -> Option<heimdall_contract::remote::ProbeObservation> {
        #[cfg(unix)]
        {
            self.agent.as_ref()?;
            let socket = self
                .agent_dir
                .as_ref()?
                .socket(heimdall_credential::mgmt::agent::PROBE_SOCKET);
            let disposable = env_ssh::DisposableAgent::start(&socket).ok()?;
            env_ssh::run_probes(
                &self.ssh_client,
                &self.config_file,
                &self.alias,
                &disposable,
                self.fill,
            )
            .await
        }
        #[cfg(not(unix))]
        {
            // ⟨M06 W5⟩ Not run on Windows: the agent-forwarding probe needs a disposable
            // agent the in-box client can be pointed at, which this build does not have
            // there. No observation is reported, so the callers take their closed side (a
            // limited-role join and a policy re-check refuse; an owner session needs none).
            let _ = (&self.ssh_client, &self.config_file, &self.alias, self.fill);
            None
        }
    }

    /// ⟨M06 W5⟩ On Windows the probes above never run, and the callers say why
    /// (`heimdall_app::remote_env::PROBES_NOT_ON_WINDOWS`) instead of "inconclusive".
    fn probes_unavailable(&self) -> Option<&'static str> {
        if cfg!(windows) {
            Some(heimdall_app::remote_env::PROBES_NOT_ON_WINDOWS)
        } else {
            None
        }
    }

    async fn call(&mut self, call: ManagementCall) -> Result<Envelope<serde_json::Value>, OpError> {
        self.client.request(call.into_request()).await.map_err(|_| {
            OpError::new(
                Code::OutcomeUnknown,
                "the management session ended before the runner answered: the request may \
                 have been applied; repeat it (it is idempotent) to read the outcome",
            )
        })
    }
}

fn session_error(stderr: &[u8]) -> OpError {
    match env_ssh::classify_preflight(stderr) {
        env_ssh::PreflightVerdict::HostKeyMismatch => OpError::new(
            Code::CapabilityUnavailable,
            "the runner's host key is not the pinned key: held, nothing sent (repair the pin \
             only through independently verified access)",
        )
        .with_reason(reason::ENVIRONMENT_IDENTITY_MISMATCH),
        env_ssh::PreflightVerdict::HostVerified => OpError::new(
            Code::CapabilityUnavailable,
            "the runner refused this device's management key (revoked, an expired invitation, \
             or not enrolled)",
        ),
        // ⟨`w5v`; ADR-0006 §18.9⟩ Why, from what the client said (`Other` keeps the message
        // it always had). ⟨`w5w`, M06-W5-RC03; ADR-0006 §18.9 item 12⟩ The client's own
        // failures (it refused its options, or did not start) are this controller's, as the
        // preflight says, so `environment add` never sends the user to the runner for them.
        env_ssh::PreflightVerdict::Unreachable(
            cause @ (env_ssh::UnreachableCause::ClientRejected
            | env_ssh::UnreachableCause::ClientNotStarted),
        ) => on_this_controller(cause.error("for a management session")),
        env_ssh::PreflightVerdict::Unreachable(cause) => cause.error("for a management session"),
    }
    .with_effect(EffectStatus::None)
}

impl SshSessions {
    fn session_dir(&self) -> Result<PathBuf, OpError> {
        let mut bytes = [0u8; 6];
        heimdall_credential::vault::SystemRng::fill(&mut bytes).map_err(|_| rng_unavailable())?;
        let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let dir = self.root.join(name);
        // ⟨M06 W5; ADR-0012 §2.6⟩ Windows: the session directory is created exclusively
        // with a protected owner-only DACL, under a root that is a real directory (a
        // symbolic link or junction at the root's name is refused, never followed).
        #[cfg(windows)]
        let created = std::fs::create_dir_all(&self.root)
            .and_then(|()| std::fs::symlink_metadata(&self.root))
            .and_then(|meta| {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    Err(std::io::Error::other("the session root is not a directory"))
                } else {
                    heimdall_ipc::windows::create_dir_owner_only(&dir)
                }
            });
        #[cfg(not(windows))]
        let created = {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder.create(&dir)
        };
        created.map_err(|e| {
            local_io_failed(&e, "management session directory could not be created")
        })?;
        Ok(dir)
    }
}

/// ⟨M06 W5 `w5r`, `w5t`; ADR-0006 §18.9⟩ The refusal of a management session whose K_mgmt
/// agent could not start on this controller ([`controller_fault`]): effect `none`, one
/// `mgmt_agent_*` reason per class (`heimdall_credential::mgmt::agent::AgentFailure`), and a
/// message that names this controller's agent, why and the fix, never a path. Split by
/// whether an unchanged retry can help (the code table's placement rule): a path too long
/// or a denied directory is `CAPABILITY_UNAVAILABLE`; a name still taken after the fresh
/// names (`AGENT_DIR_ATTEMPTS`) or any other failure is `STATE_UNAVAILABLE`.
/// ⟨M06 W5 `w5t`, ruling 2026-11-23⟩ Why the agent is "in use": on Windows another process
/// holds every pipe name this controller tried (the first-instance refusal), elsewhere every
/// fresh directory name was taken.
const AGENT_NAMES_IN_USE: &str = if cfg!(windows) {
    "another process already holds every pipe name it tried, and a pipe of another process is \
     never joined"
} else {
    "every fresh name it tried was already in use, and what is there is never reused or removed"
};

fn agent_failed(e: &std::io::Error) -> OpError {
    use heimdall_credential::mgmt::agent::AgentFailure;
    const WHAT: &str = "management key agent could not start";
    let (code, why, fix, reason) = match AgentFailure::of(e) {
        AgentFailure::PathTooLong => (
            Code::CapabilityUnavailable,
            "its socket path would be longer than this platform allows",
            "give this controller a shorter runtime or temporary directory, then try again",
            reason::MGMT_AGENT_PATH_TOO_LONG,
        ),
        AgentFailure::PermissionDenied => (
            Code::CapabilityUnavailable,
            "the operating system denied it an owner-only directory, socket or pipe",
            "correct the ownership or permissions of this controller's runtime or temporary \
             directory, then try again",
            reason::MGMT_AGENT_PERMISSION_DENIED,
        ),
        AgentFailure::AddressInUse => (
            Code::StateUnavailable,
            AGENT_NAMES_IN_USE,
            "try again",
            reason::MGMT_AGENT_ADDRESS_IN_USE,
        ),
        AgentFailure::Other => (
            Code::StateUnavailable,
            "its endpoint could not be created",
            "try again",
            reason::MGMT_AGENT_UNAVAILABLE,
        ),
    };
    controller_fault(code, &format!("{WHAT}: {why}"), fix).with_reason(reason)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), OpError> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
        .map_err(|e| local_io_failed(&e, "management session file could not be written"))
}

/// ⟨M06 W5 `w5t`⟩ A management session's directory or file that could not be made on this
/// controller ([`controller_fault`]): the operating system's refusal, which an unchanged
/// retry cannot fix, is `CAPABILITY_UNAVAILABLE` and names the fix; any other failure (a
/// full disk, say) is `STATE_UNAVAILABLE`. Never a path.
fn local_io_failed(e: &std::io::Error, what: &str) -> OpError {
    use std::io::ErrorKind;
    if matches!(
        e.kind(),
        ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
    ) {
        controller_fault(
            Code::CapabilityUnavailable,
            &format!("{what}: the operating system denied it"),
            "correct the ownership or permissions of this controller's Heimdall home, \
             then try again",
        )
    } else {
        controller_fault(Code::StateUnavailable, what, "try again")
    }
}

fn render_refused(_e: heimdall_sshconf::render::RenderError) -> OpError {
    render_refusal()
}

/// ⟨M06 W5 `w5t`⟩ The controller-local failures of the session opener, each a named site so
/// that `every_session_opener_failure_on_this_controller_is_classed_as_its_fault` lists
/// them all. A new site on this controller gets a function here and a row there.
fn rng_unavailable() -> OpError {
    controller_fault(
        Code::InternalError,
        "management session could not start: operating system randomness is unavailable",
        "report it",
    )
}

fn no_ssh_client() -> OpError {
    controller_fault(
        Code::LaunchFailed,
        "management session could not start: no OpenSSH client was found",
        "install OpenSSH on this controller",
    )
}

/// This controller's K_mgmt store (opening, loading, the public key, the signer): code and
/// reason kept.
fn key_store_failed(e: MgmtKeyUnavailable) -> OpError {
    on_this_controller(e.to_error())
}

/// The management `ssh` this controller could not start (`env_ssh::spawn_management`).
fn ssh_spawn_failed(e: OpError) -> OpError {
    on_this_controller(e)
}

fn render_refusal() -> OpError {
    controller_fault(
        Code::CapabilityUnavailable,
        "management configuration cannot be rendered for this runner's recorded route",
        "review the runner's record on this controller",
    )
    .with_reason(reason::HOST_PIN_DEFEATED)
}

#[async_trait::async_trait]
impl ManagementSessions for SshSessions {
    async fn open(&self, target: &SessionTarget) -> Result<Box<dyn ManagementSession>, OpError> {
        use heimdall_sshconf::mgmt::{
            HopIdentity, MgmtHop, MgmtTarget, PinnedKey, render_mgmt_config, render_mgmt_pin_file,
        };
        use heimdall_sshconf::render::{HostName, PathStyle, RenderPath};
        // ⟨M06 W5; ADR-0012 §2.6⟩ Unix serves K_mgmt on a socket, Windows on a named pipe for
        // the in-box OpenSSH. Anywhere else there is no agent: refused before K_mgmt is read.
        if !cfg!(any(unix, windows)) {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "management sessions are not available on this platform in this build",
            )
            .with_reason(reason::DRIVER_UNAVAILABLE));
        }
        if target.route.jump.is_some() {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "management through a jump hop is not available in this build",
            )
            .with_reason(reason::ROUTE_DEPENDENCY_OUT_OF_SCOPE));
        }
        let ssh_client = self.ssh_client.clone().ok_or_else(no_ssh_client)?;
        let store = self.key.store().map_err(key_store_failed)?;
        let key = store.load().map_err(|e| key_store_failed(unavailable(e)))?;
        let public = key
            .public()
            .map_err(|_| key_store_failed(MgmtKeyUnavailable::Failed))?;
        let name = match &target.name {
            SessionName::Environment(e) => e.as_str().to_owned(),
            SessionName::Bootstrap(d) => format!("bootstrap.{}", d.as_str()),
        };
        let runner = &target.route.runner;
        let dir = self.session_dir()?;
        let cleanup = |e: OpError| {
            let _ = std::fs::remove_dir_all(&dir);
            e
        };
        let style = if cfg!(windows) {
            PathStyle::Windows
        } else {
            PathStyle::Unix
        };
        let pub_file = dir.join("k_mgmt.pub");
        let pins_file = dir.join("known_hosts");
        let config_file = dir.join("mgmt.conf");
        let path = |p: &Path| RenderPath::absolute(p, style).map_err(render_refused);
        // ⟨M06 W5 `w5r`⟩ The agent's socket is in a short owner-only directory of its own
        // (`AgentDir`: `$XDG_RUNTIME_DIR` or `/tmp`), not under the Heimdall home, whose
        // length must never decide whether a session can open.
        #[cfg(unix)]
        let agent_dir = heimdall_credential::mgmt::agent::AgentDir::create()
            .map_err(|e| cleanup(agent_failed(&e)))?;
        #[cfg(unix)]
        let socket = agent_dir.socket(heimdall_credential::mgmt::agent::AGENT_SOCKET);
        #[cfg(not(windows))]
        let agent_endpoint = path(&socket).map_err(cleanup)?;
        // ⟨M06 W5; ADR-0012 §2.6⟩ Windows: the agent's pipe is named by a token it draws
        // itself, so it starts before the configuration that names it. It lives in this
        // function until the session owns it: every refusal below drops it, which closes the
        // pipe and drops the key.
        #[cfg(windows)]
        let (agent, agent_endpoint) = {
            let signer = MgmtSigner::with_host_key_lines(
                key,
                [runner.account.as_str().to_owned()],
                &runner.host_keys,
            )
            .map_err(|_| cleanup(key_store_failed(MgmtKeyUnavailable::Failed)))?;
            let agent = SessionAgent::start_pipe(signer).map_err(|e| cleanup(agent_failed(&e)))?;
            let endpoint = agent
                .path()
                .to_str()
                .and_then(|name| RenderPath::pipe(name).ok())
                .ok_or_else(|| {
                    cleanup(agent_failed(&std::io::Error::other(
                        "the pipe name cannot be rendered",
                    )))
                })?;
            (agent, endpoint)
        };
        let mgmt_target = (|| -> Result<MgmtTarget, OpError> {
            Ok(MgmtTarget {
                environment: name.clone(),
                hop: MgmtHop {
                    hostname: HostName::parse(&runner.hostname).map_err(render_refused)?,
                    port: runner.port,
                    user: runner.account.as_str().to_owned(),
                    pins: runner
                        .host_keys
                        .iter()
                        .map(|k| PinnedKey::parse(k))
                        .collect::<Result<_, _>>()
                        .map_err(render_refused)?,
                    identity: HopIdentity::new(agent_endpoint.clone(), path(&pub_file)?)
                        .map_err(render_refused)?,
                },
                jump: None,
            })
        })()
        .map_err(cleanup)?;
        let config = render_mgmt_config(&mgmt_target, &path(&pins_file).map_err(cleanup)?, style)
            .map_err(render_refused)
            .map_err(cleanup)?;
        let pins = render_mgmt_pin_file(&mgmt_target)
            .map_err(render_refused)
            .map_err(cleanup)?;
        write_private(&pub_file, format!("{}\n", public.openssh_line).as_bytes())
            .map_err(cleanup)?;
        write_private(&pins_file, &pins).map_err(cleanup)?;
        write_private(&config_file, &config).map_err(cleanup)?;
        #[cfg(not(windows))]
        let agent = {
            let signer = MgmtSigner::with_host_key_lines(
                key,
                [runner.account.as_str().to_owned()],
                &runner.host_keys,
            )
            .map_err(|_| cleanup(key_store_failed(MgmtKeyUnavailable::Failed)))?;
            SessionAgent::start(&socket, signer).map_err(|e| cleanup(agent_failed(&e)))?
        };
        let alias = mgmt_target.alias();
        let args = env_ssh::management_args(&config_file, &alias);
        let child = env_ssh::spawn_management(&ssh_client, &args, self.fill)
            .map_err(|e| cleanup(ssh_spawn_failed(e)))?;
        let env_ssh::ManagementChild {
            child,
            stdin,
            stdout,
            stderr,
        } = child;
        // ⟨M06 W5 D1⟩ The role rule (`SessionCapabilities::of`, shared by every platform):
        // `remote-control/1` is required only when this controller's record says owner (or
        // the session is the bootstrap's or a join's); `runner/1` is then offered and not
        // required. A limited record's session requires nothing and offers neither.
        let wanted = heimdall_app::remote_env::SessionCapabilities::of(
            target.standing,
            heimdall_ipc::session::server_capabilities(),
        );
        // ⟨M08 U2b-2⟩ With a kept epoch the session offers `request-epoch/1` (never requires
        // it), so the runner can check the epoch; without one the hello is unchanged.
        let mut offered = wanted.offered.clone();
        if self.kept_epoch.is_some() {
            offered.insert(heimdall_contract::ipc::capability::REQUEST_EPOCH_V1.to_owned());
        }
        let handshake = tokio::time::timeout(
            SESSION_HELLO_BOUND,
            heimdall_ipc::session::ControlClient::handshake_hello(
                tokio::io::join(stdout, stdin),
                heimdall_contract::ipc::ClientHello {
                    protocol: heimdall_contract::PROTOCOL_VERSION,
                    schema_version: heimdall_contract::SchemaVersion::current(),
                    client: heimdall_contract::ipc::PeerInfo {
                        name: CLIENT_NAME.to_owned(),
                        version: env!("CARGO_PKG_VERSION").to_owned(),
                    },
                    capabilities: offered,
                    required: wanted.required.clone(),
                    interaction: InteractionMode::NonInteractive,
                    remote_client: None,
                },
            ),
        )
        .await;
        let mut client = match handshake {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                if let Some(heimdall_ipc::session::ServerRefusal::Rejected(env)) =
                    heimdall_ipc::session::server_refusal(&e)
                {
                    return Err(cleanup(OpError::from_detail(env.data.error.clone(), None)));
                }
                let kept = stderr
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                // ⟨`w5v`; debug builds only⟩ The session's `ssh` messages for a native run's
                // evidence (a release build refuses the variable, so this reads nothing).
                if let Some(file) = crate::testcfg::launch_hooks(&|n| std::env::var_os(n))
                    .ok()
                    .and_then(|h| h.ssh_stderr_file)
                {
                    env_ssh::append_stderr_record(&file, "management session", None, &kept);
                }
                return Err(cleanup(session_error(&kept)));
            }
            Err(_) => {
                return Err(cleanup(OpError::new(
                    Code::DestinationUnreachable,
                    "the runner did not answer the management hello in time",
                )));
            }
        };
        // ⟨M06 W5 D1⟩ Whatever the server's hello said, a session that did not get what its
        // standing requires is not used.
        if !wanted.granted(&client.server().capabilities) {
            return Err(cleanup(
                OpError::new(
                    Code::CapabilityUnavailable,
                    "the runner did not grant this session the owner's management capability",
                )
                .with_reason(reason::ROLE_INSUFFICIENT)
                .with_effect(EffectStatus::None),
            ));
        }
        // ⟨M08 U2b-2⟩ The kept epoch travels with every mutating request of the session.
        client.keep_epoch(self.kept_epoch);
        let hello = SessionHello {
            environment: client.server().environment_id.clone(),
            role: client.server().role,
            client: client.server().remote_client.clone(),
        };
        Ok(Box::new(SshSession {
            client,
            hello,
            _child: child,
            agent: Some(agent),
            #[cfg(unix)]
            agent_dir: Some(agent_dir),
            dir,
            ssh_client,
            config_file,
            alias,
            fill: self.fill,
        }))
    }
}

// --- the handlers ------------------------------------------------------------------------

/// The verified `ssh` client (the M02 selection), when one is found.
fn ssh_client() -> Option<PathBuf> {
    use heimdall_localenv::clients::{ClientKind, ClientsConfig, selected_path};
    use heimdall_localenv::env::{Env, Platform};
    let env = Env::capture();
    let path = selected_path(&env, &ClientsConfig::default(), ClientKind::Ssh)?;
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    heimdall_launch::resolve::resolve_program(path.as_os_str(), &env, &cwd, Platform::current())
        .ok()
        .map(|p| p.path)
}

/// The installation's environment ID, read from the state database (read-only; `None` when
/// the installation has no state yet).
fn self_environment(db: &Path) -> Option<EnvironmentId> {
    heimdall_store::Store::open_read_only(db, Arc::new(heimdall_store::NoFaults))
        .and_then(|s| s.transaction(|tx| tx.self_environment()))
        .ok()
        .flatten()
}

/// The ports of one invocation.
struct Wiring {
    key: Arc<StoreKey>,
    registry: StoreRegistry,
    catalog: StateCatalog,
    bootstrap: env_ssh::BootstrapSsh,
    sessions: SshSessions,
    confirm: TerminalConfirm,
}

/// The ports; `write`: the command writes the controller's records ([`record_writes`]:
/// directly under the instance lock held for its whole run, or through the running runtime).
async fn wiring(ctx: &Ctx, write: bool) -> Result<Wiring, OpError> {
    let paths = ctx.paths().map_err(|e| {
        OpError::new(Code::UsageError, e.data.error.message.clone()).with_effect(EffectStatus::None)
    })?;
    let writes = if write {
        Some(record_writes(ctx, &paths).await?)
    } else {
        None
    };
    // ⟨M08 U2b-1⟩ The database the pointer names, read after the writer, which may have
    // adopted the flat store or installed the first generation under the lock.
    let db = heimdall_store::layout::db_path(&paths.state_dir)
        .map_err(|_| state_refusal("the state database cannot be located"))?;
    let environment = match &writes {
        Some(RecordWrites::Direct(w)) => w
            .store
            .transaction(|tx| tx.self_environment())
            .ok()
            .flatten(),
        _ => self_environment(&db),
    };
    let store = match environment {
        Some(environment) => Some(Arc::<dyn MgmtKeyStore>::from(mgmt_store(
            ctx,
            &environment,
        )?)),
        None => None,
    };
    let key = Arc::new(StoreKey { store });
    let ssh = ssh_client();
    let root = paths.runtime_dir.join("mgmt");
    Ok(Wiring {
        key: key.clone(),
        registry: StoreRegistry {
            db: db.clone(),
            writes,
        },
        catalog: StateCatalog { db: db.clone() },
        bootstrap: env_ssh::BootstrapSsh {
            // No client found: an empty path, which the adapter refuses (`LAUNCH_FAILED`).
            ssh_client: ssh.clone().unwrap_or_default(),
            scratch_dir: root.clone(),
            // (`environment` refused a release build's or a malformed variable already.)
            config: bootstrap_test_config(&|n| std::env::var_os(n))
                .ok()
                .flatten(),
            extra_options: Vec::new(),
            // ⟨`w5v`; debug builds only, refused by a release build with the config above⟩
            // The preflight's and the session's `ssh` messages for a native run's evidence.
            stderr_file: crate::testcfg::launch_hooks(&|n| std::env::var_os(n))
                .ok()
                .and_then(|h| h.ssh_stderr_file),
            // ⟨M06 W3⟩ The runner trusts this controller's CA and designates it as the time
            // source in the bootstrap's confirmation (omitted without an issuer).
            issuer_ca: controller_issuer_ca(&db),
            // ⟨ADR-0006 §18.7 item 8⟩ This device's endpoint ID when its verified store
            // holds K_iroh: the runner admits the bootstrap owner over Iroh with it.
            iroh_endpoint: own_iroh_endpoint(ctx),
            fill: OPENSSH_FILL,
        },
        sessions: SshSessions {
            ssh_client: ssh,
            root,
            key,
            fill: OPENSSH_FILL,
            kept_epoch: ctx.request_epoch,
        },
        confirm: TerminalConfirm {
            interactive: ctx.interactive(),
        },
    })
}

fn now() -> heimdall_contract::Timestamp {
    heimdall_contract::Timestamp::now()
}

/// ⟨M06 W5⟩ The bootstrap session's `-F` file under the test configuration: the scratch
/// account home's own `.ssh/config` (`HEIMDALL_TEST_SSH_HOME`, **debug builds only**), so
/// a fixture `environment add` reads the fixture's existing access and never the account's
/// real `~/.ssh` (which OpenSSH takes from the account database, whatever `HOME` says).
/// `Ok(None)` in every other invocation: the owner's own configuration, as the command is
/// for.
///
/// # Errors
/// The usage message (exit 2): **a release build refuses the variable** (and every other
/// launch test variable: `testcfg::launch_hooks`), never honours it and never silently
/// ignores it; a debug build refuses a relative value. [`environment`] checks this before
/// anything else.
fn bootstrap_test_config(
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<Option<PathBuf>, String> {
    Ok(crate::testcfg::launch_hooks(env)?
        .ssh_home
        .map(|home| home.join(".ssh").join("config")))
}

fn record_line(r: &RemoteEnvironmentRecord) -> String {
    format!(
        "{}  destination {}  account {}  role {:?}  client {}{}",
        r.environment.as_str(),
        r.destination.as_str(),
        r.route.runner.account.as_str(),
        r.role,
        r.client.as_str(),
        r.label
            .as_deref()
            .map(|l| format!("  label {}", output::quoted_field(l)))
            .unwrap_or_default()
    )
}

/// `environment recheck`'s human line, from the runner's answer.
fn recheck_line(environment: &EnvironmentId, data: &serde_json::Value) -> String {
    if data.get("recorded").and_then(serde_json::Value::as_bool) == Some(true) {
        format!(
            "recheck recorded on {}: the probes agree with its sshd policy. Nothing is lifted \
             yet: at the runner, run `heimdall remote policy recheck` within 15 minutes",
            environment.as_str()
        )
    } else {
        format!(
            "{} is not downgraded: nothing was recorded and there is nothing to lift",
            environment.as_str()
        )
    }
}

/// `environment remove`'s data: `removed` (the environment, as before) and, ⟨M06 W5;
/// ADR-0006 §18.9 item 6⟩ whether this device's client was revoked on the runner first.
fn remove_data(removed: &heimdall_app::remote_env::RemoveOutcome) -> serde_json::Value {
    let mut data = serde_json::json!({
        "removed": removed.environment.as_str(),
        "revoked_on_runner": removed.revoked_on_runner,
    });
    if !removed.revoked_on_runner
        && let Some(map) = data.as_object_mut()
    {
        map.insert("client".to_owned(), serde_json::json!(removed.client));
        map.insert("role".to_owned(), serde_json::json!(removed.role));
    }
    data
}

/// `environment remove`'s human line. A limited record is forgotten here only: the line
/// says that an owner must still revoke this device's client on the runner, and names it.
fn remove_line(removed: &heimdall_app::remote_env::RemoveOutcome) -> String {
    let environment = removed.environment.as_str();
    if removed.revoked_on_runner {
        return format!("removed {environment} (this device's management key is kept)");
    }
    format!(
        "forgot {environment} on this device only (this device's management key is kept). \
         This device's role there cannot revoke a client, so client {} is still enrolled on \
         the runner: an owner must still revoke it there (`heimdall environment \
         revoke-client {environment} {}` on an owner controller)",
        removed.client.as_str(),
        removed.client.as_str()
    )
}

/// ⟨M06 W5; ADR-0006 §18.9 item 6⟩ The runner's own view, as a limited role's `environment
/// status <env>` read it over its session.
fn runner_view_read(view: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "read": true, "view": view })
}

/// The same entry when the session, or the read, failed: the refusal, never a guess.
fn runner_view_unread(e: &OpError) -> serde_json::Value {
    let mut v = serde_json::json!({
        "read": false,
        "code": e.code,
        "message": e.message,
    });
    if let (Some(reason), Some(map)) = (&e.reason, v.as_object_mut()) {
        map.insert("reason".to_owned(), serde_json::json!(reason));
    }
    v
}

/// The human line of [`runner_view_read`] or [`runner_view_unread`]: what the runner said
/// of itself, or why nothing was read.
fn runner_view_lines(view: &serde_json::Value) -> String {
    if view["read"] != true {
        return format!(
            "\n  runner's view: not read ({}{}): {}",
            view["code"].as_str().unwrap_or("unknown"),
            view["reason"]
                .as_str()
                .map(|r| format!(", {r}"))
                .unwrap_or_default(),
            output::quoted_field(view["message"].as_str().unwrap_or_default()),
        );
    }
    // `inspect environments` as a role that is not the owner sees it: the runner's own
    // environment ID and whether it is enrolled.
    format!(
        "\n  runner's view (read over this device's session): environment {}  enrolled {}",
        output::quoted_field(view["view"]["environment_id"].as_str().unwrap_or("unknown")),
        view["view"]["enrolled"]
            .as_bool()
            .map_or_else(|| "unknown".to_owned(), |b| b.to_string()),
    )
}

/// `environment …`.
pub(crate) fn environment(ctx: &Ctx, command: EnvironmentCommand) -> ExitCode {
    // ⟨M06 W5⟩ The bootstrap's test seam is read here, before anything else: a release
    // build refuses its variable (exit 2) rather than ignoring it, and a malformed value
    // is a usage error (`bootstrap_test_config`; tools/validation/release-gate.sh probes
    // `environment add`).
    if let Err(message) = bootstrap_test_config(&|n| std::env::var_os(n)) {
        return emit_error(ctx, usage(&message));
    }
    // ⟨M06 W5 `w5m`⟩ So is the fixture K_mgmt store's variable: refused by a release build
    // before the terminal check, any state and any key store (release-gate.sh probes it).
    if let Some(message) = crate::testcfg::mgmt_store_refusal(&|n| std::env::var_os(n)) {
        return emit_error(ctx, usage(message));
    }
    let rt = match crate::service_cmd::current_thread() {
        Ok(rt) => rt,
        Err(env) => {
            let env = output::error_value(env);
            output::emit(&env, ctx.json);
            return output::exit_code_for(env.code, false);
        }
    };
    if let EnvironmentCommand::Join(EnvJoinArgs { show_key: true, .. }) = &command {
        return show_key(ctx);
    }
    if let EnvironmentCommand::ResumeIssuance(a) = &command {
        return environment_resume_issuance(ctx, &a.environment);
    }
    // `add` needs the owner at a terminal: refused before any state is touched.
    if matches!(command, EnvironmentCommand::Add(_)) && !ctx.interactive() {
        return emit_error(
            ctx,
            OpError::new(
                Code::InteractionRequired,
                "environment add runs an interactive ssh session with a terminal, where the \
                 runner confirms the enrollment: run it from a terminal",
            )
            .with_effect(EffectStatus::None),
        );
    }
    // The commands that write the controller's records hold the instance lock throughout, or
    // write through the running runtime (⟨rev6.3⟩ ADR-0006 §18.7 item 6).
    let write = matches!(
        command,
        EnvironmentCommand::Add(_) | EnvironmentCommand::Join(_) | EnvironmentCommand::Remove(_)
    );
    let w = match rt.block_on(wiring(ctx, write)) {
        Ok(w) => w,
        Err(e) => return emit_error(ctx, e),
    };
    let controller = RemoteEnvController::new(ControllerPorts {
        key: w.key.as_ref(),
        registry: &w.registry,
        catalog: &w.catalog,
        bootstrap: &w.bootstrap,
        sessions: &w.sessions,
        confirm: &w.confirm,
        now: now(),
    });
    let result = rt.block_on(async {
        match command {
            EnvironmentCommand::Add(a) => {
                let destination = DestinationId::parse(&a.destination)
                    .map_err(|_| usage("the destination ID is malformed"))?;
                let account = AccountName::parse(&a.account)
                    .map_err(|_| usage("the account name is malformed"))?;
                if let Some(label) = &a.label
                    && (label.is_empty()
                        || label.len() > heimdall_contract::remote::MAX_REMOTE_LABEL_BYTES
                        || label.chars().any(char::is_control))
                {
                    return Err(usage("the label must be 1 to 64 bytes without control characters"));
                }
                let record = controller
                    .add(&AddInput {
                        destination,
                        account,
                        label: a.label,
                        runner_program: a.runner_program,
                        runner_home: Some(a.runner_home),
                        runner_sha256: a.runner_sha256,
                    })
                    .await?;
                let human = format!("added {}", record_line(&record));
                Ok((serde_json::to_value(&record).unwrap_or_default(), human))
            }
            EnvironmentCommand::Invite(a) => {
                let environment = parse_environment(&a.environment)?;
                let key_fingerprint = mgmt::openssh_fingerprint(&a.public_key)
                    .ok_or_else(|| usage("--public-key is not one OpenSSH public key line"))?;
                let request_id = match a.request_id {
                    Some(id) => RequestId::parse(&id).map_err(|_| usage("the request ID is malformed"))?,
                    None => heimdall_app::remote_env::new_request_id()?,
                };
                match controller
                    .invite(&InviteInput {
                        environment: environment.clone(),
                        role: a.role.into(),
                        public_key: a.public_key,
                        key_fingerprint,
                        request_id,
                        iroh_admission: a.iroh,
                    })
                    .await?
                {
                    InviteOutcome::Created(bundle) => {
                        let value = serde_json::to_value(&*bundle).unwrap_or_default();
                        let human = format!(
                            "invitation created; give this bundle to the invited device (it is public; it grants nothing by itself):\n{}",
                            serde_json::to_string_pretty(&value).unwrap_or_default()
                        );
                        Ok((value, human))
                    }
                    // ⟨M08 U2b-2 follow-up B⟩ The retry names the epoch beside the request ID.
                    InviteOutcome::Pending {
                        decision_ref,
                        request_id,
                        request_epoch,
                    } => Err(OpError::new(
                        Code::ApprovalRequired,
                        format!(
                            "the runner holds the invitation for its local confirmation: confirm \
                             decision {decision_ref} at the runner, then run this command again \
                             with {}",
                            crate::cli::retry_args(&request_id, request_epoch)
                        ),
                    )
                    .with_effect(EffectStatus::None)
                    .with_next(NextAction {
                        action: "observe".into(),
                        decision_ref: Some(decision_ref),
                        ..NextAction::default()
                    })),
                }
            }
            EnvironmentCommand::Join(a) => {
                let bundle = read_bundle(a.bundle.as_deref())?;
                // ⟨rev6.3; ADR-0006 §18.7 item 3⟩ This device's K_iroh endpoint ID, when a
                // verified store holds it and the invitation admits Iroh.
                let own = if bundle.iroh_admission {
                    own_iroh_endpoint(ctx)
                } else {
                    None
                };
                let record = controller.join_with_endpoint(&bundle, own).await?;
                let human = format!("joined {}", record_line(&record));
                Ok((serde_json::to_value(&record).unwrap_or_default(), human))
            }
            EnvironmentCommand::RevokeClient(a) => {
                let environment = parse_environment(&a.environment)?;
                let client = ClientId::parse(&a.client).map_err(|_| usage("the client ID is malformed"))?;
                let data = controller.revoke_client(&environment, &client).await?;
                Ok((data, format!("revoked client {} on {}", client.as_str(), environment.as_str())))
            }
            EnvironmentCommand::Remove(a) => {
                let environment = parse_environment(&a.environment)?;
                let removed = controller.remove(&environment).await?;
                Ok((remove_data(&removed), remove_line(&removed)))
            }
            EnvironmentCommand::Update(a) => {
                let environment = parse_environment(&a.environment)?;
                let data = controller.update(&environment).await?;
                Ok((data, format!("update requested on {}", environment.as_str())))
            }
            EnvironmentCommand::Recheck(a) => {
                let environment = parse_environment(&a.environment)?;
                let data = controller.recheck(&environment).await?;
                let human = recheck_line(&environment, &data);
                Ok((data, human))
            }
            // Answered before the wiring (`environment_resume_issuance`).
            EnvironmentCommand::ResumeIssuance(_) => Err(OpError::new(
                Code::InternalError,
                "environment resume-issuance was not dispatched",
            )),
            EnvironmentCommand::Status(a) => {
                let environment = a.environment.as_deref().map(parse_environment).transpose()?;
                let mut report = controller.status(environment.as_ref())?;
                // ⟨M06 W3; ADR-0006 §18.7 item 13⟩ The controller's own view of each runner
                // (ADR-0012 §7.1) sits in that environment's entry: connectivity, the
                // last-known readiness computed forward, the `remote_pending` effects and
                // the residuals. Read-only, no session; absent when the state cannot be
                // read (the records still answer).
                let ids: Vec<_> = report
                    .environments
                    .iter()
                    .map(|e| e.record.environment.clone())
                    .collect();
                let mut views = remote_status_views(ctx, &ids);
                for e in &mut report.environments {
                    e.remote = views
                        .iter()
                        .position(|v| v.environment == e.record.environment)
                        .map(|i| views.swap_remove(i));
                }
                let mut human = format!("management: {}", report.management);
                for e in &report.environments {
                    human.push('\n');
                    human.push_str(&record_line(&e.record));
                    if let Some(v) = &e.remote {
                        human.push_str(&remote_lines(v));
                    }
                }
                let mut data = serde_json::to_value(&report).unwrap_or_default();
                // ⟨M06 W5; ADR-0006 §18.9 item 6⟩ A limited role's `environment status
                // <env>` also opens a session and shows the runner's own view (read-only
                // forms only). The record's own lines above answer whatever happens to
                // the session; an owner record opens none.
                if let Some(environment) = &environment {
                    let view = match controller.runner_view(environment).await {
                        Ok(None) => None,
                        Ok(Some(view)) => Some(runner_view_read(view)),
                        Err(e) => Some(runner_view_unread(&e)),
                    };
                    if let Some(view) = view {
                        human.push_str(&runner_view_lines(&view));
                        if let Some(entry) = data
                            .get_mut("environments")
                            .and_then(|l| l.get_mut(0))
                            .and_then(serde_json::Value::as_object_mut)
                        {
                            entry.insert("runner_view".to_owned(), view);
                        }
                    }
                }
                Ok((data, human))
            }
        }
    });
    match result {
        Ok((data, human)) => emit_ok(ctx, data, &human),
        Err(e) => emit_error(ctx, e),
    }
}

/// ⟨M06 W4; ADR-0006 §18.8 item 4; ADR-0012 §7.4 ⟨2026-11-21⟩⟩ `environment resume-issuance
/// <env>`: the owner's attended acknowledgement, on this controller, that the pauses and
/// cutoffs it delivered to the runner were lifted there
/// (`controller_record.resume_issuance`). A terminal and a typed `yes` to the list of
/// those effects (each with its ID, what it is, when it was delivered and whether the
/// runner's last recorded report shows it lifted); then rows are written for exactly the
/// effect IDs shown, directly under the instance lock when no runtime runs, or by the
/// running runtime over an attended local session. A pause or cutoff delivered after the
/// list was read is not acknowledged and keeps blocking. Nothing is asked when there is
/// nothing to acknowledge.
fn environment_resume_issuance(ctx: &Ctx, environment: &str) -> ExitCode {
    use heimdall_app::remote_status_driver::{DeliveredHold, delivered_holds, pin_of};
    let environment = match parse_environment(environment) {
        Ok(e) => e,
        Err(e) => return emit_error(ctx, e),
    };
    if !ctx.interactive() {
        return emit_error(
            ctx,
            OpError::new(
                Code::InteractionRequired,
                "resuming issuance needs the owner at this controller's terminal: nothing was \
                 recorded",
            )
            .with_effect(EffectStatus::None),
        );
    }
    let paths = match ctx.paths() {
        Ok(p) => p,
        Err(e) => {
            let env = output::error_value(*e);
            output::emit(&env, ctx.json);
            return output::exit_code_for(env.code, false);
        }
    };
    let db = match heimdall_store::layout::db_path(&paths.state_dir) {
        Ok(db) => db,
        Err(_) => {
            return emit_error(
                ctx,
                state_refusal("the controller's records cannot be read"),
            );
        }
    };
    let unrecorded = || {
        OpError::new(
            Code::NotFound,
            "this controller holds no record of that runner environment",
        )
        .with_effect(EffectStatus::None)
    };
    if !db.exists() {
        // No state yet: no records.
        return emit_error(ctx, unrecorded());
    }
    // What would be acknowledged, read without a lock (the write re-reads it).
    let read = heimdall_store::Store::open_read_only(&db, Arc::new(heimdall_store::NoFaults))
        .and_then(|state| {
            state.transaction(|tx| {
                if pin_of(tx, &environment)?.is_none() {
                    return Ok(None);
                }
                delivered_holds(tx, &environment).map(Some)
            })
        });
    let holds: Vec<DeliveredHold> = match read {
        Ok(Some(holds)) => holds,
        Ok(None) => return emit_error(ctx, unrecorded()),
        Err(_) => {
            return emit_error(
                ctx,
                state_refusal("the controller's records cannot be read"),
            );
        }
    };
    let undelivered = holds.iter().filter(|h| h.delivered_at.is_none()).count();
    let open: Vec<&DeliveredHold> = holds
        .iter()
        .filter(|h| h.delivered_at.is_some() && h.lift_acknowledged_at.is_none())
        .collect();
    if open.is_empty() {
        let already = holds.len() - undelivered;
        let mut human = format!(
            "nothing to acknowledge on {}: this controller delivered no pause or cutoff \
             that still awaits it",
            environment.as_str()
        );
        if undelivered > 0 {
            human.push_str(&format!(
                " ({undelivered} not yet delivered to the runner; see `heimdall environment \
                 status`)"
            ));
        }
        return emit_ok(
            ctx,
            serde_json::json!({
                "environment": environment,
                "acknowledged": [],
                "already_acknowledged": already,
                "undelivered": undelivered,
            }),
            &human,
        );
    }
    // Exactly what the owner is shown is what is acknowledged: these IDs, nothing else.
    let shown: Vec<heimdall_contract::ids::EffectId> =
        open.iter().map(|h| h.key.effect.clone()).collect();
    let text = resume_issuance_text(&environment, &open);
    let confirm = || TerminalConfirm { interactive: true }.ask(&text);
    let env = match heimdall_runtime::InstanceLock::try_acquire(&paths.state_dir) {
        Ok(lock) => {
            // No runtime: the direct write, holding the lock (⟨M08 U2b-1⟩ through the layout).
            let applied = open_locked_store(&paths).and_then(|opened| {
                acknowledge_shown(&opened.store, &environment, &shown, confirm, now())
            });
            drop(lock);
            match applied {
                Ok(data) => Envelope::ok(data),
                Err(e) => output::error_value(e.into_envelope()),
            }
        }
        Err(heimdall_runtime::instance::InstanceError::AlreadyRunning) => {
            let rt = match crate::service_cmd::current_thread() {
                Ok(rt) => rt,
                Err(env) => {
                    let env = output::error_value(env);
                    output::emit(&env, ctx.json);
                    return output::exit_code_for(env.code, false);
                }
            };
            rt.block_on(async {
                let mut client = match crate::client::connect(ctx, false).await {
                    Ok(c) => c,
                    Err(env) => return output::error_value(*env),
                };
                let attended = client.attend().await;
                if !attended.code.is_success() {
                    return attended;
                }
                if !confirm() {
                    return output::error_value(lift_not_confirmed().into_envelope());
                }
                client
                    .request(resume_issuance_request(&environment, &shown))
                    .await
            })
        }
        Err(_) => {
            output::error_value(state_refusal("the instance lock cannot be taken").into_envelope())
        }
    };
    let acknowledged = env.data["acknowledged"].as_array().map_or(0, Vec::len);
    let mut human = format!(
        "acknowledged {acknowledged} lifted effect(s) on {}; certificates are issued for it \
         again once its report shows each lift",
        environment.as_str()
    );
    if let Some(later) = env.data["not_named"].as_u64().filter(|n| *n > 0) {
        human.push_str(&format!(
            "\n{later} pause(s) or cutoff(s) delivered since the list was shown were not \
             acknowledged and still block: run the command again to see them"
        ));
    }
    emit_envelope(ctx, &env, &human)
}

/// `environment resume-issuance`'s confirmation: every delivered pause and cutoff that
/// awaits the owner's acknowledgement (`open`), one per line with its effect ID, what it is
/// (kind, policy or scope), when its delivery was recorded, and whether the runner's last
/// recorded report shows it lifted.
fn resume_issuance_text(
    environment: &EnvironmentId,
    open: &[&heimdall_app::remote_status_driver::DeliveredHold],
) -> String {
    use heimdall_app::remote_status_driver::hold_statement;
    let mut text = format!(
        "Resume issuance for runner {}.\nThis controller delivered to it:\n",
        environment.as_str()
    );
    for hold in open {
        let delivered = hold.delivered_at.map_or_else(
            || "not delivered".to_owned(),
            |at| format!("delivered {at}"),
        );
        let lift = match hold.lift_reported {
            Some(r) if r.shown => format!("the runner's report read {} shows it lifted", r.at),
            Some(r) => format!("the runner's report read {} does NOT show it lifted", r.at),
            None => "no report of the runner is recorded: not known to be lifted".to_owned(),
        };
        text.push_str(&format!(
            "    {}  {}; {delivered}; {lift}\n",
            hold.key.effect.as_str(),
            output::sanitize_for_terminal(&hold_statement(hold)),
        ));
    }
    text.push_str(
        "Confirm that you lifted each of these at the runner (its attended resume or cutoff \
         clear).\nOnly the effects listed here are acknowledged; one delivered later keeps \
         blocking until it is acknowledged itself.\nCertificates are issued for the runner \
         again only once its report shows each lift as well.\nType yes to continue: ",
    );
    text
}

/// The acknowledgement's wire form for exactly the effects the owner was shown.
fn resume_issuance_request(
    environment: &EnvironmentId,
    shown: &[heimdall_contract::ids::EffectId],
) -> heimdall_contract::request::Request {
    heimdall_contract::request::Request::ControllerRecord(
        heimdall_contract::controller_record::ControllerRecordRequest::ResumeIssuance {
            environment: environment.clone(),
            effects: shown.to_vec(),
        },
    )
}

fn lift_not_confirmed() -> OpError {
    OpError::new(
        Code::InteractionRequired,
        "the acknowledgement was not confirmed: nothing was recorded",
    )
    .with_effect(EffectStatus::None)
}

/// The direct write (no runtime; the caller holds the instance lock): after the owner's
/// `confirm`, acknowledge exactly the `shown` effects in `store`. Whatever was delivered
/// since the list was read is not among them and is left blocking.
fn acknowledge_shown(
    store: &heimdall_store::Store,
    environment: &EnvironmentId,
    shown: &[heimdall_contract::ids::EffectId],
    confirm: impl FnOnce() -> bool,
    now: heimdall_contract::Timestamp,
) -> Result<serde_json::Value, OpError> {
    if !confirm() {
        return Err(lift_not_confirmed());
    }
    heimdall_app::remote_status_driver::resume_issuance_named(store, environment, shown, true, now)
}

/// ⟨M06 U4⟩ The controller's view of each of `environments` (`heimdall_app::remote_status`),
/// read from the state store read-only at this device's clock. The command itself opens no
/// session and holds no issuer barrier: a runner reads `connected`, and issuance open, only
/// while this installation's running runtime records that its hosted driver holds a
/// resynchronized session to it. Empty when the store cannot be read.
fn remote_status_views(
    ctx: &Ctx,
    environments: &[EnvironmentId],
) -> Vec<heimdall_app::remote_status::RemoteStatus> {
    let Ok(paths) = ctx.paths() else {
        return Vec::new();
    };
    let Ok(state) = heimdall_store::layout::db_path(&paths.state_dir).and_then(|db| {
        heimdall_store::Store::open_read_only(&db, Arc::new(heimdall_store::NoFaults))
    }) else {
        return Vec::new();
    };
    let now = heimdall_contract::Timestamp::now();
    // ⟨M06 W3 host⟩ The runtime running now, if any: a session its hosted driver holds shows
    // as `connected` (a marker another instance left says nothing).
    let live = heimdall_runtime::instance::InstanceInfo::read_valid(&paths.runtime_dir)
        .ok()
        .flatten()
        .map(|i| heimdall_app::remote_status::instance_identity(i.pid, &i.started_at));
    state
        .transaction(|tx| {
            environments
                .iter()
                .map(|e| {
                    heimdall_app::remote_status::status_of_recorded(tx, e, live.as_deref(), now)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `environment status`' human lines for one runner's remote fields.
fn remote_lines(v: &heimdall_app::remote_status::RemoteStatus) -> String {
    use heimdall_contract::remote::Connectivity;
    let connectivity = match &v.connectivity {
        Connectivity::Connected => "connected".to_owned(),
        Connectivity::Disconnected { last_seen_at } => {
            format!("disconnected, last seen {last_seen_at}")
        }
        Connectivity::Unreachable { reason } => {
            format!("unreachable ({})", output::sanitize_for_terminal(reason))
        }
        _ => "unknown".to_owned(),
    };
    let mut out = format!(
        "\n    {connectivity}; {} effect(s) pending on the runner; issuance {}",
        v.remote_pending.len(),
        match v.issuance {
            heimdall_app::remote_status::IssuanceGate::Reconciled => "open",
            heimdall_app::remote_status::IssuanceGate::AwaitingResync =>
                "waits for a resynchronization",
        }
    );
    for r in &v.residuals {
        out.push_str(&format!(
            "\n    revoke of {} {}: {}",
            r.grant.as_str(),
            if r.acknowledged {
                "applied on the runner"
            } else {
                "pending on the runner"
            },
            r.statement
        ));
    }
    for c in &v.cutoffs_fired_early {
        out.push_str(&format!(
            "\n    {}",
            output::sanitize_for_terminal(&c.statement())
        ));
    }
    for f in &v.issuance_failures {
        out.push_str(&format!(
            "\n    issuance for {} failed at {} ({}); nothing was issued for it since",
            f.grant.as_str(),
            f.at,
            output::sanitize_for_terminal(&f.reason)
        ));
    }
    out
}

/// This installation's K_iroh endpoint ID when a verified platform store holds its key
/// (`heimdall_runtime::supervise_transport::held_endpoint`); `None` otherwise.
fn own_iroh_endpoint(ctx: &Ctx) -> Option<heimdall_contract::ids::IrohEndpointId> {
    let db = heimdall_store::layout::db_path(&ctx.paths().ok()?.state_dir).ok()?;
    let state =
        heimdall_store::Store::open_read_only(&db, Arc::new(heimdall_store::NoFaults)).ok()?;
    let environment = state.transaction(|tx| tx.self_environment()).ok()??;
    let keys = iroh_store(ctx, &environment);
    heimdall_runtime::supervise_transport::held_endpoint(&state, keys.as_ref())
}

/// The largest invitation bundle read.
const MAX_BUNDLE_BYTES: u64 = 64 * 1024;

fn read_bundle(path: Option<&Path>) -> Result<InvitationBundle, OpError> {
    let bad = || {
        usage(
            "the invitation bundle cannot be read (expected the JSON `environment invite` printed)",
        )
    };
    let mut text = Vec::new();
    match path {
        Some(p) if p.as_os_str() == "-" => {
            std::io::stdin()
                .take(MAX_BUNDLE_BYTES + 1)
                .read_to_end(&mut text)
                .map_err(|_| bad())?;
        }
        Some(p) => {
            crate::input_file::open_regular(p)
                .and_then(|f| f.take(MAX_BUNDLE_BYTES + 1).read_to_end(&mut text))
                .map_err(|_| bad())?;
        }
        None => return Err(bad()),
    }
    if text.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(usage("the invitation bundle is too large"));
    }
    serde_json::from_slice(&text).map_err(|_| bad())
}

/// `environment join --show-key`: this device's K_mgmt public key and fingerprint, created
/// when absent. The store item is scoped to the installation's environment ID: read from the
/// state database, or, on an installation with no state yet, recorded under the instance
/// lock first ([`writer`]); no runtime is started.
fn show_key(ctx: &Ctx) -> ExitCode {
    let result = (|| -> Result<(serde_json::Value, String), OpError> {
        let paths = ctx
            .paths()
            .map_err(|_| usage("cannot resolve the Heimdall directories"))?;
        let db = heimdall_store::layout::db_path(&paths.state_dir)
            .map_err(|_| state_refusal("the installation's environment cannot be read"))?;
        let environment = match self_environment(&db) {
            Some(environment) => environment,
            None => writer(&paths)?
                .store
                .transaction(|tx| tx.self_environment())
                .ok()
                .flatten()
                .ok_or_else(|| state_refusal("the installation's environment cannot be read"))?,
        };
        let store = mgmt_store(ctx, &environment)?;
        let (key, created) =
            mgmt::load_or_create(store.as_ref()).map_err(|e| unavailable(e).to_error())?;
        let public = key
            .public()
            .map_err(|_| MgmtKeyUnavailable::Failed.to_error())?;
        let kind = match store.kind() {
            mgmt::MgmtStoreKind::Product(k) => serde_json::to_value(k).unwrap_or_default(),
            mgmt::MgmtStoreKind::Test(name) => serde_json::json!({ "test": name }),
            _ => serde_json::Value::Null,
        };
        let data = serde_json::json!({
            "public_key": public.openssh_line,
            "fingerprint": public.fingerprint.as_str(),
            "created": created,
            "store": kind,
        });
        let human = format!(
            "this device's management key (send the line to the owner; compare the fingerprint when they invite it):\n{}\n{}",
            public.openssh_line,
            public.fingerprint.as_str()
        );
        Ok((data, human))
    })();
    match result {
        Ok((data, human)) => emit_ok(ctx, data, &human),
        Err(e) => emit_error(ctx, e),
    }
}

/// `device retire` (ADR-0012 §3.4, §3.10 item 4).
pub(crate) fn device(ctx: &Ctx, command: DeviceCommand) -> ExitCode {
    let DeviceCommand::Retire = command;
    // ⟨M06 W5 `w5m`⟩ A release build refuses the fixture K_mgmt store's variable first.
    if let Some(message) = crate::testcfg::mgmt_store_refusal(&|n| std::env::var_os(n)) {
        return emit_error(ctx, usage(message));
    }
    if !ctx.interactive() {
        return emit_error(
            ctx,
            OpError::new(
                Code::InteractionRequired,
                "device retire needs the owner at this device's terminal (a typed yes); \
                 nothing was read, revoked or destroyed",
            )
            .with_effect(EffectStatus::None),
        );
    }
    let rt = match crate::service_cmd::current_thread() {
        Ok(rt) => rt,
        Err(env) => {
            let env = output::error_value(env);
            output::emit(&env, ctx.json);
            return output::exit_code_for(env.code, false);
        }
    };
    let w = match rt.block_on(wiring(ctx, true)) {
        Ok(w) => w,
        Err(e) => return emit_error(ctx, e),
    };
    let controller = RemoteEnvController::new(ControllerPorts {
        key: w.key.as_ref(),
        registry: &w.registry,
        catalog: &w.catalog,
        bootstrap: &w.bootstrap,
        sessions: &w.sessions,
        confirm: &w.confirm,
        now: now(),
    });
    match rt.block_on(controller.retire()) {
        Ok(outcome) => {
            // ⟨M06 W5 `w5l`⟩ The line names every runner a limited record was forgotten
            // for: an owner must still revoke this device's client there.
            let human = outcome.line();
            emit_ok(
                ctx,
                serde_json::to_value(&outcome).unwrap_or_default(),
                &human,
            )
        }
        Err(e) => emit_error(ctx, e),
    }
}

// --- the runner's side (`remote init`, `remote serve`) --------------------------------------

/// `remote …`.
pub(crate) fn remote(ctx: &Ctx, command: RemoteCommand) -> ExitCode {
    match command {
        RemoteCommand::Init(a) => remote_init(ctx, &a),
        RemoteCommand::Serve(a) => remote_serve(&a),
        RemoteCommand::IssuerTrust(c) => remote_issuer_trust(ctx, c),
        RemoteCommand::TimeSource(c) => remote_time_source(ctx, c),
        RemoteCommand::Policy(RemotePolicyCommand::Recheck) => remote_policy_recheck(ctx),
    }
}

/// The SHA-256 of this executable (lowercase hex), for the bootstrap's checksum step.
fn own_sha256() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    heimdall_localenv::clients::sha256_file(&exe)
}

/// `remote init` (ADR-0012 §3.3 steps 1–3; ⟨M06-W2-R02⟩; ADR-0006 §18.7 items 7–8): the
/// checksum step, then, after the owner's typed `yes` on this terminal (the runner-local
/// confirmation of an owner enrollment, §3.10), the runner marker, the owner client
/// (idempotent for a retried bootstrap of the same key), its Iroh admission and first
/// endpoint when `--iroh-endpoint` names one (added, never replaced), the controller's CA
/// and the time-source designation when `--issuer-ca` names one, and the owner's management
/// line in this account's authorized_keys.
///
/// With no runtime on this installation the command writes under the instance lock
/// (`heimdall_runtime::paired::{enroll_owner, write_owner_line}`). With one running, it
/// attends a local session and sends `runner_local.enroll_owner` (and the issuer forms): the
/// runtime writes the records and its reconciler the line.
fn remote_init(ctx: &Ctx, a: &RemoteInitArgs) -> ExitCode {
    match remote_init_run(ctx, a) {
        Ok(Ok((data, human))) => emit_ok(ctx, data, &human),
        Ok(Err(refusal)) => emit_envelope(ctx, &refusal, ""),
        Err(e) => emit_error(ctx, e),
    }
}

/// The confirmed parts of one `remote init`.
struct InitPlan {
    enrollment: heimdall_runtime::paired::OwnerEnrollment,
    /// The controller's CA line and its fingerprint.
    issuer: Option<(String, KeyFingerprint)>,
    command: heimdall_runtime::paired::RunnerServeCommand,
    confirmation: String,
}

/// `remote init`'s confirmation: the owner key's fingerprint, the client, and next to them
/// what else this enrollment grants (the Iroh endpoint ID, the CA and the time source).
fn remote_init_confirmation(
    client: &ClientId,
    key: &KeyFingerprint,
    iroh_endpoint: Option<&IrohEndpointId>,
    issuer_ca: Option<&KeyFingerprint>,
) -> String {
    let iroh = iroh_endpoint.map_or_else(String::new, |e| {
        format!(
            "It also ADMITS this controller to this runner over Iroh, as endpoint ID:\n    \
             {}\n",
            e.as_str()
        )
    });
    let issuer = issuer_ca.map_or_else(String::new, |fp| {
        format!(
            "It also TRUSTS this controller's CA as the issuer of its grants:\n    {}\nand \
             DESIGNATES this controller as the runner's time source.\n",
            fp.as_str()
        )
    });
    format!(
        "Make this installation a Heimdall remote runner and enroll a controller as its OWNER.\n\
         Management key fingerprint:\n    {}\nClient: {}\n{iroh}{issuer}\
         Compare the fingerprints with the controller's display. Anyone with a shell on this \
         account is owner of this runner too.\nType yes to continue: ",
        key.as_str(),
        client.as_str()
    )
}

/// Everything `remote init` checks before it asks (nothing is written here).
fn remote_init_plan(ctx: &Ctx, a: &RemoteInitArgs) -> Result<InitPlan, OpError> {
    use heimdall_remote::line::PublicKeyText;
    let home = ctx
        .home
        .clone()
        .filter(|h| h.is_absolute())
        .ok_or_else(|| {
            usage("remote init needs an explicit, absolute --home (the forced command names it)")
        })?;
    let client =
        ClientId::parse(&a.owner_client).map_err(|_| usage("the client ID is malformed"))?;
    let key = PublicKeyText::parse(&a.owner_key)
        .map_err(|_| usage("--owner-key is not one ssh-ed25519 public key"))?;
    let exe = std::env::current_exe().map_err(|_| usage("cannot locate this executable"))?;
    let command = heimdall_runtime::paired::RunnerServeCommand::new(
        exe.to_str().unwrap_or_default(),
        home.to_str().unwrap_or_default(),
    )
    .map_err(|_| usage("the forced command's paths are not from the permitted character set"))?;
    if let Some(expected) = &a.expect_sha256 {
        let well_formed = expected.len() == 64
            && expected
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !well_formed {
            return Err(usage(
                "--expect-sha256 takes 64 lowercase hexadecimal characters",
            ));
        }
        if own_sha256().as_deref() != Some(expected.as_str()) {
            return Err(OpError::new(
                Code::ConfigConflict,
                "this runner's Heimdall executable does not have the expected SHA-256: nothing \
                 was written (install the verified build, then bootstrap again)",
            )
            .with_effect(EffectStatus::None));
        }
    }
    // ⟨ADR-0006 §18.7 item 8⟩ The controller's endpoint ID, validated before anything is
    // written: the contract's form, then the Iroh library's own parser where this build has
    // it (`heimdall_runtime::paired::iroh_endpoint_ok`). Anything else is refused.
    let iroh_endpoint = match &a.iroh_endpoint {
        Some(text) => Some(
            IrohEndpointId::parse(text)
                .ok()
                .filter(heimdall_runtime::paired::iroh_endpoint_ok)
                .ok_or_else(|| usage("--iroh-endpoint is not an Iroh endpoint ID"))?,
        ),
        None => None,
    };
    if !ctx.interactive() {
        return Err(OpError::new(
            Code::InteractionRequired,
            "remote init needs the owner at this runner's terminal (the bootstrap's \
             interactive ssh session): nothing was written",
        )
        .with_effect(EffectStatus::None));
    }
    // ⟨M06 W3⟩ The controller's CA, validated before anything is written: one plain Ed25519
    // key, whose fingerprint the confirmation shows.
    let issuer = match &a.issuer_ca {
        Some(line) => {
            let ca = PublicKeyText::parse(line)
                .map_err(|_| usage("--issuer-ca is not one ssh-ed25519 public key"))?;
            Some((ca.openssh(), ca.fingerprint()))
        }
        None => None,
    };
    let confirmation = remote_init_confirmation(
        &client,
        &key.fingerprint(),
        iroh_endpoint.as_ref(),
        issuer.as_ref().map(|(_, fp)| fp),
    );
    Ok(InitPlan {
        enrollment: heimdall_runtime::paired::OwnerEnrollment {
            client,
            public_key: key.openssh(),
            iroh_endpoint,
        },
        issuer,
        command,
        confirmation,
    })
}

/// The two forms `--issuer-ca` adds, for the effective owner client. ⟨M06-W3-R04⟩ Each
/// request carries its own `request_id` (one ID names one request); the forms themselves are
/// advisory and convergent on the runner (ADR-0006 §18.7: nothing is journaled by ID).
fn issuer_forms(
    owner: &ClientId,
    ca_line: &str,
) -> Result<[heimdall_contract::remote::RunnerLocalRequest; 2], OpError> {
    Ok([
        heimdall_contract::remote::RunnerLocalRequest::TrustIssuer {
            controller: owner.clone(),
            ca_public_key: ca_line.to_owned(),
            request_id: heimdall_app::remote_env::new_request_id()?,
        },
        heimdall_contract::remote::RunnerLocalRequest::DesignateTimeSource {
            client: owner.clone(),
            request_id: heimdall_app::remote_env::new_request_id()?,
        },
    ])
}

/// This runner account's authorized_keys files, when no runtime runs (`remote init`'s own
/// write): as the runtime builds them (`heimdall_runtime::paired::runner_lines`), under the
/// account's `~/.ssh`, or the test configuration's scratch home with no sshd check.
fn runner_account_lines(
    paths: &heimdall_runtime::Paths,
) -> Result<heimdall_runtime::paired_lines::AuthorizedKeysFiles, OpError> {
    let (user_dir, sshd) = runner_user_dir(paths)?;
    let rt = crate::service_cmd::current_thread()
        .map_err(|_| state_refusal("the sshd policy check cannot be started"))?;
    Ok(rt
        .block_on(heimdall_runtime::paired::runner_lines(
            sshd.as_ref(),
            &user_dir,
        ))
        .0)
}

/// This runner account's `~/.ssh` and its sshd check: the account's own (from the account
/// database), or the test configuration's scratch home with no check.
fn runner_user_dir(
    paths: &heimdall_runtime::Paths,
) -> Result<(PathBuf, Option<heimdall_runtime::paired::RunnerSshd>), OpError> {
    let hooks = crate::testcfg::launch_hooks(&|n| std::env::var_os(n)).map_err(|m| usage(&m))?;
    Ok(match hooks.ssh_home {
        Some(home) => (home.join(".ssh"), None),
        None => (
            heimdall_localenv::paths::SshPaths::resolve()
                .map_err(|_| state_refusal("the account home cannot be resolved"))?
                .user_dir,
            heimdall_runtime::paired::RunnerSshd::account(&paths.state_dir),
        ),
    })
}

/// What stands at this account's `~/.ssh` (never following a link).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshDir {
    /// Nothing: `remote init` may create it.
    Absent,
    /// The account's own directory: left exactly as it is.
    Present,
    /// Something `remote init` refuses to write under, and why.
    Refused(&'static str),
}

fn account_ssh_dir(user_dir: &Path) -> SshDir {
    match std::fs::symlink_metadata(user_dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SshDir::Absent,
        Err(_) => SshDir::Refused("cannot be inspected"),
        Ok(m) if m.file_type().is_symlink() => SshDir::Refused("is a symbolic link"),
        Ok(m) if !m.is_dir() => SshDir::Refused("is not a directory"),
        Ok(m) if !owned_by_account(&m) => SshDir::Refused("is not owned by this account"),
        Ok(_) => SshDir::Present,
    }
}

#[cfg(unix)]
fn owned_by_account(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    meta.uid() == heimdall_localenv::sys::current_uid()
}

#[cfg(not(unix))]
fn owned_by_account(_: &std::fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn create_owner_only_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn create_owner_only_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir(dir)
}

/// ⟨ADR-0006 §18.7 "Also ruled", 2026-11-21⟩ This account's `~/.ssh` for the owner's line:
/// with `create` (after the owner's confirmation) a missing one is created (mode 0700, that
/// one directory, never its parents), as `ssh-copy-id` does. An existing directory is never
/// changed (no mode, no owner). The line writer never creates the directory.
///
/// # Errors
///
/// `CONFIG_CONFLICT` (effect `none`) for a symbolic link, anything that is not a directory,
/// or a directory this account does not own: nothing is written under it.
fn ensure_account_ssh_dir(user_dir: &Path, create: bool) -> Result<(), OpError> {
    let refused = |why: &str| {
        OpError::new(
            Code::ConfigConflict,
            format!(
                "this account's ~/.ssh {why}: nothing was written (remote init creates a \
                 missing ~/.ssh and never changes or replaces an existing one)"
            ),
        )
        .with_effect(EffectStatus::None)
    };
    match account_ssh_dir(user_dir) {
        SshDir::Present => Ok(()),
        SshDir::Refused(why) => Err(refused(why)),
        SshDir::Absent if !create => Ok(()),
        SshDir::Absent => match create_owner_only_dir(user_dir) {
            Ok(()) => Ok(()),
            // Something appeared meanwhile: judged as it is now. Any other failure leaves
            // no directory, and the line is then reported unwritten.
            Err(_) => match account_ssh_dir(user_dir) {
                SshDir::Refused(why) => Err(refused(why)),
                SshDir::Present | SshDir::Absent => Ok(()),
            },
        },
    }
}

/// One thing sshd's `StrictModes` (its default) refuses an account's keys for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StrictModesProblem {
    /// `home`, `ssh_dir` or `authorized_keys`.
    pub(crate) what: &'static str,
    /// `group_or_other_writable` or `wrong_owner`.
    pub(crate) problem: &'static str,
}

/// ⟨ADR-0006 §18.7 "Also ruled", 2026-11-21⟩ What sshd's `StrictModes` would refuse this
/// account's `authorized_keys` for, as sshd checks it: the home directory, `~/.ssh` and the
/// file must each be owned by the account or by root and not be writable by group or
/// others. Reported, never fixed. Missing entries are not problems. Unix only.
#[cfg(unix)]
pub(crate) fn strict_modes_problems(user_dir: &Path) -> Vec<StrictModesProblem> {
    use std::os::unix::fs::MetadataExt as _;
    let uid = heimdall_localenv::sys::current_uid();
    let keys = user_dir.join("authorized_keys");
    let entries = [
        ("home", user_dir.parent()),
        ("ssh_dir", Some(user_dir)),
        ("authorized_keys", Some(keys.as_path())),
    ];
    let mut problems = Vec::new();
    for (what, path) in entries {
        let Some(meta) = path.and_then(|p| std::fs::metadata(p).ok()) else {
            continue;
        };
        if meta.uid() != uid && meta.uid() != 0 {
            problems.push(StrictModesProblem {
                what,
                problem: "wrong_owner",
            });
        }
        if meta.mode() & 0o022 != 0 {
            problems.push(StrictModesProblem {
                what,
                problem: "group_or_other_writable",
            });
        }
    }
    problems
}

/// No `StrictModes` on this platform's account files: nothing to report.
#[cfg(not(unix))]
pub(crate) fn strict_modes_problems(_: &Path) -> Vec<StrictModesProblem> {
    Vec::new()
}

/// The sentence naming `problems` (`remote init`'s output and `doctor`'s finding).
pub(crate) fn strict_modes_statement(problems: &[StrictModesProblem]) -> String {
    let named: Vec<String> = problems
        .iter()
        .map(|p| {
            let what = match p.what {
                "home" => "the home directory",
                "ssh_dir" => "~/.ssh",
                _ => "~/.ssh/authorized_keys",
            };
            let problem = match p.problem {
                "wrong_owner" => "is not owned by this account",
                _ => "is writable by group or others",
            };
            format!("{what} {problem}")
        })
        .collect();
    format!(
        "sshd's StrictModes (its default) refuses this account's authorized_keys, so no \
         management key can log in: {}. Heimdall does not change these; fix the owner or \
         remove the group and other write permission (`chmod go-w`) yourself",
        named.join("; ")
    )
}

/// This runner account's `StrictModes` problems (`doctor`'s finding): none when the
/// account's SSH directory cannot be resolved.
pub(crate) fn runner_strict_modes(paths: &heimdall_runtime::Paths) -> Vec<StrictModesProblem> {
    runner_user_dir(paths)
        .map(|(user_dir, _)| strict_modes_problems(&user_dir))
        .unwrap_or_default()
}

type InitAnswer = Result<(serde_json::Value, String), Envelope<serde_json::Value>>;

fn remote_init_run(ctx: &Ctx, a: &RemoteInitArgs) -> Result<InitAnswer, OpError> {
    let plan = remote_init_plan(ctx, a)?;
    let paths = ctx
        .paths()
        .map_err(|_| usage("cannot resolve the Heimdall directories"))?;
    let not_confirmed = || {
        OpError::new(
            Code::InteractionRequired,
            "the owner enrollment was not confirmed: nothing was written",
        )
        .with_effect(EffectStatus::None)
    };
    // ⟨ADR-0006 §18.7 "Also ruled"⟩ A `~/.ssh` that is a link, not a directory or not this
    // account's is refused before anything is asked or written; the confirmed enrollment
    // creates a missing one for its line (and judges again what stands there then).
    let (user_dir, _) = runner_user_dir(&paths)?;
    ensure_account_ssh_dir(&user_dir, false)?;
    let confirm = || -> Result<bool, OpError> {
        let yes = TerminalConfirm { interactive: true }.ask(&plan.confirmation);
        if yes {
            ensure_account_ssh_dir(&user_dir, true)?;
        }
        Ok(yes)
    };
    let Some(w) = try_writer(&paths)? else {
        let answer = remote_init_through_runtime(ctx, &plan, &user_dir, &confirm, &not_confirmed)?;
        // A runtime holds this home and answered as a runner's: it is running.
        return Ok(answer.map(|(data, human)| {
            if a.offer_runtime_start {
                output::diagnostic(RUNTIME_RUNNING);
            }
            (data, human)
        }));
    };
    if !confirm()? {
        return Err(not_confirmed());
    }
    let enrolled = heimdall_runtime::paired::enroll_owner(&w.store, now(), &plan.enrollment)?;
    // ⟨M06 W3; ADR-0006 §18.7 item 7⟩ Confirmed in the same confirmation: the controller's CA
    // trusted for the effective owner client, and that client designated as the time source
    // (both idempotent for a retried bootstrap).
    let mut issuer_data = None;
    if let Some((ca_line, ca_fp)) = &plan.issuer {
        for request in issuer_forms(&enrolled.owner.client, ca_line)? {
            heimdall_runtime::runner::runner_local(&w.store, now(), true, &request)?;
        }
        issuer_data = Some(serde_json::json!({
            "ca_fingerprint": ca_fp.as_str(),
            "time_source": enrolled.owner.client.as_str(),
        }));
    }
    // ⟨M06-W2-R02⟩ The owner's line, written now through the runner's own writer.
    let line = enrolled
        .line(&plan.command)
        .ok_or_else(|| usage("the management line cannot be rendered"))?;
    let lines = runner_account_lines(&paths)?;
    let written =
        heimdall_runtime::paired::write_owner_line(&w.store, &lines, &enrolled.owner.client, &line);
    let mut data = enrolled.data(Some(&line), written);
    let answer = init_answer(&mut data, issuer_data, &user_dir);
    // ⟨M06 W5⟩ The instance lock is released before the runtime may be started; then the
    // bootstrap's offer, on this terminal (never a silent second pass). What it states is
    // printed there once, in text and JSON mode alike, before the command's answer.
    drop(w);
    if a.offer_runtime_start {
        offer_runtime_start(ctx, &paths, &|text| {
            TerminalConfirm { interactive: true }.ask(text)
        });
    }
    Ok(Ok(answer))
}

/// ⟨M06 W5⟩ What the bootstrap says when this runner's runtime already runs.
const RUNTIME_RUNNING: &str = "The runner's runtime is running on this installation.";

/// ⟨M06 W5⟩ What the bootstrap says, before its offer, when the runtime does not run.
const RUNTIME_NOT_RUNNING: &str = "The runner's runtime is NOT running on this installation, so the controller cannot open \
     its management session yet.";

/// ⟨M06 W5; ADR-0012 §2.6, the 2026-11-22 bullets⟩ The command a runner's runtime is
/// started with, for the offer's text and its declined next step: this executable, the
/// explicit home, `service run --runner --detach`.
fn runtime_start_line(exe: &Path, home: &Path) -> String {
    format!(
        "{} --home {} service run --runner --detach",
        exe.display(),
        home.display()
    )
}

/// The offer's prompt.
fn runtime_start_offer(line: &str) -> String {
    format!(
        "{RUNTIME_NOT_RUNNING}\nStart it now, detached from this session? It runs:\n    {line}\n\
         Started here it belongs to this login session and may stop when the session's \
         processes are ended; a user service that starts it at login outlives that.\n\
         Type yes to start it: "
    )
}

/// What a declined (or unanswered) offer leaves on the terminal: the next step.
fn runtime_start_declined(line: &str) -> String {
    format!(
        "The runner's runtime was not started. Next step: start it on this runner,\n    \
         {line}\nthen run `heimdall environment add` on the controller again with the same \
         arguments: it repairs the record after the same confirmation. Until then the \
         controller has recorded nothing."
    )
}

/// ⟨M06 W5⟩ The variables a runtime started from the bootstrap session receives from that
/// session, and nothing else of it (no `SSH_AUTH_SOCK`, `SSH_CONNECTION`, `SSH_TTY`,
/// askpass or agent variable: a runner's runtime never inherits a login session's
/// credential sources, ADR-0012 §4). A debug build also passes its own `HEIMDALL_TEST_*`
/// configuration, so a fixture runner keeps its scratch SSH home.
#[cfg_attr(not(unix), allow(dead_code))]
const RUNTIME_START_ENV: [&str; 11] = [
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
];

/// The environment of the started runtime: [`RUNTIME_START_ENV`] from `vars`, plus, when
/// the test configuration is available (debug builds), every `HEIMDALL_TEST_*` variable.
#[cfg_attr(not(unix), allow(dead_code))]
fn runtime_start_env(
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    test_configuration: bool,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    vars.filter(|(name, _)| {
        name.to_str().is_some_and(|n| {
            RUNTIME_START_ENV.contains(&n)
                || (test_configuration && n.starts_with("HEIMDALL_TEST_"))
        })
    })
    .collect()
}

/// ⟨M06 W5; ADR-0012 §2.6, the 2026-11-22 bullets⟩ The bootstrap's offer on a runner whose
/// runtime does not run (the caller released the instance lock): say so, ask for a typed
/// `yes` through `ask`, and on `yes` start `service run --runner --detach` on this home
/// with [`runtime_start_env`], detached, then wait until it serves. Returns the line that
/// states the outcome (also printed): running, or not started with the next step. Nothing
/// is started without the typed `yes`.
fn offer_runtime_start(
    ctx: &Ctx,
    paths: &heimdall_runtime::Paths,
    ask: &dyn Fn(&str) -> bool,
) -> String {
    let (Some(home), Ok(exe)) = (ctx.home.as_deref(), std::env::current_exe()) else {
        // (`remote init` refused a missing home before this.)
        let stated = format!(
            "{RUNTIME_NOT_RUNNING} Start it on this runner, then run `heimdall environment add` on the controller again."
        );
        output::diagnostic(&stated);
        return stated;
    };
    let line = runtime_start_line(&exe, home);
    let stated = if ask(&runtime_start_offer(&line)) {
        match start_runner_runtime(&exe, home, paths) {
            Ok(()) => {
                "The runner's runtime is running on this installation (started now).".to_owned()
            }
            Err(why) => format!(
                "The runner's runtime did not start ({why}). {}",
                runtime_start_declined(&line)
            ),
        }
    } else {
        runtime_start_declined(&line)
    };
    output::diagnostic(&stated);
    stated
}

/// Start this runner's runtime detached and wait until it serves (the launcher's bound).
#[cfg(unix)]
fn start_runner_runtime(
    exe: &Path,
    home: &Path,
    paths: &heimdall_runtime::Paths,
) -> Result<(), String> {
    use std::os::unix::process::CommandExt as _;
    let spawn = || -> std::io::Result<()> {
        let mut command = heimdall_app::no_window!(std::process::Command::new(exe));
        command
            .arg("--home")
            .arg(home)
            .args(["service", "run", "--runner", "--detach"])
            .env_clear()
            .envs(runtime_start_env(
                std::env::vars_os(),
                crate::testcfg::AVAILABLE,
            ))
            // The same home as `--home`, for the processes the runtime starts itself.
            .env(heimdall_runtime::paths::HOME_ENV, home)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .process_group(0);
        // Only the three null standard descriptors reach the long-lived runtime.
        heimdall_runtime::platform::disinherit_descriptors_above_stdio()?;
        command.spawn().map(drop)
    };
    let rt = crate::service_cmd::current_thread().map_err(|_| "no client runtime".to_owned())?;
    rt.block_on(heimdall_runtime::launcher::ensure_running_with(
        &paths.runtime_dir,
        true,
        heimdall_runtime::launcher::LauncherConfig::default(),
        &spawn,
    ))
    .map(drop)
    .map_err(|e| e.to_string())
}

/// A runner is Unix-only in V1 (m06-plan §5): nothing is started elsewhere.
#[cfg(not(unix))]
fn start_runner_runtime(_: &Path, _: &Path, _: &heimdall_runtime::Paths) -> Result<(), String> {
    Err("a remote runner's runtime is not available on this platform".to_owned())
}

/// Add the issuer part and what sshd's `StrictModes` would refuse (`strict_modes`, omitted
/// when nothing), and render the human text of a `remote init` answer.
fn init_answer(
    data: &mut serde_json::Value,
    issuer: Option<serde_json::Value>,
    user_dir: &Path,
) -> (serde_json::Value, String) {
    if let (Some(issuer), Some(map)) = (issuer, data.as_object_mut()) {
        map.insert("issuer_trust".to_owned(), issuer);
    }
    let strict = strict_modes_problems(user_dir);
    if let (false, Some(map)) = (strict.is_empty(), data.as_object_mut()) {
        let items: Vec<serde_json::Value> = strict
            .iter()
            .map(|p| serde_json::json!({ "path": p.what, "problem": p.problem }))
            .collect();
        map.insert("strict_modes".to_owned(), items.into());
    }
    let text = |k: &str| data[k].as_str().unwrap_or_default().to_owned();
    let line = if data["line_written"] == true {
        "Its management line is in this account's authorized_keys."
    } else {
        "Its management line could not be written to this account's authorized_keys (the \
         file, or its directory, is missing or is one Heimdall does not rewrite): the line is \
         in the JSON output (`management_line`), and the runner runtime writes it at its next \
         start once the file can be written."
    };
    let mut human = format!(
        "this installation is remote runner {} with owner client {}{}.\n{line}",
        text("environment"),
        text("client"),
        if data["created"] == true {
            ""
        } else {
            " (already enrolled)"
        }
    );
    if !strict.is_empty() {
        human.push_str("\nWarning: ");
        human.push_str(&strict_modes_statement(&strict));
        human.push('.');
    }
    (data.clone(), human)
}

/// ⟨M06-W2-R02⟩ `remote init` while this installation's runtime runs (it holds the instance
/// lock): a local session, attended, the same typed confirmation, then
/// `runner_local.enroll_owner` and, with `--issuer-ca`, the two issuer forms for the
/// effective owner client. The first refusal is the answer.
fn remote_init_through_runtime(
    ctx: &Ctx,
    plan: &InitPlan,
    user_dir: &Path,
    confirm: &dyn Fn() -> Result<bool, OpError>,
    not_confirmed: &dyn Fn() -> OpError,
) -> Result<InitAnswer, OpError> {
    use heimdall_contract::remote::RunnerLocalRequest;
    use heimdall_contract::request::Request;
    let rt = crate::service_cmd::current_thread().map_err(|env| {
        OpError::new(env.code.clone(), "the client runtime cannot be started")
            .with_effect(EffectStatus::None)
    })?;
    rt.block_on(async {
        let mut client = match crate::client::connect_requiring(
            ctx,
            false,
            &[heimdall_contract::ipc::capability::REMOTE_CONTROL_V1],
        )
        .await
        {
            Ok(c) => c,
            // ⟨ADR-0006 §18.7 "Also ruled"⟩ The runtime that holds this home is not a
            // runner's (it does not offer `remote-control/1`): a first `remote init` cannot
            // go through it.
            Err(env) if env.code == Code::SchemaUnsupported => return Err(not_a_runner_runtime()),
            Err(env) => return Ok(Err(output::error_value(*env))),
        };
        let attended = client.attend().await;
        if !attended.code.is_success() {
            return Ok(Err(attended));
        }
        if !confirm()? {
            return Err(not_confirmed());
        }
        let enrolled = client
            .request(Request::RunnerLocal(RunnerLocalRequest::EnrollOwner {
                client: plan.enrollment.client.clone(),
                public_key: plan.enrollment.public_key.clone(),
                iroh_endpoint: plan.enrollment.iroh_endpoint.clone(),
                request_id: heimdall_app::remote_env::new_request_id()?,
            }))
            .await;
        if !enrolled.code.is_success() {
            return Ok(Err(enrolled));
        }
        let mut data = enrolled.data;
        let mut issuer_data = None;
        if let Some((ca_line, ca_fp)) = &plan.issuer {
            let owner = data["client"]
                .as_str()
                .and_then(|c| ClientId::parse(c).ok())
                .ok_or_else(|| {
                    OpError::new(Code::InternalError, "the runtime's answer names no client")
                        .with_effect(EffectStatus::Unknown)
                })?;
            for request in issuer_forms(&owner, ca_line)? {
                let env = client.request(Request::RunnerLocal(request)).await;
                if !env.code.is_success() {
                    return Ok(Err(env));
                }
            }
            issuer_data = Some(serde_json::json!({
                "ca_fingerprint": ca_fp.as_str(),
                "time_source": owner.as_str(),
            }));
        }
        Ok(Ok(init_answer(&mut data, issuer_data, user_dir)))
    })
}

/// A first `remote init` while this home's runtime runs and is not a runner's
/// (`driver_unavailable`, effect `none`): the owner stops it and runs `remote init` again.
fn not_a_runner_runtime() -> OpError {
    OpError::driver_unavailable(
        "this installation's runtime is running and is not a remote runner's, so the first \
         remote init cannot go through it: stop the local runtime first (`heimdall service \
         stop`), then run remote init again. Nothing was written",
    )
    .with_effect(EffectStatus::None)
}

// --- ⟨M06 W3⟩ the runner-local decisions (`remote issuer-trust`, `remote time-source`) -----

/// The controller's active issuer CA public key line, read from the state database (read
/// only; `None` without state or without an active issuer): the bootstrap passes it to the
/// runner's `remote init` (ADR-0006 §18.7 item 7).
fn controller_issuer_ca(db: &Path) -> Option<String> {
    heimdall_store::Store::open_read_only(db, Arc::new(heimdall_store::NoFaults))
        .and_then(|s| s.transaction(|tx| tx.issuers()))
        .ok()?
        .into_iter()
        .find(|i| i.state == heimdall_contract::issuer::CaState::Active)
        .map(|i| i.public_key)
}

/// This installation's state database path.
fn state_db(ctx: &Ctx) -> Result<PathBuf, OpError> {
    let paths = ctx
        .paths()
        .map_err(|_| usage("cannot resolve the Heimdall directories"))?;
    heimdall_store::layout::db_path(&paths.state_dir)
        .map_err(|_| state_refusal("the state database cannot be located"))
}

/// A read-only view of this runner's state (`None`: no state yet). Refuses an installation
/// that is not a remote runner before anything else is read or written.
fn runner_read<T>(
    ctx: &Ctx,
    read: impl FnOnce(&mut heimdall_store::Txn<'_>) -> heimdall_store::Result<T>,
) -> Result<T, OpError> {
    let not_runner = || {
        OpError::driver_unavailable(
            "this installation is not a remote runner (`remote init` first)",
        )
        .with_effect(EffectStatus::None)
    };
    let db = state_db(ctx)?;
    if !db.exists() {
        return Err(not_runner());
    }
    let store = heimdall_store::Store::open_read_only(&db, Arc::new(heimdall_store::NoFaults))
        .map_err(|_| state_refusal("the state database cannot be opened"))?;
    store
        .transaction(|tx| {
            if !heimdall_runtime::paired::is_runner(tx)? {
                return Ok(None);
            }
            read(tx).map(Some)
        })
        .map_err(|_| state_refusal("this runner's state cannot be read"))?
        .ok_or_else(not_runner)
}

/// Apply one runner-local form (ADR-0006 §18.7 item 7): sent to the runtime when one runs on
/// this installation (a local owner session, attended for a widening form), written directly
/// under the instance lock when none does. A widening form needs this terminal and the
/// owner's typed `yes` to `confirmation` first (`--non-interactive` or a non-terminal stdin
/// is refused `INTERACTION_REQUIRED` before anything is read).
fn runner_local_apply(
    ctx: &Ctx,
    request: heimdall_contract::remote::RunnerLocalRequest,
    confirmation: Option<String>,
) -> Envelope<serde_json::Value> {
    let refusal = |e: OpError| output::error_value(e.into_envelope());
    if request.is_widening() && !ctx.interactive() {
        return refusal(
            OpError::new(
                Code::InteractionRequired,
                "this decision needs the owner at this runner's terminal (an interactive ssh \
                 session counts): nothing was changed",
            )
            .with_effect(EffectStatus::None),
        );
    }
    if let Err(e) = runner_read(ctx, |_| Ok(())) {
        return refusal(e);
    }
    let confirm = |text: &Option<String>| match text {
        Some(t) => TerminalConfirm { interactive: true }.ask(t),
        None => true,
    };
    let not_confirmed = || {
        refusal(
            OpError::new(
                Code::InteractionRequired,
                "the decision was not confirmed: nothing was changed",
            )
            .with_effect(EffectStatus::None),
        )
    };
    let paths = match ctx.paths() {
        Ok(p) => p,
        Err(e) => return output::error_value(*e),
    };
    match heimdall_runtime::InstanceLock::try_acquire(&paths.state_dir) {
        Ok(lock) => {
            // No runtime: the direct write, holding the lock (⟨M08 U2b-1⟩ through the layout).
            let store = match open_locked_store(&paths) {
                Ok(opened) => opened.store,
                Err(e) => return refusal(e),
            };
            if !confirm(&confirmation) {
                return not_confirmed();
            }
            let applied = match &request {
                // ⟨§18.7 item 19⟩ The attended lift, judged on this process's clock reading.
                heimdall_contract::remote::RunnerLocalRequest::PolicyRecheck { .. } => {
                    heimdall_runtime::paired::lift_downgrade(
                        &store,
                        &heimdall_runtime::paired::ClockReading::of(
                            &heimdall_runtime::platform::SystemClock,
                        ),
                        true,
                    )
                }
                _ => heimdall_runtime::runner::runner_local(
                    &store,
                    now(),
                    request.is_widening(),
                    &request,
                ),
            };
            let env = heimdall_runtime::dispatch::render(applied);
            drop(lock);
            env
        }
        Err(heimdall_runtime::instance::InstanceError::AlreadyRunning) => {
            let rt = match crate::service_cmd::current_thread() {
                Ok(rt) => rt,
                Err(env) => return output::error_value(env),
            };
            rt.block_on(async {
                let mut client = match crate::client::connect_requiring(
                    ctx,
                    false,
                    &[heimdall_contract::ipc::capability::REMOTE_CONTROL_V1],
                )
                .await
                {
                    Ok(c) => c,
                    Err(env) => return output::error_value(*env),
                };
                if request.is_widening() {
                    let attended = client.attend().await;
                    if !attended.code.is_success() {
                        return attended;
                    }
                }
                if !confirm(&confirmation) {
                    return not_confirmed();
                }
                client
                    .request(heimdall_contract::request::Request::RunnerLocal(request))
                    .await
            })
        }
        Err(_) => refusal(state_refusal("the instance lock cannot be taken")),
    }
}

fn emit_envelope(ctx: &Ctx, env: &Envelope<serde_json::Value>, human: &str) -> ExitCode {
    if env.code.is_success() && !ctx.json {
        output::emit_rendered(env, false, human);
    } else {
        output::emit(env, ctx.json);
    }
    output::exit_code_for(env.code.clone(), false)
}

/// `remote issuer-trust …` (ADR-0006 §18.7 item 7).
fn remote_issuer_trust(ctx: &Ctx, command: IssuerTrustCommand) -> ExitCode {
    use heimdall_contract::remote::RunnerLocalRequest;
    match command {
        IssuerTrustCommand::List => match runner_read(ctx, |tx| tx.remote_issuer_trust()) {
            Ok(entries) => {
                let human = if entries.is_empty() {
                    "no trusted issuer".to_owned()
                } else {
                    entries
                        .iter()
                        .map(|e| format!("{}  controller {}", e.ca_fingerprint, e.controller))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                let data = serde_json::json!({
                    "issuer_trust": entries.iter().map(|e| serde_json::json!({
                        "ca_fingerprint": e.ca_fingerprint,
                        "controller": e.controller,
                        "trusted_at": e.trusted_at,
                    })).collect::<Vec<_>>(),
                });
                emit_ok(ctx, data, &human)
            }
            Err(e) => emit_error(ctx, e),
        },
        IssuerTrustCommand::Remove(a) => {
            let Ok(ca_fingerprint) = heimdall_contract::ids::CaFingerprint::parse(&a.fingerprint)
            else {
                return emit_error(
                    ctx,
                    usage("the fingerprint is not `SHA256:` and 43 characters"),
                );
            };
            let env = runner_local_apply(
                ctx,
                RunnerLocalRequest::DistrustIssuer { ca_fingerprint },
                None,
            );
            emit_envelope(ctx, &env, "issuer trust updated")
        }
        IssuerTrustCommand::Add(a) => {
            let added = (|| -> Result<(RunnerLocalRequest, String), OpError> {
                let text = read_small_file(&a.file)?;
                let line = text.trim();
                let fingerprint = heimdall_issuer::remote::public_key_fingerprint(line)
                    .ok_or_else(|| usage("the file does not hold one OpenSSH public key line"))?;
                let controller = match &a.controller {
                    Some(c) => {
                        ClientId::parse(c).map_err(|_| usage("the client ID is malformed"))?
                    }
                    None => sole_owner(ctx)?,
                };
                // ⟨ruling Q12⟩ The confirmation names the controller by its client ID and its
                // management key's fingerprint, read from this runner's role table.
                let mgmt = runner_read(ctx, |tx| tx.remote_client(&controller))?
                    .filter(|c| {
                        c.state == heimdall_store::ext_m06::ClientState::Active
                            && c.role == Role::Owner
                    })
                    .map(|c| c.key_fingerprint)
                    .ok_or_else(|| {
                        OpError::new(
                            Code::CapabilityUnavailable,
                            "the controller is not an active owner client of this runner",
                        )
                        .with_reason(reason::ROLE_INSUFFICIENT)
                        .with_effect(EffectStatus::None)
                    })?;
                let text = issuer_trust_confirmation(&controller, &mgmt, &fingerprint);
                Ok((
                    RunnerLocalRequest::TrustIssuer {
                        controller,
                        ca_public_key: line.to_owned(),
                        request_id: heimdall_app::remote_env::new_request_id()?,
                    },
                    text,
                ))
            })();
            match added {
                Ok((request, text)) => {
                    let env = runner_local_apply(ctx, request, Some(text));
                    emit_envelope(ctx, &env, "issuer trusted")
                }
                Err(e) => emit_error(ctx, e),
            }
        }
    }
}

/// `remote time-source …` (ADR-0006 §18.7 item 7).
fn remote_time_source(ctx: &Ctx, command: TimeSourceCommand) -> ExitCode {
    use heimdall_contract::remote::RunnerLocalRequest;
    match command {
        TimeSourceCommand::Show => match runner_read(ctx, |tx| tx.time_source()) {
            Ok(d) => {
                let human = d.as_ref().map_or_else(
                    || "no time source is designated".to_owned(),
                    |d| format!("time source: {}", d.client),
                );
                let data = serde_json::json!({
                    "time_source": d.map(|d| serde_json::json!({
                        "client": d.client,
                        "designated_at": d.designated_at,
                    })),
                });
                emit_ok(ctx, data, &human)
            }
            Err(e) => emit_error(ctx, e),
        },
        TimeSourceCommand::Clear => {
            let env = runner_local_apply(ctx, RunnerLocalRequest::ClearTimeSource, None);
            emit_envelope(ctx, &env, "time source cleared")
        }
        TimeSourceCommand::Set(a) => {
            let set = (|| -> Result<RunnerLocalRequest, OpError> {
                Ok(RunnerLocalRequest::DesignateTimeSource {
                    client: ClientId::parse(&a.client)
                        .map_err(|_| usage("the client ID is malformed"))?,
                    request_id: heimdall_app::remote_env::new_request_id()?,
                })
            })();
            match set {
                Ok(request) => {
                    let text = format!(
                        "Designate client {} as this runner's trusted time source (its time \
                         samples may shorten deadlines, never extend them).\nType yes to \
                         continue: ",
                        a.client
                    );
                    let env = runner_local_apply(ctx, request, Some(text));
                    emit_envelope(ctx, &env, "time source designated")
                }
                Err(e) => emit_error(ctx, e),
            }
        }
    }
}

/// ⟨ADR-0006 §18.7 item 19⟩ `remote policy recheck`: show the evidence an owner's controller
/// left, then lift the owner-only downgrade after the typed `yes`. Refused before anything
/// is asked when the evidence would not lift it now; the lift judges it again, in its own
/// transaction.
fn remote_policy_recheck(ctx: &Ctx) -> ExitCode {
    if !ctx.interactive() {
        return emit_error(
            ctx,
            OpError::new(
                Code::InteractionRequired,
                "this decision needs the owner at this runner's terminal (an interactive ssh \
                 session counts): nothing was changed",
            )
            .with_effect(EffectStatus::None),
        );
    }
    let text = match policy_recheck_precheck(ctx) {
        Ok(Some(text)) => text,
        Ok(None) => {
            return emit_ok(
                ctx,
                serde_json::json!({ "downgraded": false, "lifted": false }),
                "this runner is not downgraded: there is nothing to lift",
            );
        }
        Err(e) => return emit_error(ctx, e),
    };
    let request = match heimdall_app::remote_env::new_request_id() {
        Ok(request_id) => {
            heimdall_contract::remote::RunnerLocalRequest::PolicyRecheck { request_id }
        }
        Err(e) => return emit_error(ctx, e),
    };
    let env = runner_local_apply(ctx, request, Some(text));
    emit_envelope(
        ctx,
        &env,
        "the owner-only downgrade is lifted: limited roles are admitted again wherever this \
         runner's start check verifies its sshd policy",
    )
}

/// `remote policy recheck`'s read-only pre-check, before anything is asked: the
/// confirmation to show when the recorded evidence would lift the standing downgrade now;
/// `None` when this runner is not downgraded and no downgrade event is pending.
///
/// ⟨W3.1 re-check, low finding 2⟩ A downgrade the bridge could not record (its marker in
/// this home's log directory, `heimdall_runtime::paired::unrecorded_downgrade`) is a
/// downgrade although the store holds no row yet: with no row it is refused here, as the
/// lift itself refuses it, instead of being reported as "not downgraded". Nothing is
/// drained here (the runtime, or the lift under the instance lock, records the row).
///
/// # Errors
/// The refusal: not a runner, unreadable state, a pending unrecorded downgrade, or
/// evidence that would not lift the downgrade now.
fn policy_recheck_precheck(ctx: &Ctx) -> Result<Option<String>, OpError> {
    use heimdall_runtime::paired::{ClockReading, LiftRefusal, recheck_view, unrecorded_downgrade};
    let reading = ClockReading::of(&heimdall_runtime::platform::SystemClock);
    let view = runner_read(ctx, |tx| recheck_view(tx, &reading))?;
    let Some(downgrade) = &view.downgrade else {
        let pending = ctx
            .paths()
            .is_ok_and(|paths| unrecorded_downgrade(&paths.log_dir).is_some());
        return if pending {
            Err(LiftRefusal::MarkerPending.to_error())
        } else {
            Ok(None)
        };
    };
    view.verdict.map_err(LiftRefusal::to_error)?;
    let (Some(evidence), Some(controller)) = (&view.evidence, &view.controller) else {
        return Err(LiftRefusal::NoEvidence.to_error());
    };
    Ok(Some(policy_recheck_confirmation(
        downgrade,
        evidence,
        &controller.key_fingerprint,
    )))
}

/// `remote policy recheck`'s attended confirmation: why the runner is owner-only, and the
/// evidence (the probing controller by its client ID and management key fingerprint, when,
/// and what its probes observed).
fn policy_recheck_confirmation(
    downgrade: &heimdall_store::ext_runner::RunnerDowngrade,
    evidence: &heimdall_store::ext_runner::PolicyRecheckEvidence,
    mgmt: &heimdall_contract::ids::KeyFingerprint,
) -> String {
    let cause = heimdall_runtime::paired::OwnerOnlyCause::of_token(&downgrade.cause);
    let said = |refused: bool| if refused { "refused" } else { "GRANTED" };
    format!(
        "This runner is owner-only since {}: {}.\nA recheck was recorded at {} from the \
         controller with client ID\n    {}\nand management key fingerprint\n    {}\nIts \
         probes of a real management session observed: terminal {}, port forwarding {}, \
         agent forwarding {}, client environment {}.\nLifting the downgrade lets limited \
         roles (requester, viewer) be invited to this runner again. Do it only if you have \
         corrected what caused it. Type yes to continue: ",
        downgrade.recorded_at,
        cause.statement(),
        evidence.recorded_at,
        evidence.controller.as_str(),
        mgmt.as_str(),
        said(evidence.probe.pty_refused),
        said(evidence.probe.forward_refused),
        said(evidence.probe.agent_forward_refused),
        said(!evidence.probe.setenv_canary_delivered),
    )
}

/// `remote issuer-trust add`'s attended confirmation (ruling Q12): the CA's fingerprint, and
/// the controller by its client ID and its management key's (K_mgmt) fingerprint.
fn issuer_trust_confirmation(
    controller: &ClientId,
    mgmt: &heimdall_contract::ids::KeyFingerprint,
    ca: &impl std::fmt::Display,
) -> String {
    format!(
        "Trust this CA as the issuer of this runner's grants:\n    {ca}\nfor the controller \
         with client ID\n    {}\nand management key fingerprint\n    {}\nCompare both \
         fingerprints with the controller's display. Type yes to continue: ",
        controller.as_str(),
        mgmt.as_str()
    )
}

/// This runner's only active owner client (the default controller of `issuer-trust add`).
fn sole_owner(ctx: &Ctx) -> Result<ClientId, OpError> {
    let owners = runner_read(ctx, |tx| {
        Ok(tx
            .remote_clients()?
            .into_iter()
            .filter(|c| {
                c.state == heimdall_store::ext_m06::ClientState::Active && c.role == Role::Owner
            })
            .map(|c| c.client)
            .collect::<Vec<_>>())
    })?;
    match owners.as_slice() {
        [one] => Ok(one.clone()),
        [] => Err(usage("this runner has no active owner client")),
        _ => Err(usage(
            "this runner has several owner clients: name one with --controller",
        )),
    }
}

/// A small text file (at most 16 KiB): a public key line. A regular file only
/// (`input_file::open_regular`: a FIFO or a device is refused, never waited on).
fn read_small_file(path: &Path) -> Result<String, OpError> {
    let file =
        crate::input_file::open_regular(path).map_err(|_| usage("the file cannot be read"))?;
    let mut text = String::new();
    file.take(16 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| usage("the file is not text"))?;
    if text.len() > 16 * 1024 {
        return Err(usage("the file is larger than a public key"));
    }
    Ok(text)
}

/// ⟨ADR-0006 §18.7 item 17; ADR-0012 §3.2 "Limits"⟩ What the bridge finds wrong with its own
/// session at start, from the three variables sshd (or the client's `SetEnv`) would have
/// set. A management session never asks for a terminal or an agent, so either one shows the
/// session is not restricted as the runner's line says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionFault {
    /// `SSH_TTY` is set: sshd allocated a PTY.
    Pty,
    /// `SSH_AUTH_SOCK` is set: sshd forwarded an agent.
    Agent,
    /// The `SetEnv` probe's variable arrived (`remote_env::ssh::SETENV_PROBE_NAME`).
    ProbeVariable,
}

impl SessionFault {
    /// The first fault `env` shows (presence only: no value is read or kept).
    fn find(env: &dyn Fn(&str) -> bool) -> Option<Self> {
        if env("SSH_TTY") {
            Some(Self::Pty)
        } else if env("SSH_AUTH_SOCK") {
            Some(Self::Agent)
        } else if env(env_ssh::SETENV_PROBE_NAME) {
            Some(Self::ProbeVariable)
        } else {
            None
        }
    }

    /// The closing message (the controller's probes look for exactly these).
    fn message(self) -> &'static str {
        match self {
            Self::Pty => env_ssh::SESSION_REFUSED_PTY,
            Self::Agent => env_ssh::SESSION_REFUSED_AGENT,
            Self::ProbeVariable => env_ssh::SESSION_REFUSED_SETENV,
        }
    }

    /// What the runner records: a terminal or an agent makes it owner-only. A delivered
    /// probe variable is only reported to the prober, whose `join` carries it.
    fn cause(self) -> Option<heimdall_runtime::paired::OwnerOnlyCause> {
        use heimdall_runtime::paired::OwnerOnlyCause;
        match self {
            Self::Pty => Some(OwnerOnlyCause::SessionPty),
            Self::Agent => Some(OwnerOnlyCause::SessionAgent),
            Self::ProbeVariable => None,
        }
    }
}

/// Refuse a faulty session before any frame is read: record the runner owner-only (when
/// the fault says so), then close with one `Goodbye`. The record is written first, so a
/// session is never refused without it; if it cannot be written the session is refused all
/// the same.
///
/// ⟨ADR-0012 §3.2 "How the downgrade is kept"⟩ The write is the bridge's one exception to
/// the single-writer rule (`paired::record_owner_only_in_home`: set-only, idempotent, one
/// `BEGIN IMMEDIATE` transaction, a bounded wait). When it fails, the failure is logged (a
/// fixed line on standard error) and the event is queued: a line of fixed tokens in the
/// marker in the home's owner-only log directory (`paired::UNRECORDED_DOWNGRADE_LOG`). The
/// marker is a pending write that fails closed: while it exists the runtime treats the
/// runner as owner-only, records the row under its lock at start and at each limited-role
/// admission, and only then removes it. `doctor` reports it
/// (`runner_downgrade_unrecorded`). Neither names a path, a variable's value or a key. A
/// log directory or marker that is a link (or a directory others can write) is refused.
fn refuse_session(fault: SessionFault, home: &Path, out: &mut dyn std::io::Write) -> ExitCode {
    use heimdall_runtime::paired;
    if let Some(cause) = fault.cause() {
        let at = now();
        // ⟨§18.7 item 18⟩ A row of the runner's own state database: the row is the
        // authority. A write that fails is queued in the marker, which only ever lowers.
        if paired::record_owner_only_in_home(home, cause, at).is_err() {
            output::diagnostic("heimdall remote serve: the owner-only record was not written");
            let log_dir = heimdall_runtime::Paths::under(home).log_dir;
            if paired::note_unrecorded_downgrade(&log_dir, cause, at).is_err() {
                output::diagnostic(
                    "heimdall remote serve: the pending record could not be queued either",
                );
            }
        }
    }
    output::diagnostic(&format!("heimdall remote serve: {}", fault.message()));
    let goodbye = heimdall_contract::ipc::ServerMessage::Goodbye {
        code: Code::CapabilityUnavailable,
        message: fault.message().to_owned(),
    };
    if let Ok(frame) =
        heimdall_ipc::frame::encode_frame(&goodbye, heimdall_contract::ipc::MAX_CONTROL_FRAME_BYTES)
    {
        let _ = out.write_all(&frame).and_then(|()| out.flush());
    }
    ExitCode::Unavailable
}

/// `remote serve --client <cid> --home <abs>` (ADR-0012 §3.6): identity and home from argv
/// only (`ServeArgs::parse`), bridged to the home's running runtime. The environment names
/// neither; the only variables looked at are the three of the session check
/// ([`SessionFault`]), and only whether they are set. Standard output carries protocol
/// frames only; diagnostics go to standard error.
fn remote_serve(args: &crate::cli::PlannedArgs) -> ExitCode {
    let parsed = match heimdall_runtime::paired::ServeArgs::parse(&args.args) {
        Ok(p) => p,
        Err(e) => {
            output::diagnostic(&format!("heimdall remote serve: {e}"));
            return ExitCode::Usage;
        }
    };
    if let Some(fault) = SessionFault::find(&|name| std::env::var_os(name).is_some()) {
        return refuse_session(fault, &parsed.home, &mut std::io::stdout().lock());
    }
    let rt = match crate::service_cmd::current_thread() {
        Ok(rt) => rt,
        Err(_) => return ExitCode::Unavailable,
    };
    let ended = rt.block_on(heimdall_runtime::paired::serve_bridge(
        &parsed,
        tokio::io::stdin(),
        tokio::io::stdout(),
        |home: &Path| {
            let home = home.to_path_buf();
            async move {
                crate::client::control_stream_for_home(&home)
                    .await
                    .map_err(|e| std::io::Error::other(e.data.error.message))
            }
        },
    ));
    match ended {
        Ok(_) => ExitCode::Success,
        Err(_) => ExitCode::Unavailable,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Command, dispatch};

    /// ⟨M06 exit; ADR-0006 §18.9 item 13⟩ The wired fill ([`OPENSSH_FILL`]) on an M06
    /// launch whose environment has no `ProgramData` (removed on the command, as a stripped
    /// parent would leave it), through the same seam every M06 launch uses
    /// (`env_ssh::prepare_client_environment`, with the guard checked). On Windows the launch
    /// carries `ProgramData` and `ALLUSERSPROFILE` from the operating system and passes. Off
    /// Windows the operating system fill has no source (it does nothing), so the guard,
    /// forced on here, refuses: `CAPABILITY_UNAVAILABLE` / `ssh_client_not_started`.
    #[test]
    fn the_os_fill_reaches_an_m06_launch_without_program_data() {
        let mut command = std::process::Command::new("ssh");
        command
            .env_remove("ProgramData")
            .env_remove("ALLUSERSPROFILE");
        let parent = |n: &str| std::env::var_os(n);
        let got = env_ssh::prepare_client_environment(&mut command, OPENSSH_FILL, true, &parent);
        if cfg!(windows) {
            got.expect("the operating system's fill");
            for name in ["ProgramData", "ALLUSERSPROFILE"] {
                assert!(
                    env_ssh::launch_env_value(&command, name, &parent)
                        .is_some_and(|v| !v.is_empty()),
                    "{name} from the operating system"
                );
            }
        } else {
            let refused = got.unwrap_err();
            assert_eq!(refused.code, Code::CapabilityUnavailable);
            assert_eq!(
                refused.reason.as_deref(),
                Some(reason::SSH_CLIENT_NOT_STARTED)
            );
            assert_eq!(
                env_ssh::launch_env_value(&command, "ProgramData", &parent),
                None
            );
        }
    }

    /// ⟨M06 W5 `w5r`, `w5t`; ADR-0006 §18.9⟩ One way the controller's K_mgmt agent can fail
    /// to start, from the error the platform gives (the credential crate's tests cause each
    /// one for real): the code, exit code, `retryable` and reason of its class, effect
    /// `none`, and a message that names this controller's agent, why and the fix, with no
    /// path in it.
    fn assert_agent_class(
        e: &std::io::Error,
        code: Code,
        exit: ExitCode,
        retryable: bool,
        want: &str,
        why: &str,
        fix: &str,
    ) {
        let got = agent_failed(e);
        assert_eq!(got.code, code);
        assert_eq!(got.code.exit_code_for_reason(got.reason.as_deref()), exit);
        let detail = got.detail();
        assert_eq!(detail.retryable, retryable);
        assert_eq!(detail.reason.as_deref(), Some(want));
        assert_eq!(got.effect_status, EffectStatus::None);
        assert!(
            got.message
                .starts_with("this controller's management key agent could not start: "),
            "{}",
            got.message
        );
        assert!(got.message.contains(why), "{}", got.message);
        assert!(got.message.ends_with(fix), "{}", got.message);
        assert!(!got.message.contains('/'), "no path: {}", got.message);
        assert!(!got.message.contains("120"), "{}", got.message);
        assert!(reason::MGMT_CONTROLLER_SIDE.contains(&want));
        assert!(heimdall_app::remote_env::is_controller_fault(&got));
    }

    #[test]
    fn an_agent_path_too_long_is_capability_unavailable_and_names_a_shorter_directory() {
        let too_long = std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            heimdall_credential::mgmt::agent::AgentPathTooLong {
                bytes: 120,
                limit: 103,
            },
        );
        assert_agent_class(
            &too_long,
            Code::CapabilityUnavailable,
            ExitCode::Denied,
            false,
            reason::MGMT_AGENT_PATH_TOO_LONG,
            "longer than this platform allows",
            "give this controller a shorter runtime or temporary directory, then try again",
        );
    }

    #[test]
    fn an_agent_permission_denied_is_capability_unavailable_and_names_the_permissions() {
        assert_agent_class(
            &std::io::Error::new(std::io::ErrorKind::PermissionDenied, "/private/secret/path"),
            Code::CapabilityUnavailable,
            ExitCode::Denied,
            false,
            reason::MGMT_AGENT_PERMISSION_DENIED,
            "denied",
            "correct the ownership or permissions of this controller's runtime or temporary \
             directory, then try again",
        );
    }

    #[test]
    fn an_agent_address_in_use_is_state_unavailable_and_retryable() {
        for kind in [
            std::io::ErrorKind::AlreadyExists,
            std::io::ErrorKind::AddrInUse,
        ] {
            assert_agent_class(
                &std::io::Error::new(kind, "/private/secret/path"),
                Code::StateUnavailable,
                ExitCode::Unavailable,
                true,
                reason::MGMT_AGENT_ADDRESS_IN_USE,
                AGENT_NAMES_IN_USE,
                "try again",
            );
        }
    }

    #[test]
    fn any_other_agent_failure_is_state_unavailable_and_retryable() {
        assert_agent_class(
            &std::io::Error::other("/private/secret/path"),
            Code::StateUnavailable,
            ExitCode::Unavailable,
            true,
            reason::MGMT_AGENT_UNAVAILABLE,
            "could not be created",
            "try again",
        );
    }

    /// ⟨M06 W5 `w5t`, ruling 2026-11-23⟩ Every failure of the session opener on this
    /// controller, one row per site: each is classed as this controller's fault
    /// (`is_controller_fault`), so `environment add` after a bootstrap never blames the
    /// runner's runtime for it, and a wording change that drops the class breaks this test.
    #[test]
    fn every_session_opener_failure_on_this_controller_is_classed_as_its_fault() {
        use std::io::{Error, ErrorKind};
        let sites: Vec<(&str, OpError)> = vec![
            ("session directory randomness", rng_unavailable()),
            (
                "session directory, denied",
                local_io_failed(
                    &Error::from(ErrorKind::PermissionDenied),
                    "management session directory could not be created",
                ),
            ),
            (
                "session directory, other",
                local_io_failed(
                    &Error::from(ErrorKind::StorageFull),
                    "management session directory could not be created",
                ),
            ),
            (
                "session file, denied",
                local_io_failed(
                    &Error::from(ErrorKind::ReadOnlyFilesystem),
                    "management session file could not be written",
                ),
            ),
            (
                "session file, other",
                local_io_failed(
                    &Error::from(ErrorKind::StorageFull),
                    "management session file could not be written",
                ),
            ),
            ("no OpenSSH client", no_ssh_client()),
            (
                "K_mgmt store locked",
                key_store_failed(MgmtKeyUnavailable::Locked),
            ),
            (
                "K_mgmt store unavailable",
                key_store_failed(MgmtKeyUnavailable::StoreUnavailable),
            ),
            (
                "K_mgmt not found",
                key_store_failed(MgmtKeyUnavailable::NotFound),
            ),
            (
                "K_mgmt store failed",
                key_store_failed(MgmtKeyUnavailable::Failed),
            ),
            ("configuration render", render_refusal()),
            (
                "ssh spawn",
                ssh_spawn_failed(OpError::new(
                    Code::LaunchFailed,
                    "the ssh client could not be started",
                )),
            ),
            (
                "agent path too long",
                agent_failed(&Error::new(
                    ErrorKind::InvalidInput,
                    heimdall_credential::mgmt::agent::AgentPathTooLong {
                        bytes: 120,
                        limit: 103,
                    },
                )),
            ),
            (
                "agent denied",
                agent_failed(&Error::from(ErrorKind::PermissionDenied)),
            ),
            (
                "agent in use",
                agent_failed(&Error::from(ErrorKind::AddrInUse)),
            ),
            ("agent other", agent_failed(&Error::other("x"))),
            // ⟨`w5w`, M06-W5-RC03⟩ The session's own ssh refused its options.
            (
                "session ssh rejected its options",
                session_error(b"command-line line 0: Bad configuration option: x\r\n"),
            ),
        ];
        for (site, e) in &sites {
            assert!(
                heimdall_app::remote_env::is_controller_fault(e),
                "{site}: {}",
                e.message
            );
            assert!(
                e.message
                    .starts_with(heimdall_app::remote_env::CONTROLLER_FAULT_HEAD),
                "{site}: {}",
                e.message
            );
            assert!(
                !e.message.contains("runner's runtime"),
                "{site}: {}",
                e.message
            );
            assert!(!e.message.contains('/'), "{site}: {}", e.message);
        }
        // The kept codes (ADR-0006 code table): only the denials changed.
        let code = |site: &str| {
            sites
                .iter()
                .find(|(s, _)| *s == site)
                .map(|(_, e)| e.code.clone())
                .unwrap()
        };
        assert_eq!(code("session directory randomness"), Code::InternalError);
        assert_eq!(
            code("session directory, denied"),
            Code::CapabilityUnavailable
        );
        assert_eq!(code("session file, other"), Code::StateUnavailable);
        assert_eq!(code("no OpenSSH client"), Code::LaunchFailed);
        assert_eq!(code("K_mgmt store failed"), Code::ServiceUnavailable);
        assert_eq!(code("configuration render"), Code::CapabilityUnavailable);
        assert_eq!(code("ssh spawn"), Code::LaunchFailed);
        assert_eq!(
            code("session ssh rejected its options"),
            Code::CapabilityUnavailable
        );
        let rejected = &sites.last().unwrap().1;
        assert_eq!(
            rejected.reason.as_deref(),
            Some(reason::SSH_CLIENT_CONFIG_REJECTED)
        );
        // A network outcome stays the runner's side.
        assert!(!heimdall_app::remote_env::is_controller_fault(
            &session_error(b"ssh: connect to host h port 22: Connection refused\r\n")
        ));
    }

    /// ⟨M06 W5 `w5t`⟩ A session directory this controller may not create (an unwritable
    /// Heimdall home): `CAPABILITY_UNAVAILABLE` (an unchanged retry cannot fix it), effect
    /// `none`, and the message blames this controller, names the fix and carries no path.
    #[cfg(unix)]
    #[test]
    fn an_unwritable_session_directory_blames_this_controller() {
        use std::os::unix::fs::PermissionsExt as _;
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("sessions");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();
        let sessions = SshSessions {
            ssh_client: None,
            root: root.clone(),
            key: Arc::new(StoreKey { store: None }),
            fill: OPENSSH_FILL,
            kept_epoch: None,
        };
        let got = sessions.session_dir().unwrap_err();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(got.code, Code::CapabilityUnavailable);
        assert!(!got.detail().retryable);
        assert_eq!(got.effect_status, EffectStatus::None);
        assert_eq!(
            got.message,
            "this controller's management session directory could not be created: the \
             operating system denied it; correct the ownership or permissions of this \
             controller's Heimdall home, then try again"
        );
        assert!(heimdall_app::remote_env::is_controller_fault(&got));
    }

    /// ⟨M06 W5, the 2026-11-22 incident⟩ A debug build under a scratch Heimdall home with
    /// no `HEIMDALL_TEST_MGMT_STORE` selects no K_mgmt store at all: the refusal names the
    /// variable, is `CAPABILITY_UNAVAILABLE` / `mgmt_key_store_unavailable` with effect
    /// `none`, and comes from `mgmt_store` before any platform store is constructed. The
    /// same for K_iroh (`iroh_store`): a store that refuses everything, never the
    /// platform's. A home that is not scratch, or the variable set, is not refused.
    #[test]
    fn a_scratch_home_without_the_fixture_variables_never_selects_a_platform_key_store() {
        use heimdall_credential::iroh::IrohStoreAvailability;
        use heimdall_credential::scratch_guard::{HOME_ENV, IROH_FIXTURE_ENV, MGMT_FIXTURE_ENV};
        assert_eq!(HOME_ENV, heimdall_runtime::paths::HOME_ENV);
        assert_eq!(MGMT_FIXTURE_ENV, TEST_MGMT_STORE_ENV);
        assert_eq!(IROH_FIXTURE_ENV, crate::testcfg::IROH_KEY_STORE_ENV);
        assert_eq!(
            heimdall_credential::MACOS_KEYCHAIN_ISSUER_SERVICE_PREFIX,
            heimdall_issuer::store::ITEM_LABEL_PREFIX
        );
        let scratch = tempfile::tempdir().unwrap();
        let home = scratch.path().join("hm");
        let none = |_: &str| None;
        let refused = mgmt_scratch_refusal(Some(&home), &none).expect("refused");
        assert_eq!(refused.code, Code::CapabilityUnavailable);
        assert_eq!(
            refused.reason.as_deref(),
            Some(reason::MGMT_KEY_STORE_UNAVAILABLE)
        );
        assert!(refused.message.contains(MGMT_FIXTURE_ENV), "{refused:?}");
        // Through the home in the environment, and lifted by the variable alone.
        let home_os = home.clone().into_os_string();
        let env_home = |n: &str| (n == HOME_ENV).then(|| home_os.clone());
        assert!(mgmt_scratch_refusal(None, &env_home).is_some());
        let with_var = |n: &str| (n == MGMT_FIXTURE_ENV).then(|| "fixture-file:/x".into());
        assert!(mgmt_scratch_refusal(Some(&home), &with_var).is_none());
        assert!(mgmt_scratch_refusal(Some(Path::new("/srv/heimdall-home")), &none).is_none());
        // The selection site itself (this test process sets neither fixture variable).
        if cfg!(not(windows)) && std::env::var_os(MGMT_FIXTURE_ENV).is_none() {
            let ctx = Ctx {
                json: true,
                non_interactive: true,
                home: Some(home.clone()),
                stdin_tty: false,
                request_epoch: None,
            };
            let environment = EnvironmentId::from_random_bytes([3; 16]);
            let Err(e) = mgmt_store(&ctx, &environment) else {
                panic!("a platform K_mgmt store was selected under a scratch home");
            };
            assert!(e.message.contains(MGMT_FIXTURE_ENV), "{e:?}");
            if std::env::var_os(IROH_FIXTURE_ENV).is_none() {
                let keys = iroh_store(&ctx, &environment);
                assert_eq!(
                    keys.availability(),
                    IrohStoreAvailability::FixtureStoreRequired
                );
                assert!(keys.kind().product().is_none());
                assert!(keys.availability().as_str().contains(IROH_FIXTURE_ENV));
            }
        }
    }

    /// ⟨M06 W5⟩ The bootstrap's test seam: only `HEIMDALL_TEST_SSH_HOME` moves the
    /// bootstrap session's `-F` file, to that scratch home's own `.ssh/config`; unset, the
    /// owner's configuration (no `-F`); a relative value is a usage error. A build without
    /// the test configuration refuses the variable (the same gate `run` and `connect`
    /// use: `testcfg::launch_hooks`; the release binary is probed by
    /// tools/validation/release-gate.sh, `environment add`).
    #[test]
    fn the_bootstrap_config_seam_is_the_scratch_ssh_home_only_and_gated_like_run() {
        use crate::testcfg::SSH_HOME_ENV;
        assert_eq!(bootstrap_test_config(&|_| None), Ok(None));
        let set = |value: &'static str| move |n: &str| (n == SSH_HOME_ENV).then(|| value.into());
        if crate::testcfg::AVAILABLE {
            let scratch = if cfg!(windows) {
                r"C:\scratch\acct"
            } else {
                "/scratch/acct"
            };
            assert_eq!(
                bootstrap_test_config(&set(scratch)),
                Ok(Some(Path::new(scratch).join(".ssh").join("config")))
            );
            let relative = bootstrap_test_config(&set("rel")).unwrap_err();
            assert!(relative.contains(SSH_HOME_ENV), "{relative}");
            // No other variable is a seam of the bootstrap.
            let other = |n: &str| (n == "HOME" || n == "HEIMDALL_HOME").then(|| "/x".into());
            assert_eq!(bootstrap_test_config(&other), Ok(None));
        } else {
            let refused = bootstrap_test_config(&set("/scratch/acct")).unwrap_err();
            assert_eq!(Some(refused.as_str()), crate::testcfg::refusal(false, true));
        }
        // The gate itself, for a build that cannot honour the configuration.
        assert!(crate::testcfg::refusal(false, true).is_some_and(|m| m.contains("HEIMDALL_TEST_")));
    }

    /// ⟨M06 W5; ADR-0012 §2.6, the 2026-11-22 bullets⟩ The bootstrap's offer, without a
    /// terminal: the runtime that an accepted offer starts receives only the listed
    /// variables of the bootstrap session (never its agent, connection, terminal or askpass
    /// variables, nor an arbitrary one), plus a debug build's own test configuration; the
    /// offer names the exact command and says the runtime is not running; a declined offer
    /// starts nothing and leaves the next step. (The typed answers on a pseudo-terminal are
    /// `e2e_environment_runner_m06`'s.)
    #[test]
    fn the_runtime_start_offer_says_what_it_runs_and_passes_no_session_credentials() {
        let session = [
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/home/r"),
            ("LANG", "C.UTF-8"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("SSH_AUTH_SOCK", "/tmp/ssh-x/agent.1"),
            ("SSH_AGENT_PID", "1"),
            ("SSH_CONNECTION", "192.0.2.1 1 192.0.2.2 22"),
            ("SSH_CLIENT", "192.0.2.1 1 22"),
            ("SSH_TTY", "/dev/pts/0"),
            ("SSH_ASKPASS", "/x"),
            ("TERM", "xterm"),
            ("HEIMDALL_HOME", "/elsewhere"),
            ("HEIMDALL_TEST_SSH_HOME", "/scratch/acct"),
            ("LD_PRELOAD", "/x.so"),
        ];
        let vars = || session.iter().map(|(k, v)| ((*k).into(), (*v).into()));
        let names = |test: bool| -> Vec<String> {
            runtime_start_env(vars(), test)
                .into_iter()
                .map(|(k, _)| k.to_string_lossy().into_owned())
                .collect()
        };
        assert_eq!(names(false), ["PATH", "HOME", "LANG", "XDG_RUNTIME_DIR"]);
        assert_eq!(
            names(true),
            [
                "PATH",
                "HOME",
                "LANG",
                "XDG_RUNTIME_DIR",
                "HEIMDALL_TEST_SSH_HOME"
            ]
        );
        assert!(RUNTIME_START_ENV.iter().all(|n| !n.starts_with("SSH_")));

        let line = runtime_start_line(Path::new("/opt/h/heimdall"), Path::new("/srv/r"));
        assert_eq!(
            line,
            "/opt/h/heimdall --home /srv/r service run --runner --detach"
        );
        let offer = runtime_start_offer(&line);
        assert!(offer.starts_with(RUNTIME_NOT_RUNNING), "{offer}");
        assert!(offer.contains("is NOT running") && offer.contains(&line));
        assert!(offer.ends_with("Type yes to start it: "));
        let declined = runtime_start_declined(&line);
        assert!(declined.starts_with("The runner's runtime was not started. Next step:"));
        assert!(declined.contains(&line) && declined.contains("`heimdall environment add`"));

        // A declined offer starts nothing: the answer is asked once and no runtime serves.
        let scratch = tempfile::tempdir().unwrap();
        let home = scratch.path().join("hm");
        let ctx = Ctx {
            json: false,
            non_interactive: false,
            home: Some(home.clone()),
            stdin_tty: false,
            request_epoch: None,
        };
        let paths = heimdall_runtime::Paths::under(&home);
        let asked = std::cell::RefCell::new(Vec::new());
        let stated = offer_runtime_start(&ctx, &paths, &|text| {
            asked.borrow_mut().push(text.to_owned());
            false
        });
        assert_eq!(asked.borrow().len(), 1);
        assert!(asked.borrow()[0].contains("Type yes to start it"));
        assert!(
            stated.starts_with("The runner's runtime was not started."),
            "{stated}"
        );
        assert!(!home.exists(), "nothing was created or started");
    }

    /// ⟨M06-W3-R04⟩ `--issuer-ca`'s two requests each carry their own `request_id`.
    #[test]
    fn the_issuer_forms_carry_distinct_request_ids() {
        use heimdall_contract::remote::RunnerLocalRequest;
        let owner = ClientId::from_random_bytes([7; 16]);
        let forms = issuer_forms(&owner, "ssh-ed25519 AAAA").unwrap();
        let (
            RunnerLocalRequest::TrustIssuer { request_id: a, .. },
            RunnerLocalRequest::DesignateTimeSource { request_id: b, .. },
        ) = (&forms[0], &forms[1])
        else {
            panic!("the two forms are trust_issuer then designate_time_source");
        };
        assert_ne!(a, b);
    }

    /// ⟨ADR-0012 §3.2 "How the downgrade is kept"⟩ The bridge refuses a faulty session
    /// whether or not its downgrade can be recorded. On a runner's home the row is written
    /// (and again: still set, the epoch moved) and nothing is noted. On a home whose state
    /// database cannot take the row (here: none exists) the session is refused all the
    /// same with the same `Goodbye`, no database is created, and the failure is noted in
    /// the log directory for `doctor`, in fixed tokens. A delivered probe variable records
    /// and notes nothing.
    #[test]
    fn the_bridge_refuses_a_faulty_session_and_notes_a_downgrade_it_cannot_record() {
        use heimdall_runtime::paired::{self, OwnerOnlyCause};
        let goodbye = |fault: SessionFault, home: &Path| {
            let mut out = Vec::new();
            assert_eq!(refuse_session(fault, home, &mut out), ExitCode::Unavailable);
            let text = String::from_utf8_lossy(&out).into_owned();
            assert!(text.contains(fault.message()), "{text}");
        };
        let dir = tempfile::tempdir().unwrap();
        let paths = heimdall_runtime::Paths::under(dir.path());
        // The log directory is not there: the bridge creates it, owner-only.
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let db = paired::state_db_of_home(dir.path()).unwrap();

        // No state database: refused, nothing created, the failure noted.
        goodbye(SessionFault::Pty, dir.path());
        assert!(!db.exists(), "the bridge created a state database");
        let noted = paired::unrecorded_downgrade(&paths.log_dir).unwrap();
        assert_eq!(noted.cause, OwnerOnlyCause::SessionPty);
        assert!(noted.at.is_some());
        let note = paths.log_dir.join(paired::UNRECORDED_DOWNGRADE_LOG);
        let text = std::fs::read_to_string(&note).unwrap();
        assert!(
            text.starts_with("session_pty ") && text.lines().count() == 1,
            "{text}"
        );
        assert!(
            !text.contains(&dir.path().display().to_string()),
            "the note names a path: {text}"
        );
        std::fs::remove_file(&note).unwrap();

        // A runner's database: recorded, and nothing noted.
        let store = heimdall_store::Store::open(&db, std::sync::Arc::new(heimdall_store::NoFaults))
            .unwrap();
        paired::init_runner(&store).unwrap();
        let downgrade = || store.transaction(|tx| tx.runner_downgrade()).unwrap();
        goodbye(SessionFault::ProbeVariable, dir.path());
        assert_eq!(downgrade(), None);
        goodbye(SessionFault::Agent, dir.path());
        goodbye(SessionFault::Pty, dir.path());
        let standing = downgrade().unwrap();
        assert_eq!(
            (standing.cause.as_str(), standing.epoch),
            ("session_agent_forwarded", 2)
        );
        assert_eq!(paired::unrecorded_downgrade(&paths.log_dir), None);
    }

    /// ⟨ADR-0012 §3.2 "How the downgrade is kept"⟩ The bridge's database write fails on a
    /// real runner's home (the write lock is held past its bounded wait): the session is
    /// refused, no row exists, and the event is queued in the marker in the owner-only log
    /// directory, which the bridge creates. The runner's next limited-role admission is
    /// refused although no row existed, records the row with the bridge's cause, and
    /// removes the marker; the runner stays owner-only after that.
    #[test]
    fn a_downgrade_the_bridge_cannot_write_is_queued_and_the_next_admission_records_it() {
        use heimdall_contract::remote::{ManagementPolicy, ProbeObservation, Role};
        use heimdall_remote::Refusal;
        use heimdall_runtime::paired::{self, OwnerOnlyCause, RunnerPolicy};
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().canonicalize().unwrap();
        let paths = heimdall_runtime::Paths::under(&home);
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let store = std::sync::Arc::new(
            heimdall_store::Store::open(
                &paired::state_db_of_home(&home).unwrap(),
                std::sync::Arc::new(heimdall_store::NoFaults),
            )
            .unwrap(),
        );
        paired::init_runner(&store).unwrap();
        let downgrade = || store.transaction(|tx| tx.runner_downgrade()).unwrap();

        // The runtime's connection holds the write lock while the bridge runs.
        store
            .transaction(|_| {
                let mut out = Vec::new();
                assert_eq!(
                    refuse_session(SessionFault::Pty, &home, &mut out),
                    ExitCode::Unavailable
                );
                assert!(String::from_utf8_lossy(&out).contains(SessionFault::Pty.message()));
                Ok(())
            })
            .unwrap();
        assert_eq!(downgrade(), None, "the bridge's write went through");
        let marker = paths.log_dir.join(paired::UNRECORDED_DOWNGRADE_LOG);
        assert!(marker.exists(), "nothing was queued");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&paths.log_dir)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }

        let policy = RunnerPolicy::with_store(ManagementPolicy::Verified, store.clone());
        let client = heimdall_contract::ids::ClientId::from_random_bytes([7; 16]);
        let agrees = ProbeObservation {
            pty_refused: true,
            forward_refused: true,
            agent_forward_refused: true,
            setenv_canary_delivered: false,
        };
        assert_eq!(
            policy.check_join(&client, Role::Viewer, Some(&agrees)),
            Err(Refusal::ManagementSshdUnverified)
        );
        let standing = downgrade().unwrap();
        assert_eq!(
            (standing.cause.as_str(), standing.epoch),
            (OwnerOnlyCause::SessionPty.token(), 1)
        );
        assert!(!marker.exists(), "the marker was not removed");
        assert_eq!(paired::unrecorded_downgrade(&paths.log_dir), None);
        assert_eq!(policy.current(), ManagementPolicy::OwnerOnly);
    }

    /// ⟨W3.1 re-check, low finding 2⟩ `remote policy recheck` with no runtime running: a
    /// downgrade the bridge could not record (its marker is pending, the store holds no row
    /// yet) is not reported as "not downgraded". The pre-check refuses, as the lift would;
    /// without the marker the same runner reads as not downgraded.
    #[test]
    fn remote_policy_recheck_reports_a_pending_unrecorded_downgrade() {
        use heimdall_runtime::paired::{self, OwnerOnlyCause};
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().canonicalize().unwrap();
        let paths = heimdall_runtime::Paths::under(&home);
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let store = heimdall_store::Store::open(
            &paired::state_db_of_home(&home).unwrap(),
            std::sync::Arc::new(heimdall_store::NoFaults),
        )
        .unwrap();
        paired::init_runner(&store).unwrap();
        drop(store);
        let ctx = Ctx {
            json: true,
            non_interactive: false,
            home: Some(home.clone()),
            stdin_tty: true,
            request_epoch: None,
        };
        assert_eq!(policy_recheck_precheck(&ctx).unwrap(), None);

        paired::note_unrecorded_downgrade(
            &paths.log_dir,
            OwnerOnlyCause::SessionPty,
            heimdall_contract::Timestamp::now(),
        )
        .unwrap();
        let refused = policy_recheck_precheck(&ctx).unwrap_err();
        assert_eq!(refused.code, Code::CapabilityUnavailable, "{refused:?}");
        assert_eq!(
            refused.message,
            paired::LiftRefusal::MarkerPending.to_error().message
        );
        // Read-only: the marker stands for the runtime (or the lift) to record.
        assert!(paired::unrecorded_downgrade(&paths.log_dir).is_some());
    }

    /// ⟨M06 W3⟩ The route and transport command lines that are refused before the runtime is
    /// contacted or the home created: malformed typed inputs (`USAGE_ERROR`, exit 2, effect
    /// `none`), and the hidden helper and serve child with arguments other than their own.
    const EP: &str = "abababababababababababababababababababababababababababababababab";
    const REFUSED_LOCALLY: &[&[&str]] = &[
        &["route", "add", "lab", "--direct", "a b"],
        &["route", "add", "lab", "--direct", "host:0"],
        &["route", "add", "bad id", "--direct", "10.0.0.1:22"],
        &["route", "add", "lab", "--iroh", "00"],
        &["route", "add", "lab", "--iroh", EP, "--address", "nope"],
        &["route", "remove", "lab", "not-a-route"],
        &["route", "prefer", "lab", "not-a-route"],
        &["transport", "adopt-roost", "lab", "--endpoint", "00"],
        &[
            "route",
            "add",
            "lab",
            "--direct",
            "h",
            "--address",
            "127.0.0.1:1",
        ],
    ];

    /// ⟨M06 W4 `w4d`; ADR-0006 §18.8 item 4⟩ `environment resume-issuance` names what it
    /// shows. The confirmation lists each delivered, unacknowledged pause and cutoff with
    /// its effect ID, what it is, its delivery time and what the runner's last recorded
    /// report says of its lift. The request and the direct write carry exactly those IDs:
    /// a cutoff delivered between the list and the `yes` gets no row, on either path's
    /// input; an unconfirmed prompt writes nothing.
    #[test]
    fn resume_issuance_acknowledges_exactly_the_effects_it_showed() {
        use heimdall_app::remote_status_driver::delivered_holds;
        use heimdall_contract::controller_record::{
            ControllerRecordRequest, ManagementHop, ManagementRoute, RemoteEnvironmentPin,
        };
        use heimdall_contract::ids::{
            AccountName, ClientId, DestinationId, EffectId, KeyFingerprint, PolicyId,
        };
        use heimdall_contract::remote::EffectTarget;
        use heimdall_contract::trust::PolicyTarget;
        use heimdall_store::ext_effects::{
            AppliedRecord, AuthorityReport, EffectAck, EffectKey, ReportedPolicy,
        };
        let at = |s: &str| s.parse::<heimdall_contract::Timestamp>().unwrap();
        let store =
            heimdall_store::Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap();
        let env = EnvironmentId::from_random_bytes([3; 16]);
        let producer = ClientId::from_random_bytes([1; 16]);
        let (paused, cut) = (
            PolicyId::parse("polpause").unwrap(),
            PolicyId::parse("polcut").unwrap(),
        );
        let pin = RemoteEnvironmentPin {
            environment: env.clone(),
            destination: DestinationId::parse("runner1").unwrap(),
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname: "runner.example".into(),
                    port: None,
                    account: AccountName::parse("deploy").unwrap(),
                    host_keys: vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA".into()],
                },
                jump: None,
            },
            client: producer.clone(),
            role: heimdall_contract::remote::Role::Owner,
            key_fingerprint: KeyFingerprint::parse(&format!("SHA256:{}", "K".repeat(43))).unwrap(),
            label: None,
            pinned_at: at("2026-11-21T09:00:00Z"),
        };
        store
            .transaction(|tx| {
                tx.put_remote_environment_pin(
                    &pin.environment,
                    &pin.destination,
                    &pin.route.runner.account,
                    &pin.key_fingerprint,
                    &serde_json::to_string(&pin).unwrap(),
                    pin.pinned_at,
                )
            })
            .unwrap();
        let key = |n: u8, target: EffectTarget| EffectKey {
            producer: producer.clone(),
            effect: EffectId::from_random_bytes([n; 16]),
            target,
        };
        let cutoff = |n: u8| {
            key(
                n,
                EffectTarget::PolicyCutoff {
                    scope: PolicyTarget::Policy {
                        policy_id: cut.clone(),
                    },
                    at: at("2026-11-21T10:00:00Z"),
                    revision: u64::from(n),
                },
            )
        };
        let deliver = |key: &EffectKey, policy: &PolicyId, now: &str| {
            let ack = EffectAck {
                key: key.clone(),
                applied_at: at(now),
                record: AppliedRecord::PolicyRevision {
                    scope_key: heimdall_store::ext_effects::policy_scope_key(policy),
                    runner_seq: key.target.generation(),
                    policies: vec![policy.clone()],
                    cutoff_at: None,
                    fired: false,
                },
            };
            store
                .transaction(|tx| {
                    assert!(tx.enqueue_remote_effect(&env, key, at(now))?);
                    assert!(tx.acknowledge_remote_effect(&ack, at(now))?);
                    Ok(())
                })
                .unwrap();
        };
        let holds = || store.transaction(|tx| delivered_holds(tx, &env)).unwrap();
        let lift_ack = |key: &EffectKey| store.transaction(|tx| tx.remote_lift_ack(key)).unwrap();

        let pause = key(
            1,
            EffectTarget::PolicyPause {
                policy: paused.clone(),
                revision: 1,
            },
        );
        let first = cutoff(2);
        deliver(&pause, &paused, "2026-11-21T10:00:01Z");
        deliver(&first, &cut, "2026-11-21T10:00:02Z");

        // No report recorded yet: the lift is not known.
        let listed = holds();
        let text = resume_issuance_text(&env, &listed.iter().collect::<Vec<_>>());
        assert_eq!(
            text.matches("no report of the runner is recorded").count(),
            2
        );
        // The runner's report, read later: the pause lifted, the cutoff standing. ⟨W5;
        // ADR-0006 §18.9 item 4⟩ It says so per delivered effect: each one's own row
        // states whether it is still in force.
        let row = |key: &EffectKey, in_force: bool| {
            let (scope, kind, cutoff_at) = match &key.target {
                EffectTarget::PolicyCutoff { scope, at, .. } => (
                    scope.clone(),
                    heimdall_store::ext_effects::PolicyRevisionKind::Cutoff,
                    Some(*at),
                ),
                EffectTarget::PolicyPause { policy, .. } => (
                    PolicyTarget::Policy {
                        policy_id: policy.clone(),
                    },
                    heimdall_store::ext_effects::PolicyRevisionKind::Pause,
                    None,
                ),
                _ => unreachable!("a pause or a cutoff"),
            };
            heimdall_store::ext_effects::PolicyRevisionRecord {
                scope_key: heimdall_store::ext_effects::target_ref(&key.target).unwrap(),
                scope,
                producer: key.producer.clone(),
                revision: key.target.generation(),
                runner_seq: key.target.generation(),
                kind,
                effect: key.effect.clone(),
                received_at: at("2026-11-21T10:00:00Z"),
                cutoff_at,
                fired_uncertain_at: None,
                in_force,
            }
        };
        store
            .transaction(|tx| {
                tx.note_remote_report(
                    &env,
                    at("2026-11-21T10:05:00Z"),
                    &AuthorityReport {
                        environment: env.clone(),
                        authority_generation: 1,
                        tombstones: Vec::new(),
                        policy_revisions: vec![row(&pause, false), row(&first, true)],
                        policies: vec![
                            ReportedPolicy {
                                policy: paused.clone(),
                                revision: 1,
                                paused: false,
                                cutoff_at: None,
                            },
                            ReportedPolicy {
                                policy: cut.clone(),
                                revision: 1,
                                paused: false,
                                cutoff_at: Some(at("2026-11-21T10:00:00Z")),
                            },
                        ],
                        certificates: Vec::new(),
                        time_bounded: true,
                        pending_grants: Vec::new(),
                    },
                )
            })
            .unwrap();
        let listed = holds();
        let open: Vec<_> = listed.iter().collect();
        let text = resume_issuance_text(&env, &open);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[2],
            format!(
                "    {}  pause of policy polpause; delivered 2026-11-21T10:00:01Z; the \
                 runner's report read 2026-11-21T10:05:00Z shows it lifted",
                pause.effect.as_str()
            )
        );
        assert_eq!(
            lines[3],
            format!(
                "    {}  cutoff of policy:polcut at 2026-11-21T10:00:00Z; delivered \
                 2026-11-21T10:00:02Z; the runner's report read 2026-11-21T10:05:00Z does NOT \
                 show it lifted",
                first.effect.as_str()
            )
        );
        assert!(text.ends_with("Type yes to continue: "));

        // What is sent names exactly the effects shown.
        let shown: Vec<EffectId> = open.iter().map(|h| h.key.effect.clone()).collect();
        assert_eq!(shown, [pause.effect.clone(), first.effect.clone()]);
        assert_eq!(
            resume_issuance_request(&env, &shown),
            heimdall_contract::request::Request::ControllerRecord(
                ControllerRecordRequest::ResumeIssuance {
                    environment: env.clone(),
                    effects: shown.clone(),
                }
            )
        );

        // Not confirmed: nothing is written.
        let now = at("2026-11-21T10:06:00Z");
        let e = acknowledge_shown(&store, &env, &shown, || false, now).unwrap_err();
        assert_eq!(e.code, Code::InteractionRequired);
        assert_eq!(lift_ack(&pause), None);
        // A cutoff is delivered while the owner reads the list; then they type yes.
        let later = cutoff(3);
        let done = acknowledge_shown(
            &store,
            &env,
            &shown,
            || {
                deliver(&later, &cut, "2026-11-21T10:05:30Z");
                true
            },
            now,
        )
        .unwrap();
        assert_eq!(done["acknowledged"].as_array().unwrap().len(), 2);
        assert_eq!(done["not_named"], 1);
        assert!(lift_ack(&pause).is_some() && lift_ack(&first).is_some());
        assert_eq!(lift_ack(&later), None, "delivered after the list: unseen");
        // The next list shows the later cutoff alone.
        let next: Vec<_> = holds()
            .into_iter()
            .filter(|h| h.delivered_at.is_some() && h.lift_acknowledged_at.is_none())
            .map(|h| h.key.effect)
            .collect();
        assert_eq!(next, std::slice::from_ref(&later.effect));
    }

    /// ⟨M06 W3⟩ The M06 route and transport commands are wired (no "planned for M06"
    /// refusal): each line parses into its typed arguments; malformed inputs are refused as
    /// usage errors before any runtime contact, without creating the Heimdall home; the
    /// hidden helper and serve child refuse anything but their own arguments; clap refuses
    /// a zero `--port`, a `--port` without `--serve`, and a route with no or two kinds.
    /// ⟨M06 W5; ADR-0006 §18.9 item 1⟩ `transport enable --serve --sshd-port <n>`: 1–65535
    /// only (`0`, a value past 65535 and a non-number are refused by the parser), only
    /// with `--serve`, and no flag names the target's host. The request names the port in
    /// the serve policy, and 22 (or no flag) is the request with no policy at all.
    #[test]
    fn the_sshd_port_flag_is_bounded_needs_serve_and_omits_the_default() {
        use heimdall_contract::route::ExposurePolicy;
        for wrong in [
            &["transport", "enable", "--serve", "--sshd-port", "0"][..],
            &["transport", "enable", "--serve", "--sshd-port", "65536"],
            &["transport", "enable", "--serve", "--sshd-port", "-1"],
            &["transport", "enable", "--serve", "--sshd-port", "ssh"],
            &[
                "transport",
                "enable",
                "--serve",
                "--sshd-port",
                "127.0.0.2:22",
            ],
            &["transport", "enable", "--sshd-port", "2222"],
            &["transport", "enable", "--serve", "--sshd-host", "127.0.0.2"],
        ] {
            let mut argv = vec!["heimdall"];
            argv.extend_from_slice(wrong);
            assert!(Cli::try_parse_from(&argv).is_err(), "{wrong:?} parsed");
        }
        let parsed = |args: &[&str]| {
            let mut argv = vec!["heimdall", "transport", "enable"];
            argv.extend_from_slice(args);
            match Cli::try_parse_from(&argv).unwrap().command {
                Some(Command::Transport(TransportCommand::Enable(a))) => {
                    enable_exposure(a.port, a.sshd_port)
                }
                _ => panic!("{args:?}"),
            }
        };
        assert_eq!(parsed(&["--serve"]), None);
        assert_eq!(parsed(&["--serve", "--sshd-port", "22"]), None);
        for port in [1u16, 2222, 65535] {
            assert_eq!(
                parsed(&["--serve", "--sshd-port", &port.to_string()]),
                Some(ExposurePolicy {
                    sshd_port: port,
                    ..ExposurePolicy::default()
                })
            );
        }
        assert_eq!(
            parsed(&["--serve", "--port", "4433", "--sshd-port", "2222"]),
            Some(ExposurePolicy {
                port: Some(4433),
                sshd_port: 2222,
                ..ExposurePolicy::default()
            })
        );
        assert_eq!(
            parsed(&["--serve", "--port", "4433"]),
            Some(ExposurePolicy {
                port: Some(4433),
                ..ExposurePolicy::default()
            })
        );
    }

    // --- ⟨M06 W5 `w5n`⟩ the route helper's pin and jump leg ------------------------------

    fn helper_paths(root: &Path) -> heimdall_runtime::paths::Paths {
        heimdall_runtime::paths::Paths {
            config_dir: root.join("config"),
            state_dir: root.join("state"),
            runtime_dir: root.join("run"),
            log_dir: root.join("log"),
        }
    }

    fn approved_jump(account: &str) -> heimdall_domain::catalog::ApprovedRoute {
        heimdall_domain::catalog::ApprovedRoute {
            jump: DestinationId::parse("bastion").unwrap(),
            jump_alias: "bast".into(),
            jump_pair: heimdall_domain::scope::AccessPair {
                destination: DestinationId::parse("bastion").unwrap(),
                account: AccountName::parse(account).unwrap(),
            },
        }
    }

    const KEY_A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaa";
    const KEY_B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbb";

    /// The helper's expected `ProxyCommand` is, character for character, what P renders
    /// (`heimdall_sshconf::routes::helper_command`), so `ssh -G`'s value compares equal.
    #[test]
    fn the_helpers_expected_proxy_command_is_the_rendered_one() {
        use heimdall_sshconf::render::{PathStyle, RenderPath};
        use heimdall_sshconf::routes::{HelperRoute, helper_command};
        let unix = |p: &str| RenderPath::unix(Path::new(p)).unwrap();
        let route = HelperRoute::new(
            unix("/opt/hm dir/heimdall"),
            "lab",
            unix("/c/keys/host_pins"),
        )
        .unwrap();
        let rendered = helper_command(
            &route,
            "deploy",
            &unix("/run/hm/signing.sock"),
            PathStyle::Unix,
        )
        .unwrap();
        let args = heimdall_app::routes::HelperArgs::parse(
            [
                "--destination",
                "lab",
                "--account",
                "deploy",
                "--endpoint",
                "/run/hm/signing.sock",
            ]
            .map(std::ffi::OsString::from),
        )
        .unwrap();
        assert_eq!(
            rendered_helper_command("/opt/hm dir/heimdall", &args),
            rendered
        );
    }

    /// The helper applies the alias's pin check only when it is that alias's own effective
    /// proxy: exactly one `proxycommand` line, with exactly its own command.
    #[test]
    fn the_alias_check_applies_only_when_the_alias_names_this_helper() {
        let command =
            "\"/opt/heimdall\" route connect --destination lab --account a --endpoint \"/e\"";
        let g = |proxy: &str| format!("host lab\nuser a\n{proxy}stricthostkeychecking true\n");
        assert!(alias_proxy_is(
            &g(&format!("proxycommand {command}\n")),
            command
        ));
        assert!(alias_proxy_is(
            &g(&format!("ProxyCommand {command}\r\n")),
            command
        ));
        // Not the alias's proxy: none, another command, another endpoint, or two lines.
        assert!(!alias_proxy_is(&g(""), command));
        assert!(!alias_proxy_is(&g("proxycommand nc %h %p\n"), command));
        assert!(!alias_proxy_is(
            &g(&format!(
                "proxycommand {}\n",
                command.replace("/e", "/other")
            )),
            command
        ));
        assert!(!alias_proxy_is(
            &g(&format!("proxycommand {command}\nproxycommand {command}\n")),
            command
        ));
    }

    /// ⟨M06 W5 `w5o` item 8⟩ A helper invocation that is not the alias's own proxy is
    /// refused wherever P renders that alias through the helper, and only there: with no P,
    /// a P without the alias, or a P that renders the alias natively, the check does not
    /// apply (an installation that projects no helper alias for the destination).
    #[test]
    fn a_helper_that_is_not_the_projected_aliass_proxy_is_refused() {
        let helper_p = "Host lab\n    HostName 10.0.0.2\n    ProxyCommand \"/opt/heimdall\" route \
                        connect --destination lab --account a --endpoint \"/e\"\n    \
                        HostKeyAlias hm-dest-lab\n    UserKnownHostsFile \"/c/keys/host_pins\"\n\
                        Host other\n    HostName 10.0.0.3\n";
        assert_eq!(
            not_the_projected_proxy(Some(helper_p), "lab"),
            Some("proxycommand".to_owned())
        );
        assert_eq!(not_the_projected_proxy(Some(helper_p), "other"), None);
        assert_eq!(not_the_projected_proxy(Some(helper_p), "absent"), None);
        assert_eq!(not_the_projected_proxy(Some(""), "lab"), None);
        assert_eq!(not_the_projected_proxy(None, "lab"), None);
    }

    /// Catalog-only trust (ADR-0012 §5.2): the projected pin file holds the pin only when it
    /// has exactly the catalog's keys under the destination's own name.
    #[test]
    fn the_pin_file_holds_only_with_exactly_the_catalogs_keys() {
        let file = format!("hm-dest-lab {KEY_A}\nhm-dest-bastion {KEY_B}\n");
        let catalog = |k: &[&str]| k.iter().map(|k| (*k).to_owned()).collect::<Vec<_>>();
        assert!(pins_hold(Some(&file), "hm-dest-lab", &catalog(&[KEY_A])));
        // No catalog pin; no file; a key the catalog does not approve; a key it has
        // approved since; another destination's name.
        assert!(!pins_hold(Some(&file), "hm-dest-lab", &[]));
        assert!(!pins_hold(None, "hm-dest-lab", &catalog(&[KEY_A])));
        assert!(!pins_hold(Some(&file), "hm-dest-lab", &catalog(&[KEY_B])));
        assert!(!pins_hold(
            Some(&file),
            "hm-dest-lab",
            &catalog(&[KEY_A, KEY_B])
        ));
        assert!(!pins_hold(Some(&file), "hm-dest-other", &catalog(&[KEY_A])));
        let extra = format!("{file}hm-dest-lab {KEY_B}\n");
        assert!(!pins_hold(Some(&extra), "hm-dest-lab", &catalog(&[KEY_A])));
    }

    /// The brief's constraint 4 (ADR-0012 §5.4; ADR-0010 §5 item 2): a managed jump hop is
    /// built only when the alias's endpoint serves the jump pair through the **same
    /// binding** as the final pair; another grant's jump pair is
    /// `route_dependency_out_of_scope`, whatever else is in place. The hop pins the jump's
    /// own catalog key and names the jump pair's slot certificate at the alias's endpoint.
    #[test]
    fn a_managed_jump_hop_needs_the_final_pairs_own_binding() {
        use heimdall_app::routes::RouteHelperError;
        use heimdall_contract::environment::JumpAccess;
        let dir = tempfile::tempdir().unwrap();
        let paths = helper_paths(dir.path());
        let route = approved_jump("jump");
        let slot = heimdall_localenv::projection::content::managed_slot_paths(
            &paths.state_dir,
            &route.jump,
        )
        .unwrap();
        std::fs::create_dir_all(&slot.dir).unwrap();
        std::fs::write(&slot.cert_pub, "cert\n").unwrap();
        let pin_file = paths.config_dir.join("keys").join("host_pins");
        let pin_text = format!("hm-dest-bastion {KEY_B}\n");
        let facts = JumpFacts {
            hostname: "10.0.0.1".into(),
            port: Some(2200),
            account: AccountName::parse("jump").unwrap(),
            pins: vec![KEY_B.to_owned()],
            identity: None,
        };
        let hop = |same_grant: bool, pins: Option<&str>| {
            jump_hop_for(
                &route,
                JumpAccess::Managed,
                &facts,
                same_grant,
                "/run/hm/signing.sock",
                &pin_file,
                pins,
                &paths,
            )
        };
        let ok = hop(true, Some(&pin_text)).unwrap();
        assert_eq!(ok.alias, "bast");
        assert_eq!(ok.host_key_alias, "hm-dest-bastion");
        assert_eq!(ok.identity_agent, "/run/hm/signing.sock");
        assert_eq!(ok.identity_file, ssh_path(&slot.cert_pub));
        assert_eq!(ok.host_key_algorithms.as_deref(), Some("ssh-ed25519"));
        assert_eq!(
            (ok.hostname.as_str(), ok.port, ok.user.as_str()),
            ("10.0.0.1", Some(2200), "jump")
        );
        // Another grant's binding serves the jump pair (or none does): refused.
        assert_eq!(
            hop(false, Some(&pin_text)).unwrap_err(),
            RouteHelperError::NoUsableRoute("route_dependency_out_of_scope")
        );
        // The jump's pin is not the catalog's: not attempted either.
        let stale = format!("hm-dest-bastion {KEY_A}\n");
        assert_eq!(
            hop(true, Some(&stale)).unwrap_err(),
            RouteHelperError::NoUsableRoute("host_pin_defeated")
        );
        assert_eq!(
            hop(true, None).unwrap_err(),
            RouteHelperError::NoUsableRoute("host_pin_defeated")
        );
        // Existing access without an agent endpoint for the jump identity: refused.
        assert_eq!(
            jump_hop_for(
                &route,
                JumpAccess::Existing,
                &facts,
                false,
                "/run/hm/signing.sock",
                &pin_file,
                Some(&pin_text),
                &paths,
            )
            .unwrap_err(),
            RouteHelperError::NoUsableRoute("route_dependency_out_of_scope")
        );
    }

    /// ⟨rev7⟩ m07-plan U3 (ADR-0013 §6.3, D21) through the route helper's own port:
    /// `deleted_hop_fails_closed` and `failed_hop_lookup_fails_closed`. The jump's catalog facts
    /// are read by point lookups of exactly the hop; a hop that is absent from the store (the
    /// row deleted), one that is not a managed destination, and a store that cannot be read
    /// each leave the route `route_undetermined` (the route is not attempted), never
    /// `Unavailable` read as "no route". The same-grant check is unchanged: a hop that is
    /// present is still built only for the final pair's own binding
    /// ([`a_managed_jump_hop_needs_the_final_pairs_own_binding`]).
    #[test]
    fn a_hop_that_is_absent_or_unreadable_leaves_the_helper_route_undetermined() {
        use heimdall_app::routes::{RouteBinding, RouteHelperError, RouteHelperPorts as _};
        use heimdall_contract::environment::JumpAccess;
        let dir = tempfile::tempdir().unwrap();
        let paths = helper_paths(dir.path());
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let db = heimdall_store::layout::db_path(&paths.state_dir).unwrap();
        let store = heimdall_store::Store::open(&db, Arc::new(heimdall_store::NoFaults)).unwrap();
        let route = approved_jump("jump");
        let ctx = Ctx {
            json: true,
            non_interactive: true,
            home: Some(dir.path().join("hm")),
            stdin_tty: false,
            request_epoch: None,
        };
        let binding = RouteBinding {
            binding: heimdall_contract::ids::BindingId::from_random_bytes([1; 16]),
            grant: heimdall_contract::ids::GrantId::from_random_bytes([2; 16]),
            endpoint: "/run/hm/signing.sock".into(),
            pairs: std::collections::BTreeSet::new(),
        };
        let hop = |db: PathBuf, access: JumpAccess| {
            let ports = HelperPorts {
                ctx: &ctx,
                db,
                paths: helper_paths(dir.path()),
                endpoint: "/run/hm/signing.sock".into(),
                pin_text: None,
            };
            let route = route.clone();
            let binding = binding.clone();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move { ports.jump_hop(&route, access, &binding).await })
        };
        let undetermined = RouteHelperError::NoUsableRoute(reason::ROUTE_UNDETERMINED);
        // The hop's row is absent (deleted): for a managed jump and for existing access alike.
        for access in [JumpAccess::Managed, JumpAccess::Existing] {
            assert_eq!(hop(db.clone(), access).unwrap_err(), undetermined);
        }
        // The hop is listed but is not a managed destination (malformed as a hop).
        store
            .transaction(|tx| {
                tx.upsert_destination(&heimdall_domain::catalog::DestinationRecord {
                    id: route.jump.clone(),
                    alias: "bast".into(),
                    revision: 1,
                    definition: heimdall_domain::catalog::DestinationDefinition::Observed,
                    label: None,
                    updated_at: "2026-11-25T09:00:00Z".parse().unwrap(),
                })
            })
            .unwrap();
        assert_eq!(
            hop(db.clone(), JumpAccess::Managed).unwrap_err(),
            undetermined
        );
        // The lookup itself fails: the store cannot be opened.
        assert_eq!(
            hop(dir.path().join("absent.db"), JumpAccess::Managed).unwrap_err(),
            undetermined
        );
    }

    /// ⟨M06 W5; ADR-0006 §18.9 item 8⟩ `route add --iroh <E> --relay <URL>` names the relays
    /// in the request's exposure policy (the widening the runtime then records as a local
    /// decision); without `--relay` the request carries no policy, as before; a relay
    /// without `--iroh`, or one that is not a plain `https://` URL, is refused before any
    /// contact.
    #[test]
    fn route_add_relay_names_the_relays_and_nothing_else() {
        use heimdall_contract::route::{InfrastructureProfile, RouteRequest};
        let parse = |line: &[&str]| {
            let mut argv = vec!["heimdall", "route", "add", "lab"];
            argv.extend_from_slice(line);
            match Cli::try_parse_from(&argv).map(|c| c.command) {
                Ok(Some(Command::Route(r))) => Ok(route_request(r)),
                Ok(_) => panic!("{line:?}: not a route command"),
                Err(e) => Err(e),
            }
        };
        let exposure = |line: &[&str]| match parse(line).unwrap().unwrap() {
            RouteRequest::Add { exposure, .. } => exposure,
            other => panic!("{other:?}"),
        };
        assert_eq!(exposure(&["--iroh", EP]), None);
        let with = exposure(&[
            "--iroh",
            EP,
            "--relay",
            "https://relay.invalid./",
            "--relay",
            "https://other.invalid./",
        ])
        .unwrap();
        assert_eq!(
            with,
            heimdall_contract::route::ExposurePolicy {
                infrastructure: InfrastructureProfile::Custom {
                    relays: vec![
                        "https://other.invalid./".into(),
                        "https://relay.invalid./".into()
                    ],
                },
                ..heimdall_contract::route::ExposurePolicy::default()
            }
        );
        let misplaced = parse(&["--direct", "h", "--relay", "https://relay.invalid./"]).unwrap();
        assert_eq!(misplaced.unwrap_err().code, Code::UsageError);
        // ⟨ADR-0006 §18.9 item 9⟩ One spelling: two spellings of one URL are one relay, and
        // each distinct URL is named once, sorted (the order of the flags does not matter).
        let spelled = exposure(&[
            "--iroh",
            EP,
            "--relay",
            "HTTPS://Relay.Invalid.:443",
            "--relay",
            "http://other.invalid.:8080/r",
            "--relay",
            "https://relay.invalid./",
        ])
        .unwrap();
        assert_eq!(
            spelled.infrastructure,
            InfrastructureProfile::Custom {
                relays: vec![
                    "http://other.invalid.:8080/r".into(),
                    "https://relay.invalid./".into()
                ],
            }
        );
        // Each refusal class is a usage error that names the flag's position and the
        // class, and never the URL.
        for (bad, class) in [
            ("ftp://relay.invalid./", "https:// or http://"),
            ("relay", "https:// or http://"),
            (
                "https://user:hunter2@relay.invalid./",
                "no user name or password",
            ),
            ("https://relay.invalid./?token=hunter2", "no query string"),
            ("https://relay.invalid./#hunter2", "no fragment"),
            ("https://", "a scheme, a host"),
            ("https://a b", "a scheme, a host"),
            ("https://a;b", "a scheme, a host"),
        ] {
            let refused = parse(&[
                "--iroh",
                EP,
                "--relay",
                "https://ok.invalid./",
                "--relay",
                bad,
            ])
            .unwrap()
            .unwrap_err();
            assert_eq!(refused.code, Code::UsageError, "{bad}");
            assert!(
                refused.message.contains("--relay 2"),
                "{bad}: {}",
                refused.message
            );
            assert!(
                refused.message.contains(class),
                "{bad}: {}",
                refused.message
            );
            assert!(!refused.message.contains("hunter2"), "{bad}");
        }
    }

    /// ⟨rev7; D20, ruling R-A⟩ `route add --iroh <E> --address …` sends each address in its
    /// one spelling and refuses, before any contact, an address that is not one (`USAGE_ERROR`,
    /// `fix_request`), an entry over 64 bytes, a fourth address and a ninth relay (each
    /// `item_too_large`).
    #[test]
    fn route_add_addresses_are_canonical_and_bounded() {
        use heimdall_contract::route::{RouteRequest, RouteSpec};
        let parse = |line: &[&str]| {
            let mut argv = vec!["heimdall", "route", "add", "lab", "--iroh", EP];
            argv.extend_from_slice(line);
            match Cli::try_parse_from(&argv).map(|c| c.command) {
                Ok(Some(Command::Route(r))) => route_request(r),
                other => panic!("{line:?}: {other:?}"),
            }
        };
        let request = parse(&[
            "--address",
            "192.0.2.1:22",
            "--address",
            "[2001:0DB8:0000::0001]:2222",
            "--address",
            "[fe80::1%3]:22",
        ])
        .unwrap();
        let RouteRequest::Add {
            route: RouteSpec::Iroh {
                direct_addresses, ..
            },
            ..
        } = request
        else {
            panic!("an Iroh add");
        };
        assert_eq!(
            direct_addresses,
            ["192.0.2.1:22", "[2001:db8::1]:2222", "[fe80::1%3]:22"]
        );
        let long = format!("[fe80::1%{}]:22", "0".repeat(60));
        let relays: Vec<String> = (0..9)
            .map(|i| format!("https://relay{i}.invalid./"))
            .collect();
        let mut nine = Vec::new();
        for r in &relays {
            nine.extend(["--relay", r.as_str()]);
        }
        let four = [
            "--address",
            "192.0.2.1:1",
            "--address",
            "192.0.2.1:2",
            "--address",
            "192.0.2.1:3",
            "--address",
            "192.0.2.1:4",
        ];
        for (line, reason, what) in [
            (
                vec!["--address", "[2001:db8::1%3]:22"],
                None,
                "a global zone",
            ),
            (
                vec!["--address", "[fe80::1%eth0]:22"],
                None,
                "an interface zone",
            ),
            (vec!["--address", "lab:22"], None, "a host name"),
            (
                vec!["--address", long.as_str()],
                Some("item_too_large"),
                "over 64 bytes",
            ),
            (four.to_vec(), Some("item_too_large"), "four addresses"),
            (nine, Some("item_too_large"), "nine relays"),
        ] {
            let e = parse(&line).unwrap_err();
            assert_eq!(e.code, Code::UsageError, "{what}");
            assert_eq!(e.reason.as_deref(), reason, "{what}");
            assert_eq!(e.next.action, "fix_request", "{what}");
        }
    }

    #[test]
    fn m06_route_and_transport_commands_are_wired() {
        let scratch = std::env::temp_dir().join(format!("hm-m06-w3-{}", std::process::id()));
        let home = scratch.join("never-created");
        for line in REFUSED_LOCALLY {
            let mut argv = vec!["heimdall", "--json", "--non-interactive", "--home"];
            argv.push(home.to_str().unwrap());
            argv.extend_from_slice(line);
            let cli = Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{line:?}: {e}"));
            assert!(
                matches!(cli.command, Some(Command::Route(_) | Command::Transport(_))),
                "{line:?}"
            );
            assert_eq!(dispatch(cli), ExitCode::Usage, "{line:?}");
            assert!(!home.exists(), "{line:?} created the home");
        }
        for helper in [
            &["route", "connect", "--destination", "lab"][..],
            &[
                "route",
                "connect",
                "--destination",
                "lab",
                "--account",
                "a",
                "--endpoint",
                "rel",
            ],
            &["transport", "serve"],
            &["transport", "serve", "--environment", "nope"],
        ] {
            let mut argv = vec!["heimdall", "--home"];
            argv.push(home.to_str().unwrap());
            argv.extend_from_slice(helper);
            let cli = Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("{helper:?}: {e}"));
            assert_eq!(dispatch(cli), ExitCode::Usage, "{helper:?}");
            assert!(!home.exists(), "{helper:?} created the home");
        }
        for wrong in [
            &["transport", "enable", "--serve", "--port", "0"][..],
            &["transport", "enable", "--port", "4433"],
            &["route", "add", "lab"],
            &["route", "add", "lab", "--direct", "h", "--jump", "j"],
        ] {
            let mut argv = vec!["heimdall"];
            argv.extend_from_slice(wrong);
            assert!(Cli::try_parse_from(&argv).is_err(), "{wrong:?} parsed");
        }
        for ok in [
            &["route", "add", "lab", "--direct", "10.0.0.1:22"][..],
            &["route", "add", "lab", "--direct", "[::1]:2222"],
            &["route", "add", "lab", "--jump", "bastion"],
            &[
                "route",
                "add",
                "lab",
                "--iroh",
                EP,
                "--address",
                "127.0.0.1:4433",
            ],
            &["route", "remove", "lab", "route_00"],
            &["route", "prefer", "lab", "route_00"],
            &["transport", "enable"],
            &["transport", "enable", "--serve", "--port", "4433"],
            &["transport", "disable"],
            &["transport", "rotate"],
            &["transport", "adopt-roost", "lab", "--endpoint", EP],
            &[
                "environment",
                "invite",
                "env_00",
                "--role",
                "viewer",
                "--public-key",
                "k",
                "--iroh",
            ],
        ] {
            let mut argv = vec!["heimdall"];
            argv.extend_from_slice(ok);
            assert!(Cli::try_parse_from(&argv).is_ok(), "{ok:?}");
        }
        assert_eq!(
            parse_direct("[2001:db8::1]:2222").unwrap(),
            heimdall_contract::route::RouteSpec::Direct {
                host: "2001:db8::1".into(),
                port: Some(2222)
            }
        );
        assert_eq!(
            parse_direct("2001:db8::1").unwrap(),
            heimdall_contract::route::RouteSpec::Direct {
                host: "2001:db8::1".into(),
                port: None
            }
        );
        assert!(!scratch.exists());
    }

    /// The orchestrator's naming ruling (G08 freeze): `environment` (no `env` alias),
    /// `device`, `route`, `transport` with `adopt-roost`; no top-level `roost`; `route
    /// connect` parses but is hidden.
    #[test]
    fn m06_names_follow_the_freeze() {
        for gone in [
            &["env", "status"][..],
            &["roost", "adopt", "lab"][..],
            &["transport", "connect"][..],
        ] {
            let mut argv = vec!["heimdall"];
            argv.extend_from_slice(gone);
            assert!(Cli::try_parse_from(&argv).is_err(), "{gone:?} still parses");
        }
        for line in [
            &["environment", "status"][..],
            &[
                "environment",
                "add",
                "--destination",
                "lab",
                "--account",
                "runner",
                "--runner-program",
                "/opt/heimdall",
                "--runner-home",
                "/srv/runner/heimdall",
            ][..],
            &[
                "environment",
                "invite",
                "env_00",
                "--role",
                "viewer",
                "--public-key",
                "ssh-ed25519 AAAA",
            ][..],
            &["environment", "join", "--show-key"][..],
            &["environment", "join", "bundle.json"][..],
            &["environment", "revoke-client", "env_00", "cl_00"][..],
            &["environment", "remove", "env_00"][..],
            &["environment", "update", "env_00"][..],
            // ⟨ADR-0006 §18.7 item 19⟩ The recheck's two halves.
            &["environment", "recheck", "env_00"][..],
            &["remote", "policy", "recheck"][..],
            &["device", "retire"][..],
        ] {
            let mut argv = vec!["heimdall"];
            argv.extend_from_slice(line);
            assert!(Cli::try_parse_from(&argv).is_ok(), "{line:?}");
        }
        assert!(Cli::try_parse_from(["heimdall", "environment", "join"]).is_err());
        assert!(
            Cli::try_parse_from(["heimdall", "environment", "join", "b.json", "--show-key"])
                .is_err()
        );
        use clap::CommandFactory as _;
        let mut top = Cli::command();
        let route = top.find_subcommand_mut("route").unwrap();
        let connect = route.find_subcommand("connect").unwrap();
        assert!(connect.is_hide_set(), "route connect is hidden");
        let help = route.render_help().to_string();
        assert!(!help.contains("connect"), "{help}");
        let transport = top.find_subcommand_mut("transport").unwrap();
        assert!(transport.find_subcommand("serve").unwrap().is_hide_set());
        let help = transport.render_help().to_string();
        assert!(!help.contains("serve child"), "{help}");
        assert!(help.contains("rotate"), "{help}");
    }

    /// ⟨ADR-0006 §18.7 item 19⟩ `remote policy recheck` shows the evidence before it asks:
    /// why the runner is owner-only, the probing controller (client ID and management key
    /// fingerprint), when, and what the probes observed. `environment recheck` says that
    /// nothing is lifted yet.
    #[test]
    fn the_recheck_confirmation_shows_its_evidence() {
        let at = |s: &str| -> heimdall_contract::Timestamp { s.parse().unwrap() };
        let controller = ClientId::from_random_bytes([4; 16]);
        let fp = KeyFingerprint::parse(&format!("SHA256:{}", "M".repeat(43))).unwrap();
        let text = policy_recheck_confirmation(
            &heimdall_store::ext_runner::RunnerDowngrade {
                cause: "session_agent_forwarded".to_owned(),
                epoch: 2,
                recorded_at: at("2026-11-21T08:00:00Z"),
                last_event_at: at("2026-11-21T08:30:00Z"),
            },
            &heimdall_store::ext_runner::PolicyRecheckEvidence {
                controller: controller.clone(),
                epoch: 2,
                recorded_at: at("2026-11-21T09:00:00Z"),
                boot_id: "b".to_owned(),
                continuous_ms: None,
                probe: heimdall_contract::remote::ProbeObservation {
                    pty_refused: true,
                    forward_refused: true,
                    agent_forward_refused: true,
                    setenv_canary_delivered: false,
                },
            },
            &fp,
        );
        for said in [
            "sshd forwarded an agent into a management session",
            controller.as_str(),
            fp.as_str(),
            "2026-11-21T09:00:00Z",
            "terminal refused, port forwarding refused, agent forwarding refused, client \
             environment refused",
            "Type yes to continue: ",
        ] {
            assert!(text.contains(said), "{said}: {text}");
        }
        let env = EnvironmentId::from_random_bytes([1; 16]);
        let recorded = recheck_line(&env, &serde_json::json!({ "recorded": true }));
        assert!(
            recorded.contains("Nothing is lifted yet")
                && recorded.contains("heimdall remote policy recheck"),
            "{recorded}"
        );
        let nothing = recheck_line(&env, &serde_json::json!({ "recorded": false }));
        assert!(nothing.contains("is not downgraded"), "{nothing}");
    }

    /// ⟨W2 wiring⟩ `remote serve`'s arguments reach `ServeArgs::parse` whole: the global
    /// `--home` does not capture the bridge's own `--home` (identity and home from argv only);
    /// `remote` is hidden from the top level, and `service run --runner` parses.
    #[test]
    fn remote_serve_keeps_its_own_arguments_and_remote_is_hidden() {
        let cid = ClientId::from_random_bytes([3; 16]);
        let cli = Cli::try_parse_from([
            "heimdall",
            "remote",
            "serve",
            "--client",
            cid.as_str(),
            "--home",
            "/srv/runner/heimdall",
        ])
        .unwrap();
        assert!(
            cli.home.is_none(),
            "the global --home did not capture serve's"
        );
        let Some(Command::Remote(RemoteCommand::Serve(args))) = cli.command else {
            panic!("not remote serve");
        };
        let parsed = heimdall_runtime::paired::ServeArgs::parse(&args.args).unwrap();
        assert_eq!(parsed.client, cid);
        assert_eq!(
            parsed.home,
            std::path::PathBuf::from("/srv/runner/heimdall")
        );
        assert!(
            Cli::try_parse_from([
                "heimdall",
                "remote",
                "init",
                "--owner-client",
                cid.as_str(),
                "--owner-key",
                "ssh-ed25519 AAAA"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["heimdall", "service", "run", "--runner"]).is_ok());
        use clap::CommandFactory as _;
        let top = Cli::command();
        assert!(top.find_subcommand("remote").unwrap().is_hide_set());
        assert!(!top.clone().render_help().to_string().contains("remote "));
    }

    /// `device retire` without the owner at a terminal is refused before anything is read
    /// (no home is created).
    /// ⟨M06 W3; ADR-0006 §18.7 item 7⟩ The runner-local commands with no runtime running: a
    /// widening (`time-source set`, `issuer-trust add`) with `--non-interactive` is refused
    /// `INTERACTION_REQUIRED` with nothing written; on an installation that is not a runner
    /// every form is refused first; on a runner the narrowing forms write directly under the
    /// instance lock and the read forms list what is stored.
    #[test]
    fn runner_local_commands_need_a_runner_and_a_terminal_to_widen() {
        use heimdall_store::ext_m06::{AppliedLine, ClientState, RemoteClientRecord};
        let scratch = tempfile::tempdir().unwrap();
        let home = scratch.path().join("home");
        let run = |args: &[&str]| {
            let mut argv = vec!["heimdall", "--json", "--home", home.to_str().unwrap()];
            argv.extend_from_slice(args);
            dispatch(Cli::try_parse_from(argv).unwrap())
        };
        let owner = ClientId::from_random_bytes([3; 16]);
        let ca_file = scratch.path().join("ca.pub");
        std::fs::write(
            &ca_file,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ca\n",
        )
        .unwrap();
        // Not a runner (no state at all): refused, nothing created.
        assert_eq!(run(&["remote", "time-source", "show"]), ExitCode::Denied);
        assert_eq!(run(&["remote", "time-source", "clear"]), ExitCode::Denied);
        assert!(!home.join("state").exists());
        // Make it a runner with one owner client (fixture state).
        let paths = heimdall_runtime::Paths::resolve(&|name| {
            (name == heimdall_runtime::paths::HOME_ENV).then(|| home.clone().into_os_string())
        })
        .unwrap();
        paths.ensure().unwrap();
        let store = heimdall_store::Store::open(
            &heimdall_store::layout::db_path(&paths.state_dir).unwrap(),
            Arc::new(heimdall_store::NoFaults),
        )
        .unwrap();
        store
            .transaction(|tx| tx.init_self_environment(&EnvironmentId::from_random_bytes([1; 16])))
            .unwrap();
        heimdall_runtime::paired::init_runner(&store).unwrap();
        let at = now();
        store
            .transaction(|tx| {
                tx.enroll_bootstrap_owner(
                    &RemoteClientRecord {
                        client: owner.clone(),
                        role: Role::Owner,
                        key_fingerprint: KeyFingerprint::parse(&format!(
                            "SHA256:{}",
                            "B".repeat(43)
                        ))
                        .unwrap(),
                        public_key: "ssh-ed25519 AAAA".into(),
                        state: ClientState::Active,
                        invitation: None,
                        revoked_generation: None,
                        revocation: None,
                        created_at: at,
                        updated_at: at,
                        line: AppliedLine::Absent,
                    },
                    at,
                )
                .map(drop)
            })
            .unwrap();
        heimdall_runtime::runner::runner_local(
            &store,
            at,
            true,
            &heimdall_contract::remote::RunnerLocalRequest::DesignateTimeSource {
                client: owner.clone(),
                request_id: RequestId::parse("req-fixture").unwrap(),
            },
        )
        .unwrap();
        drop(store);
        // Widening without a terminal: refused, nothing written.
        let ca = ca_file.to_str().unwrap();
        assert_eq!(
            run(&["--non-interactive", "remote", "issuer-trust", "add", ca]),
            ExitCode::InteractionRequired
        );
        assert_eq!(
            run(&[
                "--non-interactive",
                "remote",
                "time-source",
                "set",
                owner.as_str()
            ]),
            ExitCode::InteractionRequired
        );
        let read = || {
            heimdall_store::Store::open_read_only(
                &heimdall_store::layout::db_path(&paths.state_dir).unwrap(),
                Arc::new(heimdall_store::NoFaults),
            )
            .unwrap()
            .transaction(|tx| Ok((tx.remote_issuer_trust()?.len(), tx.time_source()?)))
            .unwrap()
        };
        assert_eq!(read().0, 0);
        // Reads, then the narrowing form written directly under the lock.
        assert_eq!(run(&["remote", "time-source", "show"]), ExitCode::Success);
        assert_eq!(run(&["remote", "issuer-trust", "list"]), ExitCode::Success);
        assert!(read().1.is_some());
        assert_eq!(
            run(&["--non-interactive", "remote", "time-source", "clear"]),
            ExitCode::Success
        );
        assert!(read().1.is_none());
        assert_eq!(
            run(&[
                "remote",
                "issuer-trust",
                "remove",
                &format!("SHA256:{}", "C".repeat(43))
            ]),
            ExitCode::Success,
            "removing what is not trusted is a no-op"
        );
    }

    #[test]
    fn device_retire_needs_a_terminal() {
        let scratch = std::env::temp_dir().join(format!("hm-m06-retire-{}", std::process::id()));
        let home = scratch.join("never-created");
        let cli = Cli::try_parse_from([
            "heimdall",
            "--json",
            "--non-interactive",
            "--home",
            home.to_str().unwrap(),
            "device",
            "retire",
        ])
        .unwrap();
        assert_eq!(dispatch(cli), ExitCode::InteractionRequired);
        assert!(!home.exists());
    }

    #[test]
    fn confirmation_texts_name_what_is_confirmed() {
        let fp = KeyFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap();
        let env = EnvironmentId::from_random_bytes([1; 16]);
        let invite = confirmation_text(&Confirmation::InviteKey {
            environment: env.clone(),
            role: Role::Viewer,
            fingerprint: fp.clone(),
        });
        assert!(invite.contains(fp.as_str()) && invite.contains(env.as_str()));
        // ⟨ruling Q12⟩ `remote issuer-trust add`: the CA, the controller's client ID and its
        // management key's fingerprint.
        let controller = ClientId::from_random_bytes([7; 16]);
        let ca = format!("SHA256:{}", "C".repeat(43));
        let trust = issuer_trust_confirmation(&controller, &fp, &ca);
        assert!(
            trust.contains(&ca)
                && trust.contains(controller.as_str())
                && trust.contains(fp.as_str()),
            "{trust}"
        );
        // ⟨ADR-0006 §18.7 item 8⟩ `remote init`: the endpoint ID is shown next to the owner
        // key's fingerprint, and only when the bootstrap carries one.
        let endpoint = IrohEndpointId::parse(&"ab".repeat(32)).unwrap();
        let init = remote_init_confirmation(&controller, &fp, Some(&endpoint), None);
        assert!(
            init.contains(fp.as_str()) && init.contains(endpoint.as_str()) && init.contains("Iroh"),
            "{init}"
        );
        assert!(!remote_init_confirmation(&controller, &fp, None, None).contains("Iroh"));
        let retire = confirmation_text(&Confirmation::RetireDevice {
            environments: vec![env.clone()],
            forgotten_only: Vec::new(),
            fingerprint: fp.clone(),
        });
        assert!(retire.contains("destroy") && retire.contains("revoke it on 1 runner"));
        assert!(!retire.contains("FORGOTTEN") && !retire.contains("revoke-client"));
        // ⟨M06 W5 `w5m` L3⟩ Limited records: only forgotten, with the command an owner
        // must run on each such runner; they are not counted as revoked.
        let other = EnvironmentId::from_random_bytes([2; 16]);
        let limited_client = heimdall_contract::ids::ClientId::from_random_bytes([7; 16]);
        let mixed = confirmation_text(&Confirmation::RetireDevice {
            environments: vec![env.clone(), other.clone()],
            forgotten_only: vec![heimdall_app::remote_env::StillEnrolled {
                environment: other.clone(),
                client: limited_client.clone(),
                role: Role::Viewer,
            }],
            fingerprint: fp.clone(),
        });
        assert!(mixed.contains("revoke it on 1 runner"), "{mixed}");
        assert!(mixed.contains("ONLY FORGOTTEN on this device"), "{mixed}");
        assert!(
            mixed.contains(&format!(
                "heimdall environment revoke-client {} {}",
                other.as_str(),
                limited_client.as_str()
            )),
            "{mixed}"
        );
        assert!(mixed.ends_with("Type yes to continue: "));
        assert!(
            !TerminalConfirm { interactive: false }.confirm(&Confirmation::RetireDevice {
                environments: vec![env],
                forgotten_only: Vec::new(),
                fingerprint: fp,
            })
        );
    }

    /// ⟨ADR-0006 §18.7 "Also ruled", 2026-11-21⟩ `remote init` and the account's `~/.ssh`:
    /// a missing one is created owner-only, and only when asked to (after the
    /// confirmation); an existing directory is left exactly as it is (its mode too); a
    /// symbolic link (even to the account's own directory), anything that is not a
    /// directory, and a directory another account owns are each refused with nothing
    /// written.
    #[cfg(unix)]
    #[test]
    fn remote_init_creates_a_missing_ssh_dir_and_refuses_what_is_not_the_accounts() {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = tempfile::tempdir().unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        // Absent: nothing before the confirmation, 0700 after it.
        let absent = scratch.path().join("a").join(".ssh");
        std::fs::create_dir(absent.parent().unwrap()).unwrap();
        ensure_account_ssh_dir(&absent, false).unwrap();
        assert!(!absent.exists());
        ensure_account_ssh_dir(&absent, true).unwrap();
        assert_eq!(mode(&absent), 0o700);
        // Existing: never changed, whatever its mode.
        let existing = scratch.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_account_ssh_dir(&existing, true).unwrap();
        assert_eq!(mode(&existing), 0o755);
        // Refused: a link to the account's own directory, a dangling link, a file.
        let link = scratch.path().join("link");
        std::os::unix::fs::symlink(&existing, &link).unwrap();
        let dangling = scratch.path().join("dangling");
        std::os::unix::fs::symlink(scratch.path().join("nowhere"), &dangling).unwrap();
        let file = scratch.path().join("file");
        std::fs::write(&file, b"").unwrap();
        for (path, why) in [
            (&link, "is a symbolic link"),
            (&dangling, "is a symbolic link"),
            (&file, "is not a directory"),
        ] {
            for create in [false, true] {
                let e = ensure_account_ssh_dir(path, create).unwrap_err();
                assert_eq!(e.code, Code::ConfigConflict, "{path:?}");
                assert_eq!(e.effect_status, EffectStatus::None);
                assert!(e.message.contains(why), "{}", e.message);
                assert!(e.message.contains("nothing was written"), "{}", e.message);
            }
        }
        assert!(
            !scratch.path().join("nowhere").exists(),
            "a link is never created through"
        );
        assert_eq!(mode(&existing), 0o755);
        // Another account's directory (the root directory is root's; only inspected).
        if heimdall_localenv::sys::current_uid() != 0 {
            let e = ensure_account_ssh_dir(Path::new("/"), true).unwrap_err();
            assert_eq!(e.code, Code::ConfigConflict);
            assert!(
                e.message.contains("is not owned by this account"),
                "{}",
                e.message
            );
        }
    }

    /// ⟨ADR-0006 §18.7 "Also ruled", 2026-11-21⟩ What sshd's `StrictModes` would refuse is
    /// said in `remote init`'s output (`strict_modes` and a warning) and never fixed: a
    /// home, `~/.ssh` or `authorized_keys` writable by group or others. A clean account
    /// says nothing.
    #[cfg(unix)]
    #[test]
    fn strict_modes_problems_are_reported_and_not_fixed() {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = tempfile::tempdir().unwrap();
        let home = scratch.path().join("home");
        let user_dir = home.join(".ssh");
        let keys = user_dir.join("authorized_keys");
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::write(&keys, b"").unwrap();
        let set = |p: &Path, mode: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        set(&home, 0o755);
        set(&user_dir, 0o700);
        set(&keys, 0o600);
        assert!(strict_modes_problems(&user_dir).is_empty());
        let answer = |user_dir: &Path| {
            let mut data = serde_json::json!({
                "environment": "e", "client": "c", "created": true, "line_written": true,
            });
            init_answer(&mut data, None, user_dir)
        };
        let (data, human) = answer(&user_dir);
        assert!(data.get("strict_modes").is_none(), "{data}");
        assert!(!human.contains("StrictModes"), "{human}");
        // A missing `~/.ssh` is not a problem either.
        assert!(strict_modes_problems(&scratch.path().join("none").join(".ssh")).is_empty());
        set(&home, 0o775);
        set(&user_dir, 0o702);
        set(&keys, 0o660);
        let problem = |what| StrictModesProblem {
            what,
            problem: "group_or_other_writable",
        };
        assert_eq!(
            strict_modes_problems(&user_dir),
            [
                problem("home"),
                problem("ssh_dir"),
                problem("authorized_keys")
            ]
        );
        let (data, human) = answer(&user_dir);
        assert_eq!(
            data["strict_modes"],
            serde_json::json!([
                { "path": "home", "problem": "group_or_other_writable" },
                { "path": "ssh_dir", "problem": "group_or_other_writable" },
                { "path": "authorized_keys", "problem": "group_or_other_writable" },
            ])
        );
        assert!(
            human.contains("StrictModes")
                && human.contains("the home directory is writable by group or others")
                && human.contains("Heimdall does not change these"),
            "{human}"
        );
        assert!(
            !human.contains(scratch.path().to_str().unwrap()),
            "no path: {human}"
        );
        // Reported only: nothing was changed.
        assert_eq!(
            (mode(&home), mode(&user_dir), mode(&keys)),
            (0o775, 0o702, 0o660)
        );
        // An owner that is neither the account nor root is the other problem (statement).
        let wrong = strict_modes_statement(&[StrictModesProblem {
            what: "ssh_dir",
            problem: "wrong_owner",
        }]);
        assert!(
            wrong.contains("~/.ssh is not owned by this account"),
            "{wrong}"
        );
    }

    /// ⟨ADR-0006 §18.7 "Also ruled", 2026-11-21⟩ A first `remote init` while a runtime that
    /// is not a runner's holds the home: `driver_unavailable`, nothing written, and the
    /// message says to stop the local runtime first.
    #[test]
    fn a_first_remote_init_under_a_plain_runtime_says_to_stop_it_first() {
        let e = not_a_runner_runtime();
        assert_eq!(e.code, Code::CapabilityUnavailable);
        assert_eq!(e.reason.as_deref(), Some(reason::DRIVER_UNAVAILABLE));
        assert_eq!(e.effect_status, EffectStatus::None);
        assert!(
            e.message.contains("stop the local runtime first")
                && e.message.contains("`heimdall service stop`"),
            "{}",
            e.message
        );
    }
}
