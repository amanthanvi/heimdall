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
//!   and `heimdall_app::transport`. A widening (a route or endpoint that adds exposure, a
//!   roost) is refused `exposure_unconsented` there until a local decision record exists for
//!   it (DONE question). `roost adopt` is `transport adopt-roost`.
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

use std::collections::BTreeSet;
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
    VerifiedAccess, ssh as env_ssh,
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
    /// Stops serving, destroys the endpoint key and removes every route that names it.
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

/// `remote` subcommands: the runner's side (ADR-0012 §3.3, §3.6). Hidden and frozen.
#[derive(Debug, Subcommand)]
pub enum RemoteCommand {
    /// On the runner, in the bootstrap's interactive ssh session: mark this installation a
    /// remote runner and enroll the controller's management key as owner, after the owner
    /// confirms its fingerprint on this terminal.
    Init(RemoteInitArgs),
    /// The forced command of a management line: bridge one paired session to this
    /// installation's runtime. Takes exactly `--client <client> --home <absolute path>`.
    Serve(crate::cli::PlannedArgs),
    /// ⟨M06 W3⟩ This runner's trusted issuers (`issuer_trust`): add a controller's CA (a
    /// widening, typed `yes` on this terminal), remove one (narrowing), or list them.
    #[command(subcommand)]
    IssuerTrust(IssuerTrustCommand),
    /// ⟨M06 W3⟩ This runner's designated time source: set an owner client (a widening, typed
    /// `yes` on this terminal), clear it (narrowing), or show it.
    #[command(subcommand)]
    TimeSource(TimeSourceCommand),
    /// ⟨M06 W3; ADR-0006 §18.7 item 19⟩ This runner's sshd-policy downgrade.
    #[command(subcommand)]
    Policy(RemotePolicyCommand),
}

/// ⟨M06 W3; ADR-0006 §18.7 item 19⟩ `remote policy` subcommands, run at the runner (an
/// interactive ssh TTY counts).
#[derive(Debug, Subcommand)]
pub enum RemotePolicyCommand {
    /// Lift this runner's owner-only downgrade on the recheck an owner's controller left
    /// (`heimdall environment recheck`): shows that evidence, then needs a terminal and a
    /// typed `yes`. Refused without evidence, with evidence older than 15 minutes, or with
    /// evidence from before a later downgrade.
    Recheck,
}

/// ⟨M06 W3; ADR-0006 §18.7 item 7⟩ `remote issuer-trust` subcommands, run at the runner (an
/// interactive ssh TTY counts).
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

/// ⟨M06 W3; ADR-0006 §18.7 item 7⟩ `remote time-source` subcommands, run at the runner.
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
    /// ⟨M06 W3⟩ The controller's CA public key (`ssh-ed25519 <base64>`): trusted for the owner
    /// client being enrolled, which also becomes this runner's time source, in the same
    /// confirmation. Absent when the controller has no issuer.
    #[arg(long, value_name = "KEY")]
    pub issuer_ca: Option<String>,
    /// ⟨M06 W3⟩ The controller device's Iroh endpoint ID (64 lowercase hex): the owner client
    /// is admitted to this runner over Iroh with it, in the same confirmation. Absent when
    /// the controller has no Iroh key. An endpoint already recorded is never replaced.
    #[arg(long, value_name = "ENDPOINT")]
    pub iroh_endpoint: Option<String>,
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

/// Send `request` to the runtime (started when none runs: these are effectful), requiring
/// `capability`; the answer is printed as is.
fn send_to_runtime(
    ctx: &Ctx,
    capability: &str,
    request: heimdall_contract::request::Request,
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
            Ok(mut client) => client.request(request).await,
            Err(e) => output::error_value(*e),
        }
    });
    if env.code.is_success() {
        let text = human(&env.data);
        emit_ok(ctx, env.data, &text)
    } else {
        output::emit(&env, ctx.json);
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
            let route = match (a.direct, a.jump, a.iroh) {
                (Some(d), None, None) => parse_direct(&d)?,
                (None, Some(j), None) => RouteSpec::Jump {
                    via: parse_destination(&j)?,
                },
                (None, None, Some(e)) => {
                    for addr in &a.addresses {
                        if addr.parse::<std::net::SocketAddr>().is_err() {
                            return Err(usage("--address takes ip:port"));
                        }
                    }
                    RouteSpec::Iroh {
                        endpoint: parse_endpoint(&e)?,
                        direct_addresses: a.addresses,
                        external_roost: false,
                    }
                }
                _ => return Err(usage("give exactly one of --direct, --jump, --iroh")),
            };
            RouteRequest::Add {
                destination: parse_destination(&a.destination)?,
                route,
                exposure: None,
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
    send_to_runtime(
        ctx,
        heimdall_contract::ipc::capability::ROUTES_V1,
        heimdall_contract::request::Request::Route(request),
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

/// `transport …`.
pub(crate) fn transport(ctx: &Ctx, command: TransportCommand) -> ExitCode {
    use heimdall_contract::route::{ExposurePolicy, TransportRequest};
    let request = match command {
        TransportCommand::Serve(a) => return transport_serve(&a),
        TransportCommand::Rotate => return transport_rotate(ctx),
        TransportCommand::Enable(a) => (|| {
            Ok(TransportRequest::Enable {
                serve: a.serve,
                exposure: a.port.map(|p| ExposurePolicy {
                    port: Some(p),
                    ..ExposurePolicy::default()
                }),
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
    send_to_runtime(
        ctx,
        heimdall_contract::ipc::capability::TRANSPORT_IROH_V1,
        heimdall_contract::request::Request::Transport(request),
        |data| serde_json::to_string_pretty(data).unwrap_or_default(),
    )
}

/// The ports of the route helper (`route connect`): the runtime's `route.resolve_binding`
/// (a running runtime only: the binding the alias names is served by it), the catalog's
/// route facts read read-only, and no jump-leg wiring yet (fail closed: a jump route makes
/// the helper refuse before any route is tried; DONE note). Route health has no request form
/// to reach the runtime, so it is not recorded here (DONE note).
struct HelperPorts<'a> {
    ctx: &'a Ctx,
    db: PathBuf,
}

#[async_trait::async_trait]
impl heimdall_app::routes::RouteHelperPorts for HelperPorts<'_> {
    async fn resolve_route_binding(
        &self,
        destination: &DestinationId,
        account: &AccountName,
        endpoint: &str,
    ) -> Result<heimdall_app::routes::RouteBinding, heimdall_app::routes::RouteHelperError> {
        use heimdall_app::routes::{ResolvedRouteBinding, RouteHelperError};
        let mut client = crate::client::connect_requiring(
            self.ctx,
            false,
            &[heimdall_contract::ipc::capability::ROUTES_V1],
        )
        .await
        .map_err(|_| RouteHelperError::Unavailable)?;
        let env = client
            .request(heimdall_contract::request::Request::Route(
                heimdall_contract::route::RouteRequest::ResolveBinding {
                    destination: destination.clone(),
                    account: account.clone(),
                    endpoint: endpoint.to_owned(),
                },
            ))
            .await;
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

    async fn jump_hop(
        &self,
        _route: &heimdall_domain::catalog::ApprovedRoute,
        _access: heimdall_contract::environment::JumpAccess,
        _binding: &heimdall_app::routes::RouteBinding,
    ) -> Result<heimdall_app::routes::JumpHop, heimdall_app::routes::RouteHelperError> {
        Err(heimdall_app::routes::RouteHelperError::Unavailable)
    }

    async fn record_health(&self, _payload: heimdall_contract::route::RouteHealthPayload) {}
}

/// `route connect --destination <id> --account <a> --endpoint <path>` (ADR-0012 §5.3–§5.5):
/// the typed inputs only (`heimdall_app::routes::HelperArgs`), then the helper core over
/// this process's standard streams (standard output carries SSH bytes only; diagnostics go
/// to standard error). Its exit codes are internal (ADR-0012 §1.5).
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
    let db = paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
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
                heimdall_runtime::supervise_transport::product_iroh_store(&environment),
            )
        });
    let dialer = heimdall_app::routes::legs::RouteLegDialer {
        base: heimdall_app::routes::legs::TokioLegDialer {
            ssh_client: ssh_client().unwrap_or_default(),
            relay_jump_stderr: true,
        },
        iroh,
    };
    let ports = HelperPorts { ctx, db };
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
        let db = self
            .paths
            .state_dir
            .join(heimdall_runtime::service::STATE_DB_FILE);
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
            issuer_ca: None,
            iroh_endpoint: None,
        };
        let sessions = SshSessions {
            ssh_client: ssh,
            root,
            key: key.clone(),
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
        let db = self
            .paths
            .state_dir
            .join(heimdall_runtime::service::STATE_DB_FILE);
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
        let keys = heimdall_runtime::supervise_transport::CredentialKeys(
            heimdall_runtime::supervise_transport::product_iroh_store(&environment),
        );
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
/// kind, never a product claim), with an explicit `HEIMDALL_HOME` only. A release build
/// never reads the variable.
#[cfg(debug_assertions)]
pub(crate) const TEST_MGMT_STORE_ENV: &str = "HEIMDALL_TEST_MGMT_STORE";

/// The fixture store prefix of [`TEST_MGMT_STORE_ENV`].
#[cfg(debug_assertions)]
const FIXTURE_FILE_PREFIX: &str = "fixture-file:";

/// This installation's K_mgmt store (module docs). `environment` scopes the item.
fn mgmt_store(ctx: &Ctx, environment: &EnvironmentId) -> Result<Box<dyn MgmtKeyStore>, OpError> {
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
    let db = paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    let store = heimdall_store::Store::open(&db, Arc::new(heimdall_store::NoFaults))
        .map_err(|_| state_refusal("the state database cannot be opened"))?;
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
            fingerprint,
        } => format!(
            "Retire this device: revoke it on {} runner(s), then destroy its management key {}.\nThe key cannot be recovered; this device can only rejoin by a new invitation or bootstrap.\nType yes to continue: ",
            environments.len(),
            fingerprint.as_str()
        ),
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
    /// A private directory for per-session configuration and agent sockets.
    root: PathBuf,
    key: Arc<StoreKey>,
}

type SessionStream = tokio::io::Join<tokio::process::ChildStdout, tokio::process::ChildStdin>;

/// One open management session; its scratch directory is removed when it ends.
struct SshSession {
    client: heimdall_ipc::session::ControlClient<SessionStream>,
    hello: SessionHello,
    _child: tokio::process::Child,
    agent: Option<SessionAgent>,
    dir: PathBuf,
    /// What the confirming probes run with: the session's own client, configuration and
    /// alias (so its key, pins and route).
    ssh_client: PathBuf,
    config_file: PathBuf,
    alias: String,
}

impl Drop for SshSession {
    fn drop(&mut self) {
        drop(self.agent.take());
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
            let disposable = env_ssh::DisposableAgent::start(&self.dir.join("p.sock")).ok()?;
            env_ssh::run_probes(
                &self.ssh_client,
                &self.config_file,
                &self.alias,
                &disposable,
            )
            .await
        }
        #[cfg(not(unix))]
        {
            // No management session opens on this platform (`SshSessions::open`).
            let _ = (&self.ssh_client, &self.config_file, &self.alias);
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
        env_ssh::PreflightVerdict::Unreachable => OpError::new(
            Code::DestinationUnreachable,
            "the runner could not be reached for a management session",
        ),
    }
    .with_effect(EffectStatus::None)
}

impl SshSessions {
    fn session_dir(&self) -> Result<PathBuf, OpError> {
        let mut bytes = [0u8; 6];
        heimdall_credential::vault::SystemRng::fill(&mut bytes).map_err(|_| {
            OpError::new(
                Code::InternalError,
                "operating system randomness unavailable",
            )
        })?;
        let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let dir = self.root.join(name);
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&dir).map_err(|_| {
            OpError::new(
                Code::StateUnavailable,
                "the management session directory could not be created",
            )
        })?;
        Ok(dir)
    }
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
        .map_err(|_| {
            OpError::new(
                Code::StateUnavailable,
                "a management session file could not be written",
            )
        })
}

fn render_refused(_e: heimdall_sshconf::render::RenderError) -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "the management configuration cannot be rendered for this runner's recorded route",
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
        if !cfg!(unix) {
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
        let ssh_client = self
            .ssh_client
            .clone()
            .ok_or_else(|| OpError::new(Code::LaunchFailed, "no OpenSSH client was found"))?;
        let store = self.key.store().map_err(MgmtKeyUnavailable::to_error)?;
        let key = store.load().map_err(|e| unavailable(e).to_error())?;
        let public = key
            .public()
            .map_err(|_| MgmtKeyUnavailable::Failed.to_error())?;
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
        let socket = dir.join("a.sock");
        let pub_file = dir.join("k_mgmt.pub");
        let pins_file = dir.join("known_hosts");
        let config_file = dir.join("mgmt.conf");
        let path = |p: &Path| RenderPath::absolute(p, PathStyle::Unix).map_err(render_refused);
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
                    identity: HopIdentity::new(path(&socket)?, path(&pub_file)?)
                        .map_err(render_refused)?,
                },
                jump: None,
            })
        })()
        .map_err(cleanup)?;
        let config = render_mgmt_config(
            &mgmt_target,
            &path(&pins_file).map_err(cleanup)?,
            PathStyle::Unix,
        )
        .map_err(render_refused)
        .map_err(cleanup)?;
        let pins = render_mgmt_pin_file(&mgmt_target)
            .map_err(render_refused)
            .map_err(cleanup)?;
        write_private(&pub_file, format!("{}\n", public.openssh_line).as_bytes())
            .map_err(cleanup)?;
        write_private(&pins_file, &pins).map_err(cleanup)?;
        write_private(&config_file, &config).map_err(cleanup)?;
        let signer = MgmtSigner::with_host_key_lines(
            key,
            [runner.account.as_str().to_owned()],
            &runner.host_keys,
        )
        .map_err(|_| cleanup(MgmtKeyUnavailable::Failed.to_error()))?;
        let agent = SessionAgent::start(&socket, signer).map_err(|_| {
            cleanup(OpError::new(
                Code::StateUnavailable,
                "the management key agent could not be started",
            ))
        })?;
        let alias = mgmt_target.alias();
        let args = env_ssh::management_args(&config_file, &alias);
        let child = env_ssh::spawn_management(&ssh_client, &args).map_err(cleanup)?;
        let env_ssh::ManagementChild {
            child,
            stdin,
            stdout,
            stderr,
        } = child;
        // ⟨M06 W3⟩ `remote-control/1` is required; `runner/1` is offered and not required:
        // the runner negotiates it for an owner session only (ADR-0006 §18.7, ruling Q3), so
        // a limited role's session still opens, without it.
        let required: BTreeSet<String> =
            [heimdall_app::remote_env::MANAGEMENT_CAPABILITY.to_owned()].into();
        let mut capabilities = heimdall_ipc::session::server_capabilities();
        capabilities.extend(required.iter().cloned());
        capabilities.insert(heimdall_contract::ipc::capability::RUNNER_V1.to_owned());
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
                    capabilities,
                    required,
                    interaction: InteractionMode::NonInteractive,
                    remote_client: None,
                },
            ),
        )
        .await;
        let client = match handshake {
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
                return Err(cleanup(session_error(&kept)));
            }
            Err(_) => {
                return Err(cleanup(OpError::new(
                    Code::DestinationUnreachable,
                    "the runner did not answer the management hello in time",
                )));
            }
        };
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
            dir,
            ssh_client,
            config_file,
            alias,
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
    let db = paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    let writes = if write {
        Some(record_writes(ctx, &paths).await?)
    } else {
        None
    };
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
            config: None,
            extra_options: Vec::new(),
            // ⟨M06 W3⟩ The runner trusts this controller's CA and designates it as the time
            // source in the bootstrap's confirmation (omitted without an issuer).
            issuer_ca: controller_issuer_ca(&db),
            // ⟨ADR-0006 §18.7 item 8⟩ This device's endpoint ID when its verified store
            // holds K_iroh: the runner admits the bootstrap owner over Iroh with it.
            iroh_endpoint: own_iroh_endpoint(ctx),
        },
        sessions: SshSessions {
            ssh_client: ssh,
            root,
            key,
        },
        confirm: TerminalConfirm {
            interactive: ctx.interactive(),
        },
    })
}

fn now() -> heimdall_contract::Timestamp {
    heimdall_contract::Timestamp::now()
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

/// `environment …`.
pub(crate) fn environment(ctx: &Ctx, command: EnvironmentCommand) -> ExitCode {
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
                    InviteOutcome::Pending {
                        decision_ref,
                        request_id,
                    } => Err(OpError::new(
                        Code::ApprovalRequired,
                        format!(
                            "the runner holds the invitation for its local confirmation: confirm \
                             decision {decision_ref} at the runner, then run this command again \
                             with --request-id {}",
                            request_id.as_str()
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
                controller.remove(&environment).await?;
                Ok((
                    serde_json::json!({ "removed": environment.as_str() }),
                    format!("removed {} (this device's management key is kept)", environment.as_str()),
                ))
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
                let data = serde_json::to_value(&report).unwrap_or_default();
                Ok((data, human))
            }
        }
    });
    match result {
        Ok((data, human)) => emit_ok(ctx, data, &human),
        Err(e) => emit_error(ctx, e),
    }
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
    let db = paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    let Ok(state) = heimdall_store::Store::open_read_only(&db, Arc::new(heimdall_store::NoFaults))
    else {
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
    let db = ctx
        .paths()
        .ok()?
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    let state =
        heimdall_store::Store::open_read_only(&db, Arc::new(heimdall_store::NoFaults)).ok()?;
    let environment = state.transaction(|tx| tx.self_environment()).ok()??;
    let keys = heimdall_runtime::supervise_transport::product_iroh_store(&environment);
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
        let db = paths
            .state_dir
            .join(heimdall_runtime::service::STATE_DB_FILE);
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
            let human = format!(
                "retired: revoked on {} runner(s); management key destroyed",
                outcome.revoked_on.len()
            );
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
        return remote_init_through_runtime(ctx, &plan, &user_dir, &confirm, &not_confirmed);
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
    Ok(Ok(init_answer(&mut data, issuer_data, &user_dir)))
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
    Ok(paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE))
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
            // No runtime: the direct write, holding the lock.
            let db = paths
                .state_dir
                .join(heimdall_runtime::service::STATE_DB_FILE);
            let store = match heimdall_store::Store::open(&db, Arc::new(heimdall_store::NoFaults)) {
                Ok(s) => s,
                Err(_) => return refusal(state_refusal("the state database cannot be opened")),
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
    use heimdall_runtime::paired::{ClockReading, recheck_view};
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
    let reading = ClockReading::of(&heimdall_runtime::platform::SystemClock);
    let view = match runner_read(ctx, |tx| recheck_view(tx, &reading)) {
        Ok(v) => v,
        Err(e) => return emit_error(ctx, e),
    };
    let Some(downgrade) = &view.downgrade else {
        return emit_ok(
            ctx,
            serde_json::json!({ "downgraded": false, "lifted": false }),
            "this runner is not downgraded: there is nothing to lift",
        );
    };
    if let Err(refusal) = view.verdict {
        return emit_error(ctx, refusal.to_error());
    }
    let (Some(evidence), Some(controller)) = (&view.evidence, &view.controller) else {
        return emit_error(
            ctx,
            heimdall_runtime::paired::LiftRefusal::NoEvidence.to_error(),
        );
    };
    let text = policy_recheck_confirmation(downgrade, evidence, &controller.key_fingerprint);
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
        let db = paired::state_db_of_home(dir.path());

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
                &paired::state_db_of_home(&home),
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

    /// ⟨M06 W3⟩ The M06 route and transport commands are wired (no "planned for M06"
    /// refusal): each line parses into its typed arguments; malformed inputs are refused as
    /// usage errors before any runtime contact, without creating the Heimdall home; the
    /// hidden helper and serve child refuse anything but their own arguments; clap refuses
    /// a zero `--port`, a `--port` without `--serve`, and a route with no or two kinds.
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
            &paths
                .state_dir
                .join(heimdall_runtime::service::STATE_DB_FILE),
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
                &paths
                    .state_dir
                    .join(heimdall_runtime::service::STATE_DB_FILE),
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
            fingerprint: fp.clone(),
        });
        assert!(retire.contains("destroy") && retire.contains("1 runner"));
        assert!(
            !TerminalConfirm { interactive: false }.confirm(&Confirmation::RetireDevice {
                environments: vec![env],
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
