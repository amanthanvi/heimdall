//! ⟨M06 U2⟩ The controller's management of remote runner environments (ADR-0012 §3.1–§3.4,
//! §3.9–§3.11, §5.2; ADR-0006 §18 revision 6: `remote_environment
//! add|invite|join|revoke_client|remove|update|status` and `device retire`; m06-plan U2).
//!
//! **What the controller is.** It holds K_mgmt (one per device, `heimdall_credential::mgmt`)
//! and a record per paired runner ([`RemoteEnvironmentRecord`]: the environment ID, the
//! catalog destination and account that reach it, its pinned host keys and this device's
//! client there). It decides nothing on a runner: every authority decision is the runner's,
//! and every widening is confirmed runner-locally (ADR-0012 §3.10).
//!
//! * **`add`** ([`RemoteEnvController::add`], ADR-0012 §3.3): bootstrap over the owner's
//!   **existing, independently host-verified access** to the runner account. The host keys
//!   come from the catalog pin ([`AccessCatalog`]); a destination with none is refused
//!   (`host_trust_undetermined`) before anything runs, and nothing here can scan for a key
//!   (no port offers it; `ssh-keyscan` is never run). The [`BootstrapRunner`] runs one
//!   interactive ssh session with a TTY, verified against those pins, in which the runner's
//!   `heimdall remote init` creates the environment and the owner confirms, **at the
//!   runner**, the enrollment of this device's K_mgmt as `owner`. The controller then opens
//!   a management session under the isolated configuration with the same pins, reads the
//!   environment ID from the runner's hello, and records it. The same path repairs a lost
//!   host pin or a lost K_mgmt.
//! * **`invite`** (§3.9): carries the receiving device's public key; the owner first
//!   confirms its fingerprint locally ([`LocalConfirm`]). Creating an invitation is a
//!   widening action, so the runner answers `APPROVAL_REQUIRED` with its own
//!   `decision_ref`, which the controller returns as is ([`InviteOutcome::Pending`]) with the
//!   request ID to replay; after the runner-local confirmation, the same request returns the
//!   recorded terminal result (T-RA3), from which the public [`InvitationBundle`] is built.
//! * **`join`** (§3.9 item 1): on the new device, the user confirms the runner's host-key
//!   fingerprint and environment ID from the bundle; the bundle's key fingerprint must be this
//!   device's K_mgmt; then the pending client's two permitted forms, the activation probe and
//!   `join`, are sent.
//! * **`revoke_client`**, **`remove`**, **`update`**: one management call each (narrowing,
//!   or the runner's own explicit update). `remove` revokes this device's client on that
//!   runner, then forgets the record; it never destroys K_mgmt.
//! * **`status`**: the controller's own view, read locally: it opens no session, so a
//!   locked K_mgmt store is reported (`mgmt_key_store_locked`) while the runners' work is
//!   untouched.
//! * **`retire`** (§3.4, §3.10 item 4): a locally attended decision; revokes this device's
//!   client on **every** runner, and only when every revocation succeeded destroys K_mgmt
//!   (a K_mgmt destroyed first could never finish the remaining revocations). Distinct from
//!   revoking one runner, which never destroys K_mgmt.
//! * **Rotation** is invite-then-revoke (§3.4): the new key is invited on each runner (a
//!   widening, confirmed there), joins, and the old client is then revoked. Nothing
//!   overwrites or exports a stored key.
//!
//! **The controller never decides over a management session.** [`ManagementCall`] can only
//! express the revision-6 management forms; it has no `Decide` or `Attend` form, and every
//! session is opened non-interactive, so a paired session is never attended (§3.10 item 1).
//!
//! **Ports.** K_mgmt custody ([`MgmtKeyPort`]), the controller's records
//! ([`EnvironmentRegistry`]: `remote_environment_pins`, whose store API does not exist yet;
//! DONE question U2-Q3), the catalog's verified access ([`AccessCatalog`]), the bootstrap
//! session ([`BootstrapRunner`]), management sessions ([`ManagementSessions`]: the isolated
//! `-F` configuration, the per-session K_mgmt agent and the IPC client over `ssh`'s standard
//! streams, wired by the CLI) and the owner's local confirmation ([`LocalConfirm`]).

use heimdall_contract::envelope::{Envelope, ErrorData, reason};
use heimdall_contract::ids::{
    AccountName, ClientId, DestinationId, EnvironmentId, InvitationId, KeyFingerprint, RequestId,
};
use heimdall_contract::remote::{DeviceRequest, RemoteEnvironmentRequest, Role};
use heimdall_contract::request::Request;
use heimdall_contract::{Code, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::OpError;

#[path = "remote_env_ssh.rs"]
pub mod ssh;

/// The capability every management session requires (ADR-0006 §18).
pub const MANAGEMENT_CAPABILITY: &str = heimdall_contract::ipc::capability::REMOTE_CONTROL_V1;

/// The largest number of pinned host keys a record or bundle carries.
pub const MAX_HOST_KEYS: usize = 16;

// --- records -----------------------------------------------------------------------------

/// One hop of a management route: where it is and the host keys pinned for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementHop {
    /// `HostName`.
    pub hostname: String,
    /// `Port`; 22 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The account.
    pub account: AccountName,
    /// The catalog-pinned host keys (OpenSSH public key lines, at least one).
    pub host_keys: Vec<String>,
}

/// The single jump hop of a management route (ADR-0012 §5.1 `jump{via}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementJump {
    /// The jump destination.
    pub destination: DestinationId,
    /// Its hop.
    pub hop: ManagementHop,
}

/// The route a management session takes to a runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementRoute {
    /// The runner hop.
    pub runner: ManagementHop,
    /// The single jump hop, when the approved route is a jump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump: Option<ManagementJump>,
}

/// The controller's record of one paired runner environment: the authoritative document of
/// a `remote_environment_pins` row (ADR-0012 §7.5: a changed host key or environment ID is
/// `held`, never silently re-pinned).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteEnvironmentRecord {
    /// The runner's environment ID, as its hello reported it.
    pub environment: EnvironmentId,
    /// The catalog destination that reaches it.
    pub destination: DestinationId,
    /// The route and pins.
    pub route: ManagementRoute,
    /// This device's client on that runner.
    pub client: ClientId,
    /// This device's role there.
    pub role: Role,
    /// The fingerprint of the K_mgmt enrolled there.
    pub key_fingerprint: KeyFingerprint,
    /// The owner's label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// When the record was written.
    pub pinned_at: Timestamp,
}

/// The public invitation bundle the owner hands to the new device (ADR-0012 §3.9 item 1).
/// Nothing in it is secret: it names the runner, its pinned host keys, the invitation and
/// the receiving key's fingerprint, and grants nothing by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationBundle {
    /// The runner environment.
    pub environment: EnvironmentId,
    /// The route (from the inviting controller's record).
    pub route: ManagementRoute,
    /// The destination ID the inviting controller uses for the runner.
    pub destination: DestinationId,
    /// The invitation.
    pub invitation: InvitationId,
    /// The client the runner minted for the new device.
    pub client: ClientId,
    /// The role.
    pub role: Role,
    /// The invitation's generation.
    pub generation: u64,
    /// The receiving key's fingerprint, as the owner confirmed it.
    pub key_fingerprint: KeyFingerprint,
    /// The pending record's activation nonce, when the runner returned one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

// --- ports -------------------------------------------------------------------------------

/// The public half of this device's K_mgmt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MgmtKeyInfo {
    /// The OpenSSH public key line.
    pub openssh_line: String,
    /// `SHA256:…`.
    pub fingerprint: KeyFingerprint,
}

/// Why K_mgmt is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtKeyUnavailable {
    /// The store is locked, or would need interaction: `mgmt_key_store_locked`.
    Locked,
    /// No verified persistent store on this host, or the store is absent or corrupt.
    StoreUnavailable,
    /// No K_mgmt exists on this device.
    NotFound,
    /// The store refused for another reason.
    Failed,
}

impl MgmtKeyUnavailable {
    /// The refusal.
    #[must_use]
    pub fn to_error(self) -> OpError {
        match self {
            MgmtKeyUnavailable::Locked => OpError::new(
                Code::CapabilityUnavailable,
                "the management key store is locked: management connections are unavailable \
                 until it is unlocked; the runners' work continues",
            )
            .with_reason(reason::MGMT_KEY_STORE_LOCKED),
            MgmtKeyUnavailable::StoreUnavailable => OpError::new(
                Code::CapabilityUnavailable,
                "no verified persistent key store for the management key on this device \
                 (desktop controllers only); the runners' work continues",
            )
            .with_reason(reason::MGMT_KEY_STORE_UNAVAILABLE),
            MgmtKeyUnavailable::NotFound => {
                OpError::new(Code::NotFound, "this device holds no management key")
            }
            MgmtKeyUnavailable::Failed => OpError::new(
                Code::ServiceUnavailable,
                "the management key store refused the operation",
            ),
        }
    }
}

/// K_mgmt custody, as the controller operations see it (implemented over
/// `heimdall_credential::mgmt::MgmtKeyStore`).
pub trait MgmtKeyPort: Send + Sync {
    /// Whether K_mgmt can be used now, read without interaction.
    ///
    /// # Errors
    /// [`MgmtKeyUnavailable`].
    fn check(&self) -> Result<(), MgmtKeyUnavailable>;

    /// This device's K_mgmt public half; generated and stored first when `create` and none
    /// exists.
    ///
    /// # Errors
    /// [`MgmtKeyUnavailable`].
    fn public_key(&self, create: bool) -> Result<MgmtKeyInfo, MgmtKeyUnavailable>;

    /// Destroy this device's K_mgmt (device retirement only).
    ///
    /// # Errors
    /// [`MgmtKeyUnavailable`].
    fn destroy(&self) -> Result<(), MgmtKeyUnavailable>;

    /// The OpenSSH SHA-256 fingerprint of one public key line (public data; `None` for a
    /// line that is not one public key). The crypto stays in `heimdall-credential`.
    fn fingerprint_of(&self, openssh_line: &str) -> Option<KeyFingerprint>;
}

/// The controller's records (`remote_environment_pins`).
pub trait EnvironmentRegistry: Send + Sync {
    /// Every record, by environment ID.
    ///
    /// # Errors
    /// [`OpError`] (`STATE_UNAVAILABLE`, or `driver_unavailable` where no store API exists).
    fn list(&self) -> Result<Vec<RemoteEnvironmentRecord>, OpError>;

    /// Insert or replace the record of its environment.
    ///
    /// # Errors
    /// [`OpError`].
    fn put(&self, record: &RemoteEnvironmentRecord) -> Result<(), OpError>;

    /// Remove the record of `environment`; `false` when there was none.
    ///
    /// # Errors
    /// [`OpError`].
    fn remove(&self, environment: &EnvironmentId) -> Result<bool, OpError>;
}

/// The owner's existing, independently host-verified access to a runner account
/// (ADR-0012 §3.3), as the catalog records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAccess {
    /// The catalog destination.
    pub destination: DestinationId,
    /// The OpenSSH alias of the existing access (the owner's own configuration and
    /// identity authenticate the bootstrap session).
    pub alias: String,
    /// The route, with the catalog-pinned host keys.
    pub route: ManagementRoute,
}

/// The catalog's view of verified access.
pub trait AccessCatalog: Send + Sync {
    /// The verified access to `account` at `destination`; `None` when the destination is not
    /// in the catalog. Host keys are the catalog pin only, never a scanned key.
    ///
    /// # Errors
    /// [`OpError`].
    fn verified_access(
        &self,
        destination: &DestinationId,
        account: &AccountName,
    ) -> Result<Option<VerifiedAccess>, OpError>;
}

/// What the bootstrap session runs (ADR-0012 §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapPlan {
    /// The verified access it runs over.
    pub access: VerifiedAccess,
    /// The runner's Heimdall executable (absolute, on the runner).
    pub runner_program: String,
    /// The runner's Heimdall home (absolute, on the runner), when not its default.
    pub runner_home: Option<String>,
    /// The expected SHA-256 of the runner's executable (the checksum step).
    pub runner_sha256: Option<String>,
    /// The K_mgmt public key to enroll as `owner`.
    pub owner_key: MgmtKeyInfo,
    /// The client ID the runner records for this device.
    pub owner_client: ClientId,
}

/// The bootstrap session: one interactive ssh session with a TTY over the verified access,
/// in which the runner-local confirmation happens.
#[async_trait::async_trait]
pub trait BootstrapRunner: Send + Sync {
    /// Run it. `Ok` only when the session exited 0.
    ///
    /// # Errors
    /// [`OpError`]: a host-key verification failure is `HOST_TRUST_CHANGED`; any other
    /// failure leaves nothing recorded on the controller.
    async fn run(&self, plan: &BootstrapPlan) -> Result<(), OpError>;
}

/// The name a management session's runner hop is rendered under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionName {
    /// A recorded environment: `hm-env-<id>`.
    Environment(EnvironmentId),
    /// The first session after a bootstrap, before the environment ID is known: rendered
    /// under the destination's name, with the same catalog pins.
    Bootstrap(DestinationId),
}

/// Where a management session goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTarget {
    /// The runner hop's name.
    pub name: SessionName,
    /// The route and pins.
    pub route: ManagementRoute,
}

/// What the runner's hello reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHello {
    /// The runner's environment ID.
    pub environment: EnvironmentId,
    /// The role the session was negotiated for, when reported.
    pub role: Option<Role>,
    /// ⟨rev6.2⟩ The client the runner bound the session to, when reported.
    pub client: Option<ClientId>,
}

/// A request a management session may carry: the revision-6 management forms only. There
/// is no `Decide` and no `Attend` form, so the controller can never decide on a runner
/// (ADR-0012 §3.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagementCall {
    /// A `remote_environment` form.
    Environment(RemoteEnvironmentRequest),
}

impl ManagementCall {
    /// The request sent.
    #[must_use]
    pub fn into_request(self) -> Request {
        match self {
            ManagementCall::Environment(r) => Request::RemoteEnvironment(r),
        }
    }
}

/// One open management session (non-interactive, never attended).
#[async_trait::async_trait]
pub trait ManagementSession: Send {
    /// The runner's hello.
    fn hello(&self) -> &SessionHello;

    /// Send one call and read its response envelope.
    ///
    /// # Errors
    /// [`OpError`] for a transport failure (the request may have been sent:
    /// `OUTCOME_UNKNOWN`).
    async fn call(&mut self, call: ManagementCall) -> Result<Envelope<serde_json::Value>, OpError>;
}

/// Opens management sessions (the isolated `-F` configuration, K_mgmt's per-session agent,
/// `ssh`'s standard streams).
#[async_trait::async_trait]
pub trait ManagementSessions: Send + Sync {
    /// Open a session to `target`.
    ///
    /// # Errors
    /// [`OpError`]: K_mgmt unavailable, host-key verification failure (`HOST_TRUST_CHANGED`),
    /// refused authentication, or a refused hello.
    async fn open(&self, target: &SessionTarget) -> Result<Box<dyn ManagementSession>, OpError>;
}

/// What the owner is asked to confirm locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmation {
    /// `invite`: the receiving key's fingerprint matches the new device's display.
    InviteKey {
        /// The runner environment.
        environment: EnvironmentId,
        /// The role.
        role: Role,
        /// The receiving key's fingerprint.
        fingerprint: KeyFingerprint,
    },
    /// `join`: the runner's host-key fingerprints and environment ID match the owner's
    /// controller display.
    JoinRunner {
        /// The runner environment.
        environment: EnvironmentId,
        /// The pinned host keys' fingerprints.
        host_fingerprints: Vec<String>,
        /// The role offered.
        role: Role,
    },
    /// `device retire`: revoke this device on every listed runner, then destroy K_mgmt.
    RetireDevice {
        /// The environments this device is enrolled on.
        environments: Vec<EnvironmentId>,
        /// K_mgmt's fingerprint.
        fingerprint: KeyFingerprint,
    },
}

/// The owner's local attended confirmation: a typed `yes` on this device's own terminal.
/// A non-interactive or non-terminal caller never confirms.
pub trait LocalConfirm: Send + Sync {
    /// Whether the owner confirmed.
    fn confirm(&self, what: &Confirmation) -> bool;
}

/// The ports of [`RemoteEnvController`].
pub struct ControllerPorts<'a> {
    /// K_mgmt custody.
    pub key: &'a dyn MgmtKeyPort,
    /// The controller's records.
    pub registry: &'a dyn EnvironmentRegistry,
    /// The catalog's verified access.
    pub catalog: &'a dyn AccessCatalog,
    /// The bootstrap session.
    pub bootstrap: &'a dyn BootstrapRunner,
    /// Management sessions.
    pub sessions: &'a dyn ManagementSessions,
    /// The owner's local confirmation.
    pub confirm: &'a dyn LocalConfirm,
    /// The wall clock, for `pinned_at` only (no authority decision reads it).
    pub now: Timestamp,
}

// --- inputs and outcomes -----------------------------------------------------------------

/// `add`'s input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddInput {
    /// The catalog destination.
    pub destination: DestinationId,
    /// The runner account.
    pub account: AccountName,
    /// The owner's label.
    pub label: Option<String>,
    /// The runner's Heimdall executable (absolute).
    pub runner_program: String,
    /// The runner's Heimdall home (absolute), when not its default.
    pub runner_home: Option<String>,
    /// The expected SHA-256 of the runner's Heimdall executable (64 lowercase hex): the
    /// bootstrap's checksum step, checked by `remote init` before anything is written.
    pub runner_sha256: Option<String>,
}

/// `invite`'s input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteInput {
    /// The runner environment.
    pub environment: EnvironmentId,
    /// The role offered.
    pub role: Role,
    /// The receiving key (one OpenSSH public key line).
    pub public_key: String,
    /// Its fingerprint, computed by the caller from `public_key`.
    pub key_fingerprint: KeyFingerprint,
    /// The idempotency key: reuse it to read the runner's terminal result after its local
    /// confirmation.
    pub request_id: RequestId,
}

/// `invite`'s outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteOutcome {
    /// The runner recorded a pending runner-local decision: confirm it at the runner, then
    /// repeat the request with the same `request_id`.
    Pending {
        /// The runner's decision reference.
        decision_ref: String,
        /// The request ID to replay.
        request_id: RequestId,
    },
    /// The invitation exists: hand the bundle to the new device.
    Created(Box<InvitationBundle>),
}

/// `status`' per-environment line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvironmentStatus {
    /// The record.
    #[serde(flatten)]
    pub record: RemoteEnvironmentRecord,
}

/// `status`' report: the controller's own view (no session is opened).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusReport {
    /// Whether management connections are possible now: `available`, or the refusal
    /// reason (`mgmt_key_store_locked`, …). The runners' work never depends on it.
    pub management: String,
    /// The environments.
    pub environments: Vec<EnvironmentStatus>,
}

/// `retire`'s outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetireOutcome {
    /// The environments on which this device's client was revoked.
    pub revoked_on: Vec<EnvironmentId>,
    /// Whether K_mgmt was destroyed (only after every revocation succeeded).
    pub key_destroyed: bool,
}

// --- the controller ------------------------------------------------------------------------

/// The controller's environment management (module docs).
pub struct RemoteEnvController<'a> {
    ports: ControllerPorts<'a>,
}

fn refuse(code: Code, message: &str, why: &str) -> OpError {
    OpError::new(code, message).with_reason(why)
}

/// Map a runner's response: `OK` is its data; `APPROVAL_REQUIRED` or `INTERACTION_REQUIRED`
/// carrying the runner's `decision_ref` is returned as that refusal with the reference
/// unchanged (the controller never decides); any other error is the runner's error detail.
///
/// # Errors
/// [`OpError`].
pub fn runner_result(envelope: Envelope<serde_json::Value>) -> Result<serde_json::Value, OpError> {
    if envelope.code == Code::Ok {
        return Ok(envelope.data);
    }
    let decision_ref = envelope.next.as_ref().and_then(|n| n.decision_ref.clone());
    if matches!(
        envelope.code,
        Code::ApprovalRequired | Code::InteractionRequired
    ) && let Some(decision_ref) = decision_ref
    {
        return Err(OpError::new(
            envelope.code,
            "the runner recorded a pending decision: confirm it at the runner (its own CLI or \
             TUI, or an interactive ssh session with a terminal), then repeat the request with \
             the same request ID",
        )
        .with_decision(decision_ref));
    }
    let operation_id = envelope.operation_id.clone();
    match serde_json::from_value::<ErrorData>(envelope.data) {
        Ok(data) => Err(OpError::from_detail(data.error, operation_id)),
        Err(_) => Err(OpError::new(
            Code::OutcomeUnknown,
            "the runner's response could not be read",
        )),
    }
}

/// Check a route's pins: every hop has 1 to [`MAX_HOST_KEYS`] key lines.
fn check_pins(route: &ManagementRoute) -> Result<(), OpError> {
    let hop_ok =
        |hop: &ManagementHop| !hop.host_keys.is_empty() && hop.host_keys.len() <= MAX_HOST_KEYS;
    let jump_ok = route.jump.as_ref().is_none_or(|j| hop_ok(&j.hop));
    if hop_ok(&route.runner) && jump_ok {
        Ok(())
    } else {
        Err(refuse(
            Code::CapabilityUnavailable,
            "the destination has no catalog-pinned host key: bootstrap runs only over \
             independently host-verified access (a key is never scanned)",
            reason::HOST_TRUST_UNDETERMINED,
        ))
    }
}

impl<'a> RemoteEnvController<'a> {
    /// A controller over `ports`.
    #[must_use]
    pub fn new(ports: ControllerPorts<'a>) -> Self {
        Self { ports }
    }

    fn fingerprint(&self, line: &str) -> Result<KeyFingerprint, OpError> {
        self.ports
            .key
            .fingerprint_of(line)
            .ok_or_else(|| OpError::new(Code::UsageError, "not an OpenSSH public key line"))
    }

    fn record(&self, environment: &EnvironmentId) -> Result<RemoteEnvironmentRecord, OpError> {
        self.ports
            .registry
            .list()?
            .into_iter()
            .find(|r| r.environment == *environment)
            .ok_or_else(|| {
                OpError::new(
                    Code::NotFound,
                    "no remote environment with that ID is recorded on this controller",
                )
                .with_resource("environment", Some(environment.as_str().to_owned()))
            })
    }

    /// K_mgmt must be usable before any session opens; a locked store refuses with
    /// `mgmt_key_store_locked` and nothing is sent.
    fn key_ready(&self) -> Result<MgmtKeyInfo, OpError> {
        self.ports
            .key
            .check()
            .map_err(MgmtKeyUnavailable::to_error)?;
        self.ports
            .key
            .public_key(false)
            .map_err(MgmtKeyUnavailable::to_error)
    }

    async fn open_recorded(
        &self,
        record: &RemoteEnvironmentRecord,
    ) -> Result<Box<dyn ManagementSession>, OpError> {
        let session = self
            .ports
            .sessions
            .open(&SessionTarget {
                name: SessionName::Environment(record.environment.clone()),
                route: record.route.clone(),
            })
            .await?;
        if session.hello().environment != record.environment {
            return Err(refuse(
                Code::CapabilityUnavailable,
                "the runner's environment ID does not match this controller's pin: held, \
                 nothing sent (re-pin only through independently host-verified access)",
                reason::ENVIRONMENT_IDENTITY_MISMATCH,
            ));
        }
        if session
            .hello()
            .client
            .as_ref()
            .is_some_and(|c| *c != record.client)
        {
            return Err(refuse(
                Code::CapabilityUnavailable,
                "the runner bound this session to another client than this controller's \
                 record: held, nothing sent (repair with `environment add`)",
                reason::ENVIRONMENT_IDENTITY_MISMATCH,
            ));
        }
        Ok(session)
    }

    async fn call_recorded(
        &self,
        environment: &EnvironmentId,
        call: ManagementCall,
    ) -> Result<serde_json::Value, OpError> {
        let record = self.record(environment)?;
        self.key_ready()?;
        let mut session = self.open_recorded(&record).await?;
        runner_result(session.call(call).await?)
    }

    /// `environment add` (module docs; ADR-0012 §3.3).
    ///
    /// # Errors
    /// [`OpError`]: an unverified host key (`host_trust_undetermined`), a locked K_mgmt store
    /// (`mgmt_key_store_locked`), a failed bootstrap, a runner that does not report the owner
    /// role, or an environment ID already recorded for another destination.
    pub async fn add(&self, input: &AddInput) -> Result<RemoteEnvironmentRecord, OpError> {
        let access = self
            .ports
            .catalog
            .verified_access(&input.destination, &input.account)?
            .ok_or_else(|| {
                OpError::new(Code::NotFound, "no such destination in the catalog")
                    .with_resource("destination", Some(input.destination.as_str().to_owned()))
            })?;
        check_pins(&access.route)?;
        if access.route.runner.account != input.account {
            return Err(OpError::new(
                Code::UsageError,
                "the catalog's access is for another account",
            ));
        }
        // The records are read before K_mgmt is touched: an unreadable registry refuses
        // with nothing created. A repair keeps this device's client on that runner; a first
        // add mints one.
        let existing = self.ports.registry.list()?.into_iter().find(|r| {
            r.destination == input.destination && r.route.runner.account == input.account
        });
        self.ports
            .key
            .check()
            .map_err(MgmtKeyUnavailable::to_error)?;
        let owner_key = self
            .ports
            .key
            .public_key(true)
            .map_err(MgmtKeyUnavailable::to_error)?;
        let owner_client = match &existing {
            Some(r) => r.client.clone(),
            None => new_client_id()?,
        };
        let plan = BootstrapPlan {
            access: access.clone(),
            runner_program: input.runner_program.clone(),
            runner_home: input.runner_home.clone(),
            runner_sha256: input.runner_sha256.clone(),
            owner_key: owner_key.clone(),
            owner_client: owner_client.clone(),
        };
        self.ports.bootstrap.run(&plan).await?;
        let session = self
            .ports
            .sessions
            .open(&SessionTarget {
                name: SessionName::Bootstrap(input.destination.clone()),
                route: access.route.clone(),
            })
            .await?;
        let hello = session.hello().clone();
        drop(session);
        if hello.role.is_some_and(|r| r != Role::Owner) {
            return Err(refuse(
                Code::CapabilityUnavailable,
                "the runner did not enroll this device as owner",
                reason::ROLE_INSUFFICIENT,
            ));
        }
        if let Some(previous) = &existing
            && previous.environment != hello.environment
        {
            return Err(refuse(
                Code::CapabilityUnavailable,
                "the runner reports a different environment ID than this controller's record: \
                 held (remove the old record first if the runner was re-initialized)",
                reason::ENVIRONMENT_IDENTITY_MISMATCH,
            ));
        }
        if let Some(other) = self
            .ports
            .registry
            .list()?
            .into_iter()
            .find(|r| r.environment == hello.environment && r.destination != input.destination)
        {
            let _ = other;
            return Err(refuse(
                Code::CapabilityUnavailable,
                "that environment is already recorded through another destination",
                reason::ENVIRONMENT_IDENTITY_MISMATCH,
            ));
        }
        // ⟨rev6.2⟩ The client the runner bound the session to wins: a retried bootstrap of the
        // same key keeps the client the runner enrolled first.
        let client = hello.client.clone().unwrap_or(owner_client);
        let record = RemoteEnvironmentRecord {
            environment: hello.environment,
            destination: input.destination.clone(),
            route: access.route,
            client,
            role: Role::Owner,
            key_fingerprint: owner_key.fingerprint,
            label: input.label.clone(),
            pinned_at: self.ports.now,
        };
        self.ports.registry.put(&record)?;
        Ok(record)
    }

    /// `environment invite` (module docs; ADR-0012 §3.9).
    ///
    /// # Errors
    /// [`OpError`]: the owner did not confirm the fingerprint (`INTERACTION_REQUIRED`), a
    /// fingerprint that does not match the key (`USAGE_ERROR`), a locked K_mgmt store, or the
    /// runner's refusal.
    pub async fn invite(&self, input: &InviteInput) -> Result<InviteOutcome, OpError> {
        let record = self.record(&input.environment)?;
        if self.fingerprint(&input.public_key)? != input.key_fingerprint {
            return Err(OpError::new(
                Code::UsageError,
                "the receiving key does not have that fingerprint",
            ));
        }
        // K_mgmt first: a locked store refuses before the owner is asked anything.
        self.key_ready()?;
        let confirmed = self.ports.confirm.confirm(&Confirmation::InviteKey {
            environment: input.environment.clone(),
            role: input.role,
            fingerprint: input.key_fingerprint.clone(),
        });
        if !confirmed {
            return Err(OpError::new(
                Code::InteractionRequired,
                "the receiving key's fingerprint was not confirmed: nothing was sent",
            ));
        }
        let mut session = self.open_recorded(&record).await?;
        let response = session
            .call(ManagementCall::Environment(
                RemoteEnvironmentRequest::Invite {
                    environment: input.environment.clone(),
                    role: input.role,
                    key_fingerprint: input.key_fingerprint.clone(),
                    public_key: input.public_key.clone(),
                    request_id: input.request_id.clone(),
                },
            ))
            .await?;
        match runner_result(response) {
            Ok(data) => {
                let created: InviteCreated = serde_json::from_value(data).map_err(|_| {
                    OpError::new(
                        Code::OutcomeUnknown,
                        "the runner's invitation result could not be read",
                    )
                })?;
                Ok(InviteOutcome::Created(Box::new(InvitationBundle {
                    environment: record.environment.clone(),
                    route: record.route.clone(),
                    destination: record.destination.clone(),
                    invitation: created.invitation,
                    client: created.client,
                    role: input.role,
                    generation: created.generation,
                    key_fingerprint: input.key_fingerprint.clone(),
                    nonce: created.nonce,
                })))
            }
            Err(e) if e.code == Code::ApprovalRequired && e.next.decision_ref.is_some() => {
                Ok(InviteOutcome::Pending {
                    decision_ref: e.next.decision_ref.unwrap_or_default(),
                    request_id: input.request_id.clone(),
                })
            }
            Err(e) => Err(e),
        }
    }

    /// `environment join` on the new device (module docs; ADR-0012 §3.9).
    ///
    /// # Errors
    /// [`OpError`]: the user did not confirm the runner (`INTERACTION_REQUIRED`), the bundle
    /// names another key, an environment ID mismatch, or the runner's refusal.
    pub async fn join(
        &self,
        bundle: &InvitationBundle,
    ) -> Result<RemoteEnvironmentRecord, OpError> {
        check_pins(&bundle.route)?;
        let host_fingerprints = bundle
            .route
            .runner
            .host_keys
            .iter()
            .map(|k| self.fingerprint(k).map(|f| f.as_str().to_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        // K_mgmt first: a locked store, or a bundle for another key, refuses before the user
        // is asked anything.
        let key = self.key_ready()?;
        if key.fingerprint != bundle.key_fingerprint {
            return Err(OpError::new(
                Code::UsageError,
                "the invitation is for another key than this device's management key",
            ));
        }
        let confirmed = self.ports.confirm.confirm(&Confirmation::JoinRunner {
            environment: bundle.environment.clone(),
            host_fingerprints,
            role: bundle.role,
        });
        if !confirmed {
            return Err(OpError::new(
                Code::InteractionRequired,
                "the runner's host key and environment ID were not confirmed: nothing was sent",
            ));
        }
        let mut session = self
            .ports
            .sessions
            .open(&SessionTarget {
                name: SessionName::Environment(bundle.environment.clone()),
                route: bundle.route.clone(),
            })
            .await?;
        let mismatched_client = session
            .hello()
            .client
            .as_ref()
            .is_some_and(|c| *c != bundle.client);
        if session.hello().environment != bundle.environment || mismatched_client {
            return Err(refuse(
                Code::CapabilityUnavailable,
                "the runner's environment ID or client does not match the invitation: \
                 nothing sent",
                reason::ENVIRONMENT_IDENTITY_MISMATCH,
            ));
        }
        if let Some(nonce) = &bundle.nonce {
            runner_result(
                session
                    .call(ManagementCall::Environment(
                        RemoteEnvironmentRequest::ActivationProbe {
                            environment: bundle.environment.clone(),
                            nonce: nonce.clone(),
                        },
                    ))
                    .await?,
            )?;
        }
        runner_result(
            session
                .call(ManagementCall::Environment(
                    RemoteEnvironmentRequest::Join {
                        environment: bundle.environment.clone(),
                        invitation: bundle.invitation.clone(),
                        role: bundle.role,
                        generation: bundle.generation,
                    },
                ))
                .await?,
        )?;
        let record = RemoteEnvironmentRecord {
            environment: bundle.environment.clone(),
            destination: bundle.destination.clone(),
            route: bundle.route.clone(),
            client: bundle.client.clone(),
            role: bundle.role,
            key_fingerprint: key.fingerprint,
            label: None,
            pinned_at: self.ports.now,
        };
        self.ports.registry.put(&record)?;
        Ok(record)
    }

    /// `environment revoke-client`: narrowing, no decision (ADR-0012 §3.11). Revoking one
    /// runner's client never touches K_mgmt.
    ///
    /// # Errors
    /// [`OpError`].
    pub async fn revoke_client(
        &self,
        environment: &EnvironmentId,
        client: &ClientId,
    ) -> Result<serde_json::Value, OpError> {
        self.call_recorded(
            environment,
            ManagementCall::Environment(RemoteEnvironmentRequest::RevokeClient {
                environment: environment.clone(),
                client: client.clone(),
            }),
        )
        .await
    }

    /// `environment remove`: revoke this device's client on that runner, then forget the
    /// record (pins included). K_mgmt is kept: it may serve other runners.
    ///
    /// # Errors
    /// [`OpError`]: the revocation failed (nothing is forgotten, so it can be retried).
    pub async fn remove(&self, environment: &EnvironmentId) -> Result<(), OpError> {
        let record = self.record(environment)?;
        self.revoke_client(environment, &record.client).await?;
        self.ports.registry.remove(environment)?;
        Ok(())
    }

    /// `environment update`: the runner's explicit, checksum-verified binary update
    /// (ADR-0012 §6.4), requested over the management session.
    ///
    /// # Errors
    /// [`OpError`].
    pub async fn update(&self, environment: &EnvironmentId) -> Result<serde_json::Value, OpError> {
        self.call_recorded(
            environment,
            ManagementCall::Environment(RemoteEnvironmentRequest::Update {
                environment: environment.clone(),
            }),
        )
        .await
    }

    /// `environment status`: the controller's own view (no session; module docs).
    ///
    /// # Errors
    /// [`OpError`]: the records cannot be read, or `environment` is not recorded.
    pub fn status(&self, environment: Option<&EnvironmentId>) -> Result<StatusReport, OpError> {
        let mut records = self.ports.registry.list()?;
        if let Some(env) = environment {
            records.retain(|r| r.environment == *env);
            if records.is_empty() {
                return Err(OpError::new(
                    Code::NotFound,
                    "no remote environment with that ID is recorded on this controller",
                ));
            }
        }
        records.sort_by(|a, b| a.environment.cmp(&b.environment));
        let management = match self.ports.key.check() {
            Ok(()) => "available".to_owned(),
            Err(e) => e
                .to_error()
                .reason
                .unwrap_or_else(|| "unavailable".to_owned()),
        };
        Ok(StatusReport {
            management,
            environments: records
                .into_iter()
                .map(|record| EnvironmentStatus { record })
                .collect(),
        })
    }

    /// `device retire` (module docs; ADR-0012 §3.4): a locally attended decision, then this
    /// device's client revoked on every recorded runner, then K_mgmt destroyed only if every
    /// revocation succeeded.
    ///
    /// # Errors
    /// [`OpError`]: not confirmed (`INTERACTION_REQUIRED`, nothing sent); a locked K_mgmt
    /// store; a revocation that failed (`OUTCOME_UNKNOWN` naming the environment; K_mgmt is
    /// kept and the records of the runners already revoked are forgotten, so a retry
    /// continues with the rest).
    pub async fn retire(&self) -> Result<RetireOutcome, OpError> {
        let key = self.key_ready()?;
        let mut records = self.ports.registry.list()?;
        records.sort_by(|a, b| a.environment.cmp(&b.environment));
        let confirmed = self.ports.confirm.confirm(&Confirmation::RetireDevice {
            environments: records.iter().map(|r| r.environment.clone()).collect(),
            fingerprint: key.fingerprint.clone(),
        });
        if !confirmed {
            return Err(OpError::new(
                Code::InteractionRequired,
                "device retirement was not confirmed: nothing was revoked or destroyed",
            ));
        }
        let mut revoked_on = Vec::new();
        for record in &records {
            let outcome = async {
                let mut session = self.open_recorded(record).await?;
                runner_result(
                    session
                        .call(ManagementCall::Environment(
                            RemoteEnvironmentRequest::RevokeClient {
                                environment: record.environment.clone(),
                                client: record.client.clone(),
                            },
                        ))
                        .await?,
                )
            }
            .await;
            match outcome {
                Ok(_) => {
                    self.ports.registry.remove(&record.environment)?;
                    revoked_on.push(record.environment.clone());
                }
                Err(e) => {
                    return Err(OpError::new(
                        Code::OutcomeUnknown,
                        format!(
                            "device retirement stopped: revoking this device on {} failed ({}); \
                             the management key was kept so the retirement can be retried",
                            record.environment.as_str(),
                            e.code
                        ),
                    )
                    .with_resource("environment", Some(record.environment.as_str().to_owned())));
                }
            }
        }
        self.ports
            .key
            .destroy()
            .map_err(MgmtKeyUnavailable::to_error)?;
        Ok(RetireOutcome {
            revoked_on,
            key_destroyed: true,
        })
    }
}

/// The runner's terminal `invite` result (the fields the bundle needs; others are ignored).
#[derive(Debug, Clone, Deserialize)]
struct InviteCreated {
    invitation: InvitationId,
    client: ClientId,
    generation: u64,
    #[serde(default)]
    nonce: Option<String>,
}

/// A new client ID from the OS CSPRNG.
fn new_client_id() -> Result<ClientId, OpError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| {
        OpError::new(
            Code::InternalError,
            "operating system randomness unavailable",
        )
    })?;
    Ok(ClientId::from_random_bytes(bytes))
}

/// A new request ID (`req_<32 hex>`) from the OS CSPRNG.
///
/// # Errors
/// `INTERNAL_ERROR` when no randomness is available.
pub fn new_request_id() -> Result<RequestId, OpError> {
    use std::fmt::Write as _;
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| {
        OpError::new(
            Code::InternalError,
            "operating system randomness unavailable",
        )
    })?;
    let mut text = String::from("req_");
    for b in bytes {
        let _ = write!(text, "{b:02x}");
    }
    RequestId::parse(&text).map_err(|_| OpError::new(Code::InternalError, "request ID"))
}

/// `device retire`'s request form (ADR-0006 §18), for a frontend that records it.
#[must_use]
pub fn retire_request() -> DeviceRequest {
    DeviceRequest::Retire
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "remote_env_tests.rs"]
mod tests;
