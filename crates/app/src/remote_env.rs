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

/// ⟨rev6.3; ADR-0006 §18.7 item 6⟩ The record types moved to the contract unchanged in shape
/// (`heimdall_contract::controller_record`), so the runtime can write them for the CLI.
pub use heimdall_contract::controller_record::{
    ControllerRecordRequest, ManagementHop, ManagementJump, ManagementRoute, RemoteEnvironmentPin,
};

/// The controller's record of one paired runner environment (the contract's
/// [`RemoteEnvironmentPin`]; this name is kept for the controller's code).
pub type RemoteEnvironmentRecord = RemoteEnvironmentPin;

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
    /// ⟨rev6.3; ADR-0006 §18.7 item 2⟩ The invitation admits the client over Iroh: the
    /// joining device sends its own endpoint ID with `join` (omitted when false).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub iroh_admission: bool,
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

/// The controller's records (`remote_environment_pins`). ⟨rev6.3⟩ The writes are async: the
/// CLI's implementation sends `Request::ControllerRecord` when a runtime answers (the
/// runtime is its store's single writer) and writes directly under the instance lock when
/// none does.
#[async_trait::async_trait]
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
    async fn put(&self, record: &RemoteEnvironmentRecord) -> Result<(), OpError>;

    /// Remove the record of `environment`; `false` when there was none.
    ///
    /// # Errors
    /// [`OpError`].
    async fn remove(&self, environment: &EnvironmentId) -> Result<bool, OpError>;
}

/// ⟨rev6.3; ADR-0006 §18.7 item 6⟩ Apply one controller-record form to `store`: the one writer
/// of `remote_environment_pins` for the runtime's form and the CLI's direct path alike.
/// `put_environment` checks the record (its route's pins: 1 to [`MAX_HOST_KEYS`] key lines
/// per hop; a label of 1 to 64 bytes without control characters) and inserts or replaces it,
/// keyed by its environment, with the runner hop's first pinned key's fingerprint
/// (`host_fingerprint`, the crypto staying in `heimdall-credential`); `remove_environment`
/// forgets one (`removed: false` when there was none) and, ⟨M06 W5⟩ in the same
/// transaction, every standing policy held here that names it (`remove_policies_naming`;
/// `now` dates their last history row) and, ⟨M06-W4-R03⟩ this controller's outbox rows,
/// lift acknowledgements and delivered grants for it, and ⟨ADR-0006 §18.9 item 7⟩ its
/// contact record (the last report and the held state). Who may send it (the local owner
/// only) is the caller's check. Answers `{environment, put: true}` or `{environment,
/// removed}`.
///
/// # Errors
/// `USAGE_ERROR` (effect `none`) for a record that does not check; `STATE_UNAVAILABLE` when
/// the store fails; `driver_unavailable` for a form this build does not know.
pub fn apply_controller_record(
    store: &heimdall_store::Store,
    request: &ControllerRecordRequest,
    host_fingerprint: &dyn Fn(&str) -> Option<KeyFingerprint>,
    now: heimdall_contract::Timestamp,
) -> Result<serde_json::Value, OpError> {
    let unwritable = || {
        OpError::new(
            Code::StateUnavailable,
            "the controller's remote environment records cannot be written",
        )
        .with_effect(heimdall_contract::envelope::EffectStatus::None)
    };
    let invalid = |m: &str| {
        OpError::new(Code::UsageError, m.to_owned())
            .with_effect(heimdall_contract::envelope::EffectStatus::None)
    };
    match request {
        ControllerRecordRequest::PutEnvironment { record } => {
            check_pins(&record.route)
                .map_err(|_| invalid("the record's route has no valid pins"))?;
            if let Some(label) = &record.label
                && (label.is_empty()
                    || label.len() > heimdall_contract::remote::MAX_REMOTE_LABEL_BYTES
                    || label.chars().any(char::is_control))
            {
                return Err(invalid(
                    "the label must be 1 to 64 bytes without control characters",
                ));
            }
            let host = record
                .route
                .runner
                .host_keys
                .first()
                .and_then(|k| host_fingerprint(k))
                .ok_or_else(|| invalid("the record's first pinned host key is not a public key"))?;
            let json = serde_json::to_string(record).map_err(|_| unwritable())?;
            store
                .transaction(|tx| {
                    tx.put_remote_environment_pin(
                        &record.environment,
                        &record.destination,
                        &record.route.runner.account,
                        &host,
                        &json,
                        record.pinned_at,
                    )
                })
                .map_err(|_| unwritable())?;
            Ok(serde_json::json!({ "environment": record.environment, "put": true }))
        }
        ControllerRecordRequest::RemoveEnvironment { environment } => {
            let removed = store
                .transaction(|tx| {
                    let removed = tx.remove_remote_environment_pin(environment)?;
                    remove_policies_naming(tx, environment, now)?;
                    // ⟨M06 W5; M06-W4-R03⟩ What this controller produced for and delivered
                    // to that runner goes with its record: the outbox rows (pending and
                    // acknowledged), the owner's lift acknowledgements, and the delivered
                    // grants. A later record of the same environment starts clean: it
                    // inherits no hold, no acknowledgement and nothing to issue for.
                    tx.forget_remote_effect_outbox(environment)?;
                    tx.forget_delivered_grants(environment)?;
                    // ⟨M06 W5; ADR-0006 §18.9 item 7⟩ And what this controller last saw
                    // of it: the contact record (last seen, last failure, the last report,
                    // the refused pending grants, the held-session marker).
                    tx.forget_remote_contact(environment)?;
                    Ok(removed)
                })
                .map_err(|_| unwritable())?;
            Ok(serde_json::json!({ "environment": environment, "removed": removed }))
        }
        _ => Err(OpError::driver_unavailable(
            "this controller-record form is not known to this build",
        )),
    }
}

/// ⟨M06 W5 ruling, 2026-11-22; m06-plan §2 item 3 "As built and ruled in W5"⟩ Delete every
/// standing policy held here that names the runner `environment`, in the caller's
/// transaction (the one that removes the runner's record): a policy that names a runner
/// is this controller's authorization to sign for that runner and nothing else, so it
/// goes with the record and a later record of the same environment never finds it. Each
/// gets one last history row, the record as removed, whose cause names the removed
/// environment; its cooldowns go with it. A runner's policy is never a default and has no
/// workspace (`trust_m05::admit_create`), so nothing local rests on it. Also run when no
/// record was left, so a policy an earlier build left behind goes too.
fn remove_policies_naming(
    tx: &mut heimdall_store::Txn<'_>,
    environment: &EnvironmentId,
    now: heimdall_contract::Timestamp,
) -> heimdall_store::Result<()> {
    use heimdall_domain::policy::{PolicyRevision, PolicySource};
    use heimdall_domain::workspace::{PolicyChangeCause, PolicyHistoryEntry};
    // This installation's own environment is never a runner record's.
    if tx.self_environment()?.as_ref() == Some(environment) {
        return Ok(());
    }
    for mut p in tx.policies()? {
        if !p.environments.contains(environment) {
            continue;
        }
        tx.delete_policy(&p.id)?;
        for c in tx.decision_cooldowns_for_policy(&p.id)? {
            tx.delete_decision_cooldown(&c.key)?;
        }
        p.revision = PolicyRevision(p.revision.0.saturating_add(1));
        p.source = PolicySource::OwnerDecision { decided_at: now };
        p.default = false;
        tx.append_policy_history(&PolicyHistoryEntry {
            policy: p.id.clone(),
            revision: p.revision,
            record: p.clone(),
            cause: PolicyChangeCause::EnvironmentRemoved {
                environment: environment.clone(),
            },
            at: now,
        })?;
    }
    Ok(())
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

/// ⟨M06 W5 D1⟩ What this controller's own records say about the session it opens. It
/// selects what the hello requires ([`SessionCapabilities::of`]) and nothing else: the
/// runner takes a session's role from its role table, never from the hello, and checks
/// every request against that role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStanding {
    /// The record's role is `owner`, or the session is the bootstrap's first (the owner
    /// enrollment `environment add` just confirmed).
    Owner,
    /// The record's role is a limited one (`requester`, `viewer`).
    Limited,
    /// No record yet: an invitation being joined. The client is pending on the runner, and a
    /// pending session negotiates only the capability that carries the probe and `join`.
    Joining,
}

impl SessionStanding {
    /// The standing of a recorded runner on which this controller holds `role`.
    #[must_use]
    pub fn of_record(role: Role) -> Self {
        if role == Role::Owner {
            SessionStanding::Owner
        } else {
            SessionStanding::Limited
        }
    }
}

/// ⟨M06 W5 D1⟩ What a management session's hello offers and requires (ADR-0006 §18.5
/// reading 5; ADR-0012 §3.8). The one rule, shared by every platform's opener:
///
/// * [`SessionStanding::Owner`] and [`SessionStanding::Joining`] **require**
///   [`MANAGEMENT_CAPABILITY`] and offer `runner/1` (which the runner negotiates for an
///   owner session only). A runner whose role table gives this client less refuses the
///   hello (`role_insufficient`): an owner record never opens a session without it.
/// * [`SessionStanding::Limited`] requires nothing and offers the base capabilities only:
///   neither `remote-control/1` nor `runner/1` is offered, so no form that needs one can be
///   dispatched on that session whatever the runner would grant. The session gets the
///   intersection of the base set with its role's set, and each request is still checked
///   against the role at the runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCapabilities {
    /// The hello's `capabilities`.
    pub offered: std::collections::BTreeSet<String>,
    /// The hello's `required`.
    pub required: std::collections::BTreeSet<String>,
}

impl SessionCapabilities {
    /// The hello's sets for `standing`; `base` is this build's ordinary offer.
    #[must_use]
    pub fn of(standing: SessionStanding, base: std::collections::BTreeSet<String>) -> Self {
        let mut offered = base;
        // A base set never carries an owner capability into a limited session.
        offered.remove(MANAGEMENT_CAPABILITY);
        offered.remove(heimdall_contract::ipc::capability::RUNNER_V1);
        let mut required = std::collections::BTreeSet::new();
        match standing {
            SessionStanding::Owner | SessionStanding::Joining => {
                required.insert(MANAGEMENT_CAPABILITY.to_owned());
                offered.insert(MANAGEMENT_CAPABILITY.to_owned());
                offered.insert(heimdall_contract::ipc::capability::RUNNER_V1.to_owned());
            }
            SessionStanding::Limited => {}
        }
        Self { offered, required }
    }

    /// Whether a session that negotiated `negotiated` may be used for the standing these
    /// sets were made for: everything required was granted. The opener refuses otherwise,
    /// whatever the server's hello said.
    #[must_use]
    pub fn granted(&self, negotiated: &std::collections::BTreeSet<String>) -> bool {
        self.required.is_subset(negotiated)
    }
}

/// Where a management session goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTarget {
    /// The runner hop's name.
    pub name: SessionName,
    /// The route and pins.
    pub route: ManagementRoute,
    /// ⟨M06 W5 D1⟩ What this controller's records say its role there is.
    pub standing: SessionStanding,
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

/// ⟨ADR-0006 §18.7, the ruling under item 19⟩ What the controller says when a confirming
/// probe gave no answer either way: the probe was inconclusive (never "refused").
pub const PROBE_INCONCLUSIVE: &str =
    "a confirming probe of the management session was inconclusive";

/// The rest of the join's message: without an observation only an owner join is possible.
pub const PROBE_INCONCLUSIVE_JOIN: &str = "this device's limited-role join was not sent and nothing was joined; only an owner \
     join is possible without a conclusive probe; try again";

/// The rest of the recheck's message.
pub const PROBE_INCONCLUSIVE_RECHECK: &str =
    "nothing was sent to the runner, and its owner-only state is unchanged; try again";

/// ⟨M06 W5; ADR-0012 §2.6, the 2026-11-22 bullets⟩ What `environment add` says when the
/// bootstrap session completed and the management session that follows it could not be
/// opened: the enrollment stands on the runner, nothing is recorded here, and the next step
/// is named. There is no silent second pass.
pub const AFTER_BOOTSTRAP_NO_SESSION: &str = "the runner confirmed the enrollment, but this \
     controller could not open its management session, so nothing was recorded on this \
     controller. The usual cause is that the runner's runtime is not running (the bootstrap \
     session says so and offers to start it): start it on the runner, then run `environment add` \
     again with the same arguments; it repairs the record after the same confirmation";

/// ⟨M06 W5 `w5r`⟩ What `environment add` says instead of [`AFTER_BOOTSTRAP_NO_SESSION`]
/// when the management session failed on **this controller** before anything reached the
/// runner (an error this controller built itself, [`is_controller_fault`]: its management
/// key agent, its K_mgmt store, its session files): the runner and its runtime are not
/// blamed.
pub const AFTER_BOOTSTRAP_CONTROLLER_FAILED: &str = "the runner confirmed the enrollment, but \
     this controller could not open its management session because of a fault on this \
     controller, not on the runner, so nothing was recorded on this controller. Correct the \
     cause below on this controller, then run `environment add` again with the same \
     arguments; it repairs the record after the same confirmation";

/// ⟨M06 W5 `w5t`⟩ The head of the message of every management-session failure on this
/// controller, before anything reached the runner ([`controller_fault`],
/// [`on_this_controller`]).
pub const CONTROLLER_FAULT_HEAD: &str = "this controller's ";

/// ⟨M06 W5 `w5t`⟩ A management session that failed on **this controller** before anything
/// reached the runner: `code` (chosen by whether an unchanged retry can help), effect
/// `none`, and the message `this controller's <what>; <fix>`. `what` and `fix` never carry
/// a path.
#[must_use]
pub fn controller_fault(code: Code, what: &str, fix: &str) -> OpError {
    let mut e = OpError::new(code, format!("{CONTROLLER_FAULT_HEAD}{what}; {fix}"))
        .with_effect(heimdall_contract::envelope::EffectStatus::None);
    e.controller_local = true;
    e
}

/// ⟨M06 W5 `w5t`⟩ An error of a step on this controller (its K_mgmt store, its OpenSSH
/// client, rendering the session's configuration): code, reason and effect kept, the
/// message under [`CONTROLLER_FAULT_HEAD`] so that no later text blames the runner.
#[must_use]
pub fn on_this_controller(mut e: OpError) -> OpError {
    e.controller_local = true;
    if !e.message.starts_with(CONTROLLER_FAULT_HEAD) {
        e.message = format!(
            "{CONTROLLER_FAULT_HEAD}management session could not start: {}",
            e.message
        );
    }
    e
}

/// ⟨M06 W5 `w5r`, `w5t`, `w5v`⟩ Whether a session's failure is this controller's: only an
/// error this controller built itself ([`controller_fault`], [`on_this_controller`]: the
/// non-wire `OpError::controller_local`). Neither its reason nor its words decide it: a
/// refusal the runner sent keeps its own text and is never reclassified, whatever its
/// reason or its first words.
#[must_use]
pub fn is_controller_fault(e: &OpError) -> bool {
    e.controller_local
}

/// The first session's failure after a completed bootstrap, with its code, reason and
/// effect kept and [`AFTER_BOOTSTRAP_NO_SESSION`] (or, for a failure on this controller,
/// [`is_controller_fault`], [`AFTER_BOOTSTRAP_CONTROLLER_FAILED`]) in front of its own
/// message.
fn after_bootstrap(mut e: OpError) -> OpError {
    let head = if is_controller_fault(&e) {
        AFTER_BOOTSTRAP_CONTROLLER_FAILED
    } else {
        AFTER_BOOTSTRAP_NO_SESSION
    };
    e.message = format!("{head}. The session's error: {}", e.message);
    e
}

/// ⟨M06 W5; ADR-0012 §2.6, the 2026-11-22 paragraph⟩ Why a Windows controller's session
/// runs no confirming probe ([`ManagementSession::probes_unavailable`]): it is a property of
/// the build, not of this connection, so the message says so instead of "inconclusive, try
/// again".
pub const PROBES_NOT_ON_WINDOWS: &str = "the confirming probes of a management session do not \
     run on Windows in this release, so a Windows device can be an owner controller of a runner, \
     not a limited client (viewer or requester)";

/// The rest of the join's message when the probes cannot run on this device at all.
pub const PROBES_UNAVAILABLE_JOIN: &str = "this device's limited-role join was not sent and \
     nothing was joined; join from a macOS or Linux device, or have the runner's owner invite \
     this device as an owner";

/// The rest of the recheck's message when the probes cannot run on this device at all.
pub const PROBES_UNAVAILABLE_RECHECK: &str = "nothing was sent to the runner, and its owner-only \
     state is unchanged; run `environment recheck` from a macOS or Linux owner controller of \
     this runner";

/// The refusal of an operation that needs the confirming probes on a device whose sessions
/// run none (`why`, [`ManagementSession::probes_unavailable`]): `CAPABILITY_UNAVAILABLE`,
/// effect `none`. Repeating it cannot succeed, unlike an inconclusive probe.
fn probes_unavailable(why: &str, rest: &str) -> OpError {
    OpError::new(Code::CapabilityUnavailable, format!("{why}: {rest}"))
        .with_effect(heimdall_contract::envelope::EffectStatus::None)
}

/// A request a management session may carry: the revision-6 management forms only. There
/// is no `Decide` and no `Attend` form, so the controller can never decide on a runner
/// (ADR-0012 §3.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagementCall {
    /// A `remote_environment` form.
    Environment(RemoteEnvironmentRequest),
    /// ⟨M06 W3⟩ A `runner/1` form (`crate::remote_status_driver::SessionChannel`): typed
    /// narrowing effects, the authority report, the time exchange and remote issuance. None
    /// of them decides anything at the runner; a session that did not negotiate `runner/1`
    /// has such a request refused by the runner before dispatch.
    Runner(heimdall_contract::remote::RunnerRequest),
    /// ⟨M06 W3 grant-path; ADR-0012 §4 item 2⟩ An `ensure` this controller forwards to the
    /// runner (`crate::remote_status_driver::ControllerSync::forward_ensure`). The runner
    /// admits it as a paired client's request, under its own standing policy or a decision
    /// confirmed at the runner; the session never decides.
    Ensure(Box<heimdall_contract::request::EnsureRequest>),
    /// ⟨M06 W5; ADR-0006 §18.9 item 6⟩ A read-only `inspect` (the role table's `view`):
    /// what a limited role's `environment status <env>` reads of the runner's own view
    /// ([`RemoteEnvController::runner_view`]). It needs no capability beyond the base one.
    Inspect(Box<heimdall_contract::request::InspectRequest>),
}

impl ManagementCall {
    /// The request sent.
    #[must_use]
    pub fn into_request(self) -> Request {
        match self {
            ManagementCall::Environment(r) => Request::RemoteEnvironment(r),
            ManagementCall::Runner(r) => Request::Runner(r),
            ManagementCall::Ensure(r) => Request::Ensure(*r),
            ManagementCall::Inspect(r) => Request::Inspect(*r),
        }
    }
}

/// One open management session (non-interactive, never attended).
#[async_trait::async_trait]
pub trait ManagementSession: Send {
    /// The runner's hello.
    fn hello(&self) -> &SessionHello;

    /// ⟨M06 W3⟩ Whether the session negotiated `runner/1` (the runner offers it to owner
    /// sessions only). `false` unless the opener says otherwise.
    fn runner_negotiated(&self) -> bool {
        false
    }

    /// ⟨rev6.3; ADR-0006 §18.7 item 16⟩ Run the four confirming probes (ADR-0012 §3.2: a
    /// PTY, a `-W` forward, agent forwarding with a disposable agent, a `SetEnv` variable)
    /// with this session's key over this session's route, and report what they observed.
    /// `None` when the opener runs none, or when any probe was inconclusive.
    async fn probe(&mut self) -> Option<heimdall_contract::remote::ProbeObservation> {
        None
    }

    /// ⟨M06 W5⟩ `Some(why)` when this session's opener can never run the confirming probes
    /// on this device (a Windows controller: [`PROBES_NOT_ON_WINDOWS`]), as opposed to a
    /// probe that ran and was inconclusive. A limited-role join and a policy re-check then
    /// refuse with `why` before anything is sent. `None` (the default): [`Self::probe`]
    /// decides.
    fn probes_unavailable(&self) -> Option<&'static str> {
        None
    }

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
        /// ⟨M06 W5 `w5m` L3⟩ Those of them whose record holds a limited role: retiring
        /// only **forgets** them on this device (a limited role cannot revoke a client), so
        /// the confirmation says so and names the command an owner must run for each.
        forgotten_only: Vec<StillEnrolled>,
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
    /// ⟨rev6.3; ADR-0006 §18.7 item 2⟩ The invited client may reach the runner over Iroh
    /// (`environment invite --iroh`): part of the invitation's exact request, so the
    /// runner-local decision confirms it.
    pub iroh_admission: bool,
}

/// ⟨rev6.3⟩ One runner's answer to `transport rotate`'s announcement
/// ([`RemoteEnvController::announce_endpoint`]).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EndpointAnnouncement {
    /// The runner environment.
    pub environment: EnvironmentId,
    /// Its answer.
    pub result: AnnouncementResult,
}

/// A runner's answer to the endpoint announcement.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AnnouncementResult {
    /// The runner recorded (or already had) the endpoint.
    Accepted {
        /// The runner's result.
        data: serde_json::Value,
    },
    /// The runner refused, or could not be reached.
    Refused {
        /// The code.
        code: Code,
        /// The reason.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// The message.
        message: String,
    },
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
    /// ⟨M06 W3; ADR-0006 §18.7 item 13⟩ The remote fields, in this environment's own entry:
    /// connectivity, the last-known readiness, the pending effects and the residuals
    /// (`crate::remote_status::status_of`). Absent when the caller has no state to read
    /// them from.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub remote: Option<crate::remote_status::RemoteStatus>,
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

/// `remove`'s outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoveOutcome {
    /// The environment whose record was forgotten.
    pub environment: EnvironmentId,
    /// This device's client there.
    pub client: ClientId,
    /// The role the record held.
    pub role: Role,
    /// Whether this device's client was revoked on the runner first. `false` for a
    /// limited record: it is forgotten here only, and an owner must still revoke that
    /// client on the runner.
    pub revoked_on_runner: bool,
}

/// `retire`'s outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetireOutcome {
    /// The environments on which this device's client was revoked.
    pub revoked_on: Vec<EnvironmentId>,
    /// Whether K_mgmt was destroyed (only after every revocation succeeded).
    pub key_destroyed: bool,
    /// ⟨M06 W5 `w5l`; ADR-0006 §18.9 item 6⟩ The runners whose record held a **limited**
    /// role: forgotten on this device with no revoke (revoking a client is an owner's
    /// form), so this device's client is still enrolled there until an owner revokes it.
    /// Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub still_enrolled_on: Vec<StillEnrolled>,
}

/// A runner this device was retired from without a revoke ([`RetireOutcome`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StillEnrolled {
    /// The runner environment.
    pub environment: EnvironmentId,
    /// This device's client there, which an owner must still revoke.
    pub client: ClientId,
    /// The role its record held.
    pub role: Role,
}

impl RetireOutcome {
    /// The outcome in words. For each runner whose record held a limited role it says that
    /// an owner must still revoke this device's client there, and names the command.
    #[must_use]
    pub fn line(&self) -> String {
        let mut line = format!(
            "retired: revoked on {} runner(s); management key destroyed",
            self.revoked_on.len()
        );
        if !self.still_enrolled_on.is_empty() {
            line.push_str(
                ". This device's role on the following runner(s) cannot revoke a client, so \
                 they were forgotten on this device only and its client is still enrolled \
                 there: an owner must still revoke it on each, on an owner controller:",
            );
            for s in &self.still_enrolled_on {
                line.push_str(&format!(
                    " `heimdall environment revoke-client {} {}`",
                    s.environment.as_str(),
                    s.client.as_str()
                ));
            }
        }
        line
    }
}

// --- the controller ------------------------------------------------------------------------

/// The controller's environment management (module docs).
pub struct RemoteEnvController<'a> {
    ports: ControllerPorts<'a>,
}

fn refuse(code: Code, message: &str, why: &str) -> OpError {
    OpError::new(code, message).with_reason(why)
}

/// A role's wire name, for a message.
fn role_name(role: Role) -> String {
    serde_json::to_value(role)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "limited".to_owned())
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
                standing: SessionStanding::of_record(record.role),
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

    /// ⟨M06 W5; ADR-0006 §18.9 item 6⟩ An owner command on a record whose role is a
    /// limited one is refused here, on the controller, from the record: `role_insufficient`,
    /// before K_mgmt is touched or a session opens (the runner would refuse it per request
    /// too; a session that negotiated no owner capability could only answer
    /// `SCHEMA_UNSUPPORTED`, which says nothing about the role).
    fn owner_record(
        &self,
        environment: &EnvironmentId,
        what: &str,
    ) -> Result<RemoteEnvironmentRecord, OpError> {
        let record = self.record(environment)?;
        if record.role != Role::Owner {
            return Err(refuse(
                Code::CapabilityUnavailable,
                &format!(
                    "{what} is an owner's command, and this device's role on that runner \
                     is {}: nothing was sent",
                    role_name(record.role)
                ),
                reason::ROLE_INSUFFICIENT,
            )
            .with_effect(heimdall_contract::envelope::EffectStatus::None));
        }
        Ok(record)
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
                standing: SessionStanding::Owner,
            })
            .await
            .map_err(after_bootstrap)?;
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
        self.ports.registry.put(&record).await?;
        Ok(record)
    }

    /// `environment invite` (module docs; ADR-0012 §3.9).
    ///
    /// # Errors
    /// [`OpError`]: the owner did not confirm the fingerprint (`INTERACTION_REQUIRED`), a
    /// fingerprint that does not match the key (`USAGE_ERROR`), a locked K_mgmt store, the
    /// runner's refusal, or `role_insufficient` (nothing asked, nothing sent) for a record
    /// whose role is limited.
    pub async fn invite(&self, input: &InviteInput) -> Result<InviteOutcome, OpError> {
        let record = self.owner_record(&input.environment, "inviting a client")?;
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
                    iroh_admission: input.iroh_admission,
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
                    iroh_admission: input.iroh_admission,
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

    /// `environment join` on the new device (module docs; ADR-0012 §3.9), sending no Iroh
    /// endpoint ([`Self::join_with_endpoint`]).
    ///
    /// # Errors
    /// As [`Self::join_with_endpoint`].
    pub async fn join(
        &self,
        bundle: &InvitationBundle,
    ) -> Result<RemoteEnvironmentRecord, OpError> {
        self.join_with_endpoint(bundle, None).await
    }

    /// `environment join` (module docs; ADR-0012 §3.9). ⟨rev6.3; ADR-0006 §18.7 item 3⟩
    /// `own_endpoint` is this device's K_iroh endpoint ID when a verified store holds K_iroh;
    /// it is sent (`Join.iroh_endpoint`) only when the bundle's invitation admits Iroh.
    ///
    /// # Errors
    /// [`OpError`]: the user did not confirm the runner (`INTERACTION_REQUIRED`), the bundle
    /// names another key, an environment ID mismatch, or the runner's refusal.
    pub async fn join_with_endpoint(
        &self,
        bundle: &InvitationBundle,
        own_endpoint: Option<heimdall_contract::ids::IrohEndpointId>,
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
                standing: SessionStanding::Joining,
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
        // ⟨M06 W5⟩ A device whose sessions run no confirming probe (a Windows controller)
        // cannot join in a limited role: refused here, with the reason, before the
        // activation probe or anything else is sent. An owner join needs no probe.
        if bundle.role != Role::Owner
            && let Some(why) = session.probes_unavailable()
        {
            return Err(probes_unavailable(why, PROBES_UNAVAILABLE_JOIN));
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
        // ⟨rev6.3; ADR-0006 §18.7 item 16⟩ What this device's confirming probes observed on
        // its real connection. The runner refuses a limited role without it, so nothing is
        // sent then; an owner join is exempt and goes without one.
        let probe = session.probe().await;
        if probe.is_none() && bundle.role != Role::Owner {
            return Err(OpError::new(
                Code::DestinationUnreachable,
                format!("{PROBE_INCONCLUSIVE}: {PROBE_INCONCLUSIVE_JOIN}"),
            )
            .with_effect(heimdall_contract::envelope::EffectStatus::None));
        }
        runner_result(
            session
                .call(ManagementCall::Environment(
                    RemoteEnvironmentRequest::Join {
                        environment: bundle.environment.clone(),
                        invitation: bundle.invitation.clone(),
                        role: bundle.role,
                        generation: bundle.generation,
                        // ⟨rev6.3; ADR-0006 §18.7 item 3⟩ Only an invitation that admits
                        // Iroh carries this device's endpoint (the runner refuses it
                        // otherwise); none when no verified store holds K_iroh.
                        iroh_endpoint: own_endpoint.filter(|_| bundle.iroh_admission),
                        probe,
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
        self.ports.registry.put(&record).await?;
        Ok(record)
    }

    /// `environment revoke-client`: narrowing, no decision (ADR-0012 §3.11). Revoking one
    /// runner's client never touches K_mgmt.
    ///
    /// # Errors
    /// [`OpError`]; `role_insufficient`, nothing sent, for a record whose role is limited.
    pub async fn revoke_client(
        &self,
        environment: &EnvironmentId,
        client: &ClientId,
    ) -> Result<serde_json::Value, OpError> {
        self.owner_record(environment, "revoking a client")?;
        self.call_recorded(
            environment,
            ManagementCall::Environment(RemoteEnvironmentRequest::RevokeClient {
                environment: environment.clone(),
                client: client.clone(),
            }),
        )
        .await
    }

    /// ⟨rev6.3; ADR-0006 §18.7 item 4⟩ `transport rotate`'s announcement: send this
    /// device's new K_iroh endpoint ID (`remote_environment.rotate_endpoint`) to every
    /// recorded runner, each over its own management session, and report each runner's
    /// answer. A runner whose invitation did not admit Iroh refuses; that is reported and the
    /// others still get it.
    ///
    /// # Errors
    /// [`OpError`] when the records cannot be read (no runner was contacted).
    pub async fn announce_endpoint(
        &self,
        endpoint: &heimdall_contract::ids::IrohEndpointId,
    ) -> Result<Vec<EndpointAnnouncement>, OpError> {
        let mut out = Vec::new();
        for record in self.ports.registry.list()? {
            let answer = self
                .announce_endpoint_to(&record.environment, endpoint)
                .await;
            out.push(EndpointAnnouncement {
                environment: record.environment.clone(),
                result: match answer {
                    Ok(data) => AnnouncementResult::Accepted { data },
                    Err(e) => AnnouncementResult::Refused {
                        code: e.code.clone(),
                        reason: e.reason.clone(),
                        message: e.message.clone(),
                    },
                },
            });
        }
        Ok(out)
    }

    /// ⟨rev6.3; ADR-0006 §18.7 item 10⟩ [`Self::announce_endpoint`] to one recorded
    /// runner: `transport.rotate`'s per-runner step (`crate::transport::EndpointAnnouncer`).
    ///
    /// # Errors
    /// [`OpError`]: no such record, K_mgmt unavailable, the session's failure, or the
    /// runner's refusal (the runner then stays pending).
    pub async fn announce_endpoint_to(
        &self,
        environment: &EnvironmentId,
        endpoint: &heimdall_contract::ids::IrohEndpointId,
    ) -> Result<serde_json::Value, OpError> {
        self.call_recorded(
            environment,
            ManagementCall::Environment(RemoteEnvironmentRequest::RotateEndpoint {
                environment: environment.clone(),
                endpoint: endpoint.clone(),
            }),
        )
        .await
    }

    /// ⟨rev6.3; ADR-0006 §18.7 item 19⟩ `environment recheck`: run the four confirming
    /// probes over a real management session to a recorded runner and send what they
    /// observed (`remote_environment.runner_policy_recheck`). The runner records it as the
    /// evidence its attended `remote policy recheck` judges; nothing is lifted here. Only
    /// this controller's owner client may send it (checked here from the record, and by the
    /// runner per request).
    ///
    /// # Errors
    /// [`OpError`]: no such record, a record whose role is not `owner` (`role_insufficient`),
    /// K_mgmt unavailable, the session's failure, an inconclusive probe (nothing sent), or
    /// the runner's refusal.
    pub async fn recheck(&self, environment: &EnvironmentId) -> Result<serde_json::Value, OpError> {
        let record = self.record(environment)?;
        if record.role != Role::Owner {
            return Err(refuse(
                Code::CapabilityUnavailable,
                "only this runner's owner may recheck its sshd policy: nothing was sent",
                reason::ROLE_INSUFFICIENT,
            ));
        }
        self.key_ready()?;
        let mut session = self.open_recorded(&record).await?;
        if let Some(why) = session.probes_unavailable() {
            return Err(probes_unavailable(why, PROBES_UNAVAILABLE_RECHECK));
        }
        let Some(probe) = session.probe().await else {
            return Err(OpError::new(
                Code::DestinationUnreachable,
                format!("{PROBE_INCONCLUSIVE}: {PROBE_INCONCLUSIVE_RECHECK}"),
            )
            .with_effect(heimdall_contract::envelope::EffectStatus::None));
        };
        runner_result(
            session
                .call(ManagementCall::Environment(
                    RemoteEnvironmentRequest::RunnerPolicyRecheck {
                        environment: environment.clone(),
                        probe,
                    },
                ))
                .await?,
        )
    }

    /// `environment remove`: revoke this device's client on that runner, then forget the
    /// record (pins included). K_mgmt is kept: it may serve other runners.
    ///
    /// ⟨M06 W5; ADR-0006 §18.9 item 6⟩ A record whose role is limited is forgotten
    /// **locally, without the revoke**: revoking a client is an owner's form, so this
    /// device cannot remove its own line. No session is opened and K_mgmt is not needed;
    /// the outcome says the client is still enrolled on the runner
    /// ([`RemoveOutcome::revoked_on_runner`] is `false`), and an owner must revoke it there.
    ///
    /// # Errors
    /// [`OpError`]: the revocation failed (nothing is forgotten, so it can be retried).
    pub async fn remove(&self, environment: &EnvironmentId) -> Result<RemoveOutcome, OpError> {
        let record = self.record(environment)?;
        let revoked_on_runner = record.role == Role::Owner;
        if revoked_on_runner {
            self.revoke_client(environment, &record.client).await?;
        }
        self.ports.registry.remove(environment).await?;
        Ok(RemoveOutcome {
            environment: environment.clone(),
            client: record.client,
            role: record.role,
            revoked_on_runner,
        })
    }

    /// ⟨M06 W5; ADR-0006 §18.9 item 6⟩ The runner's own view for a record whose role is a
    /// limited one: `environment status <env>` opens one management session of that
    /// standing and sends read-only forms only (`inspect environments`, the role table's
    /// `view`). `None` for an owner record: its status is this controller's own view, and
    /// no session is opened for it (unchanged).
    ///
    /// # Errors
    /// [`OpError`]: no such record, K_mgmt unavailable, the session's failure, a runner
    /// whose identity does not match the record, or the runner's refusal.
    pub async fn runner_view(
        &self,
        environment: &EnvironmentId,
    ) -> Result<Option<serde_json::Value>, OpError> {
        let record = self.record(environment)?;
        if record.role == Role::Owner {
            return Ok(None);
        }
        self.key_ready()?;
        let mut session = self.open_recorded(&record).await?;
        let view = runner_result(
            session
                .call(ManagementCall::Inspect(Box::new(
                    heimdall_contract::request::InspectRequest {
                        subject: heimdall_contract::request::InspectSubject::Environments,
                        preview: None,
                        cwd: None,
                        redact: false,
                        select: None,
                        page: None,
                    },
                )))
                .await?,
        )?;
        Ok(Some(view))
    }

    /// `environment update`: the runner's explicit, checksum-verified binary update
    /// (ADR-0012 §6.4), requested over the management session.
    ///
    /// # Errors
    /// [`OpError`].
    pub async fn update(&self, environment: &EnvironmentId) -> Result<serde_json::Value, OpError> {
        self.owner_record(environment, "updating the runner")?;
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
                .map(|record| EnvironmentStatus {
                    record,
                    remote: None,
                })
                .collect(),
        })
    }

    /// `device retire` (module docs; ADR-0012 §3.4): a locally attended decision, then this
    /// device's client revoked on every recorded runner, then K_mgmt destroyed only if every
    /// revocation succeeded. ⟨M06 W5 `w5l`⟩ A record whose role is limited is forgotten
    /// locally with no revoke, as `remove` does; the outcome lists those runners
    /// ([`RetireOutcome::still_enrolled_on`]): an owner must still revoke this client there.
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
            forgotten_only: records
                .iter()
                .filter(|r| r.role != Role::Owner)
                .map(|r| StillEnrolled {
                    environment: r.environment.clone(),
                    client: r.client.clone(),
                    role: r.role,
                })
                .collect(),
            fingerprint: key.fingerprint.clone(),
        });
        if !confirmed {
            return Err(OpError::new(
                Code::InteractionRequired,
                "device retirement was not confirmed: nothing was revoked or destroyed",
            ));
        }
        let mut revoked_on = Vec::new();
        let mut still_enrolled_on = Vec::new();
        for record in &records {
            // ⟨M06 W5 `w5l`; ADR-0006 §18.9 item 6⟩ A limited record is forgotten locally:
            // revoking a client is an owner's form, so no session is opened and nothing is
            // sent for it. An owner record keeps revoke-then-forget.
            if record.role != Role::Owner {
                self.ports.registry.remove(&record.environment).await?;
                still_enrolled_on.push(StillEnrolled {
                    environment: record.environment.clone(),
                    client: record.client.clone(),
                    role: record.role,
                });
                continue;
            }
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
                    self.ports.registry.remove(&record.environment).await?;
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
            still_enrolled_on,
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
