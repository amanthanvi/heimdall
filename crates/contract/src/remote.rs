//! ⟨M06⟩ ADR-0006 revision 6 (§18; ADR-0012 §9): roles, the controller's management of
//! remote runner environments, the runner-internal requests, typed narrowing effects,
//! and the remote fields of the environment view and of the events.
//!
//! Types and wire forms only. Wave 0 lands them fail closed: every request here answers
//! `CAPABILITY_UNAVAILABLE` / `driver_unavailable` before any record is written, and the
//! capabilities `remote-control/1` and `runner/1` are declared and not offered. Nothing
//! here sets a caller: a paired client is named only by the runner from its bridge's
//! hello (ADR-0012 §3.6), never by a request field.

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::ids::{
    AccountName, ClientId, DestinationId, EffectId, EnvironmentId, GrantId, InvitationId,
    KeyFingerprint, PolicyId, RequestId,
};
use crate::trust::PolicyTarget;

// --- roles (ADR-0012 §3.8) ---------------------------------------------------------------

/// A paired client's role on a runner (ADR-0012 §3.8). The local same-user caller is
/// always `owner` (ADR-0006 §2.1); `requester` and `viewer` are defined here and unused
/// until the role table lands (m06-plan U1).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Role {
    /// Every permission.
    Owner,
    /// `view` and `request`.
    Requester,
    /// `view` only.
    Viewer,
}

/// A permission a role holds (ADR-0012 §3.8). Limited roles never include execution on
/// the runner.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Permission {
    /// See status and the views the role permits.
    View,
    /// Request work allowed by policy (a widening request creates a pending record only).
    Request,
    /// Approve (always runner-locally attended for a widening, ADR-0012 §3.10).
    Approve,
    /// Change the runner's trusted issuers.
    IssuerTrust,
    /// Enroll and revoke clients.
    Enroll,
    /// Service control.
    Service,
    /// Answer the runner's time challenge as its designated time source (ADR-0012 §4.4).
    TimeSource,
}

impl Role {
    /// The permissions this role holds (ADR-0012 §3.8).
    #[must_use]
    pub fn permissions(self) -> &'static [Permission] {
        match self {
            Role::Owner => &[
                Permission::View,
                Permission::Request,
                Permission::Approve,
                Permission::IssuerTrust,
                Permission::Enroll,
                Permission::Service,
                Permission::TimeSource,
            ],
            Role::Requester => &[Permission::View, Permission::Request],
            Role::Viewer => &[Permission::View],
        }
    }

    /// Whether this role holds `permission`.
    #[must_use]
    pub fn has(self, permission: Permission) -> bool {
        self.permissions().contains(&permission)
    }

    /// The capabilities this role may negotiate
    /// ([`crate::ipc::capability::for_role`]).
    #[must_use]
    pub fn capabilities(self) -> &'static [&'static str] {
        crate::ipc::capability::for_role(self)
    }
}

// --- the controller's environment management (capability `remote-control/1`) ------------

/// Maximum length of a remote environment's label, in bytes.
pub const MAX_REMOTE_LABEL_BYTES: usize = 64;

/// `Request::RemoteEnvironment`, tagged by `action` (ADR-0012 §3, §6.4, §9 item 6:
/// `env add|invite|join|revoke-client|remove|update|status`). Capability
/// `remote-control/1`. A form that can widen authority or exposure (`invite`) carries a
/// `request_id`, so a replay after the runner-local decision returns the recorded
/// terminal result (ADR-0012 §3.10 T-RA3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemoteEnvironmentRequest {
    /// Bootstrap a runner over the owner's existing, independently host-verified SSH
    /// access to the runner account (ADR-0012 §3.3): install or verify the binary, run
    /// `heimdall remote init`, enroll this controller's K_mgmt as `owner` (confirmed in
    /// the bootstrap's interactive ssh session with a TTY). Also the repair path for a
    /// lost host pin or K_mgmt. Kind `remote_environment.add`.
    Add {
        /// The catalog destination whose pinned host key and existing access reach the
        /// runner account (never `ssh-keyscan`).
        destination: DestinationId,
        /// The runner account.
        account: AccountName,
        /// The owner's label (1 to [`MAX_REMOTE_LABEL_BYTES`] bytes).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    /// Create an invitation on the runner (ADR-0012 §3.9): a widening action, confirmed
    /// runner-locally. The runner mints the invitation and client IDs. Kind
    /// `remote_environment.invite`.
    Invite {
        /// The runner environment.
        environment: EnvironmentId,
        /// The role the invited client will hold.
        role: Role,
        /// The receiving key's fingerprint, which the owner confirmed against the new
        /// device's display (§3.9 item 1).
        key_fingerprint: KeyFingerprint,
        /// Idempotency key (ADR-0006 §7).
        request_id: RequestId,
    },
    /// Consume an invitation: `pending → active` only if the invitation, the client (from
    /// the bridge's argv), the line's key fingerprint, the role and the generation all
    /// match and the invitation is live (§3.9 items 4–5). Kind `remote_environment.join`.
    Join {
        /// The runner environment, from the public bundle the user confirmed.
        environment: EnvironmentId,
        /// The invitation.
        invitation: InvitationId,
        /// The role the invitation was created for.
        role: Role,
        /// The invitation's generation.
        generation: u64,
    },
    /// Revoke one client on the runner (ADR-0012 §3.11): tombstone, close Iroh admission,
    /// then remove the line. Narrowing; no decision. Kind
    /// `remote_environment.revoke_client`.
    RevokeClient {
        /// The runner environment.
        environment: EnvironmentId,
        /// The client.
        client: ClientId,
    },
    /// Remove the runner environment from this controller. Kind
    /// `remote_environment.remove`.
    Remove {
        /// The runner environment.
        environment: EnvironmentId,
    },
    /// Explicit runner binary update: a checksum-verified copy, drain, restart; the
    /// environment ID and the role table are preserved (ADR-0012 §6.4). Kind
    /// `remote_environment.update`.
    Update {
        /// The runner environment.
        environment: EnvironmentId,
    },
    /// The controller's view of one or every remote environment (ADR-0012 §7.1).
    /// Read-only. Kind `remote_environment.status`.
    Status {
        /// One environment; every remote environment when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        environment: Option<EnvironmentId>,
    },
}

impl RemoteEnvironmentRequest {
    /// The operation-kind name.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            RemoteEnvironmentRequest::Add { .. } => "remote_environment.add",
            RemoteEnvironmentRequest::Invite { .. } => "remote_environment.invite",
            RemoteEnvironmentRequest::Join { .. } => "remote_environment.join",
            RemoteEnvironmentRequest::RevokeClient { .. } => "remote_environment.revoke_client",
            RemoteEnvironmentRequest::Remove { .. } => "remote_environment.remove",
            RemoteEnvironmentRequest::Update { .. } => "remote_environment.update",
            RemoteEnvironmentRequest::Status { .. } => "remote_environment.status",
        }
    }
}

/// `Request::Device`, tagged by `action` (ADR-0012 §3.4: `device retire`). Capability
/// `remote-control/1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeviceRequest {
    /// Retire this controller device: revoke its client on every runner where it is
    /// enrolled, then destroy K_mgmt. Needs an attended local decision (ADR-0012 §3.10
    /// item 4). Kind `device.retire`.
    Retire,
}

impl DeviceRequest {
    /// The operation-kind name.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            DeviceRequest::Retire => "device.retire",
        }
    }
}

// --- the runner-internal requests (capability `runner/1`) --------------------------------

/// Maximum size of an OpenSSH certificate line in `install_certificate` (the 16 KiB
/// public-key bound, [`crate::catalog::MAX_PUBLIC_KEY_BYTES`]).
pub const MAX_CERTIFICATE_BYTES: usize = crate::catalog::MAX_PUBLIC_KEY_BYTES;

/// A typed narrowing effect's target (ADR-0012 §7.2). With the authenticated producing
/// controller (the session's client, never a field) and the effect ID, it keys the
/// effect; each target carries its own generation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EffectTarget {
    /// Applied as a durable grant tombstone (ADR-0005 §6.1 "Revocation"), acknowledged
    /// with its enforcement state.
    GrantRevoke {
        /// The grant.
        grant: GrantId,
        /// The grant's generation.
        grant_generation: u64,
    },
    /// Applied as a durable policy revision: running grants continue, new activations
    /// are refused (§6.1 "Pause"). Not a tombstone.
    PolicyPause {
        /// The policy.
        policy: PolicyId,
        /// The revision this pause produces.
        revision: u64,
    },
    /// Applied as a durable policy revision that also ends every affected grant like
    /// expiry and refuses new grants until cleared (§6.1 "Cutoff"). Wave 0 reads a
    /// delivered cutoff as taking effect when applied (no scheduled instant).
    PolicyCutoff {
        /// The policies it applies to.
        scope: PolicyTarget,
        /// The revision this cutoff produces.
        revision: u64,
    },
}

impl EffectTarget {
    /// The target generation (`grant_generation` or `revision`).
    #[must_use]
    pub fn generation(&self) -> u64 {
        match self {
            EffectTarget::GrantRevoke {
                grant_generation, ..
            } => *grant_generation,
            EffectTarget::PolicyPause { revision, .. }
            | EffectTarget::PolicyCutoff { revision, .. } => *revision,
        }
    }
}

/// `Request::Runner`, tagged by `action` (ADR-0012 §4, §7, §9 item 6): the requests a
/// controller sends a runner over the management channel. Capability `runner/1`. None
/// carries a caller identity; the producing controller of an effect is the session's
/// authenticated client. The serve child's lease and suspend messages are internal to
/// its supervision channel and are not here (§2.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RunnerRequest {
    /// Ask the runner to generate K_env for a grant it admitted and return K_env.pub
    /// bound to the grant and its generation (ADR-0012 §4.2 step 2). Kind
    /// `runner.prepare_remote_grant`.
    PrepareRemoteGrant {
        /// The grant.
        grant: GrantId,
        /// The grant's generation.
        grant_generation: u64,
    },
    /// Install the issuer's certificate for that key (§4.2 step 4): the runner checks its
    /// key, issuer (`issuer_trust`), principals, generation, scope and `valid_before`.
    /// Kind `runner.install_certificate`.
    InstallCertificate {
        /// The grant.
        grant: GrantId,
        /// The grant's generation.
        grant_generation: u64,
        /// The OpenSSH certificate, one line of public text (at most
        /// [`MAX_CERTIFICATE_BYTES`]).
        certificate: String,
    },
    /// Ask the runner for a fresh time-challenge nonce (ADR-0012 §4.4). Kind
    /// `runner.time_challenge`.
    TimeChallenge,
    /// Answer it as the runner's designated time source: fresh, nonce-bound, counted only
    /// within the RTT bound; it may move an anchor earlier only (§4.4). Kind
    /// `runner.time_response`.
    TimeResponse {
        /// The runner's nonce, echoed.
        nonce: String,
        /// The controller's clock reading (T_c).
        controller_time: Timestamp,
    },
    /// Deliver a typed narrowing effect (ADR-0012 §7.2): acknowledged only after the
    /// durable record it names exists. Kind `runner.deliver_effect`.
    DeliverEffect {
        /// The effect ID the producing controller minted.
        effect: EffectId,
        /// The typed target.
        target: EffectTarget,
    },
    /// The runner's authority report: tombstones, policy revisions with their
    /// generations, installed certificates (§7.4 step 3), read by the issuer's
    /// reconciliation barrier. Read-only. Kind `runner.authority_report`.
    AuthorityReport,
}

impl RunnerRequest {
    /// The operation-kind name.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            RunnerRequest::PrepareRemoteGrant { .. } => "runner.prepare_remote_grant",
            RunnerRequest::InstallCertificate { .. } => "runner.install_certificate",
            RunnerRequest::TimeChallenge => "runner.time_challenge",
            RunnerRequest::TimeResponse { .. } => "runner.time_response",
            RunnerRequest::DeliverEffect { .. } => "runner.deliver_effect",
            RunnerRequest::AuthorityReport => "runner.authority_report",
        }
    }
}

// --- the environment view's remote fields (ADR-0012 §7.1, §9 item 5) ---------------------

/// A remote environment's connectivity as the controller sees it (ADR-0012 §7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Connectivity {
    /// A management session is open.
    Connected,
    /// No session; last seen then.
    Disconnected {
        /// When the runner was last reached.
        last_seen_at: Timestamp,
    },
    /// The runner cannot be reached for a known reason.
    Unreachable {
        /// The reason (a stable reason string).
        reason: String,
    },
}

/// The runner runtime's lifetime (ADR-0012 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RunnerLifetime {
    /// A verified `systemd --user` unit with linger enabled by the owner.
    UserService,
    /// The narrower lifetime: survives logout only while `KillUserProcesses=no`.
    SessionScope,
    /// Not determined.
    Unknown,
}

/// Whether limited roles may enroll on the runner (ADR-0012 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ManagementPolicy {
    /// The effective sshd policy for the account was verified: limited roles may enroll.
    Verified,
    /// Not verified: only `owner` clients may enroll (`management_sshd_unverified`).
    OwnerOnly,
}

/// One entry of `EnvironmentView.remote_pending` (ADR-0012 §2.3 item 4, §7.1): a
/// narrowing step reported but not yet applied on the runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemotePending {
    /// A typed effect not yet acknowledged.
    Effect {
        /// The effect.
        effect: EffectId,
        /// Its target.
        target: EffectTarget,
        /// A pending reason ([`crate::envelope::reason::M06_PENDING`]).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// A client revocation whose Iroh admission is not yet closed
    /// (`iroh_admission_closing`).
    ClientRevocation {
        /// The client.
        client: ClientId,
        /// A pending reason ([`crate::envelope::reason::M06_PENDING`]).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

// --- events (ADR-0012 §9 item 8) ---------------------------------------------------------

/// What an `environment` event reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnvironmentEventKind {
    /// `environment.connectivity_changed`.
    ConnectivityChanged,
}

/// Payload of `EventType::Environment` (not emitted by wave 0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnvironmentEventPayload {
    /// The kind.
    pub kind: EnvironmentEventKind,
    /// The remote environment.
    pub environment: EnvironmentId,
    /// Its connectivity now.
    pub connectivity: Connectivity,
}

/// What a `client` event reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ClientEventKind {
    /// `client.enrolled`.
    Enrolled,
    /// `client.revoked` (also the terminal event of the client's own subscriptions).
    Revoked,
}

/// Payload of `EventType::Client` (not emitted by wave 0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClientEventPayload {
    /// The kind.
    pub kind: ClientEventKind,
    /// The runner environment.
    pub environment: EnvironmentId,
    /// The client.
    pub client: ClientId,
    /// Its role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
}

/// What a `device` event reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeviceEventKind {
    /// `device.retired`.
    Retired,
}

/// Payload of `EventType::Device` (not emitted by wave 0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeviceEventPayload {
    /// The kind.
    pub kind: DeviceEventKind,
    /// The runners where this device's client was revoked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_on: Vec<EnvironmentId>,
}

/// What a `remote_effect` event reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemoteEffectEventKind {
    /// `remote_effect.pending`.
    Pending,
    /// `remote_effect.acknowledged`.
    Acknowledged,
}

/// Payload of `EventType::RemoteEffect` (not emitted by wave 0): the effect's key
/// (ADR-0012 §7.2), its target carrying the target generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RemoteEffectEventPayload {
    /// The kind.
    pub kind: RemoteEffectEventKind,
    /// The runner environment.
    pub environment: EnvironmentId,
    /// The producing controller (its authenticated client on that runner).
    pub producer: ClientId,
    /// The effect.
    pub effect: EffectId,
    /// The typed target, with its generation.
    pub target: EffectTarget,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// ADR-0012 §3.8: the three roles' permissions; only `owner` holds the widening and
    /// enrollment permissions.
    #[test]
    fn roles_hold_their_permissions() {
        assert_eq!(Role::Owner.permissions().len(), 7);
        assert!(Role::Requester.has(Permission::Request));
        assert!(!Role::Requester.has(Permission::Approve));
        assert!(Role::Viewer.has(Permission::View));
        assert!(!Role::Viewer.has(Permission::Request));
        for p in [
            Permission::Approve,
            Permission::IssuerTrust,
            Permission::Enroll,
            Permission::Service,
            Permission::TimeSource,
        ] {
            assert!(Role::Owner.has(p));
            assert!(!Role::Requester.has(p) && !Role::Viewer.has(p), "{p:?}");
        }
        assert_eq!(
            serde_json::to_string(&Role::Requester).unwrap(),
            "\"requester\""
        );
    }

    /// The typed targets' wire forms and their generation.
    #[test]
    fn effect_targets_are_typed() {
        let t: EffectTarget = serde_json::from_str(
            r#"{"kind":"grant_revoke","grant":"grant_00","grant_generation":3}"#,
        )
        .unwrap();
        assert_eq!(t.generation(), 3);
        let c: EffectTarget =
            serde_json::from_str(r#"{"kind":"policy_cutoff","scope":{"kind":"all"},"revision":9}"#)
                .unwrap();
        assert_eq!(c.generation(), 9);
        assert!(
            serde_json::from_str::<EffectTarget>(r#"{"kind":"grant_revoke","grant":"grant_00"}"#)
                .is_err(),
            "a target without its generation is refused"
        );
    }
}
