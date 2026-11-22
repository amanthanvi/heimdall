//! ⟨M06⟩ ADR-0006 revision 6.3 (§18.7 item 6; ADR-0012 §3.3, §3.4, §7.5): the controller's
//! records of its paired runner environments, and the request form that writes them through
//! the controller's own runtime.
//!
//! A controller keeps one [`RemoteEnvironmentPin`] per runner it manages (the
//! `remote_environment_pins` row's authoritative document): the runner's environment ID, the
//! route and the catalog-pinned host keys of each hop, and this device's client and role
//! there. A changed host key or environment ID is `held`, never silently re-pinned (ADR-0012
//! §7.5). The shapes moved here from `heimdall_app::remote_env` unchanged, so every stored
//! record reads back byte for byte.
//!
//! [`ControllerRecordRequest`] lets the CLI write these records while a runtime runs (the
//! runtime is the single writer of its store): the local owner only; a paired session is
//! refused. The CLI keeps the TTY confirmations and the ssh bootstrap, and writes directly
//! under the instance lock when no runtime answers.

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::ids::{AccountName, ClientId, DestinationId, EffectId, EnvironmentId, KeyFingerprint};
use crate::remote::Role;

/// One hop of a management route: where it is and the host keys pinned for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ManagementJump {
    /// The jump destination.
    pub destination: DestinationId,
    /// Its hop.
    pub hop: ManagementHop,
}

/// The route a management session takes to a runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RemoteEnvironmentPin {
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

/// `Request::ControllerRecord`, tagged by `action` (ADR-0006 §18.7 item 6): write the
/// controller's own records of its runners through its runtime. Local owner only; a paired
/// session is refused. No form widens anything on a runner: the runner-side effects
/// (enrollment, revocation) are the management session's, confirmed where ADR-0012 §3.10
/// says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
// The record is the form's whole content (one per request, never stored in bulk): boxing it
// would only move the allocation.
#[allow(clippy::large_enum_variant)]
pub enum ControllerRecordRequest {
    /// Insert or replace the record of `record.environment`. Kind
    /// `controller_record.put_environment`.
    PutEnvironment {
        /// The record.
        record: RemoteEnvironmentPin,
    },
    /// Forget one runner's record (absent: nothing to remove). Kind
    /// `controller_record.remove_environment`.
    RemoveEnvironment {
        /// The runner environment.
        environment: EnvironmentId,
    },
    /// ⟨rev6.4; ADR-0006 §18.8 item 4; ADR-0012 §7.4 ⟨2026-11-21⟩⟩ Record the owner's
    /// acknowledgement that the pauses and cutoffs named in `effects`, which this controller
    /// delivered to the runner `environment`, were lifted there (`heimdall environment
    /// resume-issuance`). It names the specific delivered effects the owner was shown and
    /// releases only those: a pause or cutoff delivered later is not acknowledged by it.
    /// Attended: a local owner in an attended session, after the CLI's typed confirmation.
    /// An empty list, or an ID that is not a pause or cutoff this controller delivered to
    /// `environment`, is refused whole with effect `none`. Issuance for that runner resumes
    /// only when its authority report shows each lift as well; the acknowledgement alone
    /// reopens nothing. Kind `controller_record.resume_issuance`.
    ResumeIssuance {
        /// The runner environment.
        environment: EnvironmentId,
        /// The delivered effects the owner was shown and confirmed lifted (at least one).
        #[schemars(length(min = 1))]
        effects: Vec<EffectId>,
    },
}

impl ControllerRecordRequest {
    /// The operation-kind name.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            ControllerRecordRequest::PutEnvironment { .. } => "controller_record.put_environment",
            ControllerRecordRequest::RemoveEnvironment { .. } => {
                "controller_record.remove_environment"
            }
            ControllerRecordRequest::ResumeIssuance { .. } => "controller_record.resume_issuance",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::request::{Admission, Request};

    fn pin() -> RemoteEnvironmentPin {
        RemoteEnvironmentPin {
            environment: EnvironmentId::from_random_bytes([1; 16]),
            destination: DestinationId::parse("lab").unwrap(),
            route: ManagementRoute {
                runner: ManagementHop {
                    hostname: "10.0.0.2".into(),
                    port: None,
                    account: AccountName::parse("runner").unwrap(),
                    host_keys: vec!["ssh-ed25519 AAAA".into()],
                },
                jump: None,
            },
            client: ClientId::from_random_bytes([2; 16]),
            role: Role::Owner,
            key_fingerprint: KeyFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap(),
            label: None,
            pinned_at: "2026-11-21T12:00:00Z".parse().unwrap(),
        }
    }

    /// ADR-0006 §18.7 item 6: the wire forms, their kinds and classification (synchronous,
    /// no operation row; not attended-only); the record's shape omits empty fields.
    #[test]
    fn controller_record_wire_forms() {
        let put =
            Request::ControllerRecord(ControllerRecordRequest::PutEnvironment { record: pin() });
        let v = serde_json::to_value(&put).unwrap();
        assert_eq!(v["op"], "controller_record");
        assert_eq!(v["action"], "put_environment");
        assert!(v["record"].get("label").is_none());
        assert!(v["record"]["route"].get("jump").is_none());
        assert!(v["record"]["route"]["runner"].get("port").is_none());
        let back: Request = serde_json::from_value(v).unwrap();
        assert_eq!(back, put);
        assert_eq!(put.kind(), "controller_record.put_environment");
        assert_eq!(put.admission(), Admission::Synchronous);
        assert!(!put.requires_attended_session());
        let remove: Request = serde_json::from_str(&format!(
            r#"{{"op":"controller_record","action":"remove_environment","environment":"{}"}}"#,
            EnvironmentId::from_random_bytes([1; 16]).as_str()
        ))
        .unwrap();
        assert_eq!(remove.kind(), "controller_record.remove_environment");
        assert_eq!(remove.admission(), Admission::Synchronous);
        assert!(remove.is_revision_6());
        // ⟨rev6.4; ADR-0006 §18.8 item 4⟩
        let effect = EffectId::from_random_bytes([3; 16]);
        let resume: Request = serde_json::from_str(&format!(
            r#"{{"op":"controller_record","action":"resume_issuance","environment":"{}","effects":["{}"]}}"#,
            EnvironmentId::from_random_bytes([1; 16]).as_str(),
            effect.as_str()
        ))
        .unwrap();
        assert_eq!(
            resume,
            Request::ControllerRecord(ControllerRecordRequest::ResumeIssuance {
                environment: EnvironmentId::from_random_bytes([1; 16]),
                effects: vec![effect],
            })
        );
        // The effects are required: the environment alone is no acknowledgement.
        assert!(
            serde_json::from_str::<Request>(&format!(
                r#"{{"op":"controller_record","action":"resume_issuance","environment":"{}"}}"#,
                EnvironmentId::from_random_bytes([1; 16]).as_str()
            ))
            .is_err()
        );
        assert_eq!(resume.kind(), "controller_record.resume_issuance");
        assert_eq!(resume.admission(), Admission::Synchronous);
        assert!(resume.is_revision_6());
    }
}
