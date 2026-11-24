//! ⟨rev7⟩ Typed event payloads as emitted (ADR-0013 §5.1, D5).
//!
//! [`EventPayload`] is the discriminated form of an event's `type` and `payload`: one variant
//! per [`EventType`](crate::event::EventType), each holding every key its emission sites
//! write, with optional keys (`?`, absent on some forms) and nullable keys (`|null`, written as
//! JSON `null`) kept apart. It was derived from every emission site
//! (`tests/contracts/golden/event-emission-sites.json`, checked by
//! `event_payload_schema_covers_every_emission_site`) and the replay corpus
//! (`stored_samples_replay_through_revision_7_readers`). **Declared:** [`Event::payload`]
//! stays a `serde_json::Value`, so no published schema of a live document changes; a reader
//! decodes with [`EventPayload::decode`]. Persisted payloads are unchanged (D9): a nullable key
//! serializes as `null`, an optional key is omitted when absent.
//!
//! Open value sets (an operation kind, a decision kind, a reason) are strings: a reader treats
//! a value it does not know as opaque, and an event type it does not know is skipped
//! (ADR-0013 §3.2).
//!
//! [`Event::payload`]: crate::event::Event::payload

use serde::{Deserialize, Deserializer, Serialize};

use crate::Timestamp;
use crate::code::Code;
use crate::envelope::EffectStatus;
use crate::ids::{DecisionId, GrantId, OperationId, PolicyId};
use crate::state::{GrantState, OperationState};

/// A key that may be absent (`None`) or present and `null` (`Some(None)`).
fn present<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

/// `operation_state_changed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OperationStateChanged {
    /// The operation's kind (`ensure`, `setup.apply`, `enrollment.verify`, …).
    pub kind: String,
    /// Its new state.
    pub state: OperationState,
    /// Its code, `null` while it has none.
    #[serde(default)]
    pub code: Option<Code>,
    /// Its effect status. Every emission site writes a value; a `null` reads as absent.
    #[serde(default)]
    pub effect_status: Option<EffectStatus>,
}

/// `grant_state_changed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GrantStateChanged {
    /// The grant.
    pub grant_id: GrantId,
    /// Its new state.
    pub state: GrantState,
    /// Why it is degraded (`mechanism_unavailable`, `credential_reissue_pending`,
    /// `pair_unenrolled`); present only on a degraded grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `decision`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecisionChanged {
    /// The decision. Always stored; absent from what a paired reader receives (its
    /// delivery removes every `decision_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<DecisionId>,
    /// The decision's kind (`approve_authority`, `widen_policy`, `confirm_time`, …).
    pub kind: String,
    /// Its new state (`pending`, `approved`, `denied`, `expired`, `stale`, `withdrawn`).
    pub state: String,
    /// When it lapses.
    pub expires_at: Timestamp,
}

/// `policy_changed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicyChanged {
    /// The policy.
    pub policy_id: PolicyId,
    /// Its new revision.
    pub revision: u64,
    /// Whether it is paused.
    pub paused: bool,
    /// Its cutoff, `null` when it has none.
    #[serde(default)]
    pub cutoff_at: Option<Timestamp>,
}

/// `credential_lifecycle`: one of `expired`, `revoked_locally`, `authority_withdrawn`,
/// `reserved` / `published` / `voided` (an issuance), `installed` / `destroyed` /
/// `reissued` / `lost` (a credential instance), told apart by `event`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CredentialLifecycle {
    /// The grant.
    pub grant_id: GrantId,
    /// What happened.
    pub event: String,
    /// Why (`revoked_locally`, `authority_withdrawn`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    /// The grants ended with it (`authority_withdrawn`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cascade: Option<Vec<GrantId>>,
    /// Whether the local effect applied (`authority_withdrawn`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_applied: Option<bool>,
    /// The grants whose remote effect is pending (`authority_withdrawn`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_pending: Option<Vec<GrantId>>,
    /// The latest instant a credential already issued may still be valid
    /// (`authority_withdrawn`; `null` when none can be).
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub latest_possible_credential_expiry: Option<Option<Timestamp>>,
    /// The issuance (`reserved`, `published`, `voided`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance_id: Option<String>,
    /// The credential instance (`installed`, `destroyed`, `reissued`, `lost`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_instance_id: Option<String>,
}

/// `resource_changed`: a declaration (`declaration_revision`, `change: declared`), a
/// projection item (`item`, `generation`, `change`), or a supervised resource
/// (`resource_id`, `kind`, `generation`, `outcome`, `code|null`, `attempts`; no `change`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResourceChanged {
    /// What changed (`declared`, `applied`, `rolled_back`, `repaired`, `restored`, `held`,
    /// `conflict`); absent on a supervised resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<String>,
    /// The declaration's revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration_revision: Option<u64>,
    /// The projection item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// The projection generation, or a supervised resource's generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    /// A supervised resource's ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    /// A supervised resource's kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// A supervised resource's outcome (`deleted`, `cleanup_failed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// A supervised resource's code, `null` when none.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub code: Option<Option<Code>>,
    /// A supervised resource's attempts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u64>,
}

/// `runtime_lifecycle`: `started` (the counts) or `unresolved` (one operation's report).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RuntimeLifecycle {
    /// `started` or `unresolved`.
    pub phase: String,
    /// Operations open at start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_operations: Option<u64>,
    /// Operations unresolved at start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unresolved_operations: Option<u64>,
    /// The unresolved operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    /// Its kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Its state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<OperationState>,
    /// Why it is unresolved (an open set: any operation's reason).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `resync_required` (on the wire only; never stored).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResyncRequired {
    /// Why (`subscriber_lagged`, `history_trimmed`, `event_too_large`).
    pub reason: String,
    /// Events dropped (`subscriber_lagged`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<u64>,
    /// Whether the stream ends after it. Revision 7: every gap ends the stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_ended: Option<bool>,
}

/// An event's `type` and `payload`, typed (ADR-0013 §5.1). The wire form is the event's own
/// pair of keys: `{"type": "<event type>", "payload": {…}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventPayload {
    /// `operation_state_changed`.
    OperationStateChanged(OperationStateChanged),
    /// `grant_state_changed`.
    GrantStateChanged(GrantStateChanged),
    /// `policy_changed`.
    PolicyChanged(PolicyChanged),
    /// `resource_changed`.
    ResourceChanged(ResourceChanged),
    /// `credential_lifecycle`.
    CredentialLifecycle(CredentialLifecycle),
    /// `decision`.
    Decision(DecisionChanged),
    /// `resync_required`.
    ResyncRequired(ResyncRequired),
    /// `runtime_lifecycle`.
    RuntimeLifecycle(RuntimeLifecycle),
    /// `enrollment`.
    Enrollment(crate::managed::EnrollmentEventPayload),
    /// `connection`.
    Connection(crate::managed::ConnectionEventPayload),
    /// `session_lock`.
    SessionLock(crate::managed::SessionLockEventPayload),
    /// `activation`.
    Activation(crate::trust::ActivationEventPayload),
    /// `environment` (declared by revision 6; no emitter yet).
    Environment(crate::remote::EnvironmentEventPayload),
    /// `client`.
    Client(crate::remote::ClientEventPayload),
    /// `device` (declared by revision 6; no emitter yet).
    Device(crate::remote::DeviceEventPayload),
    /// `remote_effect` (declared by revision 6; no emitter yet).
    RemoteEffect(crate::remote::RemoteEffectEventPayload),
    /// `route`.
    Route(crate::route::RouteHealthPayload),
}

impl EventPayload {
    /// Decode an event's `type` and `payload`.
    ///
    /// # Errors
    ///
    /// When the payload does not have its type's shape (an unknown event type is an error
    /// here; a reader that only skips unknown types checks the type first).
    pub fn decode(event: &crate::event::Event) -> Result<Self, serde_json::Error> {
        serde_json::from_value(serde_json::json!({
            "type": event.event_type,
            "payload": event.payload,
        }))
    }

    /// The event type this payload is of.
    #[must_use]
    pub fn event_type(&self) -> crate::event::EventType {
        use crate::event::EventType as T;
        match self {
            EventPayload::OperationStateChanged(_) => T::OperationStateChanged,
            EventPayload::GrantStateChanged(_) => T::GrantStateChanged,
            EventPayload::PolicyChanged(_) => T::PolicyChanged,
            EventPayload::ResourceChanged(_) => T::ResourceChanged,
            EventPayload::CredentialLifecycle(_) => T::CredentialLifecycle,
            EventPayload::Decision(_) => T::Decision,
            EventPayload::ResyncRequired(_) => T::ResyncRequired,
            EventPayload::RuntimeLifecycle(_) => T::RuntimeLifecycle,
            EventPayload::Enrollment(_) => T::Enrollment,
            EventPayload::Connection(_) => T::Connection,
            EventPayload::SessionLock(_) => T::SessionLock,
            EventPayload::Activation(_) => T::Activation,
            EventPayload::Environment(_) => T::Environment,
            EventPayload::Client(_) => T::Client,
            EventPayload::Device(_) => T::Device,
            EventPayload::RemoteEffect(_) => T::RemoteEffect,
            EventPayload::Route(_) => T::Route,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn round(v: serde_json::Value) -> serde_json::Value {
        let p: EventPayload = serde_json::from_value(v).unwrap();
        serde_json::to_value(&p).unwrap()
    }

    /// Nullable keys stay `null`, optional keys stay absent, and a present `null` is kept
    /// apart from an absent key: the persisted bytes round-trip.
    #[test]
    fn nullable_and_optional_keys_round_trip_as_written() {
        for v in [
            serde_json::json!({"type": "operation_state_changed", "payload":
                {"kind": "ensure", "state": "running", "code": null, "effect_status": "none"}}),
            serde_json::json!({"type": "policy_changed", "payload":
                {"policy_id": "pol", "revision": 2, "paused": false, "cutoff_at": null}}),
            serde_json::json!({"type": "credential_lifecycle", "payload":
                {"grant_id": "grant_00000000000000000000000000000001", "event": "authority_withdrawn",
                 "cause": "revoked", "cascade": [], "local_applied": true, "remote_pending": [],
                 "latest_possible_credential_expiry": null}}),
            serde_json::json!({"type": "credential_lifecycle", "payload":
                {"grant_id": "grant_00000000000000000000000000000001", "event": "expired"}}),
            serde_json::json!({"type": "resource_changed", "payload":
                {"resource_id": "r1", "kind": "materialized_file", "generation": 3,
                 "outcome": "deleted", "code": null, "attempts": 1}}),
            serde_json::json!({"type": "resync_required", "payload":
                {"reason": "subscriber_lagged", "dropped": 7}}),
        ] {
            assert_eq!(round(v.clone()), v);
        }
    }

    #[test]
    fn every_event_type_has_a_payload_variant() {
        use crate::event::EventType as T;
        let all = [
            T::OperationStateChanged,
            T::GrantStateChanged,
            T::PolicyChanged,
            T::ResourceChanged,
            T::CredentialLifecycle,
            T::Decision,
            T::ResyncRequired,
            T::RuntimeLifecycle,
            T::Enrollment,
            T::Connection,
            T::SessionLock,
            T::Activation,
            T::Environment,
            T::Client,
            T::Device,
            T::RemoteEffect,
            T::Route,
        ];
        let schema = serde_json::to_value(schemars::schema_for!(EventPayload)).unwrap();
        let text = schema.to_string();
        for t in all {
            let name = serde_json::to_value(t).unwrap();
            assert!(text.contains(&format!("{name}")), "{t:?}");
        }
    }
}
