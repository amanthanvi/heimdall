//! ⟨rev6.5⟩ The typed parts of a decision document (ADR-0006 §3.1, §18.9 item 8).
//!
//! `inspect decisions` returns each pending record as a view whose `request` is the
//! record's own content. Most kinds stay untyped there. Revision 6.5 types two parts and
//! publishes a schema for each, so neither is a code-only field:
//!
//! * [`RemoteWidening`], the `request` of a `remote_widening` decision (schema
//!   `decision.remote-widening`), which gains [`WideningOrigin`];
//! * [`LiftedEffect`], one entry of a `widen_policy` decision's `lifted_effects` (schema
//!   `decision.lifted-effect`).
//!
//! Like every other document, both tolerate unknown fields and omit what is empty or
//! default, so every document written before revision 6.5 reads unchanged.

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::ids::{ClientId, EffectId, KeyFingerprint, RequestId};

/// ⟨rev6.5; ADR-0006 §18.9 item 8⟩ Who submitted a widening record: a paired client over
/// its management session, or this installation's local owner in an attended session. It
/// is a field of its own, never a client ID that stands for the local owner (a controller
/// mints its own client ID, so any such value could be enrolled).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WideningOrigin {
    /// The installation's local owner (no paired client).
    Local,
    /// A paired client (the default: every record before revision 6.5 is one).
    #[default]
    Paired,
}

impl WideningOrigin {
    /// The stored token (`local`, `paired`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            WideningOrigin::Local => "local",
            WideningOrigin::Paired => "paired",
        }
    }

    /// Whether this is the default, [`WideningOrigin::Paired`] (omitted from the document).
    #[must_use]
    pub fn is_paired(&self) -> bool {
        matches!(self, WideningOrigin::Paired)
    }
}

/// ⟨M06⟩ W2: what a `remote_widening` decision record is bound to (ADR-0012 §3.10), and the
/// `request` of its decision view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RemoteWidening {
    /// ⟨rev6.5; ADR-0006 §18.9 item 8⟩ Who submitted it; omitted when `paired`.
    #[serde(default, skip_serializing_if = "WideningOrigin::is_paired")]
    pub origin: WideningOrigin,
    /// The paired client that submitted the request (from the bridge's argv, resolved by
    /// the role table; never a request field). Absent exactly when `origin` is `local`
    /// ([`RemoteWidening::origin_is_consistent`]; the store's CHECK constraint, migration
    /// 0013).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientId>,
    /// The request kind (`remote_environment.invite`, `route.add`, …).
    pub request_kind: String,
    /// The request's ID (the third part of the key).
    pub request_id: RequestId,
    /// The exact request, verbatim: approval runs this and nothing wider.
    pub request: crate::request::Request,
    /// ⟨M06-W0-R07⟩ For an invite: the exact key and role the approval enrolls,
    /// recomputed by the runner before the record existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite: Option<RemoteInviteBinding>,
    /// ⟨M06 W2, U56-Q6⟩ For an exposure widening (a transport or route form): the exact
    /// exposure delta the request applies, computed by the runtime when the record was
    /// created and shown with it. Approval executes only while the delta the request would
    /// apply is still exactly this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<serde_json::Value>,
}

impl RemoteWidening {
    /// Whether the origin and the client agree: a `paired` record names its client and a
    /// `local` one names none. A record that fails this is never stored, decided or run.
    #[must_use]
    pub fn origin_is_consistent(&self) -> bool {
        match self.origin {
            WideningOrigin::Local => self.client.is_none(),
            WideningOrigin::Paired => self.client.is_some(),
        }
    }
}

/// ⟨M06-W0-R07⟩ The key and role a runner-local invite decision enrolls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RemoteInviteBinding {
    /// The role the invited client will hold.
    pub role: crate::remote::Role,
    /// The receiving key, canonical OpenSSH public text (no comment).
    pub public_key: String,
    /// Its fingerprint, recomputed by the runner and equal to the confirmed one.
    pub key_fingerprint: KeyFingerprint,
}

/// ⟨rev6.5; ADR-0006 §18.9⟩ One delivered pause or cutoff that approving a targeted
/// `resume` or `clear_cutoff` record lifts on this runner, as the decision view shows it
/// (`lifted_effects`, omitted when the record lifts none).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LiftedEffect {
    /// The target the record's action names; `null` when the action names none.
    #[serde(default)]
    pub scope: Option<crate::trust::PolicyTarget>,
    /// The scope's canonical key (`all`, `profile:<id>`, `workspace:<id>`, `policy:<id>`).
    pub scope_key: String,
    /// `pause` or `cutoff`.
    pub kind: String,
    /// The controller (its paired client) that delivered the effect.
    pub controller: ClientId,
    /// That controller's revision number for the scope.
    pub revision: u64,
    /// The effect that delivered it.
    pub effect: EffectId,
    /// When the runner received it (the runner's clock).
    pub delivered_at: Timestamp,
}
