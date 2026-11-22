//! ⟨M06 U4b⟩ The second controller (ADR-0012 §8; m06-plan U4b; M06-T06).
//!
//! A runner may have several owner controllers. Each is its own device with its own K_mgmt
//! and its own K_ca; none shares a key or an issuer with another.
//!
//! * **Enrolment** ([`invite_second_owner`], §8 item 1): by invitation, like any client
//!   (§3.9), for the `owner` role. Creating the invitation is a widening the runner confirms
//!   locally; the new device joins with its own K_mgmt. This module only fixes the role and
//!   checks that the inviting device is itself an owner before anything is sent.
//! * **Narrowing** ([`narrow`], §8 item 2): either owner may deliver any typed narrowing
//!   effect (a grant revoke, a policy pause or cutoff), for any grant or policy of the
//!   runner, whoever issued or decided it. Each controller's effects are keyed by its own
//!   client, so two controllers' effects never collide.
//! * **Issuance and renewal** ([`issuer_standing`], §8 item 3): only by a grant's issuing
//!   controller, after the reconciliation barrier
//!   ([`crate::remote_status_barrier::IssuerBarrier`]). A controller with no issuer of its
//!   own cannot renew anything (`CAPABILITY_UNAVAILABLE`); a grant pinned to another
//!   controller or CA is not this controller's to issue for (`issuer_untrusted`). If the
//!   issuing controller is gone its grants run to their bounds.
//! * **A separate grant for the second controller** is a widening confirmed at the runner,
//!   only after a runner-local `issuer_trust` change (`heimdall remote issuer-trust add`):
//!   the runner refuses to prepare an unpinned grant for a controller whose CA it does not
//!   trust, and never re-pins a grant. Nothing here can do either remotely.

use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::controller_record::RemoteEnvironmentPin;
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::ids::{CaFingerprint, ClientId, EnvironmentId, KeyFingerprint, RequestId};
use heimdall_contract::remote::Role;
use heimdall_store::Txn;
use heimdall_store::ext_effects::EffectKey;

use crate::error::OpError;
use crate::remote_env::{InviteInput, InviteOutcome, RemoteEnvController};
use crate::remote_status::{Narrowing, produce_effect};

fn refused(message: &str, why: &str) -> OpError {
    OpError::new(Code::CapabilityUnavailable, message)
        .with_reason(why)
        .with_effect(EffectStatus::None)
}

/// The invitation of a second owner: the `owner` role for the receiving key. The request ID
/// is the idempotency key: repeat it after the runner-local confirmation to read the result.
#[must_use]
pub fn owner_invitation(
    environment: EnvironmentId,
    public_key: String,
    key_fingerprint: KeyFingerprint,
    request_id: RequestId,
    iroh_admission: bool,
) -> InviteInput {
    InviteInput {
        environment,
        role: Role::Owner,
        public_key,
        key_fingerprint,
        request_id,
        iroh_admission,
    }
}

/// Invite a second owner controller to the runner (module docs, "Enrolment"). The inviting
/// device must itself be an owner there; the runner confirms the invitation locally and
/// checks the role again.
///
/// # Errors
///
/// `CAPABILITY_UNAVAILABLE` / `role_insufficient` when this device is not an owner on that
/// runner or the input names another role (nothing sent); otherwise
/// [`RemoteEnvController::invite`]'s.
pub async fn invite_second_owner(
    controller: &RemoteEnvController<'_>,
    input: &InviteInput,
) -> Result<InviteOutcome, OpError> {
    if input.role != Role::Owner {
        return Err(refused(
            "a second controller is enrolled as an owner",
            reason::ROLE_INSUFFICIENT,
        ));
    }
    let status = controller.status(Some(&input.environment))?;
    let is_owner = status
        .environments
        .iter()
        .any(|e| e.record.environment == input.environment && e.record.role == Role::Owner);
    if !is_owner {
        return Err(refused(
            "only an owner of the runner may invite another controller",
            reason::ROLE_INSUFFICIENT,
        ));
    }
    controller.invite(input).await
}

/// Produce a typed narrowing effect for the runner `pin` names (module docs, "Narrowing"):
/// any grant or policy of the runner, whichever controller issued or decided it.
///
/// # Errors
///
/// As [`produce_effect`].
pub fn narrow(
    tx: &mut Txn<'_>,
    pin: &RemoteEnvironmentPin,
    narrowing: &Narrowing,
    now: Timestamp,
) -> heimdall_store::Result<Result<EffectKey, OpError>> {
    produce_effect(tx, pin, narrowing, now)
}

/// Where this controller stands as the issuer of one runner grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerStanding {
    /// The grant is pinned to this controller and its CA: it may renew, after the barrier.
    Pinned,
    /// The grant has no pin yet: this controller may issue its first certificate only if
    /// the runner trusts its CA (the runner decides; a runner-local `issuer_trust` change).
    Unpinned,
}

/// Whether this controller may act as the issuer of a runner grant (module docs, "Issuance
/// and renewal"). `own_ca` is this controller's active CA, when it has an issuer; `grant_pin`
/// the grant's pin as the runner reported it (its issuing client and CA), when it has one.
///
/// # Errors
///
/// `CAPABILITY_UNAVAILABLE`: with `role_insufficient` for a device that is not an owner;
/// with no reason for a controller without an issuer (it can never renew); with
/// `issuer_untrusted` for a grant pinned to another controller or to another CA.
pub fn issuer_standing(
    pin: &RemoteEnvironmentPin,
    own_ca: Option<&CaFingerprint>,
    grant_pin: Option<(&ClientId, &CaFingerprint)>,
) -> Result<IssuerStanding, OpError> {
    if pin.role != Role::Owner {
        return Err(refused(
            "only an owner controller issues for a runner's grants",
            reason::ROLE_INSUFFICIENT,
        ));
    }
    let Some(own_ca) = own_ca else {
        return Err(OpError::new(
            Code::CapabilityUnavailable,
            "this controller has no issuer: it cannot issue or renew; the grant runs to its \
             bounds",
        )
        .with_effect(EffectStatus::None));
    };
    match grant_pin {
        None => Ok(IssuerStanding::Unpinned),
        Some((client, ca)) if *client == pin.client && ca == own_ca => Ok(IssuerStanding::Pinned),
        Some(_) => Err(refused(
            "the grant is pinned to another issuing controller or CA: only its issuer renews \
             it; a grant from this controller is a separate grant, approved at the runner",
            reason::ISSUER_UNTRUSTED,
        )),
    }
}
