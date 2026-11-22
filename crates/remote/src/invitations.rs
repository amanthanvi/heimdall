//! Invitations and client revocation (ADR-0012 §3.9, §3.11; M06 U1).
//!
//! **The pending record** ([`pending_records`]) is `{invitation ID, cid, role, receiving key
//! fingerprint, created_wall, created_boot_id, created_elapsed, expires_wall ≤ created +
//! 15 min, generation}`, with the activation probe's nonce. It is created only on a checked
//! (`Safe`) time reading, for a key whose fingerprint equals the one the owner confirmed,
//! and, for a limited role, only on a runner whose sshd policy is verified
//! (`management_sshd_unverified`). Creating it is a widening, confirmed runner-locally
//! (§3.10): [`Invitations::invite`] is the executor of that decision, never a remote path.
//!
//! **Expiry never extends** ([`liveness`]). An invitation is live only while **both** the
//! checked wall clock is before `expires_wall` and, under the boot anchor it was created
//! in, the continuous clock shows less than `expires_wall − created_wall` elapsed. An
//! unchecked wall clock (`TIME_UNCERTAIN`), an unreadable anchor or a reboot refuses
//! (`invitation_expired`); a wall-clock rollback cannot help because the elapsed bound
//! still runs out.
//!
//! **`join` is a compare-and-set** ([`decide_join`], [`Invitations::join`]): identity first
//! (the cid from the bridge's argv, the invitation ID, and the key fingerprint on the cid's
//! line), and a mismatch says nothing about the record; then, for a pending record, the
//! environment, role and generation, and liveness **at join time**; then `pending → active`
//! in one transaction. A retried join returns the recorded result only after the same
//! identity check.
//!
//! **Ordering and recovery.** The database transition commits first; only then is the line
//! rewritten (without `expiry-time` once active, or removed once revoked or expired), and
//! [`Invitations::reconcile`] makes every line match the database idempotently. A crash
//! between the commit and the rewrite leaves the pending line's `expiry-time` in place,
//! which fails closed. Consumed, expired and revoked records stay refused whatever the
//! line says, because every session is checked against the database ([`crate::roles`]).
//! Ordinary connections of an active client consume nothing.
//!
//! **Line writes are serialized and re-read the row** (⟨M06 W1 review⟩): every line write
//! takes the runner's [`LineSerial`], re-reads the client's row and invitation **under it**,
//! and writes only what that row asks for. A revocation commits its tombstone first and then
//! removes the line under the same lock, so an in-flight reconcile either finished before the
//! removal (which then removes its line) or re-reads the tombstone (and writes nothing): a
//! revoked client never ends with a line.
//!
//! **Join re-checks time at its commit point** (⟨M06 W1 review⟩): the caller's checked sample
//! may be older than the commit (the line read can block), so inside the transaction the
//! join re-reads the boot anchor from [`Invitations::clock`] and advances the checked wall
//! clock by the continuous time elapsed since the sample ([`at_commit`]); both bounds are
//! evaluated on that reading, and an invitation that expired meanwhile never commits.
//! ⟨2026-11-21, ruling 2; ADR-0012 §3.9 item 5⟩ The wall deadline is judged on the **upper**
//! bound of now: the gate-checked time plus the tolerance the gate accepted it with
//! ([`TimeReading::slack`]), advanced by the elapsed reading of the process's continuous,
//! suspend-inclusive clock (Linux `CLOCK_BOOTTIME`). A backwards reading, another boot, or
//! an unavailable boot anchor (the platform's `unavailable:` sentinel) leaves the commit
//! uncertain, which refuses (`invitation_expired`).
//!
//! **The admission generation** (⟨M06 W3; m06-plan U56, ruling W0C-Q4⟩): an invitation records
//! the runner's admission authority generation current at its creation, and `join` commits
//! only while it is still current, so any narrowing in between (a revocation, a transport
//! disable, an endpoint replacement…) refuses the join (`invitation_expired`).
//!
//! **Iroh endpoints** (⟨M06 W3; ADR-0006 §18.7 items 2–4⟩): `join` records the client's own
//! endpoint ID in its commit transaction only when the invitation has `iroh_admission`, and
//! refuses it otherwise ([`Refusal::InvalidRequest`], effect `none`); [`rotate_endpoint`] sets or
//! replaces an active client's own row under the same condition.

use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    ClientId, EnvironmentId, InvitationId, IrohEndpointId, KeyFingerprint,
};
use heimdall_contract::remote::{
    ManagementPolicy, ProbeObservation, RemoteEnvironmentRequest, Role,
};
use heimdall_contract::request::Request;
use heimdall_domain::time::{BootId, Clock, TimeAnchor};
use heimdall_store::Store;
use heimdall_store::ext_m06::{
    AppliedLine, ClientState, EndpointChange, InvitationState, JoinRecord, RemoteClientRecord,
    RemoteInvitationRecord, RevocationCause,
};

use crate::line::{
    DesiredLine, ManagementLine, ManagementLines, PublicKeyText, ServeCommand,
    key_already_authorized, line_fingerprint, marked_lines,
};
use crate::roles::Refusal;
use crate::sshd_policy::limited_role_gate;

/// The longest an invitation may live (ADR-0012 §3.9 item 2).
pub const MAX_INVITATION_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// The boot anchor part of a reading: the boot and the continuous clock in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootReading {
    /// The current boot.
    pub boot_id: BootId,
    /// The continuous clock in it.
    pub continuous: Duration,
}

/// The prefix of the per-process boot ID a platform clock reports when the boot identifier
/// is unreadable (`heimdall_runtime::platform`): such an anchor is unavailable, never a boot.
pub const UNAVAILABLE_BOOT_PREFIX: &str = "unavailable:";

/// ⟨M06-W2-R01; ADR-0012 §3.9 item 5⟩ The gate's step tolerance: how far the wall clock read
/// at a commit point may be behind the projection of the gate-checked time before the commit
/// is `TIME_UNCERTAIN` (`TimePolicy::default().max_tolerated_rollback`, the policy the
/// runner's gate runs with; a test holds the two equal).
pub const WALL_STEP_TOLERANCE: Duration = Duration::from_secs(5);

/// A time reading for the invitation rules. The runtime builds it from the shared time
/// gate: `checked_wall` is set only when the gate assessed the observation `Safe`
/// (ADR-0006 §10), and `boot` only when the boot ID and continuous clock were readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeReading {
    /// The wall clock, when checked `Safe`: the **lower** bound of now (the accepted wall
    /// time may lag the truth by [`Self::slack`]).
    pub checked_wall: Option<Timestamp>,
    /// The boot anchor, when readable.
    pub boot: Option<BootReading>,
    /// ⟨2026-11-21, ruling 2⟩ How far the truth may exceed `checked_wall` (the gate's
    /// `tolerance_used`): deadlines are judged on `checked_wall + slack`, the upper bound.
    pub slack: Duration,
    /// ⟨M06-W2-R01⟩ Set only by [`at_commit`]: the wall clock read at the commit point was
    /// behind the projection by more than [`WALL_STEP_TOLERANCE`]. `checked_wall` is then
    /// `None`, and a join answers `TIME_UNCERTAIN`.
    pub wall_stepped_back: bool,
}

impl TimeReading {
    /// A `Safe` gate observation (`heimdall_app::SafeNow::anchor`) with no tolerance.
    #[must_use]
    pub fn safe(anchor: &TimeAnchor) -> Self {
        Self::safe_within(anchor, Duration::ZERO)
    }

    /// A `Safe` gate observation accepted with `tolerance` (`heimdall_app::SafeNow::
    /// tolerance_used`): the truth lies in `[anchor.wall, anchor.wall + tolerance]`.
    #[must_use]
    pub fn safe_within(anchor: &TimeAnchor, tolerance: Duration) -> Self {
        Self {
            checked_wall: Some(anchor.wall),
            boot: Some(BootReading {
                boot_id: anchor.boot_id.clone(),
                continuous: anchor.continuous,
            }),
            slack: tolerance,
            wall_stepped_back: false,
        }
    }

    /// An uncertain wall clock (`TIME_UNCERTAIN`), with the boot anchor when readable.
    #[must_use]
    pub fn uncertain(boot: Option<BootReading>) -> Self {
        Self {
            checked_wall: None,
            boot,
            slack: Duration::ZERO,
            wall_stepped_back: false,
        }
    }

    fn safe_parts(&self) -> Option<(Timestamp, &BootReading)> {
        Some((self.checked_wall?, self.boot.as_ref()?))
    }

    /// The upper bound of now (`checked_wall + slack`), when checked; an overflow fails
    /// closed as "past every deadline".
    fn upper_wall(&self) -> Option<Timestamp> {
        let wall = self.checked_wall?;
        Some(
            jiff::SignedDuration::try_from(self.slack)
                .ok()
                .and_then(|d| wall.checked_add(d).ok())
                .unwrap_or(Timestamp::MAX),
        )
    }
}

/// Whether an invitation is live at a reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// Both bounds hold on checked time in the creation boot.
    Live,
    /// Not live now (time uncertain or the anchor unreadable), but not known to have
    /// passed: refused, not tombstoned.
    Undetermined,
    /// Definitely past: another boot, the elapsed bound passed, the checked wall deadline
    /// passed, or the continuous clock went backwards.
    Expired,
}

/// The liveness rule (module docs, "Expiry never extends").
#[must_use]
pub fn liveness(inv: &RemoteInvitationRecord, now: &TimeReading) -> Liveness {
    let same_boot = now
        .boot
        .as_ref()
        .filter(|b| b.boot_id == inv.created_boot_id);
    let other_boot = now
        .boot
        .as_ref()
        .is_some_and(|b| b.boot_id != inv.created_boot_id);
    let elapsed_passed = same_boot.is_some_and(|b| {
        b.continuous
            .checked_sub(inv.created_elapsed)
            .is_none_or(|elapsed| elapsed >= inv.elapsed_bound)
    });
    // ⟨2026-11-21, ruling 2⟩ The upper bound of now.
    let wall_passed = now.upper_wall().is_some_and(|w| w >= inv.expires_wall);
    if other_boot || elapsed_passed || wall_passed {
        return Liveness::Expired;
    }
    match now.safe_parts() {
        Some((_, b)) if b.boot_id == inv.created_boot_id => Liveness::Live,
        _ => Liveness::Undetermined,
    }
}

/// What the owner confirmed for a new invitation.
#[derive(Debug, Clone, Copy)]
pub struct NewInvitation<'a> {
    /// The role.
    pub role: Role,
    /// The receiving public key (OpenSSH public text).
    pub public_key: &'a str,
    /// The fingerprint the owner confirmed against the new device's display.
    pub key_fingerprint: &'a KeyFingerprint,
    /// The lifetime, clamped to 1 s ..= [`MAX_INVITATION_LIFETIME`].
    pub lifetime: Duration,
    /// ⟨M06 W3⟩ Whether the client may reach this runner over Iroh (`Invite.
    /// iroh_admission`, confirmed with the rest of the invitation).
    pub iroh_admission: bool,
}

/// The runner-minted identifiers of a new invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedIds {
    /// The invitation.
    pub invitation: InvitationId,
    /// The client.
    pub client: ClientId,
    /// The probe nonce (32 lowercase hex, nonsecret).
    pub probe_nonce: String,
}

impl MintedIds {
    /// Mint from the operating system's CSPRNG.
    ///
    /// # Errors
    ///
    /// [`Refusal::State`] when randomness is unavailable.
    pub fn random() -> Result<Self, Refusal> {
        let mut b = [0u8; 48];
        getrandom::fill(&mut b).map_err(|_| Refusal::State)?;
        let mut inv = [0u8; 16];
        let mut cl = [0u8; 16];
        inv.copy_from_slice(&b[..16]);
        cl.copy_from_slice(&b[16..32]);
        Ok(Self {
            invitation: InvitationId::from_random_bytes(inv),
            client: ClientId::from_random_bytes(cl),
            probe_nonce: b[32..].iter().map(|x| format!("{x:02x}")).collect(),
        })
    }
}

/// Build the pending client and invitation (module docs, "The pending record").
///
/// # Errors
///
/// `management_sshd_unverified` for a limited role on an `owner_only` runner;
/// `TIME_UNCERTAIN` without a checked reading; `decision_binding_mismatch` when the key is
/// not one Ed25519 key whose fingerprint is the confirmed one.
pub fn pending_records(
    new: &NewInvitation<'_>,
    ids: MintedIds,
    now: &TimeReading,
    generation: u64,
    policy: ManagementPolicy,
) -> Result<(RemoteClientRecord, RemoteInvitationRecord), Refusal> {
    limited_role_gate(new.role, policy)?;
    let (wall, boot) = now.safe_parts().ok_or(Refusal::TimeUncertain)?;
    let key = PublicKeyText::parse(new.public_key).map_err(|_| Refusal::BindingMismatch)?;
    if &key.fingerprint() != new.key_fingerprint {
        return Err(Refusal::BindingMismatch);
    }
    let lifetime = new
        .lifetime
        .clamp(Duration::from_secs(1), MAX_INVITATION_LIFETIME);
    let span = jiff::SignedDuration::try_from(lifetime).map_err(|_| Refusal::State)?;
    let expires_wall = wall.checked_add(span).map_err(|_| Refusal::State)?;
    let client = RemoteClientRecord {
        client: ids.client.clone(),
        role: new.role,
        key_fingerprint: new.key_fingerprint.clone(),
        public_key: key.openssh(),
        state: ClientState::Pending,
        invitation: Some(ids.invitation.clone()),
        revoked_generation: None,
        revocation: None,
        created_at: wall,
        updated_at: wall,
        line: AppliedLine::Absent,
    };
    let invitation = RemoteInvitationRecord {
        invitation: ids.invitation,
        client: ids.client,
        role: new.role,
        key_fingerprint: new.key_fingerprint.clone(),
        generation,
        created_wall: wall,
        created_boot_id: boot.boot_id.clone(),
        created_elapsed: boot.continuous,
        expires_wall,
        elapsed_bound: lifetime,
        probe_nonce: ids.probe_nonce,
        state: InvitationState::Pending,
        consumed_at: None,
        join: None,
        iroh_admission: new.iroh_admission,
    };
    Ok((client, invitation))
}

/// A `join` request's fields (`RemoteEnvironmentRequest::Join`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    /// The runner environment the joining device confirmed.
    pub environment: EnvironmentId,
    /// The invitation.
    pub invitation: InvitationId,
    /// The role.
    pub role: Role,
    /// The generation.
    pub generation: u64,
    /// ⟨M06 W3⟩ The client's own Iroh endpoint ID, when it sent one.
    pub iroh_endpoint: Option<IrohEndpointId>,
    /// ⟨M06 W3; §18.7 item 16⟩ What the joining device's confirming probes observed, when it
    /// reported them.
    pub probe: Option<ProbeObservation>,
}

impl JoinRequest {
    /// The join fields of a request, when it is a `join`.
    #[must_use]
    pub fn from_request(request: &Request) -> Option<Self> {
        match request {
            Request::RemoteEnvironment(RemoteEnvironmentRequest::Join {
                environment,
                invitation,
                role,
                generation,
                iroh_endpoint,
                probe,
            }) => Some(Self {
                environment: environment.clone(),
                invitation: invitation.clone(),
                role: *role,
                generation: *generation,
                iroh_endpoint: iroh_endpoint.clone(),
                probe: *probe,
            }),
            _ => None,
        }
    }
}

/// The activation probe's fields (`RemoteEnvironmentRequest::ActivationProbe`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRequest {
    /// The runner environment the probing device names.
    pub environment: EnvironmentId,
    /// The pending record's nonce, echoed.
    pub nonce: String,
}

impl ProbeRequest {
    /// The probe fields of a request, when it is an activation probe.
    #[must_use]
    pub fn from_request(request: &Request) -> Option<Self> {
        match request {
            Request::RemoteEnvironment(RemoteEnvironmentRequest::ActivationProbe {
                environment,
                nonce,
            }) => Some(Self {
                environment: environment.clone(),
                nonce: nonce.clone(),
            }),
            _ => None,
        }
    }
}

/// ⟨M06 W3⟩ A rotation form's fields (`RemoteEnvironmentRequest::RotateEndpoint`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateRequest {
    /// The runner environment the client names.
    pub environment: EnvironmentId,
    /// The client's new endpoint ID.
    pub endpoint: IrohEndpointId,
}

impl RotateRequest {
    /// The rotation fields of a request, when it is a rotation form.
    #[must_use]
    pub fn from_request(request: &Request) -> Option<Self> {
        match request {
            Request::RemoteEnvironment(RemoteEnvironmentRequest::RotateEndpoint {
                environment,
                endpoint,
            }) => Some(Self {
                environment: environment.clone(),
                endpoint: endpoint.clone(),
            }),
            _ => None,
        }
    }
}

/// ⟨M06 W3⟩ What [`rotate_endpoint`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotated {
    /// The session's client.
    pub client: ClientId,
    /// Its endpoint ID now.
    pub endpoint: IrohEndpointId,
    /// Recorded, replaced (with the admission generation it moved to) or unchanged.
    pub change: EndpointChange,
}

/// ⟨M06 W3; ADR-0006 §18.7 item 4; ADR-0012 §2.3 item 1⟩ Set or replace the session's own
/// client's endpoint ID, in one transaction: only for an **active** client of **this**
/// runner that is admitted over Iroh (⟨§18.7 item 8⟩ the client's own attribute, copied from
/// its invitation at `join` or confirmed for the bootstrap owner at `remote init`), and only for an endpoint no other
/// client holds. A replacement moves the admission authority generation in the same
/// transaction; the same endpoint again is a no-op.
///
/// # Errors
///
/// [`Refusal::InvalidRequest`] for another environment, a client not admitted over Iroh,
/// or another client's endpoint;
/// `client_revoked` / `invitation_pending` for a client that is not active;
/// `STATE_UNAVAILABLE`.
pub fn rotate_endpoint(
    store: &Store,
    runner: &EnvironmentId,
    session: &ClientId,
    request: &RotateRequest,
    now: Timestamp,
) -> Result<Rotated, Refusal> {
    if &request.environment != runner {
        return Err(Refusal::InvalidRequest);
    }
    let change = store
        .transaction(|tx| {
            let Some(client) = tx.remote_client(session)? else {
                return Ok(Err(Refusal::ClientRevoked));
            };
            match client.state {
                ClientState::Active => {}
                ClientState::Pending => return Ok(Err(Refusal::InvitationPending)),
                ClientState::Revoked => return Ok(Err(Refusal::ClientRevoked)),
            }
            // ⟨§18.7 item 8⟩ The client's own attribute: copied from its invitation at
            // `join`, or confirmed for the bootstrap owner at `remote init`.
            if !tx.remote_client_iroh_admission(session)? {
                return Ok(Err(Refusal::InvalidRequest));
            }
            let taken = tx
                .remote_client_endpoints()?
                .iter()
                .any(|(c, held)| held == &request.endpoint && c != session);
            if taken {
                return Ok(Err(Refusal::InvalidRequest));
            }
            tx.set_remote_client_endpoint(session, &request.endpoint, now)
                .map(Ok)
        })
        .map_err(state_err)??;
    Ok(Rotated {
        client: session.clone(),
        endpoint: request.endpoint.clone(),
        change,
    })
}

/// What [`decide_join`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinDecision {
    /// Commit this join (`pending → active`).
    Activate(JoinRecord),
    /// Return the recorded result of the earlier join (identity checked).
    Replay(JoinRecord),
    /// Refuse.
    Refuse(Refusal),
}

/// What `join` reads in its transaction besides the records (module docs, "Join re-checks
/// time", "The admission generation", "Iroh endpoints").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinContext<'a> {
    /// This runner's environment.
    pub runner: &'a EnvironmentId,
    /// The commit point's time reading ([`at_commit`]).
    pub now: &'a TimeReading,
    /// The runner's admission authority generation now.
    pub generation: u64,
    /// The endpoint ID recorded for the session's client, if any.
    pub recorded_endpoint: Option<&'a IrohEndpointId>,
    /// Whether another client holds the request's endpoint ID.
    pub endpoint_taken: bool,
}

/// `join`'s pure decision over the records read in the join's transaction (module docs).
/// `line_fingerprint` is the key fingerprint on the session cid's line
/// ([`crate::line::line_fingerprint`]); `None` identifies nobody.
#[must_use]
pub fn decide_join(
    invitation: Option<&RemoteInvitationRecord>,
    client: Option<&RemoteClientRecord>,
    session: &ClientId,
    line_fingerprint: Option<&KeyFingerprint>,
    request: &JoinRequest,
    admission: JoinContext<'_>,
) -> JoinDecision {
    let (runner, now) = (admission.runner, admission.now);
    // 1. Identity, before anything about the record is used. A mismatch is the uniform
    // "not live" answer, whatever the record holds.
    let Some(inv) = invitation.filter(|inv| {
        inv.invitation == request.invitation
            && &inv.client == session
            && line_fingerprint == Some(&inv.key_fingerprint)
    }) else {
        return JoinDecision::Refuse(Refusal::InvitationExpired);
    };
    let client =
        client.filter(|c| &c.client == session && c.invitation.as_ref() == Some(&inv.invitation));
    let binding_matches = &request.environment == runner
        && request.role == inv.role
        && request.generation == inv.generation;
    // ⟨M06 W3; §18.7 item 3⟩ An endpoint the invitation did not admit is refused, first time
    // or retried, before anything is recorded.
    if request.iroh_endpoint.is_some() && !inv.iroh_admission {
        return JoinDecision::Refuse(Refusal::InvalidRequest);
    }
    match inv.state {
        InvitationState::Consumed => match (&inv.join, client) {
            (Some(j), Some(c)) if c.state == ClientState::Active => {
                // A retry replays only the join it repeats: an endpoint other than the one
                // recorded is not that join (the client rotates it instead).
                let same_endpoint = request
                    .iroh_endpoint
                    .as_ref()
                    .is_none_or(|e| admission.recorded_endpoint == Some(e));
                if binding_matches && &j.environment == runner && same_endpoint {
                    JoinDecision::Replay(j.clone())
                } else {
                    JoinDecision::Refuse(Refusal::InvitationConsumed)
                }
            }
            (_, Some(c)) if c.state == ClientState::Revoked => {
                JoinDecision::Refuse(Refusal::ClientRevoked)
            }
            _ => JoinDecision::Refuse(Refusal::InvitationConsumed),
        },
        InvitationState::Expired => JoinDecision::Refuse(Refusal::InvitationExpired),
        InvitationState::Revoked => JoinDecision::Refuse(Refusal::ClientRevoked),
        InvitationState::Pending => {
            let Some(c) = client.filter(|c| c.state == ClientState::Pending) else {
                return JoinDecision::Refuse(Refusal::InvitationExpired);
            };
            if !binding_matches || c.role != inv.role || c.key_fingerprint != inv.key_fingerprint {
                return JoinDecision::Refuse(Refusal::BindingMismatch);
            }
            if admission.endpoint_taken {
                return JoinDecision::Refuse(Refusal::InvalidRequest);
            }
            // ⟨M06 W3, ruling W0C-Q4⟩ Any narrowing since the invitation refuses the join.
            if admission.generation != inv.generation {
                return JoinDecision::Refuse(Refusal::InvitationExpired);
            }
            match (liveness(inv, now), now.checked_wall) {
                (Liveness::Live, Some(joined_at)) => JoinDecision::Activate(JoinRecord {
                    environment: runner.clone(),
                    invitation: inv.invitation.clone(),
                    client: session.clone(),
                    role: inv.role,
                    generation: inv.generation,
                    joined_at,
                }),
                // ⟨M06-W2-R01⟩ Not known to have expired, but the wall clock stepped back
                // at the commit point: uncertain time, not an expiry.
                (Liveness::Undetermined, _) if now.wall_stepped_back => {
                    JoinDecision::Refuse(Refusal::TimeUncertain)
                }
                _ => JoinDecision::Refuse(Refusal::InvitationExpired),
            }
        }
    }
}

/// A created invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invited {
    /// The pending client.
    pub client: RemoteClientRecord,
    /// The invitation.
    pub invitation: RemoteInvitationRecord,
    /// Whether its pending line was written (otherwise the reconciler writes it).
    pub line_written: bool,
}

/// A committed (or replayed) join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Joined {
    /// The recorded result.
    pub join: JoinRecord,
    /// A retried join returned the earlier result.
    pub replayed: bool,
    /// Whether the active line was written (otherwise the pending line's `expiry-time`
    /// stays until the reconciler rewrites it).
    pub line_written: bool,
}

/// A revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoked {
    /// The tombstone.
    pub client: RemoteClientRecord,
    /// Whether the line was removed (otherwise the reconciler removes it).
    pub line_removed: bool,
}

/// The activation probe's echo (ADR-0012 §3.2): the client ID from the bridge's argv and
/// the pending record's nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeEcho {
    /// The session's client (from argv, through the bridge's hello).
    pub client: ClientId,
    /// The invitation's nonce.
    pub nonce: String,
}

/// One reconciler pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Lines written or removed.
    pub changed: usize,
    /// Clients whose line could not be reconciled this pass.
    pub failed: usize,
}

fn state_err(_: heimdall_store::StoreError) -> Refusal {
    Refusal::State
}

/// The runner's check of a join that would activate ([`Invitations::join_confirmed`]): run
/// inside the join's commit transaction, which it may read and write.
pub type JoinCheck<'a> = dyn Fn(&mut heimdall_store::Txn<'_>, &JoinRecord) -> heimdall_store::Result<Result<(), Refusal>>
    + 'a;

/// The runner's line-write lock (module docs, "Line writes are serialized"): one per runner
/// (per store), shared by every [`Invitations`] over it.
#[derive(Debug, Default)]
pub struct LineSerial(std::sync::Mutex<()>);

impl LineSerial {
    fn hold(&self) -> std::sync::MutexGuard<'_, ()> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The time reading at a commit point (module docs, "Join re-checks time"): the sample's
/// checked wall clock advanced by the continuous time elapsed since the sample, in the
/// sample's boot, keeping the sample's slack (so deadlines see the upper bound of now).
///
/// ⟨M06-W2-R01; ADR-0012 §3.9 item 5⟩ **The projection is a floor.** The wall clock read at
/// the commit point (`now.wall`) can only move the reading later: the result's
/// `checked_wall` is the later of the projection and `now.wall`, so a forward wall step past
/// a deadline expires it at once. A wall clock behind the projection by more than
/// [`WALL_STEP_TOLERANCE`] is a backward step: the reading is uncertain with
/// [`TimeReading::wall_stepped_back`] set.
///
/// Uncertain also when the sample was, when the boot changed (liveness then sees another
/// boot), when either boot anchor is the platform's unavailable sentinel, or when the
/// continuous clock went backwards.
#[must_use]
pub fn at_commit(sample: &TimeReading, now: &TimeAnchor) -> TimeReading {
    let unavailable = now.boot_id.0.starts_with(UNAVAILABLE_BOOT_PREFIX);
    let fresh = BootReading {
        boot_id: now.boot_id.clone(),
        continuous: now.continuous,
    };
    if unavailable {
        return TimeReading::uncertain(None);
    }
    let (Some(wall), Some(boot)) = (sample.checked_wall, sample.boot.as_ref()) else {
        return TimeReading::uncertain(Some(fresh));
    };
    if boot.boot_id != now.boot_id || boot.boot_id.0.starts_with(UNAVAILABLE_BOOT_PREFIX) {
        return TimeReading::uncertain(Some(fresh));
    }
    let projected = now
        .continuous
        .checked_sub(boot.continuous)
        .and_then(|d| jiff::SignedDuration::try_from(d).ok())
        .and_then(|d| wall.checked_add(d).ok());
    let Some(projected) = projected else {
        return TimeReading::uncertain(Some(fresh));
    };
    let tolerance =
        jiff::SignedDuration::try_from(WALL_STEP_TOLERANCE).unwrap_or(jiff::SignedDuration::ZERO);
    if projected.duration_since(now.wall) > tolerance {
        return TimeReading {
            wall_stepped_back: true,
            ..TimeReading::uncertain(Some(fresh))
        };
    }
    TimeReading {
        checked_wall: Some(projected.max(now.wall)),
        boot: Some(fresh),
        slack: sample.slack,
        wall_stepped_back: false,
    }
}

/// ⟨2026-11-21, ruling 2; runner Q6⟩ The reading at a commit point from `clock`: [`at_commit`]
/// over one observation, or uncertain when the continuous clock is unavailable
/// (`Clock::try_continuous` is `None`), which a join refuses as `invitation_expired`. An
/// unavailable clock never reads as "no time elapsed".
fn commit_reading(sample: &TimeReading, clock: &dyn Clock) -> TimeReading {
    let Some(continuous) = clock.try_continuous() else {
        return TimeReading::uncertain(None);
    };
    let observed = clock.observe();
    // The later of the two readings: never less elapsed than the fallible one saw.
    let now = TimeAnchor {
        continuous: observed.continuous.max(continuous),
        ..observed
    };
    at_commit(sample, &now)
}

/// The invitation service over the store and the line port (module docs).
#[derive(Clone, Copy)]
pub struct Invitations<'a> {
    /// The state store.
    pub store: &'a Store,
    /// The authorized_keys port.
    pub lines: &'a dyn ManagementLines,
    /// This runner's environment ID.
    pub environment: &'a EnvironmentId,
    /// The forced command's paths.
    pub command: &'a ServeCommand,
    /// The clock a join re-reads at its commit point ([`at_commit`]).
    pub clock: &'a dyn Clock,
    /// The runner's line-write lock.
    pub serial: &'a LineSerial,
}

impl std::fmt::Debug for Invitations<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invitations")
            .field("environment", self.environment)
            .finish_non_exhaustive()
    }
}

impl Invitations<'_> {
    /// The line `client` should have now (none for a revoked client, or a pending one whose
    /// invitation is no longer pending or has expired; a record whose key does not render
    /// gets none, failing closed).
    ///
    /// # Errors
    ///
    /// [`Refusal::State`].
    pub fn desired_line(
        &self,
        client: &RemoteClientRecord,
        now: &TimeReading,
    ) -> Result<DesiredLine, Refusal> {
        let expiry = match client.state {
            ClientState::Revoked => return Ok(DesiredLine::Absent),
            ClientState::Active => None,
            ClientState::Pending => {
                let Some(inv_id) = &client.invitation else {
                    return Ok(DesiredLine::Absent);
                };
                let inv = self
                    .store
                    .transaction(|tx| tx.remote_invitation(inv_id))
                    .map_err(state_err)?;
                match inv {
                    Some(inv)
                        if inv.state == InvitationState::Pending
                            && liveness(&inv, now) != Liveness::Expired =>
                    {
                        Some(inv.expires_wall)
                    }
                    _ => return Ok(DesiredLine::Absent),
                }
            }
        };
        let Ok(key) = PublicKeyText::parse(&client.public_key) else {
            return Ok(DesiredLine::Absent);
        };
        let line = ManagementLine {
            client: client.client.clone(),
            command: self.command.clone(),
            key,
            expiry,
        };
        Ok(line
            .render()
            .map_or(DesiredLine::Absent, DesiredLine::Present))
    }

    /// Reconcile one client's line and record the result: `None` when the port failed
    /// (the reconciler retries), else whether a write happened. Under the [`LineSerial`],
    /// the client's row is re-read and only what it asks for is written (module docs); an
    /// unknown client gets no line.
    fn sync_line(&self, id: &ClientId, now: &TimeReading) -> Result<Option<bool>, Refusal> {
        let _held = self.serial.hold();
        // ⟨M06-W2-R01⟩ The files first (the read can block), then the reading: under the
        // lock, as at a commit, and never older than the read. A record created at its
        // commit (after `now` was sampled) is judged against time no earlier than its
        // creation.
        let Ok(files) = self.lines.read_all() else {
            return Ok(None);
        };
        let now = &commit_reading(now, self.clock);
        let have = marked_lines(&files, id);
        // `reconcile_line`'s comparison, over the files read above.
        let apply = |desired: &DesiredLine| match desired {
            DesiredLine::Absent if have.is_empty() => Ok(false),
            DesiredLine::Absent => self.lines.remove(id).map(|()| true),
            DesiredLine::Present(line) if have.len() == 1 && &have[0] == line => Ok(false),
            DesiredLine::Present(line) => self.lines.put(id, line).map(|()| true),
        };
        let Some(client) = self.reread(id)? else {
            return Ok(apply(&DesiredLine::Absent).ok());
        };
        let client = &client;
        let desired = self.desired_line(client, now)?;
        let Ok(changed) = apply(&desired) else {
            return Ok(None);
        };
        let applied = match (&desired, client.state) {
            (DesiredLine::Absent, _) => AppliedLine::Absent,
            (DesiredLine::Present(_), ClientState::Active) => AppliedLine::Active,
            (DesiredLine::Present(_), _) => {
                let inv = client
                    .invitation
                    .as_ref()
                    .map(|id| self.store.transaction(|tx| tx.remote_invitation(id)))
                    .transpose()
                    .map_err(state_err)?
                    .flatten();
                inv.map_or(AppliedLine::Absent, |i| AppliedLine::Pending {
                    expires_wall: i.expires_wall,
                })
            }
        };
        // Bookkeeping only, and only while the row is still in the state this write was
        // computed from (⟨Gemini R01⟩); a failure here costs one more idempotent pass.
        let _ = self.store.transaction(|tx| {
            tx.set_remote_client_line_if(&client.client, client.state, applied.clone())
        });
        Ok(Some(changed))
    }

    /// Create an invitation (the executor of the runner-local widening decision; module
    /// docs): refuse a key already authorized under another line or held by a pending or
    /// active client, commit the pending records, then write the pending line.
    ///
    /// # Errors
    ///
    /// [`Refusal`] as [`pending_records`], plus `key_already_authorized`, and
    /// `driver_unavailable` when the authorized_keys files cannot be read.
    pub fn invite(
        &self,
        new: &NewInvitation<'_>,
        policy: ManagementPolicy,
        now: &TimeReading,
    ) -> Result<Invited, Refusal> {
        limited_role_gate(new.role, policy)?;
        now.safe_parts().ok_or(Refusal::TimeUncertain)?;
        let key = PublicKeyText::parse(new.public_key).map_err(|_| Refusal::BindingMismatch)?;
        if &key.fingerprint() != new.key_fingerprint {
            return Err(Refusal::BindingMismatch);
        }
        let files = self
            .lines
            .read_all()
            .map_err(|_| Refusal::LinesUnavailable)?;
        if key_already_authorized(&files, key.blob(), None) {
            return Err(Refusal::KeyAlreadyAuthorized);
        }
        let ids = MintedIds::random()?;
        let made = self
            .store
            .transaction(|tx| {
                let held = tx
                    .remote_clients_with_key(new.key_fingerprint)?
                    .iter()
                    .any(|c| c.state != ClientState::Revoked);
                if held {
                    return Ok(Err(Refusal::KeyAlreadyAuthorized));
                }
                // ⟨M06 W3, ruling W0C-Q4⟩ The admission generation current now: `join`
                // commits only while it still is (module docs).
                let generation = tx.remote_authority_generation()?;
                // ⟨Gemini R01⟩ The commit point's reading: the record's created_wall, boot
                // anchor and deadline are those of the commit, not of the (older) sample.
                let commit_time = commit_reading(now, self.clock);
                let (client, invitation) =
                    match pending_records(new, ids, &commit_time, generation, policy) {
                        Ok(pair) => pair,
                        Err(r) => return Ok(Err(r)),
                    };
                let at = client.created_at;
                tx.insert_remote_invitation(&client, &invitation, at)?;
                Ok(Ok((client, invitation)))
            })
            .map_err(state_err)??;
        let (client, invitation) = made;
        let line_written = self.sync_line(&client.client, now)?.is_some();
        let client = self.reread(&client.client)?.unwrap_or(client);
        Ok(Invited {
            client,
            invitation,
            line_written,
        })
    }

    /// ⟨M06-W0-R07⟩ The executor of an approved runner-local invite decision: create the
    /// invitation for exactly the key and role the decision is bound to
    /// ([`crate::widening::WideningRecord::invite`]); [`Self::invite`] recomputes the
    /// fingerprint again.
    ///
    /// # Errors
    ///
    /// As [`Self::invite`].
    pub fn invite_bound(
        &self,
        binding: &crate::widening::InviteBinding,
        policy: ManagementPolicy,
        now: &TimeReading,
    ) -> Result<Invited, Refusal> {
        self.invite(
            &NewInvitation {
                role: binding.role,
                public_key: &binding.public_key,
                key_fingerprint: &binding.key_fingerprint,
                lifetime: MAX_INVITATION_LIFETIME,
                iroh_admission: binding.iroh_admission,
            },
            policy,
            now,
        )
    }

    fn reread(&self, id: &ClientId) -> Result<Option<RemoteClientRecord>, Refusal> {
        self.store
            .transaction(|tx| tx.remote_client(id))
            .map_err(state_err)
    }

    /// `join` for the session's client (module docs): identity, the compare-and-set at join
    /// time, commit, then the line rewrite without `expiry-time`. A retried join returns
    /// the recorded result after the same identity check, and rewrites the line if a crash
    /// left it pending.
    ///
    /// # Errors
    ///
    /// [`Refusal`]: `invitation_expired` (also for any identity mismatch),
    /// `invitation_consumed`, `decision_binding_mismatch`, `client_revoked`,
    /// `driver_unavailable` (the files cannot be read), `STATE_UNAVAILABLE`.
    pub fn join(
        &self,
        session: &ClientId,
        request: &JoinRequest,
        now: &TimeReading,
    ) -> Result<Joined, Refusal> {
        self.join_confirmed(session, request, now, &|_, _| Ok(Ok(())))
    }

    /// [`Self::join`], with the runner's policy check run **before the commit** (ADR-0006
    /// §18.7 item 16): `confirm` is called with the join that would activate, inside the
    /// commit's transaction and only for an activation (never for a refusal or a replayed
    /// join, so only a client holding a live invitation reaches it).
    ///
    /// ⟨ADR-0012 §3.2 "How the downgrade is kept"⟩ `confirm` is handed that transaction:
    /// it reads the policy in force there, and what it writes (the runner's owner-only
    /// downgrade for a disagreeing probe) commits with the outcome. Its refusal refuses the
    /// join: the transaction then commits what `confirm` wrote and **none** of the join's
    /// own changes (the client stays pending, the invitation unconsumed, no endpoint). Its
    /// store error rolls everything back.
    ///
    /// # Errors
    ///
    /// As [`Self::join`], and `confirm`'s refusal.
    pub fn join_confirmed(
        &self,
        session: &ClientId,
        request: &JoinRequest,
        now: &TimeReading,
        confirm: &JoinCheck<'_>,
    ) -> Result<Joined, Refusal> {
        let files = self
            .lines
            .read_all()
            .map_err(|_| Refusal::LinesUnavailable)?;
        let on_line = line_fingerprint(&files, session);
        let decided = self
            .store
            .transaction(|tx| {
                let inv = tx.remote_invitation(&request.invitation)?;
                let client = tx.remote_client(session)?;
                let generation = tx.remote_authority_generation()?;
                let recorded = tx.remote_client_endpoint(session)?.map(|(e, _)| e);
                let endpoint_taken = match &request.iroh_endpoint {
                    Some(e) => tx
                        .remote_client_endpoints()?
                        .iter()
                        .any(|(c, held)| held == e && c != session),
                    None => false,
                };
                // The commit point's reading, not the (possibly stale) sample.
                let at = commit_reading(now, self.clock);
                let d = decide_join(
                    inv.as_ref(),
                    client.as_ref(),
                    session,
                    on_line.as_ref(),
                    request,
                    JoinContext {
                        runner: self.environment,
                        now: &at,
                        generation,
                        recorded_endpoint: recorded.as_ref(),
                        endpoint_taken,
                    },
                );
                if let JoinDecision::Activate(j) = &d {
                    // A refusal returns before any of the join's own writes, so the
                    // commit below carries the check's writes alone.
                    if let Err(refused) = confirm(tx, j)? {
                        return Ok(JoinDecision::Refuse(refused));
                    }
                    tx.activate_remote_client(j)?;
                    // §18.7 item 3: recorded in the join's commit transaction (the
                    // decision already refused an endpoint the invitation did not admit).
                    if let Some(e) = &request.iroh_endpoint {
                        tx.set_remote_client_endpoint(session, e, j.joined_at)?;
                    }
                }
                Ok(d)
            })
            .map_err(state_err)?;
        let (join, replayed) = match decided {
            JoinDecision::Activate(j) => (j, false),
            JoinDecision::Replay(j) => (j, true),
            JoinDecision::Refuse(r) => return Err(r),
        };
        let line_written = self.sync_line(session, now)?.is_some();
        Ok(Joined {
            join,
            replayed,
            line_written,
        })
    }

    /// The activation probe (ADR-0012 §3.2; ⟨Gemini R03⟩ the wire form
    /// `remote_environment.activation_probe`): echoes the session's client and the pending
    /// record's nonce, only for a probe naming **this** runner and **that** nonce, and, for a
    /// pending client, only while its invitation is pending and live at `now` (the shared
    /// gate's reading). An active client's probe (its invitation consumed) still echoes.
    ///
    /// # Errors
    ///
    /// `decision_binding_mismatch` for another environment or nonce; `invitation_expired`
    /// for a pending client whose invitation is not live (or a client tombstoned by expiry);
    /// `client_revoked` for an unknown or revoked client or one without an invitation.
    pub fn probe(
        &self,
        session: &ClientId,
        request: &ProbeRequest,
        now: &TimeReading,
    ) -> Result<ProbeEcho, Refusal> {
        if &request.environment != self.environment {
            return Err(Refusal::BindingMismatch);
        }
        let found = self
            .store
            .transaction(|tx| {
                let Some(c) = tx.remote_client(session)? else {
                    return Ok(Err(Refusal::ClientRevoked));
                };
                if c.state == ClientState::Revoked {
                    return Ok(Err(match c.revocation {
                        Some(RevocationCause::InvitationExpired) => Refusal::InvitationExpired,
                        _ => Refusal::ClientRevoked,
                    }));
                }
                let Some(inv) = c.invitation.as_ref() else {
                    return Ok(Err(Refusal::ClientRevoked));
                };
                let Some(inv) = tx.remote_invitation(inv)? else {
                    return Ok(Err(Refusal::ClientRevoked));
                };
                if c.state == ClientState::Pending
                    && (inv.state != InvitationState::Pending
                        || liveness(&inv, now) != Liveness::Live)
                {
                    return Ok(Err(Refusal::InvitationExpired));
                }
                Ok(Ok(inv.probe_nonce))
            })
            .map_err(state_err)??;
        if request.nonce != found {
            return Err(Refusal::BindingMismatch);
        }
        Ok(ProbeEcho {
            client: session.clone(),
            nonce: found,
        })
    }

    /// Revoke a client (§3.11): commit the tombstone first, then remove the line. The
    /// tombstone is authoritative even when the removal fails. Closing the client's
    /// sessions, subscriptions and Iroh admission is the runtime's, after this returns.
    ///
    /// # Errors
    ///
    /// `client_revoked` for an unknown client; `STATE_UNAVAILABLE`.
    pub fn revoke(&self, client: &ClientId, now: Timestamp) -> Result<Revoked, Refusal> {
        let tomb = self
            .store
            .transaction(|tx| {
                if tx.remote_client(client)?.is_none() {
                    return Ok(None);
                }
                tx.revoke_remote_client(client, RevocationCause::Revoked, now)
                    .map(Some)
            })
            .map_err(state_err)?
            .ok_or(Refusal::ClientRevoked)?;
        let line_removed = self
            .sync_line(client, &TimeReading::uncertain(None))?
            .is_some();
        let client = self.reread(client)?.unwrap_or(tomb);
        Ok(Revoked {
            client,
            line_removed,
        })
    }

    /// Tombstone every pending invitation that has definitely expired (another boot, an
    /// elapsed bound or a checked wall deadline passed) and remove its line. An undetermined
    /// one is left pending and stays refused. Returns the clients tombstoned.
    ///
    /// # Errors
    ///
    /// `STATE_UNAVAILABLE`.
    pub fn expire_due(&self, now: &TimeReading) -> Result<Vec<ClientId>, Refusal> {
        let pending = self
            .store
            .transaction(|tx| tx.remote_invitations_pending())
            .map_err(state_err)?;
        let mut out = Vec::new();
        for inv in pending {
            if liveness(&inv, now) != Liveness::Expired {
                continue;
            }
            let tomb = self
                .store
                .transaction(|tx| {
                    // Re-read inside the transaction: a join may have consumed it.
                    match tx.remote_invitation(&inv.invitation)? {
                        Some(cur)
                            if cur.state == InvitationState::Pending
                                && liveness(&cur, now) == Liveness::Expired =>
                        {
                            tx.revoke_remote_client(
                                &cur.client,
                                RevocationCause::InvitationExpired,
                                now.checked_wall.unwrap_or(cur.expires_wall),
                            )
                            .map(Some)
                        }
                        _ => Ok(None),
                    }
                })
                .map_err(state_err)?;
            if let Some(t) = tomb {
                let _ = self.sync_line(&t.client, now)?;
                out.push(t.client);
            }
        }
        Ok(out)
    }

    /// Make every client's line match the database, idempotently.
    ///
    /// # Errors
    ///
    /// `STATE_UNAVAILABLE`.
    pub fn reconcile(&self, now: &TimeReading) -> Result<ReconcileReport, Refusal> {
        let clients = self
            .store
            .transaction(|tx| tx.remote_clients())
            .map_err(state_err)?;
        let mut report = ReconcileReport::default();
        for c in clients {
            match self.sync_line(&c.client, now)? {
                Some(changed) => report.changed += usize::from(changed),
                None => report.failed += 1,
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn anchor(wall: &str, boot: &str, secs: u64) -> TimeAnchor {
        TimeAnchor {
            boot_id: BootId(boot.into()),
            continuous: Duration::from_secs(secs),
            wall: wall.parse().unwrap(),
        }
    }

    fn inv() -> RemoteInvitationRecord {
        RemoteInvitationRecord {
            invitation: InvitationId::from_random_bytes([1; 16]),
            client: ClientId::from_random_bytes([1; 16]),
            role: Role::Owner,
            key_fingerprint: KeyFingerprint::parse(&format!("SHA256:{}", "C".repeat(43))).unwrap(),
            generation: 1,
            created_wall: "2026-11-20T10:00:00Z".parse().unwrap(),
            created_boot_id: BootId("b1".into()),
            created_elapsed: Duration::from_secs(1000),
            expires_wall: "2026-11-20T10:15:00Z".parse().unwrap(),
            elapsed_bound: Duration::from_secs(900),
            probe_nonce: "00".into(),
            state: InvitationState::Pending,
            consumed_at: None,
            join: None,
            iroh_admission: false,
        }
    }

    #[test]
    fn liveness_needs_both_bounds_on_checked_time_in_the_creation_boot() {
        let i = inv();
        let at = |w: &str, b: &str, s: u64| liveness(&i, &TimeReading::safe(&anchor(w, b, s)));
        assert_eq!(at("2026-11-20T10:14:59Z", "b1", 1899), Liveness::Live);
        // The wall deadline passes first.
        assert_eq!(at("2026-11-20T10:15:00Z", "b1", 1100), Liveness::Expired);
        // A rollback of the wall clock: the elapsed bound still runs out.
        assert_eq!(at("2026-11-20T09:00:00Z", "b1", 1900), Liveness::Expired);
        // Reboot: the anchor is lost.
        assert_eq!(at("2026-11-20T10:01:00Z", "b2", 10), Liveness::Expired);
        // The continuous clock went backwards: impossible, fails closed.
        assert_eq!(at("2026-11-20T10:01:00Z", "b1", 999), Liveness::Expired);
        // Uncertain time: refused, not tombstoned, unless a bound is known to have passed.
        let uncertain = |s: u64| {
            liveness(
                &i,
                &TimeReading::uncertain(Some(BootReading {
                    boot_id: BootId("b1".into()),
                    continuous: Duration::from_secs(s),
                })),
            )
        };
        assert_eq!(uncertain(1100), Liveness::Undetermined);
        assert_eq!(uncertain(1900), Liveness::Expired);
        assert_eq!(
            liveness(&i, &TimeReading::uncertain(None)),
            Liveness::Undetermined
        );
    }

    fn client_of(i: &RemoteInvitationRecord) -> RemoteClientRecord {
        RemoteClientRecord {
            client: i.client.clone(),
            role: i.role,
            key_fingerprint: i.key_fingerprint.clone(),
            public_key: "ssh-ed25519 AAAA".into(),
            state: ClientState::Pending,
            invitation: Some(i.invitation.clone()),
            revoked_generation: None,
            revocation: None,
            created_at: i.created_wall,
            updated_at: i.created_wall,
            line: AppliedLine::Absent,
        }
    }

    fn join_req(i: &RemoteInvitationRecord, runner: &EnvironmentId) -> JoinRequest {
        JoinRequest {
            environment: runner.clone(),
            invitation: i.invitation.clone(),
            role: i.role,
            generation: i.generation,
            iroh_endpoint: None,
            probe: None,
        }
    }

    fn endpoint(c: char) -> IrohEndpointId {
        IrohEndpointId::parse(&c.to_string().repeat(64)).unwrap()
    }

    /// ⟨M06 W3⟩ `join`'s refusals beyond W2's: an endpoint the invitation did not admit
    /// (`INVALID_REQUEST`-class, also on a retry), an endpoint another client holds, any
    /// admission-generation move since the invitation (`invitation_expired`), and a retry
    /// with an endpoint other than the recorded one; a live join with an admitted endpoint
    /// activates.
    #[test]
    fn join_refuses_unadmitted_endpoints_and_any_narrowing_since_the_invitation() {
        let runner = EnvironmentId::from_random_bytes([5; 16]);
        let now = TimeReading::safe(&anchor("2026-11-20T10:05:00Z", "b1", 1300));
        let mut i = inv();
        let c = client_of(&i);
        let fp = i.key_fingerprint.clone();
        fn ctx<'a>(
            runner: &'a EnvironmentId,
            now: &'a TimeReading,
            generation: u64,
            recorded: Option<&'a IrohEndpointId>,
            taken: bool,
        ) -> JoinContext<'a> {
            JoinContext {
                runner,
                now,
                generation,
                recorded_endpoint: recorded,
                endpoint_taken: taken,
            }
        }
        let decide = |i: &RemoteInvitationRecord,
                      c: &RemoteClientRecord,
                      r: &JoinRequest,
                      x: JoinContext<'_>| {
            decide_join(Some(i), Some(c), &i.client, Some(&fp), r, x)
        };
        let mut with_endpoint = join_req(&i, &runner);
        with_endpoint.iroh_endpoint = Some(endpoint('a'));
        // No `iroh_admission`: the endpoint is refused before anything else.
        assert_eq!(
            decide(&i, &c, &with_endpoint, ctx(&runner, &now, 1, None, false)),
            JoinDecision::Refuse(Refusal::InvalidRequest)
        );
        assert!(matches!(
            decide(
                &i,
                &c,
                &join_req(&i, &runner),
                ctx(&runner, &now, 1, None, false)
            ),
            JoinDecision::Activate(_)
        ));
        // A narrowing since the invitation (the admission generation moved) refuses.
        assert_eq!(
            decide(
                &i,
                &c,
                &join_req(&i, &runner),
                ctx(&runner, &now, 2, None, false)
            ),
            JoinDecision::Refuse(Refusal::InvitationExpired)
        );
        i.iroh_admission = true;
        assert!(matches!(
            decide(&i, &c, &with_endpoint, ctx(&runner, &now, 1, None, false)),
            JoinDecision::Activate(_)
        ));
        assert_eq!(
            decide(&i, &c, &with_endpoint, ctx(&runner, &now, 1, None, true)),
            JoinDecision::Refuse(Refusal::InvalidRequest),
            "another client's endpoint"
        );
        // A retry after the commit replays only with the recorded endpoint (or none).
        let JoinDecision::Activate(j) =
            decide(&i, &c, &with_endpoint, ctx(&runner, &now, 1, None, false))
        else {
            panic!("activates");
        };
        let mut consumed = i.clone();
        consumed.state = InvitationState::Consumed;
        consumed.join = Some(j.clone());
        let mut active = c.clone();
        active.state = ClientState::Active;
        let recorded = endpoint('a');
        assert_eq!(
            decide(
                &consumed,
                &active,
                &with_endpoint,
                ctx(&runner, &now, 7, Some(&recorded), false)
            ),
            JoinDecision::Replay(j.clone())
        );
        assert_eq!(
            decide(
                &consumed,
                &active,
                &join_req(&i, &runner),
                ctx(&runner, &now, 7, Some(&recorded), false)
            ),
            JoinDecision::Replay(j)
        );
        let mut other = with_endpoint.clone();
        other.iroh_endpoint = Some(endpoint('b'));
        assert_eq!(
            decide(
                &consumed,
                &active,
                &other,
                ctx(&runner, &now, 7, Some(&recorded), false)
            ),
            JoinDecision::Refuse(Refusal::InvitationConsumed)
        );
    }

    /// ⟨2026-11-21, ruling 2; ADR-0012 §3.9 item 5⟩ The commit-time reading: the wall deadline
    /// is judged on the upper bound of now (the gate's tolerance carried through
    /// `at_commit`); a continuous clock that went backwards since the sample, another boot,
    /// or the platform's unavailable boot anchor leaves it uncertain, and `join` refuses
    /// (`invitation_expired`).
    #[test]
    fn the_commit_reading_projects_the_upper_bound_and_refuses_backwards_or_unavailable_clocks() {
        let runner = EnvironmentId::from_random_bytes([5; 16]);
        let i = inv();
        let c = client_of(&i);
        let fp = i.key_fingerprint.clone();
        let decide = |at: &TimeReading| {
            decide_join(
                Some(&i),
                Some(&c),
                &i.client,
                Some(&fp),
                &join_req(&i, &runner),
                JoinContext {
                    runner: &runner,
                    now: at,
                    generation: 1,
                    recorded_endpoint: None,
                    endpoint_taken: false,
                },
            )
        };
        // Sampled at 10:14:00 (continuous 1840 s, elapsed 840 of 900): live on its own.
        let exact = TimeReading::safe(&anchor("2026-11-20T10:14:00Z", "b1", 1840));
        let commit = anchor("2026-11-20T10:14:10Z", "b1", 1850);
        assert!(matches!(
            decide(&at_commit(&exact, &commit)),
            JoinDecision::Activate(_)
        ));
        // The same sample accepted with 60 s of tolerance: its upper bound at the commit
        // (10:14:10 + 60 s) is past the wall deadline, so the join is refused.
        let tolerant = TimeReading::safe_within(
            &anchor("2026-11-20T10:14:00Z", "b1", 1840),
            Duration::from_secs(60),
        );
        let at = at_commit(&tolerant, &commit);
        assert_eq!(at.slack, Duration::from_secs(60), "the slack is carried");
        assert_eq!(
            decide(&at),
            JoinDecision::Refuse(Refusal::InvitationExpired)
        );
        // Backwards since the sample.
        let back = at_commit(&exact, &anchor("2026-11-20T10:14:01Z", "b1", 1839));
        assert_eq!(back.checked_wall, None);
        assert_eq!(
            decide(&back),
            JoinDecision::Refuse(Refusal::InvitationExpired)
        );
        // The boot anchor became unavailable (the platform's per-process sentinel).
        let gone = at_commit(
            &exact,
            &anchor("2026-11-20T10:14:01Z", "unavailable:4242:1", 1850),
        );
        assert_eq!(gone, TimeReading::uncertain(None));
        assert_eq!(
            decide(&gone),
            JoinDecision::Refuse(Refusal::InvitationExpired)
        );
        // A sample whose own anchor was the sentinel never advances either.
        let sentinel = TimeReading::safe(&anchor("2026-11-20T10:14:00Z", "unavailable:1:2", 1840));
        assert_eq!(
            at_commit(
                &sentinel,
                &anchor("2026-11-20T10:14:01Z", "unavailable:1:2", 1850)
            ),
            TimeReading::uncertain(None)
        );
    }

    /// ⟨M06-W2-R01; ADR-0012 §3.9 item 5⟩ The projection is a floor: the commit point's wall
    /// clock moves the reading later, never earlier; a step back within the tolerance keeps
    /// the projection, and one beyond it is uncertain with the step recorded.
    #[test]
    fn the_commit_wall_clock_is_a_floor_and_a_step_back_is_uncertain() {
        assert_eq!(
            WALL_STEP_TOLERANCE,
            heimdall_domain::time::TimePolicy::default().max_tolerated_rollback
        );
        let ts = |s: &str| s.parse::<Timestamp>().unwrap();
        let sample = TimeReading::safe_within(
            &anchor("2026-11-20T10:00:00Z", "b1", 1000),
            Duration::from_secs(2),
        );
        // One second elapsed; the wall clock reads 20 minutes later: the later one wins.
        let ahead = at_commit(&sample, &anchor("2026-11-20T10:20:01Z", "b1", 1001));
        assert_eq!(ahead.checked_wall, Some(ts("2026-11-20T10:20:01Z")));
        assert_eq!(ahead.slack, Duration::from_secs(2));
        assert!(!ahead.wall_stepped_back);
        // Behind the projection by exactly the tolerance: the projection stands.
        let near = at_commit(&sample, &anchor("2026-11-20T09:59:56Z", "b1", 1001));
        assert_eq!(near.checked_wall, Some(ts("2026-11-20T10:00:01Z")));
        assert!(!near.wall_stepped_back);
        // Behind it by more: uncertain, with the boot anchor kept.
        let back = at_commit(&sample, &anchor("2026-11-20T09:59:55Z", "b1", 1001));
        assert_eq!(back.checked_wall, None);
        assert!(back.wall_stepped_back);
        assert_eq!(
            back.boot.as_ref().map(|b| b.continuous),
            Some(Duration::from_secs(1001))
        );
    }

    /// ⟨M06 W3; ADR-0006 §18.7 item 4⟩ Rotation over a real store: refused for another
    /// environment, a pending client, an invitation without `iroh_admission` and another
    /// client's endpoint, writing nothing; the first endpoint records, the same one is a
    /// no-op, a different one replaces and moves the admission generation once.
    #[test]
    fn rotation_is_admitted_by_the_invitation_and_a_replacement_moves_the_generation() {
        use std::sync::Arc;
        let store = Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap();
        let runner = EnvironmentId::from_random_bytes([5; 16]);
        let at: Timestamp = "2026-11-20T10:06:00Z".parse().unwrap();
        let make = |n: u8, admitted: bool, join: bool| {
            let mut i = inv();
            i.invitation = InvitationId::from_random_bytes([n; 16]);
            i.client = ClientId::from_random_bytes([n; 16]);
            i.key_fingerprint = KeyFingerprint::parse(&format!(
                "SHA256:{}",
                char::from(b'A' + n).to_string().repeat(43)
            ))
            .unwrap();
            i.iroh_admission = admitted;
            i.generation = 0;
            let c = client_of(&i);
            store
                .transaction(|tx| {
                    tx.insert_remote_invitation(&c, &i, at)?;
                    if join {
                        tx.activate_remote_client(&JoinRecord {
                            environment: runner.clone(),
                            invitation: i.invitation.clone(),
                            client: i.client.clone(),
                            role: i.role,
                            generation: i.generation,
                            joined_at: at,
                        })?;
                    }
                    Ok(())
                })
                .unwrap();
            i.client
        };
        let a = make(1, true, true);
        let b = make(2, true, true);
        let plain = make(3, false, true);
        let pending = make(4, true, false);
        let req = |e: char| RotateRequest {
            environment: runner.clone(),
            endpoint: endpoint(e),
        };
        let generation = || {
            store
                .transaction(|tx| tx.remote_authority_generation())
                .unwrap()
        };
        let g0 = generation();
        let wrong_env = RotateRequest {
            environment: EnvironmentId::from_random_bytes([6; 16]),
            endpoint: endpoint('a'),
        };
        assert_eq!(
            rotate_endpoint(&store, &runner, &a, &wrong_env, at),
            Err(Refusal::InvalidRequest)
        );
        assert_eq!(
            rotate_endpoint(&store, &runner, &plain, &req('a'), at),
            Err(Refusal::InvalidRequest)
        );
        assert_eq!(
            rotate_endpoint(&store, &runner, &pending, &req('a'), at),
            Err(Refusal::InvitationPending)
        );
        assert_eq!(
            rotate_endpoint(&store, &runner, &a, &req('a'), at).map(|r| r.change),
            Ok(EndpointChange::Recorded)
        );
        assert_eq!(
            rotate_endpoint(&store, &runner, &b, &req('a'), at),
            Err(Refusal::InvalidRequest),
            "another client's endpoint"
        );
        assert_eq!(
            rotate_endpoint(&store, &runner, &a, &req('a'), at).map(|r| r.change),
            Ok(EndpointChange::Unchanged)
        );
        assert_eq!(generation(), g0, "recording and repeating narrow nothing");
        assert_eq!(
            rotate_endpoint(&store, &runner, &a, &req('c'), at).map(|r| r.change),
            Ok(EndpointChange::Replaced(g0 + 1))
        );
        assert_eq!(generation(), g0 + 1);
        assert_eq!(
            store
                .transaction(|tx| tx.remote_client_endpoints())
                .unwrap(),
            vec![(a, endpoint('c'))]
        );
    }
}
