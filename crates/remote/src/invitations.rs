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

use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{ClientId, EnvironmentId, InvitationId, KeyFingerprint};
use heimdall_contract::remote::{ManagementPolicy, RemoteEnvironmentRequest, Role};
use heimdall_contract::request::Request;
use heimdall_domain::time::{BootId, TimeAnchor};
use heimdall_store::Store;
use heimdall_store::ext_m06::{
    AppliedLine, ClientState, InvitationState, JoinRecord, RemoteClientRecord,
    RemoteInvitationRecord, RevocationCause,
};

use crate::line::{
    DesiredLine, ManagementLine, ManagementLines, PublicKeyText, ServeCommand,
    key_already_authorized, line_fingerprint, reconcile_line,
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

/// A time reading for the invitation rules. The runtime builds it from the shared time
/// gate: `checked_wall` is set only when the gate assessed the observation `Safe`
/// (ADR-0006 §10), and `boot` only when the boot ID and continuous clock were readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeReading {
    /// The wall clock, when checked `Safe`.
    pub checked_wall: Option<Timestamp>,
    /// The boot anchor, when readable.
    pub boot: Option<BootReading>,
}

impl TimeReading {
    /// A `Safe` gate observation (`heimdall_app::SafeNow::anchor`).
    #[must_use]
    pub fn safe(anchor: &TimeAnchor) -> Self {
        Self {
            checked_wall: Some(anchor.wall),
            boot: Some(BootReading {
                boot_id: anchor.boot_id.clone(),
                continuous: anchor.continuous,
            }),
        }
    }

    /// An uncertain wall clock (`TIME_UNCERTAIN`), with the boot anchor when readable.
    #[must_use]
    pub fn uncertain(boot: Option<BootReading>) -> Self {
        Self {
            checked_wall: None,
            boot,
        }
    }

    fn safe_parts(&self) -> Option<(Timestamp, &BootReading)> {
        Some((self.checked_wall?, self.boot.as_ref()?))
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
    let wall_passed = now.checked_wall.is_some_and(|w| w >= inv.expires_wall);
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
            }) => Some(Self {
                environment: environment.clone(),
                invitation: invitation.clone(),
                role: *role,
                generation: *generation,
            }),
            _ => None,
        }
    }
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
    runner: &EnvironmentId,
    now: &TimeReading,
) -> JoinDecision {
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
    match inv.state {
        InvitationState::Consumed => match (&inv.join, client) {
            (Some(j), Some(c)) if c.state == ClientState::Active => {
                if binding_matches && &j.environment == runner {
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
            match (liveness(inv, now), now.checked_wall) {
                (Liveness::Live, Some(joined_at)) => JoinDecision::Activate(JoinRecord {
                    environment: runner.clone(),
                    invitation: inv.invitation.clone(),
                    client: session.clone(),
                    role: inv.role,
                    generation: inv.generation,
                    joined_at,
                }),
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
    /// (the reconciler retries), else whether a write happened.
    fn sync_line(
        &self,
        client: &RemoteClientRecord,
        now: &TimeReading,
    ) -> Result<Option<bool>, Refusal> {
        let desired = self.desired_line(client, now)?;
        let Ok(changed) = reconcile_line(self.lines, &client.client, &desired) else {
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
        // Bookkeeping only: a failure here costs one more idempotent pass.
        let _ = self
            .store
            .transaction(|tx| tx.set_remote_client_line(&client.client, applied.clone()));
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
                let generation = tx.authority_generation()?.0;
                let (client, invitation) = match pending_records(new, ids, now, generation, policy)
                {
                    Ok(pair) => pair,
                    Err(r) => return Ok(Err(r)),
                };
                let at = client.created_at;
                tx.insert_remote_invitation(&client, &invitation, at)?;
                Ok(Ok((client, invitation)))
            })
            .map_err(state_err)??;
        let (client, invitation) = made;
        let line_written = self.sync_line(&client, now)?.is_some();
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
                let d = decide_join(
                    inv.as_ref(),
                    client.as_ref(),
                    session,
                    on_line.as_ref(),
                    request,
                    self.environment,
                    now,
                );
                if let JoinDecision::Activate(j) = &d {
                    tx.activate_remote_client(j)?;
                }
                Ok(d)
            })
            .map_err(state_err)?;
        let (join, replayed) = match decided {
            JoinDecision::Activate(j) => (j, false),
            JoinDecision::Replay(j) => (j, true),
            JoinDecision::Refuse(r) => return Err(r),
        };
        let client = self.reread(session)?.ok_or(Refusal::State)?;
        let line_written = self.sync_line(&client, now)?.is_some();
        Ok(Joined {
            join,
            replayed,
            line_written,
        })
    }

    /// The activation probe's echo for the session's client (pending or active; the
    /// per-frame check has already refused anything else).
    ///
    /// # Errors
    ///
    /// `client_revoked` for an unknown or revoked client or one without an invitation.
    pub fn probe(&self, session: &ClientId) -> Result<ProbeEcho, Refusal> {
        let found = self
            .store
            .transaction(|tx| {
                let Some(c) = tx.remote_client(session)? else {
                    return Ok(None);
                };
                if c.state == ClientState::Revoked {
                    return Ok(None);
                }
                let Some(inv) = c.invitation.as_ref() else {
                    return Ok(None);
                };
                Ok(tx.remote_invitation(inv)?.map(|i| i.probe_nonce))
            })
            .map_err(state_err)?;
        found
            .map(|nonce| ProbeEcho {
                client: session.clone(),
                nonce,
            })
            .ok_or(Refusal::ClientRevoked)
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
            .sync_line(&tomb, &TimeReading::uncertain(None))?
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
                let _ = self.sync_line(&t, now)?;
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
            match self.sync_line(&c, now)? {
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
}
