//! ⟨M06⟩ Store methods for the runner's role table and invitations (ADR-0012 §3.7–§3.9,
//! §3.11; m06-plan U1). Schema: `migrations/0009_remote.sql` (`remote_clients`,
//! `remote_invitations`, `remote_authority_generation`); ⟨W3⟩ `0011_remote_client_endpoints`
//! (`remote_client_endpoints`, `remote_invitations.iroh_admission`; ADR-0006 §18.7 item 1).
//!
//! Conventions (as [`crate::ext_m05`]): every method runs inside the caller's [`Txn`];
//! reads return `Option`/`Vec`; the store reads no clock (every instant is the caller's);
//! inserting a record whose key already exists is a [`StoreError::GenerationConflict`]
//! and writes nothing; a stale compare-and-set is a [`StoreError::GenerationConflict`]
//! and writes nothing; updating through a key that does not exist is
//! `StoreError::Sqlite(QueryReturnedNoRows)`.
//!
//! **The records** live here, beside their tables, because the store may depend only on the
//! contract and the domain and neither defines them. `record_json` is the authoritative
//! document; the other columns mirror it for lookups. The line-reconcile state
//! ([`AppliedLine`]) rides in the client's document: no column was needed.
//!
//! **Generations.** Creating an invitation (a pending client), activating a client and
//! revoking one widen or narrow authority, so each moves the authority generation
//! (ADR-0006 §13.7 item 5). ⟨M06 W3; m06-plan U56, ruling W0C-Q4⟩ The runner's admission
//! authority generation (`remote_authority_generation`, ADR-0012 §2.3 items 3–5) moves only
//! for a change that narrows remote admission: here, a client's tombstone and the
//! replacement of a client's Iroh endpoint ID ([`Txn::set_remote_client_endpoint`]); in
//! [`crate::ext_transport`], transport disable, exposure narrowing and K_iroh rotation or
//! removal. Invitations, activation and the bootstrap owner's enrollment widen and leave it,
//! so an invitation records the admission generation current at its creation and `join`
//! refuses when anything narrowed in between. A client's line-reconcile bookkeeping moves
//! neither.

use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, ClientId, DecisionId, DestinationId, EnvironmentId, InvitationId, IrohEndpointId,
    KeyFingerprint, RequestId,
};
use heimdall_contract::remote::Role;
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState, WideningOrigin};
use heimdall_domain::time::BootId;
use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize};

use crate::{Result, StoreError, Txn, codec};

fn conflict(what: &str) -> StoreError {
    StoreError::GenerationConflict(what.into())
}

fn missing() -> StoreError {
    StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows)
}

/// A paired client's state in the role table (ADR-0012 §3.9, §3.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientState {
    /// Invited, not yet joined: the session may send only the activation probe and `join`.
    Pending,
    /// Joined: ordinary connections authenticate as this client and consume nothing.
    Active,
    /// The tombstone: the admission authority. Never leaves this state.
    Revoked,
}

/// Why a client was tombstoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationCause {
    /// An owner revoked it (ADR-0012 §3.11), or its invitation was revoked.
    Revoked,
    /// Its invitation expired before a `join` (ADR-0012 §3.9 item 4).
    InvitationExpired,
}

/// The management line last confirmed written for a client (the line-reconcile state,
/// ADR-0012 §3.9 item 6). Advisory: the reconciler compares the desired line with the
/// file itself, so a crash between a write and this bookkeeping only causes one more
/// idempotent pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AppliedLine {
    /// No line is known to be written (also the state before the first write).
    Absent,
    /// The pending line, with `expiry-time` = this instant (the sshd-enforced backstop).
    Pending {
        /// The `expiry-time` the line carries.
        expires_wall: Timestamp,
    },
    /// The active line, without `expiry-time`.
    Active,
}

/// One row of the role table (`remote_clients`): a paired client, its role, the receiving
/// key, its state and its line-reconcile state. Nonsecret: identifiers, a public key and a
/// fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteClientRecord {
    /// The client (`cl_…`), minted by the runner at invitation.
    pub client: ClientId,
    /// Its role.
    pub role: Role,
    /// The receiving key's fingerprint, confirmed by the owner (ADR-0012 §3.9 item 1).
    pub key_fingerprint: KeyFingerprint,
    /// The receiving public key, `<type> <base64>` (public text), from which the line is
    /// rendered.
    pub public_key: String,
    /// The state.
    pub state: ClientState,
    /// The invitation that created the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation: Option<InvitationId>,
    /// The admission authority generation the tombstone produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_generation: Option<u64>,
    /// Why it was tombstoned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<RevocationCause>,
    /// When the row was created.
    pub created_at: Timestamp,
    /// When the row last changed.
    pub updated_at: Timestamp,
    /// The line-reconcile state.
    pub line: AppliedLine,
}

/// An invitation's state (`remote_invitations.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationState {
    /// Created, not consumed.
    Pending,
    /// Consumed once by `join`'s compare-and-set.
    Consumed,
    /// Expired before a `join`.
    Expired,
    /// Revoked (its client was revoked before a `join`).
    Revoked,
}

/// The recorded result of a successful `join` (ADR-0012 §3.9 item 6): what a retried
/// `join` returns, after its identity check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRecord {
    /// The runner environment.
    pub environment: EnvironmentId,
    /// The invitation.
    pub invitation: InvitationId,
    /// The client now active.
    pub client: ClientId,
    /// Its role.
    pub role: Role,
    /// The invitation's generation.
    pub generation: u64,
    /// When the join committed.
    pub joined_at: Timestamp,
}

/// One invitation (`remote_invitations`; ADR-0012 §3.9 item 2): the pending record
/// `{invitation ID, cid, role, receiving key fingerprint, created_wall, created_boot_id,
/// created_elapsed, expires_wall ≤ created + 15 min, generation}`, its probe nonce, its
/// state and the recorded join.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteInvitationRecord {
    /// The invitation (`inv_…`).
    pub invitation: InvitationId,
    /// The invited client.
    pub client: ClientId,
    /// The role it will hold.
    pub role: Role,
    /// The receiving key's fingerprint.
    pub key_fingerprint: KeyFingerprint,
    /// The binding generation `join` must name.
    pub generation: u64,
    /// The checked wall clock at creation.
    pub created_wall: Timestamp,
    /// The boot the elapsed bound is measured in.
    pub created_boot_id: BootId,
    /// The continuous clock at creation, in that boot.
    pub created_elapsed: Duration,
    /// The wall deadline (`expiry-time` on the line).
    pub expires_wall: Timestamp,
    /// The non-extending elapsed bound, `expires_wall − created_wall`.
    pub elapsed_bound: Duration,
    /// The nonce the activation probe echoes (nonsecret, 32 lowercase hex).
    pub probe_nonce: String,
    /// The state.
    pub state: InvitationState,
    /// When it was consumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<Timestamp>,
    /// The recorded join result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join: Option<JoinRecord>,
    /// ⟨M06 W3; ADR-0006 §18.7 item 2⟩ Whether the invited client may reach this runner
    /// over Iroh (mirrored in the `iroh_admission` column). Omitted when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub iroh_admission: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// ⟨ADR-0006 §18.7 item 8⟩ What [`Txn::admit_bootstrap_owner_iroh`] did with the endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerEndpoint {
    /// The owner had none: this one was recorded.
    Recorded,
    /// The owner already had exactly this one.
    Unchanged,
    /// The owner has another endpoint, which was kept (never replaced here).
    Kept(IrohEndpointId),
}

/// ⟨M06 W3⟩ What [`Txn::set_remote_client_endpoint`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointChange {
    /// The client had no endpoint; it has this one now (no generation moved: admitting a
    /// new peer narrows nothing).
    Recorded,
    /// The client's endpoint was replaced; the admission authority generation moved to
    /// this value in the same transaction.
    Replaced(u64),
    /// The client already had this endpoint; nothing was written.
    Unchanged,
}

fn millis(d: Duration) -> Result<i64> {
    codec::int(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl Txn<'_> {
    // --- the role table -----------------------------------------------------------------

    fn write_client(&mut self, rec: &RemoteClientRecord, insert: bool) -> Result<()> {
        let params = rusqlite::params![
            rec.client.as_str(),
            codec::enum_str(&rec.role)?,
            rec.key_fingerprint.as_str(),
            codec::enum_str(&rec.state)?,
            rec.invitation.as_ref().map(InvitationId::as_str),
            rec.revoked_generation.map(codec::int).transpose()?,
            codec::doc(rec)?,
            codec::ts(rec.updated_at),
        ];
        let sql = if insert {
            "INSERT INTO remote_clients (client_id, role, key_fingerprint, state, invitation_id,
                 revoked_generation, record_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
        } else {
            "UPDATE remote_clients SET role = ?2, key_fingerprint = ?3, state = ?4,
                 invitation_id = ?5, revoked_generation = ?6, record_json = ?7, updated_at = ?8
             WHERE client_id = ?1"
        };
        if self.tx.execute(sql, params)? == 0 {
            return Err(missing());
        }
        Ok(())
    }

    fn write_invitation(&mut self, rec: &RemoteInvitationRecord, insert: bool) -> Result<()> {
        if insert {
            self.tx.execute(
                "INSERT INTO remote_invitations (invitation_id, client_id, role, key_fingerprint,
                     generation, created_wall, created_boot_id, created_elapsed_ms, expires_wall,
                     elapsed_bound_ms, state, consumed_at, record_json, iroh_admission)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                rusqlite::params![
                    rec.invitation.as_str(),
                    rec.client.as_str(),
                    codec::enum_str(&rec.role)?,
                    rec.key_fingerprint.as_str(),
                    codec::int(rec.generation)?,
                    codec::ts(rec.created_wall),
                    rec.created_boot_id.0,
                    millis(rec.created_elapsed)?,
                    codec::ts(rec.expires_wall),
                    millis(rec.elapsed_bound)?,
                    codec::enum_str(&rec.state)?,
                    rec.consumed_at.map(codec::ts),
                    codec::doc(rec)?,
                    i64::from(rec.iroh_admission),
                ],
            )?;
            return Ok(());
        }
        let n = self.tx.execute(
            "UPDATE remote_invitations SET state = ?2, consumed_at = ?3, record_json = ?4
             WHERE invitation_id = ?1",
            rusqlite::params![
                rec.invitation.as_str(),
                codec::enum_str(&rec.state)?,
                rec.consumed_at.map(codec::ts),
                codec::doc(rec)?,
            ],
        )?;
        if n == 0 {
            return Err(missing());
        }
        Ok(())
    }

    /// Insert an invitation and its pending client in one step (ADR-0012 §3.9 item 2). Both
    /// IDs must be new ([`StoreError::GenerationConflict`] otherwise); both records must be
    /// pending, name each other and agree on the role and the key fingerprint, and the
    /// client's line state must be [`AppliedLine::Absent`] (the line is written after this
    /// commit). Moves the authority generation; ⟨W3⟩ never the admission authority
    /// generation (module docs). Returns the admission authority generation, unchanged.
    pub fn insert_remote_invitation(
        &mut self,
        client: &RemoteClientRecord,
        invitation: &RemoteInvitationRecord,
        _now: Timestamp,
    ) -> Result<u64> {
        let consistent = client.state == ClientState::Pending
            && invitation.state == InvitationState::Pending
            && client.invitation.as_ref() == Some(&invitation.invitation)
            && invitation.client == client.client
            && invitation.role == client.role
            && invitation.key_fingerprint == client.key_fingerprint
            && client.line == AppliedLine::Absent
            && client.revoked_generation.is_none()
            && client.revocation.is_none()
            && invitation.consumed_at.is_none()
            && invitation.join.is_none();
        if !consistent {
            return Err(codec::doc_error(
                "an invitation is inserted pending, with its pending client",
            ));
        }
        if self.remote_client(&client.client)?.is_some() {
            return Err(conflict("the client already exists"));
        }
        if self.remote_invitation(&invitation.invitation)?.is_some() {
            return Err(conflict("the invitation already exists"));
        }
        self.write_client(client, true)?;
        self.write_invitation(invitation, true)?;
        self.bump_generation()?;
        self.remote_authority_generation()
    }

    /// One client, whatever its state.
    pub fn remote_client(&mut self, id: &ClientId) -> Result<Option<RemoteClientRecord>> {
        self.one_doc(
            "SELECT record_json FROM remote_clients WHERE client_id = ?1",
            [id.as_str()],
        )
    }

    /// Every client, by ID.
    pub fn remote_clients(&mut self) -> Result<Vec<RemoteClientRecord>> {
        self.docs(
            "SELECT record_json FROM remote_clients ORDER BY client_id",
            [],
        )
    }

    /// Every client (any state) whose receiving key has this fingerprint, by ID.
    /// ⟨Reading 16, amended⟩ Key uniqueness is scoped to this runner's role table (this
    /// store): the invitation service refuses a key a pending or active client of this table
    /// holds; other runners have their own tables, and a tombstoned holder's key may be
    /// invited again (no unique index).
    pub fn remote_clients_with_key(
        &mut self,
        fingerprint: &KeyFingerprint,
    ) -> Result<Vec<RemoteClientRecord>> {
        self.docs(
            "SELECT record_json FROM remote_clients WHERE key_fingerprint = ?1 ORDER BY client_id",
            [fingerprint.as_str()],
        )
    }

    /// One invitation, whatever its state.
    pub fn remote_invitation(
        &mut self,
        id: &InvitationId,
    ) -> Result<Option<RemoteInvitationRecord>> {
        self.one_doc(
            "SELECT record_json FROM remote_invitations WHERE invitation_id = ?1",
            [id.as_str()],
        )
    }

    /// Every pending invitation, by ID (the expiry sweep's input).
    pub fn remote_invitations_pending(&mut self) -> Result<Vec<RemoteInvitationRecord>> {
        self.docs(
            "SELECT record_json FROM remote_invitations WHERE state = ?1 ORDER BY invitation_id",
            [codec::enum_str(&InvitationState::Pending)?],
        )
    }

    /// `join`'s compare-and-set (ADR-0012 §3.9 item 5), the store half: the invitation
    /// `pending → consumed` with `join` recorded, and its client `pending → active`, in this
    /// transaction. The caller has already checked identity, role, generation and liveness
    /// against the records read in this same transaction. A missing invitation is
    /// `QueryReturnedNoRows`; an invitation or client that is not pending, or a `join` that
    /// does not name the records, is [`StoreError::GenerationConflict`] and writes nothing.
    /// Moves the authority generation; ⟨W3⟩ never the admission authority generation
    /// (module docs). The caller records the client's endpoint in the same transaction
    /// ([`Self::set_remote_client_endpoint`]) when the join carries one.
    pub fn activate_remote_client(
        &mut self,
        join: &JoinRecord,
    ) -> Result<(RemoteClientRecord, RemoteInvitationRecord)> {
        let Some(mut inv) = self.remote_invitation(&join.invitation)? else {
            return Err(missing());
        };
        let Some(mut client) = self.remote_client(&inv.client)? else {
            return Err(StoreError::Corrupt(
                "an invitation names a client that does not exist".into(),
            ));
        };
        if inv.state != InvitationState::Pending || client.state != ClientState::Pending {
            return Err(conflict("the invitation is not pending"));
        }
        if client.invitation.as_ref() != Some(&inv.invitation)
            || join.client != inv.client
            || join.role != inv.role
            || join.generation != inv.generation
        {
            return Err(conflict("the join does not match the invitation"));
        }
        inv.state = InvitationState::Consumed;
        inv.consumed_at = Some(join.joined_at);
        inv.join = Some(join.clone());
        client.state = ClientState::Active;
        client.updated_at = join.joined_at;
        self.write_invitation(&inv, false)?;
        self.write_client(&client, false)?;
        // ⟨§18.7 item 8⟩ The invitation's Iroh admission becomes the client's.
        if inv.iroh_admission {
            self.admit_remote_client_iroh(&client.client)?;
        }
        self.bump_generation()?;
        Ok((client, inv))
    }

    /// Tombstone a client (ADR-0012 §3.11 step 1; §3.9 item 4 for an expired invitation):
    /// `pending | active → revoked`, recording the admission authority generation it
    /// produces and the cause; a pending invitation of the client becomes `expired` (cause
    /// [`RevocationCause::InvitationExpired`]) or `revoked`. Moves the authority generation
    /// and the admission authority generation. ⟨W3; ADR-0012 §3.11⟩ The client's
    /// `remote_client_endpoints` row is deleted in this same transaction. Idempotent: a
    /// client already revoked is returned unchanged and moves nothing. A missing client is
    /// `QueryReturnedNoRows`.
    pub fn revoke_remote_client(
        &mut self,
        id: &ClientId,
        cause: RevocationCause,
        now: Timestamp,
    ) -> Result<RemoteClientRecord> {
        let Some(mut client) = self.remote_client(id)? else {
            return Err(missing());
        };
        if client.state == ClientState::Revoked {
            return Ok(client);
        }
        if let Some(inv_id) = client.invitation.clone()
            && let Some(mut inv) = self.remote_invitation(&inv_id)?
            && inv.state == InvitationState::Pending
        {
            inv.state = match cause {
                RevocationCause::InvitationExpired => InvitationState::Expired,
                RevocationCause::Revoked => InvitationState::Revoked,
            };
            self.write_invitation(&inv, false)?;
        }
        self.tx.execute(
            "DELETE FROM remote_client_endpoints WHERE client_id = ?1",
            [id.as_str()],
        )?;
        self.bump_generation()?;
        let generation = self.bump_remote_authority_generation(now)?;
        client.state = ClientState::Revoked;
        client.revoked_generation = Some(generation);
        client.revocation = Some(cause);
        client.updated_at = now;
        self.write_client(&client, false)?;
        Ok(client)
    }

    /// Record the line last confirmed written for a client (line-reconcile bookkeeping).
    /// Moves no generation. A missing client is `QueryReturnedNoRows`.
    pub fn set_remote_client_line(
        &mut self,
        id: &ClientId,
        line: AppliedLine,
    ) -> Result<RemoteClientRecord> {
        let Some(mut client) = self.remote_client(id)? else {
            return Err(missing());
        };
        if client.line != line {
            client.line = line;
            self.write_client(&client, false)?;
        }
        Ok(client)
    }

    /// ⟨M06 W1 review (Gemini R01)⟩ Record the line last confirmed written only if the
    /// client's state is still `expected` (the state the write was computed from): a
    /// tombstone committed meanwhile is never marked with the active line. Returns whether
    /// it recorded. Moves no generation. A missing client is `QueryReturnedNoRows`.
    pub fn set_remote_client_line_if(
        &mut self,
        id: &ClientId,
        expected: ClientState,
        line: AppliedLine,
    ) -> Result<bool> {
        let Some(mut client) = self.remote_client(id)? else {
            return Err(missing());
        };
        if client.state != expected {
            return Ok(false);
        }
        if client.line != line {
            client.line = line;
            self.write_client(&client, false)?;
        }
        Ok(true)
    }

    // --- ⟨M06 W3⟩ paired clients' Iroh endpoint IDs (ADR-0006 §18.7 items 1, 3, 4) ------

    /// ⟨ADR-0006 §18.7 item 8⟩ Whether `client` is admitted over Iroh (the client's own
    /// attribute: copied from its invitation at `join`, or set for the bootstrap owner by
    /// [`Self::admit_bootstrap_owner_iroh`]). `false` for an unknown client.
    pub fn remote_client_iroh_admission(&mut self, client: &ClientId) -> Result<bool> {
        let admitted: Option<i64> = self
            .tx
            .query_row(
                "SELECT iroh_admission FROM remote_clients WHERE client_id = ?1",
                [client.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(admitted == Some(1))
    }

    /// Set `client`'s Iroh admission (never cleared: a tombstone ends it with the client).
    fn admit_remote_client_iroh(&mut self, client: &ClientId) -> Result<()> {
        let n = self.tx.execute(
            "UPDATE remote_clients SET iroh_admission = 1 WHERE client_id = ?1",
            [client.as_str()],
        )?;
        if n == 1 { Ok(()) } else { Err(missing()) }
    }

    /// ⟨ADR-0006 §18.7 item 8⟩ The bootstrap owner's Iroh admission and first endpoint, in
    /// the caller's transaction (the owner enrollment's, or `remote init`'s repair of the
    /// same key and client): `client` must be an **active owner with no invitation** (what
    /// [`Self::enroll_bootstrap_owner`] returns), else [`StoreError::GenerationConflict`]
    /// with nothing written. It sets the client's admission and records `endpoint` only when
    /// the client has none: an existing endpoint is **never replaced** (that is the
    /// rotation form's job) and is answered as [`OwnerEndpoint::Kept`]. Another client's
    /// endpoint is a conflict. No generation moves (a first endpoint, as at a join).
    pub fn admit_bootstrap_owner_iroh(
        &mut self,
        client: &ClientId,
        endpoint: &IrohEndpointId,
        now: Timestamp,
    ) -> Result<OwnerEndpoint> {
        let Some(record) = self.remote_client(client)? else {
            return Err(missing());
        };
        if record.state != ClientState::Active
            || record.role != Role::Owner
            || record.invitation.is_some()
        {
            return Err(conflict("only the bootstrap owner is admitted this way"));
        }
        if let Some((current, _)) = self.remote_client_endpoint(client)?
            && &current != endpoint
        {
            // Admission stands (it was needed to record `current`); the endpoint is kept.
            self.admit_remote_client_iroh(client)?;
            return Ok(OwnerEndpoint::Kept(current));
        }
        self.admit_remote_client_iroh(client)?;
        Ok(
            match self.set_remote_client_endpoint(client, endpoint, now)? {
                EndpointChange::Recorded => OwnerEndpoint::Recorded,
                EndpointChange::Unchanged | EndpointChange::Replaced(_) => OwnerEndpoint::Unchanged,
            },
        )
    }

    /// Set or replace `client`'s Iroh endpoint ID (`join`'s commit transaction, or the
    /// client's rotation form). The client must be **active** and admitted over Iroh
    /// ([`Self::remote_client_iroh_admission`]; the caller checked both against the records
    /// it read in this transaction; they are checked again here). A first endpoint is recorded with no
    /// generation move, insert-if-absent (a first set never overwrites a row; the serve child
    /// learns of it by its replacement, U56-Q10); a different endpoint replaces the row by a
    /// compare-and-set on the current one and moves the admission authority generation in
    /// this transaction (module docs); the same endpoint again writes nothing. Another client's endpoint, a client that is not active or whose
    /// invitation did not admit Iroh, is [`StoreError::GenerationConflict`] and writes
    /// nothing; a missing client is `QueryReturnedNoRows`.
    pub fn set_remote_client_endpoint(
        &mut self,
        client: &ClientId,
        endpoint: &IrohEndpointId,
        now: Timestamp,
    ) -> Result<EndpointChange> {
        let Some(record) = self.remote_client(client)? else {
            return Err(missing());
        };
        if record.state != ClientState::Active {
            return Err(conflict("only an active client records an endpoint"));
        }
        // ⟨§18.7 item 8⟩ The client's own attribute (a first set reads it).
        if !self.remote_client_iroh_admission(client)? {
            return Err(conflict("the client is not admitted over Iroh"));
        }
        let holder: Option<String> = self
            .tx
            .query_row(
                "SELECT client_id FROM remote_client_endpoints WHERE endpoint_id = ?1",
                [endpoint.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        if holder.as_deref().is_some_and(|h| h != client.as_str()) {
            return Err(conflict("the endpoint is another client's"));
        }
        match self.remote_client_endpoint(client)? {
            Some((current, _)) if &current == endpoint => Ok(EndpointChange::Unchanged),
            Some((current, _)) => {
                // A compare-and-set on the endpoint read above: a concurrent writer that
                // replaced it first wins, and this one writes nothing.
                let n = self.tx.execute(
                    "UPDATE remote_client_endpoints SET endpoint_id = ?3, recorded_at = ?4
                     WHERE client_id = ?1 AND endpoint_id = ?2",
                    rusqlite::params![
                        client.as_str(),
                        current.as_str(),
                        endpoint.as_str(),
                        codec::ts(now)
                    ],
                )?;
                if n != 1 {
                    return Err(conflict("the client's endpoint changed meanwhile"));
                }
                Ok(EndpointChange::Replaced(
                    self.bump_remote_authority_generation(now)?,
                ))
            }
            None => {
                // ⟨orchestrator condition 2, 2026-11-21⟩ A first set is insert-if-absent in one
                // statement: of two concurrent first sets only one inserts, and a first set
                // never overwrites a row (the same endpoint again is a no-op).
                let n = self.tx.execute(
                    "INSERT INTO remote_client_endpoints (client_id, endpoint_id, recorded_at)
                     VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
                    rusqlite::params![client.as_str(), endpoint.as_str(), codec::ts(now)],
                )?;
                if n == 1 {
                    return Ok(EndpointChange::Recorded);
                }
                match self.remote_client_endpoint(client)? {
                    Some((current, _)) if &current == endpoint => Ok(EndpointChange::Unchanged),
                    _ => Err(conflict("another endpoint was recorded first")),
                }
            }
        }
    }

    /// `client`'s endpoint ID and when it was recorded, whatever the client's state.
    pub fn remote_client_endpoint(
        &mut self,
        client: &ClientId,
    ) -> Result<Option<(IrohEndpointId, Timestamp)>> {
        let raw: Option<(String, String)> = self
            .tx
            .query_row(
                "SELECT endpoint_id, recorded_at FROM remote_client_endpoints
                 WHERE client_id = ?1",
                [client.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        raw.map(|(e, at)| {
            let e = IrohEndpointId::parse(&e)
                .map_err(|_| StoreError::Corrupt("a client endpoint ID is malformed".into()))?;
            Ok((e, codec::parse_ts(&at)?))
        })
        .transpose()
    }

    /// The serve allowlist's source (ADR-0012 §2.3 item 1): every **active**, non-tombstoned
    /// client's endpoint ID, by client ID. A row of a client that is not active (a
    /// tombstone's row is deleted with it; this filter is the second guard) is left out.
    pub fn remote_client_endpoints(&mut self) -> Result<Vec<(ClientId, IrohEndpointId)>> {
        let mut stmt = self.tx.prepare(
            "SELECT e.client_id, e.endpoint_id FROM remote_client_endpoints e
             JOIN remote_clients c ON c.client_id = e.client_id
             WHERE c.state = ?1 ORDER BY e.client_id",
        )?;
        let active = codec::enum_str(&ClientState::Active)?;
        let rows = stmt.query_map([active], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (c, e) = row?;
            let c = ClientId::parse(&c).map_err(|_| {
                StoreError::Corrupt("a client endpoint's client is malformed".into())
            })?;
            let e = IrohEndpointId::parse(&e)
                .map_err(|_| StoreError::Corrupt("a client endpoint ID is malformed".into()))?;
            out.push((c, e));
        }
        Ok(out)
    }

    /// ⟨M06-W3-R01⟩ `transport disable`'s part of the serve allowlist (ADR-0012 §2.5): delete
    /// **every** client's endpoint ID, whatever the client's state, and move the admission
    /// authority generation when any row went, in the caller's transaction (the narrowing
    /// write's). Returns how many rows went. A client is admitted again only by recording an
    /// endpoint anew over its K_mgmt session (its rotation form).
    pub fn clear_remote_client_endpoints(&mut self, now: Timestamp) -> Result<usize> {
        let n = self.tx.execute("DELETE FROM remote_client_endpoints", [])?;
        if n > 0 {
            self.bump_remote_authority_generation(now)?;
        }
        Ok(n)
    }

    // --- the admission authority generation ---------------------------------------------

    /// The runner's admission authority generation (0 before the first change).
    pub fn remote_authority_generation(&mut self) -> Result<u64> {
        let v: Option<i64> = self
            .tx
            .query_row(
                "SELECT generation FROM remote_authority_generation WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        v.map_or(Ok(0), codec::uint)
    }

    /// Move the admission authority generation up by one; returns the new value. ⟨M06 W2,
    /// U56-Q3⟩ The single writer of `remote_authority_generation`: the client tombstone here
    /// and every narrowing in [`crate::ext_transport`] (`Txn::narrow_remote_admission`)
    /// move it through this function only.
    pub(crate) fn bump_remote_authority_generation(&mut self, now: Timestamp) -> Result<u64> {
        let next = self
            .remote_authority_generation()?
            .checked_add(1)
            .ok_or_else(|| codec::doc_error("the admission authority generation overflowed"))?;
        self.tx.execute(
            "INSERT INTO remote_authority_generation (id, generation, updated_at)
             VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET generation = excluded.generation,
                 updated_at = excluded.updated_at",
            rusqlite::params![codec::int(next)?, codec::ts(now)],
        )?;
        Ok(next)
    }

    // --- ⟨M06 W2⟩ the runner-local widening records (ADR-0012 §3.10; migration 0010) ----

    fn remote_widening_row(
        &mut self,
        where_sql: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<Option<(DecisionRecord, RemoteWideningRow)>> {
        let sql = format!(
            "SELECT decision_id, origin, client_id, request_kind, request_id, request_hash,
                 result_json, delta_digest
             FROM remote_widening WHERE {where_sql}"
        );
        type Raw = (
            String,
            String,
            Option<String>,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
        );
        let raw: Option<Raw> = self
            .tx
            .query_row(&sql, params, |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            })
            .optional()?;
        let Some((
            decision,
            origin,
            client,
            request_kind,
            request_id,
            request_hash,
            result,
            digest,
        )) = raw
        else {
            return Ok(None);
        };
        let decision = DecisionId::parse(&decision).map_err(|_| {
            StoreError::Corrupt("a widening record's decision ID is malformed".into())
        })?;
        let Some(record) = self.decision(&decision)? else {
            return Err(StoreError::Corrupt(
                "a widening record names a decision that does not exist".into(),
            ));
        };
        let DecisionKind::RemoteWidening(w) = &record.kind else {
            return Err(StoreError::Corrupt(
                "a widening record names a decision of another kind".into(),
            ));
        };
        let client = client
            .map(|c| {
                ClientId::parse(&c).map_err(|_| {
                    StoreError::Corrupt("a widening record's client is malformed".into())
                })
            })
            .transpose()?;
        // ⟨M06 W5; ADR-0006 §18.9 item 8⟩ The origin is read from the row and must agree with
        // the decision document and with the client and digest columns (the CHECK constraint
        // again, so a row that got past it some other way is still never decided).
        let origin = match (origin.as_str(), &client, &digest) {
            ("paired", Some(_), None) => WideningOrigin::Paired,
            ("local", None, Some(_)) => WideningOrigin::Local,
            _ => {
                return Err(StoreError::Corrupt(
                    "a widening record's origin does not fit its client".into(),
                ));
            }
        };
        if w.origin != origin || w.client != client || !w.origin_is_consistent() {
            return Err(StoreError::Corrupt(
                "a widening record's origin differs from its decision's".into(),
            ));
        }
        let row = RemoteWideningRow {
            decision,
            origin,
            client,
            request_kind,
            request_id: RequestId::parse(&request_id).map_err(|_| {
                StoreError::Corrupt("a widening record's request ID is malformed".into())
            })?,
            request_hash,
            delta_digest: digest,
            result: result
                .map(|text| {
                    serde_json::from_str(&text).map_err(|_| {
                        StoreError::Corrupt("a widening record's result is malformed".into())
                    })
                })
                .transpose()?,
        };
        Ok(Some((record, row)))
    }

    /// Insert a widening record: its `remote_widening` decision (pending, as
    /// [`Txn::insert_decision`] requires) and its side row, in this transaction. The
    /// decision must be of kind [`DecisionKind::RemoteWidening`].
    ///
    /// * **A paired record** (`origin = paired`) names its client and no `delta_digest`;
    ///   its key `(client, request kind, request ID)` must be new.
    /// * ⟨M06 W5; ADR-0006 §18.9 item 8⟩ **A local record** (`origin = local`) names no
    ///   client and carries its `delta_digest`; no other local record of the same request
    ///   kind and digest may be pending.
    ///
    /// A decision ID, key, or pending local digest that exists is a
    /// [`StoreError::GenerationConflict`] and writes nothing; an origin that does not fit
    /// the client or the digest is a document error and writes nothing. Moves no generation
    /// (the record grants nothing).
    pub fn insert_remote_widening(
        &mut self,
        decision: &DecisionRecord,
        request_hash: &str,
        delta_digest: Option<&str>,
    ) -> Result<()> {
        let DecisionKind::RemoteWidening(w) = &decision.kind else {
            return Err(codec::doc_error(
                "a widening record is a remote_widening decision",
            ));
        };
        if !w.origin_is_consistent() {
            return Err(codec::doc_error(
                "a widening record's origin does not fit its client",
            ));
        }
        match (w.origin, &w.client, delta_digest) {
            (WideningOrigin::Paired, Some(client), None) => {
                if self
                    .remote_widening_by_key(client, &w.request_kind, &w.request_id)?
                    .is_some()
                {
                    return Err(conflict("a widening record with this key exists"));
                }
            }
            (WideningOrigin::Local, None, Some(digest)) => {
                if self
                    .pending_local_widening(&w.request_kind, digest)?
                    .is_some()
                {
                    return Err(conflict(
                        "a pending local widening record for this delta exists",
                    ));
                }
            }
            _ => {
                return Err(codec::doc_error(
                    "a widening record's delta digest does not fit its origin",
                ));
            }
        }
        self.insert_decision(decision)?;
        self.tx.execute(
            "INSERT INTO remote_widening (decision_id, origin, client_id, request_kind,
                 request_id, request_hash, result_json, delta_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
            rusqlite::params![
                decision.id.as_str(),
                w.origin.as_str(),
                w.client.as_ref().map(ClientId::as_str),
                w.request_kind,
                w.request_id.as_str(),
                request_hash,
                delta_digest,
            ],
        )?;
        Ok(())
    }

    /// One runner-local widening record by its decision ID.
    pub fn remote_widening(
        &mut self,
        id: &DecisionId,
    ) -> Result<Option<(DecisionRecord, RemoteWideningRow)>> {
        self.remote_widening_row("decision_id = ?1", &[&id.as_str()])
    }

    /// One paired widening record by its caller-namespaced key (ADR-0012 §3.7). A local
    /// record has no client and is never found here.
    pub fn remote_widening_by_key(
        &mut self,
        client: &ClientId,
        request_kind: &str,
        request_id: &RequestId,
    ) -> Result<Option<(DecisionRecord, RemoteWideningRow)>> {
        self.remote_widening_row(
            "origin = 'paired' AND client_id = ?1 AND request_kind = ?2 AND request_id = ?3",
            &[&client.as_str(), &request_kind, &request_id.as_str()],
        )
    }

    /// ⟨M06 W5; ADR-0006 §18.9 item 8⟩ The pending local widening record of `request_kind`
    /// and `delta_digest`, if any (at most one: [`Txn::insert_remote_widening`] refuses a
    /// second). Expiry is the caller's to judge: the store compares no clock.
    pub fn pending_local_widening(
        &mut self,
        request_kind: &str,
        delta_digest: &str,
    ) -> Result<Option<(DecisionRecord, RemoteWideningRow)>> {
        self.remote_widening_row(
            "origin = 'local' AND request_kind = ?1 AND delta_digest = ?2
             AND decision_id IN (SELECT id FROM decisions WHERE state = 'pending')",
            &[&request_kind, &delta_digest],
        )
    }

    /// Settle a pending runner-local widening record to `state` at `at` (a compare-and-set
    /// on `pending`, consume-once), with its terminal `result` when already known (a
    /// denial, a lapse). `decided_at` is `at`. A record that is not pending is a
    /// [`StoreError::GenerationConflict`] and writes nothing; a missing one is
    /// `QueryReturnedNoRows`. Returns the record as stored.
    pub fn settle_remote_widening(
        &mut self,
        id: &DecisionId,
        state: DecisionState,
        at: Timestamp,
        result: Option<&serde_json::Value>,
    ) -> Result<(DecisionRecord, RemoteWideningRow)> {
        let Some((mut record, _)) = self.remote_widening(id)? else {
            return Err(missing());
        };
        if record.state != DecisionState::Pending || state == DecisionState::Pending {
            return Err(conflict("the widening record is not pending"));
        }
        record.state = state;
        record.decided_at = Some(at);
        self.write_decision(&record)?;
        if let Some(result) = result {
            self.tx.execute(
                "UPDATE remote_widening SET result_json = ?2 WHERE decision_id = ?1",
                rusqlite::params![id.as_str(), codec::doc(result)?],
            )?;
        }
        self.remote_widening(id)?.ok_or_else(missing)
    }

    /// Record the terminal result of an approved runner-local widening record that has none
    /// yet. Anything else is a [`StoreError::GenerationConflict`] and writes nothing; a
    /// missing record is `QueryReturnedNoRows`. Returns the record as stored.
    pub fn record_remote_widening_result(
        &mut self,
        id: &DecisionId,
        result: &serde_json::Value,
    ) -> Result<(DecisionRecord, RemoteWideningRow)> {
        let Some((record, row)) = self.remote_widening(id)? else {
            return Err(missing());
        };
        if record.state != DecisionState::Approved || row.result.is_some() {
            return Err(conflict("the widening record has no result to record"));
        }
        let n = self.tx.execute(
            "UPDATE remote_widening SET result_json = ?2
             WHERE decision_id = ?1 AND result_json IS NULL",
            rusqlite::params![id.as_str(), codec::doc(result)?],
        )?;
        if n == 0 {
            return Err(conflict("the widening record has no result to record"));
        }
        self.remote_widening(id)?.ok_or_else(missing)
    }
}

// --- ⟨M08 W4 SEC-3b⟩ R4: the widening records are bounded --------------------------------
//
// ADR-0006 §7.4 and ADR-0012 §7.4 as amended 2026-11-27 (ruling of 2026-11-26, R4). A paired
// client's pending widening records are capped (`BACKPRESSURE`); a pending record past its
// deadline is settled `expired` by the retention pass; a settled record is purged
// `retention.operations` after its decision, leaving a 30-day expired-key marker so a replay of
// its key answers `REQUEST_EXPIRED`. An approved record with no recorded result
// (`OUTCOME_UNKNOWN`) is never purged.

/// ⟨M08 W4 SEC-3b, R4⟩ The most pending (not yet expired) widening records one paired client
/// may have; past it a new submission is refused `BACKPRESSURE`.
pub const PENDING_WIDENING_PER_CLIENT: usize = 32;

/// ⟨M08 W4 SEC-3b, R4⟩ The most pending widening records of every paired client together
/// (below ADR-0013 §5.5's 256 pending decisions of an event snapshot).
pub const PENDING_WIDENING_TOTAL: usize = 128;

/// ⟨M08 W4 SEC-3b, R4⟩ The expired-key marker key (`idempotency_markers.key_hash`) of a widening
/// record's key: SHA-256 (hex) over the canonical JSON of its origin, client, request kind and
/// request ID, in its own domain, so it never equals an operation key's hash.
///
/// # Errors
/// When the key cannot be encoded (it always can).
pub fn widening_marker_key(
    client: Option<&ClientId>,
    request_kind: &str,
    request_id: &RequestId,
) -> Result<String> {
    let value = serde_json::json!({
        "origin": if client.is_some() { "paired" } else { "local" },
        "client": client,
        "kind": request_kind,
        "request_id": request_id,
    });
    heimdall_contract::canonical::request_hash("remote-widening-marker", &value)
        .map(|h| h.to_hex())
        .map_err(|_| codec::doc_error("a widening record's key cannot be encoded"))
}

impl Txn<'_> {
    /// ⟨M08 W4 SEC-3b, R4⟩ The pending paired widening records still before their deadline at
    /// `now`: `client`'s, and every client's.
    pub fn pending_paired_widening_counts(
        &mut self,
        client: &ClientId,
        now: Timestamp,
    ) -> Result<(usize, usize)> {
        let pending = codec::enum_str(&DecisionState::Pending)?;
        let base = "SELECT count(*) FROM remote_widening w JOIN decisions d ON d.id = w.decision_id
                    WHERE w.origin = 'paired' AND d.state = ?1 AND d.expires_at > ?2";
        let mine: i64 = self.tx.query_row(
            &format!("{base} AND w.client_id = ?3"),
            rusqlite::params![pending, codec::ts(now), client.as_str()],
            |r| r.get(0),
        )?;
        let all: i64 =
            self.tx
                .query_row(base, rusqlite::params![pending, codec::ts(now)], |r| {
                    r.get(0)
                })?;
        Ok((
            usize::try_from(mine).unwrap_or(usize::MAX),
            usize::try_from(all).unwrap_or(usize::MAX),
        ))
    }

    /// ⟨M08 W4 SEC-3b, R4⟩ Whether the expired-key marker `key` ([`widening_marker_key`]) is
    /// still live at `now`: a record of that key was purged within the marker window.
    pub fn widening_marker_live(&mut self, key: &str, now: Timestamp) -> Result<bool> {
        let n: i64 = self.tx.query_row(
            "SELECT count(*) FROM idempotency_markers WHERE key_hash = ?1 AND marker_until > ?2",
            rusqlite::params![key, codec::ts(now)],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// ⟨M08 W4 SEC-3b, R4⟩ The pending paired widening records whose deadline is at or before
    /// `now` (the retention pass settles them `expired`).
    pub fn expired_paired_widening(&mut self, now: Timestamp) -> Result<Vec<DecisionRecord>> {
        self.docs(
            "SELECT d.record_json FROM remote_widening w JOIN decisions d ON d.id = w.decision_id
             WHERE w.origin = 'paired' AND d.state = ?1 AND d.expires_at <= ?2
             ORDER BY d.expires_at, d.id",
            rusqlite::params![codec::enum_str(&DecisionState::Pending)?, codec::ts(now)],
        )
    }

    /// ⟨M08 W4 SEC-3b, R4⟩ Purge every settled widening record decided at or before `now` −
    /// `retention` (the time the retention pass's time gate accepted): its side row, then its
    /// decision, leaving an expired-key marker of its key until 30 days after its retention
    /// ended (`heimdall_domain::idempotency::marker_until`). A pending record, and an approved
    /// one with no recorded result (`OUTCOME_UNKNOWN`), are never purged. The number purged.
    pub fn purge_settled_widening(&mut self, now: Timestamp, retention: Duration) -> Result<usize> {
        type Row = (
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            String,
            String,
        );
        let rows: Vec<Row> = {
            let mut stmt = self.tx.prepare(
                "SELECT w.decision_id, w.client_id, w.request_kind, w.request_id, w.result_json,
                        d.state, d.decided_at
                 FROM remote_widening w JOIN decisions d ON d.id = w.decision_id
                 WHERE d.state <> ?1 AND d.decided_at IS NOT NULL",
            )?;
            let rows = stmt.query_map([codec::enum_str(&DecisionState::Pending)?], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let approved = codec::enum_str(&DecisionState::Approved)?;
        let span = jiff::SignedDuration::try_from(retention)
            .map_err(|_| codec::doc_error("the retention does not fit a duration"))?;
        let mut purged = 0usize;
        for (decision, client, kind, request_id, result, state, decided_at) in rows {
            // `OUTCOME_UNKNOWN`: approved, and no result recorded. Never purged.
            if state == approved && result.is_none() {
                continue;
            }
            let expired_at = codec::parse_ts(&decided_at)?
                .checked_add(span)
                .unwrap_or(Timestamp::MAX);
            if expired_at > now {
                continue;
            }
            let client = client
                .map(|c| {
                    ClientId::parse(&c).map_err(|_| {
                        StoreError::Corrupt("a widening record's client is malformed".into())
                    })
                })
                .transpose()?;
            let request_id = RequestId::parse(&request_id).map_err(|_| {
                StoreError::Corrupt("a widening record's request ID is malformed".into())
            })?;
            let key = widening_marker_key(client.as_ref(), &kind, &request_id)?;
            let until = heimdall_domain::idempotency::marker_until(expired_at);
            self.tx.execute(
                "INSERT INTO idempotency_markers (key_hash, expired_at, marker_until)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(key_hash) DO UPDATE SET
                     expired_at = max(expired_at, excluded.expired_at),
                     marker_until = max(marker_until, excluded.marker_until)",
                rusqlite::params![key, codec::ts(expired_at), codec::ts(until)],
            )?;
            self.tx.execute(
                "DELETE FROM remote_widening WHERE decision_id = ?1",
                [decision.as_str()],
            )?;
            purged += self
                .tx
                .execute("DELETE FROM decisions WHERE id = ?1", [decision.as_str()])?;
        }
        Ok(purged)
    }
}

// --- ⟨M06 U2⟩ the controller's environment records and the bootstrap owner -------------

/// The largest controller pin document accepted (a record names one route and at most 16
/// pinned host keys).
const MAX_PIN_RECORD_BYTES: usize = 64 * 1024;

impl Txn<'_> {
    /// ⟨M06 U2⟩ Every controller environment record (`remote_environment_pins`; ADR-0012
    /// §7.5), by environment ID: `(environment, record_json)`. The document is
    /// `heimdall_app::remote_env::RemoteEnvironmentRecord`, which the store cannot name, so it
    /// is returned as text; the other columns mirror it for lookups.
    pub fn remote_environment_pins(&mut self) -> Result<Vec<(EnvironmentId, String)>> {
        let mut stmt = self.tx.prepare(
            "SELECT environment_id, record_json FROM remote_environment_pins
             ORDER BY environment_id",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, json) = row?;
            let id = EnvironmentId::parse(&id).map_err(|_| {
                StoreError::Corrupt("a controller pin names a malformed environment".into())
            })?;
            out.push((id, json));
        }
        Ok(out)
    }

    /// ⟨M06 U2⟩ Insert or replace the controller record of `environment` (a first `add` or
    /// `join`, or a repair through independently verified access). `record_json` must be one
    /// JSON object of at most 64 KiB ([`codec::doc_error`] otherwise, nothing written).
    /// Moves no generation: the record is the controller's view of a runner, and grants
    /// nothing on this installation.
    pub fn put_remote_environment_pin(
        &mut self,
        environment: &EnvironmentId,
        destination: &DestinationId,
        account: &AccountName,
        host_fingerprint: &KeyFingerprint,
        record_json: &str,
        pinned_at: Timestamp,
    ) -> Result<()> {
        let is_object = record_json.len() <= MAX_PIN_RECORD_BYTES
            && serde_json::from_str::<serde_json::Value>(record_json).is_ok_and(|v| v.is_object());
        if !is_object {
            return Err(codec::doc_error(
                "a controller pin record is one JSON object of at most 64 KiB",
            ));
        }
        self.tx.execute(
            "INSERT INTO remote_environment_pins (environment_id, destination, account,
                 host_fingerprint, record_json, pinned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(environment_id) DO UPDATE SET destination = excluded.destination,
                 account = excluded.account, host_fingerprint = excluded.host_fingerprint,
                 record_json = excluded.record_json, pinned_at = excluded.pinned_at",
            rusqlite::params![
                environment.as_str(),
                destination.as_str(),
                account.as_str(),
                host_fingerprint.as_str(),
                record_json,
                codec::ts(pinned_at),
            ],
        )?;
        Ok(())
    }

    /// ⟨M06 U2⟩ Remove the controller record of `environment`; `false` when there was none.
    pub fn remove_remote_environment_pin(&mut self, environment: &EnvironmentId) -> Result<bool> {
        let n = self.tx.execute(
            "DELETE FROM remote_environment_pins WHERE environment_id = ?1",
            [environment.as_str()],
        )?;
        Ok(n > 0)
    }

    /// ⟨M06 U2⟩ The bootstrap's owner enrollment on the runner (ADR-0012 §3.3 step 3):
    /// `client` is inserted **active** with role `owner`, no invitation, no revocation and
    /// line state [`AppliedLine::Absent`] (the line is written after this commit), moving the
    /// authority generation (⟨W3⟩ never the admission authority generation: an enrollment
    /// widens; module docs). The caller confirmed it on the runner's own terminal (a
    /// runner-local widening, §3.10).
    ///
    /// Idempotent for a retried bootstrap of the same key: a non-revoked **active owner**
    /// that already holds this key fingerprint (under this client ID or another one) is
    /// returned unchanged with `false`, moving nothing, so a first `add` that failed after
    /// this commit can be repeated. Anything else holding the key (a pending or limited
    /// client), or a client ID that exists with another key, role or state, is
    /// [`StoreError::GenerationConflict`] and writes nothing. Returns the effective owner
    /// client and whether it was created now.
    pub fn enroll_bootstrap_owner(
        &mut self,
        client: &RemoteClientRecord,
        _now: Timestamp,
    ) -> Result<(RemoteClientRecord, bool)> {
        let consistent = client.state == ClientState::Active
            && client.role == Role::Owner
            && client.invitation.is_none()
            && client.revoked_generation.is_none()
            && client.revocation.is_none()
            && client.line == AppliedLine::Absent;
        if !consistent {
            return Err(codec::doc_error(
                "a bootstrap owner is inserted active, owner, with no invitation or line",
            ));
        }
        let holders: Vec<RemoteClientRecord> = self
            .remote_clients_with_key(&client.key_fingerprint)?
            .into_iter()
            .filter(|c| c.state != ClientState::Revoked)
            .collect();
        if let Some(owner) = holders
            .iter()
            .find(|c| c.state == ClientState::Active && c.role == Role::Owner)
        {
            return Ok((owner.clone(), false));
        }
        if !holders.is_empty() {
            return Err(conflict("the key is already authorized for another client"));
        }
        if self.remote_client(&client.client)?.is_some() {
            return Err(conflict("the client already exists with another key"));
        }
        self.write_client(client, true)?;
        self.bump_generation()?;
        Ok((client.clone(), true))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod controller_tests {
    use std::sync::Arc;

    use super::*;
    use crate::{NoFaults, Store};

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn fp(c: char) -> KeyFingerprint {
        KeyFingerprint::parse(&format!("SHA256:{}", c.to_string().repeat(43))).unwrap()
    }

    fn owner(n: u8, key: char) -> RemoteClientRecord {
        RemoteClientRecord {
            client: ClientId::from_random_bytes([n; 16]),
            role: Role::Owner,
            key_fingerprint: fp(key),
            public_key: "ssh-ed25519 AAAA".into(),
            state: ClientState::Active,
            invitation: None,
            revoked_generation: None,
            revocation: None,
            created_at: t("2026-11-21T10:00:00Z"),
            updated_at: t("2026-11-21T10:00:00Z"),
            line: AppliedLine::Absent,
        }
    }

    /// The controller's records: insert, replace (one row per environment), list, remove;
    /// a document that is not one JSON object is refused with nothing written.
    #[test]
    fn controller_pins_insert_replace_list_and_remove() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let env = EnvironmentId::from_random_bytes([1; 16]);
        let dest = DestinationId::parse("lab").unwrap();
        let account = AccountName::parse("runner").unwrap();
        store
            .transaction(|tx| {
                tx.put_remote_environment_pin(
                    &env,
                    &dest,
                    &account,
                    &fp('A'),
                    r#"{"v":1}"#,
                    t("2026-11-21T10:00:00Z"),
                )?;
                tx.put_remote_environment_pin(
                    &env,
                    &dest,
                    &account,
                    &fp('B'),
                    r#"{"v":2}"#,
                    t("2026-11-21T11:00:00Z"),
                )
            })
            .unwrap();
        let pins = store
            .transaction(|tx| tx.remote_environment_pins())
            .unwrap();
        assert_eq!(pins, vec![(env.clone(), r#"{"v":2}"#.to_owned())]);
        for bad in ["[1]", "not json", "\"text\""] {
            assert!(
                store
                    .transaction(|tx| tx.put_remote_environment_pin(
                        &env,
                        &dest,
                        &account,
                        &fp('C'),
                        bad,
                        t("2026-11-21T12:00:00Z"),
                    ))
                    .is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            store
                .transaction(|tx| tx.remote_environment_pins())
                .unwrap()[0]
                .1,
            r#"{"v":2}"#
        );
        assert!(
            store
                .transaction(|tx| tx.remove_remote_environment_pin(&env))
                .unwrap()
        );
        assert!(
            !store
                .transaction(|tx| tx.remove_remote_environment_pin(&env))
                .unwrap()
        );
        assert!(
            store
                .transaction(|tx| tx.remote_environment_pins())
                .unwrap()
                .is_empty()
        );
    }

    /// The bootstrap owner: inserted active, moving the authority generation and (⟨W3, ruling
    /// W0C-Q4⟩ an enrollment widens) not the admission authority generation; a retried
    /// bootstrap of the same key (same or new client ID) returns the existing owner
    /// and moves nothing; a key held by a pending or limited client, or a client ID taken by
    /// another key, is a conflict that writes nothing.
    #[test]
    fn bootstrap_owner_is_enrolled_once_and_retries_are_idempotent() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let now = t("2026-11-21T10:00:00Z");
        let (rec, created) = store
            .transaction(|tx| tx.enroll_bootstrap_owner(&owner(1, 'K'), now))
            .unwrap();
        assert!(created);
        let generation = store
            .transaction(|tx| tx.remote_authority_generation())
            .unwrap();
        assert_eq!(generation, 0);
        let authority = store.transaction(|tx| tx.authority_generation()).unwrap();
        for retry in [owner(1, 'K'), owner(2, 'K')] {
            let (again, created) = store
                .transaction(|tx| tx.enroll_bootstrap_owner(&retry, now))
                .unwrap();
            assert!(!created);
            assert_eq!(again.client, rec.client);
        }
        assert_eq!(
            store
                .transaction(|tx| tx.remote_authority_generation())
                .unwrap(),
            0
        );
        assert_eq!(
            store.transaction(|tx| tx.authority_generation()).unwrap(),
            authority,
            "a retry moves nothing"
        );
        assert!(
            store
                .transaction(|tx| tx.enroll_bootstrap_owner(&owner(1, 'Z'), now))
                .is_err()
        );
        let mut limited = owner(3, 'L');
        limited.role = Role::Viewer;
        assert!(
            store
                .transaction(|tx| tx.enroll_bootstrap_owner(&limited, now))
                .is_err()
        );
        assert_eq!(
            store.transaction(|tx| tx.remote_clients()).unwrap().len(),
            1
        );
    }
}

/// ⟨M06 W2⟩ The side half of a runner-local widening record (`remote_widening`, migration
/// 0010; ADR-0012 §3.10): the caller-namespaced key, the request's canonical hash and the
/// recorded terminal result. The decision record itself is in `decisions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteWideningRow {
    /// The decision record.
    pub decision: DecisionId,
    /// ⟨M06 W5; migration 0013⟩ Who submitted the request.
    pub origin: WideningOrigin,
    /// The paired client that submitted the request; `None` exactly for a local record.
    pub client: Option<ClientId>,
    /// The request kind.
    pub request_kind: String,
    /// The request ID.
    pub request_id: RequestId,
    /// The request's canonical hash (lowercase hex).
    pub request_hash: String,
    /// ⟨M06 W5⟩ A local record's lookup key: the digest of its exact request (without the
    /// request ID) and exact exposure delta; `None` exactly for a paired record.
    pub delta_digest: Option<String>,
    /// The recorded terminal result (a redacted envelope), once there is one.
    pub result: Option<serde_json::Value>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{NoFaults, Store};

    fn now(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn fp() -> KeyFingerprint {
        KeyFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap()
    }

    fn pair(n: u8) -> (RemoteClientRecord, RemoteInvitationRecord) {
        let at = now("2026-11-20T10:00:00Z");
        let client = ClientId::from_random_bytes([n; 16]);
        let invitation = InvitationId::from_random_bytes([n; 16]);
        (
            RemoteClientRecord {
                client: client.clone(),
                role: Role::Requester,
                key_fingerprint: fp(),
                public_key: "ssh-ed25519 AAAA".into(),
                state: ClientState::Pending,
                invitation: Some(invitation.clone()),
                revoked_generation: None,
                revocation: None,
                created_at: at,
                updated_at: at,
                line: AppliedLine::Absent,
            },
            RemoteInvitationRecord {
                invitation,
                client,
                role: Role::Requester,
                key_fingerprint: fp(),
                generation: 4,
                created_wall: at,
                created_boot_id: BootId("boot-1".into()),
                created_elapsed: Duration::from_secs(100),
                expires_wall: now("2026-11-20T10:15:00Z"),
                elapsed_bound: Duration::from_secs(900),
                probe_nonce: "00".repeat(16),
                state: InvitationState::Pending,
                consumed_at: None,
                join: None,
                iroh_admission: false,
            },
        )
    }

    fn join_of(inv: &RemoteInvitationRecord) -> JoinRecord {
        JoinRecord {
            environment: EnvironmentId::from_random_bytes([7; 16]),
            invitation: inv.invitation.clone(),
            client: inv.client.clone(),
            role: inv.role,
            generation: inv.generation,
            joined_at: now("2026-11-20T10:05:00Z"),
        }
    }

    /// Invite, join once (a second join is a conflict that writes nothing), revoke (the
    /// tombstone records the admission generation; a second revoke changes nothing); each
    /// change moves the authority generation; ⟨W3, ruling W0C-Q4⟩ only the tombstone moves
    /// the admission authority generation; the line bookkeeping moves neither.
    #[test]
    fn invite_join_revoke_round_trip_and_generations() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let (client, inv) = pair(1);
        let at = client.created_at;
        let g = store
            .transaction(|tx| {
                let g0 = tx.authority_generation()?;
                let r = tx.insert_remote_invitation(&client, &inv, at)?;
                assert!(tx.authority_generation()? > g0);
                Ok(r)
            })
            .unwrap();
        assert_eq!(g, 0, "an invitation widens: the admission generation stays");
        let dup = store.transaction(|tx| tx.insert_remote_invitation(&client, &inv, at));
        assert!(matches!(dup, Err(StoreError::GenerationConflict(_))));

        let (active, consumed) = store
            .transaction(|tx| tx.activate_remote_client(&join_of(&inv)))
            .unwrap();
        assert_eq!(active.state, ClientState::Active);
        assert_eq!(consumed.state, InvitationState::Consumed);
        assert_eq!(consumed.join, Some(join_of(&inv)));
        let again = store.transaction(|tx| tx.activate_remote_client(&join_of(&inv)));
        assert!(matches!(again, Err(StoreError::GenerationConflict(_))));

        let before = store
            .transaction(|tx| tx.remote_authority_generation())
            .unwrap();
        assert_eq!(
            before, 0,
            "an activation widens: the admission generation stays"
        );
        store
            .transaction(|tx| tx.set_remote_client_line(&client.client, AppliedLine::Active))
            .unwrap();
        assert_eq!(
            store
                .transaction(|tx| tx.remote_authority_generation())
                .unwrap(),
            before
        );

        let revoked = store
            .transaction(|tx| tx.revoke_remote_client(&client.client, RevocationCause::Revoked, at))
            .unwrap();
        assert_eq!(revoked.state, ClientState::Revoked);
        assert_eq!(revoked.revoked_generation, Some(before + 1));
        assert_eq!(revoked.line, AppliedLine::Active, "bookkeeping kept");
        let twice = store
            .transaction(|tx| tx.revoke_remote_client(&client.client, RevocationCause::Revoked, at))
            .unwrap();
        assert_eq!(twice, revoked);
        assert_eq!(
            store
                .transaction(|tx| tx.remote_authority_generation())
                .unwrap(),
            before + 1
        );
    }

    /// An expired pending invitation tombstones its client and becomes `expired`; a join
    /// afterwards is a conflict. A mismatched join writes nothing.
    #[test]
    fn expiry_tombstones_and_mismatched_join_writes_nothing() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let (client, inv) = pair(2);
        let at = client.created_at;
        store
            .transaction(|tx| tx.insert_remote_invitation(&client, &inv, at))
            .unwrap();
        let mut wrong = join_of(&inv);
        wrong.role = Role::Owner;
        assert!(matches!(
            store.transaction(|tx| tx.activate_remote_client(&wrong)),
            Err(StoreError::GenerationConflict(_))
        ));
        assert_eq!(
            store
                .transaction(|tx| tx.remote_invitation(&inv.invitation))
                .unwrap()
                .unwrap()
                .state,
            InvitationState::Pending
        );
        store
            .transaction(|tx| {
                tx.revoke_remote_client(&client.client, RevocationCause::InvitationExpired, at)
            })
            .unwrap();
        let after = store
            .transaction(|tx| tx.remote_invitation(&inv.invitation))
            .unwrap()
            .unwrap();
        assert_eq!(after.state, InvitationState::Expired);
        assert!(matches!(
            store.transaction(|tx| tx.activate_remote_client(&join_of(&inv))),
            Err(StoreError::GenerationConflict(_))
        ));
        assert!(
            store
                .transaction(|tx| tx.remote_invitations_pending())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .transaction(|tx| tx.remote_clients_with_key(&fp()))
                .unwrap()
                .len(),
            1
        );
    }

    /// ⟨Gemini R01⟩ The conditional bookkeeping never marks a tombstone with a line.
    #[test]
    fn line_bookkeeping_is_conditional_on_the_state_it_was_computed_from() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let (client, inv) = pair(4);
        let at = client.created_at;
        store
            .transaction(|tx| tx.insert_remote_invitation(&client, &inv, at))
            .unwrap();
        store
            .transaction(|tx| tx.revoke_remote_client(&client.client, RevocationCause::Revoked, at))
            .unwrap();
        let recorded = store
            .transaction(|tx| {
                tx.set_remote_client_line_if(
                    &client.client,
                    ClientState::Pending,
                    AppliedLine::Pending {
                        expires_wall: inv.expires_wall,
                    },
                )
            })
            .unwrap();
        assert!(!recorded);
        let row = store
            .transaction(|tx| tx.remote_client(&client.client))
            .unwrap()
            .unwrap();
        assert_eq!(row.line, AppliedLine::Absent);
        assert!(
            store
                .transaction(|tx| tx.set_remote_client_line_if(
                    &client.client,
                    ClientState::Revoked,
                    AppliedLine::Absent
                ))
                .unwrap()
        );
    }

    /// An inconsistent pair is refused before any write.
    #[test]
    fn inconsistent_insert_is_refused() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let (mut client, inv) = pair(3);
        client.role = Role::Owner;
        let at = client.created_at;
        assert!(
            store
                .transaction(|tx| tx.insert_remote_invitation(&client, &inv, at))
                .is_err()
        );
        assert!(
            store
                .transaction(|tx| tx.remote_clients())
                .unwrap()
                .is_empty()
        );
    }

    /// ⟨M06 W2⟩ A runner-local widening record: inserted pending with its key; a second
    /// record under the key is refused; settled once (a lost compare-and-set writes nothing);
    /// its terminal result recorded once, only after approval; read back by key and by ID.
    #[test]
    fn widening_records_are_keyed_settled_once_and_keep_their_result() {
        use heimdall_domain::decision::RemoteWidening;
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let at = now("2026-11-20T10:00:00Z");
        let client = ClientId::from_random_bytes([3; 16]);
        let record = |n: u8, request_id: &str| DecisionRecord {
            id: DecisionId::from_random_bytes([n; 16]),
            kind: DecisionKind::RemoteWidening(Box::new(RemoteWidening {
                origin: WideningOrigin::Paired,
                client: Some(client.clone()),
                request_kind: "transport.disable".into(),
                request_id: RequestId::parse(request_id).unwrap(),
                request: serde_json::from_str(r#"{"op":"transport","action":"disable"}"#).unwrap(),
                invite: None,
                exposure: None,
            })),
            generation: heimdall_domain::policy::AuthorityGeneration(0),
            created_at: at,
            expires_at: now("2026-11-20T10:15:00Z"),
            state: DecisionState::Pending,
            decided_at: None,
        };
        let hash = "ab".repeat(32);
        store
            .transaction(|tx| tx.insert_remote_widening(&record(1, "r1"), &hash, None))
            .unwrap();
        assert!(matches!(
            store.transaction(|tx| tx.insert_remote_widening(&record(2, "r1"), &hash, None)),
            Err(StoreError::GenerationConflict(_))
        ));
        let (d, row) = store
            .transaction(|tx| {
                tx.remote_widening_by_key(
                    &client,
                    "transport.disable",
                    &RequestId::parse("r1").unwrap(),
                )
            })
            .unwrap()
            .unwrap();
        assert_eq!(d.id, record(1, "r1").id);
        assert_eq!(
            (row.request_hash.as_str(), row.result),
            (hash.as_str(), None)
        );
        // No result before approval.
        let id = d.id;
        let result = serde_json::json!({"code": "OK"});
        assert!(matches!(
            store.transaction(|tx| tx.record_remote_widening_result(&id, &result)),
            Err(StoreError::GenerationConflict(_))
        ));
        let (d, _) = store
            .transaction(|tx| tx.settle_remote_widening(&id, DecisionState::Approved, at, None))
            .unwrap();
        assert_eq!((d.state, d.decided_at), (DecisionState::Approved, Some(at)));
        assert!(matches!(
            store.transaction(|tx| tx.settle_remote_widening(&id, DecisionState::Denied, at, None)),
            Err(StoreError::GenerationConflict(_))
        ));
        let (_, row) = store
            .transaction(|tx| tx.record_remote_widening_result(&id, &result))
            .unwrap();
        assert_eq!(row.result, Some(result.clone()));
        assert!(matches!(
            store.transaction(|tx| tx.record_remote_widening_result(&id, &result)),
            Err(StoreError::GenerationConflict(_))
        ));
        assert_eq!(
            store
                .transaction(|tx| tx.remote_widening(&id))
                .unwrap()
                .unwrap()
                .1
                .result,
            Some(result)
        );
        // Another kind of decision is never a widening record.
        let mut other = record(4, "r4");
        other.kind = DecisionKind::ConfirmTime {
            boot_id: BootId("b".into()),
            observed_wall: at,
        };
        assert!(
            store
                .transaction(|tx| tx.insert_remote_widening(&other, &hash, None))
                .is_err()
        );
    }

    /// ⟨M06 W5; ADR-0006 §18.9 item 8⟩ A local widening record has no client and is found
    /// only by its request kind and delta digest while pending: a second pending record of
    /// the same kind and digest is refused, another digest is its own record, and a settled
    /// one no longer blocks a new one. An origin that does not fit the client or the digest
    /// writes nothing, whichever way it is wrong; a paired key lookup never finds a local
    /// record.
    #[test]
    fn local_widening_records_have_no_client_and_dedup_by_delta_digest() {
        use heimdall_domain::decision::RemoteWidening;
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let at = now("2026-11-22T10:00:00Z");
        let client = ClientId::from_random_bytes([3; 16]);
        let record = |n: u8, origin: WideningOrigin, client: Option<ClientId>| DecisionRecord {
            id: DecisionId::from_random_bytes([n; 16]),
            kind: DecisionKind::RemoteWidening(Box::new(RemoteWidening {
                origin,
                client,
                request_kind: "transport.enable".into(),
                request_id: RequestId::parse(&format!("r{n}")).unwrap(),
                request: serde_json::from_str(r#"{"op":"transport","action":"disable"}"#).unwrap(),
                invite: None,
                exposure: None,
            })),
            generation: heimdall_domain::policy::AuthorityGeneration(0),
            created_at: at,
            expires_at: now("2026-11-22T10:15:00Z"),
            state: DecisionState::Pending,
            decided_at: None,
        };
        let local = |n: u8| record(n, WideningOrigin::Local, None);
        let hash = "ab".repeat(32);
        // Every inconsistent shape is refused and writes nothing.
        let wrong: [(DecisionRecord, Option<&str>); 5] = [
            (
                record(20, WideningOrigin::Local, Some(client.clone())),
                Some("d"),
            ),
            (record(21, WideningOrigin::Paired, None), None),
            (local(22), None),
            (
                record(23, WideningOrigin::Paired, Some(client.clone())),
                Some("d"),
            ),
            (record(24, WideningOrigin::Paired, None), Some("d")),
        ];
        for (rec, digest) in &wrong {
            assert!(
                store
                    .transaction(|tx| tx.insert_remote_widening(rec, &hash, *digest))
                    .is_err(),
                "{:?} with digest {digest:?}",
                rec.kind
            );
            assert!(
                store
                    .transaction(|tx| tx.remote_widening(&rec.id))
                    .unwrap()
                    .is_none()
            );
            assert!(
                store
                    .transaction(|tx| tx.decision(&rec.id))
                    .unwrap()
                    .is_none()
            );
        }
        store
            .transaction(|tx| tx.insert_remote_widening(&local(1), &hash, Some("d1")))
            .unwrap();
        assert!(matches!(
            store.transaction(|tx| tx.insert_remote_widening(&local(2), &hash, Some("d1"))),
            Err(StoreError::GenerationConflict(_))
        ));
        store
            .transaction(|tx| tx.insert_remote_widening(&local(3), &hash, Some("d2")))
            .unwrap();
        let (d, row) = store
            .transaction(|tx| tx.pending_local_widening("transport.enable", "d1"))
            .unwrap()
            .unwrap();
        assert_eq!(d.id, local(1).id);
        assert_eq!(
            (row.origin, row.client, row.delta_digest.as_deref()),
            (WideningOrigin::Local, None, Some("d1"))
        );
        assert!(
            store
                .transaction(|tx| tx.pending_local_widening("route.add", "d1"))
                .unwrap()
                .is_none(),
            "another request kind is another record"
        );
        // A paired lookup with the local record's request ID finds nothing, for any client.
        assert!(
            store
                .transaction(|tx| tx.remote_widening_by_key(
                    &client,
                    "transport.enable",
                    &RequestId::parse("r1").unwrap()
                ))
                .unwrap()
                .is_none()
        );
        // Once settled it is no longer the pending record, and a new one may be made.
        store
            .transaction(|tx| tx.settle_remote_widening(&d.id, DecisionState::Denied, at, None))
            .unwrap();
        assert!(
            store
                .transaction(|tx| tx.pending_local_widening("transport.enable", "d1"))
                .unwrap()
                .is_none()
        );
        store
            .transaction(|tx| tx.insert_remote_widening(&local(4), &hash, Some("d1")))
            .unwrap();
    }

    fn endpoint(c: char) -> IrohEndpointId {
        IrohEndpointId::parse(&c.to_string().repeat(64)).unwrap()
    }

    /// An active client whose consumed invitation has `iroh_admission` as given.
    fn joined(store: &Store, n: u8, iroh_admission: bool) -> ClientId {
        let (mut client, mut inv) = pair(n);
        client.key_fingerprint = KeyFingerprint::parse(&format!(
            "SHA256:{}",
            char::from(b'A' + n).to_string().repeat(43)
        ))
        .unwrap();
        inv.key_fingerprint = client.key_fingerprint.clone();
        inv.iroh_admission = iroh_admission;
        let at = client.created_at;
        store
            .transaction(|tx| {
                tx.insert_remote_invitation(&client, &inv, at)?;
                tx.activate_remote_client(&join_of(&inv)).map(drop)
            })
            .unwrap();
        client.client
    }

    /// ⟨ADR-0006 §18.7 item 8⟩ Iroh admission is the client's attribute: a join copies the
    /// invitation's; the bootstrap owner (no invitation) gets it, with a first endpoint,
    /// from `admit_bootstrap_owner_iroh`, which adds but never replaces an endpoint and
    /// moves no generation; a first set and a rotation read the client's attribute.
    #[test]
    fn iroh_admission_is_the_clients_and_the_bootstrap_owner_adds_but_never_replaces() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let at = now("2026-11-20T10:06:00Z");
        let invited = joined(&store, 1, true);
        let plain = joined(&store, 2, false);
        let owner = RemoteClientRecord {
            client: ClientId::from_random_bytes([9; 16]),
            role: Role::Owner,
            key_fingerprint: KeyFingerprint::parse(&format!("SHA256:{}", "o".repeat(43))).unwrap(),
            public_key: "ssh-ed25519 AAAA".into(),
            state: ClientState::Active,
            invitation: None,
            revoked_generation: None,
            revocation: None,
            created_at: at,
            updated_at: at,
            line: AppliedLine::Absent,
        };
        let admitted = |c: &ClientId| {
            store
                .transaction(|tx| tx.remote_client_iroh_admission(c))
                .unwrap()
        };
        assert!(
            admitted(&invited),
            "the join copied the invitation's admission"
        );
        assert!(!admitted(&plain));
        // Without the token: the owner is enrolled with no admission, and a first set is
        // refused with nothing written.
        store
            .transaction(|tx| tx.enroll_bootstrap_owner(&owner, at))
            .unwrap();
        assert!(!admitted(&owner.client));
        assert!(matches!(
            store.transaction(|tx| tx.set_remote_client_endpoint(
                &owner.client,
                &endpoint('a'),
                at
            )),
            Err(StoreError::GenerationConflict(_))
        ));
        // An invited client, or one that is not an owner, is not admitted this way.
        assert!(matches!(
            store.transaction(|tx| tx.admit_bootstrap_owner_iroh(&plain, &endpoint('a'), at)),
            Err(StoreError::GenerationConflict(_))
        ));
        assert!(!admitted(&plain));
        // With the token (in the enrollment's transaction, idempotent for the same key).
        let g0 = admission_generation(&store);
        let recorded = store
            .transaction(|tx| {
                let (o, created) = tx.enroll_bootstrap_owner(&owner, at)?;
                assert!(!created);
                tx.admit_bootstrap_owner_iroh(&o.client, &endpoint('a'), at)
            })
            .unwrap();
        assert_eq!(recorded, OwnerEndpoint::Recorded);
        assert!(admitted(&owner.client));
        let again = store
            .transaction(|tx| tx.admit_bootstrap_owner_iroh(&owner.client, &endpoint('a'), at))
            .unwrap();
        assert_eq!(again, OwnerEndpoint::Unchanged);
        // The repair never replaces an endpoint.
        let kept = store
            .transaction(|tx| tx.admit_bootstrap_owner_iroh(&owner.client, &endpoint('b'), at))
            .unwrap();
        assert_eq!(kept, OwnerEndpoint::Kept(endpoint('a')));
        let current = store
            .transaction(|tx| tx.remote_client_endpoint(&owner.client))
            .unwrap()
            .map(|(e, _)| e);
        assert_eq!(current, Some(endpoint('a')));
        assert_eq!(admission_generation(&store), g0, "nothing narrowed");
        // The rotation form's set reads the client's attribute: it replaces.
        let rotated = store
            .transaction(|tx| tx.set_remote_client_endpoint(&owner.client, &endpoint('b'), at))
            .unwrap();
        assert!(matches!(rotated, EndpointChange::Replaced(g) if g == g0 + 1));
    }

    fn admission_generation(store: &Store) -> u64 {
        store
            .transaction(|tx| tx.remote_authority_generation())
            .unwrap()
    }

    /// ⟨W3; ADR-0006 §18.7 items 1, 3, 4⟩ A client's endpoint: recorded only for an active
    /// client whose consumed invitation admitted Iroh (a first record moves no generation);
    /// the same endpoint again writes nothing; a replacement moves the admission authority
    /// generation in its transaction; another client's endpoint, a pending client and an
    /// invitation without `iroh_admission` are refused with nothing written. The allowlist
    /// source lists active clients only, and the invitation's flag survives a round trip
    /// through its document and its column.
    #[test]
    fn client_endpoints_are_admitted_only_by_the_invitation_and_replacement_moves_the_generation() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let at = now("2026-11-20T10:06:00Z");
        let a = joined(&store, 1, true);
        let b = joined(&store, 2, true);
        let plain = joined(&store, 3, false);
        let g0 = admission_generation(&store);
        assert_eq!(g0, 0);
        let column: i64 = store
            .transaction(|tx| {
                Ok(tx.tx.query_row(
                    "SELECT count(*) FROM remote_invitations WHERE iroh_admission = 1",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(column, 2, "the column mirrors the document");

        let set = |c: &ClientId, e: char| {
            store.transaction(|tx| tx.set_remote_client_endpoint(c, &endpoint(e), at))
        };
        assert_eq!(set(&a, 'a').unwrap(), EndpointChange::Recorded);
        assert_eq!(
            admission_generation(&store),
            g0,
            "a first endpoint narrows nothing"
        );
        assert_eq!(set(&a, 'a').unwrap(), EndpointChange::Unchanged);
        assert_eq!(admission_generation(&store), g0);
        // Refusals write nothing.
        assert!(matches!(
            set(&b, 'a'),
            Err(StoreError::GenerationConflict(_))
        ));
        assert!(matches!(
            set(&plain, 'c'),
            Err(StoreError::GenerationConflict(_))
        ));
        let (pending, pending_inv) = pair(9);
        store
            .transaction(|tx| tx.insert_remote_invitation(&pending, &pending_inv, at))
            .unwrap();
        assert!(matches!(
            set(&pending.client, 'd'),
            Err(StoreError::GenerationConflict(_))
        ));
        assert!(matches!(
            set(&ClientId::from_random_bytes([42; 16]), 'e'),
            Err(StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows))
        ));
        assert_eq!(admission_generation(&store), g0);
        // A replacement moves the generation in its own transaction.
        assert_eq!(set(&a, 'f').unwrap(), EndpointChange::Replaced(g0 + 1));
        assert_eq!(admission_generation(&store), g0 + 1);
        assert_eq!(
            set(&b, 'a').unwrap(),
            EndpointChange::Recorded,
            "the old ID is free"
        );
        assert_eq!(
            store
                .transaction(|tx| tx.remote_client_endpoints())
                .unwrap(),
            {
                let mut v = vec![(a.clone(), endpoint('f')), (b.clone(), endpoint('a'))];
                v.sort();
                v
            }
        );
        assert_eq!(
            store
                .transaction(|tx| tx.remote_client_endpoint(&a))
                .unwrap()
                .map(|(e, _)| e),
            Some(endpoint('f'))
        );
    }

    /// ⟨W3; ADR-0012 §3.11 as amended⟩ Revocation deletes the client's endpoint row in the
    /// tombstone's transaction: a transaction that tombstones and then fails leaves both the
    /// row and the active client; a committed one leaves neither, and the allowlist source
    /// no longer names the client.
    #[test]
    fn revocation_deletes_the_endpoint_row_in_the_tombstone_transaction() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let at = now("2026-11-20T10:07:00Z");
        let a = joined(&store, 1, true);
        store
            .transaction(|tx| tx.set_remote_client_endpoint(&a, &endpoint('a'), at))
            .unwrap();
        let rolled_back = store.transaction(|tx| {
            let r = tx.revoke_remote_client(&a, RevocationCause::Revoked, at)?;
            assert_eq!(r.state, ClientState::Revoked);
            assert!(
                tx.remote_client_endpoint(&a)?.is_none(),
                "gone inside the txn"
            );
            Err::<(), _>(StoreError::Corrupt("abort".into()))
        });
        assert!(rolled_back.is_err());
        assert!(
            store
                .transaction(|tx| tx.remote_client_endpoint(&a))
                .unwrap()
                .is_some(),
            "the row stays with the active client when the tombstone did not commit"
        );
        assert_eq!(
            store
                .transaction(|tx| tx.remote_client(&a))
                .unwrap()
                .unwrap()
                .state,
            ClientState::Active
        );
        let g = admission_generation(&store);
        let revoked = store
            .transaction(|tx| tx.revoke_remote_client(&a, RevocationCause::Revoked, at))
            .unwrap();
        assert_eq!(revoked.revoked_generation, Some(g + 1));
        assert!(
            store
                .transaction(|tx| tx.remote_client_endpoint(&a))
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .transaction(|tx| tx.remote_client_endpoints())
                .unwrap()
                .is_empty()
        );
    }

    /// ⟨orchestrator condition 2⟩ Two writers race to set the same client's first endpoint
    /// from two threads over one file-backed store, each in its own transaction: exactly one
    /// records a **first** endpoint. The other either lost the insert-if-absent (refused,
    /// nothing written) or ran after it, saw the row and became a replacement, which moved
    /// the admission generation in its own transaction; a first set never overwrote a row.
    /// Repeated to vary the interleaving.
    #[test]
    fn two_concurrent_first_sets_cannot_both_win() {
        for round in 0..16u8 {
            let dir = tempfile::tempdir().unwrap();
            let store =
                Arc::new(Store::open(&dir.path().join("s.db"), Arc::new(NoFaults)).unwrap());
            let a = joined(&store, 1, true);
            let g0 = admission_generation(&store);
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let at = now("2026-11-20T10:06:00Z");
            let racers: Vec<_> = ['b', 'c']
                .into_iter()
                .map(|e| {
                    let (store, barrier, a) = (Arc::clone(&store), Arc::clone(&barrier), a.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        let r = store
                            .transaction(|tx| tx.set_remote_client_endpoint(&a, &endpoint(e), at));
                        (e, r)
                    })
                })
                .collect();
            let results: Vec<_> = racers.into_iter().map(|t| t.join().unwrap()).collect();
            let first: Vec<char> = results
                .iter()
                .filter(|(_, r)| matches!(r, Ok(EndpointChange::Recorded)))
                .map(|(e, _)| *e)
                .collect();
            assert_eq!(first.len(), 1, "round {round}: one first set: {results:?}");
            let other = results.iter().find(|(e, _)| *e != first[0]).unwrap();
            let row = store
                .transaction(|tx| tx.remote_client_endpoint(&a))
                .unwrap()
                .map(|(e, _)| e);
            match &other.1 {
                Err(StoreError::GenerationConflict(_)) => {
                    assert_eq!(row, Some(endpoint(first[0])), "round {round}");
                    assert_eq!(admission_generation(&store), g0, "round {round}");
                }
                Ok(EndpointChange::Replaced(g)) => {
                    assert_eq!(*g, g0 + 1, "round {round}");
                    assert_eq!(row, Some(endpoint(other.0)), "round {round}");
                    assert_eq!(admission_generation(&store), g0 + 1, "round {round}");
                }
                r => panic!("round {round}: unexpected {r:?}"),
            }
        }
    }
}
