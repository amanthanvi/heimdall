//! ⟨M06⟩ Store methods for the runner's role table and invitations (ADR-0012 §3.7–§3.9,
//! §3.11; m06-plan U1). Schema: `migrations/0009_remote.sql` (`remote_clients`,
//! `remote_invitations`, `remote_authority_generation`); no migration of its own.
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
//! (ADR-0006 §13.7 item 5) **and** the runner's admission authority generation
//! (`remote_authority_generation`, ADR-0012 §2.3 items 3–5) in the same transaction. A
//! client's line-reconcile bookkeeping moves neither.

use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{ClientId, EnvironmentId, InvitationId, KeyFingerprint};
use heimdall_contract::remote::Role;
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
                     elapsed_bound_ms, state, consumed_at, record_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
    /// commit). Moves the authority generation and the admission authority generation.
    /// Returns the new admission authority generation.
    pub fn insert_remote_invitation(
        &mut self,
        client: &RemoteClientRecord,
        invitation: &RemoteInvitationRecord,
        now: Timestamp,
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
        self.bump_remote_authority_generation(now)
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
    /// Moves the authority generation and the admission authority generation.
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
        self.bump_generation()?;
        self.bump_remote_authority_generation(join.joined_at)?;
        Ok((client, inv))
    }

    /// Tombstone a client (ADR-0012 §3.11 step 1; §3.9 item 4 for an expired invitation):
    /// `pending | active → revoked`, recording the admission authority generation it
    /// produces and the cause; a pending invitation of the client becomes `expired` (cause
    /// [`RevocationCause::InvitationExpired`]) or `revoked`. Moves the authority generation
    /// and the admission authority generation. Idempotent: a client already revoked is
    /// returned unchanged and moves nothing. A missing client is `QueryReturnedNoRows`.
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

    /// Move the admission authority generation up by one; returns the new value.
    fn bump_remote_authority_generation(&mut self, now: Timestamp) -> Result<u64> {
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
    /// change moves both generations, the line bookkeeping moves neither.
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
        assert_eq!(g, 1);
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
}
