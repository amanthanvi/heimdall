//! ⟨M08 U2b-2; ADR-0014 H9, §3.6 "The restore epoch and the replay fence"⟩ The store's part of
//! the epoch and the fence.
//!
//! * **The current epoch** ([`Txn::restore_epoch`]) is `meta.restore_epoch` (migration 0014),
//!   canonical decimal; anything else is `state_corrupt`. Only a restore or a repair raises it
//!   (U2b-3). In this slice nothing in production raises it: the tests raise it through the
//!   test seam [`Txn::raise_restore_epoch_for_test`].
//! * **Everything minted carries its epoch** (§3.6 step 2): a row inserted into `operations`,
//!   `decisions` or `remote_effect_outbox` carries the current epoch in its `restore_epoch`, and
//!   an idempotency row in its `request_epoch` (the epoch its request was bound to: a request
//!   with any other epoch is refused before the store is written). The columns default to 0, so
//!   the insert writes the epoch only when it is above 0 (`Txn::minted_epoch`). Every row
//!   written before migration 0014 reads 0.
//! * **The ledger digest** ([`ledger_digest`]): SHA-256 over the canonical JSON of the full
//!   idempotency key, `{"caller": {principal, role, remote_client?}, "kind", "request_id"}`
//!   (ADR-0006 §7.1 as extended by ADR-0012 §3.7). For a journaled request it is the canonical
//!   form of the domain's `IdempotencyKey` ([`idempotency_digest`]); the request ledger
//!   (`heimdall_stategen::ledger`) and the fence table are keyed by it. Two clients, two roles
//!   or two kinds with the same request ID have different digests.
//! * **Fence records** (`request_fences`, [`RequestFence`]): a key that must never run again,
//!   with its stored answer (`REQUEST_STALE`, `restored_before_completion`). Their lifetimes
//!   are ADR-0006 §7.4's ([`RequestFence::verdict`]): an unresolved key's fence is answered
//!   after any wait and never purged; a settled key's is answered until its retention ends
//!   (`expires_at`), then as an expired key (`REQUEST_EXPIRED`) until its 30-day marker ends
//!   (`marker_until`), when [`Txn::purge_markers_before`] removes it. U2b-3's restore and
//!   repair write them; this slice's tests write them through
//!   [`Txn::insert_request_fence`] and [`fence_ledger_for_test`].

use std::collections::BTreeSet;
use std::path::Path;

use heimdall_contract::Timestamp;
use heimdall_contract::canonical::canonical_json;
use heimdall_contract::envelope::{EffectStatus, ErrorDetail, NextAction, reason};
use heimdall_contract::ids::{DecisionId, RequestId};
use heimdall_contract::lifecycle::RestoreEpoch;
use heimdall_contract::{Code, OperationState};
use heimdall_domain::idempotency::IdempotencyKey;
use heimdall_domain::principal::CallerContext;
use rusqlite::OptionalExtension as _;

use crate::{META_RESTORE_EPOCH, Result, Store, StoreError, Txn, codec};

/// The schema version that added the restore epoch (migration 0014).
const EPOCH_SCHEMA_VERSION: u32 = 14;

/// The canonical bytes of a request's full idempotency key: the canonical JSON (keys sorted,
/// no whitespace; `heimdall_contract::canonical`) of `{"caller", "kind", "request_id"}`, where
/// `kind` is the request's kind (`Request::kind`, equal to the journaled
/// `OperationKind::as_str`). The caller is `{principal, role, remote_client}`, with
/// `remote_client` omitted when absent, as the stored key is.
///
/// # Errors
/// [`StoreError::Json`] when the key cannot be encoded (it always can).
pub fn ledger_key(caller: &CallerContext, kind: &str, request_id: &RequestId) -> Result<Vec<u8>> {
    let value = serde_json::json!({
        "caller": caller,
        "kind": kind,
        "request_id": request_id,
    });
    canonical_json(&value).map_err(|_| codec::doc_error("the idempotency key cannot be encoded"))
}

/// The digest the request ledger and the fence table key a request by
/// (`heimdall_stategen::ledger::key_digest` over [`ledger_key`]).
///
/// # Errors
/// As [`ledger_key`].
pub fn ledger_digest(
    caller: &CallerContext,
    kind: &str,
    request_id: &RequestId,
) -> Result<[u8; 32]> {
    ledger_key(caller, kind, request_id).map(|k| heimdall_stategen::ledger::key_digest(&k))
}

/// [`ledger_digest`] of a journaled request's stored idempotency key.
///
/// # Errors
/// As [`ledger_key`].
pub fn idempotency_digest(key: &IdempotencyKey) -> Result<[u8; 32]> {
    ledger_digest(&key.caller, key.kind.as_str(), &key.request_id)
}

/// Lowercase hex of a digest, as `request_fences.key_digest` stores it.
#[must_use]
pub fn digest_hex(digest: &[u8; 32]) -> String {
    heimdall_contract::canonical::RequestHash(*digest).to_hex()
}

/// The answer a fence written at a restore or a repair stores: `REQUEST_STALE`, reason
/// `restored_before_completion`, effect `none`, next `new_request_id` (ADR-0014 §3.6 step 4).
#[must_use]
pub fn restored_before_completion() -> ErrorDetail {
    ErrorDetail {
        code: Code::RequestStale,
        effect_status: EffectStatus::None,
        retryable: false,
        resource: None,
        next: NextAction::for_code(Code::RequestStale),
        message: "this request was received before the state was restored, and its outcome \
                  is not in the restored state: it is never run again. Send a new request with \
                  a new request ID"
            .to_owned(),
        reason: Some(reason::RESTORED_BEFORE_COMPLETION.to_owned()),
        entries: Vec::new(),
    }
}

/// A settled key's lifetimes (ADR-0006 §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceSettlement {
    /// When the key settled.
    pub settled_at: Timestamp,
    /// When its retention ends: the fence's answer is given until then.
    pub expires_at: Timestamp,
    /// When its expired-key marker ends: an expired-key answer until then, after which the
    /// fence may be purged.
    pub marker_until: Timestamp,
}

/// One fence record (`request_fences`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFence {
    /// The fenced key's [`ledger_digest`].
    pub key_digest: [u8; 32],
    /// The epoch the fenced request was received under (its ledger entry's).
    pub epoch: RestoreEpoch,
    /// The stored answer.
    pub answer: ErrorDetail,
    /// When the fence was written.
    pub created_at: Timestamp,
    /// `None`: an unresolved key, kept and answered indefinitely.
    pub settlement: Option<FenceSettlement>,
}

/// What a fence answers a request with its key at a given time ([`RequestFence::verdict`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceVerdict {
    /// The stored answer: the request is never executed.
    Answer(Box<ErrorDetail>),
    /// The retention ended and the marker lives: `REQUEST_EXPIRED`, never executed.
    Expired,
    /// The marker window ended: the fence no longer answers (it is purged).
    Lapsed,
}

impl RequestFence {
    /// The fence's answer at `now` (ADR-0006 §7.4): unresolved, its answer always; settled,
    /// its answer before `expires_at`, an expired key before `marker_until`, then nothing.
    #[must_use]
    pub fn verdict(&self, now: Timestamp) -> FenceVerdict {
        match self.settlement {
            None => FenceVerdict::Answer(Box::new(self.answer.clone())),
            Some(s) if now < s.expires_at => FenceVerdict::Answer(Box::new(self.answer.clone())),
            Some(s) if now < s.marker_until => FenceVerdict::Expired,
            Some(_) => FenceVerdict::Lapsed,
        }
    }
}

impl Txn<'_> {
    /// The current restore epoch (`meta.restore_epoch`). A missing or malformed value is
    /// [`StoreError::Corrupt`], never epoch 0 (review U0-R06).
    ///
    /// # Errors
    /// [`StoreError::Corrupt`], or a database error.
    pub fn restore_epoch(&mut self) -> Result<RestoreEpoch> {
        let text: Option<String> = self
            .tx
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [META_RESTORE_EPOCH],
                |r| r.get(0),
            )
            .optional()?;
        text.as_deref()
            .and_then(crate::parse_restore_epoch)
            .map(RestoreEpoch)
            .ok_or_else(|| {
                StoreError::Corrupt("the restore epoch is missing or malformed".to_owned())
            })
    }

    /// The epoch a row inserted now is minted under, as the epoch columns store it, when it
    /// is not 0: every epoch column defaults to 0, so a store at epoch 0 writes nothing more
    /// (and a store from before migration 0014, which has no epoch column, stays writable by
    /// the same statements: everything in it is epoch 0). From schema version 14 on a missing
    /// or malformed epoch is [`StoreError::Corrupt`], as [`Self::restore_epoch`] says.
    pub(crate) fn minted_epoch(&mut self) -> Result<Option<i64>> {
        let text: Option<String> = self
            .tx
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [META_RESTORE_EPOCH],
                |r| r.get(0),
            )
            .optional()?;
        if text.is_none() && crate::migrations::user_version(&self.tx)? < EPOCH_SCHEMA_VERSION {
            return Ok(None);
        }
        match self.restore_epoch()? {
            RestoreEpoch(0) => Ok(None),
            RestoreEpoch(e) => codec::int(e).map(Some),
        }
    }

    /// ⟨test seam; U2b-3 replaces it⟩ Raise the restore epoch to `to`. Only a restore and a
    /// repair raise it (ADR-0014 §3.6 step 1; U2b-3); until they land, the tests of the
    /// server's check raise it here, on a stopped runtime's store. Lowering it, or setting
    /// the same value, is refused.
    ///
    /// # Errors
    /// [`StoreError::GenerationConflict`] when `to` is not above the current epoch.
    #[doc(hidden)]
    pub fn raise_restore_epoch_for_test(&mut self, to: RestoreEpoch) -> Result<()> {
        let current = self.restore_epoch()?;
        if to <= current {
            return Err(StoreError::GenerationConflict(
                "the restore epoch only rises".to_owned(),
            ));
        }
        self.tx.execute(
            "UPDATE meta SET value = ?2 WHERE key = ?1",
            [META_RESTORE_EPOCH, to.0.to_string().as_str()],
        )?;
        Ok(())
    }

    /// The fence record for `digest`, if any.
    ///
    /// # Errors
    /// A database error, or a malformed row ([`StoreError::Corrupt`]-class).
    pub fn request_fence(&mut self, digest: &[u8; 32]) -> Result<Option<RequestFence>> {
        type Row = (
            i64,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        let row: Option<Row> = self
            .tx
            .query_row(
                "SELECT epoch, answer_json, created_at, settled_at, expires_at, marker_until
                 FROM request_fences WHERE key_digest = ?1",
                [digest_hex(digest)],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((epoch, answer, created, settled, expires, until)) = row else {
            return Ok(None);
        };
        // A stored answer that does not decode still fences: the request is never run.
        let answer = codec::parse_doc(&answer).unwrap_or_else(|_| restored_before_completion());
        let settlement = match (settled, expires, until) {
            (Some(s), Some(e), Some(u)) => Some(FenceSettlement {
                settled_at: codec::parse_ts(&s)?,
                expires_at: codec::parse_ts(&e)?,
                marker_until: codec::parse_ts(&u)?,
            }),
            // Unresolved; and a partly settled row fails closed as unresolved.
            _ => None,
        };
        Ok(Some(RequestFence {
            key_digest: *digest,
            epoch: RestoreEpoch(codec::uint(epoch)?),
            answer,
            created_at: codec::parse_ts(&created)?,
            settlement,
        }))
    }

    /// ⟨U2b-3's writer; a test seam in this slice⟩ Write a fence record. A key already fenced
    /// keeps its record (nothing written): a fence is never shortened or replaced.
    ///
    /// # Errors
    /// A database error.
    #[doc(hidden)]
    pub fn insert_request_fence(&mut self, fence: &RequestFence) -> Result<bool> {
        let settled = fence.settlement;
        let n = self.tx.execute(
            "INSERT INTO request_fences (key_digest, epoch, answer_json, created_at, settled_at,
                 expires_at, marker_until)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(key_digest) DO NOTHING",
            rusqlite::params![
                digest_hex(&fence.key_digest),
                codec::int(fence.epoch.0)?,
                codec::doc(&fence.answer)?,
                codec::ts(fence.created_at),
                settled.map(|s| codec::ts(s.settled_at)),
                settled.map(|s| codec::ts(s.expires_at)),
                settled.map(|s| codec::ts(s.marker_until)),
            ],
        )?;
        Ok(n > 0)
    }

    /// The [`ledger_digest`] of every key whose operation is terminal (succeeded, failed or
    /// cancelled): the terminal records a restore checks ledger entries against
    /// (`heimdall_stategen::ledger::unfenced`).
    ///
    /// # Errors
    /// A database error, or a malformed row.
    pub fn terminal_request_digests(&mut self) -> Result<BTreeSet<[u8; 32]>> {
        let sql = format!(
            "SELECT i.caller_json, i.kind, i.request_id
             FROM idempotency i JOIN operations o ON o.id = i.operation_id
             WHERE o.state IN ({})",
            crate::sql_in_list(&crate::operation_states(OperationState::is_settled))?
        );
        let rows: Vec<(String, String, String)> = {
            let mut stmt = self.tx.prepare(&sql)?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut out = BTreeSet::new();
        for (caller, kind, request_id) in rows {
            let caller: CallerContext = codec::parse_doc(&caller)?;
            let request_id = RequestId::parse(&request_id)
                .map_err(|_| codec::doc_error("stored request id is malformed"))?;
            out.insert(ledger_digest(&caller, &kind, &request_id)?);
        }
        Ok(out)
    }

    /// The epoch a decision reference was minted under, if the decision is recorded.
    ///
    /// # Errors
    /// A database error.
    pub fn decision_restore_epoch(&mut self, id: &DecisionId) -> Result<Option<RestoreEpoch>> {
        let epoch: Option<i64> = self
            .tx
            .query_row(
                "SELECT restore_epoch FROM decisions WHERE id = ?1",
                [id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        epoch.map(|e| codec::uint(e).map(RestoreEpoch)).transpose()
    }
}

/// ⟨test seam; U2b-3's restore does this for real⟩ What a restore does to the replay fence, in
/// miniature, on a stopped runtime's store: raise the restore epoch to `to`, then write a
/// fence record (`REQUEST_STALE`, `restored_before_completion`, unresolved) for every entry of
/// the request ledger in `state_dir` that has no terminal record in the store
/// (`heimdall_stategen::ledger::unfenced`). Returns how many fences were written. Nothing
/// else of a restore (sanitization, carry-forward, a new generation) happens here.
///
/// # Errors
/// The ledger cannot be read (damaged or unreadable: [`StoreError::Corrupt`]), or a store
/// error.
#[doc(hidden)]
pub fn fence_ledger_for_test(
    store: &Store,
    state_dir: &Path,
    to: RestoreEpoch,
    now: Timestamp,
) -> Result<usize> {
    use heimdall_stategen::{Ledger, RealFs};
    let entries = Ledger::new(RealFs, state_dir)
        .read()
        .map_err(|e| StoreError::Corrupt(format!("state_corrupt: the request ledger: {e}")))?
        .entries;
    store.transaction(|tx| {
        tx.raise_restore_epoch_for_test(to)?;
        let terminal = tx.terminal_request_digests()?;
        let mut written = 0;
        for entry in heimdall_stategen::ledger::unfenced(&entries, |e| terminal.contains(&e.digest))
        {
            let fence = RequestFence {
                key_digest: entry.digest,
                epoch: RestoreEpoch(entry.epoch),
                answer: restored_before_completion(),
                created_at: now,
                settlement: None,
            };
            if tx.insert_request_fence(&fence)? {
                written += 1;
            }
        }
        Ok(written)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use heimdall_contract::canonical::RequestHash;
    use heimdall_contract::ids::{ClientId, EnvironmentId, OperationId};
    use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
    use heimdall_domain::idempotency::{IdempotencyRecord, MARKER_WINDOW};
    use heimdall_domain::operation::{
        EffectClass, OperationKind, OperationRecord, RecoveryMetadata,
    };
    use heimdall_domain::policy::AuthorityGeneration;
    use heimdall_domain::principal::{ClientRole, PrincipalRef};

    use super::*;
    use crate::NoFaults;

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn owner() -> CallerContext {
        CallerContext::local(PrincipalRef::UnixUser { uid: 501 }, ClientRole::Owner)
    }

    fn rid(s: &str) -> RequestId {
        RequestId::parse(s).unwrap()
    }

    /// The digest is the canonical form of the stored idempotency key for every journaled
    /// kind, and the full key separates: another principal, another role, another paired
    /// client or another kind with the same request ID is another digest.
    #[test]
    fn the_digest_covers_the_full_idempotency_key() {
        for kind in OperationKind::ALL {
            let key = IdempotencyKey {
                caller: owner(),
                kind,
                request_id: rid("r1"),
            };
            let canonical = canonical_json(&serde_json::to_value(&key).unwrap()).unwrap();
            assert_eq!(
                ledger_key(&key.caller, kind.as_str(), &key.request_id).unwrap(),
                canonical,
                "{kind:?}"
            );
            assert_eq!(
                idempotency_digest(&key).unwrap(),
                heimdall_stategen::ledger::key_digest(&canonical)
            );
        }
        let base = ledger_digest(&owner(), "ensure", &rid("r1")).unwrap();
        let mut other_principal = owner();
        other_principal.principal = PrincipalRef::UnixUser { uid: 502 };
        let mut limited = owner();
        limited.role = ClientRole::LimitedConsumer;
        let mut paired = owner();
        paired.remote_client = Some(ClientId::from_random_bytes([1; 16]));
        let mut paired_other = owner();
        paired_other.remote_client = Some(ClientId::from_random_bytes([2; 16]));
        let digests: BTreeSet<[u8; 32]> = [
            base,
            ledger_digest(&other_principal, "ensure", &rid("r1")).unwrap(),
            ledger_digest(&limited, "ensure", &rid("r1")).unwrap(),
            ledger_digest(&paired, "ensure", &rid("r1")).unwrap(),
            ledger_digest(&paired_other, "ensure", &rid("r1")).unwrap(),
            ledger_digest(&owner(), "revoke", &rid("r1")).unwrap(),
            ledger_digest(&owner(), "ensure", &rid("r2")).unwrap(),
        ]
        .into_iter()
        .collect();
        assert_eq!(digests.len(), 7);
        // Not the key hash of the expired-key markers (another domain).
        let key = IdempotencyKey {
            caller: owner(),
            kind: OperationKind::Ensure,
            request_id: rid("r1"),
        };
        assert_ne!(key.hash().unwrap().0.0, base);
    }

    fn fence(digest: [u8; 32], settlement: Option<FenceSettlement>) -> RequestFence {
        RequestFence {
            key_digest: digest,
            epoch: RestoreEpoch(0),
            answer: restored_before_completion(),
            created_at: ts("2026-01-01T00:00:00Z"),
            settlement,
        }
    }

    /// ADR-0006 §7.4 for fences, at the store: an unresolved key's fence answers after any
    /// wait and is never purged; a settled key's answers until its retention ends, then as an
    /// expired key until its marker ends, and is purged then. The ledger keeps every entry
    /// whose settlement it cannot see.
    #[test]
    fn fence_lifetimes_follow_the_idempotency_contract_in_the_store() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let settled = ts("2026-01-01T00:00:00Z");
        let retention = jiff::SignedDuration::from_hours(7 * 24);
        let expires = settled.checked_add(retention).unwrap();
        let until = heimdall_domain::idempotency::marker_until(expires);
        let window = jiff::SignedDuration::try_from(MARKER_WINDOW).unwrap();
        assert_eq!(until, expires.checked_add(window).unwrap());
        let unresolved = [1u8; 32];
        let ended = [2u8; 32];
        store
            .transaction(|tx| {
                assert!(tx.insert_request_fence(&fence(unresolved, None))?);
                assert!(tx.insert_request_fence(&fence(
                    ended,
                    Some(FenceSettlement {
                        settled_at: settled,
                        expires_at: expires,
                        marker_until: until,
                    }),
                ))?);
                // A key already fenced keeps its record.
                assert!(!tx.insert_request_fence(&fence(ended, None))?);
                Ok(())
            })
            .unwrap();
        let read = |d: &[u8; 32]| store.transaction(|tx| tx.request_fence(d)).unwrap();
        let second = jiff::SignedDuration::from_secs(1);
        let far = ts("2100-01-01T00:00:00Z");
        let answer = FenceVerdict::Answer(Box::new(restored_before_completion()));
        assert_eq!(read(&unresolved).unwrap().verdict(far), answer);
        let f = read(&ended).unwrap();
        assert_eq!(f.verdict(expires.checked_sub(second).unwrap()), answer);
        assert_eq!(f.verdict(expires), FenceVerdict::Expired);
        assert_eq!(
            f.verdict(until.checked_sub(second).unwrap()),
            FenceVerdict::Expired
        );
        assert_eq!(f.verdict(until), FenceVerdict::Lapsed);
        // The purge keeps both inside the marker window, then only the unresolved one.
        store
            .transaction(|tx| tx.purge_markers_before(until.checked_sub(second).unwrap()))
            .unwrap();
        assert!(read(&ended).is_some());
        store
            .transaction(|tx| tx.purge_markers_before(far))
            .unwrap();
        assert!(read(&ended).is_none());
        assert!(read(&unresolved).is_some());
        // The ledger's own rule (stategen): an entry whose settlement no store shows is never
        // trimmed; a settled one only after its retention and its marker.
        use heimdall_stategen::ledger::{Settlement, may_trim};
        assert!(!may_trim(Settlement::Unknown, far));
        assert!(!may_trim(Settlement::Unresolved, far));
        let s = Settlement::Settled {
            at: settled,
            retention,
        };
        assert!(!may_trim(s, until.checked_sub(second).unwrap()));
        assert!(may_trim(s, until));
    }

    fn operation(n: u8, kind: OperationKind) -> (OperationRecord, IdempotencyRecord) {
        let key = IdempotencyKey {
            caller: owner(),
            kind,
            request_id: rid(&format!("req-{n}")),
        };
        let at = ts("2026-01-01T00:00:00Z");
        let op = OperationRecord {
            id: OperationId::from_random_bytes([n; 16]),
            kind,
            environment: EnvironmentId::from_random_bytes([7; 16]),
            key: key.clone(),
            request_hash: RequestHash([n; 32]),
            effect_class: EffectClass::Local,
            state: OperationState::Succeeded,
            code: None,
            effect_status: EffectStatus::None,
            result: None,
            created_at: at,
            updated_at: at,
            cancellation: None,
            recovery: RecoveryMetadata::default(),
        };
        let idem = IdempotencyRecord {
            key,
            request_hash: op.request_hash,
            operation_id: op.id.clone(),
            created_at: at,
            expires_at: None,
        };
        (op, idem)
    }

    fn epochs(store: &Store, op: &OperationId) -> (i64, i64) {
        store
            .transaction(|tx| {
                let o: i64 = tx.tx.query_row(
                    "SELECT restore_epoch FROM operations WHERE id = ?1",
                    [op.as_str()],
                    |r| r.get(0),
                )?;
                let i: i64 = tx.tx.query_row(
                    "SELECT request_epoch FROM idempotency WHERE operation_id = ?1",
                    [op.as_str()],
                    |r| r.get(0),
                )?;
                Ok((o, i))
            })
            .unwrap()
    }

    /// ADR-0014 §3.6 step 2: what is minted after the epoch rises carries the new epoch; what
    /// was minted before keeps its own. The seam only raises it.
    #[test]
    fn rows_minted_after_the_epoch_rises_carry_it() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let (before, before_idem) = operation(1, OperationKind::Ensure);
        let decision = |n: u8| DecisionRecord {
            id: DecisionId::from_random_bytes([n; 16]),
            kind: DecisionKind::WidenPolicy {
                action: heimdall_contract::request::PolicyAction::Resume {
                    policy_id: None,
                    target: None,
                },
            },
            generation: AuthorityGeneration(0),
            created_at: ts("2026-01-01T00:00:00Z"),
            expires_at: ts("2026-01-02T00:00:00Z"),
            state: DecisionState::Pending,
            decided_at: None,
        };
        store
            .transaction(|tx| {
                assert_eq!(tx.restore_epoch()?, RestoreEpoch(0));
                tx.insert_operation(&before, &before_idem)?;
                tx.insert_decision(&decision(1))
            })
            .unwrap();
        assert_eq!(epochs(&store, &before.id), (0, 0));
        store
            .transaction(|tx| {
                assert!(tx.raise_restore_epoch_for_test(RestoreEpoch(0)).is_err());
                tx.raise_restore_epoch_for_test(RestoreEpoch(3))?;
                assert!(tx.raise_restore_epoch_for_test(RestoreEpoch(2)).is_err());
                let (after, after_idem) = operation(2, OperationKind::Revoke);
                tx.insert_operation(&after, &after_idem)?;
                tx.insert_decision(&decision(2))
            })
            .unwrap();
        assert_eq!(epochs(&store, &before.id), (0, 0));
        assert_eq!(
            epochs(&store, &OperationId::from_random_bytes([2; 16])),
            (3, 3)
        );
        let minted = |n: u8| {
            store
                .transaction(|tx| {
                    tx.decision_restore_epoch(&DecisionId::from_random_bytes([n; 16]))
                })
                .unwrap()
        };
        assert_eq!(minted(1), Some(RestoreEpoch(0)));
        assert_eq!(minted(2), Some(RestoreEpoch(3)));
        assert_eq!(minted(3), None);
        // A terminal record's digest is what a restore checks a ledger entry against.
        let terminal = store
            .transaction(|tx| tx.terminal_request_digests())
            .unwrap();
        assert!(terminal.contains(&idempotency_digest(&before.key).unwrap()));
        assert_eq!(terminal.len(), 2);
    }
}
