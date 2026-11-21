//! ⟨M06 U56⟩ Store methods for the Iroh transport (ADR-0012 §2.1, §2.3–§2.5, §2.8; m06-plan
//! U56). Schema: `migrations/0009_remote.sql`'s `transport_keys` and `route_consents`; no
//! migration of its own.
//!
//! Conventions (as [`crate::ext_m06`]): every method runs inside the caller's [`Txn`];
//! reads return `Option`/`Vec`; the store reads no clock (every instant is the caller's);
//! inserting a record whose key already exists is a [`StoreError::GenerationConflict`]
//! and writes nothing; changing a record that does not exist is
//! `StoreError::Sqlite(QueryReturnedNoRows)`.
//!
//! * **`transport_keys`** holds **references** to K_iroh, never the key (spec §7.3, §13.3):
//!   the endpoint ID, the platform store's kind (`keychain`, `dpapi`, `secret_service`) and
//!   the item's nonsecret locator. At most one reference is `active` (the installation's
//!   K_iroh). Withdrawing it ([`Txn::destroy_transport_key`]: rotation, loss or removal)
//!   marks it `destroyed` **before** the platform item is deleted, so a failed deletion is
//!   retried from the row; [`Txn::remove_transport_key`] deletes a `destroyed` row once
//!   its item is gone (ADR-0012 §2.5: removal leaves no key).
//! * **`route_consents`** holds the recorded exposure consents (ADR-0012 §2.1, §2.8): each
//!   bound to the exact [`ExposureDelta`] and to the attended runner-local decision that
//!   confirmed it. A consent with no route (`route_id` NULL) is the serving endpoint's own
//!   exposure; one with a route is that route's (an adopted roost, a widened dialer).
//!
//! **The admission authority generation** (`remote_authority_generation`, ADR-0012 §2.3;
//! m06-plan U56): it moves on every change that narrows remote admission and on nothing
//! else. Here that is withdrawing a K_iroh reference (rotation or removal) and removing an
//! exposure consent (exposure narrowing); each moves it in the same transaction as the
//! change, so the bump commits before the change counts as applied (RC-R02).
//! [`Txn::narrow_remote_admission`] moves it for a narrowing change recorded elsewhere
//! (transport disable with no key, role narrowing). Client tombstones move it in
//! [`crate::ext_m06`]. Recording a key or a consent (a widening) does not move it.

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{ConsentId, DecisionId, IrohEndpointId, RouteId};
use heimdall_contract::route::{BindScope, ExposurePolicy};
use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize};

use crate::{Result, StoreError, Txn, codec};

fn conflict(what: &str) -> StoreError {
    StoreError::GenerationConflict(what.into())
}

fn missing() -> StoreError {
    StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows)
}

fn corrupt(what: &str) -> StoreError {
    StoreError::Corrupt(what.into())
}

/// A K_iroh reference's state (`transport_keys.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKeyState {
    /// The installation's K_iroh: its endpoint serves and dials.
    Active,
    /// Withdrawn (rotation, loss or removal). The platform item may still exist until the
    /// row is removed.
    Destroyed,
}

/// One `transport_keys` row: where K_iroh lives, never the key (ADR-0012 §2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportKeyRecord {
    /// The endpoint ID the key authenticates as (public).
    pub endpoint: IrohEndpointId,
    /// The platform store's kind: `keychain`, `dpapi`, `secret_service` (or a test kind).
    pub store_kind: String,
    /// The store item's nonsecret locator.
    pub store_ref: String,
    /// The state.
    pub state: TransportKeyState,
    /// When the key was generated.
    pub created_at: Timestamp,
    /// When it was withdrawn.
    pub destroyed_at: Option<Timestamp>,
}

/// The exact exposure delta a consent is bound to (ADR-0012 §2.1 ⟨r3⟩, §2.8): each added
/// relay URL, the bind scope before and after, and the direct-fallback, public
/// infrastructure, serving and external-roost changes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExposureDelta {
    /// The endpoint whose exposure changes: this host's serving endpoint, or the adopted
    /// roost (absent before a serving key exists).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<IrohEndpointId>,
    /// Whether the endpoint served before.
    pub serve_before: bool,
    /// Whether it serves after.
    pub serve_after: bool,
    /// The bind scope before.
    pub bind_before: BindScope,
    /// The bind scope after.
    pub bind_after: BindScope,
    /// Each relay URL added.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays_added: Vec<String>,
    /// Direct fallback to learned or public addresses is added.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub direct_fallback_added: bool,
    /// Public infrastructure (`n0-public`) is added.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub public_infrastructure_added: bool,
    /// An adopted stock roost (external infrastructure, ADR-0012 §2.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_roost: Option<IrohEndpointId>,
    /// The effective policy after the change.
    pub after: ExposurePolicy,
}

/// One `route_consents` row: a recorded exposure consent (ADR-0012 §2.1, §2.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteConsentRecord {
    /// The consent (`cns_…`).
    pub consent: ConsentId,
    /// The route it belongs to; `None` for the serving endpoint's own exposure.
    pub route: Option<RouteId>,
    /// The attended runner-local decision that confirmed it.
    pub decision: DecisionId,
    /// The exact delta.
    pub delta: ExposureDelta,
    /// When it was recorded.
    pub recorded_at: Timestamp,
}

type KeyRow = (String, String, String, String, String, Option<String>);

fn key_of(row: KeyRow) -> Result<TransportKeyRecord> {
    let (endpoint, store_kind, store_ref, state, created_at, destroyed_at) = row;
    Ok(TransportKeyRecord {
        endpoint: IrohEndpointId::parse(&endpoint)
            .map_err(|_| corrupt("a transport key reference names no endpoint"))?,
        store_kind,
        store_ref,
        state: codec::enum_parse(&state)?,
        created_at: codec::parse_ts(&created_at)?,
        destroyed_at: destroyed_at.as_deref().map(codec::parse_ts).transpose()?,
    })
}

fn key_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<KeyRow> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
    ))
}

type ConsentRow = (String, Option<String>, String, String, String);

fn consent_of(row: ConsentRow) -> Result<RouteConsentRecord> {
    let (consent, route, decision, delta, recorded_at) = row;
    Ok(RouteConsentRecord {
        consent: ConsentId::parse(&consent).map_err(|_| corrupt("a consent has no ID"))?,
        route: route
            .as_deref()
            .map(RouteId::parse)
            .transpose()
            .map_err(|_| corrupt("a consent names no route"))?,
        decision: DecisionId::parse(&decision)
            .map_err(|_| corrupt("a consent names no decision"))?,
        delta: codec::parse_doc(&delta)?,
        recorded_at: codec::parse_ts(&recorded_at)?,
    })
}

fn consent_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ConsentRow> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
}

/// A store kind or locator: a short printable ASCII token with no spaces (the callers build
/// them from IDs; no key material fits a reference row, [`codec::doc`] guards documents).
fn valid_token(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_graphic())
}

const KEY_COLUMNS: &str = "endpoint_id, store_kind, store_ref, state, created_at, destroyed_at";
const CONSENT_COLUMNS: &str = "consent_id, route_id, decision_id, delta_json, recorded_at";

impl Txn<'_> {
    // --- K_iroh references ---------------------------------------------------------------

    /// Record the installation's new K_iroh reference (state `active`). Refused, writing
    /// nothing, when another reference is active (one K_iroh per installation: rotate with
    /// [`Txn::rotate_transport_key`]), when the endpoint already has a row, or when the
    /// record is not `active` or its kind or locator is not a short printable token. Moves
    /// no generation (a new key widens nothing that is admitted).
    pub fn insert_transport_key(&mut self, rec: &TransportKeyRecord) -> Result<()> {
        if rec.state != TransportKeyState::Active || rec.destroyed_at.is_some() {
            return Err(conflict("a new transport key reference must be active"));
        }
        if !valid_token(&rec.store_kind, 32) || !valid_token(&rec.store_ref, 256) {
            return Err(conflict("a transport key reference is malformed"));
        }
        if self.active_transport_key()?.is_some() {
            return Err(conflict("a transport key is already active"));
        }
        let inserted = self.tx.execute(
            "INSERT INTO transport_keys (endpoint_id, store_kind, store_ref, state, created_at, destroyed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL) ON CONFLICT(endpoint_id) DO NOTHING",
            rusqlite::params![
                rec.endpoint.as_str(),
                rec.store_kind,
                rec.store_ref,
                codec::enum_str(&rec.state)?,
                codec::ts(rec.created_at),
            ],
        )?;
        if inserted == 0 {
            return Err(conflict(
                "the endpoint already has a transport key reference",
            ));
        }
        Ok(())
    }

    /// One reference.
    pub fn transport_key(
        &mut self,
        endpoint: &IrohEndpointId,
    ) -> Result<Option<TransportKeyRecord>> {
        let row = self
            .tx
            .query_row(
                &format!("SELECT {KEY_COLUMNS} FROM transport_keys WHERE endpoint_id = ?1"),
                [endpoint.as_str()],
                key_row,
            )
            .optional()?;
        row.map(key_of).transpose()
    }

    /// The active reference, if any. Two active rows (which the writers never produce) are
    /// [`StoreError::Corrupt`]: fail closed.
    pub fn active_transport_key(&mut self) -> Result<Option<TransportKeyRecord>> {
        let active = codec::enum_str(&TransportKeyState::Active)?;
        let mut stmt = self.tx.prepare(&format!(
            "SELECT {KEY_COLUMNS} FROM transport_keys WHERE state = ?1"
        ))?;
        let rows = stmt.query_map([active], key_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(key_of(row?)?);
        }
        if out.len() > 1 {
            return Err(corrupt("more than one transport key is active"));
        }
        Ok(out.pop())
    }

    /// Every reference, oldest first.
    pub fn transport_keys(&mut self) -> Result<Vec<TransportKeyRecord>> {
        let mut stmt = self.tx.prepare(&format!(
            "SELECT {KEY_COLUMNS} FROM transport_keys ORDER BY created_at, endpoint_id"
        ))?;
        let rows = stmt.query_map([], key_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(key_of(row?)?);
        }
        Ok(out)
    }

    /// Withdraw a K_iroh reference (rotation, loss or removal): state `destroyed`, with
    /// `now`. Narrows remote admission, so it moves the admission authority generation in
    /// this transaction. Idempotent: a reference already destroyed is returned unchanged and
    /// moves nothing. A missing one is `QueryReturnedNoRows`.
    pub fn destroy_transport_key(
        &mut self,
        endpoint: &IrohEndpointId,
        now: Timestamp,
    ) -> Result<TransportKeyRecord> {
        let Some(mut rec) = self.transport_key(endpoint)? else {
            return Err(missing());
        };
        if rec.state == TransportKeyState::Destroyed {
            return Ok(rec);
        }
        self.narrow_remote_admission(now)?;
        rec.state = TransportKeyState::Destroyed;
        rec.destroyed_at = Some(now);
        self.tx.execute(
            "UPDATE transport_keys SET state = ?2, destroyed_at = ?3 WHERE endpoint_id = ?1",
            rusqlite::params![
                rec.endpoint.as_str(),
                codec::enum_str(&rec.state)?,
                codec::ts(now),
            ],
        )?;
        Ok(rec)
    }

    /// Rotation (ADR-0012 §2.4 item 4): withdraw the active reference (moving the admission
    /// authority generation) and record `new` as active, in one transaction. Returns the
    /// withdrawn reference (`None` when none was active).
    pub fn rotate_transport_key(
        &mut self,
        new: &TransportKeyRecord,
        now: Timestamp,
    ) -> Result<Option<TransportKeyRecord>> {
        let old = match self.active_transport_key()? {
            Some(old) => Some(self.destroy_transport_key(&old.endpoint, now)?),
            None => None,
        };
        self.insert_transport_key(new)?;
        Ok(old)
    }

    /// Delete a `destroyed` reference once its platform item is gone (ADR-0012 §2.5). An
    /// active reference is refused ([`StoreError::GenerationConflict`]): withdraw it first.
    /// Returns whether a row was deleted.
    pub fn remove_transport_key(&mut self, endpoint: &IrohEndpointId) -> Result<bool> {
        match self.transport_key(endpoint)? {
            None => Ok(false),
            Some(rec) if rec.state == TransportKeyState::Active => Err(conflict(
                "an active transport key reference is never deleted",
            )),
            Some(_) => {
                let n = self.tx.execute(
                    "DELETE FROM transport_keys WHERE endpoint_id = ?1",
                    [endpoint.as_str()],
                )?;
                Ok(n > 0)
            }
        }
    }

    // --- exposure consents ---------------------------------------------------------------

    /// Record one exposure consent. A consent ID already stored is a
    /// [`StoreError::GenerationConflict`] and writes nothing. Moves no generation (a consent
    /// is recorded only by an approved widening).
    pub fn insert_route_consent(&mut self, rec: &RouteConsentRecord) -> Result<()> {
        let inserted = self.tx.execute(
            "INSERT INTO route_consents (consent_id, route_id, decision_id, delta_json, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(consent_id) DO NOTHING",
            rusqlite::params![
                rec.consent.as_str(),
                rec.route.as_ref().map(RouteId::as_str),
                rec.decision.as_str(),
                codec::doc(&rec.delta)?,
                codec::ts(rec.recorded_at),
            ],
        )?;
        if inserted == 0 {
            return Err(conflict("the consent is already recorded"));
        }
        Ok(())
    }

    /// One consent.
    pub fn route_consent(&mut self, consent: &ConsentId) -> Result<Option<RouteConsentRecord>> {
        let row = self
            .tx
            .query_row(
                &format!("SELECT {CONSENT_COLUMNS} FROM route_consents WHERE consent_id = ?1"),
                [consent.as_str()],
                consent_row,
            )
            .optional()?;
        row.map(consent_of).transpose()
    }

    /// The consents of `route` (`None`: the serving endpoint's own), oldest first.
    pub fn route_consents(&mut self, route: Option<&RouteId>) -> Result<Vec<RouteConsentRecord>> {
        let mut stmt = match route {
            Some(_) => self.tx.prepare(&format!(
                "SELECT {CONSENT_COLUMNS} FROM route_consents WHERE route_id = ?1 \
                 ORDER BY recorded_at, consent_id"
            ))?,
            None => self.tx.prepare(&format!(
                "SELECT {CONSENT_COLUMNS} FROM route_consents WHERE route_id IS NULL \
                 ORDER BY recorded_at, consent_id"
            ))?,
        };
        let rows = match route {
            Some(r) => stmt.query_map([r.as_str()], consent_row)?,
            None => stmt.query_map([], consent_row)?,
        };
        let mut out = Vec::new();
        for row in rows {
            out.push(consent_of(row?)?);
        }
        Ok(out)
    }

    /// Every consent, oldest first.
    pub fn all_route_consents(&mut self) -> Result<Vec<RouteConsentRecord>> {
        let mut stmt = self.tx.prepare(&format!(
            "SELECT {CONSENT_COLUMNS} FROM route_consents ORDER BY recorded_at, consent_id"
        ))?;
        let rows = stmt.query_map([], consent_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(consent_of(row?)?);
        }
        Ok(out)
    }

    /// Remove the consents of `route` (`None`: the serving endpoint's own). Exposure
    /// narrowing: when a row was removed, moves the admission authority generation in this
    /// transaction. Returns how many were removed.
    pub fn remove_route_consents(
        &mut self,
        route: Option<&RouteId>,
        now: Timestamp,
    ) -> Result<usize> {
        let n = match route {
            Some(r) => self.tx.execute(
                "DELETE FROM route_consents WHERE route_id = ?1",
                [r.as_str()],
            )?,
            None => self
                .tx
                .execute("DELETE FROM route_consents WHERE route_id IS NULL", [])?,
        };
        if n > 0 {
            self.narrow_remote_admission(now)?;
        }
        Ok(n)
    }

    // --- the admission authority generation ----------------------------------------------

    /// Move the admission authority generation (`remote_authority_generation`, the serve
    /// lease's generation) up by one for a change that narrows remote admission (module
    /// docs); returns the new value. The same row and rule as the client tombstone's bump
    /// in [`crate::ext_m06`]. ⟨M06 W2, U56-Q3⟩ One writer: it moves the generation through
    /// `ext_m06`'s bump, the same function the tombstone uses.
    pub fn narrow_remote_admission(&mut self, now: Timestamp) -> Result<u64> {
        self.bump_remote_authority_generation(now)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use heimdall_contract::route::InfrastructureProfile;

    use super::*;
    use crate::{NoFaults, Store};

    fn now(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn endpoint(c: char) -> IrohEndpointId {
        IrohEndpointId::parse(&c.to_string().repeat(64)).unwrap()
    }

    fn key(c: char) -> TransportKeyRecord {
        TransportKeyRecord {
            endpoint: endpoint(c),
            store_kind: "fixture_test".into(),
            store_ref: format!("heimdall-iroh/env/{}", endpoint(c).as_str()),
            state: TransportKeyState::Active,
            created_at: now("2026-11-21T10:00:00Z"),
            destroyed_at: None,
        }
    }

    fn consent(n: u8, route: Option<RouteId>) -> RouteConsentRecord {
        RouteConsentRecord {
            consent: ConsentId::from_random_bytes([n; 16]),
            route,
            decision: DecisionId::from_random_bytes([n; 16]),
            delta: ExposureDelta {
                endpoint: Some(endpoint('a')),
                serve_before: false,
                serve_after: true,
                bind_before: BindScope::Loopback,
                bind_after: BindScope::Wildcard,
                relays_added: vec!["https://relay.invalid".into()],
                direct_fallback_added: true,
                public_infrastructure_added: false,
                external_roost: None,
                after: ExposurePolicy {
                    bind: BindScope::Wildcard,
                    infrastructure: InfrastructureProfile::Custom {
                        relays: vec!["https://relay.invalid".into()],
                    },
                    direct_fallback: true,
                },
            },
            recorded_at: now("2026-11-21T10:00:00Z"),
        }
    }

    fn generation(store: &Store) -> u64 {
        store
            .transaction(|tx| tx.remote_authority_generation())
            .unwrap()
    }

    /// Key references: one active at a time; withdrawal (rotation, removal) moves the
    /// admission authority generation once, before the row may be deleted; recording a key
    /// moves nothing.
    #[test]
    fn key_references_rotate_withdraw_and_move_the_admission_generation() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let t = now("2026-11-21T11:00:00Z");
        store
            .transaction(|tx| tx.insert_transport_key(&key('a')))
            .unwrap();
        assert_eq!(
            generation(&store),
            0,
            "recording a key widens nothing admitted"
        );
        // One active key: a second insert is refused and writes nothing.
        assert!(matches!(
            store.transaction(|tx| tx.insert_transport_key(&key('b'))),
            Err(StoreError::GenerationConflict(_))
        ));
        // Malformed or non-active records are refused.
        let mut bad = key('c');
        bad.store_ref = "has a space".into();
        assert!(
            store
                .transaction(|tx| tx.insert_transport_key(&bad))
                .is_err()
        );
        // An active row is never deleted.
        assert!(
            store
                .transaction(|tx| tx.remove_transport_key(&endpoint('a')))
                .is_err()
        );
        // Rotation: the old reference is withdrawn (generation +1) and the new one active.
        let old = store
            .transaction(|tx| tx.rotate_transport_key(&key('b'), t))
            .unwrap()
            .unwrap();
        assert_eq!(old.state, TransportKeyState::Destroyed);
        assert_eq!(old.destroyed_at, Some(t));
        assert_eq!(generation(&store), 1);
        let active = store
            .transaction(|tx| tx.active_transport_key())
            .unwrap()
            .unwrap();
        assert_eq!(active.endpoint, endpoint('b'));
        // Withdrawing again is idempotent.
        store
            .transaction(|tx| tx.destroy_transport_key(&endpoint('a'), t))
            .unwrap();
        assert_eq!(generation(&store), 1);
        assert!(
            store
                .transaction(|tx| tx.remove_transport_key(&endpoint('a')))
                .unwrap()
        );
        // Removal of the active key: withdraw (generation +1), then delete.
        store
            .transaction(|tx| tx.destroy_transport_key(&endpoint('b'), t))
            .unwrap();
        assert_eq!(generation(&store), 2);
        assert!(
            store
                .transaction(|tx| tx.remove_transport_key(&endpoint('b')))
                .unwrap()
        );
        assert!(
            store
                .transaction(|tx| tx.transport_keys())
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            store.transaction(|tx| tx.destroy_transport_key(&endpoint('b'), t)),
            Err(StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows))
        ));
    }

    /// Consents round trip with their exact delta, endpoint-level (no route) and per route;
    /// removing one is exposure narrowing (generation +1); recording one moves nothing.
    #[test]
    fn consents_round_trip_and_removal_narrows() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let route = RouteId::from_random_bytes([9; 16]);
        let t = now("2026-11-21T11:00:00Z");
        store
            .transaction(|tx| {
                tx.insert_route_consent(&consent(1, None))?;
                tx.insert_route_consent(&consent(2, Some(route.clone())))
            })
            .unwrap();
        assert_eq!(generation(&store), 0);
        assert!(matches!(
            store.transaction(|tx| tx.insert_route_consent(&consent(1, None))),
            Err(StoreError::GenerationConflict(_))
        ));
        let own = store.transaction(|tx| tx.route_consents(None)).unwrap();
        assert_eq!(own, vec![consent(1, None)]);
        let routed = store
            .transaction(|tx| tx.route_consents(Some(&route)))
            .unwrap();
        assert_eq!(routed, vec![consent(2, Some(route.clone()))]);
        assert_eq!(
            store
                .transaction(|tx| tx.all_route_consents())
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            store
                .transaction(|tx| tx.route_consent(&consent(2, None).consent))
                .unwrap()
                .unwrap()
                .route,
            Some(route.clone())
        );
        assert_eq!(
            store
                .transaction(|tx| tx.remove_route_consents(None, t))
                .unwrap(),
            1
        );
        assert_eq!(generation(&store), 1);
        assert_eq!(
            store
                .transaction(|tx| tx.remove_route_consents(None, t))
                .unwrap(),
            0
        );
        assert_eq!(generation(&store), 1, "removing nothing narrows nothing");
        assert_eq!(
            store
                .transaction(|tx| tx.remove_route_consents(Some(&route), t))
                .unwrap(),
            1
        );
        assert_eq!(generation(&store), 2);
    }
}
