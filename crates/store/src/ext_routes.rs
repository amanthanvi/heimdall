//! ⟨M06 U5a⟩ Store methods for a destination's ordered approved routes (ADR-0012 §5.1, §9
//! items 9 and 11; m06-plan U5a). Schema: `migrations/0009_remote.sql`'s
//! `destination_routes`; no migration of its own.
//!
//! Conventions (as [`crate::ext_m04`]): every method runs inside the caller's [`Txn`]; reads
//! return `Vec`/maps; the store reads no clock (every instant is the caller's).
//!
//! **The one-element case.** A destination with no stored rows has the one route its
//! definition states (`heimdall_domain::routes::approved_routes`); storing a list replaces
//! it, and removing the list returns to it. `route_json` is the authoritative document (a
//! `heimdall_contract::route::DestinationRoute`); `position` is the preference order, most
//! preferred first.
//!
//! **Generations.** A route list decides which jump pairs a grant's certificates may forward
//! through (`permit-port-forwarding`, ADR-0010 §5 item 2) and which routes the helper may
//! take, so every write moves the authority generation (ADR-0006 §13.7 item 5) in the same
//! transaction, and re-validation runs against the new list.

use std::collections::BTreeMap;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::DestinationId;
use heimdall_contract::route::DestinationRoute;

use crate::{Result, StoreError, Txn, codec};

impl Txn<'_> {
    /// Replace `destination`'s stored route list with `routes`, in order. An empty list is
    /// refused (use [`Txn::remove_destination_routes`]); a route ID another destination
    /// already stores, or one repeated in `routes`, is a [`StoreError::GenerationConflict`]
    /// and writes nothing. Moves the authority generation.
    pub fn put_destination_routes(
        &mut self,
        destination: &DestinationId,
        routes: &[DestinationRoute],
        now: Timestamp,
    ) -> Result<()> {
        if routes.is_empty() {
            return Err(StoreError::GenerationConflict(
                "an empty route list is not stored".into(),
            ));
        }
        for r in routes {
            let owner: Option<String> = rusqlite::OptionalExtension::optional(self.tx.query_row(
                "SELECT destination FROM destination_routes WHERE route_id = ?1",
                [r.id.as_str()],
                |row| row.get(0),
            ))?;
            if owner.is_some_and(|o| o != destination.as_str()) {
                return Err(StoreError::GenerationConflict(
                    "a route ID belongs to another destination".into(),
                ));
            }
        }
        self.tx.execute(
            "DELETE FROM destination_routes WHERE destination = ?1",
            [destination.as_str()],
        )?;
        for (position, r) in routes.iter().enumerate() {
            let inserted = self.tx.execute(
                "INSERT INTO destination_routes (route_id, destination, position, route_json, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(route_id) DO NOTHING",
                rusqlite::params![
                    r.id.as_str(),
                    destination.as_str(),
                    codec::int(u64::try_from(position).map_err(|_| codec::doc_error("position"))?)?,
                    codec::doc(r)?,
                    codec::ts(now),
                ],
            )?;
            if inserted == 0 {
                return Err(StoreError::GenerationConflict(
                    "a route ID is repeated in the list".into(),
                ));
            }
        }
        self.bump_generation()
    }

    /// Remove `destination`'s stored route list (back to the one-element case). Moves the
    /// authority generation when a row was removed; returns how many were.
    pub fn remove_destination_routes(&mut self, destination: &DestinationId) -> Result<usize> {
        let n = self.tx.execute(
            "DELETE FROM destination_routes WHERE destination = ?1",
            [destination.as_str()],
        )?;
        if n > 0 {
            self.bump_generation()?;
        }
        Ok(n)
    }

    /// `destination`'s stored route list, most preferred first (empty: the one-element case).
    pub fn destination_routes(
        &mut self,
        destination: &DestinationId,
    ) -> Result<Vec<DestinationRoute>> {
        let mut stmt = self.tx.prepare(
            "SELECT route_json FROM destination_routes WHERE destination = ?1 ORDER BY position",
        )?;
        let rows = stmt.query_map([destination.as_str()], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for json in rows {
            out.push(codec::parse_doc(&json?)?);
        }
        Ok(out)
    }

    /// Every stored route list, by destination, each most preferred first (the input of
    /// `heimdall_domain::catalog::RouteCatalogView::routes`).
    pub fn all_destination_routes(
        &mut self,
    ) -> Result<BTreeMap<DestinationId, Vec<DestinationRoute>>> {
        let mut stmt = self.tx.prepare(
            "SELECT destination, route_json FROM destination_routes ORDER BY destination, position",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out: BTreeMap<DestinationId, Vec<DestinationRoute>> = BTreeMap::new();
        for row in rows {
            let (destination, json) = row?;
            let destination = DestinationId::parse(&destination)
                .map_err(|_| StoreError::Corrupt("a stored route names no destination".into()))?;
            out.entry(destination)
                .or_default()
                .push(codec::parse_doc(&json)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use heimdall_contract::ids::RouteId;
    use heimdall_contract::route::RouteSpec;

    use crate::{NoFaults, Store, StoreError};

    use super::*;

    fn route(n: u8, host: &str) -> DestinationRoute {
        DestinationRoute {
            id: RouteId::from_random_bytes([n; 16]),
            route: RouteSpec::Direct {
                host: host.into(),
                port: None,
            },
            exposure: None,
            consents: Vec::new(),
            identification_timeout_ms: Some(2_000),
        }
    }

    /// A stored list round-trips in order; replacing it keeps the order given; a route ID of
    /// another destination, a repeated ID or an empty list writes nothing; removal returns to
    /// the one-element case; every write moves the authority generation.
    #[test]
    fn route_lists_round_trip_in_order_and_move_the_generation() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let now: Timestamp = "2026-11-20T12:00:00Z".parse().unwrap();
        let (lab, other) = (
            DestinationId::parse("lab").unwrap(),
            DestinationId::parse("other").unwrap(),
        );
        let list = vec![route(1, "a"), route(2, "b"), route(3, "c")];
        let g0 = store.transaction(|tx| tx.authority_generation()).unwrap();
        store
            .transaction(|tx| tx.put_destination_routes(&lab, &list, now))
            .unwrap();
        let g1 = store.transaction(|tx| tx.authority_generation()).unwrap();
        assert!(g1 > g0);
        assert_eq!(
            store.transaction(|tx| tx.destination_routes(&lab)).unwrap(),
            list
        );
        let reordered = vec![route(3, "c"), route(1, "a")];
        store
            .transaction(|tx| tx.put_destination_routes(&lab, &reordered, now))
            .unwrap();
        assert_eq!(
            store.transaction(|tx| tx.destination_routes(&lab)).unwrap(),
            reordered
        );
        for bad in [
            vec![route(3, "x")],
            vec![route(9, "x"), route(9, "y")],
            Vec::new(),
        ] {
            let target = if bad.first().is_some_and(|r| r.id == route(3, "").id) {
                &other
            } else {
                &lab
            };
            let r = store.transaction(|tx| tx.put_destination_routes(target, &bad, now));
            assert!(
                matches!(r, Err(StoreError::GenerationConflict(_))),
                "{bad:?}"
            );
        }
        assert_eq!(
            store.transaction(|tx| tx.destination_routes(&lab)).unwrap(),
            reordered,
            "a refused write changes nothing"
        );
        assert!(
            store
                .transaction(|tx| tx.destination_routes(&other))
                .unwrap()
                .is_empty()
        );
        let all = store.transaction(|tx| tx.all_destination_routes()).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[&lab], reordered);
        let g2 = store.transaction(|tx| tx.authority_generation()).unwrap();
        assert_eq!(
            store
                .transaction(|tx| tx.remove_destination_routes(&lab))
                .unwrap(),
            2
        );
        assert!(store.transaction(|tx| tx.authority_generation()).unwrap() > g2);
        assert!(
            store
                .transaction(|tx| tx.destination_routes(&lab))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .transaction(|tx| tx.remove_destination_routes(&lab))
                .unwrap(),
            0
        );
    }
}
