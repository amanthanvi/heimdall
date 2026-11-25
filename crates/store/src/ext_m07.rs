//! ⟨rev7⟩ m07-plan U3 (ADR-0013 §6.1, §6.2, §6.4; D2): the keyset reads behind `inspect`'s
//! `page` form and the restore epoch a page token is bound to.
//!
//! **Keyset order.** Every read here is ordered by the record's immutable ID (SQLite's
//! `BINARY` collation, which is byte order, the order of Rust's `str`), strictly after the
//! previous page's last ID, and reads at most `take` rows: the caller asks for its page's
//! `limit + 1`, so it learns whether more remain without reading them. A record inserted or
//! deleted between two pages never moves another one across the position, so a stable record
//! is never repeated or skipped.
//!
//! Reads only: nothing here writes, and none of them reads the clock.

use heimdall_domain::catalog::{DestinationRecord, IdentityRecord};
use heimdall_domain::profile::ProfileDefinition;

use crate::{META_RESTORE_EPOCH, Result, StoreError, Txn, codec, parse_restore_epoch};

/// A page's row count as SQLite's `LIMIT`.
fn limit(take: usize) -> Result<i64> {
    codec::int(u64::try_from(take).unwrap_or(u64::MAX))
}

impl Txn<'_> {
    /// ⟨rev7; ADR-0014 H9, §3.6⟩ The store's current restore epoch, read where a page is
    /// served (a page token minted under another epoch is refused). A missing or malformed
    /// value is damage ([`StoreError::Corrupt`]), never epoch 0, as at every open.
    pub fn restore_epoch(&mut self) -> Result<u64> {
        self.meta(META_RESTORE_EPOCH)?
            .as_deref()
            .and_then(parse_restore_epoch)
            .ok_or_else(|| {
                StoreError::Corrupt("the restore epoch is missing or malformed".to_owned())
            })
    }

    /// ⟨rev7⟩ At most `take` catalog destinations whose ID sorts after `after` (every one
    /// when `None`), ordered by ID.
    pub fn destinations_after(
        &mut self,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<DestinationRecord>> {
        self.docs(
            "SELECT record_json FROM destinations WHERE ?1 IS NULL OR id > ?1
             ORDER BY id LIMIT ?2",
            rusqlite::params![after, limit(take)?],
        )
    }

    /// ⟨rev7⟩ At most `take` current profile definitions whose ID sorts after `after`,
    /// ordered by ID. Removed definitions are not listed, as in [`Txn::profiles`].
    pub fn profiles_after(
        &mut self,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<ProfileDefinition>> {
        self.docs(
            "SELECT record_json FROM profiles WHERE ?1 IS NULL OR id > ?1
             ORDER BY id LIMIT ?2",
            rusqlite::params![after, limit(take)?],
        )
    }

    /// ⟨rev7⟩ At most `take` catalog identities whose ID sorts after `after`, ordered by ID.
    pub fn identities_after(
        &mut self,
        after: Option<&str>,
        take: usize,
    ) -> Result<Vec<IdentityRecord>> {
        self.docs(
            "SELECT record_json FROM identities WHERE ?1 IS NULL OR id > ?1
             ORDER BY id LIMIT ?2",
            rusqlite::params![after, limit(take)?],
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use crate::{NoFaults, Store};

    #[test]
    fn restore_epoch_reads_the_migrated_value_and_refuses_damage() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        assert_eq!(store.transaction(|tx| tx.restore_epoch()).unwrap(), 0);
        store
            .transaction(|tx| tx.set_meta(crate::META_RESTORE_EPOCH, "007"))
            .unwrap();
        assert!(matches!(
            store.transaction(|tx| tx.restore_epoch()),
            Err(crate::StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn page_token_key_is_generated_once_and_damage_is_refused() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let first = store
            .transaction(|tx| tx.page_token_key(|| [7; 32]))
            .unwrap();
        assert_eq!(first.expose(), &[7; 32]);
        let again = store
            .transaction(|tx| tx.page_token_key(|| unreachable!("generated once")))
            .unwrap();
        assert_eq!(again, first);
        assert_eq!(format!("{first:?}"), "PageTokenKey(..)");
        store
            .transaction(|tx| tx.set_meta(crate::META_PAGE_TOKEN_KEY, "0707"))
            .unwrap();
        assert!(matches!(
            store.transaction(|tx| tx.page_token_key(|| [9; 32])),
            Err(crate::StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn keyset_reads_are_bounded_and_strictly_after() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let all = store
            .transaction(|tx| tx.destinations_after(None, 10))
            .unwrap();
        assert!(all.is_empty());
        let profiles = store
            .transaction(|tx| tx.profiles_after(Some("a"), 0))
            .unwrap();
        assert!(profiles.is_empty());
        let identities = store
            .transaction(|tx| tx.identities_after(None, 1))
            .unwrap();
        assert!(identities.is_empty());
    }
}
