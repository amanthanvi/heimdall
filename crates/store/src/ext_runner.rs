//! ⟨M06 U3⟩ Store methods for the runner runtime's issuance and time source (ADR-0012 §4.2,
//! §4.4; m06-plan U3). Schema: `migrations/0009_remote.sql`'s `remote_grant_issuers`, and two
//! `meta` keys; no migration of its own.
//!
//! Conventions (as [`crate::ext_m06`]): every method runs inside the caller's [`Txn`]; reads
//! return `Option`/`Vec`; the store reads no clock (every instant is the caller's).
//!
//! * **Grant-to-issuer pins** (`remote_grant_issuers`, ADR-0012 §4.2 "pinned to its issuer"):
//!   the first certificate a runner installs for a grant pins that grant to the controller
//!   (its paired client) and the CA that issued it. A pin is never replaced:
//!   [`Txn::pin_remote_grant_issuer`] answers [`PinOutcome::Conflict`] for a different issuer
//!   and writes nothing. In V1 a different issuer needs a separately approved grant. A pin is
//!   removed only with its grant's record ([`Txn::forget_remote_grant_issuer`]).
//! * **`issuer_trust`** (ADR-0012 §3.8, §3.10, §8 item 3): the CAs this runner accepts
//!   certificates from, each naming the controller (paired client) it belongs to. Changing it
//!   is a widening action confirmed **runner-locally**; the store only keeps the rows (the
//!   caller checked the attended confirmation). Meta rows `runner_issuer_trust:<fingerprint>`.
//! * **The designated time source** (ADR-0012 §4.4): the one owner client whose
//!   `time_response` this runner counts. Designating it is a widening action confirmed
//!   runner-locally. Meta row `runner_time_source`. The samples themselves are process state
//!   (`heimdall_runtime::runner::time`), never stored here.
//!
//! Nothing here moves a generation: a pin records who issued, and the trust set and the
//! designation are re-read by every install and every time response in their own
//! transaction, so a removal applies to the next one without a generation bump.

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{CaFingerprint, ClientId, GrantId};
use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize};

use crate::{Result, StoreError, Txn, codec};

/// ⟨M06 U3⟩ The meta key of the designated time source (ADR-0012 §4.4).
pub const META_RUNNER_TIME_SOURCE: &str = "runner_time_source";

/// ⟨M06 U3⟩ The meta key prefix of the runner's `issuer_trust` entries (one per CA).
pub const META_RUNNER_ISSUER_TRUST: &str = "runner_issuer_trust:";

/// The largest OpenSSH public key line kept for a trusted CA.
const MAX_CA_PUBLIC_KEY_BYTES: usize = 16 * 1024;

fn corrupt(what: &str) -> StoreError {
    StoreError::Corrupt(what.into())
}

/// One grant-to-issuer pin (`remote_grant_issuers`; ADR-0012 §4.2): the controller and the CA
/// that issued a runner grant's first installed certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteGrantIssuer {
    /// The runner's grant.
    pub grant: GrantId,
    /// The issuing controller: the paired client whose session installed the certificate.
    pub issuer_client: ClientId,
    /// The CA that signed it.
    pub ca_fingerprint: CaFingerprint,
    /// The grant's authority generation at the pin.
    pub grant_generation: u64,
    /// When pinned (the caller's clock).
    pub pinned_at: Timestamp,
}

/// What [`Txn::pin_remote_grant_issuer`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinOutcome {
    /// No pin existed; this one was written.
    Pinned,
    /// The same controller and CA were already pinned; nothing written.
    Same,
    /// Another controller or CA is pinned; nothing written. The stored pin.
    Conflict(RemoteGrantIssuer),
}

/// One `issuer_trust` entry (ADR-0012 §3.8): a CA this runner accepts certificates from, and
/// the controller it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedIssuer {
    /// The CA.
    pub ca_fingerprint: CaFingerprint,
    /// The CA's OpenSSH public key line (public text).
    pub ca_public_key: String,
    /// The controller (paired client) whose issuer holds it.
    pub controller: ClientId,
    /// When the owner confirmed it (runner-locally).
    pub trusted_at: Timestamp,
}

/// The designated time source (ADR-0012 §4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeSourceDesignation {
    /// The owner client whose `time_response` counts.
    pub client: ClientId,
    /// When the owner designated it (runner-locally).
    pub designated_at: Timestamp,
}

fn trust_key(ca: &CaFingerprint) -> String {
    format!("{META_RUNNER_ISSUER_TRUST}{}", ca.as_str())
}

impl Txn<'_> {
    // --- grant-to-issuer pins ---------------------------------------------------------------

    /// ⟨M06 U3⟩ Pin `pin.grant` to its issuer (module docs): written when the grant has no pin;
    /// [`PinOutcome::Same`] when the same controller and CA are pinned; otherwise
    /// [`PinOutcome::Conflict`] with the stored pin. Never replaces a pin.
    pub fn pin_remote_grant_issuer(&mut self, pin: &RemoteGrantIssuer) -> Result<PinOutcome> {
        if let Some(stored) = self.remote_grant_issuer(&pin.grant)? {
            return Ok(
                if stored.issuer_client == pin.issuer_client
                    && stored.ca_fingerprint == pin.ca_fingerprint
                {
                    PinOutcome::Same
                } else {
                    PinOutcome::Conflict(stored)
                },
            );
        }
        self.tx.execute(
            "INSERT INTO remote_grant_issuers (grant_id, issuer_client, ca_fingerprint,
                 record_json, pinned_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                pin.grant.as_str(),
                pin.issuer_client.as_str(),
                pin.ca_fingerprint.as_str(),
                codec::doc(pin)?,
                codec::ts(pin.pinned_at),
            ],
        )?;
        Ok(PinOutcome::Pinned)
    }

    /// ⟨M06 U3⟩ The pin of `grant`, if any.
    pub fn remote_grant_issuer(&mut self, grant: &GrantId) -> Result<Option<RemoteGrantIssuer>> {
        let json: Option<String> = self
            .tx
            .query_row(
                "SELECT record_json FROM remote_grant_issuers WHERE grant_id = ?1",
                [grant.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        let Some(json) = json else {
            return Ok(None);
        };
        let pin: RemoteGrantIssuer = codec::parse_doc(&json)?;
        if &pin.grant != grant {
            return Err(corrupt("a grant-to-issuer pin names another grant"));
        }
        Ok(Some(pin))
    }

    /// ⟨M06 U3⟩ Every pin, by grant (the runner's authority report, ADR-0012 §7.4 step 3).
    pub fn remote_grant_issuers(&mut self) -> Result<Vec<RemoteGrantIssuer>> {
        let mut stmt = self
            .tx
            .prepare("SELECT record_json FROM remote_grant_issuers ORDER BY grant_id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(codec::parse_doc(&row?)?);
        }
        Ok(out)
    }

    /// ⟨M06 U3⟩ Remove `grant`'s pin with its grant's record (the grant purged); `false` when
    /// there was none.
    pub fn forget_remote_grant_issuer(&mut self, grant: &GrantId) -> Result<bool> {
        let n = self.tx.execute(
            "DELETE FROM remote_grant_issuers WHERE grant_id = ?1",
            [grant.as_str()],
        )?;
        Ok(n > 0)
    }

    // --- issuer_trust --------------------------------------------------------------------------

    /// ⟨M06 U3⟩ Add or replace the `issuer_trust` entry of `entry.ca_fingerprint` (a widening
    /// confirmed runner-locally; the caller checked the confirmation). The public key line must
    /// be at most 16 KiB of one line ([`codec::doc_error`] otherwise, nothing written).
    pub fn trust_remote_issuer(&mut self, entry: &TrustedIssuer) -> Result<()> {
        if entry.ca_public_key.len() > MAX_CA_PUBLIC_KEY_BYTES
            || entry.ca_public_key.contains(['\n', '\r'])
        {
            return Err(codec::doc_error(
                "a trusted CA key is one line of at most 16 KiB",
            ));
        }
        self.set_meta(&trust_key(&entry.ca_fingerprint), &codec::doc(entry)?)
    }

    /// ⟨M06 U3⟩ Remove the `issuer_trust` entry of `ca` (a narrowing); `false` when there was
    /// none.
    pub fn untrust_remote_issuer(&mut self, ca: &CaFingerprint) -> Result<bool> {
        let key = trust_key(ca);
        let present = self.meta(&key)?.is_some();
        if present {
            self.delete_meta(&key)?;
        }
        Ok(present)
    }

    /// ⟨M06 U3⟩ The `issuer_trust` entry of `ca`, if any.
    pub fn trusted_remote_issuer(&mut self, ca: &CaFingerprint) -> Result<Option<TrustedIssuer>> {
        let Some(json) = self.meta(&trust_key(ca))? else {
            return Ok(None);
        };
        let entry: TrustedIssuer = codec::parse_doc(&json)?;
        if &entry.ca_fingerprint != ca {
            return Err(corrupt("an issuer_trust entry names another CA"));
        }
        Ok(Some(entry))
    }

    /// ⟨M06 U3⟩ Every `issuer_trust` entry, by CA fingerprint.
    pub fn remote_issuer_trust(&mut self) -> Result<Vec<TrustedIssuer>> {
        self.meta_with_prefix(META_RUNNER_ISSUER_TRUST)?
            .iter()
            .map(|json| codec::parse_doc(json))
            .collect()
    }

    // --- the designated time source --------------------------------------------------------------

    /// ⟨M06 U3⟩ Designate the runner's time source (a widening confirmed runner-locally; the
    /// caller checked the confirmation and that the client is an active owner). Replaces any
    /// earlier designation.
    pub fn designate_time_source(&mut self, designation: &TimeSourceDesignation) -> Result<()> {
        self.set_meta(META_RUNNER_TIME_SOURCE, &codec::doc(designation)?)
    }

    /// ⟨M06 U3⟩ The designated time source, if any.
    pub fn time_source(&mut self) -> Result<Option<TimeSourceDesignation>> {
        self.meta(META_RUNNER_TIME_SOURCE)?
            .as_deref()
            .map(codec::parse_doc)
            .transpose()
    }

    /// ⟨M06 U3⟩ Clear the designation (a narrowing: no sample counts until the owner designates
    /// again); `false` when there was none.
    pub fn clear_time_source(&mut self) -> Result<bool> {
        let present = self.meta(META_RUNNER_TIME_SOURCE)?.is_some();
        if present {
            self.delete_meta(META_RUNNER_TIME_SOURCE)?;
        }
        Ok(present)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{NoFaults, Store};

    fn store() -> Store {
        Store::open_in_memory(Arc::new(NoFaults)).unwrap()
    }

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn client(b: u8) -> ClientId {
        ClientId::from_random_bytes([b; 16])
    }

    fn ca(c: char) -> CaFingerprint {
        CaFingerprint::parse(&format!("SHA256:{}", c.to_string().repeat(43))).unwrap()
    }

    fn grant() -> GrantId {
        GrantId::from_random_bytes([9; 16])
    }

    fn pin(c: u8, f: char) -> RemoteGrantIssuer {
        RemoteGrantIssuer {
            grant: grant(),
            issuer_client: client(c),
            ca_fingerprint: ca(f),
            grant_generation: 4,
            pinned_at: t("2026-11-21T09:00:00Z"),
        }
    }

    #[test]
    fn a_grant_is_pinned_once_and_never_repinned_to_another_issuer() {
        let s = store();
        s.transaction(|tx| {
            assert_eq!(tx.remote_grant_issuer(&grant())?, None);
            assert_eq!(
                tx.pin_remote_grant_issuer(&pin(1, 'A'))?,
                PinOutcome::Pinned
            );
            // The same issuer again (a second pair's certificate): nothing written.
            let mut later = pin(1, 'A');
            later.pinned_at = t("2026-11-21T10:00:00Z");
            assert_eq!(tx.pin_remote_grant_issuer(&later)?, PinOutcome::Same);
            // Another controller, or the same controller with another CA: refused.
            assert_eq!(
                tx.pin_remote_grant_issuer(&pin(2, 'A'))?,
                PinOutcome::Conflict(pin(1, 'A'))
            );
            assert_eq!(
                tx.pin_remote_grant_issuer(&pin(1, 'B'))?,
                PinOutcome::Conflict(pin(1, 'A'))
            );
            assert_eq!(tx.remote_grant_issuer(&grant())?, Some(pin(1, 'A')));
            assert_eq!(tx.remote_grant_issuers()?, vec![pin(1, 'A')]);
            assert!(tx.forget_remote_grant_issuer(&grant())?);
            assert!(!tx.forget_remote_grant_issuer(&grant())?);
            assert_eq!(tx.remote_grant_issuer(&grant())?, None);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn issuer_trust_and_the_time_source_are_kept_and_removed() {
        let s = store();
        s.transaction(|tx| {
            let entry = TrustedIssuer {
                ca_fingerprint: ca('C'),
                ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA".into(),
                controller: client(3),
                trusted_at: t("2026-11-21T09:00:00Z"),
            };
            tx.trust_remote_issuer(&entry)?;
            assert_eq!(tx.trusted_remote_issuer(&ca('C'))?, Some(entry.clone()));
            assert_eq!(tx.trusted_remote_issuer(&ca('D'))?, None);
            assert_eq!(tx.remote_issuer_trust()?, vec![entry.clone()]);
            let mut two_lines = entry.clone();
            two_lines.ca_public_key.push_str("\nssh-ed25519 AAAA");
            assert!(tx.trust_remote_issuer(&two_lines).is_err());
            assert!(tx.untrust_remote_issuer(&ca('C'))?);
            assert!(!tx.untrust_remote_issuer(&ca('C'))?);
            assert!(tx.remote_issuer_trust()?.is_empty());

            assert_eq!(tx.time_source()?, None);
            let d = TimeSourceDesignation {
                client: client(4),
                designated_at: t("2026-11-21T09:00:00Z"),
            };
            tx.designate_time_source(&d)?;
            assert_eq!(tx.time_source()?, Some(d));
            let d2 = TimeSourceDesignation {
                client: client(5),
                designated_at: t("2026-11-21T09:05:00Z"),
            };
            tx.designate_time_source(&d2)?;
            assert_eq!(tx.time_source()?, Some(d2));
            assert!(tx.clear_time_source()?);
            assert!(!tx.clear_time_source()?);
            assert_eq!(tx.time_source()?, None);
            Ok(())
        })
        .unwrap();
    }
}
