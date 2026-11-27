//! ⟨M06 U3⟩ Store methods for the runner runtime's issuance and time source (ADR-0012 §4.2,
//! §4.4; m06-plan U3). Schema: `migrations/0009_remote.sql`'s `remote_grant_issuers`, and two
//! `meta` keys; no migration of its own. ⟨M06 W3⟩ Two more `meta` keys hold the runner's
//! owner-only downgrade and the evidence an attended lift needs (ADR-0006 §18.7 items 18–19).
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
//! * ⟨ADR-0006 §18.7 item 18⟩ **The owner-only downgrade** ([`RunnerDowngrade`], meta row
//!   `runner_owner_only`): while the row exists the runner enrolls owner clients only
//!   (ADR-0012 §3.2). It is authority-bearing: in the recovery snapshot, compared, and never
//!   silently restored to a different value. A later downgrade event keeps the first cause
//!   and moves the row's epoch ([`Txn::record_runner_downgrade`]).
//! * ⟨§18.7 item 19⟩ **The recheck evidence** ([`PolicyRecheckEvidence`], meta row
//!   `runner_policy_recheck`): what an owner controller's probes observed on the real
//!   management path, recorded by the runner only after its own checks, for the epoch it was
//!   taken at. The attended lift ([`Txn::lift_runner_downgrade`]) removes both rows, and only
//!   for the epoch its caller judged.
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

/// ⟨M06 W3; ADR-0006 §18.7 item 18⟩ The meta key of the runner's owner-only downgrade.
pub const META_RUNNER_OWNER_ONLY: &str = "runner_owner_only";

/// ⟨M06 W3; ADR-0006 §18.7 item 19⟩ The meta key of the evidence an attended lift needs.
pub const META_RUNNER_POLICY_RECHECK: &str = "runner_policy_recheck";

/// The largest cause token kept in a downgrade.
const MAX_CAUSE_BYTES: usize = 64;

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

/// ⟨ADR-0006 §18.7 item 18⟩ The runner's owner-only downgrade (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerDowngrade {
    /// Why, as the first event's cause token (the writer's vocabulary; opaque here).
    pub cause: String,
    /// Which downgrade event this is: 1 for the first, one more for each later event while
    /// the row stands. Evidence taken at an earlier epoch never lifts a later one.
    pub epoch: u64,
    /// When the first event was recorded (the caller's clock).
    pub recorded_at: Timestamp,
    /// When the latest event was recorded.
    pub last_event_at: Timestamp,
}

/// ⟨ADR-0006 §18.7 item 19⟩ What the runner recorded of an owner controller's recheck
/// (module docs): the probing client, when, and the downgrade epoch it was taken at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRecheckEvidence {
    /// The owner client whose session sent the observation.
    pub controller: ClientId,
    /// The downgrade epoch the evidence was recorded at.
    pub epoch: u64,
    /// When it was recorded (wall clock).
    pub recorded_at: Timestamp,
    /// The boot it was recorded in.
    pub boot_id: String,
    /// The continuous (suspend-inclusive) clock then, in milliseconds since that boot's
    /// origin; `None` when the source was unavailable.
    pub continuous_ms: Option<u64>,
    /// What the four probes observed.
    pub probe: heimdall_contract::remote::ProbeObservation,
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

    // --- ⟨ADR-0006 §18.7 items 18–19⟩ the owner-only downgrade -------------------------------

    /// ⟨M06 W3⟩ The runner's owner-only downgrade, if it stands. A row that does not parse
    /// is an error, which every reader treats as "downgraded" (fail closed).
    pub fn runner_downgrade(&mut self) -> Result<Option<RunnerDowngrade>> {
        self.meta(META_RUNNER_OWNER_ONLY)?
            .as_deref()
            .map(codec::parse_doc)
            .transpose()
    }

    /// ⟨M06 W3⟩ Record a downgrade event (a narrowing: any writer, no confirmation). The
    /// first event writes the row at epoch 1; a later one keeps the first cause and time and
    /// moves the epoch, so evidence recorded before it no longer lifts. Returns the row.
    pub fn record_runner_downgrade(
        &mut self,
        cause: &str,
        now: Timestamp,
    ) -> Result<RunnerDowngrade> {
        if cause.is_empty() || cause.len() > MAX_CAUSE_BYTES || cause.contains(['\n', '\r']) {
            return Err(codec::doc_error("a downgrade cause is one short token"));
        }
        let row = match self.runner_downgrade()? {
            Some(mut standing) => {
                standing.epoch = standing.epoch.saturating_add(1);
                standing.last_event_at = now;
                standing
            }
            None => RunnerDowngrade {
                cause: cause.to_owned(),
                epoch: 1,
                recorded_at: now,
                last_event_at: now,
            },
        };
        self.set_meta(META_RUNNER_OWNER_ONLY, &codec::doc(&row)?)?;
        Ok(row)
    }

    /// ⟨M06 W3⟩ The recorded recheck evidence, if any.
    pub fn policy_recheck(&mut self) -> Result<Option<PolicyRecheckEvidence>> {
        self.meta(META_RUNNER_POLICY_RECHECK)?
            .as_deref()
            .map(codec::parse_doc)
            .transpose()
    }

    /// ⟨M06 W3⟩ Record recheck evidence, replacing any earlier one. `false`, with nothing
    /// written, unless a downgrade stands at exactly `evidence.epoch` (the caller ran its
    /// checks against that row).
    pub fn record_policy_recheck(&mut self, evidence: &PolicyRecheckEvidence) -> Result<bool> {
        if self
            .runner_downgrade()?
            .is_none_or(|d| d.epoch != evidence.epoch)
        {
            return Ok(false);
        }
        self.set_meta(META_RUNNER_POLICY_RECHECK, &codec::doc(evidence)?)?;
        Ok(true)
    }

    /// ⟨M06 W3⟩ Lift the downgrade (a widening confirmed runner-locally; the caller judged
    /// the evidence and checked the confirmation): removes the downgrade and its evidence,
    /// only while the downgrade is still at `epoch`. `false`, with nothing removed, otherwise
    /// (a later event moved it, or none stands).
    pub fn lift_runner_downgrade(&mut self, epoch: u64) -> Result<bool> {
        if self.runner_downgrade()?.is_none_or(|d| d.epoch != epoch) {
            return Ok(false);
        }
        self.delete_meta(META_RUNNER_OWNER_ONLY)?;
        self.delete_meta(META_RUNNER_POLICY_RECHECK)?;
        Ok(true)
    }

    /// ⟨M06 W3; ADR-0012 §3.2 "How the downgrade is kept"⟩ A restore carries the downgrade
    /// forward: write `standing` (the row of the database being replaced, with its epoch)
    /// into this, the restored, database. Set-only: it writes when no row stands here or the
    /// one here is at an earlier epoch, and never lowers an epoch or removes a row. Recheck
    /// evidence here for an earlier epoch is removed with the move (it lifts nothing).
    /// `true` when the row was written.
    pub fn carry_runner_downgrade(&mut self, standing: &RunnerDowngrade) -> Result<bool> {
        if self
            .runner_downgrade()?
            .is_some_and(|d| d.epoch >= standing.epoch)
        {
            return Ok(false);
        }
        self.set_meta(META_RUNNER_OWNER_ONLY, &codec::doc(standing)?)?;
        self.delete_meta(META_RUNNER_POLICY_RECHECK)?;
        Ok(true)
    }
}

impl crate::Store {
    /// ⟨ADR-0012 §3.2 "How the downgrade is kept"⟩ The file this store's database is, when
    /// it is one (`None` for an in-memory store). The runner's runtime finds the bridge's
    /// pending-downgrade marker from it: the bridge is given the same home.
    #[must_use]
    pub fn database_path(&self) -> Option<std::path::PathBuf> {
        let conn = self.conn.lock().ok()?;
        conn.path()
            .filter(|p| !p.is_empty())
            .map(std::path::PathBuf::from)
    }
}

/// ⟨ADR-0012 §3.2 "How the downgrade is kept"⟩ How long the bridge's write waits for the
/// database's write lock (the runtime it runs beside holds it only for single transactions).
pub const BRIDGE_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// ⟨ADR-0012 §3.2 "How the downgrade is kept"; ADR-0006 §18.7 items 17–18⟩ **The one
/// exception to the single-writer rule:** record a downgrade event in the state database at
/// `path` from the bridge, which holds no instance lock (a runtime may be running on the
/// same file).
///
/// * **Set-only:** the one statement this path can execute is the upsert of the
///   `runner_owner_only` row ([`Txn::record_runner_downgrade`]): it can never clear the row
///   or write any other. It never creates, migrates, repairs or changes the journal mode of
///   the database: only an existing database at exactly this build's schema whose own
///   environment is a remote runner is written.
/// * **Idempotent:** a repeated event leaves the row set with its first cause and time; it
///   moves only the row's epoch, so recheck evidence from before it lifts nothing (§18.7
///   item 19).
/// * **One `BEGIN IMMEDIATE` transaction** with a bounded busy timeout
///   ([`BRIDGE_BUSY_TIMEOUT`]). The schema check and the runner check are made inside it,
///   under the write lock, before the upsert.
///
/// ⟨review W3-R01; ADR-0014 §3.6 adoption, step 2⟩ **Why the schema is read again inside
/// the transaction.** The runtime's start can adopt this database's flat family while the
/// bridge runs. The adoption's fence (`layout::fence`, its own `BEGIN IMMEDIATE`
/// transaction) sets the family's `user_version` to [`crate::layout::ADOPTION_FENCE`], and
/// from then on a copy of the family is served, never the family itself. A check made only
/// before the transaction lets a fence that commits in between pass: the row then lands in
/// the fenced family, which is residue, and no marker is queued. Read inside the write
/// lock, the check sees every fence that committed first and refuses
/// ([`StoreError::AdoptionFenced`]). A fence that starts later waits for this commit, so
/// the row is in the family before the fence and therefore in the adoption's copy.
///
/// ⟨M08 W4 SEC-3b; U2b-3b open item 1⟩ **Why the pointer is read inside the transaction.**
/// A restore or a reset (`crate::restore`) makes another generation current by the pointer
/// switch, under the instance lock the bridge does not hold. It reads the replaced
/// generation inside a `BEGIN IMMEDIATE` transaction that it holds until after the switch, so
/// a bridge transaction either commits before that read (the row is carried forward) or
/// begins after the switch. In the second case the database at `path` is the replaced
/// generation, residue. So when `path` is a generation's database, the transaction reads the
/// pointer again under its write lock and refuses ([`StoreError::Corrupt`]) when it no longer
/// names that generation: nothing is written there, and the caller queues the event in its
/// fail-closed marker, which the runtime records in the generation it serves.
///
/// # Errors
///
/// No such database, another schema (a family fenced for adoption included), not a
/// runner's, a generation that is no longer current, a write lock not obtained in time, or
/// SQLite's failure: nothing was recorded.
/// The caller refuses its session all the same and queues the event in its fail-closed
/// marker (`heimdall_runtime::paired::note_unrecorded_downgrade`).
pub fn bridge_record_runner_downgrade(
    path: &std::path::Path,
    cause: &str,
    now: Timestamp,
) -> Result<RunnerDowngrade> {
    bridge_record_with(
        path,
        cause,
        now,
        BRIDGE_BUSY_TIMEOUT,
        std::sync::Arc::new(crate::NoFaults),
    )
}

/// Test support (review W3-R01; `heimdall-runtime`'s
/// `paired::adoption_window_tests::a_bridge_write_after_the_adoption_fence_is_refused_and_reaches_the_served_generation_by_the_marker`):
/// [`bridge_record_runner_downgrade`] with `faults` as the hook of the bridge's store. Its
/// [`crate::FaultPoint::BeforeTransaction`] fires after the bridge has opened the database
/// and checked its schema, and before its transaction begins: the window a concurrent
/// adoption's fence can commit in. Never used by production code.
///
/// # Errors
/// As [`bridge_record_runner_downgrade`], and the hook's injected fault.
#[doc(hidden)]
pub fn bridge_record_runner_downgrade_with_faults(
    path: &std::path::Path,
    cause: &str,
    now: Timestamp,
    faults: std::sync::Arc<dyn crate::FaultHook>,
) -> Result<RunnerDowngrade> {
    bridge_record_with(path, cause, now, BRIDGE_BUSY_TIMEOUT, faults)
}

fn bridge_record_with(
    path: &std::path::Path,
    cause: &str,
    now: Timestamp,
    busy: std::time::Duration,
    faults: std::sync::Arc<dyn crate::FaultHook>,
) -> Result<RunnerDowngrade> {
    use heimdall_domain::environment::EnvironmentKind;
    // No `SQLITE_OPEN_CREATE`: a missing file is an error, never a new database.
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(codec::classify)?;
    conn.busy_timeout(busy).map_err(codec::classify)?;
    // A first refusal, before anything is set on the connection: a file at another schema
    // (an empty file, an older or newer store, a family fenced for adoption) is never
    // written. It does not decide the write; the same check inside the transaction does.
    at_this_builds_schema(&conn)?;
    // Connection settings only (none of them writes the file).
    for (pragma, value) in [
        ("synchronous", "FULL"),
        ("foreign_keys", "ON"),
        ("trusted_schema", "OFF"),
    ] {
        conn.pragma_update(None, pragma, value)
            .map_err(codec::classify)?;
    }
    let store = crate::Store {
        conn: std::sync::Mutex::new(conn),
        faults,
        read_only: false,
    };
    // ⟨M08 W4 SEC-3b; U2b-3b open item 1⟩ The generation this database is, when it is one.
    let opened = generation_of(path);
    // `Store::transaction` on a writable store is `BEGIN IMMEDIATE` (`read_only` is false
    // here): the write lock is taken at `BEGIN`, so no other writer can commit between the
    // version read and the upsert below. A deferred transaction would read first and take
    // the write lock only at the upsert, and the adoption's fence could commit in between.
    store.transaction(|tx| {
        // ⟨W3-R01⟩ The schema again, under the write lock (doc above).
        at_this_builds_schema(&tx.tx)?;
        // ⟨M08 W4 SEC-3b; U2b-3b open item 1⟩ The pointer again, under the same write lock
        // (doc above, "Why the pointer is read inside the transaction").
        if let Some((state_dir, name)) = &opened {
            let pointed = crate::layout::pointed_generation(state_dir)?;
            if pointed.as_deref().and_then(std::path::Path::file_name) != Some(name.as_os_str()) {
                return Err(corrupt(
                    "a restore or a reset made another store generation current before the \
                     bridge's write: nothing was written",
                ));
            }
        }
        let runner = match tx.self_environment()? {
            Some(id) => tx
                .environment(&id)?
                .is_some_and(|e| e.kind == EnvironmentKind::RemoteRunner),
            None => false,
        };
        if !runner {
            return Err(corrupt("the state database is not a runner's"));
        }
        tx.record_runner_downgrade(cause, now)
    })
}

/// ⟨M08 W4 SEC-3b; U2b-3b open item 1⟩ When `path` is the database of a store generation
/// (`<state>/generations/<name>/<file>`, `heimdall_stategen::generations::GENERATIONS`), the
/// state directory whose pointer must still name it and the generation's name. `None` for
/// any other path (the flat family of a build before generations: the adoption's fence
/// guards it, W3-R01).
fn generation_of(path: &std::path::Path) -> Option<(std::path::PathBuf, std::ffi::OsString)> {
    let generation = path.parent()?;
    let generations = generation.parent()?;
    if generations.file_name()? != heimdall_stategen::generations::GENERATIONS {
        return None;
    }
    Some((
        generations.parent()?.to_path_buf(),
        generation.file_name()?.to_os_string(),
    ))
}

/// The database is at exactly this build's schema. An older one (an empty file included)
/// is [`StoreError::OlderSchema`]; a newer one is [`StoreError::NewerSchema`]; a family
/// fenced for adoption is [`StoreError::AdoptionFenced`] (`migrations::check_version`).
fn at_this_builds_schema(conn: &rusqlite::Connection) -> Result<()> {
    let found = crate::migrations::check_version(conn, crate::migrations::MIGRATIONS)?;
    if found < crate::SCHEMA_VERSION {
        return Err(StoreError::OlderSchema {
            found,
            supported: crate::SCHEMA_VERSION,
        });
    }
    Ok(())
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

    /// ⟨ADR-0006 §18.7 items 18–19⟩ The downgrade row: the first cause stands, each later
    /// event moves the epoch, evidence is kept only for the standing epoch, and a lift
    /// removes both rows only at the epoch its caller judged.
    #[test]
    fn the_downgrade_keeps_its_first_cause_and_a_lift_is_bound_to_its_epoch() {
        let s = store();
        s.transaction(|tx| {
            let evidence = |epoch| PolicyRecheckEvidence {
                controller: client(7),
                epoch,
                recorded_at: t("2026-11-21T09:10:00Z"),
                boot_id: "boot-1".into(),
                continuous_ms: Some(5_000),
                probe: heimdall_contract::remote::ProbeObservation {
                    pty_refused: true,
                    forward_refused: true,
                    agent_forward_refused: true,
                    setenv_canary_delivered: false,
                },
            };
            assert_eq!(tx.runner_downgrade()?, None);
            // No downgrade: no evidence is kept, and nothing lifts.
            assert!(!tx.record_policy_recheck(&evidence(1))?);
            assert!(!tx.lift_runner_downgrade(1)?);
            let first = tx.record_runner_downgrade("session_pty", t("2026-11-21T09:00:00Z"))?;
            assert_eq!((first.epoch, first.cause.as_str()), (1, "session_pty"));
            assert!(tx.record_policy_recheck(&evidence(1))?);
            // A later event: the cause stands, the epoch moves, the old evidence is stale.
            let second =
                tx.record_runner_downgrade("probe_disagreed", t("2026-11-21T09:20:00Z"))?;
            assert_eq!((second.epoch, second.cause.as_str()), (2, "session_pty"));
            assert_eq!(second.recorded_at, first.recorded_at);
            assert_eq!(tx.policy_recheck()?, Some(evidence(1)));
            assert!(!tx.record_policy_recheck(&evidence(1))?);
            assert!(!tx.lift_runner_downgrade(1)?);
            assert_eq!(tx.runner_downgrade()?, Some(second));
            assert!(tx.record_policy_recheck(&evidence(2))?);
            assert!(tx.lift_runner_downgrade(2)?);
            assert_eq!(tx.runner_downgrade()?, None);
            assert_eq!(tx.policy_recheck()?, None);
            assert!(
                tx.record_runner_downgrade("two\nlines", t("2026-11-21T09:30:00Z"))
                    .is_err()
            );
            Ok(())
        })
        .unwrap();
    }

    /// A runner's (or, with `runner` false, an ordinary installation's) state database
    /// file, closed again.
    fn database(dir: &std::path::Path, runner: bool) -> std::path::PathBuf {
        use heimdall_domain::environment::{
            EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
        };
        let path = dir.join("state.db");
        let s = Store::open(&path, Arc::new(NoFaults)).unwrap();
        s.transaction(|tx| {
            let id = heimdall_contract::ids::EnvironmentId::from_random_bytes([7; 16]);
            tx.init_self_environment(&id)?;
            if runner {
                tx.upsert_environment(&EnvironmentRecord {
                    id,
                    device: heimdall_contract::ids::DeviceId::from_random_bytes([0; 16]),
                    kind: EnvironmentKind::RemoteRunner,
                    label: None,
                    permissions: EnvironmentPermissions::default(),
                })?;
            }
            Ok(())
        })
        .unwrap();
        path
    }

    /// Every `meta` row but the downgrade's, and the row counts of every table.
    fn everything_else(path: &std::path::Path) -> Vec<(String, String)> {
        let c = rusqlite::Connection::open(path).unwrap();
        let mut out: Vec<(String, String)> = c
            .prepare("SELECT key, value FROM meta WHERE key <> ?1 ORDER BY key")
            .unwrap()
            .query_map([META_RUNNER_OWNER_ONLY], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        let tables: Vec<String> = c
            .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        for t in tables.iter().filter(|t| *t != "meta") {
            let n: i64 = c
                .query_row(&format!("SELECT count(*) FROM \"{t}\""), [], |r| r.get(0))
                .unwrap();
            out.push((t.clone(), n.to_string()));
        }
        out
    }

    #[test]
    fn the_bridges_write_is_set_only_idempotent_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = database(dir.path(), true);
        let before = everything_else(&path);
        // The runtime's connection stays open beside the bridge's (no instance lock).
        let runtime = Store::open(&path, Arc::new(NoFaults)).unwrap();
        let first = bridge_record_runner_downgrade(&path, "session_pty", t("2026-11-21T09:00:00Z"))
            .unwrap();
        assert_eq!((first.cause.as_str(), first.epoch), ("session_pty", 1));
        // The running runtime reads it on its next transaction.
        assert_eq!(
            runtime.transaction(|tx| tx.runner_downgrade()).unwrap(),
            Some(first.clone())
        );
        // Again: still set, the first cause and time stand, only the epoch moves.
        let again = bridge_record_runner_downgrade(
            &path,
            "session_agent_forwarded",
            t("2026-11-21T09:10:00Z"),
        )
        .unwrap();
        assert_eq!(
            (again.cause.as_str(), again.recorded_at, again.epoch),
            ("session_pty", first.recorded_at, 2)
        );
        // Nothing else was written, in `meta` or in any table.
        assert_eq!(everything_else(&path), before);

        // While another connection holds the write lock the bridge waits a bounded time,
        // fails, and has written nothing.
        let started = std::time::Instant::now();
        let busy = runtime.transaction(|_| {
            Ok(bridge_record_with(
                &path,
                "session_pty",
                t("2026-11-21T09:20:00Z"),
                std::time::Duration::from_millis(150),
                Arc::new(NoFaults),
            ))
        });
        assert!(matches!(busy, Ok(Err(_))), "{busy:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(
            runtime.transaction(|tx| tx.runner_downgrade()).unwrap(),
            Some(again)
        );
    }

    #[test]
    fn the_bridges_write_never_creates_or_writes_a_database_that_is_not_a_runners() {
        let dir = tempfile::tempdir().unwrap();
        let now = t("2026-11-21T09:00:00Z");
        // No database: none is created.
        let missing = dir.path().join("state.db");
        assert!(bridge_record_runner_downgrade(&missing, "session_pty", now).is_err());
        assert!(!missing.exists());
        // An empty file (schema 0): refused as an older schema, left empty.
        std::fs::write(&missing, b"").unwrap();
        assert!(matches!(
            bridge_record_runner_downgrade(&missing, "session_pty", now),
            Err(StoreError::OlderSchema { .. })
        ));
        assert_eq!(std::fs::metadata(&missing).unwrap().len(), 0);
        std::fs::remove_file(&missing).unwrap();
        // An ordinary installation's database: refused, no row.
        let path = database(dir.path(), false);
        assert!(bridge_record_runner_downgrade(&path, "session_pty", now).is_err());
        let s = Store::open(&path, Arc::new(NoFaults)).unwrap();
        assert_eq!(s.transaction(|tx| tx.runner_downgrade()).unwrap(), None);
    }

    #[test]
    fn a_restore_carries_the_downgrade_forward_and_never_lowers_it() {
        let standing = RunnerDowngrade {
            cause: "session_pty".to_owned(),
            epoch: 3,
            recorded_at: t("2026-11-21T09:00:00Z"),
            last_event_at: t("2026-11-21T09:40:00Z"),
        };
        // Into a database from before the downgrade: the row, with its epoch.
        let s = store();
        s.transaction(|tx| {
            assert!(tx.carry_runner_downgrade(&standing)?);
            assert_eq!(tx.runner_downgrade()?, Some(standing.clone()));
            // Again: nothing to do.
            assert!(!tx.carry_runner_downgrade(&standing)?);
            Ok(())
        })
        .unwrap();
        // Into one from between two events: the later epoch, and the evidence recorded for
        // the earlier one is gone.
        let s = store();
        s.transaction(|tx| {
            let early = tx.record_runner_downgrade("session_pty", standing.recorded_at)?;
            assert!(tx.record_policy_recheck(&PolicyRecheckEvidence {
                controller: client(1),
                epoch: early.epoch,
                recorded_at: standing.recorded_at,
                boot_id: "boot".to_owned(),
                continuous_ms: None,
                probe: heimdall_contract::remote::ProbeObservation {
                    pty_refused: true,
                    forward_refused: true,
                    agent_forward_refused: true,
                    setenv_canary_delivered: false,
                },
            })?);
            assert!(tx.carry_runner_downgrade(&standing)?);
            assert_eq!(tx.runner_downgrade()?, Some(standing.clone()));
            assert_eq!(tx.policy_recheck()?, None);
            Ok(())
        })
        .unwrap();
        // Into one already at a later epoch: left as it is (never lowered, never cleared).
        let s = store();
        s.transaction(|tx| {
            for _ in 0..4 {
                tx.record_runner_downgrade("probe_disagreed", standing.recorded_at)?;
            }
            let later = tx.runner_downgrade()?;
            assert!(!tx.carry_runner_downgrade(&standing)?);
            assert_eq!(tx.runner_downgrade()?, later);
            Ok(())
        })
        .unwrap();
    }
}
