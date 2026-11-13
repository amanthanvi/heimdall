//! ⟨M03⟩ wave 4 (U10): the issuer request handling over the store (ADR-0008 D3, D4;
//! m03-plan U10 `issuer::handle`): `issuer.status`, `register` (through the
//! `RegisterIssuer` decision), `unlock`, `retire` (through the `RetireIssuer`
//! decision) and `bundle`; the completion of both decision kinds; the supervisor's
//! issuer supervision pass. The public part is [`crate::issuer`].
//!
//! **Fail closed (R4).** Every action needs the runtime's issuer wiring
//! (`ManagedWiring.issuer`; `register` and `unlock` also `issuer_lifecycle`): without
//! it the answer is `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`, before any
//! record is written. Every action needs the owner role; `unlock` an attended session
//! (the dispatcher refuses both first; checked again here, R5).
//!
//! **`register`** (D4 item 1 steps 3 and 7) validates the request (one Ed25519 public
//! key line without a comment, a hex SHA-256 backup digest, no second registration of
//! the fingerprint, a rotation's CA registered and `active`), then always creates (or
//! joins: spec §5.5, one logical decision, one record) a pending `RegisterIssuer`
//! decision with time assessed in the writing transaction, and answers
//! `APPROVAL_REQUIRED` (attended) or `INTERACTION_REQUIRED` with its reference. It
//! never executes on dispatch. Approval, in the decide transaction: the `issuers` row
//! (`active`, or `pending` for a rotation's new CA), the native environment's
//! `managed_signing` and `issuer_access` permissions (which moves the authority
//! generation, ADR-0006 §13.7 item 5) and, when the record disclosed it, the lock
//! disclosure's acknowledgement; after the commit the child is started or reloaded.
//!
//! **The registration's public key** and `backup_created_at` are part of the
//! `RegisterIssuer` record (ADR-0008 §17.21 item 3: additive `ca_public_key` and
//! `backup_created_at`), so the pending registration survives a restart and its
//! approval reads only the record: no process memory. A record written before those
//! fields is refused `DECISION_STALE` on approval and not consumed: register again.
//!
//! **The store locator** (§17.22 item 12, R2B-Q1; §17.21 item 3; §17.17 item 3) of
//! the CA's K_ca item is reported by the ceremony on `issuer.register`
//! (`store_locator`): the `put` that returns it happens after the request and before
//! the approval (D4 item 1 step 6), so the ceremony sends the same registration again
//! after the put. ⟨§17.23 item 3, R3B-Q2 (a)⟩ That report must repeat the pending
//! registration's facts **exactly** (fingerprint, public key, store kind, backup digest
//! and time, rotation, key-only restore, expected locator) and only attaches the
//! locator, once (`Txn::attach_register_issuer_store_locator`, which checks the facts
//! again): the same locator again is an idempotent answer naming the decision; another
//! locator, or a report repeating no pending registration of an unregistered CA
//! (`CONFIG_CONFLICT` when one of that CA is pending with other facts,
//! `DECISION_STALE` when none is), refuses with nothing created or changed. The
//! approval records the locator with the CA (`Txn::set_issuer_store_locator`). A registration approved
//! without one records the CA without a locator: its retirement stops at `unloaded`
//! (`issuer_store_locator_unrecorded`).
//!
//! **A restore that wrote a new store item** for a CA whose record survives (D4 item
//! 4, log intact) is a re-registration of the known CA: `store_locator` (the new
//! item) and `expected_store_locator` (the locator it expects recorded; absent: none).
//! Its `RegisterIssuer` approval compares and swaps the recorded locator
//! (`Txn::replace_issuer_store_locator`); a mismatch, at the request or the approval,
//! refuses and changes nothing. The displaced item is listed in `issuer.status`'s
//! `orphan_store_items` (with its locator) until the CLI confirms its deletion. A
//! registration of an unknown CA (a log-lost restore included) expects no locator.
//!
//! **`retire`** (D4 item 3; §17.1 item 7) is refused, writing nothing, while any
//! enrollment of the CA is neither final nor `abandoned`; otherwise it creates (or
//! joins) a `RetireIssuer` decision listing the abandoned enrollments. Approval moves
//! the CA to `retiring` in the decide transaction (which refuses new reservations
//! for it, `ca_retiring`); after the commit [`Operations::resume_ca_retirements`]
//! asks the child to unload it (`retiring → unloaded`; the supervision pass resumes
//! it). ⟨§17.22 item 12, R2B-Q2; D3⟩ **Neither the runtime nor the child ever writes
//! or deletes the platform store.** An `unloaded` CA waits for the owner-present CLI:
//! `issuer.status` (and `retire` on that CA) names the recorded locator
//! (`CaStatus::store_locator`), the CLI deletes exactly that item, and confirms on an
//! attended `issuer.retire` with `deleted_locator` equal to it; only then does the
//! record move `unloaded → deleted → retired` (one transaction). The same
//! confirmation of a displaced item removes it from `orphan_store_items`. Any other
//! locator is refused, changing nothing.
//!
//! **`unlock`** (D4 item 2; §17.17 item 10, U4-Q2(b)) reloads the CA set through the
//! lifecycle. Heimdall never shows a store prompt: a locked store is reported
//! (`issuer_store_locked`, with how to unlock it), never unlocked.
//!
//! **`status`** is the child's last observed state (no I/O) with the store's CA
//! records filled in; **`bundle`** is `crate::issuer::bundle::export` over the store.

use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{CaFingerprint, EnrollmentId, OperationId};
use heimdall_contract::issuer::{
    CaState, CaStatus, IssuerRequest, IssuerState, IssuerStatus, OrphanStoreItem, StoreKind,
};
use heimdall_contract::managed::IssuerIsolation;
use heimdall_contract::request::Verdict;
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
use heimdall_domain::enrollment::EnrollmentRecord;
use heimdall_domain::issuance::CaEvent;
use heimdall_domain::operation::OperationRecord;
use heimdall_store::ext_m03::same_registration_facts;
use heimdall_store::{IssuerRecord, StoreError, Txn};

use super::{Emit, Operations, approval_needed, internal, plus};
use crate::context::Caller;
use crate::error::{Completed, OpError, OpResult};
use crate::issuer::bundle::{EnrollmentEntry, Redaction, StoreView, export_with_foreign};
use crate::issuer::{
    IssuerLifecycle, ca_public_key_fingerprint, enrollment_counts, is_sha256_hex,
    register_disclosures, retire_admissible, unlock_guidance,
};
use crate::ports::{IssuerError, IssuerPort, IssuerStatusSnapshot};
use crate::timegate::uncertain;

// -----------------------------------------------------------------------------
// Per-instance state
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Pure views and checks
// -----------------------------------------------------------------------------

fn owner_only() -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "issuer requests need the owner role",
    )
}

fn not_wired() -> OpError {
    OpError::driver_unavailable("the issuer is not available in this runtime")
}

fn stale(msg: &str) -> OpError {
    OpError::new(Code::DecisionStale, msg.to_owned())
}

fn unknown_ca(ca: &CaFingerprint) -> OpError {
    OpError::new(Code::NotFound, "no registered CA has that fingerprint")
        .with_resource("issuer", Some(ca.to_string()))
}

/// An issuer failure as the request's error (nonsecret reason only).
fn issuer_failure(e: &IssuerError) -> OpError {
    match e {
        IssuerError::Unavailable(why) => {
            let (code, why) = match why.as_str() {
                reason::ISSUER_RESTARTING => (Code::ServiceUnavailable, reason::ISSUER_RESTARTING),
                reason::ISSUER_STORE_LOCKED => {
                    (Code::CapabilityUnavailable, reason::ISSUER_STORE_LOCKED)
                }
                reason::ISSUER_STORE_UNAVAILABLE => (
                    Code::CapabilityUnavailable,
                    reason::ISSUER_STORE_UNAVAILABLE,
                ),
                reason::ISSUER_NOT_INITIALIZED => {
                    (Code::CapabilityUnavailable, reason::ISSUER_NOT_INITIALIZED)
                }
                _ => (Code::CapabilityUnavailable, reason::ISSUER_UNAVAILABLE),
            };
            let msg = unlock_guidance(why).unwrap_or("the issuer is not available");
            OpError::new(code, msg).with_reason(why)
        }
        IssuerError::Timeout => OpError::new(
            Code::ServiceUnavailable,
            "the issuer did not answer in time",
        )
        .with_reason(reason::ISSUER_UNAVAILABLE),
        IssuerError::Refused(_) | IssuerError::Protocol(_) => {
            OpError::new(Code::CapabilityUnavailable, "the issuer is not available")
                .with_reason(reason::ISSUER_UNAVAILABLE)
        }
    }
}

/// ⟨§17.22 item 12⟩ A CA's store items as this installation recorded them.
#[derive(Debug, Clone, Default)]
pub(crate) struct CaStoreItems {
    /// The recorded locator (`Txn::issuer_store_locator`).
    recorded: Option<String>,
    /// Items a restore displaced, awaiting the CLI's deletion confirmation.
    displaced: Vec<String>,
}

/// The `issuer.status` view: the child's last observed state (`snapshot`; `None`
/// without an issuer port) with the store's CA records, their recorded store items
/// and their enrollment counts. No CA registered is `not_initialized`, whatever the
/// child says. Orphan store items: ⟨§17.22 item 12⟩ every item a restore displaced
/// (with its locator) until its deletion is confirmed; items no registration names
/// at all are the CLI's to find (the runtime holds no store handle).
/// ⟨wave 5, U10B-Q3 (b)⟩ `bundle_stale`: [`bundle_stale`] over the recorded
/// `last_bundle_at` (absent: stale whenever an enrollment exists, the wave-4 reading).
pub(crate) fn status_view(
    snapshot: Option<&IssuerStatusSnapshot>,
    cas: &[(IssuerRecord, CaStoreItems)],
    enrollments: &[EnrollmentRecord],
    last_bundle_at: Option<Timestamp>,
) -> IssuerStatus {
    let (state, reason_text) = if cas.is_empty() {
        (
            IssuerState::NotInitialized,
            Some(reason::ISSUER_NOT_INITIALIZED.to_owned()),
        )
    } else {
        match snapshot {
            Some(s) => (s.status.state, s.status.reason.clone()),
            None => (
                IssuerState::Unavailable,
                Some(reason::ISSUER_UNAVAILABLE.to_owned()),
            ),
        }
    };
    IssuerStatus {
        state,
        reason: reason_text,
        cas: cas
            .iter()
            .map(|(c, items)| CaStatus {
                fingerprint: c.ca_fingerprint.clone(),
                state: c.state,
                store: c.store_kind,
                backup_sha256: c.backup_sha256.clone(),
                backup_created_at: c.backup_created_at,
                restored_without_log: c.restored_without_log,
                enrollments: enrollment_counts(&c.ca_fingerprint, enrollments),
                store_locator: items.recorded.clone(),
            })
            .collect(),
        orphan_store_items: cas
            .iter()
            .flat_map(|(c, items)| {
                items.displaced.iter().map(|l| OrphanStoreItem {
                    fingerprint: Some(c.ca_fingerprint.clone()),
                    store: c.store_kind,
                    locator: Some(l.clone()),
                })
            })
            .collect(),
        issuer_isolation: IssuerIsolation::SameUserProcess,
        bundle_stale: bundle_stale(cas, enrollments, last_bundle_at),
    }
}

/// ⟨wave 5, Q-IS2⟩ Whether a recovery bundle built at `last_bundle_at` predates an
/// enrollment or CA change: no enrollment, never stale; no recorded bundle, stale;
/// otherwise stale when any enrollment was updated, or any CA created or retired, at or
/// after it (an equal instant counts as after: the fail-closed side).
pub(crate) fn bundle_stale(
    cas: &[(IssuerRecord, CaStoreItems)],
    enrollments: &[EnrollmentRecord],
    last_bundle_at: Option<Timestamp>,
) -> bool {
    if enrollments.is_empty() {
        return false;
    }
    let Some(at) = last_bundle_at else {
        return true;
    };
    enrollments.iter().any(|e| e.updated_at >= at)
        || cas
            .iter()
            .any(|(c, _)| c.created_at >= at || c.retired_at.is_some_and(|r| r >= at))
}

/// ⟨ADR-0008 §17.25 item 8⟩ `issuer.bundle_written`'s record, in the caller's
/// transaction: the CLI wrote and fsynced an unredacted bundle built at `created_at` whose
/// exact bytes hash to `sha256`. Records the digest with its `created_at`
/// (`Txn::record_bundle_digest`) and raises `last_bundle_at` to `created_at`; neither ever
/// lowers. The path is never recorded. Refused, recording nothing: a digest that is not 64
/// lowercase hex characters, or a `created_at` later than `now` (the runtime built the
/// bundle with its own clock, so a later one is not a bundle it built).
///
/// Returns the recorded `last_bundle_at`.
pub(crate) fn record_bundle_written(
    tx: &mut Txn<'_>,
    created_at: Timestamp,
    sha256: &str,
    now: Timestamp,
) -> heimdall_store::Result<Result<Timestamp, OpError>> {
    if !is_sha256_hex(sha256) {
        return Ok(Err(OpError::new(
            Code::UsageError,
            "sha256 must be the lowercase hex SHA-256 of the written bundle's exact bytes",
        )));
    }
    if created_at > now {
        return Ok(Err(OpError::new(
            Code::UsageError,
            "created_at is later than this runtime's clock: it is not a bundle this runtime built",
        )));
    }
    tx.record_bundle_digest(sha256, created_at)?;
    Ok(Ok(tx.set_last_bundle_at(created_at)?))
}

/// Every registered CA with its recorded store items.
type CasWithItems = Vec<(IssuerRecord, CaStoreItems)>;

/// Every registered CA with its recorded store items, and every enrollment under one
/// of them, in one transaction.
fn read_cas_and_enrollments(
    tx: &mut Txn<'_>,
) -> heimdall_store::Result<(CasWithItems, Vec<EnrollmentRecord>)> {
    let cas = tx.issuers()?;
    let mut enrollments = Vec::new();
    let mut out = Vec::with_capacity(cas.len());
    for c in cas {
        enrollments.extend(tx.enrollments_for_ca(&c.ca_fingerprint)?);
        let items = CaStoreItems {
            recorded: tx.issuer_store_locator(&c.ca_fingerprint)?,
            displaced: tx.issuer_displaced_store_locators(&c.ca_fingerprint)?,
        };
        out.push((c, items));
    }
    Ok((out, enrollments))
}

/// ⟨§17.22 item 12⟩ A store locator as a request may carry it: 1 to 4096 bytes,
/// no control characters (the store's own rule).
fn locator_ok(locator: &str) -> bool {
    !locator.is_empty() && locator.len() <= 4096 && !locator.chars().any(char::is_control)
}

fn bad_locator() -> OpError {
    OpError::new(
        Code::UsageError,
        "a store locator is 1 to 4096 bytes without control characters",
    )
}

/// The decision a `register` creates or joins.
#[derive(Debug, Clone)]
struct RegisterAsk {
    fingerprint: CaFingerprint,
    public_key: String,
    store: StoreKind,
    backup_sha256: String,
    backup_created_at: Timestamp,
    rotation_of: Option<CaFingerprint>,
    restored_without_log: bool,
    store_locator: Option<String>,
    expected_store_locator: Option<String>,
}

impl RegisterAsk {
    /// The registration as a `RegisterIssuer` kind (its record, or the report a
    /// pending record is compared with), showing `disclosures`.
    fn kind(
        &self,
        disclosures: Vec<heimdall_contract::enrollment::DisclosureKind>,
    ) -> DecisionKind {
        DecisionKind::RegisterIssuer {
            ca_fingerprint: self.fingerprint.clone(),
            store: self.store,
            backup_sha256: self.backup_sha256.clone(),
            rotation_of: self.rotation_of.clone(),
            restored_without_log: self.restored_without_log,
            disclosures,
            ca_public_key: Some(self.public_key.clone()),
            backup_created_at: Some(self.backup_created_at),
            store_locator: self.store_locator.clone(),
            expected_store_locator: self.expected_store_locator.clone(),
        }
    }

    /// Whether `kind` is a `RegisterIssuer` for exactly this registration: every
    /// recorded fact equal ([`same_registration_facts`]), the public key and backup
    /// time included (§17.21 item 3: a record written before them is never joined, it
    /// could not be approved), and the restore's expected locator (§17.22 item 12).
    /// The reported `store_locator` is not part of the identity: a report joins the
    /// registration it completes (§17.23 item 3).
    fn same(&self, kind: &DecisionKind) -> bool {
        same_registration_facts(&self.kind(Vec::new()), kind)
    }

    fn facts(&self) -> RegFacts<'_> {
        RegFacts {
            fingerprint: &self.fingerprint,
            public_key: &self.public_key,
            store: self.store,
            backup_sha256: &self.backup_sha256,
            rotation_of: self.rotation_of.as_ref(),
            restored_without_log: self.restored_without_log,
            store_locator: self.store_locator.as_deref(),
            expected_store_locator: self.expected_store_locator.as_deref(),
        }
    }
}

/// The facts of a registration that [`register_admissible`] checks against the
/// store, from the request or from its `RegisterIssuer` record.
#[derive(Debug, Clone, Copy)]
struct RegFacts<'a> {
    fingerprint: &'a CaFingerprint,
    public_key: &'a str,
    store: StoreKind,
    backup_sha256: &'a str,
    rotation_of: Option<&'a CaFingerprint>,
    restored_without_log: bool,
    store_locator: Option<&'a str>,
    expected_store_locator: Option<&'a str>,
}

/// ⟨§17.21 item 3⟩ The registration facts a `RegisterIssuer` record must carry for
/// its approval: the public key (matching the recorded fingerprint) and the backup
/// time. A record without them (written before the fields) or whose key does not
/// match is stale: refused, not consumed.
fn recorded_registration(
    ca_fingerprint: &CaFingerprint,
    ca_public_key: Option<&String>,
    backup_created_at: Option<Timestamp>,
) -> Result<(String, Timestamp), OpError> {
    let (Some(public_key), Some(backup_created_at)) = (ca_public_key, backup_created_at) else {
        return Err(stale(
            "this registration decision was recorded without the CA's public key; run the registration again",
        ));
    };
    if ca_public_key_fingerprint(public_key).as_ref() != Some(ca_fingerprint) {
        return Err(stale("the registration does not match its decision"));
    }
    Ok((public_key.clone(), backup_created_at))
}

/// The state checks a registration needs now (request and approval alike).
///
/// * **A new CA**: not registered; a rotation's CA registered and `active`; no
///   expected store locator (nothing is recorded for an unknown CA, so a restore
///   without its log expects none).
/// * ⟨§17.22 item 12⟩ **A known CA** (a log-intact restore that wrote a new store
///   item): only with a reported `store_locator`, not a rotation nor a key-only
///   restore, the CA `active` or `pending` with the same public key, store kind and
///   backup digest, and the recorded locator equal to `expected_store_locator` (the
///   compare-and-swap; absent: none recorded) and different from the new one.
///
/// Every refusal is `CONFIG_CONFLICT` (`NOT_FOUND` for an unknown rotated CA).
fn register_admissible(
    tx: &mut Txn<'_>,
    f: &RegFacts<'_>,
) -> heimdall_store::Result<Result<(), OpError>> {
    let conflict = |msg: &str| {
        OpError::new(Code::ConfigConflict, msg.to_owned())
            .with_resource("issuer", Some(f.fingerprint.to_string()))
    };
    if let Some(record) = tx.issuer(f.fingerprint)? {
        let Some(new) = f.store_locator else {
            return Ok(Err(conflict(
                "a CA with that fingerprint is already registered; restore its store item with `heimdall issuer restore` instead",
            )));
        };
        if f.rotation_of.is_some() || f.restored_without_log {
            return Ok(Err(conflict(
                "a CA with that fingerprint is already registered: only its store item can be registered again",
            )));
        }
        if !matches!(record.state, CaState::Active | CaState::Pending) {
            return Ok(Err(conflict(
                "the CA's retirement has begun: its store item is fixed",
            )));
        }
        if record.public_key != f.public_key
            || record.store_kind != f.store
            || record.backup_sha256 != f.backup_sha256
        {
            return Ok(Err(conflict(
                "the registration does not match the registered CA (public key, store or backup)",
            )));
        }
        let recorded = tx.issuer_store_locator(f.fingerprint)?;
        if recorded.as_deref() != f.expected_store_locator {
            return Ok(Err(conflict(
                "the CA's recorded store item is not the expected one: nothing changed (read `heimdall issuer status`)",
            )));
        }
        if recorded.as_deref() == Some(new) {
            return Ok(Err(conflict(
                "that store item is already recorded for the CA: nothing to register",
            )));
        }
        return Ok(Ok(()));
    }
    if f.expected_store_locator.is_some() {
        return Ok(Err(conflict(
            "no store item is recorded for an unregistered CA: expected_store_locator must be absent",
        )));
    }
    if let Some(old) = f.rotation_of {
        match tx.issuer(old)? {
            Some(r) if r.state == CaState::Active => {}
            Some(_) => {
                return Ok(Err(OpError::new(
                    Code::ConfigConflict,
                    "the CA being rotated is not active",
                )
                .with_resource("issuer", Some(old.to_string()))));
            }
            None => return Ok(Err(unknown_ca(old))),
        }
    }
    Ok(Ok(()))
}

/// The state checks a retirement needs now: the CA is registered and `active` or
/// `pending`, and every enrollment under it is final or abandoned. `Ok(Ok(abandoned))`.
fn retire_check(
    tx: &mut Txn<'_>,
    ca: &CaFingerprint,
) -> heimdall_store::Result<Result<Vec<EnrollmentId>, OpError>> {
    let Some(record) = tx.issuer(ca)? else {
        return Ok(Err(unknown_ca(ca)));
    };
    if !matches!(record.state, CaState::Active | CaState::Pending) {
        return Ok(Err(OpError::new(
            Code::ConfigConflict,
            "the CA's retirement has already begun; it resumes on its own",
        )
        .with_resource("issuer", Some(ca.to_string()))));
    }
    let enrollments = tx.enrollments_for_ca(ca)?;
    Ok(retire_admissible(ca, &enrollments).map_err(|open| {
        OpError::new(
            Code::ConfigConflict,
            format!(
                "{} enrollment(s) under this CA are neither final nor abandoned: remove or abandon them first",
                open.len()
            ),
        )
        .with_resource("issuer", Some(ca.to_string()))
    }))
}

// -----------------------------------------------------------------------------
// The request handling
// -----------------------------------------------------------------------------

impl Operations {
    /// `Request::Issuer` (capability `issuer/1`; module docs).
    ///
    /// # Errors
    /// [`OpError`].
    pub async fn issuer_request(
        &self,
        caller: &Caller,
        req: IssuerRequest,
    ) -> OpResult<serde_json::Value> {
        if !caller.context.is_owner() {
            return Err(owner_only());
        }
        let wiring = self.managed_wiring().ok_or_else(not_wired)?;
        let issuer = wiring.issuer.clone().ok_or_else(not_wired)?;
        match req {
            IssuerRequest::Status => self.issuer_status(issuer.as_ref()).await,
            IssuerRequest::Bundle { redact_hostnames } => {
                self.issuer_bundle(redact_hostnames).await
            }
            IssuerRequest::Register {
                ca_public_key,
                store,
                backup_sha256,
                backup_created_at,
                rotation_of,
                restored_without_log,
                store_locator,
                expected_store_locator,
            } => {
                if wiring.issuer_lifecycle.is_none() {
                    return Err(not_wired());
                }
                let ask = Registration {
                    ca_public_key,
                    store,
                    backup_sha256,
                    backup_created_at,
                    rotation_of,
                    restored_without_log,
                    store_locator,
                    expected_store_locator,
                };
                self.issuer_register(caller, ask).await
            }
            IssuerRequest::Unlock => {
                let lifecycle = wiring.issuer_lifecycle.clone().ok_or_else(not_wired)?;
                self.issuer_unlock(caller, issuer.as_ref(), lifecycle.as_ref())
                    .await
            }
            IssuerRequest::Retire {
                ca_fingerprint,
                deleted_locator: None,
            } => {
                self.issuer_retire(caller, issuer.as_ref(), ca_fingerprint)
                    .await
            }
            IssuerRequest::Retire {
                ca_fingerprint,
                deleted_locator: Some(locator),
            } => {
                self.issuer_confirm_store_deletion(caller, issuer.as_ref(), ca_fingerprint, locator)
                    .await
            }
            // ⟨ADR-0008 §17.25 item 8⟩ The CLI wrote and fsynced an unredacted bundle.
            IssuerRequest::BundleWritten { created_at, sha256 } => {
                self.issuer_bundle_written(issuer.as_ref(), created_at, sha256)
                    .await
            }
            _ => Err(OpError::new(
                Code::UsageError,
                "this issuer action is not supported by this runtime",
            )),
        }
    }

    async fn issuer_status(&self, issuer: &dyn IssuerPort) -> OpResult<serde_json::Value> {
        let snapshot = issuer.status();
        let (cas, enrollments, last_bundle_at) = self
            .write(|tx, _| {
                let (cas, enrollments) = read_cas_and_enrollments(tx)?;
                Ok((cas, enrollments, tx.last_bundle_at()?))
            })
            .await?;
        let view = status_view(Some(&snapshot), &cas, &enrollments, last_bundle_at);
        let data = serde_json::to_value(view).map_err(|_| internal("issuer status"))?;
        Ok(Completed::ok(Code::Ok, data))
    }

    /// `issuer.bundle_written` ([`record_bundle_written`]), answered with the status
    /// after it (its `bundle_stale` now measured from this bundle).
    async fn issuer_bundle_written(
        &self,
        issuer: &dyn IssuerPort,
        created_at: Timestamp,
        sha256: String,
    ) -> OpResult<serde_json::Value> {
        let now = self.inner.config.clock.wall();
        self.write(move |tx, _| record_bundle_written(tx, created_at, &sha256, now))
            .await??;
        self.issuer_status(issuer).await
    }

    async fn issuer_bundle(&self, redact_hostnames: bool) -> OpResult<serde_json::Value> {
        let created_at = self.inner.config.clock.wall();
        let (cas, enrollments, aliases, foreign) = self
            .write(move |tx, _| {
                let (cas, enrollments) = read_cas_and_enrollments(tx)?;
                // ⟨ADR-0008 §17.27 item 1 (W5-R01)⟩ the foreign removals not yet final,
                // read in the same transaction (only their descriptors are exported).
                let foreign = tx.outstanding_obligations()?.foreign_removals;
                let cas: Vec<IssuerRecord> = cas.into_iter().map(|(c, _)| c).collect();
                let mut aliases = Vec::with_capacity(enrollments.len());
                for e in &enrollments {
                    // A destination no longer in the catalog keeps its ID as the label.
                    aliases.push(
                        tx.destination(&e.destination)?
                            .map_or_else(|| e.destination.as_str().to_owned(), |d| d.alias),
                    );
                }
                Ok((cas, enrollments, aliases, foreign))
            })
            .await?;
        let entries: Vec<EnrollmentEntry<'_>> = enrollments
            .iter()
            .zip(&aliases)
            .map(|(record, alias)| EnrollmentEntry { record, alias })
            .collect();
        let redact = if redact_hostnames {
            Redaction::Hostnames
        } else {
            Redaction::None
        };
        let bundle = export_with_foreign(
            &StoreView {
                created_at,
                cas: &cas,
                enrollments: &entries,
            },
            &foreign,
            redact,
        )
        .map_err(|_| internal("the recovery bundle names an unregistered CA"))?;
        let data = serde_json::to_value(bundle).map_err(|_| internal("recovery bundle"))?;
        Ok(Completed::ok(Code::Ok, data))
    }

    async fn issuer_register(
        &self,
        caller: &Caller,
        reg: Registration,
    ) -> OpResult<serde_json::Value> {
        let Some(fingerprint) = ca_public_key_fingerprint(&reg.ca_public_key) else {
            return Err(OpError::new(
                Code::UsageError,
                "ca_public_key must be one OpenSSH Ed25519 public key line without a comment",
            ));
        };
        if !is_sha256_hex(&reg.backup_sha256) {
            return Err(OpError::new(
                Code::UsageError,
                "backup_sha256 must be the hex SHA-256 of the prepared backup bytes",
            ));
        }
        if reg.rotation_of.is_some() && reg.restored_without_log {
            return Err(OpError::new(
                Code::UsageError,
                "a key-only restore is not a rotation",
            ));
        }
        if reg.rotation_of.as_ref() == Some(&fingerprint) {
            return Err(OpError::new(Code::UsageError, "a CA cannot rotate itself"));
        }
        if [&reg.store_locator, &reg.expected_store_locator]
            .into_iter()
            .flatten()
            .any(|l| !locator_ok(l))
        {
            return Err(bad_locator());
        }
        let ask = RegisterAsk {
            fingerprint,
            public_key: reg.ca_public_key,
            store: reg.store,
            backup_sha256: reg.backup_sha256,
            backup_created_at: reg.backup_created_at,
            rotation_of: reg.rotation_of,
            restored_without_log: reg.restored_without_log,
            store_locator: reg.store_locator,
            expected_store_locator: reg.expected_store_locator,
        };
        let gate = self.inner.timegate.in_txn();
        let decision_id = crate::ids::new_decision_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        let decided = self
            .write(move |tx, emit| {
                // A decision's lifetime is measured on accepted time only (G10).
                let now = match gate.check(tx)? {
                    Ok(s) => s.wall(),
                    Err(u) => return Ok(Err(uncertain(&u))),
                };
                if let Err(e) = register_admissible(tx, &ask.facts())? {
                    return Ok(Err(e));
                }
                let current = tx.authority_generation()?;
                let live: Vec<DecisionRecord> = tx
                    .pending_decisions()?
                    .into_iter()
                    .filter(|d| now < d.expires_at && d.generation == current)
                    .collect();
                if let Some(existing) = live.iter().find(|d| ask.same(&d.kind)) {
                    // ⟨§17.22 item 12; §17.23 item 3⟩ The ceremony's store-item report
                    // completes the registration it repeats exactly: it attaches the
                    // locator once; the same locator again is a no-op; another item for
                    // the same pending registration is refused.
                    let DecisionKind::RegisterIssuer { store_locator, .. } = &existing.kind else {
                        return Ok(Err(internal("a joined registration is not one")));
                    };
                    match (store_locator, &ask.store_locator) {
                        (_, None) => {}
                        (Some(have), Some(new)) if have == new => {}
                        (Some(_), Some(_)) => {
                            return Ok(Err(OpError::new(
                                Code::ConfigConflict,
                                "the pending registration already records another store item",
                            )
                            .with_resource("decision", Some(existing.id.to_string()))));
                        }
                        (None, Some(_)) => {
                            match tx
                                .attach_register_issuer_store_locator(&existing.id, &ask.kind(Vec::new()))
                            {
                                Ok(_) => {}
                                Err(StoreError::GenerationConflict(_)) => {
                                    return Ok(Err(stale(
                                        "the pending registration changed meanwhile; register again",
                                    )));
                                }
                                Err(e) => return Err(e),
                            }
                        }
                    }
                    return Ok(Ok(existing.id.clone()));
                }
                // ⟨§17.23 item 3, R3B-Q2 (a)⟩ A store-item report for an unregistered
                // CA only completes a pending registration it repeats exactly; it never
                // creates one. (A registered CA's report is a restore's re-registration,
                // checked by `register_admissible`.)
                if ask.store_locator.is_some() && tx.issuer(&ask.fingerprint)?.is_none() {
                    let pending_for_ca = live.iter().any(|d| {
                        matches!(&d.kind, DecisionKind::RegisterIssuer { ca_fingerprint, .. }
                            if *ca_fingerprint == ask.fingerprint)
                    });
                    let refusal = if pending_for_ca {
                        OpError::new(
                            Code::ConfigConflict,
                            "the store-item report does not repeat the pending registration exactly (public key, store, backup, rotation or restore): nothing changed",
                        )
                    } else {
                        stale(
                            "no pending registration of this CA to report the store item on: nothing changed; run the registration again",
                        )
                    };
                    return Ok(Err(
                        refusal.with_resource("issuer", Some(ask.fingerprint.to_string()))
                    ));
                }
                let acknowledged = tx.lock_disclosure_ack()?.is_some();
                let d = DecisionRecord {
                    id: decision_id,
                    kind: ask.kind(register_disclosures(ask.restored_without_log, acknowledged)),
                    generation: current,
                    created_at: now,
                    expires_at: plus(now, lifetime),
                    state: DecisionState::Pending,
                    decided_at: None,
                };
                tx.insert_decision(&d)?;
                emit.decision(tx, &d, None)?;
                Ok(Ok(d.id))
            })
            .await??;
        Err(approval_needed(
            caller.is_attended(),
            decided.as_str(),
            "registering a CA needs an attended owner decision (RegisterIssuer)",
        )
        .with_resource("decision", Some(decided.to_string())))
    }

    async fn issuer_unlock(
        &self,
        caller: &Caller,
        issuer: &dyn IssuerPort,
        lifecycle: &dyn IssuerLifecycle,
    ) -> OpResult<serde_json::Value> {
        if !caller.is_attended() {
            return Err(OpError::new(
                Code::InteractionRequired,
                "issuer unlock is completed only on an attended session",
            ));
        }
        let registered = self
            .write(|tx, _| {
                Ok(tx
                    .issuers()?
                    .iter()
                    .any(|c| matches!(c.state, CaState::Active | CaState::Pending)))
            })
            .await?;
        if !registered {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "no CA is registered: run `heimdall issuer init` first",
            )
            .with_reason(reason::ISSUER_NOT_INITIALIZED));
        }
        // §17.17 item 10 (U4-Q2(b)): a reload over the child, which never allows
        // interaction on a store read. A locked store is reported, never unlocked.
        match tokio::time::timeout(self.adapter_limit(), lifecycle.reload()).await {
            Ok(Ok(())) => self.issuer_status(issuer).await,
            Ok(Err(e)) => Err(issuer_failure(&e)),
            Err(_) => Err(issuer_failure(&IssuerError::Timeout)),
        }
    }

    async fn issuer_retire(
        &self,
        caller: &Caller,
        issuer: &dyn IssuerPort,
        ca: CaFingerprint,
    ) -> OpResult<serde_json::Value> {
        // ⟨§17.22 item 12⟩ A retirement waiting at `unloaded` for the owner-present
        // CLI's deletion: the answer is the status, which names the recorded store
        // item to delete (`CaStatus::store_locator`). Nothing is written.
        let id = ca.clone();
        let state = self
            .write(move |tx, _| Ok(tx.issuer(&id)?.map(|r| r.state)))
            .await?;
        if state == Some(CaState::Unloaded) {
            return self.issuer_status(issuer).await;
        }
        let gate = self.inner.timegate.in_txn();
        let decision_id = crate::ids::new_decision_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        let decided = self
            .write(move |tx, emit| {
                let now = match gate.check(tx)? {
                    Ok(s) => s.wall(),
                    Err(u) => return Ok(Err(uncertain(&u))),
                };
                let abandoned = match retire_check(tx, &ca)? {
                    Ok(a) => a,
                    Err(e) => return Ok(Err(e)),
                };
                let current = tx.authority_generation()?;
                if let Some(existing) = tx.pending_decisions()?.into_iter().find(|d| {
                    matches!(
                        &d.kind,
                        DecisionKind::RetireIssuer { ca_fingerprint, abandoned_enrollments }
                            if *ca_fingerprint == ca && *abandoned_enrollments == abandoned
                    ) && now < d.expires_at
                        && d.generation == current
                }) {
                    return Ok(Ok(existing.id));
                }
                let d = DecisionRecord {
                    id: decision_id,
                    kind: DecisionKind::RetireIssuer {
                        ca_fingerprint: ca.clone(),
                        abandoned_enrollments: abandoned,
                    },
                    generation: current,
                    created_at: now,
                    expires_at: plus(now, lifetime),
                    state: DecisionState::Pending,
                    decided_at: None,
                };
                tx.insert_decision(&d)?;
                emit.decision(tx, &d, None)?;
                Ok(Ok(d.id))
            })
            .await??;
        Err(approval_needed(
            caller.is_attended(),
            decided.as_str(),
            "retiring a CA needs an attended owner decision (RetireIssuer)",
        )
        .with_resource("decision", Some(decided.to_string())))
    }

    /// ⟨ADR-0008 §17.22 item 12; D3⟩ `issuer.retire` with `deleted_locator`: the
    /// owner-present CLI deleted exactly the store item `locator` of `ca` and a re-read
    /// found it absent (attended sessions only; the owner role is checked first).
    ///
    /// * `locator` is the CA's **recorded** locator: the CA must be `unloaded` (the
    ///   child confirmed it zeroized the key); the record moves `unloaded → deleted →
    ///   retired` in one transaction. Already `deleted` completes to `retired`;
    ///   already `retired` changes nothing (idempotent). Any other state is refused.
    /// * `locator` is one of the CA's **displaced** items (`orphan_store_items`): it
    ///   leaves the list, in any CA state.
    /// * Anything else (an unknown CA: `NOT_FOUND`; another locator; a CA without a
    ///   recorded locator) is refused `CONFIG_CONFLICT`, changing nothing.
    ///
    /// The answer is the issuer status after the change. The runtime deletes nothing
    /// and reads no platform store here: it records the owner's confirmation.
    async fn issuer_confirm_store_deletion(
        &self,
        caller: &Caller,
        issuer: &dyn IssuerPort,
        ca: CaFingerprint,
        locator: String,
    ) -> OpResult<serde_json::Value> {
        if !caller.is_attended() {
            return Err(OpError::new(
                Code::InteractionRequired,
                "a store item's deletion is confirmed only on an attended session",
            ));
        }
        if !locator_ok(&locator) {
            return Err(bad_locator());
        }
        let at = self.inner.config.clock.wall();
        self.write(move |tx, _| {
            let conflict = |msg: &str| {
                OpError::new(Code::ConfigConflict, msg.to_owned())
                    .with_resource("issuer", Some(ca.to_string()))
            };
            let Some(record) = tx.issuer(&ca)? else {
                return Ok(Err(unknown_ca(&ca)));
            };
            if tx.issuer_store_locator(&ca)?.as_deref() == Some(locator.as_str()) {
                let steps: &[(CaState, CaEvent)] = match record.state {
                    CaState::Unloaded => &[
                        (CaState::Unloaded, CaEvent::StoreItemDeleted),
                        (CaState::Deleted, CaEvent::RetirementRecorded),
                    ],
                    CaState::Deleted => &[(CaState::Deleted, CaEvent::RetirementRecorded)],
                    CaState::Retired => &[],
                    _ => {
                        return Ok(Err(conflict(
                            "the CA's store item is deleted only after the issuer unloaded it (state unloaded); nothing changed",
                        )));
                    }
                };
                // Read and written in this one transaction: the table admits both
                // steps from the state just read, so a refusal here is a store
                // fault, and the error rolls both back.
                for (from, event) in steps {
                    if tx.set_issuer_state(&ca, *from, *event, at)?.is_err() {
                        return Err(StoreError::GenerationConflict(format!(
                            "issuer {ca} refused {event:?}"
                        )));
                    }
                }
                return Ok(Ok(()));
            }
            if tx.resolve_displaced_store_locator(&ca, &locator)? {
                return Ok(Ok(()));
            }
            Ok(Err(conflict(
                "that locator is not this CA's store item awaiting deletion: nothing changed",
            )))
        })
        .await??;
        self.issuer_status(issuer).await
    }

    /// Supervisor pass (m03-plan U10 `issuer_supervision_pass`; ADR-0008 D3 item 7,
    /// D4 item 3): with a CA registered (`active` or `pending`) and a child never
    /// started (`not_initialized`), start it (a child that crashed is restarted by the
    /// client's own bounded backoff; one that was **stopped** is never restarted here,
    /// §17.19 item 3); then resume every CA retirement left in `retiring`, `unloaded`
    /// or `deleted` (each step only after its effect is confirmed). Existing grants
    /// keep signing whatever the issuer's state: nothing here degrades a grant (the
    /// re-issue pass does that, for a lost K_env, `credential_reissue_pending`).
    ///
    /// # Errors
    /// [`OpError`] (the store).
    pub async fn issuer_supervision_pass(&self) -> Result<(), OpError> {
        let Some(wiring) = self.managed_wiring() else {
            return Ok(());
        };
        let Some(issuer) = wiring.issuer.clone() else {
            return Ok(());
        };
        let cas = self.write(|tx, _| tx.issuers()).await?;
        let live = cas
            .iter()
            .any(|c| matches!(c.state, CaState::Active | CaState::Pending));
        if live
            && issuer.status().status.state == IssuerState::NotInitialized
            && let Some(lifecycle) = wiring.issuer_lifecycle.as_ref()
        {
            match tokio::time::timeout(self.adapter_limit(), lifecycle.start()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "the issuer child did not start"),
                Err(_) => tracing::warn!("the issuer child did not start in time"),
            }
        }
        if cas.iter().any(|c| {
            matches!(
                c.state,
                CaState::Retiring | CaState::Unloaded | CaState::Deleted
            )
        }) {
            let report = self.resume_ca_retirements(Some(issuer.as_ref())).await?;
            for (ca, state, why) in &report.stalled {
                tracing::debug!(ca = %ca, ?state, reason = %why, "a CA retirement waits");
            }
        }
        Ok(())
    }

    /// After an issuer decision committed (see `decisions_m03`): a registration's
    /// child start or reload, a retirement's steps. Never fails the decide request.
    pub(super) async fn issuer_after_decision(&self, record: &DecisionRecord, verdict: Verdict) {
        let wiring = self.managed_wiring();
        match (&record.kind, verdict) {
            (DecisionKind::RegisterIssuer { .. }, Verdict::Approve) => {
                let Some(lifecycle) = wiring.as_ref().and_then(|w| w.issuer_lifecycle.clone())
                else {
                    return;
                };
                // D4 item 1 step 7: "Then it starts the issuer child" (a reload starts
                // one when none runs, and loads a rotation's new CA into a running one).
                match tokio::time::timeout(self.adapter_limit(), lifecycle.reload()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "the issuer child did not load the new CA");
                    }
                    Err(_) => tracing::warn!("the issuer child did not load the new CA in time"),
                }
            }
            (DecisionKind::RetireIssuer { .. }, Verdict::Approve) => {
                let issuer = wiring.as_ref().and_then(|w| w.issuer.clone());
                if let Err(e) = self.resume_ca_retirements(issuer.as_deref()).await {
                    tracing::warn!(code = %e.code, "a CA retirement could not be resumed");
                }
            }
            _ => {}
        }
    }
}

/// An `issuer.register` request's fields.
struct Registration {
    ca_public_key: String,
    store: StoreKind,
    backup_sha256: String,
    backup_created_at: Timestamp,
    rotation_of: Option<CaFingerprint>,
    restored_without_log: bool,
    store_locator: Option<String>,
    expected_store_locator: Option<String>,
}

/// The [`RegFacts`] of a `RegisterIssuer` record whose public key `public_key` was
/// checked by [`recorded_registration`]; `None` for another kind.
fn record_facts<'a>(kind: &'a DecisionKind, public_key: &'a str) -> Option<RegFacts<'a>> {
    match kind {
        DecisionKind::RegisterIssuer {
            ca_fingerprint,
            store,
            backup_sha256,
            rotation_of,
            restored_without_log,
            store_locator,
            expected_store_locator,
            ..
        } => Some(RegFacts {
            fingerprint: ca_fingerprint,
            public_key,
            store: *store,
            backup_sha256,
            rotation_of: rotation_of.as_ref(),
            restored_without_log: *restored_without_log,
            store_locator: store_locator.as_deref(),
            expected_store_locator: expected_store_locator.as_deref(),
        }),
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// The decisions (inside `Operations::decide`'s transaction)
// -----------------------------------------------------------------------------

/// `decisions_m03::precheck` for `RegisterIssuer` and `RetireIssuer`: an approval
/// re-checks what the request checked against the current store (and, for a
/// registration, that its record carries the public key and backup time, §17.21
/// item 3); a refusal writes nothing,
/// so the record stays pending and is not consumed. A denial always proceeds. Neither
/// kind waits on an operation.
pub(super) fn decision_precheck(
    tx: &mut Txn<'_>,
    d: &DecisionRecord,
    verdict: Verdict,
    _now: Timestamp,
) -> heimdall_store::Result<Result<Option<OperationRecord>, OpError>> {
    if verdict != Verdict::Approve {
        return Ok(Ok(None));
    }
    match &d.kind {
        DecisionKind::RegisterIssuer {
            ca_fingerprint,
            ca_public_key,
            backup_created_at,
            ..
        } => {
            let (public_key, _) = match recorded_registration(
                ca_fingerprint,
                ca_public_key.as_ref(),
                *backup_created_at,
            ) {
                Ok(facts) => facts,
                Err(e) => return Ok(Err(e)),
            };
            let Some(facts) = record_facts(&d.kind, &public_key) else {
                return Ok(Err(internal("a registration record is not one")));
            };
            Ok(register_admissible(tx, &facts)?.map(|()| None))
        }
        DecisionKind::RetireIssuer {
            ca_fingerprint,
            abandoned_enrollments,
        } => Ok(match retire_check(tx, ca_fingerprint)? {
            Ok(abandoned) if abandoned == *abandoned_enrollments => Ok(None),
            Ok(_) => Err(stale(
                "the enrollments under the CA changed since the decision; retire again",
            )),
            Err(e) => Err(e),
        }),
        _ => Ok(Err(OpError::driver_unavailable(
            "this decision kind is not available in this build",
        ))),
    }
}

/// `decisions_m03::apply` for `RegisterIssuer` and `RetireIssuer` (module docs). A
/// denial changes nothing. An inner `Err` rolls the decide transaction back.
#[allow(clippy::too_many_arguments)]
pub(super) fn decision_apply(
    tx: &mut Txn<'_>,
    _emit: &mut Emit,
    record: &DecisionRecord,
    verdict: Verdict,
    _waiting: Option<OperationRecord>,
    now: Timestamp,
    _retention: std::time::Duration,
) -> heimdall_store::Result<Result<Vec<OperationId>, OpError>> {
    if verdict != Verdict::Approve {
        return Ok(Ok(Vec::new()));
    }
    match &record.kind {
        DecisionKind::RegisterIssuer {
            ca_fingerprint,
            store,
            backup_sha256,
            rotation_of,
            restored_without_log,
            disclosures,
            ca_public_key,
            backup_created_at,
            store_locator,
            expected_store_locator,
        } => {
            let (public_key, backup_created_at) = match recorded_registration(
                ca_fingerprint,
                ca_public_key.as_ref(),
                *backup_created_at,
            ) {
                Ok(facts) => facts,
                Err(e) => return Ok(Err(e)),
            };
            let Some(facts) = record_facts(&record.kind, &public_key) else {
                return Ok(Err(internal("a registration record is not one")));
            };
            if let Err(e) = register_admissible(tx, &facts)? {
                return Ok(Err(e));
            }
            // ⟨§17.22 item 12⟩ A known CA: the restore's compare-and-swap of its store
            // item (admitted above: a reported locator, the expected one recorded).
            if tx.issuer(ca_fingerprint)?.is_some() {
                let Some(new) = store_locator.as_deref() else {
                    return Ok(Err(internal("a re-registration without a store item")));
                };
                return match tx.replace_issuer_store_locator(
                    ca_fingerprint,
                    expected_store_locator.as_deref(),
                    new,
                ) {
                    Ok(()) => Ok(Ok(Vec::new())),
                    Err(StoreError::GenerationConflict(_)) => Ok(Err(stale(
                        "the CA's recorded store item changed since the decision",
                    ))),
                    Err(e) => Err(e),
                };
            }
            let issuer = IssuerRecord {
                ca_fingerprint: ca_fingerprint.clone(),
                public_key,
                // D4 item 3: a rotation's new CA starts `pending`.
                state: if rotation_of.is_some() {
                    CaState::Pending
                } else {
                    CaState::Active
                },
                store_kind: *store,
                backup_sha256: backup_sha256.clone(),
                backup_created_at,
                restored_without_log: *restored_without_log,
                created_at: now,
                retired_at: None,
            };
            match tx.insert_issuer(&issuer) {
                Ok(()) => {}
                Err(StoreError::GenerationConflict(_)) => {
                    return Ok(Err(stale(
                        "a CA with that fingerprint is already registered",
                    )));
                }
                Err(e) => return Err(e),
            }
            // ⟨§17.22 item 12⟩ The store item the ceremony reported, recorded with the
            // approval (none reported: the CA is recorded without one).
            if let Some(locator) = store_locator.as_deref() {
                match tx.set_issuer_store_locator(ca_fingerprint, locator) {
                    Ok(()) => {}
                    Err(StoreError::GenerationConflict(_)) => {
                        return Ok(Err(stale("the CA's store item changed since the decision")));
                    }
                    Err(e) => return Err(e),
                }
            }
            // D4 item 1 step 7: the native environment's `managed_signing` and
            // `issuer_access`, which moves the generation (ADR-0006 §13.7 item 5).
            let Some(env_id) = tx.self_environment()? else {
                return Ok(Err(internal("this installation has no environment")));
            };
            let Some(mut env) = tx.environment(&env_id)? else {
                return Ok(Err(internal("this installation's environment is unknown")));
            };
            if !(env.permissions.managed_signing && env.permissions.issuer_access) {
                env.permissions.managed_signing = true;
                env.permissions.issuer_access = true;
                tx.upsert_environment(&env)?;
            }
            if disclosures
                .contains(&heimdall_contract::enrollment::DisclosureKind::LockContinuityOnce)
            {
                tx.set_lock_disclosure_ack(now)?;
            }
            Ok(Ok(Vec::new()))
        }
        DecisionKind::RetireIssuer { ca_fingerprint, .. } => {
            let Some(current) = tx.issuer(ca_fingerprint)? else {
                return Ok(Err(unknown_ca(ca_fingerprint)));
            };
            match tx.set_issuer_state(ca_fingerprint, current.state, CaEvent::RetireApproved, now) {
                Ok(Ok(_)) => Ok(Ok(Vec::new())),
                Ok(Err(_)) | Err(StoreError::GenerationConflict(_)) => {
                    Ok(Err(stale("the CA's state changed since the decision")))
                }
                Err(e) => Err(e),
            }
        }
        _ => Ok(Ok(Vec::new())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod last_bundle_tests {
    //! ⟨wave 5, U10B-Q3 (b), Q-IS2⟩ The `last_bundle_at` refinement of `bundle_stale`.
    use std::sync::Arc;
    use std::time::Duration;

    use heimdall_store::{NoFaults, Store};

    use super::*;

    fn at(s: u64) -> Timestamp {
        "2026-11-01T00:00:00Z"
            .parse::<Timestamp>()
            .unwrap()
            .checked_add(Duration::from_secs(s))
            .unwrap()
    }

    fn ca(created: u64, retired: Option<u64>) -> (IssuerRecord, CaStoreItems) {
        (
            IssuerRecord {
                ca_fingerprint: CaFingerprint::parse(&format!("SHA256:{}", "A".repeat(43)))
                    .unwrap(),
                public_key: "ssh-ed25519 AAAA".into(),
                state: CaState::Active,
                store_kind: StoreKind::LinuxSecretService,
                backup_sha256: "ab".repeat(32),
                backup_created_at: at(created),
                restored_without_log: false,
                created_at: at(created),
                retired_at: retired.map(at),
            },
            CaStoreItems::default(),
        )
    }

    fn enrollment_updated_at(t: Timestamp) -> EnrollmentRecord {
        use heimdall_contract::ids::{AccountName, DestinationId, IdentityId};
        use heimdall_domain::enrollment::{
            ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentState, ExistingAccessRecord,
            NoProxy, RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
        };
        let id = EnrollmentId::from_random_bytes([1; 16]);
        let account = AccountName::parse("deploy").unwrap();
        EnrollmentRecord {
            marker: marker_for(&id),
            id,
            destination: DestinationId::parse("dst-lab").unwrap(),
            account: account.clone(),
            ca_fingerprint: ca(0, None).0.ca_fingerprint,
            form: EnrollmentForm::Account,
            registry: RegistryRef {
                path_display: "~/.ssh/authorized_keys".into(),
                resolved_by: RegistryResolvedBy::RemoteHome,
            },
            registry_canonical: RegistryCanonical {
                path: None,
                resolved_by: RegistryResolvedBy::RemoteHome,
            },
            line_sha256: "ab".repeat(32),
            target: ApprovedTarget {
                hostname: "example.invalid".into(),
                port: 22,
                user: account,
                proxy: NoProxy::None,
                host_key: ApprovedHostKey {
                    algorithm: "ssh-ed25519".into(),
                    key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                    fingerprint: "SHA256:hostfixture".into(),
                },
            },
            existing_access: ExistingAccessRecord {
                identity: IdentityId::from_random_bytes([1; 16]),
                endpoint: None,
                public_key_file: None,
            },
            hold: None,
            removal_origin: None,
            late_write: None,
            state: EnrollmentState::Verified,
            verified_at: None,
            evidence: None,
            created_at: t,
            updated_at: t,
        }
    }

    /// No enrollment: never stale. No recorded bundle: stale. A bundle after every
    /// change: fresh; an enrollment or CA change at or after it: stale.
    #[test]
    fn bundle_stale_follows_the_last_recorded_bundle() {
        let enrollment = enrollment_updated_at(at(10));
        let cas = [ca(0, None)];
        assert!(!bundle_stale(&cas, &[], None));
        assert!(bundle_stale(&cas, std::slice::from_ref(&enrollment), None));
        assert!(!bundle_stale(
            &cas,
            std::slice::from_ref(&enrollment),
            Some(at(11))
        ));
        assert!(bundle_stale(
            &cas,
            std::slice::from_ref(&enrollment),
            Some(at(10))
        ));
        assert!(bundle_stale(
            &cas,
            std::slice::from_ref(&enrollment),
            Some(at(9))
        ));
        let retired = [ca(0, Some(20))];
        assert!(bundle_stale(
            &retired,
            std::slice::from_ref(&enrollment),
            Some(at(15))
        ));
        assert!(!bundle_stale(
            &retired,
            std::slice::from_ref(&enrollment),
            Some(at(21))
        ));
    }

    /// The meta key never lowers; it is absent until recorded.
    #[test]
    fn last_bundle_at_is_recorded_once_and_never_lowers() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        store
            .transaction(|tx| {
                assert_eq!(tx.last_bundle_at()?, None);
                assert_eq!(tx.set_last_bundle_at(at(5))?, at(5));
                assert_eq!(tx.set_last_bundle_at(at(3))?, at(5));
                assert_eq!(tx.set_last_bundle_at(at(8))?, at(8));
                assert_eq!(tx.last_bundle_at()?, Some(at(8)));
                Ok(())
            })
            .unwrap();
    }

    /// ⟨ADR-0008 §17.25 item 8⟩ `issuer.bundle_written` records the digest and raises
    /// `last_bundle_at`, never lowering either; a malformed digest or a future
    /// `created_at` records nothing.
    #[test]
    fn bundle_written_records_digest_and_last_bundle_at_never_lowered() {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        let (d1, d2) = ("ab".repeat(32), "cd".repeat(32));
        store
            .transaction(|tx| {
                assert_eq!(
                    record_bundle_written(tx, at(10), &d1, at(20))?.unwrap(),
                    at(10)
                );
                assert_eq!(tx.last_bundle_at()?, Some(at(10)));
                assert_eq!(tx.bundle_digest_recorded_at(&d1)?, Some(at(10)));
                // An older bundle confirmed later: its digest is recorded, nothing lowers.
                assert_eq!(
                    record_bundle_written(tx, at(5), &d2, at(20))?.unwrap(),
                    at(10)
                );
                assert_eq!(tx.bundle_digest_recorded_at(&d2)?, Some(at(5)));
                assert_eq!(tx.last_bundle_at()?, Some(at(10)));
                assert_eq!(
                    record_bundle_written(tx, at(3), &d1, at(20))?.unwrap(),
                    at(10)
                );
                assert_eq!(tx.bundle_digest_recorded_at(&d1)?, Some(at(10)));
                // Refused, recording nothing.
                let upper = "AB".repeat(32);
                for (t, d) in [
                    (at(12), upper.as_str()),
                    (at(12), "ab"),
                    (at(21), d1.as_str()),
                ] {
                    let e = record_bundle_written(tx, t, d, at(20))?.unwrap_err();
                    assert_eq!(e.code, Code::UsageError);
                }
                assert_eq!(tx.last_bundle_at()?, Some(at(10)));
                assert_eq!(tx.bundle_digest_recorded_at(&"ef".repeat(32))?, None);
                Ok(())
            })
            .unwrap();
    }
}
