//! ⟨M03⟩ The managed capability report (ADR-0008 D12; m03-plan §5 items 7–9; ADR-0005
//! §7.2): the `EnsureData` additions, the `Enforcement` additions and the
//! `RevokeData` additions of a managed grant.
//!
//! **Three kinds of value (D12 item 3).**
//! * *Runtime evidence*: `destination_scope: verified_server_principals` for a pair
//!   with its own fresh verification (the enrollment's evidence), labelled with its
//!   time and versions; `identity_selection: client_configuration_and_signer` only when
//!   the static selection is `exclusive` (D10 item 6).
//! * *The claim table* (`heimdall_domain::claims`), the only source of platform
//!   mechanism claims: `lock_continuity: verified`, `new_signing_expiry: signer`,
//!   `owned_multiplexing: closed_at_deadline`, `existing_connections`,
//!   `new_authentication_expiry: credential_and_signer`, the summary
//!   `enforcement.revocation` and `revocation.remote` (gated the same way, F11).
//! * *Limitations and the binding's own configuration*, always reported, claiming
//!   nothing: `owned_multiplexing: disabled`, `remote_processes: not_terminated`,
//!   `unmanaged_connections: not_controlled`, `workload_isolation: shared_os_user`,
//!   `issuer_isolation: same_user_process`, and the computed residual facts.
//!
//! **Per-field rule (D12 item 2):** a value whose test has not passed for this
//! platform reads `unknown` (`not_verified` for `lock_continuity`). The claims handed
//! to [`compute`] are the applicable ones (the adapter's `read_sources` selects them
//! for the running platform); [`claimed`] still checks field, value and platform.

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{AccountName, DestinationId};
use heimdall_contract::managed::{
    ClockMeasurement, ConnectionPolicy, ConnectionPolicyReport, DestinationClock, EvidenceEntry,
    EvidenceSource, ExistingConnectionsMode, IdentitySelectionEnforcement, IssuerIsolation,
    LocalRevocation, LockBehavior, LockContinuityReport, MultiplexingMode, NewSigningExpiry,
    OwnedConnectionReport, OwnedConnectionReportState, OwnedMultiplexing, ReadinessCondition,
    RefreshCondition, RefreshTrigger, RemoteEffectReport, RemoteProcesses, RemoteRevocation,
    ResidualStatus, RevocationSemantics, RevokeNote, UnmanagedConnections,
};
use heimdall_contract::provider::CredentialAvailability;
use heimdall_contract::request::{
    AccessPairRef, DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy,
    NewAuthenticationExpiry, RefreshDependency, RevocationStatus, WorkloadIsolation,
};
use heimdall_domain::claims::{Claim, Platform};
use heimdall_domain::enrollment::EnrollmentEvidence;
use heimdall_domain::grant::GrantSnapshot;
use heimdall_domain::issuance::{IssuanceEntry, IssuanceState};
use heimdall_domain::managed::{OwnedConnection, OwnedConnectionState};
use heimdall_domain::scope::AccessPair;

/// The running platform's claim-table row (`Platform::os`: `macos`, `linux`,
/// `windows`; `arch`: `aarch64`, `x86_64`, as `std::env::consts` names them).
#[must_use]
pub fn current_platform() -> Platform {
    Platform {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
    }
}

/// Whether `claims` hold an entry for `field` = `value` on `platform`.
#[must_use]
pub fn claimed(claims: &[Claim], platform: &Platform, field: &str, value: &str) -> bool {
    claims
        .iter()
        .any(|c| c.field == field && c.value == value && c.platform == *platform)
}

/// The claim-table entry for `field` = `value` on `platform`, if any.
#[must_use]
pub fn claim<'a>(
    claims: &'a [Claim],
    platform: &Platform,
    field: &str,
    value: &str,
) -> Option<&'a Claim> {
    claims
        .iter()
        .find(|c| c.field == field && c.value == value && c.platform == *platform)
}

// --- revoke additions (§5 item 9; F15) ------------------------------------------------

/// The cascade's owned connections as a revoke reports them (F15): a row still `up`
/// is `closing` (the revoke's cleanup closes it after the gates are released), a
/// closing one `closing`, a closed one `closed`, and an unverified one `unverified`
/// (never signalled).
#[must_use]
pub fn owned_connection_reports(rows: &[OwnedConnection]) -> Vec<OwnedConnectionReport> {
    rows.iter()
        .map(|c| OwnedConnectionReport {
            id: c.id.clone(),
            kind: c.kind,
            state: match c.state {
                OwnedConnectionState::Closed => OwnedConnectionReportState::Closed,
                OwnedConnectionState::Unverified => OwnedConnectionReportState::Unverified,
                // `Up`, `Closing`, and any later state: being closed.
                _ => OwnedConnectionReportState::Closing,
            },
        })
        .collect()
}

/// The fixed notes of a managed revoke: always `[ordinary_connections_not_closed]`
/// (D7 item 2 step 6; F15).
#[must_use]
pub fn revoke_notes() -> Vec<RevokeNote> {
    vec![RevokeNote::OrdinaryConnectionsNotClosed]
}

/// `enforcement.owned_multiplexing` (ADR-0008 D8 item 3, D12): `disabled` while the
/// policy disables masters (the binding's own configuration, reported from the start,
/// on every platform: the §5 item 8 golden is a Windows result); `owned_masters` on
/// Windows is `unavailable` (no masters there); elsewhere `closed_at_deadline` only
/// with its claim-table entry for `platform`, otherwise `unknown`.
#[must_use]
pub fn owned_multiplexing(
    policy: &ConnectionPolicy,
    platform: Platform,
    claims: &[Claim],
) -> OwnedMultiplexing {
    match policy.multiplexing {
        MultiplexingMode::Disabled => OwnedMultiplexing::Disabled,
        _ if platform.os == "windows" => OwnedMultiplexing::Unavailable,
        _ if claimed(
            claims,
            &platform,
            FIELD_OWNED_MULTIPLEXING,
            "closed_at_deadline",
        ) =>
        {
            OwnedMultiplexing::ClosedAtDeadline
        }
        _ => OwnedMultiplexing::Unknown,
    }
}

// --- claim-table field names (D12 item 3) ---------------------------------------------

/// `lock_continuity`.
pub const FIELD_LOCK_CONTINUITY: &str = "lock_continuity";
/// `enforcement.new_signing_expiry`.
pub const FIELD_NEW_SIGNING_EXPIRY: &str = "new_signing_expiry";
/// `enforcement.owned_multiplexing`.
pub const FIELD_OWNED_MULTIPLEXING: &str = "owned_multiplexing";
/// `enforcement.existing_connections`.
pub const FIELD_EXISTING_CONNECTIONS: &str = "existing_connections";
/// `enforcement.new_authentication_expiry`.
pub const FIELD_NEW_AUTHENTICATION_EXPIRY: &str = "new_authentication_expiry";
/// The summary `enforcement.revocation`.
pub const FIELD_REVOCATION: &str = "enforcement.revocation";
/// `revocation.remote`.
pub const FIELD_REVOCATION_REMOTE: &str = "revocation.remote";

// --- residuals (D7 items 2–3; §17.1 item 10) ------------------------------------------

/// The destination-clock drift allowance of D7 item 3: 100 ppm of the time since the
/// measurement.
pub const DRIFT_PPM: u64 = 100;

/// The completion allowance of one measurement at `now` (D7 item 3; §17.20 item
/// 10): `behind_upper + rtt + 100 ppm × (now − measured_at)`, in milliseconds. `None`
/// on overflow (no allowance is claimed).
#[must_use]
pub fn completion_allowance_ms(clock: &ClockMeasurement, now: Timestamp) -> Option<u64> {
    // A measurement "in the future" (a negative span) adds no drift.
    let elapsed_ms = u64::try_from(now.duration_since(clock.measured_at).as_millis()).unwrap_or(0);
    let drift_ms = elapsed_ms.checked_mul(DRIFT_PPM)? / 1_000_000;
    clock
        .behind_upper_ms
        .checked_add(clock.rtt_ms)?
        .checked_add(drift_ms)
}

/// The completion bound of a measured residual (D7 item 3):
/// `latest_valid_before + behind_upper + rtt + 100 ppm × (now − measured_at)`.
/// `None` on overflow (no bound is claimed).
#[must_use]
pub fn completion_bound(
    latest_valid_before: Timestamp,
    clock: &ClockMeasurement,
    now: Timestamp,
) -> Option<Timestamp> {
    let total = completion_allowance_ms(clock, now)?;
    latest_valid_before
        .checked_add(std::time::Duration::from_millis(total))
        .ok()
}

/// The status of one residual (D7 item 3). `bound_at` is the time the completion
/// bound's drift allowance runs to (a later value only widens the bound); `safe_now`
/// is the wall time the time gate accepted, and only it moves a status: `None` (time
/// not safe, or a caller that cannot vouch for its time) moves nothing, the residual
/// stays `pending_until`.
///
/// | measured | before the bound | after (on safe time) |
/// |---|---|---|
/// | yes | `pending_until` (until = the bound) | `bounded_complete` |
/// | no | `pending_until` (until absent) before `latest_valid_before` | `nominally_expired`, never cleared |
#[must_use]
pub fn residual_status(
    latest_valid_before: Timestamp,
    clock: &DestinationClock,
    bound_at: Timestamp,
    safe_now: Option<Timestamp>,
    unbounded: bool,
) -> (ResidualStatus, Option<Timestamp>) {
    if unbounded {
        return (ResidualStatus::UnboundedUnknown, None);
    }
    match clock {
        DestinationClock::Measured(m) => {
            let at = safe_now.map_or(bound_at, |n| n.max(bound_at));
            let bound = completion_bound(latest_valid_before, m, at);
            match (safe_now, bound) {
                (Some(now), Some(b)) if now >= b => (ResidualStatus::BoundedComplete, Some(b)),
                (_, b) => (ResidualStatus::PendingUntil, b),
            }
        }
        _ => match safe_now {
            Some(now) if now >= latest_valid_before => (ResidualStatus::NominallyExpired, None),
            _ => (ResidualStatus::PendingUntil, None),
        },
    }
}

/// `latest_possible_credential_expiry` (D7 item 2 step 5): the maximum `valid_before`
/// over every `reserved` or `published` entry, delivered or not; `voided` entries are
/// excluded (ADR-0005 §3.5).
#[must_use]
pub fn latest_possible_credential_expiry(entries: &[IssuanceEntry]) -> Option<Timestamp> {
    entries
        .iter()
        .filter(|e| counts(e))
        .map(|e| e.bounds.valid_before)
        .max()
}

fn counts(e: &IssuanceEntry) -> bool {
    matches!(e.state, IssuanceState::Reserved | IssuanceState::Published)
}

/// One pair's clock measurement for the residual: the enrollment's, or `unmeasured`.
pub type PairClock<'a> = (&'a AccessPair, Option<ClockMeasurement>);

/// `remote_effects` (D7 item 2 step 5): one row per (destination, account) with an
/// entry that counts (a residual already `nominally_expired` or `bounded_complete` is
/// still listed: it is never shown as cleared), with the pair's
/// `latest_valid_before`, its clock (`clocks`; absent = `unmeasured`) and the status
/// of D7 item 3 ([`residual_status`] at `bound_at` / `safe_now`). `unbounded` (a
/// key-only restore) makes every row `unbounded_unknown`.
#[must_use]
pub fn remote_effects(
    entries: &[IssuanceEntry],
    clocks: &[PairClock<'_>],
    bound_at: Timestamp,
    safe_now: Option<Timestamp>,
    unbounded: bool,
) -> Vec<RemoteEffectReport> {
    let mut latest: std::collections::BTreeMap<(DestinationId, AccountName), Timestamp> =
        std::collections::BTreeMap::new();
    for e in entries.iter().filter(|e| counts(e)) {
        let k = (e.pair.destination.clone(), e.pair.account.clone());
        let v = latest.entry(k).or_insert(e.bounds.valid_before);
        if e.bounds.valid_before > *v {
            *v = e.bounds.valid_before;
        }
    }
    latest
        .into_iter()
        .map(|((destination, account), lvb)| {
            let clock = clocks
                .iter()
                .find(|(p, _)| p.destination == destination && p.account == account)
                .and_then(|(_, c)| *c)
                .map_or(DestinationClock::Unmeasured, DestinationClock::Measured);
            let (status, until) = residual_status(lvb, &clock, bound_at, safe_now, unbounded);
            RemoteEffectReport {
                destination,
                account,
                latest_valid_before: lvb,
                destination_clock: clock,
                status,
                until,
            }
        })
        .collect()
}

// --- CA removal (ADR-0008 §17.3 item 3, Q20; reading R7) --------------------------------

/// The grants whose certificate is under `removed` (§17.3 item 3, Q20): every grant
/// with a `reserved` or `published` entry signed (or to be signed) by that CA. Removing
/// the CA degrades **each** of them (`pair_unenrolled`), whatever else the pair has;
/// the removal preview names the same set. A `voided` entry names no certificate.
#[must_use]
pub fn grants_under_ca(
    removed: &heimdall_contract::ids::CaFingerprint,
    entries: &[IssuanceEntry],
) -> std::collections::BTreeSet<heimdall_contract::ids::GrantId> {
    entries
        .iter()
        .filter(|e| counts(e) && e.bounds.ca_fingerprint.as_ref() == Some(removed))
        .map(|e| e.grant.clone())
        .collect()
}

/// The pair's preference after a CA's removal (§17.3 item 3): `managed_certificate`
/// while another verified CA remains for the pair, `existing` once none does. It
/// governs only the preference, never which grants degrade ([`grants_under_ca`]).
#[must_use]
pub fn preference_after_removal(
    remaining_verified: &std::collections::BTreeSet<heimdall_contract::ids::CaFingerprint>,
) -> heimdall_contract::managed::PreferredMechanism {
    if remaining_verified.is_empty() {
        heimdall_contract::managed::PreferredMechanism::Existing
    } else {
        heimdall_contract::managed::PreferredMechanism::ManagedCertificate
    }
}

// --- the ensure report (§5 items 7–8; D6 item 6, D12) ---------------------------------

/// The static identity selection of a managed alias as `compute` needs it (D10 item 6).
/// The classification for managed aliases is U0b phase 2's (wave 4): until it lands
/// every pair is [`SelectionClass::Undetermined`] and `identity_selection` reads
/// `unknown` (fail closed; [`MANAGED_SELECTION_CLASSIFIED`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionClass {
    /// Only the slot certificate (in the selected form).
    Exclusive,
    /// Inherited entries are offered too.
    NotExclusive,
    /// Not determined.
    Undetermined,
}

/// ⟨U6-Q3⟩ Whether a managed alias's static selection is classified (D10 item 6;
/// U0b phase 2, wave 4, files not U6's). `false`: callers pass `Undetermined`.
pub const MANAGED_SELECTION_CLASSIFIED: bool = false;

/// Platform facts [`compute`] reports conditions from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportContext {
    /// The running platform.
    pub platform: Platform,
    /// The grant's lock behaviour (its origin's).
    pub lock_behavior: LockBehavior,
    /// The effective connection policy.
    pub policy: ConnectionPolicy,
    /// `issuer.status` was `ready` at activation (D6 item 6).
    pub issuer_ready: bool,
    /// A credential instance is `lost`, or a re-issue is pending (D6 item 6).
    pub reissue_pending: bool,
    /// The observation time (`usable_until` while re-issue is pending).
    pub now: Timestamp,
    /// The pairs' selection, `Undetermined` by default.
    pub selection: SelectionClass,
}

/// One pair's verification evidence: the pair and its enrollment's evidence.
pub type PairEvidence<'a> = (&'a AccessPair, &'a EnrollmentEvidence);

/// The managed report: what `EnsureData` and `Enforcement` gain for a managed grant
/// (§5 items 7–8). The runtime copies it into the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedReport {
    /// `usable_until`.
    pub usable_until: Timestamp,
    /// `offline_until`.
    pub offline_until: Timestamp,
    /// `refresh_dependency` (`local_issuer`).
    pub refresh_dependency: RefreshDependency,
    /// `refresh_condition`.
    pub refresh_condition: RefreshCondition,
    /// `conditions`.
    pub conditions: Vec<ReadinessCondition>,
    /// `credential_availability`.
    pub availability: CredentialAvailability,
    /// `lock_continuity`.
    pub lock_continuity: LockContinuityReport,
    /// The claim table holds `lock_continuity: verified` for this platform (whatever
    /// the grant's lock behaviour; D6 item 7's first condition).
    pub lock_claim_verified: bool,
    /// `enforcement`.
    pub enforcement: Enforcement,
    /// `revocation`.
    pub revocation: RevocationSemantics,
    /// `evidence`.
    pub evidence: Vec<EvidenceEntry>,
    /// `connection_policy`.
    pub connection_policy: ConnectionPolicyReport,
}

/// ⟨§17.20 item 9⟩ D8 item 3's disclosure, added to the wording when owned masters
/// are applied: sessions through Heimdall's master end at the deadline under every
/// policy (ADR-0008 D8 item 3, quoted).
pub const OWNED_MASTERS_DISCLOSURE: &str =
    "Sessions shared through a Heimdall connection end at the deadline.";

/// The contract's identity selection of a [`SelectionClass`].
#[must_use]
pub fn identity_selection(
    selection: SelectionClass,
) -> heimdall_contract::provider::IdentitySelection {
    use heimdall_contract::provider::IdentitySelection;
    match selection {
        SelectionClass::Exclusive => IdentitySelection::Exclusive,
        SelectionClass::NotExclusive => IdentitySelection::NotExclusive,
        SelectionClass::Undetermined => IdentitySelection::Undetermined,
    }
}

/// Whether owned masters are applied for `policy` on `platform` (D8 item 3: never on
/// Windows, where `owned_masters` is unavailable).
#[must_use]
pub fn owned_masters_applied(policy: &ConnectionPolicy, platform: &Platform) -> bool {
    policy.multiplexing == MultiplexingMode::OwnedMasters && platform.os != "windows"
}

/// The deadline wording of a managed grant (ADR-0008 D8 items 3 and 6; §17.20 item
/// 9): U8's `heimdall_localenv::projection::plan::deadline_wording` for the identity
/// selection and the effective `existing` mode (no retyped text; `undetermined` gets
/// D8 item 6's qualified wording), followed by [`OWNED_MASTERS_DISCLOSURE`] when owned
/// masters are applied.
#[must_use]
pub fn connection_wording(
    selection: SelectionClass,
    policy: &ConnectionPolicy,
    platform: &Platform,
) -> String {
    let base = heimdall_localenv::projection::plan::deadline_wording(
        identity_selection(selection),
        policy.existing,
    );
    if owned_masters_applied(policy, platform) {
        format!("{base} {OWNED_MASTERS_DISCLOSURE}")
    } else {
        base.to_owned()
    }
}

/// The weakest clock of `clocks` at the observation time `now` (§5 item 7: "per pair
/// the weakest is shown"; §17.20 item 10): `unmeasured` if any pair is unmeasured,
/// else the measurement with the largest completion allowance at `now`
/// ([`completion_allowance_ms`]: `behind_upper + rtt + drift × age`). A measurement
/// whose allowance overflows is the weakest.
#[must_use]
pub fn weakest_clock(clocks: &[Option<ClockMeasurement>], now: Timestamp) -> DestinationClock {
    if clocks.is_empty() || clocks.iter().any(Option::is_none) {
        return DestinationClock::Unmeasured;
    }
    clocks
        .iter()
        .flatten()
        // `None` (overflow) maps to `u64::MAX`: the largest allowance.
        .max_by_key(|m| completion_allowance_ms(m, now).unwrap_or(u64::MAX))
        .copied()
        .map_or(DestinationClock::Unmeasured, DestinationClock::Measured)
}

/// The managed report of `grant` (D6 item 6, D12; §5 items 7–8).
///
/// * `usable_until = offline_until = min(D, cutoff, parent deadline, the shortest
///   prepared certificate's valid_before)` (§17.20 item 8: coverage never exceeds the
///   shortest certificate) with the issuer `ready` at activation: `through_deadline`
///   when that is the deadline, `refresh_dependent` when a certificate ends earlier;
///   while re-issue is pending, `refresh_dependent` and `usable_until = now`.
/// * `destination_scope: verified_server_principals` only when **every** pair has its
///   own fresh evidence (`fresh_until > now`), else `unknown`; one evidence entry per
///   pair that has it.
/// * claim-gated fields read `unknown` (or `not_verified`) without their entries.
/// * `revocation.latest_possible_credential_expiry` is the maximum `valid_before` of
///   the prepared certificates; `destination_clock` the weakest pair's.
#[must_use]
pub fn compute(
    grant: &GrantSnapshot,
    prepared: &heimdall_app::ports::ManagedPrepared,
    claims: &[Claim],
    ctx: &ReportContext,
    evidence: &[PairEvidence<'_>],
) -> ManagedReport {
    let platform = ctx.platform;
    let has = |field: &str, value: &str| claimed(claims, &platform, field, value);
    let deadline = grant.deadline.effective;
    let covered = prepared
        .certificates
        .iter()
        .map(|c| c.valid_before)
        .min()
        .map_or(deadline, |shortest| shortest.min(deadline));
    let usable = !ctx.reissue_pending && ctx.issuer_ready;
    let (usable_until, availability) = if usable && covered == deadline {
        (deadline, CredentialAvailability::ThroughDeadline)
    } else if usable {
        (covered, CredentialAvailability::RefreshDependent)
    } else {
        (
            ctx.now.min(covered),
            CredentialAvailability::RefreshDependent,
        )
    };

    let mut conditions = vec![
        ReadinessCondition::SignerRunning,
        ReadinessCondition::TimeConfirmationAfterReboot,
    ];
    if platform.os == "macos" {
        conditions.push(ReadinessCondition::IssuerStoreUnlockedAtStart);
    }

    let lock_continuity = if ctx.lock_behavior == LockBehavior::RevokeOnLock {
        LockContinuityReport::LockRevokes
    } else if has(FIELD_LOCK_CONTINUITY, "verified") {
        LockContinuityReport::Verified
    } else {
        LockContinuityReport::NotVerified
    };

    // Runtime evidence: every pair verified and fresh.
    let pairs: Vec<&AccessPair> = grant.scope.pairs.iter().collect();
    let fresh = |p: &AccessPair| {
        evidence
            .iter()
            .find(|(q, _)| *q == p)
            .filter(|(_, e)| e.fresh_until > ctx.now)
            .map(|(_, e)| *e)
    };
    let all_verified = !pairs.is_empty() && pairs.iter().all(|p| fresh(p).is_some());
    let destination_scope = if all_verified {
        DestinationScopeEnforcement::VerifiedServerPrincipals
    } else {
        DestinationScopeEnforcement::Unknown
    };
    let mut entries = Vec::new();
    for p in &pairs {
        if let Some(e) = fresh(p) {
            entries.push(EvidenceEntry {
                field: "destination_scope".into(),
                source: EvidenceSource::RuntimeVerification,
                pair: Some(AccessPairRef {
                    destination: p.destination.clone(),
                    account: p.account.clone(),
                }),
                record: None,
                operation_id: Some(e.operation.clone()),
                client: Some(e.client.clone()),
                server: Some(e.server.clone()),
                observed_at: e.verified_at,
                fresh_until: Some(e.fresh_until),
            });
        }
    }
    for (field, value) in [
        (FIELD_LOCK_CONTINUITY, "verified"),
        (FIELD_NEW_SIGNING_EXPIRY, "signer"),
        (FIELD_OWNED_MULTIPLEXING, "closed_at_deadline"),
        (FIELD_NEW_AUTHENTICATION_EXPIRY, "credential_and_signer"),
        (FIELD_REVOCATION, "bounded_by_credential_expiry"),
        (FIELD_REVOCATION_REMOTE, "bounded_by_credential_expiry"),
    ] {
        if let Some(c) = claim(claims, &platform, field, value) {
            entries.push(EvidenceEntry {
                field: field.to_owned(),
                source: EvidenceSource::ClaimTable,
                pair: None,
                record: Some(c.record.to_owned()),
                operation_id: None,
                client: None,
                server: None,
                observed_at: ctx.now,
                fresh_until: None,
            });
        }
    }

    let existing_connections = match ctx.policy.existing {
        ExistingConnectionsMode::Strict if has(FIELD_EXISTING_CONNECTIONS, "strict_disconnect") => {
            ExistingConnectionsPolicy::StrictDisconnect
        }
        ExistingConnectionsMode::Graceful
            if has(FIELD_EXISTING_CONNECTIONS, "graceful_dedicated_connections") =>
        {
            ExistingConnectionsPolicy::GracefulDedicatedConnections
        }
        _ => ExistingConnectionsPolicy::Unknown,
    };
    let enforcement = Enforcement {
        destination_scope,
        new_authentication_expiry: if has(FIELD_NEW_AUTHENTICATION_EXPIRY, "credential_and_signer")
        {
            NewAuthenticationExpiry::CredentialAndSigner
        } else {
            NewAuthenticationExpiry::Unknown
        },
        workload_isolation: WorkloadIsolation::SharedOsUser,
        existing_connections,
        revocation: if has(FIELD_REVOCATION, "bounded_by_credential_expiry") {
            RevocationStatus::BoundedByCredentialExpiry
        } else {
            RevocationStatus::Unknown
        },
        identity_selection: Some(match ctx.selection {
            SelectionClass::Exclusive => IdentitySelectionEnforcement::ClientConfigurationAndSigner,
            _ => IdentitySelectionEnforcement::Unknown,
        }),
        new_signing_expiry: Some(if has(FIELD_NEW_SIGNING_EXPIRY, "signer") {
            NewSigningExpiry::Signer
        } else {
            NewSigningExpiry::Unknown
        }),
        owned_multiplexing: Some(owned_multiplexing(&ctx.policy, platform, claims)),
        remote_processes: Some(RemoteProcesses::NotTerminated),
        unmanaged_connections: Some(UnmanagedConnections::NotControlled),
        issuer_isolation: Some(IssuerIsolation::SameUserProcess),
    };

    let clocks: Vec<Option<ClockMeasurement>> = pairs
        .iter()
        .map(|p| {
            evidence
                .iter()
                .find(|(q, _)| q == p)
                .and_then(|(_, e)| e.clock)
        })
        .collect();
    let revocation = RevocationSemantics {
        local: LocalRevocation::Immediate,
        remote: if has(FIELD_REVOCATION_REMOTE, "bounded_by_credential_expiry") {
            RemoteRevocation::BoundedByCredentialExpiry
        } else {
            RemoteRevocation::Unknown
        },
        latest_possible_credential_expiry: prepared
            .certificates
            .iter()
            .map(|c| c.valid_before)
            .max(),
        destination_clock: weakest_clock(&clocks, ctx.now),
    };

    ManagedReport {
        usable_until,
        offline_until: usable_until,
        refresh_dependency: RefreshDependency::LocalIssuer,
        refresh_condition: RefreshCondition {
            needed_only_after: RefreshTrigger::SignerRestart,
            source: RefreshDependency::LocalIssuer,
        },
        conditions,
        availability,
        lock_continuity,
        lock_claim_verified: has(FIELD_LOCK_CONTINUITY, "verified"),
        enforcement,
        revocation,
        evidence: entries,
        connection_policy: ConnectionPolicyReport {
            existing: ctx.policy.existing,
            multiplexing: ctx.policy.multiplexing,
            wording: connection_wording(ctx.selection, &ctx.policy, &platform),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn notes_and_multiplexing() {
        assert_eq!(
            revoke_notes(),
            vec![RevokeNote::OrdinaryConnectionsNotClosed]
        );
        let mac = Platform {
            os: "macos",
            arch: "aarch64",
        };
        let win = Platform {
            os: "windows",
            arch: "x86_64",
        };
        let masters = ConnectionPolicy {
            existing: ExistingConnectionsMode::Graceful,
            multiplexing: MultiplexingMode::OwnedMasters,
        };
        assert_eq!(
            owned_multiplexing(&ConnectionPolicy::default(), mac, &[]),
            OwnedMultiplexing::Disabled
        );
        assert_eq!(
            owned_multiplexing(&masters, mac, &[]),
            OwnedMultiplexing::Unknown
        );
        assert_eq!(
            owned_multiplexing(&ConnectionPolicy::default(), win, &[]),
            OwnedMultiplexing::Disabled
        );
        assert_eq!(
            owned_multiplexing(&masters, win, &[]),
            OwnedMultiplexing::Unavailable
        );
    }

    #[test]
    fn completion_bound_matches_d7_item_3() {
        let m = ClockMeasurement {
            behind_upper_ms: 1400,
            rtt_ms: 38,
            measured_at: t("2026-11-10T00:00:00Z"),
        };
        // 10 000 s after the measurement: 100 ppm = 1 000 ms of drift.
        let now = t("2026-11-10T02:46:40Z");
        let lvb = t("2026-11-10T01:00:00Z");
        assert_eq!(
            completion_bound(lvb, &m, now),
            Some(t("2026-11-10T01:00:02.438Z"))
        );
    }
}
