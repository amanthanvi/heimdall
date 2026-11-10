//! ⟨M03⟩ U0b rows 2 and 3 (ADR-0008 D4 item 3, D6 item 1; m03-plan §5 item 16): the
//! CA inputs of the issuance predicate, and the CA the reserve transaction selects.
//!
//! **Which path.** A request is on the **M03 path** when it names a CA
//! ([`Operations::reserve_issuance_naming_ca`]) or when the grant's recorded
//! mechanism (`GrantOrigin.mechanism`) is `managed_certificate`. Every other request
//! is on the **M01 path**: no CA is selected, the bounds name none, and the predicate
//! gets no CA inputs (`IssuanceCheck.enrolled_cas = None`), so M01 behaviour and M01
//! issuance-log entries are unchanged. An entry whose bounds name a CA is always
//! checked on the M03 path (at publish too).
//!
//! **Selection** (D4 item 3), inside the reserve transaction: the newest `active` CA
//! (latest registration) that has a `verified` enrollment for the pair. A request
//! that names a CA other than the selected one is refused `UnknownCa`; a request that
//! names a CA while none is selectable keeps that CA in its bounds, so the predicate
//! names the specific refusal (`UnknownCa` for an unregistered CA, `CaRetiring`,
//! `CaNotVerifiedForPair`). Publish re-reads the CA facts, so an enrollment removed
//! or a CA retired in between voids the entry.

use heimdall_contract::ids::{CaFingerprint, GrantId};
use heimdall_contract::issuer::CaState;
use heimdall_domain::issuance::{CertificateBounds, EnrolledCas, IssuanceEntry, IssuanceRefusal};
use heimdall_domain::scope::AccessPair;
use heimdall_store::Txn;

use super::{IssuanceRequest, Operations};
use crate::error::OpError;

/// The credential mechanism name of managed certificates (ADR-0008; the
/// `credential_mechanism` the managed adapter reports).
pub const MANAGED_CERTIFICATE: &str = "managed_certificate";

/// Whether `grant`'s recorded mechanism is `managed_certificate`.
pub(super) fn grant_is_managed(tx: &mut Txn<'_>, grant: &GrantId) -> heimdall_store::Result<bool> {
    Ok(tx
        .grant_origin(grant)?
        .is_some_and(|o| o.mechanism == MANAGED_CERTIFICATE))
}

/// The CAs with a `verified` enrollment for `pair`, with their registered state,
/// newest registration first (ties by fingerprint, descending). A CA without an
/// `issuers` row (impossible under the foreign key) is skipped.
fn verified_newest_first(
    tx: &mut Txn<'_>,
    pair: &AccessPair,
) -> heimdall_store::Result<Vec<(CaFingerprint, CaState)>> {
    let mut found = Vec::new();
    for ca in tx.verified_cas_for_pair(pair)? {
        if let Some(issuer) = tx.issuer(&ca)? {
            found.push((issuer.created_at, ca, issuer.state));
        }
    }
    found.sort_by(|a, b| (b.0, &b.1).cmp(&(a.0, &a.1)));
    Ok(found
        .into_iter()
        .map(|(_, ca, state)| (ca, state))
        .collect())
}

/// The CA facts of one issuance check (owned, so the predicate's input can borrow
/// them).
pub(super) struct CaFacts {
    verified_for_pair: Vec<CaFingerprint>,
    ca_state: Option<CaState>,
}

impl CaFacts {
    /// The predicate's input.
    pub(super) fn input(&self) -> EnrolledCas<'_> {
        EnrolledCas {
            verified_for_pair: &self.verified_for_pair,
            ca_state: self.ca_state,
        }
    }
}

/// The CA facts for checking `bounds` of `grant` for `pair` in this transaction:
/// `None` on the M01 path (module docs).
pub(super) fn ca_facts(
    tx: &mut Txn<'_>,
    grant: &GrantId,
    pair: &AccessPair,
    bounds: &CertificateBounds,
) -> heimdall_store::Result<Option<CaFacts>> {
    if bounds.ca_fingerprint.is_none() && !grant_is_managed(tx, grant)? {
        return Ok(None);
    }
    let verified_for_pair = verified_newest_first(tx, pair)?
        .into_iter()
        .map(|(ca, _)| ca)
        .collect();
    let ca_state = match &bounds.ca_fingerprint {
        Some(ca) => tx.issuer(ca)?.map(|i| i.state),
        None => None,
    };
    Ok(Some(CaFacts {
        verified_for_pair,
        ca_state,
    }))
}

/// The CA the reserve transaction puts in the bounds (module docs): `Ok(None)` on
/// the M01 path, or on the M03 path when nothing is selectable and nothing is named
/// (the predicate then refuses `UnknownCa`); `Err(UnknownCa)` for a request naming
/// another CA than the selected one.
pub(super) fn select_ca(
    tx: &mut Txn<'_>,
    grant: &GrantId,
    pair: &AccessPair,
    named: Option<&CaFingerprint>,
) -> heimdall_store::Result<Result<Option<CaFingerprint>, IssuanceRefusal>> {
    if named.is_none() && !grant_is_managed(tx, grant)? {
        return Ok(Ok(None));
    }
    let selected = verified_newest_first(tx, pair)?
        .into_iter()
        .find(|(_, state)| *state == CaState::Active)
        .map(|(ca, _)| ca);
    Ok(match (named, selected) {
        (Some(n), Some(s)) if *n == s => Ok(Some(s)),
        (Some(_), Some(_)) => Err(IssuanceRefusal::UnknownCa),
        (Some(n), None) => Ok(Some(n.clone())),
        (None, s) => Ok(s),
    })
}

/// The caller's error for an issuance refusal: `OpError::from_issuance_refusal`, plus
/// the M03 sub-reason of the CA refusals (`ca_retiring`; `pair_not_enrolled` for a CA
/// without a verified enrollment for the pair). Every M01 refusal maps exactly as
/// before.
pub(super) fn refusal_error(refusal: &IssuanceRefusal) -> OpError {
    use heimdall_contract::envelope::reason;
    let e = OpError::from_issuance_refusal(refusal);
    match refusal {
        IssuanceRefusal::CaRetiring => e.with_reason(reason::CA_RETIRING),
        IssuanceRefusal::CaNotVerifiedForPair => e.with_reason(reason::PAIR_NOT_ENROLLED),
        _ => e,
    }
}

impl Operations {
    /// ⟨M03⟩ U0b row 3: [`Operations::reserve_issuance`] for a request that names the
    /// CA it expects to sign with. The reserve transaction still selects the CA
    /// itself (module docs); a request naming another CA is refused
    /// `CAPABILITY_UNAVAILABLE` (`UnknownCa`) with nothing reserved.
    ///
    /// # Errors
    /// As [`Operations::reserve_issuance`].
    pub async fn reserve_issuance_naming_ca(
        &self,
        req: IssuanceRequest,
        ca: CaFingerprint,
    ) -> Result<IssuanceEntry, OpError> {
        self.reserve_issuance_with(req, Some(ca)).await
    }
}
