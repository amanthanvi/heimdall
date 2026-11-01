//! Interaction states, provider states and the readiness table (m02-plan U6;
//! ADR-0007 §7; M2-D05, M2-R04, M2-R05).
//!
//! **One rule.** [`interaction_profile`], [`pair_eligibility`] and
//! [`fallback_clearance`] delegate to the pure domain rules
//! (`heimdall_domain::catalog::{eligibility, fallback_clearance}`), so the runtime,
//! the adapters and the CLI apply one rule. A declaration counts only when it is
//! `live`, its endpoint equals the current endpoint, and `expires_at > now`. A native
//! key with no counting declaration is `unknown` (inferred), never `none` (M2-D05).
//! `prepare` narrows the clearance further, never widens it
//! (`crate::integration::strict_clearance`: a managed entry that is not the adopted
//! key is an alternative; escalated for the domain rule).
//!
//! **Provider states** ([`status_from_listing`]): only the explicit `agent` level
//! observes `available` or `locked`. An empty listing, or an agent that refuses to
//! list, is reported `locked` with basis `inferred`: a native `ssh-agent` locked with
//! `ssh-add -x` lists nothing (ADR-0007 §7 `[I]`, settled for OpenSSH's agent by
//! `integration_adapters::a11_locked_native_agent_lists_nothing`), and an unlocked
//! agent holding no key answers the same.
//!
//! **Results and codes** ([`readiness`]): ADR-0007 §7's table, in its row order.

use heimdall_app::OpError;
use heimdall_app::ports::{AdapterError, IdentityListing, InteractionRequirement, LockContinuity};
use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{NextAction, reason};
use heimdall_contract::ids::IdentityId;
use heimdall_contract::provider::{
    CredentialAvailability, EndpointRef, EvidenceBasis, IdentitySelection, IdentitySelectionReport,
    InteractionKind, NoninteractiveEligibility, ProbeLevel, ProviderAvailability,
    ProviderInteractionRef, ProviderKind, ProviderStatus, noninteractive_reason,
};
use heimdall_domain::catalog::{
    FallbackClearance, IdentityRecord, InteractionDeclaration, PairEligibility,
};

/// The `resource.kind` of provider results (m02-plan §5 item 15).
pub const PROVIDER_RESOURCE: &str = "provider";

/// What passive detection observed of an identity's endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointObservation {
    /// The endpoint as currently configured.
    pub endpoint: EndpointRef,
    /// Whether the socket or pipe exists.
    pub present: bool,
    /// When.
    pub observed_at: Timestamp,
}

/// The identity's interaction and its basis (ADR-0007 §7's table, declaration lapse
/// included): `heimdall_domain::catalog::eligibility` at the observed endpoint.
#[must_use]
pub fn interaction_profile(
    identity: &IdentityRecord,
    declaration: Option<&InteractionDeclaration>,
    endpoint: &EndpointObservation,
    now: Timestamp,
) -> (InteractionKind, EvidenceBasis) {
    let e = pair_eligibility(identity, declaration, &endpoint.endpoint, now);
    (e.interaction, e.basis)
}

/// The identity's full fresh eligibility at `endpoint`:
/// `heimdall_domain::catalog::eligibility`, unchanged.
#[must_use]
pub fn pair_eligibility(
    identity: &IdentityRecord,
    declaration: Option<&InteractionDeclaration>,
    endpoint: &EndpointRef,
    now: Timestamp,
) -> PairEligibility {
    heimdall_domain::catalog::eligibility(identity, declaration, endpoint, now)
}

/// Whether every fallback identity of a non-exclusive selection is cleared
/// (ADR-0007 §7 clearance rule).
#[must_use]
pub fn fallback_clearance(
    report: &IdentitySelectionReport,
    identities: &[IdentityRecord],
    eligibility: &dyn Fn(&IdentityId) -> PairEligibility,
    endpoint: &EndpointRef,
) -> FallbackClearance {
    heimdall_domain::catalog::fallback_clearance(report, identities, eligibility, endpoint)
}

/// A provider's documented interaction (ADR-0007 §7 table): 1Password asks for
/// approval (documented, F17); anything else is `unknown` (inferred) until a
/// declaration or a key type says otherwise.
#[must_use]
pub fn documented_interaction(provider: ProviderKind) -> (InteractionKind, EvidenceBasis) {
    match provider {
        ProviderKind::OnePassword => (InteractionKind::ProviderApproval, EvidenceBasis::Documented),
        _ => (InteractionKind::Unknown, EvidenceBasis::Inferred),
    }
}

/// The provider's status after an explicit `agent` probe (ADR-0007 §7 "Provider
/// states"): a non-empty listing is `available` (observed); an empty listing or a
/// refusal to list is `locked` with interaction `provider_unlock` (inferred, see the
/// module documentation); an absent or unreachable endpoint is `unavailable`
/// (observed); anything else is `unknown`.
#[must_use]
pub fn status_from_listing(
    provider: ProviderKind,
    listing: &Result<IdentityListing, AdapterError>,
    now: Timestamp,
) -> ProviderStatus {
    let (documented, _) = documented_interaction(provider);
    let (availability, interaction, basis) = match listing {
        Ok(l) if !l.identities.is_empty() => (
            ProviderAvailability::Available,
            documented,
            EvidenceBasis::Observed,
        ),
        Ok(_) | Err(AdapterError::ProviderLocked) => (
            ProviderAvailability::Locked,
            InteractionKind::ProviderUnlock,
            EvidenceBasis::Inferred,
        ),
        Err(AdapterError::Unavailable(_)) => (
            ProviderAvailability::Unavailable,
            documented,
            EvidenceBasis::Observed,
        ),
        Err(_) => (
            ProviderAvailability::Unknown,
            documented,
            EvidenceBasis::Inferred,
        ),
    };
    ProviderStatus {
        provider,
        availability,
        interaction,
        observed_level: ProbeLevel::Agent,
        observed_at: now,
        basis,
    }
}

/// Whether `required.unattended` is met (m02-plan U6 "Minimum handling"): only with
/// verified lock continuity **and** every pair's interaction `none`. No M02 adapter
/// has verified lock continuity, so this is never true in M02. No pair is no claim.
#[must_use]
pub fn unattended_met(
    lock_continuity: LockContinuity,
    interactions: impl IntoIterator<Item = InteractionKind>,
) -> bool {
    let mut any = false;
    let all_none = interactions.into_iter().all(|i| {
        any = true;
        i == InteractionKind::None
    });
    lock_continuity == LockContinuity::Verified && any && all_none
}

/// One pair as readiness judges it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairReadiness {
    /// The identity's fresh eligibility.
    pub eligibility: PairEligibility,
    /// The recorded static selection verdict.
    pub selection: IdentitySelection,
    /// The fallback clearance, when one was evaluated (not for `exclusive`).
    pub clearance: Option<FallbackClearance>,
}

impl PairReadiness {
    /// Non-interactive eligibility with the fallback rule applied (ADR-0007 §7
    /// "Fallback identities on the no-interaction path"): an eligible identity whose
    /// selection is not `exclusive` stays eligible only when every alternative is
    /// cleared; a missing clearance clears nothing.
    #[must_use]
    pub fn noninteractive(&self) -> NoninteractiveEligibility {
        if !self.eligibility.noninteractive.eligible {
            return self.eligibility.noninteractive.clone();
        }
        let cleared = self.selection == IdentitySelection::Exclusive
            || self.clearance.as_ref().is_some_and(|c| c.cleared);
        if cleared {
            NoninteractiveEligibility {
                eligible: true,
                reason: None,
            }
        } else {
            NoninteractiveEligibility {
                eligible: false,
                reason: Some(noninteractive_reason::FALLBACK_IDENTITY_INTERACTION.to_owned()),
            }
        }
    }
}

/// Why readiness refused (ADR-0007 §7 "Results and codes").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No usable endpoint: `SERVICE_UNAVAILABLE`, `resource.kind = "provider"`.
    EndpointAbsent {
        /// The provider.
        provider: ProviderKind,
    },
    /// `required.unattended` is not met: `CAPABILITY_UNAVAILABLE`.
    UnattendedUnavailable {
        /// The provider.
        provider: ProviderKind,
    },
    /// A probe observed `locked`: `PROVIDER_LOCKED`, next `interact`.
    ProviderLocked {
        /// The provider.
        provider: ProviderKind,
    },
    /// A human step may be needed on the no-interaction path:
    /// `INTERACTION_REQUIRED`, next `interact` with the provider interaction, never
    /// a `decision_ref` (spec §5.5).
    InteractionRequired {
        /// The provider.
        provider: ProviderKind,
        /// The interaction that may be needed.
        kind: InteractionKind,
        /// `provider_interaction`, `interaction_unknown` or
        /// `fallback_identity_interaction`.
        reason: &'static str,
    },
}

fn provider_name(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::NativeAgent => "native_agent",
        ProviderKind::OnePassword => "onepassword",
        _ => "unknown",
    }
}

fn interact(code: Code, provider: ProviderKind, kind: InteractionKind) -> NextAction {
    NextAction {
        provider_interaction: Some(ProviderInteractionRef { provider, kind }),
        ..NextAction::for_code(code)
    }
}

impl Refusal {
    /// The result code.
    #[must_use]
    pub fn code(&self) -> Code {
        match self {
            Refusal::EndpointAbsent { .. } => Code::ServiceUnavailable,
            Refusal::UnattendedUnavailable { .. } => Code::CapabilityUnavailable,
            Refusal::ProviderLocked { .. } => Code::ProviderLocked,
            Refusal::InteractionRequired { .. } => Code::InteractionRequired,
        }
    }

    /// The full result: code, `resource.kind = "provider"`, reason and next action.
    #[must_use]
    pub fn op_error(&self) -> OpError {
        let code = self.code();
        match self {
            Refusal::EndpointAbsent { provider } => OpError::new(
                code,
                "the credential provider's agent endpoint is absent",
            )
            .with_reason(reason::ENDPOINT_ABSENT)
            .with_resource(PROVIDER_RESOURCE, Some(provider_name(*provider).to_owned())),
            Refusal::UnattendedUnavailable { provider } => OpError::new(
                code,
                "existing access cannot guarantee unattended use; managed unattended access arrives in M03",
            )
            .with_resource(PROVIDER_RESOURCE, Some(provider_name(*provider).to_owned())),
            Refusal::ProviderLocked { provider } => {
                OpError::new(code, "the credential provider is locked")
                    .with_resource(PROVIDER_RESOURCE, Some(provider_name(*provider).to_owned()))
                    .with_next(interact(
                        Code::ProviderLocked,
                        *provider,
                        InteractionKind::ProviderUnlock,
                    ))
            }
            Refusal::InteractionRequired {
                provider,
                kind,
                reason,
            } => OpError::new(
                code,
                "the credential provider may need a human step this request does not permit",
            )
            .with_reason(reason)
            .with_resource(PROVIDER_RESOURCE, Some(provider_name(*provider).to_owned()))
            .with_next(interact(Code::InteractionRequired, *provider, *kind)),
        }
    }

    /// The adapter-port form (`prepare`'s answer).
    #[must_use]
    pub fn adapter_error(&self) -> AdapterError {
        match self {
            Refusal::EndpointAbsent { .. } => {
                AdapterError::Unavailable("agent endpoint absent".to_owned())
            }
            Refusal::UnattendedUnavailable { .. } => AdapterError::CapabilityUnavailable,
            Refusal::ProviderLocked { .. } => AdapterError::ProviderLocked,
            Refusal::InteractionRequired { kind, .. } => {
                AdapterError::InteractionRequired(if *kind == InteractionKind::HardwarePresence {
                    InteractionRequirement::HardwarePresence
                } else {
                    InteractionRequirement::ProviderDialog
                })
            }
        }
    }
}

fn static_reason(r: Option<&str>) -> &'static str {
    match r {
        Some(noninteractive_reason::PROVIDER_INTERACTION) => reason::PROVIDER_INTERACTION,
        Some(noninteractive_reason::FALLBACK_IDENTITY_INTERACTION) => {
            reason::FALLBACK_IDENTITY_INTERACTION
        }
        // `interaction_unknown`, and any reason a newer domain adds: the narrowing
        // reading.
        _ => reason::INTERACTION_UNKNOWN,
    }
}

/// ADR-0007 §7 "Results and codes", in row order:
///
/// 1. no usable endpoint: `SERVICE_UNAVAILABLE`;
/// 2. `required.unattended` not met ([`unattended_met`]): `CAPABILITY_UNAVAILABLE`;
/// 3. a probe observed `locked`: `PROVIDER_LOCKED`;
/// 4. not interactive and any pair needs or may need interaction, an uncleared
///    fallback included ([`PairReadiness::noninteractive`]), or no pair at all (then
///    the provider's documented interaction): `INTERACTION_REQUIRED`;
/// 5. otherwise ready, with `credential_availability` `current_only` when every pair
///    is `none` (declared), else `interaction_required` (`unknown` without pairs).
///
/// # Errors
/// The [`Refusal`] of the first row that applies.
pub fn readiness(
    status: &ProviderStatus,
    pairs: &[PairReadiness],
    interactive: bool,
    required_unattended: bool,
    lock_continuity: LockContinuity,
) -> Result<CredentialAvailability, Refusal> {
    let provider = status.provider;
    if status.availability == ProviderAvailability::Unavailable {
        return Err(Refusal::EndpointAbsent { provider });
    }
    if required_unattended
        && !unattended_met(
            lock_continuity,
            pairs.iter().map(|p| p.eligibility.interaction),
        )
    {
        return Err(Refusal::UnattendedUnavailable { provider });
    }
    if status.availability == ProviderAvailability::Locked {
        return Err(Refusal::ProviderLocked { provider });
    }
    if !interactive {
        if pairs.is_empty() {
            let (kind, _) = documented_interaction(provider);
            return Err(Refusal::InteractionRequired {
                provider,
                kind,
                reason: if kind == InteractionKind::Unknown {
                    reason::INTERACTION_UNKNOWN
                } else {
                    reason::PROVIDER_INTERACTION
                },
            });
        }
        for pair in pairs {
            let n = pair.noninteractive();
            if !n.eligible {
                return Err(Refusal::InteractionRequired {
                    provider,
                    kind: pair.eligibility.interaction,
                    reason: static_reason(n.reason.as_deref()),
                });
            }
        }
    }
    Ok(if pairs.is_empty() {
        CredentialAvailability::Unknown
    } else if pairs
        .iter()
        .all(|p| p.eligibility.interaction == InteractionKind::None)
    {
        CredentialAvailability::CurrentOnly
    } else {
        CredentialAvailability::InteractionRequired
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::provider::EndpointKind;

    fn status(provider: ProviderKind, availability: ProviderAvailability) -> ProviderStatus {
        ProviderStatus {
            provider,
            availability,
            interaction: InteractionKind::Unknown,
            observed_level: ProbeLevel::Static,
            observed_at: Timestamp::UNIX_EPOCH,
            basis: EvidenceBasis::Inferred,
        }
    }

    fn pair(interaction: InteractionKind, selection: IdentitySelection) -> PairReadiness {
        let eligible = interaction == InteractionKind::None;
        PairReadiness {
            eligibility: PairEligibility {
                interaction,
                basis: EvidenceBasis::Inferred,
                declaration: None,
                noninteractive: NoninteractiveEligibility {
                    eligible,
                    reason: (!eligible)
                        .then(|| noninteractive_reason::INTERACTION_UNKNOWN.to_owned()),
                },
            },
            selection,
            clearance: None,
        }
    }

    #[test]
    fn unattended_is_never_met_without_verified_continuity() {
        for lock in [LockContinuity::Unknown, LockContinuity::StopsOnLock] {
            assert!(!unattended_met(lock, [InteractionKind::None]));
        }
        assert!(unattended_met(
            LockContinuity::Verified,
            [InteractionKind::None]
        ));
        assert!(!unattended_met(LockContinuity::Verified, []));
        assert!(!unattended_met(
            LockContinuity::Verified,
            [InteractionKind::None, InteractionKind::Unknown]
        ));
    }

    #[test]
    fn table_rows_apply_in_order() {
        let p = ProviderKind::NativeAgent;
        let none = [pair(InteractionKind::None, IdentitySelection::Exclusive)];
        let gone = status(p, ProviderAvailability::Unavailable);
        assert_eq!(
            readiness(&gone, &none, false, true, LockContinuity::Unknown).map_err(|r| r.code()),
            Err(Code::ServiceUnavailable)
        );
        let up = status(p, ProviderAvailability::Unknown);
        assert_eq!(
            readiness(&up, &none, true, true, LockContinuity::Unknown).map_err(|r| r.code()),
            Err(Code::CapabilityUnavailable)
        );
        let locked = status(p, ProviderAvailability::Locked);
        assert_eq!(
            readiness(&locked, &none, true, false, LockContinuity::Unknown).map_err(|r| r.code()),
            Err(Code::ProviderLocked)
        );
        assert_eq!(
            readiness(&up, &none, false, false, LockContinuity::Unknown),
            Ok(CredentialAvailability::CurrentOnly)
        );
        let unknown = [pair(InteractionKind::Unknown, IdentitySelection::Exclusive)];
        assert_eq!(
            readiness(&up, &unknown, true, false, LockContinuity::Unknown),
            Ok(CredentialAvailability::InteractionRequired)
        );
        let refused = readiness(&up, &unknown, false, false, LockContinuity::Unknown).unwrap_err();
        let e = refused.op_error();
        assert_eq!(e.code, Code::InteractionRequired);
        assert_eq!(e.reason.as_deref(), Some(reason::INTERACTION_UNKNOWN));
        assert_eq!(e.next.action, "interact");
        assert!(e.next.decision_ref.is_none() && e.next.provider_interaction.is_some());
    }

    #[test]
    fn non_exclusive_selection_without_clearance_is_a_fallback_refusal() {
        let up = status(ProviderKind::NativeAgent, ProviderAvailability::Unknown);
        for selection in [
            IdentitySelection::NotExclusive,
            IdentitySelection::Undetermined,
        ] {
            let pairs = [pair(InteractionKind::None, selection)];
            let r = readiness(&up, &pairs, false, false, LockContinuity::Unknown).unwrap_err();
            assert_eq!(
                r.op_error().reason.as_deref(),
                Some(reason::FALLBACK_IDENTITY_INTERACTION)
            );
            let mut cleared = pairs[0].clone();
            cleared.clearance = Some(FallbackClearance {
                cleared: true,
                uncleared: Vec::new(),
            });
            assert_eq!(
                readiness(&up, &[cleared], false, false, LockContinuity::Unknown),
                Ok(CredentialAvailability::CurrentOnly)
            );
        }
    }

    #[test]
    fn listing_states() {
        let now = Timestamp::UNIX_EPOCH;
        let endpoint = EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: "/scratch/a.sock".into(),
        };
        let listed = |n: usize| IdentityListing {
            endpoint: endpoint.clone(),
            identities: (0..n)
                .map(|i| heimdall_app::ports::ListedIdentity {
                    key_type: "ssh-ed25519".into(),
                    fingerprint: format!("SHA256:k{i}"),
                })
                .collect(),
            observed_at: now,
        };
        let p = ProviderKind::OnePassword;
        let s = status_from_listing(p, &Ok(listed(2)), now);
        assert_eq!(s.availability, ProviderAvailability::Available);
        assert_eq!(s.interaction, InteractionKind::ProviderApproval);
        assert_eq!(s.observed_level, ProbeLevel::Agent);
        for locked in [Ok(listed(0)), Err(AdapterError::ProviderLocked)] {
            let s = status_from_listing(p, &locked, now);
            assert_eq!(s.availability, ProviderAvailability::Locked);
            assert_eq!(s.interaction, InteractionKind::ProviderUnlock);
            assert_eq!(s.basis, EvidenceBasis::Inferred);
        }
        let s = status_from_listing(p, &Err(AdapterError::Unavailable("x".into())), now);
        assert_eq!(s.availability, ProviderAvailability::Unavailable);
        let s = status_from_listing(p, &Err(AdapterError::Protocol("x".into())), now);
        assert_eq!(s.availability, ProviderAvailability::Unknown);
    }
}
