//! The destination and identity catalog, owner interaction declarations, prepared
//! facts, and the two pure rules every layer shares: fresh launch eligibility and
//! fallback-identity clearance (ADR-0007 §7; m02-plan §5 item 17; U0b rows 5, 21,
//! 22).
//!
//! **One rule.** The runtime (U0b rows 5 and 21), the adapters (U6 `state`) and the
//! CLI's pre-launch check and doctor (U8) all call [`eligibility`] and
//! [`fallback_clearance`]. They live here because the application cannot depend on
//! `heimdall-adapters`.
//!
//! **History and eligibility are separate** (M2-R04). [`PreparedFacts`] records
//! what `prepare` observed and has no interaction, availability or eligibility
//! field, so a stored fact can never re-establish `interaction: none`. Eligibility is
//! recomputed from the identity's live declaration row in the transaction that
//! builds each result.

use heimdall_contract::Timestamp;
use heimdall_contract::catalog::{
    CatalogRequest, DeclaredInteraction, DestinationSpec, IdentitySpec, ProfileSpec, WithdrawReason,
};
use heimdall_contract::ids::{AccountName, DecisionId, DestinationId, IdentityId, ProfileId};
use heimdall_contract::provider::{
    Certainty, DeclarationRef, EndpointRef, EvidenceBasis, IdentitiesOnly, IdentityBacking,
    IdentityEntrySource, IdentitySelectionReport, InteractionKind, NoninteractiveEligibility,
    ProviderStatus, noninteractive_reason,
};
use heimdall_contract::request::{ConsumerExecutable, ConsumerOverride};
use serde::{Deserialize, Serialize};

// --- catalog records ------------------------------------------------------------------

/// How a destination is defined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DestinationDefinition {
    /// Rendered into the managed file P.
    Managed {
        /// `HostName`.
        hostname: String,
        /// `Port`, when not ssh's default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        /// `User`.
        account: AccountName,
        /// The adopted identity the alias uses.
        identity: IdentityId,
    },
    /// Defined by the user; Heimdall only observes it.
    Observed,
}

/// A catalog destination. Its ID survives an alias change (spec §4.2); the alias is
/// unique in the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationRecord {
    /// Destination ID.
    pub id: DestinationId,
    /// The OpenSSH alias.
    pub alias: String,
    /// Revision; every upsert carries a revision not lower than the stored one.
    pub revision: u64,
    /// Definition.
    pub definition: DestinationDefinition,
    /// Owner label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// When last written.
    pub updated_at: Timestamp,
}

/// Where an adopted identity is used from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IdentitySource {
    /// A key held by a native agent at this endpoint.
    NativeAgent {
        /// The agent endpoint.
        endpoint: EndpointRef,
    },
    /// A key held by the 1Password agent.
    #[serde(rename = "onepassword")]
    OnePassword {
        /// The endpoint, when not the documented default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint: Option<EndpointRef>,
    },
    /// A public key file whose private key is used through an agent (F9); the
    /// private key is never opened.
    PublicKeyFile {
        /// Path of the `.pub` file.
        path: String,
    },
}

/// The `native_agent` mechanism name.
pub const MECHANISM_NATIVE_AGENT: &str = "native_agent";
/// The `onepassword` mechanism name.
pub const MECHANISM_ONEPASSWORD: &str = "onepassword";

impl IdentitySource {
    /// The adapter mechanism this source names (U0b row 7; the U6 registry maps
    /// sources to `native_agent` or `onepassword`). A bare public-key file is used
    /// through an ordinary agent, so it names `native_agent`.
    #[must_use]
    pub fn mechanism(&self) -> &'static str {
        match self {
            IdentitySource::NativeAgent { .. } | IdentitySource::PublicKeyFile { .. } => {
                MECHANISM_NATIVE_AGENT
            }
            IdentitySource::OnePassword { .. } => MECHANISM_ONEPASSWORD,
        }
    }

    /// The recorded endpoint, when the source names one.
    #[must_use]
    pub fn endpoint(&self) -> Option<&EndpointRef> {
        match self {
            IdentitySource::NativeAgent { endpoint } => Some(endpoint),
            IdentitySource::OnePassword { endpoint } => endpoint.as_ref(),
            IdentitySource::PublicKeyFile { .. } => None,
        }
    }
}

/// An identity's default interaction profile (ADR-0007 §7 table), recorded at
/// adoption and re-derived when its public key or endpoint changes. A declaration
/// never changes it: [`eligibility`] applies declarations fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InteractionProfile {
    /// Default interaction.
    pub interaction: InteractionKind,
    /// How it was established.
    pub basis: EvidenceBasis,
}

/// An adopted identity: a public key and where it is used from. Never private
/// material. The fingerprint is unique in the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRecord {
    /// Identity ID.
    pub id: IdentityId,
    /// Revision; every upsert carries a revision not lower than the stored one.
    pub revision: u64,
    /// Where it is used from.
    pub source: IdentitySource,
    /// The OpenSSH one-line public key.
    pub public_key: String,
    /// Its fingerprint (`SHA256:…`).
    pub fingerprint: String,
    /// Default interaction profile.
    pub interaction: InteractionProfile,
    /// Owner label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// When adopted.
    pub adopted_at: Timestamp,
    /// When last written.
    pub updated_at: Timestamp,
}

impl IdentityRecord {
    /// The public key's type (its first token, e.g. `ssh-ed25519`).
    #[must_use]
    pub fn key_type(&self) -> &str {
        self.public_key
            .split_ascii_whitespace()
            .next()
            .unwrap_or("")
    }

    /// Whether the public key is a FIDO type (`sk-*`), which needs hardware presence
    /// whatever any declaration says (ADR-0007 §7).
    #[must_use]
    pub fn is_fido(&self) -> bool {
        self.key_type().starts_with("sk-")
    }
}

impl InteractionProfile {
    /// The ADR-0007 §7 default for an identity, without any declaration: 1Password
    /// `provider_approval` (documented); a FIDO key `hardware_presence` (documented);
    /// any other key `unknown` (inferred: a confirmation constraint cannot be
    /// observed passively, F23).
    #[must_use]
    pub fn default_for(source: &IdentitySource, public_key: &str) -> Self {
        let fido = public_key
            .split_ascii_whitespace()
            .next()
            .is_some_and(|t| t.starts_with("sk-"));
        match source {
            IdentitySource::OnePassword { .. } => Self {
                interaction: InteractionKind::ProviderApproval,
                basis: EvidenceBasis::Documented,
            },
            _ if fido => Self {
                interaction: InteractionKind::HardwarePresence,
                basis: EvidenceBasis::Documented,
            },
            _ => Self {
                interaction: InteractionKind::Unknown,
                basis: EvidenceBasis::Inferred,
            },
        }
    }
}

// --- interaction declarations (ADR-0007 §7; QR1) -------------------------------------

/// A declaration row's state. Expiry is computed when read, never written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclarationState {
    /// In force (subject to endpoint equality and expiry at every read).
    Live,
    /// Withdrawn by the owner.
    Withdrawn,
    /// Lapsed (listing missing, endpoint changed).
    Lapsed,
}

/// Why a declaration ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclarationEndReason {
    /// The owner withdrew it.
    OwnerWithdrawn,
    /// An explicit agent listing lacked the fingerprint.
    ListingMissing,
    /// The identity's endpoint changed.
    EndpointChanged,
}

impl From<WithdrawReason> for DeclarationEndReason {
    fn from(r: WithdrawReason) -> Self {
        match r {
            WithdrawReason::ListingMissing => DeclarationEndReason::ListingMissing,
            // `owner`, and any reason a newer client adds: the narrowing reading.
            _ => DeclarationEndReason::OwnerWithdrawn,
        }
    }
}

/// ⟨r2⟩ ⟨r3⟩ An owner's interaction declaration (ADR-0007 §7). One row per
/// identity, never deleted; `revision` grows with every declaration, withdrawal and
/// recorded lapse, each a compare-and-swap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionDeclaration {
    /// Row revision.
    pub revision: u64,
    /// State.
    pub state: DeclarationState,
    /// The declared interaction.
    pub interaction: DeclaredInteraction,
    /// The identity's fingerprint it covers.
    pub fingerprint: String,
    /// The endpoint it covers.
    pub endpoint: EndpointRef,
    /// When declared.
    pub declared_at: Timestamp,
    /// When it lapses (computed at every read).
    pub expires_at: Timestamp,
    /// The approving decision.
    pub decision: DecisionId,
    /// When it ended, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<Timestamp>,
    /// Why it ended, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_reason: Option<DeclarationEndReason>,
}

impl InteractionDeclaration {
    /// Whether it counts for `identity` at `current_endpoint` at `now` (ADR-0007 §7
    /// "Launch eligibility is checked fresh"): `live`, for the identity's current
    /// fingerprint, at the same endpoint, and `expires_at > now`.
    #[must_use]
    pub fn counts_for(
        &self,
        identity: &IdentityRecord,
        current_endpoint: &EndpointRef,
        now: Timestamp,
    ) -> bool {
        self.state == DeclarationState::Live
            && self.interaction == DeclaredInteraction::None
            && self.fingerprint == identity.fingerprint
            && self.endpoint == *current_endpoint
            && self.expires_at > now
    }
}

// --- intents and approvals ---------------------------------------------------------

/// ⟨r3⟩ The declaration approval, only in [`CatalogIntent::approval`] (m02-plan §5
/// item 17; frozen). `decide` copies it from a `DeclareInteraction` record's fields,
/// and the catalog driver builds the [`InteractionDeclaration`] from it and from
/// nothing else. A projection approval cannot be represented here: unknown fields
/// are refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclarationApproval {
    /// The approved decision record.
    pub decision: DecisionId,
    /// The identity.
    pub identity: IdentityId,
    /// Its fingerprint when the decision was created.
    pub fingerprint: String,
    /// The endpoint the declaration covers.
    pub endpoint: EndpointRef,
    /// The declared interaction.
    pub interaction: DeclaredInteraction,
    /// When the declaration lapses.
    pub valid_until: Timestamp,
}

/// The catalog request's action in canonical form: the request without its
/// `request_id`, tagged `action` as on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum CatalogAction {
    /// Create or replace a destination.
    UpsertDestination {
        /// The destination.
        destination: DestinationSpec,
    },
    /// Remove a destination.
    RemoveDestination {
        /// Destination ID.
        id: DestinationId,
    },
    /// Adopt an identity.
    AdoptIdentity {
        /// The identity.
        identity: IdentitySpec,
    },
    /// Remove an identity.
    RemoveIdentity {
        /// Identity ID.
        id: IdentityId,
    },
    /// Create or replace a profile.
    UpsertProfile {
        /// The profile.
        profile: ProfileSpec,
    },
    /// Remove a profile.
    RemoveProfile {
        /// Profile ID.
        id: ProfileId,
    },
    /// Declare an identity's interaction (needs a decision).
    DeclareInteraction {
        /// Identity ID.
        identity: IdentityId,
        /// The declared interaction.
        interaction: DeclaredInteraction,
    },
    /// Withdraw a declaration (narrowing).
    WithdrawDeclaration {
        /// Identity ID.
        identity: IdentityId,
        /// Expected revision (compare-and-swap), if given.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revision: Option<u64>,
        /// Why.
        reason: WithdrawReason,
    },
    // M03 wave 0 (O): the ninth action (m03-plan §5 item 4b; U0b row 22).
    /// ⟨M03⟩ Set a pair's preferred mechanism (local only; P follows through
    /// `setup apply`).
    SetPreference {
        /// Destination.
        destination: DestinationId,
        /// Account.
        account: AccountName,
        /// The preferred mechanism.
        mechanism: heimdall_contract::managed::PreferredMechanism,
    },
}

impl CatalogAction {
    /// The canonical action of a catalog request; `None` for an action this build
    /// does not know (the request type is `#[non_exhaustive]`).
    #[must_use]
    pub fn from_request(request: &CatalogRequest) -> Option<Self> {
        Some(match request {
            CatalogRequest::UpsertDestination { destination, .. } => {
                CatalogAction::UpsertDestination {
                    destination: destination.clone(),
                }
            }
            CatalogRequest::RemoveDestination { id, .. } => {
                CatalogAction::RemoveDestination { id: id.clone() }
            }
            CatalogRequest::AdoptIdentity { identity, .. } => CatalogAction::AdoptIdentity {
                identity: identity.clone(),
            },
            CatalogRequest::RemoveIdentity { id, .. } => {
                CatalogAction::RemoveIdentity { id: id.clone() }
            }
            CatalogRequest::UpsertProfile { profile, .. } => CatalogAction::UpsertProfile {
                profile: profile.clone(),
            },
            CatalogRequest::RemoveProfile { id, .. } => {
                CatalogAction::RemoveProfile { id: id.clone() }
            }
            CatalogRequest::DeclareInteraction {
                identity,
                interaction,
                ..
            } => CatalogAction::DeclareInteraction {
                identity: identity.clone(),
                interaction: *interaction,
            },
            CatalogRequest::WithdrawDeclaration {
                identity,
                revision,
                reason,
                ..
            } => CatalogAction::WithdrawDeclaration {
                identity: identity.clone(),
                revision: *revision,
                reason: *reason,
            },
            // M03 wave 0 (O)
            CatalogRequest::SetPreference {
                destination,
                account,
                mechanism,
                ..
            } => CatalogAction::SetPreference {
                destination: destination.clone(),
                account: account.clone(),
                mechanism: *mechanism,
            },
            _ => return None,
        })
    }
}

/// ⟨r3⟩ The local intent of a catalog operation (m02-plan §5 item 17; frozen).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogIntent {
    /// The request's action, canonical.
    pub action: CatalogAction,
    /// The declaration approval; `Some` only for a `DeclareInteraction` action.
    /// Add-only: `None → Some` once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<DeclarationApproval>,
}

/// Why a catalog intent is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CatalogIntentError {
    /// An approval on an action other than `declare_interaction`.
    #[error("only a declare_interaction action carries an approval")]
    ApprovalOnOtherAction,
    /// The approval names another identity or interaction than the action.
    #[error("the approval does not match the declared identity and interaction")]
    ApprovalMismatch,
}

impl CatalogIntent {
    /// Validate on build and on every read.
    pub fn validate(&self) -> Result<(), CatalogIntentError> {
        let Some(approval) = &self.approval else {
            return Ok(());
        };
        match &self.action {
            CatalogAction::DeclareInteraction {
                identity,
                interaction,
            } => {
                if approval.identity == *identity && approval.interaction == *interaction {
                    Ok(())
                } else {
                    Err(CatalogIntentError::ApprovalMismatch)
                }
            }
            _ => Err(CatalogIntentError::ApprovalOnOtherAction),
        }
    }

    /// This intent with its approval removed.
    #[must_use]
    pub fn without_approval(&self) -> CatalogIntent {
        CatalogIntent {
            action: self.action.clone(),
            approval: None,
        }
    }
}

// --- prepared facts: history only (M2-R04) --------------------------------------------

/// One pair's prepared history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedPair {
    /// Destination.
    pub destination: DestinationId,
    /// Account.
    pub account: AccountName,
    /// The adopted identity.
    pub identity: IdentityId,
    /// Mechanism.
    pub mechanism: String,
    /// The agent endpoint, when one.
    pub endpoint: Option<EndpointRef>,
    /// The managed alias, when one.
    pub alias: Option<String>,
    /// The static identity selection at prepare time.
    pub identity_selection: IdentitySelectionReport,
    /// When the selection was observed.
    pub selection_observed_at: Timestamp,
}

/// ⟨r2⟩ ⟨r3⟩ What `prepare` observed for a grant, stored per grant (nonsecret;
/// spec §7.3). **History only**: there is no availability, interaction or
/// eligibility field, so a stored fact cannot re-establish `interaction: none`
/// (m02-plan §5 item 17; M2-R04). `PreparedFacts::from(&PrepareOutcome)` lives
/// with the port type in the application and drops every such field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedFacts {
    /// The provider status `prepare` observed.
    pub provider: Option<ProviderStatus>,
    /// Client executables.
    #[serde(default)]
    pub executables: Vec<ConsumerExecutable>,
    /// Overriding consumer settings.
    #[serde(default)]
    pub overrides: Vec<ConsumerOverride>,
    /// Environment values a launcher sets (names and values; never secrets).
    #[serde(default)]
    pub environment: Vec<(String, String)>,
    /// Per-pair history.
    #[serde(default)]
    pub pairs: Vec<PreparedPair>,
    /// When recorded.
    pub recorded_at: Timestamp,
}

// --- the pure rules (ADR-0007 §7; U0b row 22) ---------------------------------------

/// A pair's fresh eligibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairEligibility {
    /// Interaction.
    pub interaction: InteractionKind,
    /// How it was established.
    pub basis: EvidenceBasis,
    /// The live declaration relied on, when `basis: declared`.
    pub declaration: Option<DeclarationRef>,
    /// Non-interactive eligibility.
    pub noninteractive: NoninteractiveEligibility,
}

fn not_eligible(reason: &str) -> NoninteractiveEligibility {
    NoninteractiveEligibility {
        eligible: false,
        reason: Some(reason.to_owned()),
    }
}

/// ⟨r3⟩ ADR-0007 §7's interaction table, applied fresh (M2-R04):
///
/// * a 1Password identity is `provider_approval` (documented), whatever any
///   declaration says;
/// * a FIDO (`sk-*`) key is `hardware_presence` (documented), whatever any
///   declaration says;
/// * any other key is `none` (declared) only while its declaration counts
///   ([`InteractionDeclaration::counts_for`]: live, same fingerprint, same endpoint,
///   `expires_at > now`; so `expires_at == now` no longer counts), and the result
///   names that declaration;
/// * otherwise `unknown` (inferred), with no declaration.
///
/// Only `none` is eligible for non-interactive use. Pure: the caller supplies the
/// declaration row it read in the transaction that builds the result, the
/// identity's current endpoint, and the runtime's current time.
#[must_use]
pub fn eligibility(
    identity: &IdentityRecord,
    declaration: Option<&InteractionDeclaration>,
    current_endpoint: &EndpointRef,
    now: Timestamp,
) -> PairEligibility {
    if matches!(identity.source, IdentitySource::OnePassword { .. }) {
        return PairEligibility {
            interaction: InteractionKind::ProviderApproval,
            basis: EvidenceBasis::Documented,
            declaration: None,
            noninteractive: not_eligible(noninteractive_reason::PROVIDER_INTERACTION),
        };
    }
    if identity.is_fido() {
        return PairEligibility {
            interaction: InteractionKind::HardwarePresence,
            basis: EvidenceBasis::Documented,
            declaration: None,
            noninteractive: not_eligible(noninteractive_reason::PROVIDER_INTERACTION),
        };
    }
    match declaration {
        Some(d) if d.counts_for(identity, current_endpoint, now) => PairEligibility {
            interaction: InteractionKind::None,
            basis: EvidenceBasis::Declared,
            declaration: Some(DeclarationRef {
                revision: d.revision,
                endpoint: d.endpoint.clone(),
                expires_at: d.expires_at,
            }),
            noninteractive: NoninteractiveEligibility {
                eligible: true,
                reason: None,
            },
        },
        _ => PairEligibility {
            interaction: InteractionKind::Unknown,
            basis: EvidenceBasis::Inferred,
            declaration: None,
            noninteractive: not_eligible(noninteractive_reason::INTERACTION_UNKNOWN),
        },
    }
}

/// The result of [`fallback_clearance`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackClearance {
    /// Every reachable alternative identity is cleared, and `IdentitiesOnly` is a
    /// determined `yes`.
    pub cleared: bool,
    /// Indexes (into `report.entries`) of the alternatives that are not cleared.
    pub uncleared: Vec<usize>,
}

/// ⟨r3⟩ ADR-0007 §7's fallback clearance rule (M2-R05).
///
/// ⟨M02⟩ ADR-0007 §12.15 item 3(d): the adopted identity is the entry sourced from
/// Heimdall's managed projection **whose fingerprint equals `adopted_fingerprint`**
/// (the pair's identity); it is not a fallback. Any other managed entry (a stale
/// projection, a missing `.pub`, another key) is an alternative ssh may offer, and it
/// is never cleared. So readiness, the adapters and the CLI's pre-launch check apply
/// this one rule (it replaces the adapters' `strict_clearance`).
///
/// The alternatives are every other entry of `report`. An alternative that is not
/// managed is cleared only when **all** of these hold:
/// * the alias's `IdentitiesOnly` is a determined `yes`; without it every
///   alternative is uncleared and the result is never cleared, because the agent may
///   then offer keys that cannot be listed passively;
/// * the entry is determined and agent-backed (its private key file is absent, F9);
/// * its fingerprint, read from the `.pub`, is present (a missing `.pub` is
///   uncleared) and is a catalog identity whose recorded endpoint is `endpoint` (the
///   alias's effective `IdentityAgent`), that is not a FIDO key;
/// * that identity's fresh eligibility (`eligibility_of`) is `interaction: none`.
///
/// So a file-backed entry, an `sk-` entry, an undetermined entry, a `.pub`-less entry
/// and an undeclared or differently-located identity are never cleared; nor is a
/// managed entry that is not the adopted identity. An empty `adopted_fingerprint`
/// names no entry. Pure.
#[must_use]
pub fn fallback_clearance(
    report: &IdentitySelectionReport,
    identities: &[IdentityRecord],
    eligibility_of: &dyn Fn(&IdentityId) -> PairEligibility,
    endpoint: &EndpointRef,
    adopted_fingerprint: &str,
) -> FallbackClearance {
    let identities_only = report.identities_only == IdentitiesOnly::DeterminedYes;
    let mut uncleared = Vec::new();
    for (i, entry) in report.entries.iter().enumerate() {
        if entry.source == IdentityEntrySource::Managed {
            let adopted = !adopted_fingerprint.is_empty()
                && entry.fingerprint.as_deref() == Some(adopted_fingerprint);
            if !adopted {
                uncleared.push(i);
            }
            continue;
        }
        let cleared = identities_only
            && entry.certainty == Certainty::Determined
            && entry.backing == IdentityBacking::Agent
            && entry.fingerprint.as_deref().is_some_and(|fp| {
                identities.iter().any(|id| {
                    id.fingerprint == fp
                        && id.source.endpoint() == Some(endpoint)
                        && !id.is_fido()
                        && eligibility_of(&id.id).interaction == InteractionKind::None
                })
            });
        if !cleared {
            uncleared.push(i);
        }
    }
    FallbackClearance {
        cleared: identities_only && uncleared.is_empty(),
        uncleared,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::provider::{
        EndpointKind, IdentityEntry, IdentityEntryKind, IdentitySelection, ProbeLevel,
        ProviderAvailability, ProviderKind,
    };

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn now() -> Timestamp {
        t("2026-11-01T12:00:00Z")
    }

    fn endpoint(locator: &str) -> EndpointRef {
        EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: locator.into(),
        }
    }

    fn identity(n: u8, source: IdentitySource, key_type: &str) -> IdentityRecord {
        let public_key = format!("{key_type} AAAAfixture{n} fixture");
        IdentityRecord {
            id: IdentityId::from_random_bytes([n; 16]),
            revision: 1,
            interaction: InteractionProfile::default_for(&source, &public_key),
            source,
            public_key,
            fingerprint: format!("SHA256:fixture{n}"),
            label: None,
            adopted_at: t("2026-10-01T00:00:00Z"),
            updated_at: t("2026-10-01T00:00:00Z"),
        }
    }

    fn native(n: u8, at: &str) -> IdentityRecord {
        identity(
            n,
            IdentitySource::NativeAgent {
                endpoint: endpoint(at),
            },
            "ssh-ed25519",
        )
    }

    fn declaration(id: &IdentityRecord, at: &str, expires: Timestamp) -> InteractionDeclaration {
        InteractionDeclaration {
            revision: 4,
            state: DeclarationState::Live,
            interaction: DeclaredInteraction::None,
            fingerprint: id.fingerprint.clone(),
            endpoint: endpoint(at),
            declared_at: t("2026-10-15T00:00:00Z"),
            expires_at: expires,
            decision: DecisionId::from_random_bytes([9; 16]),
            ended_at: None,
            end_reason: None,
        }
    }

    fn unknown() -> PairEligibility {
        PairEligibility {
            interaction: InteractionKind::Unknown,
            basis: EvidenceBasis::Inferred,
            declaration: None,
            noninteractive: not_eligible(noninteractive_reason::INTERACTION_UNKNOWN),
        }
    }

    /// U0b `domain_eligibility_rule_table` (M2-R04).
    #[test]
    fn domain_eligibility_rule_table() {
        let a = "/scratch/a.sock";
        let id = native(1, a);
        let later = t("2026-12-01T00:00:00Z");
        let live = declaration(&id, a, later);
        // Live, same endpoint, unexpired: none / declared, naming the declaration.
        assert_eq!(
            eligibility(&id, Some(&live), &endpoint(a), now()),
            PairEligibility {
                interaction: InteractionKind::None,
                basis: EvidenceBasis::Declared,
                declaration: Some(DeclarationRef {
                    revision: 4,
                    endpoint: endpoint(a),
                    expires_at: later,
                }),
                noninteractive: NoninteractiveEligibility {
                    eligible: true,
                    reason: None,
                },
            }
        );
        // Withdrawn, lapsed, expired (expires_at == now included), another endpoint,
        // another fingerprint, or no declaration: unknown.
        let mut withdrawn = live.clone();
        withdrawn.state = DeclarationState::Withdrawn;
        withdrawn.end_reason = Some(DeclarationEndReason::OwnerWithdrawn);
        let mut lapsed = live.clone();
        lapsed.state = DeclarationState::Lapsed;
        lapsed.end_reason = Some(DeclarationEndReason::ListingMissing);
        let at_now = declaration(&id, a, now());
        let past = declaration(&id, a, t("2026-11-01T11:59:59Z"));
        let elsewhere = declaration(&id, "/scratch/b.sock", later);
        let mut other_key = live.clone();
        other_key.fingerprint = "SHA256:other".into();
        for d in [&withdrawn, &lapsed, &at_now, &past, &elsewhere, &other_key] {
            assert_eq!(
                eligibility(&id, Some(d), &endpoint(a), now()),
                unknown(),
                "{d:?}"
            );
        }
        assert_eq!(eligibility(&id, None, &endpoint(a), now()), unknown());
        // The identity's endpoint changed after the declaration: unknown.
        assert_eq!(
            eligibility(&id, Some(&live), &endpoint("/scratch/moved.sock"), now()),
            unknown()
        );
        // 1Password and FIDO keep their documented kinds whatever the declaration.
        let op = identity(
            2,
            IdentitySource::OnePassword {
                endpoint: Some(endpoint(a)),
            },
            "ssh-ed25519",
        );
        let op_decl = declaration(&op, a, later);
        let e = eligibility(&op, Some(&op_decl), &endpoint(a), now());
        assert_eq!(
            (e.interaction, e.basis, e.declaration.is_none()),
            (
                InteractionKind::ProviderApproval,
                EvidenceBasis::Documented,
                true
            )
        );
        assert_eq!(
            e.noninteractive,
            not_eligible(noninteractive_reason::PROVIDER_INTERACTION)
        );
        let fido = identity(
            3,
            IdentitySource::NativeAgent {
                endpoint: endpoint(a),
            },
            "sk-ssh-ed25519@openssh.com",
        );
        let fido_decl = declaration(&fido, a, later);
        let e = eligibility(&fido, Some(&fido_decl), &endpoint(a), now());
        assert_eq!(
            (
                e.interaction,
                e.basis,
                e.declaration.is_none(),
                e.noninteractive.eligible
            ),
            (
                InteractionKind::HardwarePresence,
                EvidenceBasis::Documented,
                true,
                false
            )
        );
        // The recorded defaults match the table.
        assert_eq!(id.interaction.interaction, InteractionKind::Unknown);
        assert_eq!(
            op.interaction.interaction,
            InteractionKind::ProviderApproval
        );
        assert_eq!(
            fido.interaction.interaction,
            InteractionKind::HardwarePresence
        );
        assert_eq!(id.source.mechanism(), MECHANISM_NATIVE_AGENT);
        assert_eq!(op.source.mechanism(), MECHANISM_ONEPASSWORD);
    }

    fn entry(
        source: IdentityEntrySource,
        fingerprint: Option<&str>,
        backing: IdentityBacking,
    ) -> IdentityEntry {
        IdentityEntry {
            kind: IdentityEntryKind::IdentityFile,
            source,
            provenance: None,
            certainty: Certainty::Determined,
            fingerprint: fingerprint.map(str::to_owned),
            backing,
            cleared: None,
        }
    }

    fn report(
        entries: Vec<IdentityEntry>,
        identities_only: IdentitiesOnly,
    ) -> IdentitySelectionReport {
        IdentitySelectionReport {
            selection: IdentitySelection::NotExclusive,
            entries,
            identities_only,
        }
    }

    /// U0b `domain_fallback_clearance_rule_table` (M2-R05), one case each.
    #[test]
    fn domain_fallback_clearance_rule_table() {
        let a = "/scratch/a.sock";
        let later = t("2026-12-01T00:00:00Z");
        let declared = native(1, a);
        let undeclared = native(2, a);
        let fido = identity(
            3,
            IdentitySource::NativeAgent {
                endpoint: endpoint(a),
            },
            "sk-ecdsa-sha2-nistp256@openssh.com",
        );
        let declared_elsewhere = native(4, a);
        let catalog = vec![
            declared.clone(),
            undeclared.clone(),
            fido.clone(),
            declared_elsewhere.clone(),
        ];
        let rows: std::collections::BTreeMap<IdentityId, InteractionDeclaration> = [
            (declared.id.clone(), declaration(&declared, a, later)),
            (fido.id.clone(), declaration(&fido, a, later)),
            (
                declared_elsewhere.id.clone(),
                declaration(&declared_elsewhere, "/scratch/b.sock", later),
            ),
        ]
        .into_iter()
        .collect();
        let eligibility_of = |id: &IdentityId| {
            let record = catalog.iter().find(|r| r.id == *id).unwrap();
            eligibility(record, rows.get(id), &endpoint(a), now())
        };
        const ADOPTED: &str = "SHA256:adopted";
        let managed = entry(
            IdentityEntrySource::Managed,
            Some(ADOPTED),
            IdentityBacking::Agent,
        );
        let clear = |entries: Vec<IdentityEntry>, only: IdentitiesOnly| {
            fallback_clearance(
                &report(entries, only),
                &catalog,
                &eligibility_of,
                &endpoint(a),
                ADOPTED,
            )
        };
        // An agent-backed entry declared `none` at the same endpoint is cleared; the
        // managed (adopted) entry is never a fallback.
        let ok = entry(
            IdentityEntrySource::User,
            Some(&declared.fingerprint),
            IdentityBacking::Agent,
        );
        assert_eq!(
            clear(
                vec![managed.clone(), ok.clone()],
                IdentitiesOnly::DeterminedYes
            ),
            FallbackClearance {
                cleared: true,
                uncleared: Vec::new()
            }
        );
        // Each of these alternatives is uncleared.
        let mut undetermined = ok.clone();
        undetermined.certainty = Certainty::Undetermined;
        let cases: Vec<(&str, IdentityEntry)> = vec![
            (
                "undeclared agent-backed",
                entry(
                    IdentityEntrySource::User,
                    Some(&undeclared.fingerprint),
                    IdentityBacking::Agent,
                ),
            ),
            (
                "file-backed",
                entry(
                    IdentityEntrySource::User,
                    Some(&declared.fingerprint),
                    IdentityBacking::File,
                ),
            ),
            (
                "unknown backing",
                entry(
                    IdentityEntrySource::System,
                    Some(&declared.fingerprint),
                    IdentityBacking::Unknown,
                ),
            ),
            (
                "sk- entry",
                entry(
                    IdentityEntrySource::User,
                    Some(&fido.fingerprint),
                    IdentityBacking::Agent,
                ),
            ),
            ("undetermined", undetermined),
            (
                ".pub-less",
                entry(IdentityEntrySource::Default, None, IdentityBacking::Agent),
            ),
            (
                "declared at another endpoint",
                entry(
                    IdentityEntrySource::User,
                    Some(&declared_elsewhere.fingerprint),
                    IdentityBacking::Agent,
                ),
            ),
            (
                "not in the catalog",
                entry(
                    IdentityEntrySource::User,
                    Some("SHA256:stranger"),
                    IdentityBacking::Agent,
                ),
            ),
        ];
        for (name, alt) in cases {
            assert_eq!(
                clear(
                    vec![managed.clone(), ok.clone(), alt],
                    IdentitiesOnly::DeterminedYes
                ),
                FallbackClearance {
                    cleared: false,
                    uncleared: vec![2]
                },
                "{name}"
            );
        }
        // A catalog identity recorded at another endpoint than the alias's agent.
        let moved = native(5, "/scratch/b.sock");
        let moved_catalog = vec![moved.clone()];
        let moved_rows = declaration(&moved, a, later);
        let moved_eligibility =
            |_: &IdentityId| eligibility(&moved, Some(&moved_rows), &endpoint(a), now());
        let r = fallback_clearance(
            &report(
                vec![entry(
                    IdentityEntrySource::User,
                    Some(&moved.fingerprint),
                    IdentityBacking::Agent,
                )],
                IdentitiesOnly::DeterminedYes,
            ),
            &moved_catalog,
            &moved_eligibility,
            &endpoint(a),
            ADOPTED,
        );
        assert_eq!(r.uncleared, vec![0]);
        // Every alternative of an alias without a determined `IdentitiesOnly yes` is
        // uncleared, and such an alias is never cleared, even with no alternative.
        for only in [IdentitiesOnly::DeterminedNo, IdentitiesOnly::Undetermined] {
            assert_eq!(
                clear(vec![ok.clone(), managed.clone(), ok.clone()], only),
                FallbackClearance {
                    cleared: false,
                    uncleared: vec![0, 2]
                }
            );
            assert_eq!(
                clear(vec![managed.clone()], only),
                FallbackClearance {
                    cleared: false,
                    uncleared: Vec::new()
                }
            );
        }
    }

    /// ADR-0007 §12.15 item 3(d): a managed entry is the adopted identity only when
    /// its fingerprint is the adopted one. Any other managed entry (another key, a
    /// missing `.pub`) is an uncleared alternative, so the alias is never cleared
    /// through it, whatever `IdentitiesOnly` says; an empty adopted fingerprint names
    /// no entry.
    #[test]
    fn fallback_clearance_clears_a_managed_entry_only_with_the_adopted_fingerprint() {
        let a = "/scratch/a.sock";
        let later = t("2026-12-01T00:00:00Z");
        let declared = native(1, a);
        let catalog = vec![declared.clone()];
        let rows: std::collections::BTreeMap<IdentityId, InteractionDeclaration> =
            [(declared.id.clone(), declaration(&declared, a, later))]
                .into_iter()
                .collect();
        let eligibility_of = |id: &IdentityId| {
            let record = catalog.iter().find(|r| r.id == *id).unwrap();
            eligibility(record, rows.get(id), &endpoint(a), now())
        };
        let adopted = "SHA256:adopted";
        let managed =
            |fp: Option<&str>| entry(IdentityEntrySource::Managed, fp, IdentityBacking::Agent);
        let cleared_alt = entry(
            IdentityEntrySource::User,
            Some(&declared.fingerprint),
            IdentityBacking::Agent,
        );
        let clear = |entries: Vec<IdentityEntry>, fp: &str| {
            fallback_clearance(
                &report(entries, IdentitiesOnly::DeterminedYes),
                &catalog,
                &eligibility_of,
                &endpoint(a),
                fp,
            )
        };
        // The adopted key's own managed entry is not a fallback.
        assert_eq!(
            clear(vec![managed(Some(adopted)), cleared_alt.clone()], adopted),
            FallbackClearance {
                cleared: true,
                uncleared: Vec::new()
            }
        );
        // A managed entry naming another key, or no key, is uncleared, even when
        // that key is a declared catalog identity at the same endpoint.
        for other in [
            managed(Some("SHA256:stale")),
            managed(None),
            managed(Some(&declared.fingerprint)),
        ] {
            assert_eq!(
                clear(
                    vec![managed(Some(adopted)), other.clone(), cleared_alt.clone()],
                    adopted
                ),
                FallbackClearance {
                    cleared: false,
                    uncleared: vec![1]
                },
                "{other:?}"
            );
        }
        // No adopted fingerprint: no managed entry is the adopted one.
        assert_eq!(
            clear(vec![managed(Some(adopted))], ""),
            FallbackClearance {
                cleared: false,
                uncleared: vec![0]
            }
        );
        assert_eq!(
            clear(vec![managed(None)], ""),
            FallbackClearance {
                cleared: false,
                uncleared: vec![0]
            }
        );
    }

    #[test]
    fn catalog_intent_approval_fits_its_action() {
        let idn = IdentityId::from_random_bytes([3; 16]);
        let approval = DeclarationApproval {
            decision: DecisionId::from_random_bytes([2; 16]),
            identity: idn.clone(),
            fingerprint: "SHA256:fixture".into(),
            endpoint: endpoint("/scratch/a.sock"),
            interaction: DeclaredInteraction::None,
            valid_until: t("2026-12-01T00:00:00Z"),
        };
        let declare = CatalogIntent {
            action: CatalogAction::DeclareInteraction {
                identity: idn.clone(),
                interaction: DeclaredInteraction::None,
            },
            approval: Some(approval.clone()),
        };
        assert_eq!(declare.validate(), Ok(()));
        assert_eq!(declare.without_approval().approval, None);
        let other = CatalogIntent {
            action: CatalogAction::DeclareInteraction {
                identity: IdentityId::from_random_bytes([4; 16]),
                interaction: DeclaredInteraction::None,
            },
            approval: Some(approval.clone()),
        };
        assert_eq!(other.validate(), Err(CatalogIntentError::ApprovalMismatch));
        let remove = CatalogIntent {
            action: CatalogAction::RemoveIdentity { id: idn },
            approval: Some(approval),
        };
        assert_eq!(
            remove.validate(),
            Err(CatalogIntentError::ApprovalOnOtherAction)
        );
        let request: CatalogRequest = serde_json::from_str(
            r#"{"action":"withdraw_declaration","identity":"idn_03030303030303030303030303030303","revision":4,"reason":"listing_missing","request_id":"r1"}"#,
        )
        .unwrap();
        let action = CatalogAction::from_request(&request).unwrap();
        assert_eq!(
            serde_json::to_string(&action).unwrap(),
            r#"{"action":"withdraw_declaration","identity":"idn_03030303030303030303030303030303","revision":4,"reason":"listing_missing"}"#
        );
        assert_eq!(
            DeclarationEndReason::from(WithdrawReason::ListingMissing),
            DeclarationEndReason::ListingMissing
        );
    }

    /// PreparedFacts is history only: no availability, interaction or eligibility
    /// field outside the provider status it records (M2-R04).
    #[test]
    fn prepared_facts_have_no_interaction_field() {
        let facts = PreparedFacts {
            provider: Some(ProviderStatus {
                provider: ProviderKind::NativeAgent,
                availability: ProviderAvailability::Available,
                interaction: InteractionKind::Unknown,
                observed_level: ProbeLevel::Static,
                observed_at: t("2026-11-01T00:00:00Z"),
                basis: EvidenceBasis::Observed,
            }),
            executables: Vec::new(),
            overrides: Vec::new(),
            environment: vec![("SSH_AUTH_SOCK".into(), "/scratch/a.sock".into())],
            pairs: vec![PreparedPair {
                destination: DestinationId::parse("work").unwrap(),
                account: AccountName::parse("git").unwrap(),
                identity: IdentityId::from_random_bytes([1; 16]),
                mechanism: MECHANISM_NATIVE_AGENT.into(),
                endpoint: Some(endpoint("/scratch/a.sock")),
                alias: Some("work".into()),
                identity_selection: report(Vec::new(), IdentitiesOnly::DeterminedYes),
                selection_observed_at: t("2026-11-01T00:00:00Z"),
            }],
            recorded_at: t("2026-11-01T00:00:00Z"),
        };
        let mut value = serde_json::to_value(&facts).unwrap();
        let top: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            top,
            [
                "environment",
                "executables",
                "overrides",
                "pairs",
                "provider",
                "recorded_at"
            ]
        );
        let pair: Vec<&str> = value["pairs"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for forbidden in [
            "interaction",
            "interaction_basis",
            "declared_at",
            "declaration",
            "noninteractive",
            "eligibility_checked_at",
            "availability",
            "credential_availability",
        ] {
            assert!(!pair.contains(&forbidden), "{forbidden}");
            assert!(!top.contains(&forbidden), "{forbidden}");
        }
        let back: PreparedFacts = serde_json::from_value(value.take()).unwrap();
        assert_eq!(back, facts);
    }
}
