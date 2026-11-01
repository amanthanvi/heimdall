//! Provider, interaction and identity-selection types (ADR-0007 §7, §3 item 3, §10;
//! m02-plan §5 items 8 to 10; ADR-0006 revision 3).
//!
//! These describe what Heimdall observed or was told about an existing-access
//! provider (a native agent, 1Password, an unknown one). They never carry key
//! material: a fingerprint is the public `SHA256:` form, and an endpoint is a
//! socket path or pipe name. Every enum is `#[non_exhaustive]` and `snake_case`
//! on the wire.

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::doctor::ConfigProvenance;

/// Which provider serves an agent endpoint (ADR-0007 §7 "Detection is passive").
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProviderKind {
    /// An OpenSSH-compatible agent (`ssh-agent`, the Windows OpenSSH agent service).
    NativeAgent,
    /// The 1Password SSH agent.
    #[serde(rename = "onepassword")]
    OnePassword,
    /// Not determinable passively (for example the Windows `openssh-ssh-agent` pipe,
    /// F18).
    Unknown,
}

/// Whether the provider can sign now (ADR-0007 §7 "Provider states").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProviderAvailability {
    /// Observed available.
    Available,
    /// Observed locked (needs the explicit `agent` level).
    Locked,
    /// No endpoint (passively established).
    Unavailable,
    /// Not established.
    Unknown,
}

/// The human step an authentication may need (ADR-0007 §7 interaction profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InteractionKind {
    /// No interaction (only ever `declared` for a native agent key).
    None,
    /// The provider asks for approval (1Password).
    ProviderApproval,
    /// The provider must be unlocked.
    ProviderUnlock,
    /// A hardware presence touch (FIDO `sk-*` keys).
    HardwarePresence,
    /// A passphrase prompt.
    Passphrase,
    /// Not known; never satisfies a non-interactive requirement.
    Unknown,
}

/// How a reported fact was established (ADR-0007 §7). `declared` is an owner
/// statement, never an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EvidenceBasis {
    /// Observed by a probe.
    Observed,
    /// Taken from pinned vendor documentation.
    Documented,
    /// Inferred; labelled `[I]` in reports.
    Inferred,
    /// Declared by the owner through an attended decision.
    Declared,
}

/// The probe ladder levels (ADR-0007 §6; spec §10.2), weakest first.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProbeLevel {
    /// Parse and evaluate without executing anything (the default).
    Static,
    /// `ssh -G` against the real tree (needs `--allow-config-commands`).
    Evaluate,
    /// One `SSH_AGENTC_REQUEST_IDENTITIES` to a named endpoint.
    Agent,
    /// TCP connect and read the identification line.
    Network,
    /// Host-key verification with nothing to sign (needs `--allow-config-commands`).
    HostVerification,
    /// A real authentication (needs `--allow-config-commands`).
    Authentication,
}

/// A provider's observed state (ADR-0007 §7 "Provider states").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProviderStatus {
    /// Which provider.
    pub provider: ProviderKind,
    /// Whether it can sign now.
    pub availability: ProviderAvailability,
    /// The interaction its identities need.
    pub interaction: InteractionKind,
    /// The probe level that observed it.
    pub observed_level: ProbeLevel,
    /// When it was observed (RFC 3339, explicit offset).
    pub observed_at: Timestamp,
    /// How it was established.
    pub basis: EvidenceBasis,
}

/// Credential availability (spec §4.3): how long new authentications keep working
/// without further action.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CredentialAvailability {
    /// Usable now; no claim about later.
    CurrentOnly,
    /// Usable through the deadline.
    ThroughDeadline,
    /// Depends on a refresh before the deadline.
    RefreshDependent,
    /// A human step may be needed for new authentications.
    InteractionRequired,
    /// Not established (the default for older documents).
    #[default]
    Unknown,
}

/// The provider-owned interaction a next action points at (spec §5.5). Used with
/// action `interact` for `PROVIDER_LOCKED` and provider-owned
/// `INTERACTION_REQUIRED`; never combined with `decision_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProviderInteractionRef {
    /// The provider whose dialog it is.
    pub provider: ProviderKind,
    /// What it asks for.
    pub kind: InteractionKind,
}

/// Whether ssh can only use the adopted identity for an alias (ADR-0007 §3 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentitySelection {
    /// Only the adopted identity can be offered.
    Exclusive,
    /// Other identities the configuration adds can be offered.
    NotExclusive,
    /// Static evaluation cannot decide (for example behind `Match exec`).
    Undetermined,
}

/// The kind of an identity-list entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentityEntryKind {
    /// An `IdentityFile` entry.
    IdentityFile,
    /// A `CertificateFile` entry.
    CertificateFile,
}

/// Where an identity-list entry comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentityEntrySource {
    /// The Heimdall-managed projection.
    Managed,
    /// The user's configuration.
    User,
    /// The system configuration.
    System,
    /// ssh's default identity files.
    Default,
}

/// Whether a statically evaluated value is decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Certainty {
    /// Decided statically.
    Determined,
    /// Not decidable statically.
    Undetermined,
}

/// What backs an identity entry (ADR-0007 §7, F9): an agent when the private key
/// file is absent, a file when it is present (stat only; never opened).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentityBacking {
    /// Private key file absent: used through the alias's agent.
    Agent,
    /// Private key file present.
    File,
    /// Not established.
    Unknown,
}

/// `IdentitiesOnly` as statically evaluated for the alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentitiesOnly {
    /// Determined `yes`.
    DeterminedYes,
    /// Determined `no` (or unset).
    DeterminedNo,
    /// Not decidable statically.
    Undetermined,
}

/// One entry of an alias's identity list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentityEntry {
    /// Entry kind.
    pub kind: IdentityEntryKind,
    /// Where it comes from.
    pub source: IdentityEntrySource,
    /// Directive location, when it comes from a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ConfigProvenance>,
    /// Whether the entry is decided.
    pub certainty: Certainty,
    /// Public fingerprint (`SHA256:…`) read from the `.pub` file, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// What backs it.
    pub backing: IdentityBacking,
    /// Whether a fallback clearance (ADR-0007 §7, M2-R05) cleared it; present only
    /// where a clearance was evaluated (readiness, the pre-launch check, doctor).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleared: Option<bool>,
}

/// The static identity selection of an alias (ADR-0007 §3 item 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentitySelectionReport {
    /// The verdict.
    pub selection: IdentitySelection,
    /// Every entry ssh may try, in order.
    #[serde(default)]
    pub entries: Vec<IdentityEntry>,
    /// `IdentitiesOnly` for the alias.
    pub identities_only: IdentitiesOnly,
}

/// The transport of an agent endpoint.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EndpointKind {
    /// A Unix-domain socket path.
    UnixSocket,
    /// A Windows named pipe name.
    NamedPipe,
}

/// A reference to an agent endpoint. The locator is a path or pipe name, never a
/// secret; it is compared exactly (a changed locator lapses a declaration,
/// ADR-0007 §7).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct EndpointRef {
    /// Transport.
    pub kind: EndpointKind,
    /// Socket path or pipe name.
    pub locator: String,
}

/// The declaration a fresh eligibility relied on (ADR-0007 §7 "Launch eligibility is
/// checked fresh"). The CLI's pre-launch check requires the same revision and
/// endpoint and an unexpired `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeclarationRef {
    /// The declaration row's revision.
    pub revision: u64,
    /// The endpoint it covers.
    pub endpoint: EndpointRef,
    /// When it lapses.
    pub expires_at: Timestamp,
}

/// Whether a pair may be used on the no-interaction path, computed fresh per result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NoninteractiveEligibility {
    /// Eligible for non-interactive use.
    pub eligible: bool,
    /// Why not, when not: one of [`noninteractive_reason`]'s values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Stable values of [`NoninteractiveEligibility::reason`].
pub mod noninteractive_reason {
    /// The identity's interaction is `unknown` (including a lapsed declaration).
    pub const INTERACTION_UNKNOWN: &str = "interaction_unknown";
    /// The provider owns an interaction (1Password approval, a FIDO touch).
    pub const PROVIDER_INTERACTION: &str = "provider_interaction";
    /// An uncleared fallback identity may prompt (ADR-0007 §7, M2-R05).
    pub const FALLBACK_IDENTITY_INTERACTION: &str = "fallback_identity_interaction";
    /// Every value, in documentation order.
    pub const ALL: &[&str] = &[
        INTERACTION_UNKNOWN,
        PROVIDER_INTERACTION,
        FALLBACK_IDENTITY_INTERACTION,
    ];
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn provider_kind_wire_names() {
        for (kind, wire) in [
            (ProviderKind::NativeAgent, "\"native_agent\""),
            (ProviderKind::OnePassword, "\"onepassword\""),
            (ProviderKind::Unknown, "\"unknown\""),
        ] {
            assert_eq!(serde_json::to_string(&kind).unwrap(), wire);
            assert_eq!(serde_json::from_str::<ProviderKind>(wire).unwrap(), kind);
        }
    }

    #[test]
    fn credential_availability_defaults_to_unknown() {
        assert_eq!(
            CredentialAvailability::default(),
            CredentialAvailability::Unknown
        );
        assert_eq!(
            serde_json::to_string(&CredentialAvailability::InteractionRequired).unwrap(),
            "\"interaction_required\""
        );
    }

    #[test]
    fn probe_levels_order_weakest_first() {
        assert!(ProbeLevel::Static < ProbeLevel::Evaluate);
        assert!(ProbeLevel::HostVerification < ProbeLevel::Authentication);
        assert_eq!(
            serde_json::to_string(&ProbeLevel::HostVerification).unwrap(),
            "\"host_verification\""
        );
    }
}
