//! Capability and enforcement evidence (spec §4.3, §3.3; R-AU-08, R-SE-03).
//! Every enforcement claim references evidence, supported versions and a test.
//! `Unknown` is a valid state.

use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::request::Enforcement;
use serde::{Deserialize, Serialize};

/// Compatibility label (spec §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportLabel {
    /// Verified by a recorded test.
    Verified,
    /// Works with recorded limitations.
    SupportedWithLimitations,
    /// Experimental.
    Experimental,
    /// Unsupported.
    Unsupported,
    /// Not tested.
    NotTested,
}

/// One piece of evidence behind a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// Mechanism named (e.g. `openssh_certificate_principals`).
    pub mechanism: String,
    /// Test or evidence record ID (e.g. `A10`, `g04-exp-e3`).
    pub test_id: Option<String>,
    /// Versions observed (client, server, provider).
    pub versions: Vec<String>,
    /// When observed.
    pub observed_at: Timestamp,
    /// How long the observation is considered fresh.
    pub freshness: Duration,
    /// Label.
    pub label: SupportLabel,
}

impl EvidenceRef {
    /// Whether the evidence is still within its freshness window at `now`.
    #[must_use]
    pub fn is_fresh_at(&self, now: Timestamp) -> bool {
        let Ok(span) = jiff::SignedDuration::try_from(self.freshness) else {
            return false;
        };
        match self.observed_at.checked_add(span) {
            Ok(until) => now < until,
            Err(_) => false,
        }
    }
}

/// Enforcement report plus the evidence behind each field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementEvidence {
    /// The wire-level report.
    pub report: Enforcement,
    /// Evidence for the report (may be empty, in which case fields must be
    /// `Unknown` or the weakest label).
    pub evidence: Vec<EvidenceRef>,
}

impl EnforcementEvidence {
    /// A report that claims nothing (every field `Unknown`).
    #[must_use]
    pub fn unknown() -> Self {
        use heimdall_contract::request::{
            DestinationScopeEnforcement, ExistingConnectionsPolicy, NewAuthenticationExpiry,
            RevocationStatus, WorkloadIsolation,
        };
        Self {
            report: Enforcement::new(
                DestinationScopeEnforcement::Unknown,
                NewAuthenticationExpiry::Unknown,
                WorkloadIsolation::Unknown,
                ExistingConnectionsPolicy::Unknown,
                RevocationStatus::Unknown,
            ),
            evidence: Vec::new(),
        }
    }
}
