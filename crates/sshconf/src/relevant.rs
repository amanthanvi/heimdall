//! The behaviour that matters for access, reduced from an [`Evaluation`] (m02-plan
//! U2; ADR-0007 §3, §5.2).

use std::path::Path;

use heimdall_contract::provider::IdentitySelectionReport;
use heimdall_domain::projection::{BehaviorDigest, BehaviorState};

use crate::directive::KnownKeyword;
use crate::eval::{Candidate, Evaluation, Resolved, Unresolved, Value};
use crate::include::ConfigSource;
use crate::parse::Span;

/// Which proxy competes and wins (F10: `ProxyJump` and `ProxyCommand` compete; the
/// first obtained of the two wins).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proxy {
    /// Neither applies (or `none`).
    None,
    /// `ProxyJump`.
    Jump(Value),
    /// `ProxyCommand` (never run here).
    Command(Value),
}

/// The proxy outcome of an evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyResolution {
    /// Known.
    Determined(Proxy),
    /// One of these, depending on something not evaluated.
    Undetermined(Vec<Proxy>),
}

/// The directives that decide how a host is reached and authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelevantBehavior {
    /// `HostName`.
    pub hostname: Resolved,
    /// `Port`.
    pub port: Resolved,
    /// `User`.
    pub user: Resolved,
    /// `IdentityAgent`.
    pub identity_agent: Resolved,
    /// `IdentityFile`, in order.
    pub identity_files: Vec<Candidate>,
    /// `IdentitiesOnly`.
    pub identities_only: Resolved,
    /// `CertificateFile`, in order.
    pub certificate_files: Vec<Candidate>,
    /// `ProxyJump`/`ProxyCommand` under F10.
    pub proxy: ProxyResolution,
    /// `ControlMaster`.
    pub control_master: Resolved,
    /// `ControlPath`.
    pub control_path: Resolved,
    /// `ControlPersist`.
    pub control_persist: Resolved,
    /// `ForwardAgent`.
    pub forward_agent: Resolved,
    /// `StrictHostKeyChecking`.
    pub strict_host_key_checking: Resolved,
    /// `UserKnownHostsFile`.
    pub user_known_hosts_file: Resolved,
    /// `GlobalKnownHostsFile`.
    pub global_known_hosts_file: Resolved,
    /// `HostKeyAlias`.
    pub host_key_alias: Resolved,
    /// `CanonicalizeHostname`.
    pub canonicalize_hostname: Resolved,
    /// `PermitLocalCommand`.
    pub permit_local_command: Resolved,
    /// `LocalCommand`.
    pub local_command: Resolved,
    /// `KnownHostsCommand`.
    pub known_hosts_command: Resolved,
    /// `AddKeysToAgent`.
    pub add_keys_to_agent: Resolved,
    /// `PKCS11Provider`.
    pub pkcs11_provider: Resolved,
    /// `SecurityKeyProvider`.
    pub security_key_provider: Resolved,
}

/// One relevant directive whose resolved state differs between two behaviours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehaviorChange {
    /// The directive.
    pub directive: KnownKeyword,
    /// Before.
    pub before: Resolved,
    /// After.
    pub after: Resolved,
}

/// Reduce an evaluation to its relevant behaviour.
#[must_use]
pub fn relevant(evaluation: &Evaluation) -> RelevantBehavior {
    let _ = evaluation;
    todo!("M02-U2 relevant::relevant")
}

/// The relevant directives whose state differs.
#[must_use]
pub fn diff(before: &RelevantBehavior, after: &RelevantBehavior) -> Vec<BehaviorChange> {
    let _ = (before, after);
    todo!("M02-U2 relevant::diff")
}

/// The behaviour's digest, with provenance reduced to its source role (a moved line
/// or a comment does not change it; a value does; ADR-0007 §5.2).
#[must_use]
pub fn behavior_digest(behavior: &RelevantBehavior) -> BehaviorDigest {
    let _ = behavior;
    todo!("M02-U2 relevant::behavior_digest")
}

/// The digest and whether every directive is determined (M2-R03).
#[must_use]
pub fn behavior_state(behavior: &RelevantBehavior) -> BehaviorState {
    let _ = behavior;
    todo!("M02-U2 relevant::behavior_state")
}

/// Which identities ssh may offer for the alias, and whether the adopted key is the
/// only one (ADR-0007 §3 item 3). `source` is used only to stat for a private key's
/// presence and to read `.pub` files; a private key file is never opened.
#[must_use]
pub fn identity_selection(
    evaluation: &Evaluation,
    adopted: &Path,
    source: &dyn ConfigSource,
) -> IdentitySelectionReport {
    let _ = (evaluation, adopted, source);
    todo!("M02-U2 relevant::identity_selection")
}

/// Every construct that runs a command: `Match exec`, `ProxyCommand`,
/// `KnownHostsCommand`, and `LocalCommand` with `PermitLocalCommand`.
#[must_use]
pub fn executing_constructs(evaluation: &Evaluation) -> Vec<Span> {
    let _ = evaluation;
    todo!("M02-U2 relevant::executing_constructs")
}

/// The unresolved points that make the tree not fully readable for the probes
/// (`IncludeUnreadable`, `BoundExceeded`, a `TokenUnavailable` in an `Include`;
/// ADR-0007 §6).
#[must_use]
pub fn unreadable_includes(evaluation: &Evaluation) -> Vec<Unresolved> {
    let _ = evaluation;
    todo!("M02-U2 relevant::unreadable_includes")
}
