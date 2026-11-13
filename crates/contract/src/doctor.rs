//! The doctor report, its finding codes and probe records (ADR-0007 §6, §10;
//! m02-plan §5 item 11; schema `doctor-report`).
//!
//! Also the Git SSH-selection observations, which the doctor report, the setup
//! plan (`GitConfigChange`) and consumer overrides share (ADR-0007 §5.6, §8).
//!
//! Paths are display forms (`~` for the home directory). A Git configuration
//! *value* never appears here: only its scope, origin, a digest and a
//! classification (ADR-0007 §5.6). Finding codes and reasons are stable
//! `snake_case` strings; readers tolerate unknown ones.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::code::Code;
use crate::envelope::{NextAction, ResourceRef};
use crate::provider::{IdentitySelectionReport, ProbeLevel, ProviderStatus};
use crate::request::ConsumerKind;
use crate::setup::ConflictKind;

/// Maximum number of [`ConfigTreeDifference`] entries in one probe record (the
/// 256-file read bound, ADR-0007 §6).
pub const MAX_CONFIG_TREE_DIFFERENCES: usize = 256;

/// Where a configuration directive was read: a display path and a 1-based line.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct ConfigProvenance {
    /// Display path (`~` for the home directory; `--redact` aware).
    pub path_display: String,
    /// 1-based line number.
    pub line: u32,
}

/// Whether a directive's static value is decided (ADR-0007 §6 three-valued
/// evaluation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DirectiveCertainty {
    /// One value, decided.
    Determined,
    /// Several candidate values; static evaluation cannot choose.
    Undetermined,
    /// Not set.
    Unset,
}

/// One directive of an alias's relevant behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DirectiveObservation {
    /// Directive keyword (canonical case, e.g. `IdentityAgent`).
    pub directive: String,
    /// The value (determined) or the candidate values (undetermined); empty when
    /// unset.
    #[serde(default)]
    pub values: Vec<String>,
    /// Certainty.
    pub certainty: DirectiveCertainty,
    /// Where each value or candidate was read.
    #[serde(default)]
    pub provenance: Vec<ConfigProvenance>,
}

/// How a client executable was found (U3 `ClientSource`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ClientSource {
    /// Found on `PATH`.
    Path,
    /// The Windows in-box `System32\OpenSSH` client.
    System32,
    /// The client bundled with Git for Windows.
    GitBundled,
    /// Named in `config.toml` `[clients]`.
    Configured,
}

/// One client executable candidate (R-SS-03: path, version and SHA-256 reported).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClientObservation {
    /// Which consumer program.
    pub consumer: ConsumerKind,
    /// Display path.
    pub path_display: String,
    /// How it was found.
    pub source: ClientSource,
    /// Reported version (`OpenSSH_9.5p2`), when a local query ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// SHA-256 of the executable, lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Whether this is the verified client Heimdall selects.
    pub selected: bool,
}

/// The role of a configuration file in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConfigFileRole {
    /// The user's `~/.ssh/config`.
    User,
    /// The system `ssh_config`.
    System,
    /// A file reached through `Include`.
    Included,
    /// The Heimdall-managed include file P.
    Managed,
    /// The global Git configuration file.
    GitGlobal,
    /// The Heimdall-managed Git file P_git.
    GitManaged,
}

/// One configuration file the static pass read or tried to read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConfigFileObservation {
    /// Display path.
    pub path_display: String,
    /// Role.
    pub role: ConfigFileRole,
    /// Whether it could be read within the bounds.
    pub readable: bool,
    /// SHA-256 of its content, lowercase hex, when read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Size in bytes, when read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

/// How an alias is defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AliasDefinition {
    /// Rendered by Heimdall into P.
    Managed,
    /// A catalog destination whose definition stays in the user's file.
    Observed,
    /// Only in the user's configuration; not in the catalog.
    UserOnly,
}

/// One alias's statically evaluated behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AliasObservation {
    /// The alias (`--redact` aware).
    pub alias: String,
    /// How it is defined.
    pub definition: AliasDefinition,
    /// Its relevant directives.
    #[serde(default)]
    pub behavior: Vec<DirectiveObservation>,
    /// Its identity selection, when evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_selection: Option<IdentitySelectionReport>,
}

/// The state of the managed projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProjectionState {
    /// No projection is installed.
    Absent,
    /// Installed and matching its record.
    Healthy,
    /// A conflict was found (see `conflict`).
    Conflict,
    /// Manual mode: Heimdall writes P but not the user file.
    Manual,
    /// The include block is conditional (inside `Host` or `Match`).
    Conditional,
}

/// The managed projection as the doctor sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProjectionObservation {
    /// State.
    pub state: ProjectionState,
    /// Recorded generation, when one is recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    /// The conflict, when `state` is `conflict`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict: Option<ConflictKind>,
}

/// A Git configuration scope (`git config --show-scope`).
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
pub enum GitScope {
    /// System file.
    System,
    /// Global file (`~/.gitconfig` or the XDG file).
    Global,
    /// Repository file.
    Local,
    /// Worktree file.
    Worktree,
    /// Command scope (`-c`, `GIT_CONFIG_COUNT`).
    Command,
}

/// Where Git's effective SSH program comes from (ADR-0007 F22 order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GitSshSource {
    /// `GIT_SSH_COMMAND` in the environment.
    EnvGitSshCommand,
    /// `core.sshCommand` at its winning scope.
    Config,
    /// `GIT_SSH` in the environment.
    EnvGitSsh,
    /// Git's default.
    Default,
}

/// What Git's effective SSH program is (the value itself is never reported).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GitSshClassification {
    /// The verified client.
    VerifiedClient,
    /// Git for Windows' bundled MSYS ssh.
    BundledMsys,
    /// Something else.
    Other,
    /// Not established.
    Undetermined,
}

/// Git's effective SSH selection (ADR-0007 §5.6, §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GitSshSelection {
    /// Where it comes from.
    pub source: GitSshSource,
    /// The winning scope, for `config`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<GitScope>,
    /// What it is.
    pub classification: GitSshClassification,
}

/// One observed `core.sshCommand` value, by digest only (ADR-0007 §5.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GitValueObservation {
    /// Scope.
    pub scope: GitScope,
    /// Display origin (`file:~/.gitconfig`), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_display: Option<String>,
    /// SHA-256 of the value, lowercase hex.
    pub value_sha256: String,
    /// How many times the value occurs at this origin.
    pub count: u32,
    /// Reached through `includeIf` (counted whatever the condition).
    #[serde(default)]
    pub conditional: bool,
}

/// Git as the doctor sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GitObservation {
    /// Effective selection.
    pub selection: GitSshSelection,
    /// Every observed value that is a user's. Heimdall's own value, reached once through
    /// its intact include block, is not listed: it is the effective selection above
    /// (ADR-0007 §12.37 item 1).
    #[serde(default)]
    pub values: Vec<GitValueObservation>,
}

/// Finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FindingSeverity {
    /// Informational.
    Info,
    /// Worth attention.
    Warning,
    /// Breaks or weakens access.
    Problem,
}

/// One doctor or preview finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Finding {
    /// Stable code: one of [`finding`]'s values (readers tolerate unknown ones).
    pub code: String,
    /// Severity.
    pub severity: FindingSeverity,
    /// What it concerns.
    pub subject: ResourceRef,
    /// The probe level that found it.
    pub level: ProbeLevel,
    /// Configuration location, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ConfigProvenance>,
    /// Human text; never contains secrets.
    pub message: String,
    /// The remedy.
    pub next: NextAction,
    /// Stable `snake_case` sub-reason (for example `modified_after_exchange` on
    /// `conflict_artifact_present`, the hold reason on `projection_held`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Stable finding codes (m02-plan §5 item 11).
pub mod finding {
    /// The configuration is invalid for ssh.
    pub const CONFIG_INVALID: &str = "config_invalid";
    /// A `Match exec` or `localnetwork` section cannot be decided statically.
    pub const DYNAMIC_MATCH_UNRESOLVED: &str = "dynamic_match_unresolved";
    /// A directive that executes a program is present.
    pub const EXECUTABLE_DIRECTIVE_PRESENT: &str = "executable_directive_present";
    /// An included file is missing.
    pub const INCLUDE_MISSING: &str = "include_missing";
    /// The include block is conditional.
    pub const INCLUDE_CONDITIONAL: &str = "include_conditional";
    /// The include block is not first.
    pub const INCLUDE_NOT_FIRST: &str = "include_not_first";
    /// The projection file was edited.
    pub const PROJECTION_EDITED: &str = "projection_edited";
    /// A marker line was edited.
    pub const MARKER_EDITED: &str = "marker_edited";
    /// A managed alias collides with a user alias.
    pub const ALIAS_COLLISION: &str = "alias_collision";
    /// Identity selection is not exclusive.
    pub const IDENTITY_SELECTION_NOT_EXCLUSIVE: &str = "identity_selection_not_exclusive";
    /// Identity selection is undetermined.
    pub const IDENTITY_SELECTION_UNDETERMINED: &str = "identity_selection_undetermined";
    /// The effective `IdentityAgent` overrides the provider endpoint.
    pub const IDENTITY_AGENT_OVERRIDDEN: &str = "identity_agent_overridden";
    /// Too many identities may be offered.
    pub const TOO_MANY_IDENTITIES: &str = "too_many_identities";
    /// `StrictHostKeyChecking` is weakened.
    pub const STRICT_HOST_KEY_CHECKING_WEAK: &str = "strict_host_key_checking_weak";
    /// A configuration file's permissions are unsafe.
    pub const CONFIG_PERMISSIONS_UNSAFE: &str = "config_permissions_unsafe";
    /// A directive is not supported by the parser.
    pub const PARSE_UNSUPPORTED_DIRECTIVE: &str = "parse_unsupported_directive";
    /// A read bound was exceeded.
    pub const BOUND_EXCEEDED: &str = "bound_exceeded";
    /// A file's encoding is not supported.
    pub const UNSUPPORTED_ENCODING: &str = "unsupported_encoding";
    /// The atomic exchange is not supported on this filesystem.
    pub const ATOMIC_EXCHANGE_UNSUPPORTED: &str = "atomic_exchange_unsupported";
    /// A conflict artifact is present.
    pub const CONFLICT_ARTIFACT_PRESENT: &str = "conflict_artifact_present";
    /// A displaced entry is missing.
    pub const DISPLACED_MISSING: &str = "displaced_missing";
    /// A setup operation is held for the owner.
    pub const PROJECTION_HELD: &str = "projection_held";
    /// A client executable was not found.
    pub const CLIENT_NOT_FOUND: &str = "client_not_found";
    /// A client's version is below the floor.
    pub const CLIENT_UNSUPPORTED_VERSION: &str = "client_unsupported_version";
    /// Git's SSH program cannot reach the agent.
    pub const GIT_SSH_UNREACHABLE_AGENT: &str = "git_ssh_unreachable_agent";
    /// A `core.sshCommand` value is present.
    pub const GIT_SSH_COMMAND_PRESENT: &str = "git_ssh_command_present";
    /// `GIT_CONFIG_GLOBAL` redirects the global file.
    pub const GIT_GLOBAL_REDIRECTED: &str = "git_global_redirected";
    /// Git's configuration lock is held.
    pub const GIT_CONFIG_LOCK_HELD: &str = "git_config_lock_held";
    /// A Git configuration file is unreadable.
    pub const GIT_CONFIG_UNREADABLE: &str = "git_config_unreadable";
    /// A user Git value in another global file is shadowed by the managed one: Heimdall's
    /// `core.sshCommand` is the effective value and a user's, read before it, loses
    /// (ADR-0007 §5.6, §12.37 item 2).
    pub const GIT_USER_VALUE_SHADOWED: &str = "git_user_value_shadowed";
    /// The agent endpoint is missing.
    pub const AGENT_ENDPOINT_MISSING: &str = "agent_endpoint_missing";
    /// The agent endpoint is owned by another user.
    pub const AGENT_ENDPOINT_FOREIGN_OWNER: &str = "agent_endpoint_foreign_owner";
    /// The identity is not listed by its agent.
    pub const IDENTITY_NOT_LISTED: &str = "identity_not_listed";
    /// The identity's public key is unknown (no `.pub`).
    pub const IDENTITY_PUBLIC_KEY_UNKNOWN: &str = "identity_public_key_unknown";
    /// A key file's permissions are unsafe.
    pub const KEY_FILE_PERMISSIONS_UNSAFE: &str = "key_file_permissions_unsafe";
    /// The identity's interaction is unknown.
    pub const INTERACTION_UNKNOWN: &str = "interaction_unknown";
    /// An interaction declaration lapsed.
    pub const INTERACTION_DECLARATION_LAPSED: &str = "interaction_declaration_lapsed";
    /// No `known_hosts` entry for the destination.
    pub const KNOWN_HOST_MISSING: &str = "known_host_missing";
    /// The `known_hosts` entry does not match.
    pub const KNOWN_HOST_MISMATCH: &str = "known_host_mismatch";
    /// The account home differs from `$HOME`.
    pub const HOME_MISMATCH: &str = "home_mismatch";

    /// Every code, in documentation order (configuration, clients, agents and
    /// identities, host trust, environment).
    pub const ALL: &[&str] = &[
        CONFIG_INVALID,
        DYNAMIC_MATCH_UNRESOLVED,
        EXECUTABLE_DIRECTIVE_PRESENT,
        INCLUDE_MISSING,
        INCLUDE_CONDITIONAL,
        INCLUDE_NOT_FIRST,
        PROJECTION_EDITED,
        MARKER_EDITED,
        ALIAS_COLLISION,
        IDENTITY_SELECTION_NOT_EXCLUSIVE,
        IDENTITY_SELECTION_UNDETERMINED,
        IDENTITY_AGENT_OVERRIDDEN,
        TOO_MANY_IDENTITIES,
        STRICT_HOST_KEY_CHECKING_WEAK,
        CONFIG_PERMISSIONS_UNSAFE,
        PARSE_UNSUPPORTED_DIRECTIVE,
        BOUND_EXCEEDED,
        UNSUPPORTED_ENCODING,
        ATOMIC_EXCHANGE_UNSUPPORTED,
        CONFLICT_ARTIFACT_PRESENT,
        DISPLACED_MISSING,
        PROJECTION_HELD,
        CLIENT_NOT_FOUND,
        CLIENT_UNSUPPORTED_VERSION,
        GIT_SSH_UNREACHABLE_AGENT,
        GIT_SSH_COMMAND_PRESENT,
        GIT_GLOBAL_REDIRECTED,
        GIT_CONFIG_LOCK_HELD,
        GIT_CONFIG_UNREADABLE,
        GIT_USER_VALUE_SHADOWED,
        AGENT_ENDPOINT_MISSING,
        AGENT_ENDPOINT_FOREIGN_OWNER,
        IDENTITY_NOT_LISTED,
        IDENTITY_PUBLIC_KEY_UNKNOWN,
        KEY_FILE_PERMISSIONS_UNSAFE,
        INTERACTION_UNKNOWN,
        INTERACTION_DECLARATION_LAPSED,
        KNOWN_HOST_MISSING,
        KNOWN_HOST_MISMATCH,
        HOME_MISMATCH,
    ];

    /// ⟨M03⟩ A re-verification ended inconclusive (the record stays `verified`).
    pub const REVERIFICATION_INCONCLUSIVE: &str = "reverification_inconclusive";
    /// ⟨M03⟩ An enrollment's evidence is no longer fresh.
    pub const ENROLLMENT_EVIDENCE_STALE: &str = "enrollment_evidence_stale";
    /// ⟨M03⟩ The verified client's trace family or version is unrecorded (names both).
    pub const CLIENT_TRACE_FAMILY_UNRECORDED: &str = "client_trace_family_unrecorded";
    /// ⟨M03⟩ A managed alias's slot is free (with the command that holds one).
    pub const SLOT_FREE: &str = "slot_free";
    /// ⟨M03⟩ A directory under the managed runtime directory is not owner-only, so binding
    /// clears refuse until it is removed (ADR-0008 §17.20 item 15: "the doctor (U12) reports
    /// it"; nothing is repaired silently).
    pub const MANAGED_DIR_UNSAFE: &str = "managed_dir_unsafe";

    /// ⟨M03⟩ The findings M03 adds (m03-plan §5 item 14); [`ALL`] stays M02's list.
    pub const M03: &[&str] = &[
        REVERIFICATION_INCONCLUSIVE,
        ENROLLMENT_EVIDENCE_STALE,
        CLIENT_TRACE_FAMILY_UNRECORDED,
        SLOT_FREE,
        MANAGED_DIR_UNSAFE,
    ];
}

/// How a probe level ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProbeOutcome {
    /// Completed.
    Ok,
    /// Completed with a failure.
    Failed,
    /// Timed out and was stopped.
    Timeout,
    /// Refused (for example a non-interactive authentication with an interactive
    /// identity).
    Refused,
    /// Not run; see `decline_reason`.
    Declined,
}

/// An effect Heimdall enforced did not happen during a level (ADR-0007 §6).
/// Whenever configuration commands ran, a record excludes nothing they could do.
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
pub enum ExcludedEffect {
    /// No configuration command ran.
    ConfigExecution,
    /// No agent was contacted.
    AgentContact,
    /// No provider was contacted.
    ProviderContact,
    /// No network was used.
    Network,
    /// Nothing was signed.
    Signing,
    /// Nothing was changed.
    Mutation,
}

/// How a probe's children were contained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Containment {
    /// No child was started.
    None,
    /// Unix process group (a descendant that leaves it is not contained).
    ProcessGroup,
    /// Windows job object with kill-on-close.
    JobObject,
}

/// How a file differs between the static pass's snapshot and the one taken after
/// the level (ADR-0007 §6 "After the run").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TreeChange {
    /// Reached only after the level.
    Added,
    /// Reached only before the level.
    Removed,
    /// Content digest differs.
    Modified,
    /// Unreadable in the second snapshot.
    Unreadable,
}

/// One difference between the two configuration-tree snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConfigTreeDifference {
    /// Display path.
    pub path_display: String,
    /// The change.
    pub change: TreeChange,
}

/// What one probe level did (ADR-0007 §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProbeRecord {
    /// The level.
    pub level: ProbeLevel,
    /// What it targeted (an alias, an endpoint display form, or `*`).
    pub target: String,
    /// When it started.
    pub started_at: Timestamp,
    /// How long it ran.
    pub duration_ms: u64,
    /// How it ended.
    pub outcome: ProbeOutcome,
    /// Why it was declined: one of [`decline_reason`]'s values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<String>,
    /// The code it ended with, when it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Code>,
    /// The authorizations given (for example `allow_config_commands`).
    #[serde(default)]
    pub authorization: Vec<String>,
    /// The executing constructs the static pass found **before** the run. Never
    /// complete: the run may have executed others.
    #[serde(default)]
    pub executed_config_commands: Vec<ConfigProvenance>,
    /// The effects Heimdall enforced did not happen.
    #[serde(default)]
    pub effects_excluded: BTreeSet<ExcludedEffect>,
    /// How children were contained.
    pub containment: Containment,
    /// Whether the snapshot after the level differs from the static pass's; absent
    /// for levels that run no configuration. `false` is not proof that the tree was
    /// unchanged while ssh read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_tree_changed: Option<bool>,
    /// The differences (at most [`MAX_CONFIG_TREE_DIFFERENCES`]).
    #[serde(default)]
    pub config_tree_differences: Vec<ConfigTreeDifference>,
}

/// Stable values of [`ProbeRecord::decline_reason`].
pub mod decline_reason {
    /// A real-tree level without `--allow-config-commands`.
    pub const CONFIG_COMMANDS_NOT_AUTHORIZED: &str = "config_commands_not_authorized";
    /// The static pass could not fully read the alias's tree.
    pub const CONFIG_NOT_FULLY_READABLE: &str = "config_not_fully_readable";
    /// Every value.
    pub const ALL: &[&str] = &[CONFIG_COMMANDS_NOT_AUTHORIZED, CONFIG_NOT_FULLY_READABLE];
}

/// The doctor report (`heimdall doctor --json` data; schema `doctor-report`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DoctorReport {
    /// Every level performed.
    pub levels_performed: BTreeSet<ProbeLevel>,
    /// Every level declined (with its reason in `probes`).
    #[serde(default)]
    pub levels_declined: BTreeSet<ProbeLevel>,
    /// Client executables.
    #[serde(default)]
    pub clients: Vec<ClientObservation>,
    /// Configuration files.
    #[serde(default)]
    pub config_files: Vec<ConfigFileObservation>,
    /// Aliases.
    #[serde(default)]
    pub aliases: Vec<AliasObservation>,
    /// Providers.
    #[serde(default)]
    pub providers: Vec<ProviderStatus>,
    /// The managed projection, when the store could be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<ProjectionObservation>,
    /// Git, when a `git` executable was found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<GitObservation>,
    /// Findings.
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// One record per level performed or declined.
    #[serde(default)]
    pub probes: Vec<ProbeRecord>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn finding_codes_are_unique_snake_case() {
        let mut seen = std::collections::BTreeSet::new();
        for code in finding::ALL {
            assert!(
                !code.is_empty()
                    && code
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit()),
                "{code}"
            );
            assert!(seen.insert(*code), "duplicate {code}");
        }
        assert_eq!(finding::ALL.len(), 40);
        assert!(!seen.contains("inherited_identities"), "withdrawn in r2");
    }

    #[test]
    fn excluded_effects_are_a_set_in_wire_order() {
        let set: BTreeSet<ExcludedEffect> = [ExcludedEffect::Mutation, ExcludedEffect::Network]
            .into_iter()
            .collect();
        assert_eq!(
            serde_json::to_string(&set).unwrap(),
            r#"["network","mutation"]"#
        );
    }
}
