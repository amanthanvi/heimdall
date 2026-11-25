//! ⟨rev7⟩ The lifecycle contract of M08 (ADR-0014 §3, §5, §7: H1–H7, H10, H13; the contract
//! owner's rulings on U0-Q5, Q6 and Q8). **Declared, not served.** Every type here is
//! standalone: no emitter builds it, and no live document carries it, until its unit lands
//! (U2b for the state commands, the stop preview and the epoch; U6b for the support bundle;
//! U3 for the build provenance). The CLI's new commands answer "not available in this
//! build" until then.
//!
//! * [`SupportBundleManifest`] (H1): `manifest.json` of `heimdall-support-bundle/1`.
//! * [`StopPreview`] (H2): `service stop --preview`, read-only, complete.
//! * [`StateStatus`], [`RestoreReport`], [`ResetReport`], [`RepairReport`] (H3, Q8).
//! * [`StateRestoredPayload`] (H4, H10): the payload of the `state_restored` event
//!   ([`STATE_RESTORED_EVENT`]), one event for both deltas (ruling on ASK-H10).
//! * [`BuildProvenance`] (H7).
//! * [`RestoreEpoch`] and [`REQUEST_EPOCH_FIELD`] (H13, Q5): the epoch in the hello and on
//!   every mutating request frame.
//! * The doctor finding [`EXECUTABLE_MOVED`] (H5) and the residue kinds of
//!   [`residue_kind`] (H6), as names: the `RemainingArtifactKind` and doctor variants join
//!   with their emitters, so no published schema changes now.

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::ids::EnvironmentId;

// --- H13: the restore epoch --------------------------------------------------------------

/// A restore epoch (ADR-0014 §3.6 "The restore epoch and the replay fence"). Every restore
/// raises it, durably, before its pointer moves; a store with no restore is at epoch 0, and
/// every reference minted before revision 7's migration belongs to epoch 0.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct RestoreEpoch(pub u64);

/// The name of the optional field a request frame carries (`ClientMessage::Request`, beside
/// `seq` and `request`): the epoch the frame's request ID was minted under. It is outside
/// every canonical request hash, so every existing hash is unchanged and a retry with the
/// same epoch matches. A mutating request whose epoch is not the current one is refused
/// `REQUEST_STALE` / `restore_epoch_stale` before any store write or effect, attended or
/// not; one with no epoch is bound to the current epoch at receipt, and a fence record for
/// its key then answers `REQUEST_STALE` / `restored_before_completion`. Sent only on a
/// session that negotiated [`crate::ipc::capability::REQUEST_EPOCH_V1`]: a client holding
/// a kept epoch refuses (`SCHEMA_UNSUPPORTED`) instead of sending it to a runtime that does
/// not offer it, and a fresh request with no kept epoch is sent without one.
pub const REQUEST_EPOCH_FIELD: &str = "request_epoch";

/// The name of the hello field that reports the runtime's current epoch (`ServerHello`).
pub const HELLO_EPOCH_FIELD: &str = "restore_epoch";

/// The code a stale request answers (ADR-0014 H13; ruling on U0-Q6): exit class 6
/// (conflict), not retryable, effect `none`, next action `new_request_id`. **Declared in
/// the reason table only** (ruling on ASK-CODE): `Code` gains it, with `schema show codes`
/// and `codes.json`, in the change that adds its emitter and both harnesses' tables.
pub const REQUEST_STALE: &str = "REQUEST_STALE";

/// [`REQUEST_STALE`]'s exit class.
pub const REQUEST_STALE_EXIT: i32 = 6;

/// [`REQUEST_STALE`]'s default next action.
pub const REQUEST_STALE_NEXT: &str = "new_request_id";

// --- H5, H6: names --------------------------------------------------------------------------

/// ⟨H5⟩ The doctor finding for an integration entry (login entry, shell hook, route helper,
/// WSL helper) that names an executable path which no longer holds this executable, with
/// its repair command (ADR-0014 §3.2 item 12). Declared; `doctor` produces it in U2b.
pub const EXECUTABLE_MOVED: &str = "executable_moved";

/// ⟨H6⟩ The residue kinds a lifecycle step leaves for the owner (ADR-0014 §3.4). Declared;
/// `RemainingArtifactKind` gains them with their emitters (U2b), so `setup-result`'s
/// published schema is unchanged now.
pub mod residue_kind {
    /// A migration backup, `<store>.v<N>.backup*`.
    pub const MIGRATION_BACKUP: &str = "migration_backup";
    /// An earlier store generation kept by a restore or a reset.
    pub const EARLIER_STORE_GENERATION: &str = "earlier_store_generation";
    /// The previous binary an update kept (`heimdall.previous`).
    pub const PREVIOUS_BINARY: &str = "previous_binary";
    /// A Heimdall include block the owner moved to the other global Git file.
    pub const GIT_BLOCK_MOVED: &str = "git_block_moved";
    /// Every kind, in ADR-0014 §7 H6's order.
    pub const ALL: &[&str] = &[
        MIGRATION_BACKUP,
        EARLIER_STORE_GENERATION,
        PREVIOUS_BINARY,
        GIT_BLOCK_MOVED,
    ];
}

// --- H7: build provenance ------------------------------------------------------------------

/// ⟨H7⟩ What build this is (ADR-0014 §4.4): in the version output and `inspect
/// capabilities` once attached (U3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BuildProvenance {
    /// The source commit, 40 lowercase hex.
    pub commit: String,
    /// The target triple.
    pub target: String,
    /// The cargo profile (`release`, `debug`).
    pub profile: String,
    /// The enabled cargo features, sorted.
    #[serde(default)]
    pub features: Vec<String>,
}

// --- H1: the support bundle's manifest ---------------------------------------------------

/// The support bundle's container format name.
pub const SUPPORT_BUNDLE_FORMAT: &str = "heimdall-support-bundle";

/// The support bundle's container format version.
pub const SUPPORT_BUNDLE_FORMAT_VERSION: u64 = 1;

/// ⟨H1⟩ `manifest.json` of a support bundle (ADR-0014 §5.1): every other file's name, size
/// and digest, the withheld counts, the pseudonym counts and whether identifiers were
/// included. It holds codes and counts only, never free text. Its SHA-256 is the bundle's
/// digest. (The writer is `crates/support`; this type is the published shape.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SupportBundleManifest {
    /// [`SUPPORT_BUNDLE_FORMAT`].
    pub format: String,
    /// [`SUPPORT_BUNDLE_FORMAT_VERSION`].
    pub format_version: u64,
    /// `pseudonymized`, or `included` with `--include-identifiers`.
    pub identifiers: BundleIdentifiers,
    /// Every file after the manifest, in order.
    pub files: Vec<BundleFile>,
    /// Withheld values per field path.
    #[serde(default)]
    pub withheld: std::collections::BTreeMap<String, u64>,
    /// Withheld values per reason (`free_text`, `secret`, `malformed`,
    /// `failed_secret_check`).
    #[serde(default)]
    pub withheld_by_reason: std::collections::BTreeMap<String, u64>,
    /// Every withheld value.
    pub withheld_total: u64,
    /// Pseudonyms assigned per kind (`user`, `host`, `alias`, `label`, `path`, `fp`,
    /// `comment`, `id`).
    #[serde(default)]
    pub pseudonyms: std::collections::BTreeMap<String, u64>,
}

/// Whether a bundle's identifiers are pseudonyms or the values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BundleIdentifiers {
    /// Every identifier is a pseudonym; the inverse map stays on the machine.
    Pseudonymized,
    /// Identifiers typed as public were written as they are.
    Included,
}

/// One file of a support bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BundleFile {
    /// The file's name.
    pub name: String,
    /// Its length in bytes.
    pub bytes: u64,
    /// Its SHA-256, lowercase hex.
    pub sha256: String,
}

// --- H2: the stop preview --------------------------------------------------------------------

/// ⟨H2⟩ What stopping the runtime interrupts (ADR-0014 §3.2 item 2, §3.3): read-only,
/// complete, changes nothing. An emergency restart prints the same list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StopPreview {
    /// Whether a runtime is serving now (nothing is interrupted when none is).
    pub running: bool,
    /// Operations not yet terminal: they settle or are reported, and are recovered or
    /// reported after restart.
    pub open_operations: u64,
    /// Bindings with a live holder: the child keeps running, its endpoint is gone until
    /// restart.
    pub held_bindings: u64,
    /// Working keys held only in memory: gone, re-issued within their terms after restart.
    pub in_memory_keys: u64,
    /// Owned multiplexing masters and dedicated connections, and what happens to each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owned_connections: Vec<StopPreviewItem>,
    /// WSL bridges and container endpoints that become unavailable inside their
    /// environment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment_endpoints: Vec<StopPreviewItem>,
    /// The transport and runner state that stops (a served Iroh endpoint; a runner issues
    /// nothing while down).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote: Vec<StopPreviewItem>,
    /// Migration backups present (residue, ADR-0014 §3.4).
    #[serde(default)]
    pub migration_backups: u64,
    /// The macOS note: the issuer may lose access to its CA key after an update of a build
    /// without a Developer ID signature, and whether an offline backup is recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_key_access: Option<IssuerKeyAccessNote>,
}

/// One interrupted item of a [`StopPreview`]: its kind, its ID, and what happens to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StopPreviewItem {
    /// The item's kind (`connection`, `master`, `wsl_bridge`, `container_endpoint`,
    /// `iroh_endpoint`, `runner`).
    pub kind: String,
    /// Its opaque ID.
    pub id: String,
    /// What stopping does to it (`closed`, `left_to_client`, `unavailable_until_restart`).
    pub effect: String,
}

/// The macOS update note of a [`StopPreview`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IssuerKeyAccessNote {
    /// Whether the issuer may lose access to its CA key after an update.
    pub may_lose_access: bool,
    /// Whether an offline recovery bundle is recorded.
    pub offline_backup_recorded: bool,
}

// --- H3, Q8: the state commands ------------------------------------------------------------

/// What created a store generation (ADR-0014 §3.6 "The operation record").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum GenerationOperation {
    /// A fresh installation.
    Install,
    /// The adoption of an earlier build's flat store.
    Adopt,
    /// `state restore`.
    Restore,
    /// `state reset`.
    Reset,
}

/// A store generation's operation record, as `state status` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GenerationRecord {
    /// The generation's unique name.
    pub generation: String,
    /// What created it.
    pub operation: GenerationOperation,
    /// When.
    pub created_at: Timestamp,
    /// The generation it replaced, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_generation: Option<String>,
    /// The backup it was restored from, by SHA-256, for a restore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_sha256: Option<String>,
    /// Its environment ID.
    pub environment_id: EnvironmentId,
    /// Its restore epoch.
    pub restore_epoch: RestoreEpoch,
    /// The schema migrations applied to it, in order (store schema versions).
    #[serde(default)]
    pub migrations: Vec<u32>,
}

/// The state store's health, as `state status` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StateHealth {
    /// Readable, at this build's schema or migratable to it.
    Ok,
    /// Damaged, or a pointer that is unreadable or names a missing or record-less
    /// generation (`STATE_UNAVAILABLE` / `state_corrupt`).
    Corrupt,
    /// Newer than this build (`STATE_UNAVAILABLE` / `state_newer_than_build`).
    NewerThanBuild,
}

/// The request ledger's state, as `state status` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LedgerHealth {
    /// Readable; appends proceed.
    Ok,
    /// A torn tail only, discarded on the next append.
    TornTail,
    /// Damaged: every append is refused until `state repair`.
    Damaged,
    /// Absent.
    Absent,
}

/// ⟨H3⟩ `heimdall state status`: read-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StateStatus {
    /// The store's health.
    pub health: StateHealth,
    /// The current generation's record, when the pointer names a readable one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<GenerationRecord>,
    /// The store's schema version, when readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    /// The request ledger's state.
    pub ledger: LedgerHealth,
    /// Earlier generations kept as residue, each with its record.
    #[serde(default)]
    pub earlier_generations: Vec<GenerationRecord>,
    /// Migration backups present.
    #[serde(default)]
    pub migration_backups: u64,
    /// A staged generation that never became current (removed at start-up).
    #[serde(default)]
    pub staged_leftover: bool,
}

/// ⟨H3⟩ `heimdall state restore --backup <file>`: attended, typed confirmation. It recovers
/// identity and configuration and no authority (ADR-0014 §3.6); this is its report (§3.6
/// "The restore protocol" item 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RestoreReport {
    /// The new current generation's record.
    pub generation: GenerationRecord,
    /// The earlier generation left behind, whole, under its own name.
    pub left_behind: String,
    /// What the restore ended, quarantined and voided.
    pub ended: StateRestoredPayload,
    /// Requests fenced from the ledger (`REQUEST_STALE` / `restored_before_completion`).
    pub fenced_requests: u64,
    /// Whether the request ledger was readable.
    pub ledger_readable: bool,
    /// Whether the replaced generation was readable, so its more restrictive states and
    /// later terminal records were carried forward.
    pub carried_forward: bool,
    /// Remote effects of ending recovered authority, pending until acknowledged.
    #[serde(default)]
    pub remote_effects_pending: u64,
    /// Remote residue the restore cannot remove (opaque references).
    #[serde(default)]
    pub remote_residue: Vec<String>,
}

/// ⟨H3⟩ `heimdall state reset`: attended, typed confirmation, never automatic; a new
/// identity at epoch 0, the old generation kept (ADR-0014 §3.2 item 10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResetReport {
    /// The new current generation's record.
    pub generation: GenerationRecord,
    /// The generation it replaced, kept whole.
    pub left_behind: String,
    /// Whether an inventory of what the reset orphans (remote enrollments, pairings,
    /// management lines) was readable, from the old store or the last recovery bundle.
    pub inventory_readable: bool,
    /// What it orphans, when the inventory was readable (opaque references).
    #[serde(default)]
    pub orphaned: Vec<String>,
}

/// ⟨Q8⟩ `heimdall state repair` (ledger scope in 1.0): attended, typed confirmation, never
/// non-interactive. In order it carries every decodable record after the damage into the
/// store as fence records, raises the restore epoch, and truncates the ledger at the first
/// damaged record. **The residual it states:** a request among the dropped records retried
/// without its epoch could run again; a retry carrying its old epoch is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepairReport {
    /// Decodable records after the damage, written into the store as fence records.
    pub fenced_records: u64,
    /// Undecodable records dropped.
    pub dropped_records: u64,
    /// The restore epoch after the repair.
    pub restore_epoch: RestoreEpoch,
}

// --- H4, H10: the restore event ------------------------------------------------------------

/// The event type a restore emits (`state_restored`), one for H4's and H10's (ruling on
/// ASK-H10). Declared: `EventType` gains it with its emitter (U2b), so the `event` schema is
/// unchanged now.
pub const STATE_RESTORED_EVENT: &str = "state_restored";

/// ⟨H4, H10⟩ The payload of a `state_restored` event: what the restore ended
/// (ADR-0014 §3.6's table). Counts and opaque IDs only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StateRestoredPayload {
    /// The restore epoch after the restore.
    pub restore_epoch: RestoreEpoch,
    /// Grants (with their bindings, slots and owned connections) ended, each with a
    /// tombstone.
    #[serde(default)]
    pub grants_ended: Vec<crate::ids::GrantId>,
    /// Standing policies paused, with a cutoff at the restore time.
    #[serde(default)]
    pub policies_paused: Vec<crate::ids::PolicyId>,
    /// Pending decisions closed as stale.
    #[serde(default)]
    pub decisions_closed: Vec<crate::ids::DecisionId>,
    /// Operations closed as stale (`restored_before_completion`).
    #[serde(default)]
    pub operations_closed: Vec<crate::ids::OperationId>,
    /// Management clients quarantined until reauthorized
    /// (`client_quarantined_after_restore`).
    #[serde(default)]
    pub clients_quarantined: Vec<crate::ids::ClientId>,
    /// Invitations voided (`invitation_void_after_restore`), by opaque ID.
    #[serde(default)]
    pub invitations_voided: Vec<String>,
    /// Exposure and admission state disabled (`exposure_disabled_after_restore`), by kind.
    #[serde(default)]
    pub exposure_disabled: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_is_a_bare_number_and_zero_by_default() {
        assert_eq!(serde_json::to_string(&RestoreEpoch(7)).unwrap(), "7");
        assert_eq!(RestoreEpoch::default(), RestoreEpoch(0));
    }

    #[test]
    fn declared_names_are_snake_case() {
        for name in residue_kind::ALL
            .iter()
            .chain([&EXECUTABLE_MOVED, &STATE_RESTORED_EVENT])
        {
            assert!(
                name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{name}"
            );
        }
        assert_eq!(REQUEST_STALE_EXIT, 6);
    }
}
