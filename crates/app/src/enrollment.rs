//! ⟨M03⟩ The enrollment stage driver's public surface (m03-plan U10; ADR-0008 D5
//! §6.4–§6.9): pure stage logic and the types the runtime and tests name.
//!
//! The store-backed driver itself (journal, receipts, decisions, events) is
//! `crate::operations::enrollment_m03`, a child of `operations` so that it shares the
//! operation journal's private helpers; its entry point is
//! [`crate::Operations::enrollment_request`]. Every path that is not wired fails
//! closed (`CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`) before any record
//! is written.
//!
//! **What lives here:**
//! * [`EnrollmentHost`], the runtime's facts that no frozen M03 port carries (the
//!   generated host-trust files under `<runtime_dir>/e/<tag>/`, the verified client,
//!   the Q24 `IdentityAgent` reading, the existing-access endpoint's re-validation,
//!   Heimdall's own endpoints, and the `ssh -G` effective-configuration check);
//! * [`StepAnswer`], what `Enrollment::Step` and `Enrollment::StepResult` answer;
//! * [`Journal`], an enrollment operation's durable facts (persisted as stage
//!   receipts; see `enrollment_m03`);
//! * the pure helpers: the plan rebuilt from a record ([`plan_of_record`]), the route
//!   comparison ([`route_matches`]) and the generated known-hosts line.

use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::enrollment::{
    ApprovedTarget, BootstrapPlan, DisclosureKind, EndpointSource, EnrollmentForm, EnrollmentPlan,
    EnrollmentResult, EnrollmentState, ExistingAccessPlan, NoProxy, RegistryResolvedBy,
    RemoteStage, RemoteStep, RollbackPlan, VerificationPlan, VerifyMode,
};
use heimdall_contract::ids::{DecisionId, EnrollmentId, ForeignRemovalId};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_contract::setup::PlanDigest;
use heimdall_domain::enrollment::{
    Determinism, EnrollmentRecord, ProxyRoute, ReverifyFrom, TargetEvaluation,
};
use heimdall_domain::projection::Sha256Hex;
use heimdall_registry::classify::{DirState, FileKind, HolderRecord, Inspection, LockReading};
use heimdall_registry::post_image::ImageDigest;
use heimdall_registry::step;
use serde::{Deserialize, Serialize};

/// The types and the one helper an [`EnrollmentHost`] implementation names
/// (re-exported, so the runtime and tests need no `heimdall-registry` edge).
pub use heimdall_registry::plan::AgentReading;
pub use heimdall_registry::step::{TrustPaths, effective_config_args};

// --- the host port ---------------------------------------------------------------------

/// Why an [`EnrollmentHost`] call failed (fixed, nonsecret text).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("enrollment host: {0}")]
pub struct HostError(pub String);

/// The generated files of one enrollment (`<runtime_dir>/e/<tag>/`; ADR-0008 D5 §6.3
/// host-trust table): the one-line known-hosts file, the empty global known-hosts
/// file, and the generated copy of the adopted public key (pinned with
/// `IdentityFile` for an agent-held identity).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GeneratedPaths {
    /// The host-trust files and tag.
    pub trust: TrustPaths,
    /// `<runtime_dir>/e/<tag>/identity.pub`.
    pub identity_file: String,
}

/// ⟨M03 wave 4⟩ The runtime facts the enrollment driver needs that no frozen M03
/// port carries (module docs). Implemented by the runtime over `heimdall-localenv`
/// and its paths (U10-D); tests implement it over a scratch directory.
///
/// Every path is an absolute literal with `/` separators. Nothing here contacts a
/// destination except [`effective_config`](Self::effective_config), which runs the
/// client's `ssh -G` (it parses configuration and connects to nothing).
pub trait EnrollmentHost: Send + Sync {
    /// The verified client's absolute path (M02's client inventory), or `None`.
    fn client(&self) -> Option<String>;

    /// The verified client's version line (`ssh -V`), for evidence and for the
    /// client-change re-verification (§17.4 item 11).
    fn client_version(&self) -> Option<String>;

    /// The generated paths of `tag` (no write; the preview names them).
    fn paths(&self, tag: &str) -> Option<GeneratedPaths>;

    /// Write `tag`'s generated files: the known-hosts file holding exactly
    /// `known_hosts_line`, the empty global file, and `identity_public` (an OpenSSH
    /// public-key line) when given. Owner-only directory and files; the contents are
    /// read back and compared (D5 §6.3 "written and digest-checked by the runtime
    /// before it returns the step").
    ///
    /// # Errors
    /// [`HostError`]; the step is then refused.
    fn write_files(
        &self,
        tag: &str,
        known_hosts_line: &str,
        identity_public: Option<&str>,
    ) -> Result<GeneratedPaths, HostError>;

    /// The Q24 reading: the alias's own `IdentityAgent`, statically evaluated with
    /// the managed block excluded.
    fn identity_agent(&self, alias: &str) -> AgentReading;

    /// Re-validate the approved existing-access endpoint before a step (§17.4 item
    /// 4): present, owned by the user, and not Heimdall's (nor resolving to one).
    fn endpoint_valid(&self, endpoint: &str) -> bool;

    /// Heimdall's endpoints and the runtime directory prefix (an existing-access
    /// endpoint resolving to one is refused).
    fn heimdall_endpoints(&self) -> Vec<String>;

    /// Run the client's `ssh -G` with exactly `step`'s pins and alias; its stdout.
    ///
    /// # Errors
    /// [`HostError`] (the step is refused `host_trust_unpinnable`).
    fn effective_config(&self, step: &RemoteStep) -> Result<String, HostError>;
}

// --- what Step and StepResult answer ------------------------------------------------------

/// What `Enrollment::Step` answers: the next client-executed step, or that none is
/// needed (the operation's result, or its state while the runtime works).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "next", rename_all = "snake_case")]
#[non_exhaustive]
pub enum StepAnswer {
    /// Run this step, then send `Enrollment::StepResult` with its token.
    Step {
        /// The step.
        step: Box<RemoteStep>,
    },
    /// No remote step is needed now.
    Done {
        /// The enrollment's result.
        result: Box<EnrollmentResult>,
    },
}

/// What `Enrollment::StepResult` answers: how the result was recorded, and whether a
/// further step follows (`Enrollment::Step` again) or the operation is done.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepRecorded {
    /// The stage whose result was recorded.
    pub stage: RemoteStage,
    /// The classification (`confirmed`, `already_present`, `not_applied`,
    /// `uncertain`, `held`, `host_trust_changed`, `provider_locked`,
    /// `interaction_required`).
    pub class: String,
    /// The enrollment's state after it.
    pub state: EnrollmentState,
    /// Whether `Enrollment::Step` has another step.
    pub more: bool,
    /// The result, once the operation succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Box<EnrollmentResult>>,
    /// The operation's error (`data.error`), once it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
}

// --- the durable journal ----------------------------------------------------------------

/// The approval an `enrollment.apply` (or a removal, a target change) rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalFact {
    /// The approved decision.
    pub decision: DecisionId,
    /// When it was approved (safe wall time).
    pub at: Timestamp,
}

/// Which step a mutation serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StepPurpose {
    /// The initial append (and its bootstrap).
    Append,
    /// A failed verification's rollback.
    Rollback,
    /// An explicit removal (own or foreign).
    Removal,
    /// A reconcile's read or fence.
    Reconcile,
}

/// A step the runtime issued and whose result it awaits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedStep {
    /// The stage.
    pub stage: RemoteStage,
    /// The step token (32 lowercase hex).
    pub token: String,
    /// What it serves.
    pub purpose: StepPurpose,
    /// The continuous clock at issue (milliseconds).
    pub issued_continuous_ms: u64,
    /// The wall clock at issue.
    pub issued_wall: Timestamp,
    /// The boot it was issued in.
    pub boot_id: String,
    /// The step timeout (milliseconds).
    pub timeout_ms: u64,
    /// The hard deadline on the continuous clock (milliseconds).
    pub hard_deadline_ms: u64,
    /// The hard deadline on the wall clock.
    pub hard_deadline_wall: Timestamp,
    /// The script's remote not-after (mutating stages).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_remote: Option<i64>,
    /// `fence --terminate`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub terminate: bool,
    /// The preimage a `remove` must still equal, by its digest (§17.21 item 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage: Option<RegistryDigest>,
    /// The post-image a `remove` renames over the registry, by its digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_image: Option<RegistryDigest>,
}

/// A registry image by its length and SHA-256 (ADR-0008 §17.21 item 4: the
/// journal never stores the inspected registry's foreign bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryDigest {
    /// Length in bytes.
    pub len: u64,
    /// SHA-256.
    pub sha256: Sha256Hex,
}

impl RegistryDigest {
    /// The digest of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> RegistryDigest {
        RegistryDigest::from(&ImageDigest::of(bytes))
    }

    /// The registry crate's form.
    #[must_use]
    pub fn image(&self) -> ImageDigest {
        ImageDigest {
            len: self.len,
            sha256: self.sha256.clone(),
        }
    }

    /// Whether `bytes` are exactly this image.
    #[must_use]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        u64::try_from(bytes.len()).ok() == Some(self.len) && Sha256Hex::of(bytes) == self.sha256
    }
}

impl From<&ImageDigest> for RegistryDigest {
    fn from(d: &ImageDigest) -> RegistryDigest {
        RegistryDigest {
            len: d.len,
            sha256: d.sha256.clone(),
        }
    }
}

/// The parsed facts of an `inspect` reading that the stage machine needs, **without
/// the server owner's bytes** (§17.21 item 4; ⟨round 3⟩ §17.22 item 2): the
/// registry's own metadata, the lock, Heimdall's **exact canonical** entry (only when
/// a line matches it byte for byte) and, for every other line carrying the marker (an
/// owner's comment, an unrelated key, a damaged entry), parsed facts only: a count, a
/// classification and a SHA-256. No other line's bytes are stored, in any encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredReading {
    /// The resolved registry path (hex; the plan's path).
    pub path_hex: String,
    /// The directory is present.
    pub dir_present: bool,
    /// The directory's mode string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir_mode: Option<String>,
    /// The directory is owned by the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir_owner_self: Option<bool>,
    /// The file's kind (`regular`, `absent`, `symlink`, `other`).
    pub file: String,
    /// Link count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<u64>,
    /// The file's mode string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// The file is owned by the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_self: Option<bool>,
    /// The file's last byte is a newline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_byte_newline: Option<bool>,
    /// Lines containing the marker.
    pub marker_lines: u64,
    /// ⟨round 3⟩ The marker (Heimdall's own; rebuilds the reading's stand-ins).
    #[serde(default)]
    pub marker: String,
    /// ⟨round 3⟩ Lines equal to Heimdall's canonical entry, for a regular file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_entries: Option<u64>,
    /// ⟨round 3⟩ The canonical entry (hex, without `\n`), only when a line matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own_entry_hex: Option<String>,
    /// ⟨round 3⟩ Other lines carrying the marker: counted, never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other_marker_lines: Option<u64>,
    /// ⟨round 3⟩ The SHA-256 over those other lines (each with its `\n`), when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other_marker_sha256: Option<String>,
    /// ⟨round 3⟩ The classification (`absent`, `exact`, `duplicated`, `damaged`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker_class: Option<String>,
    /// The lock's holder record (Heimdall's own lock), when held with one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_holder: Option<String>,
    /// A lock is held whose record is not a holder record.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lock_foreign: bool,
}

impl StoredReading {
    /// The stored form of `full`, minimized against `marker` and Heimdall's exact
    /// canonical `line` (`None` when it cannot be rebuilt: every marker-bearing line
    /// then counts as "other").
    #[must_use]
    pub fn of(full: &Inspection, marker: &str, line: Option<&str>) -> StoredReading {
        let facts = full.marker_facts(marker, line);
        StoredReading {
            path_hex: heimdall_registry::hm1::encode_hex(&full.path),
            dir_present: full.dir == DirState::Present,
            dir_mode: full.dir_mode.clone(),
            dir_owner_self: full.dir_owner_self,
            file: match full.file {
                FileKind::Regular => "regular",
                FileKind::Absent => "absent",
                FileKind::Symlink => "symlink",
                _ => "other",
            }
            .to_owned(),
            links: full.links,
            mode: full.mode.clone(),
            owner_self: full.owner_self,
            last_byte_newline: full.last_byte_newline,
            marker_lines: full.marker_lines,
            marker: marker.to_owned(),
            own_entries: facts.as_ref().map(|f| f.own_entries),
            own_entry_hex: facts
                .as_ref()
                .filter(|f| f.own_entries > 0)
                .and(line)
                .map(|l| heimdall_registry::hm1::encode_hex(l.as_bytes())),
            other_marker_lines: facts.as_ref().map(|f| f.other_lines),
            other_marker_sha256: facts
                .as_ref()
                .and_then(|f| f.other_sha256.as_ref())
                .map(|d| d.as_str().to_owned()),
            marker_class: facts.as_ref().map(|f| f.class.as_str().to_owned()),
            lock_holder: match &full.lock {
                LockReading::Held(h) => Some(h.render()),
                _ => None,
            },
            lock_foreign: matches!(full.lock, LockReading::HeldForeign),
        }
    }

    /// The minimized reading: its content is rebuilt from the facts (Heimdall's
    /// canonical entry, and a stand-in per other marker line: module docs of
    /// [`StoredReading`]). `None` when a stored field does not decode or the facts
    /// are inconsistent.
    #[must_use]
    pub fn inspection(&self, remote_now: i64) -> Option<Inspection> {
        let lock = match (&self.lock_holder, self.lock_foreign) {
            (Some(h), _) => LockReading::Held(HolderRecord::parse(h)?),
            (None, true) => LockReading::HeldForeign,
            (None, false) => LockReading::None,
        };
        // A regular file's content is rebuilt from the facts: the canonical entry
        // and one stand-in per other marker line (§17.22 item 2).
        let content = match self.own_entries {
            Some(own) => {
                let entry = match &self.own_entry_hex {
                    Some(h) => Some(heimdall_registry::hm1::decode_hex(h)?),
                    None => None,
                };
                Some(heimdall_registry::classify::minimized_content(
                    &self.marker,
                    entry.as_deref(),
                    own,
                    self.other_marker_lines?,
                    self.marker_lines,
                )?)
            }
            None => None,
        };
        Some(Inspection {
            path: heimdall_registry::hm1::decode_hex(&self.path_hex)?,
            dir: if self.dir_present {
                DirState::Present
            } else {
                DirState::Absent
            },
            dir_mode: self.dir_mode.clone(),
            dir_owner_self: self.dir_owner_self,
            file: match self.file.as_str() {
                "regular" => FileKind::Regular,
                "absent" => FileKind::Absent,
                "symlink" => FileKind::Symlink,
                _ => FileKind::Other,
            },
            links: self.links,
            mode: self.mode.clone(),
            owner_self: self.owner_self,
            content,
            last_byte_newline: self.last_byte_newline,
            marker_lines: self.marker_lines,
            lock,
            remote_now,
        })
    }
}

/// The latest `inspect` reading (E2 `enroll.inspect.observed`), minimized (§17.21
/// item 4): the registry's SHA-256, Heimdall's own marker entries and the parsed
/// facts the stage machine needs, and when it arrived. A later step that needs the
/// full bytes (the removal's post-image) takes them from this runtime's memory of the
/// same reading, checked against [`registry`](Self::registry), or inspects again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectFact {
    /// The registry's length and SHA-256 (`None`: a symlink or another kind).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegistryDigest>,
    /// The parsed, minimized reading.
    pub reading: StoredReading,
    /// The client's exit status.
    pub exit_status: i32,
    /// The continuous clock when the reading arrived (milliseconds).
    pub read_continuous_ms: u64,
    /// The wall clock then.
    pub read_wall: Timestamp,
    /// The boot.
    pub boot_id: String,
    /// The remote clock reading (epoch seconds).
    pub remote_now: i64,
    /// A mutation ran after it (a later mutation needs a fresh inspect).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub consumed: bool,
}

impl InspectFact {
    /// The minimized reading (see [`StoredReading::inspection`]).
    #[must_use]
    pub fn inspection(&self) -> Option<Inspection> {
        self.reading.inspection(self.remote_now)
    }
}

/// An uncertain mutation awaiting reconcile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UncertainStep {
    /// Its stage.
    pub stage: RemoteStage,
    /// Its token.
    pub token: String,
    /// Its not-after.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_remote: Option<i64>,
    /// What it served.
    pub purpose: StepPurpose,
    /// Its hard deadline (continuous ms, in `boot_id`).
    pub hard_deadline_ms: u64,
    /// Its hard deadline (wall).
    pub hard_deadline_wall: Timestamp,
    /// The boot.
    pub boot_id: String,
}

/// An owner reconcile in progress (D5 §6.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileFact {
    /// The session was attended.
    pub attended: bool,
    /// The steps may prompt (interactive).
    pub interactive: bool,
    /// `--after-manual-recovery`: classify only.
    pub after_manual_recovery: bool,
    /// What the last fence of this reconcile showed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fence: Option<FenceFact>,
}

/// The lock a fence showed (a serializable `heimdall_registry::fence::LockView`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FenceFact {
    /// No lock.
    None,
    /// Another enrollment's lock.
    Other,
    /// Ours, proven gone and removed.
    Gone,
    /// Ours, alive.
    Alive {
        /// Its not-after has passed on the remote clock.
        not_after_passed: bool,
        /// Signals were sent.
        terminated: bool,
    },
    /// Ours, unproven (exit 44).
    Unproven {
        /// Signals sent (`""`, `TERM`, `TERM,KILL`).
        terminated: bool,
    },
}

/// An enrollment operation's durable facts (ADR-0008 D5 §6.4 stage table), folded
/// from its `enroll.journal` receipts (the last one is current).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    /// The enrollment this operation drives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment: Option<EnrollmentId>,
    /// The foreign removal this operation drives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreign: Option<ForeignRemovalId>,
    /// The approval (E1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalFact>,
    /// The steps run interactively (`BatchMode=no`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub interactive: bool,
    /// The step awaiting its result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outstanding: Option<IssuedStep>,
    /// The latest inspect reading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspection: Option<InspectFact>,
    /// The E2 inspect's offset of the destination clock (ms, remote − local) and its
    /// uncertainty (ms): the initial verification's known offset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_offset: Option<(i64, u64)>,
    /// The bootstrap was confirmed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bootstrap_done: bool,
    /// The `ssh -G` check passed; with the Q23 option when `Some(true)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_checked: Option<bool>,
    /// `busy` results in a row.
    #[serde(default)]
    pub busy: u32,
    /// `remove` exit 20 results (registry changed since read).
    #[serde(default)]
    pub changed: u32,
    /// The uncertain mutation, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uncertain: Option<UncertainStep>,
    /// An owner reconcile in progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconcile: Option<ReconcileFact>,
    /// Reconciles that ended without a holder proof.
    #[serde(default)]
    pub fence_attempts: u32,
    /// A verify operation's mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<VerifyMode>,
    /// Where a re-verification started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverify_from: Option<ReverifyFrom>,
    /// A target-change verification's proposed target (§17.7 item 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_target: Option<ApprovedTarget>,
    /// A removal's freshly evaluated target (a held host-key change; D5 §6.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh_target: Option<ApprovedTarget>,
    /// The generated paths' tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

impl Journal {
    /// The approval is within its validity at safe time `now`.
    #[must_use]
    pub fn approval_valid(&self, now: Timestamp, validity: Duration) -> bool {
        let Some(a) = &self.approval else {
            return false;
        };
        let Ok(v) = jiff::SignedDuration::try_from(validity) else {
            return false;
        };
        a.at.checked_add(v).is_ok_and(|until| now < until)
    }
}

// --- pure helpers ---------------------------------------------------------------------

/// The 16-hex tag of an enrollment's generated files (`registry::plan::trust_tag`).
#[must_use]
pub fn tag_of(enrollment: &EnrollmentId) -> String {
    heimdall_registry::plan::trust_tag(enrollment)
}

/// The generated known-hosts line: `hm-target-<tag> <algorithm> <key>` (D5 §6.3: one
/// plain line, no marker, no pattern, no hashed name).
#[must_use]
pub fn known_hosts_line(tag: &str, target: &ApprovedTarget) -> String {
    format!(
        "{}{tag} {} {}\n",
        step::HOST_KEY_ALIAS_PREFIX,
        target.host_key.algorithm,
        target.host_key.key
    )
}

/// Whether a fresh evaluation is the approved target (D5 §6.3 "Route re-evaluation
/// before every dispatch"): determined, direct, the same `HostName`, `Port` and
/// `User`, and exactly the approved host key among the non-revoked known keys.
#[must_use]
pub fn route_matches(approved: &ApprovedTarget, eval: &TargetEvaluation) -> bool {
    if eval.determinism != Determinism::Determined || eval.proxy != ProxyRoute::None {
        return false;
    }
    if eval.hostname != approved.hostname
        || eval.port != approved.port
        || eval.user != approved.user.as_str()
    {
        return false;
    }
    let live: Vec<_> = eval.host_keys.iter().filter(|k| !k.revoked).collect();
    let revoked_approved = eval.host_keys.iter().any(|k| {
        k.revoked && k.key_type == approved.host_key.algorithm && k.key_b64 == approved.host_key.key
    });
    !revoked_approved
        && !live.is_empty()
        && live.iter().all(|k| {
            k.key_type == approved.host_key.algorithm && k.key_b64 == approved.host_key.key
        })
}

/// The version token of a client version line: `OpenSSH_10.5p1, LibreSSL …` →
/// `10.5p1` (the Verifier's evidence names the client as `<path> <family> <version>`).
#[must_use]
pub fn version_token(line: &str) -> &str {
    let first = line.split([',', ' ']).next().unwrap_or("");
    first.rsplit_once('_').map_or(first, |(_, v)| v).trim()
}

/// Whether `evidence_client` (an [`EnrollmentEvidence`](heimdall_domain::enrollment::EnrollmentEvidence)'s
/// `client`: `<path> <family> <version>`, or a version line) names the client whose
/// version line is `current` (§17.4 item 11): one of its words has the same
/// [`version_token`]. `None` or an empty token: not established, so `false`.
#[must_use]
pub fn evidence_client_current(evidence_client: &str, current: Option<&str>) -> bool {
    current.map(version_token).is_some_and(|v| {
        !v.is_empty()
            && evidence_client
                .split_whitespace()
                .any(|t| version_token(t) == v)
    })
}

/// Whether `eval` finds the approved `HostName`, `Port` and `User`, directly and
/// determined, but not exactly the approved host key: a host-key change (a route
/// change is not one).
#[must_use]
pub fn host_key_changed(approved: &ApprovedTarget, eval: &TargetEvaluation) -> bool {
    eval.determinism == Determinism::Determined
        && eval.proxy == ProxyRoute::None
        && eval.hostname == approved.hostname
        && eval.port == approved.port
        && eval.user == approved.user.as_str()
        && !route_matches(approved, eval)
}

/// ⟨wave 4, round 3⟩ ADR-0008 §17.22 item 7 (D5 §6.5 freshness): the comparison
/// `inspect` and `ensure` run when they touch a pair. A record's evidence still holds
/// only when the evaluation of the pair's alias (`eval`) is exactly its approved
/// target ([`route_matches`]: the same route and exactly the approved host key) and
/// the evidence names the current client (`client_version`,
/// [`evidence_client_current`]). Anything else, including no evaluation or no known
/// client, invalidates the evidence **at once**, whatever the record's state and
/// whatever a later network attempt finds. (The CA is compared where the certificate
/// is known: the managed adapter's `pair_evidence`.) A record without evidence has
/// none to hold.
#[must_use]
pub fn evidence_holds(
    record: &EnrollmentRecord,
    eval: Option<&TargetEvaluation>,
    client_version: Option<&str>,
) -> bool {
    let Some(e) = &record.evidence else {
        return false;
    };
    eval.is_some_and(|ev| route_matches(&record.target, ev))
        && evidence_client_current(&e.client, client_version)
}

/// The proposed target of a held host-key change: the fresh evaluation, when it is
/// determined, direct, the approved `HostName`/`Port`/`User`, with exactly one
/// non-revoked, pinnable key that differs from the approved one.
#[must_use]
pub fn proposed_target(
    approved: &ApprovedTarget,
    eval: &TargetEvaluation,
) -> Option<ApprovedTarget> {
    if eval.determinism != Determinism::Determined || eval.proxy != ProxyRoute::None {
        return None;
    }
    if eval.hostname != approved.hostname
        || eval.port != approved.port
        || eval.user != approved.user.as_str()
    {
        return None;
    }
    let mut live = eval.host_keys.iter().filter(|k| !k.revoked);
    let key = live.next()?;
    if live.any(|k| k.key_type != key.key_type || k.key_b64 != key.key_b64) {
        return None;
    }
    step::host_key_algorithms(&key.key_type)?;
    let approved_key = key.approved();
    if approved_key.algorithm == approved.host_key.algorithm
        && approved_key.key == approved.host_key.key
    {
        return None;
    }
    Some(ApprovedTarget {
        host_key: approved_key,
        ..approved.clone()
    })
}

/// The rendered existing-access endpoint of a record (the plan's concrete form).
#[must_use]
pub fn endpoint_of(record: &EnrollmentRecord) -> Option<String> {
    record
        .existing_access
        .endpoint
        .as_ref()
        .map(|e| e.locator.clone())
}

/// The endpoint reference stored with a record for a rendered endpoint.
#[must_use]
pub fn endpoint_ref(rendered: &str) -> EndpointRef {
    let kind = if rendered.to_ascii_lowercase().starts_with("//./pipe/") {
        EndpointKind::NamedPipe
    } else {
        EndpointKind::UnixSocket
    };
    EndpointRef {
        kind,
        locator: rendered.to_owned(),
    }
}

/// The plan an existing record approved, rebuilt from the record (and `target`, the
/// approved or a proposed target), the CA's public key and the generated paths: what
/// every later step, the removal and the verification use (§17.19 item 5: "the
/// verification factory receives the plan"). `None` when a part cannot be rebuilt
/// (a line whose digest differs from the record's, an unusable path).
#[must_use]
pub fn plan_of_record(
    record: &EnrollmentRecord,
    target: &ApprovedTarget,
    alias: &str,
    ca_public_key: &str,
    mechanism: &str,
    paths: &GeneratedPaths,
) -> Option<EnrollmentPlan> {
    let pair_principal =
        heimdall_registry::line::principal(&record.destination, &record.account).ok()?;
    let line =
        heimdall_registry::line::expected_line(ca_public_key, &pair_principal, &record.marker)
            .ok()?;
    if Sha256Hex::of(line.as_bytes()).as_str() != record.line_sha256 {
        return None;
    }
    let endpoint = endpoint_of(record)?;
    let identity_file = record
        .existing_access
        .public_key_file
        .clone()
        .unwrap_or_else(|| paths.identity_file.clone());
    let host_trust = step::trust_pins(target, &paths.trust).ok()?;
    let access = step::access_pins(&endpoint, &identity_file).ok()?;
    let account_form = record.form == EnrollmentForm::Account;
    let mut plan = EnrollmentPlan {
        plan_digest: PlanDigest::from_sha256([0; 32]),
        destination_id: record.destination.clone(),
        alias: alias.to_owned(),
        account: record.account.clone(),
        form: record.form,
        registry: record.registry.clone(),
        line_sha256: record.line_sha256.clone(),
        line,
        ca_fingerprint: record.ca_fingerprint.clone(),
        existing_access: ExistingAccessPlan {
            identity_id: record.existing_access.identity.clone(),
            mechanism: mechanism.to_owned(),
            endpoint,
            endpoint_source: EndpointSource::CatalogRecord,
            invocation: step::render_invocation(&access),
        },
        host_trust: step::render_pairs(&host_trust),
        approved_target: ApprovedTarget {
            proxy: NoProxy::None,
            ..target.clone()
        },
        bootstrap: account_form.then_some(BootstrapPlan::CreateRegistryDir0700IfAbsent),
        verification: VerificationPlan {
            positive_principal: pair_principal,
            negative: true,
            max_validity_seconds: heimdall_registry::plan::VERIFICATION_MAX_VALIDITY_SECONDS,
        },
        rollback: RollbackPlan::CompareThenRenameByMarker,
        disclosures: vec![DisclosureKind::OrdinarySshNeedsHeldSlot],
    };
    plan.plan_digest = heimdall_registry::plan::plan_digest(&plan).ok()?;
    Some(plan)
}

/// The canonical registry of a record as the scripts take it.
#[must_use]
pub fn registry_canonical(
    record: &EnrollmentRecord,
) -> heimdall_contract::enrollment::RegistryCanonical {
    let mut r = record.registry_canonical.clone();
    if r.resolved_by == RegistryResolvedBy::RemoteHome {
        r.path = None;
    }
    r
}

/// The system form's lines (ADR-0008 D5 §6.9): the CA line for `TrustedUserCAKeys`,
/// the principals-file line, and the `sshd_config` directives.
#[must_use]
pub fn system_form_lines(
    ca_public_key: &str,
    principal: &str,
) -> heimdall_domain::decision::SystemFormLines {
    heimdall_domain::decision::SystemFormLines {
        trusted_user_ca_keys_line: ca_public_key.trim().to_owned(),
        principals_line: principal.to_owned(),
        sshd_directives: vec![
            "TrustedUserCAKeys <file holding the CA line>".to_owned(),
            "AuthorizedPrincipalsFile <file per account holding the principals line>".to_owned(),
        ],
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::enrollment::ApprovedHostKey;
    use heimdall_contract::ids::AccountName;
    use heimdall_domain::enrollment::RawHostKey;

    fn target(key: &str) -> ApprovedTarget {
        ApprovedTarget {
            hostname: "127.0.0.1".into(),
            port: 2222,
            user: AccountName::parse("deploy").unwrap(),
            proxy: NoProxy::None,
            host_key: ApprovedHostKey {
                algorithm: "ssh-ed25519".into(),
                key: key.into(),
                fingerprint: "SHA256:x".into(),
            },
        }
    }

    fn eval(keys: &[(&str, bool)]) -> TargetEvaluation {
        TargetEvaluation {
            hostname: "127.0.0.1".into(),
            port: 2222,
            user: "deploy".into(),
            proxy: ProxyRoute::None,
            determinism: Determinism::Determined,
            host_keys: keys
                .iter()
                .map(|(k, revoked)| RawHostKey {
                    key_type: "ssh-ed25519".into(),
                    key_b64: (*k).into(),
                    fingerprint: "SHA256:y".into(),
                    origin_display: "known_hosts".into(),
                    revoked: *revoked,
                })
                .collect(),
        }
    }

    #[test]
    fn route_comparison_and_proposed_target() {
        let t = target("AAAA");
        assert!(route_matches(&t, &eval(&[("AAAA", false)])));
        assert!(!route_matches(&t, &eval(&[("BBBB", false)])));
        assert!(!route_matches(
            &t,
            &eval(&[("AAAA", false), ("BBBB", false)])
        ));
        assert!(!route_matches(
            &t,
            &eval(&[("AAAA", false), ("AAAA", true)])
        ));
        let mut moved = eval(&[("AAAA", false)]);
        moved.port = 2223;
        assert!(!route_matches(&t, &moved));
        let mut proxied = eval(&[("AAAA", false)]);
        proxied.proxy = ProxyRoute::Jump;
        assert!(!route_matches(&t, &proxied));
        let p = proposed_target(&t, &eval(&[("BBBB", false)])).unwrap();
        assert_eq!(p.host_key.key, "BBBB");
        assert_eq!(p.hostname, t.hostname);
        assert!(proposed_target(&t, &eval(&[("AAAA", false)])).is_none());
        assert!(proposed_target(&t, &eval(&[("BBBB", false), ("CCCC", false)])).is_none());
    }

    #[test]
    fn known_hosts_line_is_one_plain_line() {
        let l = known_hosts_line("0123456789abcdef", &target("AAAA"));
        assert_eq!(l, "hm-target-0123456789abcdef ssh-ed25519 AAAA\n");
    }

    #[test]
    fn approval_validity_is_strict() {
        let at: Timestamp = "2026-11-11T10:00:00Z".parse().unwrap();
        let j = Journal {
            approval: Some(ApprovalFact {
                decision: DecisionId::from_random_bytes([1; 16]),
                at,
            }),
            ..Journal::default()
        };
        let day = Duration::from_secs(24 * 3600);
        assert!(j.approval_valid(at, day));
        let later = at
            .checked_add(jiff::SignedDuration::from_hours(24))
            .unwrap();
        assert!(!j.approval_valid(later, day));
        assert!(!Journal::default().approval_valid(at, day));
    }
}
