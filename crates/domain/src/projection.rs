//! The managed OpenSSH (and Git) projection: the durable setup intent, its file
//! steps and their content, file identities, consent records, projection records,
//! and the recovery-state types that cross the `ProjectionWriter` port (ADR-0007
//! §5.2, §5.6, §5.7; m02-plan §5 items 15, 17 and 17a).
//!
//! Frozen in wave 0 (m02-plan U0 "Frozen in wave 0"): [`SetupIntent`] with its
//! [`FileStep`] list, [`StepContent`] (wire form, binding rule and bounds),
//! [`Rendered`] provenance, [`FileRole::GitLock`] and the `git_lock` step rule,
//! [`FileIdentity`] with its optional Unix `birth` and equality, [`ProjectionApproval`],
//! and the recovery types [`RecoveryState`], [`StepShape`], [`StepObservation`],
//! [`EntryObs`], [`StepFingerprint`] and [`EntryFingerprint`]. Later units change
//! them only through an ADR-0007 revision.
//!
//! Everything here is pure data or a pure function: no I/O and no clock.
//!
//! **Placement of the recovery types** (wave-0 verifier escalation E8). The design
//! places `RecoveryState`, `StepObservation`, `EntryObs` and the fingerprints in
//! `heimdall-localenv`, but the app port `ProjectionWriter::observe_held` returns
//! `HeldStep`s that embed them, and `heimdall-localenv` implements the app ports, so
//! the app cannot name localenv types. The types that cross the port therefore live
//! here, in the integrator-owned domain crate. `recovery::decide`, `decide_item`,
//! `StepDecision`, `observe_*` and `content::materialize` stay in
//! `heimdall-localenv` (U4).

use std::collections::{BTreeMap, BTreeSet};

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{DecisionId, EnvironmentId, OperationId, ResourceId};
use heimdall_contract::setup::{PlanDigest, PreviewIntent, ProjectionItem, SetupPlan};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::operation::{
    FilePhase, PostVerdict, PreservedEntry, RestoreCause, SettleConflictFound, SettleSource,
    SettledDisposition, StageReceipt,
};

// --- digests -----------------------------------------------------------------------

/// A SHA-256 digest as 64 lowercase hexadecimal characters, transparent on the wire.
/// Decoding refuses any other form, so a stored digest always re-encodes
/// byte-identically.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Hex(String);

/// A malformed [`Sha256Hex`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a SHA-256 digest is 64 lowercase hexadecimal characters")]
pub struct DigestError;

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Sha256Hex {
    /// The digest of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(hex_lower(&Sha256::digest(bytes)))
    }

    /// Parse a wire string: exactly 64 lowercase hex characters.
    pub fn parse(s: &str) -> Result<Self, DigestError> {
        if is_lower_hex(s, 64) {
            Ok(Self(s.to_owned()))
        } else {
            Err(DigestError)
        }
    }

    /// The wire string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Sha256Hex {
    type Error = DigestError;
    fn try_from(s: String) -> Result<Self, DigestError> {
        Self::parse(&s)
    }
}

impl From<Sha256Hex> for String {
    fn from(d: Sha256Hex) -> String {
        d.0
    }
}

impl std::fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A behaviour digest (ADR-0007 §5.2): SHA-256 over the canonical `RelevantBehavior`
/// with each value's provenance reduced to its source role.
pub type BehaviorDigest = Sha256Hex;

// --- file identity (ADR-0007 F25; m02-plan §5 item 17) -------------------------------

/// The identity of a directory entry's file, never its content.
///
/// Wire forms: `{"platform":"unix","dev":<u64>,"ino":<u64>}`, with
/// `"birth":"<integer ns since the epoch, as a decimal string>"` when the filesystem
/// records a birth time (Linux `statx` `STATX_BTIME`, macOS `st_birthtimespec`), and
/// `{"platform":"windows","volume":<u64>,"file_id":"<32 lowercase hex>"}`.
///
/// **Equality** (m02-plan §5 item 17, ⟨r5⟩ §12.11 item 7): two identities are equal
/// when every field present on both is equal and `birth` is present on both or on
/// neither. So with the same `(dev, ino)`, `Some(birth)` never equals `None`, in
/// either direction, and two different births never compare equal: an optional birth
/// is never a wildcard. The derived [`PartialEq`] is exactly this rule (`Option`
/// equality), and [`FileIdentity::same_file`] is the one comparison every helper uses.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum FileIdentity {
    /// A Unix inode.
    Unix {
        /// `st_dev`.
        dev: u64,
        /// `st_ino`.
        ino: u64,
        /// Birth time in nanoseconds since the epoch, when the filesystem records it.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "ns_decimal_opt"
        )]
        birth: Option<i128>,
    },
    /// A Windows file (`FILE_ID_INFO`).
    Windows {
        /// Volume serial number.
        volume: u64,
        /// 128-bit file ID, as 32 lowercase hex characters.
        #[serde(with = "file_id_hex")]
        file_id: [u8; 16],
    },
}

impl FileIdentity {
    /// The identity comparison (see the type's equality rule). Every helper that
    /// compares identities (`Expected` matching, the observation classifier) calls
    /// this, so `Some(birth)` and `None` are never equal anywhere.
    #[must_use]
    pub fn same_file(&self, other: &FileIdentity) -> bool {
        self == other
    }
}

/// A signed nanosecond count as a canonical decimal string: an optional `-`, then
/// digits with no leading zero (except `0` itself), never `-0`. Decoding refuses
/// every other form, so the value re-encodes byte-identically.
pub mod ns_decimal {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Parse the canonical form.
    #[must_use]
    pub fn parse(s: &str) -> Option<i128> {
        let digits = s.strip_prefix('-').unwrap_or(s);
        let canonical = !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'))
            && s != "-0";
        if !canonical {
            return None;
        }
        s.parse().ok()
    }

    /// Serialize.
    pub fn serialize<S: Serializer>(v: &i128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    /// Deserialize.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<i128, D::Error> {
        let s = String::deserialize(d)?;
        parse(&s)
            .ok_or_else(|| serde::de::Error::custom("not a canonical decimal nanosecond count"))
    }
}

mod ns_decimal_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option)] // serde's `with` passes `&Option<T>`.
    pub fn serialize<S: Serializer>(v: &Option<i128>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(n) => s.serialize_str(&n.to_string()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<i128>, D::Error> {
        let s = String::deserialize(d)?;
        super::ns_decimal::parse(&s)
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("not a canonical decimal nanosecond count"))
    }
}

mod file_id_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::hex_lower(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        if !super::is_lower_hex(&s, 32) {
            return Err(serde::de::Error::custom(
                "a Windows file ID is 32 lowercase hexadecimal characters",
            ));
        }
        let mut out = [0u8; 16];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|_| serde::de::Error::custom("malformed Windows file ID"))?;
        }
        Ok(out)
    }
}

mod b64 {
    use base64ct::{Base64, Encoding as _};
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ptr_arg)] // serde's `with` passes `&Vec<u8>`.
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&Base64::encode_string(v))
    }

    /// RFC 4648 §4, padded. A string that does not re-encode to itself (a
    /// non-canonical form) is refused, so stored content re-encodes byte-identically.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = Base64::decode_vec(&s)
            .map_err(|_| serde::de::Error::custom("content is not padded RFC 4648 base64"))?;
        if Base64::encode_string(&bytes) != s {
            return Err(serde::de::Error::custom("content base64 is not canonical"));
        }
        Ok(bytes)
    }
}

// --- file steps ---------------------------------------------------------------------

/// The role of a file step (m02-plan §5 item 17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileRole {
    /// The user's OpenSSH configuration; Heimdall splices B in or out.
    UserSsh,
    /// The managed OpenSSH file P.
    ManagedSsh,
    /// A materialized public key file.
    Key,
    /// The global Git file; Heimdall splices B_git in or out.
    GitInclude,
    /// The managed Git file P_git.
    GitManaged,
    /// ⟨r5⟩ The Git lock holder K at `<global file>.lock` (ADR-0007 §5.6).
    GitLock,
}

impl FileRole {
    /// The projection item this role belongs to.
    #[must_use]
    pub fn item(self) -> ProjectionItem {
        match self {
            FileRole::UserSsh | FileRole::ManagedSsh | FileRole::Key => ProjectionItem::Ssh,
            FileRole::GitInclude | FileRole::GitManaged | FileRole::GitLock => ProjectionItem::Git,
        }
    }

    /// Stable name (also the `role` part of a quarantine slot name).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FileRole::UserSsh => "user_ssh",
            FileRole::ManagedSsh => "managed_ssh",
            FileRole::Key => "key",
            FileRole::GitInclude => "git_include",
            FileRole::GitManaged => "git_managed",
            FileRole::GitLock => "git_lock",
        }
    }
}

/// A step's base: the file as the plan read it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Base {
    /// The file did not exist.
    Absent,
    /// The file existed with this content digest.
    Present {
        /// SHA-256 of the base bytes.
        sha256: Sha256Hex,
    },
}

/// A step's target: the file after the step.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    /// The file is removed (the cleaner's, ADR-0007 §5.8), or the step is the
    /// `git_lock` step.
    Absent,
    /// The file exists with this content digest.
    Present {
        /// SHA-256 of the target bytes.
        sha256: Sha256Hex,
    },
}

/// Bytes rendered by Heimdall itself: the only source of [`StepContent`] bytes
/// (ADR-0007 §5.7 "Provenance"; m02-plan §5 item 17).
///
/// **Producers.** Only `heimdall_sshconf::render::*`,
/// `heimdall_localenv::materialize::public_key_bytes` and ⟨r5⟩
/// `heimdall_localenv::projection::git::lock_holder` build a `Rendered`, through
/// [`Rendered::from_renderer`]. Rust visibility cannot restrict a constructor to
/// three modules of other crates, so a source-scan test in this crate
/// (`rendered_is_built_only_by_the_renderers`) fails when any other production file
/// calls it (wave-0 verifier escalation E9). Decoded intents are never trusted: every
/// read runs [`SetupIntent::validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    bytes: Vec<u8>,
}

impl Rendered {
    /// Wrap renderer output. **Only** the producers named on [`Rendered`] call this
    /// (source-scanned).
    #[doc(hidden)]
    #[must_use]
    pub fn from_renderer(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// The rendered bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 of the rendered bytes.
    #[must_use]
    pub fn sha256(&self) -> Sha256Hex {
        Sha256Hex::of(&self.bytes)
    }

    /// The whole target of P, P_git or a key file.
    #[must_use]
    pub fn into_whole(self) -> StepContent {
        StepContent(ContentInner::Whole {
            bytes_b64: self.bytes,
        })
    }

    /// A splice of the user file or the global Git file that inserts these bytes (B
    /// or B_git) at `offset`, after removing `remove_len` bytes whose SHA-256 is
    /// `removed_sha256` (present exactly when `remove_len > 0`).
    #[must_use]
    pub fn into_splice(
        self,
        offset: u64,
        remove_len: u64,
        removed_sha256: Option<Sha256Hex>,
    ) -> StepContent {
        StepContent(ContentInner::Splice {
            offset,
            remove_len,
            removed_sha256,
            insert_b64: self.bytes,
        })
    }

    /// The content of the `git_lock` step: the lock holder K's one line.
    #[must_use]
    pub fn into_lock_holder(self) -> StepContent {
        StepContent(ContentInner::LockHolder {
            bytes_b64: self.bytes,
        })
    }
}

/// The bytes a step writes, durable in the intent (ADR-0007 §5.7; frozen).
///
/// Wire form, tagged `kind`, bytes as RFC 4648 §4 padded base64:
/// * `{"kind":"whole","bytes_b64":…}`: P, P_git or a key file;
/// * `{"kind":"splice","offset":…,"remove_len":…,"removed_sha256":…,"insert_b64":…}`:
///   the user file or the global Git file; `removed_sha256` is present exactly when
///   `remove_len > 0`, and `insert_b64` holds B or B_git or is empty;
/// * `{"kind":"absent"}`: a target-absent step (the cleaner removes it);
/// * `{"kind":"lock_holder","bytes_b64":…}`: the `git_lock` step only.
///
/// A `StepContent` that carries bytes is built only from [`Rendered`]; the two
/// byte-free forms ([`StepContent::absent`], [`StepContent::remove_range`]) store no
/// bytes and so cannot carry anything Heimdall did not render.
///
/// ```compile_fail
/// // The representation is private: content cannot be built from raw bytes.
/// use heimdall_domain::projection::StepContent;
/// let _ = StepContent(Default::default());
/// ```
///
/// ```compile_fail
/// // There is no public variant to build with arbitrary bytes.
/// use heimdall_domain::projection::StepContent;
/// let _ = StepContent::Whole { bytes_b64: b"Host x\n".to_vec() };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StepContent(ContentInner);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ContentInner {
    Whole {
        #[serde(with = "b64")]
        bytes_b64: Vec<u8>,
    },
    Splice {
        offset: u64,
        remove_len: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        removed_sha256: Option<Sha256Hex>,
        #[serde(with = "b64")]
        insert_b64: Vec<u8>,
    },
    Absent,
    LockHolder {
        #[serde(with = "b64")]
        bytes_b64: Vec<u8>,
    },
}

/// A read-only view of a [`StepContent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepContentView<'a> {
    /// A whole target.
    Whole {
        /// The bytes.
        bytes: &'a [u8],
    },
    /// A splice.
    Splice {
        /// Byte offset of the removed range (and of the insert).
        offset: u64,
        /// Length of the removed range.
        remove_len: u64,
        /// SHA-256 of the removed range, present exactly when `remove_len > 0`.
        removed_sha256: Option<&'a Sha256Hex>,
        /// Inserted bytes (B or B_git), possibly empty.
        insert: &'a [u8],
    },
    /// Target absent.
    Absent,
    /// The Git lock holder's line.
    LockHolder {
        /// The bytes.
        bytes: &'a [u8],
    },
}

impl StepContent {
    /// The content of a target-absent step.
    #[must_use]
    pub fn absent() -> Self {
        Self(ContentInner::Absent)
    }

    /// A splice that only removes `remove_len` bytes at `offset` (a recorded block
    /// whose SHA-256 is `removed_sha256`). It stores no bytes.
    #[must_use]
    pub fn remove_range(offset: u64, remove_len: u64, removed_sha256: Sha256Hex) -> Self {
        Self(ContentInner::Splice {
            offset,
            remove_len,
            removed_sha256: Some(removed_sha256),
            insert_b64: Vec::new(),
        })
    }

    /// Read access.
    #[must_use]
    pub fn view(&self) -> StepContentView<'_> {
        match &self.0 {
            ContentInner::Whole { bytes_b64 } => StepContentView::Whole { bytes: bytes_b64 },
            ContentInner::Splice {
                offset,
                remove_len,
                removed_sha256,
                insert_b64,
            } => StepContentView::Splice {
                offset: *offset,
                remove_len: *remove_len,
                removed_sha256: removed_sha256.as_ref(),
                insert: insert_b64,
            },
            ContentInner::Absent => StepContentView::Absent,
            ContentInner::LockHolder { bytes_b64 } => {
                StepContentView::LockHolder { bytes: bytes_b64 }
            }
        }
    }

    /// Decoded bytes this content stores (the per-intent bound counts these).
    #[must_use]
    pub fn stored_len(&self) -> usize {
        match &self.0 {
            ContentInner::Whole { bytes_b64 } | ContentInner::LockHolder { bytes_b64 } => {
                bytes_b64.len()
            }
            ContentInner::Splice { insert_b64, .. } => insert_b64.len(),
            ContentInner::Absent => 0,
        }
    }
}

/// Content bounds (m02-plan §5 item 17, P11; ADR-0007 §5.7 "Bounded").
pub mod bounds {
    /// P (the managed OpenSSH file) as a whole target.
    pub const MANAGED_SSH_MAX: usize = 256 << 10;
    /// One key file as a whole target.
    pub const KEY_FILE_MAX: usize = 16 << 10;
    /// P_git as a whole target.
    pub const GIT_MANAGED_MAX: usize = 4 << 10;
    /// One splice's insert (B or B_git).
    pub const INSERT_MAX: usize = 4 << 10;
    /// ⟨r5⟩ The lock holder K's line.
    pub const LOCK_HOLDER_MAX: usize = 128;
    /// Key-file steps per intent.
    pub const KEY_FILES_MAX: usize = 256;
    /// Decoded content per intent.
    pub const INTENT_CONTENT_MAX: usize = 1 << 20;
    /// One file name (staged or displaced).
    pub const NAME_MAX: usize = 255;
    /// One step path.
    pub const PATH_MAX: usize = 4096;
}

/// The fixed prefix of the lock holder line.
const LOCK_HOLDER_PREFIX: &str = "heimdall setup lock, generation ";

/// ⟨r5⟩ The lock holder K's exact bytes (ADR-0007 §5.6, §5.7): one line,
/// `heimdall setup lock, generation <N>, <32 lowercase hex>`, terminated by a single
/// `\n` (the terminator is fixed here; wave-0 verifier escalation E11). `nonce` is
/// fixed at admission and is not part of `plan_digest`.
/// `heimdall_localenv::projection::git::lock_holder` renders through this function.
#[must_use]
pub fn lock_holder_line(generation: u64, nonce: [u8; 16]) -> Vec<u8> {
    format!("{LOCK_HOLDER_PREFIX}{generation}, {}\n", hex_lower(&nonce)).into_bytes()
}

/// Whether `bytes` is exactly a lock holder line for `generation`.
#[must_use]
pub fn is_lock_holder_line(bytes: &[u8], generation: u64) -> bool {
    if bytes.len() > bounds::LOCK_HOLDER_MAX {
        return false;
    }
    let Ok(s) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Some(rest) = s.strip_prefix(LOCK_HOLDER_PREFIX) else {
        return false;
    };
    let Some(line) = rest.strip_suffix('\n') else {
        return false;
    };
    let Some((n, hex)) = line.split_once(", ") else {
        return false;
    };
    n == generation.to_string() && is_lower_hex(hex, 32)
}

/// One file step of a setup intent (ADR-0007 §5.7; m02-plan §5 item 17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStep {
    /// Role.
    pub role: FileRole,
    /// The target path (for the `git_lock` step, `<global file>.lock`).
    pub path: String,
    /// The file as planned.
    pub base: Base,
    /// The file after the step.
    pub target: Target,
    /// The bytes the step writes.
    pub content: StepContent,
    /// Whether this is its item's commit step (ADR-0007 §5.4).
    pub commit: bool,
    /// Random staged name (128 bits), fixed before anything is written; absent for
    /// a target-absent step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_name: Option<String>,
    /// Where the displaced file is left: the staged name on Unix,
    /// `.<name>.hm-displaced-<generation>` on Windows. Present exactly for a step
    /// that replaces an existing file; absent for a create, a target-absent step
    /// and the `git_lock` step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub displaced_name: Option<String>,
}

/// One consented item (ADR-0007 §5.2): an alias name for a managed alias
/// (`alias:<name>`) or Git's SSH selection (`git`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ItemId(pub String);

impl ItemId {
    /// A managed alias item.
    #[must_use]
    pub fn alias(name: &str) -> Self {
        Self(format!("alias:{name}"))
    }

    /// Git's SSH selection.
    #[must_use]
    pub fn git_selection() -> Self {
        Self("git".to_owned())
    }
}

/// ⟨r3⟩ A recorded behaviour state: its digest and whether it was determined when
/// recorded (ADR-0007 §5.2). Only a determined consented state counts as consent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BehaviorState {
    /// Behaviour digest.
    pub digest: BehaviorDigest,
    /// Every directive of the item's relevant behaviour was `Determined` or `Unset`.
    pub determined: bool,
}

/// The two states the last executed `ApplyProjection` decision covering an item
/// recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentedStates {
    /// The approved managed state.
    pub managed: BehaviorState,
    /// The restore state that decision showed in its restore column.
    pub restore: BehaviorState,
    /// The decision.
    pub decision: DecisionId,
}

/// Consent per item (ADR-0007 §5.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// Items.
    #[serde(default)]
    pub items: BTreeMap<ItemId, ConsentedStates>,
}

/// ⟨r3⟩ The projection approval, only in [`SetupIntent::approval`] (m02-plan §5 item
/// 17; frozen). `decide` writes it from an `ApplyProjection` record whose
/// `plan_digest` equals the intent's. A declaration approval cannot be represented
/// here: unknown fields are refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionApproval {
    /// The approved decision record.
    pub decision: DecisionId,
    /// The plan digest it approved.
    pub plan_digest: PlanDigest,
}

/// The durable setup intent, persisted in `RecoveryIntent.local` before any write
/// (ADR-0007 §5.7; frozen).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupIntent {
    /// The digest of the plan this intent executes.
    pub plan_digest: PlanDigest,
    /// What the plan does (apply, rollback, or repair with its kind).
    pub intent: PreviewIntent,
    /// The generation this intent writes (N+1).
    pub generation: u64,
    /// The owner's approval, when a decision was required. Add-only: `None → Some`
    /// once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ProjectionApproval>,
    /// The consented states this intent records at commit.
    pub consent: ConsentRecord,
    /// Every file step, in execution order.
    pub files: Vec<FileStep>,
}

/// Armor suffix of PEM and OpenSSH private keys (as the store refuses for
/// documents). Base64 content would hide it from a substring scan, so
/// [`SetupIntent::validate`] scans the decoded bytes (wave-0 verifier escalation
/// E10).
const PRIVATE_KEY_ARMOR: &[u8] = b"PRIVATE KEY-----";

/// Why a setup intent is refused. Messages are fixed and never echo content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IntentError {
    /// The generation is 0 (an intent writes N+1 ≥ 1).
    #[error("an intent's generation is at least 1")]
    ZeroGeneration,
    /// More steps than a receipt's `u16` step index can name.
    #[error("too many file steps")]
    TooManySteps,
    /// The approval names another plan digest.
    #[error("the approval names another plan digest")]
    ApprovalDigestMismatch,
    /// A step's content variant does not fit its role, base or target.
    #[error("step {step}: content does not fit the step's role, base or target")]
    ShapeMismatch {
        /// Step index.
        step: usize,
    },
    /// A whole target, or an insert-only splice over an absent base, does not hash
    /// to `target.sha256`.
    #[error("step {step}: content does not hash to the target digest")]
    TargetDigestMismatch {
        /// Step index.
        step: usize,
    },
    /// A splice over an absent base that is not insert-only (a non-zero offset or
    /// removal, or a removed digest).
    #[error("step {step}: a splice over an absent base must be insert-only")]
    NotInsertOnly {
        /// Step index.
        step: usize,
    },
    /// A splice over an absent base with an empty insert.
    #[error("step {step}: a splice over an absent base must insert bytes")]
    EmptyInsert {
        /// Step index.
        step: usize,
    },
    /// `remove_len > 0` without `removed_sha256`.
    #[error("step {step}: a removal needs the removed range's digest")]
    RemovedDigestMissing {
        /// Step index.
        step: usize,
    },
    /// `removed_sha256` with `remove_len == 0`.
    #[error("step {step}: a removed digest needs a removal")]
    RemovedDigestUnexpected {
        /// Step index.
        step: usize,
    },
    /// `offset + remove_len` overflows.
    #[error("step {step}: the splice range overflows")]
    RangeOverflow {
        /// Step index.
        step: usize,
    },
    /// A step's content exceeds its bound.
    #[error("step {step}: content exceeds its bound")]
    TooLarge {
        /// Step index.
        step: usize,
    },
    /// More than 256 key files.
    #[error("too many key files")]
    TooManyKeyFiles,
    /// More than 1 MiB of decoded content.
    #[error("the intent's content exceeds its bound")]
    IntentTooLarge,
    /// Decoded content carries private-key armor.
    #[error("step {step}: content carries private key material")]
    PrivateKeyMaterial {
        /// Step index.
        step: usize,
    },
    /// A lock holder that is not the exact one-line form for this generation.
    #[error("step {step}: the lock holder is not the exact one-line form")]
    LockHolderForm {
        /// Step index.
        step: usize,
    },
    /// A `git_lock` step that is not alone or not directly before its `git_include`
    /// step, or a `git_include` step not directly after one.
    #[error("step {step}: the git_lock step must directly precede the git_include step")]
    LockPlacement {
        /// Step index.
        step: usize,
    },
    /// A malformed, missing, extra or duplicated staged or displaced name, or a
    /// malformed or duplicated path.
    #[error("step {step}: malformed or duplicated step names")]
    StepNames {
        /// Step index.
        step: usize,
    },
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= bounds::NAME_MAX
        && name != "."
        && name != ".."
        && !name.bytes().any(|b| matches!(b, b'/' | b'\\' | 0))
}

fn valid_path(path: &str) -> bool {
    !path.is_empty() && path.len() <= bounds::PATH_MAX && !path.bytes().any(|b| b == 0)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

impl SetupIntent {
    /// Every check that needs no base bytes (ADR-0007 §5.7; m02-plan U0
    /// `setup_intent_content_wire_forms`). Run when the intent is built and again
    /// every time it is read; `content::materialize` checks the rest (the base
    /// digest, the removed range and a splice's result over a present base) before
    /// any write.
    pub fn validate(&self) -> Result<(), IntentError> {
        if self.generation == 0 {
            return Err(IntentError::ZeroGeneration);
        }
        if self.files.len() > usize::from(u16::MAX) + 1 {
            return Err(IntentError::TooManySteps);
        }
        if let Some(a) = &self.approval
            && a.plan_digest != self.plan_digest
        {
            return Err(IntentError::ApprovalDigestMismatch);
        }
        let mut total = 0usize;
        let mut keys = 0usize;
        let mut paths = BTreeSet::new();
        let mut staged = BTreeSet::new();
        for (i, step) in self.files.iter().enumerate() {
            self.validate_step(i, step)?;
            if step.role == FileRole::Key {
                keys += 1;
            }
            total = total
                .checked_add(step.content.stored_len())
                .ok_or(IntentError::IntentTooLarge)?;
            if !paths.insert(step.path.as_str()) {
                return Err(IntentError::StepNames { step: i });
            }
            if let Some(n) = &step.staged_name
                && !staged.insert(n.as_str())
            {
                return Err(IntentError::StepNames { step: i });
            }
        }
        if keys > bounds::KEY_FILES_MAX {
            return Err(IntentError::TooManyKeyFiles);
        }
        if total > bounds::INTENT_CONTENT_MAX {
            return Err(IntentError::IntentTooLarge);
        }
        self.validate_lock_placement()
    }

    fn validate_step(&self, i: usize, step: &FileStep) -> Result<(), IntentError> {
        let shape = || IntentError::ShapeMismatch { step: i };
        let names = || IntentError::StepNames { step: i };
        if !valid_path(&step.path) {
            return Err(names());
        }
        // Names: a step that writes bytes has a staged name; only a replace has a
        // displaced name; a target-absent step has neither.
        let writes = !matches!(step.content.view(), StepContentView::Absent);
        let replaces = matches!(step.base, Base::Present { .. }) && step.role != FileRole::GitLock;
        match (&step.staged_name, writes) {
            (Some(n), true) if valid_name(n) => {}
            (None, false) => {}
            _ => return Err(names()),
        }
        match (&step.displaced_name, writes && replaces) {
            (Some(n), true) if valid_name(n) => {}
            (None, false) => {}
            _ => return Err(names()),
        }
        let armor = |bytes: &[u8]| {
            if contains(bytes, PRIVATE_KEY_ARMOR) {
                Err(IntentError::PrivateKeyMaterial { step: i })
            } else {
                Ok(())
            }
        };
        match step.content.view() {
            StepContentView::Whole { bytes } => {
                let max = match step.role {
                    FileRole::ManagedSsh => bounds::MANAGED_SSH_MAX,
                    FileRole::Key => bounds::KEY_FILE_MAX,
                    FileRole::GitManaged => bounds::GIT_MANAGED_MAX,
                    _ => return Err(shape()),
                };
                let Target::Present { sha256 } = &step.target else {
                    return Err(shape());
                };
                if bytes.len() > max {
                    return Err(IntentError::TooLarge { step: i });
                }
                armor(bytes)?;
                if Sha256Hex::of(bytes) != *sha256 {
                    return Err(IntentError::TargetDigestMismatch { step: i });
                }
            }
            StepContentView::Splice {
                offset,
                remove_len,
                removed_sha256,
                insert,
            } => {
                if !matches!(step.role, FileRole::UserSsh | FileRole::GitInclude) {
                    return Err(shape());
                }
                let Target::Present { sha256 } = &step.target else {
                    return Err(shape());
                };
                if insert.len() > bounds::INSERT_MAX {
                    return Err(IntentError::TooLarge { step: i });
                }
                armor(insert)?;
                offset
                    .checked_add(remove_len)
                    .ok_or(IntentError::RangeOverflow { step: i })?;
                match (remove_len > 0, removed_sha256.is_some()) {
                    (true, false) => return Err(IntentError::RemovedDigestMissing { step: i }),
                    (false, true) => {
                        return Err(IntentError::RemovedDigestUnexpected { step: i });
                    }
                    _ => {}
                }
                if step.base == Base::Absent {
                    // An absent base is an empty, insert-only splice input
                    // (ADR-0007 §5.7 "The materializer checks both digests").
                    if offset != 0 || remove_len != 0 || removed_sha256.is_some() {
                        return Err(IntentError::NotInsertOnly { step: i });
                    }
                    if insert.is_empty() {
                        return Err(IntentError::EmptyInsert { step: i });
                    }
                    if Sha256Hex::of(insert) != *sha256 {
                        return Err(IntentError::TargetDigestMismatch { step: i });
                    }
                }
            }
            StepContentView::Absent => {
                if !matches!(
                    step.role,
                    FileRole::ManagedSsh | FileRole::Key | FileRole::GitManaged
                ) || step.target != Target::Absent
                    || step.base == Base::Absent
                {
                    return Err(shape());
                }
            }
            StepContentView::LockHolder { bytes } => {
                if step.role != FileRole::GitLock {
                    return Err(shape());
                }
                if bytes.len() > bounds::LOCK_HOLDER_MAX {
                    return Err(IntentError::TooLarge { step: i });
                }
                if !is_lock_holder_line(bytes, self.generation) {
                    return Err(IntentError::LockHolderForm { step: i });
                }
            }
        }
        if step.role == FileRole::GitLock
            && (step.base != Base::Absent
                || step.target != Target::Absent
                || step.commit
                || step.displaced_name.is_some()
                || !matches!(step.content.view(), StepContentView::LockHolder { .. }))
        {
            return Err(shape());
        }
        Ok(())
    }

    /// ⟨r5⟩ ADR-0007 §5.7 "The `git_lock` step", read fail-closed (escalation E11):
    /// at most one `git_lock` step; every `git_lock` step is directly followed by a
    /// `git_include` step, and every `git_include` step is directly preceded by a
    /// `git_lock` step.
    fn validate_lock_placement(&self) -> Result<(), IntentError> {
        let mut locks = 0usize;
        for (i, step) in self.files.iter().enumerate() {
            match step.role {
                FileRole::GitLock => {
                    locks += 1;
                    let next = self.files.get(i + 1).map(|s| s.role);
                    if locks > 1 || next != Some(FileRole::GitInclude) {
                        return Err(IntentError::LockPlacement { step: i });
                    }
                }
                FileRole::GitInclude => {
                    let prev = i
                        .checked_sub(1)
                        .and_then(|p| self.files.get(p))
                        .map(|s| s.role);
                    if prev != Some(FileRole::GitLock) {
                        return Err(IntentError::LockPlacement { step: i });
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// This intent with its approval removed (the part that never changes once
    /// stored; `heimdall_store`'s add-only rule compares it).
    #[must_use]
    pub fn without_approval(&self) -> SetupIntent {
        SetupIntent {
            approval: None,
            ..self.clone()
        }
    }
}

// --- projection records, resources and commits ------------------------------------

/// Where a projection file is, which file it is, and what it holds: the locator of a
/// `config_projection` resource (ADR-0007 §5.8). Canonical JSON, nonsecret.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProjectionLocator {
    /// Role.
    pub role: FileRole,
    /// Path.
    pub path: String,
    /// The file's identity.
    pub identity: FileIdentity,
    /// Its content digest.
    pub sha256: Sha256Hex,
}

impl ProjectionLocator {
    /// The canonical JSON form stored in `resources.locator`.
    pub fn canonical(&self) -> Result<String, heimdall_contract::canonical::CanonicalError> {
        let value = serde_json::to_value(self)
            .map_err(|_| heimdall_contract::canonical::CanonicalError::NonFiniteNumber)?;
        let bytes = heimdall_contract::canonical::canonical_json(&value)?;
        String::from_utf8(bytes)
            .map_err(|_| heimdall_contract::canonical::CanonicalError::NonFiniteNumber)
    }
}

/// The resource ID of the projection file at (`environment`, `role`, `path`): stable
/// across generations, so a newer generation replaces the older one by generation
/// compare-and-swap (`res_` + the first 16 bytes of a domain-separated SHA-256).
#[must_use]
pub fn projection_resource_id(
    environment: &EnvironmentId,
    role: FileRole,
    path: &str,
) -> ResourceId {
    let mut h = Sha256::new();
    h.update(b"heimdall projection resource\0");
    h.update(environment.as_str().as_bytes());
    h.update([0]);
    h.update(role.as_str().as_bytes());
    h.update([0]);
    h.update(path.as_bytes());
    let digest = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    ResourceId::from_random_bytes(id)
}

/// One item's last committed state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRecord {
    /// Last committed generation.
    pub generation: u64,
    /// The item's files at that generation.
    #[serde(default)]
    pub files: Vec<ProjectionLocator>,
    /// Managed aliases rendered into P (the `ssh` item); empty for `git`.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// The operation that committed it.
    pub operation: OperationId,
    /// When it was committed (the `item.committed` receipt's time).
    pub committed_at: Timestamp,
}

/// The projection record of an environment: what each item last committed
/// (`ProjectionWriter::observe`, previews and `setup status` start from it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionRecord {
    /// Environment.
    pub environment: EnvironmentId,
    /// Items.
    #[serde(default)]
    pub items: BTreeMap<ProjectionItem, ItemRecord>,
}

/// What one item's commit writes besides its `item.committed` receipt, in **one**
/// store transaction (`StageSink::commit_item`, `heimdall_store::Txn::
/// commit_projection_item`; M2-R01).
///
/// Placement: m02-plan §5 item 15 names `ItemCommit` under the app port `StageSink`,
/// but `Txn::commit_projection_item` (§5 item 18) takes it and the store cannot
/// depend on the app, so it lives here and the port uses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemCommit {
    /// The item.
    pub item: ProjectionItem,
    /// The generation committed (N+1).
    pub generation: u64,
    /// The item's `config_projection` resources at that generation.
    pub resources: Vec<ProjectionLocator>,
    /// The environment's projection record after the commit.
    pub record: ProjectionRecord,
    /// The consented states recorded for the item's affected aliases.
    pub consent: ConsentRecord,
}

// --- previews, plans and decision summaries ----------------------------------------

/// One managed alias to render (U2's renderer input).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedAliasSpec {
    /// The alias (`Host` pattern Heimdall owns).
    pub alias: String,
    /// The destination it realizes.
    pub destination: heimdall_contract::ids::DestinationId,
    /// `HostName`.
    pub hostname: String,
    /// `Port`, when not the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// `User`.
    pub account: heimdall_contract::ids::AccountName,
    /// The adopted identity.
    pub identity: heimdall_contract::ids::IdentityId,
    /// `IdentityAgent`: the identity's endpoint, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<heimdall_contract::provider::EndpointRef>,
    /// `IdentityFile`: the materialized public key file.
    pub key_file: String,
}

/// What a preview renders from (catalog, consent and the last record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionSpec {
    /// Environment.
    pub environment: EnvironmentId,
    /// Managed aliases, in render order.
    #[serde(default)]
    pub aliases: Vec<ManagedAliasSpec>,
    /// The last committed record, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<ProjectionRecord>,
    /// The stored consent.
    #[serde(default)]
    pub consent: ConsentRecord,
}

/// The intent of a decision summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryIntent {
    /// An apply.
    Apply,
    /// A rollback.
    Rollback,
    /// A repair.
    Repair,
}

/// The restore column entry of one affected item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRestore {
    /// The item.
    pub item: ItemId,
    /// Its behaviour if its section were removed now.
    pub digest: BehaviorDigest,
}

/// ⟨r2⟩ What an `ApplyProjection` decision shows (m02-plan §5 item 17; ADR-0007
/// §5.2): the before, after and restore columns, bounded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionSummary {
    /// Apply, rollback or repair.
    pub intent: SummaryIntent,
    /// Aliases the plan adds.
    #[serde(default)]
    pub added_aliases: Vec<String>,
    /// Aliases whose behaviour the plan changes.
    #[serde(default)]
    pub changed_aliases: Vec<String>,
    /// Aliases the plan removes.
    #[serde(default)]
    pub removed_aliases: Vec<String>,
    /// Display paths of the files the plan changes (never the `git_lock` step).
    #[serde(default)]
    pub files: Vec<String>,
    /// Whether Git's SSH selection changes.
    pub git: bool,
    /// The restore column.
    #[serde(default)]
    pub restore: Vec<ItemRestore>,
    /// The diff, at most [`ProjectionSummary::MAX_DIFF_TEXT`] bytes.
    pub diff_text: String,
}

impl ProjectionSummary {
    /// Bound of `diff_text` (64 KiB, ADR-0006 §3.1).
    pub const MAX_DIFF_TEXT: usize = heimdall_contract::setup::MAX_DIFF_BYTES;

    /// Whether the summary is within its bounds.
    #[must_use]
    pub fn within_bounds(&self) -> bool {
        self.diff_text.len() <= Self::MAX_DIFF_TEXT
    }
}

/// A preview's result: the wire plan plus everything admission stores
/// (`ProjectionWriter::preview`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionPlan {
    /// The wire plan (`Request::Setup(Preview)` data).
    pub view: SetupPlan,
    /// The generation the plan writes (N+1).
    pub generation: u64,
    /// The consented states the plan records at commit.
    pub consent: ConsentRecord,
    /// Every file step with its content, in execution order.
    pub files: Vec<FileStep>,
    /// The decision summary, when a decision is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<ProjectionSummary>,
}

impl ProjectionPlan {
    /// The intent admission stores, without an approval.
    #[must_use]
    pub fn intent(&self) -> SetupIntent {
        SetupIntent {
            plan_digest: self.view.plan_digest.clone(),
            intent: self.view.intent.clone(),
            generation: self.generation,
            approval: None,
            consent: self.consent.clone(),
            files: self.files.clone(),
        }
    }
}

// --- recovery types that cross the ProjectionWriter port (ADR-0007 §5.7; U4) --------

/// A step's shape (ADR-0007 §5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepShape {
    /// Base present, target present.
    Replace,
    /// Base absent.
    Create,
    /// ⟨r5⟩ The Git lock holder (the `git_lock` step).
    GitLock,
    /// Target absent: the cleaner's.
    Removal,
}

impl StepShape {
    /// The shape of `step`.
    #[must_use]
    pub fn of(step: &FileStep) -> StepShape {
        if step.role == FileRole::GitLock {
            StepShape::GitLock
        } else if step.target == Target::Absent {
            StepShape::Removal
        } else if step.base == Base::Absent {
            StepShape::Create
        } else {
            StepShape::Replace
        }
    }
}

/// A step's effective phase: [`FilePhase`] without `held`, so `held` cannot be a
/// recovery input (⟨r5⟩ M2-T04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EffectivePhase {
    /// `file.staged`.
    Staged {
        /// S (K for the `git_lock` step).
        identity: FileIdentity,
    },
    /// `file.validated`.
    Validated {
        /// V, or `None` for an absent base.
        base: Option<FileIdentity>,
    },
    /// `file.exchanged`.
    Exchanged,
    /// `file.post_validated`.
    PostValidated {
        /// Valid or mismatch.
        verdict: PostVerdict,
        /// The identity observed at the displaced name on a mismatch.
        observed: Option<FileIdentity>,
    },
    /// `file.restore_started`.
    RestoreStarted {
        /// Why.
        cause: RestoreCause,
    },
    /// `file.restored`.
    Restored,
    /// `file.settling`.
    Settling {
        /// Source.
        source: SettleSource,
        /// Source name.
        name: String,
        /// Expected identity.
        expected: FileIdentity,
        /// Expected digest.
        expected_sha256: Sha256Hex,
        /// Quarantine slot.
        slot: String,
    },
    /// `file.settled`.
    Settled {
        /// Disposition.
        disposition: SettledDisposition,
    },
    /// `file.settle_conflict`.
    SettleConflict {
        /// What was found.
        found: SettleConflictFound,
        /// Where it was kept.
        kept: Vec<PreservedEntry>,
    },
}

impl TryFrom<FilePhase> for EffectivePhase {
    /// `held` is never an effective phase.
    type Error = FilePhase;
    fn try_from(p: FilePhase) -> Result<Self, FilePhase> {
        Ok(match p {
            FilePhase::Staged { identity } => EffectivePhase::Staged { identity },
            FilePhase::Validated { base } => EffectivePhase::Validated { base },
            FilePhase::Exchanged => EffectivePhase::Exchanged,
            FilePhase::PostValidated { verdict, observed } => {
                EffectivePhase::PostValidated { verdict, observed }
            }
            FilePhase::RestoreStarted { cause } => EffectivePhase::RestoreStarted { cause },
            FilePhase::Restored => EffectivePhase::Restored,
            FilePhase::Settling {
                source,
                name,
                expected,
                expected_sha256,
                slot,
            } => EffectivePhase::Settling {
                source,
                name,
                expected,
                expected_sha256,
                slot,
            },
            FilePhase::Settled { disposition } => EffectivePhase::Settled { disposition },
            FilePhase::SettleConflict { found, kept } => {
                EffectivePhase::SettleConflict { found, kept }
            }
            held @ FilePhase::Held { .. } => return Err(held),
        })
    }
}

/// Whether a restore is due for a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "cause", rename_all = "snake_case")]
pub enum RestoreCtx {
    /// No restore is due.
    NotDue,
    /// Due: after `post_validated{mismatch}` (`file_mismatch`) or after
    /// `post_validated{valid}` with `item.rolling_back` (`transaction_check`).
    Due(RestoreCause),
    /// After `file.restore_started`.
    Started(RestoreCause),
    /// After `file.restored`.
    Done,
}

/// An open settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SettleCtx {
    /// The name `file.settling` recorded as its source.
    pub source: SettleSource,
    /// Part of a create's restore (`file.restored` follows the settlement).
    pub create_restore: bool,
}

/// The item's state from its receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    /// No item receipt.
    Open,
    /// `item.committed`.
    Committed,
    /// `item.rolling_back`.
    RollingBack,
    /// `item.finished`.
    Finished,
}

/// ⟨r5⟩ A step's recovery state, built from the receipt history (ADR-0007 §5.7 "The
/// recovery state"; M2-T04). `recovery::decide`'s input instead of the last
/// receipt; `held` receipts never affect it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryState {
    /// The effective phase, or `None` before any receipt.
    pub phase: Option<EffectivePhase>,
    /// The restore context.
    pub restore: RestoreCtx,
    /// The open settlement, if any.
    pub settlement: Option<SettleCtx>,
    /// The item state.
    pub item: ItemState,
    /// `git_lock` step only: every other step of the Git item is final.
    pub release_due: bool,
}

/// A receipt history that breaks the phase order, or item receipts that contradict
/// each other (→ `Hold(ContradictoryReceipts)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the step's receipts contradict each other")]
pub struct Contradictory;

impl RecoveryState {
    /// Build the recovery state of step `step` from the operation's receipts
    /// (ADR-0007 §5.7). Pure. Drops every `held` receipt, checks the shape's phase
    /// order and the item receipts, and derives the restore and settlement context
    /// and, for the `git_lock` step, `release_due`.
    ///
    /// **Signature** (wave-0 verifier escalation E7, fail-closed reading): the frozen
    /// design names `build(step, receipts)`, but the per-shape phase order and
    /// `release_due` (which steps belong to the Git item, which are removals) do not
    /// follow from a step index and receipts, so the builder also takes the intent's
    /// `files`. Body: U4 (unreachable from any request, restart or CLI path in wave
    /// 0; only U4's `reconcile` calls it).
    pub fn build(
        step: u16,
        files: &[FileStep],
        receipts: &[StageReceipt],
    ) -> Result<RecoveryState, Contradictory> {
        let _ = (step, files, receipts);
        todo!("M02-U4 RecoveryState::build (ADR-0007 §5.7 \"The recovery state\")")
    }
}

/// Which recorded entry an observed name holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedRole {
    /// S: the staged file (K for the `git_lock` step).
    S,
    /// V: the validated base.
    V,
    /// D: the identity `post_validated{mismatch}` recorded.
    D,
    /// Q: the identity `file.settling` recorded, in a settlement.
    Q,
}

/// Whether a recorded entry still holds its expected content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentState {
    /// The expected digest (S, V, Q, K).
    Unchanged,
    /// Other content, or unreadable within 1 MiB (S′, V′, Q′, K′).
    Modified,
}

/// One observed name's symbol (ADR-0007 §5.7: ∅, S/S′, V/V′, D, Q/Q′, X, ?).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntryObs {
    /// ∅: no entry.
    Absent,
    /// A recorded entry: a regular file owned by the user with link count 1.
    Recorded {
        /// Which.
        which: RecordedRole,
        /// Content.
        content: ContentState,
    },
    /// X: anything else.
    Foreign,
    /// ?: the observation failed.
    Unobservable,
}

/// An impossible observation, rejected by [`StepObservation::normalize`] (ADR-0007
/// §5.7 "Normalization" item 3). The generated tests count these by reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum Impossible {
    /// One recorded identity at two names.
    #[error("one recorded identity at two names")]
    RecordedAtTwoNames,
    /// Q at a name other than the open settlement's source or slot.
    #[error("Q outside the settlement's source and slot")]
    QuarantineOutsideSettlement,
    /// D without a recorded mismatch.
    #[error("D without a recorded mismatch")]
    DisplacedWithoutMismatch,
    /// V for a step whose base was absent.
    #[error("V for a step without a base")]
    ValidatedWithoutBase,
    /// An entry in a slot when no `file.settling` names one.
    #[error("a slot entry without a settlement")]
    SlotWithoutSettlement,
    /// A `git_lock`-only state on another shape.
    #[error("a git_lock-only state on another shape")]
    LockStateOnOtherShape,
}

/// ⟨r5⟩ A normalized observation of a step's three names (ADR-0007 §5.7; M2-T05).
/// Built **only** by [`StepObservation::normalize`], which `observe_step` and the
/// generated tests both call. It holds identities' classifications, never content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct StepObservation {
    path: EntryObs,
    aside: EntryObs,
    slot: EntryObs,
}

impl StepObservation {
    /// The only constructor (ADR-0007 §5.7 "Normalization"): applies the shape rule
    /// and rejects impossible combinations. The role precedence (Q at the
    /// settlement's source and slot, then S, then D only when distinct from S and V,
    /// then V only with a present base) is applied by the classifier that produces
    /// each [`EntryObs`] (`observe_step`). Body: U4 (unreachable from any request,
    /// restart or CLI path in wave 0).
    pub fn normalize(
        path: EntryObs,
        aside: EntryObs,
        slot: EntryObs,
        state: &RecoveryState,
        shape: StepShape,
    ) -> Result<StepObservation, Impossible> {
        let _ = (path, aside, slot, state, shape);
        todo!("M02-U4 StepObservation::normalize (ADR-0007 §5.7 \"Normalization\")")
    }

    /// The path's symbol.
    #[must_use]
    pub fn path(&self) -> EntryObs {
        self.path
    }

    /// The aside name's symbol.
    #[must_use]
    pub fn aside(&self) -> EntryObs {
        self.aside
    }

    /// The quarantine slot's symbol.
    #[must_use]
    pub fn slot(&self) -> EntryObs {
        self.slot
    }
}

/// A directory entry's type, as a fingerprint records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryFileType {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link or reparse point.
    Symlink,
    /// Anything else.
    Other,
}

/// A fingerprint's content part.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FingerprintContent {
    /// The content's SHA-256.
    Sha256 {
        /// Digest.
        sha256: Sha256Hex,
    },
    /// The content could not be read within 1 MiB, or the read failed.
    Unreadable,
}

/// ⟨r5⟩ One observed name's content fingerprint (ADR-0007 §5.7 "Held previews carry
/// content fingerprints"; M2-T03). Digests and metadata only, never bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntryFingerprint {
    /// No entry.
    Absent,
    /// The observation failed.
    Unobservable,
    /// An entry.
    Present {
        /// Identity.
        identity: FileIdentity,
        /// Type.
        file_type: EntryFileType,
        /// Owned by the user.
        owned_by_user: bool,
        /// Link count.
        link_count: u64,
        /// Length in bytes.
        len: u64,
        /// Change time in nanoseconds (Unix `st_ctime`, Windows `ChangeTime`), as a
        /// canonical decimal string.
        #[serde(with = "ns_decimal")]
        changed_ns: i128,
        /// Content digest, or unreadable.
        content: FingerprintContent,
    },
}

/// ⟨r5⟩ A held step's fingerprints (`HeldStep.fingerprint`): the path, the aside
/// name (both names on Windows), and the slot when one is named.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StepFingerprint {
    /// The path.
    pub path: EntryFingerprint,
    /// The aside name(s).
    pub aside: Vec<EntryFingerprint>,
    /// The quarantine slot, when one is named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<EntryFingerprint>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::catalog::{CatalogAction, CatalogIntent};
    use crate::operation::LocalIntent;
    use heimdall_contract::ids::IdentityId;

    const WHOLE: &[u8] =
        b"\xef\xbb\xbfHost work\r\n  HostName example.invalid\r\n  IdentitiesOnly yes\r\n";
    const WHOLE_B64: &str =
        "77u/SG9zdCB3b3JrDQogIEhvc3ROYW1lIGV4YW1wbGUuaW52YWxpZA0KICBJZGVudGl0aWVzT25seSB5ZXMNCg==";
    const INSERT: &[u8] =
        b"\xef\xbb\xbf# heimdall:begin\r\nInclude heimdall.conf\r\n# heimdall:end\r\n";
    const INSERT_B64: &str =
        "77u/IyBoZWltZGFsbDpiZWdpbg0KSW5jbHVkZSBoZWltZGFsbC5jb25mDQojIGhlaW1kYWxsOmVuZA0K";
    const LOCK_BOM: &[u8] = b"\xef\xbb\xbfheimdall setup lock\r\n";
    const LOCK_BOM_B64: &str = "77u/aGVpbWRhbGwgc2V0dXAgbG9jaw0K";
    const LOCK_B64: &str = "aGVpbWRhbGwgc2V0dXAgbG9jaywgZ2VuZXJhdGlvbiAzLCAwMDExMjIzMzQ0NTU2Njc3ODg5OWFhYmJjY2RkZWVmZgo=";
    const NONCE: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn rendered(bytes: &[u8]) -> Rendered {
        Rendered::from_renderer(bytes.to_vec())
    }

    fn digest(n: u8) -> Sha256Hex {
        Sha256Hex::of(&[n])
    }

    fn plan_digest(n: u8) -> PlanDigest {
        PlanDigest::from_sha256([n; 32])
    }

    fn unix(dev: u64, ino: u64, birth: Option<i128>) -> FileIdentity {
        FileIdentity::Unix { dev, ino, birth }
    }

    fn round_trip<T>(value: &T, golden: &str)
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        assert_eq!(serde_json::to_string(value).unwrap(), golden);
        let back: T = serde_json::from_str(golden).unwrap();
        assert_eq!(&back, value);
        assert_eq!(
            serde_json::to_string(&back).unwrap(),
            golden,
            "re-encodes byte-identically"
        );
    }

    fn step(
        role: FileRole,
        path: &str,
        base: Base,
        target: Target,
        content: StepContent,
    ) -> FileStep {
        let writes = !matches!(content.view(), StepContentView::Absent);
        let replaces = matches!(base, Base::Present { .. }) && role != FileRole::GitLock;
        let staged = format!(
            ".{role:?}.hm-stage-{}",
            &Sha256Hex::of(path.as_bytes()).as_str()[..32]
        );
        FileStep {
            role,
            path: path.to_owned(),
            base,
            target,
            content,
            commit: false,
            staged_name: writes.then(|| staged.clone()),
            displaced_name: (writes && replaces).then_some(staged),
        }
    }

    fn whole_step(role: FileRole, path: &str, base: Base, bytes: &[u8]) -> FileStep {
        step(
            role,
            path,
            base,
            Target::Present {
                sha256: Sha256Hex::of(bytes),
            },
            rendered(bytes).into_whole(),
        )
    }

    /// A valid intent: key file, P (replace), the user file (first adoption, absent
    /// base), P_git, the git_lock step, and B_git into an existing global file.
    fn intent() -> SetupIntent {
        let key = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureFixtureFixtureFixtureFixtureFixtureAA fixture\n";
        let mut user = step(
            FileRole::UserSsh,
            "/scratch/ssh/config",
            Base::Absent,
            Target::Present {
                sha256: Sha256Hex::of(INSERT),
            },
            rendered(INSERT).into_splice(0, 0, None),
        );
        user.commit = true;
        let mut b_git = step(
            FileRole::GitInclude,
            "/scratch/gitconfig",
            Base::Present { sha256: digest(1) },
            Target::Present { sha256: digest(2) },
            rendered(b"[include]\n\tpath = heimdall.gitconfig\n").into_splice(17, 0, None),
        );
        b_git.commit = true;
        SetupIntent {
            plan_digest: plan_digest(7),
            intent: PreviewIntent::Apply { include_git: true },
            generation: 3,
            approval: None,
            consent: ConsentRecord::default(),
            files: vec![
                whole_step(
                    FileRole::Key,
                    "/scratch/ssh/heimdall/k1.pub",
                    Base::Absent,
                    key,
                ),
                whole_step(
                    FileRole::ManagedSsh,
                    "/scratch/ssh/heimdall.conf",
                    Base::Present { sha256: digest(3) },
                    WHOLE,
                ),
                user,
                whole_step(
                    FileRole::GitManaged,
                    "/scratch/heimdall.gitconfig",
                    Base::Absent,
                    b"[core]\n\tsshCommand = ssh\n",
                ),
                step(
                    FileRole::GitLock,
                    "/scratch/gitconfig.lock",
                    Base::Absent,
                    Target::Absent,
                    rendered(&lock_holder_line(3, NONCE)).into_lock_holder(),
                ),
                b_git,
            ],
        }
    }

    #[test]
    fn file_identity_wire_forms_with_birth() {
        let with = unix(64769, 1_234_567, Some(1_730_419_200_123_456_789));
        let without = unix(64769, 1_234_567, None);
        let windows = FileIdentity::Windows {
            volume: 3_735_928_559,
            file_id: NONCE,
        };
        round_trip(
            &with,
            r#"{"platform":"unix","dev":64769,"ino":1234567,"birth":"1730419200123456789"}"#,
        );
        round_trip(&without, r#"{"platform":"unix","dev":64769,"ino":1234567}"#);
        round_trip(
            &windows,
            r#"{"platform":"windows","volume":3735928559,"file_id":"00112233445566778899aabbccddeeff"}"#,
        );
        round_trip(
            &unix(u64::MAX, 0, Some(-5)),
            r#"{"platform":"unix","dev":18446744073709551615,"ino":0,"birth":"-5"}"#,
        );

        // Equality: every field present on both is equal, and birth is present on
        // both or on neither. Some(birth) never equals None, in both directions,
        // through `==` and through the helper every comparison uses.
        assert_eq!(with, with.clone());
        assert!(with.same_file(&with.clone()));
        assert_ne!(with, without);
        assert_ne!(without, with);
        assert!(!with.same_file(&without));
        assert!(!without.same_file(&with));
        let other_birth = unix(64769, 1_234_567, Some(1));
        assert_ne!(with, other_birth);
        assert!(!with.same_file(&other_birth));
        assert_ne!(without, unix(64769, 1_234_568, None));
        assert_ne!(
            windows,
            FileIdentity::Windows {
                volume: 3_735_928_559,
                file_id: [0; 16]
            }
        );
        assert_ne!(windows, without);
        // A map keyed by identity separates the birth forms too (Hash agrees).
        let set: BTreeSet<String> = [&with, &without, &other_birth]
            .iter()
            .map(|i| serde_json::to_string(i).unwrap())
            .collect();
        assert_eq!(set.len(), 3);

        // Non-canonical forms are refused, so a stored identity re-encodes exactly.
        for bad in [
            r#"{"platform":"unix","dev":1,"ino":2,"birth":"007"}"#,
            r#"{"platform":"unix","dev":1,"ino":2,"birth":"-0"}"#,
            r#"{"platform":"unix","dev":1,"ino":2,"birth":"+5"}"#,
            r#"{"platform":"unix","dev":1,"ino":2,"birth":5}"#,
            r#"{"platform":"unix","dev":1,"ino":2,"birth":""}"#,
            r#"{"platform":"windows","volume":1,"file_id":"00112233445566778899AABBCCDDEEFF"}"#,
            r#"{"platform":"windows","volume":1,"file_id":"0011"}"#,
            r#"{"platform":"plan9","dev":1,"ino":2}"#,
        ] {
            assert!(serde_json::from_str::<FileIdentity>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn setup_intent_content_wire_forms() {
        // One golden per StepContent variant, with a BOM and CRLF inside the bytes.
        round_trip(
            &rendered(WHOLE).into_whole(),
            &format!(r#"{{"kind":"whole","bytes_b64":"{WHOLE_B64}"}}"#),
        );
        round_trip(
            &rendered(INSERT).into_splice(3, 0, None),
            &format!(
                r#"{{"kind":"splice","offset":3,"remove_len":0,"insert_b64":"{INSERT_B64}"}}"#
            ),
        );
        round_trip(
            &rendered(INSERT).into_splice(3, 60, Some(Sha256Hex::of(INSERT))),
            &format!(
                r#"{{"kind":"splice","offset":3,"remove_len":60,"removed_sha256":"{}","insert_b64":"{INSERT_B64}"}}"#,
                Sha256Hex::of(INSERT)
            ),
        );
        round_trip(
            &StepContent::remove_range(3, 60, Sha256Hex::of(INSERT)),
            &format!(
                r#"{{"kind":"splice","offset":3,"remove_len":60,"removed_sha256":"{}","insert_b64":""}}"#,
                Sha256Hex::of(INSERT)
            ),
        );
        round_trip(&StepContent::absent(), r#"{"kind":"absent"}"#);
        round_trip(
            &rendered(LOCK_BOM).into_lock_holder(),
            &format!(r#"{{"kind":"lock_holder","bytes_b64":"{LOCK_BOM_B64}"}}"#),
        );
        round_trip(
            &rendered(&lock_holder_line(3, NONCE)).into_lock_holder(),
            &format!(r#"{{"kind":"lock_holder","bytes_b64":"{LOCK_B64}"}}"#),
        );
        let whole = rendered(WHOLE).into_whole();
        let StepContentView::Whole { bytes } = whole.view() else {
            panic!("whole");
        };
        assert_eq!(bytes, WHOLE, "BOM and CRLF survive exactly");
        // Base64 must be padded, canonical RFC 4648 §4.
        for bad in [
            r#"{"kind":"whole","bytes_b64":"QQ"}"#,
            r#"{"kind":"whole","bytes_b64":"QR=="}"#,
            r#"{"kind":"whole","bytes_b64":"Q-=="}"#,
            r#"{"kind":"replace","bytes_b64":"QQ=="}"#,
        ] {
            assert!(serde_json::from_str::<StepContent>(bad).is_err(), "{bad}");
        }

        // The whole intent round-trips and validates.
        let good = intent();
        assert_eq!(good.validate(), Ok(()));
        let json = serde_json::to_string(&good).unwrap();
        let back: SetupIntent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, good);
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
        assert_eq!(back.validate(), Ok(()));

        let refuse = |mutate: &dyn Fn(&mut SetupIntent), expect: IntentError| {
            let mut i = intent();
            mutate(&mut i);
            assert_eq!(i.validate(), Err(expect));
        };
        // Whole bytes whose digest is not target.sha256.
        refuse(
            &|i| i.files[1].target = Target::Present { sha256: digest(9) },
            IntentError::TargetDigestMismatch { step: 1 },
        );
        // An insert-only splice over an absent base binds its result digest too.
        refuse(
            &|i| i.files[2].target = Target::Present { sha256: digest(9) },
            IntentError::TargetDigestMismatch { step: 2 },
        );
        // removed_sha256 missing with remove_len > 0, present with remove_len 0.
        refuse(
            &|i| i.files[5].content = rendered(b"x").into_splice(17, 4, None),
            IntentError::RemovedDigestMissing { step: 5 },
        );
        refuse(
            &|i| i.files[5].content = rendered(b"x").into_splice(17, 0, Some(digest(4))),
            IntentError::RemovedDigestUnexpected { step: 5 },
        );
        refuse(
            &|i| i.files[5].content = rendered(b"x").into_splice(u64::MAX, 1, Some(digest(4))),
            IntentError::RangeOverflow { step: 5 },
        );
        // An absent base admits only an insert-only splice with a non-empty insert.
        refuse(
            &|i| i.files[2].content = rendered(INSERT).into_splice(1, 0, None),
            IntentError::NotInsertOnly { step: 2 },
        );
        refuse(
            &|i| i.files[2].content = rendered(INSERT).into_splice(0, 2, Some(digest(4))),
            IntentError::NotInsertOnly { step: 2 },
        );
        refuse(
            &|i| i.files[2].content = rendered(INSERT).into_splice(0, 0, Some(digest(4))),
            IntentError::RemovedDigestUnexpected { step: 2 },
        );
        refuse(
            &|i| i.files[2].content = rendered(b"").into_splice(0, 0, None),
            IntentError::EmptyInsert { step: 2 },
        );
        // Bounds.
        let over = |n: usize| vec![b'a'; n];
        refuse(
            &|i| {
                let b = over(bounds::KEY_FILE_MAX + 1);
                i.files[0] = whole_step(
                    FileRole::Key,
                    "/scratch/ssh/heimdall/k1.pub",
                    Base::Absent,
                    &b,
                );
            },
            IntentError::TooLarge { step: 0 },
        );
        refuse(
            &|i| {
                let b = over(bounds::MANAGED_SSH_MAX + 1);
                i.files[1] = whole_step(
                    FileRole::ManagedSsh,
                    "/scratch/ssh/heimdall.conf",
                    Base::Present { sha256: digest(3) },
                    &b,
                );
            },
            IntentError::TooLarge { step: 1 },
        );
        refuse(
            &|i| {
                let b = over(bounds::GIT_MANAGED_MAX + 1);
                i.files[3] = whole_step(
                    FileRole::GitManaged,
                    "/scratch/heimdall.gitconfig",
                    Base::Absent,
                    &b,
                );
            },
            IntentError::TooLarge { step: 3 },
        );
        refuse(
            &|i| {
                i.files[5].content =
                    rendered(&over(bounds::INSERT_MAX + 1)).into_splice(17, 0, None)
            },
            IntentError::TooLarge { step: 5 },
        );
        refuse(
            &|i| {
                let b = over(bounds::LOCK_HOLDER_MAX + 1);
                i.files[4].content = rendered(&b).into_lock_holder();
            },
            IntentError::TooLarge { step: 4 },
        );
        refuse(
            &|i| {
                for k in 0..=bounds::KEY_FILES_MAX {
                    let path = format!("/scratch/ssh/heimdall/extra{k}.pub");
                    i.files
                        .insert(0, whole_step(FileRole::Key, &path, Base::Absent, b"k\n"));
                }
            },
            IntentError::TooManyKeyFiles,
        );
        refuse(
            &|i| {
                let b = over(bounds::KEY_FILE_MAX);
                for k in 0..=(bounds::INTENT_CONTENT_MAX / bounds::KEY_FILE_MAX) {
                    let path = format!("/scratch/ssh/heimdall/big{k}.pub");
                    i.files
                        .insert(0, whole_step(FileRole::Key, &path, Base::Absent, &b));
                }
            },
            IntentError::IntentTooLarge,
        );
        // Private-key armor hidden inside base64 content is refused (escalation E10).
        refuse(
            &|i| {
                let b = b"-----BEGIN OPENSSH PRIVATE KEY-----\n".to_vec();
                i.files[0] = whole_step(
                    FileRole::Key,
                    "/scratch/ssh/heimdall/k1.pub",
                    Base::Absent,
                    &b,
                );
            },
            IntentError::PrivateKeyMaterial { step: 0 },
        );
        // The lock holder: exact one-line form, this generation, at most 128 bytes.
        refuse(
            &|i| i.files[4].content = rendered(LOCK_BOM).into_lock_holder(),
            IntentError::LockHolderForm { step: 4 },
        );
        refuse(
            &|i| i.files[4].content = rendered(&lock_holder_line(4, NONCE)).into_lock_holder(),
            IntentError::LockHolderForm { step: 4 },
        );
        refuse(
            &|i| {
                let mut line = lock_holder_line(3, NONCE);
                line.pop();
                i.files[4].content = rendered(&line).into_lock_holder();
            },
            IntentError::LockHolderForm { step: 4 },
        );
        refuse(
            &|i| {
                let line = String::from_utf8(lock_holder_line(3, NONCE))
                    .unwrap()
                    .to_uppercase();
                i.files[4].content = rendered(line.as_bytes()).into_lock_holder();
            },
            IntentError::LockHolderForm { step: 4 },
        );
        // The git_lock step: alone, directly before git_include, no base, target,
        // displaced name or commit.
        refuse(
            &|i| {
                let mut second = i.files[4].clone();
                second.path = "/scratch/other.lock".into();
                second.staged_name = Some(".other.hm-stage".into());
                i.files.insert(4, second);
            },
            IntentError::LockPlacement { step: 4 },
        );
        refuse(
            &|i| {
                let lock = i.files.remove(4);
                i.files.insert(3, lock);
            },
            IntentError::LockPlacement { step: 3 },
        );
        refuse(
            &|i| {
                i.files.remove(4);
            },
            IntentError::LockPlacement { step: 4 },
        );
        refuse(
            &|i| i.files[4].base = Base::Present { sha256: digest(5) },
            IntentError::ShapeMismatch { step: 4 },
        );
        refuse(
            &|i| i.files[4].target = Target::Present { sha256: digest(5) },
            IntentError::ShapeMismatch { step: 4 },
        );
        refuse(
            &|i| i.files[4].displaced_name = Some(".gitconfig.hm-displaced-3".into()),
            IntentError::StepNames { step: 4 },
        );
        refuse(
            &|i| i.files[4].commit = true,
            IntentError::ShapeMismatch { step: 4 },
        );
        refuse(
            &|i| i.files[1].content = rendered(&lock_holder_line(3, NONCE)).into_lock_holder(),
            IntentError::ShapeMismatch { step: 1 },
        );
        // Variant/role fit, names, approval and generation.
        refuse(
            &|i| i.files[0].content = rendered(b"k").into_splice(0, 0, None),
            IntentError::ShapeMismatch { step: 0 },
        );
        refuse(
            &|i| i.files[2].content = rendered(INSERT).into_whole(),
            IntentError::ShapeMismatch { step: 2 },
        );
        refuse(
            &|i| i.files[1].displaced_name = None,
            IntentError::StepNames { step: 1 },
        );
        refuse(
            &|i| i.files[0].displaced_name = Some(".k1.hm-displaced-3".into()),
            IntentError::StepNames { step: 0 },
        );
        refuse(
            &|i| i.files[0].staged_name = Some("a/b".into()),
            IntentError::StepNames { step: 0 },
        );
        refuse(
            &|i| {
                let first = i.files[0].staged_name.clone();
                i.files[3].staged_name = first;
            },
            IntentError::StepNames { step: 3 },
        );
        refuse(
            &|i| {
                i.approval = Some(ProjectionApproval {
                    decision: DecisionId::from_random_bytes([1; 16]),
                    plan_digest: plan_digest(8),
                });
            },
            IntentError::ApprovalDigestMismatch,
        );
        refuse(&|i| i.generation = 0, IntentError::ZeroGeneration);

        // A target-absent step: Heimdall's own file, no names, an existing base.
        let mut removal = intent();
        removal.files = vec![step(
            FileRole::ManagedSsh,
            "/scratch/ssh/heimdall.conf",
            Base::Present { sha256: digest(3) },
            Target::Absent,
            StepContent::absent(),
        )];
        assert_eq!(removal.validate(), Ok(()));
        removal.files[0].role = FileRole::UserSsh;
        assert_eq!(
            removal.validate(),
            Err(IntentError::ShapeMismatch { step: 0 })
        );
    }

    #[test]
    fn approval_wire_forms() {
        let projection = ProjectionApproval {
            decision: DecisionId::from_random_bytes([1; 16]),
            plan_digest: plan_digest(7),
        };
        let pd = "07".repeat(32);
        round_trip(
            &projection,
            &format!(
                r#"{{"decision":"dec_01010101010101010101010101010101","plan_digest":"{pd}"}}"#
            ),
        );
        let declaration = crate::catalog::DeclarationApproval {
            decision: DecisionId::from_random_bytes([2; 16]),
            identity: IdentityId::from_random_bytes([3; 16]),
            fingerprint: "SHA256:fixturefingerprint".into(),
            endpoint: heimdall_contract::provider::EndpointRef {
                kind: heimdall_contract::provider::EndpointKind::UnixSocket,
                locator: "/scratch/agent.sock".into(),
            },
            interaction: heimdall_contract::catalog::DeclaredInteraction::None,
            valid_until: "2026-12-01T00:00:00Z".parse().unwrap(),
        };
        let declaration_json = concat!(
            r#"{"decision":"dec_02020202020202020202020202020202","#,
            r#""identity":"idn_03030303030303030303030303030303","#,
            r#""fingerprint":"SHA256:fixturefingerprint","#,
            r#""endpoint":{"kind":"unix_socket","locator":"/scratch/agent.sock"},"#,
            r#""interaction":"none","valid_until":"2026-12-01T00:00:00Z"}"#
        );
        round_trip(&declaration, declaration_json);

        // Each approval lives only in its own intent: a SetupIntent carrying a
        // declaration approval, or a CatalogIntent carrying a projection approval,
        // does not decode.
        let mut setup = intent();
        setup.approval = Some(projection.clone());
        let mut setup_json: serde_json::Value = serde_json::to_value(&setup).unwrap();
        assert!(serde_json::from_value::<SetupIntent>(setup_json.clone()).is_ok());
        setup_json["approval"] = serde_json::from_str(declaration_json).unwrap();
        assert!(serde_json::from_value::<SetupIntent>(setup_json.clone()).is_err());
        let mut both = serde_json::to_value(&projection).unwrap();
        both["identity"] = serde_json::json!("idn_03030303030303030303030303030303");
        setup_json["approval"] = both;
        assert!(
            serde_json::from_value::<SetupIntent>(setup_json).is_err(),
            "a superset of both approvals is refused too"
        );

        let catalog = CatalogIntent {
            action: CatalogAction::DeclareInteraction {
                identity: IdentityId::from_random_bytes([3; 16]),
                interaction: heimdall_contract::catalog::DeclaredInteraction::None,
            },
            approval: Some(declaration),
        };
        assert_eq!(catalog.validate(), Ok(()));
        let local = LocalIntent::Catalog(catalog);
        let mut catalog_json = serde_json::to_value(&local).unwrap();
        assert_eq!(catalog_json["kind"], "catalog");
        assert_eq!(
            serde_json::from_value::<LocalIntent>(catalog_json.clone()).unwrap(),
            local
        );
        catalog_json["approval"] = serde_json::to_value(&projection).unwrap();
        assert!(serde_json::from_value::<LocalIntent>(catalog_json).is_err());

        let local_setup = LocalIntent::Setup(setup);
        let json = serde_json::to_value(&local_setup).unwrap();
        assert_eq!(json["kind"], "setup");
        assert_eq!(
            serde_json::from_value::<LocalIntent>(json).unwrap(),
            local_setup
        );
    }

    #[test]
    fn lock_holder_line_is_one_bounded_line() {
        let line = lock_holder_line(u64::MAX, [0xff; 16]);
        assert!(line.len() <= bounds::LOCK_HOLDER_MAX);
        assert!(is_lock_holder_line(&line, u64::MAX));
        assert_eq!(line.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(
            lock_holder_line(3, NONCE),
            b"heimdall setup lock, generation 3, 00112233445566778899aabbccddeeff\n"
        );
        assert!(!is_lock_holder_line(
            b"heimdall setup lock, generation 03, 00112233445566778899aabbccddeeff\n",
            3
        ));
    }

    #[test]
    fn step_shapes_follow_role_base_and_target() {
        let i = intent();
        let shapes: Vec<StepShape> = i.files.iter().map(StepShape::of).collect();
        assert_eq!(
            shapes,
            [
                StepShape::Create,
                StepShape::Replace,
                StepShape::Create,
                StepShape::Create,
                StepShape::GitLock,
                StepShape::Replace
            ]
        );
        let removal = step(
            FileRole::Key,
            "/scratch/k.pub",
            Base::Present { sha256: digest(1) },
            Target::Absent,
            StepContent::absent(),
        );
        assert_eq!(StepShape::of(&removal), StepShape::Removal);
        // `held` is never an effective phase.
        let held = FilePhase::Held {
            reason: crate::operation::HoldReason::Unmatched,
            observed: Vec::new(),
        };
        assert!(EffectivePhase::try_from(held).is_err());
        assert_eq!(
            EffectivePhase::try_from(FilePhase::Exchanged),
            Ok(EffectivePhase::Exchanged)
        );
    }

    #[test]
    fn fingerprints_hold_metadata_and_digests_only() {
        let fp = StepFingerprint {
            path: EntryFingerprint::Present {
                identity: unix(1, 2, Some(3)),
                file_type: EntryFileType::Regular,
                owned_by_user: true,
                link_count: 1,
                len: 64,
                changed_ns: 1_730_419_200_000_000_001,
                content: FingerprintContent::Sha256 {
                    sha256: Sha256Hex::of(WHOLE),
                },
            },
            aside: vec![EntryFingerprint::Absent, EntryFingerprint::Unobservable],
            slot: Some(EntryFingerprint::Present {
                identity: unix(1, 9, None),
                file_type: EntryFileType::Regular,
                owned_by_user: true,
                link_count: 1,
                len: 2 << 20,
                changed_ns: 7,
                content: FingerprintContent::Unreadable,
            }),
        };
        let json = serde_json::to_string(&fp).unwrap();
        assert_eq!(serde_json::from_str::<StepFingerprint>(&json).unwrap(), fp);
        assert!(json.contains(r#""changed_ns":"1730419200000000001""#));
        assert!(!json.contains("Host work"), "no bytes, only digests");
    }

    #[test]
    fn projection_locator_is_canonical_and_resource_ids_are_stable() {
        let env = EnvironmentId::from_random_bytes([4; 16]);
        let loc = ProjectionLocator {
            role: FileRole::ManagedSsh,
            path: "/scratch/ssh/heimdall.conf".into(),
            identity: unix(1, 2, None),
            sha256: Sha256Hex::of(WHOLE),
        };
        let canonical = loc.canonical().unwrap();
        assert!(
            canonical.starts_with(r#"{"identity":{"dev":1,"ino":2,"platform":"unix"},"path":"#)
        );
        let a = projection_resource_id(&env, FileRole::ManagedSsh, &loc.path);
        assert_eq!(
            a,
            projection_resource_id(&env, FileRole::ManagedSsh, &loc.path)
        );
        assert_ne!(a, projection_resource_id(&env, FileRole::Key, &loc.path));
        assert_ne!(
            a,
            projection_resource_id(
                &EnvironmentId::from_random_bytes([5; 16]),
                FileRole::ManagedSsh,
                &loc.path
            )
        );
    }

    /// E9: `Rendered` is built only by the renderers. Scans every production source
    /// file of the workspace for its constructor.
    #[test]
    fn rendered_is_built_only_by_the_renderers() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        let Ok(crates) = std::fs::read_dir(root.join("crates")) else {
            panic!("workspace crates directory not found");
        };
        for c in crates.flatten() {
            walk(&c.path().join("src"), &mut files);
        }
        assert!(!files.is_empty());
        let allowed = |rel: &str| {
            rel == "crates/domain/src/projection.rs"
                || rel == "crates/sshconf/src/render.rs"
                || rel.starts_with("crates/sshconf/src/render/")
                || rel == "crates/localenv/src/materialize.rs"
                || rel == "crates/localenv/src/projection/git.rs"
        };
        let needle = concat!("from_", "renderer(");
        let mut offenders = Vec::new();
        for f in files {
            let rel = f
                .strip_prefix(&root)
                .unwrap_or(&f)
                .to_string_lossy()
                .replace('\\', "/");
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            if text.contains(needle) && !allowed(&rel) {
                offenders.push(rel);
            }
        }
        assert!(
            offenders.is_empty(),
            "Rendered built outside the renderers: {offenders:?}"
        );
    }

    mod props {
        use super::*;
        use proptest::prelude::*;
        use proptest::test_runner::{FileFailurePersistence, RngSeed};

        /// 256 cases, fixed seed unless `PROPTEST_RNG_SEED` is set (reproduces).
        fn config() -> ProptestConfig {
            let mut c = ProptestConfig {
                cases: 256,
                failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                    "proptest-regressions",
                ))),
                ..ProptestConfig::default()
            };
            if matches!(c.rng_seed, RngSeed::Random) {
                c.rng_seed = RngSeed::Fixed(0x4d30_3257_305f_5043);
            }
            c
        }

        proptest! {
            #![proptest_config(config())]

            /// Any bytes survive the base64 wire form exactly, and a whole target
            /// validates exactly when its digest is the target's.
            #[test]
            fn step_content_round_trips_and_binds_its_digest(
                bytes in prop::collection::vec(any::<u8>(), 0..2048),
                other in any::<u8>(),
            ) {
                let content = rendered(&bytes).into_whole();
                let json = serde_json::to_string(&content).unwrap();
                let back: StepContent = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(&back, &content);
                prop_assert_eq!(serde_json::to_string(&back).unwrap(), json);

                let mut i = intent();
                i.files[1] = whole_step(
                    FileRole::ManagedSsh,
                    "/scratch/ssh/heimdall.conf",
                    Base::Present { sha256: digest(3) },
                    &bytes,
                );
                let armor = contains(&bytes, PRIVATE_KEY_ARMOR);
                prop_assert_eq!(i.validate().is_ok(), !armor);
                let mut wrong = bytes.clone();
                wrong.push(other);
                i.files[1].target = Target::Present { sha256: Sha256Hex::of(&wrong) };
                prop_assert!(i.validate().is_err());
            }

            /// Identity equality is field equality with birth on both or neither.
            #[test]
            fn file_identity_equality_never_wildcards_birth(
                dev in any::<u64>(), ino in any::<u64>(), b1 in any::<i64>(), b2 in any::<i64>(),
            ) {
                let some1 = unix(dev, ino, Some(i128::from(b1)));
                let some2 = unix(dev, ino, Some(i128::from(b2)));
                let none = unix(dev, ino, None);
                prop_assert!(!some1.same_file(&none) && !none.same_file(&some1));
                prop_assert_eq!(some1.same_file(&some2), b1 == b2);
                for id in [&some1, &none] {
                    let json = serde_json::to_string(id).unwrap();
                    let back: FileIdentity = serde_json::from_str(&json).unwrap();
                    prop_assert_eq!(&back, id);
                }
            }
        }
    }
}
