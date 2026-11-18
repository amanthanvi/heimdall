//! The `.heimdall.toml` manifest (ADR-0011 §2.2): a bounded, closed-schema **request**.
//!
//! Order of checks (every step before the next; the first failure wins, except that the
//! authority-vocabulary scan runs before every structural check so a key like `trust` is
//! always reported as authority, never as a mere schema error):
//!
//! 1. bytes: at most [`MAX_MANIFEST_BYTES`], valid UTF-8, no NUL;
//! 2. TOML syntax into a value tree (the `toml` crate rejects duplicate keys and
//!    redefined tables);
//! 3. the authority-key scan, at any depth, `[metadata]` included (§10 item 2 for
//!    `background_work`);
//! 4. depth and pair-count bounds, then the closed schema (`deny_unknown_fields`, except
//!    under `[metadata]`);
//! 5. value grammar: tokens, pairs, capability names, label bound.
//!
//! **Depth rule.** The root table is depth 0; every table or array nested in a container
//! adds 1; scalars add nothing. A container deeper than [`MAX_MANIFEST_DEPTH`] (4) is
//! invalid. So `[access] pairs = [..]` is depth 2 and `[metadata.a.b.c]` is depth 4, the
//! deepest legal table.
//!
//! **Pairs.** [`MAX_MANIFEST_PAIRS`] bounds the `pairs` list (the pairs a manifest names);
//! the same bound is applied to `environments` and `required_capabilities`.

use std::collections::BTreeSet;

use heimdall_contract::envelope::reason::{MANIFEST_AUTHORITY_KEY, MANIFEST_INVALID};
use heimdall_contract::ids::{AccountName, DestinationId};
use heimdall_contract::project::{
    MANIFEST_SCHEMA_VERSION, MAX_MANIFEST_BYTES, MAX_MANIFEST_DEPTH, MAX_MANIFEST_PAIRS,
    MAX_MANIFEST_TOKEN_BYTES, Manifest,
};
use heimdall_contract::request::{AccessPairRef, Capability};
use serde::Deserialize as _;
use sha2::{Digest as _, Sha256};

use crate::{normalized_key, sanitized_key};

/// The longest `project` label accepted, in bytes (descriptive only; ADR-0011 I5).
pub const MAX_LABEL_BYTES: usize = 128;

/// The longest label [`ParsedManifest::label_for_display`] returns, in bytes.
pub const MAX_DISPLAY_LABEL_BYTES: usize = 128;

/// Key names refused at any depth, `[metadata]` included (compared after
/// [`normalized_key`]: ASCII lower-casing and `-` → `_`; matched whole). Quoted keys are the
/// same names. `background_work` is in the list but is allowed at exactly one path,
/// `preferences.background_work`, as a boolean (ADR-0011 §10 item 2).
pub const MANIFEST_AUTHORITY_KEYS: &[&str] = &[
    // --- `heimdall_runtime::config::FORBIDDEN_KEYS`, verbatim (crates/runtime/src/config.rs) ---
    "trusted",
    "trust",
    "trust_project",
    "private_key",
    "identity_file",
    "ssh_key",
    "key_file",
    "socket",
    "socket_path",
    "agent_socket",
    "ssh_auth_sock",
    "control_socket",
    "signing_socket",
    "hook",
    "hooks",
    "script",
    "command",
    "exec",
    "policy",
    "policy_override",
    "override",
    "overrides",
    "authority",
    "issuer",
    "issuing_credential",
    "ca_key",
    "certificate_authority",
    "enroll",
    "enrollment",
    "background_work",
    "unattended",
    "allow_unattended",
    "auto_approve",
    "approve",
    "approved",
    "consent",
    "attended",
    // --- ADR-0011 §2.2's list, the names `FORBIDDEN_KEYS` lacks (the rest is covered above) ---
    "key",
    "cutoff",
    "until",
];

/// Why a manifest is `manifest_invalid`. Fixed categories: no variant carries repository
/// text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidReason {
    /// More than [`MAX_MANIFEST_BYTES`].
    #[error("the manifest exceeds the size bound")]
    TooLarge,
    /// Not valid UTF-8.
    #[error("the manifest is not valid UTF-8")]
    NotUtf8,
    /// A NUL byte.
    #[error("the manifest contains a NUL byte")]
    Nul,
    /// Not TOML (including a duplicate key or a redefined table).
    #[error("the manifest is not valid TOML (or repeats a key)")]
    Syntax,
    /// Nested deeper than [`MAX_MANIFEST_DEPTH`].
    #[error("the manifest nests too deeply")]
    TooDeep,
    /// More than [`MAX_MANIFEST_PAIRS`] entries in a list.
    #[error("the manifest lists too many entries")]
    TooManyEntries,
    /// `schema_version` is missing, not an integer, or not 1.
    #[error("the manifest schema_version is not 1")]
    SchemaVersion,
    /// A key outside the closed schema, a missing key, or a value of the wrong type.
    #[error("the manifest does not match its closed schema")]
    Schema,
    /// `preferences.background_work` is not a boolean.
    #[error("preferences.background_work must be a boolean")]
    BackgroundWork,
    /// A value is not a bounded token (`[A-Za-z0-9._:-]`, 1 to 128 bytes).
    #[error("an access value is not a valid token")]
    Token,
    /// A pair is not `destination:account`.
    #[error("an access pair is not destination:account")]
    Pair,
    /// A capability name the contract does not know.
    #[error("an unknown capability name")]
    Capability,
    /// The `project` label exceeds [`MAX_LABEL_BYTES`].
    #[error("the project label is too long")]
    Label,
}

/// A manifest the parser refused. Maps to exactly two stable reasons ([`Self::reason`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// Authority vocabulary at any depth. Carries the key name sanitized to token
    /// characters and at most 64 bytes; never the value, never other repository text.
    #[error("the manifest uses authority vocabulary: key `{0}`")]
    AuthorityKey(String),
    /// Everything else.
    #[error("the manifest is invalid: {0}")]
    Invalid(InvalidReason),
}

impl ManifestError {
    /// The stable envelope reason: `manifest_authority_key` or `manifest_invalid`.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::AuthorityKey(_) => MANIFEST_AUTHORITY_KEY,
            Self::Invalid(_) => MANIFEST_INVALID,
        }
    }
}

/// A manifest that passed every check, with what the review needs.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedManifest {
    /// The decoded closed schema.
    pub manifest: Manifest,
    /// [`access_digest`] of `manifest`.
    pub access_digest: String,
    /// The requested pairs, sorted and deduplicated.
    pub pairs: Vec<AccessPairRef>,
    /// The requested environment labels, sorted and deduplicated.
    pub environments: Vec<String>,
    /// The requested capabilities, sorted and deduplicated.
    pub capabilities: Vec<Capability>,
    /// The requested lock behaviour (`preferences.background_work`; absent = false).
    pub background_work: bool,
}

impl ParsedManifest {
    /// The `project` label made safe to quote in a decision (ADR-0011 I5): every control
    /// character stripped (C0, C1, DEL, and Unicode line, bidi and other format controls),
    /// truncated to [`MAX_DISPLAY_LABEL_BYTES`] on a char boundary. `None` when there is no
    /// label or nothing printable remains.
    #[must_use]
    pub fn label_for_display(&self) -> Option<String> {
        let label = self.manifest.project.as_deref()?;
        let mut out = String::new();
        for c in label.chars().filter(|c| !is_display_control(*c)) {
            if out.len() + c.len_utf8() > MAX_DISPLAY_LABEL_BYTES {
                break;
            }
            out.push(c);
        }
        let trimmed = out.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    }
}

/// A character that must never reach a terminal or a decision as repository text.
fn is_display_control(c: char) -> bool {
    c.is_control()
        || matches!(
            u32::from(c),
            0x00AD
                | 0x061C
                | 0x180E
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x206F
                | 0xFEFF
                | 0xFFF9..=0xFFFB
                | 0x1D173..=0x1D17A
                | 0xE0000..=0xE007F
        )
}

fn invalid(reason: InvalidReason) -> ManifestError {
    ManifestError::Invalid(reason)
}

/// Parse a manifest. See the module doc for the order of checks. Total: never panics.
pub fn parse_manifest(bytes: &[u8]) -> Result<ParsedManifest, ManifestError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(invalid(InvalidReason::TooLarge));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid(InvalidReason::NotUtf8))?;
    if bytes.contains(&0) {
        return Err(invalid(InvalidReason::Nul));
    }
    let mut table: toml::Table =
        toml::from_str(text).map_err(|_| invalid(InvalidReason::Syntax))?;

    let mut scan = Scan::default();
    scan.table(&table, 0, Position::Root)?;
    if scan.too_deep {
        return Err(invalid(InvalidReason::TooDeep));
    }
    if scan.background_work_not_bool {
        return Err(invalid(InvalidReason::BackgroundWork));
    }

    match table.get("schema_version") {
        Some(toml::Value::Integer(v)) if *v == i64::from(MANIFEST_SCHEMA_VERSION) => {}
        _ => return Err(invalid(InvalidReason::SchemaVersion)),
    }

    // `[metadata]` is ignored but must still decode into the contract's JSON map: TOML
    // datetimes have no JSON form, so they become strings first.
    if let Some(metadata) = table.get_mut("metadata") {
        stringify_datetimes(metadata);
    }
    let manifest = Manifest::deserialize(toml::Value::Table(table))
        .map_err(|_| invalid(InvalidReason::Schema))?;

    validate_values(&manifest)?;
    let (pairs, environments, capabilities) = canonical_lists(&manifest)?;
    Ok(ParsedManifest {
        access_digest: access_digest(&manifest),
        background_work: manifest.preferences.background_work.unwrap_or(false),
        manifest,
        pairs,
        environments,
        capabilities,
    })
}

/// Where a table sits, as far as the one exemption needs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Position {
    /// The root table.
    Root,
    /// The table at exactly `preferences` (a direct child of the root).
    Preferences,
    /// Anywhere else.
    Other,
}

/// Containers deeper than this are not descended into (the file is invalid regardless);
/// the `toml` crate's own recursion limit is far lower, this is the second line.
const SCAN_DEPTH_STOP: usize = 64;

#[derive(Default)]
struct Scan {
    too_deep: bool,
    background_work_not_bool: bool,
}

impl Scan {
    fn table(
        &mut self,
        table: &toml::Table,
        depth: usize,
        position: Position,
    ) -> Result<(), ManifestError> {
        if depth > MAX_MANIFEST_DEPTH {
            self.too_deep = true;
        }
        if depth > SCAN_DEPTH_STOP {
            return Ok(());
        }
        for (key, value) in table {
            let exempt = position == Position::Preferences && key == "background_work";
            if exempt {
                if !value.is_bool() {
                    self.background_work_not_bool = true;
                }
            } else if MANIFEST_AUTHORITY_KEYS.contains(&normalized_key(key).as_str()) {
                return Err(ManifestError::AuthorityKey(sanitized_key(key)));
            }
            let child = if position == Position::Root && key == "preferences" {
                Position::Preferences
            } else {
                Position::Other
            };
            self.value(value, depth + 1, child)?;
        }
        Ok(())
    }

    fn value(
        &mut self,
        value: &toml::Value,
        depth: usize,
        position: Position,
    ) -> Result<(), ManifestError> {
        match value {
            toml::Value::Table(t) => self.table(t, depth, position),
            toml::Value::Array(items) => {
                if depth > MAX_MANIFEST_DEPTH {
                    self.too_deep = true;
                }
                if depth > SCAN_DEPTH_STOP {
                    return Ok(());
                }
                // An array keeps its own position for the tables it holds only as
                // `Other`: `[[preferences]]` is not the `preferences` table.
                items
                    .iter()
                    .try_for_each(|v| self.value(v, depth + 1, Position::Other))
            }
            _ => Ok(()),
        }
    }
}

fn stringify_datetimes(value: &mut toml::Value) {
    match value {
        toml::Value::Datetime(d) => *value = toml::Value::String(d.to_string()),
        toml::Value::Table(t) => t.iter_mut().for_each(|(_, v)| stringify_datetimes(v)),
        toml::Value::Array(a) => a.iter_mut().for_each(stringify_datetimes),
        _ => {}
    }
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_MANIFEST_TOKEN_BYTES
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn validate_values(manifest: &Manifest) -> Result<(), ManifestError> {
    if manifest
        .project
        .as_deref()
        .is_some_and(|p| p.len() > MAX_LABEL_BYTES)
    {
        return Err(invalid(InvalidReason::Label));
    }
    let access = &manifest.access;
    // `ProfileId` already refused anything but a bounded token while decoding; re-check
    // against the manifest's own bound so the two cannot drift.
    if !is_token(access.profile.as_str()) {
        return Err(invalid(InvalidReason::Token));
    }
    for list in [
        &access.pairs,
        &access.environments,
        &access.required_capabilities,
    ] {
        if list.len() > MAX_MANIFEST_PAIRS {
            return Err(invalid(InvalidReason::TooManyEntries));
        }
        if list.iter().any(|s| !is_token(s)) {
            return Err(invalid(InvalidReason::Token));
        }
    }
    Ok(())
}

/// Parse `destination:account` the way `AccessPairRef` is built: exactly one `:`, each half
/// a bounded identifier token.
fn parse_pair(s: &str) -> Result<AccessPairRef, ManifestError> {
    let (destination, account) = s.split_once(':').ok_or(invalid(InvalidReason::Pair))?;
    if account.contains(':') {
        return Err(invalid(InvalidReason::Pair));
    }
    Ok(AccessPairRef {
        destination: DestinationId::parse(destination).map_err(|_| invalid(InvalidReason::Pair))?,
        account: AccountName::parse(account).map_err(|_| invalid(InvalidReason::Pair))?,
    })
}

type CanonicalLists = (Vec<AccessPairRef>, Vec<String>, Vec<Capability>);

fn canonical_lists(manifest: &Manifest) -> Result<CanonicalLists, ManifestError> {
    let access = &manifest.access;
    let pairs = access
        .pairs
        .iter()
        .map(|p| parse_pair(p))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let capabilities = access
        .required_capabilities
        .iter()
        .map(|c| {
            serde_json::from_value::<Capability>(serde_json::Value::String(c.clone()))
                .map_err(|_| invalid(InvalidReason::Capability))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let environments: BTreeSet<String> = access.environments.iter().cloned().collect();
    Ok((
        pairs.into_iter().collect(),
        environments.into_iter().collect(),
        capabilities.into_iter().collect(),
    ))
}

const DIGEST_DOMAIN: &[u8] = b"heimdall-manifest-access/1\n";

fn put(hasher: &mut Sha256, bytes: &[u8]) {
    // A 64-bit length prefix: no field can run into the next.
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn put_set(hasher: &mut Sha256, tag: &[u8], items: &BTreeSet<&str>) {
    put(hasher, tag);
    hasher.update((items.len() as u64).to_be_bytes());
    for item in items {
        put(hasher, item.as_bytes());
    }
}

/// The access digest: lower-case hex SHA-256, domain-separated, over the canonical form of
/// the policy-sensitive fields only (ADR-0011 §2.2): profile; pairs, environments and
/// required capabilities (each sorted and deduplicated); `background_work` (absent =
/// false). The label, `[metadata]`, comments, key order and whitespace never reach it.
#[must_use]
pub fn access_digest(manifest: &Manifest) -> String {
    let access = &manifest.access;
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    put(&mut hasher, b"profile");
    put(&mut hasher, access.profile.as_str().as_bytes());
    put_set(
        &mut hasher,
        b"pairs",
        &access.pairs.iter().map(String::as_str).collect(),
    );
    put_set(
        &mut hasher,
        b"environments",
        &access.environments.iter().map(String::as_str).collect(),
    );
    put_set(
        &mut hasher,
        b"required_capabilities",
        &access
            .required_capabilities
            .iter()
            .map(String::as_str)
            .collect(),
    );
    put(&mut hasher, b"background_work");
    hasher.update([u8::from(
        manifest.preferences.background_work.unwrap_or(false),
    )]);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}
