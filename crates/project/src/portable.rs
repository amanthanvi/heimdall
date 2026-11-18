//! The portable bundle, v1 (ADR-0011 §2.4 I4): catalog intent only.
//!
//! **Emit** ([`emit_bundle`]) is pure and deterministic: destinations, identity references
//! (public fingerprint and provider kind) and profiles, each sorted; with `redact` the host
//! names, addresses, ports and labels are removed (an alias is replaced by the destination
//! ID, which profiles reference anyway). The `reestablish` list is a fixed set of plain
//! sentences. Policies, workspace records, environment permissions, grants, decisions,
//! enrollments, socket or home paths and private material have no field to travel in.
//!
//! **Parse** ([`parse_bundle`]) is bounded and treats the bytes as hostile: the raw JSON is
//! walked first, and an unknown top-level key or any authority section or key at any depth
//! refuses the bundle ([`BundleError::AuthoritySection`]); only then is it decoded and every
//! value validated. An imported bundle can never carry authority, so it can never
//! self-authorize (I1, I4).

use std::collections::BTreeMap;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{AccountName, DestinationId, ProfileId};
use heimdall_contract::project::{
    PORTABLE_BUNDLE_SCHEMA, PortableBundle, PortableDestination, PortableIdentity, PortableProfile,
};
use heimdall_contract::provider::ProviderKind;
use serde_json::Value;

use crate::manifest::MANIFEST_AUTHORITY_KEYS;
use crate::{normalized_key, sanitized_key};

/// The largest bundle accepted, in bytes.
pub const MAX_BUNDLE_BYTES: usize = 1 << 20;
/// The most entries in each of a bundle's lists (and in a profile's pairs).
pub const MAX_BUNDLE_ENTRIES: usize = 4096;
/// The longest alias or host name, in bytes (the catalog's own bounds).
const MAX_NAME_BYTES: usize = 255;
/// The longest `SHA256:` fingerprint text: the prefix and 43 base64 characters.
const FINGERPRINT_LEN: usize = 7 + 43;
/// JSON nesting is bounded by serde_json's recursion limit (128); a second bound for the
/// walk, which stops descending past this and refuses the bundle.
const MAX_WALK_DEPTH: usize = 64;

/// Section and key names refused at any depth in a bundle (normalized like the manifest's),
/// in addition to [`MANIFEST_AUTHORITY_KEYS`].
const BUNDLE_AUTHORITY_KEYS: &[&str] = &[
    "policies",
    "policy",
    "workspaces",
    "workspace",
    "grants",
    "grant",
    "decisions",
    "decision",
    "enrollments",
    "enrollment",
    "trust",
    "trusted",
    "permissions",
    "automatic_activation",
    "socket",
    "home",
    "private_key",
];

const TOP_LEVEL_KEYS: &[&str] = &[
    "schema",
    "created_at",
    "redacted",
    "destinations",
    "identities",
    "profiles",
    "reestablish",
];
const DESTINATION_KEYS: &[&str] = &[
    "id",
    "alias",
    "hostname",
    "port",
    "account",
    "host_key_fingerprints",
];
const IDENTITY_KEYS: &[&str] = &["fingerprint", "provider"];
const PROFILE_KEYS: &[&str] = &["id", "pairs"];

/// What the importer must re-establish locally: fixed sentences, never derived from input.
pub const REESTABLISH: &[&str] = &[
    "Trust each workspace again on this installation; no workspace trust is imported.",
    "Recreate standing policies here; no policy is imported.",
    "Set each environment's permissions here, including automatic activation.",
    "Re-enroll each destination here; no enrollment or credential is imported.",
    "Verify each host key here; exported fingerprints are shown for comparison and then discarded.",
];

/// Why a bundle was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    /// An unknown top-level key, or an authority section or key at any depth. Carries the
    /// key name sanitized to token characters, at most 64 bytes.
    #[error("the bundle carries a section or key that is not portable intent: `{0}`")]
    AuthoritySection(String),
    /// More than [`MAX_BUNDLE_BYTES`].
    #[error("the bundle exceeds the size bound")]
    TooLarge,
    /// Not valid JSON (or not valid UTF-8).
    #[error("the bundle is not valid JSON")]
    Syntax,
    /// `schema` is not `heimdall-portable/1`.
    #[error("the bundle schema is not heimdall-portable/1")]
    Schema,
    /// A value, ID, alias, fingerprint or provider failed validation, or a nested object has
    /// an unknown key.
    #[error("the bundle has an invalid value")]
    Invalid,
}

/// The catalog intent to export. The caller supplies only what may travel; there is no field
/// for anything else.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundleInput {
    /// Destinations.
    pub destinations: Vec<PortableDestination>,
    /// Identity references.
    pub identities: Vec<PortableIdentity>,
    /// Profiles.
    pub profiles: Vec<PortableProfile>,
}

/// Build a bundle. `redact` removes host names, addresses, ports and labels (an alias
/// becomes the destination ID). Output lists are sorted by ID (fingerprint for identities)
/// with duplicate IDs collapsed to the first, so the same catalog always yields the same
/// bundle.
#[must_use]
pub fn emit_bundle(input: &BundleInput, redact: bool, created_at: Timestamp) -> PortableBundle {
    let mut destinations: BTreeMap<DestinationId, PortableDestination> = BTreeMap::new();
    for d in &input.destinations {
        let mut d = d.clone();
        d.host_key_fingerprints.sort();
        d.host_key_fingerprints.dedup();
        if redact {
            d.alias = d.id.as_str().to_owned();
            d.hostname = None;
            d.port = None;
        }
        destinations.entry(d.id.clone()).or_insert(d);
    }
    let mut identities: BTreeMap<String, PortableIdentity> = BTreeMap::new();
    for i in &input.identities {
        identities
            .entry(i.fingerprint.clone())
            .or_insert_with(|| i.clone());
    }
    let mut profiles: BTreeMap<ProfileId, PortableProfile> = BTreeMap::new();
    for p in &input.profiles {
        let mut p = p.clone();
        p.pairs.sort();
        p.pairs.dedup();
        profiles.entry(p.id.clone()).or_insert(p);
    }
    PortableBundle {
        schema: PORTABLE_BUNDLE_SCHEMA.to_owned(),
        created_at,
        redacted: redact,
        destinations: destinations.into_values().collect(),
        identities: identities.into_values().collect(),
        profiles: profiles.into_values().collect(),
        reestablish: REESTABLISH.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn is_authority_key(key: &str) -> bool {
    let k = normalized_key(key);
    BUNDLE_AUTHORITY_KEYS.contains(&k.as_str()) || MANIFEST_AUTHORITY_KEYS.contains(&k.as_str())
}

/// Refuse any authority key at any depth. Keys are checked before values; the first hit in
/// the (sorted) key order is reported.
fn walk(value: &Value, depth: usize) -> Result<(), BundleError> {
    if depth > MAX_WALK_DEPTH {
        return Err(BundleError::Invalid);
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if is_authority_key(key) {
                    return Err(BundleError::AuthoritySection(sanitized_key(key)));
                }
                walk(child, depth + 1)?;
            }
            Ok(())
        }
        Value::Array(items) => items.iter().try_for_each(|v| walk(v, depth + 1)),
        _ => Ok(()),
    }
}

/// `object`'s keys must all be in `allowed` (exactly: bundle v1 is closed).
fn closed(object: &serde_json::Map<String, Value>, allowed: &[&str]) -> bool {
    object.keys().all(|k| allowed.contains(&k.as_str()))
}

fn is_token(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// A literal OpenSSH `Host` name (the catalog's own rule: no pattern, whitespace or quote,
/// no leading `-` or `.`).
fn valid_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= MAX_NAME_BYTES
        && !alias.starts_with(['-', '.'])
        && alias
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A host name or address as the catalog renders `HostName`.
fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_NAME_BYTES
        && !host.starts_with('-')
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'[' | b']')
        })
}

/// `SHA256:` and exactly 43 unpadded base64 characters.
fn valid_fingerprint(fp: &str) -> bool {
    fp.len() == FINGERPRINT_LEN
        && fp.strip_prefix("SHA256:").is_some_and(|d| {
            d.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        })
}

/// `destination:account`: exactly one `:`, each half a bounded identifier.
fn valid_pair(pair: &str) -> bool {
    pair.split_once(':').is_some_and(|(d, a)| {
        !a.contains(':') && DestinationId::parse(d).is_ok() && AccountName::parse(a).is_ok()
    })
}

fn validate(bundle: &PortableBundle) -> Result<(), BundleError> {
    if bundle.schema != PORTABLE_BUNDLE_SCHEMA {
        return Err(BundleError::Schema);
    }
    let bounded = bundle.destinations.len() <= MAX_BUNDLE_ENTRIES
        && bundle.identities.len() <= MAX_BUNDLE_ENTRIES
        && bundle.profiles.len() <= MAX_BUNDLE_ENTRIES
        && bundle.reestablish.len() <= MAX_BUNDLE_ENTRIES;
    let destinations = bundle.destinations.iter().all(|d| {
        valid_alias(&d.alias)
            && d.hostname.as_deref().is_none_or(valid_hostname)
            && d.host_key_fingerprints.len() <= MAX_BUNDLE_ENTRIES
            && d.host_key_fingerprints.iter().all(|f| valid_fingerprint(f))
    });
    let identities = bundle.identities.iter().all(|i| {
        valid_fingerprint(&i.fingerprint)
            && is_token(&i.provider, 64)
            && serde_json::from_value::<ProviderKind>(Value::String(i.provider.clone())).is_ok()
    });
    let profiles = bundle
        .profiles
        .iter()
        .all(|p| p.pairs.len() <= MAX_BUNDLE_ENTRIES && p.pairs.iter().all(|s| valid_pair(s)));
    // The re-establish sentences are shown to the importer: bounded text, no controls.
    let sentences = bundle
        .reestablish
        .iter()
        .all(|s| s.len() <= 512 && !s.chars().any(char::is_control));
    if bounded && destinations && identities && profiles && sentences {
        Ok(())
    } else {
        Err(BundleError::Invalid)
    }
}

/// Parse a bundle: at most [`MAX_BUNDLE_BYTES`], JSON. The raw value tree is walked first
/// (unknown top-level keys and authority keys at any depth → [`BundleError::AuthoritySection`]),
/// then decoded, then every value validated. Total: never panics.
pub fn parse_bundle(bytes: &[u8]) -> Result<PortableBundle, BundleError> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(BundleError::TooLarge);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| BundleError::Syntax)?;
    let Value::Object(top) = &value else {
        return Err(BundleError::Invalid);
    };
    // Authority first (any depth), so a section like `policies` is never reported as a
    // mere unknown key.
    walk(&value, 0)?;
    if let Some(unknown) = top.keys().find(|k| !TOP_LEVEL_KEYS.contains(&k.as_str())) {
        return Err(BundleError::AuthoritySection(sanitized_key(unknown)));
    }
    for (key, allowed) in [
        ("destinations", DESTINATION_KEYS),
        ("identities", IDENTITY_KEYS),
        ("profiles", PROFILE_KEYS),
    ] {
        if let Some(Value::Array(items)) = top.get(key) {
            let ok = items
                .iter()
                .all(|i| i.as_object().is_some_and(|o| closed(o, allowed)));
            if !ok {
                return Err(BundleError::Invalid);
            }
        }
    }
    let bundle: PortableBundle = serde_json::from_value(value).map_err(|_| BundleError::Invalid)?;
    validate(&bundle)?;
    Ok(bundle)
}
