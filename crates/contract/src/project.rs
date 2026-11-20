//! ⟨M05⟩ ADR-0006 revision 5 (§17; m05-plan §4 item 11): the two public file formats of
//! trusted work, as data models for their schemas (`project-manifest`,
//! `project-portable`). The parsers are `heimdall_project`'s (M05 U1): the manifest parser
//! is a bounded, closed-schema reader that rejects authority vocabulary at any depth
//! (ADR-0011 §2.2, §10 item 2), which serde alone does not express; these types fix the
//! shape the parser produces and the schema documents.
//!
//! A manifest is a **request**, never an authorization (ADR-0011 I2); a bundle carries
//! portable intent only, never authority (I4).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::ids::{AccountName, DestinationId, ProfileId};

/// The only manifest schema version.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Maximum manifest size, in bytes (ADR-0011 §2.2 "Bounds").
pub const MAX_MANIFEST_BYTES: usize = 64 << 10;
/// Maximum number of pairs a manifest names.
pub const MAX_MANIFEST_PAIRS: usize = 256;
/// Maximum nesting depth of a manifest.
pub const MAX_MANIFEST_DEPTH: usize = 4;
/// Maximum length of a manifest value token, in bytes (`[A-Za-z0-9._:-]`).
pub const MAX_MANIFEST_TOKEN_BYTES: usize = 128;
/// The bundle's schema name.
pub const PORTABLE_BUNDLE_SCHEMA: &str = "heimdall-portable/1";

/// `.heimdall.toml` (ADR-0011 §2.2). Closed: any key outside the schema rejects the whole
/// file (`manifest_invalid`), except under `[metadata]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Always 1.
    pub schema_version: u32,
    /// A descriptive label only: never identity, never a decision's title or action
    /// (ADR-0011 I5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// The requested access.
    pub access: ManifestAccess,
    /// Requested preferences, shown at review.
    #[serde(default)]
    pub preferences: ManifestPreferences,
    /// The only open table; ignored (authority vocabulary is still rejected in it).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// `[access]`: tokens resolved against the local catalog, never paths, commands, URLs or
/// executables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManifestAccess {
    /// A catalog profile.
    pub profile: ProfileId,
    /// An optional subset of the profile, as `destination:account` tokens.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pairs: Vec<String>,
    /// An optional subset of environments, by label.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environments: Vec<String>,
    /// Capability names (`ssh-authentication`, `git-signing`, `agent-forwarding`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
}

/// `[preferences]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManifestPreferences {
    /// A requested lock behaviour (`true`: work while locked), the only place this key is
    /// accepted (ADR-0011 §10 item 2). It reaches a policy only through an attended
    /// `TrustWorkspace` or `ExtendScope`; activation uses the policy's recorded lock
    /// behaviour only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_work: Option<bool>,
}

/// A portable bundle (ADR-0011 I4; `inspect export`, `catalog apply_import`): catalog
/// intent only. Never policies, workspace records, environment permissions, grants,
/// decisions, enrollments, socket or home paths, or private material.
///
/// ⟨M05⟩ Revision 5.1 (ADR-0006 §17.9): a **closed** file format (this type and the three
/// it contains, `deny_unknown_fields`), as the manifest is: a request that carries a bundle
/// with an unknown or authority-bearing key at any level fails to decode, as the file path
/// (`heimdall_project::parse_bundle`) already refuses it. Public requests otherwise tolerate
/// unknown fields (§9); the bundle is a file format that travels inside one (ADR-0011 I4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PortableBundle {
    /// [`PORTABLE_BUNDLE_SCHEMA`].
    pub schema: String,
    /// When it was exported.
    pub created_at: Timestamp,
    /// Whether host names, addresses and labels were redacted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub redacted: bool,
    /// Catalog destinations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<PortableDestination>,
    /// Identity references (public fingerprints and provider kind only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identities: Vec<PortableIdentity>,
    /// Profiles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<PortableProfile>,
    /// What the importing installation must re-establish locally (trust, policies,
    /// enrollments, host keys), as plain sentences.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reestablish: Vec<String>,
}

/// A destination in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PortableDestination {
    /// Destination ID.
    pub id: DestinationId,
    /// The OpenSSH alias.
    pub alias: String,
    /// Host name (absent when redacted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountName>,
    /// Host-key fingerprints, shown in the import preview for comparison and then
    /// discarded: import never trusts a host key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_key_fingerprints: Vec<String>,
    /// ⟨M05⟩ Revision 5.3 (ADR-0006 §17.11 item 23): the jump destination of a managed
    /// destination reached through a single-hop jump (its route's `jump`), as a reference to
    /// that destination's ID. Import resolves it against the bundle or the local catalog, or
    /// refuses the destination (`jump_unresolved`); a jump route is never imported as a direct
    /// one. Omitted for a direct or observed destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump: Option<DestinationId>,
}

/// An identity reference in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PortableIdentity {
    /// `SHA256:` public-key fingerprint.
    pub fingerprint: String,
    /// The provider kind (`native_agent`, `onepassword`, ...).
    pub provider: String,
}

/// A profile in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PortableProfile {
    /// Profile ID.
    pub id: ProfileId,
    /// Its pairs, as `destination:account` tokens.
    pub pairs: Vec<String>,
}
