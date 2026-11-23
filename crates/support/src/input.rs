//! The bundle's inputs (ADR-0014 §5.1 "What it holds"). **Private and provisional**
//! (m08-plan U6a): these are this crate's own types, not the public contract views. M08
//! U6b maps the frozen views onto them, a view field being free text unless its type
//! says otherwise.
//!
//! Every leaf is a [`Code`], a [`Safe`] value (or one of its typed forms), an [`Ident`],
//! a [`FreeText`] or a generic [`Field`]; nothing is a bare `String`. A collector that
//! could not reach a source (the runtime down, doctor not runnable) leaves that section
//! empty; a store that will not open is [`StoreInput::Unreadable`], which has room for the
//! integrity result code and nothing else.

use jiff::Timestamp;

use crate::value::{BuildId, Code, Field, FreeText, Value, Version};

/// Everything a bundle holds.
#[derive(Clone, Debug)]
pub struct BundleInput {
    /// The build: version, commit, target, profile, feature set.
    pub build: BuildInfo,
    /// The platform and the SSH client.
    pub platform: PlatformInfo,
    /// Doctor's findings.
    pub doctor: Vec<Finding>,
    /// The capability table.
    pub capabilities: Vec<StatusRow>,
    /// The claims table.
    pub claims: Vec<StatusRow>,
    /// Setup status: one row per setup item, keyed by its kind.
    pub setup: Vec<StatusRow>,
    /// Projection status: one row per projection, keyed by its kind.
    pub projections: Vec<StatusRow>,
    /// Configuration settings: every key, and the value typed as the setting is.
    pub config: Vec<Setting>,
    /// The store, readable or not.
    pub store: StoreInput,
    /// Log records; exported only as per-code counts with first and last times.
    pub log: Vec<LogRecord>,
}

/// The build.
#[derive(Clone, Debug)]
pub struct BuildInfo {
    /// The product version.
    pub version: Version,
    /// The source commit.
    pub commit: Option<BuildId>,
    /// The target triple, as a code (`x86_64-unknown-linux-gnu`).
    pub target: Code,
    /// The build profile (`release`, `debug`).
    pub profile: Option<Code>,
    /// The enabled features.
    pub features: Vec<Code>,
}

/// The platform.
#[derive(Clone, Debug)]
pub struct PlatformInfo {
    /// The operating system (`macos`, `linux`, `windows`).
    pub os: Code,
    /// The operating-system version.
    pub os_version: Option<Version>,
    /// The architecture (`aarch64`, `x86_64`).
    pub arch: Code,
    /// The SSH client, when one was found. Its `-V` text is free text: the caller parses
    /// it into an implementation code and a version, or leaves this out.
    pub ssh_client: Option<SshClient>,
}

/// The SSH client.
#[derive(Clone, Debug)]
pub struct SshClient {
    /// The implementation (`openssh`, `openssh_windows`).
    pub implementation: Code,
    /// Its version (`9.9p1`).
    pub version: Option<Version>,
}

/// One doctor finding: its code and its typed fields. A finding's detail text is a
/// [`FreeText`] field, and is exported as the note that it was withheld.
#[derive(Clone, Debug)]
pub struct Finding {
    /// The finding code.
    pub code: Code,
    /// The severity.
    pub severity: Option<Code>,
    /// Typed fields.
    pub fields: Vec<Field>,
}

/// One row of a status table (capabilities, claims, setup items, projections): a key
/// code, a state code and typed fields.
#[derive(Clone, Debug)]
pub struct StatusRow {
    /// The capability or claim key, or the setup item or projection kind.
    pub key: Code,
    /// The state.
    pub state: Code,
    /// Typed fields.
    pub fields: Vec<Field>,
}

/// One configuration setting. The key is a code. The value is typed as the setting is: a
/// non-identifying setting is a code or a safe value and is written; an identifying one
/// is an [`crate::Ident`] and is pseudonymized; anything else is free text or a secret
/// and is withheld.
#[derive(Clone, Debug)]
pub struct Setting {
    /// The key (`transport.enabled`).
    pub key: Code,
    /// The value.
    pub value: Value,
}

/// The store, as the bundle sees it.
#[derive(Clone, Debug)]
pub enum StoreInput {
    /// The store opened and was read.
    Readable(StoreContents),
    /// The store would not open: only its integrity result code is reported, and nothing
    /// from inside it (no row counts, no operations).
    Unreadable {
        /// The integrity result (`store_unopenable`, `store_corrupt`).
        integrity: Code,
    },
}

/// What a readable store contributes.
#[derive(Clone, Debug)]
pub struct StoreContents {
    /// The schema version.
    pub schema_version: u64,
    /// The integrity result (`ok`).
    pub integrity: Code,
    /// Row counts per table.
    pub rows: Vec<RowCount>,
    /// The last operations.
    pub operations: Vec<Operation>,
}

/// A table's row count.
#[derive(Clone, Debug)]
pub struct RowCount {
    /// The table.
    pub table: Code,
    /// The number of rows.
    pub count: u64,
}

/// One operation: its code, state, effect status and times.
#[derive(Clone, Debug)]
pub struct Operation {
    /// The operation kind.
    pub kind: Code,
    /// The state.
    pub state: Code,
    /// The effect status.
    pub effect: Option<Code>,
    /// When it was created.
    pub created: Option<Timestamp>,
    /// When it last changed.
    pub updated: Option<Timestamp>,
    /// Typed fields (the operation's ID as an [`crate::Ident`], its result code).
    pub fields: Vec<Field>,
}

/// One log record. Only its code and time are used; the line itself is free text.
#[derive(Clone, Debug)]
pub struct LogRecord {
    /// The record's code.
    pub code: Code,
    /// When it was written.
    pub at: Timestamp,
    /// The line, when the caller has one: never exported, counted as withheld.
    pub line: Option<FreeText>,
}
