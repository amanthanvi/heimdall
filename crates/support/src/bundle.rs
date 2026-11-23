//! Building the bundle, once (ADR-0014 §5.1 "The preview is the bundle", "Plain and
//! bounded").
//!
//! [`build`] walks the input in a fixed order, writes every value its type allows, counts
//! every value it withholds, and returns one [`Bundle`]: the exact bytes, the manifest's
//! digest, a preview that contains those same bytes, and the inverse map, which is
//! separate from the bytes and never inside them. The command previews the bundle and,
//! on confirmation, writes [`Bundle::bytes`]; nothing is collected again in between.
//!
//! # The container
//!
//! One UTF-8 text file. Every line outside the files is ASCII:
//!
//! ```text
//! heimdall-support-bundle 1
//! file manifest.json <byte length>
//! <the manifest's bytes>
//! file build.json <byte length>
//! <the file's bytes>
//! ...
//! end
//! ```
//!
//! Each file is pretty-printed JSON (two-space indent, object keys sorted) followed by
//! one newline, and the byte length on its `file` line counts that newline, so the bytes
//! of every file can be cut out exactly and checked against the manifest. The files, in
//! order: `manifest.json`, then [`FILES`]. The manifest lists every other file's name,
//! byte length and SHA-256, the withheld counts per field path and per reason, the number
//! of pseudonyms per kind, and whether identifiers were included; the SHA-256 of its
//! bytes is the bundle's digest ([`Bundle::manifest_sha256`]).
//!
//! In a record, a value that was withheld is left out and its field name is listed in the
//! record's `withheld` array (`["fields.detail"]`): a diagnostic whose content is text is
//! exported as its code and that note. Durations are whole milliseconds; timestamps are
//! RFC 3339 UTC in whole seconds.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::io;

use jiff::Timestamp;
use serde_json::{Map, Value as Json};
use sha2::{Digest, Sha256};

use crate::input::{
    BuildInfo, BundleInput, Finding, LogRecord, PlatformInfo, Setting, StatusRow, StoreInput,
};
use crate::screen::{
    CODE_MAX_LEN, IdentKind, Withheld, screen_build_id, screen_code, screen_identifier,
    screen_version,
};
use crate::value::{BuildId, Code, Field, Ident, Safe, Value, Version};

/// The largest bundle, in bytes (8 MiB). A larger one is an error, never a truncation.
pub const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;

/// The container's format name (its first line, and the manifest's `format`).
pub const FORMAT: &str = "heimdall-support-bundle";

/// The container's format version.
pub const FORMAT_VERSION: u64 = 1;

/// The manifest's file name; always the first file.
pub const MANIFEST_FILE: &str = "manifest.json";

/// The other files, in container order.
pub const FILES: [&str; 9] = [
    "build.json",
    "platform.json",
    "doctor.json",
    "capabilities.json",
    "setup.json",
    "config.json",
    "store.json",
    "operations.json",
    "log.json",
];

/// The inverse map file's format name.
pub const INVERSE_MAP_FORMAT: &str = "heimdall-support-inverse-map";

/// Longest field name, in bytes, so that every withheld-count key
/// (`<section>.fields.<name>`) stays within [`CODE_MAX_LEN`].
pub const FIELD_NAME_MAX_LEN: usize = 40;

/// The preview's line just before the bundle bytes.
pub const PREVIEW_BEGIN: &str = ">>> bundle bytes begin";

/// The preview's line just after the bundle bytes.
pub const PREVIEW_END: &str = "<<< bundle bytes end";

/// Build options.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// Write the real value, instead of a pseudonym, for fields typed as public
    /// identifiers that pass the identifier checks (`--include-identifiers`). It never
    /// applies to free text or secrets, and a value that fails a check is still withheld.
    pub include_identifiers: bool,
}

/// Why a bundle could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    /// The bundle would exceed [`MAX_BUNDLE_BYTES`].
    #[error("the support bundle would be {bytes} bytes, over the {limit}-byte limit")]
    TooLarge {
        /// The size it would have had.
        bytes: usize,
        /// The limit.
        limit: usize,
    },
    /// A file could not be encoded as JSON (not expected: every value is a string, an
    /// integer, a boolean, an array or an object).
    #[error("a support bundle file could not be encoded")]
    Encode,
}

/// A built bundle: the exact bytes to write, their manifest digest, the preview of those
/// same bytes, and the inverse map (separate; never in the bytes).
pub struct Bundle {
    bytes: Vec<u8>,
    manifest_sha256: String,
    preview: String,
    inverse: InverseMap,
    withheld_total: u64,
}

impl Bundle {
    /// The bundle's bytes: what the command writes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The SHA-256 of `manifest.json`'s bytes, lower-case hex: the digest printed with the
    /// preview and after the write.
    #[must_use]
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    /// The preview: a short header (the manifest digest, the size, the withheld count, how
    /// identifiers were treated and that the inverse map must not be sent), then exactly
    /// [`Bundle::bytes`] between [`PREVIEW_BEGIN`] and [`PREVIEW_END`].
    #[must_use]
    pub fn preview(&self) -> &str {
        &self.preview
    }

    /// The inverse map, for the file beside the bundle.
    #[must_use]
    pub fn inverse_map(&self) -> &InverseMap {
        &self.inverse
    }

    /// How many values were withheld.
    #[must_use]
    pub fn withheld_total(&self) -> u64 {
        self.withheld_total
    }

    /// Write [`Bundle::bytes`] to `out`, and nothing else.
    ///
    /// # Errors
    /// The writer's error.
    pub fn write_to<W: io::Write>(&self, out: &mut W) -> io::Result<()> {
        out.write_all(&self.bytes)
    }
}

impl fmt::Debug for Bundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bundle")
            .field("bytes", &self.bytes.len())
            .field("manifest_sha256", &self.manifest_sha256)
            .field("withheld_total", &self.withheld_total)
            .field("inverse_map", &self.inverse)
            .finish()
    }
}

/// The pseudonyms of one bundle and the values they stand for. It stays on the machine,
/// in a file beside the bundle ([`InverseMap::file_bytes`]); the bundle never contains it.
/// With identifier inclusion it holds only the identifiers that were still pseudonymized
/// (none, today). Its `Debug` output shows only the number of entries.
pub struct InverseMap {
    entries: Vec<InverseEntry>,
    file: Vec<u8>,
}

struct InverseEntry {
    pseudonym: String,
    kind: IdentKind,
    value: String,
}

impl InverseMap {
    /// The number of pseudonyms.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No pseudonyms.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The value a pseudonym stands for.
    #[must_use]
    pub fn get(&self, pseudonym: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.pseudonym == pseudonym)
            .map(|e| e.value.as_str())
    }

    /// Every entry, in assignment order: pseudonym, kind, value.
    pub fn iter(&self) -> impl Iterator<Item = (&str, IdentKind, &str)> {
        self.entries
            .iter()
            .map(|e| (e.pseudonym.as_str(), e.kind, e.value.as_str()))
    }

    /// The inverse map file's bytes (pretty JSON with a notice not to send it, the
    /// bundle's manifest digest, and the entries).
    #[must_use]
    pub fn file_bytes(&self) -> &[u8] {
        &self.file
    }
}

impl fmt::Debug for InverseMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InverseMap")
            .field("entries", &self.entries.len())
            .finish()
    }
}

/// Build a bundle from `input`.
///
/// # Errors
/// [`BundleError::TooLarge`] when the bundle would exceed [`MAX_BUNDLE_BYTES`].
pub fn build(input: &BundleInput, options: Options) -> Result<Bundle, BundleError> {
    let mut c = Collector::new(options.include_identifiers);
    // A fixed walk order: pseudonyms are numbered in order of first appearance.
    let build = build_file(&mut c, &input.build);
    let platform = platform_file(&mut c, &input.platform);
    let doctor = doctor_file(&mut c, &input.doctor);
    let capabilities = rows(&mut c, "capabilities", &input.capabilities);
    let claims = rows(&mut c, "claims", &input.claims);
    let setup = rows(&mut c, "setup", &input.setup);
    let projections = rows(&mut c, "projections", &input.projections);
    let config = config_file(&mut c, &input.config);
    let (store, operations) = store_files(&mut c, &input.store);
    let log = log_file(&mut c, &input.log);

    let files = [
        build,
        platform,
        doctor,
        object([("capabilities", capabilities), ("claims", claims)]),
        object([("setup", setup), ("projections", projections)]),
        config,
        store,
        operations,
        log,
    ];
    let mut rendered = Vec::with_capacity(FILES.len());
    for (name, value) in FILES.into_iter().zip(files.iter()) {
        rendered.push((name, render(value)?));
    }
    let manifest = render(&manifest_file(&rendered, &c))?;
    let manifest_sha256 = sha256_hex(manifest.as_bytes());

    let mut text = format!("{FORMAT} {FORMAT_VERSION}\n");
    push_section(&mut text, MANIFEST_FILE, &manifest);
    for (name, body) in &rendered {
        push_section(&mut text, name, body);
    }
    text.push_str("end\n");
    if text.len() > MAX_BUNDLE_BYTES {
        return Err(BundleError::TooLarge {
            bytes: text.len(),
            limit: MAX_BUNDLE_BYTES,
        });
    }

    let withheld_total = c.withheld.values().sum();
    let preview = preview_text(
        &text,
        &manifest_sha256,
        withheld_total,
        options.include_identifiers,
        c.inverse.len(),
    );
    let inverse = inverse_map(c.inverse, &manifest_sha256)?;
    Ok(Bundle {
        bytes: text.into_bytes(),
        manifest_sha256,
        preview,
        inverse,
        withheld_total,
    })
}

/// The walk's state: the pseudonyms so far, every withheld count, and the verdict on
/// each distinct code (codes repeat: states, log codes, finding codes, field names).
struct Collector {
    include_identifiers: bool,
    code_verdicts: HashMap<String, Result<(), Withheld>>,
    pseudonyms: HashMap<(IdentKind, String), String>,
    counters: BTreeMap<IdentKind, u64>,
    inverse: Vec<InverseEntry>,
    withheld: BTreeMap<String, u64>,
    reasons: BTreeMap<Withheld, u64>,
}

impl Collector {
    fn new(include_identifiers: bool) -> Self {
        Self {
            include_identifiers,
            code_verdicts: HashMap::new(),
            pseudonyms: HashMap::new(),
            counters: BTreeMap::new(),
            inverse: Vec::new(),
            withheld: BTreeMap::new(),
            reasons: BTreeMap::new(),
        }
    }

    /// Count one withheld value at `path` (a static field path, code-shaped).
    fn withhold(&mut self, path: &str, why: Withheld) {
        *self.withheld.entry(path.to_owned()).or_default() += 1;
        *self.reasons.entry(why).or_default() += 1;
    }

    fn checked(&mut self, path: &str, result: Result<(), Withheld>, text: &str) -> Option<Json> {
        match result {
            Ok(()) => Some(Json::String(text.to_owned())),
            Err(why) => {
                self.withhold(path, why);
                None
            }
        }
    }

    /// [`screen_code`], once per distinct code. A string over the code length cap is
    /// malformed at once, without being hashed or kept.
    fn screen_code(&mut self, code: &str) -> Result<(), Withheld> {
        if code.len() > CODE_MAX_LEN {
            return Err(Withheld::Malformed);
        }
        if let Some(verdict) = self.code_verdicts.get(code) {
            return *verdict;
        }
        let verdict = screen_code(code);
        self.code_verdicts.insert(code.to_owned(), verdict);
        verdict
    }

    fn code(&mut self, path: &str, code: &Code) -> Option<Json> {
        let verdict = self.screen_code(code.as_str());
        self.checked(path, verdict, code.as_str())
    }

    fn version(&mut self, path: &str, version: &Version) -> Option<Json> {
        self.checked(path, screen_version(version.as_str()), version.as_str())
    }

    fn build_id(&mut self, path: &str, id: &BuildId) -> Option<Json> {
        self.checked(path, screen_build_id(id.as_str()), id.as_str())
    }

    fn timestamp(&mut self, path: &str, at: Timestamp) -> Option<Json> {
        let text = timestamp_text(at);
        if text.is_none() {
            self.withhold(path, Withheld::Malformed);
        }
        text.map(Json::String)
    }

    fn safe(&mut self, path: &str, value: &Safe) -> Option<Json> {
        match value {
            Safe::Bool(b) => Some(Json::Bool(*b)),
            Safe::Integer(n) => Some(Json::from(*n)),
            Safe::Count(n) => Some(Json::from(*n)),
            Safe::Duration(d) => Some(Json::from(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))),
            Safe::Timestamp(t) => self.timestamp(path, *t),
            Safe::Version(v) => self.version(path, v),
            Safe::BuildId(b) => self.build_id(path, b),
        }
    }

    /// Screen an identifier (in both modes, so a failing value reaches neither the bundle
    /// nor the inverse map), then pseudonymize it or, with inclusion, write it.
    fn ident(&mut self, path: &str, id: &Ident) -> Option<Json> {
        if let Err(why) = screen_identifier(id.kind(), id.value()) {
            self.withhold(path, why);
            return None;
        }
        if self.include_identifiers {
            return Some(Json::String(id.value().to_owned()));
        }
        let key = (id.kind(), id.value().to_owned());
        if let Some(pseudonym) = self.pseudonyms.get(&key) {
            return Some(Json::String(pseudonym.clone()));
        }
        let n = self.counters.entry(id.kind()).or_default();
        *n += 1;
        let pseudonym = format!("{}-{n}", id.kind().prefix());
        self.inverse.push(InverseEntry {
            pseudonym: pseudonym.clone(),
            kind: id.kind(),
            value: id.value().to_owned(),
        });
        self.pseudonyms.insert(key, pseudonym.clone());
        Some(Json::String(pseudonym))
    }

    fn value(&mut self, path: &str, value: &Value) -> Option<Json> {
        match value {
            Value::Code(c) => self.code(path, c),
            Value::Safe(s) => self.safe(path, s),
            Value::Ident(i) => self.ident(path, i),
            Value::Secret(_) => {
                self.withhold(path, Withheld::Secret);
                None
            }
            Value::Text(_) => {
                self.withhold(path, Withheld::FreeText);
                None
            }
        }
    }

    /// A record's generic fields, as its `fields` object. A name that is not code-shaped,
    /// is longer than [`FIELD_NAME_MAX_LEN`] or repeats an earlier one is withheld as
    /// malformed under `<section>.fields`, with its value unread.
    fn fields(&mut self, section: &str, fields: &[Field], record: &mut Record) {
        let mut out = Map::new();
        let mut seen = BTreeSet::new();
        for field in fields {
            if field.name.len() > FIELD_NAME_MAX_LEN
                || self.screen_code(field.name).is_err()
                || !seen.insert(field.name)
            {
                self.withhold(&format!("{section}.fields"), Withheld::Malformed);
                record.withheld.insert("fields".to_owned());
                continue;
            }
            let name = format!("fields.{}", field.name);
            match self.value(&format!("{section}.{name}"), &field.value) {
                Some(v) => {
                    out.insert(field.name.to_owned(), v);
                }
                None => {
                    record.withheld.insert(name);
                }
            }
        }
        if !out.is_empty() {
            record.set("fields", Json::Object(out));
        }
    }

    /// A list of codes under `name`; any withheld one is noted once in the record.
    fn codes(&mut self, path: &str, codes: &[Code], record: &mut Record, name: &str) {
        let mut out = Vec::with_capacity(codes.len());
        for code in codes {
            match self.code(path, code) {
                Some(v) => out.push(v),
                None => {
                    record.withheld.insert(name.to_owned());
                }
            }
        }
        record.set(name, Json::Array(out));
    }
}

/// One JSON object under construction, with its `withheld` note.
#[derive(Default)]
struct Record {
    map: Map<String, Json>,
    withheld: BTreeSet<String>,
}

impl Record {
    /// Set `name`, or note it as withheld when `value` is `None`.
    fn put(&mut self, name: &str, value: Option<Json>) {
        match value {
            Some(v) => {
                self.map.insert(name.to_owned(), v);
            }
            None => {
                self.withheld.insert(name.to_owned());
            }
        }
    }

    fn set(&mut self, name: &str, value: Json) {
        self.map.insert(name.to_owned(), value);
    }

    fn finish(mut self) -> Json {
        if !self.withheld.is_empty() {
            let names = self.withheld.into_iter().map(Json::String).collect();
            self.map.insert("withheld".to_owned(), Json::Array(names));
        }
        Json::Object(self.map)
    }
}

fn object<const N: usize>(entries: [(&str, Json); N]) -> Json {
    Json::Object(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
    )
}

fn build_file(c: &mut Collector, build: &BuildInfo) -> Json {
    let mut r = Record::default();
    r.put("version", c.version("build.version", &build.version));
    if let Some(commit) = &build.commit {
        r.put("commit", c.build_id("build.commit", commit));
    }
    r.put("target", c.code("build.target", &build.target));
    if let Some(profile) = &build.profile {
        r.put("profile", c.code("build.profile", profile));
    }
    c.codes("build.features", &build.features, &mut r, "features");
    r.finish()
}

fn platform_file(c: &mut Collector, platform: &PlatformInfo) -> Json {
    let mut r = Record::default();
    r.put("os", c.code("platform.os", &platform.os));
    if let Some(v) = &platform.os_version {
        r.put("os_version", c.version("platform.os_version", v));
    }
    r.put("arch", c.code("platform.arch", &platform.arch));
    if let Some(ssh) = &platform.ssh_client {
        let mut s = Record::default();
        s.put(
            "implementation",
            c.code("platform.ssh_client.implementation", &ssh.implementation),
        );
        if let Some(v) = &ssh.version {
            s.put("version", c.version("platform.ssh_client.version", v));
        }
        r.set("ssh_client", s.finish());
    }
    r.finish()
}

fn doctor_file(c: &mut Collector, findings: &[Finding]) -> Json {
    let list = findings
        .iter()
        .map(|finding| {
            let mut r = Record::default();
            r.put("code", c.code("doctor.code", &finding.code));
            if let Some(severity) = &finding.severity {
                r.put("severity", c.code("doctor.severity", severity));
            }
            c.fields("doctor", &finding.fields, &mut r);
            r.finish()
        })
        .collect();
    object([("findings", Json::Array(list))])
}

fn rows(c: &mut Collector, section: &str, rows: &[StatusRow]) -> Json {
    let (key_path, state_path) = (format!("{section}.key"), format!("{section}.state"));
    Json::Array(
        rows.iter()
            .map(|row| {
                let mut r = Record::default();
                r.put("key", c.code(&key_path, &row.key));
                r.put("state", c.code(&state_path, &row.state));
                c.fields(section, &row.fields, &mut r);
                r.finish()
            })
            .collect(),
    )
}

fn config_file(c: &mut Collector, settings: &[Setting]) -> Json {
    let list = settings
        .iter()
        .map(|setting| {
            let mut r = Record::default();
            r.put("key", c.code("config.key", &setting.key));
            r.put("value", c.value("config.value", &setting.value));
            r.finish()
        })
        .collect();
    object([("settings", Json::Array(list))])
}

/// `store.json` and `operations.json`. An unreadable store contributes its integrity
/// code only, and no operations.
fn store_files(c: &mut Collector, store: &StoreInput) -> (Json, Json) {
    match store {
        StoreInput::Unreadable { integrity } => {
            let mut r = Record::default();
            r.set("readable", Json::Bool(false));
            r.put("integrity", c.code("store.integrity", integrity));
            let operations = object([
                ("available", Json::Bool(false)),
                ("operations", Json::Array(Vec::new())),
            ]);
            (r.finish(), operations)
        }
        StoreInput::Readable(contents) => {
            let mut r = Record::default();
            r.set("readable", Json::Bool(true));
            r.put("integrity", c.code("store.integrity", &contents.integrity));
            r.set("schema_version", Json::from(contents.schema_version));
            let rows = contents
                .rows
                .iter()
                .map(|row| {
                    let mut t = Record::default();
                    t.put("table", c.code("store.rows.table", &row.table));
                    t.set("count", Json::from(row.count));
                    t.finish()
                })
                .collect();
            r.set("rows", Json::Array(rows));
            let operations = contents
                .operations
                .iter()
                .map(|op| {
                    let mut o = Record::default();
                    o.put("kind", c.code("operations.kind", &op.kind));
                    o.put("state", c.code("operations.state", &op.state));
                    if let Some(effect) = &op.effect {
                        o.put("effect", c.code("operations.effect", effect));
                    }
                    if let Some(at) = op.created {
                        o.put("created", c.timestamp("operations.created", at));
                    }
                    if let Some(at) = op.updated {
                        o.put("updated", c.timestamp("operations.updated", at));
                    }
                    c.fields("operations", &op.fields, &mut o);
                    o.finish()
                })
                .collect();
            let operations = object([
                ("available", Json::Bool(true)),
                ("operations", Json::Array(operations)),
            ]);
            (r.finish(), operations)
        }
    }
}

/// `log.json`: per-code counts with first and last times, never a line. A record whose
/// code is withheld is counted but not grouped.
fn log_file(c: &mut Collector, records: &[LogRecord]) -> Json {
    let mut by_code: BTreeMap<&str, (u64, Timestamp, Timestamp)> = BTreeMap::new();
    let mut lines = 0u64;
    for record in records {
        if record.line.is_some() {
            c.withhold("log.line", Withheld::FreeText);
            lines += 1;
        }
        if let Err(why) = c.screen_code(record.code.as_str()) {
            c.withhold("log.code", why);
            continue;
        }
        by_code
            .entry(record.code.as_str())
            .and_modify(|(count, first, last)| {
                *count += 1;
                *first = (*first).min(record.at);
                *last = (*last).max(record.at);
            })
            .or_insert((1, record.at, record.at));
    }
    let codes = by_code
        .into_iter()
        .map(|(code, (count, first, last))| {
            let mut r = Record::default();
            r.set("code", Json::String(code.to_owned()));
            r.set("count", Json::from(count));
            r.put("first", c.timestamp("log.first", first));
            r.put("last", c.timestamp("log.last", last));
            r.finish()
        })
        .collect();
    object([
        ("codes", Json::Array(codes)),
        ("records", Json::from(records.len())),
        ("lines_withheld", Json::from(lines)),
    ])
}

fn manifest_file(files: &[(&str, String)], c: &Collector) -> Json {
    let list = files
        .iter()
        .map(|(name, body)| {
            object([
                ("name", Json::String((*name).to_owned())),
                ("bytes", Json::from(body.len())),
                ("sha256", Json::String(sha256_hex(body.as_bytes()))),
            ])
        })
        .collect();
    let withheld = c
        .withheld
        .iter()
        .map(|(path, n)| (path.clone(), Json::from(*n)))
        .collect();
    let reasons = Withheld::ALL
        .iter()
        .map(|why| {
            let n = c.reasons.get(why).copied().unwrap_or(0);
            (why.code().to_owned(), Json::from(n))
        })
        .collect();
    let pseudonyms = IdentKind::ALL
        .iter()
        .map(|kind| {
            let n = c.counters.get(kind).copied().unwrap_or(0);
            (kind.prefix().to_owned(), Json::from(n))
        })
        .collect();
    let identifiers = if c.include_identifiers {
        "included"
    } else {
        "pseudonymized"
    };
    object([
        ("format", Json::String(FORMAT.to_owned())),
        ("format_version", Json::from(FORMAT_VERSION)),
        ("identifiers", Json::String(identifiers.to_owned())),
        ("files", Json::Array(list)),
        ("withheld", Json::Object(withheld)),
        ("withheld_by_reason", Json::Object(reasons)),
        (
            "withheld_total",
            Json::from(c.withheld.values().sum::<u64>()),
        ),
        ("pseudonyms", Json::Object(pseudonyms)),
    ])
}

fn inverse_map(
    entries: Vec<InverseEntry>,
    manifest_sha256: &str,
) -> Result<InverseMap, BundleError> {
    let list = entries
        .iter()
        .map(|e| {
            object([
                ("pseudonym", Json::String(e.pseudonym.clone())),
                ("kind", Json::String(e.kind.prefix().to_owned())),
                ("value", Json::String(e.value.clone())),
            ])
        })
        .collect();
    let file = object([
        ("format", Json::String(INVERSE_MAP_FORMAT.to_owned())),
        ("format_version", Json::from(FORMAT_VERSION)),
        (
            "notice",
            Json::String(
                "Keep this file on this machine. It maps the support bundle's pseudonyms \
                 back to the real names and is not part of the bundle. Do not send it."
                    .to_owned(),
            ),
        ),
        (
            "bundle_manifest_sha256",
            Json::String(manifest_sha256.to_owned()),
        ),
        ("entries", Json::Array(list)),
    ]);
    Ok(InverseMap {
        entries,
        file: render(&file)?.into_bytes(),
    })
}

fn render(value: &Json) -> Result<String, BundleError> {
    let mut text = serde_json::to_string_pretty(value).map_err(|_| BundleError::Encode)?;
    text.push('\n');
    Ok(text)
}

fn push_section(out: &mut String, name: &str, body: &str) {
    out.push_str("file ");
    out.push_str(name);
    out.push(' ');
    out.push_str(&body.len().to_string());
    out.push('\n');
    out.push_str(body);
}

fn preview_text(
    bundle: &str,
    manifest_sha256: &str,
    withheld: u64,
    include_identifiers: bool,
    pseudonyms: usize,
) -> String {
    let identifiers = if include_identifiers {
        "Identifiers: real values, for the identifier fields that passed the secret \
         checks (identifier inclusion is on); a value that failed a check is withheld."
            .to_owned()
    } else {
        format!(
            "Identifiers: replaced by {pseudonyms} placeholders such as host-1 and user-1. \
             The inverse map that resolves them is written beside the bundle, is not part \
             of it, and must not be sent."
        )
    };
    format!(
        "Heimdall support bundle preview\n\
         Manifest SHA-256: {manifest_sha256}\n\
         Size: {} bytes: {MANIFEST_FILE} and {} files\n\
         Withheld values: {withheld}. Free text and secrets are never collected; the counts \
         per field are in {MANIFEST_FILE}.\n\
         {identifiers}\n\
         These are the exact bytes that will be written; nothing is collected again.\n\
         {PREVIEW_BEGIN}\n\
         {bundle}\
         {PREVIEW_END}\n",
        bundle.len(),
        FILES.len(),
    )
}

/// RFC 3339 UTC in whole seconds; `None` before the Unix epoch.
fn timestamp_text(at: Timestamp) -> Option<String> {
    let second = at.as_second();
    if second < 0 {
        return None;
    }
    Timestamp::from_second(second).ok().map(|t| t.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{BuildInfo, PlatformInfo, StoreContents, StoreInput};

    fn minimal(store: StoreInput) -> BundleInput {
        BundleInput {
            build: BuildInfo {
                version: Version::new("1.0.0-rc.1"),
                commit: Some(BuildId::new("08662ad9")),
                target: Code::new("aarch64-apple-darwin"),
                profile: Some(Code::new("release")),
                features: vec![Code::new("transport-iroh")],
            },
            platform: PlatformInfo {
                os: Code::new("macos"),
                os_version: Some(Version::new("15.1")),
                arch: Code::new("aarch64"),
                ssh_client: None,
            },
            doctor: Vec::new(),
            capabilities: Vec::new(),
            claims: Vec::new(),
            setup: Vec::new(),
            projections: Vec::new(),
            config: Vec::new(),
            store,
            log: Vec::new(),
        }
    }

    fn readable() -> StoreInput {
        StoreInput::Readable(StoreContents {
            schema_version: 7,
            integrity: Code::new("ok"),
            rows: Vec::new(),
            operations: Vec::new(),
        })
    }

    #[test]
    fn timestamps_are_rfc3339_utc_seconds() {
        // 1_700_000_000 is the well-known 2023-11-14T22:13:20Z.
        let at = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
        assert_eq!(timestamp_text(at).as_deref(), Some("2023-11-14T22:13:20Z"));
        let with_fraction = Timestamp::new(1_700_000_000, 999_000_000).unwrap_or(at);
        assert_eq!(
            timestamp_text(with_fraction).as_deref(),
            Some("2023-11-14T22:13:20Z")
        );
        assert_eq!(
            timestamp_text(Timestamp::UNIX_EPOCH).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        let before = Timestamp::from_second(-1).unwrap_or(Timestamp::UNIX_EPOCH);
        assert_eq!(timestamp_text(before), None);
    }

    #[test]
    fn pseudonyms_are_stable_within_a_bundle_and_counted_per_kind() {
        let mut c = Collector::new(false);
        let a = c.ident("t", &Ident::host("alpha.invalid"));
        let b = c.ident("t", &Ident::host("beta.invalid"));
        let a2 = c.ident("t", &Ident::host("alpha.invalid"));
        let u = c.ident("t", &Ident::user("alpha.invalid"));
        assert_eq!(a, Some(Json::String("host-1".into())));
        assert_eq!(b, Some(Json::String("host-2".into())));
        assert_eq!(a2, a);
        assert_eq!(u, Some(Json::String("user-1".into())));
        assert_eq!(c.inverse.len(), 3);
    }

    #[test]
    fn the_container_is_deterministic_and_the_digest_is_the_manifests() {
        let one = build(&minimal(readable()), Options::default());
        let two = build(&minimal(readable()), Options::default());
        let (Ok(one), Ok(two)) = (one, two) else {
            panic!("build failed");
        };
        assert_eq!(one.bytes(), two.bytes());
        assert_eq!(one.manifest_sha256(), two.manifest_sha256());
        let text = std::str::from_utf8(one.bytes()).unwrap_or("");
        let header = format!("{FORMAT} {FORMAT_VERSION}\nfile {MANIFEST_FILE} ");
        assert!(text.starts_with(&header));
        let rest = &text[header.len()..];
        let (len, rest) = rest.split_once('\n').unwrap_or(("0", ""));
        let len: usize = len.parse().unwrap_or(0);
        assert_eq!(sha256_hex(&rest.as_bytes()[..len]), one.manifest_sha256());
        assert!(text.ends_with("\nend\n"));
        assert!(one.preview().contains(text));
    }

    #[test]
    fn an_unreadable_store_contributes_its_integrity_code_only() {
        let input = minimal(StoreInput::Unreadable {
            integrity: Code::new("store_unopenable"),
        });
        let Ok(bundle) = build(&input, Options::default()) else {
            panic!("build failed");
        };
        let text = std::str::from_utf8(bundle.bytes()).unwrap_or("");
        assert!(text.contains("\"integrity\": \"store_unopenable\""));
        assert!(text.contains("\"readable\": false"));
        assert!(text.contains("\"available\": false"));
        assert!(!text.contains("schema_version"));
    }
}
