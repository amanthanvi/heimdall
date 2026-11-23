//! The support bundle under adversarial input (M08 U6a; m08-plan U6a; ADR-0014 §5.1
//! "Tests").
//!
//! Cargo test target `adversarial_support_bundle_redaction` hosted by `heimdall-support`.
//! Pure: every input is built in memory.
//!
//! **No planted value is printed or written, even on failure.** A failing check names the
//! field (a slot name, which is this file's own text) and the first 16 hex digits of the
//! planted value's SHA-256; it never prints the bundle, the value, or a `Debug` of
//! either, and the properties run through [`TestRunner`] with failure persistence off so
//! a shrunk input is never written to a regression file. Planted values are generated per
//! run from std's `RandomState`; canaries are `HEIMDALL_CANARY_` plus a per-run suffix.
//! Nothing here reads a real key, host, user name, path, keychain, agent or environment
//! secret; the fixture's names use the `.invalid` domain and `/srv/fixture`.
//!
//! The container and JSON checks below are written independently of the crate (their own
//! parser and shape matchers), so a defect in the crate's checks is not mirrored here.
//! Reproduce a property failure with `PROPTEST_RNG_SEED=<seed>`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{BuildHasher, Hasher};
use std::sync::OnceLock;
use std::time::Duration;

use heimdall_support::{
    BuildId, BuildInfo, Bundle, BundleError, BundleInput, Code, FILES, Field, Finding, FreeText,
    Ident, IdentKind, LogRecord, MANIFEST_FILE, MAX_BUNDLE_BYTES, Operation, Options,
    PREVIEW_BEGIN, PREVIEW_END, PlatformInfo, RowCount, Secret, Setting, SshClient, StatusRow,
    StoreContents, StoreInput, Timestamp, Version, build,
};
use proptest::prelude::*;
use proptest::test_runner::{RngSeed, TestCaseError, TestError, TestRunner};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};

const CANARY_PREFIX: &str = "HEIMDALL_CANARY_";

// --- slots: every free-text, secret, identifier, code, version, build-ID and field-name
// input of the fixture, with the manifest path a withheld value is counted under ---------

/// Free-text inputs: messages, `ssh` and operating-system error strings, finding detail,
/// a command line, log lines.
const TEXT_SLOTS: &[(&str, &str)] = &[
    ("doctor.detail", "doctor.fields.detail"),
    ("doctor.ssh_error", "doctor.fields.ssh_error"),
    ("doctor.os_error", "doctor.fields.os_error"),
    ("capabilities.note", "capabilities.fields.note"),
    ("claims.note", "claims.fields.note"),
    ("setup.message", "setup.fields.message"),
    ("projection.detail", "projections.fields.detail"),
    ("config.banner", "config.value"),
    ("operation.message", "operations.fields.message"),
    ("operation.command", "operations.fields.command_line"),
    ("log.line", "log.line"),
];

/// Secret inputs.
const SECRET_SLOTS: &[(&str, &str)] = &[
    ("doctor.token", "doctor.fields.token"),
    ("setup.secret", "setup.fields.secret"),
    ("config.passphrase", "config.value"),
    ("operation.environment", "operations.fields.environment"),
];

/// Identifier inputs: slot, kind, manifest path.
const IDENT_SLOTS: &[(&str, IdentKind, &str)] = &[
    ("doctor.host", IdentKind::Host, "doctor.fields.host"),
    ("doctor.path", IdentKind::Path, "doctor.fields.include_path"),
    ("doctor.user", IdentKind::User, "doctor.fields.user"),
    ("doctor.alias", IdentKind::Alias, "doctor.fields.alias"),
    (
        "doctor.key_comment",
        IdentKind::KeyComment,
        "doctor.fields.key_comment",
    ),
    ("claims.host", IdentKind::Host, "claims.fields.host"),
    ("setup.label", IdentKind::Label, "setup.fields.label"),
    ("setup.path", IdentKind::Path, "setup.fields.path"),
    (
        "projection.alias",
        IdentKind::Alias,
        "projections.fields.alias",
    ),
    ("config.default_user", IdentKind::User, "config.value"),
    ("config.identity_file", IdentKind::Path, "config.value"),
    (
        "operation.id",
        IdentKind::HeimdallId,
        "operations.fields.operation",
    ),
    (
        "operation.fingerprint",
        IdentKind::Fingerprint,
        "operations.fields.fingerprint",
    ),
];

/// Code inputs.
const CODE_SLOTS: &[&str] = &[
    "build.target",
    "build.profile",
    "build.feature",
    "platform.os",
    "platform.arch",
    "ssh.implementation",
    "doctor.code",
    "doctor.severity",
    "doctor.reason",
    "capabilities.key",
    "capabilities.state",
    "claims.key",
    "claims.state",
    "setup.kind",
    "setup.state",
    "projection.kind",
    "projection.state",
    "config.key",
    "config.level",
    "store.integrity",
    "store.table",
    "operation.kind",
    "operation.state",
    "operation.effect",
    "log.code",
];

/// Version inputs.
const VERSION_SLOTS: &[&str] = &["build.version", "platform.os_version", "ssh.version"];

/// Build-identifier inputs.
const BUILD_ID_SLOTS: &[&str] = &["build.commit"];

/// Field-name inputs (a `&'static str` in the API; planted here by leaking a run-time
/// string, the only way data could reach one).
const NAME_SLOTS: &[&str] = &[
    "doctor.field_name",
    "capabilities.field_name",
    "setup.field_name",
    "operation.field_name",
];

fn all_slots() -> &'static BTreeSet<&'static str> {
    static SLOTS: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    SLOTS.get_or_init(|| {
        TEXT_SLOTS
            .iter()
            .chain(SECRET_SLOTS)
            .map(|(s, _)| *s)
            .chain(IDENT_SLOTS.iter().map(|(s, _, _)| *s))
            .chain(CODE_SLOTS.iter().copied())
            .chain(VERSION_SLOTS.iter().copied())
            .chain(BUILD_ID_SLOTS.iter().copied())
            .chain(NAME_SLOTS.iter().copied())
            .collect()
    })
}

// --- per-run values and the leak report ---------------------------------------------------

/// `n` bytes seeded from the OS for this run only (std's `RandomState`).
fn run_bytes(n: usize) -> Vec<u8> {
    let state = std::collections::hash_map::RandomState::new();
    let mut out = Vec::with_capacity(n + 8);
    let mut i = 0u64;
    while out.len() < n {
        let mut h = state.build_hasher();
        h.write_u64(i);
        out.extend_from_slice(&h.finish().to_le_bytes());
        i += 1;
    }
    out.truncate(n);
    out
}

fn run_hex(bytes: usize) -> String {
    run_bytes(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn pick(alphabet: &[u8], n: usize) -> String {
    run_bytes(n)
        .iter()
        .map(|b| char::from(alphabet[usize::from(*b) % alphabet.len()]))
        .collect()
}

fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(A[((n >> shift) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A per-run name that every identifier check accepts: two lower-case words and at most
/// six digits (`amberfalcon482913`).
fn run_name() -> String {
    let b = run_bytes(6);
    let n = u32::from_le_bytes([b[2], b[3], b[4], b[5]]) % 1_000_000;
    format!("{}{}{n}", word(b[0]), word(b[1]))
}

/// A canary for this run.
fn canary(tag: usize) -> String {
    format!("{CANARY_PREFIX}{}{tag:03}", run_hex(6).to_ascii_uppercase())
}

/// The first 16 hex digits of the SHA-256 of a planted value: all a report shows of it.
fn digest(planted: &str) -> String {
    Sha256::digest(planted.as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `Err` naming `field` and the planted value's digest when `planted`, or any piece of
/// `window` characters of it that `baseline` does not contain, is in `text`.
fn leak(
    text: &str,
    baseline: &str,
    field: &str,
    planted: &str,
    window: usize,
) -> Result<(), String> {
    // `text` first: it is the smaller haystack and rarely holds the piece.
    if !planted.is_empty() && text.contains(planted) && !baseline.contains(planted) {
        return Err(format!(
            "{field}: the planted value (sha256 {}) reached the output",
            digest(planted)
        ));
    }
    let starts: Vec<usize> = planted.char_indices().map(|(i, _)| i).collect();
    for (k, &start) in starts.iter().enumerate() {
        if starts.len() < k + window {
            break;
        }
        let end = starts.get(k + window).copied().unwrap_or(planted.len());
        let piece = &planted[start..end];
        if text.contains(piece) && !baseline.contains(piece) {
            return Err(format!(
                "{field}: a {window}-character piece of the planted value (sha256 {}) reached the output",
                digest(planted)
            ));
        }
    }
    Ok(())
}

/// `text` with every run of exactly 64 lowercase hex digits (a SHA-256 the bundle computed
/// over its own files) replaced by `#`, so a planted value's hex piece cannot match a
/// digest by chance. A planted value is never 64 hex digits here.
fn masked(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |out: &mut String, run: &mut String| {
        if run.len() == 64 {
            out.push('#');
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if c.is_ascii_digit() || ('a'..='f').contains(&c) {
            run.push(c);
        } else {
            flush(&mut out, &mut run);
            out.push(c);
        }
    }
    flush(&mut out, &mut run);
    out
}

fn assert_no_leak(text: &str, baseline: &str, field: &str, planted: &str, window: usize) {
    if let Err(report) = leak(text, baseline, field, planted, window) {
        panic!("{report}");
    }
}

/// The canary marker in any casing or separator form.
fn has_canary_marker(text: &str) -> bool {
    let normalized: String = text
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    normalized.contains("heimdallcanary")
}

// --- the fixture ----------------------------------------------------------------------------

/// Planted values by slot; every other slot gets the fixture's neutral default. Records
/// which slots the fixture read, so a slot cannot silently go unused.
#[derive(Default)]
struct Plants {
    values: BTreeMap<&'static str, String>,
    used: RefCell<BTreeSet<&'static str>>,
}

impl Plants {
    fn with(mut self, slot: &'static str, value: impl Into<String>) -> Self {
        assert!(all_slots().contains(slot), "unknown slot {slot}");
        self.values.insert(slot, value.into());
        self
    }

    fn get(&self, slot: &'static str, default: &str) -> String {
        assert!(all_slots().contains(slot), "unknown slot {slot}");
        self.used.borrow_mut().insert(slot);
        self.values
            .get(slot)
            .cloned()
            .unwrap_or_else(|| default.to_owned())
    }

    fn text(&self, slot: &'static str) -> FreeText {
        FreeText::new(self.get(slot, "fixture text"))
    }

    fn secret(&self, slot: &'static str) -> Secret {
        Secret::new(self.get(slot, "fixture secret"))
    }

    fn ident(&self, slot: &'static str, default: &str) -> Ident {
        let kind = IDENT_SLOTS
            .iter()
            .find(|(s, _, _)| *s == slot)
            .map(|(_, k, _)| *k)
            .expect("identifier slot");
        Ident::new(kind, self.get(slot, default))
    }

    fn code(&self, slot: &'static str, default: &str) -> Code {
        Code::new(self.get(slot, default))
    }

    fn version(&self, slot: &'static str, default: &str) -> Version {
        Version::new(self.get(slot, default))
    }

    fn build_id(&self, slot: &'static str, default: &str) -> BuildId {
        BuildId::new(self.get(slot, default))
    }

    fn name(&self, slot: &'static str, default: &'static str) -> &'static str {
        match self.values.get(slot) {
            Some(planted) => {
                self.used.borrow_mut().insert(slot);
                Box::leak(planted.clone().into_boxed_str())
            }
            None => {
                self.get(slot, default);
                default
            }
        }
    }
}

fn at(second: i64) -> Timestamp {
    Timestamp::from_second(second).expect("timestamp")
}

/// The fixture: one value in every input of every section, each default distinct.
fn fixture(p: &Plants) -> BundleInput {
    let t0 = 1_700_000_000;
    let fingerprint = format!("SHA256:{}", "Fx".repeat(21) + "A");
    let op_id = format!("op_{}", "0123456789abcdef".repeat(2));
    BundleInput {
        build: BuildInfo {
            version: p.version("build.version", "1.0.0-rc.1"),
            commit: Some(p.build_id("build.commit", "08662ad9")),
            target: p.code("build.target", "aarch64-apple-darwin"),
            profile: Some(p.code("build.profile", "release")),
            features: vec![
                Code::new("transport-iroh"),
                p.code("build.feature", "debug-support"),
            ],
        },
        platform: PlatformInfo {
            os: p.code("platform.os", "macos"),
            os_version: Some(p.version("platform.os_version", "15.1")),
            arch: p.code("platform.arch", "aarch64"),
            ssh_client: Some(SshClient {
                implementation: p.code("ssh.implementation", "openssh"),
                version: Some(p.version("ssh.version", "9.9p1")),
            }),
        },
        doctor: vec![
            Finding {
                code: p.code("doctor.code", "include_missing"),
                severity: Some(p.code("doctor.severity", "warning")),
                fields: vec![
                    Field::new(
                        "include_path",
                        p.ident("doctor.path", "/srv/fixture/.ssh/config.d/extra"),
                    ),
                    Field::new("host", p.ident("doctor.host", "fixture-host.invalid")),
                    Field::new("user", p.ident("doctor.user", "fixture-user")),
                    Field::new("alias", p.ident("doctor.alias", "fixture-alias")),
                    Field::new(
                        "key_comment",
                        p.ident("doctor.key_comment", "fixture@workstation.invalid"),
                    ),
                    Field::new("depth", 2u64),
                    Field::new("detail", p.text("doctor.detail")),
                    Field::new("ssh_error", p.text("doctor.ssh_error")),
                    Field::new("os_error", p.text("doctor.os_error")),
                    Field::new("token", p.secret("doctor.token")),
                    Field::new("reason", p.code("doctor.reason", "not_found")),
                    Field::new(p.name("doctor.field_name", "followed"), true),
                ],
            },
            Finding {
                code: Code::new("strict_host_key_checking_weak"),
                severity: None,
                fields: vec![Field::new(
                    "host",
                    p.ident("doctor.host", "fixture-host.invalid"),
                )],
            },
        ],
        capabilities: vec![StatusRow {
            key: p.code("capabilities.key", "transport.iroh"),
            state: p.code("capabilities.state", "disabled"),
            fields: vec![
                Field::new("note", p.text("capabilities.note")),
                Field::new(p.name("capabilities.field_name", "since"), at(t0)),
            ],
        }],
        claims: vec![StatusRow {
            key: p.code("claims.key", "custody:macos-keychain"),
            state: p.code("claims.state", "blocked"),
            fields: vec![
                Field::new("host", p.ident("claims.host", "claims-host.invalid")),
                Field::new("note", p.text("claims.note")),
            ],
        }],
        setup: vec![StatusRow {
            key: p.code("setup.kind", "ssh_config_include"),
            state: p.code("setup.state", "applied"),
            fields: vec![
                Field::new("label", p.ident("setup.label", "fixture-label")),
                Field::new("path", p.ident("setup.path", "/srv/fixture/.ssh/config")),
                Field::new("message", p.text("setup.message")),
                Field::new("secret", p.secret("setup.secret")),
                Field::new(p.name("setup.field_name", "attempts"), 1u64),
            ],
        }],
        projections: vec![StatusRow {
            key: p.code("projection.kind", "ssh_alias"),
            state: p.code("projection.state", "current"),
            fields: vec![
                Field::new("alias", p.ident("projection.alias", "projected-alias")),
                Field::new("detail", p.text("projection.detail")),
            ],
        }],
        config: vec![
            Setting {
                key: p.code("config.key", "log.level"),
                value: p.code("config.level", "warn").into(),
            },
            Setting {
                key: Code::new("history.retention"),
                value: Duration::from_secs(7 * 86_400).into(),
            },
            Setting {
                key: Code::new("transport.enabled"),
                value: false.into(),
            },
            Setting {
                key: Code::new("default_user"),
                value: p.ident("config.default_user", "default-user").into(),
            },
            Setting {
                key: Code::new("identity_file"),
                value: p
                    .ident("config.identity_file", "/srv/fixture/.ssh/id_ed25519")
                    .into(),
            },
            Setting {
                key: Code::new("banner"),
                value: p.text("config.banner").into(),
            },
            Setting {
                key: Code::new("passphrase"),
                value: p.secret("config.passphrase").into(),
            },
        ],
        store: StoreInput::Readable(StoreContents {
            schema_version: 7,
            integrity: p.code("store.integrity", "ok"),
            rows: vec![
                RowCount {
                    table: p.code("store.table", "grants"),
                    count: 3,
                },
                RowCount {
                    table: Code::new("operations"),
                    count: 12,
                },
            ],
            operations: vec![Operation {
                kind: p.code("operation.kind", "ensure"),
                state: p.code("operation.state", "succeeded"),
                effect: Some(p.code("operation.effect", "applied")),
                created: Some(at(t0)),
                updated: Some(at(t0 + 5)),
                fields: vec![
                    Field::new("operation", p.ident("operation.id", &op_id)),
                    Field::new(
                        "fingerprint",
                        p.ident("operation.fingerprint", &fingerprint),
                    ),
                    Field::new("message", p.text("operation.message")),
                    Field::new("command_line", p.text("operation.command")),
                    Field::new("environment", p.secret("operation.environment")),
                    Field::new(p.name("operation.field_name", "attempt"), 1u64),
                ],
            }],
        }),
        log: (0..5)
            .map(|i| LogRecord {
                code: if i == 4 {
                    p.code("log.code", "runtime_started")
                } else {
                    Code::new("request_served")
                },
                at: at(t0 + 60 * i),
                line: Some(p.text("log.line")),
            })
            .collect(),
    }
}

fn built(p: &Plants, options: Options) -> Bundle {
    build(&fixture(p), options).expect("the fixture builds")
}

fn text_of(bundle: &Bundle) -> &str {
    std::str::from_utf8(bundle.bytes()).expect("the bundle is UTF-8")
}

fn include() -> Options {
    Options {
        include_identifiers: true,
    }
}

/// Everything the crate itself writes, masked: the bundle, preview and inverse map of the
/// neutral fixture and of a fixture whose every input is withheld (which adds every
/// withheld-count path, record note and reason code). A planted value's piece that is in
/// here is not unique to it; the leak checks look for the pieces that are.
fn baseline(options: Options) -> String {
    static BASES: OnceLock<[String; 2]> = OnceLock::new();
    let bases = BASES.get_or_init(|| {
        let mut withheld = Plants::default();
        for (i, slot) in all_slots().iter().enumerate() {
            withheld = withheld.with(slot, canary(500 + i));
        }
        [Options::default(), include()].map(|o| {
            let mut out = String::new();
            for p in [&Plants::default(), &withheld] {
                let b = built(p, o);
                out.push_str(text_of(&b));
                out.push_str(b.preview());
                out.push_str(std::str::from_utf8(b.inverse_map().file_bytes()).expect("UTF-8"));
            }
            masked(&out)
        })
    });
    bases[usize::from(options.include_identifiers)].clone()
}

/// The neutral fixture's bundle bytes.
fn baseline_bytes(options: Options) -> Vec<u8> {
    built(&Plants::default(), options).bytes().to_vec()
}

fn withheld_counts(bundle: &Bundle) -> BTreeMap<String, u64> {
    manifest(bundle)["withheld"]
        .as_object()
        .expect("withheld counts")
        .iter()
        .map(|(k, v)| (k.clone(), v.as_u64().unwrap_or(0)))
        .collect()
}

// --- an independent reader: the container, the JSON, the shapes --------------------------

/// Cut the container into (name, bytes) strictly: the header, `file <name> <len>` sections
/// whose bytes end in a newline, and `end`. Panics (without content) on anything else.
fn parse_container(bytes: &[u8]) -> Vec<(String, String)> {
    let text = std::str::from_utf8(bytes).expect("UTF-8");
    let mut rest = text
        .strip_prefix("heimdall-support-bundle 1\n")
        .expect("the container header");
    let mut files = Vec::new();
    while rest != "end\n" {
        let (line, after) = rest.split_once('\n').expect("a section line");
        let mut parts = line.split(' ');
        assert!(
            parts.next() == Some("file"),
            "a section line starts with `file`"
        );
        let name = parts.next().expect("a file name").to_owned();
        let len: usize = parts.next().expect("a length").parse().expect("a number");
        assert!(parts.next().is_none(), "a section line has three words");
        let body = after.get(..len).expect("the section's bytes");
        assert!(body.ends_with('\n'), "a file ends with a newline");
        files.push((name, body.to_owned()));
        rest = &after[len..];
    }
    files
}

fn files_json(bundle: &Bundle) -> BTreeMap<String, Json> {
    parse_container(bundle.bytes())
        .into_iter()
        .map(|(name, body)| {
            let v: Json = serde_json::from_str(&body).expect("each file is JSON");
            (name, v)
        })
        .collect()
}

/// Every string in a JSON value, keys included, with its path.
fn strings<'a>(v: &'a Json, path: &str, out: &mut Vec<(String, &'a str)>) {
    match v {
        Json::String(s) => out.push((path.to_owned(), s)),
        Json::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                strings(item, &format!("{path}[{i}]"), out);
            }
        }
        Json::Object(map) => {
            for (k, item) in map {
                let p = format!("{path}.{k}");
                out.push((format!("{p} (key)"), k));
                strings(item, &p, out);
            }
        }
        Json::Null | Json::Bool(_) | Json::Number(_) => {}
    }
}

/// `^[A-Za-z][A-Za-z0-9]*([_.:-][A-Za-z0-9]+)*$`, at most 64 bytes.
fn is_code(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 || !b[0].is_ascii_alphabetic() {
        return false;
    }
    let mut sep = false;
    for &c in b {
        if c.is_ascii_alphanumeric() {
            sep = false;
        } else if b"_.:-".contains(&c) && !sep {
            sep = true;
        } else {
            return false;
        }
    }
    !sep
}

/// `^(user|host|alias|label|path|fp|comment|id)-[1-9][0-9]*$`.
fn is_pseudonym(s: &str) -> bool {
    s.split_once('-').is_some_and(|(kind, n)| {
        [
            "user", "host", "alias", "label", "path", "fp", "comment", "id",
        ]
        .contains(&kind)
            && !n.starts_with('0')
            && !n.is_empty()
            && n.bytes().all(|b| b.is_ascii_digit())
    })
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
fn is_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            19 => *c == b'Z',
            _ => c.is_ascii_digit(),
        })
}

/// A version (`^[0-9][0-9A-Za-z.+-]*$`, at most 64) or lowercase hex (a build ID, a
/// digest).
fn is_safe_string(s: &str) -> bool {
    let b = s.as_bytes();
    let version = !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_digit()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b".+-".contains(c));
    let hex = (7..=64).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c));
    version || hex || is_timestamp(s)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Shape {
    Code,
    Safe,
    Pseudonym,
}

fn shape(s: &str) -> Option<Shape> {
    if is_pseudonym(s) {
        Some(Shape::Pseudonym)
    } else if is_safe_string(s) {
        Some(Shape::Safe)
    } else if is_code(s) {
        Some(Shape::Code)
    } else {
        None
    }
}

/// Every string in every file is a code, a safe value or a pseudonym. Returns the shapes
/// seen, or a report naming the path and a digest of the string.
fn check_shapes(bundle: &Bundle) -> Result<BTreeSet<Shape>, String> {
    let mut seen = BTreeSet::new();
    for (name, v) in files_json(bundle) {
        let mut found = Vec::new();
        strings(&v, &name, &mut found);
        for (path, s) in found {
            match shape(s) {
                Some(kind) => {
                    seen.insert(kind);
                }
                None => {
                    return Err(format!(
                        "{path}: a string that is not a code, a safe value or a pseudonym (sha256 {})",
                        digest(s)
                    ));
                }
            }
        }
    }
    Ok(seen)
}

fn manifest(bundle: &Bundle) -> Json {
    let files = parse_container(bundle.bytes());
    let (name, body) = files.first().expect("a first file");
    assert!(name == MANIFEST_FILE, "the first file is the manifest");
    serde_json::from_str(body).expect("the manifest is JSON")
}

fn withheld_at(bundle: &Bundle, path: &str) -> u64 {
    manifest(bundle)["withheld"][path].as_u64().unwrap_or(0)
}

// --- planted-value generators ---------------------------------------------------------------

/// A per-run secret generator, given a tag that keeps each planted copy distinct.
type Generator = fn(usize) -> String;

fn short_password(tag: usize) -> String {
    format!(
        "{}{tag}",
        pick(
            b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%&*?",
            8
        )
    )
}

const WORDS: &[&str] = &[
    "amber", "falcon", "maple", "orbit", "velvet", "harbor", "cinder", "meadow", "quartz",
    "lantern", "willow", "summit", "pebble", "thistle", "ember", "juniper",
];

fn word(i: u8) -> &'static str {
    WORDS[usize::from(i) % WORDS.len()]
}

fn word_token(tag: usize) -> String {
    let b = run_bytes(3);
    format!("{}{}{}{tag}", word(b[0]), word(b[1]), b[2] % 100)
}

/// Three words and digits glued to the last one (a free-standing number could equal a
/// size or a count the preview prints, which is not a leak).
fn passphrase(tag: usize) -> String {
    let b = run_bytes(4);
    format!(
        "{} {} {}{}x{tag}",
        word(b[0]),
        word(b[1]),
        word(b[2]),
        u32::from(b[3]) * 37
    )
}

/// A fake private-key block for this run: armor around the base64 of the OpenSSH key
/// magic and random bytes (228 bytes: four 70-character lines and a 24-character one).
/// It is not a key and is never written anywhere.
struct KeyBlock {
    header: String,
    footer: String,
    lines: Vec<String>,
}

impl KeyBlock {
    fn new() -> Self {
        let mut raw = b"openssh-key-v1\0".to_vec();
        raw.extend(run_bytes(228 - raw.len()));
        let body = base64(&raw);
        let lines = body
            .as_bytes()
            .chunks(70)
            .map(|c| String::from_utf8(c.to_vec()).expect("ASCII"))
            .collect();
        Self {
            header: format!("-----BEGIN OPENSSH {} KEY-----", "PRIVATE"),
            footer: format!("-----END OPENSSH {} KEY-----", "PRIVATE"),
            lines,
        }
    }

    fn body(&self) -> String {
        self.lines.concat()
    }

    fn joined(&self, header: &str, footer: &str, newline: &str) -> String {
        let mut out = vec![header.to_owned()];
        out.extend(self.lines.iter().cloned());
        out.push(footer.to_owned());
        out.join(newline)
    }

    /// The armor, altered: casing, spacing, dash count, Unicode dashes, no dashes,
    /// joined by underscores.
    fn altered_armor(&self) -> Vec<(String, String)> {
        let kind = format!("OPENSSH {} KEY", "PRIVATE");
        vec![
            (self.header.clone(), self.footer.clone()),
            (
                self.header.to_ascii_lowercase(),
                self.footer.to_ascii_lowercase(),
            ),
            (
                format!("-----  BEGIN   {kind}  -----"),
                format!("-----  END   {kind}  -----"),
            ),
            (
                format!("----BEGIN {kind}----"),
                format!("----END {kind}----"),
            ),
            (
                format!("- - - - - BEGIN {kind} - - - - -"),
                format!("- - - - - END {kind} - - - - -"),
            ),
            (
                format!(
                    "\u{2014}\u{2014}\u{2014}\u{2014}\u{2014}BEGIN {kind}\u{2014}\u{2014}\u{2014}\u{2014}\u{2014}"
                ),
                format!(
                    "\u{2014}\u{2014}\u{2014}\u{2014}\u{2014}END {kind}\u{2014}\u{2014}\u{2014}\u{2014}\u{2014}"
                ),
            ),
            (format!("BEGIN {kind}"), format!("END {kind}")),
            (
                format!("BEGIN_{}", kind.replace(' ', "_")),
                format!("END_{}", kind.replace(' ', "_")),
            ),
            (
                format!("-----BEGIN RSA {} KEY-----", "PRIVATE"),
                format!("-----END RSA {} KEY-----", "PRIVATE"),
            ),
            (
                format!("{}{}", "PuTTY-User-", "Key-File-3: ssh-ed25519"),
                format!("{}{}", "Private-", "MAC: 00"),
            ),
        ]
    }
}

/// Every key-material piece that must never reach a bundle: each line, each half of each
/// full line, every 16-character window of the body, the header and the footer.
fn key_pieces(block: &KeyBlock) -> Vec<String> {
    let mut out = vec![block.header.clone(), block.footer.clone()];
    for line in &block.lines {
        out.push(line.clone());
        if line.len() == 70 {
            out.push(line[..35].to_owned());
            out.push(line[35..].to_owned());
        }
    }
    let body = block.body();
    for start in 0..=body.len() - 16 {
        out.push(body[start..start + 16].to_owned());
    }
    out
}

// --- the tests ---------------------------------------------------------------------------------

#[test]
fn the_fixture_wires_every_slot() {
    let p = Plants::default();
    let _ = fixture(&p);
    let used = p.used.borrow().clone();
    let missing: Vec<&str> = all_slots().difference(&used).copied().collect();
    assert!(
        missing.is_empty(),
        "slots the fixture does not read: {missing:?}"
    );
}

#[test]
fn bundle_holds_only_codes_safe_values_and_pseudonyms() {
    // Plant in every free-text, secret and identifier input: text with spaces, paths and
    // punctuation; identifiers that pass the checks and identifiers that fail them.
    let tok = run_hex(6);
    let name = run_name();
    let mut p = Plants::default();
    for (i, (slot, _)) in TEXT_SLOTS.iter().enumerate() {
        p = p.with(
            slot,
            format!(
                "error {i}: open /srv/fixture/{tok}/{i} failed: \"Permission denied\" (os error 13)"
            ),
        );
    }
    for (i, (slot, _)) in SECRET_SLOTS.iter().enumerate() {
        p = p.with(slot, short_password(i));
    }
    for (i, (slot, kind, _)) in IDENT_SLOTS.iter().enumerate() {
        let v = match kind {
            IdentKind::Path => format!("/srv/fixture/{name}/dir {i}/file.txt"),
            IdentKind::Fingerprint => {
                format!("SHA256:{}", base64(&run_bytes(32)).trim_end_matches('='))
            }
            IdentKind::HeimdallId => format!("op_{}", run_hex(16)),
            _ if i % 3 == 0 => canary(i),
            _ => format!("Name With Spaces {name} {i}"),
        };
        p = p.with(slot, v);
    }
    let bundle = built(&p, Options::default());
    let seen = check_shapes(&bundle).unwrap_or_else(|report| panic!("{report}"));
    // Non-vacuous: all three shapes occur.
    assert!(seen.contains(&Shape::Code), "no code in the bundle");
    assert!(seen.contains(&Shape::Safe), "no safe value in the bundle");
    assert!(
        seen.contains(&Shape::Pseudonym),
        "no pseudonym in the bundle"
    );
    assert!(
        bundle.inverse_map().len() >= 6,
        "too few identifiers were pseudonymized"
    );
    // And no planted value is in it.
    let base = baseline(Options::default());
    let text = masked(text_of(&bundle));
    for (slot, v) in &p.values {
        assert_no_leak(&text, &base, slot, v, 6);
    }
}

#[test]
fn free_text_is_never_exported() {
    let tok = run_hex(6);
    let host = format!("h{}.invalid", run_name());
    let messages = |variant: &str| -> Vec<String> {
        vec![
            format!("ssh: connect to host {host} port 22: Connection refused {variant}"),
            format!(
                "open /srv/fixture/{tok}/config: No such file or directory (os error 2) {variant}"
            ),
            format!("{variant} 2026-11-22T10:00:00Z WARN served request for {host} in 12ms"),
            format!("ssh -i /srv/fixture/{tok}/id -o ProxyCommand='nc %h %p' {host} {variant}"),
            format!("Load key \"/srv/fixture/{tok}/id\": invalid format {variant}"),
            format!("{variant}: kex_exchange_identification: read: Connection reset by peer"),
        ]
    };
    let plant = |variant: &str| {
        let m = messages(variant);
        let mut p = Plants::default();
        for (i, (slot, _)) in TEXT_SLOTS.iter().enumerate() {
            p = p.with(slot, format!("{} [{i}]", m[i % m.len()]));
        }
        p
    };
    let a = plant(&run_hex(4));
    let b = plant(&run_hex(4));
    let bundle_a = built(&a, Options::default());
    let bundle_b = built(&b, Options::default());
    // The bundle does not depend on free text at all: not on its content, and not on
    // whether it is the fixture's neutral text.
    assert!(
        bundle_a.bytes() == bundle_b.bytes(),
        "the bundle's bytes changed with free-text content"
    );
    assert!(
        bundle_a.bytes() == baseline_bytes(Options::default()).as_slice(),
        "the bundle's bytes differ from the neutral fixture's"
    );
    for options in [Options::default(), include()] {
        let base = baseline(options);
        let bundle = built(&a, options);
        let (text, preview) = (masked(text_of(&bundle)), masked(bundle.preview()));
        for (slot, v) in &a.values {
            assert_no_leak(&text, &base, slot, v, 6);
            assert_no_leak(&preview, &base, slot, v, 6);
        }
    }
    // Each free-text field is counted where it was withheld, and noted in its record.
    for (slot, path) in TEXT_SLOTS {
        assert!(
            withheld_at(&bundle_a, path) >= 1,
            "{slot}: not counted at {path}"
        );
    }
    assert_eq!(withheld_at(&bundle_a, "log.line"), 5);
    let files = files_json(&bundle_a);
    let finding = &files["doctor.json"]["findings"][0];
    let notes: Vec<&str> = finding["withheld"]
        .as_array()
        .expect("a withheld note")
        .iter()
        .filter_map(Json::as_str)
        .collect();
    for name in [
        "fields.detail",
        "fields.ssh_error",
        "fields.os_error",
        "fields.token",
    ] {
        assert!(notes.contains(&name), "the finding does not note {name}");
    }
    // The log is per-code counts with first and last times, never lines.
    let log = &files["log.json"];
    assert_eq!(log["records"].as_u64(), Some(5));
    assert_eq!(log["lines_withheld"].as_u64(), Some(5));
    let codes = log["codes"].as_array().expect("codes");
    assert_eq!(codes.len(), 2);
    assert!(codes[0]["code"] == "request_served", "first log code");
    assert_eq!(codes[0]["count"].as_u64(), Some(4));
    assert!(codes[0]["first"] == "2023-11-14T22:13:20Z", "first time");
    assert!(codes[0]["last"] == "2023-11-14T22:16:20Z", "last time");
    assert!(codes[1]["code"] == "runtime_started", "second log code");
    assert_eq!(codes[1]["count"].as_u64(), Some(1));
    for entry in codes {
        let keys: BTreeSet<&str> = entry
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert!(
            keys == BTreeSet::from(["code", "count", "first", "last"]),
            "a log entry carries more than a code, a count and two times"
        );
    }
}

#[test]
fn unmarked_secrets_never_reach_the_bundle() {
    let generators: [(&str, Generator); 3] = [
        ("short password", short_password),
        ("word-like token", word_token),
        ("passphrase", passphrase),
    ];
    let base = baseline(Options::default());
    for (label, generate) in generators {
        let mut p = Plants::default();
        let mut planted = Vec::new();
        for (i, (slot, _)) in TEXT_SLOTS.iter().chain(SECRET_SLOTS).enumerate() {
            let secret = generate(i);
            // In free text, the secret sits inside an error string.
            let text =
                format!("Load key \"/srv/fixture/id\": incorrect passphrase supplied ({secret})");
            p = p.with(slot, text);
            planted.push((*slot, secret));
        }
        for (i, (slot, _, _)) in IDENT_SLOTS.iter().enumerate() {
            let secret = generate(100 + i);
            p = p.with(slot, secret.clone());
            planted.push((*slot, secret));
        }
        let bundle = built(&p, Options::default());
        let (text, preview) = (masked(text_of(&bundle)), masked(bundle.preview()));
        for (slot, secret) in &planted {
            let field = format!("{slot} ({label})");
            assert_no_leak(&text, &base, &field, secret, 6);
            assert_no_leak(&preview, &base, &field, secret, 6);
        }
        for (slot, v) in &p.values {
            assert_no_leak(
                &text,
                &base,
                &format!("{slot} ({label}, whole value)"),
                v,
                6,
            );
        }
        check_shapes(&bundle).unwrap_or_else(|report| panic!("{label}: {report}"));
    }
}

#[test]
fn split_and_multiline_key_material_never_reaches_the_bundle() {
    let block = KeyBlock::new();
    // Every input that takes run-time text: free text, secrets, identifiers, codes,
    // versions and build identifiers.
    let input_slots: Vec<&'static str> = all_slots()
        .iter()
        .copied()
        .filter(|s| !NAME_SLOTS.contains(s))
        .collect();
    let mut cases: Vec<(String, Plants, Vec<String>)> = Vec::new();
    for (v, (header, footer)) in block.altered_armor().into_iter().enumerate() {
        // The whole block, multiline (LF and CRLF), in every input.
        for newline in ["\n", "\r\n"] {
            let whole = block.joined(&header, &footer, newline);
            let mut p = Plants::default();
            for slot in &input_slots {
                p = p.with(slot, whole.clone());
            }
            cases.push((
                format!("whole block, armor variant {v}"),
                p,
                vec![header.clone(), footer.clone()],
            ));
        }
        // The armor lines alone, in every input.
        let mut p = Plants::default();
        for (i, slot) in input_slots.iter().enumerate() {
            p = p.with(
                slot,
                if i % 2 == 0 {
                    header.clone()
                } else {
                    footer.clone()
                },
            );
        }
        cases.push((
            format!("armor lines, variant {v}"),
            p,
            vec![header.clone(), footer.clone()],
        ));
    }
    // Split across fields: the header, each line, each half of each full line and the
    // footer in successive inputs, at every offset, so every piece lands in every input.
    let mut fragments = vec![block.header.clone()];
    for line in &block.lines {
        fragments.push(line.clone());
        if line.len() == 70 {
            fragments.push(line[..35].to_owned());
            fragments.push(line[35..].to_owned());
        }
    }
    fragments.push(block.footer.clone());
    for offset in 0..input_slots.len().max(fragments.len()) {
        let mut p = Plants::default();
        for (i, slot) in input_slots.iter().enumerate() {
            p = p.with(slot, fragments[(i + offset) % fragments.len()].clone());
        }
        cases.push((
            format!("split across fields, offset {offset}"),
            p,
            Vec::new(),
        ));
    }
    let pieces = key_pieces(&block);
    for options in [Options::default(), include()] {
        let base = baseline(options);
        for (label, p, armor) in &cases {
            let bundle = built(p, options);
            let text = masked(text_of(&bundle));
            let inverse = std::str::from_utf8(bundle.inverse_map().file_bytes()).expect("UTF-8");
            let field = format!(
                "{label} (include_identifiers: {})",
                options.include_identifiers
            );
            for piece in pieces.iter().chain(armor) {
                let in_text = text.contains(piece.as_str());
                let in_inverse = inverse.contains(piece.as_str());
                if !(in_text || in_inverse) || base.contains(piece.as_str()) {
                    continue;
                }
                assert!(
                    !in_text,
                    "{field}: key material (sha256 {}) reached the bundle",
                    digest(piece)
                );
                assert!(
                    !in_inverse,
                    "{field}: key material (sha256 {}) reached the inverse map",
                    digest(piece)
                );
            }
        }
    }
}

#[test]
fn identifier_bearing_diagnostics_are_withheld_or_pseudonymized() {
    let name = run_name();
    let host = format!("db-{name}.fixture.invalid");
    let path = format!("/srv/fixture/{name}/.ssh/config.d/hosts");
    let p = Plants::default()
        // A host name inside an error message, and a path inside a finding's detail.
        .with(
            "doctor.ssh_error",
            format!("ssh: Could not resolve hostname {host}: nodename nor servname provided"),
        )
        .with(
            "doctor.detail",
            format!("Include {path} is missing (resolved from ~/.ssh/config line 3)"),
        )
        // The same host and path in their identifier-typed fields.
        .with("doctor.host", host.clone())
        .with("doctor.path", path.clone())
        // A path and a host typed wrongly: the path as a code, the host as a version.
        .with("doctor.reason", path.clone())
        .with("ssh.version", host.clone());
    let bundle = built(&p, Options::default());
    let base = baseline(Options::default());
    let text = masked(text_of(&bundle));
    for (slot, v) in &p.values {
        assert_no_leak(&text, &base, slot, v, 6);
    }
    let inverse = bundle.inverse_map();
    let host_pseudonym = inverse
        .iter()
        .find(|(_, kind, v)| *kind == IdentKind::Host && *v == host)
        .map(|(p, _, _)| p.to_owned())
        .expect("the host is pseudonymized");
    let path_pseudonym = inverse
        .iter()
        .find(|(_, kind, v)| *kind == IdentKind::Path && *v == path)
        .map(|(p, _, _)| p.to_owned())
        .expect("the path is pseudonymized");
    assert!(host_pseudonym.starts_with("host-") && path_pseudonym.starts_with("path-"));
    let files = files_json(&bundle);
    let findings = &files["doctor.json"]["findings"];
    // Both findings carry the same host pseudonym; the path is a pseudonym too.
    assert!(
        findings[0]["fields"]["host"] == host_pseudonym,
        "first finding's host"
    );
    assert!(
        findings[1]["fields"]["host"] == host_pseudonym,
        "second finding's host"
    );
    assert!(
        findings[0]["fields"]["include_path"] == path_pseudonym,
        "the finding's path"
    );
    // The text-bearing fields and the wrongly typed one are noted as withheld.
    let notes: Vec<&str> = findings[0]["withheld"]
        .as_array()
        .expect("a withheld note")
        .iter()
        .filter_map(Json::as_str)
        .collect();
    for name in ["fields.detail", "fields.ssh_error", "fields.reason"] {
        assert!(notes.contains(&name), "the finding does not note {name}");
    }
    assert_eq!(withheld_at(&bundle, "doctor.fields.reason"), 1);
    assert_eq!(withheld_at(&bundle, "platform.ssh_client.version"), 1);
    assert!(manifest(&bundle)["withheld_by_reason"]["malformed"].as_u64() >= Some(2));
    check_shapes(&bundle).unwrap_or_else(|report| panic!("{report}"));
}

#[test]
fn include_identifiers_never_bypasses_secret_checks() {
    let block = KeyBlock::new();
    let tok = run_hex(6);
    // Random letters around a fixed digit-then-letter pair, so the token is never
    // word-shaped whatever the run draws.
    let letters = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let variants: Vec<(&str, String)> = vec![
        ("canary", canary(1)),
        (
            "canary, lower case with dashes",
            canary(2).to_ascii_lowercase().replace('_', "-"),
        ),
        (
            "canary inside a path",
            format!("/srv/fixture/{}/x", canary(3)),
        ),
        ("armor header", block.header.clone()),
        (
            "altered armor",
            format!("begin  openssh  {} key", "private"),
        ),
        (
            "whole key block",
            block.joined(&block.header, &block.footer, "\n"),
        ),
        ("base64 line", block.lines[0].clone()),
        ("half a base64 line", block.lines[1][..35].to_owned()),
        ("last base64 line", block.lines[4].clone()),
        ("40 hex", run_hex(20)),
        (
            "mixed token",
            format!("{}7q{}", pick(letters, 10), pick(letters, 10)),
        ),
        (
            "padded base64",
            format!("{}9z{}==", pick(letters, 6), pick(letters, 6)),
        ),
        ("embedded newline", format!("fixture-{tok}\nsecond line")),
        ("carriage return", format!("fixture-{tok}\rx")),
        ("tab", format!("fixture-{tok}\tx")),
        ("nul", format!("fixture-{tok}\0x")),
        ("line separator", format!("fixture-{tok}\u{2028}x")),
        ("bidi override", format!("fixture-{tok}\u{202E}x")),
        // Review M08-W0-R05: one of each invisible or formatting class the filter lists.
        ("soft hyphen", format!("fixture-{tok}\u{00AD}x")),
        (
            "combining grapheme joiner",
            format!("fixture-{tok}\u{034F}x"),
        ),
        ("Arabic letter mark", format!("fixture-{tok}\u{061C}x")),
        (
            "Mongolian vowel separator",
            format!("fixture-{tok}\u{180E}x"),
        ),
        ("reserved U+2065", format!("fixture-{tok}\u{2065}x")),
        (
            "deprecated format U+206A",
            format!("fixture-{tok}\u{206A}x"),
        ),
        (
            "deprecated format U+206F",
            format!("fixture-{tok}\u{206F}x"),
        ),
        ("Hangul filler", format!("fixture-{tok}\u{3164}x")),
        ("variation selector 16", format!("fixture-{tok}\u{FE0F}x")),
        (
            "variation selector supplement",
            format!("fixture-{tok}\u{E0100}x"),
        ),
        (
            "tag-encoded text",
            format!("fixture-{tok}\u{E0053}\u{E0045}\u{E0043}\u{E007F}"),
        ),
        (
            "over the cap",
            format!("fixture-{tok}-{}", "x".repeat(1100)),
        ),
    ];
    let base = baseline(include());
    let base_counts = withheld_counts(&built(&Plants::default(), include()));
    let mut checked = 0usize;
    for (label, value) in &variants {
        for (slot, _, path) in IDENT_SLOTS {
            let p = Plants::default().with(slot, value.clone());
            let bundle = built(&p, include());
            let field = format!("{slot} ({label})");
            let (text, preview) = (masked(text_of(&bundle)), masked(bundle.preview()));
            assert_no_leak(&text, &base, &field, value, 6);
            assert_no_leak(&preview, &base, &field, value, 6);
            let inverse = std::str::from_utf8(bundle.inverse_map().file_bytes()).expect("UTF-8");
            assert_no_leak(&masked(inverse), &base, &field, value, 6);
            // Withheld exactly where the fixture reads the slot (twice for doctor.host).
            let reads = if *slot == "doctor.host" { 2 } else { 1 };
            let counted = withheld_counts(&bundle).get(*path).copied().unwrap_or(0);
            let before = base_counts.get(*path).copied().unwrap_or(0);
            assert!(
                counted == before + reads,
                "{field}: not counted as withheld at {path}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, variants.len() * IDENT_SLOTS.len());
    // Free text and secrets stay withheld with inclusion on.
    let mut p = Plants::default();
    for (i, (slot, _)) in TEXT_SLOTS.iter().chain(SECRET_SLOTS).enumerate() {
        p = p.with(slot, format!("plain words {tok} {i}"));
    }
    let bundle = built(&p, include());
    let text = masked(text_of(&bundle));
    for (slot, v) in &p.values {
        assert_no_leak(&text, &base, slot, v, 6);
    }
    // Positive control: an identifier that passes is included as itself, not
    // pseudonymized, and the inverse map is empty.
    let host = format!("included-{}.fixture.invalid", run_name());
    let bundle = built(
        &Plants::default().with("claims.host", host.clone()),
        include(),
    );
    let files = files_json(&bundle);
    assert!(
        files["capabilities.json"]["claims"][0]["fields"]["host"] == host,
        "a passing identifier was not included"
    );
    assert!(bundle.inverse_map().is_empty());
    assert!(manifest(&bundle)["identifiers"] == "included");
}

#[test]
fn the_inverse_map_is_not_in_the_bundle() {
    let name = run_name();
    let mut p = Plants::default();
    for (i, (slot, kind, _)) in IDENT_SLOTS.iter().enumerate() {
        let v = match kind {
            IdentKind::Path => format!("/srv/fixture/{name}/{i}/config"),
            IdentKind::Fingerprint => {
                format!("SHA256:{}", base64(&run_bytes(32)).trim_end_matches('='))
            }
            IdentKind::HeimdallId => format!("grant_{}", run_hex(16)),
            _ => format!("{name}-{i}.fixture.invalid"),
        };
        p = p.with(slot, v);
    }
    let bundle = built(&p, Options::default());
    let raw = text_of(&bundle);
    let text = masked(raw);
    let inverse = bundle.inverse_map();
    // Every slot holds a distinct value; doctor.host is read twice and has one pseudonym.
    assert_eq!(inverse.len(), IDENT_SLOTS.len());
    let base = baseline(Options::default());
    let preview = masked(bundle.preview());
    for (pseudonym, kind, value) in inverse.iter() {
        assert!(
            raw.contains(&format!("\"{pseudonym}\"")),
            "a pseudonym of kind {kind:?} is missing from the bundle"
        );
        assert!(inverse.get(pseudonym) == Some(value));
        let field = format!("inverse map entry {pseudonym}");
        assert_no_leak(&text, &base, &field, value, 6);
        assert_no_leak(&preview, &base, &field, value, 6);
    }
    let file = std::str::from_utf8(inverse.file_bytes()).expect("UTF-8");
    assert!(
        !raw.contains(file.trim_end()),
        "the inverse map file is inside the bundle"
    );
    let map: Json = serde_json::from_str(file).expect("the inverse map file is JSON");
    assert!(map["bundle_manifest_sha256"] == bundle.manifest_sha256());
    assert_eq!(
        map["entries"].as_array().map(Vec::len),
        Some(IDENT_SLOTS.len())
    );
    for marker in [
        "heimdall-support-inverse-map",
        "bundle_manifest_sha256",
        "Do not send it",
    ] {
        assert!(
            !raw.contains(marker),
            "an inverse-map marker is inside the bundle"
        );
    }
    assert!(bundle.preview().contains("must not be sent"));
    // With identifier inclusion nothing is pseudonymized, so the map is empty.
    assert!(built(&p, include()).inverse_map().is_empty());
}

#[test]
fn previewed_bytes_are_the_written_bytes() {
    let p = Plants::default().with("doctor.detail", format!("detail {}", run_hex(6)));
    let bundle = built(&p, Options::default());
    let text = text_of(&bundle);
    let preview = bundle.preview();
    // The preview holds the bytes once, exactly, between its two marker lines.
    let begin = format!("{PREVIEW_BEGIN}\n");
    let start = preview.find(begin.as_str()).expect("the begin marker") + begin.len();
    let end = preview
        .rfind(format!("{PREVIEW_END}\n").as_str())
        .expect("the end marker");
    assert!(
        &preview[start..end] == text,
        "the preview's bytes are not the bundle's"
    );
    assert_eq!(preview.matches(text).count(), 1);
    // The written bytes are those bytes.
    let mut written = Vec::new();
    bundle.write_to(&mut written).expect("write to memory");
    assert!(
        written == bundle.bytes(),
        "the written bytes are not the bundle's"
    );
    // The digest in the preview is the manifest's, computed independently.
    let files = parse_container(&written);
    let (name, manifest_bytes) = &files[0];
    assert!(name == MANIFEST_FILE, "the first file is not the manifest");
    let digest_hex: String = Sha256::digest(manifest_bytes.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(
        bundle.manifest_sha256() == digest_hex,
        "the manifest digest"
    );
    assert!(preview.contains(&format!("Manifest SHA-256: {digest_hex}\n")));
    // The header outside the bytes carries nothing planted.
    let header = masked(&preview[..start]);
    for (slot, v) in &p.values {
        assert_no_leak(&header, &baseline(Options::default()), slot, v, 6);
    }
    // Building again from the same input gives the same bytes.
    assert!(built(&p, Options::default()).bytes() == bundle.bytes());
}

#[test]
fn canaries_in_every_input_never_reach_the_bundle() {
    let mut p = Plants::default();
    for (i, slot) in all_slots().iter().enumerate() {
        p = p.with(slot, canary(i));
    }
    assert_eq!(p.values.len(), all_slots().len());
    for options in [Options::default(), include()] {
        let bundle = built(&p, options);
        assert!(
            &*p.used.borrow() == all_slots(),
            "a slot was not read by the fixture"
        );
        let inverse = std::str::from_utf8(bundle.inverse_map().file_bytes()).expect("UTF-8");
        for (where_, text) in [
            ("bundle", text_of(&bundle)),
            ("preview", bundle.preview()),
            ("inverse map", inverse),
        ] {
            assert!(
                !has_canary_marker(text),
                "a canary marker reached the {where_} (include_identifiers: {})",
                options.include_identifiers
            );
            for (slot, v) in &p.values {
                assert!(
                    !text.contains(v.as_str()),
                    "{slot}: a canary (sha256 {}) reached the {where_}",
                    digest(v)
                );
            }
        }
        // Every planted input was withheld at least once.
        assert!(bundle.withheld_total() >= u64::try_from(all_slots().len()).unwrap());
        assert!(bundle.inverse_map().is_empty());
    }
}

#[test]
fn bundle_is_plain_text_and_bounded() {
    let p = Plants::default()
        .with(
            "claims.host",
            format!("ünïcödé-{}.fixture.invalid", run_name()),
        )
        .with("doctor.detail", "multi\nline\ttext\r\n".to_owned());
    for options in [Options::default(), include()] {
        let bundle = built(&p, options);
        let text = text_of(&bundle);
        assert!(bundle.bytes().len() <= MAX_BUNDLE_BYTES);
        assert!(
            text.chars().all(|c| c == '\n' || !c.is_control()),
            "a control character other than a newline is in the bundle"
        );
        if !options.include_identifiers {
            assert!(text.is_ascii(), "a default bundle is not ASCII");
        }
        // The container: the manifest, then the declared files, each JSON ending in a
        // newline and listed in the manifest with its length and digest.
        let files = parse_container(bundle.bytes());
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        let mut expected = vec![MANIFEST_FILE];
        expected.extend(FILES);
        assert!(
            names == expected,
            "the container's files are not the declared ones"
        );
        let manifest: Json = serde_json::from_str(&files[0].1).expect("the manifest is JSON");
        assert!(
            manifest["format"] == "heimdall-support-bundle",
            "the format name"
        );
        assert_eq!(manifest["format_version"].as_u64(), Some(1));
        let listed = manifest["files"].as_array().expect("files");
        assert_eq!(listed.len(), FILES.len());
        for (entry, (name, body)) in listed.iter().zip(&files[1..]) {
            assert!(entry["name"] == name.as_str(), "a manifest entry's name");
            assert_eq!(entry["bytes"].as_u64(), Some(body.len() as u64));
            let digest_hex: String = Sha256::digest(body.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert!(
                entry["sha256"] == digest_hex.as_str(),
                "{name}: digest mismatch"
            );
            let _: Json = serde_json::from_str(body).expect("each file is JSON");
        }
        let total: u64 = manifest["withheld"]
            .as_object()
            .expect("withheld counts")
            .values()
            .filter_map(Json::as_u64)
            .sum();
        assert_eq!(manifest["withheld_total"].as_u64(), Some(total));
        let by_reason: u64 = manifest["withheld_by_reason"]
            .as_object()
            .expect("reasons")
            .values()
            .filter_map(Json::as_u64)
            .sum();
        assert_eq!(by_reason, total);
        assert_eq!(bundle.withheld_total(), total);
    }

    // Over the cap is an error, not a truncation.
    let mut big = fixture(&Plants::default());
    // About 121 bytes a finding: 80 000 of them are about 9.7 MB, over the 8 MiB cap.
    big.doctor = (0..80_000u64)
        .map(|i| Finding {
            code: Code::new("include_missing"),
            severity: Some(Code::new("warning")),
            fields: vec![Field::new("depth", i)],
        })
        .collect();
    match build(&big, Options::default()) {
        Err(BundleError::TooLarge { bytes, limit }) => {
            assert!(bytes > limit);
            assert_eq!(limit, MAX_BUNDLE_BYTES);
        }
        Ok(bundle) => panic!(
            "an oversized input built a bundle of {} bytes",
            bundle.bytes().len()
        ),
        Err(other) => panic!("unexpected error: {other}"),
    }
}

#[test]
fn an_unreadable_store_reports_only_its_integrity_code() {
    let mut input = fixture(&Plants::default());
    input.store = StoreInput::Unreadable {
        integrity: Code::new("store_unopenable"),
    };
    let bundle = build(&input, Options::default()).expect("builds without a store");
    let files = files_json(&bundle);
    let store = files["store.json"].as_object().expect("store.json");
    let keys: BTreeSet<&str> = store.keys().map(String::as_str).collect();
    assert!(
        keys == BTreeSet::from(["integrity", "readable"]),
        "store.json holds more than the integrity result"
    );
    assert!(
        store["integrity"] == "store_unopenable",
        "the integrity code"
    );
    assert!(store["readable"] == false, "readable");
    assert!(
        files["operations.json"]["available"] == false,
        "operations available"
    );
    assert_eq!(
        files["operations.json"]["operations"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    check_shapes(&bundle).unwrap_or_else(|report| panic!("{report}"));
}

// --- properties (256 cases, fixed seed unless `PROPTEST_RNG_SEED` is set) ------------------

/// Failure persistence off (a regression file would hold the shrunk input) and verbosity
/// off (proptest would print it).
fn property_config() -> ProptestConfig {
    let mut c = ProptestConfig {
        cases: 256,
        failure_persistence: None,
        verbose: 0,
        ..ProptestConfig::default()
    };
    if matches!(c.rng_seed, RngSeed::Random) {
        c.rng_seed = RngSeed::Fixed(0x5536_615f_4255_4e44);
    }
    c
}

/// Run a property; a failure reports only the case's own message (a slot and a digest),
/// never the generated input.
fn run_property<S: Strategy>(
    name: &str,
    strategy: S,
    test: impl Fn(S::Value) -> Result<(), TestCaseError>,
) {
    let mut runner = TestRunner::new(property_config());
    match runner.run(&strategy, test) {
        Ok(()) => {}
        Err(TestError::Fail(reason, _input)) => panic!("{name}: {reason}"),
        Err(TestError::Abort(reason)) => panic!("{name}: aborted: {reason}"),
    }
}

fn arbitrary_text() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "[ -~]{0,80}",
        "[A-Za-z0-9+/=]{6,90}",
        "[a-z]{3,10}( [a-z]{3,10}){0,6}",
        "[A-Z0-9]{4,12}".prop_map(|s| format!("{CANARY_PREFIX}{s}")),
        Just(String::new()),
    ]
}

#[test]
fn arbitrary_free_text_and_secrets_never_reach_the_bundle() {
    let slots: Vec<&'static str> = TEXT_SLOTS
        .iter()
        .chain(SECRET_SLOTS)
        .map(|(s, _)| *s)
        .collect();
    let bases = [
        (
            Options::default(),
            baseline_bytes(Options::default()),
            baseline(Options::default()),
        ),
        (include(), baseline_bytes(include()), baseline(include())),
    ];
    run_property(
        "arbitrary free text and secrets",
        prop::collection::vec(arbitrary_text(), slots.len()),
        |values| {
            let mut p = Plants::default();
            for (slot, v) in slots.iter().zip(&values) {
                p = p.with(slot, v.clone());
            }
            for (options, base_bytes, base) in &bases {
                let bundle = build(&fixture(&p), *options)
                    .map_err(|e| TestCaseError::fail(format!("build failed: {e}")))?;
                // The bytes do not depend on free text or secrets at all ...
                if bundle.bytes() != base_bytes.as_slice() {
                    return Err(TestCaseError::fail(
                        "the bundle's bytes depend on free-text or secret content",
                    ));
                }
                // ... so no 6-character piece unique to a planted value is in them.
                let text = std::str::from_utf8(bundle.bytes())
                    .map(masked)
                    .map_err(|_| TestCaseError::fail("the bundle is not UTF-8"))?;
                for (slot, v) in slots.iter().zip(&values) {
                    leak(&text, base, slot, v, 6).map_err(TestCaseError::fail)?;
                }
            }
            Ok(())
        },
    );
}

fn arbitrary_identifier() -> impl Strategy<Value = String> {
    let injected = prop_oneof![
        Just(String::new()),
        "[A-Z0-9]{4,12}".prop_map(|s| format!("{CANARY_PREFIX}{s}")),
        Just(format!("-----BEGIN OPENSSH {} KEY-----", "PRIVATE")),
        "[A-Za-z0-9+/]{40,70}",
        Just("\n".to_owned()),
        Just("\u{2028}".to_owned()),
    ];
    (any::<String>(), injected, "[ -~]{0,30}").prop_map(|(a, b, c)| format!("{a}{b}{c}"))
}

/// The test's own, weaker checks on an included identifier: no canary marker, no control
/// character or line separator, no armor dash run, no base64 run of 40 or more.
fn independently_clean(value: &str) -> bool {
    let no_control = !value
        .chars()
        .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}');
    let no_dashes = !value.contains("----");
    let longest_run = value
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/'))
        .map(str::len)
        .max()
        .unwrap_or(0);
    no_control && no_dashes && longest_run < 40 && !has_canary_marker(value)
}

#[test]
fn arbitrary_identifiers_are_pseudonymized_or_withheld() {
    let base = baseline(Options::default());
    let vocabulary: BTreeSet<String> = {
        let bundle = built(&Plants::default(), Options::default());
        let files = files_json(&bundle);
        let mut found = Vec::new();
        for (name, v) in &files {
            strings(v, name, &mut found);
        }
        found.into_iter().map(|(_, s)| s.to_owned()).collect()
    };
    run_property(
        "arbitrary identifiers",
        prop::collection::vec(arbitrary_identifier(), IDENT_SLOTS.len()),
        |values| {
            let mut p = Plants::default();
            for ((slot, _, _), v) in IDENT_SLOTS.iter().zip(&values) {
                p = p.with(slot, v.clone());
            }
            // Default: every string is a code, a safe value or a pseudonym, and no planted
            // value is in the bundle unless the neutral fixture's bundle has it too.
            let bundle = build(&fixture(&p), Options::default())
                .map_err(|e| TestCaseError::fail(format!("build failed: {e}")))?;
            check_shapes(&bundle).map_err(TestCaseError::fail)?;
            let text = std::str::from_utf8(bundle.bytes())
                .map(masked)
                .map_err(|_| TestCaseError::fail("the bundle is not UTF-8"))?;
            for ((slot, _, _), v) in IDENT_SLOTS.iter().zip(&values) {
                let unique =
                    v.chars().count() >= 6 && !vocabulary.contains(v) && !base.contains(v.as_str());
                if unique && text.contains(v.as_str()) {
                    return Err(TestCaseError::fail(format!(
                        "{slot}: the planted identifier (sha256 {}) reached a default bundle",
                        digest(v)
                    )));
                }
            }
            // Inclusion: a planted value that is exported passes the test's own checks.
            let bundle = build(&fixture(&p), include())
                .map_err(|e| TestCaseError::fail(format!("build failed: {e}")))?;
            let files = files_json(&bundle);
            let mut found = Vec::new();
            for (name, v) in &files {
                strings(v, name, &mut found);
            }
            let exported: BTreeSet<&str> = found.into_iter().map(|(_, s)| s).collect();
            for ((slot, _, _), v) in IDENT_SLOTS.iter().zip(&values) {
                if exported.contains(v.as_str()) && !independently_clean(v) {
                    return Err(TestCaseError::fail(format!(
                        "{slot}: an included identifier (sha256 {}) failed the test's own checks",
                        digest(v)
                    )));
                }
            }
            Ok(())
        },
    );
}
