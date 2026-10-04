//! Profile loading and validation (contract §2). Shared by `profile show` and `tui`.
//!
//! Error messages may name a key path but never echo a value from the file, with
//! one contract-mandated exception: an unsupported *integer* `schema_version` is
//! named in a warning.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde_json::{Value as Json, json};
use toml::{Table, Value};

use crate::envelope::{Code, Envelope};
use crate::text::key_segment;

/// Maximum accepted profile size in bytes (contract §2).
pub const MAX_PROFILE_BYTES: u64 = 1_048_576;

const TOP_KEYS: &[&str] = &["schema_version", "name", "revision", "meta", "destinations"];
const DEST_KEYS: &[&str] = &["id", "alias", "host", "port", "account", "labels"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub id: String,
    pub alias: String,
    pub host: String,
    pub port: u16,
    pub account: String,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub revision: i64,
    pub destinations: Vec<Destination>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError {
    pub code: Code,
    pub key_path: Option<String>,
    pub message: String,
    pub warnings: Vec<String>,
}

impl ProfileError {
    fn new(code: Code, key_path: Option<String>, message: impl Into<String>) -> Self {
        ProfileError {
            code,
            key_path,
            message: message.into(),
            warnings: Vec::new(),
        }
    }
    fn schema(key_path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(Code::SchemaInvalid, Some(key_path.into()), message)
    }
    pub fn to_envelope(&self) -> Envelope {
        Envelope::failure(self.code, self.key_path.clone(), self.message.clone())
            .with_warnings(self.warnings.clone())
    }
}

impl Destination {
    pub fn to_json(&self) -> Json {
        json!({
            "id": self.id, "alias": self.alias, "host": self.host,
            "port": self.port, "account": self.account, "labels": self.labels,
        })
    }
}

impl Profile {
    pub fn to_json(&self) -> Json {
        let dests: Vec<Json> = self.destinations.iter().map(Destination::to_json).collect();
        json!({"profile": {"name": self.name, "revision": self.revision, "destinations": dests}})
    }

    pub fn to_envelope(&self) -> Envelope {
        Envelope::success(Code::ProfileOk, self.to_json())
    }
}

/// Open `path` for reading without ever blocking: on Unix with O_NONBLOCK, so a FIFO
/// without a writer (or a device) opens at once and is then rejected by the
/// regular-file check in [`read_bounded`] (contract §9.1 K14).
fn open_nonblocking(path: &Path) -> std::io::Result<File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NONBLOCK);
    }
    o.open(path)
}

/// Read a profile file with the size bound applied before parsing. Anything that is
/// not a regular file (FIFO, socket, device, directory) is a usage error (K14).
pub fn read_bounded(path: &Path) -> Result<Vec<u8>, ProfileError> {
    let file = open_nonblocking(path).map_err(|e| {
        ProfileError::new(
            Code::UsageError,
            None,
            format!("cannot open profile file: {}", io_kind(&e)),
        )
    })?;
    let meta = file.metadata().map_err(|e| {
        ProfileError::new(
            Code::UsageError,
            None,
            format!("cannot inspect profile file: {}", io_kind(&e)),
        )
    })?;
    if !meta.is_file() {
        return Err(ProfileError::new(
            Code::UsageError,
            None,
            if meta.is_dir() {
                "profile path is a directory"
            } else {
                "profile path is not a regular file"
            },
        ));
    }
    if meta.len() > MAX_PROFILE_BYTES {
        return Err(too_large());
    }
    // Bound the read as well, in case the file grows while it is read.
    let mut buf = Vec::new();
    file.take(MAX_PROFILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| {
            ProfileError::new(
                Code::UsageError,
                None,
                format!("cannot read profile file: {}", io_kind(&e)),
            )
        })?;
    if buf.len() as u64 > MAX_PROFILE_BYTES {
        return Err(too_large());
    }
    Ok(buf)
}

fn too_large() -> ProfileError {
    ProfileError::new(
        Code::InputTooLarge,
        None,
        format!("profile file exceeds {MAX_PROFILE_BYTES} bytes; not parsed"),
    )
}

fn io_kind(e: &std::io::Error) -> String {
    // Only the error kind; never the path or OS-provided strings echoing input.
    format!("{:?}", e.kind())
}

/// Load and validate a profile file.
pub fn load_file(path: &Path) -> Result<Profile, ProfileError> {
    let bytes = read_bounded(path)?;
    parse_bytes(&bytes)
}

/// Parse and validate profile bytes.
pub fn parse_bytes(bytes: &[u8]) -> Result<Profile, ProfileError> {
    let text = std::str::from_utf8(bytes).map_err(|e| {
        let (line, col) = line_col(bytes, e.valid_up_to());
        ProfileError::new(
            Code::SchemaInvalid,
            None,
            format!("malformed TOML: invalid UTF-8 at line {line} column {col}"),
        )
    })?;
    let table: Table = text.parse().map_err(|e: toml::de::Error| {
        // Never use the parser's Display output: it quotes the offending source line.
        let msg = match e.span() {
            Some(span) => {
                let (line, col) = line_col(bytes, span.start);
                format!("malformed TOML at line {line} column {col}")
            }
            None => "malformed TOML".to_string(),
        };
        ProfileError::new(Code::SchemaInvalid, None, msg)
    })?;
    validate(&table)
}

fn line_col(bytes: &[u8], offset: usize) -> (usize, usize) {
    let offset = offset.min(bytes.len());
    let before = &bytes[..offset];
    let line = before.iter().filter(|&&b| b == b'\n').count() + 1;
    let line_start = before
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|p| p + 1)
        .unwrap_or(0);
    let col = String::from_utf8_lossy(&before[line_start..])
        .chars()
        .count()
        + 1;
    (line, col)
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::String(_) => "string",
        Value::Integer(_) => "integer",
        Value::Float(_) => "float",
        Value::Boolean(_) => "boolean",
        Value::Datetime(_) => "datetime",
        Value::Array(_) => "array",
        Value::Table(_) => "table",
    }
}

fn validate(t: &Table) -> Result<Profile, ProfileError> {
    // schema_version first: an unsupported version is rejected before its keys are judged.
    match t.get("schema_version") {
        None => {
            return Err(ProfileError::schema(
                "schema_version",
                "required key schema_version is missing",
            ));
        }
        Some(Value::Integer(1)) => {}
        Some(Value::Integer(n)) => {
            let mut e = ProfileError::schema(
                "schema_version",
                "unsupported schema_version; this prototype supports only 1",
            );
            e.warnings.push(format!("unsupported schema_version {n}"));
            return Err(e);
        }
        Some(other) => {
            let mut e =
                ProfileError::schema("schema_version", "schema_version must be the integer 1");
            e.warnings.push(format!(
                "unsupported schema_version of type {}",
                type_name(other)
            ));
            return Err(e);
        }
    }

    for key in t.keys() {
        if !TOP_KEYS.contains(&key.as_str()) {
            let kp = key_segment(key);
            return Err(ProfileError::schema(
                kp.clone(),
                format!("unknown key {kp}"),
            ));
        }
    }

    let name = req_string(t, "name", "name")?;
    let revision = match t.get("revision") {
        None => {
            return Err(ProfileError::schema(
                "revision",
                "required key revision is missing",
            ));
        }
        Some(Value::Integer(n)) if *n >= 1 => *n,
        Some(Value::Integer(_)) => {
            return Err(ProfileError::schema(
                "revision",
                "revision must be an integer >= 1",
            ));
        }
        Some(v) => {
            return Err(ProfileError::schema(
                "revision",
                format!("revision must be an integer, found {}", type_name(v)),
            ));
        }
    };
    if let Some(m) = t.get("meta")
        && !m.is_table()
    {
        return Err(ProfileError::schema(
            "meta",
            format!("meta must be a table, found {}", type_name(m)),
        ));
    }

    let mut destinations = Vec::new();
    match t.get("destinations") {
        None => {}
        Some(Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                let base = format!("destinations[{i}]");
                let Value::Table(d) = item else {
                    return Err(ProfileError::schema(
                        base,
                        format!("destination must be a table, found {}", type_name(item)),
                    ));
                };
                destinations.push(validate_destination(d, &base)?);
            }
        }
        Some(v) => {
            return Err(ProfileError::schema(
                "destinations",
                format!(
                    "destinations must be an array of tables, found {}",
                    type_name(v)
                ),
            ));
        }
    }

    // Linear-time duplicate check (round 1 compared every pair: O(n^2)).
    let mut ids = std::collections::HashSet::with_capacity(destinations.len());
    let mut aliases = std::collections::HashSet::with_capacity(destinations.len());
    for (i, d) in destinations.iter().enumerate() {
        if !ids.insert(d.id.as_str()) {
            return Err(ProfileError::schema(
                format!("destinations[{i}].id"),
                "duplicate destination id",
            ));
        }
        if !aliases.insert(d.alias.as_str()) {
            return Err(ProfileError::schema(
                format!("destinations[{i}].alias"),
                "duplicate destination alias",
            ));
        }
    }

    Ok(Profile {
        name,
        revision,
        destinations,
    })
}

fn validate_destination(d: &Table, base: &str) -> Result<Destination, ProfileError> {
    for key in d.keys() {
        if !DEST_KEYS.contains(&key.as_str()) {
            let kp = format!("{base}.{}", key_segment(key));
            return Err(ProfileError::schema(
                kp.clone(),
                format!("unknown key {kp}"),
            ));
        }
    }
    let id = req_string(d, "id", &format!("{base}.id"))?;
    let alias = req_string(d, "alias", &format!("{base}.alias"))?;
    let host = req_string(d, "host", &format!("{base}.host"))?;
    let account = req_string(d, "account", &format!("{base}.account"))?;
    let port = match d.get("port") {
        None => 22,
        Some(Value::Integer(n)) if (1..=65535).contains(n) => *n as u16,
        Some(Value::Integer(_)) => {
            return Err(ProfileError::schema(
                format!("{base}.port"),
                "port must be in 1..65535",
            ));
        }
        Some(v) => {
            return Err(ProfileError::schema(
                format!("{base}.port"),
                format!("port must be an integer, found {}", type_name(v)),
            ));
        }
    };
    let labels = match d.get("labels") {
        None => Vec::new(),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for (j, it) in items.iter().enumerate() {
                let kp = format!("{base}.labels[{j}]");
                match it {
                    Value::String(s) => out.push(check_text(s, &kp, true)?),
                    other => {
                        return Err(ProfileError::schema(
                            kp,
                            format!("label must be a string, found {}", type_name(other)),
                        ));
                    }
                }
            }
            out
        }
        Some(v) => {
            return Err(ProfileError::schema(
                format!("{base}.labels"),
                format!("labels must be an array of strings, found {}", type_name(v)),
            ));
        }
    };
    Ok(Destination {
        id,
        alias,
        host,
        port,
        account,
        labels,
    })
}

fn req_string(t: &Table, key: &str, key_path: &str) -> Result<String, ProfileError> {
    match t.get(key) {
        None => Err(ProfileError::schema(
            key_path,
            format!("required key {key_path} is missing"),
        )),
        Some(Value::String(s)) => check_text(s, key_path, false),
        Some(v) => Err(ProfileError::schema(
            key_path,
            format!("{key_path} must be a string, found {}", type_name(v)),
        )),
    }
}

/// Strings are echoed in JSON and drawn in the TUI, so control characters
/// (terminal escapes) are rejected rather than emitted. Empty required strings are
/// rejected because the result schema requires `minLength: 1`.
fn check_text(s: &str, key_path: &str, allow_empty: bool) -> Result<String, ProfileError> {
    if !allow_empty && s.is_empty() {
        return Err(ProfileError::schema(
            key_path,
            format!("{key_path} must not be empty"),
        ));
    }
    if s.chars().any(crate::text::is_unsafe_control) {
        return Err(ProfileError::schema(
            key_path,
            format!("{key_path} contains control characters"),
        ));
    }
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Fixture directory: `$HEIMDALL_G02_FIXTURES` (relocated test runs), else the
    /// repository layout relative to this crate.
    fn fixtures() -> PathBuf {
        std::env::var_os("HEIMDALL_G02_FIXTURES")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/g02/profiles")
            })
    }

    fn load(name: &str) -> Result<Profile, ProfileError> {
        load_file(&fixtures().join(name))
    }

    fn assert_no_canary(e: &ProfileError) {
        let out = e.to_envelope().to_line();
        assert!(!out.contains("HEIMDALL_CANARY_"), "canary leaked: {out}");
    }

    #[test]
    fn homelab_ok() {
        let p = load("homelab.toml").unwrap();
        assert_eq!(p.name, "homelab");
        assert_eq!(p.revision, 3);
        let ids: Vec<_> = p.destinations.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(ids, ["dst_lab_server", "dst_nas", "dst_vps_ünïcode"]);
        assert_eq!(p.destinations[1].port, 22, "port default applied to nas");
        assert_eq!(p.destinations[2].alias, "vps-東京");
        assert_eq!(p.destinations[2].port, 2222);
        assert_eq!(p.destinations[0].labels, ["homelab", "fixed-auth"]);
        assert!(p.destinations[2].labels.is_empty());
        let out = p.to_envelope().to_line();
        assert!(
            !out.contains("free-form metadata"),
            "meta must not be echoed"
        );
        assert!(!out.contains("owner_hint"));
    }

    #[test]
    fn example_json_matches_contract_shape() {
        let p = load("homelab.toml").unwrap();
        let v = p.to_envelope().to_value();
        assert_eq!(v["code"], "PROFILE_OK");
        assert_eq!(v["state"], "succeeded");
        assert_eq!(
            v["data"]["profile"]["destinations"][0],
            json!({"id":"dst_lab_server","alias":"lab-server","host":"lab.example.internal",
                   "port":22,"account":"aman","labels":["homelab","fixed-auth"]})
        );
        let keys: Vec<_> = v["data"]["profile"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(keys, ["name", "revision", "destinations"]);
    }

    #[test]
    fn spaced_unicode_path_identical() {
        let a = load("homelab.toml").unwrap();
        let b = load("spaced dir ü/prøfile homelab.toml").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn large_100() {
        let p = load("large-100.toml").unwrap();
        assert_eq!(p.destinations.len(), 100);
        assert_eq!(p.destinations[0].alias, "host-000-web");
        assert_eq!(p.destinations[99].id, "dst_099");
    }

    #[test]
    fn forbidden_key_no_canary() {
        let e = load("invalid-forbidden-key.toml").unwrap_err();
        assert_eq!(e.code, Code::SchemaInvalid);
        assert_eq!(e.key_path.as_deref(), Some("private_key"));
        assert_no_canary(&e);
    }

    #[test]
    fn unknown_dest_key() {
        let e = load("invalid-unknown-dest-key.toml").unwrap_err();
        assert_eq!(e.code, Code::SchemaInvalid);
        assert_eq!(e.key_path.as_deref(), Some("destinations[0].identity_file"));
        assert_no_canary(&e);
    }

    #[test]
    fn malformed() {
        let e = load("invalid-malformed.toml").unwrap_err();
        assert_eq!(e.code, Code::SchemaInvalid);
        assert!(e.message.starts_with("malformed TOML"), "{}", e.message);
        assert!(
            !e.message.contains("homelab"),
            "must not quote source: {}",
            e.message
        );
    }

    #[test]
    fn malformed_with_canary_not_quoted() {
        let e = parse_bytes(b"schema_version = 1\nname = \"HEIMDALL_CANARY_x\nrevision = 1\n")
            .unwrap_err();
        assert_eq!(e.code, Code::SchemaInvalid);
        assert_no_canary(&e);
    }

    #[test]
    fn schema_version_unsupported() {
        let e = load("invalid-schema-version.toml").unwrap_err();
        assert_eq!(e.code, Code::SchemaInvalid);
        assert_eq!(e.warnings, ["unsupported schema_version 2"]);
        let e = parse_bytes(b"schema_version = \"HEIMDALL_CANARY_v\"\nname=\"n\"\nrevision=1\n")
            .unwrap_err();
        assert_eq!(e.code, Code::SchemaInvalid);
        assert_no_canary(&e);
        let e = parse_bytes(b"name=\"n\"\nrevision=1\n").unwrap_err();
        assert_eq!(e.key_path.as_deref(), Some("schema_version"));
    }

    #[test]
    fn duplicate_alias_and_id() {
        let e = load("invalid-duplicate-alias.toml").unwrap_err();
        assert_eq!(e.code, Code::SchemaInvalid);
        assert_eq!(e.key_path.as_deref(), Some("destinations[1].alias"));
        let e = parse_bytes(
            b"schema_version=1\nname=\"n\"\nrevision=1\n[[destinations]]\nid=\"x\"\nalias=\"a\"\nhost=\"h\"\naccount=\"u\"\n[[destinations]]\nid=\"x\"\nalias=\"b\"\nhost=\"h\"\naccount=\"u\"\n",
        )
        .unwrap_err();
        assert_eq!(e.key_path.as_deref(), Some("destinations[1].id"));
    }

    #[test]
    fn port_out_of_range() {
        let e = load("invalid-port.toml").unwrap_err();
        assert_eq!(e.code, Code::SchemaInvalid);
        assert_eq!(e.key_path.as_deref(), Some("destinations[0].port"));
        assert!(!e.message.contains("70000"));
        for bad in ["0", "-1", "65536", "\"22\"", "22.0"] {
            let src = format!(
                "schema_version=1\nname=\"n\"\nrevision=1\n[[destinations]]\nid=\"x\"\nalias=\"a\"\nhost=\"h\"\naccount=\"u\"\nport={bad}\n"
            );
            assert_eq!(
                parse_bytes(src.as_bytes()).unwrap_err().code,
                Code::SchemaInvalid,
                "port={bad}"
            );
        }
        let ok = "schema_version=1\nname=\"n\"\nrevision=1\n[[destinations]]\nid=\"x\"\nalias=\"a\"\nhost=\"h\"\naccount=\"u\"\nport=65535\n";
        assert_eq!(
            parse_bytes(ok.as_bytes()).unwrap().destinations[0].port,
            65535
        );
    }

    #[test]
    fn required_and_types() {
        let cases: &[(&str, &str)] = &[
            ("schema_version=1\nrevision=1\n", "name"),
            ("schema_version=1\nname=\"n\"\n", "revision"),
            ("schema_version=1\nname=\"n\"\nrevision=0\n", "revision"),
            ("schema_version=1\nname=\"n\"\nrevision=\"1\"\n", "revision"),
            ("schema_version=1\nname=\"\"\nrevision=1\n", "name"),
            ("schema_version=1\nname=\"n\"\nrevision=1\nmeta=3\n", "meta"),
            (
                "schema_version=1\nname=\"n\"\nrevision=1\ndestinations=3\n",
                "destinations",
            ),
            (
                "schema_version=1\nname=\"n\"\nrevision=1\n[[destinations]]\nalias=\"a\"\nhost=\"h\"\naccount=\"u\"\n",
                "destinations[0].id",
            ),
            (
                "schema_version=1\nname=\"n\"\nrevision=1\n[[destinations]]\nid=\"i\"\nhost=\"h\"\naccount=\"u\"\n",
                "destinations[0].alias",
            ),
            (
                "schema_version=1\nname=\"n\"\nrevision=1\n[[destinations]]\nid=\"i\"\nalias=\"a\"\naccount=\"u\"\n",
                "destinations[0].host",
            ),
            (
                "schema_version=1\nname=\"n\"\nrevision=1\n[[destinations]]\nid=\"i\"\nalias=\"a\"\nhost=\"h\"\n",
                "destinations[0].account",
            ),
            (
                "schema_version=1\nname=\"n\"\nrevision=1\n[[destinations]]\nid=\"i\"\nalias=\"a\"\nhost=\"h\"\naccount=\"u\"\nlabels=[1]\n",
                "destinations[0].labels[0]",
            ),
            (
                "schema_version=1\nname=\"n\"\nrevision=1\n[[destinations]]\nid=\"i\"\nalias=\"a\\u001b[31m\"\nhost=\"h\"\naccount=\"u\"\n",
                "destinations[0].alias",
            ),
            ("schema_version=1\nname=\"n\"\nrevision=1\n[x]\ny=1\n", "x"),
        ];
        for (src, kp) in cases {
            let e = parse_bytes(src.as_bytes()).unwrap_err();
            assert_eq!(e.code, Code::SchemaInvalid, "{src}");
            assert_eq!(e.key_path.as_deref(), Some(*kp), "{src}");
        }
    }

    /// K2: a C0 (incl. TAB), DEL or C1 control in any string value outside [meta]
    /// is SCHEMA_INVALID naming the key; the message never carries the value.
    /// Controls inside [meta] are tolerated and not echoed.
    #[test]
    fn k2_control_chars_in_values_rejected_outside_meta() {
        let head = "schema_version=1\nrevision=1\n";
        let dest = |field: &str, v: &str| {
            let mut d = vec![
                ("id", "\"i\"".to_string()),
                ("alias", "\"a\"".to_string()),
                ("host", "\"h\"".to_string()),
                ("account", "\"u\"".to_string()),
            ];
            for e in d.iter_mut() {
                if e.0 == field {
                    e.1 = v.to_string();
                }
            }
            let mut s = format!("{head}name=\"n\"\n[[destinations]]\n");
            for (k, val) in d {
                s.push_str(&format!("{k}={val}\n"));
            }
            if field == "labels" {
                s.push_str(&format!("labels=[\"ok\", {v}]\n"));
            }
            s
        };
        let cases: Vec<(String, &str)> = vec![
            (format!("{head}name=\"n\\tCANARYV\"\n"), "name"),
            (format!("{head}name=\"n\tCANARYV\"\n"), "name"),
            (format!("{head}name=\"n\\u0000CANARYV\"\n"), "name"),
            (dest("id", "\"i\\u007fCANARYV\""), "destinations[0].id"),
            (
                dest("alias", "\"a\\u001bCANARYV\""),
                "destinations[0].alias",
            ),
            (dest("host", "\"h\\u0085CANARYV\""), "destinations[0].host"),
            (
                dest("account", "\"u\\u009fCANARYV\""),
                "destinations[0].account",
            ),
            (
                dest("labels", "\"l\\u0080CANARYV\""),
                "destinations[0].labels[1]",
            ),
        ];
        for (src, kp) in &cases {
            let e = parse_bytes(src.as_bytes()).unwrap_err();
            assert_eq!(e.code, Code::SchemaInvalid, "{src}");
            assert_eq!(e.code.exit_code(), 2);
            assert_eq!(e.key_path.as_deref(), Some(*kp), "{src}");
            let line = e.to_envelope().to_line();
            assert!(!line.contains("CANARYV"), "value echoed: {line}");
        }
        let p = parse_bytes(
            format!("{head}name=\"n\"\n[meta]\nnote=\"x\\u001b\\u0085\\tCANARYV\"\n").as_bytes(),
        )
        .unwrap();
        assert!(!p.to_envelope().to_line().contains("CANARYV"));
    }

    #[test]
    fn meta_content_tolerated_including_unknown_nested_keys() {
        let p = parse_bytes(b"schema_version=1\nname=\"n\"\nrevision=1\n[meta]\nprivate_key=\"HEIMDALL_CANARY_m\"\n[meta.deep]\nx=1\n").unwrap();
        assert!(p.destinations.is_empty());
        assert!(!p.to_envelope().to_line().contains("HEIMDALL_CANARY_"));
    }

    #[test]
    fn invalid_utf8_is_schema_invalid() {
        let e = parse_bytes(b"schema_version=1\nname=\"\xff\"\n").unwrap_err();
        assert_eq!(e.code, Code::SchemaInvalid);
    }

    #[test]
    fn oversize_not_parsed_and_missing_is_usage() {
        let dir = std::env::temp_dir().join(format!("hp-rs-prof-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let big = dir.join("oversize ü.toml");
        // Not valid TOML at all: proves the size check happens before parsing.
        std::fs::write(&big, vec![b'['; (MAX_PROFILE_BYTES + 1) as usize]).unwrap();
        assert_eq!(load_file(&big).unwrap_err().code, Code::InputTooLarge);
        let exact = dir.join("exact.toml");
        let mut body = b"schema_version=1\nname=\"n\"\nrevision=1\n".to_vec();
        body.resize(MAX_PROFILE_BYTES as usize, b'\n');
        std::fs::write(&exact, &body).unwrap();
        assert!(load_file(&exact).is_ok(), "exactly 1 MiB is accepted");
        assert_eq!(
            load_file(&dir.join("missing.toml")).unwrap_err().code,
            Code::UsageError
        );
        assert_eq!(load_file(&dir).unwrap_err().code, Code::UsageError);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
