//! Human-editable TOML configuration with a generated JSON Schema (spec P10,
//! §13.3 "separate configuration, ... runtime state, secrets, and logs").
//!
//! Unknown security-sensitive keys are rejected; ordinary unknown metadata is
//! tolerated under `[x]` (spec §13.4). Paths are resolved per platform through
//! `etcetera` (XDG on every Unix including macOS, so the include path matches spec
//! §10.1; Known Folders on Windows).

use std::time::Duration;

use serde::{Deserialize, Serialize};

pub use crate::paths::Paths;

/// Current configuration schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Lock behaviour preference (spec §6.4 "Users can choose lock-revokes").
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LockBehavior {
    /// Approved work continues through desktop/vault lock until its deadline.
    #[default]
    Continue,
    /// Lock revokes active managed grants.
    Revoke,
}

/// Session defaults (spec P04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionConfig {
    /// Maximum window for new trusted work, as a duration string (`12h`).
    pub max_window: String,
    /// Lock behaviour.
    #[serde(default)]
    pub lock_behavior: LockBehavior,
    /// Strict disconnect at expiry (spec §6.6).
    #[serde(default)]
    pub strict_disconnect: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_window: "12h".to_owned(),
            lock_behavior: LockBehavior::Continue,
            strict_disconnect: false,
        }
    }
}

/// Retention (spec §13.6 draft defaults).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    /// Operation history and idempotency records (`7d`).
    pub operations: String,
    /// Event log (`7d`).
    pub events: String,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            operations: "7d".to_owned(),
            events: "7d".to_owned(),
        }
    }
}

/// Default of [`SetupConfig::declaration_validity_days`] (m02-plan §5 item 19; QR1).
pub const DEFAULT_DECLARATION_VALIDITY_DAYS: u32 = 30;

/// Accepted range of [`SetupConfig::declaration_validity_days`] (m02-plan §5 item 19).
pub const DECLARATION_VALIDITY_DAYS: std::ops::RangeInclusive<u32> = 1..=90;

fn default_declaration_validity_days() -> u32 {
    DEFAULT_DECLARATION_VALIDITY_DAYS
}

/// ⟨M02⟩ Existing-access setup (m02-plan §5 item 19; ADR-0007 §12.22 item 10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetupConfig {
    /// How many days an owner's approved interaction declaration stays in force
    /// (ADR-0007 §7, QR1): 1–90, default 30. It bounds the declaration the owner
    /// approves from then on; it never extends one already approved, and it grants
    /// nothing by itself (every declaration still needs the owner's attended
    /// decision).
    #[serde(default = "default_declaration_validity_days")]
    #[schemars(range(min = 1, max = 90))]
    pub declaration_validity_days: u32,
}

impl Default for SetupConfig {
    fn default() -> Self {
        Self {
            declaration_validity_days: DEFAULT_DECLARATION_VALIDITY_DAYS,
        }
    }
}

/// Top-level configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Schema version.
    pub schema_version: u32,
    /// Session defaults.
    #[serde(default)]
    pub session: SessionConfig,
    /// Retention.
    #[serde(default)]
    pub retention: RetentionConfig,
    /// ⟨M02⟩ Existing-access setup.
    #[serde(default)]
    pub setup: SetupConfig,
    /// Free-form, non-security metadata tolerated for forward compatibility
    /// (a TOML table, held as a generic JSON map so the schema can describe it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<serde_json::Map<String, serde_json::Value>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            session: SessionConfig::default(),
            retention: RetentionConfig::default(),
            setup: SetupConfig::default(),
            x: None,
        }
    }
}

/// Configuration errors. Messages never echo configuration values (a value may
/// be a secret pasted into the wrong place); key names are echoed only when they
/// come from Heimdall's own fixed vocabulary.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Parse failure (location and a fixed category; no input text).
    #[error("config parse error: {0}")]
    Parse(String),
    /// Unsupported schema version.
    #[error("config schema_version {0} is not supported")]
    UnsupportedVersion(u32),
    /// A duration string is invalid.
    #[error("invalid duration {field}: {value}")]
    Duration {
        /// Field.
        field: &'static str,
        /// The offending value, redacted and truncated.
        value: String,
    },
    /// ⟨M02⟩ A number outside its accepted range (the value itself is not echoed).
    #[error("{field} must be between {min} and {max}")]
    OutOfRange {
        /// Field.
        field: &'static str,
        /// Smallest accepted value.
        min: u32,
        /// Largest accepted value.
        max: u32,
    },
    /// A security-sensitive or authority-widening key appeared anywhere in the
    /// file, including under `[x]` (spec §13.4: "Unknown security-sensitive keys
    /// are rejected"). The key name is the matched entry of
    /// [`FORBIDDEN_KEYS`], never the input text.
    #[error("config key `{0}` is not allowed: authority is never granted by configuration")]
    ForbiddenKey(&'static str),
    /// Platform directories unavailable.
    #[error("cannot determine platform directories")]
    NoHome,
    /// I/O.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Largest `config.toml` accepted (bytes). Larger input is refused before parsing.
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// Longest duration string looked at (same bound as the deadline parser).
const MAX_DURATION_LEN: usize = 128;

/// Key names that are refused at any depth, including inside the free-form `[x]`
/// table (compared after ASCII lower-casing and mapping `-` to `_`). They name the
/// things spec §13.4 says configuration never carries: a trust flag, a private
/// key, a socket path, a script hook, a policy override, an issuing credential,
/// enrollment authority, or unattended consent. The typed schema already rejects
/// every unknown key outside `[x]` (`deny_unknown_fields`); this list closes the
/// `[x]` escape hatch for the security-relevant vocabulary so that no later reader
/// can be tempted to honour such a value.
pub const FORBIDDEN_KEYS: &[&str] = &[
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
];

/// Maximum nesting depth scanned under `[x]`; deeper input is refused.
const MAX_DEPTH: usize = 32;

impl Config {
    /// Parse from TOML text (bounded to [`MAX_CONFIG_BYTES`]).
    ///
    /// Order: size bound → TOML syntax → `schema_version` check (so a newer file
    /// reports its version, not an unknown key) → forbidden-key scan at every
    /// depth → typed decode with `deny_unknown_fields` → duration validation.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        if text.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Parse(format!(
                "config.toml exceeds {MAX_CONFIG_BYTES} bytes"
            )));
        }
        let table: toml::Table = toml::from_str(text).map_err(|e| parse_error(text, &e))?;
        match table.get("schema_version") {
            Some(toml::Value::Integer(v)) => {
                let v = u32::try_from(*v).unwrap_or(u32::MAX);
                if v != CONFIG_SCHEMA_VERSION {
                    return Err(ConfigError::UnsupportedVersion(v));
                }
            }
            Some(_) => {
                return Err(ConfigError::Parse(
                    "schema_version must be an integer".to_owned(),
                ));
            }
            None => {
                return Err(ConfigError::Parse(
                    "missing required key `schema_version`".to_owned(),
                ));
            }
        }
        scan_forbidden(&table, 0)?;
        let config: Config = toml::from_str(text).map_err(|e| parse_error(text, &e))?;
        config.validate()?;
        Ok(config)
    }

    /// Check every duration field (positive, bounded, exact units) and the
    /// retention floor of the idempotency contract (ADR-0006 §7.4: operation and
    /// idempotency records are kept at least 24 h).
    pub fn validate(&self) -> Result<(), ConfigError> {
        let window = self.max_window()?;
        if window.is_zero() {
            return Err(duration_error(
                "session.max_window",
                &self.session.max_window,
            ));
        }
        let ops = parse_duration("retention.operations", &self.retention.operations)?;
        if ops < heimdall_domain::idempotency::MIN_RETENTION {
            return Err(duration_error(
                "retention.operations",
                &self.retention.operations,
            ));
        }
        let events = parse_duration("retention.events", &self.retention.events)?;
        if events.is_zero() {
            return Err(duration_error("retention.events", &self.retention.events));
        }
        self.declaration_validity()?;
        Ok(())
    }

    /// ⟨M02⟩ `setup.declaration_validity_days` as a duration (whole days of 24 h),
    /// checked against [`DECLARATION_VALIDITY_DAYS`] (ADR-0007 §12.22 item 10).
    pub fn declaration_validity(&self) -> Result<Duration, ConfigError> {
        let days = self.setup.declaration_validity_days;
        if !DECLARATION_VALIDITY_DAYS.contains(&days) {
            return Err(ConfigError::OutOfRange {
                field: "setup.declaration_validity_days",
                min: *DECLARATION_VALIDITY_DAYS.start(),
                max: *DECLARATION_VALIDITY_DAYS.end(),
            });
        }
        Ok(Duration::from_secs(u64::from(days) * 24 * 60 * 60))
    }

    /// Parsed `session.max_window`.
    pub fn max_window(&self) -> Result<Duration, ConfigError> {
        parse_duration("session.max_window", &self.session.max_window)
    }

    /// Parsed `retention.operations`.
    pub fn retention_operations(&self) -> Result<Duration, ConfigError> {
        parse_duration("retention.operations", &self.retention.operations)
    }

    /// Parsed `retention.events`.
    pub fn retention_events(&self) -> Result<Duration, ConfigError> {
        parse_duration("retention.events", &self.retention.events)
    }

    /// JSON Schema for `config.toml` (`schemas/configuration/config.schema.json`).
    #[must_use]
    pub fn json_schema() -> schemars::Schema {
        schemars::schema_for!(Config)
    }

    /// The exported schema file text: pretty JSON plus a trailing newline, the
    /// same rendering `heimdall schema export` uses for `schemas/public-api/`.
    pub fn json_schema_text() -> Result<String, serde_json::Error> {
        let mut text = serde_json::to_string_pretty(&Self::json_schema())?;
        text.push('\n');
        Ok(text)
    }
}

/// Non-negative duration of exact units: ISO 8601 (`PT12H`, `P7D`) or friendly
/// (`12h`, `7d`, `1w 2d`). Days and weeks count as 24 h / 168 h (configuration is
/// a policy length, not a calendar instant); months and years are refused.
fn parse_duration(field: &'static str, value: &str) -> Result<Duration, ConfigError> {
    if value.len() > MAX_DURATION_LEN {
        return Err(duration_error(field, value));
    }
    let text = value.trim();
    let signed = match text.parse::<jiff::SignedDuration>() {
        Ok(d) => d,
        Err(_) => text
            .parse::<jiff::Span>()
            .ok()
            .and_then(|span| {
                span.to_duration(jiff::SpanRelativeTo::days_are_24_hours())
                    .ok()
            })
            .ok_or_else(|| duration_error(field, value))?,
    };
    if signed.is_negative() {
        return Err(duration_error(field, value));
    }
    Duration::try_from(signed).map_err(|_| duration_error(field, value))
}

fn duration_error(field: &'static str, value: &str) -> ConfigError {
    let mut shown = crate::telemetry::redact(value);
    if shown.chars().count() > 32 {
        shown = shown.chars().take(32).collect::<String>() + "…";
    }
    ConfigError::Duration {
        field,
        value: shown,
    }
}

fn normalized(key: &str) -> String {
    key.to_ascii_lowercase().replace('-', "_")
}

fn scan_forbidden(table: &toml::Table, depth: usize) -> Result<(), ConfigError> {
    if depth > MAX_DEPTH {
        return Err(ConfigError::Parse("config nesting is too deep".to_owned()));
    }
    for (key, value) in table {
        let k = normalized(key);
        if let Some(hit) = FORBIDDEN_KEYS.iter().find(|f| **f == k) {
            return Err(ConfigError::ForbiddenKey(hit));
        }
        scan_value(value, depth + 1)?;
    }
    Ok(())
}

fn scan_value(value: &toml::Value, depth: usize) -> Result<(), ConfigError> {
    if depth > MAX_DEPTH {
        return Err(ConfigError::Parse("config nesting is too deep".to_owned()));
    }
    match value {
        toml::Value::Table(t) => scan_forbidden(t, depth),
        toml::Value::Array(items) => items.iter().try_for_each(|v| scan_value(v, depth + 1)),
        _ => Ok(()),
    }
}

/// Turn a TOML error into a location and a fixed category. The TOML library's
/// own message is not used verbatim because it may quote the offending value.
fn parse_error(text: &str, e: &toml::de::Error) -> ConfigError {
    let location = e
        .span()
        .map(|span| {
            let start = span.start.min(text.len());
            let before = text.get(..start).unwrap_or("");
            let line = before.matches('\n').count() + 1;
            let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
            format!("line {line}, column {column}: ")
        })
        .unwrap_or_default();
    let message = e.message();
    let category = if let Some(name) = quoted_key(message, "unknown field `") {
        format!("unknown key `{name}`")
    } else if let Some(name) = quoted_key(message, "missing field `") {
        format!("missing required key `{name}`")
    } else if message.starts_with("unknown variant") {
        "unsupported value".to_owned()
    } else if message.starts_with("invalid type") {
        "value has the wrong type".to_owned()
    } else if message.starts_with("invalid value") {
        "invalid value".to_owned()
    } else if message.contains("duplicate key") {
        "duplicate key".to_owned()
    } else {
        "syntax error".to_owned()
    };
    ConfigError::Parse(format!("{location}{category}"))
}

/// A key name quoted by the TOML library, echoed only when it is a short plain
/// identifier and not secret-like after redaction.
fn quoted_key(message: &str, prefix: &str) -> Option<String> {
    let rest = message.strip_prefix(prefix)?;
    let name = rest.split('`').next()?;
    let plain = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if plain && crate::telemetry::redact(name) == name {
        Some(name.to_owned())
    } else {
        Some("<redacted>".to_owned())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn schema_generates() {
        let v = serde_json::to_value(Config::json_schema()).unwrap();
        assert!(v.is_object());
    }

    #[test]
    fn unknown_sensitive_keys_rejected_by_serde() {
        let r: Result<Config, _> = toml::from_str("schema_version = 1\ntrusted = true\n");
        assert!(r.is_err());
    }

    #[test]
    fn defaults_validate() {
        let c = Config::parse("schema_version = 1\n").unwrap();
        assert_eq!(c, Config::default());
        assert_eq!(c.max_window().unwrap(), Duration::from_secs(12 * 3600));
        assert_eq!(
            c.retention_operations().unwrap(),
            Duration::from_secs(7 * 24 * 3600)
        );
        assert_eq!(c.setup.declaration_validity_days, 30);
        assert_eq!(
            c.declaration_validity().unwrap(),
            Duration::from_secs(30 * 24 * 3600)
        );
    }

    /// ⟨M02⟩ ADR-0007 §12.22 item 10: `[setup] declaration_validity_days` is read,
    /// defaults to 30, accepts 1–90 and refuses anything else (without echoing the
    /// value) or any unknown key in the table.
    #[test]
    fn setup_declaration_validity_days_is_bounded() {
        let c = Config::parse("schema_version = 1\n[setup]\n").unwrap();
        assert_eq!(c.setup.declaration_validity_days, 30, "an empty table");
        for days in [1u32, 7, 90] {
            let c = Config::parse(&format!(
                "schema_version = 1\n[setup]\ndeclaration_validity_days = {days}\n"
            ))
            .unwrap();
            assert_eq!(
                c.declaration_validity().unwrap(),
                Duration::from_secs(u64::from(days) * 24 * 3600)
            );
        }
        for days in ["0", "91", "4294967295"] {
            let e = Config::parse(&format!(
                "schema_version = 1\n[setup]\ndeclaration_validity_days = {days}\n"
            ))
            .unwrap_err();
            assert!(
                matches!(
                    e,
                    ConfigError::OutOfRange {
                        field: "setup.declaration_validity_days",
                        min: 1,
                        max: 90
                    }
                ),
                "{days}: {e}"
            );
            // Fixed text: the value itself is never echoed.
            assert_eq!(
                e.to_string(),
                "setup.declaration_validity_days must be between 1 and 90"
            );
        }
        for bad in [
            "declaration_validity_days = -1",
            "declaration_validity_days = \"30\"",
            "declaration_validity_days = 4294967296",
            "unknown_key = 1",
        ] {
            assert!(
                matches!(
                    Config::parse(&format!("schema_version = 1\n[setup]\n{bad}\n")),
                    Err(ConfigError::Parse(_))
                ),
                "{bad}"
            );
        }
        // A struct built in code is validated the same way.
        let mut c = Config::default();
        c.setup.declaration_validity_days = 0;
        assert!(c.validate().is_err());
        let schema = serde_json::to_value(Config::json_schema()).unwrap();
        let text = schema.to_string();
        assert!(text.contains("declaration_validity_days"), "{text}");
    }
}
