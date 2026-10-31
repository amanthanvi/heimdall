//! Human-editable TOML configuration with a generated JSON Schema (spec P10,
//! §13.3 "separate configuration, ... runtime state, secrets, and logs").
//!
//! Unknown security-sensitive keys are rejected; ordinary unknown metadata is
//! tolerated under `[x]` (spec §13.4). Paths are resolved per platform through
//! `etcetera` (XDG on every Unix including macOS, so the include path matches spec
//! §10.1; Known Folders on Windows).

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Current configuration schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Resolved directories. Never a cloud-sync folder for the state database
/// (spec §13.3); setup refuses known sync roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// `config.toml` and the managed OpenSSH include live here.
    pub config_dir: PathBuf,
    /// State database, backups, instance lock.
    pub state_dir: PathBuf,
    /// Endpoints (sockets) and instance info; `XDG_RUNTIME_DIR` when available.
    pub runtime_dir: PathBuf,
    /// Logs (redacted, bounded).
    pub log_dir: PathBuf,
}

impl Paths {
    /// Discover platform defaults, honouring `HEIMDALL_HOME` for fixtures and tests.
    pub fn discover() -> Result<Self, ConfigError> {
        todo!("M01-T05: etcetera XDG/Windows strategies; HEIMDALL_HOME override")
    }
}

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
            x: None,
        }
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Parse failure.
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
        /// Value.
        value: String,
    },
    /// Platform directories unavailable.
    #[error("cannot determine platform directories")]
    NoHome,
    /// I/O.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl Config {
    /// Parse from TOML text (bounded by the caller to 1 MiB).
    pub fn parse(_text: &str) -> Result<Self, ConfigError> {
        todo!("M01-T05: toml::from_str, version check, duration validation")
    }

    /// Parsed `session.max_window`.
    pub fn max_window(&self) -> Result<Duration, ConfigError> {
        todo!("M01-T05")
    }

    /// JSON Schema for `config.toml` (`schemas/configuration/config.schema.json`).
    #[must_use]
    pub fn json_schema() -> schemars::Schema {
        schemars::schema_for!(Config)
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
}
