//! Local diagnostics (spec §13.6; R-SE-08). No telemetry leaves the machine
//! (spec P09). Logs go to stderr for foreground runs and to a bounded file under
//! `Paths::log_dir` for the service; a redaction layer is mandatory before M02
//! ships adapters (canary tests, A33).

use std::path::Path;

/// Log sink selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSink {
    /// Standard error (CLI, foreground service).
    Stderr,
    /// Rotating file in the log directory (detached service).
    File,
}

/// Install the global tracing subscriber once. Idempotent; a second call is a
/// no-op. Never prints ANSI escapes (NO_COLOR semantics, spec §12.2).
pub fn init(_sink: LogSink, _log_dir: Option<&Path>) -> std::io::Result<()> {
    todo!(
        "M01-T05: tracing_subscriber fmt without ansi, level from HEIMDALL_LOG, redaction layer hook"
    )
}

/// Redact a free-text diagnostic string before it is logged or returned. Replaces
/// anything that looks like a secret or canary and bounds length. Canary
/// detection is tested with injected fixtures (plan §6.2); it must not rely on a
/// list of token prefixes alone (spec §13.6).
#[must_use]
pub fn redact(_text: &str) -> String {
    todo!("M01-T06: structural redaction (base64/hex runs, key blocks, known markers) + length cap")
}
