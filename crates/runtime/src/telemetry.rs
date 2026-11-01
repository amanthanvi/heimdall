//! Local diagnostics (spec §13.6; R-SE-08). No telemetry leaves the machine
//! (spec P09). Logs go to stderr for foreground runs and to a bounded file under
//! `Paths::log_dir` for the service; every formatted log line passes through
//! [`redact`] before it reaches the sink (canary tests, A33).
//!
//! **Redaction is structural** (spec §13.6 "must not rely solely on a list of known
//! token prefixes"). [`redact`] applies, in order:
//!
//! 1. armored key material: any `-----BEGIN …-----` block through the matching
//!    `-----END …-----` line (or to the end of the text when unterminated) and a
//!    PuTTY key file body (`PuTTY-User-Key-File-…` to the end);
//! 2. home directories: the current user's home path (exact) and the structural
//!    forms `/Users/<name>`, `/home/<name>`, `/root`, `C:\Users\<name>`, replaced by
//!    `~` (before rule 3, so a home path is shortened rather than swallowed);
//! 3. canary-format tokens (`HEIMDALL_CANARY_…`, ADR-0004 §4) and key-like runs: a
//!    maximal run of base64/base64url/hex characters of at least
//!    [`SECRET_RUN_MIN`] characters that is pure hex of at least 32, or is not made
//!    of word-like segments and mixes character classes (see `secret_like`).
//!    Heimdall's own `<prefix>_<32 hex>` identifiers are random but public handles
//!    and are kept. Inside a path only the offending segments are replaced;
//!
//! then bounds the result to [`MAX_REDACTED_LEN`] bytes.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Log sink selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSink {
    /// Standard error (CLI, foreground service).
    Stderr,
    /// Rotating file in the log directory (detached service).
    File,
}

/// Environment variable selecting the level (`off`, `error`, `warn`, `info`,
/// `debug`, `trace`). Default: `warn` on stderr, `info` in the file.
pub const LOG_ENV: &str = "HEIMDALL_LOG";

/// Log file name inside the log directory; the previous generation is
/// `heimdall.log.1`.
pub const LOG_FILE: &str = "heimdall.log";

/// Size at which the log file rotates (one previous generation is kept, so disk
/// use is bounded by twice this).
pub const LOG_FILE_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Longest redacted output (bytes); longer text is cut at a character boundary
/// and marked.
pub const MAX_REDACTED_LEN: usize = 4096;

/// Shortest character run treated as possible key material.
pub const SECRET_RUN_MIN: usize = 24;

/// Canary marker (ADR-0004 §4; `heimdall_testkit::CANARY_PREFIX`).
const CANARY_MARKER: &str = "HEIMDALL_CANARY_";

const REDACTED: &str = "[REDACTED]";
const REDACTED_KEY: &str = "[REDACTED KEY MATERIAL]";
const TRUNCATED: &str = "…[truncated]";

/// Prefixes of Heimdall's runtime identifiers (`heimdall_contract::ids`), which
/// are kept by [`redact`] when followed by exactly 32 lowercase hex digits.
const ID_PREFIXES: &[&str] = &[
    "op", "grant", "binding", "env", "dev", "ws", "res", "evt", "dec", "iss", "cred",
];

static INSTALLED: OnceLock<()> = OnceLock::new();

/// Install the global tracing subscriber once. Idempotent; a second call is a
/// no-op. Never prints ANSI escapes (NO_COLOR semantics, spec §12.2). Every line
/// is redacted before it is written.
pub fn init(sink: LogSink, log_dir: Option<&Path>) -> std::io::Result<()> {
    if INSTALLED.get().is_some() {
        return Ok(());
    }
    let level = level_from_env(sink);
    let result = match sink {
        LogSink::Stderr => install(level, RedactingMakeWriter::stderr()),
        LogSink::File => {
            let dir = log_dir.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "the file log sink needs a log directory",
                )
            })?;
            let file = BoundedFile::open(dir)?;
            install(level, RedactingMakeWriter::file(file))
        }
    };
    // Another subscriber (ours from a racing call, or a host's) already owns the
    // global slot: init is a no-op in that case.
    let _ = result;
    let _ = INSTALLED.set(());
    Ok(())
}

fn install(
    level: tracing_subscriber::filter::LevelFilter,
    writer: RedactingMakeWriter,
) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(level)
        .with_target(true)
        .with_writer(writer)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
}

fn level_from_env(sink: LogSink) -> tracing_subscriber::filter::LevelFilter {
    use tracing_subscriber::filter::LevelFilter;
    let default = match sink {
        LogSink::Stderr => LevelFilter::WARN,
        LogSink::File => LevelFilter::INFO,
    };
    std::env::var(LOG_ENV)
        .ok()
        .and_then(|v| parse_level(&v))
        .unwrap_or(default)
}

/// Parse a `HEIMDALL_LOG` value; `None` when unrecognised (the default applies).
#[must_use]
pub fn parse_level(value: &str) -> Option<tracing_subscriber::filter::LevelFilter> {
    use tracing_subscriber::filter::LevelFilter;
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::OFF),
        "error" => Some(LevelFilter::ERROR),
        "warn" | "warning" => Some(LevelFilter::WARN),
        "info" => Some(LevelFilter::INFO),
        "debug" => Some(LevelFilter::DEBUG),
        "trace" => Some(LevelFilter::TRACE),
        _ => None,
    }
}

/// Size-bounded log file with one previous generation, created owner-only.
#[derive(Debug)]
struct BoundedFile {
    dir: PathBuf,
    file: std::fs::File,
    len: u64,
}

impl BoundedFile {
    fn open(dir: &Path) -> std::io::Result<Self> {
        let file = open_log(&dir.join(LOG_FILE))?;
        let len = file.metadata()?.len();
        Ok(Self {
            dir: dir.to_path_buf(),
            file,
            len,
        })
    }

    fn write_line(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if self.len.saturating_add(bytes.len() as u64) > LOG_FILE_MAX_BYTES && self.len > 0 {
            let current = self.dir.join(LOG_FILE);
            let previous = self.dir.join(format!("{LOG_FILE}.1"));
            std::fs::rename(&current, &previous)?;
            self.file = open_log(&current)?;
            self.len = 0;
        }
        self.file.write_all(bytes)?;
        self.len = self.len.saturating_add(bytes.len() as u64);
        Ok(())
    }
}

fn open_log(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

#[derive(Clone)]
enum Target {
    Stderr,
    File(Arc<Mutex<BoundedFile>>),
}

/// `MakeWriter` whose writers buffer one formatted event and emit it redacted.
#[derive(Clone)]
struct RedactingMakeWriter {
    target: Target,
}

impl RedactingMakeWriter {
    fn stderr() -> Self {
        Self {
            target: Target::Stderr,
        }
    }

    fn file(file: BoundedFile) -> Self {
        Self {
            target: Target::File(Arc::new(Mutex::new(file))),
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RedactingMakeWriter {
    type Writer = RedactingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            target: self.target.clone(),
            buf: Vec::new(),
            truncated: false,
        }
    }
}

/// Buffers everything written for one event; on flush/drop redacts the whole
/// event (so a multi-line key block is recognised as one block) and writes it.
struct RedactingWriter {
    target: Target,
    buf: Vec<u8>,
    truncated: bool,
}

/// Per-event buffer bound (bytes).
const MAX_EVENT_BYTES: usize = 4 * MAX_REDACTED_LEN;

impl RedactingWriter {
    fn emit(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let mut text = String::from_utf8_lossy(&self.buf).into_owned();
        self.buf.clear();
        if std::mem::take(&mut self.truncated) {
            // Never emit the cut-off tail of a token: it may be part of a secret
            // too short on its own to be recognised.
            let keep = text.rfind(char::is_whitespace).unwrap_or(0);
            text.truncate(keep);
            text.push_str(TRUNCATED);
        }
        let mut out = redact(text.trim_end_matches('\n'));
        out.push('\n');
        match &self.target {
            Target::Stderr => std::io::stderr().lock().write_all(out.as_bytes()),
            Target::File(file) => file
                .lock()
                .map_err(|_| std::io::Error::other("log file lock poisoned"))?
                .write_line(out.as_bytes()),
        }
    }
}

impl Write for RedactingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        // Bound the per-event buffer; redaction caps the output anyway.
        let room = MAX_EVENT_BYTES.saturating_sub(self.buf.len());
        if bytes.len() > room {
            self.truncated = true;
        }
        self.buf
            .extend_from_slice(bytes.get(..bytes.len().min(room)).unwrap_or(&[]));
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.emit()
    }
}

impl Drop for RedactingWriter {
    fn drop(&mut self) {
        let _ = self.emit();
    }
}

/// Redact a free-text diagnostic string before it is logged or returned. Replaces
/// anything that looks like a secret or canary and bounds length. Canary
/// detection is tested with injected fixtures (plan §6.2); it does not rely on a
/// list of token prefixes alone (spec §13.6; module docs).
#[must_use]
pub fn redact(text: &str) -> String {
    let home = home_dir_string();
    redact_with_home(text, home.as_deref())
}

/// [`redact`] with an explicit home directory (tests; `None` = structural rules
/// only).
#[doc(hidden)]
#[must_use]
pub fn redact_with_home(text: &str, home: Option<&str>) -> String {
    let text = redact_key_blocks(text);
    let text = redact_homes(&text, home);
    let text = redact_tokens(&text);
    truncate(text)
}

fn home_dir_string() -> Option<String> {
    static HOME: OnceLock<Option<String>> = OnceLock::new();
    HOME.get_or_init(|| {
        etcetera::home_dir()
            .ok()
            .and_then(|p| p.to_str().map(str::to_owned))
            .filter(|h| h.len() > 1)
    })
    .clone()
}

/// Rule 1: armored key blocks and PuTTY key files.
fn redact_key_blocks(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let begin = rest.find("-----BEGIN ");
        let putty = rest.find("PuTTY-User-Key-File-");
        let next = match (begin, putty) {
            (Some(a), Some(b)) => Some((a.min(b), a <= b)),
            (Some(a), None) => Some((a, true)),
            (None, Some(b)) => Some((b, false)),
            (None, None) => None,
        };
        let Some((at, armored)) = next else {
            out.push_str(rest);
            return out;
        };
        out.push_str(rest.get(..at).unwrap_or(""));
        out.push_str(REDACTED_KEY);
        let tail = rest.get(at..).unwrap_or("");
        if !armored {
            return out;
        }
        // Skip to the end of the matching END line, or to the end of the text.
        match tail.find("-----END ") {
            Some(end) => {
                let after_end = tail.get(end + "-----END ".len()..).unwrap_or("");
                let close = after_end.find("-----").map_or(after_end.len(), |c| c + 5);
                rest = after_end.get(close..).unwrap_or("");
            }
            None => return out,
        }
    }
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-')
}

/// Rules 2 and 3: canary tokens and key-like runs.
fn redact_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run_start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        if is_token_char(c) {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else {
            if let Some(start) = run_start.take() {
                push_run(&mut out, text.get(start..i).unwrap_or(""));
            }
            out.push(c);
        }
    }
    if let Some(start) = run_start {
        push_run(&mut out, text.get(start..).unwrap_or(""));
    }
    out
}

fn push_run(out: &mut String, run: &str) {
    let bad = |seg: &str| seg.contains(CANARY_MARKER) || secret_like(seg);
    if !bad(run) {
        out.push_str(run);
        return;
    }
    // The run must go. When it is a path made of ordinary words plus offending
    // segments, redact only those segments; otherwise (standard base64 contains
    // '/') redact the whole run, so no piece of a secret survives.
    let segments: Vec<&str> = run.split('/').collect();
    let path_like = segments.len() > 1
        && segments.iter().any(|s| bad(s))
        && segments.iter().all(|s| bad(s) || wordy(s));
    if path_like {
        let parts: Vec<&str> = segments
            .iter()
            .map(|seg| if bad(seg) { REDACTED } else { *seg })
            .collect();
        out.push_str(&parts.join("/"));
    } else {
        out.push_str(REDACTED);
    }
}

/// Heimdall runtime identifier `<prefix>_<32 lowercase hex>`.
fn is_heimdall_id(run: &str) -> bool {
    run.split_once('_').is_some_and(|(prefix, hex)| {
        ID_PREFIXES.contains(&prefix)
            && hex.len() == 32
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Every piece between separators (`_ - / + = .`) is [`word_like`].
fn wordy(text: &str) -> bool {
    text.split(['_', '-', '/', '+', '=', '.']).all(word_like)
}

/// A piece that reads as a word: at most three characters, or letters shaped
/// `word`, `WORD` or `CamelCase` (every capital followed by at least two lower-case
/// letters, no two capitals in a row) followed by at most four digits. Random
/// key material almost never has this shape.
fn word_like(piece: &str) -> bool {
    if piece.len() <= 3 {
        return true;
    }
    let letters_end = piece
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(piece.len());
    let (letters, digits) = piece.split_at(letters_end);
    if digits.len() > 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let bytes = letters.as_bytes();
    if bytes.iter().all(u8::is_ascii_uppercase) {
        return true;
    }
    // Lower case, Capitalised or CamelCase: each capital (after the first
    // character) is followed by at least two lower-case letters.
    bytes.iter().enumerate().all(|(i, b)| {
        !b.is_ascii_uppercase()
            || bytes
                .get(i + 1..i + 3)
                .is_some_and(|next| next.iter().all(u8::is_ascii_lowercase))
    })
}

/// Rule 3. A run is key-like when it is at least [`SECRET_RUN_MIN`] characters
/// and either pure hex of at least 32, or not [`wordy`] and mixing at least two of
/// {upper, lower, digit, `+`/`=`}. Identifiers, snake/kebab/camel case and
/// ordinary paths are kept; the rule needs no list of token prefixes.
fn secret_like(run: &str) -> bool {
    if run.len() < SECRET_RUN_MIN || is_heimdall_id(run) {
        return false;
    }
    let core = run.trim_end_matches('=');
    if core.len() >= 32 && core.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }
    if wordy(core) {
        return false;
    }
    let (mut upper, mut lower, mut digit, mut sym) = (false, false, false, false);
    for b in core.bytes() {
        match b {
            b'A'..=b'Z' => upper = true,
            b'a'..=b'z' => lower = true,
            b'0'..=b'9' => digit = true,
            b'+' | b'=' => sym = true,
            _ => {}
        }
    }
    [upper, lower, digit, sym].iter().filter(|x| **x).count() >= 2
}

/// Rule 4: home directories.
fn redact_homes(text: &str, home: Option<&str>) -> String {
    let mut s = match home {
        Some(h) if h.len() > 1 => text.replace(h, "~"),
        _ => text.to_owned(),
    };
    for marker in ["/Users/", "/home/", "\\Users\\", "/users/", "\\users\\"] {
        s = replace_home_marker(&s, marker);
    }
    // `/root` as a whole path component.
    s = replace_component(&s, "/root");
    s
}

/// Replace `<anything up to marker><name>` (where `<name>` is the next path
/// component) by `~`. For Windows markers the drive letter before the marker is
/// consumed too.
fn replace_home_marker(text: &str, marker: &str) -> String {
    let sep = if marker.starts_with('\\') { '\\' } else { '/' };
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(marker) {
        let mut head = rest.get(..at).unwrap_or("");
        if sep == '\\' {
            // Drop a preceding drive spec such as `C:`.
            let bytes = head.as_bytes();
            if bytes.len() >= 2
                && bytes[bytes.len() - 1] == b':'
                && bytes[bytes.len() - 2].is_ascii_alphabetic()
            {
                head = head.get(..head.len() - 2).unwrap_or("");
            }
        }
        out.push_str(head);
        let after = rest.get(at + marker.len()..).unwrap_or("");
        let name_len = after
            .find(|c: char| c == sep || c.is_whitespace() || matches!(c, '"' | '\'' | ':' | ','))
            .unwrap_or(after.len());
        if name_len == 0 {
            out.push_str(marker);
            rest = after;
            continue;
        }
        out.push('~');
        rest = after.get(name_len..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

fn replace_component(text: &str, component: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(component) {
        let before_ok = at == 0
            || rest
                .get(..at)
                .and_then(|h| h.chars().last())
                .is_some_and(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '.');
        let after = rest.get(at + component.len()..).unwrap_or("");
        let after_ok = after
            .chars()
            .next()
            .is_none_or(|c| c == '/' || c.is_whitespace() || matches!(c, '"' | '\'' | ':' | ','));
        out.push_str(rest.get(..at).unwrap_or(""));
        if before_ok && after_ok {
            out.push('~');
        } else {
            out.push_str(component);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

fn truncate(mut text: String) -> String {
    if text.len() <= MAX_REDACTED_LEN {
        return text;
    }
    let mut cut = MAX_REDACTED_LEN - TRUNCATED.len();
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text.push_str(TRUNCATED);
    text
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_words_survive() {
        let id = format!("op_{}", "0123456789abcdef".repeat(2));
        assert_eq!(redact_with_home(&id, None), id);
        let word = "heimdall_runtime_supervisor_scheduler_pass";
        assert_eq!(redact_with_home(word, None), word);
    }

    #[test]
    fn levels_parse() {
        assert_eq!(
            parse_level("Debug"),
            Some(tracing_subscriber::filter::LevelFilter::DEBUG)
        );
        assert_eq!(parse_level("loud"), None);
    }
}
