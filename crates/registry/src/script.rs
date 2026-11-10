//! The remote scripts `inspect`, `bootstrap`, `append`, `remove` and `fence`
//! (ADR-0008 D5 §6.3; m03-plan U5 `registry::script`, §5 item 21). Pure: the scripts
//! are rendered from validated parameters, and nothing here runs them.
//!
//! **Hardening** (§17.4 item 2): every script is one function, `hm_main`, called on
//! its **last** line, so a stream cut anywhere before that line runs nothing (an
//! incomplete definition is a syntax error; a complete one is never called). Its
//! first statement is `export LC_ALL=C` and its second `umask 077`. Every value is a
//! validated literal inside single quotes: the parameter types below admit no `'`,
//! no newline and no byte outside their documented sets, so rendering is infallible.
//!
//! **Output** is the frozen HM1 grammar of [`crate::hm1`]: the first line the script
//! prints is [`crate::hm1::VERSION_LINE`], then `HM1 <key>=<value>` lines, the last of
//! which is `status` (and `reason` for a refusal), then the exit code of
//! [`crate::hm1::ExitCode`]. In `append` and `remove`, the `file`, `links`, `mode`,
//! `owner_self` and `size` lines describe the registry **before** the write;
//! `last_byte_newline`, `marker_lines` and `content_hex` describe it **after** (or as
//! it is, for exit 10). `inspect` reports everything it can read and exits 30 with the
//! first refusal reason when the registry is not manageable, so a registry Heimdall
//! cannot rewrite can still be checked for absence. `fence` prints one round of
//! `pgid`, `boot_identity`, `group_control`, `group_probe`, `group_listed`,
//! `start_identity` and `fence` per decision, in order, and `fence_signals` last.
//!
//! **Fencing** is ADR-0008 D5 §6.3's holder-recording lock: `ln -s
//! hm1-<token>-<pid>-<start hex>-<boot hex>-<not_after> <dir>/.hm-lock.<name>`, taken
//! only after the process-group check (Linux: token 3 after the last `)` of
//! `/proc/$$/stat`, through [`PROCSTAT_AWK`]; macOS and the BSDs: `ps -o pgid= -p $$`;
//! Q29), the directory check (32) and the not-after check (41); re-checked
//! immediately before the write (42, 41); released by its owning contents only.
//! `fence` decides `gone`, `alive` or `unproven` from the control `kill -s 0 -- -$$`,
//! the probe `kill -s 0 -- -PID` and the listing `ps -A -o pgid=`, which must agree
//! (§17.7 item 1); exit 44 is no unlock and no further signal, and the signals
//! already sent are reported in `fence_signals` (§17.10 item 4).
//!
//! **The boot identity** (ADR-0008 §17.17 item 2): Linux `/proc/sys/kernel/random/
//! boot_id`; macOS `sysctl -n kern.bootsessionuuid`, which does not move when the
//! wall clock is stepped; the BSDs `sysctl -n kern.boottime` (up to its first `}`), a
//! **timestamp** that the kernel shifts with a clock step. A boot-identity difference
//! proves `gone` on its own only where the identity is stable (Linux, macOS); on a
//! timestamp row the group proof is still required.
//!
//! **The remote clock** (`remote_now`) is read with POSIX `date -u '+%Y %m %d %H %M
//! %S'` and converted to epoch seconds in `awk` ([`REMOTE_CLOCK_COMMAND`]), not with
//! `awk 'BEGIN { srand(); print srand() }'`: Debian 13's default `awk` (mawk 1.3.4
//! 20250131) returns the time in **nanoseconds** there (observed `1794305972306619648`
//! beside `date +%s` `1794305972`), so M-F23's reading does not hold on the primary
//! target. Ruled in ADR-0008 §17.17 item 7 (U5S-Q1, M-F23 revised); the command is
//! [`REMOTE_CLOCK_COMMAND`].
//!
//! **Test configuration.** Release builds contain only the release form, which has
//! no pause point. Debug builds (`cfg(debug_assertions)`, the same gate as
//! `heimdall/src/testcfg.rs`) also contain [`test_form`], which inserts `HM_PAUSE
//! <name>` lines (ADR-0008 D13 item 3) into a release script's text, so the CLI that
//! read `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` can pause the script it received.
//!
//! The goldens live in `tests/contracts/golden/enroll-scripts/`
//! (`release_scripts_match_golden_and_have_no_pause_points`).

use std::fmt::{self, Write as _};

use heimdall_contract::enrollment::RemoteStage;

use crate::hm1::MAX_CONTENT_BYTES;

/// The shared `/proc/<pid>/stat` parser's `awk` program (ADR-0008 D5 §6.3, §17.13
/// item 2): the whole file, the **last** `)`, then token 3 (the process group) and
/// token 20 (the start time) of the suffix, validated; it prints `<pgid> <start>` or
/// exits 2. `heimdall_domain::procstat::parse` is its Rust twin. The scripts run it
/// as `awk '<this>' "/proc/$P/stat"`.
pub const PROCSTAT_AWK: &str = r#"{ b = b $0 "\n" } END { i = length(b); while (i > 0 && substr(b, i, 1) != ")") i--;
        if (i == 0) exit 2; n = split(substr(b, i + 1), f, " ");
        if (n < 20 || f[1] !~ /^[A-Za-z]$/ || f[3] !~ /^[0-9]+$/ || f[3] + 0 < 1 ||
            f[20] !~ /^[0-9]+$/) exit 2; print f[3], f[20] }"#;

/// How the scripts read the remote clock as epoch seconds (U5S-Q1; module docs): POSIX
/// `date -u` with POSIX conversions, converted to days since the epoch in `awk`
/// (the civil-from-days rule; 1970-01-01 is day 0). It prints the seconds or nothing.
pub const REMOTE_CLOCK_COMMAND: &str = r#"date -u '+%Y %m %d %H %M %S' 2>/dev/null | awk 'NF == 6 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ && $5 ~ /^[0-9]+$/ && $6 ~ /^[0-9]+$/ { y = $1 + 0; m = $2 + 0; if (m <= 2) { y = y - 1; m = m + 12 }; e = int(y / 400); a = y - e * 400; d = a * 365 + int(a / 4) - int(a / 100) + int((153 * (m - 3) + 2) / 5) + $3 - 1; printf "%d\n", (e * 146097 + d - 719468) * 86400 + $4 * 3600 + $5 * 60 + $6 }'"#;

/// The largest payload `remove` carries (each of the preimage and the post-image):
/// the registry bound of [`crate::hm1::MAX_CONTENT_BYTES`].
pub const MAX_PAYLOAD_BYTES: usize = MAX_CONTENT_BYTES;

/// The longest explicit registry path (ADR-0008 D5 §6.1).
pub const MAX_REGISTRY_PATH_BYTES: usize = 255;

/// The longest registry line a script carries.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// The longest marker.
pub const MAX_MARKER_BYTES: usize = 256;

/// Why a script parameter was refused (nothing is rendered from it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum ScriptError {
    /// The registry path is not absolute POSIX, ≤ 255 bytes, from `[A-Za-z0-9._/-]`,
    /// with no empty, `.` or `..` component and a file name last (ADR-0008 D5 §6.1).
    #[error("the registry path is not a valid absolute POSIX path")]
    RegistryPath,
    /// The marker is not `heimdall:` followed by `[A-Za-z0-9._:-]`.
    #[error("the marker is malformed")]
    Marker,
    /// The line is empty, too long, outside the line character set, or does not
    /// contain the marker.
    #[error("the registry line is malformed")]
    Line,
    /// The step token is not 32 lowercase hex digits.
    #[error("the step token is malformed")]
    Token,
    /// The not-after is negative.
    #[error("the not-after is negative")]
    NotAfter,
    /// A `remove` payload exceeds [`MAX_PAYLOAD_BYTES`].
    #[error("a remove payload exceeds the registry bound")]
    Payload,
    /// (Test form) the pause directory is not an absolute path from
    /// `[A-Za-z0-9._/-]` of at most 1024 bytes.
    #[error("the pause directory is not a valid absolute path")]
    PauseDir,
    /// (Test form) the text is not a release script rendered by this module.
    #[error("the text is not a release script of this module")]
    NotAReleaseScript,
}

fn is_hex_lower(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `path` is absolute, from `[A-Za-z0-9._/-]`, at most `max` bytes, with
/// every component non-empty and neither `.` nor `..` (so no `//` and no trailing
/// `/`).
fn is_plain_absolute_path(path: &str, max: usize) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    path.len() <= max
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
        && rest
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

/// A validated explicit registry path (ADR-0008 D5 §6.1: absolute POSIX, ≤ 255
/// bytes, `[A-Za-z0-9._/-]`, no `..` component; also no empty or `.` component, so
/// the script's directory and file name are exact).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegistryPath(String);

impl RegistryPath {
    /// Validate `path`.
    ///
    /// # Errors
    /// [`ScriptError::RegistryPath`].
    pub fn parse(path: &str) -> Result<RegistryPath, ScriptError> {
        if is_plain_absolute_path(path, MAX_REGISTRY_PATH_BYTES) {
            Ok(RegistryPath(path.to_owned()))
        } else {
            Err(ScriptError::RegistryPath)
        }
    }

    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where the registry is: the remote `$HOME/.ssh/authorized_keys` (resolved by the
/// remote shell; a `HOME` that is unset or not absolute refuses with 30) or an
/// explicit path (`--registry-path`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegistryLocation {
    /// `$HOME/.ssh/authorized_keys` on the remote.
    RemoteHome,
    /// The explicit path.
    Explicit(RegistryPath),
}

impl RegistryLocation {
    /// From the plan's optional path (`None` is [`RegistryLocation::RemoteHome`]).
    ///
    /// # Errors
    /// [`ScriptError::RegistryPath`].
    pub fn from_plan(path: Option<&str>) -> Result<RegistryLocation, ScriptError> {
        match path {
            None => Ok(RegistryLocation::RemoteHome),
            Some(p) => RegistryPath::parse(p).map(RegistryLocation::Explicit),
        }
    }

    /// The script literal: the path, or empty for the remote home.
    fn literal(&self) -> &str {
        match self {
            RegistryLocation::RemoteHome => "",
            RegistryLocation::Explicit(p) => p.as_str(),
        }
    }
}

/// A validated marker, `heimdall:<enrollment-id>` (`[A-Za-z0-9._:-]`, at most
/// [`MAX_MARKER_BYTES`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Marker(String);

impl Marker {
    /// Validate `marker`.
    ///
    /// # Errors
    /// [`ScriptError::Marker`].
    pub fn parse(marker: &str) -> Result<Marker, ScriptError> {
        let ok = marker
            .strip_prefix("heimdall:")
            .is_some_and(|id| !id.is_empty())
            && marker.len() <= MAX_MARKER_BYTES
            && marker
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
        if ok {
            Ok(Marker(marker.to_owned()))
        } else {
            Err(ScriptError::Marker)
        }
    }

    /// The marker.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated registry line: non-empty, at most [`MAX_LINE_BYTES`], every byte in
/// [`crate::line::LINE_CHARSET`] (no `'`, no newline), and containing its marker, so
/// the `append` script's idempotency check (exit 10) sees it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegistryLine(String);

impl RegistryLine {
    /// Validate `line` for `marker`.
    ///
    /// # Errors
    /// [`ScriptError::Line`].
    pub fn parse(line: &str, marker: &Marker) -> Result<RegistryLine, ScriptError> {
        let charset = crate::line::LINE_CHARSET.as_bytes();
        let ok = !line.is_empty()
            && line.len() <= MAX_LINE_BYTES
            && line.bytes().all(|b| charset.contains(&b))
            && line.contains(marker.as_str());
        if ok {
            Ok(RegistryLine(line.to_owned()))
        } else {
            Err(ScriptError::Line)
        }
    }

    /// The line (without its newline).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated step token: 32 lowercase hex digits (128 random bits; ADR-0008 D5
/// §6.3 item 1). It also names `remove`'s temporary files.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StepToken(String);

impl StepToken {
    /// Validate `token`.
    ///
    /// # Errors
    /// [`ScriptError::Token`].
    pub fn parse(token: &str) -> Result<StepToken, ScriptError> {
        if token.len() == 32 && is_hex_lower(token) {
            Ok(StepToken(token.to_owned()))
        } else {
            Err(ScriptError::Token)
        }
    }

    /// The token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A step's remote not-after, in remote epoch seconds (`RemoteStep.not_after_remote`;
/// ADR-0008 D5 §6.3). A script refuses with 41 once the remote clock reads **at or
/// after** it, so a write happens only strictly before it, and an `inspect` reading
/// past it shows every write that can still happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NotAfter(i64);

impl NotAfter {
    /// Validate `seconds` (≥ 0).
    ///
    /// # Errors
    /// [`ScriptError::NotAfter`].
    pub fn new(seconds: i64) -> Result<NotAfter, ScriptError> {
        if seconds >= 0 {
            Ok(NotAfter(seconds))
        } else {
            Err(ScriptError::NotAfter)
        }
    }

    /// The seconds.
    #[must_use]
    pub fn seconds(self) -> i64 {
        self.0
    }
}

/// A `remove` payload (the expected preimage or the post-image): any bytes, at most
/// [`MAX_PAYLOAD_BYTES`]. A NUL byte is refused by the script itself (exit 30,
/// `decode_failed`), because registries are text (ADR-0008 D5 §6.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Payload(Vec<u8>);

impl Payload {
    /// Validate `bytes`.
    ///
    /// # Errors
    /// [`ScriptError::Payload`].
    pub fn new(bytes: &[u8]) -> Result<Payload, ScriptError> {
        if bytes.len() <= MAX_PAYLOAD_BYTES {
            Ok(Payload(bytes.to_vec()))
        } else {
            Err(ScriptError::Payload)
        }
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// `inspect`'s parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectParams {
    /// The registry.
    pub registry: RegistryLocation,
    /// The marker whose lines are counted.
    pub marker: Marker,
}

/// `bootstrap`'s parameters (ADR-0008 D5 §6.3: one `mkdir -m 0700`, no lock).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapParams {
    /// The registry whose directory is created.
    pub registry: RegistryLocation,
}

/// `append`'s parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendParams {
    /// The registry.
    pub registry: RegistryLocation,
    /// The marker (the idempotency key: exit 10 when any line contains it).
    pub marker: Marker,
    /// The exact line.
    pub line: RegistryLine,
    /// The step token (in the holder record).
    pub token: StepToken,
    /// The remote not-after (in the holder record; checked before the lock and
    /// before the write).
    pub not_after_remote: NotAfter,
}

/// `remove`'s parameters (compare-then-rename, ADR-0008 D5 §6.3, §6.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveParams {
    /// The registry.
    pub registry: RegistryLocation,
    /// The marker.
    pub marker: Marker,
    /// The step token (in the holder record and the temporary file names).
    pub token: StepToken,
    /// The remote not-after.
    pub not_after_remote: NotAfter,
    /// The inspected preimage the registry must still equal (`cmp`, else exit 20).
    pub preimage: Payload,
    /// The post-image renamed over the registry.
    pub post_image: Payload,
}

/// `fence`'s parameters (ADR-0008 D5 §6.3, §6.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceParams {
    /// The registry whose lock is fenced.
    pub registry: RegistryLocation,
    /// The token of the uncertain step whose lock this is. A lock carrying any other
    /// token, or a malformed record, is `busy` (exit 40) and is never touched.
    pub token: StepToken,
    /// `--terminate`: an `alive` holder whose recorded not-after has passed on the
    /// remote clock is sent TERM, then KILL, to its exact process group.
    pub terminate: bool,
}

/// A rendered remote script: written to ssh's stdin after `HM1 ready`.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteScript {
    stage: RemoteStage,
    text: String,
}

impl RemoteScript {
    /// The stage.
    #[must_use]
    pub fn stage(&self) -> RemoteStage {
        self.stage
    }

    /// The script text (ASCII, LF line ends, ends with `hm_main\n`).
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The script text, owned (for `RemoteStep.script`).
    #[must_use]
    pub fn into_text(self) -> String {
        self.text
    }
}

impl fmt::Debug for RemoteScript {
    // The text carries no secret, but it can be large (a remove payload): show the
    // stage and the size only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteScript")
            .field("stage", &self.stage)
            .field("bytes", &self.text.len())
            .finish()
    }
}

/// The `inspect` script: reports the directory, the file, the content as hex (≤ 128
/// KiB), the marker count, the lock and the remote clock (exit 0, 30, 31).
#[must_use]
pub fn inspect(params: &InspectParams) -> RemoteScript {
    let literals = [
        ("HM_REG_ARG", params.registry.literal().to_owned()),
        ("HM_MARKER", params.marker.as_str().to_owned()),
    ];
    render(
        RemoteStage::Inspect,
        &literals,
        &[COMMON, FILE_HELPERS, INSPECT_BODY],
        None,
    )
}

/// The `bootstrap` script: `mkdir -m 0700` of the registry's directory when absent
/// (exit 0, 11, 30, 33).
#[must_use]
pub fn bootstrap(params: &BootstrapParams) -> RemoteScript {
    let literals = [("HM_REG_ARG", params.registry.literal().to_owned())];
    render(
        RemoteStage::Bootstrap,
        &literals,
        &[COMMON, BOOTSTRAP_BODY],
        None,
    )
}

/// The `append` script: under the holder-recording lock, appends the line unless a
/// line already contains the marker (exit 0, 10, 30, 31, 32, 33, 40, 41, 42).
#[must_use]
pub fn append(params: &AppendParams) -> RemoteScript {
    let literals = [
        ("HM_REG_ARG", params.registry.literal().to_owned()),
        ("HM_MARKER", params.marker.as_str().to_owned()),
        ("HM_LINE", params.line.as_str().to_owned()),
        ("HM_TOKEN", params.token.as_str().to_owned()),
        (
            "HM_NOT_AFTER",
            params.not_after_remote.seconds().to_string(),
        ),
    ];
    render(
        RemoteStage::Append,
        &literals,
        &[
            COMMON,
            FILE_HELPERS,
            IDENTITY_HELPERS,
            LOCK_HELPERS,
            APPEND_BODY,
        ],
        None,
    )
}

/// The `remove` script: under the holder-recording lock, `cmp` against the preimage,
/// then `mv -f` of the post-image (exit 0, 20, 30, 31, 32, 33, 40, 41, 42).
#[must_use]
pub fn remove(params: &RemoveParams) -> RemoteScript {
    let literals = [
        ("HM_REG_ARG", params.registry.literal().to_owned()),
        ("HM_MARKER", params.marker.as_str().to_owned()),
        ("HM_TOKEN", params.token.as_str().to_owned()),
        (
            "HM_NOT_AFTER",
            params.not_after_remote.seconds().to_string(),
        ),
    ];
    let payloads = (
        hex_lines(params.preimage.as_bytes()),
        hex_lines(params.post_image.as_bytes()),
    );
    render(
        RemoteStage::Remove,
        &literals,
        &[
            COMMON,
            FILE_HELPERS,
            IDENTITY_HELPERS,
            LOCK_HELPERS,
            REMOVE_BODY,
        ],
        Some(payloads),
    )
}

/// The `fence` script: reads the lock's holder record and decides `gone`, `alive`,
/// `unproven` or `none`; with `terminate`, TERM then KILL of an `alive` holder past
/// its not-after (exit 0, 30, 33, 40, 43, 44).
#[must_use]
pub fn fence(params: &FenceParams) -> RemoteScript {
    let literals = [
        ("HM_REG_ARG", params.registry.literal().to_owned()),
        ("HM_TOKEN", params.token.as_str().to_owned()),
        (
            "HM_TERMINATE",
            if params.terminate { "yes" } else { "no" }.to_owned(),
        ),
    ];
    render(
        RemoteStage::Fence,
        &literals,
        &[COMMON, IDENTITY_HELPERS, FENCE_HELPERS, FENCE_BODY],
        None,
    )
}

/// The stage's wire name.
fn stage_name(stage: RemoteStage) -> &'static str {
    match stage {
        RemoteStage::Inspect => "inspect",
        RemoteStage::Bootstrap => "bootstrap",
        RemoteStage::Append => "append",
        RemoteStage::Remove => "remove",
        RemoteStage::Fence => "fence",
        // A stage added later has no script here.
        _ => "unknown",
    }
}

/// Lowercase hex, 128 digits (64 bytes) per line, for `remove`'s here-documents.
fn hex_lines(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2 + bytes.len() / 64 + 1);
    for chunk in bytes.chunks(64) {
        for b in chunk {
            let _ = write!(out, "{b:02x}");
        }
        out.push('\n');
    }
    out
}

/// The line that marks a pause point in a template (dropped in the release form).
const PAUSE_TAG: &str = "@@PAUSE ";

/// The placeholders of `remove`'s two here-document bodies.
const HEX_PRE_TAG: &str = "@@HEX_PRE@@\n";
const HEX_POST_TAG: &str = "@@HEX_POST@@\n";

/// The script's header and the start of `hm_main`.
fn prelude(stage: RemoteStage) -> String {
    format!(
        "# Heimdall remote registry script: {name} (HM1 v=1; ADR-0008 D5 6.3).\n\
         # Every value is a validated literal in single quotes. /bin/sh -s reads this\n\
         # after the HM1 ready line; nothing runs before the call on the last line.\n\
         hm_main() {{\n  export LC_ALL=C\n  umask 077\n  export TZ=UTC0\n  set -f\n  \
         HM_STAGE='{name}'\n",
        name = stage_name(stage)
    )
}

fn render(
    stage: RemoteStage,
    literals: &[(&str, String)],
    fragments: &[&str],
    payloads: Option<(String, String)>,
) -> RemoteScript {
    let mut text = prelude(stage);
    for (name, value) in literals {
        // Every value type above excludes `'` and newlines; checked again here so a
        // future parameter can never break out of its quotes.
        debug_assert!(!value.contains('\'') && !value.contains('\n'));
        let _ = writeln!(text, "  {name}='{value}'");
    }
    for fragment in fragments {
        let fragment = expand(fragment);
        for line in fragment.split_inclusive('\n') {
            if line.trim_start().starts_with(PAUSE_TAG) {
                continue;
            }
            match (&payloads, line) {
                (Some((pre, _)), HEX_PRE_TAG) => text.push_str(pre),
                (Some((_, post)), HEX_POST_TAG) => text.push_str(post),
                _ => text.push_str(line),
            }
        }
    }
    text.push_str("}\nhm_main\n");
    RemoteScript { stage, text }
}

// ---------------------------------------------------------------------------------
// The shell text. Indentation is two spaces per level; here-document bodies and
// their delimiters start in column 0. `@@PAUSE <name>@@` lines are the test form's
// pause points (dropped in the release form; see `test_form`).
// ---------------------------------------------------------------------------------

/// Output, hex, ending, the clock, the path and the account (every script).
const COMMON: &str = r#"  HM_LOCKED=no
  HM_PRE_MADE=no
  HM_POST_MADE=no
  HM_REFUSAL=
  hm_out() {
    printf 'HM1 %s=%s\n' "$1" "$2"
  }
  hm_hex() {
    od -An -v -tx1 | awk '{ for (i = 1; i <= NF; i++) printf "%s", $i }'
  }
  hm_unlock() {
    if [ "$HM_LOCKED" = yes ]; then
      HM_LOCKED=no
      hm_lock_read
      if [ "$HM_LOCK_STATE" = held ] && [ "$HM_LOCK_REC" = "$HM_RECORD" ]; then
        rm -f "$HM_LOCK"
      fi
    fi
  }
  hm_cleanup() {
    if [ "$HM_PRE_MADE" = yes ]; then
      rm -f "$HM_PRE"
    fi
    if [ "$HM_POST_MADE" = yes ]; then
      rm -f "$HM_POST"
    fi
    hm_unlock
  }
  hm_end() {
    hm_unlock
    hm_out status "$2"
    if [ -n "$3" ]; then
      hm_out reason "$3"
    fi
    exit "$1"
  }
  hm_refuse() {
    if [ "$HM_STAGE" = inspect ]; then
      if [ -z "$HM_REFUSAL" ]; then
        HM_REFUSAL=$1
      fi
    else
      hm_end 30 refused "$1"
    fi
  }
  hm_clock() {
    HM_NOW=$(@@CLOCK@@)
    case "$HM_NOW" in
      ''|*[!0-9]*) hm_end 30 refused clock_unavailable ;;
    esac
  }
  hm_resolve() {
    if [ -n "$HM_REG_ARG" ]; then
      HM_REG=$HM_REG_ARG
    else
      case "${HOME-}" in
        /*) HM_REG="$HOME/.ssh/authorized_keys" ;;
        *) hm_end 30 refused home_unset ;;
      esac
    fi
    HM_NAME=${HM_REG##*/}
    HM_DIR=${HM_REG%/*}
    if [ -z "$HM_DIR" ]; then
      HM_DIR=/
    fi
    HM_LOCK="$HM_DIR/.hm-lock.$HM_NAME"
    HM_PRE="$HM_DIR/.hm-pre.${HM_TOKEN-}"
    HM_POST="$HM_DIR/.hm-post.${HM_TOKEN-}"
    printf 'HM1 path_hex='
    printf '%s' "$HM_REG" | hm_hex
    printf '\n'
  }
  hm_uid() {
    HM_UID=$(id -u 2>/dev/null)
    case "$HM_UID" in
      ''|*[!0-9]*) hm_end 30 refused uid_unavailable ;;
    esac
  }
  hm_ls() {
    HM_LS_MODE=
    HM_LS_OUT=$(ls -ldn "$1" 2>/dev/null) || return 1
    set -- $HM_LS_OUT
    if [ "$#" -lt 5 ]; then
      return 1
    fi
    HM_LS_MODE=$1
    HM_LS_LINKS=$2
    HM_LS_UID=$3
    HM_LS_SIZE=$5
    case "$HM_LS_LINKS:$HM_LS_UID:$HM_LS_SIZE" in
      *[!0-9:]*|:*|*::*|*:) return 1 ;;
    esac
    case "$HM_LS_MODE" in
      ??????????) HM_MODE10=$HM_LS_MODE; HM_MODE_IND= ;;
      ??????????[+@.]) HM_MODE10=${HM_LS_MODE%?}; HM_MODE_IND=${HM_LS_MODE#??????????} ;;
      *) return 1 ;;
    esac
    case "$HM_MODE10" in
      *[!A-Za-z-]*) return 1 ;;
    esac
  }
  hm_lock_read() {
    HM_LOCK_REC=
    if [ -L "$HM_LOCK" ]; then
      HM_LOCK_STATE=held
      HM_LOCK_LS=$(ls -ld "$HM_LOCK" 2>/dev/null)
      case "$HM_LOCK_LS" in
        l*' -> '*) HM_LOCK_REC=${HM_LOCK_LS##* -> } ;;
      esac
    elif [ -e "$HM_LOCK" ]; then
      HM_LOCK_STATE=other
    else
      HM_LOCK_STATE=none
    fi
  }
  hm_record_ok() {
    case "$1" in
      hm1-*-*-*-*-*) ;;
      *) return 1 ;;
    esac
    case "$1" in
      *[!0-9a-z-]*|*--*|*-) return 1 ;;
    esac
    HM_R_IFS=$IFS
    IFS=-
    set -- $1
    IFS=$HM_R_IFS
    if [ "$#" -ne 6 ]; then
      return 1
    fi
    HM_R_TOKEN=$2
    HM_R_PID=$3
    HM_R_START=$4
    HM_R_BOOT=$5
    HM_R_NA=$6
    case "$HM_R_TOKEN" in
      ????????????????????????????????) ;;
      *) return 1 ;;
    esac
    case "$HM_R_TOKEN:$HM_R_START:$HM_R_BOOT" in
      *[!0-9a-f:]*) return 1 ;;
    esac
    case "$HM_R_PID" in
      0*|*[!0-9]*) return 1 ;;
    esac
    case "$HM_R_NA" in
      *[!0-9]*) return 1 ;;
    esac
  }
  hm_lock_report() {
    hm_lock_read
    if [ "$HM_LOCK_STATE" = none ]; then
      hm_out lock none
    else
      hm_out lock held
      if hm_record_ok "$HM_LOCK_REC"; then
        hm_out lock_holder "$HM_LOCK_REC"
      fi
    fi
  }
"#;

/// The directory, file and content reports and checks (`inspect`, `append`,
/// `remove`). `hm_refuse` ends a mutating script; `inspect` keeps the first reason.
const FILE_HELPERS: &str = r#"  hm_check_dir() {
    if hm_ls "$HM_DIR"; then
      hm_out dir present
      hm_out dir_mode "$HM_LS_MODE"
      if [ "$HM_LS_UID" = "$HM_UID" ]; then
        hm_out dir_owner_self yes
      else
        hm_out dir_owner_self no
      fi
    else
      hm_out dir present
      hm_refuse dir_unreadable
      return 0
    fi
    case "$HM_MODE10" in
      d*) ;;
      *) hm_refuse dir_not_directory ;;
    esac
    if [ "$HM_LS_UID" != "$HM_UID" ]; then
      hm_refuse dir_owner_foreign
    fi
    case "$HM_MODE10" in
      ?????w????|????????w?) hm_refuse dir_writable_by_others ;;
    esac
    if [ "$HM_MODE_IND" = + ]; then
      hm_refuse dir_acl
    fi
  }
  hm_check_file() {
    HM_SIZE=0
    if [ -L "$HM_REG" ]; then
      HM_FILE=symlink
      hm_out file symlink
      hm_refuse registry_symlink
    elif [ ! -e "$HM_REG" ]; then
      HM_FILE=absent
      hm_out file absent
    elif [ ! -f "$HM_REG" ]; then
      HM_FILE=other
      hm_out file other
      hm_refuse registry_not_regular
    elif hm_ls "$HM_REG"; then
      HM_FILE=regular
      HM_SIZE=$HM_LS_SIZE
      hm_out file regular
      hm_out links "$HM_LS_LINKS"
      hm_out mode "$HM_LS_MODE"
      if [ "$HM_LS_UID" = "$HM_UID" ]; then
        hm_out owner_self yes
      else
        hm_out owner_self no
      fi
      hm_out size "$HM_LS_SIZE"
      if [ "$HM_LS_LINKS" != 1 ]; then
        hm_refuse registry_hardlinked
      fi
      if [ "$HM_LS_UID" != "$HM_UID" ]; then
        hm_refuse registry_owner_foreign
      fi
      if [ -n "$HM_MODE_IND" ]; then
        hm_refuse registry_acl_or_label
      fi
    else
      HM_FILE=other
      hm_out file other
      hm_refuse registry_unreadable
    fi
  }
  hm_content() {
    if [ ! -r "$HM_REG" ]; then
      if [ "$1" = check ]; then
        hm_refuse registry_unreadable
      fi
      return 0
    fi
    HM_LAST=$(tail -c 1 "$HM_REG" 2>/dev/null | hm_hex)
    if [ "$HM_LAST" = 0a ]; then
      hm_out last_byte_newline yes
    else
      hm_out last_byte_newline no
    fi
    HM_COUNT=$(grep -c -F -e "$HM_MARKER" "$HM_REG" 2>/dev/null)
    case "$HM_COUNT" in
      ''|*[!0-9]*)
        if [ "$1" = check ]; then
          hm_refuse registry_unreadable
        fi
        return 0
        ;;
    esac
    hm_out marker_lines "$HM_COUNT"
    printf 'HM1 content_hex='
    hm_hex < "$HM_REG"
    printf '\n'
  }
"#;

/// The start identity, boot identity and process group of the script's own shell
/// (`append`, `remove`, `fence`), per the shell table of ADR-0008 D5 §6.3, with
/// `HM_BOOT_STABLE` saying whether a boot-identity difference alone proves a reboot
/// (§17.17 item 2: Linux and macOS yes; the BSDs' `kern.boottime` timestamp no).
const IDENTITY_HELPERS: &str = r#"  hm_procstat() {
    awk '@@PROCSTAT@@' "/proc/$1/stat" 2>/dev/null
  }
  hm_identity_fail() {
    if [ "$HM_STAGE" = fence ]; then
      hm_out fence unproven
      hm_fence_end 44 unproven start_identity_unavailable
    fi
    hm_end 30 refused start_identity_unavailable
  }
  hm_identity() {
    HM_OS=$(uname -s 2>/dev/null)
    HM_PGID=
    HM_START_RAW=
    HM_BOOT_RAW=
    HM_BOOT_STABLE=no
    case "$HM_OS" in
      Linux)
        HM_PS=$(hm_procstat "$$") || hm_identity_fail
        set -- $HM_PS
        HM_PGID=${1-}
        HM_START_RAW=${2-}
        HM_BOOT_RAW=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
        HM_BOOT_STABLE=yes
        ;;
      Darwin)
        HM_PS=$(ps -o pgid= -p "$$" 2>/dev/null)
        set -- $HM_PS
        HM_PGID=${1-}
        HM_START_RAW=$(ps -o lstart= -p "$$" 2>/dev/null | awk '{ $1 = $1; print }')
        HM_BOOT_RAW=$(sysctl -n kern.bootsessionuuid 2>/dev/null)
        HM_BOOT_STABLE=yes
        ;;
      FreeBSD|NetBSD|OpenBSD)
        HM_PS=$(ps -o pgid= -p "$$" 2>/dev/null)
        set -- $HM_PS
        HM_PGID=${1-}
        HM_START_RAW=$(ps -o lstart= -p "$$" 2>/dev/null | awk '{ $1 = $1; print }')
        HM_BOOT_RAW=$(sysctl -n kern.boottime 2>/dev/null | awk '{ i = index($0, "}"); if (i > 0) { print substr($0, 1, i); exit } }')
        ;;
      *) hm_identity_fail ;;
    esac
    case "$HM_PGID" in
      ''|*[!0-9]*) hm_identity_fail ;;
    esac
    if [ -z "$HM_START_RAW" ] || [ -z "$HM_BOOT_RAW" ]; then
      hm_identity_fail
    fi
    if [ "$HM_PGID" != "$$" ]; then
      hm_out pgid "$HM_PGID"
      if [ "$HM_STAGE" = fence ]; then
        hm_fence_end 33 no_process_group no_process_group
      fi
      hm_end 33 no_process_group no_process_group
    fi
    HM_START=$(printf '%s' "$HM_START_RAW" | hm_hex)
    HM_BOOT=$(printf '%s' "$HM_BOOT_RAW" | hm_hex)
  }
"#;

/// The holder-recording lock (`append`, `remove`).
const LOCK_HELPERS: &str = r#"  hm_take_lock() {
    HM_RECORD="hm1-$HM_TOKEN-$$-$HM_START-$HM_BOOT-$HM_NOT_AFTER"
    if [ -d "$HM_LOCK" ] && [ ! -L "$HM_LOCK" ]; then
      hm_out lock held
      hm_end 30 refused lock_is_directory
    fi
    if [ -L "$HM_LOCK" ] || [ -e "$HM_LOCK" ]; then
      hm_lock_report
      hm_end 40 busy ''
    fi
    @@PAUSE before_ln@@
    if ln -s "$HM_RECORD" "$HM_LOCK" 2>/dev/null; then
      :
    elif [ -L "$HM_LOCK" ] || [ -e "$HM_LOCK" ]; then
      hm_lock_report
      hm_end 40 busy ''
    else
      hm_end 30 refused lock_not_created
    fi
    hm_lock_read
    if [ "$HM_LOCK_STATE" = held ] && [ "$HM_LOCK_REC" = "$HM_RECORD" ]; then
      HM_LOCKED=yes
      return 0
    fi
    if [ -d "$HM_LOCK" ] && [ -L "$HM_LOCK/$HM_RECORD" ]; then
      HM_INNER=$(ls -ld "$HM_LOCK/$HM_RECORD" 2>/dev/null)
      if [ "${HM_INNER##* -> }" = "$HM_RECORD" ]; then
        rm -f "$HM_LOCK/$HM_RECORD"
      fi
    fi
    hm_end 30 refused lock_not_verified
  }
  hm_recheck() {
    hm_lock_read
    if [ "$HM_LOCK_STATE" != held ] || [ "$HM_LOCK_REC" != "$HM_RECORD" ]; then
      HM_LOCKED=no
      hm_end 42 lock_lost ''
    fi
    hm_clock
    if [ "$HM_NOW" -ge "$HM_NOT_AFTER" ]; then
      hm_end 41 not_after_passed ''
    fi
  }
  hm_before_lock() {
    hm_identity
    hm_out pgid "$$"
    hm_out start_identity "$HM_START"
    hm_out boot_identity "$HM_BOOT"
    if [ ! -L "$HM_DIR" ] && [ ! -e "$HM_DIR" ]; then
      hm_out dir absent
      hm_end 32 dir_absent ''
    fi
    if [ "$HM_NOW" -ge "$HM_NOT_AFTER" ]; then
      hm_end 41 not_after_passed ''
    fi
    hm_check_dir
  }
"#;

// ⟨integrator, wave-1 review finding 1⟩ The order is clock, then lock, then content
// (ADR-0008 D5 §6.7: "Reconcile reads the lock state in the inspect result before it
// reads the marker"). A holder that wrote and released between a content read and a
// later lock read would otherwise be invisible: no marker line and `lock=none` past the
// not-after, which `late_write_cleared` and the not-after rule read as proof.
const INSPECT_BODY: &str = r#"  printf 'HM1 v=1\n'
  hm_resolve
  hm_clock
  hm_out remote_now "$HM_NOW"
  hm_uid
  if [ -L "$HM_DIR" ] || [ -e "$HM_DIR" ]; then
    hm_lock_report
    hm_check_dir
    hm_check_file
    if [ "$HM_FILE" = regular ]; then
      if [ "$HM_SIZE" -gt 131072 ]; then
        hm_end 31 too_large ''
      fi
      hm_content check
    fi
  else
    hm_out dir absent
    hm_out file absent
    hm_out lock none
  fi
  if [ -n "$HM_REFUSAL" ]; then
    hm_end 30 refused "$HM_REFUSAL"
  fi
  hm_end 0 ok ''
"#;

const BOOTSTRAP_BODY: &str = r#"  hm_dir_private() {
    if [ -L "$HM_DIR" ]; then
      hm_out dir present
      HM_WHY=dir_symlink
      return 1
    fi
    if ! hm_ls "$HM_DIR"; then
      hm_out dir present
      HM_WHY=dir_unreadable
      return 1
    fi
    hm_out dir present
    hm_out dir_mode "$HM_LS_MODE"
    if [ "$HM_LS_UID" = "$HM_UID" ]; then
      hm_out dir_owner_self yes
    else
      hm_out dir_owner_self no
      HM_WHY=dir_owner_foreign
      return 1
    fi
    if [ "$HM_LS_MODE" != drwx------ ]; then
      HM_WHY=dir_not_private
      return 1
    fi
  }
  printf 'HM1 v=1\n'
  hm_resolve
  hm_clock
  hm_out remote_now "$HM_NOW"
  hm_uid
  HM_PARENT=${HM_DIR%/*}
  if [ -z "$HM_PARENT" ]; then
    HM_PARENT=/
  fi
  if [ -L "$HM_DIR" ] || [ -e "$HM_DIR" ]; then
    if hm_dir_private; then
      hm_end 11 already_present ''
    fi
    hm_end 30 refused "$HM_WHY"
  fi
  if [ -L "$HM_PARENT" ]; then
    hm_end 30 refused parent_symlink
  fi
  if [ ! -e "$HM_PARENT" ]; then
    hm_out dir absent
    hm_end 33 parent_absent ''
  fi
  if [ ! -d "$HM_PARENT" ] || ! hm_ls "$HM_PARENT"; then
    hm_end 30 refused parent_not_directory
  fi
  case "$HM_MODE10" in
    d*) ;;
    *) hm_end 30 refused parent_not_directory ;;
  esac
  if [ "$HM_LS_UID" != "$HM_UID" ] && [ "$HM_LS_UID" != 0 ]; then
    hm_end 30 refused parent_owner_foreign
  fi
  case "$HM_MODE10" in
    ?????w????|????????w?) hm_end 30 refused parent_writable_by_others ;;
  esac
  @@PAUSE before_mkdir@@
  if mkdir -m 0700 "$HM_DIR" 2>/dev/null; then
    HM_CREATED=yes
  else
    HM_CREATED=no
  fi
  if hm_dir_private; then
    if [ "$HM_CREATED" = yes ]; then
      hm_end 0 created ''
    fi
    hm_end 11 already_present ''
  fi
  if [ "$HM_CREATED" = no ] && [ ! -L "$HM_DIR" ] && [ ! -e "$HM_DIR" ]; then
    hm_end 30 refused mkdir_failed
  fi
  hm_end 30 refused "$HM_WHY"
"#;

const APPEND_BODY: &str = r#"  trap 'hm_cleanup' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  printf 'HM1 v=1\n'
  hm_resolve
  hm_clock
  hm_out remote_now "$HM_NOW"
  hm_uid
  hm_before_lock
  hm_take_lock
  @@PAUSE after_lock@@
  hm_check_file
  if [ "$HM_FILE" = regular ]; then
    if [ "$HM_SIZE" -gt 131072 ]; then
      hm_end 31 too_large ''
    fi
    if [ ! -r "$HM_REG" ]; then
      hm_end 30 refused registry_unreadable
    fi
    if grep -q -F -e "$HM_MARKER" "$HM_REG" 2>/dev/null; then
      hm_content check
      hm_end 10 already_present ''
    fi
  fi
  hm_recheck
  HM_NL=no
  if [ "$HM_FILE" = regular ]; then
    HM_LAST=$(tail -c 1 "$HM_REG" 2>/dev/null | hm_hex)
    if [ -n "$HM_LAST" ] && [ "$HM_LAST" != 0a ]; then
      HM_NL=yes
    fi
  fi
  @@PAUSE before_write@@
  if [ "$HM_FILE" = absent ]; then
    set -C
    if printf '%s\n' "$HM_LINE" > "$HM_REG"; then
      set +C
      chmod 600 "$HM_REG"
    else
      set +C
      hm_end 30 refused write_failed
    fi
  elif [ "$HM_NL" = yes ]; then
    if ! printf '\n%s\n' "$HM_LINE" >> "$HM_REG"; then
      hm_content keep
      hm_end 30 refused write_failed
    fi
  else
    if ! printf '%s\n' "$HM_LINE" >> "$HM_REG"; then
      hm_content keep
      hm_end 30 refused write_failed
    fi
  fi
  hm_content keep
  hm_end 0 written ''
"#;

const REMOVE_BODY: &str = r#"  hm_decode() {
    awk 'BEGIN { h = "0123456789abcdef" } { n = length($0); if (n % 2) exit 3; for (i = 1; i < n; i += 2) { a = index(h, substr($0, i, 1)); b = index(h, substr($0, i + 1, 1)); if (a == 0 || b == 0) exit 3; v = (a - 1) * 16 + b - 1; if (v == 0) exit 4; printf "%c", v } }'
  }
  hm_perm() {
    HM_PERM=$(printf '%s' "$HM_MODE10" | awk '{ s = ""; for (i = 2; i <= 10; i += 3) { t = substr($0, i, 3); if (t == "rw-") s = s "6"; else if (t == "r--") s = s "4"; else if (t == "---") s = s "0"; else exit 1 } print s }')
    case "$HM_PERM" in
      [0-7][0-7][0-7]) ;;
      *) hm_end 30 refused registry_mode_unsupported ;;
    esac
  }
  trap 'hm_cleanup' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  printf 'HM1 v=1\n'
  hm_resolve
  hm_clock
  hm_out remote_now "$HM_NOW"
  hm_uid
  hm_before_lock
  hm_take_lock
  @@PAUSE after_lock@@
  hm_check_file
  if [ "$HM_FILE" = absent ]; then
    hm_end 20 changed_since_read registry_absent
  fi
  if [ "$HM_SIZE" -gt 131072 ]; then
    hm_end 31 too_large ''
  fi
  hm_perm
  set -C
  if : > "$HM_PRE" 2>/dev/null; then
    HM_PRE_MADE=yes
  else
    set +C
    hm_end 30 refused temp_create_failed
  fi
  if : > "$HM_POST" 2>/dev/null; then
    HM_POST_MADE=yes
  else
    set +C
    hm_end 30 refused temp_create_failed
  fi
  set +C
  if hm_decode > "$HM_PRE" <<'HM_HEX_PRE'
@@HEX_PRE@@
HM_HEX_PRE
  then
    :
  else
    hm_end 30 refused decode_failed
  fi
  if hm_decode > "$HM_POST" <<'HM_HEX_POST'
@@HEX_POST@@
HM_HEX_POST
  then
    :
  else
    hm_end 30 refused decode_failed
  fi
  if ! chmod "$HM_PERM" "$HM_POST"; then
    hm_end 30 refused write_failed
  fi
  if ! cmp -s "$HM_REG" "$HM_PRE"; then
    hm_end 20 changed_since_read ''
  fi
  hm_recheck
  @@PAUSE before_write@@
  if mv -f "$HM_POST" "$HM_REG"; then
    HM_POST_MADE=no
  else
    hm_end 30 refused write_failed
  fi
  rm -f "$HM_PRE"
  HM_PRE_MADE=no
  hm_content keep
  hm_end 0 renamed ''
"#;

/// The group proof and the decision (ADR-0008 D5 §6.3, §17.7 item 1).
const FENCE_HELPERS: &str = r#"  HM_SIGNALS=
  hm_fence_end() {
    hm_out fence_signals "$HM_SIGNALS"
    hm_end "$1" "$2" "$3"
  }
  hm_holder_pid() {
    HM_PIDSTATE=unreadable
    HM_HSTART_RAW=
    if [ "$HM_OS" = Linux ]; then
      if [ -e "/proc/$HM_R_PID/stat" ]; then
        if HM_HP=$(hm_procstat "$HM_R_PID"); then
          set -- $HM_HP
          HM_HSTART_RAW=${2-}
        else
          return 0
        fi
      else
        HM_PIDSTATE=absent
        return 0
      fi
    else
      HM_HSTART_RAW=$(ps -o lstart= -p "$HM_R_PID" 2>/dev/null | awk '{ $1 = $1; print }')
      if [ -z "$HM_HSTART_RAW" ]; then
        HM_PIDSTATE=absent
        return 0
      fi
    fi
    if [ -z "$HM_HSTART_RAW" ]; then
      return 0
    fi
    HM_HSTART=$(printf '%s' "$HM_HSTART_RAW" | hm_hex)
    hm_out start_identity "$HM_HSTART"
    if [ "$HM_HSTART" = "$HM_R_START" ]; then
      HM_PIDSTATE=same
    else
      HM_PIDSTATE=different
    fi
  }
  hm_decide() {
    hm_out pgid "$HM_R_PID"
    hm_out boot_identity "$HM_BOOT"
    if [ "$HM_BOOT" != "$HM_R_BOOT" ] && [ "$HM_BOOT_STABLE" = yes ]; then
      HM_FENCE=gone
      hm_out fence gone
      return 0
    fi
    kill -s 0 -- "-$$" 2>/dev/null
    HM_GC=$?
    kill -s 0 -- "-$HM_R_PID" 2>/dev/null
    HM_GK=$?
    HM_GL=$(ps -A -o pgid= 2>/dev/null)
    HM_GLS=$?
    HM_GLV=$(printf '%s\n' "$HM_GL" | awk -v own="$$" -v tgt="$HM_R_PID" 'NF == 0 { next } NF != 1 || $1 !~ /^[0-9]+$/ { bad = 1; next } $1 == own "" { o = 1 } $1 == tgt "" { t = 1 } END { if (bad || !o) print "invalid"; else if (t) print "yes"; else print "no" }')
    if [ "$HM_GLS" -ne 0 ]; then
      HM_GLV=invalid
    fi
    hm_out group_control "$HM_GC"
    hm_out group_probe "$HM_GK"
    case "$HM_GLV" in
      yes|no) hm_out group_listed "$HM_GLV" ;;
    esac
    HM_GROUP=unproven
    if [ "$HM_GC" -eq 0 ]; then
      if [ "$HM_GK" -ne 0 ] && [ "$HM_GLV" = no ]; then
        HM_GROUP=empty
      elif [ "$HM_GK" -eq 0 ] && [ "$HM_GLV" = yes ]; then
        HM_GROUP=live
      fi
    fi
    hm_holder_pid
    case "$HM_GROUP:$HM_PIDSTATE" in
      empty:absent|empty:different) HM_FENCE=gone ;;
      live:absent|live:same) HM_FENCE=alive ;;
      *) HM_FENCE=unproven ;;
    esac
    hm_out fence "$HM_FENCE"
  }
  hm_wait() {
    HM_I=0
    while [ "$HM_I" -lt 5 ]; do
      sleep 1
      hm_decide
      if [ "$HM_FENCE" != alive ]; then
        return 0
      fi
      HM_I=$((HM_I + 1))
    done
  }
"#;

const FENCE_BODY: &str = r#"  printf 'HM1 v=1\n'
  hm_resolve
  hm_clock
  hm_out remote_now "$HM_NOW"
  hm_uid
  hm_identity
  hm_lock_read
  if [ "$HM_LOCK_STATE" = none ]; then
    hm_out lock none
    hm_out fence none
    hm_fence_end 0 none ''
  fi
  hm_out lock held
  if [ "$HM_LOCK_STATE" != held ]; then
    hm_fence_end 30 refused lock_not_symlink
  fi
  if ! hm_record_ok "$HM_LOCK_REC"; then
    hm_fence_end 40 busy lock_foreign
  fi
  hm_out lock_holder "$HM_LOCK_REC"
  if [ "$HM_R_TOKEN" != "$HM_TOKEN" ]; then
    hm_fence_end 40 busy lock_other_token
  fi
  HM_HOLDER_REC=$HM_LOCK_REC
  hm_decide
  if [ "$HM_FENCE" = alive ] && [ "$HM_TERMINATE" = yes ]; then
    if [ "$HM_NOW" -gt "$HM_R_NA" ]; then
      kill -s TERM -- "-$HM_R_PID" 2>/dev/null
      HM_SIGNALS=TERM
      @@PAUSE after_term@@
      hm_wait
      if [ "$HM_FENCE" = alive ]; then
        kill -s KILL -- "-$HM_R_PID" 2>/dev/null
        HM_SIGNALS=TERM,KILL
        @@PAUSE after_kill@@
        hm_wait
      fi
    else
      hm_fence_end 43 alive not_after_not_passed
    fi
  fi
  case "$HM_FENCE" in
    alive) hm_fence_end 43 alive '' ;;
    unproven) hm_fence_end 44 unproven '' ;;
  esac
  hm_lock_read
  if [ "$HM_LOCK_STATE" = held ] && [ "$HM_LOCK_REC" = "$HM_HOLDER_REC" ]; then
    rm -f "$HM_LOCK"
    if [ -L "$HM_LOCK" ]; then
      hm_fence_end 30 refused lock_not_removed
    fi
  elif [ "$HM_LOCK_STATE" != none ]; then
    hm_fence_end 40 busy lock_replaced
  fi
  hm_fence_end 0 gone ''
"#;

/// The pause points of each stage, in script order (ADR-0008 D13 item 3; m03-plan U5,
/// U11 `PauseHooks`). `nonce_known` is the verification's (U5-io), not a script's.
#[must_use]
pub fn pause_points(stage: RemoteStage) -> &'static [&'static str] {
    match stage {
        RemoteStage::Inspect => &[],
        RemoteStage::Bootstrap => &["before_mkdir"],
        RemoteStage::Append | RemoteStage::Remove => &["before_ln", "after_lock", "before_write"],
        RemoteStage::Fence => &["after_term", "after_kill"],
        _ => &[],
    }
}

/// The fragments of each stage, in order (for the test form's anchors).
#[cfg(debug_assertions)]
fn fragments(stage: RemoteStage) -> &'static [&'static str] {
    match stage {
        RemoteStage::Inspect => &[COMMON, FILE_HELPERS, INSPECT_BODY],
        RemoteStage::Bootstrap => &[COMMON, BOOTSTRAP_BODY],
        RemoteStage::Append => &[
            COMMON,
            FILE_HELPERS,
            IDENTITY_HELPERS,
            LOCK_HELPERS,
            APPEND_BODY,
        ],
        RemoteStage::Remove => &[
            COMMON,
            FILE_HELPERS,
            IDENTITY_HELPERS,
            LOCK_HELPERS,
            REMOVE_BODY,
        ],
        RemoteStage::Fence => &[COMMON, IDENTITY_HELPERS, FENCE_HELPERS, FENCE_BODY],
        _ => &[],
    }
}

/// The test form (debug builds only; module docs): `HM_PAUSE <name>` lines.
///
/// At each point of [`pause_points`], when `<dir>/<name>` is a FIFO, the script
/// writes `$$` (its process group, since it leads its group) to `<dir>/<name>.pid` and
/// then reads the FIFO until its writer closes it (`cat <fifo> >/dev/null`, a child
/// in the script's process group). So a test that opens the FIFO for writing returns
/// once the script is paused there, and closing it releases the script; a missing
/// FIFO is no pause. `heimdall_testkit::registry::PauseHooks` (U11) drives it.
#[cfg(debug_assertions)]
pub mod test_form {
    use super::{PAUSE_TAG, RemoteScript, RemoteStage, ScriptError, fragments, pause_points};

    /// A validated pause directory: absolute, `[A-Za-z0-9._/-]`, at most 1024 bytes,
    /// no empty, `.` or `..` component.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct PauseDir(String);

    impl PauseDir {
        /// Validate `dir`.
        ///
        /// # Errors
        /// [`ScriptError::PauseDir`].
        pub fn parse(dir: &str) -> Result<PauseDir, ScriptError> {
            if super::is_plain_absolute_path(dir, 1024) {
                Ok(PauseDir(dir.to_owned()))
            } else {
                Err(ScriptError::PauseDir)
            }
        }

        /// The directory.
        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    /// The function every pause point calls.
    fn pause_function(dir: &PauseDir) -> String {
        format!(
            "  HM_PAUSE_DIR='{}'\n  HM_PAUSE() {{\n    if [ -p \"$HM_PAUSE_DIR/$1\" ]; then\n      \
             printf '%s\\n' \"$$\" >| \"$HM_PAUSE_DIR/$1.pid\"\n      \
             cat \"$HM_PAUSE_DIR/$1\" > /dev/null\n    fi\n  }}\n",
            dir.as_str()
        )
    }

    /// For each pause point of `stage`: its name, its indentation and the template
    /// line that follows it (its anchor in the release text).
    fn anchors(stage: RemoteStage) -> Vec<(&'static str, &'static str, &'static str)> {
        let mut out = Vec::new();
        for fragment in fragments(stage) {
            let lines: Vec<&str> = fragment.split_inclusive('\n').collect();
            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim_start();
                if let Some(rest) = trimmed.strip_prefix(PAUSE_TAG) {
                    let name = rest.trim_end().trim_end_matches("@@");
                    let indent = &line[..line.len() - trimmed.len()];
                    if let Some(next) = lines.get(i + 1) {
                        out.push((name, indent, *next));
                    }
                }
            }
        }
        out
    }

    /// The stage named by a release script's `HM_STAGE` line.
    fn stage_of(text: &str) -> Option<RemoteStage> {
        [
            RemoteStage::Inspect,
            RemoteStage::Bootstrap,
            RemoteStage::Append,
            RemoteStage::Remove,
            RemoteStage::Fence,
        ]
        .into_iter()
        .find(|s| text.contains(&format!("\n  HM_STAGE='{}'\n", super::stage_name(*s))))
    }

    /// Insert the pause function and every pause point of the script's stage into a
    /// release script's text.
    ///
    /// # Errors
    /// [`ScriptError::NotAReleaseScript`] when the text names no stage, already has
    /// pause points, or any anchor is missing or not unique.
    pub fn insert_pause_points(text: &str, dir: &PauseDir) -> Result<String, ScriptError> {
        let stage = stage_of(text).ok_or(ScriptError::NotAReleaseScript)?;
        if text.contains("HM_PAUSE") || !text.ends_with("}\nhm_main\n") {
            return Err(ScriptError::NotAReleaseScript);
        }
        let mut out = text.to_owned();
        let start = "\n  set -f\n";
        if out.matches(start).count() != 1 {
            return Err(ScriptError::NotAReleaseScript);
        }
        out = out.replacen(start, &format!("{start}{}", pause_function(dir)), 1);
        let found = anchors(stage);
        if found.len() != pause_points(stage).len() {
            return Err(ScriptError::NotAReleaseScript);
        }
        for (name, indent, anchor) in found {
            let needle = format!("\n{anchor}");
            if out.matches(&needle).count() != 1 {
                return Err(ScriptError::NotAReleaseScript);
            }
            out = out.replacen(&needle, &format!("\n{indent}HM_PAUSE {name}\n{anchor}"), 1);
        }
        Ok(out)
    }

    /// [`insert_pause_points`] for a rendered script.
    ///
    /// # Errors
    /// As [`insert_pause_points`] (never for a script of this module).
    pub fn with_pause_points(
        script: &RemoteScript,
        dir: &PauseDir,
    ) -> Result<RemoteScript, ScriptError> {
        Ok(RemoteScript {
            stage: script.stage,
            text: insert_pause_points(&script.text, dir)?,
        })
    }
}

/// Substitute the shared parser and the clock command into a fragment (they contain
/// no `@@` and no `'`).
fn expand(fragment: &str) -> String {
    fragment
        .replace("@@PROCSTAT@@", PROCSTAT_AWK)
        .replace("@@CLOCK@@", REMOTE_CLOCK_COMMAND)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn token() -> StepToken {
        StepToken::parse("0123456789abcdef0123456789abcdef").unwrap()
    }

    fn marker() -> Marker {
        Marker::parse("heimdall:enr_00112233445566778899aabbccddeeff").unwrap()
    }

    fn all_scripts() -> Vec<RemoteScript> {
        let registry = RegistryLocation::from_plan(Some("/home/u/.ssh/authorized_keys")).unwrap();
        let line = RegistryLine::parse(
            "cert-authority,principals=\"hm:d:a\" ssh-ed25519 AAAA heimdall:enr_00112233445566778899aabbccddeeff",
            &marker(),
        )
        .unwrap();
        vec![
            inspect(&InspectParams {
                registry: registry.clone(),
                marker: marker(),
            }),
            bootstrap(&BootstrapParams {
                registry: RegistryLocation::RemoteHome,
            }),
            append(&AppendParams {
                registry: registry.clone(),
                marker: marker(),
                line,
                token: token(),
                not_after_remote: NotAfter::new(1_800_000_000).unwrap(),
            }),
            remove(&RemoveParams {
                registry: registry.clone(),
                marker: marker(),
                token: token(),
                not_after_remote: NotAfter::new(1).unwrap(),
                preimage: Payload::new(b"a\n").unwrap(),
                post_image: Payload::new(b"").unwrap(),
            }),
            fence(&FenceParams {
                registry,
                token: token(),
                terminate: true,
            }),
        ]
    }

    #[test]
    fn every_script_is_one_function_called_on_its_last_line() {
        for s in all_scripts() {
            let t = s.text();
            assert!(t.ends_with("}\nhm_main\n"), "{:?}", s.stage());
            assert!(t.contains("\nhm_main() {\n  export LC_ALL=C\n  umask 077\n"));
            // Nothing outside the function but comments and the call.
            let outside: Vec<&str> = t
                .lines()
                .take_while(|l| *l != "hm_main() {")
                .filter(|l| !l.starts_with('#'))
                .collect();
            assert!(outside.is_empty(), "{outside:?}");
            assert!(t.is_ascii());
            assert!(!t.contains("@@"), "{:?}", s.stage());
            assert!(!t.contains("HM_PAUSE"));
            assert!(!t.contains('\r'));
        }
    }

    #[test]
    fn parameters_refuse_quotes_and_bad_shapes() {
        for bad in [
            "relative", "/a/../b", "/a//b", "/a/./b", "/a/b/", "/", "/a b", "/a'b", "/a\nb",
        ] {
            assert_eq!(
                RegistryPath::parse(bad),
                Err(ScriptError::RegistryPath),
                "{bad:?}"
            );
        }
        assert!(RegistryPath::parse(&format!("/{}", "a".repeat(254))).is_ok());
        assert!(RegistryPath::parse(&format!("/{}", "a".repeat(255))).is_err());
        for bad in ["heimdall:", "enr_x", "heimdall:a'b", "heimdall:a b"] {
            assert_eq!(Marker::parse(bad), Err(ScriptError::Marker), "{bad:?}");
        }
        let m = marker();
        assert!(RegistryLine::parse("x y", &m).is_err());
        assert!(RegistryLine::parse(&format!("a'{} ", m.as_str()), &m).is_err());
        assert!(RegistryLine::parse(&format!("a\n{}", m.as_str()), &m).is_err());
        for bad in ["", "0123", "0123456789ABCDEF0123456789abcdef"] {
            assert_eq!(StepToken::parse(bad), Err(ScriptError::Token));
        }
        assert_eq!(NotAfter::new(-1), Err(ScriptError::NotAfter));
        assert!(Payload::new(&vec![b'a'; MAX_PAYLOAD_BYTES]).is_ok());
        assert_eq!(
            Payload::new(&vec![b'a'; MAX_PAYLOAD_BYTES + 1]),
            Err(ScriptError::Payload)
        );
    }

    #[test]
    fn the_shared_awk_and_the_clock_carry_no_single_quote() {
        assert!(!PROCSTAT_AWK.contains('\''));
        assert!(!PROCSTAT_AWK.contains("@@"));
        assert!(!REMOTE_CLOCK_COMMAND.contains("@@"));
        // The clock command's own quoting is balanced (two quoted words).
        assert_eq!(REMOTE_CLOCK_COMMAND.matches('\'').count(), 4);
    }

    #[test]
    fn remove_payloads_are_wrapped_hex_lines() {
        assert_eq!(hex_lines(b""), "");
        assert_eq!(hex_lines(b"\n\xff"), "0aff\n");
        let long = hex_lines(&[0x41; 65]);
        assert_eq!(long.lines().map(str::len).collect::<Vec<_>>(), [128, 2]);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn test_form_inserts_every_point_once_and_only_there() {
        use test_form::{PauseDir, insert_pause_points, with_pause_points};
        let dir = PauseDir::parse("/tmp/hm-pause").unwrap();
        assert!(PauseDir::parse("rel").is_err());
        for s in all_scripts() {
            let t = with_pause_points(&s, &dir).unwrap();
            let text = t.text();
            for name in pause_points(s.stage()) {
                assert_eq!(
                    text.matches(&format!("HM_PAUSE {name}\n")).count(),
                    1,
                    "{:?} {name}",
                    s.stage()
                );
            }
            assert_eq!(
                text.matches("HM_PAUSE ").count(),
                pause_points(s.stage()).len()
            );
            assert!(text.contains("HM_PAUSE_DIR='/tmp/hm-pause'"));
            // Removing the inserted lines gives the release text back.
            let back: String = text
                .split_inclusive('\n')
                .filter(|l| !l.trim_start().starts_with("HM_PAUSE "))
                .collect::<String>()
                .replace(
                    "  HM_PAUSE_DIR='/tmp/hm-pause'\n  HM_PAUSE() {\n    if [ -p \"$HM_PAUSE_DIR/$1\" ]; then\n      printf '%s\\n' \"$$\" >| \"$HM_PAUSE_DIR/$1.pid\"\n      cat \"$HM_PAUSE_DIR/$1\" > /dev/null\n    fi\n  }\n",
                    "",
                );
            assert_eq!(back, s.text(), "{:?}", s.stage());
            // A test-form text is not a release script.
            assert_eq!(
                insert_pause_points(text, &dir),
                Err(ScriptError::NotAReleaseScript)
            );
        }
        assert_eq!(
            insert_pause_points("echo hi\n", &dir),
            Err(ScriptError::NotAReleaseScript)
        );
    }
}
