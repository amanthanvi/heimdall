//! The HM1 output grammar of the remote scripts (ADR-0008 D5 §6.3; m03-plan §5 item
//! 21). **Frozen in wave 0** (m03-plan U0): the line forms, the key set, each key's
//! value shape, the bounds and the script exit codes. Later units change them only
//! through an ADR-0008 revision.
//!
//! Output is line-oriented, `HM1 <key>=<value>`. Values are decimal, a fixed token,
//! or lowercase hex (`od -An -v -tx1`), never raw bytes. The first line the client
//! reads is the ready line [`READY_LINE`], printed by the fixed remote command before
//! the script is sent; the first line of the script's own output is
//! [`VERSION_LINE`].
//!
//! **The parser** ([`parse`], U5) is strict: the output is bounded
//! ([`MAX_STDOUT_BYTES`]); its first line is exactly [`READY_LINE`] and its second
//! exactly [`VERSION_LINE`]; every later line is `HM1 <key>=<value>` with a key of
//! the frozen set (never `v` again) and a value of that key's shape; every line,
//! the last included, ends with `\n` (a cut line is refused, never read as a shorter
//! value); no `\r`, no other byte. [`handshake`] says how far a run got, for the
//! classification of a run that printed no version line.

use std::fmt;

/// The prefix of every HM1 line (with its separating space).
pub const LINE_PREFIX: &str = "HM1 ";

/// The ready line, printed by the fixed remote command
/// `printf 'HM1 ready\n'; exec /bin/sh -s` before the script is written.
pub const READY_LINE: &str = "HM1 ready";

/// The first line of every script's own output (the protocol version, `v=1`).
pub const VERSION_LINE: &str = "HM1 v=1";

/// The protocol version carried by [`Hm1Key::V`].
pub const VERSION: u32 = 1;

/// The bound on a step's stdout (ADR-0008 D5 §6.3; F25: one 1 MiB control frame
/// with its envelope).
pub const MAX_STDOUT_BYTES: usize = 512 * 1024;

/// The bound on a step's stderr as read by the client.
pub const MAX_STDERR_BYTES: usize = 64 * 1024;

/// The bound on the redacted stderr excerpt sent with a step result.
pub const STDERR_EXCERPT_BYTES: usize = 4 * 1024;

/// The bound on the registry content `inspect` reports as hex (exit 31 beyond it).
pub const MAX_CONTENT_BYTES: usize = 128 * 1024;

/// The shape of an HM1 value (ADR-0008 D5 §6.3 "Values are decimal, a fixed token,
/// or lowercase hex").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ValueShape {
    /// ASCII decimal digits, at least one (`0`..`9`); a leading `-` is never
    /// accepted.
    Decimal,
    /// Lowercase hex digit pairs (`od -An -v -tx1` with the spaces removed); may be
    /// empty (an empty file or path).
    Hex,
    /// Exactly one of the listed fixed tokens.
    Token(&'static [&'static str]),
    /// `yes` or `no`.
    Flag,
    /// A mode string from `ls -ldn`: the 10-character mode and an optional
    /// 11th indicator character (`+`, `@` or `.`; ACL, xattr or label).
    Mode,
    /// A lowercase snake_case word (`[a-z0-9_]+`): `status` and `reason`.
    Word,
    /// The lock's holder record, `hm1-<token>-<pid>-<start hex>-<boot hex>-<not_after>`
    /// (`[0-9a-z-]`, starting `hm1-`).
    HolderRecord,
    /// The signals `fence` sent: empty, `TERM` or `TERM,KILL`.
    Signals,
}

/// The tokens of [`Hm1Key::Dir`].
pub const DIR_TOKENS: &[&str] = &["present", "absent"];
/// The tokens of [`Hm1Key::File`].
pub const FILE_TOKENS: &[&str] = &["regular", "absent", "symlink", "other"];
/// The tokens of [`Hm1Key::Lock`].
pub const LOCK_TOKENS: &[&str] = &["none", "held"];
/// The tokens of [`Hm1Key::Fence`].
pub const FENCE_TOKENS: &[&str] = &["gone", "alive", "unproven", "none"];
/// The values of [`Hm1Key::FenceSignals`].
pub const SIGNAL_VALUES: &[&str] = &["", "TERM", "TERM,KILL"];

impl ValueShape {
    /// Whether `value` has this shape.
    #[must_use]
    pub fn accepts(self, value: &str) -> bool {
        let b = value.as_bytes();
        match self {
            ValueShape::Decimal => !b.is_empty() && b.iter().all(u8::is_ascii_digit),
            ValueShape::Hex => {
                b.len().is_multiple_of(2)
                    && b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
            }
            ValueShape::Token(tokens) => tokens.contains(&value),
            ValueShape::Flag => value == "yes" || value == "no",
            ValueShape::Mode => {
                (b.len() == 10 || b.len() == 11)
                    && b.iter()
                        .take(10)
                        .all(|c| c.is_ascii_alphabetic() || *c == b'-')
                    && (b.len() == 10 || matches!(b[10], b'+' | b'@' | b'.'))
            }
            ValueShape::Word => {
                !b.is_empty()
                    && b.iter()
                        .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_'))
            }
            ValueShape::HolderRecord => {
                value.starts_with("hm1-")
                    && b.iter()
                        .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'z' | b'-'))
            }
            ValueShape::Signals => SIGNAL_VALUES.contains(&value),
        }
    }
}

/// Every HM1 key (m03-plan §5 item 21; ADR-0008 D5 §6.3), with its wire name and
/// value shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Hm1Key {
    /// `v`: the protocol version (decimal, `1`).
    V,
    /// `path_hex`: the resolved registry path (hex).
    PathHex,
    /// `dir`: the registry's directory, `present` or `absent`.
    Dir,
    /// `dir_mode`: the directory's `ls -ldn` mode string.
    DirMode,
    /// `dir_owner_self`: the directory is owned by `id -u`.
    DirOwnerSelf,
    /// `file`: the registry file's kind, `regular`, `absent`, `symlink` or `other`.
    File,
    /// `links`: the file's link count (decimal).
    Links,
    /// `mode`: the file's `ls -ldn` mode string.
    Mode,
    /// `owner_self`: the file is owned by `id -u`.
    OwnerSelf,
    /// `size`: the file's size in bytes (decimal).
    Size,
    /// `last_byte_newline`: the file's last byte is `0a`.
    LastByteNewline,
    /// `marker_lines`: the number of lines containing the marker (decimal).
    MarkerLines,
    /// `content_hex`: the file's content (hex, at most [`MAX_CONTENT_BYTES`]).
    ContentHex,
    /// `status`: the script's status word.
    Status,
    /// `reason`: why the script refused (a word).
    Reason,
    /// `lock`: the registry lock, `none` or `held`.
    Lock,
    /// `lock_holder`: the holder record of a held lock.
    LockHolder,
    /// `remote_now`: the remote clock reading (decimal; M-F23).
    RemoteNow,
    /// `fence`: the fence decision, `gone`, `alive`, `unproven` or `none`.
    Fence,
    /// `start_identity`: the holder's (or the shell's) start identity (hex).
    StartIdentity,
    /// `boot_identity`: the target's boot identity (hex).
    BootIdentity,
    /// `pgid`: a process group (decimal).
    Pgid,
    /// `group_control`: the control `kill -s 0 -- -$$`'s exit status (decimal).
    GroupControl,
    /// `group_probe`: the probe `kill -s 0 -- -PGID`'s exit status (decimal).
    GroupProbe,
    /// `group_listed`: the listing `ps -A -o pgid=` lists the target group.
    GroupListed,
    /// `fence_signals`: the signals already sent (empty, `TERM`, `TERM,KILL`).
    FenceSignals,
}

impl Hm1Key {
    /// Every key, in the order of m03-plan §5 item 21.
    pub const ALL: [Hm1Key; 26] = [
        Hm1Key::V,
        Hm1Key::PathHex,
        Hm1Key::Dir,
        Hm1Key::DirMode,
        Hm1Key::DirOwnerSelf,
        Hm1Key::File,
        Hm1Key::Links,
        Hm1Key::Mode,
        Hm1Key::OwnerSelf,
        Hm1Key::Size,
        Hm1Key::LastByteNewline,
        Hm1Key::MarkerLines,
        Hm1Key::ContentHex,
        Hm1Key::Status,
        Hm1Key::Reason,
        Hm1Key::Lock,
        Hm1Key::LockHolder,
        Hm1Key::RemoteNow,
        Hm1Key::Fence,
        Hm1Key::StartIdentity,
        Hm1Key::BootIdentity,
        Hm1Key::Pgid,
        Hm1Key::GroupControl,
        Hm1Key::GroupProbe,
        Hm1Key::GroupListed,
        Hm1Key::FenceSignals,
    ];

    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Hm1Key::V => "v",
            Hm1Key::PathHex => "path_hex",
            Hm1Key::Dir => "dir",
            Hm1Key::DirMode => "dir_mode",
            Hm1Key::DirOwnerSelf => "dir_owner_self",
            Hm1Key::File => "file",
            Hm1Key::Links => "links",
            Hm1Key::Mode => "mode",
            Hm1Key::OwnerSelf => "owner_self",
            Hm1Key::Size => "size",
            Hm1Key::LastByteNewline => "last_byte_newline",
            Hm1Key::MarkerLines => "marker_lines",
            Hm1Key::ContentHex => "content_hex",
            Hm1Key::Status => "status",
            Hm1Key::Reason => "reason",
            Hm1Key::Lock => "lock",
            Hm1Key::LockHolder => "lock_holder",
            Hm1Key::RemoteNow => "remote_now",
            Hm1Key::Fence => "fence",
            Hm1Key::StartIdentity => "start_identity",
            Hm1Key::BootIdentity => "boot_identity",
            Hm1Key::Pgid => "pgid",
            Hm1Key::GroupControl => "group_control",
            Hm1Key::GroupProbe => "group_probe",
            Hm1Key::GroupListed => "group_listed",
            Hm1Key::FenceSignals => "fence_signals",
        }
    }

    /// The key with wire name `name`, if any.
    #[must_use]
    pub fn from_wire(name: &str) -> Option<Hm1Key> {
        Hm1Key::ALL.into_iter().find(|k| k.as_str() == name)
    }

    /// The value shape of this key.
    #[must_use]
    pub fn shape(self) -> ValueShape {
        match self {
            Hm1Key::V
            | Hm1Key::Links
            | Hm1Key::Size
            | Hm1Key::MarkerLines
            | Hm1Key::RemoteNow
            | Hm1Key::Pgid
            | Hm1Key::GroupControl
            | Hm1Key::GroupProbe => ValueShape::Decimal,
            Hm1Key::PathHex | Hm1Key::ContentHex | Hm1Key::StartIdentity | Hm1Key::BootIdentity => {
                ValueShape::Hex
            }
            Hm1Key::Dir => ValueShape::Token(DIR_TOKENS),
            Hm1Key::File => ValueShape::Token(FILE_TOKENS),
            Hm1Key::Lock => ValueShape::Token(LOCK_TOKENS),
            Hm1Key::Fence => ValueShape::Token(FENCE_TOKENS),
            Hm1Key::DirOwnerSelf
            | Hm1Key::OwnerSelf
            | Hm1Key::LastByteNewline
            | Hm1Key::GroupListed => ValueShape::Flag,
            Hm1Key::DirMode | Hm1Key::Mode => ValueShape::Mode,
            Hm1Key::Status | Hm1Key::Reason => ValueShape::Word,
            Hm1Key::LockHolder => ValueShape::HolderRecord,
            Hm1Key::FenceSignals => ValueShape::Signals,
        }
    }
}

impl fmt::Display for Hm1Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The script exit codes (ADR-0008 D5 §6.3 script table; m03-plan §5 item 21). The
/// meaning of some codes depends on the stage; [`ExitCode::from_status`] maps a raw
/// status, and anything not listed is unknown (the classification treats it as
/// uncertain for a mutating stage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ExitCode {
    /// 0: ok / written / renamed / created; `fence`: `gone` (link removed) or `none`.
    Ok,
    /// 10: `append`: the marker is already present (nothing written).
    AlreadyPresent,
    /// 11: `bootstrap`: the directory is already present (checked).
    BootstrapAlreadyPresent,
    /// 20: `remove`: the registry changed since it was read (nothing renamed).
    ChangedSinceRead,
    /// 30: not manageable (the output says why), including
    /// `start_identity_unavailable`.
    NotManageable,
    /// 31: the registry is too large.
    TooLarge,
    /// 32: the registry's directory is absent (`append`, `remove`).
    DirAbsent,
    /// 33: `bootstrap`: the parent is absent; `append`, `remove`, `fence`: the shell
    /// is not its own process-group leader (`no_process_group`).
    ParentAbsentOrNoProcessGroup,
    /// 40: busy (a lock exists, whoever holds it).
    Busy,
    /// 41: the step's remote not-after has passed.
    NotAfterPassed,
    /// 42: the lock was lost before the write.
    LockLost,
    /// 43: `fence`: the holder is alive (nothing removed).
    HolderAlive,
    /// 44: `fence`: unproven. No unlock and no further signal; any signal already
    /// sent is reported in `fence_signals`.
    Unproven,
    /// 255: from `ssh` itself (connection, authentication, host trust).
    Ssh,
}

impl ExitCode {
    /// Every code, ascending.
    pub const ALL: [ExitCode; 14] = [
        ExitCode::Ok,
        ExitCode::AlreadyPresent,
        ExitCode::BootstrapAlreadyPresent,
        ExitCode::ChangedSinceRead,
        ExitCode::NotManageable,
        ExitCode::TooLarge,
        ExitCode::DirAbsent,
        ExitCode::ParentAbsentOrNoProcessGroup,
        ExitCode::Busy,
        ExitCode::NotAfterPassed,
        ExitCode::LockLost,
        ExitCode::HolderAlive,
        ExitCode::Unproven,
        ExitCode::Ssh,
    ];

    /// The numeric status.
    #[must_use]
    pub fn status(self) -> i32 {
        match self {
            ExitCode::Ok => 0,
            ExitCode::AlreadyPresent => 10,
            ExitCode::BootstrapAlreadyPresent => 11,
            ExitCode::ChangedSinceRead => 20,
            ExitCode::NotManageable => 30,
            ExitCode::TooLarge => 31,
            ExitCode::DirAbsent => 32,
            ExitCode::ParentAbsentOrNoProcessGroup => 33,
            ExitCode::Busy => 40,
            ExitCode::NotAfterPassed => 41,
            ExitCode::LockLost => 42,
            ExitCode::HolderAlive => 43,
            ExitCode::Unproven => 44,
            ExitCode::Ssh => 255,
        }
    }

    /// The code with numeric status `status`, if it is one of the protocol's.
    #[must_use]
    pub fn from_status(status: i32) -> Option<ExitCode> {
        ExitCode::ALL.into_iter().find(|c| c.status() == status)
    }
}

/// One parsed script output: the HM1 key/value pairs after [`VERSION_LINE`], in
/// output order (a key may repeat).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hm1Record {
    /// The pairs, in output order.
    pub fields: Vec<(Hm1Key, String)>,
}

impl Hm1Record {
    /// The first value of `key`, if present.
    #[must_use]
    pub fn get(&self, key: Hm1Key) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Every value of `key`, in output order.
    pub fn all(&self, key: Hm1Key) -> impl Iterator<Item = &str> {
        self.fields
            .iter()
            .filter(move |(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Why script output was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The parser is not in this build (wave 0; U5 fills it). Fail closed: no output
    /// is ever read as applied.
    #[error("the HM1 parser is not available in this build")]
    Unavailable,
    /// The output exceeds [`MAX_STDOUT_BYTES`].
    #[error("the output exceeds the HM1 bound")]
    TooLarge,
    /// The first line is not [`READY_LINE`] (`registry_unsupported`).
    #[error("the output does not start with the ready line")]
    NoReadyLine,
    /// The script's first line is not [`VERSION_LINE`] (`registry_unsupported`).
    #[error("the script output does not start with the version line")]
    NoVersionLine,
    /// A line is not `HM1 <key>=<value>` with a known key and a value of its shape.
    #[error("malformed HM1 line {line}")]
    Malformed {
        /// The 1-based line number.
        line: usize,
    },
}

/// How far a run's output got (ADR-0008 D5 §6.3 "the ready handshake").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Handshake {
    /// The first line is not [`READY_LINE`]: the CLI never sent the script.
    NoReady,
    /// [`READY_LINE`] only: the script was sent, but its first line,
    /// [`VERSION_LINE`], never arrived.
    Ready,
    /// Both lines arrived: the script ran.
    Versioned,
}

const READY_WITH_NL: &[u8] = b"HM1 ready\n";
const VERSION_WITH_NL: &[u8] = b"HM1 v=1\n";

/// How far `stdout` got, read from its first two lines only (whatever its length).
#[must_use]
pub fn handshake(stdout: &[u8]) -> Handshake {
    let Some(rest) = stdout.strip_prefix(READY_WITH_NL) else {
        return Handshake::NoReady;
    };
    if rest.starts_with(VERSION_WITH_NL) {
        Handshake::Versioned
    } else {
        Handshake::Ready
    }
}

/// Parse a step's stdout: bounded ([`MAX_STDOUT_BYTES`]), first line
/// [`READY_LINE`], then [`VERSION_LINE`], then `HM1 <key>=<value>` lines (module
/// docs for the rules). The record holds the pairs after the version line.
///
/// # Errors
/// [`ParseError::TooLarge`] beyond the bound; [`ParseError::NoReadyLine`] and
/// [`ParseError::NoVersionLine`] for the first two lines; [`ParseError::Malformed`]
/// (1-based line) for anything else.
pub fn parse(stdout: &[u8]) -> Result<Hm1Record, ParseError> {
    if stdout.len() > MAX_STDOUT_BYTES {
        return Err(ParseError::TooLarge);
    }
    let mut lines = stdout.split_inclusive(|b| *b == b'\n');
    if lines.next() != Some(READY_WITH_NL) {
        return Err(ParseError::NoReadyLine);
    }
    if lines.next() != Some(VERSION_WITH_NL) {
        return Err(ParseError::NoVersionLine);
    }
    let mut fields = Vec::new();
    for (index, raw) in lines.enumerate() {
        let line = index + 3;
        let malformed = ParseError::Malformed { line };
        let pair = raw
            .strip_suffix(b"\n")
            .and_then(|body| std::str::from_utf8(body).ok())
            .and_then(|text| text.strip_prefix(LINE_PREFIX))
            .and_then(|rest| rest.split_once('='))
            .and_then(|(name, value)| Hm1Key::from_wire(name).map(|k| (k, value)));
        let Some((key, value)) = pair else {
            return Err(malformed);
        };
        let bounded = key != Hm1Key::ContentHex || value.len() <= 2 * MAX_CONTENT_BYTES;
        if key == Hm1Key::V || !bounded || !key.shape().accepts(value) {
            return Err(malformed);
        }
        fields.push((key, value.to_owned()));
    }
    Ok(Hm1Record { fields })
}

/// Decode an HM1 hex value (lowercase pairs, as [`ValueShape::Hex`] accepts).
#[must_use]
pub fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !ValueShape::Hex.accepts(value) {
        return None;
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

/// Encode bytes as an HM1 hex value (lowercase pairs, `od -An -v -tx1` without the
/// spaces).
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A key that a reading needs at most once appeared again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("HM1 key {0} repeats")]
pub struct DuplicateKey(pub Hm1Key);

impl Hm1Record {
    /// The single value of `key`: `Ok(None)` when absent.
    ///
    /// # Errors
    /// [`DuplicateKey`] when `key` appears more than once.
    pub fn single(&self, key: Hm1Key) -> Result<Option<&str>, DuplicateKey> {
        let mut values = self.all(key);
        let first = values.next();
        if values.next().is_some() {
            return Err(DuplicateKey(key));
        }
        Ok(first)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn hm1_key_set_is_the_frozen_grammar() {
        let names: Vec<&str> = Hm1Key::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(
            names,
            [
                "v",
                "path_hex",
                "dir",
                "dir_mode",
                "dir_owner_self",
                "file",
                "links",
                "mode",
                "owner_self",
                "size",
                "last_byte_newline",
                "marker_lines",
                "content_hex",
                "status",
                "reason",
                "lock",
                "lock_holder",
                "remote_now",
                "fence",
                "start_identity",
                "boot_identity",
                "pgid",
                "group_control",
                "group_probe",
                "group_listed",
                "fence_signals",
            ]
        );
        let unique: BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len());
        for k in Hm1Key::ALL {
            assert_eq!(Hm1Key::from_wire(k.as_str()), Some(k));
        }
        assert_eq!(Hm1Key::from_wire("V"), None);
    }

    #[test]
    fn exit_codes_are_the_frozen_set() {
        let codes: Vec<i32> = ExitCode::ALL.iter().map(|c| c.status()).collect();
        assert_eq!(
            codes,
            [0, 10, 11, 20, 30, 31, 32, 33, 40, 41, 42, 43, 44, 255]
        );
        for c in ExitCode::ALL {
            assert_eq!(ExitCode::from_status(c.status()), Some(c));
        }
        for unknown in [1, 2, 12, 34, 45, 127, 254, -1] {
            assert_eq!(ExitCode::from_status(unknown), None);
        }
    }

    #[test]
    fn value_shapes_accept_and_refuse() {
        assert!(Hm1Key::V.shape().accepts("1"));
        assert!(!Hm1Key::Size.shape().accepts("-1"));
        assert!(!Hm1Key::Size.shape().accepts(""));
        assert!(Hm1Key::ContentHex.shape().accepts(""));
        assert!(Hm1Key::ContentHex.shape().accepts("0a41"));
        assert!(!Hm1Key::ContentHex.shape().accepts("0A"));
        assert!(!Hm1Key::ContentHex.shape().accepts("0"));
        assert!(Hm1Key::Fence.shape().accepts("unproven"));
        assert!(!Hm1Key::Fence.shape().accepts("dead"));
        assert!(Hm1Key::Mode.shape().accepts("-rw-------"));
        assert!(Hm1Key::DirMode.shape().accepts("drwx------+"));
        assert!(!Hm1Key::Mode.shape().accepts("-rw-------x"));
        assert!(Hm1Key::OwnerSelf.shape().accepts("yes"));
        assert!(!Hm1Key::OwnerSelf.shape().accepts("1"));
        assert!(Hm1Key::FenceSignals.shape().accepts(""));
        assert!(Hm1Key::FenceSignals.shape().accepts("TERM,KILL"));
        assert!(!Hm1Key::FenceSignals.shape().accepts("KILL"));
        assert!(
            Hm1Key::LockHolder
                .shape()
                .accepts("hm1-0f-12-ab-cd-1700000000")
        );
        assert!(!Hm1Key::LockHolder.shape().accepts("hm1-0F"));
        assert!(Hm1Key::Reason.shape().accepts("registry_unsupported"));
        assert!(!Hm1Key::Reason.shape().accepts("bad reason"));
    }

    #[test]
    fn parse_is_strict() {
        let ok = format!("{READY_LINE}\n{VERSION_LINE}\nHM1 status=ok\nHM1 size=3\n");
        let rec = parse(ok.as_bytes()).unwrap();
        assert_eq!(rec.get(Hm1Key::Status), Some("ok"));
        assert_eq!(rec.single(Hm1Key::Size), Ok(Some("3")));
        assert_eq!(parse(b""), Err(ParseError::NoReadyLine));
        assert_eq!(parse(b"motd\nHM1 ready\n"), Err(ParseError::NoReadyLine));
        assert_eq!(parse(b"HM1 ready\n"), Err(ParseError::NoVersionLine));
        assert_eq!(
            parse(b"HM1 ready\nHM1 v=2\n"),
            Err(ParseError::NoVersionLine)
        );
        for bad in [
            "HM1 status=ok",     // no final newline
            "HM1 status=ok\r\n", // CR
            "HM1 nope=1\n",      // unknown key
            "HM1 size=-1\n",     // shape
            "HM1 v=1\n",         // version again
            "status=ok\n",       // no prefix
            "HM1 status\n",      // no value
        ] {
            let text = format!("HM1 ready\nHM1 v=1\n{bad}");
            assert_eq!(
                parse(text.as_bytes()),
                Err(ParseError::Malformed { line: 3 }),
                "{bad:?}"
            );
        }
        let big = vec![b'a'; MAX_STDOUT_BYTES + 1];
        assert_eq!(parse(&big), Err(ParseError::TooLarge));
        assert_eq!(handshake(b"HM1 ready\nHM1 v=1\nx"), Handshake::Versioned);
        assert_eq!(handshake(b"HM1 ready\n"), Handshake::Ready);
        assert_eq!(handshake(b"HM1 read"), Handshake::NoReady);
        assert_eq!(decode_hex("0a41"), Some(vec![0x0a, 0x41]));
        assert_eq!(decode_hex("0A"), None);
        assert_eq!(encode_hex(&[0, 255]), "00ff");
    }
}
