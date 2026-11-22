//! The management line and the authorized_keys port (ADR-0012 §3.2 "Rendering", §3.5,
//! §3.9 item 6; M06 U1).
//!
//! **The line** is
//! `restrict,command="exec \"<abs heimdall>\" remote serve --client <cid> --home \"<abs>\""[,expiry-time="YYYYMMDDHHMMSSZ"] <K_mgmt.pub> heimdall-mgmt:<cid>`,
//! built only from validated parts ([`ManagementLine::render`]):
//! * both paths are absolute, normalized and from `[A-Za-z0-9/._+-]` ([`check_abs_path`]):
//!   no shell metacharacter, no quote, no space, no `.` or `..` component;
//! * the client ID is from `[A-Za-z0-9_]` (the runner mints `cl_<32 hex>`);
//! * the key is one Ed25519 public key, `ssh-ed25519 <base64>` with its wire blob checked
//!   ([`PublicKeyText::parse`]); K_mgmt is Ed25519 (ADR-0012 §3.4), and any other type is
//!   refused rather than guessed at;
//! * `expiry-time` is the UTC form with the `Z` suffix (OpenSSH 8.7 and later read it as
//!   UTC; an older sshd rejects the line, which fails closed), rounded **down** to the
//!   second, so the backstop is never later than the record's deadline.
//!
//! The whole line is then checked against [`LINE_CHARSET`].
//!
//! **The port.** [`ManagementLines`] is how the runner reads every authorized_keys file and
//! adds, rewrites or removes the one line marked `heimdall-mgmt:<cid>`. Its production
//! implementation (W2) reuses ADR-0005 §3.3's add/remove procedure: a local edit that
//! preserves the user's own lines byte for byte. This crate may not depend on
//! `heimdall-enroll` (the crate-graph rule), so the trait lives here, with an in-memory
//! implementation for tests ([`crate::testing::MemoryLines`]).
//!
//! **Uniqueness** ([`key_already_authorized`]): a key present under any line other than its
//! own, in any authorized_keys file sshd consults, is refused (`key_already_authorized`).
//! A key's identity is its decoded wire blob, so options, comments and base64 padding do
//! not hide a duplicate.

use base64ct::{Base64, Base64Unpadded, Encoding as _};
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{ClientId, KeyFingerprint};
use sha2::{Digest as _, Sha256};

/// The comment prefix that marks a management line (`heimdall-mgmt:<cid>`).
pub const MARKER_PREFIX: &str = "heimdall-mgmt:";

/// Every character a rendered management line may contain: the path, ID, key and option
/// characters, the option quote and the backslash that escapes it inside `command="…"`.
pub const LINE_CHARSET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=,:\" ._-\\";

/// The longest path the line accepts.
pub const MAX_PATH_BYTES: usize = 1024;

/// The only key type K_mgmt may have (ADR-0012 §3.4).
pub const KEY_TYPE_ED25519: &str = "ssh-ed25519";

/// Why a line was not built or a key not accepted. Fixed messages: never the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LineError {
    /// A path is not absolute, not normalized, too long, or outside `[A-Za-z0-9/._+-]`.
    #[error("a path for the management line is not an absolute path from the permitted set")]
    Path,
    /// The client ID is outside `[A-Za-z0-9_]`.
    #[error("the client ID is outside the management line's character set")]
    Client,
    /// The public key is not one well-formed Ed25519 OpenSSH public key.
    #[error("the public key is not a well-formed Ed25519 OpenSSH public key")]
    Key,
    /// The rendered line has a character outside [`LINE_CHARSET`].
    #[error("the management line has a character outside the permitted set")]
    Charset,
    /// The deadline is outside the range `expiry-time` can carry.
    #[error("the expiry time is out of range")]
    Expiry,
}

/// Whether `p` is an absolute, normalized path from `[A-Za-z0-9/._+-]` of at most
/// [`MAX_PATH_BYTES`] bytes: no empty, `.` or `..` component and no trailing `/`.
///
/// # Errors
///
/// [`LineError::Path`].
pub fn check_abs_path(p: &str) -> Result<(), LineError> {
    let ok = p.len() > 1
        && p.len() <= MAX_PATH_BYTES
        && p.starts_with('/')
        && !p.ends_with('/')
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'+' | b'-'))
        && p[1..]
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..");
    if ok { Ok(()) } else { Err(LineError::Path) }
}

fn check_client(client: &ClientId) -> Result<(), LineError> {
    let s = client.as_str();
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        Ok(())
    } else {
        Err(LineError::Client)
    }
}

/// The marker comment of a client's line, `heimdall-mgmt:<cid>`.
#[must_use]
pub fn marker(client: &ClientId) -> String {
    format!("{MARKER_PREFIX}{}", client.as_str())
}

/// The forced command's two paths (ADR-0012 §3.2 "Rendering"), validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeCommand {
    heimdall: String,
    home: String,
}

impl ServeCommand {
    /// Validate the absolute path of the `heimdall` binary and of the Heimdall home.
    ///
    /// # Errors
    ///
    /// [`LineError::Path`] for either path.
    pub fn new(heimdall: &str, home: &str) -> Result<Self, LineError> {
        check_abs_path(heimdall)?;
        check_abs_path(home)?;
        Ok(Self {
            heimdall: heimdall.to_owned(),
            home: home.to_owned(),
        })
    }

    /// The `heimdall` binary.
    #[must_use]
    pub fn heimdall(&self) -> &str {
        &self.heimdall
    }

    /// The Heimdall home.
    #[must_use]
    pub fn home(&self) -> &str {
        &self.home
    }

    /// The command text sshd runs: `exec "<heimdall>" remote serve --client <cid> --home
    /// "<home>"` (unescaped; [`ManagementLine::render`] escapes its quotes).
    ///
    /// # Errors
    ///
    /// [`LineError::Client`].
    pub fn command(&self, client: &ClientId) -> Result<String, LineError> {
        check_client(client)?;
        Ok(format!(
            "exec \"{}\" remote serve --client {} --home \"{}\"",
            self.heimdall,
            client.as_str(),
            self.home
        ))
    }
}

/// One Ed25519 OpenSSH public key, `ssh-ed25519 <base64>`, with its decoded wire blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyText {
    base64: String,
    blob: Vec<u8>,
}

/// The wire blob of an Ed25519 public key: `string "ssh-ed25519"` then `string key[32]`.
const ED25519_BLOB_LEN: usize = 4 + 11 + 4 + 32;

impl PublicKeyText {
    /// Parse `ssh-ed25519 <base64>[ <comment>]` (the comment is dropped). The blob must be
    /// exactly an Ed25519 public key whose embedded type matches.
    ///
    /// # Errors
    ///
    /// [`LineError::Key`].
    pub fn parse(text: &str) -> Result<Self, LineError> {
        let mut parts = text.split_ascii_whitespace();
        let (Some(kind), Some(b64)) = (parts.next(), parts.next()) else {
            return Err(LineError::Key);
        };
        if kind != KEY_TYPE_ED25519 || b64.len() > 128 {
            return Err(LineError::Key);
        }
        let blob = decode_blob(b64).ok_or(LineError::Key)?;
        let mut expected = Vec::with_capacity(ED25519_BLOB_LEN);
        expected.extend_from_slice(&11u32.to_be_bytes());
        expected.extend_from_slice(KEY_TYPE_ED25519.as_bytes());
        expected.extend_from_slice(&32u32.to_be_bytes());
        if blob.len() != ED25519_BLOB_LEN || blob[..19] != expected[..] {
            return Err(LineError::Key);
        }
        Ok(Self {
            base64: Base64::encode_string(&blob),
            blob,
        })
    }

    /// `ssh-ed25519 <canonical padded base64>`, no comment.
    #[must_use]
    pub fn openssh(&self) -> String {
        format!("{KEY_TYPE_ED25519} {}", self.base64)
    }

    /// The decoded wire blob.
    #[must_use]
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// The key's fingerprint, `SHA256:` and the unpadded base64 of the blob's SHA-256, as
    /// `ssh-keygen -l` prints it.
    #[must_use]
    pub fn fingerprint(&self) -> KeyFingerprint {
        fingerprint_of_blob(&self.blob)
    }
}

/// `SHA256:<unpadded base64 of sha256(blob)>` for any key blob.
#[must_use]
pub fn fingerprint_of_blob(blob: &[u8]) -> KeyFingerprint {
    let digest = Sha256::digest(blob);
    let text = format!("SHA256:{}", Base64Unpadded::encode_string(&digest));
    // 32 digest bytes always encode to 43 unpadded characters: the rule holds by
    // construction, so a parse failure here is impossible.
    KeyFingerprint::parse(&text).unwrap_or_else(|_| unreachable_fingerprint())
}

/// Never reached (see [`fingerprint_of_blob`]): 32 digest bytes always encode to a valid
/// fingerprint.
#[cold]
#[allow(clippy::expect_used)]
fn unreachable_fingerprint() -> KeyFingerprint {
    KeyFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).expect("the fixed form is valid")
}

/// Decode a base64 key blob, padded or not. `None` when it is not base64.
fn decode_blob(b64: &str) -> Option<Vec<u8>> {
    if b64.is_empty()
        || !b64
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    {
        return None;
    }
    Base64Unpadded::decode_vec(b64.trim_end_matches('=')).ok()
}

/// The `expiry-time` value for `t`: UTC, rounded down to the second, `YYYYMMDDHHMMSSZ`.
///
/// # Errors
///
/// [`LineError::Expiry`] for a year outside 1970..=9999.
pub fn expiry_time(t: Timestamp) -> Result<String, LineError> {
    let dt = jiff::tz::Offset::UTC.to_datetime(t);
    if !(1970..=9999).contains(&dt.year()) {
        return Err(LineError::Expiry);
    }
    Ok(format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    ))
}

/// A management line, ready to render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementLine {
    /// The client the line names.
    pub client: ClientId,
    /// The forced command's paths.
    pub command: ServeCommand,
    /// The receiving key.
    pub key: PublicKeyText,
    /// The pending invitation's deadline (`expiry-time`); `None` once active.
    pub expiry: Option<Timestamp>,
}

impl ManagementLine {
    /// Render the line (module docs), checking every character against [`LINE_CHARSET`].
    ///
    /// # Errors
    ///
    /// [`LineError`] for an invalid part or character.
    pub fn render(&self) -> Result<String, LineError> {
        let command = self.command.command(&self.client)?.replace('"', "\\\"");
        let mut line = format!("restrict,command=\"{command}\"");
        if let Some(t) = self.expiry {
            line.push_str(&format!(",expiry-time=\"{}\"", expiry_time(t)?));
        }
        line.push(' ');
        line.push_str(&self.key.openssh());
        line.push(' ');
        line.push_str(&marker(&self.client));
        if line.chars().all(|c| LINE_CHARSET.contains(c)) {
            Ok(line)
        } else {
            Err(LineError::Charset)
        }
    }
}

/// One parsed authorized_keys line: its options (if any), key type, key blob and comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLine<'a> {
    /// The options field, when present.
    pub options: Option<&'a str>,
    /// The key type token.
    pub key_type: &'a str,
    /// The decoded key blob.
    pub blob: Vec<u8>,
    /// The comment (trimmed; empty when absent).
    pub comment: &'a str,
}

impl KeyLine<'_> {
    /// Whether this line is a client's management line (its comment is exactly the
    /// client's marker).
    #[must_use]
    pub fn is_marked_for(&self, client: &ClientId) -> bool {
        self.comment == marker(client)
    }

    /// The fingerprint of the line's key.
    #[must_use]
    pub fn fingerprint(&self) -> KeyFingerprint {
        fingerprint_of_blob(&self.blob)
    }
}

fn looks_like_key_type(t: &str) -> bool {
    (t.starts_with("ssh-") || t.starts_with("ecdsa-") || t.starts_with("sk-"))
        && t.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.' | b'@')
        })
}

/// Split `s` at the end of its options field: unquoted whitespace ends it; inside quotes a
/// backslash escapes the next character. `None` when a quote is left open.
fn split_options(s: &str) -> Option<(&str, &str)> {
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => return Some((&s[..i], &s[i..])),
            _ => {}
        }
    }
    None
}

fn key_and_comment(rest: &str) -> Option<(&str, Vec<u8>, &str)> {
    let rest = rest.trim_start_matches([' ', '\t']);
    let (key_type, after) = rest.split_once([' ', '\t'])?;
    if !looks_like_key_type(key_type) {
        return None;
    }
    let after = after.trim_start_matches([' ', '\t']);
    let (b64, comment) = after.split_once([' ', '\t']).unwrap_or((after, ""));
    let blob = decode_blob(b64)?;
    Some((key_type, blob, comment.trim_matches([' ', '\t', '\r'])))
}

/// Parse one authorized_keys line as sshd would: a key at the start, or an options field
/// then a key. `None` for a blank line, a comment, or a line with no parseable key (sshd
/// ignores such a line too).
#[must_use]
pub fn parse_key_line(line: &str) -> Option<KeyLine<'_>> {
    let s = line
        .trim_start_matches([' ', '\t'])
        .trim_end_matches(['\r', '\n']);
    if s.is_empty() || s.starts_with('#') {
        return None;
    }
    if let Some((key_type, blob, comment)) = key_and_comment(s) {
        return Some(KeyLine {
            options: None,
            key_type,
            blob,
            comment,
        });
    }
    let (options, rest) = split_options(s)?;
    let (key_type, blob, comment) = key_and_comment(rest)?;
    Some(KeyLine {
        options: Some(options),
        key_type,
        blob,
        comment,
    })
}

/// One authorized_keys file as the port read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysFile {
    /// A display name (never shown with content).
    pub name: String,
    /// Its text.
    pub text: String,
}

/// Every parsed line of every file.
fn lines_of(files: &[KeysFile]) -> impl Iterator<Item = KeyLine<'_>> {
    files
        .iter()
        .flat_map(|f| f.text.lines())
        .filter_map(parse_key_line)
}

/// Whether `blob` is authorized under any line other than `own`'s management line, in any
/// file (ADR-0012 §3.5 "Uniqueness"; `key_already_authorized`). ⟨Reading 16⟩ The files are
/// this runner account's (the port's); the role-table half of the uniqueness is the
/// store's, per runner ([`heimdall_store::ext_m06`]).
#[must_use]
pub fn key_already_authorized(files: &[KeysFile], blob: &[u8], own: Option<&ClientId>) -> bool {
    lines_of(files).any(|l| l.blob == blob && !own.is_some_and(|c| l.is_marked_for(c)))
}

/// The key fingerprint on `client`'s line, when there is exactly one line marked for it
/// across every file **and** its key is authorized under no other line (ADR-0012 §3.9
/// items 3 and 5: "the key fingerprint on the cid's line"). Anything else is `None`: a
/// missing, duplicated or shadowed line identifies nobody.
#[must_use]
pub fn line_fingerprint(files: &[KeysFile], client: &ClientId) -> Option<KeyFingerprint> {
    let mut own = lines_of(files).filter(|l| l.is_marked_for(client));
    let line = own.next()?;
    if own.next().is_some() || key_already_authorized(files, &line.blob, Some(client)) {
        return None;
    }
    Some(line.fingerprint())
}

/// The text of every line marked for `client`, in file order.
#[must_use]
pub fn marked_lines(files: &[KeysFile], client: &ClientId) -> Vec<String> {
    files
        .iter()
        .flat_map(|f| f.text.lines())
        .filter(|raw| parse_key_line(raw).is_some_and(|l| l.is_marked_for(client)))
        .map(|raw| raw.trim_end_matches(['\r', '\n']).to_owned())
        .collect()
}

/// Why the port failed. Fixed messages, never a path or content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LineIoError {
    /// No writer is wired in this build or for this account.
    #[error("the authorized_keys writer is not available")]
    Unavailable,
    /// Reading or writing an authorized_keys file failed.
    #[error("an authorized_keys file could not be read or written")]
    Io,
    /// A file changed under the edit (the procedure's compare step failed).
    #[error("an authorized_keys file changed during the edit")]
    Changed,
}

/// The runner's authorized_keys port (module docs). Implementations preserve every line
/// they do not own byte for byte and are idempotent.
pub trait ManagementLines: Send + Sync {
    /// Every authorized_keys file sshd consults for the account (the verified policy's
    /// list, or sshd's default list on an owner-only runner), in order.
    ///
    /// # Errors
    ///
    /// [`LineIoError`].
    fn read_all(&self) -> Result<Vec<KeysFile>, LineIoError>;

    /// Make the file Heimdall writes hold exactly one line marked for `client`, equal to
    /// `line`, and no file hold another line marked for it.
    ///
    /// # Errors
    ///
    /// [`LineIoError`].
    fn put(&self, client: &ClientId, line: &str) -> Result<(), LineIoError>;

    /// Remove every line marked for `client` from every file Heimdall writes.
    ///
    /// # Errors
    ///
    /// [`LineIoError`].
    fn remove(&self, client: &ClientId) -> Result<(), LineIoError>;
}

/// What the file should hold for one client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesiredLine {
    /// No line.
    Absent,
    /// Exactly this line.
    Present(String),
}

/// Make the files match `desired` for `client`, idempotently: read, compare, and write only
/// on a difference. Returns whether a write happened.
///
/// # Errors
///
/// [`LineIoError`] from the port; nothing is assumed written then.
pub fn reconcile_line(
    port: &dyn ManagementLines,
    client: &ClientId,
    desired: &DesiredLine,
) -> Result<bool, LineIoError> {
    let files = port.read_all()?;
    let have = marked_lines(&files, client);
    match desired {
        DesiredLine::Absent if have.is_empty() => Ok(false),
        DesiredLine::Absent => port.remove(client).map(|()| true),
        DesiredLine::Present(line) if have.len() == 1 && &have[0] == line => Ok(false),
        DesiredLine::Present(line) => port.put(client, line).map(|()| true),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    pub(crate) fn key(n: u8) -> String {
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[n; 32]);
        format!("ssh-ed25519 {}", Base64::encode_string(&blob))
    }

    fn cid(n: u8) -> ClientId {
        ClientId::from_random_bytes([n; 16])
    }

    #[test]
    fn renders_the_exact_line_and_checks_the_charset() {
        let cmd = ServeCommand::new("/opt/heimdall/bin/heimdall", "/srv/runner/heimdall").unwrap();
        let k = PublicKeyText::parse(&key(1)).unwrap();
        let line = ManagementLine {
            client: cid(0xab),
            command: cmd.clone(),
            key: k.clone(),
            expiry: Some("2026-11-20T10:15:00.9Z".parse().unwrap()),
        }
        .render()
        .unwrap();
        let c = cid(0xab);
        assert_eq!(
            line,
            format!(
                "restrict,command=\"exec \\\"/opt/heimdall/bin/heimdall\\\" remote serve --client {c} --home \\\"/srv/runner/heimdall\\\"\",expiry-time=\"20261120101500Z\" {} heimdall-mgmt:{c}",
                k.openssh()
            )
        );
        let parsed = parse_key_line(&line).unwrap();
        assert!(parsed.is_marked_for(&c));
        assert_eq!(parsed.fingerprint(), k.fingerprint());
        let active = ManagementLine {
            client: c.clone(),
            command: cmd,
            key: k,
            expiry: None,
        }
        .render()
        .unwrap();
        assert!(!active.contains("expiry-time"));
    }

    #[test]
    fn paths_and_keys_outside_the_set_are_refused() {
        for bad in [
            "relative/heimdall",
            "/",
            "/a//b",
            "/a/./b",
            "/a/../b",
            "/a/b/",
            "/a b",
            "/a\"b",
            "/a;b",
            "/a$b",
            "/a`b",
            "/a\\b",
            "/a\nb",
        ] {
            assert_eq!(
                ServeCommand::new(bad, "/h").unwrap_err(),
                LineError::Path,
                "{bad:?}"
            );
        }
        assert!(PublicKeyText::parse("ssh-rsa AAAAB3NzaC1yc2E").is_err());
        assert!(PublicKeyText::parse("ssh-ed25519 not*base64").is_err());
        // An Ed25519 type label over a blob that is not an Ed25519 key.
        let short = format!("ssh-ed25519 {}", Base64::encode_string(b"abc"));
        assert!(PublicKeyText::parse(&short).is_err());
    }

    #[test]
    fn parser_and_uniqueness_see_through_options_comments_and_padding() {
        let k1 = PublicKeyText::parse(&key(1)).unwrap();
        let unpadded = key(1).trim_end_matches('=').to_owned();
        let files = vec![
            KeysFile {
                name: "a".into(),
                text: format!(
                    "# a comment\n\ncommand=\"echo hi there\",no-pty {unpadded} user@laptop\n"
                ),
            },
            KeysFile {
                name: "b".into(),
                text: format!("{} other\n", key(2)),
            },
        ];
        assert!(key_already_authorized(&files, k1.blob(), Some(&cid(1))));
        let k3 = PublicKeyText::parse(&key(3)).unwrap();
        assert!(!key_already_authorized(&files, k3.blob(), None));
        // The second file counts too (AuthorizedKeysFile may list two).
        let k2 = PublicKeyText::parse(&key(2)).unwrap();
        assert!(key_already_authorized(&files, k2.blob(), None));
    }

    #[test]
    fn line_fingerprint_needs_exactly_one_unshadowed_line() {
        let c = cid(9);
        let k = PublicKeyText::parse(&key(4)).unwrap();
        let line = ManagementLine {
            client: c.clone(),
            command: ServeCommand::new("/h/bin/heimdall", "/h/home").unwrap(),
            key: k.clone(),
            expiry: None,
        }
        .render()
        .unwrap();
        let one = vec![KeysFile {
            name: "a".into(),
            text: format!("{line}\n"),
        }];
        assert_eq!(line_fingerprint(&one, &c), Some(k.fingerprint()));
        let shadowed = vec![
            one[0].clone(),
            KeysFile {
                name: "b".into(),
                text: format!("{} unrestricted\n", key(4)),
            },
        ];
        assert_eq!(line_fingerprint(&shadowed, &c), None);
        let twice = vec![KeysFile {
            name: "a".into(),
            text: format!("{line}\n{line}\n"),
        }];
        assert_eq!(line_fingerprint(&twice, &c), None);
        assert_eq!(line_fingerprint(&one, &cid(8)), None);
    }

    #[test]
    fn expiry_rounds_down_and_is_utc() {
        assert_eq!(
            expiry_time("2026-01-02T03:04:05.999+02:00".parse().unwrap()).unwrap(),
            "20260102010405Z"
        );
    }
}
