//! The registry line and its marker (ADR-0008 D5 §6.1; m03-plan U5 "Interfaces").
//!
//! The line is `cert-authority,principals="hm:<destination-id>:<account>" <K_ca
//! public> heimdall:<enrollment-id>`. Its character set is
//! `[A-Za-z0-9+/=,:" ._@-]` (no `'`, so a single-quoted script literal holds it).
//!
//! Signatures frozen in wave 0 (U0). [`marker`] is the domain's rule. [`expected_line`]
//! (U5) validates every component and the whole line against [`LINE_CHARSET`]:
//! * the CA key is exactly `<type> <base64>` (one space, no comment), the type from
//!   `[a-z0-9.@-]`, the blob unpadded or `=`-padded standard base64;
//! * the principal is `hm:<destination-id>:<account>` with both parts from
//!   `[A-Za-z0-9._-]` ([`principal`]; ADR-0005 §3.3, `principal_charset`);
//! * the marker is `heimdall:` and a valid enrollment ID, from `[A-Za-z0-9_]`.
//!
//! A line **contains the marker** when the marker is a substring of it, exactly as
//! the scripts count `marker_lines` (`grep -c -F`); [`marker_lines`] is that count over
//! registry bytes.

use heimdall_contract::ids::{AccountName, DestinationId, EnrollmentId};

/// The registry line's permitted characters (ADR-0008 D5 §6.3).
pub const LINE_CHARSET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=,:\" ._@-";

/// The marker's fixed prefix.
pub const MARKER_PREFIX: &str = "heimdall:";

/// The principal's fixed prefix.
pub const PRINCIPAL_PREFIX: &str = "hm:";

/// Why no line was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum LineError {
    /// The line builder is not in this build (wave 0 only; never returned since U5).
    #[error("the registry line builder is not available in this build")]
    Unavailable,
    /// A component is outside [`LINE_CHARSET`] or malformed (`principal_charset`).
    #[error("a registry line component is outside the permitted character set")]
    Charset,
}

/// The marker of an enrollment, `heimdall:<enrollment-id>`
/// (`heimdall_domain::enrollment::marker_for`).
#[must_use]
pub fn marker(id: &EnrollmentId) -> String {
    heimdall_domain::enrollment::marker_for(id)
}

/// Whether `part` fits the principal form's `[A-Za-z0-9._-]` (ADR-0005 §3.3).
#[must_use]
pub fn principal_part_ok(part: &str) -> bool {
    !part.is_empty()
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The pair's principal, `hm:<destination-id>:<account>`.
///
/// # Errors
/// [`LineError::Charset`] when either part is outside `[A-Za-z0-9._-]`
/// (`principal_charset`).
pub fn principal(destination: &DestinationId, account: &AccountName) -> Result<String, LineError> {
    let (d, a) = (destination.as_str(), account.as_str());
    if !(principal_part_ok(d) && principal_part_ok(a)) {
        return Err(LineError::Charset);
    }
    Ok(format!("{PRINCIPAL_PREFIX}{d}:{a}"))
}

/// Whether `ca_public` is exactly `<type> <base64>`: one space, no comment.
#[must_use]
pub fn ca_public_ok(ca_public: &str) -> bool {
    let Some((kind, blob)) = ca_public.split_once(' ') else {
        return false;
    };
    let kind_ok = !kind.is_empty()
        && kind
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'@' | b'-'));
    let body = blob.trim_end_matches('=');
    let pad = blob.len() - body.len();
    let blob_ok = !body.is_empty()
        && pad <= 2
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'));
    kind_ok && blob_ok
}

/// Whether `marker` is `heimdall:<enrollment-id>` with the ID from `[A-Za-z0-9_]`.
#[must_use]
pub fn marker_ok(marker: &str) -> bool {
    let Some(id) = marker.strip_prefix(MARKER_PREFIX) else {
        return false;
    };
    EnrollmentId::parse(id).is_ok() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Whether every character of `text` is in [`LINE_CHARSET`].
#[must_use]
pub fn in_charset(text: &str) -> bool {
    text.chars().all(|c| LINE_CHARSET.contains(c))
}

/// The exact registry line for `ca_public` (an OpenSSH public key line), `principal`
/// (`hm:<destination-id>:<account>`) and `marker`.
///
/// # Errors
/// [`LineError::Charset`] when a component is malformed or outside
/// [`LINE_CHARSET`].
pub fn expected_line(ca_public: &str, principal: &str, marker: &str) -> Result<String, LineError> {
    let principal_ok = principal
        .strip_prefix(PRINCIPAL_PREFIX)
        .and_then(|rest| rest.split_once(':'))
        .is_some_and(|(d, a)| principal_part_ok(d) && principal_part_ok(a));
    if !(principal_ok && ca_public_ok(ca_public) && marker_ok(marker)) {
        return Err(LineError::Charset);
    }
    let line = format!("cert-authority,principals=\"{principal}\" {ca_public} {marker}");
    if !in_charset(&line) {
        return Err(LineError::Charset);
    }
    Ok(line)
}

/// The marker of an expected line: its last space-separated field, when that is a
/// valid marker.
#[must_use]
pub fn marker_of(line: &str) -> Option<&str> {
    line.rsplit(' ').next().filter(|m| marker_ok(m))
}

/// The lines of `content`: each line's bytes without its `\n` terminator (a `\r`
/// stays part of the line). A final line without `\n` is a line; an empty file has
/// none.
pub fn lines(content: &[u8]) -> impl Iterator<Item = &[u8]> {
    content
        .split_inclusive(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\n").unwrap_or(l))
}

/// Whether `haystack` contains `needle` (bytes).
#[must_use]
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// How many lines of `content` contain `marker` (the scripts' `marker_lines`).
#[must_use]
pub fn marker_lines(content: &[u8], marker: &str) -> usize {
    lines(content)
        .filter(|l| contains(l, marker.as_bytes()))
        .count()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const CA: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv0";
    const MARKER: &str = "heimdall:enr_00112233445566778899aabbccddeeff";

    #[test]
    fn charset_has_no_single_quote_and_line_is_exact() {
        assert!(!LINE_CHARSET.contains('\''));
        let line = expected_line(CA, "hm:dst_1:deploy", MARKER).unwrap();
        assert_eq!(
            line,
            format!("cert-authority,principals=\"hm:dst_1:deploy\" {CA} {MARKER}")
        );
        assert_eq!(marker_of(&line), Some(MARKER));
    }

    #[test]
    fn components_are_validated() {
        for (ca, p, m) in [
            ("ssh-ed25519 AAAA comment", "hm:d:a", MARKER),
            ("ssh-ed25519  AAAA", "hm:d:a", MARKER),
            ("ssh-ed25519 AA'A", "hm:d:a", MARKER),
            (CA, "hm:d:a:b", MARKER),
            (CA, "hm:d", MARKER),
            (CA, "xx:d:a", MARKER),
            (CA, "hm:d:a\"", MARKER),
            (CA, "hm:d:a", "heimdall:enr_x y"),
            (CA, "hm:d:a", "heimdall:op_1"),
            (CA, "hm:d:a", "heimdall:enr_a.b"),
        ] {
            assert_eq!(
                expected_line(ca, p, m),
                Err(LineError::Charset),
                "{ca} {p} {m}"
            );
        }
        let d = DestinationId::parse("dst:1").unwrap();
        let a = AccountName::parse("deploy").unwrap();
        assert_eq!(principal(&d, &a), Err(LineError::Charset));
    }

    #[test]
    fn marker_lines_are_substring_counts() {
        let content = format!("a\n# {MARKER}\nb {MARKER}\r\nlast {MARKER}");
        assert_eq!(marker_lines(content.as_bytes(), MARKER), 3);
        assert_eq!(lines(b"a\n\nb").count(), 3);
        assert_eq!(lines(b"").count(), 0);
        assert_eq!(lines(b"a\n").count(), 1);
    }
}
