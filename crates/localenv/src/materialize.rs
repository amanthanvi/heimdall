//! Public-key files for adopted identities (m02-plan U4; ADR-0007 §2).
//!
//! Only public keys are written, through `projection::replace`; a private key file is
//! never opened. [`public_key_bytes`] is one of the `Rendered` producers (ADR-0007
//! §5.7 "Provenance").
//!
//! A key file lives at `<config_dir>/keys/<SHA256 fingerprint, base64url>.pub`
//! (ADR-0007 §2) and holds exactly one line, `<type> <base64 blob>\n`. The comment of
//! the source `.pub` is never kept: it is user text (and, in tests, a canary), and the
//! projection stores only bytes Heimdall itself renders (ADR-0007 §5.7 "What is
//! stored").

use std::path::PathBuf;

use heimdall_domain::projection::Rendered;

/// The key types a materialized `.pub` may carry: plain OpenSSH public keys only.
/// Certificates join with M03 (ADR-0007 §2 "The M02 directive set is closed").
const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// The longest public-key line accepted (a 16 KiB RSA key is well below this; the key
/// file bound is `bounds::KEY_FILE_MAX`).
const LINE_MAX: usize = 8 << 10;

/// A validated OpenSSH one-line public key (type, base64 blob, no comment kept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyLine(String);

impl PublicKeyLine {
    /// Validate a one-line public key; private-key armor is refused.
    ///
    /// Accepted: `<type> <base64 blob> [comment]`, optionally followed by one `\n` or
    /// `\r\n`, where `<type>` is a plain OpenSSH key type and the blob is canonical
    /// padded base64 whose first wire string is that same type. The comment is
    /// dropped. Anything else, including options, several lines, or a certificate, is
    /// [`KeyLineError::NotAPublicKey`]; any `PRIVATE KEY` armor or OpenSSH private-key
    /// marker is [`KeyLineError::PrivateKey`], checked first.
    ///
    /// # Errors
    /// [`KeyLineError`].
    pub fn parse(line: &str) -> Result<Self, KeyLineError> {
        if line.contains("PRIVATE KEY") || line.contains("-----BEGIN") {
            return Err(KeyLineError::PrivateKey);
        }
        if line.len() > LINE_MAX {
            return Err(KeyLineError::NotAPublicKey);
        }
        let body = line
            .strip_suffix("\r\n")
            .or_else(|| line.strip_suffix('\n'))
            .unwrap_or(line);
        if body.contains(['\n', '\r', '\0']) {
            return Err(KeyLineError::NotAPublicKey);
        }
        let mut fields = body.split([' ', '\t']).filter(|f| !f.is_empty());
        let (Some(kind), Some(blob)) = (fields.next(), fields.next()) else {
            return Err(KeyLineError::NotAPublicKey);
        };
        if !KEY_TYPES.contains(&kind) {
            return Err(KeyLineError::NotAPublicKey);
        }
        let decoded = base64_decode(blob).ok_or(KeyLineError::NotAPublicKey)?;
        if wire_string(&decoded) != Some(kind.as_bytes()) {
            return Err(KeyLineError::NotAPublicKey);
        }
        Ok(Self(format!("{kind} {blob}")))
    }

    /// The line.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A line that is not a public key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyLineError {
    /// Not a single-line OpenSSH public key.
    #[error("not an OpenSSH public key line")]
    NotAPublicKey,
    /// Private key material.
    #[error("private key material refused")]
    PrivateKey,
}

/// Where the key file for `fingerprint` lives, relative to the managed directory:
/// `keys/<base64url>.pub` (ADR-0007 §2).
///
/// `fingerprint` is OpenSSH's `SHA256:<base64>` form (the `SHA256:` prefix is
/// optional). The digest part is written in base64url (RFC 4648 §5, `+` → `-`,
/// `/` → `_`) without padding. Any other byte is written as `~` and two lowercase hex
/// digits, so the name is always a single path component of `[A-Za-z0-9_~-]` and two
/// different fingerprints never share a name.
#[must_use]
pub fn key_file_path(fingerprint: &str) -> PathBuf {
    let digest = fingerprint.strip_prefix("SHA256:").unwrap_or(fingerprint);
    let digest = digest.trim_end_matches('=');
    let mut name = String::with_capacity(digest.len() + 4);
    for b in digest.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => name.push(char::from(b)),
            b'+' => name.push('-'),
            b'/' => name.push('_'),
            other => {
                name.push('~');
                name.push(char::from(HEX[usize::from(other >> 4)]));
                name.push(char::from(HEX[usize::from(other & 0x0f)]));
            }
        }
    }
    if name.is_empty() {
        name.push('~');
    }
    name.push_str(".pub");
    PathBuf::from("keys").join(name)
}

/// The bytes of the `.pub` file for `key`: `<type> <base64 blob>\n`.
#[must_use]
pub fn public_key_bytes(key: &PublicKeyLine) -> Rendered {
    let mut bytes = key.as_str().as_bytes().to_vec();
    bytes.push(b'\n');
    Rendered::from_renderer(bytes)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The first SSH wire string of `blob` (`uint32` length, then the bytes).
fn wire_string(blob: &[u8]) -> Option<&[u8]> {
    let len_bytes: [u8; 4] = blob.get(..4)?.try_into().ok()?;
    let len = usize::try_from(u32::from_be_bytes(len_bytes)).ok()?;
    blob.get(4..4usize.checked_add(len)?)
}

/// Canonical padded standard base64 (RFC 4648 §4). Returns `None` for any other form,
/// including non-zero trailing bits, so one blob has exactly one text.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    let (chunks, rest) = bytes.as_chunks::<4>();
    if chunks.is_empty() || !rest.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(chunks.len() * 3);
    let count = chunks.len();
    for (i, chunk) in chunks.iter().enumerate() {
        let last = i + 1 == count;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut acc = 0u32;
        for (j, &c) in chunk.iter().enumerate() {
            let v = if j >= 4 - pad { 0 } else { value(c)? };
            acc = (acc << 6) | v;
        }
        let [_, b0, b1, b2] = acc.to_be_bytes();
        match pad {
            0 => out.extend_from_slice(&[b0, b1, b2]),
            1 => {
                if b2 != 0 {
                    return None;
                }
                out.extend_from_slice(&[b0, b1]);
            }
            _ => {
                if b1 != 0 || b2 != 0 {
                    return None;
                }
                out.push(b0);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // A synthetic Ed25519 public key (32 zero bytes): public data, not a real key.
    const ZERO_ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn parse_keeps_type_and_blob_and_drops_the_comment() {
        let line = PublicKeyLine::parse(&format!("{ZERO_ED25519} some comment\n")).unwrap();
        assert_eq!(line.as_str(), ZERO_ED25519);
        let r = public_key_bytes(&line);
        assert_eq!(r.bytes(), format!("{ZERO_ED25519}\n").as_bytes());
        assert!(PublicKeyLine::parse(&format!("{ZERO_ED25519}\r\n")).is_ok());
    }

    #[test]
    fn parse_refuses_private_material_and_other_shapes() {
        for bad in [
            // Built at run time so no armor literal sits in the repository.
            concat!("-----BEGIN OPENSSH ", "PRIVATE", " KEY-----"),
            "ssh-ed25519 AAAA PRIVATE KEY",
        ] {
            assert_eq!(PublicKeyLine::parse(bad), Err(KeyLineError::PrivateKey));
        }
        for bad in [
            "",
            "ssh-ed25519",
            "ssh-ed25519 !!!!",
            // The blob names another type.
            "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            // Options prefix (authorized_keys form).
            "no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            // Two lines.
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nx\n",
            // Non-canonical base64 (unpadded).
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert_eq!(
                PublicKeyLine::parse(bad),
                Err(KeyLineError::NotAPublicKey),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn key_file_path_is_one_base64url_component() {
        let p = key_file_path("SHA256:ab+/cd=");
        assert_eq!(p, PathBuf::from("keys").join("ab-_cd.pub"));
        let odd = key_file_path("SHA256:a.b");
        assert_eq!(odd, PathBuf::from("keys").join("a~2eb.pub"));
        assert_ne!(key_file_path("SHA256:a+b"), key_file_path("SHA256:a~2bb"));
        assert_eq!(key_file_path("").components().count(), 2);
    }

    #[test]
    fn base64_is_canonical_only() {
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        assert_eq!(base64_decode("TQ==").unwrap(), b"M");
        assert!(base64_decode("TR==").is_none(), "non-zero trailing bits");
        assert!(base64_decode("T===").is_none());
        assert!(base64_decode("TQ==TWFu").is_none());
        assert!(base64_decode("TWF").is_none());
    }
}
