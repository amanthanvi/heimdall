//! Public-key files for adopted identities (m02-plan U4; ADR-0007 §2).
//!
//! Only public keys are written, through `projection::replace`; a private key file is
//! never opened. [`public_key_bytes`] is one of the `Rendered` producers (ADR-0007
//! §5.7 "Provenance").

use std::path::PathBuf;

use heimdall_domain::projection::Rendered;

/// A validated OpenSSH one-line public key (type, base64 blob, no comment kept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyLine(String);

impl PublicKeyLine {
    /// Validate a one-line public key; private-key armor is refused.
    ///
    /// # Errors
    /// [`KeyLineError`].
    pub fn parse(line: &str) -> Result<Self, KeyLineError> {
        let _ = line;
        todo!("M02-U4 materialize::PublicKeyLine::parse")
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

/// Where the key file for `fingerprint` lives, relative to the managed directory.
#[must_use]
pub fn key_file_path(fingerprint: &str) -> PathBuf {
    let _ = fingerprint;
    todo!("M02-U4 materialize::key_file_path")
}

/// The bytes of the `.pub` file for `key`.
#[must_use]
pub fn public_key_bytes(key: &PublicKeyLine) -> Rendered {
    let _ = key;
    todo!("M02-U4 materialize::public_key_bytes")
}
