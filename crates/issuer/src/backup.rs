//! The D5 backup of K_ca (ADR-0008 D1, D4 item 1; §17.1 item 11; m03-plan U4
//! `backup`): the OpenSSH private-key format encrypted with bcrypt-pbkdf and
//! aes256-ctr (`ssh-key` `encryption`), prepared and decrypted back in memory before
//! anything is written, written exactly (`O_EXCL`, `fsync`, read back, digest and
//! decryption compared), and restored.
//!
//! Signatures named by m03-plan U4; bodies are U4's. **Wave 0:** every operation
//! refuses with [`BackupError::Unavailable`]; nothing is encrypted, written or read.

use std::path::Path;

use heimdall_contract::Timestamp;
use heimdall_credential::cert::SecretCaKey;
use zeroize::Zeroizing;

/// The generated backup passphrase. Shown once on the terminal, never logged,
/// serialized or passed in process arguments; zeroized on drop. No `Clone`, `Debug`
/// or `Display`.
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    /// Wrap a passphrase (generated, or typed at the terminal for a restore).
    #[must_use]
    pub fn new(text: Zeroizing<String>) -> Self {
        Self(text)
    }

    /// The passphrase text, for the encryption call and the one terminal display.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// The exact backup file bytes and their digest, built and decrypted back in memory.
pub struct PreparedBackup {
    /// The file's bytes (an encrypted OpenSSH private key; no plaintext key material).
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`, lowercase hex (the `backup_sha256` the decision records).
    pub sha256: String,
}

/// A written backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInfo {
    /// SHA-256 of the written file, lowercase hex.
    pub sha256: String,
    /// When it was written.
    pub created_at: Timestamp,
}

/// A backup operation's failure. Messages carry no key or passphrase material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BackupError {
    /// The backup is not in this build (wave 0; U4 fills it).
    #[error("the D5 backup is not available in this build")]
    Unavailable,
    /// The target file already exists (never overwritten).
    #[error("the backup file already exists")]
    Exists,
    /// What was read back differs from what was prepared.
    #[error("the written backup does not match the prepared bytes")]
    Mismatch,
    /// The passphrase does not decrypt the backup.
    #[error("the passphrase does not decrypt the backup")]
    WrongPassphrase,
    /// An I/O failure.
    #[error("backup I/O failed")]
    Io,
}

/// Build the backup bytes for `key` under `passphrase` and decrypt them back in
/// memory.
///
/// # Errors
/// **Wave 0:** always [`BackupError::Unavailable`].
pub fn prepare(key: &SecretCaKey, passphrase: &Passphrase) -> Result<PreparedBackup, BackupError> {
    let _ = (key, passphrase);
    Err(BackupError::Unavailable)
}

/// Write `prepared` to `path` exactly (exclusive create, `fsync`, read back, digest
/// and decryption compared).
///
/// # Errors
/// **Wave 0:** always [`BackupError::Unavailable`]; nothing is created.
pub fn write_exact(path: &Path, prepared: &PreparedBackup) -> Result<BackupInfo, BackupError> {
    let _ = (path, prepared);
    Err(BackupError::Unavailable)
}

/// Read and decrypt the backup at `path`.
///
/// # Errors
/// **Wave 0:** always [`BackupError::Unavailable`]; nothing is read.
pub fn restore(path: &Path, passphrase: &Passphrase) -> Result<SecretCaKey, BackupError> {
    let _ = (path, passphrase);
    Err(BackupError::Unavailable)
}
