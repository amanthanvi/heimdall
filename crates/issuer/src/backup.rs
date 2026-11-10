//! The D5 backup of K_ca (ADR-0008 D1, D4 item 1; §17.1 item 11; m03-plan U4
//! `backup`): the OpenSSH private-key format encrypted with bcrypt-pbkdf and
//! aes256-ctr (`ssh-key` `encryption`), prepared and decrypted back in memory before
//! anything is written, written exactly (`O_EXCL`, `fsync`, read back, digest and
//! decryption compared), and restored.
//!
//! * [`prepare`] builds the **exact** file bytes B in memory, decrypts B back and
//!   compares the public key, and computes `backup_sha256 = SHA-256(B)` (D4 item 1
//!   step 2). Nothing is written.
//! * [`write_exact`] creates the file exclusively (never over an existing entry, a
//!   symbolic link included) with mode 0600 on Unix or a protected owner-only DACL on
//!   Windows, writes B, `fsync`s the file and its directory, reads the file back,
//!   compares its SHA-256 with the prepared digest, then decrypts the read-back bytes
//!   and compares the public key (step 4). Any difference is [`BackupError::Mismatch`].
//! * [`restore`] reads and decrypts a backup (D4 item 4).
//!
//! The passphrase ([`Passphrase`]) is 26 symbols of the RFC 4648 base32 alphabet (130
//! bits) from the operating system's CSPRNG (`SystemRng`), zeroized on drop, never
//! `Debug`, `Display`, serialized or put in an argument. No error here carries key or
//! passphrase material.

use std::io::{Read, Write};
use std::path::Path;

use heimdall_contract::Timestamp;
use heimdall_credential::cert::{CaKeyError, SecretCaKey};
use heimdall_credential::vault::SystemRng;
use sha2::{Digest, Sha256};
use ssh_key::PublicKey;
use zeroize::Zeroizing;

/// The number of symbols in a generated passphrase (ADR-0008 D4 item 1: 26 base32
/// symbols, 130 bits).
pub const PASSPHRASE_SYMBOLS: usize = 26;

/// The RFC 4648 base32 alphabet.
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The largest backup file [`read`] accepts (an encrypted Ed25519 OpenSSH key is
/// about 460 bytes).
pub const BACKUP_MAX_BYTES: usize = 64 * 1024;

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

    /// Take `bytes` (moved, not copied, so the one buffer is zeroized on drop) as a
    /// passphrase; `None` (the bytes zeroized) when they are not UTF-8.
    #[must_use]
    pub fn from_utf8(bytes: Vec<u8>) -> Option<Self> {
        match String::from_utf8(bytes) {
            Ok(text) => Some(Self(Zeroizing::new(text))),
            Err(e) => {
                drop(Zeroizing::new(e.into_bytes()));
                None
            }
        }
    }

    /// A fresh passphrase: [`PASSPHRASE_SYMBOLS`] symbols of the RFC 4648 base32
    /// alphabet from the operating system's CSPRNG. Each symbol takes the low five
    /// bits of one random byte (256 is a multiple of 32, so every symbol is uniform).
    ///
    /// # Errors
    /// [`BackupError::RandomnessUnavailable`]: nothing was generated.
    pub fn generate() -> Result<Self, BackupError> {
        let mut raw = Zeroizing::new([0u8; PASSPHRASE_SYMBOLS]);
        SystemRng::fill(raw.as_mut()).map_err(|_| BackupError::RandomnessUnavailable)?;
        let mut text = Zeroizing::new(String::with_capacity(PASSPHRASE_SYMBOLS));
        for b in raw.iter() {
            text.push(char::from(BASE32[usize::from(b & 0x1f)]));
        }
        Ok(Self(text))
    }

    /// The passphrase text, for the encryption call and the one terminal display.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The passphrase shown in groups of five symbols separated by one space (ADR-0008
    /// D4 item 1), for the terminal display only. The spaces are not part of it.
    #[must_use]
    pub fn grouped(&self) -> Zeroizing<String> {
        let len = self.0.len();
        let mut out = Zeroizing::new(String::with_capacity(len + len / 5));
        for (i, c) in self.0.chars().enumerate() {
            if i > 0 && i.is_multiple_of(5) {
                out.push(' ');
            }
            out.push(c);
        }
        out
    }

    /// The generated-passphrase reading of a typed line: ASCII whitespace and `-`
    /// removed and letters upper-cased, when what is left is [`PASSPHRASE_SYMBOLS`]
    /// base32 symbols; `None` otherwise (the typed text is then used as it is).
    #[must_use]
    pub fn normalized_generated(&self) -> Option<Passphrase> {
        let mut out = Zeroizing::new(String::with_capacity(self.0.len()));
        for c in self.0.chars() {
            if c.is_ascii_whitespace() || c == '-' {
                continue;
            }
            let u = c.to_ascii_uppercase();
            if !u.is_ascii() || !BASE32.contains(&(u as u8)) {
                return None;
            }
            out.push(u);
        }
        (out.len() == PASSPHRASE_SYMBOLS && *out != *self.0).then(|| Passphrase(out))
    }
}

/// SHA-256 of `bytes`, lowercase hex.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(b & 0x0f)]));
    }
    out
}

/// The standard base64 alphabet (a CA fingerprint's).
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The prefix of [`fingerprint_file_stem`].
const STEM_PREFIX: &str = "sha256-";

/// A file name stem for `fingerprint` that is safe on every file system, including
/// case-insensitive ones: `sha256-<64 lowercase hex>` of the digest the fingerprint
/// encodes (used for the DPAPI blob and the scratch store's files).
#[must_use]
pub fn fingerprint_file_stem(fingerprint: &heimdall_contract::ids::CaFingerprint) -> String {
    let b64 = fingerprint
        .as_str()
        .strip_prefix("SHA256:")
        .unwrap_or_default();
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    let mut out = String::with_capacity(STEM_PREFIX.len() + 64);
    out.push_str(STEM_PREFIX);
    for c in b64.bytes() {
        let Some(v) = BASE64.iter().position(|&x| x == c) else {
            continue;
        };
        bits = ((bits << 6) | u32::try_from(v).unwrap_or(0)) & 0xffff;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            let byte = (bits >> nbits) & 0xff;
            out.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
            out.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
        }
    }
    out
}

/// The inverse of [`fingerprint_file_stem`]; `None` for any other name.
#[must_use]
pub fn fingerprint_from_file_stem(stem: &str) -> Option<heimdall_contract::ids::CaFingerprint> {
    let hex = stem.strip_prefix(STEM_PREFIX)?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    let mut text = String::from("SHA256:");
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    for b in bytes {
        bits = ((bits << 8) | u32::from(b)) & 0xffff;
        nbits += 8;
        while nbits >= 6 {
            nbits -= 6;
            text.push(char::from(BASE64[((bits >> nbits) & 0x3f) as usize]));
        }
    }
    if nbits > 0 {
        text.push(char::from(BASE64[((bits << (6 - nbits)) & 0x3f) as usize]));
    }
    heimdall_contract::ids::CaFingerprint::parse(&text).ok()
}

/// The exact backup file bytes and their digest, built and decrypted back in memory.
pub struct PreparedBackup {
    /// The file's bytes (an encrypted OpenSSH private key; no plaintext key material).
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`, lowercase hex (the `backup_sha256` the decision records).
    pub sha256: String,
    /// The CA public key the bytes decrypt to (the read-back comparison).
    public: PublicKey,
    /// The passphrase, kept for the read-back decryption; zeroized on drop.
    passphrase: Zeroizing<String>,
}

impl PreparedBackup {
    /// The CA public key the bytes decrypt to.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }
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
    /// The backup is not in this build (wave 0; no longer returned).
    #[error("the D5 backup is not available in this build")]
    Unavailable,
    /// The target file already exists (never overwritten).
    #[error("the backup file already exists")]
    Exists,
    /// What was read back differs from what was prepared, or the prepared bytes do
    /// not decrypt to the key they were made from.
    #[error("the written backup does not match the prepared bytes")]
    Mismatch,
    /// The passphrase does not decrypt the backup.
    #[error("the passphrase does not decrypt the backup")]
    WrongPassphrase,
    /// An I/O failure.
    #[error("backup I/O failed")]
    Io,
    /// The operating system's CSPRNG failed: nothing was generated.
    #[error("the system random number generator is unavailable")]
    RandomnessUnavailable,
    /// The file is not an encrypted OpenSSH private key (or is larger than
    /// [`BACKUP_MAX_BYTES`]).
    #[error("the file is not an encrypted OpenSSH key")]
    Malformed,
    /// The key could not be encoded or encrypted.
    #[error("the backup could not be encoded")]
    Encoding,
    /// A [`WriteProbe`] stopped the write where a crash would (tests only).
    #[error("the backup write was interrupted")]
    Interrupted,
}

impl From<CaKeyError> for BackupError {
    fn from(e: CaKeyError) -> Self {
        match e {
            CaKeyError::RandomnessUnavailable => BackupError::RandomnessUnavailable,
            CaKeyError::Malformed => BackupError::Malformed,
            CaKeyError::WrongPassphrase => BackupError::WrongPassphrase,
            _ => BackupError::Encoding,
        }
    }
}

/// Build the backup bytes for `key` under `passphrase` and decrypt them back in
/// memory (ADR-0008 D4 item 1 step 2).
///
/// # Errors
/// [`BackupError::Encoding`] or [`BackupError::RandomnessUnavailable`] when the
/// encryption fails; [`BackupError::Mismatch`] when the bytes do not decrypt to
/// `key`.
pub fn prepare(key: &SecretCaKey, passphrase: &Passphrase) -> Result<PreparedBackup, BackupError> {
    let bytes = key.encrypt_openssh(passphrase.expose().as_bytes())?;
    let back = SecretCaKey::decrypt_openssh(&bytes, passphrase.expose().as_bytes())
        .map_err(|_| BackupError::Mismatch)?;
    if !back.same_key(key) {
        return Err(BackupError::Mismatch);
    }
    let sha256 = sha256_hex(&bytes);
    Ok(PreparedBackup {
        bytes,
        sha256,
        public: key.public_key().clone(),
        passphrase: Zeroizing::new(passphrase.expose().to_owned()),
    })
}

/// A test seam inside [`write_exact_probed`] (m03-plan U4: a corrupted write, a crash
/// during the write). Production passes [`NoProbe`] through [`write_exact`].
pub trait WriteProbe {
    /// Called once, after the first `written` bytes reached the file and before the
    /// rest. `Err` stops the write there as a crash would: nothing more is written,
    /// synced, read or removed.
    ///
    /// # Errors
    /// [`Interrupted`] to stop.
    fn partial(&mut self, path: &Path, written: usize) -> Result<(), Interrupted> {
        let _ = (path, written);
        Ok(())
    }

    /// Called after the complete file is synced and before it is read back.
    fn before_read_back(&mut self, path: &Path) {
        let _ = path;
    }
}

/// A [`WriteProbe`] stop (a simulated crash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interrupted;

/// The production [`WriteProbe`]: never interferes.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoProbe;

impl WriteProbe for NoProbe {}

/// Write `prepared` to `path` exactly (exclusive create, `fsync`, read back, digest
/// and decryption compared; ADR-0008 D4 item 1 step 4).
///
/// # Errors
/// [`BackupError::Exists`] when anything exists at `path` (nothing is touched);
/// [`BackupError::Mismatch`] when the read-back differs or does not decrypt to the
/// prepared key; [`BackupError::Io`] otherwise.
pub fn write_exact(path: &Path, prepared: &PreparedBackup) -> Result<BackupInfo, BackupError> {
    write_exact_probed(path, prepared, &mut NoProbe)
}

/// [`write_exact`] with a [`WriteProbe`] between its steps.
///
/// # Errors
/// As [`write_exact`]; [`BackupError::Interrupted`] when the probe stopped it.
pub fn write_exact_probed(
    path: &Path,
    prepared: &PreparedBackup,
    probe: &mut dyn WriteProbe,
) -> Result<BackupInfo, BackupError> {
    let mut file = create_exclusive(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            BackupError::Exists
        } else {
            BackupError::Io
        }
    })?;
    let half = prepared.bytes.len() / 2;
    file.write_all(&prepared.bytes[..half])
        .map_err(|_| BackupError::Io)?;
    file.flush().map_err(|_| BackupError::Io)?;
    probe
        .partial(path, half)
        .map_err(|Interrupted| BackupError::Interrupted)?;
    file.write_all(&prepared.bytes[half..])
        .map_err(|_| BackupError::Io)?;
    file.sync_all().map_err(|_| BackupError::Io)?;
    drop(file);
    sync_parent(path)?;
    probe.before_read_back(path);
    let back = read(path)?;
    if back.sha256 != prepared.sha256 || back.bytes != prepared.bytes {
        return Err(BackupError::Mismatch);
    }
    let key = SecretCaKey::decrypt_openssh(&back.bytes, prepared.passphrase.as_bytes())
        .map_err(|_| BackupError::Mismatch)?;
    if key.public_key().key_data() != prepared.public.key_data() {
        return Err(BackupError::Mismatch);
    }
    Ok(BackupInfo {
        sha256: back.sha256,
        created_at: Timestamp::now(),
    })
}

/// A backup file read into memory (its bytes are encrypted; no plaintext key).
pub struct BackupFile {
    /// The file's bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`, lowercase hex.
    pub sha256: String,
}

impl BackupFile {
    /// Decrypt the file with `passphrase`; a generated passphrase typed in its
    /// groups (spaces, `-`, lower case) is also tried in its normalized form.
    ///
    /// # Errors
    /// [`BackupError::Malformed`] when the bytes are not an encrypted OpenSSH key;
    /// [`BackupError::WrongPassphrase`] when no form of `passphrase` decrypts them.
    pub fn decrypt(&self, passphrase: &Passphrase) -> Result<SecretCaKey, BackupError> {
        match SecretCaKey::decrypt_openssh(&self.bytes, passphrase.expose().as_bytes()) {
            Ok(key) => Ok(key),
            Err(CaKeyError::WrongPassphrase) => match passphrase.normalized_generated() {
                Some(normal) => {
                    SecretCaKey::decrypt_openssh(&self.bytes, normal.expose().as_bytes())
                        .map_err(BackupError::from)
                }
                None => Err(BackupError::WrongPassphrase),
            },
            Err(e) => Err(e.into()),
        }
    }
}

/// Read the backup at `path` (at most [`BACKUP_MAX_BYTES`]).
///
/// # Errors
/// [`BackupError::Io`] when it cannot be read; [`BackupError::Malformed`] when it is
/// too large.
pub fn read(path: &Path) -> Result<BackupFile, BackupError> {
    let file = std::fs::File::open(path).map_err(|_| BackupError::Io)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(BACKUP_MAX_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BackupError::Io)?;
    if bytes.len() > BACKUP_MAX_BYTES {
        return Err(BackupError::Malformed);
    }
    let sha256 = sha256_hex(&bytes);
    Ok(BackupFile { bytes, sha256 })
}

/// Read and decrypt the backup at `path`.
///
/// # Errors
/// As [`read`] and [`BackupFile::decrypt`].
pub fn restore(path: &Path, passphrase: &Passphrase) -> Result<SecretCaKey, BackupError> {
    read(path)?.decrypt(passphrase)
}

/// Create `path` exclusively, owner-only.
fn create_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_CREAT|O_EXCL never follows or replaces an existing entry, a symbolic
        // link included; the umask can only narrow 0600.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(windows)]
    {
        crate::sys::windows::create_owner_only_new(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "owner-only creation is not supported here",
        ))
    }
}

/// `fsync` the directory holding `path`, so its new entry is durable (Unix; Windows
/// has no directory sync and `FlushFileBuffers` on the file covers its metadata).
fn sync_parent(path: &Path) -> Result<(), BackupError> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        std::fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|_| BackupError::Io)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generated_passphrase_is_26_base32_symbols_grouped_by_five() {
        let p = Passphrase::generate().unwrap();
        assert_eq!(p.expose().len(), PASSPHRASE_SYMBOLS);
        assert!(p.expose().bytes().all(|b| BASE32.contains(&b)));
        let g = p.grouped();
        let groups: Vec<&str> = g.split(' ').collect();
        assert_eq!(groups.len(), 6);
        assert!(groups[..5].iter().all(|x| x.len() == 5));
        assert_eq!(groups[5].len(), 1);
        assert_eq!(groups.concat(), p.expose());
        // Two generations differ (130 bits).
        assert_ne!(Passphrase::generate().unwrap().expose(), p.expose());
    }

    #[test]
    fn typed_groups_normalize_to_the_generated_form() {
        let p = Passphrase::new(Zeroizing::new("abcde fghij-klmno pqrst uvwxy z".into()));
        assert_eq!(
            p.normalized_generated().unwrap().expose(),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        );
        let exact = Passphrase::new(Zeroizing::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ".into()));
        assert!(exact.normalized_generated().is_none());
        let other = Passphrase::new(Zeroizing::new("not a generated one!".into()));
        assert!(other.normalized_generated().is_none());
    }

    #[test]
    fn fingerprint_file_stems_round_trip_and_are_lowercase_hex() {
        for _ in 0..8 {
            let key = SecretCaKey::generate().unwrap();
            let fp = key.fingerprint().unwrap();
            let stem = fingerprint_file_stem(&fp);
            assert_eq!(stem.len(), STEM_PREFIX.len() + 64);
            assert!(stem.bytes().all(|b| !b.is_ascii_uppercase()));
            assert_eq!(fingerprint_from_file_stem(&stem).unwrap(), fp);
        }
        assert!(fingerprint_from_file_stem("sha256-zz").is_none());
        assert!(fingerprint_from_file_stem("other").is_none());
    }

    #[test]
    fn sha256_hex_known_value() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
