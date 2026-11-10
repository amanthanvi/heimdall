//! Certificates (ADR-0008 D6 item 2; ADR-0005 §3.4; m03-plan U1 `cert`): the
//! certificate profile from reserved bounds, `build_and_sign` (used only by the
//! issuer), and `validate_installed` (every refusal of D6 item 2).
//!
//! Wave 0 froze [`SecretCaKey`], because the issuer's frozen `SecretStore` trait
//! (`heimdall_issuer::store`, F23) names it; the wave-1 integrator landed its
//! generation, fingerprint and serialization API (U4 builds on it). U1 adds:
//!
//! * [`CertificateProfile`]: the ADR-0005 §3.4 profile of one reserved certificate,
//!   built from the reservation's [`CertificateBounds`] ([`CertificateProfile::from_bounds`]),
//!   plus the profile rules the reservation is built from ([`key_id`],
//!   [`valid_after_for`], [`VALID_AFTER_SKEW_SECONDS`]);
//! * [`build_and_sign`]: the issuer's signing of **exactly** the reserved certificate
//!   (ADR-0005 §3.5 step 2). It refuses a subject key or CA other than the reserved
//!   ones, starts the extensions from `clear` (none) and adds only the reserved ones,
//!   sets no critical option, and checks its own output with the installed-certificate
//!   validator before returning it;
//! * [`validate_installed`]: every refusal of ADR-0008 D6 item 2 ([`CertRefusal`]), used
//!   by the signer at install (D2 item 6) and by the tests.
//!
//! Times are whole Unix seconds: a reserved [`heimdall_contract::Timestamp`] is
//! truncated to the second ([`unix_seconds`]), the same way at signing and at
//! validation, so `valid_before` is "rounded down to the second" (ADR-0005 §3.4). The
//! nonce (32 bytes) comes from [`SystemRng`] only (ADR-0008 §17.15 item 11).

use std::collections::BTreeSet;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{CaFingerprint, EnvironmentId, GrantId};
use heimdall_domain::issuance::CertificateBounds;
use ssh_key::certificate::{Builder, CertType, Certificate};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use crate::vault::SystemRng;

/// Why a CA key operation failed. Messages carry no key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum CaKeyError {
    /// The operating system's CSPRNG failed (ADR-0008 §17.15 item 11): nothing was
    /// generated.
    #[error("the system random number generator is unavailable")]
    RandomnessUnavailable,
    /// The bytes do not decode to an unencrypted Ed25519 OpenSSH private key.
    #[error("the bytes are not an unencrypted Ed25519 CA key")]
    Malformed,
    /// The passphrase does not decrypt the encrypted key, or the decrypted key is
    /// not Ed25519.
    #[error("the passphrase does not decrypt the CA key")]
    WrongPassphrase,
    /// The key could not be encoded or encrypted.
    #[error("the CA key could not be encoded")]
    Encoding,
}

/// A CA private key (K_ca) in memory (ADR-0008 D1).
///
/// It has no `Clone`, `Debug`, `Display`, `Serialize` or `Deserialize`. Its key
/// material is zeroized on drop by `ssh-key`'s private-key types (which zeroize their
/// secret halves); every serialized form this type hands out is [`Zeroizing`]. Only
/// Ed25519 keys are held.
pub struct SecretCaKey {
    key: PrivateKey,
}

impl SecretCaKey {
    /// Wrap a decoded or generated private key.
    #[must_use]
    pub fn from_private_key(key: PrivateKey) -> Self {
        Self { key }
    }

    /// Generate a fresh Ed25519 CA key from the operating system's CSPRNG only
    /// (ADR-0008 §17.15 item 11, D-Q3), with an empty comment.
    ///
    /// # Errors
    /// [`CaKeyError::RandomnessUnavailable`] when the CSPRNG fails;
    /// [`CaKeyError::Encoding`] if `ssh-key` refuses the key data.
    pub fn generate() -> Result<Self, CaKeyError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        SystemRng::fill(seed.as_mut()).map_err(|_| CaKeyError::RandomnessUnavailable)?;
        let pair = Ed25519Keypair::from_seed(&seed);
        let key =
            PrivateKey::new(KeypairData::Ed25519(pair), "").map_err(|_| CaKeyError::Encoding)?;
        Ok(Self { key })
    }

    /// The CA's public key (safe to show; it is the registry line's key).
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }

    /// The CA's public key as one OpenSSH line with **no comment**
    /// (`ssh-ed25519 AAAA…`), the form `IssuerRequest::Register.ca_public_key` and
    /// the registry line carry.
    ///
    /// # Errors
    /// [`CaKeyError::Encoding`].
    pub fn public_openssh(&self) -> Result<String, CaKeyError> {
        let mut public = self.key.public_key().clone();
        public.set_comment("");
        public.to_openssh().map_err(|_| CaKeyError::Encoding)
    }

    /// The CA fingerprint, `SHA256:<43 base64>`.
    ///
    /// # Errors
    /// [`CaKeyError::Encoding`] if the rendered fingerprint is not a valid
    /// [`CaFingerprint`] (never for an Ed25519 key).
    pub fn fingerprint(&self) -> Result<CaFingerprint, CaKeyError> {
        let text = self.key.fingerprint(HashAlg::Sha256).to_string();
        CaFingerprint::parse(&text).map_err(|_| CaKeyError::Encoding)
    }

    /// The **unencrypted** OpenSSH private-key encoding (PEM text, LF line endings),
    /// for a platform store to protect (DPAPI, the keychain, the Secret Service).
    /// Zeroized on drop; never written anywhere in plaintext (ADR-0008 D1).
    ///
    /// # Errors
    /// [`CaKeyError::Encoding`].
    pub fn to_secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>, CaKeyError> {
        let pem = self
            .key
            .to_openssh(LineEnding::LF)
            .map_err(|_| CaKeyError::Encoding)?;
        Ok(Zeroizing::new(pem.as_bytes().to_vec()))
    }

    /// Decode [`Self::to_secret_bytes`]'s form. Refuses an encrypted key and any
    /// algorithm but Ed25519.
    ///
    /// # Errors
    /// [`CaKeyError::Malformed`].
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, CaKeyError> {
        let key = PrivateKey::from_openssh(bytes).map_err(|_| CaKeyError::Malformed)?;
        if key.is_encrypted() || key.key_data().ed25519().is_none() {
            return Err(CaKeyError::Malformed);
        }
        Ok(Self { key })
    }

    /// The D5 backup form (ADR-0008 D1, D4 item 1): the OpenSSH private-key format
    /// encrypted with bcrypt-pbkdf and aes256-ctr under `passphrase`, LF line
    /// endings. The output holds no plaintext key material. The salt comes from the
    /// operating system's CSPRNG.
    ///
    /// # Errors
    /// [`CaKeyError::Encoding`] (an encryption failure, or the CSPRNG failed).
    pub fn encrypt_openssh(&self, passphrase: &[u8]) -> Result<Vec<u8>, CaKeyError> {
        let mut rng = SystemRng;
        let encrypted = self
            .key
            .encrypt(&mut rng, passphrase)
            .map_err(|_| CaKeyError::Encoding)?;
        let pem = encrypted
            .to_openssh(LineEnding::LF)
            .map_err(|_| CaKeyError::Encoding)?;
        Ok(pem.as_bytes().to_vec())
    }

    /// Decrypt [`Self::encrypt_openssh`]'s form (or any encrypted OpenSSH Ed25519
    /// key, such as one `ssh-keygen` wrote).
    ///
    /// # Errors
    /// [`CaKeyError::Malformed`] when the bytes are not an encrypted OpenSSH key;
    /// [`CaKeyError::WrongPassphrase`] when `passphrase` does not decrypt it or the
    /// key is not Ed25519.
    pub fn decrypt_openssh(bytes: &[u8], passphrase: &[u8]) -> Result<Self, CaKeyError> {
        let encrypted = PrivateKey::from_openssh(bytes).map_err(|_| CaKeyError::Malformed)?;
        if !encrypted.is_encrypted() {
            return Err(CaKeyError::Malformed);
        }
        let key = encrypted
            .decrypt(passphrase)
            .map_err(|_| CaKeyError::WrongPassphrase)?;
        if key.key_data().ed25519().is_none() {
            return Err(CaKeyError::WrongPassphrase);
        }
        Ok(Self { key })
    }

    /// Whether `self` and `other` are the same key pair (compares public halves,
    /// which is sufficient for Ed25519; used by the backup's decrypt-back check).
    #[must_use]
    pub fn same_key(&self, other: &SecretCaKey) -> bool {
        self.key.public_key().key_data() == other.key.public_key().key_data()
    }

    /// The private key, for the certificate builder in this crate only.
    pub(crate) fn private_key(&self) -> &PrivateKey {
        &self.key
    }
}

// --- the certificate profile (ADR-0005 §3.4) ------------------------------------------

/// `valid_after` is the issuance time minus this many seconds (ADR-0005 §3.4: it
/// tolerates a destination clock up to 60 s behind at the start only).
pub const VALID_AFTER_SKEW_SECONDS: i64 = 60;

/// The size of the certificate nonce drawn from [`SystemRng`].
pub const NONCE_BYTES: usize = 32;

/// The key ID of a grant's certificate (ADR-0005 §3.4):
/// `heimdall:<environment-id>:<grant-id>:<serial>`, opaque IDs only, the serial in
/// decimal (the form sshd logs next to it as `serial <n>`).
#[must_use]
pub fn key_id(environment: &EnvironmentId, grant: &GrantId, serial: u64) -> String {
    format!(
        "heimdall:{}:{}:{serial}",
        environment.as_str(),
        grant.as_str()
    )
}

/// `valid_after` for a certificate issued at `issued_at`: `issued_at` minus
/// [`VALID_AFTER_SKEW_SECONDS`], truncated to the second. `None` when the result is
/// not representable.
#[must_use]
pub fn valid_after_for(issued_at: Timestamp) -> Option<Timestamp> {
    let secs = issued_at
        .as_second()
        .checked_sub(VALID_AFTER_SKEW_SECONDS)?;
    Timestamp::from_second(secs).ok()
}

/// A timestamp as whole Unix seconds (truncated; the conversion signing and validation
/// share).
#[must_use]
pub fn unix_seconds(t: Timestamp) -> i64 {
    t.as_second()
}

/// The profile of one reserved certificate (ADR-0005 §3.4; ADR-0008 D6 items 1–2): a
/// user certificate with exactly one principal, no critical option, exactly the
/// reserved extensions, the reserved serial, key ID and validity, for the reserved
/// subject key, signed by the reserved CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateProfile {
    /// The reserved random serial.
    pub serial: u64,
    /// The reserved key ID ([`key_id`]).
    pub key_id: String,
    /// The single principal, `hm:<destination-id>:<account>`.
    pub principal: String,
    /// `valid_after`, whole Unix seconds.
    pub valid_after: i64,
    /// `valid_before`, whole Unix seconds.
    pub valid_before: i64,
    /// The extensions; each is a flag extension with empty data. Nothing else is set
    /// (the profile starts from `clear`).
    pub extensions: BTreeSet<String>,
    /// The reserved subject key's fingerprint (`SHA256:…`).
    pub subject_fingerprint: String,
    /// The reserved CA; `None` refuses signing and validation (an M03 reservation
    /// always names one; U0b rows 2–3).
    pub ca_fingerprint: Option<CaFingerprint>,
}

impl CertificateProfile {
    /// The profile of a reservation's bounds (ADR-0005 §3.5 step 1 recorded them
    /// complete).
    #[must_use]
    pub fn from_bounds(bounds: &CertificateBounds) -> CertificateProfile {
        CertificateProfile {
            serial: bounds.serial,
            key_id: bounds.key_id.clone(),
            principal: bounds.principal.clone(),
            valid_after: unix_seconds(bounds.valid_after),
            valid_before: unix_seconds(bounds.valid_before),
            extensions: bounds.extensions.clone(),
            subject_fingerprint: bounds.subject_fingerprint.clone(),
            ca_fingerprint: bounds.ca_fingerprint.clone(),
        }
    }

    /// Whether the profile can be signed at all (before any key is looked at).
    fn check_signable(&self) -> Result<(u64, u64), CertError> {
        let (Ok(after), Ok(before)) = (
            u64::try_from(self.valid_after),
            u64::try_from(self.valid_before),
        ) else {
            return Err(CertError::InvalidProfile("validity_before_epoch"));
        };
        if before <= after {
            return Err(CertError::InvalidProfile("validity_empty"));
        }
        if self.principal.is_empty() {
            return Err(CertError::InvalidProfile("principal_empty"));
        }
        if self.key_id.is_empty() {
            return Err(CertError::InvalidProfile("key_id_empty"));
        }
        if self.extensions.iter().any(String::is_empty) {
            return Err(CertError::InvalidProfile("extension_empty"));
        }
        Ok((after, before))
    }
}

/// Why [`build_and_sign`] did not produce a certificate. Messages carry no key
/// material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum CertError {
    /// The profile cannot be signed (the reason is a nonsecret code).
    #[error("the certificate profile is invalid: {0}")]
    InvalidProfile(&'static str),
    /// The subject key is not the reserved subject.
    #[error("the subject key is not the reserved subject key")]
    SubjectMismatch,
    /// The CA key is not the reserved CA, or the profile names no CA.
    #[error("the CA key is not the reserved CA")]
    CaMismatch,
    /// The operating system's CSPRNG failed (no nonce).
    #[error("the system random number generator is unavailable")]
    RandomnessUnavailable,
    /// `ssh-key` refused to build or sign the certificate.
    #[error("the certificate could not be signed")]
    Signing,
    /// The signed certificate failed the installed-certificate validator (never
    /// expected; nothing is returned).
    #[error("the signed certificate failed its own check: {0}")]
    SelfCheck(CertRefusal),
}

/// Sign **exactly** the reserved certificate (ADR-0005 §3.5 step 2; used only by the
/// issuer, m03-plan U3): a user certificate for `subject` with `profile`'s single
/// principal, serial, key ID, validity and extensions (from `clear`, each with empty
/// data), no critical option, a 32-byte nonce from [`SystemRng`], signed by `ca`.
///
/// # Errors
/// [`CertError::InvalidProfile`] (a validity that is empty or before the epoch, an
/// empty principal, key ID or extension name); [`CertError::SubjectMismatch`] when
/// `subject`'s fingerprint is not the reserved one; [`CertError::CaMismatch`] when
/// `ca` is not the reserved CA (or none is reserved); [`CertError::RandomnessUnavailable`];
/// [`CertError::Signing`]; [`CertError::SelfCheck`].
pub fn build_and_sign(
    profile: &CertificateProfile,
    subject: &PublicKey,
    ca: &SecretCaKey,
) -> Result<Certificate, CertError> {
    let (after, before) = profile.check_signable()?;
    let subject_fp = subject.fingerprint(HashAlg::Sha256).to_string();
    if subject_fp != profile.subject_fingerprint {
        return Err(CertError::SubjectMismatch);
    }
    let ca_fp = ca.fingerprint().map_err(|_| CertError::CaMismatch)?;
    if profile.ca_fingerprint.as_ref() != Some(&ca_fp) {
        return Err(CertError::CaMismatch);
    }
    let mut nonce = vec![0u8; NONCE_BYTES];
    SystemRng::fill(&mut nonce).map_err(|_| CertError::RandomnessUnavailable)?;
    let mut builder = Builder::new(nonce, subject.key_data().clone(), after, before)
        .map_err(|_| CertError::Signing)?;
    builder
        .serial(profile.serial)
        .and_then(|b| b.key_id(profile.key_id.clone()))
        .and_then(|b| b.cert_type(CertType::User))
        .and_then(|b| b.valid_principal(profile.principal.clone()))
        .map_err(|_| CertError::Signing)?;
    for extension in &profile.extensions {
        builder
            .extension(extension.clone(), String::new())
            .map_err(|_| CertError::Signing)?;
    }
    let cert = builder
        .sign(ca.private_key())
        .map_err(|_| CertError::Signing)?;
    check_against(&cert, profile, &subject_fp, &ca_fp).map_err(CertError::SelfCheck)?;
    Ok(cert)
}

/// Why an installed certificate is refused (ADR-0008 D6 item 2; spec §7.6: unknown
/// critical options, mismatched certificate/key pairs, invalid validity intervals,
/// unexpected principals and unrecognized issuers fail closed). Each variant is a
/// nonsecret audit code ([`CertRefusal::code`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum CertRefusal {
    /// The reservation names no CA (an M03 reservation always does).
    #[error("the reservation names no CA")]
    NoReservedCa,
    /// The signature key is not the reserved CA (or not the expected CA).
    #[error("the certificate is not signed by the reserved CA")]
    WrongCa,
    /// The CA signature does not verify.
    #[error("the certificate signature does not verify")]
    BadSignature,
    /// The subject key is not the expected key (K_env or K_verify), or not the
    /// reserved one.
    #[error("the certificate subject is not the expected key")]
    WrongSubject,
    /// A host certificate (or any type but user).
    #[error("the certificate is not a user certificate")]
    NotUserCertificate,
    /// Not exactly one principal.
    #[error("the certificate has {count} principals, not exactly one")]
    PrincipalCount {
        /// How many it has.
        count: usize,
    },
    /// The one principal is not the pair's.
    #[error("the certificate principal is not the pair's")]
    WrongPrincipal,
    /// Any critical option.
    #[error("the certificate carries a critical option")]
    CriticalOption,
    /// An extension outside the reserved set.
    #[error("the certificate carries an extension outside the reserved set")]
    ExtensionOutsideReserved,
    /// A reserved extension is missing (exact equality, fail closed).
    #[error("the certificate lacks a reserved extension")]
    ExtensionMissing,
    /// An extension carries data (every profile extension is a flag).
    #[error("a certificate extension carries data")]
    ExtensionData,
    /// `valid_after` is not the reserved one.
    #[error("valid_after differs from the reservation")]
    ValidAfterMismatch,
    /// `valid_before` is not the reserved one.
    #[error("valid_before differs from the reservation")]
    ValidBeforeMismatch,
    /// The key ID is not the reserved one.
    #[error("the key ID differs from the reservation")]
    KeyIdMismatch,
    /// The serial is not the reserved one.
    #[error("the serial differs from the reservation")]
    SerialMismatch,
}

impl CertRefusal {
    /// The stable, nonsecret code of this refusal (audit events, logs).
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            CertRefusal::NoReservedCa => "no_reserved_ca",
            CertRefusal::WrongCa => "wrong_ca",
            CertRefusal::BadSignature => "bad_signature",
            CertRefusal::WrongSubject => "wrong_subject",
            CertRefusal::NotUserCertificate => "not_user_certificate",
            CertRefusal::PrincipalCount { .. } => "principal_count",
            CertRefusal::WrongPrincipal => "wrong_principal",
            CertRefusal::CriticalOption => "critical_option",
            CertRefusal::ExtensionOutsideReserved => "extension_outside_reserved",
            CertRefusal::ExtensionMissing => "extension_missing",
            CertRefusal::ExtensionData => "extension_data",
            CertRefusal::ValidAfterMismatch => "valid_after_mismatch",
            CertRefusal::ValidBeforeMismatch => "valid_before_mismatch",
            CertRefusal::KeyIdMismatch => "key_id_mismatch",
            CertRefusal::SerialMismatch => "serial_mismatch",
        }
    }
}

/// Validate an installed certificate against its reservation (ADR-0008 D6 item 2; D2
/// item 6): `subject_fp` is the fingerprint of the key the signer holds (K_env or
/// K_verify), `ca_fp` the CA the reservation was made under. Refuses (first match, in
/// this order) a missing reserved CA; a signature key that is not `ca_fp` and the
/// reserved CA; a signature that does not verify; a subject that is not `subject_fp`
/// and the reserved subject; a type other than user; a principal count ≠ 1 or a
/// principal ≠ the pair's; any critical option; an extension outside the reserved
/// set, a missing reserved extension or extension data; `valid_after`/`valid_before`
/// ≠ the reserved bounds; a key ID or serial ≠ the reserved ones. Time (whether the
/// certificate is valid now) is the signer's install check, not this one.
///
/// # Errors
/// The first [`CertRefusal`] that applies.
pub fn validate_installed(
    cert: &Certificate,
    reserved: &CertificateBounds,
    subject_fp: &str,
    ca_fp: &CaFingerprint,
) -> Result<(), CertRefusal> {
    let profile = CertificateProfile::from_bounds(reserved);
    if profile.subject_fingerprint != subject_fp {
        return Err(CertRefusal::WrongSubject);
    }
    check_against(cert, &profile, subject_fp, ca_fp)
}

/// The D6 item 2 structure check of `cert` against `profile`.
fn check_against(
    cert: &Certificate,
    profile: &CertificateProfile,
    subject_fp: &str,
    ca_fp: &CaFingerprint,
) -> Result<(), CertRefusal> {
    let Some(reserved_ca) = profile.ca_fingerprint.as_ref() else {
        return Err(CertRefusal::NoReservedCa);
    };
    let signer_fp = cert
        .signature_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();
    if reserved_ca != ca_fp || signer_fp != ca_fp.as_str() {
        return Err(CertRefusal::WrongCa);
    }
    if cert.verify_signature().is_err() {
        return Err(CertRefusal::BadSignature);
    }
    let cert_subject = cert.public_key().fingerprint(HashAlg::Sha256).to_string();
    if cert_subject != subject_fp || cert_subject != profile.subject_fingerprint {
        return Err(CertRefusal::WrongSubject);
    }
    if cert.cert_type() != CertType::User {
        return Err(CertRefusal::NotUserCertificate);
    }
    match cert.valid_principals() {
        [one] if *one == profile.principal => {}
        [_] => return Err(CertRefusal::WrongPrincipal),
        other => return Err(CertRefusal::PrincipalCount { count: other.len() }),
    }
    if !cert.critical_options().is_empty() {
        return Err(CertRefusal::CriticalOption);
    }
    let extensions = cert.extensions();
    if extensions.keys().any(|k| !profile.extensions.contains(k)) {
        return Err(CertRefusal::ExtensionOutsideReserved);
    }
    if profile
        .extensions
        .iter()
        .any(|k| !extensions.contains_key(k))
    {
        return Err(CertRefusal::ExtensionMissing);
    }
    if extensions.values().any(|v| !v.is_empty()) {
        return Err(CertRefusal::ExtensionData);
    }
    if i64::try_from(cert.valid_after()).ok() != Some(profile.valid_after) {
        return Err(CertRefusal::ValidAfterMismatch);
    }
    if i64::try_from(cert.valid_before()).ok() != Some(profile.valid_before) {
        return Err(CertRefusal::ValidBeforeMismatch);
    }
    if cert.key_id() != profile.key_id {
        return Err(CertRefusal::KeyIdMismatch);
    }
    if cert.serial() != profile.serial {
        return Err(CertRefusal::SerialMismatch);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn secret_ca_key_exposes_only_its_public_half() {
        let pair = Ed25519Keypair::from_seed(&[7; 32]);
        let expected = pair.public;
        let key = PrivateKey::new(KeypairData::Ed25519(pair), "test-ca").unwrap();
        let ca = SecretCaKey::from_private_key(key);
        assert_eq!(ca.public_key().key_data().ed25519(), Some(&expected));
    }

    #[test]
    fn generated_keys_differ_and_round_trip_through_secret_bytes() {
        let a = SecretCaKey::generate().unwrap();
        let b = SecretCaKey::generate().unwrap();
        assert!(!a.same_key(&b));
        let bytes = a.to_secret_bytes().unwrap();
        let back = SecretCaKey::from_secret_bytes(&bytes).unwrap();
        assert!(back.same_key(&a));
        assert_eq!(back.fingerprint().unwrap(), a.fingerprint().unwrap());
        let line = a.public_openssh().unwrap();
        assert!(line.starts_with("ssh-ed25519 "));
        assert_eq!(line.split(' ').count(), 2, "no comment: {line}");
    }

    #[test]
    fn encrypted_form_decrypts_only_with_its_passphrase() {
        let ca = SecretCaKey::generate().unwrap();
        let bytes = ca.encrypt_openssh(b"correct horse").unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        // The encrypted form is not the plaintext form.
        assert!(SecretCaKey::from_secret_bytes(&bytes).is_err());
        let back = SecretCaKey::decrypt_openssh(&bytes, b"correct horse").unwrap();
        assert!(back.same_key(&ca));
        assert_eq!(
            SecretCaKey::decrypt_openssh(&bytes, b"wrong").err(),
            Some(CaKeyError::WrongPassphrase)
        );
        let plain = ca.to_secret_bytes().unwrap();
        assert_eq!(
            SecretCaKey::decrypt_openssh(&plain, b"correct horse").err(),
            Some(CaKeyError::Malformed)
        );
    }
}
