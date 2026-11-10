//! The issuer's loaded CAs (ADR-0008 D3 item 4 step 4, D4 item 3; m03-plan U3
//! `ca::CaSet`): CAs by fingerprint in states `active` and `pending`, signing through
//! `heimdall_credential::cert::build_and_sign`.
//!
//! A [`CaSet`] holds K_ca only in memory: each key is a
//! `heimdall_credential::cert::SecretCaKey`, which zeroizes on drop and has no
//! `Clone`, `Debug` or serde. Unloading a CA, clearing the set and dropping it
//! zeroize every key it held.
//!
//! **Selection** (step 4): the CA named by the entry's `ca_fingerprint` must be
//! loaded; for a grant entry it must be `active`, for a verification entry `active`
//! or `pending` (a `pending` CA signs only verification certificates for its own
//! enrollments, which the verification predicate checks: the entry's CA is the
//! plan's). The "subject is not a CA key the issuer holds" ceiling (step 3) is
//! checked here too, since only the set knows its keys.

use std::collections::BTreeMap;

use heimdall_contract::ids::CaFingerprint;
use heimdall_contract::issuer::CaState;
use heimdall_credential::cert::{CertificateProfile, SecretCaKey, build_and_sign};
use heimdall_domain::issuance::CertificateBounds;
use ssh_key::{Certificate, PublicKey};

use crate::protocol::{IssuanceTable, IssuerRefusal, LoadedCa};

/// One loaded CA.
struct Loaded {
    key: SecretCaKey,
    state: CaState,
}

/// Why a key cannot join a [`CaSet`]. Messages carry no key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CaSetError {
    /// Only `active` and `pending` CAs are loaded (a `retiring` CA never is; D4 item 3).
    #[error("only active and pending CAs are loaded")]
    NotLoadable,
    /// The key's fingerprint is not the one it was loaded for.
    #[error("the key is not the registered CA")]
    WrongKey,
}

/// The CAs the issuer holds, by fingerprint (module docs).
#[derive(Default)]
pub struct CaSet {
    cas: BTreeMap<CaFingerprint, Loaded>,
}

impl std::fmt::Debug for CaSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Fingerprints and states only; never a key.
        f.debug_struct("CaSet")
            .field("cas", &self.loaded())
            .finish()
    }
}

impl CaSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `key` as the CA `fingerprint` in `state` (replacing, and zeroizing, a key
    /// already held for it).
    ///
    /// # Errors
    /// [`CaSetError::NotLoadable`] for a state other than `active`/`pending`;
    /// [`CaSetError::WrongKey`] when the key's fingerprint is not `fingerprint`.
    pub fn insert(
        &mut self,
        fingerprint: &CaFingerprint,
        key: SecretCaKey,
        state: CaState,
    ) -> Result<(), CaSetError> {
        if !matches!(state, CaState::Active | CaState::Pending) {
            return Err(CaSetError::NotLoadable);
        }
        if key.fingerprint().ok().as_ref() != Some(fingerprint) {
            return Err(CaSetError::WrongKey);
        }
        self.cas.insert(fingerprint.clone(), Loaded { key, state });
        Ok(())
    }

    /// The loaded CAs, in fingerprint order (what `loaded` and `status` report).
    #[must_use]
    pub fn loaded(&self) -> Vec<LoadedCa> {
        self.cas
            .iter()
            .map(|(fingerprint, l)| LoadedCa {
                fingerprint: fingerprint.clone(),
                state: l.state,
            })
            .collect()
    }

    /// The state of a loaded CA.
    #[must_use]
    pub fn state(&self, fingerprint: &CaFingerprint) -> Option<CaState> {
        self.cas.get(fingerprint).map(|l| l.state)
    }

    /// The number of loaded CAs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cas.len()
    }

    /// Whether no CA is loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cas.is_empty()
    }

    /// Whether `subject` is the public key of a CA this set holds.
    #[must_use]
    pub fn holds_public(&self, subject: &PublicKey) -> bool {
        self.cas
            .values()
            .any(|l| l.key.public_key().key_data() == subject.key_data())
    }

    /// Zeroize and drop the CA `fingerprint` (retirement's `unload`; D4 item 3).
    /// Returns whether it was loaded. Idempotent.
    pub fn unload(&mut self, fingerprint: &CaFingerprint) -> bool {
        // Dropping the `SecretCaKey` zeroizes it.
        self.cas.remove(fingerprint).is_some()
    }

    /// Zeroize and drop every CA (EOF, `shutdown`, a failed load).
    pub fn clear(&mut self) {
        self.cas.clear();
    }

    /// Step 4: the key that may sign an entry of `table` naming `ca`.
    ///
    /// # Errors
    /// [`IssuerRefusal::CaNotLoaded`] when `ca` is `None`, not loaded, or loaded in a
    /// state this table may not use (a `pending` CA for a grant entry).
    fn select(
        &self,
        table: IssuanceTable,
        ca: Option<&CaFingerprint>,
    ) -> Result<&SecretCaKey, IssuerRefusal> {
        let loaded = ca
            .and_then(|fp| self.cas.get(fp))
            .ok_or(IssuerRefusal::CaNotLoaded)?;
        let usable = match table {
            IssuanceTable::Grant => loaded.state == CaState::Active,
            IssuanceTable::Verification => {
                matches!(loaded.state, CaState::Active | CaState::Pending)
            }
            #[allow(unreachable_patterns)]
            _ => false,
        };
        if usable {
            Ok(&loaded.key)
        } else {
            Err(IssuerRefusal::CaNotLoaded)
        }
    }

    /// Steps 3 (the CA-key ceiling), 4 and 5: sign exactly `bounds` (an entry of
    /// `table` that `check::verify_reservation` passed) for `subject` with the CA the
    /// bounds name, through `build_and_sign`.
    ///
    /// # Errors
    /// [`IssuerRefusal::CeilingExceeded`] when `subject` is a CA key this set holds,
    /// or the bounds cannot be signed as they stand (`build_and_sign` refuses the
    /// profile, or the subject is not the reserved one); [`IssuerRefusal::CaNotLoaded`]
    /// from the selection, or when signing itself fails (no randomness, a key error).
    pub fn sign(
        &self,
        table: IssuanceTable,
        bounds: &CertificateBounds,
        subject: &PublicKey,
    ) -> Result<Certificate, IssuerRefusal> {
        if self.holds_public(subject) {
            return Err(IssuerRefusal::CeilingExceeded);
        }
        let key = self.select(table, bounds.ca_fingerprint.as_ref())?;
        build_and_sign(&CertificateProfile::from_bounds(bounds), subject, key).map_err(|e| {
            use heimdall_credential::cert::CertError;
            match e {
                CertError::InvalidProfile(_) | CertError::SubjectMismatch => {
                    IssuerRefusal::CeilingExceeded
                }
                CertError::SelfCheck(_) => IssuerRefusal::CeilingExceeded,
                _ => IssuerRefusal::CaNotLoaded,
            }
        })
    }
}
