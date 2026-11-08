//! Certificates (ADR-0008 D6 item 2; ADR-0005 §3.4; m03-plan U1 `cert`): the
//! certificate profile from reserved bounds, `build_and_sign` (used only by the
//! issuer), and `validate_installed` (every refusal of D6 item 2).
//!
//! U1 fills this module. Wave 0 freezes [`SecretCaKey`], because the issuer's frozen
//! `SecretStore` trait (`heimdall_issuer::store`, F23) names it.

use ssh_key::{PrivateKey, PublicKey};

/// A CA private key (K_ca) in memory (ADR-0008 D1).
///
/// It has no `Clone`, `Debug`, `Display`, `Serialize` or `Deserialize`. Its key
/// material is zeroized on drop by `ssh-key`'s private-key types (which zeroize their
/// secret halves). U1 adds the signing operation; U4 the store and backup
/// conversions.
pub struct SecretCaKey {
    key: PrivateKey,
}

impl SecretCaKey {
    /// Wrap a decoded or generated private key.
    #[must_use]
    pub fn from_private_key(key: PrivateKey) -> Self {
        Self { key }
    }

    /// The CA's public key (safe to show; it is the registry line's key).
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ssh_key::private::{Ed25519Keypair, KeypairData};

    #[test]
    fn secret_ca_key_exposes_only_its_public_half() {
        let pair = Ed25519Keypair::from_seed(&[7; 32]);
        let expected = pair.public;
        let key = PrivateKey::new(KeypairData::Ed25519(pair), "test-ca").unwrap();
        let ca = SecretCaKey::from_private_key(key);
        assert_eq!(ca.public_key().key_data().ed25519(), Some(&expected));
    }
}
