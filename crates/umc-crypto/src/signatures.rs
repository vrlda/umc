use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

pub const SIGNATURE_LEN: usize = 64;
pub const PUBLIC_KEY_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPublicKey(pub [u8; PUBLIC_KEY_LEN]);

#[derive(Debug, Clone)]
pub struct IdentityKeyPair {
    signing: SigningKey,
}

impl IdentityKeyPair {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// The 32-byte signing seed: reconstructs an identical keypair via
    /// [`Self::from_seed`] (used for keystore persistence).
    #[must_use]
    pub fn to_seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Reconstructs the keypair from its 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    #[must_use]
    pub fn public(&self) -> IdentityPublicKey {
        IdentityPublicKey(self.signing.verifying_key().to_bytes())
    }

    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }
}

impl IdentityPublicKey {
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != SIGNATURE_LEN {
            return false;
        }
        let bytes: &[u8; SIGNATURE_LEN] = match signature.try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let ok_signature = Signature::from_bytes(bytes);
        let Ok(key) = VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        key.verify(message, &ok_signature).is_ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticHandshakePublicKey(pub [u8; 32]);

#[derive(Clone)]
pub struct StaticHandshakeKeyPair {
    secret: x25519_dalek::StaticSecret,
}

impl std::fmt::Debug for StaticHandshakeKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticHandshakeKeyPair")
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl StaticHandshakeKeyPair {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            secret: x25519_dalek::StaticSecret::random_from_rng(OsRng),
        }
    }

    /// The 32-byte static secret: reconstructs an identical keypair via
    /// [`Self::from_seed`] (used for keystore persistence).
    #[must_use]
    pub fn to_seed(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Reconstructs the keypair from its 32-byte static secret.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            secret: x25519_dalek::StaticSecret::from(seed),
        }
    }

    #[must_use]
    pub fn public(&self) -> StaticHandshakePublicKey {
        StaticHandshakePublicKey(x25519_dalek::PublicKey::from(&self.secret).to_bytes())
    }

    #[must_use]
    pub fn diffie_hellman(&self, peer: &StaticHandshakePublicKey) -> [u8; 32] {
        let pubkey = x25519_dalek::PublicKey::from(peer.0);
        self.secret.diffie_hellman(&pubkey).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let pair = IdentityKeyPair::generate();
        let sig = pair.sign(b"message");
        assert!(pair.public().verify(b"message", &sig));
        assert!(!pair.public().verify(b"other", &sig));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let a = IdentityKeyPair::generate();
        let b = IdentityKeyPair::generate();
        let sig = a.sign(b"message");
        assert!(!b.public().verify(b"message", &sig));
    }

    #[test]
    fn dh_is_symmetric() {
        let a = StaticHandshakeKeyPair::generate();
        let b = StaticHandshakeKeyPair::generate();
        let ab = a.diffie_hellman(&b.public());
        let ba = b.diffie_hellman(&a.public());
        assert_eq!(ab, ba);
    }

    #[test]
    fn identity_seed_round_trip_preserves_key_and_signatures() {
        let pair = IdentityKeyPair::generate();
        let restored = IdentityKeyPair::from_seed(pair.to_seed());
        assert_eq!(pair.public(), restored.public());
        let sig = pair.sign(b"message");
        assert!(restored.public().verify(b"message", &sig));
        assert_eq!(sig, restored.sign(b"message"));
    }

    #[test]
    fn static_seed_round_trip_preserves_key_and_dh() {
        let pair = StaticHandshakeKeyPair::generate();
        let restored = StaticHandshakeKeyPair::from_seed(pair.to_seed());
        assert_eq!(pair.public(), restored.public());
        let peer = StaticHandshakeKeyPair::generate();
        assert_eq!(
            pair.diffie_hellman(&peer.public()),
            restored.diffie_hellman(&peer.public())
        );
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let a = IdentityKeyPair::from_seed([0u8; 32]);
        let b = IdentityKeyPair::from_seed([1u8; 32]);
        assert_ne!(a.public(), b.public());
        let sa = StaticHandshakeKeyPair::from_seed([0u8; 32]);
        let sb = StaticHandshakeKeyPair::from_seed([1u8; 32]);
        assert_ne!(sa.public(), sb.public());
    }
}
