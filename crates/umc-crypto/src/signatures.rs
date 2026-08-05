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
}
