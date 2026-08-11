use umc_crypto::signatures::{IdentityKeyPair, IdentityPublicKey, StaticHandshakePublicKey};

pub const ENDPOINT_ID_LEN: usize = 32;
pub const BINDING_VERSION: u8 = 1;
pub const MAX_BINDING_SEQUENCE_GAP: u64 = 1_000;

/// `EndpointID` = `BLAKE2s-256("UMP-ENDPOINT-ID-v1" || IdentityPublicKey)` (handshake.md §4.1).
#[must_use]
pub fn endpoint_id(identity_public_key: &IdentityPublicKey) -> [u8; ENDPOINT_ID_LEN] {
    use blake2::Digest;
    let mut hasher = blake2::Blake2s256::new();
    hasher.update(b"UMP-ENDPOINT-ID-v1");
    hasher.update(identity_public_key.0);
    hasher.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityBinding {
    pub version: u8,
    pub endpoint_id: [u8; ENDPOINT_ID_LEN],
    pub identity_public_key: IdentityPublicKey,
    pub static_handshake_public_key: StaticHandshakePublicKey,
    pub not_before: u64,
    pub not_after: u64,
    pub sequence: u64,
    pub capabilities_hash: [u8; 32],
    pub signature: [u8; 64],
}

impl IdentityBinding {
    /// Canonical bytes without signature, signed by the identity key (handshake.md §4.3).
    #[must_use]
    pub fn sign(
        identity: &IdentityKeyPair,
        static_handshake_public_key: &StaticHandshakePublicKey,
        not_before: u64,
        not_after: u64,
        sequence: u64,
        capabilities_hash: [u8; 32],
    ) -> Self {
        let pub_key = identity.public();
        let endpoint_id = endpoint_id(&pub_key);
        let mut binding = Self {
            version: BINDING_VERSION,
            endpoint_id,
            identity_public_key: pub_key,
            static_handshake_public_key: static_handshake_public_key.clone(),
            not_before,
            not_after,
            sequence,
            capabilities_hash,
            signature: [0u8; 64],
        };
        binding.signature = identity.sign(&binding.signed_message());
        binding
    }

    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        out.extend_from_slice(&self.endpoint_id);
        out.extend_from_slice(&self.identity_public_key.0);
        out.extend_from_slice(&self.static_handshake_public_key.0);
        out.extend_from_slice(&self.not_before.to_be_bytes());
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.capabilities_hash);
        out
    }

    #[must_use]
    pub fn signed_message(&self) -> [u8; 32] {
        use blake2::Digest;
        let mut hasher = blake2::Blake2s256::new();
        hasher.update(b"UMP-IDENTITY-BINDING-v1");
        hasher.update(self.signed_bytes());
        hasher.finalize().into()
    }

    /// Validates version, endpoint-id binding, signature, and validity window.
    ///
    /// # Errors
    ///
    /// Returns [`BindingError`] on version mismatch, endpoint-id mismatch,
    /// signature failure, or validity-window violation.
    pub fn validate(&self, now: u64, skew_ms: u64) -> Result<(), BindingError> {
        if self.version != BINDING_VERSION {
            return Err(BindingError::Version);
        }
        if endpoint_id(&self.identity_public_key) != self.endpoint_id {
            return Err(BindingError::EndpointIdMismatch);
        }
        if !self
            .identity_public_key
            .verify(&self.signed_message(), &self.signature)
        {
            return Err(BindingError::BadSignature);
        }
        if now.saturating_add(skew_ms) < self.not_before
            || now > self.not_after.saturating_add(skew_ms)
        {
            return Err(BindingError::ValidityWindow);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_newer_than(&self, other_sequence: u64) -> bool {
        self.sequence > other_sequence && self.sequence - other_sequence <= MAX_BINDING_SEQUENCE_GAP
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    Version,
    EndpointIdMismatch,
    BadSignature,
    ValidityWindow,
    StaleSequence,
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_crypto::signatures::StaticHandshakeKeyPair;

    #[test]
    fn endpoint_id_is_stable_and_key_bound() {
        let identity = IdentityKeyPair::generate();
        let id1 = endpoint_id(&identity.public());
        let id2 = endpoint_id(&identity.public());
        assert_eq!(id1, id2);
        assert_ne!(id1, [0u8; ENDPOINT_ID_LEN]);
    }

    #[test]
    fn binding_sign_and_validate() {
        let identity = IdentityKeyPair::generate();
        let static_key = StaticHandshakeKeyPair::generate();
        let binding = IdentityBinding::sign(
            &identity,
            &static_key.public(),
            1_700_000_000_000,
            1_730_000_000_000,
            0,
            [0u8; 32],
        );
        assert_eq!(binding.validate(1_710_000_000_000, 300_000), Ok(()));
        assert_eq!(
            binding.validate(1_700_000_000_000 - 600_000, 300_000),
            Err(BindingError::ValidityWindow)
        );
    }

    #[test]
    fn tampered_binding_fails() {
        let identity = IdentityKeyPair::generate();
        let static_key = StaticHandshakeKeyPair::generate();
        let mut binding =
            IdentityBinding::sign(&identity, &static_key.public(), 0, u64::MAX, 0, [0u8; 32]);
        binding.sequence = 1; // mutation after signing
        assert_eq!(binding.validate(1_000, 0), Err(BindingError::BadSignature));
    }

    #[test]
    fn sequence_monotonicity() {
        let identity = IdentityKeyPair::generate();
        let static_key = StaticHandshakeKeyPair::generate();
        let b5 = IdentityBinding::sign(&identity, &static_key.public(), 0, u64::MAX, 5, [0u8; 32]);
        let b3 = IdentityBinding::sign(&identity, &static_key.public(), 0, u64::MAX, 3, [0u8; 32]);
        assert!(b5.is_newer_than(b3.sequence));
        assert!(!b3.is_newer_than(b5.sequence));
        assert!(!b5.is_newer_than(b5.sequence));
    }

    #[test]
    fn max_not_after_does_not_overflow() {
        let identity = IdentityKeyPair::generate();
        let static_key = StaticHandshakeKeyPair::generate();
        let binding =
            IdentityBinding::sign(&identity, &static_key.public(), 0, u64::MAX, 0, [0u8; 32]);
        assert_eq!(binding.validate(1_900_000_000_000, 300_000), Ok(()));
        let short = IdentityBinding::sign(
            &identity,
            &static_key.public(),
            0,
            1_900_000_000_000,
            0,
            [0u8; 32],
        );
        assert_eq!(
            short.validate(1_900_000_000_000 + 600_000, 300_000),
            Err(BindingError::ValidityWindow)
        );
    }
}
