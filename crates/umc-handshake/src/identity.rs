use umc_crypto::signatures::{IdentityKeyPair, IdentityPublicKey, StaticHandshakePublicKey};

pub const ENDPOINT_ID_LEN: usize = 32;
pub const BINDING_VERSION: u8 = 1;
pub const MAX_BINDING_SEQUENCE_GAP: u64 = 1_000;
pub const IDENTITY_BINDING_WIRE_LEN: usize = 153 + 64;
pub const ROTATION_PROOF_VERSION: u8 = 1;
pub const MAX_ROTATION_PROOF_BYTES: usize = 512;

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

/// A dual-signed proof that an identity signing key changed.  The proof is
/// deliberately separate from an [`IdentityBinding`]: the new key signs its
/// binding, while the old key authorizes the endpoint transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRotationProof {
    pub version: u8,
    pub old_identity_public_key: IdentityPublicKey,
    pub new_identity_public_key: IdentityPublicKey,
    pub old_endpoint_id: [u8; ENDPOINT_ID_LEN],
    pub new_endpoint_id: [u8; ENDPOINT_ID_LEN],
    pub old_static_handshake_public_key: StaticHandshakePublicKey,
    pub new_static_handshake_public_key: StaticHandshakePublicKey,
    pub old_binding_sequence: u64,
    pub new_binding_sequence: u64,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub old_signature: [u8; 64],
    pub new_signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationProofError {
    Version,
    InvalidKey,
    EndpointMismatch,
    BindingMismatch,
    InvalidValidity,
    NotYetValid,
    Expired,
    Sequence,
    BadOldSignature,
    BadNewSignature,
    Truncated,
    TrailingBytes,
    Oversized,
}

fn rotation_take<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], RotationProofError> {
    let value = bytes
        .get(*offset..*offset + len)
        .ok_or(RotationProofError::Truncated)?;
    *offset += len;
    Ok(value)
}

impl IdentityRotationProof {
    /// Creates a proof binding the old and new identity statements.
    ///
    /// # Errors
    ///
    /// Returns [`RotationProofError`] when either binding does not match the
    /// transition or its validity window is not covered by the proof.
    pub fn sign(
        old_identity: &IdentityKeyPair,
        old_binding: &IdentityBinding,
        new_identity: &IdentityKeyPair,
        new_binding: &IdentityBinding,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, RotationProofError> {
        let mut proof = Self {
            version: ROTATION_PROOF_VERSION,
            old_identity_public_key: old_identity.public(),
            new_identity_public_key: new_identity.public(),
            old_endpoint_id: old_binding.endpoint_id,
            new_endpoint_id: new_binding.endpoint_id,
            old_static_handshake_public_key: old_binding.static_handshake_public_key.clone(),
            new_static_handshake_public_key: new_binding.static_handshake_public_key.clone(),
            old_binding_sequence: old_binding.sequence,
            new_binding_sequence: new_binding.sequence,
            created_at_ms,
            expires_at_ms,
            old_signature: [0; 64],
            new_signature: [0; 64],
        };
        proof.validate_structure(old_binding, new_binding)?;
        old_binding
            .validate(created_at_ms, 0)
            .map_err(|_| RotationProofError::BindingMismatch)?;
        new_binding
            .validate(created_at_ms, 0)
            .map_err(|_| RotationProofError::BindingMismatch)?;
        let message = proof.signed_message();
        proof.old_signature = old_identity.sign(&message);
        proof.new_signature = new_identity.sign(&message);
        Ok(proof)
    }

    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.push(self.version);
        out.extend_from_slice(&self.old_identity_public_key.0);
        out.extend_from_slice(&self.new_identity_public_key.0);
        out.extend_from_slice(&self.old_endpoint_id);
        out.extend_from_slice(&self.new_endpoint_id);
        out.extend_from_slice(&self.old_static_handshake_public_key.0);
        out.extend_from_slice(&self.new_static_handshake_public_key.0);
        out.extend_from_slice(&self.old_binding_sequence.to_be_bytes());
        out.extend_from_slice(&self.new_binding_sequence.to_be_bytes());
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out
    }

    #[must_use]
    pub fn signed_message(&self) -> [u8; 32] {
        use blake2::Digest;
        let mut hasher = blake2::Blake2s256::new();
        hasher.update(b"UMP-IDENTITY-ROTATION-v1");
        hasher.update(self.signed_bytes());
        hasher.finalize().into()
    }

    /// Encodes the fixed-size canonical proof.
    ///
    /// # Errors
    ///
    /// Returns [`RotationProofError::Oversized`] if the profile bound changes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RotationProofError> {
        if self.signed_bytes().len() + 128 > MAX_ROTATION_PROOF_BYTES {
            return Err(RotationProofError::Oversized);
        }
        let mut out = self.signed_bytes();
        out.extend_from_slice(&self.old_signature);
        out.extend_from_slice(&self.new_signature);
        Ok(out)
    }

    /// Decodes a fixed-size canonical proof.
    ///
    /// # Errors
    ///
    /// Returns [`RotationProofError`] for malformed, truncated, or oversized
    /// input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RotationProofError> {
        const SIGNED_LEN: usize = 1 + 32 + 32 + 32 + 32 + 32 + 32 + 8 + 8 + 8 + 8;
        const TOTAL_LEN: usize = SIGNED_LEN + 64 + 64;
        if bytes.len() > MAX_ROTATION_PROOF_BYTES {
            return Err(RotationProofError::Oversized);
        }
        if bytes.len() < TOTAL_LEN {
            return Err(RotationProofError::Truncated);
        }
        if bytes.len() != TOTAL_LEN {
            return Err(RotationProofError::TrailingBytes);
        }
        let mut offset = 0;
        let version = *rotation_take(bytes, &mut offset, 1)?
            .first()
            .ok_or(RotationProofError::Truncated)?;
        let array = |bytes: &[u8], offset: &mut usize| -> Result<[u8; 32], RotationProofError> {
            rotation_take(bytes, offset, 32)?
                .try_into()
                .map_err(|_| RotationProofError::Truncated)
        };
        let old_identity_public_key = IdentityPublicKey(array(bytes, &mut offset)?);
        let new_identity_public_key = IdentityPublicKey(array(bytes, &mut offset)?);
        let old_endpoint_id = array(bytes, &mut offset)?;
        let new_endpoint_id = array(bytes, &mut offset)?;
        let old_static_handshake_public_key = StaticHandshakePublicKey(array(bytes, &mut offset)?);
        let new_static_handshake_public_key = StaticHandshakePublicKey(array(bytes, &mut offset)?);
        let number = |bytes: &[u8], offset: &mut usize| -> Result<u64, RotationProofError> {
            Ok(u64::from_be_bytes(
                rotation_take(bytes, offset, 8)?
                    .try_into()
                    .map_err(|_| RotationProofError::Truncated)?,
            ))
        };
        let old_binding_sequence = number(bytes, &mut offset)?;
        let new_binding_sequence = number(bytes, &mut offset)?;
        let created_at_ms = number(bytes, &mut offset)?;
        let expires_at_ms = number(bytes, &mut offset)?;
        let old_signature = rotation_take(bytes, &mut offset, 64)?
            .try_into()
            .map_err(|_| RotationProofError::Truncated)?;
        let new_signature = rotation_take(bytes, &mut offset, 64)?
            .try_into()
            .map_err(|_| RotationProofError::Truncated)?;
        Ok(Self {
            version,
            old_identity_public_key,
            new_identity_public_key,
            old_endpoint_id,
            new_endpoint_id,
            old_static_handshake_public_key,
            new_static_handshake_public_key,
            old_binding_sequence,
            new_binding_sequence,
            created_at_ms,
            expires_at_ms,
            old_signature,
            new_signature,
        })
    }

    /// Verifies both signatures, binding references, and the proof interval.
    ///
    /// # Errors
    ///
    /// Returns [`RotationProofError`] when either signature, binding, sequence,
    /// or validity check fails.
    pub fn verify(
        &self,
        old_binding: &IdentityBinding,
        new_binding: &IdentityBinding,
        now_ms: u64,
        skew_ms: u64,
    ) -> Result<(), RotationProofError> {
        self.validate_structure(old_binding, new_binding)?;
        old_binding
            .validate(self.created_at_ms, skew_ms)
            .map_err(|_| RotationProofError::BindingMismatch)?;
        new_binding
            .validate(self.created_at_ms, skew_ms)
            .map_err(|_| RotationProofError::BindingMismatch)?;
        if now_ms.saturating_add(skew_ms) < self.created_at_ms {
            return Err(RotationProofError::NotYetValid);
        }
        if now_ms > self.expires_at_ms.saturating_add(skew_ms) {
            return Err(RotationProofError::Expired);
        }
        let message = self.signed_message();
        if !self
            .old_identity_public_key
            .verify(&message, &self.old_signature)
        {
            return Err(RotationProofError::BadOldSignature);
        }
        if !self
            .new_identity_public_key
            .verify(&message, &self.new_signature)
        {
            return Err(RotationProofError::BadNewSignature);
        }
        Ok(())
    }

    fn validate_structure(
        &self,
        old_binding: &IdentityBinding,
        new_binding: &IdentityBinding,
    ) -> Result<(), RotationProofError> {
        if self.version != ROTATION_PROOF_VERSION {
            return Err(RotationProofError::Version);
        }
        if self.old_identity_public_key.0 == [0; 32] || self.new_identity_public_key.0 == [0; 32] {
            return Err(RotationProofError::InvalidKey);
        }
        if endpoint_id(&self.old_identity_public_key) != self.old_endpoint_id
            || endpoint_id(&self.new_identity_public_key) != self.new_endpoint_id
        {
            return Err(RotationProofError::EndpointMismatch);
        }
        if old_binding.identity_public_key != self.old_identity_public_key
            || old_binding.endpoint_id != self.old_endpoint_id
            || old_binding.static_handshake_public_key != self.old_static_handshake_public_key
            || old_binding.sequence != self.old_binding_sequence
            || new_binding.identity_public_key != self.new_identity_public_key
            || new_binding.endpoint_id != self.new_endpoint_id
            || new_binding.static_handshake_public_key != self.new_static_handshake_public_key
            || new_binding.sequence != self.new_binding_sequence
        {
            return Err(RotationProofError::BindingMismatch);
        }
        if self.new_binding_sequence <= self.old_binding_sequence {
            return Err(RotationProofError::Sequence);
        }
        if self.expires_at_ms <= self.created_at_ms {
            return Err(RotationProofError::InvalidValidity);
        }
        Ok(())
    }
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

    #[test]
    fn identity_rotation_proof_requires_both_keys_and_round_trips() {
        let old_identity = IdentityKeyPair::generate();
        let old_static = StaticHandshakeKeyPair::generate();
        let new_identity = IdentityKeyPair::generate();
        let new_static = StaticHandshakeKeyPair::generate();
        let old_binding = IdentityBinding::sign(
            &old_identity,
            &old_static.public(),
            100,
            10_000,
            7,
            [1u8; 32],
        );
        let new_binding = IdentityBinding::sign(
            &new_identity,
            &new_static.public(),
            200,
            10_000,
            8,
            [1u8; 32],
        );
        let proof = IdentityRotationProof::sign(
            &old_identity,
            &old_binding,
            &new_identity,
            &new_binding,
            200,
            10_000,
        )
        .expect("rotation proof");
        let encoded = proof.to_bytes().expect("encode proof");
        let decoded = IdentityRotationProof::from_bytes(&encoded).expect("decode proof");
        decoded
            .verify(&old_binding, &new_binding, 500, 0)
            .expect("dual-signed proof");

        let mut tampered = decoded;
        tampered.old_signature[0] ^= 1;
        assert_eq!(
            tampered.verify(&old_binding, &new_binding, 500, 0),
            Err(RotationProofError::BadOldSignature)
        );
    }
}
