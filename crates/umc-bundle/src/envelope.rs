//! Bundle envelope (bundles.md §7): sealed encryption to the destination's
//! static handshake key with a fresh sender ephemeral. Provisional until
//! v0.2 cryptographic review.
use umc_crypto::aead::PacketKeys;
use umc_crypto::signatures::{StaticHandshakeKeyPair, StaticHandshakePublicKey};

pub const EPHEMERAL_KEY_LEN: usize = 32;
pub const ENVELOPE_MIN_LEN: usize = EPHEMERAL_KEY_LEN + 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleEnvelope {
    pub sender_ephemeral_public_key: [u8; EPHEMERAL_KEY_LEN],
    pub encrypted_payload: Vec<u8>,
}

impl BundleEnvelope {
    /// Serializes the envelope as `ephemeral_public || ciphertext` for object
    /// storage and transfer. The ciphertext includes the AEAD tag.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EPHEMERAL_KEY_LEN + self.encrypted_payload.len());
        out.extend_from_slice(&self.sender_ephemeral_public_key);
        out.extend_from_slice(&self.encrypted_payload);
        out
    }

    /// Decodes the compact stored envelope.
    ///
    /// # Errors
    ///
    /// Returns [`BundleEnvelopeError::Malformed`] when the ephemeral key or
    /// AEAD ciphertext is absent.
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleEnvelopeError> {
        if bytes.len() < ENVELOPE_MIN_LEN {
            return Err(BundleEnvelopeError::Malformed);
        }
        let sender_ephemeral_public_key = bytes[..EPHEMERAL_KEY_LEN]
            .try_into()
            .map_err(|_| BundleEnvelopeError::Malformed)?;
        Ok(Self {
            sender_ephemeral_public_key,
            encrypted_payload: bytes[EPHEMERAL_KEY_LEN..].to_vec(),
        })
    }
}

/// Seal a bundle payload to the destination (bundles.md §7.2).
///
/// # Panics
///
/// Panics if the payload-key derivation or the AEAD seal fails; both are
/// impossible with a 32-byte shared secret.
#[must_use]
pub fn seal_bundle(
    sender_ephemeral: &StaticHandshakeKeyPair,
    destination_static_public_key: &StaticHandshakePublicKey,
    payload: &[u8],
) -> BundleEnvelope {
    let shared = sender_ephemeral.diffie_hellman(destination_static_public_key);
    let key = derive_payload_key(&shared);
    let keys = PacketKeys::from_traffic_secret(&key).expect("32-byte key");
    let ciphertext = keys.seal(0, b"UMP-BUNDLE-v1", payload).expect("seal");
    BundleEnvelope {
        sender_ephemeral_public_key: sender_ephemeral.public().0,
        encrypted_payload: ciphertext,
    }
}

/// Open a bundle payload with the destination's static handshake key
/// (bundles.md §7.3: confidentiality + integrity for the stored payload).
///
/// # Errors
///
/// Returns `BundleEnvelopeError::DecryptFailed` when the envelope was sealed
/// to a different destination or the ciphertext was tampered with.
pub fn open_bundle(
    destination_static: &StaticHandshakeKeyPair,
    envelope: &BundleEnvelope,
) -> Result<Vec<u8>, BundleEnvelopeError> {
    let peer = StaticHandshakePublicKey(envelope.sender_ephemeral_public_key);
    let shared = destination_static.diffie_hellman(&peer);
    let key = derive_payload_key(&shared);
    let keys =
        PacketKeys::from_traffic_secret(&key).map_err(|_| BundleEnvelopeError::DecryptFailed)?;
    keys.open(0, b"UMP-BUNDLE-v1", &envelope.encrypted_payload)
        .map_err(|_| BundleEnvelopeError::DecryptFailed)
}

fn derive_payload_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let out = umc_crypto::label::expand_label(shared_secret, b"bundle payload", b"", 32)
        .expect("32-byte expansion");
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleEnvelopeError {
    DecryptFailed,
    Malformed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let sender = StaticHandshakeKeyPair::generate();
        let destination = StaticHandshakeKeyPair::generate();
        let envelope = seal_bundle(&sender, &destination.public(), b"secret bundle");
        let encoded = envelope.encode();
        assert_eq!(BundleEnvelope::decode(&encoded).unwrap(), envelope);
        let opened = open_bundle(&destination, &envelope).unwrap();
        assert_eq!(opened, b"secret bundle");
    }

    #[test]
    fn wrong_destination_cannot_open() {
        let sender = StaticHandshakeKeyPair::generate();
        let destination = StaticHandshakeKeyPair::generate();
        let attacker = StaticHandshakeKeyPair::generate();
        let envelope = seal_bundle(&sender, &destination.public(), b"secret");
        assert_eq!(
            open_bundle(&attacker, &envelope),
            Err(BundleEnvelopeError::DecryptFailed)
        );
    }

    #[test]
    fn tampering_detected() {
        let sender = StaticHandshakeKeyPair::generate();
        let destination = StaticHandshakeKeyPair::generate();
        let mut envelope = seal_bundle(&sender, &destination.public(), b"secret");
        envelope.encrypted_payload[0] ^= 0xFF;
        assert_eq!(
            open_bundle(&destination, &envelope),
            Err(BundleEnvelopeError::DecryptFailed)
        );
    }
}
