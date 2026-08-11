use blake2::{Blake2s256, Digest};

/// Transcript construction (handshake.md §10).
#[derive(Debug, Clone)]
pub struct Transcript {
    pub hash: [u8; 32],
    pub total_bytes: usize,
}

pub const MAX_TRANSCRIPT: usize = 65_536;

impl Transcript {
    #[must_use]
    pub fn new(mode: &[u8], crypto_profile: &[u8], carrier_binding: &[u8]) -> Self {
        let mut hasher = Blake2s256::new();
        hasher.update(b"UMP-HANDSHAKE-v1");
        hasher.update(mode);
        hasher.update(crypto_profile);
        hasher.update(carrier_binding);
        Self {
            hash: hasher.finalize().into(),
            total_bytes: 0,
        }
    }

    /// Update with one canonical message (handshake.md §10):
    /// BLAKE2s(prev || `canonical_message_type` || `canonical_message_length` || body)
    ///
    /// # Errors
    ///
    /// Returns `TranscriptError::TranscriptTooLarge` if the transcript would
    /// exceed [`MAX_TRANSCRIPT`], or `TranscriptError::Encoding` if the
    /// message cannot be encoded.
    pub fn update_message(
        &mut self,
        message_type: u64,
        body: &[u8],
    ) -> Result<(), TranscriptError> {
        let type_len = crate::encoding::message_encoded_len(message_type, body)?;
        if self.total_bytes + type_len > MAX_TRANSCRIPT {
            return Err(TranscriptError::TranscriptTooLarge);
        }
        let mut hasher = Blake2s256::new();
        hasher.update(self.hash);
        let mut scratch = Vec::new();
        crate::encoding::encode_message(&mut scratch, message_type, body)
            .map_err(|_| TranscriptError::Encoding)?;
        hasher.update(&scratch);
        self.hash = hasher.finalize().into();
        self.total_bytes += type_len;
        Ok(())
    }

    pub fn update_bytes(&mut self, bytes: &[u8]) {
        let mut hasher = Blake2s256::new();
        hasher.update(self.hash);
        hasher.update(bytes);
        self.hash = hasher.finalize().into();
        self.total_bytes += bytes.len();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptError {
    TranscriptTooLarge,
    Encoding,
}

impl From<crate::encoding::EncodeError> for TranscriptError {
    fn from(e: crate::encoding::EncodeError) -> Self {
        match e {
            crate::encoding::EncodeError::MessageTooLarge => TranscriptError::TranscriptTooLarge,
            crate::encoding::EncodeError::Varint => TranscriptError::Encoding,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_is_order_sensitive() {
        let mut a = Transcript::new(b"XX", b"UMP-CRYPTO-1", b"binding");
        a.update_message(0, b"first").unwrap();
        a.update_message(1, b"second").unwrap();
        let mut b = Transcript::new(b"XX", b"UMP-CRYPTO-1", b"binding");
        b.update_message(1, b"second").unwrap();
        b.update_message(0, b"first").unwrap();
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn initial_hash_binds_mode_profile_binding() {
        let a = Transcript::new(b"XX", b"UMP-CRYPTO-1", b"b1");
        let b = Transcript::new(b"IK", b"UMP-CRYPTO-1", b"b1");
        let c = Transcript::new(b"XX", b"UMP-CRYPTO-1", b"b2");
        assert_ne!(a.hash, b.hash);
        assert_ne!(a.hash, c.hash);
    }

    #[test]
    fn transcript_size_is_bounded() {
        let mut t = Transcript::new(b"XX", b"UMP-CRYPTO-1", b"b");
        let big = vec![0u8; MAX_TRANSCRIPT + 1];
        assert_eq!(
            t.update_message(0, &big),
            Err(TranscriptError::TranscriptTooLarge)
        );
    }
}
