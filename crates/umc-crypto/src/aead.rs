use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

pub const TAG_LEN: usize = 16;
pub const IV_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    InvalidKeyLength,
    DecryptFailed,
}

/// Packet keys derived from a traffic secret (handshake.md §27).
#[derive(Debug, Clone)]
pub struct PacketKeys {
    pub key: [u8; 32],
    pub iv: [u8; IV_LEN],
    /// Header-protection key derived from the same traffic secret. Keeping
    /// it beside the packet key prevents long-header callers from falling
    /// back to an unprotected packet-number field.
    pub hp_key: [u8; 32],
}

impl PacketKeys {
    /// Derives packet `key` and `iv` from a traffic secret via
    /// [`crate::label::expand_label`].
    ///
    /// # Errors
    /// Returns [`AeadError::InvalidKeyLength`] if label expansion fails.
    pub fn from_traffic_secret(secret: &[u8; 32]) -> Result<Self, AeadError> {
        let key: Vec<u8> = crate::label::expand_label(secret, b"packet key", b"", 32)
            .map_err(|_| AeadError::InvalidKeyLength)?;
        let iv: Vec<u8> = crate::label::expand_label(secret, b"packet iv", b"", IV_LEN)
            .map_err(|_| AeadError::InvalidKeyLength)?;
        let mut k = [0u8; 32];
        k.copy_from_slice(&key);
        let mut iv_arr = [0u8; IV_LEN];
        iv_arr.copy_from_slice(&iv);
        let hp_key = crate::header_protection::header_protection_key(secret);
        Ok(Self {
            key: k,
            iv: iv_arr,
            hp_key,
        })
    }

    /// Nonce = `PacketIV` XOR Encode96(PacketNumber) (handshake.md §27).
    #[must_use]
    pub fn nonce_for(&self, packet_number: u64) -> Nonce {
        let mut nonce = [0u8; IV_LEN];
        nonce.copy_from_slice(&self.iv);
        let pn = packet_number.to_be_bytes();
        let start = IV_LEN - pn.len();
        for (i, b) in pn.iter().enumerate() {
            nonce[start + i] ^= b;
        }
        Nonce::from(nonce)
    }

    /// Encrypts `plaintext` with AAD, returning the ciphertext plus 16-byte
    /// Poly1305 tag.
    ///
    /// # Errors
    /// Returns [`AeadError::DecryptFailed`] if encryption fails.
    pub fn seal(
        &self,
        packet_number: u64,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        cipher
            .encrypt(
                &self.nonce_for(packet_number),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| AeadError::DecryptFailed)
    }

    /// Decrypts and authenticates `ciphertext` with AAD.
    ///
    /// # Errors
    /// Returns [`AeadError::DecryptFailed`] if authentication or decryption
    /// fails.
    pub fn open(
        &self,
        packet_number: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        cipher
            .decrypt(
                &self.nonce_for(packet_number),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| AeadError::DecryptFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let secret = [1u8; 32];
        let keys = PacketKeys::from_traffic_secret(&secret).unwrap();
        let aad = b"public header bytes";
        let ct = keys.seal(42, aad, b"hello").unwrap();
        let pt = keys.open(42, aad, &ct).unwrap();
        assert_eq!(pt, b"hello");
        assert_eq!(ct.len(), b"hello".len() + TAG_LEN);
    }

    #[test]
    fn wrong_packet_number_fails() {
        let keys = PacketKeys::from_traffic_secret(&[1u8; 32]).unwrap();
        let ct = keys.seal(42, b"aad", b"x").unwrap();
        assert_eq!(keys.open(43, b"aad", &ct), Err(AeadError::DecryptFailed));
    }

    #[test]
    fn wrong_aad_fails() {
        let keys = PacketKeys::from_traffic_secret(&[1u8; 32]).unwrap();
        let ct = keys.seal(42, b"aad", b"x").unwrap();
        assert_eq!(keys.open(42, b"other", &ct), Err(AeadError::DecryptFailed));
    }

    #[test]
    fn nonce_construction_changes_with_pn() {
        let keys = PacketKeys::from_traffic_secret(&[1u8; 32]).unwrap();
        assert_ne!(keys.nonce_for(1).as_slice(), keys.nonce_for(2).as_slice());
        // Packet number is XORed into the low 8 bytes: pn 0 == raw iv.
        let zero = keys.nonce_for(0);
        assert_eq!(&zero[..4], &keys.iv[..4]);
    }

    #[test]
    fn packet_keys_include_header_protection_key() {
        let secret = [3u8; 32];
        let keys = PacketKeys::from_traffic_secret(&secret).unwrap();
        assert_eq!(
            keys.hp_key,
            crate::header_protection::header_protection_key(&secret)
        );
    }
}
