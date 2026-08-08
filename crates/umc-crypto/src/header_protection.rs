//! Provisional UMP header protection (wire-format §18; open decision #2):
//! a 5-byte mask from the `ChaCha20` keystream over a zero nonce.
//! This construction is provisional until the interop freeze.

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;

/// Length of the header protection mask in bytes.
pub const MASK_LEN: usize = 5;

/// Derives the header protection key from a traffic secret via
/// `expand_label(secret, b"hp key", b"", 32)` (wire-format §18).
///
/// The label is the sanctioned convention for header protection keys; it
/// domain-separates the hp key from the AEAD packet key and IV. The
/// expansion cannot fail for a 32-byte output (HKDF's length bound is
/// `255 * HashLen`), so the helper returns the key directly.
#[must_use]
pub fn header_protection_key(traffic_secret: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    if let Ok(expanded) = crate::label::expand_label(traffic_secret, b"hp key", b"", 32) {
        key.copy_from_slice(&expanded);
    }
    key
}

/// Computes the header protection mask as 5 bytes of `ChaCha20` keystream.
///
/// Provisional construction: the mask is key-only. The packet number
/// sample does not influence the mask (the `ChaCha20` state is the header
/// protection key with a zero nonce and block counter 0). This limitation
/// is documented until the interop freeze (open decision #2).
#[must_use]
pub fn mask(header_protection_key: &[u8; 32], _packet_number_sample: &[u8]) -> [u8; MASK_LEN] {
    let mut cipher = ChaCha20::new(&(*header_protection_key).into(), &([0u8; 12].into()));
    cipher.seek(0);
    let mut buf = [0u8; MASK_LEN];
    cipher.apply_keystream(&mut buf);
    buf
}

/// Protects the first byte and packet number with the mask.
///
/// The phase-bit mask (0x10) is `XOR`ed into the first byte unconditionally
/// (QUIC-style). The `key_phase_bit` parameter is reserved for the
/// provisional wire format and does not change the mask.
#[must_use]
pub fn protect(
    header_protection_key: &[u8; 32],
    first_byte: u8,
    _key_phase_bit: bool,
    packet_number: &mut [u8],
) -> (u8, [u8; MASK_LEN]) {
    let m = mask(header_protection_key, packet_number);
    let protected_first = first_byte ^ (m[4] & 0x10);
    for (byte, mask_byte) in packet_number.iter_mut().zip(m.iter()) {
        *byte ^= mask_byte;
    }
    (protected_first, m)
}

/// Removes header protection, returning the unprotected first byte, the
/// key phase flag, and the unprotected packet number.
///
/// The key phase flag is read from the *unprotected* first byte (QUIC
/// style, RFC 9001 §5.4): the protected byte's phase bit is masked, so
/// the phase is only meaningful after unprotection.
#[must_use]
pub fn unprotect(
    header_protection_key: &[u8; 32],
    protected_first: u8,
    protected_pn: &[u8],
) -> (u8, bool, Vec<u8>) {
    let m = mask(header_protection_key, protected_pn);
    let mut pn = protected_pn.to_vec();
    for (byte, mask_byte) in pn.iter_mut().zip(m.iter()) {
        *byte ^= mask_byte;
    }
    let first = protected_first ^ (m[4] & 0x10);
    (first, first & 0x10 != 0, pn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protect_unprotect_round_trip() {
        let key = [9u8; 32];
        let mut pn = [0x0F, 0xB5];
        let (protected_first, _) = protect(&key, 0b1000_0000, false, &mut pn);
        assert_ne!(protected_first, 0b1000_0000);
        let (first, _, restored) = unprotect(&key, protected_first, &pn);
        assert_eq!(first, 0b1000_0000);
        assert_eq!(restored, vec![0x0F, 0xB5]);
    }

    #[test]
    fn key_phase_bit_survives() {
        let key = [9u8; 32];
        let mut pn = [0u8; 2];
        let (pf, _) = protect(&key, 0b0001_0000, true, &mut pn);
        let (first, phase, _) = unprotect(&key, pf, &pn);
        assert_eq!(first, 0b0001_0000);
        assert!(phase);
    }

    #[test]
    fn different_keys_give_different_masks() {
        let pn = [1u8; 4];
        let a = mask(&[1u8; 32], &pn);
        let b = mask(&[2u8; 32], &pn);
        assert_ne!(a, b);
    }

    #[test]
    fn hp_key_derivation_stable_and_distinct() {
        let a = header_protection_key(&[1u8; 32]);
        let b = header_protection_key(&[1u8; 32]);
        assert_eq!(a, b, "derivation is deterministic");
        let c = header_protection_key(&[2u8; 32]);
        assert_ne!(a, c, "different traffic secrets give different hp keys");
        // The hp key is domain-separated from the packet key by label
        // (wire-format §18), so it must never equal the AEAD key.
        let packet_key = crate::aead::PacketKeys::from_traffic_secret(&[1u8; 32])
            .expect("packet keys")
            .key;
        assert_ne!(a, packet_key, "hp key differs from the packet key");
    }
}
