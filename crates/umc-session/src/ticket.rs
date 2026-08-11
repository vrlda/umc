//! Resumption PSK derivation (handshake.md §35.1).
/// Derives the resumption PSK from the ticket's resumption master secret and
/// nonce.
///
/// # Panics
/// Panics if the 32-byte label expansion fails; impossible for in-range
/// lengths.
#[must_use]
pub fn resumption_psk(resumption_master_secret: &[u8; 32], ticket_nonce: &[u8]) -> [u8; 32] {
    let out =
        umc_crypto::label::expand_label(resumption_master_secret, b"resumption", ticket_nonce, 32)
            .expect("32-byte expansion");
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&out);
    psk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psk_derivation_is_stable_and_nonce_bound() {
        let a = resumption_psk(&[1u8; 32], b"nonce-1");
        let b = resumption_psk(&[1u8; 32], b"nonce-1");
        let c = resumption_psk(&[1u8; 32], b"nonce-2");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
