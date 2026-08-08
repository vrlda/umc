//! PSK-XX admission mode (handshake.md §22, phase I3).
//!
//! This module deliberately exposes the transcript-bound derivation primitive
//! separately from the XX wire driver. The daemon can negotiate the mode and
//! feed the resulting secret into the existing traffic schedule without ever
//! putting the invitation key on the wire.

use umc_crypto::signatures::{StaticHandshakeKeyPair, StaticHandshakePublicKey};

pub const MODE_PSK_XX: &[u8] = b"PSK-XX";
const LABEL: &[u8] = b"UMP-PSK-XX-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PskConfig {
    pub key: [u8; 32],
}

impl PskConfig {
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

/// Derives the PSK-XX handshake secret from the invitation PSK and ephemeral
/// DH. The PSK is the HKDF salt, so a wrong invitation key produces unrelated
/// output before transcript expansion.
///
/// # Panics
///
/// Panics only if the fixed 32-byte HKDF expansion is rejected by the crypto
/// backend, which indicates an internal implementation error.
#[must_use]
pub fn derive_psk_xx_secret(
    psk: &[u8; 32],
    my_ephemeral: &StaticHandshakeKeyPair,
    peer_ephemeral: &StaticHandshakePublicKey,
    transcript_hash: &[u8],
) -> [u8; 32] {
    let dh_ee = my_ephemeral.diffie_hellman(peer_ephemeral);
    let extracted = umc_crypto::hkdf::extract(psk, &dh_ee);
    let mut context = Vec::with_capacity(LABEL.len() + transcript_hash.len());
    context.extend_from_slice(LABEL);
    context.extend_from_slice(transcript_hash);
    let expanded = umc_crypto::label::expand_label(&extracted, b"psk-xx handshake", &context, 32)
        .expect("fixed PSK-XX output length");
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&expanded);
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_matching_secret() {
        let client = StaticHandshakeKeyPair::generate();
        let server = StaticHandshakeKeyPair::generate();
        let psk = [7u8; 32];
        let client_secret = derive_psk_xx_secret(&psk, &client, &server.public(), b"transcript");
        let server_secret = derive_psk_xx_secret(&psk, &server, &client.public(), b"transcript");
        assert_eq!(client_secret, server_secret);
    }

    #[test]
    fn wrong_psk_or_transcript_fails_closed() {
        let client = StaticHandshakeKeyPair::generate();
        let server = StaticHandshakeKeyPair::generate();
        let right = derive_psk_xx_secret(&[1u8; 32], &client, &server.public(), b"tr");
        let wrong_psk = derive_psk_xx_secret(&[2u8; 32], &server, &client.public(), b"tr");
        let wrong_transcript =
            derive_psk_xx_secret(&[1u8; 32], &server, &client.public(), b"tampered");
        assert_ne!(right, wrong_psk);
        assert_ne!(right, wrong_transcript);
    }
}
