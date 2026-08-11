//! PSK-XX admission mode (handshake.md §22, phase I3).
//!
//! This module deliberately exposes the transcript-bound derivation primitive
//! separately from the XX wire driver. The daemon can negotiate the mode and
//! feed the resulting secret into the existing traffic schedule without ever
//! putting the invitation key on the wire.

use umc_crypto::signatures::{StaticHandshakeKeyPair, StaticHandshakePublicKey};

pub const MODE_PSK_XX: &[u8] = b"PSK-XX";
const LABEL: &[u8] = b"UMP-PSK-XX-v1";
pub const INVITATION_AUTH_LABEL: &[u8] = b"UMP-INVITE-AUTH-v1";
pub const INVITATION_AUTH_LEN: usize = 16;

/// Stateless admission context for a PSK-XX handshake. The responder keeps
/// this context outside the expensive handshake state until the invitation
/// authenticator verifies (handshake.md §§22, 47).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PskAdmissionContext {
    pub invitation_key: [u8; 32],
    pub destination_connection_id: Vec<u8>,
    pub carrier_binding: Vec<u8>,
}

/// Failure returned by the bounded PSK-XX admission gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskAdmissionError {
    UnsupportedMode,
    MissingAuthenticator,
    InvalidAuthenticator,
}

impl PskAdmissionContext {
    /// Verifies the invitation authenticator without performing a DH
    /// operation. Callers should apply their own expiry, scope, replay, and
    /// rate-limit policy before constructing this context.
    ///
    /// # Errors
    ///
    /// Returns [`PskAdmissionError`] when the hello does not offer PSK-XX,
    /// omits its authenticator, or fails authentication.
    pub fn verify_client_hello(
        &self,
        hello: &crate::xx::ClientHello,
    ) -> Result<(), PskAdmissionError> {
        if !hello
            .supported_handshake_modes
            .iter()
            .any(|mode| mode.as_slice() == MODE_PSK_XX)
        {
            return Err(PskAdmissionError::UnsupportedMode);
        }
        if hello.invitation_authenticator.is_empty() {
            return Err(PskAdmissionError::MissingAuthenticator);
        }
        if !verify_invitation_authenticator(
            &self.invitation_key,
            &hello.client_random,
            &hello.client_ephemeral_public_key,
            &self.destination_connection_id,
            &self.carrier_binding,
            &hello.invitation_authenticator,
        ) {
            return Err(PskAdmissionError::InvalidAuthenticator);
        }
        Ok(())
    }

    /// Derives `HandshakeExtract1` after the cheap admission check succeeds.
    /// The returned secret is safe to feed into the existing server-auth
    /// transcript schedule; the invitation key is never sent on the wire.
    ///
    /// # Errors
    ///
    /// Returns [`PskAdmissionError`] when the hello is not an authenticated
    /// PSK-XX offer.
    pub fn derive_handshake_extract1(
        &self,
        hello: &crate::xx::ClientHello,
        server_ephemeral: &StaticHandshakeKeyPair,
    ) -> Result<[u8; 32], PskAdmissionError> {
        self.verify_client_hello(hello)?;
        let psk_extract = derive_psk_extract(
            &self.invitation_key,
            &hello.client_random,
            &hello.client_ephemeral_public_key,
            &self.carrier_binding,
        );
        let dh_ee = server_ephemeral
            .diffie_hellman(&StaticHandshakePublicKey(hello.client_ephemeral_public_key));
        Ok(umc_crypto::hkdf::extract(&psk_extract, &dh_ee))
    }
}

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

/// Computes the truncated PSK-XX invitation authenticator from the canonical
/// handshake context (handshake.md §15.1/§15.4).
///
/// # Panics
///
/// Panics only if the fixed-size invitation key is rejected by the BLAKE2s
/// backend, which indicates an internal implementation error.
#[must_use]
pub fn invitation_authenticator(
    invitation_key: &[u8; 32],
    client_random: &[u8; 32],
    client_ephemeral_public_key: &[u8; 32],
    destination_connection_id: &[u8],
    carrier_binding: &[u8],
) -> [u8; INVITATION_AUTH_LEN] {
    let mut context = Vec::with_capacity(
        INVITATION_AUTH_LABEL.len()
            + client_random.len()
            + client_ephemeral_public_key.len()
            + destination_connection_id.len()
            + carrier_binding.len(),
    );
    context.extend_from_slice(INVITATION_AUTH_LABEL);
    context.extend_from_slice(client_random);
    context.extend_from_slice(client_ephemeral_public_key);
    context.extend_from_slice(destination_connection_id);
    context.extend_from_slice(carrier_binding);
    let full = umc_crypto::hkdf::hmac_blake2s(invitation_key, &context);
    full[..INVITATION_AUTH_LEN]
        .try_into()
        .expect("fixed authenticator length")
}

/// Derives the first PSK-XX extract input exactly as specified by
/// `handshake.md §22`.
#[must_use]
pub fn derive_psk_extract(
    invitation_key: &[u8; 32],
    client_random: &[u8; 32],
    client_ephemeral_public_key: &[u8; 32],
    carrier_binding: &[u8],
) -> [u8; 32] {
    let mut context = Vec::with_capacity(
        client_random.len() + client_ephemeral_public_key.len() + carrier_binding.len(),
    );
    context.extend_from_slice(client_random);
    context.extend_from_slice(client_ephemeral_public_key);
    context.extend_from_slice(carrier_binding);
    umc_crypto::hkdf::extract(invitation_key, &context)
}

/// Verifies a received invitation authenticator without exposing a distinct
/// mismatch branch to callers that implement private-bridge admission.
#[must_use]
pub fn verify_invitation_authenticator(
    invitation_key: &[u8; 32],
    client_random: &[u8; 32],
    client_ephemeral_public_key: &[u8; 32],
    destination_connection_id: &[u8],
    carrier_binding: &[u8],
    received: &[u8],
) -> bool {
    if received.len() != INVITATION_AUTH_LEN {
        return false;
    }
    let expected = invitation_authenticator(
        invitation_key,
        client_random,
        client_ephemeral_public_key,
        destination_connection_id,
        carrier_binding,
    );
    let mut difference = 0u8;
    for (actual, expected) in received.iter().zip(expected) {
        difference |= actual ^ expected;
    }
    difference == 0
}

/// PSK-XX secret derivation with the context binding required by handshake.md
/// §22. The older [`derive_psk_xx_secret`] primitive remains available for
/// callers that already folded this context into their transcript.
///
/// # Panics
///
/// Panics only if the fixed 32-byte HKDF expansion is rejected by the crypto
/// backend, which indicates an internal implementation error.
#[must_use]
pub fn derive_psk_xx_secret_with_context(
    psk: &[u8; 32],
    my_ephemeral: &StaticHandshakeKeyPair,
    peer_ephemeral: &StaticHandshakePublicKey,
    client_ephemeral_public_key: &[u8; 32],
    client_random: &[u8; 32],
    carrier_binding: &[u8],
    transcript_hash: &[u8],
) -> [u8; 32] {
    let psk_extract = derive_psk_extract(
        psk,
        client_random,
        client_ephemeral_public_key,
        carrier_binding,
    );
    let dh_ee = my_ephemeral.diffie_hellman(peer_ephemeral);
    let handshake_extract = umc_crypto::hkdf::extract(&psk_extract, &dh_ee);
    let mut context = Vec::with_capacity(LABEL.len() + transcript_hash.len());
    context.extend_from_slice(LABEL);
    context.extend_from_slice(transcript_hash);
    let expanded =
        umc_crypto::label::expand_label(&handshake_extract, b"psk-xx handshake", &context, 32)
            .expect("fixed PSK-XX output length");
    expanded.try_into().expect("fixed PSK-XX output length")
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

    #[test]
    fn invitation_authenticator_binds_all_context() {
        let key = [7u8; 32];
        let random = [8u8; 32];
        let ephemeral = [9u8; 32];
        let auth = invitation_authenticator(&key, &random, &ephemeral, b"dcid", b"ump.udp/1");
        assert_eq!(
            auth,
            [
                0x30, 0xfe, 0x8a, 0x6a, 0x4f, 0xab, 0x05, 0x52, 0xf0, 0xf7, 0xd4, 0xb9, 0x3e, 0xa8,
                0x93, 0xa2,
            ]
        );
        assert_eq!(auth.len(), INVITATION_AUTH_LEN);
        assert!(verify_invitation_authenticator(
            &key,
            &random,
            &ephemeral,
            b"dcid",
            b"ump.udp/1",
            &auth
        ));
        assert!(!verify_invitation_authenticator(
            &key,
            &random,
            &ephemeral,
            b"other-dcid",
            b"ump.udp/1",
            &auth
        ));
        let mut forged = auth;
        forged[0] ^= 1;
        assert!(!verify_invitation_authenticator(
            &key,
            &random,
            &ephemeral,
            b"dcid",
            b"ump.udp/1",
            &forged
        ));
    }

    #[test]
    fn context_bound_psk_derivation_agrees_and_binds_context() {
        let client = StaticHandshakeKeyPair::generate();
        let server = StaticHandshakeKeyPair::generate();
        let psk = [7u8; 32];
        let random = [3u8; 32];
        let client_secret = derive_psk_xx_secret_with_context(
            &psk,
            &client,
            &server.public(),
            &client.public().0,
            &random,
            b"ump.tcp/1",
            b"transcript",
        );
        let server_secret = derive_psk_xx_secret_with_context(
            &psk,
            &server,
            &client.public(),
            &client.public().0,
            &random,
            b"ump.tcp/1",
            b"transcript",
        );
        assert_eq!(client_secret, server_secret);
        assert_ne!(
            client_secret,
            derive_psk_xx_secret_with_context(
                &psk,
                &server,
                &client.public(),
                &client.public().0,
                &[4u8; 32],
                b"ump.tcp/1",
                b"transcript"
            )
        );
    }

    #[test]
    fn admission_verifies_wire_hello_before_dh() {
        struct Entropy;
        impl umc_types::runtime::EntropySource for Entropy {
            fn fill(&self, out: &mut [u8]) {
                out.fill(0xA5);
            }
        }

        let client = StaticHandshakeKeyPair::generate();
        let server = StaticHandshakeKeyPair::generate();
        let invitation_key = [0x31u8; 32];
        let destination_connection_id = b"destination-cid";
        let carrier_binding = b"ump.udp/1";
        let hello = crate::xx::ClientHello::new_psk_xx(
            &Entropy,
            &client,
            &invitation_key,
            destination_connection_id,
            carrier_binding,
        );
        let encoded = hello.encode().expect("encode hello");
        let decoded = crate::xx::ClientHello::decode(&encoded).expect("decode hello");
        let context = PskAdmissionContext {
            invitation_key,
            destination_connection_id: destination_connection_id.to_vec(),
            carrier_binding: carrier_binding.to_vec(),
        };
        let extract = context
            .derive_handshake_extract1(&decoded, &server)
            .expect("admission");
        let peer_extract = {
            let psk_extract = derive_psk_extract(
                &invitation_key,
                &decoded.client_random,
                &decoded.client_ephemeral_public_key,
                carrier_binding,
            );
            let dh = client.diffie_hellman(&server.public());
            umc_crypto::hkdf::extract(&psk_extract, &dh)
        };
        assert_eq!(extract, peer_extract);

        let mut tampered = decoded;
        tampered.invitation_authenticator[0] ^= 1;
        assert_eq!(
            context.verify_client_hello(&tampered),
            Err(PskAdmissionError::InvalidAuthenticator)
        );
    }

    #[test]
    fn admission_rejects_missing_or_wrong_mode_without_dh() {
        struct Entropy;
        impl umc_types::runtime::EntropySource for Entropy {
            fn fill(&self, out: &mut [u8]) {
                out.fill(0xC3);
            }
        }

        let client = StaticHandshakeKeyPair::generate();
        let server = StaticHandshakeKeyPair::generate();
        let invitation_key = [0x44u8; 32];
        let mut hello = crate::xx::ClientHello::new(&Entropy, &client);
        let context = PskAdmissionContext {
            invitation_key,
            destination_connection_id: b"dcid".to_vec(),
            carrier_binding: b"ump.tcp/1".to_vec(),
        };
        assert_eq!(
            context.verify_client_hello(&hello),
            Err(PskAdmissionError::UnsupportedMode)
        );
        hello.supported_handshake_modes = vec![MODE_PSK_XX.to_vec()];
        assert_eq!(
            context.derive_handshake_extract1(&hello, &server),
            Err(PskAdmissionError::MissingAuthenticator)
        );
    }
}
