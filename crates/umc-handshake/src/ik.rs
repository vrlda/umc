//! IK-mode session resumption (handshake.md §35): the v1 resumption scheme.
//!
//! A resumed session skips the static DH chain (es/se/ss) and the
//! `CLIENT_AUTH`/`SERVER_FINISHED` exchange: the ticket's PSK replaces the
//! identity binding as the shared secret, and the resumed traffic secrets
//! derive from `DH(eph, eph)` extracted under the PSK, expanded over the
//! resume transcript.
//!
//! This is the v1 resumption scheme: a full IK handshake with a resumed
//! transcript is future work (Phase D7b); the secrets derived here ARE the
//! resumed session's traffic keys.
use umc_crypto::signatures::{StaticHandshakeKeyPair, StaticHandshakePublicKey};

/// The IK handshake mode (handshake.md §35): the resume handshake's
/// transcript and `SERVER_HELLO` select this mode.
pub const MODE_IK: &[u8] = b"IK";

/// The secrets of a resumed session (handshake.md §35): the PSK and the two
/// traffic secrets, derived identically on both sides from the ephemeral DH
/// and the resume transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeSecrets {
    /// The resumption PSK (`resumption_psk` over the previous session's
    /// resumption secret and the ticket nonce).
    pub psk: [u8; 32],
    /// The resumed client traffic secret.
    pub client: [u8; 32],
    /// The resumed server traffic secret.
    pub server: [u8; 32],
}

/// Derives the resumed session secrets (handshake.md §35): `ee = DH(eph,
/// eph)`, `extract(psk, ee)`, then expand the labels `"client resumption
/// traffic"` and `"server resumption traffic"` over the transcript context —
/// mirroring the XX structure without the es/se/ss chain (the PSK replaces
/// the identity binding).
///
/// DH is symmetric, so each side passes its own ephemeral private key and
/// the peer's ephemeral public key from the hello exchange; both derive the
/// same `ee` and therefore the same traffic secrets.
#[must_use]
pub fn derive_resumption_secrets(
    psk: &[u8; 32],
    my_ephemeral: &StaticHandshakeKeyPair,
    peer_ephemeral_public: &[u8; 32],
    transcript_context: &[u8; 32],
) -> ResumeSecrets {
    let ee = my_ephemeral.diffie_hellman(&StaticHandshakePublicKey(*peer_ephemeral_public));
    let extracted = umc_crypto::hkdf::extract(psk, &ee);
    ResumeSecrets {
        psk: *psk,
        client: expand(&extracted, b"client resumption traffic", transcript_context),
        server: expand(&extracted, b"server resumption traffic", transcript_context),
    }
}

fn expand(secret: &[u8; 32], label: &[u8], context: &[u8; 32]) -> [u8; 32] {
    let out =
        umc_crypto::label::expand_label(secret, label, context, 32).expect("32-byte expansion");
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both sides derive identical traffic secrets from the same ephemeral
    /// pair and transcript; different ephemerals change every secret
    /// (handshake.md §35).
    #[test]
    fn resumption_secrets_agree() {
        let psk = [7u8; 32];
        let context = [9u8; 32];
        let client_eph = StaticHandshakeKeyPair::generate();
        let server_eph = StaticHandshakeKeyPair::generate();

        let client_side =
            derive_resumption_secrets(&psk, &client_eph, &server_eph.public().0, &context);
        let server_side =
            derive_resumption_secrets(&psk, &server_eph, &client_eph.public().0, &context);
        assert_eq!(client_side.client, server_side.client);
        assert_eq!(client_side.server, server_side.server);
        assert_eq!(client_side.psk, psk);
        assert_ne!(client_side.client, client_side.server);

        // Different ephemerals: the resumed traffic secrets must differ.
        let other_eph = StaticHandshakeKeyPair::generate();
        let other_side =
            derive_resumption_secrets(&psk, &other_eph, &server_eph.public().0, &context);
        assert_ne!(other_side.client, client_side.client);
        assert_ne!(other_side.server, client_side.server);
    }

    /// The transcript context binds the secrets: a different resume
    /// transcript changes both traffic secrets.
    #[test]
    fn transcript_context_changes_everything() {
        let psk = [7u8; 32];
        let client_eph = StaticHandshakeKeyPair::generate();
        let server_eph = StaticHandshakeKeyPair::generate();
        let a = derive_resumption_secrets(&psk, &client_eph, &server_eph.public().0, &[1u8; 32]);
        let b = derive_resumption_secrets(&psk, &client_eph, &server_eph.public().0, &[2u8; 32]);
        assert_ne!(a.client, b.client);
        assert_ne!(a.server, b.server);
    }
}
