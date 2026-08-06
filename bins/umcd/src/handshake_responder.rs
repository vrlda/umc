//! Server-side handshake responder (handshake.md §14-18): turns a
//! `CLIENT_HELLO` into a `SERVER_HELLO` carrying the encrypted server auth
//! block, and derives the server's session secrets.
use crate::runtime_adapters::OsEntropy;
use crate::state::RuntimeState;
use umc_crypto::signatures::{StaticHandshakeKeyPair, StaticHandshakePublicKey};
use umc_handshake::encoding::{CLIENT_HELLO, SERVER_HELLO};
use umc_handshake::identity::IdentityBinding;
use umc_handshake::traffic::{derive_session_secrets, SessionSecrets};
use umc_handshake::transcript::Transcript;
use umc_handshake::xx::{
    encrypt_server_auth, ClientHello, ServerAuthBlock, ServerHello, CRYPTO_PROFILE, MODE_XX,
};
use umc_types::runtime::EntropySource;

/// Protocol version selected by the responder (handshake.md §16).
pub const SELECTED_PROTOCOL_VERSION: u32 = 1;

/// Answer a `CLIENT_HELLO` with a `SERVER_HELLO` and the server's session
/// secrets.
///
/// The `client_static_public_key` completes the DH chain (es/se/ss) used for
/// the full session-secret derivation (handshake.md §26). In the live
/// protocol that key arrives in `CLIENT_AUTH` (handshake.md §18), so the
/// accept loop passes a provisional value until Task 20+ parses
/// `CLIENT_AUTH`; the `SERVER_HELLO` itself binds only `DH_ee` and the
/// transcript, so it is always valid.
///
/// # Errors
///
/// Returns a message when the hello body cannot be decoded, a transcript
/// update or the auth-block encryption fails, or the hello cannot be
/// encoded.
// The DH variable names follow handshake.md §14-18 (DH_ee, DH_es, DH_se,
// DH_ss) as in the deterministic driver.
#[allow(clippy::similar_names)]
pub fn respond_hello(
    state: &RuntimeState,
    carrier_binding: &[u8],
    hello_bytes: &[u8],
    client_static_public_key: &StaticHandshakePublicKey,
) -> Result<(Vec<u8>, SessionSecrets), String> {
    let hello = ClientHello::decode(hello_bytes).map_err(|e| format!("client hello: {e:?}"))?;
    let server_ephemeral = StaticHandshakeKeyPair::generate();
    let mut server_random = [0u8; 32];
    OsEntropy.fill(&mut server_random);

    // Transcript through CLIENT_HELLO (handshake.md §14-15).
    let mut transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, carrier_binding);
    transcript
        .update_message(CLIENT_HELLO, hello_bytes)
        .map_err(|e| format!("transcript: {e:?}"))?;

    // DH_ee -> extract1 -> server-auth key (handshake.md §16.1).
    let dh_ee = server_ephemeral
        .diffie_hellman(&StaticHandshakePublicKey(hello.client_ephemeral_public_key));
    let extract1 = umc_crypto::hkdf::extract(&[0u8; 32], &dh_ee);
    let binding = IdentityBinding::sign(
        &state.node_identity.identity,
        &state.node_identity.static_handshake.public(),
        0,
        u64::MAX,
        0,
        [0u8; 32],
    );
    // The auth-block AAD binds the transcript hash BEFORE the SERVER_HELLO
    // message is appended (handshake.md §16.1).
    let server_auth_transcript = transcript.hash;
    let encrypted_auth = encrypt_server_auth(
        &extract1,
        &server_auth_transcript,
        &ServerAuthBlock {
            server_static_public_key: state.node_identity.static_handshake.public().0,
            server_identity_binding: binding.signed_bytes(),
        },
        &server_ephemeral.public().0,
        &server_random,
        CRYPTO_PROFILE,
    )
    .map_err(|e| format!("server auth: {e:?}"))?;

    let server_hello = ServerHello {
        server_random,
        server_ephemeral_public_key: server_ephemeral.public().0,
        selected_protocol_version: SELECTED_PROTOCOL_VERSION,
        selected_crypto_profile: CRYPTO_PROFILE.to_vec(),
        selected_handshake_mode: MODE_XX.to_vec(),
        encrypted_server_authentication: encrypted_auth,
        padding: vec![0u8; 32],
    };
    let server_hello_bytes = server_hello
        .encode()
        .map_err(|e| format!("server hello: {e:?}"))?;
    transcript
        .update_message(SERVER_HELLO, &server_hello_bytes)
        .map_err(|e| format!("transcript: {e:?}"))?;
    let final_transcript = transcript.hash;

    // Full DH chain es/se/ss -> session secrets (handshake.md §26). DH is
    // symmetric, so the server's shares equal the client's.
    let dh_es = state
        .node_identity
        .static_handshake
        .diffie_hellman(&StaticHandshakePublicKey(hello.client_ephemeral_public_key));
    let secret2 = umc_crypto::hkdf::extract(&extract1, &dh_es);
    let dh_se = server_ephemeral.diffie_hellman(client_static_public_key);
    let secret3 = umc_crypto::hkdf::extract(&secret2, &dh_se);
    let dh_ss = state
        .node_identity
        .static_handshake
        .diffie_hellman(client_static_public_key);
    let secret4 = umc_crypto::hkdf::extract(&secret3, &dh_ss);
    let server_secrets = derive_session_secrets(&secret4, &final_transcript);
    Ok((server_hello_bytes, server_secrets))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use tokio::sync::mpsc;
    use umc_core::node::NodeIdentity;
    use umc_handshake::xx::complete_client_side;

    struct TestEntropy;

    impl EntropySource for TestEntropy {
        fn fill(&self, out: &mut [u8]) {
            out.fill(0x5C);
        }
    }

    fn test_state() -> RuntimeState {
        let dir = std::env::temp_dir().join(format!("umcd-responder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = NodeConfig {
            data_dir: dir,
            ..NodeConfig::default()
        };
        let (tx, _rx) = mpsc::channel(1);
        RuntimeState::new(config, tx).expect("state")
    }

    #[test]
    fn responder_builds_valid_server_hello() {
        let state = test_state();
        // The client identity stands in for the remote peer; its static
        // handshake key completes the server's DH chain.
        let client_identity = NodeIdentity::generate(&TestEntropy);
        let client_ephemeral = StaticHandshakeKeyPair::generate();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let hello_bytes = hello.encode().expect("hello");

        let (server_hello_bytes, server_secrets) = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello_bytes,
            &client_identity.static_handshake.public(),
        )
        .expect("responder");

        let server_hello = ServerHello::decode(&server_hello_bytes).expect("server hello");
        assert_eq!(
            server_hello.selected_protocol_version,
            SELECTED_PROTOCOL_VERSION
        );
        assert_eq!(
            server_hello.selected_crypto_profile,
            CRYPTO_PROFILE.to_vec()
        );
        assert_eq!(server_hello.selected_handshake_mode, MODE_XX.to_vec());

        // The client completes its side with the same ephemeral, hello and
        // server hello; both sides must derive identical traffic secrets.
        let (client_secrets, _) = complete_client_side(
            &client_identity.identity,
            &client_identity.static_handshake,
            &client_ephemeral,
            &hello,
            &server_hello,
            &TestEntropy,
            b"ump.tcp/1",
        )
        .expect("client side");
        assert_eq!(client_secrets.client, server_secrets.client);
    }
}
