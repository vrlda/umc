//! Server-side handshake responder (handshake.md §14-18): turns a
//! `CLIENT_HELLO` into a `SERVER_HELLO` carrying the encrypted server auth
//! block, completes the handshake when `CLIENT_AUTH` arrives, and derives
//! the server's session secrets.
//!
//! The flow is two steps (handshake.md §16, §18):
//! [`respond_hello`] builds `SERVER_HELLO` and the pending handshake state;
//! [`HandshakePending::complete`] processes `CLIENT_AUTH` — decrypts the
//! client's static key + identity binding + signature with the client-auth
//! key, verifies the static key against the one the DH chain used, stores
//! the peer identity, and answers with `SERVER_FINISHED`.
use crate::runtime_adapters::OsEntropy;
use crate::state::RuntimeState;
use umc_crypto::signatures::{IdentityPublicKey, StaticHandshakeKeyPair, StaticHandshakePublicKey};
use umc_handshake::encoding::{CLIENT_AUTH, CLIENT_HELLO, SERVER_HELLO};
use umc_handshake::identity::{endpoint_id, IdentityBinding};
use umc_handshake::traffic::{derive_session_secrets, SessionSecrets};
use umc_handshake::transcript::Transcript;
use umc_handshake::xx::{
    client_signature_input, encrypt_server_auth, finished_key, finished_mac, ClientHello,
    ServerAuthBlock, ServerHello, CRYPTO_PROFILE, MODE_XX,
};
use umc_types::runtime::EntropySource;

/// Protocol version selected by the responder (handshake.md §16).
pub const SELECTED_PROTOCOL_VERSION: u32 = 1;

/// The server-side handshake captured by [`respond_hello`], carried until
/// the client's `CLIENT_AUTH` arrives (handshake.md §18).
#[derive(Debug)]
pub struct HandshakePending {
    transcript: Transcript,
    secret3: [u8; 32],
    secret4: [u8; 32],
    client_static_public_key: StaticHandshakePublicKey,
    server_eid: [u8; 32],
    session_secrets: SessionSecrets,
}

/// The client's verified identity recovered from `CLIENT_AUTH`. Live
/// consumption (session registration) lands with the accept-loop wire
/// wiring; the responder tests drive it today.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PeerIdentity {
    pub client_static_public_key: StaticHandshakePublicKey,
    pub binding: IdentityBinding,
}

impl HandshakePending {
    /// The session secrets this handshake derives, computed at
    /// [`respond_hello`] time from the DH chain (es/se/ss).
    #[must_use]
    pub fn session_secrets(&self) -> &SessionSecrets {
        &self.session_secrets
    }

    /// The static handshake key the client's `CLIENT_AUTH` must match.
    #[must_use]
    #[allow(dead_code)] // consumed by the accept-loop wire wiring
    pub fn expected_client_static(&self) -> &StaticHandshakePublicKey {
        &self.client_static_public_key
    }

    /// Complete the server side of the handshake with the client's
    /// `CLIENT_AUTH` message (handshake.md §18-19): decrypt it with the
    /// client-auth key derived from the DH chain (per the T13 driver),
    /// verify the client's static handshake key, store the client's
    /// identity binding, and build `SERVER_FINISHED` (server signature +
    /// finished MAC). Returns `(SERVER_FINISHED bytes, session secrets,
    /// peer identity)`.
    ///
    /// # Errors
    ///
    /// Returns a message when the auth message cannot be decoded or
    /// decrypted, the recovered client static key does not match the key
    /// the DH chain used, or the client identity binding fails validation.
    #[allow(clippy::similar_names, dead_code)] // consumed by the accept-loop wire wiring
    pub fn complete(
        &self,
        state: &RuntimeState,
        auth_bytes: &[u8],
    ) -> Result<(Vec<u8>, SessionSecrets, PeerIdentity), String> {
        // The client-auth key derives from the transcript hash BEFORE the
        // CLIENT_AUTH message is appended (handshake.md §18).
        let client_auth_transcript = self.transcript.hash;
        let client_auth_key = expand(&self.secret3, b"client auth key", &client_auth_transcript);
        let (ciphertext, _) = umc_wire::bytes::decode(auth_bytes, 16_384)
            .map_err(|_| "client auth framing".to_string())?;
        let plaintext = umc_crypto::aead::PacketKeys::from_traffic_secret(&client_auth_key)
            .map_err(|e| format!("{e:?}"))?
            .open(0, &client_auth_transcript, ciphertext)
            .map_err(|e| format!("client auth open: {e:?}"))?;

        // Plaintext: client static key (32) || identity binding (153) ||
        // client signature (64), as the T13 driver lays it out.
        let recovered_static = StaticHandshakePublicKey(
            plaintext
                .get(..32)
                .and_then(|s| s.try_into().ok())
                .ok_or("client auth truncated")?,
        );
        if recovered_static.0 != self.client_static_public_key.0 {
            return Err("client static key mismatch".into());
        }
        let peer_signature: [u8; 64] = plaintext
            .get(185..185 + 64)
            .and_then(|s| s.try_into().ok())
            .ok_or("client auth truncated")?;
        let binding =
            parse_client_binding(plaintext.get(32..32 + 153).ok_or("client auth truncated")?)?;
        // The binding travels without its signature; verify its structure
        // and the client's transcript-bound signature over it.
        if binding.version != umc_handshake::identity::BINDING_VERSION {
            return Err("client binding version".into());
        }
        if endpoint_id(&binding.identity_public_key) != binding.endpoint_id {
            return Err("client binding endpoint id mismatch".into());
        }
        if binding.static_handshake_public_key.0 != recovered_static.0 {
            return Err("client binding static key mismatch".into());
        }
        let sig_input = client_signature_input(
            &client_auth_transcript,
            &binding.endpoint_id,
            &self.server_eid,
            &recovered_static.0,
            &state.node_identity.static_handshake.public().0,
        );
        if !binding
            .identity_public_key
            .verify(&sig_input, &peer_signature)
        {
            return Err("client signature invalid".into());
        }
        let peer = PeerIdentity {
            client_static_public_key: recovered_static,
            binding,
        };

        // Append CLIENT_AUTH; the finished keys and the server signature
        // bind the transcript hash AFTER the message (handshake.md §19).
        let mut transcript = self.transcript.clone();
        transcript
            .update_message(CLIENT_AUTH, auth_bytes)
            .map_err(|e| format!("transcript: {e:?}"))?;
        let server_finished_key = finished_key(&self.secret4, b"server finished", &transcript.hash);
        let server_mac = finished_mac(&server_finished_key, &transcript.hash);
        let server_sig_input: [u8; 32] = {
            use blake2::Digest;
            let mut hasher = blake2::Blake2s256::new();
            hasher.update(b"UMP-SERVER-AUTH-v1");
            hasher.update(transcript.hash);
            hasher.update(self.server_eid);
            hasher.update(peer.binding.endpoint_id);
            hasher.update(self.client_static_public_key.0);
            hasher.update(peer.client_static_public_key.0);
            hasher.finalize().into()
        };
        let server_signature = state.node_identity.identity.sign(&server_sig_input);
        let mut server_finished = Vec::with_capacity(96);
        server_finished.extend_from_slice(&server_signature);
        server_finished.extend_from_slice(&server_mac);
        Ok((server_finished, self.session_secrets.clone(), peer))
    }
}

/// Reassemble an [`IdentityBinding`] from the canonical signed bytes
/// (identity.rs §4.3 layout). The binding's own signature is not
/// transmitted; the caller verifies the client's signature instead.
///
/// # Errors
///
/// Returns a message when the slice is shorter than the fixed layout.
#[allow(dead_code)] // consumed by the accept-loop wire wiring
fn parse_client_binding(bytes: &[u8]) -> Result<IdentityBinding, String> {
    let read = |start: usize, len: usize| -> Result<&[u8], String> {
        bytes
            .get(start..start + len)
            .ok_or_else(|| "binding truncated".to_string())
    };
    let version = *read(0, 1)?
        .first()
        .ok_or_else(|| "binding truncated".to_string())?;
    let endpoint_id = read(1, 32)?.try_into().map_err(|_| "endpoint id")?;
    let identity_public_key =
        IdentityPublicKey(read(33, 32)?.try_into().map_err(|_| "identity key")?);
    let static_handshake_public_key =
        StaticHandshakePublicKey(read(65, 32)?.try_into().map_err(|_| "static key")?);
    let be = |start: usize| -> Result<u64, String> {
        Ok(u64::from_be_bytes(
            read(start, 8)?.try_into().map_err(|_| "u64")?,
        ))
    };
    let capabilities_hash = read(121, 32)?.try_into().map_err(|_| "capabilities")?;
    Ok(IdentityBinding {
        version,
        endpoint_id,
        identity_public_key,
        static_handshake_public_key,
        not_before: be(97)?,
        not_after: be(105)?,
        sequence: be(113)?,
        capabilities_hash,
        // Absent from the wire; the client's transcript-bound signature is
        // verified separately.
        signature: [0u8; 64],
    })
}

#[allow(dead_code)] // consumed by the accept-loop wire wiring
fn expand(secret: &[u8; 32], label: &[u8], context: &[u8; 32]) -> [u8; 32] {
    let out =
        umc_crypto::label::expand_label(secret, label, context, 32).expect("32-byte expansion");
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

/// Answer a `CLIENT_HELLO` with a `SERVER_HELLO` and the pending handshake
/// state. The full DH chain (es/se/ss) completes with the client's static
/// handshake key (handshake.md §26).
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
) -> Result<(Vec<u8>, HandshakePending), String> {
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
    // symmetric, so the server's shares equal the client's. `secret3` also
    // keys the client-auth message the responder will decrypt next.
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
    let server_eid = endpoint_id(&binding.identity_public_key);
    let pending = HandshakePending {
        transcript,
        secret3,
        secret4,
        client_static_public_key: client_static_public_key.clone(),
        server_eid,
        session_secrets: derive_session_secrets(&secret4, &final_transcript),
    };
    Ok((server_hello_bytes, pending))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use tokio::sync::mpsc;
    use umc_crypto::signatures::IdentityKeyPair;
    use umc_handshake::xx::{client_signature_input, complete_client_side, decrypt_server_auth};

    struct TestEntropy;

    impl EntropySource for TestEntropy {
        fn fill(&self, out: &mut [u8]) {
            out.fill(0x5C);
        }
    }

    fn test_state() -> RuntimeState {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "umcd-responder-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let config = NodeConfig {
            data_dir: dir,
            ..NodeConfig::default()
        };
        let (tx, _rx) = mpsc::channel(1);
        RuntimeState::new(config, tx).expect("state")
    }

    fn client_identity() -> (
        IdentityKeyPair,
        StaticHandshakeKeyPair,
        StaticHandshakeKeyPair,
    ) {
        let identity = IdentityKeyPair::generate();
        let static_key = StaticHandshakeKeyPair::generate();
        let ephemeral = StaticHandshakeKeyPair::generate();
        (identity, static_key, ephemeral)
    }

    /// The client's `CLIENT_AUTH` message, mirroring the T13 driver
    /// (xx.rs): client static key + the client's identity binding + the
    /// client signature, sealed with the client-auth key derived from
    /// secret3 and the transcript before the message is appended.
    #[allow(clippy::too_many_arguments, clippy::similar_names)]
    fn build_client_auth(
        client_identity: &IdentityKeyPair,
        client_static: &StaticHandshakeKeyPair,
        client_ephemeral: &StaticHandshakeKeyPair,
        hello: &ClientHello,
        server_hello: &ServerHello,
        server_binding: &IdentityBinding,
        carrier_binding: &[u8],
    ) -> Vec<u8> {
        let mut transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, carrier_binding);
        transcript
            .update_message(CLIENT_HELLO, &hello.encode().expect("hello"))
            .expect("transcript");
        let server_auth_transcript = transcript.hash;
        let dh_ee = client_ephemeral.diffie_hellman(&StaticHandshakePublicKey(
            server_hello.server_ephemeral_public_key,
        ));
        let extract1 = umc_crypto::hkdf::extract(&[0u8; 32], &dh_ee);
        let server_block = decrypt_server_auth(
            &extract1,
            &server_auth_transcript,
            &server_hello.encrypted_server_authentication,
            &server_hello.server_ephemeral_public_key,
            &server_hello.server_random,
            &server_hello.selected_crypto_profile,
        )
        .expect("server auth");
        let server_static_pub = StaticHandshakePublicKey(server_block.server_static_public_key);
        transcript
            .update_message(SERVER_HELLO, &server_hello.encode().expect("server hello"))
            .expect("transcript");
        let dh_es = client_ephemeral.diffie_hellman(&server_static_pub);
        let secret2 = umc_crypto::hkdf::extract(&extract1, &dh_es);
        let dh_se = client_static.diffie_hellman(&StaticHandshakePublicKey(
            server_hello.server_ephemeral_public_key,
        ));
        let secret3 = umc_crypto::hkdf::extract(&secret2, &dh_se);
        let auth_key = expand(&secret3, b"client auth key", &transcript.hash);
        let client_binding = IdentityBinding::sign(
            client_identity,
            &client_static.public(),
            0,
            u64::MAX,
            0,
            [0u8; 32],
        );
        let client_eid = endpoint_id(&client_identity.public());
        let server_eid = endpoint_id(&server_binding.identity_public_key);
        let sig_input = client_signature_input(
            &transcript.hash,
            &client_eid,
            &server_eid,
            &client_static.public().0,
            &server_static_pub.0,
        );
        let signature = client_identity.sign(&sig_input);
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&client_static.public().0);
        plaintext.extend_from_slice(&client_binding.signed_bytes());
        plaintext.extend_from_slice(&signature);
        let encrypted = umc_crypto::aead::PacketKeys::from_traffic_secret(&auth_key)
            .expect("keys")
            .seal(0, &transcript.hash, &plaintext)
            .expect("seal");
        let mut auth_bytes = Vec::new();
        umc_wire::bytes::encode(&mut auth_bytes, &encrypted, 16_384).expect("bytes");
        auth_bytes
    }

    #[test]
    fn responder_completes_the_client_auth_continuation() {
        let state = test_state();
        let (client_identity, client_static, client_ephemeral) = client_identity();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let hello_bytes = hello.encode().expect("hello");

        let (server_hello_bytes, pending) =
            respond_hello(&state, b"ump.tcp/1", &hello_bytes, &client_static.public())
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

        // The server's own identity binding rides in the auth block; the
        // client harness signs the same shape into CLIENT_AUTH.
        let server_binding = IdentityBinding::sign(
            &state.node_identity.identity,
            &state.node_identity.static_handshake.public(),
            0,
            u64::MAX,
            0,
            [0u8; 32],
        );
        let auth_bytes = build_client_auth(
            &client_identity,
            &client_static,
            &client_ephemeral,
            &hello,
            &server_hello,
            &server_binding,
            b"ump.tcp/1",
        );

        let (server_finished, secrets, peer) =
            pending.complete(&state, &auth_bytes).expect("complete");
        assert_eq!(peer.client_static_public_key, client_static.public());
        assert_eq!(
            peer.binding.endpoint_id,
            endpoint_id(&client_identity.public())
        );
        assert_eq!(peer.binding.identity_public_key, client_identity.public());
        // SERVER_FINISHED = 64-byte signature + 32-byte finished MAC.
        assert_eq!(server_finished.len(), 96);

        // The client side derives identical session secrets against the
        // same transcript (complete_client_side, as the live client does).
        let (client_secrets, _) = complete_client_side(
            &client_identity,
            &client_static,
            &client_ephemeral,
            &hello,
            &server_hello,
            &TestEntropy,
            b"ump.tcp/1",
        )
        .expect("client side");
        assert_eq!(client_secrets.client, secrets.client);
        assert_eq!(client_secrets.server, secrets.server);
    }

    #[test]
    fn responder_rejects_a_mismatched_client_static_key() {
        let state = test_state();
        let (_client_identity, client_static, client_ephemeral) = client_identity();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let hello_bytes = hello.encode().expect("hello");
        let (server_hello_bytes, pending) =
            respond_hello(&state, b"ump.tcp/1", &hello_bytes, &client_static.public())
                .expect("responder");
        let server_hello = ServerHello::decode(&server_hello_bytes).expect("server hello");
        let server_binding = IdentityBinding::sign(
            &state.node_identity.identity,
            &state.node_identity.static_handshake.public(),
            0,
            u64::MAX,
            0,
            [0u8; 32],
        );
        // The client encrypts for a static key the server never saw: the
        // client-auth key cannot decrypt the message (same hello/ephemeral).
        let (identity, other_static, _ephemeral) = client_identity();
        let auth_bytes = build_client_auth(
            &identity,
            &other_static,
            &client_ephemeral,
            &hello,
            &server_hello,
            &server_binding,
            b"ump.tcp/1",
        );
        assert!(pending.complete(&state, &auth_bytes).is_err());
    }

    #[test]
    fn responder_rejects_garbage_auth() {
        let state = test_state();
        let (_identity, client_static, client_ephemeral) = client_identity();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let hello_bytes = hello.encode().expect("hello");
        let (_server_hello_bytes, pending) =
            respond_hello(&state, b"ump.tcp/1", &hello_bytes, &client_static.public())
                .expect("responder");
        assert!(pending.complete(&state, b"garbage").is_err());
    }
}
