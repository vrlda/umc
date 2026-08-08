//! Server-side handshake responder (handshake.md §14-18): turns a
//! `CLIENT_HELLO` into a `SERVER_HELLO` carrying the encrypted server auth
//! block, completes the handshake when `CLIENT_AUTH` arrives, and derives
//! the server's session secrets.
//!
//! The flow is two steps (handshake.md §16, §18):
//! [`respond_hello`] builds `SERVER_HELLO` and the pending handshake state;
//! [`HandshakePending::complete`] processes `CLIENT_AUTH` — decrypts the
//! client's real static key + identity binding + signature with the
//! client-auth key, validates the binding and the transcript-bound
//! signature (the identity proof), stores the peer identity, and answers
//! with `SERVER_FINISHED`.
//!
//! The DH chain (es/se/ss) is derived with the client's EPHEMERAL standing
//! in for the static (the accept loop's provisional, handshake.md §18): the
//! real static key only arrives inside `CLIENT_AUTH`, encrypted with a key
//! derived from that same provisional chain — the circularity is resolved
//! by deriving the client-auth key provisionally on BOTH sides and carrying
//! the real static as authenticated payload. `complete` verifies the real
//! static against the binding; the provisional never becomes peer identity.
use crate::runtime_adapters::OsEntropy;
use crate::state::RuntimeState;
use umc_crypto::signatures::{IdentityPublicKey, StaticHandshakeKeyPair, StaticHandshakePublicKey};
use umc_handshake::encoding::{CLIENT_AUTH, CLIENT_HELLO, SERVER_HELLO};
use umc_handshake::identity::{endpoint_id, IdentityBinding};
use umc_handshake::traffic::{derive_session_secrets, SessionSecrets};
use umc_handshake::transcript::Transcript;
use umc_handshake::xx::{
    build_version_negotiation, canonical_capabilities, capabilities_hash, client_signature_input,
    decrypt_client_auth, encrypt_server_auth, finished_key, finished_mac, select_version,
    ClientHello, ServerAuthBlock, ServerHello, CRYPTO_PROFILE, MODE_XX, SUPPORTED_PROTOCOL_VERSION,
};
use umc_types::runtime::EntropySource;

#[cfg(test)]
use umc_handshake::xx::parse_version_negotiation;

/// Protocol version selected by the responder (handshake.md §16,
/// compatibility.md §5.2): the single version this implementation
/// supports. The selection itself is `select_version` over the client's
/// offered list; a list that excludes it gets a Version-Negotiation
/// packet instead.
pub const SELECTED_PROTOCOL_VERSION: u32 = SUPPORTED_PROTOCOL_VERSION;

/// Clock skew tolerated when checking a binding's validity window
/// (handshake.md §4.4).
pub const BINDING_SKEW_MS: u64 = 300_000;

/// Length of an [`IdentityBinding`]'s signed bytes on the wire.
pub const BINDING_SIGNED_LEN: usize = 153;

/// The binding's own signature rides after its signed bytes: the recipient
/// validates the whole binding with `IdentityBinding::validate` before
/// accepting the session (handshake.md §4.3).
pub const BINDING_SIGNATURE_LEN: usize = 64;

/// Full on-wire length of an [`IdentityBinding`].
pub const BINDING_WIRE_LEN: usize = BINDING_SIGNED_LEN + BINDING_SIGNATURE_LEN;

/// The server-side handshake captured by [`respond_hello`], carried until
/// the client's `CLIENT_AUTH` arrives (handshake.md §18).
#[derive(Debug)]
pub struct HandshakePending {
    transcript: Transcript,
    secret3: [u8; 32],
    secret4: [u8; 32],
    server_eid: [u8; 32],
    session_secrets: SessionSecrets,
}

/// The client's verified identity recovered from `CLIENT_AUTH`: the real
/// static handshake key and the identity binding, registered by the accept
/// loop as the session's peer identity (handshake.md §18).
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub client_static_public_key: StaticHandshakePublicKey,
    pub binding: IdentityBinding,
}

/// The responder's answer to a `CLIENT_HELLO` (handshake.md §16): either a
/// `SERVER_HELLO` plus the pending handshake state for the `CLIENT_AUTH`
/// continuation, or a Version-Negotiation packet when the client's offered
/// protocol versions exclude the supported one (compatibility.md §5.2).
#[derive(Debug)]
pub enum ResponderResponse {
    /// A `SERVER_HELLO` and the pending state for the client's
    /// `CLIENT_AUTH` continuation.
    ServerHello {
        bytes: Vec<u8>,
        pending: Box<HandshakePending>,
    },
    /// A Version-Negotiation packet (wire-format §25): the client's
    /// `supported_protocol_versions` excludes
    /// [`SUPPORTED_PROTOCOL_VERSION`]. The accept loop sends the raw VN
    /// bytes and closes the connection — the client retries with a fresh
    /// connection offering a supported version (compatibility.md §5.2).
    VersionNegotiation { bytes: Vec<u8> },
}

impl HandshakePending {
    /// The session secrets this handshake derives, computed at
    /// [`respond_hello`] time from the DH chain (es/se/ss).
    #[must_use]
    #[allow(dead_code)] // accessor for the secrets `complete` also returns
    pub fn session_secrets(&self) -> &SessionSecrets {
        &self.session_secrets
    }

    /// Complete the server side of the handshake with the client's
    /// `CLIENT_AUTH` message (handshake.md §18-19): decrypt it with the
    /// client-auth key derived from the DH chain (per the T13 driver),
    /// validate the client's identity binding (`IdentityBinding::validate`:
    /// version, endpoint-id binding, signature, validity window), verify
    /// the recovered static key against the binding and the client's
    /// transcript-bound signature, and build `SERVER_FINISHED` (server
    /// signature + finished MAC). Returns `(SERVER_FINISHED bytes, session
    /// secrets, peer identity)`.
    ///
    /// The DH chain's static is the client's EPHEMERAL (the accept loop's
    /// provisional, handshake.md §18) — the real static only arrives here,
    /// encrypted with the provisional-derived client-auth key; the binding
    /// and signature are the identity proof, so the recovered static is
    /// verified against the binding, not the provisional.
    ///
    /// # Errors
    ///
    /// Returns a message when the auth message cannot be decoded or
    /// decrypted, the client identity binding fails validation (the session
    /// is refused), or the client's transcript-bound signature does not
    /// verify.
    #[allow(clippy::similar_names)]
    pub fn complete(
        &self,
        state: &RuntimeState,
        auth_bytes: &[u8],
        now_ms: u64,
    ) -> Result<(Vec<u8>, SessionSecrets, PeerIdentity), String> {
        // The client-auth key derives from the transcript hash BEFORE the
        // CLIENT_AUTH message is appended (handshake.md §18).
        let client_auth_transcript = self.transcript.hash;
        let client_auth_key = expand(&self.secret3, b"client auth key", &client_auth_transcript);
        let (ciphertext, _) = umc_wire::bytes::decode(auth_bytes, 16_384)
            .map_err(|_| "client auth framing".to_string())?;
        let plaintext = decrypt_client_auth(&client_auth_key, &client_auth_transcript, ciphertext)?;

        // Plaintext: client static key (32) || identity binding (217: signed
        // bytes + the binding's own signature) || client signature (64), as
        // the T13 driver lays it out.
        let recovered_static = StaticHandshakePublicKey(
            plaintext
                .get(..32)
                .and_then(|s| s.try_into().ok())
                .ok_or("client auth truncated")?,
        );
        let peer_signature: [u8; 64] = plaintext
            .get(32 + BINDING_WIRE_LEN..32 + BINDING_WIRE_LEN + 64)
            .and_then(|s| s.try_into().ok())
            .ok_or("client auth truncated")?;
        let binding = parse_client_binding(
            plaintext
                .get(32..32 + BINDING_WIRE_LEN)
                .ok_or("client auth truncated")?,
        )?;
        // The identity binding must be self-consistent and signed by the
        // claimed identity key; a binding signed by a different key is
        // refused before the session is accepted (handshake.md §4.3).
        binding
            .validate(now_ms, BINDING_SKEW_MS)
            .map_err(|e| format!("client binding invalid: {e:?}"))?;
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
        // The server signature binds the server's and the client's REAL
        // static keys (the T13 driver layout; the client checks it against
        // its own material).
        let server_sig_input: [u8; 32] = {
            use blake2::Digest;
            let mut hasher = blake2::Blake2s256::new();
            hasher.update(b"UMP-SERVER-AUTH-v1");
            hasher.update(transcript.hash);
            hasher.update(self.server_eid);
            hasher.update(peer.binding.endpoint_id);
            hasher.update(state.node_identity.static_handshake.public().0);
            hasher.update(peer.client_static_public_key.0);
            hasher.finalize().into()
        };
        let server_signature = state.node_identity.identity.sign(&server_sig_input);
        let mut server_finished = Vec::with_capacity(96);
        server_finished.extend_from_slice(&server_signature);
        server_finished.extend_from_slice(&server_mac);
        Ok((server_finished, self.session_secrets.clone(), peer))
    }

    /// Verify the client's `CLIENT_FINISHED` confirmation MAC (handshake.md
    /// §20) against the transcript including `SERVER_FINISHED`, mirroring
    /// the T13 driver's snapshot order: the client finished key derives
    /// from the transcript hash AFTER `CLIENT_AUTH` is appended (the hash
    /// BEFORE `SERVER_FINISHED`), and the confirmation MAC covers the hash
    /// AFTER `SERVER_FINISHED` is appended.
    ///
    /// # Errors
    ///
    /// Returns a message when the confirmation MAC does not match (the
    /// session is refused and nothing is registered).
    pub fn verify_client_finished(
        &self,
        auth_bytes: &[u8],
        server_finished: &[u8],
        client_finished: &[u8],
    ) -> Result<(), String> {
        let mut transcript = self.transcript.clone();
        umc_handshake::xx::verify_client_finished(
            &self.secret4,
            &mut transcript,
            auth_bytes,
            server_finished,
            client_finished,
        )
    }
}

/// Reassemble an [`IdentityBinding`] from the canonical signed bytes plus
/// its own signature (identity.rs §4.3 layout). The client transmits the
/// full binding; the server validates it wholesale with
/// [`IdentityBinding::validate`] before accepting the session.
///
/// # Errors
///
/// Returns a message when the slice is shorter than the fixed layout.
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
    let signature = read(BINDING_SIGNED_LEN, 64)?
        .try_into()
        .map_err(|_| "signature")?;
    Ok(IdentityBinding {
        version,
        endpoint_id,
        identity_public_key,
        static_handshake_public_key,
        not_before: be(97)?,
        not_after: be(105)?,
        sequence: be(113)?,
        capabilities_hash,
        signature,
    })
}

pub(crate) fn expand(secret: &[u8; 32], label: &[u8], context: &[u8; 32]) -> [u8; 32] {
    let out =
        umc_crypto::label::expand_label(secret, label, context, 32).expect("32-byte expansion");
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

/// Answer a `CLIENT_HELLO` with a `SERVER_HELLO` and the pending handshake
/// state. The DH chain (es/se/ss) completes with the client's static
/// handshake key — the accept loop's PROVISIONAL (the client's ephemeral
/// standing in for the static, handshake.md §18): the real static only
/// arrives inside `CLIENT_AUTH`, so both sides derive the same chain and
/// the client-auth key on the provisional inputs.
///
/// Negotiation runs before any secret derivation:
/// - Version (compatibility.md §5.2, handshake.md §16): the protocol
///   version is [`select_version`] over the client's offered list; a list
///   that excludes [`SUPPORTED_PROTOCOL_VERSION`] answers with a
///   Version-Negotiation packet (`ResponderResponse::VersionNegotiation`)
///   and the handshake does NOT continue. The VN echoes the client's
///   connection IDs (VN DCID ← client SCID, VN SCID ← client DCID, RFC
///   9000 §17.2.1) and lists our supported versions; the accept loop sends
///   it and closes the connection.
/// - Capabilities (compatibility.md §5.4): the client's capabilities hash
///   (inside the transcript-bound `CLIENT_HELLO`) must equal the
///   canonical set's hash; a mismatch refuses the handshake. The server's
///   own canonical hash rides in the first 32 bytes of the `SERVER_HELLO`
///   padding (the documented convention the client verifies), so both
///   sides' capability sets are transcript-bound and the session's
///   effective set is their intersection (v1: the canonical set).
///
/// # Errors
///
/// Returns a message when the hello body cannot be decoded, the client's
/// capabilities hash mismatches the canonical set, a transcript update or
/// the auth-block encryption fails, or the hello cannot be encoded.
// The DH variable names follow handshake.md §14-18 (DH_ee, DH_es, DH_se,
// DH_ss) as in the deterministic driver.
#[allow(clippy::similar_names)]
pub fn respond_hello(
    state: &RuntimeState,
    carrier_binding: &[u8],
    hello_bytes: &[u8],
    client_static_public_key: &StaticHandshakePublicKey,
    initial_dcid: &[u8],
    initial_scid: &[u8],
) -> Result<ResponderResponse, String> {
    let hello = ClientHello::decode(hello_bytes).map_err(|e| format!("client hello: {e:?}"))?;

    // Version negotiation (compatibility.md §5.2, handshake.md §16): a
    // client offering no supported version gets a Version-Negotiation
    // packet and NO SERVER_HELLO — the handshake stops here.
    let Some(selected_version) = select_version(&hello.supported_protocol_versions) else {
        return Ok(ResponderResponse::VersionNegotiation {
            bytes: build_version_negotiation(
                initial_scid,
                initial_dcid,
                &[SELECTED_PROTOCOL_VERSION],
            ),
        });
    };

    // Capability negotiation (compatibility.md §5.4): the client's hash is
    // inside the transcript-bound CLIENT_HELLO; a mismatch is a protocol
    // violation (or a peer speaking a different capability set) and the
    // handshake is refused.
    if hello.capabilities_hash != capabilities_hash(&canonical_capabilities()) {
        return Err("client capabilities hash mismatch".into());
    }

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
        selected_protocol_version: selected_version,
        selected_crypto_profile: CRYPTO_PROFILE.to_vec(),
        selected_handshake_mode: MODE_XX.to_vec(),
        encrypted_server_authentication: encrypted_auth,
        // The server's capabilities hash rides in the first 32 bytes of
        // the padding (compatibility.md §5.4, documented convention): the
        // client reads it from the padding prefix and verifies it against
        // the canonical set. The padding is inside the encoded
        // SERVER_HELLO, so the hash is transcript-bound like every other
        // hello field.
        padding: {
            let mut padding = Vec::with_capacity(64);
            padding.extend_from_slice(&capabilities_hash(&canonical_capabilities()));
            padding.extend_from_slice(&[0u8; 32]);
            padding
        },
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
    // keys the client-auth message the responder will decrypt next; both
    // sides derive it from the PROVISIONAL static (the client's ephemeral),
    // and the real static arrives authenticated inside CLIENT_AUTH.
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
        server_eid,
        session_secrets: derive_session_secrets(&secret4, &final_transcript),
    };
    Ok(ResponderResponse::ServerHello {
        bytes: server_hello_bytes,
        pending: Box::new(pending),
    })
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
    /// (xx.rs): client static key + the client's identity binding (signed
    /// bytes and the binding's own signature) + the client transcript
    /// signature, sealed with the client-auth key derived from secret3 and
    /// the transcript before the message is appended.
    ///
    /// `claimed_identity` signs the transcript-bound signature (the identity
    /// the client claims); `client_binding` is transmitted verbatim. The
    /// happy path passes the same key for both.
    #[allow(clippy::too_many_arguments, clippy::similar_names)]
    fn build_client_auth(
        claimed_identity: &IdentityKeyPair,
        client_static: &StaticHandshakeKeyPair,
        client_ephemeral: &StaticHandshakeKeyPair,
        hello: &ClientHello,
        server_hello: &ServerHello,
        server_binding: &IdentityBinding,
        carrier_binding: &[u8],
        client_binding: &IdentityBinding,
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
        let client_eid = endpoint_id(&claimed_identity.public());
        let server_eid = endpoint_id(&server_binding.identity_public_key);
        let sig_input = client_signature_input(
            &transcript.hash,
            &client_eid,
            &server_eid,
            &client_static.public().0,
            &server_static_pub.0,
        );
        let signature = claimed_identity.sign(&sig_input);
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&client_static.public().0);
        plaintext.extend_from_slice(&client_binding.signed_bytes());
        plaintext.extend_from_slice(&client_binding.signature);
        plaintext.extend_from_slice(&signature);
        let encrypted = umc_crypto::aead::PacketKeys::from_traffic_secret(&auth_key)
            .expect("keys")
            .seal(0, &transcript.hash, &plaintext)
            .expect("seal");
        let mut auth_bytes = Vec::new();
        umc_wire::bytes::encode(&mut auth_bytes, &encrypted, 16_384).expect("bytes");
        auth_bytes
    }

    /// The `SERVER_HELLO` half of a responder response; panics when the
    /// responder answered with a Version-Negotiation packet instead.
    fn expect_server_hello(response: ResponderResponse) -> (Vec<u8>, HandshakePending) {
        match response {
            ResponderResponse::ServerHello { bytes, pending } => (bytes, *pending),
            ResponderResponse::VersionNegotiation { .. } => {
                panic!("expected a SERVER_HELLO, got a Version-Negotiation packet")
            }
        }
    }

    /// Test binding with a finite validity window (`u64::MAX` would overflow
    /// `IdentityBinding::validate`'s skew arithmetic in debug builds).
    fn client_binding(
        identity: &IdentityKeyPair,
        static_key: &StaticHandshakeKeyPair,
    ) -> IdentityBinding {
        IdentityBinding::sign(
            identity,
            &static_key.public(),
            0,
            1_800_000_000_000,
            0,
            [0u8; 32],
        )
    }

    #[test]
    fn responder_completes_the_client_auth_continuation() {
        let state = test_state();
        let (client_identity, client_static, client_ephemeral) = client_identity();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let hello_bytes = hello.encode().expect("hello");

        let (server_hello_bytes, pending) = expect_server_hello(
            respond_hello(
                &state,
                b"ump.tcp/1",
                &hello_bytes,
                &client_static.public(),
                &[1u8; 8],
                &[2u8; 8],
            )
            .expect("responder"),
        );
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
            1_800_000_000_000,
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
            &client_binding(&client_identity, &client_static),
        );

        let (server_finished, secrets, peer) = pending
            .complete(&state, &auth_bytes, 1_000)
            .expect("complete");
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
        let client_out = complete_client_side(
            &client_identity,
            &client_static,
            &client_ephemeral,
            &hello,
            &server_hello,
            &TestEntropy,
            b"ump.tcp/1",
        )
        .expect("client side");
        assert_eq!(client_out.session_secrets.client, secrets.client);
        assert_eq!(client_out.session_secrets.server, secrets.server);
    }

    #[test]
    fn responder_rejects_a_mismatched_client_static_key() {
        let state = test_state();
        let (_client_identity, client_static, client_ephemeral) = client_identity();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let hello_bytes = hello.encode().expect("hello");
        let (server_hello_bytes, pending) = expect_server_hello(
            respond_hello(
                &state,
                b"ump.tcp/1",
                &hello_bytes,
                &client_static.public(),
                &[1u8; 8],
                &[2u8; 8],
            )
            .expect("responder"),
        );
        let server_hello = ServerHello::decode(&server_hello_bytes).expect("server hello");
        let server_binding = IdentityBinding::sign(
            &state.node_identity.identity,
            &state.node_identity.static_handshake.public(),
            0,
            1_800_000_000_000,
            0,
            [0u8; 32],
        );
        // An auth message sealed with a client-auth key derived from a DH
        // chain the server never ran cannot be decrypted: the client
        // encrypts with a different static than the provisional the
        // responder used, so the session is refused at the AEAD open.
        let (identity, other_static, _ephemeral) = client_identity();
        let auth_bytes = build_client_auth(
            &identity,
            &other_static,
            &client_ephemeral,
            &hello,
            &server_hello,
            &server_binding,
            b"ump.tcp/1",
            &client_binding(&identity, &other_static),
        );
        assert!(pending.complete(&state, &auth_bytes, 1_000).is_err());
    }

    #[test]
    fn responder_rejects_a_binding_signed_by_a_different_key() {
        // The client signs its identity binding with its REAL identity key
        // but claims a different identity (transcript signature made with
        // the claimed key): `IdentityBinding::validate` detects the mismatch
        // and the session is refused (handshake.md §4.3).
        let state = test_state();
        let (client_identity, client_static, client_ephemeral) = client_identity();
        let claimed = IdentityKeyPair::generate();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let hello_bytes = hello.encode().expect("hello");

        let (server_hello_bytes, pending) = expect_server_hello(
            respond_hello(
                &state,
                b"ump.tcp/1",
                &hello_bytes,
                &client_static.public(),
                &[1u8; 8],
                &[2u8; 8],
            )
            .expect("responder"),
        );
        let server_hello = ServerHello::decode(&server_hello_bytes).expect("server hello");
        let server_binding = IdentityBinding::sign(
            &state.node_identity.identity,
            &state.node_identity.static_handshake.public(),
            0,
            1_800_000_000_000,
            0,
            [0u8; 32],
        );

        // The binding is signed by the real identity but claims the other
        // key: the transmitted signature no longer matches the claim.
        let mut spoofed = client_binding(&client_identity, &client_static);
        spoofed.identity_public_key = claimed.public();
        spoofed.endpoint_id = endpoint_id(&claimed.public());

        let auth_bytes = build_client_auth(
            &claimed,
            &client_static,
            &client_ephemeral,
            &hello,
            &server_hello,
            &server_binding,
            b"ump.tcp/1",
            &spoofed,
        );
        let error = pending
            .complete(&state, &auth_bytes, 1_000)
            .expect_err("refused");
        assert!(error.contains("binding"), "{error}");
    }

    #[test]
    fn responder_rejects_garbage_auth() {
        let state = test_state();
        let (_identity, client_static, client_ephemeral) = client_identity();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let hello_bytes = hello.encode().expect("hello");
        let (_server_hello_bytes, pending) = expect_server_hello(
            respond_hello(
                &state,
                b"ump.tcp/1",
                &hello_bytes,
                &client_static.public(),
                &[1u8; 8],
                &[2u8; 8],
            )
            .expect("responder"),
        );
        assert!(pending.complete(&state, b"garbage", 1_000).is_err());
    }

    /// Version negotiation (compatibility.md §5.2, handshake.md §16): a
    /// hello offering the supported version gets a `SERVER_HELLO` selecting
    /// it; a hello offering only unsupported versions gets a
    /// Version-Negotiation packet instead and NO `SERVER_HELLO` — the
    /// handshake does not continue.
    #[test]
    fn respond_hello_negotiates_version() {
        let state = test_state();
        let (_identity, _static_key, client_ephemeral) = client_identity();
        let mut hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        hello.supported_protocol_versions = vec![1];
        let hello_bytes = hello.encode().expect("hello");
        let response = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello_bytes,
            &client_ephemeral.public(),
            &[1u8; 8],
            &[2u8; 8],
        )
        .expect("responder");
        let server_hello = match response {
            ResponderResponse::ServerHello { bytes, .. } => {
                ServerHello::decode(&bytes).expect("server hello")
            }
            ResponderResponse::VersionNegotiation { .. } => {
                panic!("version 1 must be selected from the offered list")
            }
        };
        assert_eq!(
            server_hello.selected_protocol_version,
            SELECTED_PROTOCOL_VERSION
        );

        // Offering only version 2: a VN packet listing our supported
        // version, never a SERVER_HELLO.
        let mut hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        hello.supported_protocol_versions = vec![2];
        let hello_bytes = hello.encode().expect("hello");
        let response = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello_bytes,
            &client_ephemeral.public(),
            &[1u8; 8],
            &[2u8; 8],
        )
        .expect("responder");
        match response {
            ResponderResponse::ServerHello { .. } => {
                panic!("an unsupported offer must get a VN packet, not a SERVER_HELLO")
            }
            ResponderResponse::VersionNegotiation { bytes } => {
                let offered = parse_version_negotiation(&bytes).expect("a VN packet");
                assert_eq!(offered, vec![SELECTED_PROTOCOL_VERSION]);
            }
        }
    }

    /// The Version-Negotiation packet lists the responder's supported
    /// protocol versions as big-endian u32s (wire-format §25): parsing the
    /// daemon's VN yields exactly version 1.
    #[test]
    fn vn_packet_lists_supported_versions() {
        let state = test_state();
        let (_identity, _static_key, client_ephemeral) = client_identity();
        let mut hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        hello.supported_protocol_versions = vec![2, 3];
        let hello_bytes = hello.encode().expect("hello");
        let response = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello_bytes,
            &client_ephemeral.public(),
            &[0xAA; 8],
            &[0xBB; 8],
        )
        .expect("responder");
        let bytes = match response {
            ResponderResponse::ServerHello { .. } => panic!("expected a VN packet"),
            ResponderResponse::VersionNegotiation { bytes } => bytes,
        };
        assert_eq!(
            parse_version_negotiation(&bytes).expect("vn"),
            vec![SELECTED_PROTOCOL_VERSION]
        );
    }

    /// Capability negotiation (compatibility.md §5.4): the responder
    /// refuses a hello whose capabilities hash does not match the
    /// canonical set.
    #[test]
    fn respond_hello_refuses_bad_capabilities_hash() {
        let state = test_state();
        let (_identity, _static_key, client_ephemeral) = client_identity();
        let mut hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        hello.capabilities_hash = [0u8; 32];
        let hello_bytes = hello.encode().expect("hello");
        let error = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello_bytes,
            &client_ephemeral.public(),
            &[1u8; 8],
            &[2u8; 8],
        )
        .expect_err("a bad capabilities hash must be refused");
        assert!(error.contains("capabilities"), "{error}");
    }

    /// The server's canonical capabilities hash rides in the first 32
    /// bytes of the `SERVER_HELLO` padding (the documented convention):
    /// the client reads it from the padding prefix, exactly as
    /// `complete_client_side` verifies it.
    #[test]
    fn server_hello_carries_server_hash() {
        let state = test_state();
        let (_identity, _static_key, client_ephemeral) = client_identity();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let hello_bytes = hello.encode().expect("hello");
        let response = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello_bytes,
            &client_ephemeral.public(),
            &[1u8; 8],
            &[2u8; 8],
        )
        .expect("responder");
        let bytes = match response {
            ResponderResponse::ServerHello { bytes, .. } => bytes,
            ResponderResponse::VersionNegotiation { .. } => {
                panic!("expected a SERVER_HELLO")
            }
        };
        let server_hello = ServerHello::decode(&bytes).expect("server hello");
        assert_eq!(
            server_hello.server_capabilities_hash().expect("hash"),
            capabilities_hash(&canonical_capabilities())
        );
    }
}
