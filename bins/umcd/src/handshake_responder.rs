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
use umc_handshake::psk::{PskAdmissionContext, MODE_PSK_XX};
use umc_handshake::state::{HandshakeEvent, HandshakeMachine, HandshakeState};
use umc_handshake::traffic::{derive_session_secrets, SessionSecrets};
use umc_handshake::transcript::Transcript;
use umc_handshake::xx::{
    build_version_negotiation, canonical_capabilities, capabilities_hash,
    capabilities_hash_for_minimum_privacy, client_signature_input, decrypt_client_auth,
    encrypt_server_auth, finished_key, finished_mac, privacy_profile_level, select_version,
    ClientHello, ServerAuthBlock, ServerHello, CRYPTO_PROFILE, MAX_SUPPORTED_PRIVACY_PROFILE,
    MODE_XX, SUPPORTED_PROTOCOL_VERSION,
};
use umc_types::runtime::EntropySource;
use umc_core::revocation::RevocationStore;
use umc_core::trust::{decode_delegation_chain, DelegationStore};

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
const MAX_DELEGATION_CHAIN_BYTES: usize = 8 * 1024;

/// The server-side handshake captured by [`respond_hello`], carried until
/// the client's `CLIENT_AUTH` arrives (handshake.md §18).
#[derive(Debug)]
pub struct HandshakePending {
    transcript: Transcript,
    secret3: [u8; 32],
    secret4: [u8; 32],
    server_eid: [u8; 32],
    session_secrets: SessionSecrets,
    selected_privacy: u8,
    machine: HandshakeMachine,
}

/// The client's verified identity recovered from `CLIENT_AUTH`: the real
/// static handshake key and the identity binding, registered by the accept
/// loop as the session's peer identity (handshake.md §18).
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub client_static_public_key: StaticHandshakePublicKey,
    pub binding: IdentityBinding,
    #[allow(dead_code)]
    pub delegation_depth: Option<u8>,
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
    /// Current protocol state for this pending responder handshake.
    #[must_use]
    pub const fn handshake_state(&self) -> HandshakeState {
        self.machine.state
    }

    /// Whether the peer was authenticated and the confirmation MAC advanced
    /// this handshake to the application-key gate.
    #[must_use]
    pub fn application_keys_ready(&self) -> bool {
        self.machine.may_install_application_keys()
    }

    /// Numeric privacy profile selected during the transcript-bound hello
    /// negotiation (privacy.md §42).
    #[must_use]
    pub const fn selected_privacy_profile(&self) -> u8 {
        self.selected_privacy
    }

    /// The session secrets this handshake derives, computed at
    /// [`respond_hello`] time from the DH chain (es/se/ss).
    #[must_use]
    #[allow(dead_code)] // accessor for the secrets `complete` also returns
    pub fn session_secrets(&self) -> &SessionSecrets {
        &self.session_secrets
    }

    /// Directional Handshake traffic key material for the protected
    /// continuation (handshake.md §25). The transcript is frozen through
    /// `SERVER_HELLO`; later finished messages do not change these keys.
    #[must_use]
    pub fn handshake_traffic_secret(&self, client_direction: bool) -> [u8; 32] {
        umc_handshake::traffic::derive_handshake_traffic_secret(
            &self.secret3,
            &self.transcript.hash,
            client_direction,
        )
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
    #[allow(clippy::too_many_lines)]
    pub fn complete(
        &mut self,
        state: &RuntimeState,
        auth_bytes: &[u8],
        now_ms: u64,
    ) -> Result<(Vec<u8>, SessionSecrets, PeerIdentity), String> {
        // Stage the transition so malformed authentication leaves the
        // pending object unchanged, while a successful CLIENT_AUTH cannot be
        // replayed against the same handshake.
        let mut machine = self.machine;
        machine
            .apply(HandshakeEvent::ReceiveClientAuth)
            .map_err(|e| format!("handshake state: {e:?}"))?;
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
        let base_len = 32 + BINDING_WIRE_LEN + 64;
        let delegation_chain = if plaintext.len() == base_len {
            None
        } else {
            let tail = plaintext.get(base_len..).ok_or("client auth truncated")?;
            let (encoded, consumed) = umc_wire::bytes::decode(tail, MAX_DELEGATION_CHAIN_BYTES)
                .map_err(|_| "delegation chain framing")?;
            if consumed != tail.len() {
                return Err("delegation chain trailing bytes".into());
            }
            let chain = decode_delegation_chain(encoded)
                .map_err(|error| format!("delegation chain: {error:?}"))?;
            let persisted = DelegationStore::new(state.store.as_ref())
                .valid_chain_for_public_key(&binding.identity_public_key.0, now_ms)
                .map_err(|error| format!("delegation store unavailable: {error:?}"))?;
            let accepted = persisted.is_some_and(|record| record.certificates == chain);
            if !accepted {
                return Err("delegation chain is not locally authorized".into());
            }
            if let Some(record) = DelegationStore::new(state.store.as_ref())
                .valid_chain_for_public_key(&binding.identity_public_key.0, now_ms)
                .map_err(|error| format!("delegation store unavailable: {error:?}"))?
            {
                RevocationStore::new(state.store.as_ref())
                    .check_delegation(&record, now_ms)
                    .map_err(|error| format!("delegation revoked: {error:?}"))?;
            }
            Some(chain)
        };
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
            delegation_depth: delegation_chain.map(|chain| {
                u8::try_from(chain.len()).expect("delegation chain length is bounded")
            }),
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
        machine
            .apply(HandshakeEvent::SendServerFinished)
            .map_err(|e| format!("handshake state: {e:?}"))?;
        self.machine = machine;
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
        &mut self,
        auth_bytes: &[u8],
        server_finished: &[u8],
        client_finished: &[u8],
    ) -> Result<(), String> {
        let mut machine = self.machine;
        machine
            .apply(HandshakeEvent::ReceiveClientFinished)
            .map_err(|e| format!("handshake state: {e:?}"))?;
        let mut transcript = self.transcript.clone();
        umc_handshake::xx::verify_client_finished(
            &self.secret4,
            &mut transcript,
            auth_bytes,
            server_finished,
            client_finished,
        )?;
        machine
            .apply(HandshakeEvent::Confirm)
            .map_err(|e| format!("handshake state: {e:?}"))?;
        self.machine = machine;
        Ok(())
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
#[allow(clippy::too_many_lines)]
#[allow(dead_code)]
pub fn respond_hello(
    state: &RuntimeState,
    carrier_binding: &[u8],
    hello_bytes: &[u8],
    client_static_public_key: &StaticHandshakePublicKey,
    initial_dcid: &[u8],
    initial_scid: &[u8],
) -> Result<ResponderResponse, String> {
    respond_hello_with_retry_context(
        state,
        carrier_binding,
        hello_bytes,
        client_static_public_key,
        initial_dcid,
        initial_scid,
        None,
    )
}

/// Variant of [`respond_hello`] that incorporates the synthetic transcript
/// input after a stateless Retry exchange (handshake.md §21.1).
#[allow(clippy::similar_names, clippy::too_many_lines)]
pub fn respond_hello_with_retry_context(
    state: &RuntimeState,
    carrier_binding: &[u8],
    hello_bytes: &[u8],
    client_static_public_key: &StaticHandshakePublicKey,
    initial_dcid: &[u8],
    initial_scid: &[u8],
    retry_context: Option<&[u8; 32]>,
) -> Result<ResponderResponse, String> {
    respond_hello_with_retry_context_and_psk(
        state,
        carrier_binding,
        hello_bytes,
        client_static_public_key,
        initial_dcid,
        initial_scid,
        retry_context,
        None,
    )
}

/// Variant of [`respond_hello_with_retry_context`] that can select PSK-XX
/// when the caller has matched the client's invitation authenticator against
/// a live invitation key. The key is never serialized into the handshake.
#[allow(
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
pub fn respond_hello_with_retry_context_and_psk(
    state: &RuntimeState,
    carrier_binding: &[u8],
    hello_bytes: &[u8],
    client_static_public_key: &StaticHandshakePublicKey,
    initial_dcid: &[u8],
    initial_scid: &[u8],
    retry_context: Option<&[u8; 32]>,
    invitation_key: Option<&[u8; 32]>,
) -> Result<ResponderResponse, String> {
    if state
        .config
        .carrier_disabled(std::str::from_utf8(carrier_binding).unwrap_or_default())
    {
        return Err(format!(
            "disabled carrier: {}",
            String::from_utf8_lossy(carrier_binding)
        ));
    }
    let hello = ClientHello::decode(hello_bytes).map_err(|e| format!("client hello: {e:?}"))?;
    if !umc_handshake::xx::realm_marker_matches(
        umc_handshake::xx::client_realm_marker(&hello),
        state.config.realm_marker(),
        state.config.is_private_network(),
    ) {
        return Err("network realm mismatch".into());
    }

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

    // Emergency protocol disablement deliberately returns a VN packet with
    // no usable versions. This is the wire-level UNSUPPORTED response: a
    // peer cannot retry until the operator re-enables the version.
    if state.config.protocol_version_disabled(selected_version) {
        return Ok(ResponderResponse::VersionNegotiation {
            bytes: build_version_negotiation(initial_scid, initial_dcid, &[]),
        });
    }
    if state.config.crypto_profile_disabled(CRYPTO_PROFILE) {
        return Err(format!(
            "disabled crypto profile: {}",
            String::from_utf8_lossy(CRYPTO_PROFILE)
        ));
    }

    // Capability negotiation (compatibility.md §5.4): the client's hash is
    // inside the transcript-bound CLIENT_HELLO; it includes the requested
    // privacy floor so a tampered minimum is refused before DH work.
    let requested_privacy = hello
        .minimum_privacy_level()
        .ok_or_else(|| "invalid minimum privacy profile".to_string())?;
    let max_privacy = privacy_profile_level(MAX_SUPPORTED_PRIVACY_PROFILE)
        .expect("the implementation maximum is a valid profile");
    let local_privacy = state.config.effective_privacy_profile() as u8;
    if local_privacy > max_privacy {
        return Err(format!(
            "local privacy profile p{local_privacy} unsupported; maximum is p{max_privacy}"
        ));
    }
    if requested_privacy > max_privacy {
        return Err(format!(
            "privacy profile {} unsupported; maximum is {}",
            String::from_utf8_lossy(&hello.minimum_privacy),
            String::from_utf8_lossy(MAX_SUPPORTED_PRIVACY_PROFILE)
        ));
    }
    if hello.capabilities_hash != capabilities_hash_for_minimum_privacy(&hello.minimum_privacy) {
        return Err("client capabilities hash mismatch".into());
    }
    // Select the stronger requested/local floor. Both values were checked
    // against `max_privacy` above, so applying the implementation maximum
    // here would incorrectly raise every p0 session to p1.
    let selected_privacy = requested_privacy.max(local_privacy);

    let psk_offered = hello
        .supported_handshake_modes
        .iter()
        .any(|mode| mode.as_slice() == MODE_PSK_XX);
    let selected_mode = if psk_offered {
        if let Some(invitation_key) = invitation_key {
            let admission = PskAdmissionContext {
                invitation_key: *invitation_key,
                destination_connection_id: initial_dcid.to_vec(),
                carrier_binding: carrier_binding.to_vec(),
            };
            admission
                .verify_client_hello(&hello)
                .map_err(|_| "handshake admission failed".to_string())?;
            MODE_PSK_XX
        } else {
            return Err("handshake admission failed".into());
        }
    } else {
        // Legacy IK-only hellos that did not resume a ticket intentionally
        // continue through the full XX responder path. This preserves the
        // pre-mode-negotiation fallback used by existing callers; PSK offers
        // never take this branch because they require admission above.
        MODE_XX
    };

    let server_ephemeral = StaticHandshakeKeyPair::generate();
    let mut server_random = [0u8; 32];
    OsEntropy.fill(&mut server_random);

    // Transcript through CLIENT_HELLO (handshake.md §14-15).
    let mut transcript = Transcript::new(selected_mode, CRYPTO_PROFILE, carrier_binding);
    transcript
        .update_message(CLIENT_HELLO, hello_bytes)
        .map_err(|e| format!("transcript: {e:?}"))?;
    if let Some(retry_context) = retry_context {
        transcript.update_bytes(retry_context);
    }

    // DH_ee -> extract1 -> server-auth key (handshake.md §16.1).
    let dh_ee = server_ephemeral
        .diffie_hellman(&StaticHandshakePublicKey(hello.client_ephemeral_public_key));
    let extract1 = if selected_mode == MODE_PSK_XX {
        let invitation_key = invitation_key.ok_or("handshake admission failed")?;
        let psk_extract = umc_handshake::psk::derive_psk_extract(
            invitation_key,
            &hello.client_random,
            &hello.client_ephemeral_public_key,
            carrier_binding,
        );
        umc_crypto::hkdf::extract(&psk_extract, &dh_ee)
    } else {
        umc_crypto::hkdf::extract(&[0u8; 32], &dh_ee)
    };
    // The live server authentication must carry the same persisted binding
    // advertised by the identity service. Re-signing a zero-hash placeholder
    // here would make the wire claim diverge from the keystore record.
    let binding = state.primary_binding.clone();
    // The auth-block AAD binds the transcript hash BEFORE the SERVER_HELLO
    // message is appended (handshake.md §16.1).
    let server_auth_transcript = transcript.hash;
    let encrypted_auth = encrypt_server_auth(
        &extract1,
        &server_auth_transcript,
        &ServerAuthBlock {
            server_static_public_key: state.node_identity.static_handshake.public().0,
            server_identity_binding: {
                let mut bytes = binding.signed_bytes();
                bytes.extend_from_slice(&binding.signature);
                bytes
            },
            server_delegation_chain: Vec::new(),
        },
        &server_ephemeral.public().0,
        &server_random,
        CRYPTO_PROFILE,
    )
    .map_err(|e| format!("server auth: {e:?}"))?;

    let mut server_hello = ServerHello {
        server_random,
        server_ephemeral_public_key: server_ephemeral.public().0,
        selected_protocol_version: selected_version,
        selected_crypto_profile: CRYPTO_PROFILE.to_vec(),
        selected_handshake_mode: selected_mode.to_vec(),
        encrypted_server_authentication: encrypted_auth,
        // The server's capabilities hash rides in the first 32 bytes of
        // the padding (compatibility.md §5.4, documented convention): the
        // client reads it from the padding prefix and verifies it against
        // the canonical set. The padding is inside the encoded
        // SERVER_HELLO, so the hash is transcript-bound like every other
        // hello field.
        padding: {
            let mut padding = Vec::with_capacity(96);
            padding.extend_from_slice(&capabilities_hash(&canonical_capabilities()));
            padding.push(selected_privacy);
            padding.extend_from_slice(&[0u8; 31]);
            padding
        },
    };
    umc_handshake::xx::set_server_realm_marker(&mut server_hello, state.config.realm_marker());
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
        selected_privacy,
        machine: {
            let mut machine = HandshakeMachine::new();
            machine
                .apply(HandshakeEvent::ReceiveClientHello)
                .map_err(|e| format!("handshake state: {e:?}"))?;
            machine
                .apply(HandshakeEvent::SendServerHello)
                .map_err(|e| format!("handshake state: {e:?}"))?;
            machine
                .apply(HandshakeEvent::InstallHandshakeKeys)
                .map_err(|e| format!("handshake state: {e:?}"))?;
            machine
        },
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
        build_client_auth_with_chain(
            claimed_identity,
            client_static,
            client_ephemeral,
            hello,
            server_hello,
            server_binding,
            carrier_binding,
            client_binding,
            &[],
        )
    }

    #[allow(clippy::too_many_arguments, clippy::similar_names)]
    fn build_client_auth_with_chain(
        claimed_identity: &IdentityKeyPair,
        client_static: &StaticHandshakeKeyPair,
        client_ephemeral: &StaticHandshakeKeyPair,
        hello: &ClientHello,
        server_hello: &ServerHello,
        server_binding: &IdentityBinding,
        carrier_binding: &[u8],
        client_binding: &IdentityBinding,
        delegation_chain: &[u8],
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
        let plaintext = umc_handshake::xx::build_client_auth_plaintext_with_delegation(
            &client_static.public().0,
            client_binding,
            &signature,
            delegation_chain,
        );
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

        let (server_hello_bytes, mut pending) = expect_server_hello(
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
    fn responder_selects_psk_xx_and_client_derives_matching_auth_keys() {
        let state = test_state();
        let invitation_key = [0x3Cu8; 32];
        let client_identity = IdentityKeyPair::generate();
        let client_static = StaticHandshakeKeyPair::generate();
        let client_ephemeral = StaticHandshakeKeyPair::generate();
        let hello = ClientHello::new_psk_xx(
            &TestEntropy,
            &client_ephemeral,
            &invitation_key,
            b"dcid",
            b"ump.tcp/1",
        );
        let hello_bytes = hello.encode().expect("hello");

        let (server_hello_bytes, _pending) = expect_server_hello(
            respond_hello_with_retry_context_and_psk(
                &state,
                b"ump.tcp/1",
                &hello_bytes,
                &client_ephemeral.public(),
                b"dcid",
                b"scid",
                None,
                Some(&invitation_key),
            )
            .expect("psk responder"),
        );
        let server_hello = ServerHello::decode(&server_hello_bytes).expect("server hello");
        assert_eq!(server_hello.selected_handshake_mode, MODE_PSK_XX.to_vec());
        umc_handshake::xx::complete_client_side_with_psk(
            &client_identity,
            &client_static,
            &client_ephemeral,
            &hello,
            &server_hello,
            &TestEntropy,
            b"ump.tcp/1",
            &invitation_key,
        )
        .expect("client derives PSK auth keys");

        let wrong_key = [0x3Du8; 32];
        assert!(respond_hello_with_retry_context_and_psk(
            &state,
            b"ump.tcp/1",
            &hello_bytes,
            &client_ephemeral.public(),
            b"dcid",
            b"scid",
            None,
            Some(&wrong_key),
        )
        .is_err());
    }

    #[test]
    fn responder_accepts_only_persisted_delegation_chain() {
        let state = test_state();
        let root = IdentityKeyPair::generate();
        let client_identity = IdentityKeyPair::generate();
        let client_static = StaticHandshakeKeyPair::generate();
        let client_ephemeral = StaticHandshakeKeyPair::generate();
        let certificate = umc_core::trust_statement::SignedDelegation::sign(
            &root,
            client_identity.public().0,
            vec![b"chat".to_vec()],
            0,
            1_800_000_000_000,
            1,
        )
        .expect("certificate");
        let chain = umc_core::trust::encode_delegation_chain(std::slice::from_ref(&certificate))
            .expect("chain");
        umc_core::trust::DelegationStore::new(state.store.as_ref())
            .accept_chain(&root.public(), &[b"chat".to_vec()], &[certificate], 1_000)
            .expect("persist chain");
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let hello_bytes = hello.encode().expect("hello");
        let (server_hello_bytes, mut pending) = expect_server_hello(
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
        let auth = build_client_auth_with_chain(
            &client_identity,
            &client_static,
            &client_ephemeral,
            &hello,
            &server_hello,
            &server_binding,
            b"ump.tcp/1",
            &client_binding(&client_identity, &client_static),
            &chain,
        );
        let (_finished, _secrets, peer) = pending.complete(&state, &auth, 1_000).expect("delegated auth");
        assert_eq!(peer.delegation_depth, Some(1));

        let (rejected_hello_bytes, mut rejected_pending) = expect_server_hello(
            respond_hello(
                &state,
                b"ump.tcp/1",
                &hello_bytes,
                &client_static.public(),
                &[3u8; 8],
                &[4u8; 8],
            )
            .expect("responder"),
        );
        let rejected_server_hello = ServerHello::decode(&rejected_hello_bytes).expect("server hello");
        let mut tampered = chain.clone();
        *tampered.last_mut().expect("chain byte") ^= 1;
        let bad_auth = build_client_auth_with_chain(
            &client_identity,
            &client_static,
            &client_ephemeral,
            &hello,
            &rejected_server_hello,
            &server_binding,
            b"ump.tcp/1",
            &client_binding(&client_identity, &client_static),
            &tampered,
        );
        assert!(rejected_pending.complete(&state, &bad_auth, 1_000).is_err());
    }

    #[test]
    fn responder_rejects_a_mismatched_client_static_key() {
        let state = test_state();
        let (_client_identity, client_static, client_ephemeral) = client_identity();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let hello_bytes = hello.encode().expect("hello");
        let (server_hello_bytes, mut pending) = expect_server_hello(
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

        let (server_hello_bytes, mut pending) = expect_server_hello(
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
        let (_server_hello_bytes, mut pending) = expect_server_hello(
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

    #[test]
    fn pending_handshake_state_is_advanced_by_authenticated_messages() {
        let state = test_state();
        let (client_identity, client_static, client_ephemeral) = client_identity();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let hello_bytes = hello.encode().expect("hello");
        let (server_hello_bytes, mut pending) = expect_server_hello(
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
        assert_eq!(pending.handshake_state(), HandshakeState::HandshakeKeys);

        let server_hello = ServerHello::decode(&server_hello_bytes).expect("server hello");
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
        let (server_finished, _, _) = pending
            .complete(&state, &auth_bytes, 1_000)
            .expect("complete");
        assert_eq!(pending.handshake_state(), HandshakeState::SessionKeys);

        // A second CLIENT_AUTH is rejected by the runtime state gate even
        // when its cryptographic body is otherwise valid.
        assert!(pending.complete(&state, &auth_bytes, 1_000).is_err());
        assert_eq!(pending.handshake_state(), HandshakeState::SessionKeys);

        // Confirmation transition is exercised by the live accept-loop
        // tests; this unit test stops at SERVER_FINISHED to avoid duplicating
        // the full packet exchange fixture.
        assert_eq!(server_finished.len(), 96);
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
                let (offered, _) = parse_version_negotiation(&bytes).expect("a VN packet");
                assert_eq!(offered, vec![SELECTED_PROTOCOL_VERSION]);
            }
        }
    }

    #[test]
    fn emergency_disablement_blocks_protocol_crypto_and_carrier() {
        let (_identity, _static_key, client_ephemeral) = client_identity();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let hello_bytes = hello.encode().expect("hello");

        let mut state = test_state();
        state.config.disabled_protocol_versions = vec!["1".into()];
        let response = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello_bytes,
            &client_ephemeral.public(),
            &[1u8; 8],
            &[2u8; 8],
        )
        .expect("disabled protocol is negotiated away");
        let bytes = match response {
            ResponderResponse::VersionNegotiation { bytes } => bytes,
            ResponderResponse::ServerHello { .. } => {
                panic!("disabled protocol must not produce a SERVER_HELLO")
            }
        };
        let (versions, _) = parse_version_negotiation(&bytes).expect("VN packet");
        assert!(
            versions.is_empty(),
            "all locally supported versions are disabled"
        );

        let mut state = test_state();
        state.config.disabled_crypto_profiles = vec!["UMP-CRYPTO-1".into()];
        let error = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello_bytes,
            &client_ephemeral.public(),
            &[1u8; 8],
            &[2u8; 8],
        )
        .expect_err("disabled crypto profile must be refused");
        assert!(error.contains("disabled crypto profile"), "{error}");

        let mut state = test_state();
        state.config.disabled_carriers = vec!["ump.tcp/1".into()];
        let error = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello_bytes,
            &client_ephemeral.public(),
            &[1u8; 8],
            &[2u8; 8],
        )
        .expect_err("disabled carrier must be refused");
        assert!(error.contains("disabled carrier"), "{error}");
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
            parse_version_negotiation(&bytes).expect("vn").0,
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

    #[test]
    fn respond_hello_accepts_p3_privacy_profile() {
        let state = test_state();
        let (_identity, _static_key, client_ephemeral) = client_identity();
        let hello = ClientHello::new_with_minimum_privacy(&TestEntropy, &client_ephemeral, b"p3");
        let response = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello.encode().expect("hello"),
            &client_ephemeral.public(),
            &[1u8; 8],
            &[2u8; 8],
        )
        .expect("p3 is within the p3 implementation maximum");
        match response {
            ResponderResponse::ServerHello { pending, .. } => {
                assert_eq!(pending.selected_privacy_profile(), 3);
            }
            ResponderResponse::VersionNegotiation { .. } => {
                panic!("privacy request unexpectedly triggered version negotiation")
            }
        }
    }

    #[test]
    fn local_privacy_policy_cannot_be_silently_downgraded() {
        let mut state = test_state();
        state.config.privacy_profile = "p2".into();
        let (_identity, _static_key, client_ephemeral) = client_identity();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let response = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello.encode().expect("hello"),
            &client_ephemeral.public(),
            &[1u8; 8],
            &[2u8; 8],
        )
        .expect("a local p2 policy must raise the selected floor");
        match response {
            ResponderResponse::ServerHello { pending, .. } => {
                assert_eq!(pending.selected_privacy_profile(), 2);
            }
            ResponderResponse::VersionNegotiation { .. } => {
                panic!("local privacy policy unexpectedly triggered version negotiation")
            }
        }
    }

    #[test]
    fn respond_hello_refuses_tampered_privacy_floor() {
        let state = test_state();
        let (_identity, _static_key, client_ephemeral) = client_identity();
        let mut hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        hello.minimum_privacy = b"p1".to_vec();
        let error = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello.encode().expect("hello"),
            &client_ephemeral.public(),
            &[1u8; 8],
            &[2u8; 8],
        )
        .expect_err("changing the privacy floor without its hash must fail");
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
        assert_eq!(server_hello.selected_privacy_level(), Some(0));
    }

    #[test]
    fn private_realm_rejects_public_hello_before_server_hello() {
        let mut config = NodeConfig {
            network_mode: "private".into(),
            network_id: Some("acme-prod".into()),
            mesh_secret: Some("shared-secret".into()),
            ..NodeConfig::default()
        };
        let dir = std::env::temp_dir().join(format!(
            "umcd-private-responder-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        config.data_dir = dir;
        let (tx, _rx) = mpsc::channel(1);
        let state = RuntimeState::new(config, tx).expect("private state");
        let (_identity, _static_key, client_ephemeral) = client_identity();
        let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
        let error = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello.encode().expect("hello"),
            &client_ephemeral.public(),
            &[1u8; 8],
            &[2u8; 8],
        )
        .expect_err("public hello must not enter private realm");
        assert!(error.contains("realm"), "{error}");
    }

    #[test]
    fn p0_request_with_p0_policy_stays_p0() {
        let state = test_state();
        let (_identity, _static_key, client_ephemeral) = client_identity();
        let hello = ClientHello::new_with_minimum_privacy(&TestEntropy, &client_ephemeral, b"p0");
        let response = respond_hello(
            &state,
            b"ump.tcp/1",
            &hello.encode().expect("hello"),
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
        assert_eq!(
            ServerHello::decode(&bytes)
                .expect("server hello")
                .selected_privacy_level(),
            Some(0),
            "negotiation must not raise p0 to the implementation maximum"
        );
    }

    #[test]
    fn delegation_chain_parser_is_strictly_bounded() {
        assert!(decode_delegation_chain(&[]).is_err());
        assert!(decode_delegation_chain(&[0]).is_err());
        assert!(decode_delegation_chain(&[5]).is_err());
        assert!(decode_delegation_chain(&[1, 0, 0]).is_err());
    }
}
