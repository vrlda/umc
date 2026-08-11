//! Minimal Phase 1 Node: one identity, TCP/UDP carriers, direct sessions.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use umc_carrier::error::{CarrierError, CarrierErrorKind};
use umc_carrier::types::{
    CarrierCapabilities, CarrierTypeId, ConnectionModel, Ordering, OutboundPacket, PacketMode,
    Reliability, SendResult,
};
use umc_carrier::{BoxLink, Carrier};
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_handshake::traffic::SessionSecrets;
use umc_types::runtime::{Clock, EntropySource};

#[derive(Debug)]
pub struct NodeIdentity {
    pub identity: IdentityKeyPair,
    pub static_handshake: StaticHandshakeKeyPair,
}

impl NodeIdentity {
    pub fn generate(entropy: &dyn EntropySource) -> Self {
        let _ = entropy;
        Self {
            identity: IdentityKeyPair::generate(),
            static_handshake: StaticHandshakeKeyPair::generate(),
        }
    }

    #[must_use]
    pub fn endpoint_id(&self) -> [u8; 32] {
        umc_handshake::identity::endpoint_id(&self.identity.public())
    }
}

#[derive(Debug)]
pub struct NodeConfig {
    pub identity: NodeIdentity,
    pub dcid: Vec<u8>,
}

pub struct Node {
    pub config: NodeConfig,
    pub clock: Arc<dyn Clock>,
    pub entropy: Arc<dyn EntropySource>,
    carriers: HashMap<String, Arc<dyn Carrier + Send + Sync>>,
    sessions: Arc<Mutex<HashMap<u64, SessionEntry>>>,
    next_session: u64,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node").finish_non_exhaustive()
    }
}

// Fields are written by connect() and read by the Task 25 session wiring.
#[allow(dead_code)]
struct SessionEntry {
    pub secrets: SessionSecrets,
    pub peer_endpoint_id: [u8; 32],
}

/// Result of an outbound handshake that retains the authenticated carrier
/// link for a daemon or embedded session loop. The legacy [`Node::connect`]
/// API still returns only the node-local session id; callers that own the
/// transport lifecycle use [`Node::connect_transport`].
pub struct ConnectedTransport {
    pub session_id: u64,
    pub link: Box<dyn umc_carrier::Link + Send + Sync>,
    /// The protected Initial destination connection id used by the server's
    /// session demultiplexer and required by the protected packet builder.
    pub dcid: Vec<u8>,
    pub secrets: SessionSecrets,
    pub peer_endpoint_id: [u8; 32],
}

impl std::fmt::Debug for ConnectedTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectedTransport")
            .field("session_id", &self.session_id)
            .field("dcid", &self.dcid)
            .field("peer_endpoint_id", &self.peer_endpoint_id)
            .finish_non_exhaustive()
    }
}

impl Node {
    pub fn new(config: NodeConfig, clock: Arc<dyn Clock>, entropy: Arc<dyn EntropySource>) -> Self {
        Self {
            config,
            clock,
            entropy,
            carriers: HashMap::new(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_session: 0,
        }
    }

    pub fn register_carrier(&mut self, carrier: Box<dyn Carrier + Send + Sync>) {
        self.carriers
            .insert(carrier.type_id().0.clone(), Arc::from(carrier));
    }

    #[must_use]
    pub fn carrier(&self, type_id: &str) -> Option<&(dyn Carrier + Send + Sync)> {
        self.carriers.get(type_id).map(AsRef::as_ref)
    }

    /// Clone a registered carrier handle for bounded background operations.
    /// The control daemon uses this to enforce deadlines around synchronous
    /// carrier calls without borrowing `Node` across the worker boundary.
    #[must_use]
    pub fn carrier_handle(&self, type_id: &str) -> Option<Arc<dyn Carrier + Send + Sync>> {
        self.carriers.get(type_id).cloned()
    }

    /// Complete an XX handshake with a remote over the given carrier.
    /// Sends `CLIENT_HELLO` through the carrier link, receives `SERVER_HELLO`,
    /// sends `CLIENT_AUTH` (the real static key + identity binding +
    /// transcript signature), verifies `SERVER_FINISHED` (the server
    /// finished MAC and signature), sends `CLIENT_FINISHED` (the
    /// confirmation MAC), and derives session secrets from the transcript
    /// (handshake.md §14-20).
    ///
    /// Version negotiation (compatibility.md §5.2): a Version-Negotiation
    /// response means the server does not support the offered versions.
    /// The connect retries ONCE with a fresh connection when the VN lists
    /// our version (the retry Initial is identical — version 1 is the only
    /// version we support); a VN listing only unsupported versions aborts.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::CarrierUnknown`] when no carrier of the given type
    /// is registered, [`NodeError::Carrier`] when dialing or exchanging
    /// packets fails, and [`NodeError::Handshake`] when the XX handshake
    /// fails (including a `SERVER_FINISHED` whose MAC or signature does not
    /// verify, and a Version-Negotiation response listing no supported
    /// version).
    pub async fn connect(
        &mut self,
        carrier_type: &str,
        remote: String,
        _server_identity_public: &NodeIdentity,
    ) -> Result<u64, NodeError> {
        self.connect_with_endpoint_check(carrier_type, remote, None, None)
            .await
            .map(|connection| connection.session_id)
    }

    /// Connect using only the expected endpoint id from a static-peer
    /// configuration. The handshake still verifies the peer identity
    /// signature; no private key material is needed in the configuration.
    ///
    /// # Errors
    ///
    /// Returns the same carrier and handshake errors as [`Node::connect`],
    /// plus a handshake error when the peer endpoint does not match.
    pub async fn connect_to_endpoint(
        &mut self,
        carrier_type: &str,
        remote: String,
        expected_endpoint_id: [u8; 32],
    ) -> Result<u64, NodeError> {
        self.connect_with_endpoint_check(carrier_type, remote, Some(expected_endpoint_id), None)
            .await
            .map(|connection| connection.session_id)
    }

    /// Complete an outbound XX handshake and retain the authenticated link
    /// plus traffic secrets for a caller-owned session loop. This is the
    /// transport-owning counterpart to [`Node::connect`], which intentionally
    /// keeps its historical id-only return type.
    ///
    /// # Errors
    ///
    /// Returns the same carrier, handshake, and version-negotiation errors as
    /// [`Node::connect`].
    pub async fn connect_transport(
        &mut self,
        carrier_type: &str,
        remote: String,
        expected_endpoint_id: Option<[u8; 32]>,
    ) -> Result<ConnectedTransport, NodeError> {
        self.connect_with_endpoint_check(carrier_type, remote, expected_endpoint_id, None)
            .await
    }

    /// Complete an outbound handshake with a monotonic operation deadline.
    /// The daemon uses this entry point so a synchronous carrier dial cannot
    /// monopolize the control worker past the request boundary.
    ///
    /// # Errors
    ///
    /// Returns the same carrier, handshake, and endpoint-validation errors as
    /// [`Node::connect_transport`], plus [`NodeError::DeadlineExceeded`] when
    /// the carrier dial outlives `deadline`.
    pub async fn connect_transport_with_deadline(
        &mut self,
        carrier_type: &str,
        remote: String,
        expected_endpoint_id: Option<[u8; 32]>,
        deadline: std::time::Instant,
    ) -> Result<ConnectedTransport, NodeError> {
        self.connect_with_endpoint_check(carrier_type, remote, expected_endpoint_id, Some(deadline))
            .await
    }

    /// Complete an outbound XX handshake over a caller-owned link.
    ///
    /// This is the transport handoff used by relay-backed routes: the relay
    /// adapter supplies packet boundaries while the normal handshake remains
    /// the single source of truth for authentication, transcript binding, and
    /// traffic-secret derivation. The link is consumed exactly once.
    ///
    /// # Errors
    ///
    /// Returns the same carrier, handshake, and endpoint-validation errors as
    /// [`Node::connect_transport`]. A pre-registered carrier type is rejected
    /// so the temporary one-shot adapter cannot overwrite a live carrier.
    pub async fn connect_transport_over_link(
        &mut self,
        carrier_type: &str,
        link: BoxLink,
        expected_endpoint_id: Option<[u8; 32]>,
    ) -> Result<ConnectedTransport, NodeError> {
        self.connect_transport_over_link_inner(carrier_type, link, expected_endpoint_id, None)
            .await
    }

    /// Relay-backed variant of [`Node::connect_transport_over_link`] with a
    /// monotonic deadline for the control operation.
    ///
    /// # Errors
    ///
    /// Returns the same carrier, handshake, and endpoint-validation errors as
    /// [`Node::connect_transport_over_link`], plus
    /// [`NodeError::DeadlineExceeded`] when the operation outlives `deadline`.
    pub async fn connect_transport_over_link_with_deadline(
        &mut self,
        carrier_type: &str,
        link: BoxLink,
        expected_endpoint_id: Option<[u8; 32]>,
        deadline: std::time::Instant,
    ) -> Result<ConnectedTransport, NodeError> {
        self.connect_transport_over_link_inner(
            carrier_type,
            link,
            expected_endpoint_id,
            Some(deadline),
        )
        .await
    }

    async fn connect_transport_over_link_inner(
        &mut self,
        carrier_type: &str,
        link: BoxLink,
        expected_endpoint_id: Option<[u8; 32]>,
        deadline: Option<std::time::Instant>,
    ) -> Result<ConnectedTransport, NodeError> {
        if self.carriers.contains_key(carrier_type) {
            return Err(NodeError::Handshake(format!(
                "carrier type already registered: {carrier_type}"
            )));
        }
        self.carriers.insert(
            carrier_type.to_owned(),
            Arc::new(OneShotCarrier::new(carrier_type, link)),
        );
        let result = self
            .connect_with_endpoint_check(
                carrier_type,
                String::new(),
                expected_endpoint_id,
                deadline,
            )
            .await;
        self.carriers.remove(carrier_type);
        result
    }

    async fn connect_with_endpoint_check(
        &mut self,
        carrier_type: &str,
        remote: String,
        expected_endpoint_id: Option<[u8; 32]>,
        deadline: Option<std::time::Instant>,
    ) -> Result<ConnectedTransport, NodeError> {
        let mut retried = false;
        loop {
            match self
                .connect_attempt(carrier_type, remote.clone(), expected_endpoint_id, deadline)
                .await
            {
                Err(NodeError::VersionNegotiation) if !retried => {
                    // The VN listed a supported version: retry once with a
                    // fresh connection.
                    retried = true;
                }
                result => return result,
            }
        }
    }

    /// One handshake attempt (see [`Node::connect`] for the retry policy).
    #[allow(clippy::too_many_lines)] // one wire handshake path: hello, auth, finished, confirmation
    async fn connect_attempt(
        &mut self,
        carrier_type: &str,
        remote: String,
        expected_endpoint_id: Option<[u8; 32]>,
        deadline: Option<std::time::Instant>,
    ) -> Result<ConnectedTransport, NodeError> {
        let carrier = self
            .carrier_handle(carrier_type)
            .ok_or(NodeError::CarrierUnknown)?;
        let client_ephemeral = StaticHandshakeKeyPair::generate();
        let mut hello =
            umc_handshake::xx::ClientHello::new(self.entropy.as_ref(), &client_ephemeral);
        let mut hello_bytes = hello
            .encode()
            .map_err(|e| NodeError::Handshake(format!("{e:?}")))?;

        // The hello travels as the payload of an Initial long-header packet
        // (wire-format §13), not in plaintext. The client picks a fresh DCID
        // (the session-DCID convention) and its own SCID; both sides derive
        // the initial keys from the DCID (handshake.md §12).
        let mut dcid = [0u8; 8];
        self.entropy.fill(&mut dcid);
        let mut scid = [0u8; 8];
        self.entropy.fill(&mut scid);
        let keys = umc_handshake::initial::derive_initial_keys(&dcid);
        let mut retry_context = None;
        let mut retry_count = 0u8;
        let (link, server_packet) = loop {
            let hello_packet = build_initial_packet_with_token(
                &dcid,
                &scid,
                0,
                &hello_bytes,
                &hello.retry_token,
                &keys.client,
            )?;
            let link =
                dial_carrier_with_deadline(carrier.clone(), remote.clone(), deadline).await?;
            check_operation_deadline(deadline)?;
            // Send the protected Initial as a carrier packet (the carrier
            // restores boundaries).
            send_packet(link.as_ref(), &hello_packet).map_err(NodeError::Carrier)?;

            // The TCP carrier serializes reads and writes behind one stream
            // mutex (carriers/tcp.md): an immediate recv would hold the lock
            // and starve the link's background writer while it flushes our own
            // Initial. Pause so the writer gets its flush window before the
            // first read.
            sleep_for_operation(deadline, Duration::from_millis(100))?;

            // Receive the first response. A Retry is handled statelessly by
            // dialing a fresh link with the same ephemeral and opaque token.
            let first_receive_deadline = std::time::Instant::now() + Duration::from_secs(5);
            let server_packet = loop {
                check_operation_deadline(deadline)?;
                match link.recv() {
                    Ok(packet) => break packet.bytes,
                    Err(e)
                        if e.kind == CarrierErrorKind::WouldBlock
                            && std::time::Instant::now() < first_receive_deadline =>
                    {
                        sleep_for_operation(deadline, Duration::from_millis(10))?;
                    }
                    Err(e) => return Err(NodeError::Carrier(e)),
                }
            };
            if let Ok(retry) = umc_handshake::retry_packet::decode_retry_packet(&server_packet) {
                if retry_count >= 1 {
                    return Err(NodeError::Handshake("multiple Retry packets".into()));
                }
                if retry.destination_connection_id != scid.to_vec() {
                    return Err(NodeError::Handshake(
                        "retry: destination connection id mismatch".into(),
                    ));
                }
                if retry.token.is_empty() {
                    return Err(NodeError::Handshake("retry: empty token".into()));
                }
                retry_context = Some(umc_handshake::retry_packet::retry_context(
                    &hello_bytes,
                    &server_packet,
                ));
                hello.retry_token = retry.token;
                hello_bytes = hello
                    .encode()
                    .map_err(|e| NodeError::Handshake(format!("{e:?}")))?;
                retry_count = retry_count.saturating_add(1);
                continue;
            }
            break (link, server_packet);
        };
        // Version negotiation (compatibility.md §5.2): a Version-
        // Negotiation packet (long-header type VN, version 0) means the
        // server does not support our offered versions. It is never
        // protected (no keys exist before version agreement), so it is
        // recognized here, before the Initial decrypt. A VN listing our
        // version signals the caller to retry once; one listing only
        // unsupported versions is a hard error.
        if let Some((offered, vn_dcid)) =
            umc_handshake::xx::parse_version_negotiation(&server_packet)
        {
            // RFC 9000 §17.2.1 echo check: the VN's DCID must be our SCID.
            if vn_dcid != scid {
                return Err(NodeError::Handshake(
                    "version negotiation: DCID echo mismatch".into(),
                ));
            }
            if umc_handshake::xx::select_version(&offered).is_none() {
                return Err(NodeError::Handshake(
                    "version negotiation: server offers no supported protocol version".into(),
                ));
            }
            return Err(NodeError::VersionNegotiation);
        }
        let server_hello_bytes = parse_initial_response(&server_packet, &keys.server)?;
        let server_hello = umc_handshake::xx::ServerHello::decode(&server_hello_bytes)
            .map_err(|e| NodeError::Handshake(format!("{e:?}")))?;

        // Derive session secrets using the verified client continuation.
        // The daemon's DH chain stands the client's ephemeral in for the
        // static until the real static rides CLIENT_AUTH (handshake.md
        // §18), so the client derives with the same provisional inputs —
        // the session secrets and the client-auth key then match on both
        // sides. The CLIENT_AUTH payload itself carries the REAL static,
        // binding, and signature.
        let handshake_out = umc_handshake::xx::complete_client_side_with_retry_context(
            &self.config.identity.identity,
            &client_ephemeral,
            &client_ephemeral,
            &hello,
            &server_hello,
            self.entropy.as_ref(),
            carrier_type.as_bytes(),
            retry_context.as_ref(),
        )
        .map_err(NodeError::Handshake)?;
        if expected_endpoint_id.is_some_and(|expected| handshake_out.server_endpoint_id != expected)
        {
            return Err(NodeError::Handshake(
                "server endpoint id does not match static peer".into(),
            ));
        }

        // CLIENT_AUTH (handshake.md §18): the client's real static handshake
        // key, its identity binding, and a transcript-bound signature over
        // both endpoint ids, sealed with the provisional-chain client-auth
        // key. The message rides in an encrypted Handshake packet using the
        // directional traffic secret derived from the frozen transcript.
        let binding = umc_handshake::identity::IdentityBinding::sign(
            &self.config.identity.identity,
            &self.config.identity.static_handshake.public(),
            0,
            u64::MAX,
            0,
            [0u8; 32],
        );
        let client_eid =
            umc_handshake::identity::endpoint_id(&self.config.identity.identity.public());
        let sig_input = umc_handshake::xx::client_signature_input(
            &handshake_out.transcript_hash,
            &client_eid,
            &handshake_out.server_endpoint_id,
            &self.config.identity.static_handshake.public().0,
            &handshake_out.server_static_public_key,
        );
        let client_signature = self.config.identity.identity.sign(&sig_input);
        let plaintext = umc_handshake::xx::build_client_auth_plaintext(
            &self.config.identity.static_handshake.public().0,
            &binding,
            &client_signature,
        );
        let ciphertext = umc_handshake::xx::encrypt_client_auth(
            &handshake_out.client_auth_key,
            &handshake_out.transcript_hash,
            &plaintext,
        );
        // The CLIENT_AUTH message body is length-prefixed bytes (the T13
        // driver layout the responder's `complete` decodes), inside the
        // handshake message envelope. The envelope is carried in an
        // encrypted Handshake packet (handshake.md §25), not as a raw frame.
        let mut auth_body = Vec::new();
        umc_wire::bytes::encode(
            &mut auth_body,
            &ciphertext,
            umc_handshake::encoding::MAX_HANDSHAKE_MESSAGE,
        )
        .map_err(|e| NodeError::Handshake(format!("{e:?}")))?;
        let mut auth_frame = Vec::new();
        umc_handshake::encoding::encode_message(
            &mut auth_frame,
            umc_handshake::encoding::CLIENT_AUTH,
            &auth_body,
        )
        .map_err(|e| NodeError::Handshake(format!("{e:?}")))?;
        let client_handshake_secret = umc_handshake::traffic::derive_handshake_traffic_secret(
            &handshake_out.handshake_secret3,
            &handshake_out.transcript_hash,
            true,
        );
        let client_handshake_keys = umc_handshake::traffic::traffic_keys(&client_handshake_secret);
        let auth_packet = umc_handshake::handshake_packet::build_handshake_packet(
            &dcid,
            &scid,
            0,
            &auth_frame,
            &client_handshake_keys,
        )
        .map_err(|e| NodeError::Handshake(format!("client auth packet: {e:?}")))?;
        check_operation_deadline(deadline)?;
        send_packet(link.as_ref(), &auth_packet).map_err(NodeError::Carrier)?;

        // SERVER_FINISHED (handshake.md §19): the daemon's reply after a
        // verified CLIENT_AUTH, inside an encrypted Handshake packet.
        // Pause so the link's background writer
        // flushes our CLIENT_AUTH before the first read (carriers/tcp.md),
        // then poll briefly (recv yields WouldBlock while the reply is
        // buffered).
        sleep_for_operation(deadline, Duration::from_millis(100))?;
        let receive_deadline = std::time::Instant::now() + Duration::from_secs(5);
        let finished_packet = loop {
            check_operation_deadline(deadline)?;
            match link.recv() {
                Ok(packet) => break packet.bytes,
                Err(e)
                    if e.kind == CarrierErrorKind::WouldBlock
                        && std::time::Instant::now() < receive_deadline =>
                {
                    sleep_for_operation(deadline, Duration::from_millis(10))?;
                }
                Err(e) => return Err(NodeError::Carrier(e)),
            }
        };
        let server_handshake_secret = umc_handshake::traffic::derive_handshake_traffic_secret(
            &handshake_out.handshake_secret3,
            &handshake_out.transcript_hash,
            false,
        );
        let server_handshake_keys = umc_handshake::traffic::traffic_keys(&server_handshake_secret);
        let (_server_dcid, _server_scid, _server_pn, finished_body) =
            umc_handshake::handshake_packet::parse_handshake_packet(
                &finished_packet,
                &server_handshake_keys,
                0,
            )
            .map_err(|e| NodeError::Handshake(format!("server finished packet: {e:?}")))?;
        let (finished_message, _) = umc_handshake::encoding::decode_message(&finished_body)
            .map_err(|e| NodeError::Handshake(format!("server finished framing: {e:?}")))?;
        if finished_message.message_type != umc_handshake::encoding::SERVER_FINISHED {
            return Err(NodeError::Handshake(format!(
                "expected SERVER_FINISHED, got message type {}",
                finished_message.message_type
            )));
        }
        // Rebuild the client's transcript through SERVER_HELLO (the same
        // messages both sides appended), verify the server's finished MAC
        // and signature over the hash BEFORE SERVER_FINISHED, and build the
        // CLIENT_FINISHED confirmation MAC over the hash AFTER
        // SERVER_FINISHED (the T13 driver's snapshot order, handshake.md
        // §19-20).
        let mut transcript = umc_handshake::transcript::Transcript::new(
            umc_handshake::xx::MODE_XX,
            umc_handshake::xx::CRYPTO_PROFILE,
            carrier_type.as_bytes(),
        );
        transcript
            .update_message(umc_handshake::encoding::CLIENT_HELLO, &hello_bytes)
            .map_err(|e| NodeError::Handshake(format!("transcript: {e:?}")))?;
        if let Some(retry_context) = retry_context.as_ref() {
            transcript.update_bytes(retry_context);
        }
        // Re-encode the canonical SERVER_HELLO: the Initial response's
        // decrypted payload may carry PADDING frames after the hello that
        // `decode` ignores (wire-format §13), and the transcript must bind
        // the hello bytes only — exactly what the daemon appended.
        let server_hello_canonical = server_hello
            .encode()
            .map_err(|e| NodeError::Handshake(format!("server hello: {e:?}")))?;
        transcript
            .update_message(
                umc_handshake::encoding::SERVER_HELLO,
                &server_hello_canonical,
            )
            .map_err(|e| NodeError::Handshake(format!("transcript: {e:?}")))?;
        let confirmation = umc_handshake::xx::verify_server_finished_and_build_confirmation(
            &mut transcript,
            &handshake_out.handshake_secret4,
            &handshake_out.server_identity_public_key,
            &handshake_out.server_endpoint_id,
            &client_eid,
            &handshake_out.server_static_public_key,
            &self.config.identity.static_handshake.public().0,
            &auth_body,
            &finished_message.body,
        )
        .map_err(NodeError::Handshake)?;
        // CLIENT_FINISHED (handshake.md §20): the confirmation MAC, framed
        // inside an encrypted Handshake packet. The session secrets were already
        // derived (complete_client_side); the confirmation is what the
        // daemon verifies before it activates the session.
        let mut finished_frame = Vec::new();
        umc_handshake::encoding::encode_message(
            &mut finished_frame,
            umc_handshake::encoding::CLIENT_FINISHED,
            &confirmation,
        )
        .map_err(|e| NodeError::Handshake(format!("{e:?}")))?;
        let finished_packet = umc_handshake::handshake_packet::build_handshake_packet(
            &dcid,
            &scid,
            1,
            &finished_frame,
            &client_handshake_keys,
        )
        .map_err(|e| NodeError::Handshake(format!("client finished packet: {e:?}")))?;
        check_operation_deadline(deadline)?;
        send_packet(link.as_ref(), &finished_packet).map_err(NodeError::Carrier)?;

        let id = self.next_session;
        self.next_session += 1;
        let session_dcid = transport_session_dcid(&dcid);
        let secrets = handshake_out.session_secrets.clone();
        let peer_endpoint_id = handshake_out.server_endpoint_id;
        self.sessions.lock().await.insert(
            id,
            SessionEntry {
                secrets: handshake_out.session_secrets,
                peer_endpoint_id,
            },
        );
        Ok(ConnectedTransport {
            session_id: id,
            link,
            dcid: session_dcid,
            secrets,
            peer_endpoint_id,
        })
    }

    /// Resume a session with a session ticket (handshake.md §35, IK mode):
    /// the client keeps the ticket it received when the previous session
    /// closed, plus that session's resumption secret (derived by
    /// `derive_session_secrets`). The ticket is opaque — sealed with the
    /// server's ticket key — but its v1 wire format carries the nonce in
    /// the clear, so the client derives the same resumption PSK the server
    /// does. The resume runs `CLIENT_HELLO` (mode IK, the ticket in
    /// `retry_token` — the SANCTIONED v1 ticket carrier) and
    /// `SERVER_HELLO` (mode IK, no auth block); both sides skip the
    /// `CLIENT_AUTH`/`SERVER_FINISHED` exchange and derive the resumed
    /// traffic secrets from the ephemeral DH under the PSK.
    ///
    /// Version negotiation retries once with a fresh connection, mirroring
    /// [`Node::connect`].
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::CarrierUnknown`] when no carrier of the given
    /// type is registered, [`NodeError::Carrier`] when dialing or
    /// exchanging packets fails, and [`NodeError::Handshake`] when the
    /// ticket is malformed, the server does not select IK mode (a stale or
    /// invalid ticket makes the daemon fall back to the full XX path — the
    /// caller should retry with [`Node::connect`]), or the secrets cannot
    /// be derived.
    pub async fn connect_resumed(
        &mut self,
        carrier_type: &str,
        remote: String,
        ticket: &[u8],
        resumption_secret: &[u8; 32],
    ) -> Result<u64, NodeError> {
        let mut retried = false;
        loop {
            match self
                .connect_resumed_attempt(carrier_type, remote.clone(), ticket, resumption_secret)
                .await
            {
                Err(NodeError::VersionNegotiation) if !retried => {
                    // The VN listed a supported version: retry once with a
                    // fresh connection.
                    retried = true;
                }
                result => return result,
            }
        }
    }

    /// One resume attempt (see [`Node::connect_resumed`] for the retry
    /// policy).
    #[allow(clippy::too_many_lines)] // one wire resume path: hello, server hello, secrets
    async fn connect_resumed_attempt(
        &mut self,
        carrier_type: &str,
        remote: String,
        ticket: &[u8],
        resumption_secret: &[u8; 32],
    ) -> Result<u64, NodeError> {
        let carrier = self
            .carrier(carrier_type)
            .ok_or(NodeError::CarrierUnknown)?;
        let link = carrier.dial(remote).map_err(NodeError::Carrier)?;

        // The resume hello offers only the IK mode and carries the ticket
        // in `retry_token` (the SANCTIONED v1 ticket carrier).
        let client_ephemeral = StaticHandshakeKeyPair::generate();
        let mut hello =
            umc_handshake::xx::ClientHello::new(self.entropy.as_ref(), &client_ephemeral);
        hello.supported_handshake_modes = vec![umc_handshake::ik::MODE_IK.to_vec()];
        hello.retry_token = ticket.to_vec();
        let hello_bytes = hello
            .encode()
            .map_err(|e| NodeError::Handshake(format!("{e:?}")))?;

        // The ticket's clear nonce prefix (v1 wire format): the client
        // cannot open the seal but needs the nonce for the PSK derivation.
        let nonce = umc_handshake::ticket::ticket_nonce(ticket)
            .ok_or_else(|| NodeError::Handshake("ticket malformed (no clear nonce)".into()))?;

        let mut dcid = [0u8; 8];
        self.entropy.fill(&mut dcid);
        let mut scid = [0u8; 8];
        self.entropy.fill(&mut scid);
        let keys = umc_handshake::initial::derive_initial_keys(&dcid);
        let hello_packet = build_initial_packet(&dcid, &scid, 0, &hello_bytes, &keys.client)?;
        send_packet(link.as_ref(), &hello_packet).map_err(NodeError::Carrier)?;
        std::thread::sleep(Duration::from_millis(100));

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let server_packet = loop {
            match link.recv() {
                Ok(packet) => break packet.bytes,
                Err(e)
                    if e.kind == CarrierErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(NodeError::Carrier(e)),
            }
        };
        // Version negotiation (compatibility.md §5.2): identical to the
        // full connect path.
        if let Some((offered, vn_dcid)) =
            umc_handshake::xx::parse_version_negotiation(&server_packet)
        {
            if vn_dcid != scid {
                return Err(NodeError::Handshake(
                    "version negotiation: DCID echo mismatch".into(),
                ));
            }
            if umc_handshake::xx::select_version(&offered).is_none() {
                return Err(NodeError::Handshake(
                    "version negotiation: server offers no supported protocol version".into(),
                ));
            }
            return Err(NodeError::VersionNegotiation);
        }
        let server_hello_bytes = parse_initial_response(&server_packet, &keys.server)?;
        let server_hello = umc_handshake::xx::ServerHello::decode(&server_hello_bytes)
            .map_err(|e| NodeError::Handshake(format!("{e:?}")))?;
        // The resume server hello must select IK: a mode-XX answer means
        // the daemon fell back to the full path (stale or invalid ticket)
        // and the caller must retry with a full connect.
        if server_hello.selected_handshake_mode != umc_handshake::ik::MODE_IK {
            return Err(NodeError::Handshake(
                "resume refused: server selected the full XX handshake (stale ticket?)".into(),
            ));
        }
        // Capability negotiation (compatibility.md §5.4): the server's
        // canonical hash rides in the padding prefix, as on the XX path.
        if server_hello.server_capabilities_hash()
            != Some(umc_handshake::xx::capabilities_hash(
                &umc_handshake::xx::canonical_capabilities(),
            ))
        {
            return Err(NodeError::Handshake(
                "server capabilities hash mismatch".into(),
            ));
        }

        // The resume transcript binds both hello messages under the IK mode
        // (handshake.md §35) — the exact context the daemon derives with.
        // Re-encode the canonical SERVER_HELLO, mirroring the XX path.
        let mut transcript = umc_handshake::transcript::Transcript::new(
            umc_handshake::ik::MODE_IK,
            umc_handshake::xx::CRYPTO_PROFILE,
            carrier_type.as_bytes(),
        );
        transcript
            .update_message(umc_handshake::encoding::CLIENT_HELLO, &hello_bytes)
            .map_err(|e| NodeError::Handshake(format!("transcript: {e:?}")))?;
        let server_hello_canonical = server_hello
            .encode()
            .map_err(|e| NodeError::Handshake(format!("server hello: {e:?}")))?;
        transcript
            .update_message(
                umc_handshake::encoding::SERVER_HELLO,
                &server_hello_canonical,
            )
            .map_err(|e| NodeError::Handshake(format!("transcript: {e:?}")))?;

        // The resumed traffic secrets: both sides derive the same PSK from
        // the previous session's resumption secret and the ticket's clear
        // nonce, then the ephemeral DH under the PSK.
        let psk = umc_session::ticket::resumption_psk(resumption_secret, &nonce);
        let resume = umc_handshake::ik::derive_resumption_secrets(
            &psk,
            &client_ephemeral,
            &server_hello.server_ephemeral_public_key,
            &transcript.hash,
        );

        let id = self.next_session;
        self.next_session += 1;
        // The v1 resume derives only the two traffic secrets; the remaining
        // `SessionSecrets` fields are unused by resumed sessions (the
        // stateless-reset and resumption chains of the resumed session are
        // documented as not derived). The peer identity is not re-established
        // by the resume (no identity exchange): it is unknown until a full
        // handshake.
        self.sessions.lock().await.insert(
            id,
            SessionEntry {
                secrets: SessionSecrets {
                    client: resume.client,
                    server: resume.server,
                    exporter: [0u8; 32],
                    resumption: [0u8; 32],
                    path_validation: [0u8; 32],
                    connection_id: [0u8; 32],
                    stateless_reset: [0u8; 32],
                },
                peer_endpoint_id: [0u8; 32],
            },
        );
        Ok(id)
    }
}

/// Carrier shim that hands one caller-owned link to the existing client
/// handshake path. It is intentionally single-use: a retry must establish a
/// fresh relay link rather than accidentally reusing a half-consumed stream.
struct OneShotCarrier {
    type_id: CarrierTypeId,
    link: std::sync::Mutex<Option<BoxLink>>,
}

impl OneShotCarrier {
    fn new(type_id: &str, link: BoxLink) -> Self {
        Self {
            type_id: CarrierTypeId(type_id.to_owned()),
            link: std::sync::Mutex::new(Some(link)),
        }
    }
}

impl Carrier for OneShotCarrier {
    fn type_id(&self) -> CarrierTypeId {
        self.type_id.clone()
    }

    fn capabilities(&self) -> CarrierCapabilities {
        CarrierCapabilities {
            api_version: 1,
            carrier_type: self.type_id(),
            packet_mode: PacketMode::StreamFramed,
            reliability: Reliability::ReliableUntilLinkFailure,
            ordering: Ordering::Ordered,
            connection_model: ConnectionModel::Connected,
            supports_listen: false,
            supports_dial: true,
            supports_discovery: false,
            minimum_packet_size: 1,
            maximum_packet_size: 65_535,
            scope_classes: vec!["relay".into()],
        }
    }

    fn listen(
        &self,
        _bind: String,
    ) -> Result<Box<dyn umc_carrier::Listener + Send + Sync>, umc_carrier::error::CarrierError>
    {
        Err(umc_carrier::error::CarrierError::new(
            umc_carrier::error::CarrierErrorKind::Unsupported,
            "relay listen",
        ))
    }

    fn dial(&self, _remote: String) -> Result<BoxLink, umc_carrier::error::CarrierError> {
        self.link
            .lock()
            .map_err(|_| {
                umc_carrier::error::CarrierError::new(
                    umc_carrier::error::CarrierErrorKind::LinkFailed,
                    "relay dial",
                )
            })?
            .take()
            .ok_or_else(|| {
                umc_carrier::error::CarrierError::new(
                    umc_carrier::error::CarrierErrorKind::LinkFailed,
                    "relay dial reused",
                )
            })
    }
}

fn send_packet(
    link: &(dyn umc_carrier::Link + Send + Sync),
    bytes: &[u8],
) -> Result<(), CarrierError> {
    match link.send(OutboundPacket {
        bytes: bytes.to_vec(),
        control: true,
        deadline_ms: Some(3_000),
    })? {
        SendResult::Accepted { .. } => Ok(()),
        SendResult::WouldBlock | SendResult::QueueFull => {
            Err(CarrierError::new(CarrierErrorKind::WouldBlock, "send"))
        }
    }
}

/// The protected Initial's destination connection id becomes the session
/// destination id. The daemon preserves this id when it registers the
/// session; deriving a second id from the hello would make the first
/// protected application packet unroutable.
fn transport_session_dcid(initial_dcid: &[u8]) -> Vec<u8> {
    initial_dcid.to_vec()
}

/// Seal `payload` into an Initial long-header packet (wire-format §13):
/// PADDING frames pad the payload so the whole packet reaches the
/// carrier's 1,200-byte minimum Initial size, then the payload is sealed
/// with `keys` using the header up to and including the packet-number
/// bytes as AAD — the exact convention the daemon's `try_parse_initial`
/// opens with.
///
/// # Errors
///
/// Returns [`NodeError::Handshake`] when the header cannot be encoded or
/// the AEAD seal fails.
fn build_initial_packet(
    dcid: &[u8],
    scid: &[u8],
    pn: u64,
    payload: &[u8],
    keys: &umc_crypto::aead::PacketKeys,
) -> Result<Vec<u8>, NodeError> {
    build_initial_packet_with_token(dcid, scid, pn, payload, &[], keys)
}

fn build_initial_packet_with_token(
    dcid: &[u8],
    scid: &[u8],
    pn: u64,
    payload: &[u8],
    token: &[u8],
    keys: &umc_crypto::aead::PacketKeys,
) -> Result<Vec<u8>, NodeError> {
    let tag_len = umc_crypto::aead::TAG_LEN;
    let mut plaintext = payload.to_vec();
    // Add one PADDING frame (0x00) per pass until the packet reaches the
    // minimum Initial size. The header length is monotonic in the payload
    // length varint, so the loop terminates within MIN_INITIAL_UDP passes.
    loop {
        let header = umc_wire::header::LongHeader {
            ptype: umc_wire::header::LongPacketType::Initial,
            version: umc_types::version::PROTOCOL_VERSION,
            dcid: dcid.to_vec(),
            scid: scid.to_vec(),
            token: token.to_vec(),
            payload_len: u64::try_from(plaintext.len() + tag_len)
                .map_err(|_| NodeError::Handshake("payload too large".into()))?,
            packet_number: pn,
            pn_bits: 8,
        }
        .encode()
        .map_err(|e| NodeError::Handshake(format!("header: {e:?}")))?;
        if header.len() + plaintext.len() + tag_len >= umc_types::version::MIN_INITIAL_UDP {
            let ciphertext = keys
                .seal(pn, &header, &plaintext)
                .map_err(|e| NodeError::Handshake(format!("seal: {e:?}")))?;
            let pn_offset = header
                .len()
                .checked_sub(1)
                .ok_or_else(|| NodeError::Handshake("initial header missing PN".into()))?;
            let sample = ciphertext
                .get(..umc_crypto::header_protection::SAMPLE_LEN)
                .ok_or_else(|| NodeError::Handshake("initial payload too short for HP".into()))?;
            let mut pn_bytes = header[pn_offset..].to_vec();
            let (protected_first, _) = umc_crypto::header_protection::protect(
                &keys.hp_key,
                header[0],
                false,
                sample,
                &mut pn_bytes,
            );
            let mut out = header[..pn_offset].to_vec();
            out[0] = protected_first;
            out.extend_from_slice(&pn_bytes);
            out.extend_from_slice(&ciphertext);
            return Ok(out);
        }
        plaintext.push(0x00);
    }
}

/// Parse and decrypt the peer's Initial response packet — the client-side
/// mirror of the daemon's `try_parse_initial`, decrypting with the keys
/// derived from OUR DCID (the response's DCID field routes back to our
/// SCID and must NOT re-derive the keys). Returns the decrypted payload.
///
/// # Errors
///
/// Returns [`NodeError::Handshake`] when the bytes are not an Initial
/// long-header packet or the AEAD open fails.
fn parse_initial_response(
    bytes: &[u8],
    keys: &umc_crypto::aead::PacketKeys,
) -> Result<Vec<u8>, NodeError> {
    umc_handshake::initial::parse_initial_with_keys(bytes, keys)
        .map(|(_dcid, _pn, payload, _scid)| payload)
        .ok_or_else(|| NodeError::Handshake("initial response rejected".into()))
}

async fn dial_carrier_with_deadline(
    carrier: Arc<dyn Carrier + Send + Sync>,
    remote: String,
    deadline: Option<std::time::Instant>,
) -> Result<BoxLink, NodeError> {
    let Some(deadline) = deadline else {
        return carrier.dial(remote).map_err(NodeError::Carrier);
    };
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .ok_or(NodeError::DeadlineExceeded)?;
    let operation = tokio::task::spawn_blocking(move || carrier.dial(remote));
    match tokio::time::timeout(remaining, operation).await {
        Ok(Ok(Ok(link))) => Ok(link),
        Ok(Ok(Err(error))) => Err(NodeError::Carrier(error)),
        Ok(Err(_)) => Err(NodeError::Handshake("carrier dial worker failed".into())),
        Err(_) => Err(NodeError::DeadlineExceeded),
    }
}

fn check_operation_deadline(deadline: Option<std::time::Instant>) -> Result<(), NodeError> {
    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
        return Err(NodeError::DeadlineExceeded);
    }
    Ok(())
}

fn sleep_for_operation(
    deadline: Option<std::time::Instant>,
    requested: Duration,
) -> Result<(), NodeError> {
    let duration = match deadline {
        Some(deadline) => deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or(NodeError::DeadlineExceeded)?
            .min(requested),
        None => requested,
    };
    std::thread::sleep(duration);
    check_operation_deadline(deadline)
}

#[derive(Debug)]
pub enum NodeError {
    CarrierUnknown,
    Carrier(CarrierError),
    DeadlineExceeded,
    Handshake(String),
    /// A Version-Negotiation response listing a supported protocol version
    /// (compatibility.md §5.2): the caller retries the connect with a
    /// fresh connection.
    VersionNegotiation,
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for NodeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;
    use umc_carrier::types::{
        CarrierCapabilities, CarrierTypeId, ConnectionModel, InboundPacket, LinkEvent,
        LinkProperties, Ordering, OutboundPacket, PacketMode, QueueState, Reliability, SendResult,
    };
    use umc_carrier::Carrier;
    use umc_types::runtime::{EntropySource, Instant};

    struct TestEntropy;

    impl EntropySource for TestEntropy {
        fn fill(&self, out: &mut [u8]) {
            out.fill(0x5A);
        }
    }

    struct TestClock;

    impl Clock for TestClock {
        fn now(&self) -> Instant {
            Instant(0)
        }
    }

    /// A carrier whose `dial` returns a [`RecordingLink`].
    struct RecordingCarrier {
        sent: Arc<StdMutex<Vec<u8>>>,
    }

    impl Carrier for RecordingCarrier {
        fn type_id(&self) -> CarrierTypeId {
            CarrierTypeId("rec.1".into())
        }

        fn capabilities(&self) -> CarrierCapabilities {
            CarrierCapabilities {
                api_version: 1,
                carrier_type: self.type_id(),
                packet_mode: PacketMode::StreamFramed,
                reliability: Reliability::ReliableUntilLinkFailure,
                ordering: Ordering::Ordered,
                connection_model: ConnectionModel::Connected,
                supports_listen: false,
                supports_dial: true,
                supports_discovery: false,
                minimum_packet_size: 1,
                maximum_packet_size: 65_535,
                scope_classes: vec![],
            }
        }

        fn listen(
            &self,
            _bind: String,
        ) -> Result<Box<dyn umc_carrier::Listener + Send + Sync>, CarrierError> {
            Err(CarrierError::new(CarrierErrorKind::Unsupported, "listen"))
        }

        fn dial(&self, _remote: String) -> Result<umc_carrier::BoxLink, CarrierError> {
            Ok(Box::new(RecordingLink {
                sent: self.sent.clone(),
            }))
        }
    }

    /// Records every sent packet; `recv` fails loud so a `connect` against
    /// it fails quickly after the first send.
    struct RecordingLink {
        sent: Arc<StdMutex<Vec<u8>>>,
    }

    #[test]
    fn caller_owned_link_entrypoint_exists() {
        let entrypoint = Node::connect_transport_over_link;
        let _ = entrypoint;
    }

    #[test]
    fn connect_transport_enforces_carrier_dial_deadline() {
        struct SlowDialCarrier;

        impl Carrier for SlowDialCarrier {
            fn type_id(&self) -> CarrierTypeId {
                CarrierTypeId("slow.deadline".into())
            }

            fn capabilities(&self) -> CarrierCapabilities {
                CarrierCapabilities {
                    api_version: 1,
                    carrier_type: self.type_id(),
                    packet_mode: PacketMode::StreamFramed,
                    reliability: Reliability::ReliableUntilLinkFailure,
                    ordering: Ordering::Ordered,
                    connection_model: ConnectionModel::Connected,
                    supports_listen: false,
                    supports_dial: true,
                    supports_discovery: false,
                    minimum_packet_size: 1,
                    maximum_packet_size: 65_535,
                    scope_classes: vec![],
                }
            }

            fn listen(
                &self,
                _bind: String,
            ) -> Result<Box<dyn umc_carrier::Listener + Send + Sync>, CarrierError> {
                Err(CarrierError::new(CarrierErrorKind::Unsupported, "listen"))
            }

            fn dial(&self, _remote: String) -> Result<umc_carrier::BoxLink, CarrierError> {
                std::thread::sleep(std::time::Duration::from_millis(100));
                Err(CarrierError::new(CarrierErrorKind::Unreachable, "dial"))
            }
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let mut node = Node::new(
                NodeConfig {
                    identity: NodeIdentity::generate(&TestEntropy),
                    dcid: vec![1u8; 8],
                },
                Arc::new(TestClock),
                Arc::new(TestEntropy),
            );
            node.register_carrier(Box::new(SlowDialCarrier));
            let started = std::time::Instant::now();
            let result = node
                .connect_transport_with_deadline(
                    "slow.deadline",
                    "slow://peer".into(),
                    None,
                    std::time::Instant::now() + std::time::Duration::from_millis(10),
                )
                .await;
            assert!(matches!(result, Err(NodeError::DeadlineExceeded)));
            assert!(started.elapsed() < std::time::Duration::from_millis(80));
        });
    }

    impl umc_carrier::Link for RecordingLink {
        fn properties(&self) -> LinkProperties {
            LinkProperties {
                reliability: Reliability::ReliableUntilLinkFailure,
                ordering: Ordering::Ordered,
                current_mtu: 65_535,
                queue_bytes: 0,
                queue_capacity: 2 * 1024 * 1024,
                estimated_rtt_ms: None,
                estimated_loss: None,
                metered: false,
            }
        }

        fn send(&self, packet: OutboundPacket) -> Result<SendResult, CarrierError> {
            self.sent
                .lock()
                .expect("sent")
                .extend_from_slice(&packet.bytes);
            Ok(SendResult::Accepted {
                queue_state: QueueState::SentToMedium,
            })
        }

        fn recv(&self) -> Result<InboundPacket, CarrierError> {
            Err(CarrierError::new(CarrierErrorKind::LinkFailed, "recv"))
        }

        fn events(&self) -> Result<LinkEvent, CarrierError> {
            Err(CarrierError::new(CarrierErrorKind::WouldBlock, "events"))
        }

        fn close(&self, _reason: &str) -> Result<(), CarrierError> {
            Ok(())
        }
    }

    /// A carrier whose `dial` yields links that replay scripted responses
    /// and record every sent packet: each recv pops the front of the queue
    /// (a later recv fails loud). One link per dial, so a version-
    /// negotiation retry consumes the next response on a fresh link.
    struct ScriptedCarrier {
        responses: Arc<StdMutex<VecDeque<Vec<u8>>>>,
        sent: Arc<StdMutex<Vec<Vec<u8>>>>,
    }

    impl Carrier for ScriptedCarrier {
        fn type_id(&self) -> CarrierTypeId {
            CarrierTypeId("scr.1".into())
        }

        fn capabilities(&self) -> CarrierCapabilities {
            CarrierCapabilities {
                api_version: 1,
                carrier_type: self.type_id(),
                packet_mode: PacketMode::StreamFramed,
                reliability: Reliability::ReliableUntilLinkFailure,
                ordering: Ordering::Ordered,
                connection_model: ConnectionModel::Connected,
                supports_listen: false,
                supports_dial: true,
                supports_discovery: false,
                minimum_packet_size: 1,
                maximum_packet_size: 65_535,
                scope_classes: vec![],
            }
        }

        fn listen(
            &self,
            _bind: String,
        ) -> Result<Box<dyn umc_carrier::Listener + Send + Sync>, CarrierError> {
            Err(CarrierError::new(CarrierErrorKind::Unsupported, "listen"))
        }

        fn dial(&self, _remote: String) -> Result<umc_carrier::BoxLink, CarrierError> {
            Ok(Box::new(ScriptedLink {
                responses: self.responses.clone(),
                sent: self.sent.clone(),
            }))
        }
    }

    struct ScriptedLink {
        responses: Arc<StdMutex<VecDeque<Vec<u8>>>>,
        sent: Arc<StdMutex<Vec<Vec<u8>>>>,
    }

    impl umc_carrier::Link for ScriptedLink {
        fn properties(&self) -> LinkProperties {
            LinkProperties {
                reliability: Reliability::ReliableUntilLinkFailure,
                ordering: Ordering::Ordered,
                current_mtu: 65_535,
                queue_bytes: 0,
                queue_capacity: 2 * 1024 * 1024,
                estimated_rtt_ms: None,
                estimated_loss: None,
                metered: false,
            }
        }

        fn send(&self, packet: OutboundPacket) -> Result<SendResult, CarrierError> {
            self.sent.lock().expect("sent").push(packet.bytes);
            Ok(SendResult::Accepted {
                queue_state: QueueState::SentToMedium,
            })
        }

        fn recv(&self) -> Result<InboundPacket, CarrierError> {
            match self.responses.lock().expect("responses").pop_front() {
                Some(bytes) => Ok(InboundPacket {
                    bytes,
                    received_at: Instant(0),
                }),
                None => Err(CarrierError::new(
                    CarrierErrorKind::LinkFailed,
                    "recv: no scripted response",
                )),
            }
        }

        fn events(&self) -> Result<LinkEvent, CarrierError> {
            Err(CarrierError::new(CarrierErrorKind::WouldBlock, "events"))
        }

        fn close(&self, _reason: &str) -> Result<(), CarrierError> {
            Ok(())
        }
    }

    /// An Initial-protected packet carrying a (garbage-auth) `SERVER_HELLO`
    /// sealed with the server initial keys derived from the client's DCID —
    /// the mirror of the daemon's accept-path `build_initial_packet`. The
    /// client's DCID is deterministic under `TestEntropy` (all `0x5A`), so
    /// the mock response is pre-buildable.
    fn build_server_hello_initial(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let server_hello = umc_handshake::xx::ServerHello {
            server_random: [1u8; 32],
            server_ephemeral_public_key: [2u8; 32],
            selected_protocol_version: 1,
            selected_crypto_profile: umc_handshake::xx::CRYPTO_PROFILE.to_vec(),
            selected_handshake_mode: umc_handshake::xx::MODE_XX.to_vec(),
            encrypted_server_authentication: vec![3u8; 64],
            // The canonical capabilities hash in the padding prefix: the
            // client's `complete_client_side` verification passes here.
            padding: {
                let mut p = umc_handshake::xx::capabilities_hash(
                    &umc_handshake::xx::canonical_capabilities(),
                )
                .to_vec();
                p.extend_from_slice(&[0u8; 32]);
                p
            },
        }
        .encode()
        .expect("server hello");
        let keys = umc_handshake::initial::derive_initial_keys(dcid).server;
        let header = umc_wire::header::LongHeader {
            ptype: umc_wire::header::LongPacketType::Initial,
            version: umc_types::version::PROTOCOL_VERSION,
            dcid: dcid.to_vec(),
            scid: scid.to_vec(),
            token: Vec::new(),
            payload_len: u64::try_from(server_hello.len() + umc_crypto::aead::TAG_LEN)
                .expect("fits"),
            packet_number: 0,
            pn_bits: 8,
        }
        .encode()
        .expect("header");
        let ciphertext = keys.seal(0, &header, &server_hello).expect("seal");
        let mut out = header;
        out.extend_from_slice(&ciphertext);
        out
    }

    #[test]
    fn node_identity_generates_distinct_ids() {
        let a = NodeIdentity::generate(&TestEntropy);
        let b = NodeIdentity::generate(&TestEntropy);
        assert_ne!(a.endpoint_id(), b.endpoint_id());
    }

    #[test]
    fn outbound_transport_uses_initial_session_dcid() {
        let initial = [0xA5u8; 8];
        assert_eq!(transport_session_dcid(&initial), initial);
    }

    #[test]
    fn node_registers_and_looks_up_carriers() {
        let mut node = Node::new(
            NodeConfig {
                identity: NodeIdentity::generate(&TestEntropy),
                dcid: vec![1u8; 8],
            },
            Arc::new(TestClock),
            Arc::new(TestEntropy),
        );
        assert!(node.carrier("ump.tcp/1").is_none());
        node.register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));
        assert!(node.carrier("ump.tcp/1").is_some());
        assert!(node.carrier("ump.udp/1").is_none());
    }

    /// The `CLIENT_HELLO` travels as the payload of an Initial long-header
    /// packet (wire-format §13), not in plaintext: `connect` must seal it
    /// with the client initial keys derived from a fresh DCID and pad the
    /// packet to the 1,200-byte minimum Initial size. The recording link
    /// answers recv with a failure, so `connect` fails after the send —
    /// the sent bytes carry the evidence.
    #[test]
    fn connect_sends_protected_initial() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let sent = Arc::new(StdMutex::new(Vec::new()));
            let mut node = Node::new(
                NodeConfig {
                    identity: NodeIdentity::generate(&TestEntropy),
                    dcid: vec![1u8; 8],
                },
                Arc::new(TestClock),
                Arc::new(TestEntropy),
            );
            node.register_carrier(Box::new(RecordingCarrier { sent: sent.clone() }));
            let peer = NodeIdentity::generate(&TestEntropy);
            let _ = node.connect("rec.1", "recorder".into(), &peer).await;
            let packet = sent.lock().expect("sent").clone();
            assert!(!packet.is_empty(), "a packet must have been sent");
            // TestEntropy fills every byte with 0x5A, so the client-chosen
            // DCID is deterministic: the wire parser must be able to derive
            // the same client keys and decrypt the payload.
            let dcid = [0x5Au8; 8];
            let (parsed_dcid, _pn, payload, scid) =
                umc_handshake::initial::try_parse_initial(&packet)
                    .expect("sent bytes are a parseable Initial packet");
            assert_eq!(parsed_dcid, dcid, "client-chosen DCID");
            assert_eq!(scid.len(), 8, "client SCID");
            assert!(
                packet.len() >= umc_types::version::MIN_INITIAL_UDP,
                "Initial must be padded to >= 1,200 bytes, got {}",
                packet.len()
            );
            assert!(
                umc_handshake::xx::ClientHello::decode(&payload).is_ok(),
                "decrypted payload is a CLIENT_HELLO"
            );
        });
    }

    /// Version negotiation retry (compatibility.md §5.2): a VN response
    /// listing version 1 makes the client dial a fresh link and retry the
    /// handshake — it only fails later, at the (garbage) server-auth
    /// decrypt, never at version negotiation.
    #[test]
    fn connect_retries_once_on_version_negotiation() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            // TestEntropy fixes the client DCID at [0x5A; 8], so the mock
            // SERVER_HELLO packet is buildable ahead of time.
            let dcid = [0x5Au8; 8];
            let responses = Arc::new(StdMutex::new(VecDeque::from([
                umc_handshake::xx::build_version_negotiation(&dcid, &[0x5Bu8; 8], &[1]),
                build_server_hello_initial(&dcid, &[0x5Bu8; 8]),
            ])));
            let sent = Arc::new(StdMutex::new(Vec::new()));
            let mut node = Node::new(
                NodeConfig {
                    identity: NodeIdentity::generate(&TestEntropy),
                    dcid: vec![1u8; 8],
                },
                Arc::new(TestClock),
                Arc::new(TestEntropy),
            );
            node.register_carrier(Box::new(ScriptedCarrier {
                responses: responses.clone(),
                sent: sent.clone(),
            }));
            let peer = NodeIdentity::generate(&TestEntropy);
            let error = node
                .connect("scr.1", "server".into(), &peer)
                .await
                .expect_err("the retry must fail at the server-auth decrypt");
            assert!(
                matches!(&error, NodeError::Handshake(_)),
                "the VN was accepted and the handshake continued: {error:?}"
            );
            let sent = sent.lock().expect("sent").clone();
            assert_eq!(sent.len(), 2, "the initial attempt and the retry");
            assert!(
                umc_handshake::initial::try_parse_initial(&sent[1]).is_some(),
                "the retry re-sends an Initial hello on the fresh link"
            );
        });
    }

    /// The resume hello (`connect_resumed`) travels as an Initial packet
    /// whose payload is a `CLIENT_HELLO` offering ONLY the IK mode and
    /// carrying the ticket in `retry_token` — the SANCTIONED v1 ticket
    /// carrier (handshake.md §35). The recording link answers recv with a
    /// failure, so the resume fails after the send; the sent bytes carry
    /// the evidence.
    #[test]
    fn connect_resumed_sends_ik_hello_with_ticket() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let sent = Arc::new(StdMutex::new(Vec::new()));
            let mut node = Node::new(
                NodeConfig {
                    identity: NodeIdentity::generate(&TestEntropy),
                    dcid: vec![1u8; 8],
                },
                Arc::new(TestClock),
                Arc::new(TestEntropy),
            );
            node.register_carrier(Box::new(RecordingCarrier { sent: sent.clone() }));
            let ticket = umc_handshake::ticket::issue_ticket(&[1u8; 32], &{
                use umc_handshake::ticket::TicketPayload;
                TicketPayload {
                    version: 1,
                    ticket_id: [2u8; 16],
                    client_endpoint_id_hash: [3u8; 32],
                    server_endpoint_id_hash: [4u8; 32],
                    resumption_secret: [5u8; 32],
                    issued_at_ms: 0,
                    expires_at_ms: 86_400_000,
                    protocol_version: 1,
                    crypto_profile: umc_handshake::xx::CRYPTO_PROFILE.to_vec(),
                    nonce: [6u8; 16],
                }
            });
            let _ = node
                .connect_resumed("rec.1", "recorder".into(), &ticket, &[7u8; 32])
                .await;
            let packet = sent.lock().expect("sent").clone();
            assert!(!packet.is_empty(), "a resume hello must have been sent");
            let (_dcid, _pn, payload, _scid) = umc_handshake::initial::try_parse_initial(&packet)
                .expect("sent bytes are a parseable Initial packet");
            let hello = umc_handshake::xx::ClientHello::decode(&payload)
                .expect("decrypted payload is a CLIENT_HELLO");
            assert_eq!(
                hello.supported_handshake_modes,
                vec![umc_handshake::ik::MODE_IK.to_vec()],
                "the resume hello offers only IK mode"
            );
            assert_eq!(
                hello.retry_token, ticket,
                "the ticket rides the retry_token carrier"
            );
        });
    }

    /// A Version-Negotiation response listing only unsupported versions
    /// aborts the connect: no retry is attempted (compatibility.md §5.2).
    #[test]
    fn connect_rejects_vn_not_listing_supported_version() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let dcid = [0x5Au8; 8];
            let responses = Arc::new(StdMutex::new(VecDeque::from([
                umc_handshake::xx::build_version_negotiation(&dcid, &[0x5Bu8; 8], &[2]),
            ])));
            let sent = Arc::new(StdMutex::new(Vec::new()));
            let mut node = Node::new(
                NodeConfig {
                    identity: NodeIdentity::generate(&TestEntropy),
                    dcid: vec![1u8; 8],
                },
                Arc::new(TestClock),
                Arc::new(TestEntropy),
            );
            node.register_carrier(Box::new(ScriptedCarrier {
                responses: responses.clone(),
                sent: sent.clone(),
            }));
            let peer = NodeIdentity::generate(&TestEntropy);
            let error = node
                .connect("scr.1", "server".into(), &peer)
                .await
                .expect_err("a VN listing no supported version must abort");
            assert!(
                matches!(&error, NodeError::Handshake(message) if message.contains("version negotiation")),
                "{error:?}"
            );
            let sent = sent.lock().expect("sent").clone();
            assert_eq!(sent.len(), 1, "no retry against an unsupported VN");
        });
    }
}
