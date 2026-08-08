//! Minimal Phase 1 Node: one identity, TCP/UDP carriers, direct sessions.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use umc_carrier::error::{CarrierError, CarrierErrorKind};
use umc_carrier::types::{OutboundPacket, SendResult};
use umc_carrier::Carrier;
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
    carriers: HashMap<String, Box<dyn Carrier + Send + Sync>>,
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
        self.carriers.insert(carrier.type_id().0.clone(), carrier);
    }

    #[must_use]
    pub fn carrier(&self, type_id: &str) -> Option<&(dyn Carrier + Send + Sync)> {
        self.carriers.get(type_id).map(AsRef::as_ref)
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
        server_identity_public: &NodeIdentity,
    ) -> Result<u64, NodeError> {
        let mut retried = false;
        loop {
            match self
                .connect_attempt(carrier_type, remote.clone(), server_identity_public)
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
        server_identity_public: &NodeIdentity,
    ) -> Result<u64, NodeError> {
        let carrier = self
            .carrier(carrier_type)
            .ok_or(NodeError::CarrierUnknown)?;
        let link = carrier.dial(remote).map_err(NodeError::Carrier)?;

        let client_ephemeral = StaticHandshakeKeyPair::generate();
        let hello = umc_handshake::xx::ClientHello::new(self.entropy.as_ref(), &client_ephemeral);
        let hello_bytes = hello
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
        let hello_packet = build_initial_packet(&dcid, &scid, 0, &hello_bytes, &keys.client)?;

        // Send the protected Initial as a carrier packet (the carrier
        // restores boundaries).
        send_packet(link.as_ref(), &hello_packet).map_err(NodeError::Carrier)?;

        // The TCP carrier serializes reads and writes behind one stream
        // mutex (carriers/tcp.md): an immediate recv would hold the lock
        // and starve the link's background writer while it flushes our own
        // Initial. Pause so the writer gets its flush window before the
        // first read.
        std::thread::sleep(Duration::from_millis(100));

        // Receive the SERVER_HELLO (also Initial-protected) and decrypt it
        // with the server initial keys. The TCP carrier's recv yields
        // WouldBlock while its background writer flushes our own Initial
        // (carriers/tcp.md), so the read retries with a pause until the
        // response arrives.
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
        let handshake_out = umc_handshake::xx::complete_client_side(
            &self.config.identity.identity,
            &client_ephemeral,
            &client_ephemeral,
            &hello,
            &server_hello,
            self.entropy.as_ref(),
            carrier_type.as_bytes(),
        )
        .map_err(NodeError::Handshake)?;

        // CLIENT_AUTH (handshake.md §18): the client's real static handshake
        // key, its identity binding, and a transcript-bound signature over
        // both endpoint ids, sealed with the provisional-chain client-auth
        // key. The message rides as a raw framed handshake message (the
        // transitional wire form; session protection lands with D3+).
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
        // handshake message envelope.
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
        send_packet(link.as_ref(), &auth_frame).map_err(NodeError::Carrier)?;

        // SERVER_FINISHED (handshake.md §19): the daemon's reply after a
        // verified CLIENT_AUTH, a raw framed handshake message on the
        // transitional wire path. Pause so the link's background writer
        // flushes our CLIENT_AUTH before the first read (carriers/tcp.md),
        // then poll briefly (recv yields WouldBlock while the reply is
        // buffered).
        std::thread::sleep(Duration::from_millis(100));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let finished_packet = loop {
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
        let (finished_message, _) = umc_handshake::encoding::decode_message(&finished_packet)
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
        // as a raw handshake message. The session secrets were already
        // derived (complete_client_side); the confirmation is what the
        // daemon verifies before it activates the session.
        let mut finished_frame = Vec::new();
        umc_handshake::encoding::encode_message(
            &mut finished_frame,
            umc_handshake::encoding::CLIENT_FINISHED,
            &confirmation,
        )
        .map_err(|e| NodeError::Handshake(format!("{e:?}")))?;
        send_packet(link.as_ref(), &finished_frame).map_err(NodeError::Carrier)?;

        let id = self.next_session;
        self.next_session += 1;
        self.sessions.lock().await.insert(
            id,
            SessionEntry {
                secrets: handshake_out.session_secrets,
                peer_endpoint_id: server_identity_public.endpoint_id(),
            },
        );
        Ok(id)
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
            token: Vec::new(),
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
            let mut out = header;
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
    let truncated = || NodeError::Handshake("initial response truncated".into());
    let hb = umc_wire::header::HeaderByte::decode(*bytes.first().ok_or_else(truncated)?)
        .map_err(|e| NodeError::Handshake(format!("header: {e:?}")))?;
    if !hb.long || hb.long_type() != Some(umc_wire::header::LongPacketType::Initial) {
        return Err(NodeError::Handshake("not an Initial packet".into()));
    }
    let dcid_len = usize::from(*bytes.get(5).ok_or_else(truncated)?);
    let scid_len = usize::from(*bytes.get(6 + dcid_len).ok_or_else(truncated)?);
    let mut pos = 7 + dcid_len + scid_len;
    let (token_len, n) = umc_wire::varint::decode(bytes.get(pos..).ok_or_else(truncated)?)
        .map_err(|_| NodeError::Handshake("token length".into()))?;
    pos += n;
    let token_len = usize::try_from(token_len).map_err(|_| truncated())?;
    pos = pos.checked_add(token_len).ok_or_else(truncated)?;
    if pos > bytes.len() {
        return Err(truncated());
    }
    let (_payload_len, n) = umc_wire::varint::decode(bytes.get(pos..).ok_or_else(truncated)?)
        .map_err(|_| NodeError::Handshake("payload length".into()))?;
    pos = pos.checked_add(n).ok_or_else(truncated)?;
    if pos > bytes.len() {
        return Err(truncated());
    }
    let pn_bytes = (hb.pn_bits as usize) / 8;
    let protected_pn = bytes.get(pos..pos + pn_bytes).ok_or_else(truncated)?;
    let mut pn_full = [0u8; 8];
    pn_full[8 - pn_bytes..].copy_from_slice(protected_pn);
    let truncated_pn = u64::from_be_bytes(pn_full);
    // AAD is the header up to and including the PN bytes (wire-format §25).
    let aad = bytes.get(..pos + pn_bytes).ok_or_else(truncated)?;
    let packet_number = umc_wire::pn::reconstruct(truncated_pn, hb.pn_bits, 0)
        .map_err(|e| NodeError::Handshake(format!("packet number: {e:?}")))?;
    keys.open(
        packet_number,
        aad,
        bytes.get(pos + pn_bytes..).ok_or_else(truncated)?,
    )
    .map_err(|e| NodeError::Handshake(format!("open: {e:?}")))
}

#[derive(Debug)]
pub enum NodeError {
    CarrierUnknown,
    Carrier(CarrierError),
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
