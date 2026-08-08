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
    /// and derives session secrets from the transcript (handshake.md §14-18).
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::CarrierUnknown`] when no carrier of the given type
    /// is registered, [`NodeError::Carrier`] when dialing or exchanging
    /// packets fails, and [`NodeError::Handshake`] when the XX handshake
    /// fails.
    pub async fn connect(
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
        let server_hello_bytes = parse_initial_response(&server_packet, &keys.server)?;
        let server_hello = umc_handshake::xx::ServerHello::decode(&server_hello_bytes)
            .map_err(|e| NodeError::Handshake(format!("{e:?}")))?;

        // Derive session secrets using the verified client continuation.
        let (client_secrets, _client_finished_key) = umc_handshake::xx::complete_client_side(
            &self.config.identity.identity,
            &self.config.identity.static_handshake,
            &client_ephemeral,
            &hello,
            &server_hello,
            self.entropy.as_ref(),
            carrier_type.as_bytes(),
        )
        .map_err(NodeError::Handshake)?;
        let id = self.next_session;
        self.next_session += 1;
        self.sessions.lock().await.insert(
            id,
            SessionEntry {
                secrets: client_secrets,
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
}
