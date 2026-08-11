//! Phase 12 success criterion (handshake.md §35): IK-mode session
//! resumption end to end against a live daemon.
//!
//! Flow:
//! 1. Node A runs a full XX handshake with daemon B (the harness drives
//!    `Node::connect`'s wire path synchronously) and keeps the session's
//!    resumption secret.
//! 2. The ticket comes from daemon B's own ticket key — derived from the
//!    keystore identity seed exactly as `RuntimeState::new` derives it — so
//!    the daemon accepts the resume. (The daemon's own ticket emission
//!    rides the clean-close path; it is unit-covered in
//!    `session_task.rs`.)
//! 3. `Node::connect_resumed` resumes with the ticket + resumption secret:
//!    the daemon answers the IK hello with a mode-IK `SERVER_HELLO`, skips
//!    the auth exchange, and activates the session.
//! 4. A second resume connection drives a stream round trip: a STREAM frame
//!    with the well-known echo protocol ID (`org.umc.app/1`) is echoed back
//!    by daemon B's echo application.
//!
//! The client runs against a blocking std-TCP carrier registered under
//! `ump.tcp/1` (the same length-prefixed wire framing the real TCP carrier
//! speaks): `Node::connect_resumed` — like `Node::connect` — is an async
//! method, and the real TCP carrier's `Handle::block_on` cannot nest inside
//! a runtime, so the live test drives it with a carrier that performs plain
//! blocking IO (mirroring the phase9 synchronous harness).
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use umc_carrier::error::{CarrierError, CarrierErrorKind};
use umc_carrier::types::{
    CarrierCapabilities, CarrierTypeId, InboundPacket, LinkEvent, LinkProperties, Ordering,
    OutboundPacket, PacketMode, QueueState, Reliability, SendResult,
};
use umc_carrier::{BoxLink, Carrier, Link};
use umc_core::node::{Node, NodeConfig, NodeIdentity};
use umc_core::well_known::WELL_KNOWN_APP;
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_handshake::encoding::{CLIENT_FINISHED, SERVER_FINISHED};
use umc_handshake::identity::{endpoint_id, IdentityBinding};
use umc_handshake::transcript::Transcript;
use umc_handshake::xx::{
    build_client_auth_plaintext, client_signature_input, complete_client_side, encrypt_client_auth,
    verify_server_finished_and_build_confirmation, ClientHandshakeOutput, ClientHello, ServerHello,
    CRYPTO_PROFILE, MODE_XX,
};
use umc_session::session::{Role, Session, SessionConfig};
use umc_types::frame::FrameType;
use umc_types::runtime::{Clock, EntropySource, Instant};
use umc_wire::frames::stream::StreamFrame;

struct TestClock;

impl Clock for TestClock {
    fn now(&self) -> Instant {
        Instant(0)
    }
}

struct TestEntropy;

impl EntropySource for TestEntropy {
    fn fill(&self, out: &mut [u8]) {
        out.fill(0x5A);
    }
}

/// Locate (and if necessary build) the umcd binary. Fails loud when the
/// binary cannot be produced.
fn umcd_binary() -> PathBuf {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin = here
        .join("../../target/debug")
        .join(format!("umcd{}", std::env::consts::EXE_SUFFIX));
    // Rebuild whenever the daemon sources are newer than the binary: a stale
    // daemon silently tests the wrong code (the phase12 suites have been
    // burned by this more than once).
    let src_newer = std::fs::read_dir(here.join("../../bins/umcd/src")).map_or(true, |entries| {
        entries.filter_map(Result::ok).any(|e| {
            e.path()
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .zip(bin.metadata().and_then(|m| m.modified()).ok())
                .is_some_and(|(src, bin)| src > bin)
        })
    });
    if !bin.exists() || src_newer {
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "umcd"])
            .current_dir(here.join("../.."))
            .status()
            .expect("run cargo build -p umcd");
        assert!(status.success(), "cargo build -p umcd failed");
    }
    assert!(bin.exists(), "umcd binary missing at {}", bin.display());
    bin
}

/// A running daemon; kills the child on drop.
struct Daemon {
    child: Child,
    dir: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(name: &str, tcp_port: u16, udp_port: u16) -> (Daemon, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "phase12-resume-daemon-{name}-{}-{tcp_port}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("daemon dir");
    let config = serde_json::json!({
        "data_dir": dir.join("data"),
        "control_socket": dir.join("umc.sock"),
        "carriers": ["ump.tcp/1", "ump.udp/1"],
        "tcp_listen": format!("127.0.0.1:{tcp_port}"),
        "udp_listen": format!("127.0.0.1:{udp_port}"),
    });
    let config_path = dir.join("node.json");
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("config json"),
    )
    .expect("write config");
    let log = fs::File::create(dir.join("umcd.log")).expect("log file");
    let child = Command::new(umcd_binary())
        .args(["--config", config_path.to_str().expect("config path")])
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn umcd");
    (
        Daemon {
            child,
            dir: dir.clone(),
        },
        dir.join("umc.sock"),
    )
}

/// Wait until the daemon's control socket exists: the carrier accept loops
/// are spawned before the control socket binds, so a live socket implies
/// the listeners are accepting.
fn wait_for_control_socket(socket: &Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if socket.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "daemon control socket never appeared at {}",
        socket.display()
    );
}

static TEST_PORT_COUNTER: AtomicU16 = AtomicU16::new(0);

/// Pick a per-process test port and verify it is currently bindable. The
/// old bind-to-zero-then-drop pattern let parallel workspace binaries choose
/// the same port before their daemon children had a chance to bind it.
fn next_test_port() -> u16 {
    loop {
        let sequence = u32::from(TEST_PORT_COUNTER.fetch_add(1, AtomicOrdering::Relaxed));
        let process_slot = std::process::id() % 10_000;
        let port = 20_000 + ((process_slot * 2 + sequence) % 20_000) as u16;
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
            && std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok()
        {
            return port;
        }
    }
}

fn free_tcp_port() -> u16 {
    next_test_port()
}

fn free_udp_port() -> u16 {
    next_test_port()
}

// ---------------------------------------------------------------------------
// Blocking std-TCP carrier (the client side of the daemon's `ump.tcp/1`):
// the same length-prefixed framing `umc-carrier-tcp` speaks, but with plain
// blocking IO so async `Node` methods can be driven against the live daemon
// without nesting tokio runtimes.
// ---------------------------------------------------------------------------

/// Length-prefix framing mirror of `umc-carrier-tcp`'s internal module:
/// varint-ish 1/2/4/8-byte big-endian length prefixes.
#[allow(clippy::cast_possible_truncation)] // lengths are range-checked before each cast
fn push_length(out: &mut Vec<u8>, len: usize) {
    let len = len as u64;
    if len <= 63 {
        out.push(len as u8);
    } else if len <= 16_383 {
        out.push(0b0100_0000 | ((len >> 8) as u8));
        out.push(len as u8);
    } else {
        out.push(0b1000_0000 | ((len >> 24) as u8));
        out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    }
}

/// # Allow: the cast mirrors the real carrier (lengths range-checked).
#[allow(clippy::cast_possible_truncation)]
fn read_length(buf: &[u8]) -> Option<(usize, usize)> {
    let first = *buf.first()?;
    let width = match first >> 6 {
        0 => 1usize,
        1 => 2usize,
        2 => 4usize,
        _ => 8usize,
    };
    if buf.len() < width {
        return None;
    }
    let mut raw = [0u8; 8];
    raw[..width].copy_from_slice(&buf[..width]);
    raw[0] &= 0x3F;
    let v = u64::from_be_bytes(raw) >> ((8 - width) * 8);
    if v > 65_535 {
        return None;
    }
    Some((v as usize, width))
}

/// Per-read timeout: a quiet link yields `WouldBlock`, mirroring the real
/// TCP carrier's 20 ms read timeout.
const READ_TIMEOUT: Duration = Duration::from_millis(20);

struct BlockingTcpLink {
    stream: Mutex<TcpStream>,
    buf: Mutex<Vec<u8>>,
}

impl BlockingTcpLink {
    fn new(stream: TcpStream) -> Self {
        stream
            .set_read_timeout(Some(READ_TIMEOUT))
            .expect("read timeout");
        Self {
            stream: Mutex::new(stream),
            buf: Mutex::new(Vec::new()),
        }
    }
}

impl Link for BlockingTcpLink {
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
        let mut framed = Vec::with_capacity(packet.bytes.len() + 4);
        push_length(&mut framed, packet.bytes.len());
        framed.extend_from_slice(&packet.bytes);
        {
            let mut stream = self.stream.lock().expect("stream");
            stream
                .write_all(&framed)
                .map_err(|_| CarrierError::new(CarrierErrorKind::LinkFailed, "io error"))?;
            stream
                .flush()
                .map_err(|_| CarrierError::new(CarrierErrorKind::LinkFailed, "io error"))?;
        }
        Ok(SendResult::Accepted {
            queue_state: QueueState::SentToMedium,
        })
    }

    fn recv(&self) -> Result<InboundPacket, CarrierError> {
        let mut stream = self.stream.lock().expect("stream");
        let mut buf = std::mem::take(&mut *self.buf.lock().expect("buf"));
        loop {
            let mut b = [0u8; 1];
            match stream.read(&mut b) {
                Ok(0) => {
                    return Err(CarrierError::new(CarrierErrorKind::LinkFailed, "recv"));
                }
                Ok(_) => buf.push(b[0]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Timeout mid-frame: park the partial frame and report
                    // WouldBlock, exactly like the real carrier.
                    *self.buf.lock().expect("buf") = buf;
                    return Err(CarrierError::new(CarrierErrorKind::WouldBlock, "recv"));
                }
                Err(_) => {
                    return Err(CarrierError::new(CarrierErrorKind::LinkFailed, "io error"));
                }
            }
            if let Some((len, used)) = read_length(&buf) {
                while buf.len() < used + len {
                    let mut chunk = vec![0u8; used + len - buf.len()];
                    match stream.read(&mut chunk) {
                        Ok(0) => {
                            return Err(CarrierError::new(CarrierErrorKind::LinkFailed, "recv"));
                        }
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            *self.buf.lock().expect("buf") = buf;
                            return Err(CarrierError::new(CarrierErrorKind::WouldBlock, "recv"));
                        }
                        Err(_) => {
                            return Err(CarrierError::new(
                                CarrierErrorKind::LinkFailed,
                                "io error",
                            ));
                        }
                    }
                }
                return Ok(InboundPacket {
                    bytes: buf[used..used + len].to_vec(),
                    received_at: Instant(0),
                });
            }
        }
    }

    fn events(&self) -> Result<LinkEvent, CarrierError> {
        Err(CarrierError::new(CarrierErrorKind::WouldBlock, "events"))
    }

    fn close(&self, _reason: &str) -> Result<(), CarrierError> {
        Ok(())
    }
}

/// A `Carrier` registered under the standard `ump.tcp/1` type id that dials
/// plain std TCP streams (no tokio `Handle::block_on`, so async `Node`
/// methods can drive it from a runtime thread).
struct BlockingTcpCarrier;

impl Carrier for BlockingTcpCarrier {
    fn type_id(&self) -> CarrierTypeId {
        CarrierTypeId("ump.tcp/1".into())
    }

    fn capabilities(&self) -> CarrierCapabilities {
        CarrierCapabilities {
            api_version: 1,
            carrier_type: self.type_id(),
            packet_mode: PacketMode::StreamFramed,
            reliability: Reliability::ReliableUntilLinkFailure,
            ordering: Ordering::Ordered,
            connection_model: umc_carrier::types::ConnectionModel::Connected,
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

    fn dial(&self, remote: String) -> Result<BoxLink, CarrierError> {
        let stream = TcpStream::connect(remote)
            .map_err(|_| CarrierError::new(CarrierErrorKind::Unreachable, "dial failed"))?;
        Ok(Box::new(BlockingTcpLink::new(stream)))
    }
}

// ---------------------------------------------------------------------------

fn send_packet(link: &(dyn Link + Send + Sync), bytes: &[u8]) -> Result<(), String> {
    link.send(OutboundPacket {
        bytes: bytes.to_vec(),
        control: true,
        deadline_ms: Some(3_000),
    })
    .map(|_| ())
    .map_err(|e| format!("send: {e:?}"))
}

fn client_node() -> Node {
    let mut node = Node::new(
        NodeConfig {
            identity: NodeIdentity::generate(&TestEntropy),
            dcid: vec![2u8; 8],
        },
        Arc::new(TestClock),
        Arc::new(TestEntropy),
    );
    node.register_carrier(Box::new(BlockingTcpCarrier));
    node
}

/// Send the client's `CLIENT_AUTH` message (handshake.md §18) — the REAL
/// static key plus identity binding and transcript-bound signature, sealed
/// with the provisional-chain client-auth key and carried in an encrypted
/// Handshake packet. Returns the message body (the length-prefixed ciphertext).
fn send_client_auth(
    node: &Node,
    link: &(dyn Link + Send + Sync),
    out: &ClientHandshakeOutput,
) -> Result<Vec<u8>, String> {
    let binding = IdentityBinding::sign(
        &node.config.identity.identity,
        &node.config.identity.static_handshake.public(),
        0,
        u64::MAX,
        0,
        [0u8; 32],
    );
    let client_eid = endpoint_id(&node.config.identity.identity.public());
    let sig_input = client_signature_input(
        &out.transcript_hash,
        &client_eid,
        &out.server_endpoint_id,
        &node.config.identity.static_handshake.public().0,
        &out.server_static_public_key,
    );
    let signature = node.config.identity.identity.sign(&sig_input);
    let plaintext = build_client_auth_plaintext(
        &node.config.identity.static_handshake.public().0,
        &binding,
        &signature,
    );
    let ciphertext = encrypt_client_auth(&out.client_auth_key, &out.transcript_hash, &plaintext);
    let mut auth_body = Vec::new();
    umc_wire::bytes::encode(&mut auth_body, &ciphertext, 16_384)
        .map_err(|e| format!("auth body: {e:?}"))?;
    let mut frame = Vec::new();
    umc_handshake::encoding::encode_message(
        &mut frame,
        umc_handshake::encoding::CLIENT_AUTH,
        &auth_body,
    )
    .map_err(|e| format!("auth frame: {e:?}"))?;
    let handshake_secret = umc_handshake::traffic::derive_handshake_traffic_secret(
        &out.handshake_secret3,
        &out.transcript_hash,
        true,
    );
    let handshake_keys = umc_handshake::traffic::traffic_keys(&handshake_secret);
    let packet = umc_handshake::handshake_packet::build_handshake_packet(
        &[1u8; 8],
        &[2u8; 8],
        0,
        &frame,
        &handshake_keys,
    )
    .map_err(|e| format!("client auth packet: {e:?}"))?;
    send_packet(link, &packet)?;
    Ok(auth_body)
}

/// Complete the finished exchange after `CLIENT_AUTH` (handshake.md §19-20):
/// read `SERVER_FINISHED`, verify the daemon's finished MAC and signature,
/// and send the `CLIENT_FINISHED` confirmation MAC.
fn finish_finished_exchange(
    node: &Node,
    link: &(dyn Link + Send + Sync),
    out: &ClientHandshakeOutput,
    hello_bytes: &[u8],
    server_hello_bytes: &[u8],
    auth_body: &[u8],
) -> Result<(), String> {
    std::thread::sleep(Duration::from_millis(100));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let finished_packet = loop {
        match link.recv() {
            Ok(packet) => break packet.bytes,
            Err(e)
                if e.kind == umc_carrier::error::CarrierErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(format!("recv server finished: {e:?}")),
        }
    };
    let server_handshake_secret = umc_handshake::traffic::derive_handshake_traffic_secret(
        &out.handshake_secret3,
        &out.transcript_hash,
        false,
    );
    let server_handshake_keys = umc_handshake::traffic::traffic_keys(&server_handshake_secret);
    let (_dcid, _scid, _pn, finished_body) =
        umc_handshake::handshake_packet::parse_handshake_packet(
            &finished_packet,
            &server_handshake_keys,
            0,
        )
        .map_err(|e| format!("server finished packet: {e:?}"))?;
    let (finished_message, _) = umc_handshake::encoding::decode_message(&finished_body)
        .map_err(|e| format!("server finished framing: {e:?}"))?;
    if finished_message.message_type != SERVER_FINISHED {
        return Err(format!(
            "expected SERVER_FINISHED, got message type {}",
            finished_message.message_type
        ));
    }
    let mut transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, b"ump.tcp/1");
    transcript
        .update_message(umc_handshake::encoding::CLIENT_HELLO, hello_bytes)
        .map_err(|e| format!("transcript: {e:?}"))?;
    transcript
        .update_message(umc_handshake::encoding::SERVER_HELLO, server_hello_bytes)
        .map_err(|e| format!("transcript: {e:?}"))?;
    let client_eid = endpoint_id(&node.config.identity.identity.public());
    let confirmation = verify_server_finished_and_build_confirmation(
        &mut transcript,
        &out.handshake_secret4,
        &out.server_identity_public_key,
        &out.server_endpoint_id,
        &client_eid,
        &out.server_static_public_key,
        &node.config.identity.static_handshake.public().0,
        auth_body,
        &finished_message.body,
    )
    .map_err(|e| format!("server finished refused: {e}"))?;
    let mut finished_frame = Vec::new();
    umc_handshake::encoding::encode_message(&mut finished_frame, CLIENT_FINISHED, &confirmation)
        .map_err(|e| format!("client finished frame: {e:?}"))?;
    let client_handshake_secret = umc_handshake::traffic::derive_handshake_traffic_secret(
        &out.handshake_secret3,
        &out.transcript_hash,
        true,
    );
    let client_handshake_keys = umc_handshake::traffic::traffic_keys(&client_handshake_secret);
    let finished_packet = umc_handshake::handshake_packet::build_handshake_packet(
        &[1u8; 8],
        &[2u8; 8],
        1,
        &finished_frame,
        &client_handshake_keys,
    )
    .map_err(|e| format!("client finished packet: {e:?}"))?;
    send_packet(link, &finished_packet)
}

/// Full XX handshake against daemon B (the synchronous analogue of
/// `Node::connect`), returning the live link, the client session, and the
/// session's resumption secret (handshake.md §26).
fn tcp_handshake(node: &Node, remote: &str) -> Result<(BoxLink, Session, [u8; 32]), String> {
    let carrier = node.carrier("ump.tcp/1").ok_or("tcp carrier missing")?;
    let link = carrier
        .dial(remote.to_string())
        .map_err(|e| format!("dial: {e:?}"))?;
    let client_ephemeral = StaticHandshakeKeyPair::generate();
    let hello = ClientHello::new(node.entropy.as_ref(), &client_ephemeral);
    let hello_bytes = hello.encode().map_err(|e| format!("hello: {e:?}"))?;
    let initial_keys = umc_handshake::initial::derive_initial_keys(&node.config.dcid);
    let initial = umc_handshake::initial::build_initial_packet(
        &node.config.dcid,
        &[3u8; 8],
        0,
        &hello_bytes,
        &initial_keys.client,
    )
    .map_err(|e| format!("initial packet: {e}"))?;
    send_packet(link.as_ref(), &initial)?;
    std::thread::sleep(Duration::from_millis(100));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let server_hello_bytes = loop {
        match link.recv() {
            Ok(packet) => break packet.bytes,
            Err(e)
                if e.kind == CarrierErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(format!("recv: {e:?}")),
        }
    };
    let server_hello_payload =
        umc_handshake::initial::parse_initial_with_keys(&server_hello_bytes, &initial_keys.server)
            .ok_or("server Initial rejected")?
            .2;
    let server_hello =
        ServerHello::decode(&server_hello_payload).map_err(|e| format!("server hello: {e:?}"))?;
    let server_hello_bytes = server_hello
        .encode()
        .map_err(|e| format!("server hello encode: {e:?}"))?;
    let out = complete_client_side(
        &node.config.identity.identity,
        // The daemon stands the client's ephemeral in for the static until
        // CLIENT_AUTH is parsed (handshake.md §18); mirror that here so the
        // derived session secrets AND the client-auth key match on both
        // sides.
        &client_ephemeral,
        &client_ephemeral,
        &hello,
        &server_hello,
        node.entropy.as_ref(),
        "ump.tcp/1".as_bytes(),
    )
    .map_err(|e| format!("client side: {e}"))?;
    let auth_body = send_client_auth(node, link.as_ref(), &out)?;
    finish_finished_exchange(
        node,
        link.as_ref(),
        &out,
        &hello_bytes,
        &server_hello_bytes,
        &auth_body,
    )?;
    let secrets = out.session_secrets;
    let session = Session::new(
        SessionConfig {
            role: Role::Client,
            dcid: node.config.dcid.clone(),
            local_traffic_secret: secrets.client,
            remote_traffic_secret: secrets.server,
            initial_max_data: umc_session::session::DEFAULT_INITIAL_MAX_DATA,
            initial_max_stream_data: umc_session::session::DEFAULT_INITIAL_MAX_STREAM_DATA,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .map_err(|e| format!("session: {e:?}"))?;
    Ok((link, session, secrets.resumption))
}

/// Daemon B's session-ticket key and endpoint id: read from B's keystore
/// (the identity seed hash derivation mirrors `RuntimeState::new`). The
/// ticket the test builds is exactly what B's clean-close path issues —
/// same key, same format — so B accepts the resume.
fn daemon_ticket_material(daemon_dir: &Path) -> ([u8; 32], [u8; 32]) {
    let ks_path = daemon_dir.join("data").join("keystore").join("keystore.ks");
    let ks = umc_storage::keystore::Keystore::open(ks_path, b"")
        .expect("open daemon keystore (dev default password)");
    let seeds = ks
        .load(
            umc_storage::keystore::KeyClass::IdentitySigning,
            b"node-identity",
        )
        .expect("node identity record");
    assert_eq!(seeds.len(), 64, "identity seed + static seed");
    let identity_seed: [u8; 32] = seeds[..32].try_into().expect("identity seed");
    let ticket_key = umc_crypto::hkdf::extract(&[0u8; 32], &identity_seed);
    let server_eid = endpoint_id(&IdentityKeyPair::from_seed(identity_seed).public());
    (ticket_key, server_eid)
}

/// Build the resume ticket for the given session's resumption secret,
/// sealed with daemon B's ticket key (handshake.md §35, v1 wire format).
/// The nonce is unique per issue (a monotonic counter — the daemon's
/// single-use replay guard keys on it), so two tickets for the same
/// session never collide.
fn build_ticket(
    ticket_key: &[u8; 32],
    server_eid: &[u8; 32],
    client_eid: &[u8; 32],
    resumption_secret: &[u8; 32],
) -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock")
            .as_millis(),
    )
    .unwrap_or(0);
    let mut nonce = [0u8; umc_handshake::ticket::TICKET_ENTROPY];
    nonce[..8].copy_from_slice(&NONCE_COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    umc_handshake::ticket::issue_ticket(
        ticket_key,
        &umc_handshake::ticket::TicketPayload {
            version: 1,
            ticket_id: [0x21u8; 16],
            client_endpoint_id_hash: *client_eid,
            server_endpoint_id_hash: *server_eid,
            resumption_secret: *resumption_secret,
            issued_at_ms: now,
            expires_at_ms: now + 3_600_000,
            protocol_version: 1,
            crypto_profile: CRYPTO_PROFILE.to_vec(),
            nonce,
        },
    )
}

/// The IK resume handshake over TCP (the synchronous analogue of
/// `Node::connect_resumed`), returning the live link and the resumed client
/// session. The daemon skips the auth exchange entirely.
fn resume_handshake(
    node: &Node,
    remote: &str,
    ticket: &[u8],
    resumption_secret: &[u8; 32],
) -> Result<(BoxLink, Session), String> {
    let carrier = node.carrier("ump.tcp/1").ok_or("tcp carrier missing")?;
    let link = carrier
        .dial(remote.to_string())
        .map_err(|e| format!("dial: {e:?}"))?;
    let client_ephemeral = StaticHandshakeKeyPair::generate();
    let mut hello = ClientHello::new(node.entropy.as_ref(), &client_ephemeral);
    hello.supported_handshake_modes = vec![umc_handshake::ik::MODE_IK.to_vec()];
    hello.retry_token = ticket.to_vec();
    let hello_bytes = hello.encode().map_err(|e| format!("hello: {e:?}"))?;
    let initial_keys = umc_handshake::initial::derive_initial_keys(&node.config.dcid);
    let initial = umc_handshake::initial::build_initial_packet(
        &node.config.dcid,
        &[3u8; 8],
        0,
        &hello_bytes,
        &initial_keys.client,
    )
    .map_err(|e| format!("initial packet: {e}"))?;
    send_packet(link.as_ref(), &initial)?;
    std::thread::sleep(Duration::from_millis(100));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let server_hello_bytes = loop {
        match link.recv() {
            Ok(packet) => break packet.bytes,
            Err(e)
                if e.kind == CarrierErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(format!("recv server hello: {e:?}")),
        }
    };
    let server_hello_payload =
        umc_handshake::initial::parse_initial_with_keys(&server_hello_bytes, &initial_keys.server)
            .ok_or("server Initial rejected")?
            .2;
    let server_hello =
        ServerHello::decode(&server_hello_payload).map_err(|e| format!("server hello: {e:?}"))?;
    let server_hello_bytes = server_hello
        .encode()
        .map_err(|e| format!("server hello encode: {e:?}"))?;
    if server_hello.selected_handshake_mode != umc_handshake::ik::MODE_IK {
        return Err(format!(
            "resume refused: server selected mode {:?}",
            server_hello.selected_handshake_mode
        ));
    }
    if !server_hello.encrypted_server_authentication.is_empty() {
        return Err("resumed server hello must skip the auth block".into());
    }
    // The resume transcript (handshake.md §35) — the exact context the
    // daemon derives with.
    let mut transcript = Transcript::new(umc_handshake::ik::MODE_IK, CRYPTO_PROFILE, b"ump.tcp/1");
    transcript
        .update_message(umc_handshake::encoding::CLIENT_HELLO, &hello_bytes)
        .map_err(|e| format!("transcript: {e:?}"))?;
    transcript
        .update_message(umc_handshake::encoding::SERVER_HELLO, &server_hello_bytes)
        .map_err(|e| format!("transcript: {e:?}"))?;
    let nonce = umc_handshake::ticket::ticket_nonce(ticket).ok_or("ticket has no clear nonce")?;
    let psk = umc_session::ticket::resumption_psk(resumption_secret, &nonce);
    let resume = umc_handshake::ik::derive_resumption_secrets(
        &psk,
        &client_ephemeral,
        &server_hello.server_ephemeral_public_key,
        &transcript.hash,
    );
    let session = Session::new(
        SessionConfig {
            role: Role::Client,
            dcid: node.config.dcid.clone(),
            local_traffic_secret: resume.client,
            remote_traffic_secret: resume.server,
            initial_max_data: umc_session::session::DEFAULT_INITIAL_MAX_DATA,
            initial_max_stream_data: umc_session::session::DEFAULT_INITIAL_MAX_STREAM_DATA,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .map_err(|e| format!("session: {e:?}"))?;
    Ok((link, session))
}

/// Build the payload of a STREAM frame that opens a stream with the given
/// protocol ID (phase1 shape: type byte + encoded frame body).
fn stream_frame_payload(stream_id: u64, protocol_id: &[u8], data: &[u8]) -> Vec<u8> {
    let frame = StreamFrame {
        stream_id,
        fin: true,
        offset_present: false,
        len_present: true,
        open: true,
        unidirectional: false,
        offset: 0,
        data: data.to_vec(),
        protocol_id: protocol_id.to_vec(),
        metadata: Vec::new(),
    };
    let mut payload = Vec::new();
    umc_wire::varint::encode_into(&mut payload, FrameType::STREAM.0).expect("frame type varint");
    payload.extend_from_slice(&frame.encode().expect("frame encode")[1..]);
    payload
}

/// Drive the client side of an echo round trip over a RESUMED session: send
/// a STREAM frame with the echo protocol ID, then read packets until the
/// daemon's echo arrives on the same stream ID (phase9 pattern).
fn run_echo_client(
    node: &Node,
    remote: &str,
    ticket: &[u8],
    resumption_secret: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let (link, mut session) = resume_handshake(node, remote, ticket, resumption_secret)?;
    let stream_id = session
        .open_stream()
        .map_err(|e| format!("open stream: {e:?}"))?;
    let stream_payload = stream_frame_payload(stream_id, WELL_KNOWN_APP, payload);
    let packet = session
        .build_outbound(&TestClock, Instant(0), &stream_payload)
        .map_err(|e| format!("build: {e:?}"))?
        .ok_or("no outbound packet")?;
    send_packet(link.as_ref(), &packet)?;
    std::thread::sleep(Duration::from_millis(50));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let inbound = link.recv().map_err(|e| format!("recv: {e:?}"))?;
        let _ = session.on_inbound(Instant(0), &inbound.bytes);
        if let Ok((data, _eof)) = session.read_stream(stream_id) {
            if !data.is_empty() {
                return Ok(data);
            }
        }
        let mut ping = Vec::new();
        umc_wire::varint::encode_into(&mut ping, FrameType::PING.0)
            .map_err(|e| format!("ping encode: {e:?}"))?;
        if let Ok(Some(ping_packet)) = session.build_outbound(&TestClock, Instant(0), &ping) {
            let _ = send_packet(link.as_ref(), &ping_packet);
        }
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            std::time::Instant::now() < deadline,
            "echo did not return within 10s"
        );
    }
}

/// End to end (handshake.md §35): a full XX session produces the resumption
/// secret; a ticket sealed with daemon B's own ticket key resumes the
/// session over IK mode — `Node::connect_resumed` accepts, and a second
/// resumed connection round-trips a stream through daemon B's echo
/// application without any auth exchange.
#[tokio::test(flavor = "multi_thread")]
async fn node_connect_resumed_end_to_end() {
    let tcp_port = free_tcp_port();
    let (daemon, socket) = spawn_daemon("resume", tcp_port, free_udp_port());
    wait_for_control_socket(&socket);

    let node = client_node();
    let remote = format!("127.0.0.1:{tcp_port}");

    // 1. Full XX handshake: keep the resumption secret. The harness drives
    //    the wire synchronously on a blocking thread (the carrier's read
    //    timeouts and the sleeps are blocking std IO).
    let node_clone = client_node();
    let handshake = {
        let node = node_clone;
        let remote = remote.clone();
        tokio::task::spawn_blocking(move || tcp_handshake(&node, &remote))
    };
    let (xx_link, xx_session, resumption_secret) =
        tokio::time::timeout(Duration::from_secs(20), handshake)
            .await
            .expect("handshake timed out")
            .expect("handshake thread panicked")
            .expect("node handshake failed");
    assert_ne!(resumption_secret, [0u8; 32]);
    // Close the XX link NOW (the bindings would otherwise live until the
    // test body ends): the daemon's session for the dead link must fully
    // exit before the echo round trip — the echo application's outbound
    // channel is shared across sessions, and a lingering session's writer
    // could drain the echo meant for another session.
    drop(xx_link);
    drop(xx_session);

    // 2. Ticket sealed with daemon B's own ticket key.
    let (ticket_key, server_eid) = daemon_ticket_material(&daemon.dir);
    let client_eid = endpoint_id(&node.config.identity.identity.public());
    let ticket = build_ticket(&ticket_key, &server_eid, &client_eid, &resumption_secret);

    // 3. `Node::connect_resumed`: the daemon accepts the resume over the
    //    short path (no CLIENT_AUTH) and the session id registers.
    let resumed = {
        let mut node = node;
        let remote = remote.clone();
        let ticket = ticket.clone();
        tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                node.connect_resumed("ump.tcp/1", remote, &ticket, &resumption_secret)
                    .await
            })
        })
    };
    let session_id = tokio::time::timeout(Duration::from_secs(20), resumed)
        .await
        .expect("resume timed out")
        .expect("resume thread panicked")
        .expect("resume failed");
    assert_eq!(session_id, 0, "the resumed session registers");

    // Let the daemon's sessions for the dead XX and resumed links (their
    // links were dropped when the harness functions returned) fully exit:
    // the echo application's outbound channel is shared across sessions, and
    // a dying session's writer could otherwise drain the echo meant for the
    // round-trip session below.
    std::thread::sleep(Duration::from_millis(300));

    // 4. A second resumed connection round-trips a stream through the
    //    daemon's echo application. Tickets are single-use (the daemon's
    //    replay guard keys on the clear nonce), so the second resume needs
    //    a FRESH ticket with fresh entropy — a replayed ticket would fall
    //    back to the full XX handshake.
    let expected = b"phase12 resumed echo".to_vec();
    let payload = expected.clone();
    let ticket2 = build_ticket(&ticket_key, &server_eid, &client_eid, &resumption_secret);
    let node = client_node();
    let echo = tokio::task::spawn_blocking(move || {
        run_echo_client(&node, &remote, &ticket2, &resumption_secret, &payload)
    });
    let echoed = tokio::time::timeout(Duration::from_secs(20), echo)
        .await
        .expect("resumed echo round trip timed out")
        .expect("echo thread panicked")
        .expect("resumed echo round trip failed");
    assert_eq!(echoed, expected, "echo must return the exact bytes");

    drop(daemon);
}
