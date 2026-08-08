//! Phase 12 deferral closure: cross-session `RELAY_DATA` forwarding over
//! the daemon's session bus.
//!
//! The control API cannot express a forwarding destination (`OpenCircuit`
//! has no destination field — the wire message in server.rs carries only
//! quota/lifetime/flags), so the daemon-level check drives the wire path:
//! each client opens a circuit by sending `RELAY_OPEN` with `next_hop_hint`
//! = the other client's peer endpoint id over its live session, and the
//! daemon forwards `RELAY_DATA` accepted on A's circuit into session B via
//! the session bus.
//!
//! The peer endpoint id the daemon registers for a session is the client's
//! REAL endpoint id, verified from the identity binding carried in
//! `CLIENT_AUTH` (handshake.md §18), so the test uses each node's own
//! `endpoint_id()` for the hints.
//!
//! The TCP carrier serializes reads and writes behind one mutex
//! (carriers/tcp.md): a recv in flight starves the link's background
//! writer. The test therefore runs sends with no recv in flight, and B
//! pings periodically so the daemon's recv pump hands the stream mutex to
//! B's writer long enough to flush the forwarded frame.
use prost::Message;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use umc_carrier::types::OutboundPacket;
use umc_carrier::BoxLink;
use umc_core::node::{Node, NodeConfig, NodeIdentity};
use umc_crypto::aead::PacketKeys;
use umc_crypto::signatures::StaticHandshakeKeyPair;
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
use umc_wire::frames::relay::{RelayDataFrame, RelayOpenFrame, RelayStatusFrame};

struct TestClock;

impl Clock for TestClock {
    fn now(&self) -> Instant {
        Instant(0)
    }
}

static TEST_CLOCK: TestClock = TestClock;

struct TestEntropy;

impl EntropySource for TestEntropy {
    fn fill(&self, out: &mut [u8]) {
        out.fill(0x5A);
    }
}

/// Send the client's `CLIENT_AUTH` message (handshake.md §18) — the REAL
/// static key plus identity binding and transcript-bound signature, sealed
/// with the provisional-chain client-auth key (the daemon's DH chain
/// stands the ephemeral in for the static, so the auth key matches on both
/// sides) and framed as a raw handshake message. Returns the message body
/// (the length-prefixed ciphertext): the bytes appended to the transcript
/// by both sides.
fn send_client_auth(
    node: &umc_core::node::Node,
    link: &(dyn umc_carrier::Link + Send + Sync),
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
    link.send(OutboundPacket {
        bytes: frame,
        control: true,
        deadline_ms: Some(3_000),
    })
    .map_err(|e| format!("send client auth: {e:?}"))?;
    Ok(auth_body)
}

/// Client-side TCP handshake over `Node`'s carrier, returning the live
/// link, the client session, the client's REAL peer endpoint id (which the
/// daemon registers from the `CLIENT_AUTH` binding), the client's
/// remote packet keys for parsing the daemon's protected replies, and the
/// matching remote header-protection key.
#[allow(clippy::type_complexity, clippy::too_many_lines)]
fn tcp_handshake(
    node: &umc_core::node::Node,
    remote: &str,
) -> Result<(BoxLink, Session, [u8; 32], PacketKeys, [u8; 32]), String> {
    let carrier = node.carrier("ump.tcp/1").ok_or("tcp carrier missing")?;
    let link = carrier
        .dial(remote.to_string())
        .map_err(|e| format!("dial: {e:?}"))?;
    let client_ephemeral = StaticHandshakeKeyPair::generate();
    let hello = ClientHello::new(node.entropy.as_ref(), &client_ephemeral);
    let hello_bytes = hello.encode().map_err(|e| format!("hello: {e:?}"))?;
    link.send(OutboundPacket {
        bytes: hello_bytes.clone(),
        control: true,
        deadline_ms: Some(3_000),
    })
    .map_err(|e| format!("send: {e:?}"))?;
    std::thread::sleep(Duration::from_millis(100));
    let server_hello_bytes = link.recv().map_err(|e| format!("recv: {e:?}"))?.bytes;
    let server_hello =
        ServerHello::decode(&server_hello_bytes).map_err(|e| format!("server hello: {e:?}"))?;
    let out = complete_client_side(
        &node.config.identity.identity,
        // The daemon stands the client's ephemeral in for the static in the
        // DH chain (the real static rides CLIENT_AUTH); mirror that here so
        // the derived session secrets AND the client-auth key match on both
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
    // SERVER_FINISHED (handshake.md §19): a raw framed handshake message.
    // The TCP carrier's recv yields WouldBlock while the daemon's reply is
    // buffered, so poll briefly.
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
    let (finished_message, _) = umc_handshake::encoding::decode_message(&finished_packet)
        .map_err(|e| format!("server finished framing: {e:?}"))?;
    if finished_message.message_type != SERVER_FINISHED {
        return Err(format!(
            "expected SERVER_FINISHED, got message type {}",
            finished_message.message_type
        ));
    }
    // Verify the server's finished MAC + signature and build the
    // CLIENT_FINISHED confirmation (handshake.md §19-20, the driver's
    // snapshot order: MAC/signature over the hash BEFORE SERVER_FINISHED,
    // confirmation over the hash AFTER SERVER_FINISHED).
    let mut transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, b"ump.tcp/1");
    transcript
        .update_message(umc_handshake::encoding::CLIENT_HELLO, &hello_bytes)
        .map_err(|e| format!("transcript: {e:?}"))?;
    transcript
        .update_message(umc_handshake::encoding::SERVER_HELLO, &server_hello_bytes)
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
        &auth_body,
        &finished_message.body,
    )
    .map_err(|e| format!("server finished refused: {e}"))?;
    let mut finished_frame = Vec::new();
    umc_handshake::encoding::encode_message(&mut finished_frame, CLIENT_FINISHED, &confirmation)
        .map_err(|e| format!("client finished frame: {e:?}"))?;
    link.send(OutboundPacket {
        bytes: finished_frame,
        control: true,
        deadline_ms: Some(3_000),
    })
    .map_err(|e| format!("send client finished: {e:?}"))?;
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
        &TEST_CLOCK,
    )
    .map_err(|e| format!("session: {e:?}"))?;
    let remote_keys = PacketKeys::from_traffic_secret(&secrets.server)
        .map_err(|e| format!("remote keys: {e:?}"))?;
    let remote_hp_key = umc_crypto::header_protection::header_protection_key(&secrets.server);
    Ok((
        link,
        session,
        node.config.identity.endpoint_id(),
        remote_keys,
        remote_hp_key,
    ))
}

/// Send one encoded frame as a protected packet over a client session.
/// Must run with no recv in flight: the carrier's single stream mutex
/// would otherwise starve the link's background writer.
#[allow(clippy::needless_pass_by_value)]
fn send_frame(session: &mut Session, link: &BoxLink, frame_bytes: Vec<u8>) -> Result<(), String> {
    let packet = session
        .build_outbound(&TEST_CLOCK, Instant(0), &frame_bytes)
        .map_err(|e| format!("build: {e:?}"))?
        .ok_or("no packet")?;
    link.send(OutboundPacket {
        bytes: packet,
        control: false,
        deadline_ms: None,
    })
    .map_err(|e| format!("send: {e:?}"))?;
    Ok(())
}

/// What a client receive window waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitFor {
    /// A `RELAY_STATUS` with the given code.
    Status(u64),
    /// A raw (bus-forwarded) `RELAY_DATA` frame.
    ForwardedRelayData,
}

impl WaitFor {
    fn satisfied(&self, statuses: &[u64], raw_frames: &[Vec<u8>]) -> bool {
        match self {
            Self::Status(code) => statuses.contains(code),
            Self::ForwardedRelayData => raw_frames.iter().any(|bytes| {
                let Ok((ty, used)) = umc_wire::varint::decode(bytes) else {
                    return false;
                };
                FrameType(ty) == FrameType::RELAY_DATA
                    && RelayDataFrame::decode(&bytes[used..]).is_ok()
            }),
        }
    }
}

/// Decode the `RELAY_STATUS` code from a protected packet. `RELAY_STATUS`
/// is a length-delimited type the generic frame parser refuses (the
/// daemon's session layer has the same limitation), so the payload is
/// walked varint-by-varint: `ACK` bodies are skipped via their own decode,
/// the status body is decoded directly.
fn status_from_protected(keys: &PacketKeys, hp_key: &[u8; 32], bytes: &[u8]) -> Option<u64> {
    let (_space, _dcid, _path, _pn, payload) =
        umc_session::packet::parse_protected_packet(keys, hp_key, 0, bytes).ok()?;
    let mut pos = 0usize;
    while pos < payload.len() {
        let (ty, used) = umc_wire::varint::decode(&payload[pos..]).ok()?;
        pos += used;
        if ty == FrameType::RELAY_STATUS.0 {
            // RELAY_STATUS is a length-delimited frame (type || length ||
            // body); the body decoder expects the raw body.
            let (status, used) = RelayStatusFrame::decode_length_delimited(&payload[pos..]).ok()?;
            let _ = used;
            return Some(status.status_code);
        }
        if ty == FrameType::ACK.0 {
            let (_, used) = umc_wire::frame::AckFrame::decode(&payload[pos..]).ok()?;
            pos += used;
        } else {
            return None;
        }
    }
    None
}

/// Client receive window: drain the link, feed the session state machine,
/// reply with ACK payloads, record relay statuses from protected packets
/// (body-first, the generic parser refuses them), and capture raw
/// (bus-forwarded) frames the session layer refuses. Runs until `wait_for`
/// is satisfied, then returns so the caller can release the link's stream
/// mutex before the next send phase.
#[allow(clippy::too_many_arguments)]
async fn recv_until(
    link: &Arc<BoxLink>,
    session: &Arc<Mutex<Session>>,
    keys: PacketKeys,
    hp_key: [u8; 32],
    statuses: &Arc<Mutex<Vec<u64>>>,
    raw_frames: &Arc<Mutex<Vec<Vec<u8>>>>,
    wait_for: WaitFor,
    what: &str,
) {
    let what = what.to_string();
    let link = link.clone();
    let session = session.clone();
    let statuses_arc = statuses.clone();
    let raw_arc = raw_frames.clone();
    let handle = tokio::task::spawn_blocking(move || loop {
        // WouldBlock (a timed-out partial read on the TCP carrier) is a
        // retry, not a link failure: exiting the window here raced the
        // daemon's reply and made the relay test flaky.
        let packet = match link.recv() {
            Ok(packet) => packet,
            Err(e) if e.kind == umc_carrier::error::CarrierErrorKind::WouldBlock => continue,
            Err(_) => return,
        };
        let bytes = packet.bytes;
        let mut session = session.lock().expect("client session");
        match session.on_inbound(Instant(0), &bytes) {
            Ok(ack) => {
                if !ack.is_empty() {
                    if let Ok(Some(reply)) = session.build_outbound(&TEST_CLOCK, Instant(0), &ack) {
                        let _ = link.send(OutboundPacket {
                            bytes: reply,
                            control: false,
                            deadline_ms: None,
                        });
                    }
                }
                if let Some(code) = status_from_protected(&keys, &hp_key, &bytes) {
                    statuses_arc.lock().expect("statuses").push(code);
                }
            }
            Err(_) => raw_arc.lock().expect("raw frames").push(bytes),
        }
        let snapshot_status = statuses_arc.lock().expect("statuses").clone();
        let snapshot_raw = raw_arc.lock().expect("raw frames").clone();
        if wait_for.satisfied(&snapshot_status, &snapshot_raw) {
            return;
        }
    });
    tokio::time::timeout(Duration::from_secs(15), handle)
        .await
        .unwrap_or_else(|_| {
            let statuses = statuses.lock().expect("statuses").clone();
            let raw = raw_frames.lock().expect("raw frames").clone();
            panic!("{what}: receive window timed out (statuses: {statuses:?}, raw: {raw:?})");
        })
        .expect("receive window panicked");
}

/// Locate (and if necessary build) the umcd binary. Fails loud when the
/// binary cannot be produced.
fn umcd_binary() -> std::path::PathBuf {
    let here = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin = here.join("../../target/debug/umcd");
    // Rebuild whenever the daemon sources are newer than the binary: a stale
    // daemon silently tests the wrong code.
    let src_newer = std::fs::read_dir(here.join("../../bins/umcd/src"))
        .map(|entries| {
            entries.filter_map(Result::ok).any(|e| {
                e.path()
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .zip(bin.metadata().and_then(|m| m.modified()).ok())
                    .is_some_and(|(src, bin)| src > bin)
            })
        })
        .unwrap_or(true);
    if !bin.exists() || src_newer {
        let status = std::process::Command::new(env!("CARGO"))
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
    child: std::process::Child,
    _dir: std::path::PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(name: &str, tcp_port: u16, udp_port: u16) -> (Daemon, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "phase12-bus-daemon-{name}-{}-{tcp_port}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("daemon dir");
    let config = serde_json::json!({
        "data_dir": dir.join("data"),
        "control_socket": dir.join("umc.sock"),
        "carriers": ["ump.tcp/1", "ump.udp/1"],
        "tcp_listen": format!("127.0.0.1:{tcp_port}"),
        "udp_listen": format!("127.0.0.1:{udp_port}"),
    });
    let config_path = dir.join("node.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("config json"),
    )
    .expect("write config");
    let log = std::fs::File::create(dir.join("umcd.log")).expect("log file");
    let child = std::process::Command::new(umcd_binary())
        .args(["--config", config_path.to_str().expect("config path")])
        .stdout(std::process::Stdio::from(
            log.try_clone().expect("clone log"),
        ))
        .stderr(std::process::Stdio::from(log))
        .spawn()
        .expect("spawn umcd");
    (
        Daemon {
            child,
            _dir: dir.clone(),
        },
        dir.join("umc.sock"),
    )
}

/// Wait until the daemon's control socket exists: the carrier accept loops
/// are spawned before the control socket binds, so a live socket implies
/// the listeners are accepting.
fn wait_for_control_socket(socket: &std::path::Path) {
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

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral tcp")
        .local_addr()
        .expect("tcp local addr")
        .port()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral udp")
        .local_addr()
        .expect("udp local addr")
        .port()
}

/// Wait until the daemon's event log contains an event with the given kind.
async fn wait_for_event(socket: &std::path::Path, kind: &str) {
    let mut client =
        umc_sdk::client::Client::connect(socket.to_str().expect("socket path"), "phase12-bus")
            .await
            .expect("control connect");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let response = client
            .request("NodeAdmin", "GetEvents", Vec::new())
            .await
            .expect("get events");
        assert_eq!(
            response.status.as_ref().unwrap().code,
            umc_control::proto::umc::api::v1::StatusCode::Ok as i32
        );
        let events = umc_control::proto::umc::api::v1::GetEventsResponse::decode(
            response.payload.as_slice(),
        )
        .expect("payload")
        .events;
        if events.iter().any(|e| e.kind == kind) {
            return;
        }
        assert!(
            std::time::Instant::now() <= deadline,
            "event {kind} never appeared; saw: {events:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Daemon-level smoke: two live clients, A's `RELAY_DATA` forwarded to
/// session B over the daemon's session bus, riding B's live link as a raw
/// `RELAY_DATA` frame on B's circuit.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn relay_data_forwarded_between_two_live_sessions() {
    let tcp_port = free_tcp_port();
    let (daemon, socket) = spawn_daemon("relay-forward", tcp_port, free_udp_port());
    wait_for_control_socket(&socket);
    let remote = format!("127.0.0.1:{tcp_port}");

    let mut node_a = Node::new(
        NodeConfig {
            identity: NodeIdentity::generate(&TestEntropy),
            dcid: vec![1u8; 8],
        },
        Arc::new(TestClock),
        Arc::new(TestEntropy),
    );
    node_a.register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));
    let mut node_b = Node::new(
        NodeConfig {
            identity: NodeIdentity::generate(&TestEntropy),
            dcid: vec![2u8; 8],
        },
        Arc::new(TestClock),
        Arc::new(TestEntropy),
    );
    node_b.register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));

    let handshake_a = tokio::task::spawn_blocking({
        let remote = remote.clone();
        move || tcp_handshake(&node_a, &remote)
    });
    let (link_a, session_a, peer_a_id, keys_a, hp_a) =
        tokio::time::timeout(Duration::from_secs(20), handshake_a)
            .await
            .expect("A handshake timed out")
            .expect("A handshake panicked")
            .expect("A handshake failed");
    let handshake_b = tokio::task::spawn_blocking({
        let remote = remote.clone();
        move || tcp_handshake(&node_b, &remote)
    });
    let (link_b, session_b, peer_b_eid, keys_b, hp_b) =
        tokio::time::timeout(Duration::from_secs(20), handshake_b)
            .await
            .expect("B handshake timed out")
            .expect("B handshake panicked")
            .expect("B handshake failed");

    // The daemon registers each session under its real peer endpoint id,
    // verified from the identity binding carried in CLIENT_AUTH.
    let peer_a = peer_a_id.to_vec();
    let peer_b = peer_b_eid.to_vec();

    let link_a = Arc::new(link_a);
    let link_b = Arc::new(link_b);
    let session_a = Arc::new(Mutex::new(session_a));
    let session_b = Arc::new(Mutex::new(session_b));
    let statuses_a = Arc::new(Mutex::new(Vec::new()));
    let statuses_b = Arc::new(Mutex::new(Vec::new()));
    let raw_frames_b = Arc::new(Mutex::new(Vec::new()));

    // A opens a circuit toward B (hint = B's peer id); the daemon allocates
    // circuit 1 (the first open on a fresh relay service). The send runs
    // with no recv in flight: the TCP carrier's single stream mutex would
    // otherwise starve the client's own writer.
    let open_a = RelayOpenFrame {
        circuit_id: 1000,
        bidirectional: true,
        store_forward_allowed: false,
        private_circuit: false,
        multipath_allowed: false,
        requested_lifetime: 600_000,
        requested_byte_quota: 1_048_576,
        next_hop_hint: peer_b.clone(),
        authorization: Vec::new(),
    };
    send_frame(
        &mut session_a.lock().expect("session a"),
        &link_a,
        open_a.encode().expect("encode"),
    )
    .expect("A open send");
    recv_until(
        &link_a,
        &session_a,
        keys_a.clone(),
        hp_a,
        &statuses_a,
        &raw_frames_b,
        WaitFor::Status(1),
        "A open status",
    )
    .await;

    // B opens a circuit toward A; the daemon allocates circuit 2.
    let open_b = RelayOpenFrame {
        circuit_id: 2000,
        next_hop_hint: peer_a.clone(),
        ..open_a.clone()
    };
    send_frame(
        &mut session_b.lock().expect("session b"),
        &link_b,
        open_b.encode().expect("encode"),
    )
    .expect("B open send");
    recv_until(
        &link_b,
        &session_b,
        keys_b.clone(),
        hp_b,
        &statuses_b,
        &raw_frames_b,
        WaitFor::Status(1),
        "B open status",
    )
    .await;

    // A sends data on its circuit: the daemon accepts it and forwards a
    // fresh `RELAY_DATA` into session B's bus channel, which B's session
    // task queues for B's link.
    let data = RelayDataFrame {
        circuit_id: 1,
        relay_sequence: 0,
        fin: false,
        ack_requested: false,
        high_priority: false,
        data: b"inner-packet".to_vec(),
    };
    send_frame(
        &mut session_a.lock().expect("session a"),
        &link_a,
        data.encode().expect("encode"),
    )
    .expect("A data send");

    // B's link is idle: the daemon's recv pump holds the stream mutex,
    // starving B's carrier writer (carriers/tcp.md). PINGs from B cycle
    // the pump; each recv window gives B's writer a flush window for the
    // queued forward.
    let ping = umc_wire::varint::encode(FrameType::PING.0).expect("ping encode");
    for round in 0..5 {
        tokio::time::sleep(Duration::from_millis(30)).await;
        send_frame(
            &mut session_b.lock().expect("session b"),
            &link_b,
            ping.clone(),
        )
        .expect("B ping send");
        recv_until(
            &link_b,
            &session_b,
            keys_b.clone(),
            hp_b,
            &statuses_b,
            &raw_frames_b,
            WaitFor::ForwardedRelayData,
            &format!("B forward round {round}"),
        )
        .await;
    }

    // B's client received the raw forwarded frame on B's circuit.
    let raw = raw_frames_b.lock().expect("raw frames").clone();
    let forwarded = raw
        .iter()
        .find_map(|bytes| {
            let (ty, used) = umc_wire::varint::decode(bytes).ok()?;
            if FrameType(ty) != FrameType::RELAY_DATA {
                return None;
            }
            RelayDataFrame::decode(&bytes[used..]).ok().map(|(f, _)| f)
        })
        .unwrap_or_else(|| panic!("forwarded relay data never arrived; raw: {raw:?}"));
    assert_eq!(forwarded.circuit_id, 2, "forwarded on B's circuit");
    assert_eq!(forwarded.relay_sequence, 0);
    assert!(!forwarded.fin);
    assert_eq!(forwarded.data, b"inner-packet");

    // The daemon's event log records the forward.
    wait_for_event(&socket, "relay_data_forwarded").await;

    drop(daemon);
}

/// D1+D2 end-to-end proof over a live TCP carrier: `Node::connect` speaks
/// Initial-protected `CLIENT_HELLO`/`SERVER_HELLO` (wire-format §13) and
/// then sends the real `CLIENT_AUTH` (handshake.md §18). The daemon
/// decrypts the Initial, answers with an Initial-protected `SERVER_HELLO`,
/// completes the two-step responder against `CLIENT_AUTH`, and registers
/// the session under the client's REAL endpoint id (verified from the
/// client's identity binding) — the `session_active` event records it.
#[tokio::test(flavor = "multi_thread")]
async fn node_connect_completes_protected_handshake() {
    let tcp_port = free_tcp_port();
    let (daemon, socket) = spawn_daemon("protected", tcp_port, free_udp_port());
    wait_for_control_socket(&socket);
    let remote = format!("127.0.0.1:{tcp_port}");

    let mut node = Node::new(
        NodeConfig {
            identity: NodeIdentity::generate(&TestEntropy),
            dcid: vec![3u8; 8],
        },
        Arc::new(TestClock),
        Arc::new(TestEntropy),
    );
    node.register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));
    let client_eid = node.config.identity.endpoint_id();
    let server_identity = NodeIdentity::generate(&TestEntropy);
    let handshake =
        tokio::task::spawn_blocking(move || drive_connect(&mut node, &remote, &server_identity));
    let session_id = tokio::time::timeout(Duration::from_secs(20), handshake)
        .await
        .expect("protected handshake timed out")
        .expect("client thread panicked")
        .expect("protected handshake failed");
    assert_eq!(session_id, 0);

    // The daemon accepted the protected Initial, verified CLIENT_AUTH, and
    // registered the session under the client's REAL peer endpoint id.
    wait_for_event(&socket, "session_active").await;
    let events = get_events(&socket).await;
    let active = events
        .iter()
        .find(|e| e.kind == "session_active")
        .expect("session_active event");
    assert!(
        active.detail.contains(&format!("{client_eid:02x?}")),
        "session_active must record the real peer endpoint id; detail: {}",
        active.detail
    );

    drop(daemon);
}

/// Fetch the daemon's current event log.
async fn get_events(
    socket: &std::path::Path,
) -> Vec<umc_control::proto::umc::api::v1::EventRecord> {
    let mut client =
        umc_sdk::client::Client::connect(socket.to_str().expect("socket path"), "phase12-bus")
            .await
            .expect("control connect");
    let response = client
        .request("NodeAdmin", "GetEvents", Vec::new())
        .await
        .expect("get events");
    assert_eq!(
        response.status.as_ref().unwrap().code,
        umc_control::proto::umc::api::v1::StatusCode::Ok as i32
    );
    umc_control::proto::umc::api::v1::GetEventsResponse::decode(response.payload.as_slice())
        .expect("payload")
        .events
}

/// Drive `Node::connect` to completion on a blocking thread without a
/// tokio runtime context: `Handle::block_on` would mark this thread an
/// async execution context, which panics the carriers' own nested
/// `Handle::block_on` calls ("Cannot block the current thread from within
/// a runtime"). `connect` awaits only a tokio mutex, so a plain poll loop
/// suffices; the `spawn_blocking` thread keeps the runtime context the
/// carriers require.
fn drive_connect(
    node: &mut Node,
    remote: &str,
    server_identity: &NodeIdentity,
) -> Result<u64, umc_core::node::NodeError> {
    let mut fut = Box::pin(node.connect("ump.tcp/1", remote.to_string(), server_identity));
    let waker = std::task::Waker::from(Arc::new(NoopWaker));
    let mut cx = std::task::Context::from_waker(&waker);
    loop {
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(out) => return out,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

/// A waker that does nothing: the poll loop drives progress with
/// `yield_now` instead of wake notifications.
struct NoopWaker;

impl std::task::Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}
