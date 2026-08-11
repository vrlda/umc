//! Phase 8 success criteria: a live XX handshake against the daemon over
//! TCP and UDP. The daemon's session layer answers `CLIENT_HELLO` with a
//! `SERVER_HELLO`, derives session secrets, and registers an active session.
//!
//! The client drives the same path as `Node::connect` (node.rs) but
//! synchronously: the carriers run blocking `Handle::block_on` calls that
//! panic from an async context on the same runtime, so the handshake runs
//! on a `spawn_blocking` thread exactly like the daemon's accept loops.
use prost::Message;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use umc_carrier::types::OutboundPacket;
use umc_carrier::BoxLink;
use umc_control::proto::umc::api::v1 as api;
use umc_core::node::{Node, NodeConfig, NodeIdentity};
use umc_crypto::signatures::StaticHandshakeKeyPair;
use umc_handshake::encoding::{CLIENT_FINISHED, SERVER_FINISHED};
use umc_handshake::identity::{endpoint_id, IdentityBinding};
use umc_handshake::transcript::Transcript;
use umc_handshake::xx::{
    build_client_auth_plaintext, client_signature_input, complete_client_side, encrypt_client_auth,
    verify_server_finished_and_build_confirmation, ClientHandshakeOutput, ClientHello, ServerHello,
    CRYPTO_PROFILE, MODE_XX,
};
use umc_types::runtime::{Clock, EntropySource, Instant};

/// Wire shape of the daemon's `PeerService.ListCandidates` payload. No proto
/// message exists yet; the field layout mirrors the daemon's wire struct.
#[derive(Clone, PartialEq, prost::Message)]
struct ListCandidatesResponse {
    #[prost(message, repeated, tag = "1")]
    candidates: Vec<CandidateSummary>,
    #[prost(uint32, tag = "2")]
    total: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct CandidateSummary {
    #[prost(uint64, tag = "1")]
    candidate_id: u64,
    #[prost(string, tag = "2")]
    carrier_type: String,
    #[prost(uint64, tag = "3")]
    expires_at_ms: u64,
    #[prost(bool, tag = "4")]
    public: bool,
}

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
    _dir: PathBuf,
}

impl Daemon {
    /// Send SIGINT and wait for the daemon to exit cleanly.
    fn shutdown_with_sigint(&mut self) {
        let pid = self.child.id();
        let status = Command::new("kill")
            .args(["-INT", &pid.to_string()])
            .status()
            .expect("run kill -INT");
        assert!(status.success(), "kill -INT {pid} failed");
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(exit) = self.child.try_wait().expect("try_wait") {
                assert!(exit.success(), "daemon exited with {exit}");
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "daemon did not exit after SIGINT"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(tcp_port: u16, udp_port: u16) -> (Daemon, PathBuf) {
    spawn_daemon_with_token(tcp_port, udp_port, None)
}

fn spawn_daemon_with_token(
    tcp_port: u16,
    udp_port: u16,
    development_token: Option<&str>,
) -> (Daemon, PathBuf) {
    let dir = std::env::temp_dir().join(format!("phase8-daemon-{}-{tcp_port}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("daemon dir");
    let mut config = serde_json::json!({
        "data_dir": dir.join("data"),
        "control_socket": dir.join("umc.sock"),
        "carriers": ["ump.tcp/1", "ump.udp/1"],
        "tcp_listen": format!("127.0.0.1:{tcp_port}"),
        "udp_listen": format!("127.0.0.1:{udp_port}"),
    });
    if let Some(token) = development_token {
        config["development_token"] = serde_json::Value::String(token.to_string());
    }
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
            _dir: dir.clone(),
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

fn send_packet(link: &(dyn umc_carrier::Link + Send + Sync), bytes: &[u8]) -> Result<(), String> {
    link.send(OutboundPacket {
        bytes: bytes.to_vec(),
        control: true,
        deadline_ms: Some(3_000),
    })
    .map(|_| ())
    .map_err(|e| format!("send: {e:?}"))
}

/// Send the client's `CLIENT_AUTH` message (handshake.md §18) — the REAL
/// static key plus identity binding and transcript-bound signature, sealed
/// with the provisional-chain client-auth key (the daemon's DH chain
/// stands the ephemeral in for the static, so the auth key matches on both
/// sides) and carried in an encrypted Handshake packet.
fn send_client_auth(
    node: &Node,
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

/// Complete the finished exchange after `CLIENT_AUTH` (handshake.md
/// §19-20): read `SERVER_FINISHED`, verify the daemon's finished MAC and
/// signature, and send the `CLIENT_FINISHED` confirmation MAC. The daemon
/// activates the session only after the confirmation verifies.
fn finish_finished_exchange(
    node: &Node,
    link: &(dyn umc_carrier::Link + Send + Sync),
    out: &ClientHandshakeOutput,
    hello_bytes: &[u8],
    server_hello_bytes: &[u8],
    auth_body: &[u8],
    carrier_binding: &[u8],
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
    let mut transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, carrier_binding);
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

/// Synchronous analogue of `Node::connect` over TCP: dial, send
/// `CLIENT_HELLO`, receive `SERVER_HELLO`, send `CLIENT_AUTH`, derive the
/// client session secrets.
///
/// The TCP carrier serializes reads and writes behind one mutex and a
/// background writer task, so a blocking `recv` must not start until the
/// hello write has been flushed; the brief pause lets the writer deliver
/// the frame before `recv` takes the lock.
fn tcp_handshake(node: &Node, remote: &str) -> Result<u64, String> {
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
    // TCP delivery is asynchronous: under workspace-wide parallel load the
    // daemon may not have flushed SERVER_HELLO by the time the first read is
    // attempted. Poll the non-blocking carrier within a bounded deadline,
    // matching the UDP and finished-message paths below.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let server_hello_bytes = loop {
        match link.recv() {
            Ok(packet) => break packet.bytes,
            Err(error)
                if error.kind == umc_carrier::error::CarrierErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("recv server hello: {error:?}")),
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
    finish_finished_exchange(
        node,
        link.as_ref(),
        &out,
        &hello_bytes,
        &server_hello_bytes,
        &auth_body,
        "ump.tcp/1".as_bytes(),
    )?;
    assert_ne!(
        out.session_secrets.client, [0u8; 32],
        "derived client traffic secret must be non-trivial"
    );
    Ok(1)
}

/// Synchronous analogue of `Node::connect` over UDP. The daemon's UDP
/// accept peeks at the first datagram to establish the association, leaving
/// that same hello available to the session handler.
///
/// The link is built with `UdpLink::from_parts` so the test can share the
/// Tokio-owned socket with its async harness.
fn udp_handshake(node: &Node, link: &BoxLink) -> Result<u64, String> {
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
    std::thread::sleep(Duration::from_millis(10));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let server_hello_bytes = loop {
        match link.recv() {
            Ok(packet) => break packet.bytes,
            Err(error)
                if error.kind == umc_carrier::error::CarrierErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("recv: {error:?}")),
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
        // Provisional static (the ephemeral), mirroring the daemon's DH
        // chain; the real static rides CLIENT_AUTH.
        &client_ephemeral,
        &client_ephemeral,
        &hello,
        &server_hello,
        node.entropy.as_ref(),
        "ump.udp/1".as_bytes(),
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
        "ump.udp/1".as_bytes(),
    )?;
    assert_ne!(
        out.session_secrets.client, [0u8; 32],
        "derived client traffic secret must be non-trivial"
    );
    Ok(1)
}

fn client_node(carrier_type: &str) -> Node {
    let mut node = Node::new(
        NodeConfig {
            identity: NodeIdentity::generate(&TestEntropy),
            dcid: vec![2u8; 8],
        },
        Arc::new(TestClock),
        Arc::new(TestEntropy),
    );
    if carrier_type == "ump.udp/1" {
        node.register_carrier(Box::new(umc_carrier_udp::UdpCarrier));
    } else {
        node.register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));
    }
    node
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

#[tokio::test(flavor = "multi_thread")]
async fn live_handshake_over_tcp() {
    let tcp_port = free_tcp_port();
    let (daemon, socket) = spawn_daemon(tcp_port, free_udp_port());
    wait_for_control_socket(&socket);
    let node = client_node("ump.tcp/1");
    let remote = format!("127.0.0.1:{tcp_port}");
    let client = tokio::task::spawn_blocking(move || tcp_handshake(&node, &remote));
    let result = tokio::time::timeout(Duration::from_secs(20), client)
        .await
        .expect("live TCP handshake timed out")
        .expect("client thread panicked")
        .expect("handshake failed");
    assert_eq!(result, 1);
    drop(daemon);
}

#[tokio::test(flavor = "multi_thread")]
async fn live_handshake_over_udp() {
    let udp_port = free_udp_port();
    let (daemon, socket) = spawn_daemon(free_tcp_port(), udp_port);
    wait_for_control_socket(&socket);
    let node = client_node("ump.udp/1");
    let socket = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind client udp socket"),
    );
    let link: BoxLink = Box::new(umc_carrier_udp::UdpLink::from_parts(
        socket,
        format!("127.0.0.1:{udp_port}"),
    ));
    let client = tokio::task::spawn_blocking(move || udp_handshake(&node, &link));
    let result = tokio::time::timeout(Duration::from_secs(20), client)
        .await
        .expect("live UDP handshake timed out")
        .expect("client thread panicked")
        .expect("handshake failed");
    assert_eq!(result, 1);
    drop(daemon);
}

async fn control_client(socket: &Path) -> umc_sdk::client::Client {
    umc_sdk::client::Client::connect(socket.to_str().expect("socket path"), "phase8-test")
        .await
        .expect("control client connect")
}

#[tokio::test(flavor = "multi_thread")]
async fn control_api_reports_real_state() {
    let tcp_port = free_tcp_port();
    let (daemon, socket) = spawn_daemon(tcp_port, free_udp_port());
    wait_for_control_socket(&socket);
    let mut client = control_client(&socket).await;

    let status = api::GetStatusResponse::decode(
        client
            .request("NodeAdmin", "GetStatus", vec![])
            .await
            .expect("GetStatus")
            .payload
            .as_slice(),
    )
    .expect("status payload")
    .status
    .expect("status");
    assert_eq!(status.active_sessions, 0);
    assert_eq!(status.active_relay_circuits, 0);

    let candidates = ListCandidatesResponse::decode(
        client
            .request("DiscoveryService", "ListCandidates", vec![])
            .await
            .expect("ListCandidates")
            .payload
            .as_slice(),
    )
    .expect("candidates payload");
    assert_eq!(candidates.total, 0);
    assert!(candidates.candidates.is_empty());

    let events = client
        .request("NodeAdmin", "GetEvents", vec![])
        .await
        .expect("GetEvents");
    assert_eq!(
        events.status.as_ref().expect("status").code,
        api::StatusCode::Ok as i32
    );
    drop(daemon);
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_requests_rejected_when_token_configured() {
    let tcp_port = free_tcp_port();
    let (daemon, socket) = spawn_daemon_with_token(tcp_port, free_udp_port(), Some("dev-token"));
    wait_for_control_socket(&socket);
    let mut client = control_client(&socket).await;

    let result = client.request("NodeAdmin", "GetStatus", vec![]).await;
    match result {
        Err(umc_sdk::client::ClientError::Unauthenticated) => {}
        other => panic!("expected Unauthenticated, got {other:?}"),
    }
    drop(daemon);
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_serves_control_and_sessions_together() {
    let tcp_port = free_tcp_port();
    let (mut daemon, socket) = spawn_daemon(tcp_port, free_udp_port());
    wait_for_control_socket(&socket);
    let mut client = control_client(&socket).await;

    let status = api::GetStatusResponse::decode(
        client
            .request("NodeAdmin", "GetStatus", vec![])
            .await
            .expect("GetStatus")
            .payload
            .as_slice(),
    )
    .expect("status payload")
    .status
    .expect("status");
    assert_eq!(status.active_sessions, 0);

    let node = client_node("ump.tcp/1");
    let remote = format!("127.0.0.1:{tcp_port}");
    let handshake = tokio::task::spawn_blocking(move || tcp_handshake(&node, &remote));
    let result = tokio::time::timeout(Duration::from_secs(20), handshake)
        .await
        .expect("live TCP handshake timed out")
        .expect("client thread panicked")
        .expect("handshake failed");
    assert_eq!(result, 1);

    let mut saw_active = false;
    for _ in 0..50 {
        let status = api::GetStatusResponse::decode(
            client
                .request("NodeAdmin", "GetStatus", vec![])
                .await
                .expect("GetStatus")
                .payload
                .as_slice(),
        )
        .expect("status payload")
        .status
        .expect("status");
        let active = status.active_sessions;
        if active == 1 {
            saw_active = true;
            break;
        }
        // A handshake-only client closes its carrier as soon as the
        // exchange completes. The session watcher now removes the registry
        // entry once both wire tasks terminate, so the active window may be
        // shorter than one control round-trip. The session_active event is
        // the durable evidence that registration occurred.
        let events = api::GetEventsResponse::decode(
            client
                .request("NodeAdmin", "GetEvents", vec![])
                .await
                .expect("GetEvents")
                .payload
                .as_slice(),
        )
        .expect("events payload")
        .events;
        if events.iter().any(|event| event.kind == "session_active") {
            saw_active = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        saw_active,
        "session must either remain active in GetStatus or emit session_active"
    );

    let mut saw_active_event = false;
    for _ in 0..50 {
        let events = api::GetEventsResponse::decode(
            client
                .request("NodeAdmin", "GetEvents", vec![])
                .await
                .expect("GetEvents")
                .payload
                .as_slice(),
        )
        .expect("events payload")
        .events;
        if events.iter().any(|e| e.kind == "session_active") {
            saw_active_event = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        saw_active_event,
        "event log must contain a session_active entry"
    );

    daemon.shutdown_with_sigint();
}
