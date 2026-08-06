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
use umc_handshake::xx::{complete_client_side, ClientHello, ServerHello};
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
    let bin = here.join("../../target/debug/umcd");
    if !bin.exists() {
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

/// Synchronous analogue of `Node::connect` over TCP: dial, send
/// `CLIENT_HELLO`, receive `SERVER_HELLO`, derive the client session
/// secrets.
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
    send_packet(link.as_ref(), &hello_bytes)?;
    std::thread::sleep(Duration::from_millis(100));
    let server_hello_bytes = link.recv().map_err(|e| format!("recv: {e:?}"))?.bytes;
    let server_hello =
        ServerHello::decode(&server_hello_bytes).map_err(|e| format!("server hello: {e:?}"))?;
    let (secrets, _) = complete_client_side(
        &node.config.identity.identity,
        &node.config.identity.static_handshake,
        &client_ephemeral,
        &hello,
        &server_hello,
        node.entropy.as_ref(),
        "ump.tcp/1".as_bytes(),
    )
    .map_err(|e| format!("client side: {e}"))?;
    assert_ne!(
        secrets.client, [0u8; 32],
        "derived client traffic secret must be non-trivial"
    );
    Ok(1)
}

/// Synchronous analogue of `Node::connect` over UDP. The daemon's UDP
/// accept consumes the first datagram to establish the association, so a
/// copy of the hello follows it for the daemon's first `link.recv()`.
///
/// The link is built with `UdpLink::from_parts` instead of `dial`: dial
/// connects the socket, which makes `send_to` fail with EISCONN on macOS.
fn udp_handshake(node: &Node, link: &BoxLink) -> Result<u64, String> {
    let client_ephemeral = StaticHandshakeKeyPair::generate();
    let hello = ClientHello::new(node.entropy.as_ref(), &client_ephemeral);
    let hello_bytes = hello.encode().map_err(|e| format!("hello: {e:?}"))?;
    for _ in 0..2 {
        send_packet(link.as_ref(), &hello_bytes)?;
        std::thread::sleep(Duration::from_millis(10));
    }
    let server_hello_bytes = link.recv().map_err(|e| format!("recv: {e:?}"))?.bytes;
    let server_hello =
        ServerHello::decode(&server_hello_bytes).map_err(|e| format!("server hello: {e:?}"))?;
    let (secrets, _) = complete_client_side(
        &node.config.identity.identity,
        &node.config.identity.static_handshake,
        &client_ephemeral,
        &hello,
        &server_hello,
        node.entropy.as_ref(),
        "ump.udp/1".as_bytes(),
    )
    .map_err(|e| format!("client side: {e}"))?;
    assert_ne!(
        secrets.client, [0u8; 32],
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

    let mut active = 0u32;
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
        active = status.active_sessions;
        if active == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(active, 1, "session must show up in GetStatus");

    let mut saw_active = false;
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
            saw_active = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(saw_active, "event log must contain a session_active entry");

    daemon.shutdown_with_sigint();
}
