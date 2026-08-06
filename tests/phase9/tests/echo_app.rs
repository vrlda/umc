//! Phase 9 success criterion: an application-level STREAM frame carrying
//! the well-known echo protocol ID (`org.umc.app/1`) round-trips through a
//! live daemon session. The daemon dispatches the stream to the echo
//! application, which reflects the bytes back on the same stream ID.
//!
//! The client drives the same path as `Node::connect` (node.rs) but
//! synchronously: the carriers run blocking `Handle::block_on` calls that
//! panic from an async context on the same runtime, so the handshake and
//! the session loop run on a `spawn_blocking` thread exactly like the
//! daemon's accept loops (phase8 harness).
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use umc_carrier::types::OutboundPacket;
use umc_carrier::BoxLink;
use umc_core::node::{Node, NodeConfig, NodeIdentity};
use umc_core::well_known::WELL_KNOWN_APP;
use umc_crypto::signatures::StaticHandshakeKeyPair;
use umc_handshake::xx::{complete_client_side, ClientHello, ServerHello};
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

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(tcp_port: u16, udp_port: u16) -> (Daemon, PathBuf) {
    let dir = std::env::temp_dir().join(format!("phase9-daemon-{}-{tcp_port}", std::process::id()));
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

fn client_node() -> Node {
    let mut node = Node::new(
        NodeConfig {
            identity: NodeIdentity::generate(&TestEntropy),
            dcid: vec![2u8; 8],
        },
        Arc::new(TestClock),
        Arc::new(TestEntropy),
    );
    node.register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));
    node
}

/// Synchronous analogue of `Node::connect` over TCP, returning the live
/// link and the derived client session. The TCP carrier serializes reads
/// and writes behind one mutex and a background writer task, so a blocking
/// `recv` must not start until the hello write has been flushed; the brief
/// pause lets the writer deliver the frame before `recv` takes the lock.
fn tcp_handshake(node: &Node, remote: &str) -> Result<(BoxLink, Session), String> {
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
        // The daemon stands the client's ephemeral in for the static until
        // CLIENT_AUTH is parsed (handshake.md §18); mirror that here so the
        // derived session secrets match on both sides.
        &client_ephemeral,
        &client_ephemeral,
        &hello,
        &server_hello,
        node.entropy.as_ref(),
        "ump.tcp/1".as_bytes(),
    )
    .map_err(|e| format!("client side: {e}"))?;
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

/// Drive the client side of an echo round trip: send a STREAM frame with
/// the echo protocol ID, then read packets until the daemon's echo arrives
/// on the same stream ID.
///
/// The TCP carrier serializes reads and writes behind one mutex: a blocking
/// `recv` holds the lock, so the client's queued frames only flush between
/// recvs. After the first frame the client sends a PING after every recv,
/// which releases the daemon's recv lock and lets its queued echo flush.
fn run_echo_client(node: &Node, remote: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    let (link, mut session) = tcp_handshake(node, remote)?;
    let stream_payload = stream_frame_payload(0, WELL_KNOWN_APP, payload);
    let packet = session
        .build_outbound(&TestClock, Instant(0), &stream_payload)
        .map_err(|e| format!("build: {e:?}"))?
        .ok_or("no outbound packet")?;
    send_packet(link.as_ref(), &packet)?;
    // Let the TCP writer flush the frame before the recv loop takes the
    // stream lock (phase8 harness pattern).
    std::thread::sleep(Duration::from_millis(50));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let inbound = link.recv().map_err(|e| format!("recv: {e:?}"))?;
        let _ = session.on_inbound(Instant(0), &inbound.bytes);
        if let Ok((data, _eof)) = session.read_stream(0) {
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
        // Let the TCP writer flush the ping before the next recv takes the
        // stream lock; the daemon's queued echo flushes in response.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            std::time::Instant::now() < deadline,
            "echo did not return within 10s"
        );
    }
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
async fn echo_stream_over_live_session() {
    let tcp_port = free_tcp_port();
    let (daemon, socket) = spawn_daemon(tcp_port, free_udp_port());
    wait_for_control_socket(&socket);

    let node = client_node();
    let remote = format!("127.0.0.1:{tcp_port}");
    let expected = b"phase9 echo payload".to_vec();
    let payload = expected.clone();
    let client = tokio::task::spawn_blocking(move || run_echo_client(&node, &remote, &payload));
    let echoed = tokio::time::timeout(Duration::from_secs(20), client)
        .await
        .expect("live echo round trip timed out")
        .expect("client thread panicked")
        .expect("echo round trip failed");
    assert_eq!(echoed, expected, "echo must return the exact bytes");

    drop(daemon);
}
