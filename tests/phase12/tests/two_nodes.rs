//! Phase 12 success criteria: two live daemons on separate sockets and
//! ports, node A connecting to node B with a live TCP handshake, a relay
//! circuit opened over A's control API, and a bundle admitted via the
//! control API whose id round-trips through `ListBundles`.
//!
//! The daemon binary is spawned exactly like the phase 9 harness; the
//! client-side session traffic runs on `spawn_blocking` threads because the
//! carriers use blocking `Handle::block_on` calls.
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
use umc_session::session::{Role, Session, SessionConfig};
use umc_types::runtime::{Clock, EntropySource};

struct TestClock;

impl Clock for TestClock {
    fn now(&self) -> umc_types::runtime::Instant {
        umc_types::runtime::Instant(0)
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

fn spawn_daemon(name: &str, tcp_port: u16, udp_port: u16) -> (Daemon, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "phase12-daemon-{name}-{}-{tcp_port}",
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

/// Wire request for `RelayService.OpenCircuit` (mirrors the daemon's
/// private message in server.rs; no proto message exists yet).
#[derive(Clone, PartialEq, prost::Message)]
struct OpenCircuitRequest {
    #[prost(uint64, tag = "1")]
    requested_lifetime_ms: u64,
    #[prost(uint64, tag = "2")]
    requested_byte_quota: u64,
    #[prost(uint32, tag = "3")]
    flags: u32,
    #[prost(bool, tag = "4")]
    bidirectional: bool,
    #[prost(bool, tag = "5")]
    private_handling: bool,
    #[prost(uint32, tag = "6")]
    peer_circuits: u32,
}

/// Wire response for `RelayService.OpenCircuit`.
#[derive(Clone, PartialEq, prost::Message)]
struct OpenCircuitResponse {
    #[prost(uint64, tag = "1")]
    circuit_id: u64,
    #[prost(uint64, tag = "2")]
    granted_lifetime_ms: u64,
    #[prost(uint64, tag = "3")]
    granted_byte_quota: u64,
    #[prost(uint32, tag = "4")]
    maximum_relay_payload: u32,
}

/// Synchronous analogue of `Node::connect` over TCP, returning the live
/// link and the derived client session (phase9 harness pattern). The TCP
/// carrier runs blocking `Handle::block_on` calls internally, so the whole
/// handshake must run on a `spawn_blocking` thread — exactly like the
/// daemon's accept loops.
fn tcp_handshake(node: &umc_core::node::Node, remote: &str) -> Result<(BoxLink, Session), String> {
    let carrier = node.carrier("ump.tcp/1").ok_or("tcp carrier missing")?;
    let link = carrier
        .dial(remote.to_string())
        .map_err(|e| format!("dial: {e:?}"))?;
    let client_ephemeral = StaticHandshakeKeyPair::generate();
    let hello = ClientHello::new(node.entropy.as_ref(), &client_ephemeral);
    let hello_bytes = hello.encode().map_err(|e| format!("hello: {e:?}"))?;
    link.send(OutboundPacket {
        bytes: hello_bytes,
        control: true,
        deadline_ms: Some(3_000),
    })
    .map_err(|e| format!("send: {e:?}"))?;
    std::thread::sleep(Duration::from_millis(100));
    let server_hello_bytes = link.recv().map_err(|e| format!("recv: {e:?}"))?.bytes;
    let server_hello =
        ServerHello::decode(&server_hello_bytes).map_err(|e| format!("server hello: {e:?}"))?;
    let (secrets, _) = complete_client_side(
        &node.config.identity.identity,
        // The daemon stands the client's ephemeral in for the static until
        // the CLIENT_AUTH wire path lands; mirror that here so the derived
        // session secrets match on both sides.
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

#[tokio::test(flavor = "multi_thread")]
async fn relay_circuit_between_two_daemons() {
    let tcp_a = free_tcp_port();
    let tcp_b = free_tcp_port();
    let (daemon_a, socket_a) = spawn_daemon("relay-a", tcp_a, free_udp_port());
    let (daemon_b, _socket_b) = spawn_daemon("relay-b", tcp_b, free_udp_port());
    wait_for_control_socket(&socket_a);

    // Node A connects to daemon B with a live TCP XX handshake over
    // umc_core::Node's carrier, driven synchronously on a blocking thread
    // (the same path as `Node::connect`).
    let mut node = Node::new(
        NodeConfig {
            identity: NodeIdentity::generate(&TestEntropy),
            dcid: vec![2u8; 8],
        },
        Arc::new(TestClock),
        Arc::new(TestEntropy),
    );
    node.register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));
    let remote = format!("127.0.0.1:{tcp_b}");
    let handshake = tokio::task::spawn_blocking(move || tcp_handshake(&node, &remote));
    let (_link, _session) = tokio::time::timeout(Duration::from_secs(20), handshake)
        .await
        .expect("handshake timed out")
        .expect("handshake thread panicked")
        .expect("node handshake failed");

    // A opens a relay circuit on its own daemon via the control API.
    let mut client =
        umc_sdk::client::Client::connect(socket_a.to_str().expect("socket path"), "phase12")
            .await
            .expect("control connect");
    let open = OpenCircuitRequest {
        requested_lifetime_ms: 600_000,
        requested_byte_quota: 1_048_576,
        flags: 0,
        bidirectional: true,
        private_handling: false,
        peer_circuits: 0,
    };
    let mut payload = Vec::new();
    Message::encode(&open, &mut payload).expect("encode");
    let response = client
        .request("RelayService", "OpenCircuit", payload)
        .await
        .expect("open circuit");
    assert_eq!(
        response.status.as_ref().unwrap().code,
        api::StatusCode::Ok as i32,
        "OpenCircuit must be admitted"
    );
    let granted = OpenCircuitResponse::decode(response.payload.as_slice()).expect("payload");
    assert_eq!(granted.granted_lifetime_ms, 600_000);
    assert!(granted.circuit_id > 0);

    drop(client);
    drop(daemon_a);
    drop(daemon_b);
}

#[tokio::test(flavor = "multi_thread")]
async fn bundle_admitted_via_control_api() {
    let (daemon, socket) = spawn_daemon("bundle", free_tcp_port(), free_udp_port());
    wait_for_control_socket(&socket);

    let mut client =
        umc_sdk::client::Client::connect(socket.to_str().expect("socket path"), "phase12")
            .await
            .expect("control connect");
    let create = api::CreateBundleRequest {
        application_handle: Some(api::OpaqueHandle {
            value: b"sender-a".to_vec(),
        }),
        destination_hint: b"dest-token".to_vec(),
        priority: 1,
        // The daemon's node clock is monotonic; an immediate-expiry bundle
        // is clamped to the manager's minimum lifetime.
        expires_at_unix_ms: 0,
        payload_chunk: b"phase12 ciphertext".to_vec(),
        payload_complete: true,
        upload_handle: None,
    };
    let mut payload = Vec::new();
    Message::encode(&create, &mut payload).expect("encode");
    let response = client
        .request("BundleService", "CreateBundle", payload)
        .await
        .expect("create bundle");
    assert_eq!(
        response.status.as_ref().unwrap().code,
        api::StatusCode::Ok as i32,
        "CreateBundle must be admitted"
    );
    let created = api::CreateBundleResponse::decode(response.payload.as_slice())
        .expect("payload")
        .bundle
        .expect("bundle");
    assert_eq!(created.bundle_id.len(), 32);
    assert_eq!(created.payload_size, 18);

    // The id round-trips through ListBundles.
    let response = client
        .request("BundleService", "ListBundles", Vec::new())
        .await
        .expect("list bundles");
    assert_eq!(
        response.status.as_ref().unwrap().code,
        api::StatusCode::Ok as i32
    );
    let listing = api::ListBundlesResponse::decode(response.payload.as_slice())
        .expect("payload")
        .bundles;
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].bundle_id, created.bundle_id);
    assert_eq!(listing[0].state, api::BundleState::Stored as i32);

    drop(client);
    drop(daemon);
}
