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
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering as AtomicOrdering};
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

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(name: &str, tcp_port: u16, udp_port: u16) -> (Daemon, PathBuf) {
    spawn_daemon_with_retry(name, tcp_port, udp_port, false)
}

fn spawn_daemon_with_retry(
    name: &str,
    tcp_port: u16,
    udp_port: u16,
    require_retry: bool,
) -> (Daemon, PathBuf) {
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
        "require_retry": require_retry,
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

#[tokio::test(flavor = "multi_thread")]
async fn node_connect_completes_stateless_retry_handshake() {
    let tcp_port = free_tcp_port();
    let udp_port = free_udp_port();
    let (daemon, socket) = spawn_daemon_with_retry("retry", tcp_port, udp_port, true);
    wait_for_control_socket(&socket);

    let mut node = Node::new(
        NodeConfig {
            identity: NodeIdentity::generate(&TestEntropy),
            dcid: vec![2u8; 8],
        },
        Arc::new(TestClock),
        Arc::new(TestEntropy),
    );
    node.register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));
    let remote = format!("127.0.0.1:{tcp_port}");
    let transport = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::task::spawn_blocking(move || drive_transport(&mut node, &remote)),
    )
    .await
    .expect("stateless retry handshake timed out")
    .expect("handshake thread panicked")
    .expect("stateless retry handshake failed");
    transport
        .link
        .close("retry test complete")
        .expect("close link");
    drop(daemon);
}

fn drive_transport(
    node: &mut Node,
    remote: &str,
) -> Result<umc_core::node::ConnectedTransport, umc_core::node::NodeError> {
    let mut future = Box::pin(node.connect_transport("ump.tcp/1", remote.to_string(), None));
    let waker = std::task::Waker::from(Arc::new(NoopWaker));
    let mut context = std::task::Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(result) => return result,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

struct NoopWaker;

impl std::task::Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}

    fn wake_by_ref(self: &Arc<Self>) {}
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

/// Send the client's `CLIENT_AUTH` message (handshake.md §18) — the REAL
/// static key plus identity binding and transcript-bound signature, sealed
/// with the provisional-chain client-auth key (the daemon's DH chain
/// stands the ephemeral in for the static, so the auth key matches on both
/// sides) and framed inside an encrypted Handshake packet. Returns the
/// message body (the length-prefixed ciphertext): the bytes appended to the
/// transcript by both sides.
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
    link.send(OutboundPacket {
        bytes: packet,
        control: true,
        deadline_ms: Some(3_000),
    })
    .map_err(|e| format!("send client auth: {e:?}"))?;
    Ok(auth_body)
}

/// Synchronous analogue of `Node::connect` over TCP, returning the live
/// link and the derived client session (phase9 harness pattern). The TCP
/// carrier runs blocking `Handle::block_on` calls internally, so the whole
/// handshake must run on a `spawn_blocking` thread — exactly like the
/// daemon's accept loops.
#[allow(clippy::too_many_lines)]
fn tcp_handshake(node: &umc_core::node::Node, remote: &str) -> Result<(BoxLink, Session), String> {
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
    link.send(OutboundPacket {
        bytes: initial,
        control: true,
        deadline_ms: Some(3_000),
    })
    .map_err(|e| format!("send: {e:?}"))?;
    std::thread::sleep(Duration::from_millis(100));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let server_hello_packet = loop {
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
        umc_handshake::initial::parse_initial_with_keys(&server_hello_packet, &initial_keys.server)
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
    // SERVER_FINISHED (handshake.md §19): an encrypted Handshake packet.
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
    link.send(OutboundPacket {
        bytes: finished_packet,
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
    let (daemon_b, socket_b) = spawn_daemon("relay-b", tcp_b, free_udp_port());
    wait_for_control_socket(&socket_a);
    // The control socket is the daemon's readiness barrier. Under workspace
    // parallel load daemon B can take longer to bind its TCP listener; wait
    // for both children before dialing rather than turning startup jitter
    // into a flaky connection-refused failure.
    wait_for_control_socket(&socket_b);

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
