//! Phase 12 version-negotiation coverage (compatibility.md §5.2): a client
//! offering only unsupported protocol versions gets a Version-Negotiation
//! packet from the live daemon listing version 1 (the wire's only
//! supported version), and the retry — a fresh connection offering
//! version 1 — completes the full XX handshake with session secrets.
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use umc_carrier::types::OutboundPacket;
use umc_core::node::{Node, NodeConfig, NodeIdentity};
use umc_crypto::signatures::StaticHandshakeKeyPair;
use umc_handshake::xx::{parse_version_negotiation, ClientHello};
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
        "phase12-vn-daemon-{name}-{}-{tcp_port}",
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

/// Drive `Node::connect` to completion on a blocking thread without a
/// tokio runtime context: `Handle::block_on` would mark this thread an
/// async execution context, which panics the carriers' own nested
/// `Handle::block_on` calls. `connect` awaits only a tokio mutex, so a
/// plain poll loop suffices; the `spawn_blocking` thread keeps the runtime
/// context the carriers require.
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

#[tokio::test(flavor = "multi_thread")]
async fn client_retries_on_version_negotiation() {
    let tcp = free_tcp_port();
    let (daemon, socket) = spawn_daemon("vn", tcp, free_udp_port());
    wait_for_control_socket(&socket);
    let remote = format!("127.0.0.1:{tcp}");

    let mut node = Node::new(
        NodeConfig {
            identity: NodeIdentity::generate(&TestEntropy),
            dcid: vec![2u8; 8],
        },
        Arc::new(TestClock),
        Arc::new(TestEntropy),
    );
    node.register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));

    // Attempt 1: a raw hello offering ONLY version 2. The daemon answers
    // with a Version-Negotiation packet listing version 1 (its only
    // supported version) and closes the connection — the handshake does
    // not continue (compatibility.md §5.2, handshake.md §16). The TCP
    // carrier runs blocking `Handle::block_on` calls internally, so the
    // exchange runs on a `spawn_blocking` thread.
    let node = node; // moved into the blocking closure
    let first_remote = remote.clone();
    let first_attempt = tokio::task::spawn_blocking(move || {
        let carrier = node.carrier("ump.tcp/1").ok_or("tcp carrier missing")?;
        let link = carrier
            .dial(first_remote)
            .map_err(|e| format!("dial: {e:?}"))?;
        let ephemeral = StaticHandshakeKeyPair::generate();
        let mut hello = ClientHello::new(node.entropy.as_ref(), &ephemeral);
        hello.supported_protocol_versions = vec![2];
        let hello_bytes = hello.encode().map_err(|e| format!("hello: {e:?}"))?;
        link.send(OutboundPacket {
            bytes: hello_bytes,
            control: true,
            deadline_ms: Some(3_000),
        })
        .map_err(|e| format!("send: {e:?}"))?;
        // The TCP carrier's recv yields WouldBlock while the daemon's
        // reply is buffered (carriers/tcp.md); poll briefly.
        std::thread::sleep(Duration::from_millis(100));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match link.recv() {
                Ok(packet) => return Ok::<Vec<u8>, String>(packet.bytes),
                Err(e)
                    if e.kind == umc_carrier::error::CarrierErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(format!("recv version negotiation: {e:?}")),
            }
        }
    });
    let vn_packet = tokio::time::timeout(Duration::from_secs(20), first_attempt)
        .await
        .expect("first attempt timed out")
        .expect("client thread panicked")
        .expect("first attempt failed");
    let offered = parse_version_negotiation(&vn_packet).expect("a Version-Negotiation packet");
    assert_eq!(offered, vec![1], "the daemon's VN must list version 1");
    // The daemon closed this connection; the client retries with a fresh one.

    // Attempt 2 (the retry): the canonical client offers version 1 and the
    // full XX handshake completes with session secrets.
    let mut node = Node::new(
        NodeConfig {
            identity: NodeIdentity::generate(&TestEntropy),
            dcid: vec![2u8; 8],
        },
        Arc::new(TestClock),
        Arc::new(TestEntropy),
    );
    node.register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));
    let server_identity = NodeIdentity::generate(&TestEntropy);
    let handshake =
        tokio::task::spawn_blocking(move || drive_connect(&mut node, &remote, &server_identity));
    let session_id = tokio::time::timeout(Duration::from_secs(20), handshake)
        .await
        .expect("retry handshake timed out")
        .expect("client thread panicked")
        .expect("retry handshake failed");
    assert_eq!(session_id, 0);

    drop(daemon);
}
