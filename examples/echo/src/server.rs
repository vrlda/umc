//! Echo server: listens on TCP and UDP and echoes opaque packets back.
use std::sync::Arc;
use umc_carrier::Link;
use umc_carrier_tcp::TcpCarrier;
use umc_carrier_udp::UdpCarrier;
use umc_core::node::{Node, NodeConfig, NodeIdentity};
use umc_types::runtime::{Clock, EntropySource, Instant};

struct OsClock;
impl Clock for OsClock {
    fn now(&self) -> Instant {
        use std::time::{SystemTime, UNIX_EPOCH};
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
        Instant(millis)
    }
}

struct OsEntropy;
impl EntropySource for OsEntropy {
    fn fill(&self, out: &mut [u8]) {
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(out);
    }
}

fn echo_loop(link: &(dyn Link + Send + Sync)) {
    while let Ok(inbound) = link.recv() {
        if link
            .send(umc_carrier::types::OutboundPacket {
                bytes: inbound.bytes,
                control: false,
                deadline_ms: None,
            })
            .is_err()
        {
            break;
        }
    }
}

#[tokio::main]
async fn main() {
    let identity = NodeIdentity::generate(&OsEntropy);
    let mut node = Node::new(
        NodeConfig {
            identity,
            dcid: vec![1u8; 8],
        },
        Arc::new(OsClock),
        Arc::new(OsEntropy),
    );
    node.register_carrier(Box::new(TcpCarrier));
    node.register_carrier(Box::new(UdpCarrier));

    let tcp = node.carrier("ump.tcp/1").expect("tcp");
    let tcp_listener = tcp.listen("127.0.0.1:9001".to_string()).expect("bind tcp");
    let udp = node.carrier("ump.udp/1").expect("udp");
    let udp_listener = udp.listen("127.0.0.1:9002".to_string()).expect("bind udp");

    println!("echo server: tcp 127.0.0.1:9001, udp 127.0.0.1:9002");

    loop {
        if let Ok(link) = tcp_listener.accept() {
            echo_loop(&*link);
        }
        if let Ok(link) = udp_listener.accept() {
            echo_loop(&*link);
        }
    }
}
