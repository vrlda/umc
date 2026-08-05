//! Echo client: connects over TCP or UDP, prints its endpoint ID, and
//! attempts a session (the encrypted session loop lands with the daemon in
//! Phase 8; the client exercises the live carrier path).
use std::sync::Arc;
use umc_core::node::{Node, NodeConfig, NodeIdentity};
use umc_types::runtime::{Clock, EntropySource, Instant};

struct OsClock;
impl Clock for OsClock {
    fn now(&self) -> Instant {
        use std::time::{SystemTime, UNIX_EPOCH};
        let millis = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
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

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let carrier_type = args.next().unwrap_or_else(|| "ump.tcp/1".to_string());
    let remote = args.next().unwrap_or_else(|| "127.0.0.1:9001".to_string());
    let identity = NodeIdentity::generate(&OsEntropy);
    let mut node = Node::new(
        NodeConfig { identity, dcid: vec![2u8; 8] },
        Arc::new(OsClock),
        Arc::new(OsEntropy),
    );
    if carrier_type == "ump.udp/1" {
        node.register_carrier(Box::new(umc_carrier_udp::UdpCarrier));
    } else {
        node.register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));
    }
    println!("client endpoint: {:02x?}", node.config.identity.endpoint_id());
    println!("connecting via {carrier_type} to {remote}");
    match node.connect(&carrier_type, remote, &NodeIdentity::generate(&OsEntropy)).await {
        Ok(_) => println!("session established (live path)"),
        Err(e) => println!("session attempt failed (Phase 8 will complete the loop): {e:?}"),
    }
}
