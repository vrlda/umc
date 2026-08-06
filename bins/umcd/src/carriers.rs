//! Carrier wiring (core.md §8): register the configured carriers on the
//! runtime node, bind the TCP/UDP listeners, and report listening
//! addresses. The per-link accept loops and the LAN discovery loop land in
//! Task 15+.
use crate::state::RuntimeState;
use umc_carrier::Carrier;
use umc_carrier_lan::{LanDiscoveryCarrier, LanDiscoveryConfig};
use umc_carrier_tcp::TcpCarrier;
use umc_carrier_udp::UdpCarrier;

/// Default TCP bind address when `tcp_listen` is unset.
pub const DEFAULT_TCP_LISTEN: &str = "127.0.0.1:9001";
/// Default UDP bind address when `udp_listen` is unset.
pub const DEFAULT_UDP_LISTEN: &str = "127.0.0.1:9002";

/// Registers every configured carrier on the runtime node and binds the
/// data-carrier listeners, holding the binders in the runtime state.
pub fn wire_carriers(state: &mut RuntimeState) {
    let config = state.config.clone();
    for carrier_type in &config.carriers {
        match carrier_type.as_str() {
            "ump.tcp/1" => bind_tcp(state, config.tcp_listen.clone()),
            "ump.udp/1" => bind_udp(state, config.udp_listen.clone()),
            "ump.lan-discovery/1" => register_lan(state),
            other => println!("[carrier] {other} not built in"),
        }
    }
}

fn bind_tcp(state: &mut RuntimeState, bind: Option<String>) {
    state.node.register_carrier(Box::new(TcpCarrier));
    let addr = bind.unwrap_or_else(|| DEFAULT_TCP_LISTEN.to_string());
    // The carrier binds with Handle::block_on, which must not run inside an
    // async context; block_in_place moves off the async machinery.
    let result = tokio::task::block_in_place(|| TcpCarrier.listen(addr.clone()));
    match result {
        Ok(listener) => {
            state.listeners.push(listener);
            println!("[carrier] ump.tcp/1 listening on {addr}");
        }
        Err(e) => println!("[carrier] ump.tcp/1 failed to listen on {addr}: {e:?}"),
    }
}

fn bind_udp(state: &mut RuntimeState, bind: Option<String>) {
    state.node.register_carrier(Box::new(UdpCarrier));
    let addr = bind.unwrap_or_else(|| DEFAULT_UDP_LISTEN.to_string());
    let result = tokio::task::block_in_place(|| UdpCarrier.listen(addr.clone()));
    match result {
        Ok(listener) => {
            state.listeners.push(listener);
            println!("[carrier] ump.udp/1 listening on {addr}");
        }
        Err(e) => println!("[carrier] ump.udp/1 failed to listen on {addr}: {e:?}"),
    }
}

fn register_lan(state: &mut RuntimeState) {
    let carrier = LanDiscoveryCarrier {
        config: LanDiscoveryConfig {
            node_hint: state.node.config.identity.endpoint_id().to_vec(),
            ..LanDiscoveryConfig::default()
        },
    };
    state.node.register_carrier(Box::new(carrier));
    println!("[carrier] ump.lan-discovery/1 registered (discovery loop in Task 15+)");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use tokio::sync::mpsc;

    #[tokio::test(flavor = "multi_thread")]
    async fn wires_configured_carriers_and_binds() {
        let dir = std::env::temp_dir().join(format!("umcd-carriers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = NodeConfig {
            data_dir: dir,
            tcp_listen: Some("127.0.0.1:0".to_string()),
            udp_listen: Some("127.0.0.1:0".to_string()),
            ..NodeConfig::default()
        };
        let (tx, _rx) = mpsc::channel(1);
        let mut state = crate::state::RuntimeState::new(config, tx).unwrap();
        wire_carriers(&mut state);
        assert_eq!(state.listeners.len(), 2);
        assert!(state.node.carrier("ump.tcp/1").is_some());
        assert!(state.node.carrier("ump.udp/1").is_some());
    }
}
