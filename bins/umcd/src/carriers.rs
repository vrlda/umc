//! Carrier wiring (core.md §8): register the configured carriers on the
//! runtime node, bind the TCP/UDP listeners, and report listening
//! addresses. The per-link accept loops and the LAN discovery loop land in
//! Task 15+.
use crate::state::RuntimeState;
use umc_carrier::registry::CarrierRegistry;
use umc_carrier::Carrier;
use umc_carrier_lan::{LanDiscoveryCarrier, LanDiscoveryConfig};
use umc_carrier_tcp::TcpCarrier;
use umc_carrier_tls::TlsCarrier;
use umc_carrier_udp::UdpCarrier;

/// Default TCP bind address when `tcp_listen` is unset.
pub const DEFAULT_TCP_LISTEN: &str = "127.0.0.1:9001";
/// Default UDP bind address when `udp_listen` is unset.
pub const DEFAULT_UDP_LISTEN: &str = "127.0.0.1:9002";

/// Registers every configured carrier on the runtime node and binds the
/// data-carrier listeners, holding the binders in the runtime state.
pub fn wire_carriers(state: &mut RuntimeState) {
    let config = state.config.clone();
    let registry = CarrierRegistry::default();
    for carrier_type in &config.carriers {
        if !registry.contains(carrier_type) {
            log::error!("[carrier] unknown carrier type {carrier_type}; skipped");
            continue;
        }
        if config.carrier_disabled(carrier_type) {
            log::warn!("[carrier] {carrier_type} disabled by emergency policy");
            continue;
        }
        match carrier_type.as_str() {
            "ump.tcp/1" => bind_tcp(state, config.tcp_listen.clone()),
            "ump.udp/1" => bind_udp(state, config.udp_listen.clone()),
            "ump.tls-stream/1" => bind_tls(state, config.tls_listen.clone()),
            "ump.lan-discovery/1" => register_lan(state),
            other => log::warn!("[carrier] {other} not built in"),
        }
    }
    crate::control_carriers::register_static_instances(state);
}

fn bind_tls(state: &mut RuntimeState, bind: Option<String>) {
    let carrier = match configured_tls_carrier(&state.config) {
        Ok(carrier) => carrier,
        Err(error) => {
            log::error!("[carrier] ump.tls-stream/1 configuration failed: {error}");
            return;
        }
    };
    state.node.register_carrier(Box::new(carrier.clone()));
    let Some(addr) = bind else {
        log::warn!("[carrier] ump.tls-stream/1 enabled without tls_listen; no listener bound");
        return;
    };
    let result = tokio::task::block_in_place(|| carrier.listen(addr.clone()));
    match result {
        Ok(listener) => {
            state.listeners.push(listener);
            log::info!(
                "[carrier] ump.tls-stream/1 listening on {}",
                crate::logging::redact_addr(&addr)
            );
        }
        Err(e) => log::error!("[carrier] ump.tls-stream/1 failed to listen on {addr}: {e:?}"),
    }
}

fn configured_tls_carrier(config: &crate::config::NodeConfig) -> Result<TlsCarrier, String> {
    let has_provisioned_material = config.tls_certificate.is_some()
        || config.tls_private_key.is_some()
        || !config.tls_trust_roots.is_empty()
        || config.tls_server_name != "localhost";
    if !has_provisioned_material {
        return TlsCarrier::new().map_err(|error| format!("{error:?}"));
    }
    let certificate_path = config
        .resolved_tls_certificate()
        .ok_or_else(|| "tls_certificate is required with provisioned TLS material".to_string())?;
    let private_key_path = config
        .resolved_tls_private_key()
        .ok_or_else(|| "tls_private_key is required with provisioned TLS material".to_string())?;
    let root_paths = config.resolved_tls_trust_roots();
    if root_paths.is_empty() {
        return Err("tls_trust_roots must contain at least one DER root".into());
    }
    let certificate = std::fs::read(&certificate_path).map_err(|error| {
        format!(
            "read TLS certificate {}: {error}",
            certificate_path.display()
        )
    })?;
    let private_key = std::fs::read(&private_key_path).map_err(|error| {
        format!(
            "read TLS private key {}: {error}",
            private_key_path.display()
        )
    })?;
    let mut roots = Vec::with_capacity(root_paths.len());
    for root_path in root_paths {
        roots
            .push(std::fs::read(&root_path).map_err(|error| {
                format!("read TLS trust root {}: {error}", root_path.display())
            })?);
    }
    TlsCarrier::from_der(
        certificate,
        private_key,
        roots,
        config.tls_server_name.clone(),
    )
    .map_err(|error| format!("{error:?}"))
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
            log::info!(
                "[carrier] ump.tcp/1 listening on {}",
                crate::logging::redact_addr(&addr)
            );
        }
        Err(e) => log::error!("[carrier] ump.tcp/1 failed to listen on {addr}: {e:?}"),
    }
}

fn bind_udp(state: &mut RuntimeState, bind: Option<String>) {
    state.node.register_carrier(Box::new(UdpCarrier));
    let addr = bind.unwrap_or_else(|| DEFAULT_UDP_LISTEN.to_string());
    let result = tokio::task::block_in_place(|| UdpCarrier.listen(addr.clone()));
    match result {
        Ok(listener) => {
            state.listeners.push(listener);
            log::info!(
                "[carrier] ump.udp/1 listening on {}",
                crate::logging::redact_addr(&addr)
            );
        }
        Err(e) => log::error!("[carrier] ump.udp/1 failed to listen on {addr}: {e:?}"),
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
    log::info!("[carrier] ump.lan-discovery/1 registered (discovery loop in Task 15+)");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use tokio::sync::mpsc;

    #[test]
    fn provisioned_tls_configuration_requires_all_material() {
        let config = NodeConfig {
            tls_certificate: Some("/tmp/server.der".into()),
            ..NodeConfig::default()
        };
        let error = configured_tls_carrier(&config).expect_err("incomplete TLS material");
        assert!(error.contains("tls_private_key"));
        let config = NodeConfig {
            tls_certificate: Some("/tmp/server.der".into()),
            tls_private_key: Some("/tmp/server.key".into()),
            ..NodeConfig::default()
        };
        let error = configured_tls_carrier(&config).expect_err("missing TLS roots");
        assert!(error.contains("tls_trust_roots"));
    }

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
        assert_eq!(state.carrier_instances.len(), 2);
        assert!(state
            .carrier_instances
            .values()
            .all(|instance| instance.state
                == umc_control::proto::umc::api::v1::CarrierInstanceState::Running as i32));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn disabled_carrier_is_not_registered_or_bound() {
        let dir =
            std::env::temp_dir().join(format!("umcd-carriers-disabled-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = NodeConfig {
            data_dir: dir,
            tcp_listen: Some("127.0.0.1:0".to_string()),
            udp_listen: Some("127.0.0.1:0".to_string()),
            disabled_carriers: vec!["ump.tcp/1".to_string()],
            ..NodeConfig::default()
        };
        let (tx, _rx) = mpsc::channel(1);
        let mut state = crate::state::RuntimeState::new(config, tx).unwrap();
        wire_carriers(&mut state);
        assert_eq!(state.listeners.len(), 1);
        assert!(state.node.carrier("ump.tcp/1").is_none());
        assert!(state.node.carrier("ump.udp/1").is_some());
        assert_eq!(state.carrier_instances.len(), 1);
        assert_eq!(
            state
                .carrier_instances
                .values()
                .next()
                .expect("udp instance")
                .type_id,
            "ump.udp/1"
        );
    }
}
