//! Static peer bootstrap (discovery.md §15).

use crate::config::StaticPeerConfig;
use crate::state::RuntimeState;
use blake2::{Blake2s256, Digest};
use std::sync::{Arc, Mutex};
use umc_discovery::provider::{CandidateAuth, CandidateSource, DiscoveryProvider, PeerCandidate};
use umc_types::runtime::Instant;

/// Config-backed static peers exposed through the normal discovery-provider
/// lifecycle. The daemon still performs the authenticated dial path in
/// [`dial_all`]; these candidates only provide bounded, source-attributed
/// reachability hints to discovery consumers.
pub struct StaticPeerProvider {
    candidates: Vec<PeerCandidate>,
    running: bool,
}

impl std::fmt::Debug for StaticPeerProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticPeerProvider")
            .field("candidate_count", &self.candidates.len())
            .field("running", &self.running)
            .finish()
    }
}

impl StaticPeerProvider {
    #[must_use]
    pub fn new(peers: &[StaticPeerConfig], now: Instant) -> Self {
        let candidates = peers
            .iter()
            .filter_map(|peer| {
                let endpoint = match parse_endpoint_id(&peer.endpoint_id) {
                    Ok(endpoint) => endpoint,
                    Err(error) => {
                        log::warn!(
                            "[discovery] static provider skipped {}: {error}",
                            peer.address
                        );
                        return None;
                    }
                };
                Some(PeerCandidate {
                    candidate_id: static_candidate_id(&endpoint, &peer.carrier, &peer.address),
                    carrier_type: peer.carrier.clone(),
                    connection_hint: peer.address.as_bytes().to_vec(),
                    source: CandidateSource::Static,
                    created_at: now,
                    expires_at: Instant(u64::MAX),
                    sharing_policy: umc_discovery::provider::SharingPolicy::LocalUseOnly,
                    authentication: CandidateAuth::Unauthenticated,
                    local: true,
                })
            })
            .collect();
        Self {
            candidates,
            running: false,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
}

impl DiscoveryProvider for StaticPeerProvider {
    fn source(&self) -> CandidateSource {
        CandidateSource::Static
    }

    fn start(&mut self) -> Result<(), String> {
        self.running = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        self.running = false;
        Ok(())
    }

    fn candidates(&self, maximum: usize) -> Vec<PeerCandidate> {
        if !self.running {
            return Vec::new();
        }
        self.candidates.iter().take(maximum).cloned().collect()
    }

    fn publish(&self, _hint: &[u8]) -> Result<(), String> {
        Err("static discovery provider is read-only".into())
    }
}

fn static_candidate_id(endpoint: &[u8; 32], carrier: &str, address: &str) -> u64 {
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMP-STATIC-CANDIDATE-v1");
    hasher.update(endpoint);
    hasher.update(carrier.as_bytes());
    hasher.update(address.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(prefix)
}

/// Parses the canonical 32-byte endpoint id representation used by config
/// and logs (64 hexadecimal characters, optional `0x` prefix).
pub fn parse_endpoint_id(value: &str) -> Result<[u8; 32], String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 {
        return Err(format!(
            "endpoint id must be 64 hex characters, got {}",
            value.len()
        ));
    }
    let mut endpoint_id = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| format!("invalid endpoint id at {index}"))?;
        let low = hex_nibble(pair[1]).ok_or_else(|| format!("invalid endpoint id at {index}"))?;
        endpoint_id[index] = (high << 4) | low;
    }
    Ok(endpoint_id)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// Attempts one bounded dial for every configured static peer. The node
/// mutex is held only for the handshake call; endpoint matching is enforced
/// inside `Node::connect_transport`. A successful transport is handed to the
/// daemon session loop so static peers are real live sessions rather than
/// entries stranded in the core node registry.
#[allow(clippy::await_holding_lock)]
pub fn dial_all(state: &Arc<Mutex<RuntimeState>>, peers: &[StaticPeerConfig]) {
    for peer in peers {
        let endpoint_id = match parse_endpoint_id(&peer.endpoint_id) {
            Ok(endpoint_id) => endpoint_id,
            Err(error) => {
                log::warn!("[discovery] static peer {} rejected: {error}", peer.address);
                continue;
            }
        };
        let (disabled, carrier) = {
            let state = state.lock().expect("runtime state");
            (
                state.config.carrier_disabled(&peer.carrier),
                peer.carrier.clone(),
            )
        };
        if disabled {
            log::debug!("[discovery] static peer carrier {carrier} disabled");
            continue;
        }
        let result = {
            let mut state = state.lock().expect("runtime state");
            let node = &mut state.node;
            let carrier_name = carrier.clone();
            let address = peer.address.clone();
            let handle = tokio::runtime::Handle::current();
            tokio::task::block_in_place(|| {
                handle.block_on(node.connect_transport(&carrier_name, address, Some(endpoint_id)))
            })
        };
        match result {
            Ok(connection) => {
                let selected_privacy = {
                    state
                        .lock()
                        .expect("runtime state")
                        .config
                        .effective_privacy_profile() as u8
                };
                let node_session_id = connection.session_id;
                let peer_endpoint_id = connection.peer_endpoint_id;
                let register = crate::register_session(
                    state,
                    &carrier,
                    connection.link,
                    connection.dcid,
                    connection.secrets.client,
                    connection.secrets.server,
                    Some(connection.secrets.stateless_reset),
                    None,
                    peer_endpoint_id,
                    crate::state::wall_now(),
                    selected_privacy,
                    umc_session::session::Role::Client,
                );
                match register {
                    Ok(()) => log::info!(
                        "[discovery] static peer {} connected (node session {node_session_id})",
                        peer.address
                    ),
                    Err(error) => log::warn!(
                        "[discovery] static peer {} session registration failed: {error}",
                        peer.address
                    ),
                }
            }
            Err(error) => log::debug!(
                "[discovery] static peer {} dial failed: {error:?}",
                peer.address
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_id_parser_accepts_hex_forms() {
        let plain = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert_eq!(parse_endpoint_id(plain).unwrap()[0], 0);
        assert_eq!(parse_endpoint_id(&format!("0x{plain}")).unwrap()[31], 0xff);
        assert!(parse_endpoint_id("bad").is_err());
        assert!(parse_endpoint_id(&plain[..63]).is_err());
    }

    #[test]
    fn static_provider_is_lifecycle_managed_and_local_only() {
        let endpoint = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let peers = vec![StaticPeerConfig {
            endpoint_id: endpoint.into(),
            carrier: "ump.tcp/1".into(),
            address: "127.0.0.1:9001".into(),
        }];
        let mut provider = StaticPeerProvider::new(&peers, Instant(5));
        assert!(provider.candidates(10).is_empty());
        provider.start().unwrap();
        let candidates = provider.candidates(10);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].source, CandidateSource::Static);
        assert_eq!(
            candidates[0].sharing_policy,
            umc_discovery::provider::SharingPolicy::LocalUseOnly
        );
        assert!(candidates[0].local);
        assert_eq!(candidates[0].expires_at, Instant(u64::MAX));
        assert!(provider.publish(b"hint").is_err());
        provider.stop().unwrap();
        assert!(provider.candidates(10).is_empty());
    }
}
