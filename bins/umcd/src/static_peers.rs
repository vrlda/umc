//! Static peer bootstrap (discovery.md §15).

use crate::config::{BootstrapPeerConfig, StaticPeerConfig};
use crate::state::RuntimeState;
use blake2::{Blake2s256, Digest};
use std::collections::HashMap;
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

/// Configured rendezvous contacts. Unlike pinned static peers, bootstrap
/// candidates are intentionally generic and are safe to replace with learned
/// peers after the first authenticated connection.
pub struct BootstrapPeerProvider {
    candidates: Vec<PeerCandidate>,
    running: bool,
}

impl std::fmt::Debug for BootstrapPeerProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapPeerProvider")
            .field("candidate_count", &self.candidates.len())
            .field("running", &self.running)
            .finish()
    }
}

impl BootstrapPeerProvider {
    #[must_use]
    pub fn new(peers: &[BootstrapPeerConfig], now: Instant) -> Self {
        let candidates = peers
            .iter()
            .enumerate()
            .map(|(index, peer)| PeerCandidate {
                candidate_id: bootstrap_candidate_id(index, &peer.carrier, &peer.address),
                carrier_type: peer.carrier.clone(),
                connection_hint: peer.address.as_bytes().to_vec(),
                source: CandidateSource::Bootstrap,
                created_at: now,
                expires_at: Instant(u64::MAX),
                sharing_policy: umc_discovery::provider::SharingPolicy::LocalUseOnly,
                authentication: CandidateAuth::Unauthenticated,
                local: true,
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

impl DiscoveryProvider for BootstrapPeerProvider {
    fn source(&self) -> CandidateSource {
        CandidateSource::Bootstrap
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
        Err("bootstrap discovery provider is read-only".into())
    }
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

fn bootstrap_candidate_id(index: usize, carrier: &str, address: &str) -> u64 {
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMP-BOOTSTRAP-CANDIDATE-v1");
    hasher.update(index.to_be_bytes());
    hasher.update(carrier.as_bytes());
    hasher.update(address.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(prefix)
}

/// Select bounded automatic-dial work. Local self advertisements and pinned
/// static peers are never dialed by this learned-candidate path; configured
/// bootstrap seeds are handled by the explicit fallback dialer.
#[must_use]
pub fn candidate_dial_plan(
    candidates: &[PeerCandidate],
    now: Instant,
    maximum: usize,
) -> Vec<PeerCandidate> {
    let mut selected: Vec<_> = candidates
        .iter()
        .filter(|candidate| !candidate.is_expired(now))
        .filter(|candidate| !candidate.local)
        .filter(|candidate| candidate.source != CandidateSource::Static)
        .cloned()
        .collect();
    selected.dedup_by(|left, right| {
        left.carrier_type == right.carrier_type && left.connection_hint == right.connection_hint
    });
    selected.truncate(maximum);
    selected
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

/// Dial configured rendezvous contacts. An optional endpoint id preserves the
/// pinning behavior when an operator supplies one; omitted ids still receive
/// the normal authenticated UMP handshake and learn the actual peer identity.
pub fn dial_bootstrap(
    state: &Arc<Mutex<RuntimeState>>,
    peers: &[BootstrapPeerConfig],
) {
    for peer in peers {
        let expected = match peer.endpoint_id.as_deref() {
            Some(value) => match parse_endpoint_id(value) {
                Ok(endpoint_id) => Some(endpoint_id),
                Err(error) => {
                    log::warn!(
                        "[discovery] bootstrap peer {} rejected endpoint id: {error}",
                        peer.address
                    );
                    continue;
                }
            },
            None => None,
        };
        dial_one(state, &peer.carrier, &peer.address, expected, "bootstrap");
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DialAttempt {
    pub next: Instant,
    pub peer_endpoint_id: Option<[u8; 32]>,
}

/// Dial a bounded batch of candidates learned through `PEER_HINT` or restored
/// from prior sessions. `attempted` is process-local backoff state; callers
/// retain it across timer ticks so a bad hint cannot create a hot loop.
pub fn dial_discovered(
    state: &Arc<Mutex<RuntimeState>>,
    attempted: &mut HashMap<u64, DialAttempt>,
    now: Instant,
    maximum: usize,
) {
    let candidates = {
        let state = state.lock().expect("runtime state");
        candidate_dial_plan(&state.discovery.candidates(), now, maximum)
    };
    for candidate in candidates {
        if let Some(attempt) = attempted.get(&candidate.candidate_id) {
            let connected = attempt.peer_endpoint_id.is_some_and(|peer| {
                state
                    .lock()
                    .expect("runtime state")
                    .sessions
                    .snapshot()
                    .iter()
                    .any(|(_, entry)| entry.peer_endpoint_id == peer)
            });
            if connected {
                continue;
            }
            if attempt.next > now {
                continue;
            }
        }
        let address = String::from_utf8_lossy(&candidate.connection_hint).to_string();
        let result = dial_one(
            state,
            &candidate.carrier_type,
            &address,
            None,
            "learned",
        );
        let cooldown_ms = if result.is_some() { 10 * 60_000 } else { 60_000 };
        attempted.insert(
            candidate.candidate_id,
            DialAttempt {
                next: now + umc_types::runtime::Duration::from_millis(cooldown_ms),
                peer_endpoint_id: result,
            },
        );
    }
}

fn dial_one(
    state: &Arc<Mutex<RuntimeState>>,
    carrier: &str,
    address: &str,
    expected_endpoint_id: Option<[u8; 32]>,
    source: &str,
) -> Option<[u8; 32]> {
    let (disabled, carrier_name, address) = {
        let state = state.lock().expect("runtime state");
        (
            state.config.carrier_disabled(carrier),
            carrier.to_string(),
            address.to_string(),
        )
    };
    if disabled {
        log::debug!("[discovery] {source} carrier {carrier_name} disabled");
        return None;
    }
    let result = {
        let mut state = state.lock().expect("runtime state");
        let handle = tokio::runtime::Handle::current();
        tokio::task::block_in_place(|| {
            handle.block_on(state.node.connect_transport(
                &carrier_name,
                address.clone(),
                expected_endpoint_id,
            ))
        })
    };
    match result {
        Ok(connection) => {
            let selected_privacy = state
                .lock()
                .expect("runtime state")
                .config
                .effective_privacy_profile() as u8;
            let peer_endpoint_id = connection.peer_endpoint_id;
            let node_session_id = connection.session_id;
            match crate::register_session(
                state,
                &carrier_name,
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
            ) {
                Ok(()) => {
                    log::info!(
                        "[discovery] {source} peer {address} connected (node session {node_session_id})"
                    );
                    Some(peer_endpoint_id)
                }
                Err(error) => {
                    log::warn!(
                        "[discovery] {source} peer {address} session registration failed: {error}"
                    );
                    None
                }
            }
        }
        Err(error) => {
            log::debug!("[discovery] {source} peer {address} dial failed: {error:?}");
            None
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

    #[test]
    fn bootstrap_provider_and_dial_plan_excludes_local_seeds() {
        let peers = vec![BootstrapPeerConfig {
            endpoint_id: None,
            carrier: "ump.tcp/1".into(),
            address: "seed.example:9001".into(),
        }];
        let provider = BootstrapPeerProvider::new(&peers, Instant(5));
        assert!(provider.candidates(10).is_empty());
        assert_eq!(provider.candidates.len(), 1);
        let learned = PeerCandidate {
            candidate_id: 2,
            carrier_type: "ump.tcp/1".into(),
            connection_hint: b"peer.example:9001".to_vec(),
            source: CandidateSource::PeerHint,
            created_at: Instant(5),
            expires_at: Instant(100),
            sharing_policy: umc_discovery::provider::SharingPolicy::ShareGeneral,
            authentication: CandidateAuth::IntroductionAuthenticated,
            local: false,
        };
        let seed = provider.candidates[0].clone();
        let self_advertised = PeerCandidate {
            local: true,
            source: CandidateSource::Application,
            ..learned.clone()
        };
        let plan = candidate_dial_plan(&[self_advertised, learned, seed], Instant(5), 8);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].source, CandidateSource::PeerHint);
    }
}
