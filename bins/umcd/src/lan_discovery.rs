//! Daemon integration for the discovery-only LAN carrier.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use umc_carrier_lan::LanDiscovery;
use umc_discovery::provider::{
    CandidateAuth, CandidateSource, DiscoveryProvider, PeerCandidate, SharingPolicy,
};
use umc_types::runtime::Instant;

const MAX_BATCH: usize = 256;

#[derive(Debug)]
pub struct LanDiscoveryProvider {
    discovery: Arc<LanDiscovery>,
    local_node_hint: Vec<u8>,
    tcp_port: Option<u16>,
    udp_port: Option<u16>,
    candidates: Mutex<HashMap<u64, PeerCandidate>>,
    running: Mutex<bool>,
}

impl LanDiscoveryProvider {
    #[must_use]
    pub fn new(
        discovery: Arc<LanDiscovery>,
        local_node_hint: Vec<u8>,
        tcp_port: Option<u16>,
        udp_port: Option<u16>,
    ) -> Self {
        Self {
            discovery,
            local_node_hint,
            tcp_port,
            udp_port,
            candidates: Mutex::new(HashMap::new()),
            running: Mutex::new(false),
        }
    }

    fn collect_available(&self, now: Instant) {
        for _ in 0..MAX_BATCH {
            let announcement = match self.discovery.receive() {
                Ok(announcement) => announcement,
                Err(error) if error.kind == umc_carrier::error::CarrierErrorKind::WouldBlock => {
                    break
                }
                Err(error) => {
                    log::debug!("[discovery] LAN receive failed: {error:?}");
                    break;
                }
            };
            if announcement.node_hint.is_empty() || announcement.node_hint == self.local_node_hint {
                continue;
            }
            for (carrier, port) in [("ump.tcp/1", self.tcp_port), ("ump.udp/1", self.udp_port)] {
                let Some(port) = port else { continue };
                let address = std::net::SocketAddr::new(announcement.source.ip(), port).to_string();
                let candidate_id = candidate_id(
                    &announcement.node_hint,
                    &announcement.source,
                    carrier,
                    &address,
                );
                let candidate = PeerCandidate {
                    candidate_id,
                    carrier_type: carrier.to_string(),
                    connection_hint: address.into_bytes(),
                    source: CandidateSource::LocalDiscovery,
                    created_at: now,
                    // ProviderManager applies the current refresh timestamp
                    // and caps this lifetime during the merge.
                    expires_at: Instant(u64::MAX),
                    sharing_policy: SharingPolicy::ShareLocalScope,
                    authentication: CandidateAuth::Unauthenticated,
                    local: false,
                };
                self.candidates.lock().expect("LAN candidates").insert(candidate_id, candidate);
            }
        }
        let mut candidates = self.candidates.lock().expect("LAN candidates");
        candidates.retain(|_, candidate| !candidate.is_expired(now));
    }
}

impl DiscoveryProvider for LanDiscoveryProvider {
    fn source(&self) -> CandidateSource {
        CandidateSource::LocalDiscovery
    }

    fn start(&mut self) -> Result<(), String> {
        *self.running.lock().expect("LAN provider state") = true;
        self.discovery
            .announce()
            .map_err(|error| format!("LAN announcement: {error:?}"))
    }

    fn stop(&mut self) -> Result<(), String> {
        *self.running.lock().expect("LAN provider state") = false;
        self.discovery.close();
        Ok(())
    }

    fn candidates(&self, maximum: usize) -> Vec<PeerCandidate> {
        self.candidates
            .lock()
            .expect("LAN candidates")
            .values()
            .take(maximum.min(MAX_BATCH))
            .cloned()
            .collect()
    }

    fn collect_candidates(&self, maximum: usize) -> Result<Vec<PeerCandidate>, String> {
        if !*self.running.lock().expect("LAN provider state") {
            return Ok(Vec::new());
        }
        let now = crate::state::wall_now();
        let _ = self.discovery.announce();
        self.collect_available(now);
        Ok(self.candidates(maximum))
    }

    fn publish(&self, _hint: &[u8]) -> Result<(), String> {
        self.discovery
            .announce()
            .map_err(|error| format!("LAN announcement: {error:?}"))
    }
}

fn candidate_id(
    node_hint: &[u8],
    source: &std::net::SocketAddr,
    carrier: &str,
    address: &str,
) -> u64 {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMP-LAN-CANDIDATE-v1");
    hasher.update(node_hint);
    hasher.update(source.ip().to_string().as_bytes());
    hasher.update(carrier.as_bytes());
    hasher.update(address.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    u64::from_be_bytes(digest[..8].try_into().unwrap_or([0; 8]))
}
