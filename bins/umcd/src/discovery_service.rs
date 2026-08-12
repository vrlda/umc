//! Discovery service (discovery.md §5-13): the daemon's in-memory candidate
//! table and `PEER_HINT` builder, wired into the runtime state. Candidates
//! persist to the node database under the peer namespace (storage.md §16.4);
//! after a restart the table is restored so operational hints survive.
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use blake2::{Blake2s256, Digest};
use umc_crypto::signatures::IdentityPublicKey;
use umc_discovery::bootstrap::{BootstrapBundle, BootstrapError};
use umc_discovery::hints::{
    apply_received_hints, apply_received_hints_with_mesh_secret, build_peer_hint,
    build_peer_hint_with_mesh_secret, select_for_share, HintError,
};
use umc_discovery::manager::{ProviderManager, ProviderReport, RefreshReport};
use umc_discovery::provider::{CandidateAuth, CandidateSource, PeerCandidate, SharingPolicy};
use umc_discovery::table::{CandidateTable, TableError};
use umc_storage::sqlite::SqliteStore;
use umc_storage::store::{Namespace, Store, StoreError};
use umc_types::runtime::Instant;
use umc_wire::frames::misc::PeerHintFrame;

/// Default candidate capacity (discovery.md §6).
#[allow(dead_code)] // used by daemon config wiring in Phase 12
pub const DEFAULT_TABLE_CAP: usize = umc_discovery::table::DEFAULT_TABLE_CAP;

/// Wire form of a persisted candidate (storage.md §16.4): `PeerCandidate`
/// does not derive `serde`, so this mirror is what gets serialized. Enum
/// discriminants are stable: they follow the variant order declared in
/// `umc-discovery` `provider.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CandidateJson {
    candidate_id: u64,
    carrier_type: String,
    connection_hint: Vec<u8>,
    source: u8,
    created_at_ms: u64,
    expires_at_ms: u64,
    sharing_policy: u8,
    authentication: u8,
    local: bool,
}

impl CandidateJson {
    fn from_candidate(c: &PeerCandidate) -> Self {
        Self {
            candidate_id: c.candidate_id,
            carrier_type: c.carrier_type.clone(),
            connection_hint: c.connection_hint.clone(),
            source: source_to_u8(c.source),
            created_at_ms: c.created_at.0,
            expires_at_ms: c.expires_at.0,
            sharing_policy: sharing_to_u8(c.sharing_policy),
            authentication: auth_to_u8(c.authentication),
            local: c.local,
        }
    }

    fn into_candidate(self) -> Option<PeerCandidate> {
        Some(PeerCandidate {
            candidate_id: self.candidate_id,
            carrier_type: self.carrier_type,
            connection_hint: self.connection_hint,
            source: source_from_u8(self.source)?,
            created_at: Instant(self.created_at_ms),
            expires_at: Instant(self.expires_at_ms),
            sharing_policy: sharing_from_u8(self.sharing_policy)?,
            authentication: auth_from_u8(self.authentication)?,
            local: self.local,
        })
    }
}

fn source_to_u8(source: CandidateSource) -> u8 {
    match source {
        CandidateSource::Static => 0,
        CandidateSource::LocalDiscovery => 1,
        CandidateSource::PeerHint => 2,
        CandidateSource::Invitation => 3,
        CandidateSource::Bootstrap => 4,
        CandidateSource::Application => 5,
        CandidateSource::CarrierNative => 6,
    }
}

fn source_from_u8(value: u8) -> Option<CandidateSource> {
    match value {
        0 => Some(CandidateSource::Static),
        1 => Some(CandidateSource::LocalDiscovery),
        2 => Some(CandidateSource::PeerHint),
        3 => Some(CandidateSource::Invitation),
        4 => Some(CandidateSource::Bootstrap),
        5 => Some(CandidateSource::Application),
        6 => Some(CandidateSource::CarrierNative),
        _ => None,
    }
}

fn sharing_to_u8(policy: SharingPolicy) -> u8 {
    match policy {
        SharingPolicy::LocalUseOnly => 0,
        SharingPolicy::ShareSelected => 1,
        SharingPolicy::ShareLocalScope => 2,
        SharingPolicy::ShareGeneral => 3,
        SharingPolicy::DoNotReshare => 4,
    }
}

fn sharing_from_u8(value: u8) -> Option<SharingPolicy> {
    match value {
        0 => Some(SharingPolicy::LocalUseOnly),
        1 => Some(SharingPolicy::ShareSelected),
        2 => Some(SharingPolicy::ShareLocalScope),
        3 => Some(SharingPolicy::ShareGeneral),
        4 => Some(SharingPolicy::DoNotReshare),
        _ => None,
    }
}

fn auth_to_u8(auth: CandidateAuth) -> u8 {
    match auth {
        CandidateAuth::Unauthenticated => 0,
        CandidateAuth::CarrierAuthenticated => 1,
        CandidateAuth::IntroductionAuthenticated => 2,
        CandidateAuth::InvitationAuthenticated => 3,
        CandidateAuth::PreviousSessionBound => 4,
        CandidateAuth::SignedBootstrap => 5,
    }
}

fn auth_from_u8(value: u8) -> Option<CandidateAuth> {
    match value {
        0 => Some(CandidateAuth::Unauthenticated),
        1 => Some(CandidateAuth::CarrierAuthenticated),
        2 => Some(CandidateAuth::IntroductionAuthenticated),
        3 => Some(CandidateAuth::InvitationAuthenticated),
        4 => Some(CandidateAuth::PreviousSessionBound),
        5 => Some(CandidateAuth::SignedBootstrap),
        _ => None,
    }
}

fn candidate_key(id: u64) -> [u8; 8] {
    id.to_be_bytes()
}

fn save_candidate(store: &dyn Store, candidate: &PeerCandidate) -> Result<(), StoreError> {
    let json = CandidateJson::from_candidate(candidate);
    let value = serde_json::to_vec(&json).map_err(|_| StoreError::Serialization)?;
    store.put(
        Namespace::Peer,
        &candidate_key(candidate.candidate_id),
        &value,
    )
}

/// Loads every persisted candidate, skipping corrupt or unparsable records
/// with a log line (never fatal).
fn load_candidates(store: &dyn Store) -> Vec<PeerCandidate> {
    let mut out = Vec::new();
    let entries = match store.scan(Namespace::Peer) {
        Ok(entries) => entries,
        Err(e) => {
            log::error!("[discovery] failed to scan persisted candidates: {e:?}");
            return out;
        }
    };
    for entry in entries {
        match serde_json::from_slice::<CandidateJson>(&entry.value) {
            Ok(json) => match json.into_candidate() {
                Some(candidate) => out.push(candidate),
                None => log::warn!(
                    "[discovery] skipping candidate with unknown enum discriminant (key {})",
                    u64::from_be_bytes(entry.key.try_into().unwrap_or([0; 8]))
                ),
            },
            Err(e) => log::warn!("[discovery] skipping corrupt candidate record: {e}"),
        }
    }
    out
}

/// Process-local discovery state, optionally bound to the node database for
/// candidate persistence.
pub struct DiscoveryService {
    pub candidates: CandidateTable,
    /// Optional provider coordinator. The composition root can register
    /// providers without coupling candidate persistence to provider-owned
    /// resources; failures and diversity are reported per refresh.
    pub providers: ProviderManager,
    store: Option<Arc<SqliteStore>>,
}

impl std::fmt::Debug for DiscoveryService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryService")
            .field("candidates", &self.candidates)
            .field("providers", &self.providers)
            .field("store_attached", &self.store.is_some())
            .finish()
    }
}

#[allow(dead_code)] // record_candidate/build_hint wired to PEER_HINT loop in Phase 12
impl DiscoveryService {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            candidates: CandidateTable::new(cap),
            providers: ProviderManager::new(cap),
            store: None,
        }
    }

    /// Registers a discovery provider for lifecycle-managed refreshes.
    pub fn register_provider(
        &mut self,
        provider: Box<dyn umc_discovery::provider::DiscoveryProvider>,
    ) -> usize {
        self.providers.register(provider)
    }

    /// Starts all registered providers and returns per-provider diagnostics.
    pub fn start_providers(&mut self) -> Vec<ProviderReport> {
        self.providers.start_all()
    }

    /// Stops all registered providers and returns per-provider diagnostics.
    pub fn stop_providers(&mut self) -> Vec<ProviderReport> {
        self.providers.stop_all()
    }

    /// Refreshes registered providers, mirrors accepted candidates into the
    /// service table, and persists them through the normal candidate path.
    #[must_use]
    pub fn refresh_providers(&mut self, now: Instant) -> RefreshReport {
        let report = self.providers.refresh(now);
        for candidate in self.providers.candidates() {
            if let Err(error) = self.record_candidate(candidate, now) {
                log::warn!("[discovery] provider candidate was not mirrored: {error:?}");
            }
        }
        report
    }

    /// Attaches the node database so recorded candidates persist
    /// (storage.md §16.4).
    pub fn attach_store(&mut self, store: Arc<SqliteStore>) {
        self.store = Some(store);
    }

    /// Verifies and admits a signed bootstrap bundle as candidates. The
    /// bundle issuer authenticates the source only; endpoint identity is
    /// still established by the subsequent handshake.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapError`] when the bundle or its issuer is invalid.
    pub fn apply_bootstrap_bundle(
        &mut self,
        bundle: &BootstrapBundle,
        issuer_key: &IdentityPublicKey,
        now: Instant,
    ) -> Result<usize, BootstrapError> {
        let candidates = bundle.verify(issuer_key, now.0)?;
        let mut accepted = 0;
        for candidate in candidates {
            let id = candidate.candidate_id;
            self.candidates
                .upsert(candidate, now)
                .map_err(|_| BootstrapError::TableFull)?;
            if let Some(store) = &self.store {
                if let Some(stored) = self.candidates.get(id) {
                    if let Err(error) = save_candidate(store.as_ref(), stored) {
                        log::warn!(
                            "[discovery] failed to persist bootstrap candidate {id}: {error:?}"
                        );
                    }
                }
            }
            accepted += 1;
        }
        Ok(accepted)
    }

    /// Loads persisted candidates back into the table (storage.md §16.4):
    /// hints survive restart; records already expired by load time are
    /// dropped, and the table's upsert merge preserves sharing policy.
    pub fn restore_candidates(&mut self, store: &dyn Store, now: Instant) {
        for candidate in load_candidates(store) {
            if candidate.is_expired(now) {
                continue;
            }
            if let Err(e) = self.candidates.upsert(candidate, now) {
                log::warn!("[discovery] candidate table full during restore: {e:?}");
                break;
            }
        }
    }

    /// Record or refresh a candidate (discovery.md §8.1, §17.1). Successful
    /// records also persist; a persistence failure is logged and never fails
    /// the in-memory update.
    ///
    /// # Errors
    ///
    /// Returns [`TableError::Full`] when the table is at capacity.
    pub fn record_candidate(
        &mut self,
        candidate: PeerCandidate,
        now: Instant,
    ) -> Result<(), TableError> {
        let id = candidate.candidate_id;
        self.candidates.upsert(candidate, now)?;
        if let Some(store) = &self.store {
            if let Some(stored) = self.candidates.get(id) {
                if let Err(e) = save_candidate(store.as_ref(), stored) {
                    log::error!("[discovery] failed to persist candidate {id}: {e:?}");
                }
            }
        }
        Ok(())
    }

    /// Advertise this node's explicitly configured public endpoints. These
    /// candidates are shareable through `PEER_HINT`, so every connected node can
    /// become a bootstrap contact without treating the original seed as a
    /// permanent authority.
    pub fn record_advertised_endpoints(
        &mut self,
        endpoint_id: &[u8; 32],
        endpoints: &[crate::config::AdvertisedEndpointConfig],
        now: Instant,
    ) {
        for endpoint in endpoints {
            let mut hasher = Blake2s256::new();
            hasher.update(b"UMP-ADVERTISED-CANDIDATE-v1");
            hasher.update(endpoint_id);
            hasher.update(endpoint.carrier.as_bytes());
            hasher.update(endpoint.address.as_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            let mut id = [0u8; 8];
            id.copy_from_slice(&digest[..8]);
            let candidate = PeerCandidate {
                candidate_id: u64::from_be_bytes(id),
                carrier_type: endpoint.carrier.clone(),
                connection_hint: endpoint.address.as_bytes().to_vec(),
                source: CandidateSource::Application,
                created_at: now,
                expires_at: now + umc_types::runtime::Duration::from_millis(
                    umc_discovery::provider::MAX_CANDIDATE_LIFETIME_MS,
                ),
                sharing_policy: SharingPolicy::ShareGeneral,
                authentication: CandidateAuth::CarrierAuthenticated,
                local: true,
            };
            if let Err(error) = self.record_candidate(candidate, now) {
                log::warn!("[discovery] advertised endpoint rejected: {error:?}");
            }
        }
    }

    /// A snapshot of the live candidates.
    #[must_use]
    pub fn candidates(&self) -> Vec<PeerCandidate> {
        self.candidates.iter().cloned().collect()
    }

    /// Build a `PEER_HINT` frame from the most shareable candidates, capped
    /// at `maximum` (and the wire limit of 32 entries).
    #[must_use]
    pub fn build_hint(&self, maximum: usize, now: Instant) -> Option<PeerHintFrame> {
        self.build_hint_with_mesh_secret(maximum, now, None)
    }

    /// Build a hint frame with an optional local-mesh membership secret.
    #[must_use]
    pub fn build_hint_with_mesh_secret(
        &self,
        maximum: usize,
        now: Instant,
        mesh_secret: Option<&[u8]>,
    ) -> Option<PeerHintFrame> {
        let snapshot = self.candidates();
        let selected = select_for_share(&snapshot, maximum, now);
        if selected.is_empty() {
            return None;
        }
        if mesh_secret.is_some() {
            build_peer_hint_with_mesh_secret(&selected, mesh_secret).ok()
        } else {
            build_peer_hint(&selected).ok()
        }
    }

    /// Apply a peer's hint frame and persist accepted candidates. The pure
    /// discovery helper validates the whole frame before mutating the table;
    /// persistence happens only after that validation succeeds.
    pub fn apply_received_hints(
        &mut self,
        frame: &PeerHintFrame,
        sender: &[u8],
        now: Instant,
    ) -> Result<usize, HintError> {
        self.apply_received_hints_with_mesh_secret(frame, sender, now, None)
    }

    /// Apply a hint frame with an optional local-mesh membership secret.
    pub fn apply_received_hints_with_mesh_secret(
        &mut self,
        frame: &PeerHintFrame,
        sender: &[u8],
        now: Instant,
        mesh_secret: Option<&[u8]>,
    ) -> Result<usize, HintError> {
        let accepted = if mesh_secret.is_some() {
            apply_received_hints_with_mesh_secret(
                frame,
                sender,
                now,
                &mut self.candidates,
                mesh_secret,
            )?
        } else {
            apply_received_hints(frame, sender, now, &mut self.candidates)?
        };
        if accepted > 0 {
            if let Some(store) = &self.store {
                for candidate in self.candidates() {
                    if let Err(error) = save_candidate(store.as_ref(), &candidate) {
                        log::warn!(
                            "[discovery] failed to persist hinted candidate {}: {error:?}",
                            candidate.candidate_id
                        );
                    }
                }
            }
        }
        Ok(accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_crypto::signatures::IdentityKeyPair;
    use umc_discovery::bootstrap::{BootstrapBundle, BootstrapCandidate};
    use umc_discovery::provider::{CandidateAuth, CandidateSource, SharingPolicy};

    fn candidate(id: u64, policy: SharingPolicy, expires_ms: u64) -> PeerCandidate {
        PeerCandidate {
            candidate_id: id,
            carrier_type: "ump.udp/1".into(),
            connection_hint: vec![1, 2, 3],
            source: CandidateSource::PeerHint,
            created_at: Instant(0),
            expires_at: Instant(expires_ms),
            sharing_policy: policy,
            authentication: CandidateAuth::Unauthenticated,
            local: false,
        }
    }

    #[test]
    fn advertised_endpoints_are_shareable_and_stable() {
        let endpoints = vec![crate::config::AdvertisedEndpointConfig {
            carrier: "ump.tcp/1".into(),
            address: "node.example:9001".into(),
        }];
        let mut service = DiscoveryService::new(10);
        service.record_advertised_endpoints(&[7u8; 32], &endpoints, Instant(100));
        let first = service.candidates();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].source, CandidateSource::Application);
        assert_eq!(first[0].sharing_policy, SharingPolicy::ShareGeneral);
        assert_eq!(first[0].connection_hint, b"node.example:9001");
        service.record_advertised_endpoints(&[7u8; 32], &endpoints, Instant(200));
        assert_eq!(service.candidates().len(), 1);
        assert_ne!(first[0].candidate_id, 0);
    }

    #[test]
    fn record_and_snapshot_round_trip() {
        let mut service = DiscoveryService::new(10);
        service
            .record_candidate(
                candidate(7, SharingPolicy::ShareGeneral, u64::MAX),
                Instant(0),
            )
            .unwrap();
        let snapshot = service.candidates();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].candidate_id, 7);
        // Re-recording the same id refreshes, not duplicates.
        service
            .record_candidate(
                candidate(7, SharingPolicy::ShareGeneral, u64::MAX),
                Instant(1),
            )
            .unwrap();
        assert_eq!(service.candidates().len(), 1);
    }

    #[test]
    fn hint_building_caps_at_maximum() {
        let mut service = DiscoveryService::new(100);
        for id in 0..10 {
            service
                .record_candidate(
                    candidate(id, SharingPolicy::ShareGeneral, u64::MAX),
                    Instant(0),
                )
                .unwrap();
        }
        let hint = service.build_hint(3, Instant(0)).expect("hint");
        assert_eq!(hint.entries.len(), 3);
        assert!(hint.entries.iter().all(|e| e.public));
    }

    #[test]
    fn hint_excludes_private_and_expired() {
        let mut service = DiscoveryService::new(100);
        service
            .record_candidate(
                candidate(1, SharingPolicy::LocalUseOnly, u64::MAX),
                Instant(0),
            )
            .unwrap();
        service
            .record_candidate(
                candidate(2, SharingPolicy::DoNotReshare, u64::MAX),
                Instant(0),
            )
            .unwrap();
        service
            .record_candidate(candidate(3, SharingPolicy::ShareGeneral, 0), Instant(0))
            .unwrap();
        let hint = service.build_hint(10, Instant(0));
        assert!(hint.is_none());
        service
            .record_candidate(
                candidate(4, SharingPolicy::ShareGeneral, u64::MAX),
                Instant(0),
            )
            .unwrap();
        let hint = service.build_hint(10, Instant(0)).expect("hint");
        assert_eq!(hint.entries.len(), 1);
        assert_eq!(hint.entries[0].temporary_peer_id, 4u64.to_be_bytes());
    }

    #[test]
    fn signed_bootstrap_bundle_is_verified_before_admission() {
        let issuer = IdentityKeyPair::generate();
        let bundle = BootstrapBundle::sign(
            &issuer,
            10,
            100,
            vec![BootstrapCandidate {
                candidate_id: 11,
                carrier_type: "ump.tcp/1".into(),
                connection_hint: b"127.0.0.1:9000".to_vec(),
                expires_at_ms: 90,
                sharing_policy: SharingPolicy::ShareGeneral,
            }],
        )
        .unwrap();
        let mut service = DiscoveryService::new(10);
        assert_eq!(
            service
                .apply_bootstrap_bundle(&bundle, &issuer.public(), Instant(50))
                .unwrap(),
            1
        );
        let admitted = service.candidates.get(11).unwrap();
        assert_eq!(admitted.source, CandidateSource::Bootstrap);
        assert_eq!(admitted.authentication, CandidateAuth::SignedBootstrap);
    }

    #[test]
    fn mesh_secret_hint_round_trip_requires_membership() {
        let secret = b"mesh-secret";
        let mut sender = DiscoveryService::new(10);
        sender
            .record_candidate(
                candidate(8, SharingPolicy::ShareGeneral, u64::MAX),
                Instant(0),
            )
            .unwrap();
        let frame = sender
            .build_hint_with_mesh_secret(10, Instant(0), Some(secret))
            .expect("mesh hint");
        let mut receiver = DiscoveryService::new(10);
        assert_eq!(
            receiver.apply_received_hints_with_mesh_secret(
                &frame,
                b"peer-a",
                Instant(0),
                Some(secret)
            ),
            Ok(1)
        );
        assert_eq!(
            DiscoveryService::new(10).apply_received_hints_with_mesh_secret(
                &frame,
                b"peer-a",
                Instant(0),
                None
            ),
            Err(HintError::MeshAuthentication)
        );
    }

    fn temp_store() -> std::sync::Arc<umc_storage::sqlite::SqliteStore> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("umcd-discovery-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("candidates-{c}.db"));
        std::sync::Arc::new(umc_storage::sqlite::SqliteStore::open(&path).unwrap())
    }

    #[test]
    fn candidates_persist_and_restore_across_restart() {
        let store = temp_store();
        let mut service = DiscoveryService::new(10);
        service.attach_store(store.clone());
        service
            .record_candidate(
                candidate(42, SharingPolicy::ShareGeneral, u64::MAX),
                Instant(0),
            )
            .unwrap();
        drop(service);

        // A new service over the same store restores the candidate table
        // (storage.md §16.4): operational hints survive restart.
        let mut restarted = DiscoveryService::new(10);
        restarted.restore_candidates(store.as_ref(), Instant(1000));
        let snapshot = restarted.candidates();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].candidate_id, 42);
        assert_eq!(
            snapshot[0].sharing_policy,
            SharingPolicy::ShareGeneral,
            "sharing policy is preserved (storage.md §16.4)"
        );
    }
}
