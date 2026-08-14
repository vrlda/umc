//! Discovery service (discovery.md §5-13): the daemon's in-memory candidate
//! table and `PEER_HINT` builder, wired into the runtime state. Candidates
//! persist to the node database under the peer namespace (storage.md §16.4);
//! after a restart the table is restored so operational hints survive.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use blake2::{Blake2s256, Digest};
use umc_crypto::signatures::{IdentityKeyPair, IdentityPublicKey};
use umc_discovery::bootstrap::{BootstrapBundle, BootstrapError};
use umc_discovery::dht::{DhtRecord, DhtTable, RECORD_LIFETIME_MS};
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
use umc_wire::frames::misc::{PeerHintFrame, ServiceHintFrame};

/// Default candidate capacity (discovery.md §6).
#[allow(dead_code)] // used by daemon config wiring in Phase 12
pub const DEFAULT_TABLE_CAP: usize = umc_discovery::table::DEFAULT_TABLE_CAP;
pub const MAX_SERVICE_HINTS: usize = 64;
/// Aggregate remote-hint cap across all authenticated peers. Per-peer caps
/// alone would still permit an attacker to consume memory by opening many
/// sessions and publishing one bounded hint on each.
pub const MAX_REMOTE_SERVICE_HINTS: usize = 1_024;
pub const MAX_SERVICE_HINT_LIFETIME_MS: u64 = 24 * 60 * 60 * 1_000;

/// An opaque application service advertisement received over an authenticated
/// session. The daemon indexes protocol ids but never interprets metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceHintRecord {
    pub peer_endpoint_id: [u8; 32],
    pub protocol_id: Vec<u8>,
    pub endpoint_hint: Vec<u8>,
    pub metadata: Vec<u8>,
    pub expiration_time: u64,
    pub signature: Vec<u8>,
    pub public: bool,
}

fn service_hint_message(
    protocol_id: &[u8],
    endpoint_hint: &[u8],
    metadata: &[u8],
    expiration_time: u64,
) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMP-SERVICE-HINT-v1");
    hasher.update(u16::try_from(protocol_id.len()).unwrap_or(u16::MAX).to_be_bytes());
    hasher.update(protocol_id);
    hasher.update(u16::try_from(endpoint_hint.len()).unwrap_or(u16::MAX).to_be_bytes());
    hasher.update(endpoint_hint);
    hasher.update(u16::try_from(metadata.len()).unwrap_or(u16::MAX).to_be_bytes());
    hasher.update(metadata);
    hasher.update(expiration_time.to_be_bytes());
    hasher.finalize().into()
}

fn validate_service_hint_fields(
    protocol_id: &[u8],
    endpoint_hint: &[u8],
    metadata: &[u8],
    expiration_time: u64,
    now: Instant,
) -> Result<(), String> {
    if protocol_id.is_empty() || protocol_id.len() > umc_wire::frames::misc::MAX_PROTOCOL_ID {
        return Err("service protocol id exceeds bounds".into());
    }
    if endpoint_hint.len() > umc_wire::frames::misc::MAX_ENDPOINT_HINT
        || metadata.len() > umc_wire::frames::misc::MAX_SERVICE_METADATA
    {
        return Err("service hint field exceeds bounds".into());
    }
    if expiration_time <= now.0
        || expiration_time.saturating_sub(now.0) > MAX_SERVICE_HINT_LIFETIME_MS
    {
        return Err("service hint expiration is outside the bounded lifetime".into());
    }
    Ok(())
}

/// Wire form of a persisted candidate (storage.md §16.4): `PeerCandidate`
/// does not derive `serde`, so this mirror is what gets serialized. Enum
/// discriminants are stable: they follow the variant order declared in
/// `umc-discovery` `provider.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CandidateJson {
    #[serde(default)]
    realm_marker: Vec<u8>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DhtRecordJson {
    endpoint_id: Vec<u8>,
    identity_public_key: Vec<u8>,
    carrier_type: String,
    connection_hint: Vec<u8>,
    expires_at_ms: u64,
    sequence: u64,
    signature: Vec<u8>,
}

impl DhtRecordJson {
    fn from_record(record: &DhtRecord) -> Self {
        Self {
            endpoint_id: record.endpoint_id.to_vec(),
            identity_public_key: record.identity_public_key.to_vec(),
            carrier_type: record.carrier_type.clone(),
            connection_hint: record.connection_hint.clone(),
            expires_at_ms: record.expires_at.0,
            sequence: record.sequence,
            signature: record.signature.to_vec(),
        }
    }

    fn into_record(self) -> Option<DhtRecord> {
        Some(DhtRecord {
            endpoint_id: self.endpoint_id.as_slice().try_into().ok()?,
            identity_public_key: self.identity_public_key.as_slice().try_into().ok()?,
            carrier_type: self.carrier_type,
            connection_hint: self.connection_hint,
            expires_at: Instant(self.expires_at_ms),
            sequence: self.sequence,
            signature: self.signature.as_slice().try_into().ok()?,
        })
    }
}

impl CandidateJson {
    fn from_candidate(c: &PeerCandidate, realm_marker: [u8; 32]) -> Self {
        Self {
            realm_marker: realm_marker.to_vec(),
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

fn save_candidate(
    store: &dyn Store,
    candidate: &PeerCandidate,
    realm_marker: [u8; 32],
) -> Result<(), StoreError> {
    let json = CandidateJson::from_candidate(candidate, realm_marker);
    let value = serde_json::to_vec(&json).map_err(|_| StoreError::Serialization)?;
    store.put(
        Namespace::Peer,
        &candidate_key(candidate.candidate_id),
        &value,
    )
}

fn dht_key(record: &DhtRecord, realm_marker: [u8; 32]) -> Vec<u8> {
    let mut key = b"DHT".to_vec();
    key.extend_from_slice(&realm_marker);
    key.extend_from_slice(&dht_candidate_id(record).to_be_bytes());
    key
}

fn save_dht_record(
    store: &dyn Store,
    record: &DhtRecord,
    realm_marker: [u8; 32],
) -> Result<(), StoreError> {
    let value = serde_json::to_vec(&DhtRecordJson::from_record(record))
        .map_err(|_| StoreError::Serialization)?;
    store.put(Namespace::Peer, &dht_key(record, realm_marker), &value)
}

/// Loads every persisted candidate, skipping corrupt or unparsable records
/// with a log line (never fatal).
fn load_candidates(store: &dyn Store, realm_marker: [u8; 32]) -> Vec<PeerCandidate> {
    let mut out = Vec::new();
    let entries = match store.scan(Namespace::Peer) {
        Ok(entries) => entries,
        Err(e) => {
            log::error!("[discovery] failed to scan persisted candidates: {e:?}");
            return out;
        }
    };
    for entry in entries {
        if entry.key.starts_with(b"DHT") {
            continue;
        }
        match serde_json::from_slice::<CandidateJson>(&entry.value) {
            Ok(json) => {
                if (json.realm_marker.is_empty()
                    && realm_marker != umc_handshake::xx::public_realm_marker())
                    || (!json.realm_marker.is_empty() && json.realm_marker != realm_marker)
                {
                    continue;
                }
                match json.into_candidate() {
                    Some(candidate) => out.push(candidate),
                    None => log::warn!(
                        "[discovery] skipping candidate with unknown enum discriminant (key {})",
                        u64::from_be_bytes(entry.key.try_into().unwrap_or([0; 8]))
                    ),
                }
            }
            Err(e) => log::warn!("[discovery] skipping corrupt candidate record: {e}"),
        }
    }
    out
}

fn load_dht_records(store: &dyn Store, realm_marker: [u8; 32]) -> Vec<DhtRecord> {
    let Ok(entries) = store.scan(Namespace::Peer) else {
        return Vec::new();
    };
    entries
        .into_iter()
        .filter(|entry| {
            if !entry.key.starts_with(b"DHT") {
                return false;
            }
            // Pre-realm public records used the short `DHT || id` key. Keep
            // reading those only in the public realm; private realms accept
            // exclusively their namespaced records.
            (realm_marker == umc_handshake::xx::public_realm_marker() && entry.key.len() == 11)
                || entry.key.get(3..35) == Some(realm_marker.as_slice())
        })
        .filter_map(|entry| {
            serde_json::from_slice::<DhtRecordJson>(&entry.value)
                .ok()
                .and_then(DhtRecordJson::into_record)
        })
        .collect()
}

/// Process-local discovery state, optionally bound to the node database for
/// candidate persistence.
pub struct DiscoveryService {
    pub candidates: CandidateTable,
    pub dht: DhtTable,
    /// Optional provider coordinator. The composition root can register
    /// providers without coupling candidate persistence to provider-owned
    /// resources; failures and diversity are reported per refresh.
    pub providers: ProviderManager,
    store: Option<Arc<SqliteStore>>,
    realm_marker: [u8; 32],
    local_service_hints: Vec<ServiceHintRecord>,
    remote_service_hints: HashMap<[u8; 32], Vec<ServiceHintRecord>>,
}

impl std::fmt::Debug for DiscoveryService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryService")
            .field("candidates", &self.candidates)
            .field("dht", &self.dht)
            .field("providers", &self.providers)
            .field("store_attached", &self.store.is_some())
            .field("realm_marker", &"[redacted]")
            .field("local_service_hints", &self.local_service_hints.len())
            .field("remote_service_hint_peers", &self.remote_service_hints.len())
            .finish()
    }
}

#[allow(dead_code)] // record_candidate/build_hint wired to PEER_HINT loop in Phase 12
impl DiscoveryService {
    fn trim_remote_service_hints(&mut self) {
        let mut total = self
            .remote_service_hints
            .values()
            .map(Vec::len)
            .sum::<usize>();
        while total > MAX_REMOTE_SERVICE_HINTS {
            let Some((peer, hints)) = self
                .remote_service_hints
                .iter_mut()
                .find(|(_, hints)| !hints.is_empty())
            else {
                break;
            };
            hints.remove(0);
            total = total.saturating_sub(1);
            if hints.is_empty() {
                // Removing the empty peer entry keeps the map itself bounded
                // by active hint owners rather than historical sessions.
                let peer = *peer;
                self.remote_service_hints.remove(&peer);
            }
        }
    }

    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self::new_with_realm(cap, umc_handshake::xx::public_realm_marker())
    }

    #[must_use]
    pub fn new_with_realm(cap: usize, realm_marker: [u8; 32]) -> Self {
        Self {
            candidates: CandidateTable::new(cap),
            dht: DhtTable::new(),
            providers: ProviderManager::new(cap),
            store: None,
            realm_marker,
            local_service_hints: Vec::new(),
            remote_service_hints: HashMap::new(),
        }
    }

    /// Publishes one locally signed, opaque application service hint.
    ///
    /// # Errors
    ///
    /// Returns an error when a field or lifetime exceeds the protocol bound.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_service_hint(
        &mut self,
        identity: &IdentityKeyPair,
        protocol_id: Vec<u8>,
        endpoint_hint: Vec<u8>,
        metadata: Vec<u8>,
        expiration_time: u64,
        public: bool,
        now: Instant,
    ) -> Result<ServiceHintRecord, String> {
        validate_service_hint_fields(
            &protocol_id,
            &endpoint_hint,
            &metadata,
            expiration_time,
            now,
        )?;
        let signature = identity
            .sign(&service_hint_message(
                &protocol_id,
                &endpoint_hint,
                &metadata,
                expiration_time,
            ))
            .to_vec();
        let record = ServiceHintRecord {
            peer_endpoint_id: umc_handshake::identity::endpoint_id(&identity.public()),
            protocol_id,
            endpoint_hint,
            metadata,
            expiration_time,
            signature,
            public,
        };
        self.local_service_hints.retain(|existing| {
            !(existing.protocol_id == record.protocol_id
                && existing.endpoint_hint == record.endpoint_hint)
        });
        if self.local_service_hints.len() >= MAX_SERVICE_HINTS {
            self.local_service_hints.remove(0);
        }
        self.local_service_hints.push(record.clone());
        Ok(record)
    }

    /// Accepts a signed hint from an authenticated peer. The transport
    /// authenticates the session, while the identity signature prevents a
    /// stale or cross-session relay from becoming the authority for content.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, expired, unauthenticated, or
    /// conflicting hints.
    pub fn accept_service_hint(
        &mut self,
        peer_endpoint_id: [u8; 32],
        peer_identity_public_key: Option<&[u8; 32]>,
        frame: &ServiceHintFrame,
        now: Instant,
    ) -> Result<(), String> {
        validate_service_hint_fields(
            &frame.protocol_id,
            &frame.endpoint_hint,
            &frame.metadata,
            frame.expiration_time,
            now,
        )?;
        if frame.signature.len() != 64 {
            return Err("service hint signature length is invalid".into());
        }
        let Some(peer_identity_public_key) = peer_identity_public_key else {
            return Err("service hint signer key is unavailable".into());
        };
        let public_key = IdentityPublicKey(*peer_identity_public_key);
        if umc_handshake::identity::endpoint_id(&public_key) != peer_endpoint_id
            || !public_key.verify(
                &service_hint_message(
                    &frame.protocol_id,
                    &frame.endpoint_hint,
                    &frame.metadata,
                    frame.expiration_time,
                ),
                frame.signature.as_slice(),
            )
        {
            return Err("service hint signature verification failed".into());
        }
        let records = self.remote_service_hints.entry(peer_endpoint_id).or_default();
        records.retain(|existing| {
            !(existing.protocol_id == frame.protocol_id
                && existing.endpoint_hint == frame.endpoint_hint)
        });
        if records.len() >= MAX_SERVICE_HINTS {
            records.remove(0);
        }
        records.push(ServiceHintRecord {
            peer_endpoint_id,
            protocol_id: frame.protocol_id.clone(),
            endpoint_hint: frame.endpoint_hint.clone(),
            metadata: frame.metadata.clone(),
            expiration_time: frame.expiration_time,
            signature: frame.signature.clone(),
            public: true,
        });
        self.trim_remote_service_hints();
        Ok(())
    }

    /// Returns active local and remote hints, optionally restricted to one
    /// application protocol identifier. Expired records are removed eagerly.
    pub fn service_hints(
        &mut self,
        protocol_id: Option<&[u8]>,
        now: Instant,
    ) -> Vec<ServiceHintRecord> {
        self.local_service_hints
            .retain(|hint| hint.expiration_time > now.0);
        self.remote_service_hints.retain(|_, hints| {
            hints.retain(|hint| hint.expiration_time > now.0);
            !hints.is_empty()
        });
        let mut records = self
            .local_service_hints
            .iter()
            .filter(|hint| hint.public)
            .cloned()
            .collect::<Vec<_>>();
        records.extend(
            self.remote_service_hints
                .values()
                .flat_map(|hints| hints.iter().filter(|hint| hint.public).cloned()),
        );
        if let Some(protocol_id) = protocol_id {
            records.retain(|hint| hint.protocol_id.as_slice() == protocol_id);
        }
        records
    }

    /// Builds the public local hints to carry in the next protected packet.
    pub fn service_hint_frames(&mut self, now: Instant) -> Vec<ServiceHintFrame> {
        self.local_service_hints
            .retain(|hint| hint.expiration_time > now.0);
        self.local_service_hints
            .iter()
            .filter(|hint| hint.public)
            .map(|hint| ServiceHintFrame {
                protocol_id: hint.protocol_id.clone(),
                endpoint_hint: hint.endpoint_hint.clone(),
                metadata: hint.metadata.clone(),
                expiration_time: hint.expiration_time,
                signature: hint.signature.clone(),
            })
            .collect()
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
                    if let Err(error) = save_candidate(store.as_ref(), stored, self.realm_marker) {
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
        for candidate in load_candidates(store, self.realm_marker) {
            if candidate.is_expired(now) {
                continue;
            }
            if let Err(e) = self.candidates.upsert(candidate, now) {
                log::warn!("[discovery] candidate table full during restore: {e:?}");
                break;
            }
        }
        for record in load_dht_records(store, self.realm_marker) {
            let _ = self.dht.insert(record, now);
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
                if let Err(e) = save_candidate(store.as_ref(), stored, self.realm_marker) {
                    log::error!("[discovery] failed to persist candidate {id}: {e:?}");
                }
            }
        }
        Ok(())
    }

    /// Apply bounded candidates and removals emitted by an external carrier.
    /// Carrier-native source attribution is preserved; malformed/expired
    /// entries are rejected by the same table and lifetime rules as built-ins.
    pub fn apply_external_batch(
        &mut self,
        batch: &umc_plugin::runtime::DiscoveryBatch,
        now: Instant,
    ) -> usize {
        for candidate_id in &batch.removed {
            self.remove_candidate(*candidate_id);
        }
        let mut admitted = 0;
        for candidate in batch.candidates.iter().cloned() {
            if candidate.is_expired(now) {
                continue;
            }
            if self.record_candidate(candidate, now).is_ok() {
                admitted += 1;
            }
        }
        admitted
    }

    /// Remove candidate and its persisted peer record.
    pub fn remove_candidate(&mut self, candidate_id: u64) {
        self.candidates.remove(candidate_id);
        if let Some(store) = &self.store {
            if let Err(error) = store.delete(Namespace::Peer, &candidate_key(candidate_id)) {
                log::warn!("[discovery] failed to remove candidate {candidate_id}: {error:?}");
            }
        }
    }

    /// Advertise this node's explicitly configured public endpoints. These
    /// candidates are shareable through `PEER_HINT`, so every connected node can
    /// become a bootstrap contact without treating the original seed as a
    /// permanent authority.
    pub fn record_advertised_endpoints(
        &mut self,
        identity: &umc_crypto::signatures::IdentityKeyPair,
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
            let dht_record = DhtRecord::sign(
                identity,
                endpoint.carrier.clone(),
                endpoint.address.as_bytes().to_vec(),
                now + umc_types::runtime::Duration::from_millis(RECORD_LIFETIME_MS),
                1,
            );
            let _ = self.dht.insert(dht_record, now);
            if let Some(store) = &self.store {
                if let Some(record) = self
                    .dht
                    .closest(endpoint_id, 1, now)
                    .into_iter()
                    .find(|record| record.connection_hint == endpoint.address.as_bytes())
                {
                    let _ = save_dht_record(store.as_ref(), &record, self.realm_marker);
                }
            }
            if let Err(error) = self.record_candidate(candidate, now) {
                log::warn!("[discovery] advertised endpoint rejected: {error:?}");
            }
        }
    }

    #[must_use]
    pub fn dht_exchange_frame(
        &self,
        target: &[u8; 32],
        now: Instant,
    ) -> Option<umc_wire::frames::misc::DhtLookupFrame> {
        let records = self
            .dht
            .closest(target, umc_wire::frames::misc::MAX_DHT_RECORDS, now)
            .into_iter()
            .map(dht_record_to_wire)
            .collect::<Vec<_>>();
        (!records.is_empty()).then(|| umc_wire::frames::misc::DhtLookupFrame {
            request_id: now.0,
            response: false,
            target_endpoint_id: target.to_vec(),
            records,
        })
    }

    pub fn apply_dht_frame(
        &mut self,
        frame: &umc_wire::frames::misc::DhtLookupFrame,
        now: Instant,
    ) -> usize {
        let mut accepted = 0;
        for wire in &frame.records {
            if wire.endpoint_id.len() != 32 || wire.identity_public_key.len() != 32 {
                continue;
            }
            let mut endpoint_id = [0u8; 32];
            endpoint_id.copy_from_slice(&wire.endpoint_id);
            let mut identity_public_key = [0u8; 32];
            identity_public_key.copy_from_slice(&wire.identity_public_key);
            let Ok(signature) = wire.signature.as_slice().try_into() else {
                continue;
            };
            let record = DhtRecord {
                endpoint_id,
                identity_public_key,
                carrier_type: String::from_utf8_lossy(&wire.carrier_type).to_string(),
                connection_hint: wire.connection_hint.clone(),
                expires_at: Instant(wire.expiration_time),
                sequence: wire.sequence,
                signature,
            };
            if self.dht.insert(record.clone(), now) {
                accepted += 1;
                if let Some(store) = &self.store {
                    let _ = save_dht_record(store.as_ref(), &record, self.realm_marker);
                }
                let candidate = PeerCandidate {
                    candidate_id: dht_candidate_id(&record),
                    carrier_type: record.carrier_type,
                    connection_hint: record.connection_hint,
                    source: CandidateSource::CarrierNative,
                    created_at: now,
                    expires_at: record.expires_at,
                    sharing_policy: SharingPolicy::ShareGeneral,
                    authentication: CandidateAuth::CarrierAuthenticated,
                    local: false,
                };
                let _ = self.record_candidate(candidate, now);
            }
        }
        accepted
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
                    if let Err(error) = save_candidate(store.as_ref(), &candidate, self.realm_marker) {
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

fn dht_record_to_wire(record: DhtRecord) -> umc_wire::frames::misc::DhtRecordWire {
    umc_wire::frames::misc::DhtRecordWire {
        endpoint_id: record.endpoint_id.to_vec(),
        identity_public_key: record.identity_public_key.to_vec(),
        carrier_type: record.carrier_type.into_bytes(),
        connection_hint: record.connection_hint,
        expiration_time: record.expires_at.0,
        sequence: record.sequence,
        signature: record.signature.to_vec(),
    }
}

fn dht_candidate_id(record: &DhtRecord) -> u64 {
    let mut hasher = blake2::Blake2s256::new();
    hasher.update(b"UMP-DHT-CANDIDATE-v1");
    hasher.update(record.endpoint_id);
    hasher.update(record.carrier_type.as_bytes());
    hasher.update(&record.connection_hint);
    let digest: [u8; 32] = hasher.finalize().into();
    u64::from_be_bytes(digest[..8].try_into().unwrap_or([0; 8]))
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
        let identity = IdentityKeyPair::from_seed([7u8; 32]);
        service.record_advertised_endpoints(&identity, &[7u8; 32], &endpoints, Instant(100));
        let first = service.candidates();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].source, CandidateSource::Application);
        assert_eq!(first[0].sharing_policy, SharingPolicy::ShareGeneral);
        assert_eq!(first[0].connection_hint, b"node.example:9001");
        service.record_advertised_endpoints(&identity, &[7u8; 32], &endpoints, Instant(200));
        assert_eq!(service.candidates().len(), 1);
        assert_ne!(first[0].candidate_id, 0);
        assert_eq!(service.dht.len(), 1);
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

    #[test]
    fn service_hint_signing_exchange_is_bounded_and_authenticated() {
        let identity = IdentityKeyPair::from_seed([41u8; 32]);
        let peer_endpoint = umc_handshake::identity::endpoint_id(&identity.public());
        let mut sender = DiscoveryService::new(10);
        let published = sender
            .publish_service_hint(
                &identity,
                b"org.example.chat/1".to_vec(),
                b"endpoint-token".to_vec(),
                b"opaque".to_vec(),
                500,
                true,
                Instant(100),
            )
            .expect("publish");
        assert_eq!(published.peer_endpoint_id, peer_endpoint);
        let frame = sender.service_hint_frames(Instant(101)).pop().expect("frame");
        let mut receiver = DiscoveryService::new(10);
        receiver
            .accept_service_hint(peer_endpoint, Some(&identity.public().0), &frame, Instant(101))
            .expect("accept");
        assert_eq!(receiver.service_hints(Some(b"org.example.chat/1"), Instant(102)).len(), 1);

        let mut tampered = frame.clone();
        tampered.metadata[0] ^= 1;
        assert!(receiver
            .accept_service_hint(peer_endpoint, Some(&identity.public().0), &tampered, Instant(102))
            .is_err());
        assert!(receiver
            .accept_service_hint(peer_endpoint, None, &frame, Instant(102))
            .is_err());
    }

    #[test]
    fn remote_service_hints_have_an_aggregate_memory_cap() {
        let mut receiver = DiscoveryService::new(10);
        for seed in 0..(MAX_REMOTE_SERVICE_HINTS + 32) {
            let mut seed_bytes = [0u8; 32];
            seed_bytes[..8].copy_from_slice(&(seed as u64).to_be_bytes());
            let identity = IdentityKeyPair::from_seed(seed_bytes);
            let endpoint = umc_handshake::identity::endpoint_id(&identity.public());
            let mut sender = DiscoveryService::new(1);
            sender
                .publish_service_hint(
                    &identity,
                    b"org.example.cap/1".to_vec(),
                    seed.to_be_bytes().to_vec(),
                    Vec::new(),
                    500,
                    true,
                    Instant(100),
                )
                .expect("publish");
            let frame = sender
                .service_hint_frames(Instant(101))
                .pop()
                .expect("frame");
            receiver
                .accept_service_hint(endpoint, Some(&identity.public().0), &frame, Instant(101))
                .expect("accept");
        }
        let count = receiver
            .service_hints(Some(b"org.example.cap/1"), Instant(102))
            .len();
        assert!(count <= MAX_REMOTE_SERVICE_HINTS);
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

    #[test]
    fn signed_dht_records_persist_and_restore_across_restart() {
        let store = temp_store();
        let identity = IdentityKeyPair::from_seed([9u8; 32]);
        let endpoint = umc_handshake::identity::endpoint_id(&identity.public());
        let endpoints = vec![crate::config::AdvertisedEndpointConfig {
            carrier: "ump.tcp/1".into(),
            address: "node.example:9001".into(),
        }];
        let mut service = DiscoveryService::new(10);
        service.attach_store(store.clone());
        service.record_advertised_endpoints(&identity, &endpoint, &endpoints, Instant(1));
        assert_eq!(service.dht.len(), 1);
        drop(service);
        let mut restarted = DiscoveryService::new(10);
        restarted.restore_candidates(store.as_ref(), Instant(2));
        assert_eq!(restarted.dht.len(), 1);
        assert_eq!(restarted.dht.closest(&endpoint, 1, Instant(2)).len(), 1);
    }
}
