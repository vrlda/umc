//! Discovery service (discovery.md §5-13): the daemon's in-memory candidate
//! table and `PEER_HINT` builder, wired into the runtime state. Candidates
//! persist to the node database under the peer namespace (storage.md §16.4);
//! after a restart the table is restored so operational hints survive.
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use umc_discovery::hints::{apply_received_hints, build_peer_hint, select_for_share, HintError};
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
    }
}

fn auth_from_u8(value: u8) -> Option<CandidateAuth> {
    match value {
        0 => Some(CandidateAuth::Unauthenticated),
        1 => Some(CandidateAuth::CarrierAuthenticated),
        2 => Some(CandidateAuth::IntroductionAuthenticated),
        3 => Some(CandidateAuth::InvitationAuthenticated),
        4 => Some(CandidateAuth::PreviousSessionBound),
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
    store: Option<Arc<SqliteStore>>,
}

impl std::fmt::Debug for DiscoveryService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryService")
            .field("candidates", &self.candidates)
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
            store: None,
        }
    }

    /// Attaches the node database so recorded candidates persist
    /// (storage.md §16.4).
    pub fn attach_store(&mut self, store: Arc<SqliteStore>) {
        self.store = Some(store);
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

    /// A snapshot of the live candidates.
    #[must_use]
    pub fn candidates(&self) -> Vec<PeerCandidate> {
        self.candidates.iter().cloned().collect()
    }

    /// Build a `PEER_HINT` frame from the most shareable candidates, capped
    /// at `maximum` (and the wire limit of 32 entries).
    #[must_use]
    pub fn build_hint(&self, maximum: usize, now: Instant) -> Option<PeerHintFrame> {
        let snapshot = self.candidates();
        let selected = select_for_share(&snapshot, maximum, now);
        if selected.is_empty() {
            return None;
        }
        build_peer_hint(&selected).ok()
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
        let accepted = apply_received_hints(frame, sender, now, &mut self.candidates)?;
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
