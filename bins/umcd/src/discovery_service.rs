//! Discovery service (discovery.md §5-13): the daemon's in-memory candidate
//! table and `PEER_HINT` builder, wired into the runtime state. Persistence
//! lands in Phase 12; the table is process-local for now.
use umc_discovery::hints::{build_peer_hint, select_for_share};
use umc_discovery::provider::PeerCandidate;
use umc_discovery::table::{CandidateTable, TableError};
use umc_types::runtime::Instant;
use umc_wire::frames::misc::PeerHintFrame;

/// Default candidate capacity (discovery.md §6).
#[allow(dead_code)] // used by daemon config wiring in Phase 12
pub const DEFAULT_TABLE_CAP: usize = umc_discovery::table::DEFAULT_TABLE_CAP;

/// Process-local discovery state.
#[derive(Debug)]
pub struct DiscoveryService {
    pub candidates: CandidateTable,
}

#[allow(dead_code)] // record_candidate/build_hint wired to PEER_HINT loop in Phase 12
impl DiscoveryService {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            candidates: CandidateTable::new(cap),
        }
    }

    /// Record or refresh a candidate (discovery.md §8.1, §17.1).
    ///
    /// # Errors
    ///
    /// Returns [`TableError::Full`] when the table is at capacity.
    pub fn record_candidate(
        &mut self,
        candidate: PeerCandidate,
        now: Instant,
    ) -> Result<(), TableError> {
        self.candidates.upsert(candidate, now)
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
}
