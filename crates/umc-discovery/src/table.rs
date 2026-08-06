//! Merged candidate table with source attribution (discovery.md §6-7, §17).
use crate::provider::PeerCandidate;
use std::collections::HashMap;
use umc_types::runtime::Instant;

pub const DEFAULT_TABLE_CAP: usize = 50_000;

#[derive(Debug, Clone)]
pub struct CandidateTable {
    entries: HashMap<u64, PeerCandidate>,
    cap: usize,
}

impl CandidateTable {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            entries: HashMap::new(),
            cap,
        }
    }

    /// Inserts or refreshes a candidate, preserving the strictest sharing
    /// policy and capping the lifetime (discovery.md §8.1, §17.1).
    ///
    /// # Errors
    ///
    /// Returns [`TableError::Full`] when the table is at capacity and no
    /// expired entry could be evicted to make room.
    pub fn upsert(&mut self, mut candidate: PeerCandidate, now: Instant) -> Result<(), TableError> {
        candidate.cap_lifetime(now);
        if let Some(existing) = self.entries.get(&candidate.candidate_id) {
            // Preserve the strictest sharing policy on conflict (discovery.md §17).
            if strictness(candidate.sharing_policy) < strictness(existing.sharing_policy) {
                candidate.sharing_policy = existing.sharing_policy;
            }
        } else if self.entries.len() >= self.cap {
            self.evict_expired(now);
            if self.entries.len() >= self.cap {
                return Err(TableError::Full);
            }
        }
        self.entries.insert(candidate.candidate_id, candidate);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, candidate_id: u64) -> Option<&PeerCandidate> {
        self.entries.get(&candidate_id)
    }

    pub fn remove(&mut self, candidate_id: u64) {
        self.entries.remove(&candidate_id);
    }

    pub fn evict_expired(&mut self, now: Instant) {
        self.entries.retain(|_, c| !c.is_expired(now));
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn strictness(policy: crate::provider::SharingPolicy) -> u8 {
    match policy {
        crate::provider::SharingPolicy::DoNotReshare => 4,
        crate::provider::SharingPolicy::LocalUseOnly => 3,
        crate::provider::SharingPolicy::ShareSelected => 2,
        crate::provider::SharingPolicy::ShareLocalScope => 1,
        crate::provider::SharingPolicy::ShareGeneral => 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableError {
    Full,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: u64, policy: crate::provider::SharingPolicy) -> PeerCandidate {
        PeerCandidate {
            candidate_id: id,
            carrier_type: "ump.udp/1".into(),
            connection_hint: vec![],
            source: crate::provider::CandidateSource::PeerHint,
            created_at: Instant(0),
            expires_at: Instant(u64::MAX),
            sharing_policy: policy,
            authentication: crate::provider::CandidateAuth::Unauthenticated,
            local: false,
        }
    }

    #[test]
    fn strictest_sharing_policy_wins() {
        let mut table = CandidateTable::new(100);
        table
            .upsert(
                candidate(1, crate::provider::SharingPolicy::ShareGeneral),
                Instant(0),
            )
            .unwrap();
        table
            .upsert(
                candidate(1, crate::provider::SharingPolicy::DoNotReshare),
                Instant(0),
            )
            .unwrap();
        assert_eq!(
            table.get(1).unwrap().sharing_policy,
            crate::provider::SharingPolicy::DoNotReshare
        );
    }

    #[test]
    fn table_is_bounded() {
        let mut table = CandidateTable::new(2);
        table
            .upsert(
                candidate(1, crate::provider::SharingPolicy::LocalUseOnly),
                Instant(0),
            )
            .unwrap();
        table
            .upsert(
                candidate(2, crate::provider::SharingPolicy::LocalUseOnly),
                Instant(0),
            )
            .unwrap();
        assert_eq!(
            table.upsert(
                candidate(3, crate::provider::SharingPolicy::LocalUseOnly),
                Instant(0)
            ),
            Err(TableError::Full)
        );
    }

    #[test]
    fn expired_evicted_before_admission() {
        let mut table = CandidateTable::new(2);
        let mut stale = candidate(1, crate::provider::SharingPolicy::LocalUseOnly);
        stale.expires_at = Instant(10);
        table.upsert(stale, Instant(0)).unwrap();
        table
            .upsert(
                candidate(2, crate::provider::SharingPolicy::LocalUseOnly),
                Instant(20),
            )
            .unwrap();
        table.evict_expired(Instant(20));
        assert_eq!(table.len(), 1);
        // A new candidate can now fit.
        assert!(table
            .upsert(
                candidate(3, crate::provider::SharingPolicy::LocalUseOnly),
                Instant(20)
            )
            .is_ok());
    }
}
