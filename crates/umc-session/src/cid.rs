//! Connection-ID issuance and retirement (session.md §30).
use umc_types::runtime::{Duration, EntropySource};

pub const MIN_CID_LEN: usize = 1;
pub const MAX_CID_LEN: usize = 20;
pub const DEFAULT_ACTIVE_LIMIT: u64 = 4;
pub const RESET_TOKEN_LEN: usize = 16;
pub const PRUNE_RETIRED_ALLOWANCE: usize = 8;
const EXPIRY_BUDGET_MS: u64 = 3_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionId {
    pub sequence: u64,
    pub bytes: Vec<u8>,
    pub reset_token: [u8; RESET_TOKEN_LEN],
    pub retired: bool,
}

#[derive(Debug, Clone)]
pub struct ConnectionIdManager {
    pub active_limit: u64,
    issued: Vec<ConnectionId>,
    next_sequence: u64,
}

impl ConnectionIdManager {
    #[must_use]
    pub fn new(active_limit: u64) -> Self {
        Self {
            active_limit: active_limit.max(2),
            issued: Vec::new(),
            next_sequence: 0,
        }
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.issued.iter().filter(|c| !c.retired).count()
    }

    /// Issue a fresh CID with a random reset token (session.md §30.1).
    #[allow(clippy::cast_possible_truncation)]
    pub fn issue(&mut self, len: usize, entropy: &dyn EntropySource) -> Option<ConnectionId> {
        if !(MIN_CID_LEN..=MAX_CID_LEN).contains(&len) {
            return None;
        }
        if self.active_count() >= self.active_limit as usize {
            return None;
        }
        let mut bytes = vec![0u8; len];
        entropy.fill(&mut bytes);
        let mut reset_token = [0u8; RESET_TOKEN_LEN];
        entropy.fill(&mut reset_token);
        let cid = ConnectionId {
            sequence: self.next_sequence,
            bytes,
            reset_token,
            retired: false,
        };
        self.next_sequence += 1;
        self.issued.push(cid.clone());
        Some(cid)
    }

    #[must_use]
    pub fn retire(&mut self, sequence: u64) -> bool {
        let Some(cid) = self.issued.iter_mut().find(|c| c.sequence == sequence) else {
            return false;
        };
        cid.retired = true;
        true
    }

    /// Retire all sequences below `retire_prior_to` (session.md §30.3).
    #[must_use]
    pub fn retire_prior_to(&mut self, retire_prior_to: u64) -> usize {
        let mut count = 0;
        for cid in &mut self.issued {
            if !cid.retired && cid.sequence < retire_prior_to {
                cid.retired = true;
                count += 1;
            }
        }
        count
    }

    #[must_use]
    pub fn active(&self) -> Vec<&ConnectionId> {
        self.issued.iter().filter(|c| !c.retired).collect()
    }

    /// Retain reset-token handling for at least 3 PTO after retirement
    /// (session.md §30.3): we keep the record; the session enforces the timer.
    #[must_use]
    pub fn reset_token_for(&self, sequence: u64) -> Option<[u8; RESET_TOKEN_LEN]> {
        self.issued
            .iter()
            .find(|c| c.sequence == sequence)
            .map(|c| c.reset_token)
    }

    #[must_use]
    pub fn retained_count(&self) -> usize {
        self.issued.len()
    }

    /// Bounded retention: all active CIDs plus the newest retired allowance
    /// (resource-limits.md §25).
    pub fn prune(&mut self) {
        let keep_retired: Vec<u64> = self
            .issued
            .iter()
            .filter(|c| c.retired)
            .rev()
            .take(PRUNE_RETIRED_ALLOWANCE)
            .map(|c| c.sequence)
            .collect();
        self.issued
            .retain(|c| !c.retired || keep_retired.contains(&c.sequence));
    }

    #[must_use]
    pub fn record_expiry_budget(&self) -> Duration {
        Duration::from_millis(EXPIRY_BUDGET_MS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(7);
        }
    }

    #[test]
    fn issuance_respects_active_limit() {
        let mut m = ConnectionIdManager::new(2);
        assert!(m.issue(8, &E).is_some());
        assert!(m.issue(8, &E).is_some());
        assert!(m.issue(8, &E).is_none());
    }

    #[test]
    fn retirement_frees_slots() {
        let mut m = ConnectionIdManager::new(2);
        let a = m.issue(8, &E).unwrap();
        let b = m.issue(8, &E).unwrap();
        assert!(m.retire(a.sequence));
        assert!(!m.retire(99));
        assert!(m.issue(8, &E).is_some());
        let _ = b;
    }

    #[test]
    fn retire_prior_to_bulk() {
        let mut m = ConnectionIdManager::new(8);
        for _ in 0..5 {
            m.issue(8, &E);
        }
        assert_eq!(m.retire_prior_to(3), 3);
        assert_eq!(m.active().len(), 2);
    }

    #[test]
    fn length_bounds_enforced() {
        let mut m = ConnectionIdManager::new(2);
        assert!(m.issue(0, &E).is_none());
        assert!(m.issue(21, &E).is_none());
        assert!(m.issue(20, &E).is_some());
    }

    #[test]
    fn prune_keeps_active_plus_allowance() {
        let mut m = ConnectionIdManager::new(32);
        for _ in 0..20 {
            m.issue(8, &E).unwrap();
        }
        for seq in 0..15 {
            assert!(m.retire(seq));
        }
        m.prune();
        let active = m.active().len();
        assert_eq!(active, 5);
        assert!(m.retained_count() <= active + PRUNE_RETIRED_ALLOWANCE);
        assert_eq!(m.retained_count(), active + PRUNE_RETIRED_ALLOWANCE);
    }
}
