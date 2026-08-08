//! Sybil-group request budgets (routing.md security considerations, phase I4).

use std::collections::{HashMap, VecDeque};
use umc_types::runtime::{Duration, Instant};

pub const REQUESTS_PER_GROUP_PER_MINUTE: usize = 10;
pub const GROUP_RETENTION_MS: u64 = 60_000;
pub const MAX_GROUPS: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SybilGroup {
    pub source_prefix: Vec<u8>,
    pub capabilities_hash: Vec<u8>,
}

impl SybilGroup {
    #[must_use]
    pub fn from_requester(requester: &[u8], capabilities_hash: &[u8]) -> Self {
        Self {
            source_prefix: requester.iter().copied().take(4).collect(),
            capabilities_hash: capabilities_hash.to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SybilGuard {
    groups: HashMap<SybilGroup, VecDeque<Instant>>,
    per_minute: usize,
    retention: Duration,
}

impl Default for SybilGuard {
    fn default() -> Self {
        Self::new(REQUESTS_PER_GROUP_PER_MINUTE)
    }
}

impl SybilGuard {
    #[must_use]
    pub fn new(per_minute: usize) -> Self {
        Self {
            groups: HashMap::new(),
            per_minute: per_minute.max(1),
            retention: Duration::from_millis(GROUP_RETENTION_MS),
        }
    }

    /// Returns whether a request may consume this group's minute budget.
    pub fn admit(&mut self, group: SybilGroup, now: Instant) -> bool {
        self.prune(now);
        if !self.groups.contains_key(&group) && self.groups.len() >= MAX_GROUPS {
            if let Some(oldest) = self
                .groups
                .iter()
                .min_by_key(|(_, timestamps)| timestamps.front().copied())
                .map(|(group, _)| group.clone())
            {
                self.groups.remove(&oldest);
            }
        }
        let timestamps = self.groups.entry(group).or_default();
        if timestamps.len() >= self.per_minute {
            return false;
        }
        timestamps.push_back(now);
        true
    }

    fn prune(&mut self, now: Instant) {
        let cutoff = now.0.saturating_sub(self.retention.as_millis());
        self.groups.retain(|_, timestamps| {
            while timestamps
                .front()
                .is_some_and(|timestamp| timestamp.0 <= cutoff)
            {
                timestamps.pop_front();
            }
            !timestamps.is_empty()
        });
    }

    #[must_use]
    pub fn groups(&self) -> usize {
        self.groups.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_in_one_group_share_budget() {
        let mut guard = SybilGuard::default();
        let group = SybilGroup::from_requester(&[1, 2, 3, 4, 5], &[9; 32]);
        for _ in 0..REQUESTS_PER_GROUP_PER_MINUTE {
            assert!(guard.admit(group.clone(), Instant(1)));
        }
        assert!(!guard.admit(group.clone(), Instant(1)));
        assert!(guard.admit(group, Instant(GROUP_RETENTION_MS + 2)));
    }

    #[test]
    fn different_capabilities_form_independent_groups() {
        let mut guard = SybilGuard::new(1);
        assert!(guard.admit(SybilGroup::from_requester(&[1, 2, 3, 4], &[1]), Instant(0)));
        assert!(guard.admit(SybilGroup::from_requester(&[1, 2, 3, 4], &[2]), Instant(0)));
    }
}
