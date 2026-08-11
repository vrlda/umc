//! Reverse-path state for response forwarding (routing.md §17-18).
use crate::types::MAX_RESPONSES_PER_BRANCH;
use std::collections::HashMap;
use umc_types::runtime::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ReverseEntry {
    pub request_id: [u8; 16],
    pub upstream: Vec<u8>,
    pub expiry: Instant,
    pub response_count: usize,
    /// Highest accepted response sequence for this request branch.
    pub last_response_sequence: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ReverseState {
    entries: HashMap<[u8; 16], ReverseEntry>,
    retention: Duration,
}

impl ReverseState {
    #[must_use]
    pub fn new(retention: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            retention,
        }
    }

    pub fn create(&mut self, request_id: [u8; 16], upstream: Vec<u8>, now: Instant) {
        self.entries.insert(
            request_id,
            ReverseEntry {
                request_id,
                upstream,
                expiry: now + self.retention,
                response_count: 0,
                last_response_sequence: None,
            },
        );
    }

    /// Remove a response branch that was never delivered to an upstream
    /// peer. Callers use this when a transport disappears between discovery
    /// and enqueue so failed probes do not retain unusable reverse state.
    pub fn remove(&mut self, request_id: &[u8; 16]) -> bool {
        self.entries.remove(request_id).is_some()
    }

    /// A response may only travel to the upstream peer that supplied the
    /// matching request copy (routing.md §17).
    pub fn route_response(&mut self, request_id: &[u8; 16], now: Instant) -> Option<Vec<u8>> {
        self.prune(now);
        let entry = self.entries.get_mut(request_id)?;
        if entry.response_count >= MAX_RESPONSES_PER_BRANCH {
            return None;
        }
        entry.response_count += 1;
        Some(entry.upstream.clone())
    }

    /// Return remaining reverse-state lifetime for a response branch.
    #[must_use]
    pub fn remaining_lifetime_ms(&mut self, request_id: &[u8; 16], now: Instant) -> Option<u64> {
        self.prune(now);
        let entry = self.entries.get(request_id)?;
        if entry.expiry <= now {
            return None;
        }
        Some(entry.expiry.duration_since(now).as_millis())
    }

    /// Accept one monotonically increasing response sequence and return the
    /// upstream peer. Replays and out-of-order responses are dropped before
    /// they can alter the route cache (routing.md §16.1, §18).
    pub fn route_response_with_sequence(
        &mut self,
        request_id: &[u8; 16],
        sequence: u64,
        now: Instant,
    ) -> Option<Vec<u8>> {
        self.prune(now);
        let entry = self.entries.get_mut(request_id)?;
        if entry.response_count >= MAX_RESPONSES_PER_BRANCH
            || entry
                .last_response_sequence
                .is_some_and(|last| sequence <= last)
        {
            return None;
        }
        entry.last_response_sequence = Some(sequence);
        entry.response_count += 1;
        Some(entry.upstream.clone())
    }

    #[must_use]
    pub fn upstream_of(&self, request_id: &[u8; 16], now: Instant) -> Option<Vec<u8>> {
        let entry = self.entries.get(request_id)?;
        if entry.expiry <= now {
            return None;
        }
        Some(entry.upstream.clone())
    }

    fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, e| e.expiry > now);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_routed_to_upstream_only() {
        let mut state = ReverseState::new(Duration::from_millis(30_000));
        let rid = [7u8; 16];
        state.create(rid, b"upstream-a".to_vec(), Instant(0));
        assert_eq!(
            state.route_response(&rid, Instant(10)).unwrap(),
            b"upstream-a"
        );
        // Unknown request ids are not routable.
        assert!(state.route_response(&[8u8; 16], Instant(10)).is_none());
    }

    #[test]
    fn response_budget_capped() {
        let mut state = ReverseState::new(Duration::from_millis(30_000));
        let rid = [7u8; 16];
        state.create(rid, b"up".to_vec(), Instant(0));
        for _ in 0..MAX_RESPONSES_PER_BRANCH {
            assert!(state.route_response(&rid, Instant(10)).is_some());
        }
        assert!(state.route_response(&rid, Instant(10)).is_none());
    }

    #[test]
    fn expires_with_request() {
        let mut state = ReverseState::new(Duration::from_millis(1_000));
        let rid = [7u8; 16];
        state.create(rid, b"up".to_vec(), Instant(0));
        assert!(state.upstream_of(&rid, Instant(999)).is_some());
        assert!(state.upstream_of(&rid, Instant(1_000)).is_none());
    }

    #[test]
    fn remaining_lifetime_is_bounded_by_reverse_entry() {
        let mut state = ReverseState::new(Duration::from_millis(30_000));
        let rid = [9u8; 16];
        state.create(rid, b"upstream".to_vec(), Instant(100));
        assert_eq!(
            state.remaining_lifetime_ms(&rid, Instant(1_100)),
            Some(29_000)
        );
        assert_eq!(state.remaining_lifetime_ms(&rid, Instant(30_100)), None);
    }

    #[test]
    fn response_sequences_are_strictly_increasing() {
        let mut state = ReverseState::new(Duration::from_millis(30_000));
        let rid = [10u8; 16];
        state.create(rid, b"upstream".to_vec(), Instant(0));
        assert_eq!(
            state.route_response_with_sequence(&rid, 0, Instant(1)),
            Some(b"upstream".to_vec())
        );
        assert_eq!(
            state.route_response_with_sequence(&rid, 0, Instant(2)),
            None
        );
        assert_eq!(
            state.route_response_with_sequence(&rid, 1, Instant(3)),
            Some(b"upstream".to_vec())
        );
    }

    #[test]
    fn remove_drops_failed_branch() {
        let mut state = ReverseState::new(Duration::from_millis(30_000));
        let rid = [11u8; 16];
        state.create(rid, Vec::new(), Instant(0));
        assert!(state.remove(&rid));
        assert!(state.is_empty());
        assert!(!state.remove(&rid));
    }
}
