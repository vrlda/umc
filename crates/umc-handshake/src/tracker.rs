//! Per-DCID handshake attempt tracking (handshake.md §15,
//! resource-limits.md §49): bounds the work a remote peer can force by
//! flooding Initial packets at a fresh connection ID.
use std::collections::HashMap;

/// Default budget of accepted attempts per DCID.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

/// Hard cap on distinct tracked DCIDs; the oldest-evicted bucket is dropped
/// beyond it so memory stays bounded under sustained floods.
pub const MAX_TRACKED_DCIDS: usize = 1_024;

/// Errors from the handshake attempt tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerError {
    /// The DCID has exhausted its attempt budget.
    LimitExceeded,
}

/// Counts Initial-packet attempts per DCID and refuses beyond the budget.
#[derive(Debug, Clone)]
pub struct HandshakeTracker {
    attempts: HashMap<Vec<u8>, u32>,
    max_attempts: u32,
    max_dcids: usize,
}

impl HandshakeTracker {
    /// Tracker that allows `max_attempts` attempts per DCID.
    #[must_use]
    pub fn new(max_attempts: u32) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            max_dcids: MAX_TRACKED_DCIDS,
        }
    }

    /// Record one attempt for `dcid`.
    ///
    /// # Errors
    ///
    /// Returns [`TrackerError::LimitExceeded`] when the DCID already used its
    /// full budget; the attempt is then ignored.
    pub fn register(&mut self, dcid: &[u8]) -> Result<(), TrackerError> {
        if !self.attempts.contains_key(dcid) && self.attempts.len() >= self.max_dcids {
            // Bound cardinality: evict an arbitrary bucket (all are equal
            // candidates; a complete expiry pass belongs to the daemon).
            if let Some(stale) = self.attempts.keys().next().cloned() {
                self.attempts.remove(&stale);
            }
        }
        let attempts = self.attempts.entry(dcid.to_vec()).or_insert(0);
        if *attempts >= self.max_attempts {
            return Err(TrackerError::LimitExceeded);
        }
        *attempts += 1;
        Ok(())
    }

    /// Attempts recorded for `dcid`.
    #[must_use]
    pub fn attempts(&self, dcid: &[u8]) -> u32 {
        self.attempts.get(dcid).copied().unwrap_or(0)
    }

    /// Reset the budget for `dcid` (after a successful handshake).
    pub fn clear(&mut self, dcid: &[u8]) {
        self.attempts.remove(dcid);
    }
}

impl Default for HandshakeTracker {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ATTEMPTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_after_budget_exhausted() {
        let mut tracker = HandshakeTracker::new(3);
        let dcid = [1u8; 8];
        for _ in 0..3 {
            assert_eq!(tracker.register(&dcid), Ok(()));
        }
        assert_eq!(tracker.register(&dcid), Err(TrackerError::LimitExceeded));
        // Other DCIDs are unaffected.
        assert_eq!(tracker.register(&[2u8; 8]), Ok(()));
    }

    #[test]
    fn clear_resets_the_budget() {
        let mut tracker = HandshakeTracker::new(3);
        let dcid = [1u8; 8];
        for _ in 0..3 {
            tracker.register(&dcid).unwrap();
        }
        tracker.clear(&dcid);
        assert_eq!(tracker.attempts(&dcid), 0);
        assert!(tracker.register(&dcid).is_ok());
    }

    #[test]
    fn cardinality_bounded() {
        let mut tracker = HandshakeTracker {
            attempts: HashMap::new(),
            max_attempts: 3,
            max_dcids: 8,
        };
        for i in 0..100u8 {
            assert!(tracker.register(&[i; 8]).is_ok());
        }
        assert!(tracker.attempts.len() <= 8);
    }
}
