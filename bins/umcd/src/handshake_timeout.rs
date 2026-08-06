//! Handshake timeout and retry caps (core.md §9.5, handshake.md §7): a
//! per-connection-id attempt cap and a hard deadline.
use std::collections::HashMap;
use umc_types::runtime::{Duration, Instant};

/// Maximum handshake attempts per connection id.
pub const MAX_HANDSHAKE_RETRIES: u32 = 3;
/// Hard deadline for a handshake to complete, in milliseconds.
pub const HANDSHAKE_DEADLINE_MS: u64 = 10_000;

/// Tracks handshake attempts per connection id so abusive retry storms are
/// dropped at the session layer.
#[derive(Debug, Default)]
pub struct HandshakeTracker {
    attempts: HashMap<Vec<u8>, u32>,
    deadline: HashMap<Vec<u8>, Instant>,
}

impl HandshakeTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `Ok(())` while the retry cap and the deadline hold for
    /// `dcid`.
    ///
    /// # Errors
    ///
    /// Returns a message when the attempt cap is reached or the deadline
    /// has passed.
    pub fn check(&mut self, dcid: &[u8], now: Instant) -> Result<(), String> {
        if self.attempts.get(dcid).copied().unwrap_or(0) >= MAX_HANDSHAKE_RETRIES {
            return Err(format!(
                "handshake retry cap ({MAX_HANDSHAKE_RETRIES}) reached for dcid {dcid:02x?}"
            ));
        }
        if self
            .deadline
            .get(dcid)
            .is_some_and(|deadline| now > *deadline)
        {
            return Err(format!(
                "handshake deadline ({HANDSHAKE_DEADLINE_MS} ms) exceeded for dcid {dcid:02x?}"
            ));
        }
        Ok(())
    }

    /// Record one handshake attempt, starting the deadline clock on the
    /// first attempt for `dcid`.
    pub fn record(&mut self, dcid: &[u8], now: Instant) {
        *self.attempts.entry(dcid.to_vec()).or_insert(0) += 1;
        self.deadline
            .entry(dcid.to_vec())
            .or_insert(now + Duration::from_millis(HANDSHAKE_DEADLINE_MS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_cap_and_deadline() {
        let mut tracker = HandshakeTracker::new();
        let dcid = vec![1u8; 8];
        let start = Instant(1_000);

        assert_eq!(tracker.check(&dcid, start), Ok(()));
        tracker.record(&dcid, start);
        tracker.record(&dcid, start);
        tracker.record(&dcid, start);
        assert!(
            tracker.check(&dcid, start).is_err(),
            "the fourth attempt must exceed the retry cap"
        );

        // A fresh dcid is admitted until its deadline passes.
        let other = vec![2u8; 8];
        tracker.record(&other, start);
        assert_eq!(tracker.check(&other, start), Ok(()));
        assert_eq!(
            tracker.check(&other, start + Duration::from_millis(HANDSHAKE_DEADLINE_MS)),
            Ok(()),
            "the deadline is inclusive"
        );
        assert!(
            tracker
                .check(
                    &other,
                    start + Duration::from_millis(HANDSHAKE_DEADLINE_MS + 1)
                )
                .is_err(),
            "the deadline must expire the entry"
        );
    }
}
