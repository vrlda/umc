//! Route failure classes and retry delays (routing.md §26).
use umc_types::runtime::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    NoReachability,
    CarrierFailure,
    RelayRefused,
    AuthenticationFailed,
    PolicyRejected,
    Timeout,
    Loop,
    ResourceLimit,
    ProtocolError,
}

impl FailureClass {
    /// Recommended initial retry delays (routing.md §26.1). Policy rejection
    /// and authentication failure hold until the governing state changes
    /// (routing.md §26.1), so they use a long-lived 30-day delay instead of a
    /// bounded backoff; the daemon layer re-gates them on policy or identity
    /// state changes.
    #[must_use]
    pub fn initial_retry_delay(self) -> Duration {
        match self {
            FailureClass::CarrierFailure => Duration::from_millis(1_000),
            FailureClass::Timeout | FailureClass::NoReachability | FailureClass::ResourceLimit => {
                Duration::from_millis(5_000)
            }
            FailureClass::RelayRefused | FailureClass::ProtocolError => {
                Duration::from_millis(30_000)
            }
            FailureClass::PolicyRejected | FailureClass::AuthenticationFailed => {
                Duration::from_millis(30 * 24 * 60 * 60 * 1000)
            }
            FailureClass::Loop => Duration::from_millis(10_000),
        }
    }
}

pub const MAX_BACKOFF: u64 = 5 * 60 * 1000;

/// Capped exponential backoff with jitter (routing.md §26.1).
#[must_use]
pub fn backoff_delay(failure_count: u64, base: Duration, jitter_ms: u64, seed: u64) -> Duration {
    let multiplier = 1u64 << failure_count.min(10);
    let delay = base.as_millis().saturating_mul(multiplier).min(MAX_BACKOFF);
    let jitter = seed % jitter_ms.saturating_add(1);
    Duration::from_millis(delay.saturating_add(jitter).min(MAX_BACKOFF))
}

#[derive(Debug, Clone)]
pub struct FailureTracker {
    pub last_failure: Option<(FailureClass, Instant)>,
    pub retry_after: Option<Instant>,
    pub failure_count: u64,
}

impl FailureTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_failure: None,
            retry_after: None,
            failure_count: 0,
        }
    }

    pub fn record(&mut self, class: FailureClass, now: Instant, seed: u64) {
        self.failure_count += 1;
        let delay = backoff_delay(self.failure_count, class.initial_retry_delay(), 100, seed);
        self.retry_after = Some(now + delay);
        self.last_failure = Some((class, now));
    }

    #[must_use]
    pub fn can_retry(&self, now: Instant) -> bool {
        match self.retry_after {
            Some(deadline) => now >= deadline,
            None => true,
        }
    }

    /// Persisted failure penalties decay (routing.md §25): a stale failure
    /// never blocks rediscovery forever.
    pub fn decay(&mut self, now: Instant, half_life_ms: u64) {
        if let Some((_, at)) = self.last_failure {
            let age = now.duration_since(at).as_millis();
            if age >= half_life_ms {
                self.failure_count /= 2;
                self.retry_after = None;
            }
        }
    }
}

impl Default for FailureTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delays_follow_class() {
        assert_eq!(
            FailureClass::CarrierFailure.initial_retry_delay(),
            Duration::from_millis(1_000)
        );
        assert_eq!(
            FailureClass::RelayRefused.initial_retry_delay(),
            Duration::from_millis(30_000)
        );
        assert_eq!(
            FailureClass::PolicyRejected.initial_retry_delay(),
            Duration::from_millis(30 * 24 * 60 * 60 * 1000)
        );
        assert_eq!(
            FailureClass::AuthenticationFailed.initial_retry_delay(),
            Duration::from_millis(30 * 24 * 60 * 60 * 1000)
        );
    }

    #[test]
    fn backoff_capped() {
        let d = backoff_delay(20, Duration::from_millis(1_000), 0, 0);
        assert!(d.as_millis() <= MAX_BACKOFF);
    }

    #[test]
    fn tracker_blocks_until_retry_time() {
        let mut t = FailureTracker::new();
        assert!(t.can_retry(Instant(0)));
        t.record(FailureClass::CarrierFailure, Instant(0), 0);
        assert!(!t.can_retry(Instant(500)));
        assert!(t.can_retry(Instant(2_000)));
    }

    #[test]
    fn decay_half_life() {
        let mut t = FailureTracker::new();
        t.record(FailureClass::Timeout, Instant(0), 0);
        t.failure_count = 10;
        t.decay(Instant(100_000), 60_000);
        assert_eq!(t.failure_count, 5);
        assert!(t.can_retry(Instant(100_000)));
    }
}
