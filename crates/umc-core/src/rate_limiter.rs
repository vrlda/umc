//! Per-peer rate limiting (resource-limits.md §47): token buckets keyed by
//! peer id, with rule-specific refill rates and burst capacities.
use std::collections::HashMap;

/// Tightening applied to bucket capacity so the token bucket stays inside
/// the sliding-window burst envelope (resource-limits.md §47.3).
pub const SLIDING_WINDOW_TIGHTENING: f64 = 1.05;

/// Traffic classes; each maps to a tokens-per-second refill rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Rare traffic: e.g. invitation responses.
    Sparse,
    /// Steady traffic: the default application rate.
    Steady,
    /// Chatty traffic: hint exchanges, session maintenance.
    Chatty,
}

impl Rule {
    /// Tokens refilled per second (resource-limits.md §47).
    #[must_use]
    pub const fn tokens_per_second(self) -> f64 {
        match self {
            Self::Sparse => 1.0,
            Self::Steady => 10.0,
            Self::Chatty => 100.0,
        }
    }

    /// Burst capacity in tokens: one second of refill, tightened by
    /// [`SLIDING_WINDOW_TIGHTENING`] so bursts respect the sliding window.
    #[must_use]
    pub const fn capacity(self) -> f64 {
        self.tokens_per_second() / SLIDING_WINDOW_TIGHTENING
    }
}

/// Errors from the per-peer rate limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitError {
    /// The peer exceeded its rule's budget.
    RateLimited,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    rule: Rule,
    tokens: f64,
    capacity: f64,
    last_refill_ms: u64,
}

impl TokenBucket {
    fn new(rule: Rule, now_ms: u64) -> Self {
        Self {
            rule,
            tokens: rule.capacity(),
            capacity: rule.capacity(),
            last_refill_ms: now_ms,
        }
    }
}

/// Bounded per-peer token bucket limiter.
#[derive(Debug)]
pub struct RateLimiter {
    buckets: HashMap<Vec<u8>, TokenBucket>,
    max_peers: usize,
}

impl RateLimiter {
    /// Limiter with room for `max_peers` distinct peers (stale buckets
    /// evicted beyond that).
    #[must_use]
    pub fn new(max_peers: usize) -> Self {
        Self {
            buckets: HashMap::new(),
            max_peers,
        }
    }

    /// Checks `peer` under the default rule ([`Rule::Steady`]).
    ///
    /// # Errors
    /// Returns [`RateLimitError::RateLimited`] when the bucket is empty.
    pub fn check(&mut self, peer: &[u8], now_ms: u64) -> Result<(), RateLimitError> {
        self.check_rule(peer, Rule::Steady, now_ms)
    }

    /// Checks `peer` under an explicit rule: refills the bucket for the
    /// elapsed time, then consumes one token.
    ///
    /// # Errors
    /// Returns [`RateLimitError::RateLimited`] when the bucket is empty.
    #[allow(clippy::cast_precision_loss)] // ms budgets stay far below 2^53
    pub fn check_rule(
        &mut self,
        peer: &[u8],
        rule: Rule,
        now_ms: u64,
    ) -> Result<(), RateLimitError> {
        let bucket = self.bucket(peer, rule, now_ms);
        let elapsed_ms = now_ms.saturating_sub(bucket.last_refill_ms);
        bucket.last_refill_ms = now_ms;
        bucket.tokens = (bucket.tokens
            + bucket.rule.tokens_per_second() * elapsed_ms as f64 / 1000.0)
            .min(bucket.capacity);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(RateLimitError::RateLimited)
        }
    }

    fn bucket(&mut self, peer: &[u8], rule: Rule, now_ms: u64) -> &mut TokenBucket {
        if !self.buckets.contains_key(peer) && self.buckets.len() >= self.max_peers {
            // Bound cardinality: evict the least-recently-refilled bucket.
            let oldest = self
                .buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.last_refill_ms)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.buckets.remove(&oldest);
            }
        }
        let entry = self
            .buckets
            .entry(peer.to_vec())
            .or_insert_with(|| TokenBucket::new(rule, now_ms));
        if entry.rule != rule {
            *entry = TokenBucket::new(rule, now_ms);
        }
        entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steady_traffic_passes() {
        let mut limiter = RateLimiter::new(100);
        // One call per 100 ms at 10 tokens/s refills exactly what is spent.
        for ms in (0..5_000).step_by(100) {
            assert_eq!(
                limiter.check(b"peer-1", ms),
                Ok(()),
                "steady traffic at {ms} ms must pass"
            );
        }
    }

    #[test]
    fn burst_over_limit_returns_rate_limited() {
        let mut limiter = RateLimiter::new(100);
        for _ in 0..9 {
            assert_eq!(limiter.check(b"peer-1", 0), Ok(()));
        }
        assert_eq!(
            limiter.check(b"peer-1", 0),
            Err(RateLimitError::RateLimited),
            "burst beyond the tightened capacity is limited"
        );
    }

    #[test]
    fn window_replenishes_tokens() {
        let mut limiter = RateLimiter::new(100);
        for _ in 0..9 {
            assert_eq!(limiter.check(b"peer-1", 0), Ok(()));
        }
        assert_eq!(
            limiter.check(b"peer-1", 0),
            Err(RateLimitError::RateLimited)
        );
        // A second later the Steady bucket refilled 10 tokens.
        assert_eq!(limiter.check(b"peer-1", 1_000), Ok(()));
    }
}
