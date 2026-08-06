//! Enumeration resistance (discovery.md §18, routing.md §30): per-peer cost
//! budgets keyed by message class; a peer exhausting its window budget is
//! silently dropped, so probing reveals nothing.
use std::collections::HashMap;

/// Minimum per-peer step budget granted each window (routing.md §30).
pub const MIN_BUDGET: u64 = 20;
/// Default budget window length in milliseconds.
pub const WINDOW_MS: u64 = 60_000;

/// Message cost bands (discovery.md §18): cheap messages barely touch the
/// peer table, expensive ones (broad queries, hint fan-out) dominate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CostBand {
    Cheap,
    Standard,
    Expensive,
}

impl CostBand {
    /// Cost charged per message in this band.
    #[must_use]
    pub const fn cost(self) -> u64 {
        match self {
            Self::Cheap => 1,
            Self::Standard => 2,
            Self::Expensive => 4,
        }
    }
}

/// Default band assignments (discovery.md §18): message name → band.
pub const MESSAGE_COST_BANDS: &[(&str, CostBand)] = &[
    ("query", CostBand::Cheap),
    ("resolve", CostBand::Standard),
    ("hints", CostBand::Expensive),
    ("broadcast", CostBand::Expensive),
];

/// Band of `message` under the default table; `None` when unconfigured.
#[must_use]
pub fn cost_band(message: &str) -> Option<CostBand> {
    MESSAGE_COST_BANDS
        .iter()
        .find(|(name, _)| *name == message)
        .map(|(_, band)| *band)
}

/// Default cost of `message` (discovery.md §18): band cost for known
/// messages, `Some(0)` for zero-cost keepalives, and `None` for messages
/// with no configured cost (a config gap — they are not limited).
#[must_use]
pub fn cost_of(message: &str) -> Option<u64> {
    if message == "keepalive" {
        return Some(0);
    }
    cost_band(message).map(CostBand::cost)
}

#[derive(Debug, Clone)]
struct StepBucket {
    step_budget: u64,
    used: u64,
    last_reset_ms: u64,
}

/// Per-peer enumeration guard (discovery.md §18): each peer owns a step
/// budget that refills every window; messages draw cost from the band table.
#[derive(Debug)]
pub struct EnumerationGuard {
    buckets: HashMap<Vec<u8>, StepBucket>,
    max_counters: usize,
    window_ms: u64,
    /// Cost table used by [`Self::step`]. Defaults to [`cost_of`]; `None`
    /// means the message is not limited.
    pub cost_of: fn(&str) -> Option<u64>,
}

impl EnumerationGuard {
    /// Guard with room for `max_counters` peers (stale counters evicted).
    #[must_use]
    pub fn new(max_counters: usize) -> Self {
        Self {
            buckets: HashMap::new(),
            max_counters,
            window_ms: WINDOW_MS,
            cost_of,
        }
    }

    /// Sets the per-window budget for `peer` (defaults to [`MIN_BUDGET`]).
    pub fn set_step_budget(&mut self, peer: &[u8], step_budget: u64) {
        let bucket = self.bucket(peer, 0);
        bucket.step_budget = step_budget;
    }

    /// Accounts one `message` from `peer` against its step budget. Returns
    /// `false` when the budget is exhausted (the message must be silently
    /// dropped); unknown and zero-cost messages are never limited.
    ///
    /// The budget resets when the window elapses (`last_reset_ms` vs
    /// `window_ms`).
    #[must_use]
    pub fn step(&mut self, peer: &[u8], message: &str, now_ms: u64) -> bool {
        let Some(cost) = (self.cost_of)(message) else {
            return true;
        };
        if cost == 0 {
            return true;
        }
        let bucket = self.bucket(peer, now_ms);
        if bucket.used.saturating_add(cost) > bucket.step_budget {
            return false;
        }
        bucket.used += cost;
        true
    }

    /// Number of live per-peer counters.
    #[must_use]
    pub fn counter_count(&self) -> usize {
        self.buckets.len()
    }

    fn bucket(&mut self, peer: &[u8], now_ms: u64) -> &mut StepBucket {
        if !self.buckets.contains_key(peer) && self.buckets.len() >= self.max_counters {
            // Bound cardinality: evict the least-recently-reset counter.
            let oldest = self
                .buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.last_reset_ms)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.buckets.remove(&oldest);
            }
        }
        let entry = self.buckets.entry(peer.to_vec()).or_insert(StepBucket {
            step_budget: MIN_BUDGET,
            used: 0,
            last_reset_ms: now_ms,
        });
        if now_ms.saturating_sub(entry.last_reset_ms) >= self.window_ms {
            entry.used = 0;
            entry.last_reset_ms = now_ms;
        }
        entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_cumulative_cost_per_window() {
        let mut guard = EnumerationGuard::new(10);
        guard.set_step_budget(b"prober", 5);
        // Expensive messages draw 4 from the budget; cheap ones draw 1.
        assert!(guard.step(b"prober", "broadcast", 0));
        assert!(guard.step(b"prober", "query", 0));
        assert!(!guard.step(b"prober", "resolve", 0), "4+1+2 exceeds 5");
        // Other peers have their own independent budgets.
        assert!(guard.step(b"other", "broadcast", 0));
    }

    #[test]
    fn window_resets_after_time() {
        let mut guard = EnumerationGuard::new(10);
        guard.set_step_budget(b"prober", 4);
        assert!(guard.step(b"prober", "broadcast", 0));
        assert!(!guard.step(b"prober", "broadcast", 0));
        // A new window refills the budget.
        assert!(guard.step(b"prober", "broadcast", WINDOW_MS));
    }

    #[test]
    fn zero_cost_messages_not_limited() {
        let mut guard = EnumerationGuard::new(10);
        guard.set_step_budget(b"prober", 1);
        assert!(guard.step(b"prober", "query", 0));
        assert!(!guard.step(b"prober", "query", 0), "budget exhausted");
        // Zero-cost keepalives pass even at the budget edge.
        assert!(guard.step(b"prober", "keepalive", 0));
    }

    #[test]
    fn unknown_messages_require_config() {
        let guard = EnumerationGuard::new(10);
        // The default table has no cost for unconfigured messages.
        assert_eq!((guard.cost_of)("not-a-message"), None);
        let mut guard = guard;
        guard.set_step_budget(b"prober", 1);
        assert!(guard.step(b"prober", "query", 0));
        assert!(!guard.step(b"prober", "query", 0));
        // `None` costs are treated as not limited.
        assert!(guard.step(b"prober", "not-a-message", 0));
    }
}
