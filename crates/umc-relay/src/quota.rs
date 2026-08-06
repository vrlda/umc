//! Relay queue bounds and bandwidth limits (relay.md §19, §33).
pub const PER_CIRCUIT_QUEUE_BYTES: usize = 256 * 1024;
pub const PER_PEER_QUEUE_BYTES: usize = 2 * 1024 * 1024;
pub const GLOBAL_QUEUE_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_PER_CIRCUIT_RATE: u64 = 1_048_576; // 1 MiB/s
pub const DEFAULT_PER_PEER_RATE: u64 = 4 * 1_048_576;

#[derive(Debug, Clone)]
pub struct QueueAccount {
    pub per_circuit_bytes: usize,
    /// Reserved for per-peer aggregation across circuits (relay.md §19.2);
    /// multi-circuit accounting lands in Phase 4.
    pub per_peer_bytes: usize,
}

impl QueueAccount {
    #[must_use]
    pub fn new() -> Self {
        Self {
            per_circuit_bytes: 0,
            per_peer_bytes: 0,
        }
    }

    /// Charge queue space for accepted bytes.
    ///
    /// # Errors
    ///
    /// Returns `QueueError::Full` when the per-circuit queue bound
    /// (`PER_CIRCUIT_QUEUE_BYTES`) would be exceeded.
    pub fn accept(&mut self, bytes: usize) -> Result<(), QueueError> {
        let circuit = self
            .per_circuit_bytes
            .checked_add(bytes)
            .ok_or(QueueError::Full)?;
        if circuit > PER_CIRCUIT_QUEUE_BYTES {
            return Err(QueueError::Full);
        }
        self.per_circuit_bytes = circuit;
        Ok(())
    }

    pub fn release(&mut self, bytes: usize) {
        self.per_circuit_bytes = self.per_circuit_bytes.saturating_sub(bytes);
    }
}

impl Default for QueueAccount {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    Full,
}

#[derive(Debug, Clone)]
pub struct RateLimiter {
    pub rate_bytes_per_sec: u64,
    pub bucket: u64,
    pub last_refill_ms: u64,
}

impl RateLimiter {
    #[must_use]
    pub fn new(rate_bytes_per_sec: u64, initial_burst: u64) -> Self {
        Self {
            rate_bytes_per_sec,
            bucket: initial_burst,
            last_refill_ms: 0,
        }
    }

    pub fn allow(&mut self, now_ms: u64, bytes: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_refill_ms);
        self.last_refill_ms = now_ms;
        self.bucket = self
            .bucket
            .saturating_add(elapsed.saturating_mul(self.rate_bytes_per_sec) / 1_000);
        self.bucket = self.bucket.min(self.rate_bytes_per_sec); // 1s burst cap
        if self.bucket >= bytes {
            self.bucket -= bytes;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_bounds_enforced() {
        let mut q = QueueAccount::new();
        q.accept(PER_CIRCUIT_QUEUE_BYTES).unwrap();
        assert_eq!(q.accept(1), Err(QueueError::Full));
        q.release(PER_CIRCUIT_QUEUE_BYTES);
        assert_eq!(q.accept(1), Ok(()));
    }

    #[test]
    fn rate_limiter_refills() {
        let mut r = RateLimiter::new(1_000_000, 0);
        assert!(!r.allow(0, 100));
        // 100ms later the bucket refilled by 100,000 bytes.
        assert!(r.allow(100, 100_000));
        assert!(!r.allow(100, 1));
    }
}
