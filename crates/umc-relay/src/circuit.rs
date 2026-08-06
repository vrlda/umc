//! Relay circuit state machine and identifiers (relay.md §8-9).
use umc_types::runtime::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Opening,
    Active,
    HalfClosedUpstream,
    HalfClosedDownstream,
    Closing,
    Draining,
    Closed,
}

pub const DEFAULT_LIFETIME_MS: u64 = 10 * 60 * 1000;
pub const MAX_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 2 * 60 * 1000;
pub const MAX_RELAY_PAYLOAD: usize = 64 * 1024;
pub const MAX_RELAY_NODES: usize = 4;
pub const PROTOCOL_MAX_RELAY_NODES: usize = 16;

#[derive(Debug, Clone)]
pub struct Circuit {
    pub circuit_id: u64,
    pub state: CircuitState,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub idle_deadline: Instant,
    pub granted_byte_quota: u64,
    pub bytes_forwarded: u64,
    /// Next relay sequence expected FROM the peer (relay.md §16.1, direction
    /// 1): advanced by the accept path, never by local sends.
    pub next_relay_sequence: u64,
    /// Next relay sequence this circuit has SENT to the peer (relay.md §16.1,
    /// direction 2): advanced by `allocate_sequence`, never by receives.
    pub peer_next_relay_sequence: u64,
    /// Last accepted data bytes, for exact-duplicate detection (relay.md §17).
    pub last_accepted_data: Option<Vec<u8>>,
    pub downstream: Option<Vec<u8>>,
    pub private_handling: bool,
    pub bidirectional: bool,
    pub last_activity: Instant,
}

impl Circuit {
    #[must_use]
    pub fn new(
        circuit_id: u64,
        now: Instant,
        lifetime_ms: u64,
        byte_quota: u64,
        bidirectional: bool,
        private_handling: bool,
    ) -> Self {
        let lifetime = lifetime_ms.clamp(1_000, MAX_LIFETIME_MS);
        let expires_at = now + Duration::from_millis(lifetime);
        Self {
            circuit_id,
            state: CircuitState::Opening,
            created_at: now,
            expires_at,
            // Idle timeout must never exceed the granted lifetime (relay.md §21).
            idle_deadline: (now + Duration::from_millis(DEFAULT_IDLE_TIMEOUT_MS))
                .clamp(now, expires_at),
            granted_byte_quota: byte_quota,
            bytes_forwarded: 0,
            // Per-direction sequences (relay.md §16.1): the seen counter
            // advances on accept, the sent counter on allocate_sequence.
            next_relay_sequence: 0,
            peer_next_relay_sequence: 0,
            last_accepted_data: None,
            downstream: None,
            private_handling,
            bidirectional,
            last_activity: now,
        }
    }

    pub fn touch(&mut self, now: Instant) {
        self.last_activity = now;
        // Idle deadline stays clamped to the granted lifetime (relay.md §21).
        self.idle_deadline =
            (now + Duration::from_millis(DEFAULT_IDLE_TIMEOUT_MS)).clamp(now, self.expires_at);
    }

    #[must_use]
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    #[must_use]
    pub fn is_idle(&self, now: Instant) -> bool {
        now >= self.idle_deadline
    }

    /// Quota accounting (relay.md §20): charge when a new sequence is accepted.
    ///
    /// # Errors
    ///
    /// Returns `QuotaError::Overflow` on counter overflow and
    /// `QuotaError::Exhausted` when the granted byte quota is exceeded.
    pub fn charge(&mut self, bytes: u64) -> Result<(), QuotaError> {
        let new_total = self
            .bytes_forwarded
            .checked_add(bytes)
            .ok_or(QuotaError::Overflow)?;
        if new_total > self.granted_byte_quota {
            return Err(QuotaError::Exhausted);
        }
        self.bytes_forwarded = new_total;
        Ok(())
    }

    /// Allocate the next sequence number for data SENT to the peer
    /// (relay.md §16.1, direction 2). Independent of the receive counter.
    pub fn allocate_sequence(&mut self) -> u64 {
        let seq = self.peer_next_relay_sequence;
        self.peer_next_relay_sequence += 1;
        seq
    }

    pub fn accept(&mut self, now: Instant) {
        self.state = CircuitState::Active;
        self.touch(now);
    }

    pub fn close(&mut self, now: Instant) {
        self.state = CircuitState::Closing;
        self.idle_deadline = now + Duration::from_millis(1_000);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaError {
    Exhausted,
    Overflow,
}

#[derive(Debug)]
pub struct CircuitIdAllocator {
    next: u64,
    seed: u64,
}

impl CircuitIdAllocator {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { next: 0, seed }
    }

    /// Unpredictable 62-bit-range IDs (relay.md §8), unique within the session.
    pub fn allocate(&mut self) -> u64 {
        self.seed = self
            .seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let value = self.seed & ((1u64 << 62) - 1);
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        value ^ id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_lifecycle() {
        let now = Instant(0);
        let mut c = Circuit::new(7, now, DEFAULT_LIFETIME_MS, 1_048_576, true, false);
        assert_eq!(c.state, CircuitState::Opening);
        c.accept(now + Duration::from_millis(10));
        assert_eq!(c.state, CircuitState::Active);
        assert!(!c.is_expired(now + Duration::from_millis(DEFAULT_LIFETIME_MS - 1)));
        assert!(c.is_expired(now + Duration::from_millis(DEFAULT_LIFETIME_MS)));
    }

    #[test]
    fn lifetime_capped_at_max() {
        let now = Instant(0);
        let c = Circuit::new(1, now, MAX_LIFETIME_MS + 60_000, 0, true, false);
        assert!(c.is_expired(now + Duration::from_millis(MAX_LIFETIME_MS)));
    }

    #[test]
    fn quota_enforced() {
        let now = Instant(0);
        let mut c = Circuit::new(2, now, DEFAULT_LIFETIME_MS, 100, true, false);
        c.charge(60).unwrap();
        c.charge(40).unwrap();
        assert_eq!(c.charge(1), Err(QuotaError::Exhausted));
    }

    #[test]
    fn idle_timeout_tracks_activity() {
        let now = Instant(0);
        let mut c = Circuit::new(3, now, DEFAULT_LIFETIME_MS, 100, true, false);
        c.touch(now + Duration::from_millis(50_000));
        assert!(!c.is_idle(now + Duration::from_millis(50_000 + DEFAULT_IDLE_TIMEOUT_MS - 1)));
        assert!(c.is_idle(now + Duration::from_millis(50_000 + DEFAULT_IDLE_TIMEOUT_MS)));
    }

    #[test]
    fn idle_timeout_capped_by_lifetime() {
        let now = Instant(0);
        // Lifetime shorter than the default idle timeout: idle never outlives it.
        let c = Circuit::new(9, now, 60_000, 100, true, false);
        assert_eq!(c.idle_deadline, c.expires_at);
        let mut c = Circuit::new(10, now, 60_000, 100, true, false);
        c.touch(now + Duration::from_millis(50_000));
        assert_eq!(c.idle_deadline, c.expires_at);
    }

    #[test]
    fn id_allocator_is_unique() {
        let mut allocator = CircuitIdAllocator::new(42);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            let id = allocator.allocate();
            assert!(id < (1u64 << 62));
            assert!(seen.insert(id));
        }
    }
}
