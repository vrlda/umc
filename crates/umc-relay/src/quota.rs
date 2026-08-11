//! Relay queue bounds and bandwidth limits (relay.md §19, §33).
use std::collections::HashMap;

pub const PER_CIRCUIT_QUEUE_BYTES: usize = 256 * 1024;
pub const PER_PEER_QUEUE_BYTES: usize = 2 * 1024 * 1024;
pub const GLOBAL_QUEUE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_QUEUE_PEERS: usize = 1_024;
pub const DEFAULT_PER_CIRCUIT_RATE: u64 = 1_048_576; // 1 MiB/s
pub const DEFAULT_PER_PEER_RATE: u64 = 4 * 1_048_576;

#[derive(Debug, Clone)]
pub struct QueueAccount {
    pub per_circuit_bytes: usize,
    /// Aggregated queue bytes across this peer's circuits (relay.md §19.2).
    pub per_peer_bytes: usize,
    peer_queues: HashMap<Vec<u8>, usize>,
    circuit_queues: HashMap<(Vec<u8>, u64), usize>,
}

impl QueueAccount {
    #[must_use]
    pub fn new() -> Self {
        Self {
            per_circuit_bytes: 0,
            per_peer_bytes: 0,
            peer_queues: HashMap::new(),
            circuit_queues: HashMap::new(),
        }
    }

    /// Charge queue space for accepted bytes.
    ///
    /// # Errors
    ///
    /// Returns `QueueError::Full` when the per-circuit queue bound
    /// (`PER_CIRCUIT_QUEUE_BYTES`) would be exceeded.
    pub fn accept(&mut self, bytes: usize) -> Result<(), QueueError> {
        self.accept_for_peer(&[], bytes)
    }

    /// Charge both the circuit and the owning peer. The empty peer key keeps
    /// the legacy single-account API deterministic; daemon callers should
    /// pass the authenticated peer identity to enforce cross-circuit caps.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::Full`] when either bound would be exceeded.
    pub fn accept_for_peer(&mut self, peer: &[u8], bytes: usize) -> Result<(), QueueError> {
        self.accept_for_circuit(peer, 0, bytes)
    }

    /// Charge a particular circuit while aggregating the owner's peer queue.
    /// Sharing one account across circuits makes the peer-wide cap effective.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::Full`] when the circuit, peer, or peer-entry
    /// bound would be exceeded.
    pub fn accept_for_circuit(
        &mut self,
        peer: &[u8],
        circuit_id: u64,
        bytes: usize,
    ) -> Result<(), QueueError> {
        let circuit_key = (peer.to_vec(), circuit_id);
        let circuit = self
            .circuit_queues
            .get(&circuit_key)
            .copied()
            .unwrap_or(0)
            .checked_add(bytes)
            .ok_or(QueueError::Full)?;
        if circuit > PER_CIRCUIT_QUEUE_BYTES {
            return Err(QueueError::Full);
        }
        let current_peer = self.peer_queues.get(peer).copied().unwrap_or(0);
        let peer_total = current_peer.checked_add(bytes).ok_or(QueueError::Full)?;
        if peer_total > PER_PEER_QUEUE_BYTES {
            return Err(QueueError::Full);
        }
        if !self.peer_queues.contains_key(peer) && self.peer_queues.len() >= MAX_QUEUE_PEERS {
            return Err(QueueError::Full);
        }
        self.circuit_queues.insert(circuit_key, circuit);
        if circuit_id == 0 {
            self.per_circuit_bytes = circuit;
        }
        self.peer_queues.insert(peer.to_vec(), peer_total);
        self.per_peer_bytes = self.peer_queues.values().copied().sum::<usize>();
        Ok(())
    }

    pub fn release(&mut self, bytes: usize) {
        self.release_for_peer(&[], bytes);
    }

    /// Release bytes from the circuit and its authenticated peer aggregate.
    pub fn release_for_peer(&mut self, peer: &[u8], bytes: usize) {
        self.release_for_circuit(peer, 0, bytes);
    }

    /// Release bytes from a particular circuit and its peer aggregate.
    pub fn release_for_circuit(&mut self, peer: &[u8], circuit_id: u64, bytes: usize) {
        let circuit_key = (peer.to_vec(), circuit_id);
        if let Some(total) = self.circuit_queues.get_mut(&circuit_key) {
            *total = total.saturating_sub(bytes);
            if *total == 0 {
                self.circuit_queues.remove(&circuit_key);
            }
        }
        if circuit_id == 0 {
            self.per_circuit_bytes = self.per_circuit_bytes.saturating_sub(bytes);
        }
        if let Some(total) = self.peer_queues.get_mut(peer) {
            *total = total.saturating_sub(bytes);
            if *total == 0 {
                self.peer_queues.remove(peer);
            }
        }
        self.per_peer_bytes = self.peer_queues.values().copied().sum::<usize>();
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
    fn per_peer_cap_covers_multiple_circuits() {
        let mut q = QueueAccount::new();
        for circuit_id in 0..8 {
            q.accept_for_circuit(b"peer", circuit_id, PER_CIRCUIT_QUEUE_BYTES)
                .unwrap();
        }
        assert_eq!(q.accept_for_circuit(b"peer", 8, 1), Err(QueueError::Full));
        assert_eq!(q.per_peer_bytes, PER_PEER_QUEUE_BYTES);
        assert_eq!(q.peer_queues.len(), 1);
    }

    #[test]
    fn peer_cap_rejects_without_mutating_account() {
        let mut q = QueueAccount::new();
        for circuit_id in 0..7 {
            q.accept_for_circuit(b"peer", circuit_id, PER_CIRCUIT_QUEUE_BYTES)
                .unwrap();
        }
        q.accept_for_circuit(b"peer", 7, PER_CIRCUIT_QUEUE_BYTES - 1)
            .unwrap();
        assert_eq!(q.accept_for_circuit(b"peer", 7, 2), Err(QueueError::Full));
        assert_eq!(q.per_peer_bytes, PER_PEER_QUEUE_BYTES - 1);
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
