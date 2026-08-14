//! Multi-hop circuit construction (relay.md §27): hop-by-hop extension with
//! a relay-count budget. Each relay sees only its adjacent hops.
use crate::circuit::{MAX_RELAY_NODES, PROTOCOL_MAX_RELAY_NODES};
use std::collections::BTreeMap;

/// Bounded error returned by the relay multipath scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipathError {
    NoUsablePath,
    UnknownPath,
    InvalidWeight,
    ReorderBufferFull,
    SequenceConflict,
}

/// Result of admitting one path-tagged relay frame into the ordered receive
/// side of a multipath circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipathReceive {
    Buffered,
    Duplicate,
    Delivered(Vec<(u64, Vec<u8>)>),
}

/// Per-path accounting exposed for diagnostics and release evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultipathPathStats {
    pub weight: u16,
    pub sent_bytes: u64,
    pub failed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MultipathPath {
    weight: u16,
    deficit: u64,
    sent_bytes: u64,
    failed: bool,
}

/// Small weighted scheduler for one negotiated relay circuit.
///
/// Sequence space is circuit-wide. Paths only select where a future frame is
/// sent; `accept` reorders by that shared sequence and suppresses exact
/// duplicates before delivery. All state is bounded by `reorder_limit`.
#[derive(Debug, Clone)]
pub struct MultipathScheduler {
    reorder_limit: usize,
    paths: BTreeMap<u64, MultipathPath>,
    buffered: BTreeMap<u64, Vec<u8>>,
    delivered: BTreeMap<u64, Vec<u8>>,
    next_sequence: u64,
}

impl MultipathScheduler {
    #[must_use]
    pub fn new(reorder_limit: usize) -> Self {
        Self {
            reorder_limit: reorder_limit.max(1),
            paths: BTreeMap::new(),
            buffered: BTreeMap::new(),
            delivered: BTreeMap::new(),
            next_sequence: 0,
        }
    }

    /// Add or replace one usable downstream path.
    ///
    /// # Errors
    /// Returns [`MultipathError::InvalidWeight`] for a zero weight.
    pub fn add_path(&mut self, path_id: u64, weight: u16) -> Result<(), MultipathError> {
        if weight == 0 {
            return Err(MultipathError::InvalidWeight);
        }
        self.paths.insert(
            path_id,
            MultipathPath {
                weight,
                deficit: 0,
                sent_bytes: 0,
                failed: false,
            },
        );
        Ok(())
    }

    /// Mark one path unusable. Other paths continue carrying future frames.
    ///
    /// # Errors
    /// Returns [`MultipathError::UnknownPath`] when `path_id` is not known.
    pub fn fail_path(&mut self, path_id: u64) -> Result<(), MultipathError> {
        let path = self
            .paths
            .get_mut(&path_id)
            .ok_or(MultipathError::UnknownPath)?;
        path.failed = true;
        Ok(())
    }

    /// Mark a previously attached path usable after its downstream open was
    /// authenticated and accepted.
    ///
    /// # Errors
    /// Returns [`MultipathError::UnknownPath`] when `path_id` is not known.
    pub fn activate_path(&mut self, path_id: u64) -> Result<(), MultipathError> {
        let path = self
            .paths
            .get_mut(&path_id)
            .ok_or(MultipathError::UnknownPath)?;
        path.failed = false;
        Ok(())
    }

    /// Select the next path using bounded weighted deficit scheduling.
    ///
    /// # Errors
    /// Returns [`MultipathError::NoUsablePath`] when every path has failed.
    pub fn select_path(&mut self) -> Result<u64, MultipathError> {
        let total_weight: u64 = self
            .paths
            .values()
            .filter(|path| !path.failed)
            .map(|path| u64::from(path.weight))
            .sum();
        if total_weight == 0 {
            return Err(MultipathError::NoUsablePath);
        }
        for path in self.paths.values_mut().filter(|path| !path.failed) {
            path.deficit = path.deficit.saturating_add(u64::from(path.weight));
        }
        let selected = self
            .paths
            .iter()
            .filter(|(_, path)| !path.failed)
            .max_by_key(|(id, path)| (path.deficit, std::cmp::Reverse(**id)))
            .map(|(id, _)| *id)
            .ok_or(MultipathError::NoUsablePath)?;
        if let Some(path) = self.paths.get_mut(&selected) {
            path.deficit = path.deficit.saturating_sub(total_weight);
        }
        Ok(selected)
    }

    /// Charge one accepted frame to its selected path.
    ///
    /// # Errors
    /// Returns [`MultipathError::UnknownPath`] for an unknown or failed path.
    pub fn record_sent(&mut self, path_id: u64, bytes: u64) -> Result<(), MultipathError> {
        let path = self
            .paths
            .get_mut(&path_id)
            .ok_or(MultipathError::UnknownPath)?;
        if path.failed {
            return Err(MultipathError::NoUsablePath);
        }
        path.sent_bytes = path.sent_bytes.saturating_add(bytes);
        Ok(())
    }

    #[must_use]
    pub fn path_stats(&self, path_id: u64) -> Option<MultipathPathStats> {
        self.paths.get(&path_id).map(|path| MultipathPathStats {
            weight: path.weight,
            sent_bytes: path.sent_bytes,
            failed: path.failed,
        })
    }

    #[must_use]
    pub fn usable_path_count(&self) -> usize {
        self.paths.values().filter(|path| !path.failed).count()
    }

    #[must_use]
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Admit one frame from any path and release only contiguous sequence
    /// numbers. Exact duplicates are harmless; conflicting bytes fail closed.
    ///
    /// # Errors
    /// Returns [`MultipathError::ReorderBufferFull`] or
    /// [`MultipathError::SequenceConflict`] on malformed/replayed input.
    pub fn accept(
        &mut self,
        sequence: u64,
        data: &[u8],
    ) -> Result<MultipathReceive, MultipathError> {
        if sequence < self.next_sequence {
            return match self.delivered.get(&sequence) {
                Some(previous) if previous == data => Ok(MultipathReceive::Duplicate),
                _ => Err(MultipathError::SequenceConflict),
            };
        }
        if let Some(previous) = self.buffered.get(&sequence) {
            return if previous == data {
                Ok(MultipathReceive::Duplicate)
            } else {
                Err(MultipathError::SequenceConflict)
            };
        }
        if sequence > self.next_sequence && self.buffered.len() >= self.reorder_limit {
            return Err(MultipathError::ReorderBufferFull);
        }
        self.buffered.insert(sequence, data.to_vec());
        if sequence > self.next_sequence {
            return Ok(MultipathReceive::Buffered);
        }
        let mut released = Vec::new();
        while let Some(bytes) = self.buffered.remove(&self.next_sequence) {
            let sequence = self.next_sequence;
            self.delivered.insert(sequence, bytes.clone());
            released.push((sequence, bytes));
            self.next_sequence = self.next_sequence.saturating_add(1);
        }
        while self.delivered.len() > self.reorder_limit {
            let Some(first) = self.delivered.keys().next().copied() else {
                break;
            };
            self.delivered.remove(&first);
        }
        Ok(MultipathReceive::Delivered(released))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionError {
    RelayBudgetExhausted,
    ProtocolLimit,
    HopDenied,
}

#[derive(Debug, Clone)]
pub struct ExtensionState {
    pub relays_used: usize,
    pub max_relays: usize,
}

impl ExtensionState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            relays_used: 0,
            max_relays: MAX_RELAY_NODES,
        }
    }

    /// Each extension step decrements the remaining relay count (relay.md §27.4).
    ///
    /// # Errors
    ///
    /// Returns `ExtensionError::RelayBudgetExhausted` when the local relay
    /// budget is spent and `ExtensionError::ProtocolLimit` when the protocol
    /// maximum would be exceeded.
    pub fn extend(&mut self, downstream_granted: bool) -> Result<(), ExtensionError> {
        if self.relays_used >= PROTOCOL_MAX_RELAY_NODES {
            return Err(ExtensionError::ProtocolLimit);
        }
        if self.relays_used >= self.max_relays {
            return Err(ExtensionError::RelayBudgetExhausted);
        }
        if downstream_granted {
            self.relays_used += 1;
        }
        Ok(())
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.max_relays.saturating_sub(self.relays_used)
    }
}

impl Default for ExtensionState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_balances_active_paths_and_tracks_bytes() {
        let mut scheduler = MultipathScheduler::new(8);
        scheduler.add_path(11, 1).unwrap();
        scheduler.add_path(22, 2).unwrap();
        let selected = (0..6)
            .map(|_| scheduler.select_path().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![22, 11, 22, 22, 11, 22]);
        scheduler.record_sent(22, 100).unwrap();
        assert_eq!(scheduler.path_stats(22).unwrap().sent_bytes, 100);
        scheduler.fail_path(22).unwrap();
        assert_eq!(scheduler.select_path(), Ok(11));
    }

    #[test]
    fn scheduler_reorders_and_deduplicates_frames() {
        let mut scheduler = MultipathScheduler::new(8);
        scheduler.add_path(1, 1).unwrap();
        assert_eq!(scheduler.accept(1, b"one"), Ok(MultipathReceive::Buffered));
        assert_eq!(
            scheduler.accept(0, b"zero"),
            Ok(MultipathReceive::Delivered(vec![
                (0, b"zero".to_vec()),
                (1, b"one".to_vec())
            ]))
        );
        assert_eq!(scheduler.accept(1, b"one"), Ok(MultipathReceive::Duplicate));
        assert_eq!(
            scheduler.accept(1, b"tampered"),
            Err(MultipathError::SequenceConflict)
        );
    }

    #[test]
    fn scheduler_bounds_reorder_buffer_and_fails_closed() {
        let mut scheduler = MultipathScheduler::new(1);
        scheduler.add_path(1, 1).unwrap();
        assert_eq!(
            scheduler.accept(4, b"future"),
            Ok(MultipathReceive::Buffered)
        );
        assert_eq!(
            scheduler.accept(5, b"too-far"),
            Err(MultipathError::ReorderBufferFull)
        );
        scheduler.fail_path(1).unwrap();
        assert_eq!(scheduler.select_path(), Err(MultipathError::NoUsablePath));
    }

    #[test]
    fn budget_bounds_extension() {
        let mut state = ExtensionState::new();
        for _ in 0..MAX_RELAY_NODES {
            state.extend(true).unwrap();
        }
        assert_eq!(state.remaining(), 0);
        assert_eq!(
            state.extend(true),
            Err(ExtensionError::RelayBudgetExhausted)
        );
    }

    #[test]
    fn protocol_limit_is_absolute() {
        let mut state = ExtensionState {
            relays_used: PROTOCOL_MAX_RELAY_NODES - 1,
            max_relays: PROTOCOL_MAX_RELAY_NODES,
        };
        state.extend(true).unwrap();
        assert_eq!(state.extend(true), Err(ExtensionError::ProtocolLimit));
    }

    #[test]
    fn denied_hop_does_not_consume() {
        let mut state = ExtensionState::new();
        state.extend(false).unwrap();
        assert_eq!(state.relays_used, 0);
    }
}
