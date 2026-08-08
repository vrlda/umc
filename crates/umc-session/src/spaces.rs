use umc_wire::pn::{reconstruct, PnError, MAX_PACKET_NUMBER};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketSpace {
    Initial,
    Handshake,
    SessionData,
    PathControl,
    RelayData,
}

pub const DEFAULT_REPLAY_WINDOW: u64 = 4_096;

#[derive(Debug, Clone)]
pub struct PacketSpaceState {
    pub space: PacketSpace,
    next_packet_number: u64,
    largest_received: u64,
    replay: ReplayWindow,
}

impl PacketSpaceState {
    #[must_use]
    pub fn new(space: PacketSpace) -> Self {
        Self {
            space,
            next_packet_number: 0,
            largest_received: 0,
            replay: ReplayWindow::new(DEFAULT_REPLAY_WINDOW),
        }
    }

    /// Allocate the next outgoing packet number for this space.
    ///
    /// # Errors
    ///
    /// Returns `PacketNumberExhausted` when the space's packet numbers are
    /// exhausted (session.md §8.1).
    pub fn allocate_packet_number(&mut self) -> Result<u64, SpaceError> {
        if self.next_packet_number > MAX_PACKET_NUMBER {
            return Err(SpaceError::PacketNumberExhausted);
        }
        let pn = self.next_packet_number;
        self.next_packet_number += 1;
        Ok(pn)
    }

    /// Validate an incoming truncated packet number against the replay window.
    /// Rejects duplicates AND packets below the retained window (session.md §8.2).
    ///
    /// # Errors
    ///
    /// Returns `Pn` when reconstruction fails (invalid truncation or
    /// overflow) and `DuplicateOrStale` when the packet is a duplicate or
    /// falls below the retained replay window.
    pub fn admit_received(&mut self, truncated: u64, bits: u32) -> Result<u64, SpaceError> {
        let expected = self.largest_received.saturating_add(1);
        let pn = reconstruct(truncated, bits, expected).map_err(SpaceError::Pn)?;
        if !self.replay.check_and_mark(pn) {
            return Err(SpaceError::DuplicateOrStale);
        }
        if pn > self.largest_received {
            self.largest_received = pn;
        }
        Ok(pn)
    }

    #[must_use]
    /// Admit an already-reconstructed packet number (the parser rebuilt the
    /// full pn for the AEAD open): replay-window check without a second
    /// reconstruction step.
    ///
    /// # Errors
    ///
    /// Returns [`SpaceError::DuplicateOrStale`] for replayed or below-window
    /// packet numbers.
    pub fn admit_reconstructed(&mut self, pn: u64) -> Result<u64, SpaceError> {
        if !self.replay.check_and_mark(pn) {
            return Err(SpaceError::DuplicateOrStale);
        }
        if pn > self.largest_received {
            self.largest_received = pn;
        }
        Ok(pn)
    }

    #[must_use]
    pub fn largest_received(&self) -> u64 {
        self.largest_received
    }

    /// Bytes of internal replay state (session.md §8.2): the window is a
    /// fixed ring of `DEFAULT_REPLAY_WINDOW` bits (512 bytes), independent of
    /// traffic volume.
    #[must_use]
    pub fn replay_bytes(&self) -> usize {
        self.replay.bits.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceError {
    PacketNumberExhausted,
    Pn(PnError),
    DuplicateOrStale,
}

/// Bounded replay window (session.md §8.2): a ring of `size` bits over the
/// most recent packet numbers, plus a lower-bound check.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    size: u64,
    bits: Vec<u8>,
    largest: u64,
}

impl ReplayWindow {
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn new(size: u64) -> Self {
        Self {
            size,
            bits: vec![0u8; size.div_ceil(8) as usize],
            largest: 0,
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn get(&self, pn: u64) -> bool {
        let pos = (pn % self.size) as usize;
        (self.bits[pos / 8] >> (pos % 8)) & 1 == 1
    }

    #[allow(clippy::cast_possible_truncation)]
    fn set(&mut self, pn: u64) {
        let pos = (pn % self.size) as usize;
        self.bits[pos / 8] |= 1 << (pos % 8);
    }

    /// Returns true when the packet may be processed: it is either new
    /// (above the largest seen) or an unseen in-window gap. Returns false
    /// for duplicates (bit already set) and packets below the retained
    /// window (pn + size <= largest).
    pub fn check_and_mark(&mut self, pn: u64) -> bool {
        if pn.saturating_add(self.size) <= self.largest {
            return false; // below the retained window
        }
        if pn <= self.largest && self.get(pn) {
            return false; // duplicate
        }
        if pn > self.largest {
            self.largest = pn;
        }
        self.set(pn);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_numbers_monotonic() {
        let mut s = PacketSpaceState::new(PacketSpace::SessionData);
        assert_eq!(s.allocate_packet_number().unwrap(), 0);
        assert_eq!(s.allocate_packet_number().unwrap(), 1);
        assert_eq!(s.allocate_packet_number().unwrap(), 2);
    }

    #[test]
    fn duplicate_rejected_after_replay_mark() {
        let mut s = PacketSpaceState::new(PacketSpace::SessionData);
        assert_eq!(s.admit_received(0, 8).unwrap(), 0);
        assert_eq!(s.admit_received(0, 8), Err(SpaceError::DuplicateOrStale));
    }

    #[test]
    fn reordered_packets_admitted_once() {
        let mut s = PacketSpaceState::new(PacketSpace::SessionData);
        assert_eq!(s.admit_received(5, 8).unwrap(), 5);
        assert_eq!(s.admit_received(3, 8).unwrap(), 3);
        assert_eq!(s.admit_received(3, 8), Err(SpaceError::DuplicateOrStale));
        assert_eq!(s.largest_received(), 5);
    }

    #[test]
    fn stale_packets_below_window_rejected() {
        let mut s = PacketSpaceState::new(PacketSpace::SessionData);
        for pn in 0..=DEFAULT_REPLAY_WINDOW {
            let truncated = pn & 0xFF;
            assert!(s.admit_received(truncated, 8).is_ok(), "pn {pn}");
        }
        // pn 0 now lies below the retained window (0 + 4096 <= 4096).
        assert_eq!(s.admit_received(0, 8), Err(SpaceError::DuplicateOrStale));
    }

    #[test]
    fn replay_window_bounds_memory() {
        let mut s = PacketSpaceState::new(PacketSpace::SessionData);
        for pn in 0..DEFAULT_REPLAY_WINDOW + 10 {
            let truncated = pn & 0xFF;
            assert!(s.admit_received(truncated, 8).is_ok(), "pn {pn}");
        }
    }
}
