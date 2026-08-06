use super::sent_packet::SentPacket;
use std::collections::VecDeque;

pub const MAX_ACK_RANGES: usize = 64;
pub const MAX_STORED_RANGES: usize = 256;
pub const DEFAULT_MAX_ACK_DELAY_MS: u64 = 25;

/// Received packet numbers per space, used to build ACK frames (session.md §11).
#[derive(Debug, Clone)]
pub struct AckReceiveState {
    ranges: VecDeque<(u64, u64)>, // (low, high) inclusive, ascending
    largest: Option<u64>,
    needs_ack: bool,
}

/// ACK frame fields: `(largest, ack_delay, first_range_len, [(gap, len)...])`.
pub type AckFrame = (u64, u64, u64, Vec<(u64, u64)>);

impl AckReceiveState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ranges: VecDeque::new(),
            largest: None,
            needs_ack: false,
        }
    }

    pub fn record(&mut self, packet_number: u64) {
        self.needs_ack = true;
        if match self.largest {
            Some(largest) => packet_number > largest,
            None => true,
        } {
            self.largest = Some(packet_number);
        }
        // Insert into ascending ranges, merging adjacency.
        let mut i = 0;
        while i < self.ranges.len() && self.ranges[i].1 < packet_number {
            i += 1;
        }
        if i < self.ranges.len()
            && self.ranges[i].0 <= packet_number
            && packet_number <= self.ranges[i].1
        {
            return; // duplicate
        }
        let new_range = (packet_number, packet_number);
        self.ranges.insert(i, new_range);
        // Merge with left neighbor.
        if i > 0 && self.ranges[i - 1].1 + 1 >= self.ranges[i].0 {
            let lo = self.ranges[i - 1].0;
            let hi = self.ranges[i].1.max(self.ranges[i - 1].1);
            self.ranges.remove(i);
            self.ranges[i - 1] = (lo, hi);
        }
        if i + 1 < self.ranges.len() && self.ranges[i].1 + 1 >= self.ranges[i + 1].0 {
            let lo = self.ranges[i].0;
            let hi = self.ranges[i + 1].1;
            self.ranges.remove(i);
            self.ranges[i] = (lo, hi);
        }
        while self.ranges.len() > MAX_STORED_RANGES {
            self.ranges.pop_front();
        }
    }

    #[must_use]
    pub fn largest(&self) -> Option<u64> {
        self.largest
    }

    pub fn take_needs_ack(&mut self) -> bool {
        std::mem::take(&mut self.needs_ack)
    }

    /// Build ACK frame fields: `(largest, ack_delay, first_range_len, [(gap, len)...])`.
    #[must_use]
    pub fn build_ack(&self, ack_delay_ms: u64) -> Option<AckFrame> {
        let largest = self.largest?;
        let highest = *self.ranges.back()?;
        debug_assert_eq!(highest.1, largest);
        let first_len = largest - highest.0 + 1;
        let mut additional = Vec::new();
        let mut prev_low = highest.0;
        for &(low, high) in self.ranges.iter().rev().skip(1) {
            let gap = prev_low.saturating_sub(high + 1);
            let length = high - low + 1;
            additional.push((gap, length));
            prev_low = low;
        }
        Some((largest, ack_delay_ms, first_len, additional))
    }
}

impl Default for AckReceiveState {
    fn default() -> Self {
        Self::new()
    }
}

/// Sender-side ACK validation: track sent packets, apply peer ACKs (session.md §11.3).
#[derive(Debug, Clone)]
pub struct AckSendState {
    sent: VecDeque<SentPacket>,
}

impl AckSendState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sent: VecDeque::new(),
        }
    }

    pub fn record_sent(&mut self, p: SentPacket) {
        self.sent.push_back(p);
    }

    #[must_use]
    pub fn sent(&self) -> &VecDeque<SentPacket> {
        &self.sent
    }

    /// Returns acknowledged sent packets, or Err on an unsent packet number.
    ///
    /// # Errors
    ///
    /// Returns [`AckError::EmptyRange`] when the first range length is zero,
    /// and [`AckError::AcknowledgesUnsent`] when `largest` exceeds the highest
    /// packet number recorded as sent.
    pub fn apply_ack(&mut self, largest: u64, ranges: &[(u64, u64)]) -> Result<Vec<u64>, AckError> {
        let first_len = ranges.first().map_or(0, |r| r.0);
        if first_len == 0 {
            return Err(AckError::EmptyRange);
        }
        let max_sent = self.sent.back().map_or(0, |p| p.packet_number);
        if largest > max_sent {
            return Err(AckError::AcknowledgesUnsent);
        }
        let mut acked = Vec::new();
        let in_range = |pn: u64, first_len: u64, ranges: &[(u64, u64)]| -> bool {
            if pn >= largest.saturating_sub(first_len - 1) && pn <= largest {
                return true;
            }
            let mut cursor = largest.saturating_sub(first_len);
            for &(gap, length) in ranges {
                if cursor == 0 {
                    return false;
                }
                cursor = cursor.saturating_sub(gap);
                if pn >= cursor.saturating_sub(length - 1) && pn <= cursor {
                    return true;
                }
                cursor = cursor.saturating_sub(length);
            }
            false
        };
        let extra = ranges
            .iter()
            .skip(1)
            .map(|r| (r.0, r.1))
            .collect::<Vec<_>>();
        let mut keep = VecDeque::new();
        for mut p in self.sent.drain(..) {
            if in_range(p.packet_number, first_len, &extra) {
                p.mark_acked();
                acked.push(p.packet_number);
            } else {
                keep.push_back(p);
            }
        }
        self.sent = keep;
        Ok(acked)
    }
}

impl Default for AckSendState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckError {
    AcknowledgesUnsent,
    EmptyRange,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spaces::PacketSpace;
    use umc_types::runtime::Instant;

    fn sent(pn: u64) -> SentPacket {
        SentPacket::new(pn, PacketSpace::SessionData, Instant(0), 64, true, 0)
    }

    #[test]
    fn receive_ranges_merge() {
        let mut s = AckReceiveState::new();
        s.record(1);
        s.record(2);
        s.record(3);
        s.record(10);
        let (largest, _, first_len, extra) = s.build_ack(1).unwrap();
        assert_eq!(largest, 10);
        assert_eq!(first_len, 1);
        assert_eq!(extra.len(), 1);
        assert_eq!(extra[0], (6, 3)); // gap 6, length 3
    }

    #[test]
    fn apply_ack_detects_unsent() {
        let mut s = AckSendState::new();
        s.record_sent(sent(1));
        s.record_sent(sent(2));
        assert_eq!(s.apply_ack(5, &[(1, 0)]), Err(AckError::AcknowledgesUnsent));
    }

    #[test]
    fn apply_ack_rejects_empty_first_range() {
        let mut s = AckSendState::new();
        s.record_sent(sent(1));
        s.record_sent(sent(2));
        assert_eq!(s.apply_ack(2, &[(0, 0)]), Err(AckError::EmptyRange));
    }

    #[test]
    fn apply_ack_marks_correct_packets() {
        let mut s = AckSendState::new();
        for pn in 0..10 {
            s.record_sent(sent(pn));
        }
        let acked = s.apply_ack(9, &[(3, 0)]).unwrap(); // first range covers 9,8,7
        assert_eq!(acked, vec![7, 8, 9]);
    }
}
