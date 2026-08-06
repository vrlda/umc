use super::spaces::PacketSpace;
use umc_types::runtime::Instant;

#[derive(Debug, Clone)]
pub struct SentPacket {
    pub packet_number: u64,
    pub space: PacketSpace,
    pub sent_at: Instant,
    pub size: usize,
    pub ack_eliciting: bool,
    pub in_flight: bool,
    pub key_phase: u8,
    /// Frame payload carried by the packet, retained so a lost packet can be
    /// retransmitted under a fresh packet number (session.md §14.3).
    pub payload: Vec<u8>,
}

impl SentPacket {
    #[must_use]
    pub fn new(
        packet_number: u64,
        space: PacketSpace,
        sent_at: Instant,
        size: usize,
        ack_eliciting: bool,
        key_phase: u8,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            packet_number,
            space,
            sent_at,
            size,
            ack_eliciting,
            in_flight: ack_eliciting,
            key_phase,
            payload,
        }
    }

    pub fn mark_acked(&mut self) {
        self.in_flight = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_ack_eliciting_packets_are_not_in_flight() {
        let p = SentPacket::new(
            0,
            PacketSpace::SessionData,
            Instant(0),
            64,
            false,
            0,
            Vec::new(),
        );
        assert!(!p.in_flight);
    }

    #[test]
    fn ack_eliciting_packets_are_in_flight() {
        let p = SentPacket::new(
            0,
            PacketSpace::SessionData,
            Instant(0),
            64,
            true,
            0,
            Vec::new(),
        );
        assert!(p.in_flight);
        let mut p = p;
        p.mark_acked();
        assert!(!p.in_flight);
    }
}
