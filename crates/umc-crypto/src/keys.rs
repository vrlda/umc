//! Key lifecycle bookkeeping (handshake.md §40 discard schedule).
//!
//! Tracks when Initial and Handshake secrets become discardable:
//! - Initial secrets are discarded once a Handshake-space packet is
//!   successfully processed (`on_handshake_packet`).
//! - Handshake secrets are discarded once the session is confirmed, i.e. the
//!   client/server finished exchange validated (`on_confirmation`).
//!
//! Ordering invariant: `on_confirmation` implies Handshake-space packets were
//! processed, so it also latches the Initial-discard condition. The schedule
//! therefore never reports initial-discard before handshake-discard becomes
//! possible — after `on_confirmation`, both flags are set.

/// Discard schedule for the Initial and Handshake encryption levels.
///
/// Flags are latched: once set, they stay set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyDiscardSchedule {
    initial_discarded: bool,
    handshake_discarded: bool,
}

impl KeyDiscardSchedule {
    /// True when the Initial keys may be discarded (a Handshake-space packet
    /// has been successfully processed).
    #[must_use]
    pub fn should_discard_initial(&self) -> bool {
        self.initial_discarded
    }

    /// Marks the Initial keys discardable. Called when a Handshake-space
    /// packet is successfully processed.
    pub fn on_handshake_packet(&mut self) {
        self.initial_discarded = true;
    }

    /// True once the session is confirmed (finished exchange validated).
    #[must_use]
    pub fn should_discard_handshake(&self) -> bool {
        self.handshake_discarded
    }

    /// Marks the Handshake keys discardable. Called when the finished exchange
    /// completes. Confirmation implies Handshake-space packets were processed,
    /// so the Initial-discard condition is set as well.
    pub fn on_confirmation(&mut self) {
        self.handshake_discarded = true;
        self.initial_discarded = true;
    }

    /// Whether the Initial keys have been marked discardable.
    #[must_use]
    pub fn initial_discarded(&self) -> bool {
        self.initial_discarded
    }

    /// Whether the Handshake keys have been marked discardable.
    #[must_use]
    pub fn handshake_discarded(&self) -> bool {
        self.handshake_discarded
    }
}

#[cfg(test)]
mod tests {
    use super::KeyDiscardSchedule;

    #[test]
    fn nothing_discarded_by_default() {
        let schedule = KeyDiscardSchedule::default();
        assert!(!schedule.should_discard_initial());
        assert!(!schedule.should_discard_handshake());
        assert!(!schedule.initial_discarded());
        assert!(!schedule.handshake_discarded());
    }

    #[test]
    fn handshake_packet_discards_initial() {
        let mut schedule = KeyDiscardSchedule::default();
        schedule.on_handshake_packet();
        assert!(schedule.should_discard_initial());
        assert!(!schedule.should_discard_handshake());
    }

    #[test]
    fn confirmation_discards_both() {
        let mut schedule = KeyDiscardSchedule::default();
        schedule.on_confirmation();
        assert!(schedule.should_discard_initial());
        assert!(schedule.should_discard_handshake());
    }

    #[test]
    fn discard_flags_are_latched() {
        let mut schedule = KeyDiscardSchedule::default();
        schedule.on_handshake_packet();
        schedule.on_handshake_packet();
        assert!(schedule.should_discard_initial());
        schedule.on_confirmation();
        schedule.on_confirmation();
        assert!(schedule.should_discard_handshake());
        assert!(schedule.should_discard_initial());
    }
}
