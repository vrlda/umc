//! Key-phase management (session.md §24, handshake.md §41).
use umc_crypto::aead::PacketKeys;
use umc_crypto::key_update::next_traffic_secret;
use umc_types::runtime::Duration;

pub const MAX_RETAINED_KEY_PHASES: usize = 2;

#[derive(Debug, Clone)]
pub struct KeyUpdateState {
    pub local_secret: [u8; 32],
    pub remote_secret: [u8; 32],
    pub local_phase: u8,
    pub remote_phase: u8,
    pub update_sequence: u64,
    /// True after the local endpoint initiated and is awaiting confirmation.
    pub awaiting_confirmation: bool,
}

impl KeyUpdateState {
    #[must_use]
    pub fn new(local_secret: [u8; 32], remote_secret: [u8; 32]) -> Self {
        Self {
            local_secret,
            remote_secret,
            local_phase: 0,
            remote_phase: 0,
            update_sequence: 0,
            awaiting_confirmation: false,
        }
    }

    /// Derives the current local packet keys.
    ///
    /// # Panics
    /// Panics if the 32-byte traffic secret cannot be expanded into keys;
    /// impossible for in-range lengths.
    #[must_use]
    pub fn local_keys(&self) -> PacketKeys {
        PacketKeys::from_traffic_secret(&self.local_secret).expect("32-byte key")
    }

    /// Derives the current remote packet keys.
    ///
    /// # Panics
    /// Panics if the 32-byte traffic secret cannot be expanded into keys;
    /// impossible for in-range lengths.
    #[must_use]
    pub fn remote_keys(&self) -> PacketKeys {
        PacketKeys::from_traffic_secret(&self.remote_secret).expect("32-byte key")
    }

    /// Initiate a local key update (session.md §24.1).
    ///
    /// # Errors
    /// Returns [`KeyUpdateError::AlreadyPending`] if a previous update is still
    /// awaiting confirmation.
    pub fn initiate(&mut self) -> Result<u64, KeyUpdateError> {
        if self.awaiting_confirmation {
            return Err(KeyUpdateError::AlreadyPending);
        }
        self.local_secret = next_traffic_secret(&self.local_secret);
        self.local_phase ^= 1;
        self.update_sequence += 1;
        self.awaiting_confirmation = true;
        Ok(self.update_sequence)
    }

    /// Confirm the peer's new phase after a successful authenticated decrypt
    /// with the next keys (session.md §24.2).
    pub fn confirm_remote_phase(&mut self, new_remote_secret: [u8; 32]) {
        self.remote_secret = new_remote_secret;
        self.remote_phase ^= 1;
    }

    /// The peer acknowledged our phase (authenticated packet received).
    pub fn mark_confirmed(&mut self) {
        self.awaiting_confirmation = false;
    }

    /// Old keys are retained for a bounded reordering window (session.md §24.2).
    #[must_use]
    pub fn retention_period(&self, pto_ms: u64) -> Duration {
        Duration::from_millis((3 * pto_ms).max(1_000))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUpdateError {
    AlreadyPending,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiate_toggles_phase_and_blocks_second_update() {
        let mut state = KeyUpdateState::new([1u8; 32], [2u8; 32]);
        let seq = state.initiate().unwrap();
        assert_eq!(seq, 1);
        assert_eq!(state.local_phase, 1);
        assert_eq!(state.initiate(), Err(KeyUpdateError::AlreadyPending));
        state.mark_confirmed();
        let seq = state.initiate().unwrap();
        assert_eq!(seq, 2);
        assert_eq!(state.local_phase, 0);
    }

    #[test]
    fn secrets_change_on_update() {
        let mut state = KeyUpdateState::new([1u8; 32], [2u8; 32]);
        let before = state.local_keys().key;
        state.initiate().unwrap();
        let after = state.local_keys().key;
        assert_ne!(before, after);
    }

    #[test]
    fn update_sequence_increments() {
        let mut state = KeyUpdateState::new([1u8; 32], [2u8; 32]);
        assert_eq!(state.update_sequence, 0);
        state.initiate().unwrap();
        assert_eq!(state.update_sequence, 1);
        state.mark_confirmed();
        state.initiate().unwrap();
        assert_eq!(state.update_sequence, 2);
    }
}
