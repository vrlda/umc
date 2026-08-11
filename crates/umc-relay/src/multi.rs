//! Multi-hop circuit construction (relay.md §27): hop-by-hop extension with
//! a relay-count budget. Each relay sees only its adjacent hops.
use crate::circuit::{MAX_RELAY_NODES, PROTOCOL_MAX_RELAY_NODES};

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
