/// Connection-level flow control (session.md §20).
#[derive(Debug, Clone)]
pub struct FlowControl {
    pub max_data_local: u64,
    pub max_data_remote: u64,
    pub consumed: u64,
    pub max_bidirectional_streams_local: u64,
    pub max_unidirectional_streams_local: u64,
}

impl FlowControl {
    #[must_use]
    pub fn new(initial_max_data: u64, max_bidi: u64, max_uni: u64) -> Self {
        Self {
            max_data_local: initial_max_data,
            max_data_remote: initial_max_data,
            consumed: 0,
            max_bidirectional_streams_local: max_bidi,
            max_unidirectional_streams_local: max_uni,
        }
    }

    /// Receive-side: account bytes received (final offsets only).
    ///
    /// # Errors
    ///
    /// Returns [`FlowError::Overflow`] if accounting overflows `u64`, or
    /// [`FlowError::ExceedsCredit`] if the new total exceeds
    /// `max_data_local`.
    pub fn consume(&mut self, bytes: u64) -> Result<(), FlowError> {
        let new_total = self
            .consumed
            .checked_add(bytes)
            .ok_or(FlowError::Overflow)?;
        if new_total > self.max_data_local {
            return Err(FlowError::ExceedsCredit);
        }
        self.consumed = new_total;
        Ok(())
    }

    /// Send-side: local consumption watermark tracked by the session; returns
    /// how much more data the peer may send (for `MAX_DATA` generation).
    #[must_use]
    pub fn credit_remaining_local(&self) -> u64 {
        self.max_data_local.saturating_sub(self.consumed)
    }

    pub fn grant_more(&mut self, new_max: u64) {
        if new_max > self.max_data_local {
            self.max_data_local = new_max;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowError {
    ExceedsCredit,
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_enforces_credit() {
        let mut f = FlowControl::new(100, 16, 16);
        f.consume(100).unwrap();
        assert_eq!(f.consume(1), Err(FlowError::ExceedsCredit));
        assert_eq!(f.credit_remaining_local(), 0);
    }

    #[test]
    fn grants_never_decrease() {
        let mut f = FlowControl::new(100, 16, 16);
        f.grant_more(50);
        assert_eq!(f.max_data_local, 100);
        f.grant_more(200);
        assert_eq!(f.max_data_local, 200);
    }

    #[test]
    fn overflow_detected() {
        let mut f = FlowControl::new(u64::MAX, 16, 16);
        f.consume(u64::MAX).unwrap();
        assert_eq!(f.consume(1), Err(FlowError::Overflow));
    }
}
