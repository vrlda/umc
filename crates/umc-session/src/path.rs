//! Path records and validation (session.md §25-26).
use umc_types::runtime::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    New,
    Validating,
    Validated,
    Degraded,
    Failed,
    Retired,
}

pub const MAX_CANDIDATE_PATHS: usize = 2;
pub const MAX_OUTSTANDING_CHALLENGES: usize = 3;
pub const MAX_CHALLENGE_RETRIES: u32 = 3;
const CHALLENGE_RETRY_PTO_MULTIPLIER: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathChallenge {
    pub data: [u8; 8],
    pub sent_at: Instant,
    pub expires_at: Instant,
    pub retries: u32,
}

#[derive(Debug, Clone)]
pub struct Path {
    pub path_id: u64,
    pub state: PathState,
    pub carrier_type: String,
    pub local_context: Vec<u8>,
    pub remote_context: Vec<u8>,
    pub validated: bool,
    pub rtt_ms: u64,
    pub mtu: usize,
    pub last_activity: Instant,
    pub received_bytes_unvalidated: u64,
    pub sent_bytes_unvalidated: u64,
    pub challenges: Vec<PathChallenge>,
}

impl Path {
    #[must_use]
    pub fn new(
        path_id: u64,
        carrier_type: String,
        local: Vec<u8>,
        remote: Vec<u8>,
        now: Instant,
    ) -> Self {
        Self {
            path_id,
            state: PathState::New,
            carrier_type,
            local_context: local,
            remote_context: remote,
            validated: false,
            rtt_ms: 0,
            mtu: 1_200,
            last_activity: now,
            received_bytes_unvalidated: 0,
            sent_bytes_unvalidated: 0,
            challenges: Vec::new(),
        }
    }

    /// Before validation, sent bytes are capped at 3x received (session.md §26).
    #[must_use]
    pub fn send_allowance(&self) -> u64 {
        self.received_bytes_unvalidated
            .saturating_mul(3)
            .saturating_sub(self.sent_bytes_unvalidated)
    }

    pub fn record_received(&mut self, bytes: u64, now: Instant) {
        self.received_bytes_unvalidated += bytes;
        self.last_activity = now;
    }

    pub fn record_sent(&mut self, bytes: u64) {
        self.sent_bytes_unvalidated += bytes;
    }

    /// Starts a validation challenge with a PTO-based expiry (1-second floor).
    ///
    /// # Errors
    /// Returns [`PathError::TooManyChallenges`] when the outstanding-challenge
    /// budget is exhausted.
    pub fn start_validation(
        &mut self,
        challenge: [u8; 8],
        now: Instant,
        pto_ms: u64,
    ) -> Result<(), PathError> {
        if self.challenges.len() >= MAX_OUTSTANDING_CHALLENGES {
            return Err(PathError::TooManyChallenges);
        }
        let pto = Duration::from_millis(pto_ms.max(1_000));
        self.challenges.push(PathChallenge {
            data: challenge,
            sent_at: now,
            expires_at: now
                + Duration::from_millis(CHALLENGE_RETRY_PTO_MULTIPLIER * pto.as_millis()),
            retries: 0,
        });
        self.state = PathState::Validating;
        Ok(())
    }

    /// A `PATH_RESPONSE` matching an outstanding challenge validates the path
    /// (session.md §26).
    ///
    /// # Errors
    /// Returns [`PathError::UnknownChallenge`] if no outstanding challenge
    /// matches the response.
    pub fn confirm(&mut self, response: &[u8; 8]) -> Result<(), PathError> {
        let index = self
            .challenges
            .iter()
            .position(|c| &c.data == response)
            .ok_or(PathError::UnknownChallenge)?;
        self.challenges.remove(index);
        self.validated = true;
        self.state = PathState::Validated;
        self.sent_bytes_unvalidated = 0;
        self.received_bytes_unvalidated = 0;
        Ok(())
    }

    /// Re-arm expired challenges; fail when retries exceed the budget.
    ///
    /// # Errors
    /// Returns [`PathError::ValidationFailed`] when an expired challenge has
    /// exhausted [`MAX_CHALLENGE_RETRIES`].
    pub fn retry_expired_challenges(&mut self, now: Instant) -> Result<bool, PathError> {
        let mut retried = false;
        for challenge in &mut self.challenges {
            if challenge.expires_at <= now {
                challenge.retries += 1;
                if challenge.retries > MAX_CHALLENGE_RETRIES {
                    return Err(PathError::ValidationFailed);
                }
                challenge.expires_at = now + Duration::from_millis(1_000);
                retried = true;
            }
        }
        Ok(retried)
    }

    pub fn mark_failed(&mut self) {
        self.state = PathState::Failed;
        self.validated = false;
    }

    pub fn mark_degraded(&mut self) {
        if self.state == PathState::Validated {
            self.state = PathState::Degraded;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    TooManyChallenges,
    UnknownChallenge,
    ValidationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amplification_limit_before_validation() {
        let now = Instant(0);
        let mut p = Path::new(1, "ump.udp/1".into(), vec![], vec![], now);
        p.record_received(100, now);
        assert_eq!(p.send_allowance(), 300);
        p.record_sent(300);
        assert_eq!(p.send_allowance(), 0);
    }

    #[test]
    fn challenge_validation_flow() {
        let now = Instant(0);
        let mut p = Path::new(1, "ump.udp/1".into(), vec![], vec![], now);
        p.start_validation([1u8; 8], now, 100).unwrap();
        assert_eq!(p.state, PathState::Validating);
        assert_eq!(p.confirm(&[9u8; 8]), Err(PathError::UnknownChallenge));
        p.confirm(&[1u8; 8]).unwrap();
        assert!(p.validated);
        assert_eq!(p.state, PathState::Validated);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn challenge_budget_and_retries() {
        let now = Instant(0);
        let mut p = Path::new(1, "ump.udp/1".into(), vec![], vec![], now);
        for i in 0..MAX_OUTSTANDING_CHALLENGES {
            p.start_validation([i as u8; 8], now, 100).unwrap();
        }
        assert_eq!(
            p.start_validation([9u8; 8], now, 100),
            Err(PathError::TooManyChallenges)
        );
    }
}
