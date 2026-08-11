/// RTT estimation (session.md §13).
#[derive(Debug, Clone)]
pub struct RttEstimator {
    pub latest_rtt: u64,
    pub min_rtt: u64,
    pub smoothed_rtt: u64,
    pub rtt_variance: u64,
    pub initialized: bool,
}

impl RttEstimator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            latest_rtt: 0,
            min_rtt: 0,
            smoothed_rtt: 0,
            rtt_variance: 0,
            initialized: false,
        }
    }

    pub fn sample(&mut self, sample_ms: u64) {
        if !self.initialized {
            self.latest_rtt = sample_ms;
            self.min_rtt = sample_ms;
            self.smoothed_rtt = sample_ms;
            self.rtt_variance = sample_ms / 2;
            self.initialized = true;
            return;
        }
        self.latest_rtt = sample_ms;
        self.min_rtt = self.min_rtt.min(sample_ms);
        let abs_diff = self.smoothed_rtt.abs_diff(sample_ms);
        self.rtt_variance = (3 * self.rtt_variance + abs_diff) / 4;
        self.smoothed_rtt = (7 * self.smoothed_rtt + sample_ms) / 8;
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_initializes() {
        let mut r = RttEstimator::new();
        r.sample(100);
        assert!(r.initialized);
        assert_eq!(r.latest_rtt, 100);
        assert_eq!(r.min_rtt, 100);
        assert_eq!(r.smoothed_rtt, 100);
        assert_eq!(r.rtt_variance, 50);
    }

    #[test]
    fn min_rtt_never_increases() {
        let mut r = RttEstimator::new();
        r.sample(100);
        r.sample(200);
        assert_eq!(r.min_rtt, 100);
    }

    #[test]
    fn smoothed_moves_gradually() {
        let mut r = RttEstimator::new();
        r.sample(100);
        r.sample(100);
        assert_eq!(r.smoothed_rtt, 100);
        r.sample(300);
        assert!(r.smoothed_rtt > 100 && r.smoothed_rtt < 300);
    }
}
