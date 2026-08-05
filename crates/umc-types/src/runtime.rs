//! Runtime abstractions (core.md §12, decisions.md §5).
//! Protocol-pure crates depend on these; Tokio adapters implement them.

pub type Monotonic = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(pub Monotonic);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Duration {
    pub millis: u64,
}

impl Duration {
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self { millis }
    }
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.millis
    }
}

impl std::ops::Add<Duration> for Instant {
    type Output = Instant;
    fn add(self, rhs: Duration) -> Instant {
        Instant(self.0.saturating_add(rhs.millis))
    }
}

impl Instant {
    #[must_use]
    pub fn duration_since(self, earlier: Instant) -> Duration {
        Duration {
            millis: self.0.saturating_sub(earlier.0),
        }
    }
}

/// Monotonic clock. Implemented by the runtime (Tokio in the reference daemon).
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// Secure randomness. Implemented by the runtime with an OS CSPRNG.
pub trait EntropySource: Send + Sync {
    fn fill(&self, out: &mut [u8]);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeClock(u64);

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            Instant(self.0)
        }
    }

    #[test]
    fn clock_and_duration_arithmetic() {
        let c = FakeClock(1_000);
        assert_eq!(c.now(), Instant(1_000));
        let later = Instant(1_000) + Duration::from_millis(500);
        assert_eq!(later.duration_since(Instant(1_000)).as_millis(), 500);
    }

    #[test]
    fn duration_since_saturates() {
        let d = Instant(10).duration_since(Instant(20));
        assert_eq!(d.as_millis(), 0);
    }
}
