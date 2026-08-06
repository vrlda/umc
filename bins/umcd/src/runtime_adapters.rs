//! OS and Tokio runtime adapters (core.md §12): `Clock` and `EntropySource`
//! implementations for the reference daemon.
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use umc_types::runtime::{Clock, EntropySource, Instant};

/// Wall-clock milliseconds since the Unix epoch (matches examples/echo).
#[derive(Debug)]
pub struct OsClock;

impl Clock for OsClock {
    fn now(&self) -> Instant {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
        Instant(millis)
    }
}

/// OS CSPRNG entropy.
#[derive(Debug)]
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&self, out: &mut [u8]) {
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(out);
    }
}

/// Monotonic baseline for [`TokioAdaptor`], captured on first use.
static TOKIO_BASELINE: OnceLock<tokio::time::Instant> = OnceLock::new();

/// Tokio-backed adapters. `umc_types::runtime` exposes only `Clock` and
/// `EntropySource` (Phase 1-7); there is no Tokio-specific trait to
/// implement, so this type covers the two existing traits: a monotonic
/// clock over `tokio::time` and OS entropy (the tokio ecosystem has no
/// CSPRNG of its own; `OsRng` is the reference path).
#[derive(Debug)]
pub struct TokioAdaptor;

impl Clock for TokioAdaptor {
    fn now(&self) -> Instant {
        let baseline = *TOKIO_BASELINE.get_or_init(tokio::time::Instant::now);
        Instant(u64::try_from(baseline.elapsed().as_millis()).unwrap_or(0))
    }
}

impl EntropySource for TokioAdaptor {
    fn fill(&self, out: &mut [u8]) {
        OsEntropy.fill(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_clock_is_monotonicish() {
        let clock = OsClock;
        let first = clock.now();
        let second = clock.now();
        assert!(second >= first);
    }

    #[test]
    fn os_entropy_never_all_zeros() {
        let entropy = OsEntropy;
        let mut buf = [0u8; 64];
        entropy.fill(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }
}
