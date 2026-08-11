//! `ROUTE_REQUEST` admission (routing.md §8-13): cheap checks before any work.
use crate::duplicate::{RequestCache, RequestIdentity};
use crate::types::{DEFAULT_FANOUT, MAX_FANOUT, MAX_HOP_LIMIT, MAX_REQUEST_LIFETIME_MS};
use umc_types::runtime::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Admit {
        hop_limit: u64,
        remaining_lifetime_ms: u64,
        forward_to: Vec<Vec<u8>>,
    },
    Suppress,
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    HopLimitZero,
    HopLimitExceeded,
    LifetimeTooLong,
    UnknownFlag,
    FanoutExceeded,
    RateLimited,
}

#[derive(Debug, Clone)]
pub struct RequestPolicy {
    pub max_fanout: usize,
    pub max_hops: u64,
    pub max_lifetime_ms: u64,
    /// Route requests per Observed peer per minute (routing.md §42). The
    /// default is 10/min; enforcement lives in the daemon rate-limiter layer
    /// (lands with the request loop), not in this pure admission check.
    pub requests_per_minute: u64,
}

impl Default for RequestPolicy {
    fn default() -> Self {
        Self {
            max_fanout: DEFAULT_FANOUT,
            max_hops: MAX_HOP_LIMIT,
            max_lifetime_ms: MAX_REQUEST_LIFETIME_MS,
            requests_per_minute: 10,
        }
    }
}

/// Validate and admit a route request (routing.md §10). Returns the effective
/// hop limit after decrement and the peers to forward to (default fanout).
///
/// # Errors
///
/// Returns `AdmissionError` when any cheap admission check fails: a zero or
/// oversized hop limit, an overlong lifetime, unknown flag bits, or a policy
/// fanout above the stable-profile maximum.
#[allow(clippy::too_many_arguments)]
pub fn admit_request(
    request_id: &[u8; 16],
    adjacent_sender: &[u8],
    flags: u8,
    hop_limit: u64,
    lifetime_ms: u64,
    candidates: &[Vec<u8>],
    policy: &RequestPolicy,
    cache: &mut RequestCache,
    now: Instant,
) -> Result<Admission, AdmissionError> {
    // 1. Cheap field validation.
    if hop_limit == 0 {
        return Err(AdmissionError::HopLimitZero);
    }
    if hop_limit > policy.max_hops || hop_limit > MAX_HOP_LIMIT {
        return Err(AdmissionError::HopLimitExceeded);
    }
    if lifetime_ms > policy.max_lifetime_ms || lifetime_ms > MAX_REQUEST_LIFETIME_MS {
        return Err(AdmissionError::LifetimeTooLong);
    }
    if flags & 0xE0 != 0 {
        return Err(AdmissionError::UnknownFlag);
    }
    // 2. Duplicate suppression.
    let identity = RequestIdentity {
        request_id: *request_id,
        adjacent_sender: adjacent_sender.to_vec(),
    };
    let fanout = candidates.len().min(policy.max_fanout).min(MAX_FANOUT);
    if fanout == 0 {
        // Direct-match only: no forwarding.
        return Ok(Admission::Admit {
            hop_limit: hop_limit.saturating_sub(1),
            remaining_lifetime_ms: lifetime_ms,
            forward_to: vec![],
        });
    }
    let forward_to: Vec<Vec<u8>> = candidates[..fanout].to_vec();
    if cache.already_forwarded(&identity, &forward_to[0]) {
        return Ok(Admission::Suppress);
    }
    if let Some(existing) = cache.admit(identity.clone(), hop_limit, now, &forward_to) {
        if existing.best_hop_limit >= hop_limit {
            return Ok(Admission::Suppress);
        }
    }
    // 3. Fanout bound (routing.md §13): local policy may never exceed the
    //    stable-profile maximum of eight.
    if policy.max_fanout > MAX_FANOUT {
        return Err(AdmissionError::FanoutExceeded);
    }
    Ok(Admission::Admit {
        hop_limit: hop_limit.saturating_sub(1),
        remaining_lifetime_ms: lifetime_ms,
        forward_to,
    })
}

/// Select initial peers for a new request (routing.md §9): diverse, small set.
#[must_use]
pub fn select_initial_peers(candidates: &[Vec<u8>], default_fanout: usize) -> Vec<Vec<u8>> {
    candidates
        .iter()
        .take(default_fanout.max(1))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::runtime::Duration;

    fn policy() -> RequestPolicy {
        RequestPolicy::default()
    }

    #[test]
    fn hop_limit_decremented_and_bounded() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        let peers = vec![b"p1".to_vec(), b"p2".to_vec(), b"p3".to_vec()];
        let admission = admit_request(
            &[1u8; 16],
            b"src",
            0,
            8,
            30_000,
            &peers,
            &policy(),
            &mut cache,
            Instant(0),
        )
        .unwrap();
        match admission {
            Admission::Admit {
                hop_limit,
                forward_to,
                ..
            } => {
                assert_eq!(hop_limit, 7);
                assert_eq!(forward_to.len(), 3);
            }
            other => panic!("expected admit, got {other:?}"),
        }
    }

    #[test]
    fn zero_hop_limit_rejected() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        assert_eq!(
            admit_request(
                &[1u8; 16],
                b"src",
                0,
                0,
                30_000,
                &[],
                &policy(),
                &mut cache,
                Instant(0)
            ),
            Err(AdmissionError::HopLimitZero)
        );
    }

    #[test]
    fn lifetime_capped() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        assert_eq!(
            admit_request(
                &[1u8; 16],
                b"src",
                0,
                8,
                6 * 60 * 1000,
                &[],
                &policy(),
                &mut cache,
                Instant(0)
            ),
            Err(AdmissionError::LifetimeTooLong)
        );
    }

    #[test]
    fn fanout_bounded_to_policy() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        let peers: Vec<Vec<u8>> = (0..10).map(|i| vec![i]).collect();
        let admission = admit_request(
            &[1u8; 16],
            b"src",
            0,
            8,
            30_000,
            &peers,
            &policy(),
            &mut cache,
            Instant(0),
        )
        .unwrap();
        match admission {
            Admission::Admit { forward_to, .. } => assert_eq!(forward_to.len(), DEFAULT_FANOUT),
            other => panic!("expected admit, got {other:?}"),
        }
    }

    #[test]
    fn exact_duplicate_suppressed() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        let peers = vec![b"p1".to_vec()];
        admit_request(
            &[1u8; 16],
            b"src",
            0,
            8,
            30_000,
            &peers,
            &policy(),
            &mut cache,
            Instant(0),
        )
        .unwrap();
        assert_eq!(
            admit_request(
                &[1u8; 16],
                b"src",
                0,
                8,
                30_000,
                &peers,
                &policy(),
                &mut cache,
                Instant(1)
            )
            .unwrap(),
            Admission::Suppress
        );
    }
}
