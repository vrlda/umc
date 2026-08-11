//! Discovery provider interface (core.md §35, discovery.md §5).
use umc_types::runtime::Instant;

pub const DEFAULT_MAX_CANDIDATES: usize = 256;
pub const MAX_CANDIDATE_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CandidateSource {
    Static,
    LocalDiscovery,
    PeerHint,
    Invitation,
    Bootstrap,
    Application,
    CarrierNative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateAuth {
    Unauthenticated,
    CarrierAuthenticated,
    IntroductionAuthenticated,
    InvitationAuthenticated,
    PreviousSessionBound,
    SignedBootstrap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharingPolicy {
    LocalUseOnly,
    ShareSelected,
    ShareLocalScope,
    ShareGeneral,
    DoNotReshare,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCandidate {
    pub candidate_id: u64,
    pub carrier_type: String,
    pub connection_hint: Vec<u8>,
    pub source: CandidateSource,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub sharing_policy: SharingPolicy,
    pub authentication: CandidateAuth,
    pub local: bool,
}

impl PeerCandidate {
    #[must_use]
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// Candidate lifetime capped at 24h without refresh (discovery.md §8.1).
    pub fn cap_lifetime(&mut self, now: Instant) {
        // Static/pinned configuration is an explicit local policy and may
        // outlive the provider's ordinary refresh window (discovery.md §8.1).
        if self.source == CandidateSource::Static {
            return;
        }
        let cap = now + umc_types::runtime::Duration::from_millis(MAX_CANDIDATE_LIFETIME_MS);
        if self.expires_at > cap {
            self.expires_at = cap;
        }
    }
}

pub trait DiscoveryProvider: Send + Sync {
    fn source(&self) -> CandidateSource;

    /// Starts provider activity. Implementations should make this operation
    /// idempotent so a manager can restart a provider after a transient
    /// failure (discovery.md §5, §17.3).
    ///
    /// # Errors
    ///
    /// Returns a provider-specific error when startup cannot be completed.
    fn start(&mut self) -> Result<(), String> {
        Ok(())
    }

    /// Stops provider activity and releases provider-owned resources.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific error when shutdown cannot be completed.
    fn stop(&mut self) -> Result<(), String> {
        Ok(())
    }

    /// A bounded batch of candidates. Stops on deadline.
    fn candidates(&self, maximum: usize) -> Vec<PeerCandidate>;

    /// Fallible candidate collection hook used by [`ProviderManager`]. The
    /// infallible `candidates` method remains the compatibility surface for
    /// small providers; providers that perform I/O can override this hook to
    /// report failure without taking down other providers.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific error when candidate collection fails.
    fn collect_candidates(&self, maximum: usize) -> Result<Vec<PeerCandidate>, String> {
        Ok(self.candidates(maximum))
    }

    /// Publishes a hint through the provider.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific error string if the hint could not be
    /// published.
    fn publish(&self, hint: &[u8]) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_lifetime_capped() {
        let now = Instant(0);
        let mut c = PeerCandidate {
            candidate_id: 1,
            carrier_type: "ump.udp/1".into(),
            connection_hint: vec![],
            source: CandidateSource::PeerHint,
            created_at: now,
            expires_at: now + umc_types::runtime::Duration::from_millis(48 * 60 * 60 * 1000),
            sharing_policy: SharingPolicy::DoNotReshare,
            authentication: CandidateAuth::Unauthenticated,
            local: false,
        };
        c.cap_lifetime(now);
        assert!(c.is_expired(
            now + umc_types::runtime::Duration::from_millis(MAX_CANDIDATE_LIFETIME_MS)
        ));
    }

    #[test]
    fn expired_candidates_detectable() {
        let now = Instant(0);
        let c = PeerCandidate {
            candidate_id: 2,
            carrier_type: "ump.tcp/1".into(),
            connection_hint: vec![],
            source: CandidateSource::Static,
            created_at: now,
            expires_at: now,
            sharing_policy: SharingPolicy::LocalUseOnly,
            authentication: CandidateAuth::Unauthenticated,
            local: true,
        };
        assert!(c.is_expired(now));
    }

    #[test]
    fn static_candidates_may_outlive_refresh_cap() {
        let now = Instant(0);
        let mut c = PeerCandidate {
            candidate_id: 3,
            carrier_type: "ump.tcp/1".into(),
            connection_hint: vec![],
            source: CandidateSource::Static,
            created_at: now,
            expires_at: now + umc_types::runtime::Duration::from_millis(u64::MAX / 2),
            sharing_policy: SharingPolicy::LocalUseOnly,
            authentication: CandidateAuth::Unauthenticated,
            local: true,
        };
        c.cap_lifetime(now);
        assert_eq!(c.expires_at.0, u64::MAX / 2);
    }
}
