//! Route records and state machine (routing.md §6).
use umc_types::runtime::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteState {
    Candidate,
    Probing,
    Usable,
    Degraded,
    Failed,
    Expired,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteScope {
    LinkLocal,
    LocalMesh,
    Introduced,
    General,
}

impl RouteScope {
    /// Scope may narrow, never broaden (routing.md §14.5).
    #[must_use]
    pub fn narrows_to(&self, other: RouteScope) -> bool {
        rank(*self) >= rank(other)
    }
}

fn rank(scope: RouteScope) -> u8 {
    match scope {
        RouteScope::LinkLocal => 0,
        RouteScope::LocalMesh => 1,
        RouteScope::Introduced => 2,
        RouteScope::General => 3,
    }
}

pub const MAX_HOP_LIMIT: u64 = 32;
pub const DEFAULT_HOP_LIMIT: u64 = 8;
pub const DEFAULT_FANOUT: usize = 3;
pub const MAX_FANOUT: usize = 8;
pub const MAX_REQUEST_LIFETIME_MS: u64 = 5 * 60 * 1000;
pub const DEFAULT_REQUEST_LIFETIME_MS: u64 = 30_000;
pub const MAX_RESPONSES_PER_BRANCH: usize = 8;
pub const MAX_PATH_EXCLUSIONS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRecord {
    pub key: RouteKey,
    pub state: RouteState,
    pub next_hop: String,
    pub metadata: Vec<u8>,
    pub source_peer: Vec<u8>,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub last_success: Option<Instant>,
    pub last_failure: Option<Instant>,
    pub failure_count: u64,
    pub scope: RouteScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    pub destination_profile: u8,
    pub destination_hash: [u8; 32],
    pub scope: RouteScope,
    pub policy_class: u8,
}

impl RouteRecord {
    #[must_use]
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    pub fn mark(&mut self, state: RouteState, now: Instant) {
        match state {
            RouteState::Usable => {
                self.last_success = Some(now);
                self.failure_count = 0;
            }
            RouteState::Failed => {
                self.last_failure = Some(now);
                self.failure_count += 1;
            }
            _ => {}
        }
        self.state = state;
    }

    /// Route expiry never exceeds underlying evidence expiry (routing.md §24.2).
    pub fn cap_expiry(&mut self, evidence_expiry: Instant) {
        if evidence_expiry < self.expires_at {
            self.expires_at = evidence_expiry;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::runtime::Duration;

    #[test]
    fn scopes_narrow_but_never_broaden() {
        assert!(RouteScope::General.narrows_to(RouteScope::LocalMesh));
        assert!(RouteScope::LocalMesh.narrows_to(RouteScope::LocalMesh));
        assert!(!RouteScope::LocalMesh.narrows_to(RouteScope::General));
    }

    #[test]
    fn route_record_lifecycle() {
        let now = Instant(0);
        let mut r = RouteRecord {
            key: RouteKey {
                destination_profile: 0,
                destination_hash: [0u8; 32],
                scope: RouteScope::General,
                policy_class: 0,
            },
            state: RouteState::Candidate,
            next_hop: "peer-a".into(),
            metadata: vec![],
            source_peer: vec![1],
            created_at: now,
            expires_at: now + Duration::from_millis(600_000),
            last_success: None,
            last_failure: None,
            failure_count: 0,
            scope: RouteScope::General,
        };
        assert!(!r.is_expired(now + Duration::from_millis(599_999)));
        assert!(r.is_expired(now + Duration::from_millis(600_000)));
        r.mark(RouteState::Usable, now + Duration::from_millis(10));
        assert_eq!(r.last_success, Some(now + Duration::from_millis(10)));
        r.mark(RouteState::Failed, now + Duration::from_millis(20));
        assert_eq!(r.failure_count, 1);
        assert_eq!(r.state, RouteState::Failed);
    }

    #[test]
    fn expiry_capped_by_evidence() {
        let now = Instant(0);
        let mut r = RouteRecord {
            key: RouteKey {
                destination_profile: 0,
                destination_hash: [1u8; 32],
                scope: RouteScope::General,
                policy_class: 0,
            },
            state: RouteState::Usable,
            next_hop: "x".into(),
            metadata: vec![],
            source_peer: vec![],
            created_at: now,
            expires_at: now + Duration::from_millis(1_000),
            last_success: None,
            last_failure: None,
            failure_count: 0,
            scope: RouteScope::General,
        };
        r.cap_expiry(now + Duration::from_millis(500));
        assert_eq!(r.expires_at, now + Duration::from_millis(500));
    }

    #[test]
    fn expiry_cap_never_extends() {
        let now = Instant(0);
        let mut r = RouteRecord {
            key: RouteKey {
                destination_profile: 0,
                destination_hash: [2u8; 32],
                scope: RouteScope::General,
                policy_class: 0,
            },
            state: RouteState::Usable,
            next_hop: "x".into(),
            metadata: vec![],
            source_peer: vec![],
            created_at: now,
            expires_at: now + Duration::from_millis(500),
            last_success: None,
            last_failure: None,
            failure_count: 0,
            scope: RouteScope::General,
        };
        r.cap_expiry(now + Duration::from_millis(1_000));
        assert_eq!(r.expires_at, now + Duration::from_millis(500));
    }
}
