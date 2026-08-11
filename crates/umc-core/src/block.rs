//! Endpoint blocklist (core.md §44, resource-limits.md §47): blocks with
//! bounded permanence; the daemon maps an active expiry to a refusal duration.
use std::collections::HashMap;
use umc_types::runtime::{Duration, Instant};

/// Why an endpoint was blocked; surfaced in diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// Repeated handshake or frame malformation.
    MalformedTraffic,
    /// Authentication or admission failure.
    AuthenticationFailure,
    /// Persistent rate-limit violations.
    RateLimitViolation,
    /// Discovery enumeration probing.
    Enumeration,
    /// Operator-initiated block.
    Operator,
}

#[derive(Debug, Clone)]
struct BlockEntry {
    reason: BlockReason,
    expires_at: Instant,
}

/// In-memory blocklist: endpoints blocked until `now + permanence`.
#[derive(Debug)]
pub struct Blocklist {
    permanence_seconds: u64,
    entries: HashMap<Vec<u8>, BlockEntry>,
}

impl Blocklist {
    /// Blocklist where every block lasts `permanence_seconds`.
    #[must_use]
    pub fn new(permanence_seconds: u64) -> Self {
        Self {
            permanence_seconds,
            entries: HashMap::new(),
        }
    }

    /// Blocks `endpoint` for the configured permanence starting at `now`,
    /// replacing any prior block.
    pub fn block(&mut self, endpoint: &[u8], reason: BlockReason, now: Instant) {
        let expires_at = now + Duration::from_millis(self.permanence_seconds.saturating_mul(1_000));
        self.entries
            .insert(endpoint.to_vec(), BlockEntry { reason, expires_at });
    }

    /// Removes the block for `endpoint`, if any.
    pub fn unblock(&mut self, endpoint: &[u8]) {
        self.entries.remove(endpoint);
    }

    /// Returns the expiry [`Instant`] while a block is active, `None`
    /// otherwise; the daemon maps the expiry to a refusal duration.
    #[must_use]
    pub fn is_blocked(&self, endpoint: &[u8], now: Instant) -> Option<Instant> {
        self.entries
            .get(endpoint)
            .and_then(|entry| (now < entry.expires_at).then_some(entry.expires_at))
    }

    /// Stored expiry for `endpoint`, active or elapsed.
    #[must_use]
    pub fn expiry(&self, endpoint: &[u8]) -> Option<Instant> {
        self.entries.get(endpoint).map(|entry| entry.expires_at)
    }

    /// Reason for an active block of `endpoint`.
    #[must_use]
    pub fn reason(&self, endpoint: &[u8], now: Instant) -> Option<BlockReason> {
        self.entries
            .get(endpoint)
            .and_then(|entry| (now < entry.expires_at).then_some(entry.reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expires_after_duration() {
        let mut list = Blocklist::new(60);
        list.block(b"peer-1", BlockReason::Enumeration, Instant(0));
        assert_eq!(
            list.is_blocked(b"peer-1", Instant(0)),
            Some(Instant(60_000))
        );
        assert_eq!(
            list.is_blocked(b"peer-1", Instant(59_999)),
            Some(Instant(60_000))
        );
        assert_eq!(list.is_blocked(b"peer-1", Instant(60_000)), None);
        assert_eq!(
            list.reason(b"peer-1", Instant(0)),
            Some(BlockReason::Enumeration)
        );
    }

    #[test]
    fn unblock_removes_entry() {
        let mut list = Blocklist::new(60);
        list.block(b"peer-1", BlockReason::Operator, Instant(0));
        assert!(list.is_blocked(b"peer-1", Instant(1)).is_some());
        list.unblock(b"peer-1");
        assert_eq!(list.is_blocked(b"peer-1", Instant(1)), None);
        assert_eq!(list.expiry(b"peer-1"), None);
    }

    #[test]
    fn unknown_endpoint_not_blocked() {
        let list = Blocklist::new(60);
        assert_eq!(list.is_blocked(b"nobody", Instant(0)), None);
        assert_eq!(list.expiry(b"nobody"), None);
    }
}
