//! Daemon event log (core.md §8): a bounded in-memory record of notable
//! runtime transitions (session active, circuit opened, bundle admitted).
//! Persistence lands in Phase 12; the log exists so the control surface can
//! report recent activity without holding references to live services.
use std::fmt;

/// One recorded event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonEvent {
    pub kind: String,
    pub at_ms: u64,
    pub detail: String,
}

impl fmt::Display for DaemonEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}: {}", self.kind, self.at_ms, self.detail)
    }
}

/// Bounded event ring: pushes trim to `max_entries`; `recent` returns the
/// newest first.
#[derive(Debug)]
pub struct DaemonEvents {
    log: Vec<DaemonEvent>,
    max_entries: usize,
}

impl DaemonEvents {
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            log: Vec::new(),
            max_entries,
        }
    }

    /// Append an event, dropping the oldest entries beyond the cap.
    pub fn push(&mut self, event: DaemonEvent) {
        self.log.push(event);
        let excess = self.log.len().saturating_sub(self.max_entries);
        if excess > 0 {
            self.log.drain(..excess);
        }
    }

    /// The `limit` most recent events, newest first.
    #[must_use]
    pub fn recent(&self, limit: usize) -> Vec<DaemonEvent> {
        let start = self.log.len().saturating_sub(limit);
        self.log[start..].iter().rev().cloned().collect()
    }

    // len/is_empty are test-only until a metrics or diagnostics surface
    // reports the ring occupancy; the control path reads via recent().
    #[allow(dead_code)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.log.len()
    }

    #[allow(dead_code)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: &str, at_ms: u64) -> DaemonEvent {
        DaemonEvent {
            kind: kind.to_string(),
            at_ms,
            detail: "detail".to_string(),
        }
    }

    #[test]
    fn push_trims_at_cap() {
        let mut log = DaemonEvents::new(3);
        for i in 0..5 {
            log.push(event("session_active", i));
        }
        assert_eq!(log.len(), 3);
        assert_eq!(log.recent(10)[0].at_ms, 4);
        assert_eq!(log.recent(10)[2].at_ms, 2);
    }

    #[test]
    fn recent_returns_newest_first_and_bounded() {
        let mut log = DaemonEvents::new(200);
        for i in 0..5 {
            log.push(event("bundle_admitted", i));
        }
        let recent = log.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].at_ms, 4);
        assert_eq!(recent[1].at_ms, 3);
        assert!(log.recent(0).is_empty());
    }
}
