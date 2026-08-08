//! Session manager (core.md §9.5): the registry of live daemon sessions.
//!
//! Entries are stored behind `Arc` so `lookup` can hand out a shareable
//! handle — the session task's `JoinHandle` is owned by the daemon's
//! completion watcher, so the registry keeps an `AbortHandle` instead.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::task::AbortHandle;

/// One live session: the peer endpoint id, the carrier it rides on, when it
/// became active, and a handle to abort the wire-loop task.
#[derive(Debug)]
pub struct SessionEntry {
    /// Peer endpoint id. Provisional until the client's identity binding
    /// arrives in `CLIENT_AUTH` (Task 20+): derived deterministically from
    /// the client's hello ephemeral. Placeholder: consumed by the
    /// control-socket session API in Task 20+.
    #[allow(dead_code)]
    pub peer_endpoint_id: [u8; 32],
    /// Carrier type id, e.g. `ump.tcp/1`. Placeholder: consumed by the
    /// control-socket session API in Task 20+.
    #[allow(dead_code)]
    pub carrier_type: String,
    /// Aborts the session task at shutdown. The task itself is awaited by a
    /// watcher in the accept loop, which records the `session_closed` event.
    #[allow(dead_code)]
    pub task: AbortHandle,
    /// Wall-clock millisecond timestamp of the `session_active` transition.
    #[allow(dead_code)]
    pub established_at_ms: u64,
}

/// Thread-safe session registry keyed by monotonically increasing ids.
#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<u64, Arc<SessionEntry>>>>,
    next_id: AtomicU64,
}

impl SessionManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate the next session id (monotonically increasing from 1).
    #[must_use]
    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Register a live session under `session_id`.
    pub fn register(&self, session_id: u64, entry: SessionEntry) {
        self.sessions
            .lock()
            .expect("session registry")
            .insert(session_id, Arc::new(entry));
    }

    /// Look up a live session by id. Consumed by the control-socket
    /// `SessionService.GetSession` handler.
    #[must_use]
    pub fn lookup(&self, session_id: u64) -> Option<Arc<SessionEntry>> {
        self.sessions
            .lock()
            .expect("session registry")
            .get(&session_id)
            .cloned()
    }

    /// Snapshot of every live session, ordered by session id. Consumed by
    /// the control-socket `SessionService.ListSessions` handler.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(u64, Arc<SessionEntry>)> {
        let registry = self.sessions.lock().expect("session registry");
        let mut entries: Vec<(u64, Arc<SessionEntry>)> = registry
            .iter()
            .map(|(id, entry)| (*id, entry.clone()))
            .collect();
        entries.sort_by_key(|(id, _)| *id);
        entries
    }

    /// Number of registered sessions. Placeholder: consumed by the
    /// control-socket session API in Task 20+.
    #[must_use]
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        self.sessions.lock().expect("session registry").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn register_lookup_count() {
        let manager = SessionManager::new();
        assert_eq!(manager.count(), 0);
        assert_eq!(manager.next_id(), 1);
        assert_eq!(manager.next_id(), 2);
        manager.register(
            manager.next_id(),
            SessionEntry {
                peer_endpoint_id: [7u8; 32],
                carrier_type: "ump.tcp/1".to_string(),
                task: tokio::spawn(async {}).abort_handle(),
                established_at_ms: 1_000,
            },
        );
        assert_eq!(manager.count(), 1);
        let entry = manager.lookup(3).expect("registered");
        assert_eq!(entry.peer_endpoint_id, [7u8; 32]);
        assert_eq!(entry.carrier_type, "ump.tcp/1");
        assert_eq!(entry.established_at_ms, 1_000);
        assert!(manager.lookup(99).is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_orders_by_id() {
        let manager = SessionManager::new();
        for (id, peer) in [(2u64, [8u8; 32]), (1, [7u8; 32])] {
            manager.register(
                id,
                SessionEntry {
                    peer_endpoint_id: peer,
                    carrier_type: "ump.tcp/1".to_string(),
                    task: tokio::spawn(async {}).abort_handle(),
                    established_at_ms: 1_000,
                },
            );
        }
        let snapshot = manager.snapshot();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].0, 1, "snapshot is ordered by session id");
        assert_eq!(snapshot[0].1.peer_endpoint_id, [7u8; 32]);
        assert_eq!(snapshot[1].0, 2);
    }
}
