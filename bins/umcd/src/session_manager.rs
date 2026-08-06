//! Session manager (core.md §9.5): the registry of live daemon sessions.
//!
//! Entries are stored behind `Arc` so `lookup` can hand out a shareable
//! handle — `tokio::task::JoinHandle` is not `Clone`.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

/// One live session: the peer endpoint id, the carrier it rides on, and a
/// handle to the wire-loop task.
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
    /// The session task; kept so the daemon can abort sessions at shutdown.
    /// Placeholder: consumed by the control-socket session API in Task 20+.
    #[allow(dead_code)]
    pub task: JoinHandle<()>,
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

    /// Look up a live session by id. Placeholder: consumed by the
    /// control-socket session API in Task 20+.
    #[must_use]
    #[allow(dead_code)]
    pub fn lookup(&self, session_id: u64) -> Option<Arc<SessionEntry>> {
        self.sessions
            .lock()
            .expect("session registry")
            .get(&session_id)
            .cloned()
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
                task: tokio::spawn(async {}),
            },
        );
        assert_eq!(manager.count(), 1);
        let entry = manager.lookup(3).expect("registered");
        assert_eq!(entry.peer_endpoint_id, [7u8; 32]);
        assert_eq!(entry.carrier_type, "ump.tcp/1");
        assert!(manager.lookup(99).is_none());
    }
}
