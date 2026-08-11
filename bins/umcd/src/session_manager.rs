//! Session manager (core.md §9.5): the registry of live daemon sessions.
//!
//! Entries are stored behind `Arc` so `lookup` can hand out a shareable
//! handle — the session task's `JoinHandle` is owned by the daemon's
//! completion watcher, so the registry keeps an `AbortHandle` instead.
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::task::AbortHandle;
use umc_carrier::{error::CarrierError, types::OutboundPacket, BoxLink};
use umc_session::session::Session;

/// Live transport objects exposed to the local `ApplicationService`. The
/// session task remains the normal owner of transport progress; control calls
/// use `try_lock` on the same session and send bounded packets through the
/// same carrier link.
/// Carrier links attached to one logical session. Path ids are stable session
/// selectors; carrier handles are implementation details and may be added or
/// retired without changing the application-facing session handle.
pub struct SessionLinkSet {
    links: Mutex<HashMap<u64, Arc<BoxLink>>>,
    active_path: AtomicU64,
    pending_migrations: Mutex<HashMap<u64, bool>>,
}

impl SessionLinkSet {
    #[must_use]
    pub fn single(path_id: u64, link: BoxLink) -> Arc<Self> {
        let mut links = HashMap::new();
        links.insert(path_id, Arc::new(link));
        Arc::new(Self {
            links: Mutex::new(links),
            active_path: AtomicU64::new(path_id),
            pending_migrations: Mutex::new(HashMap::new()),
        })
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn from_arc(path_id: u64, link: Arc<BoxLink>) -> Arc<Self> {
        let mut links = HashMap::new();
        links.insert(path_id, link);
        Arc::new(Self {
            links: Mutex::new(links),
            active_path: AtomicU64::new(path_id),
            pending_migrations: Mutex::new(HashMap::new()),
        })
    }

    #[must_use]
    pub fn active_path(&self) -> u64 {
        self.active_path.load(Ordering::Acquire)
    }

    pub fn set_active_path(&self, path_id: u64) -> Result<(), String> {
        if !self
            .links
            .lock()
            .expect("session links")
            .contains_key(&path_id)
        {
            return Err(format!("path {path_id} has no attached carrier"));
        }
        self.active_path.store(path_id, Ordering::Release);
        Ok(())
    }

    pub fn add(&self, path_id: u64, link: BoxLink) -> Result<Arc<BoxLink>, String> {
        let mut links = self.links.lock().expect("session links");
        if links.contains_key(&path_id) {
            return Err(format!("path {path_id} already has a carrier"));
        }
        let link = Arc::new(link);
        links.insert(path_id, link.clone());
        Ok(link)
    }

    #[allow(dead_code)]
    pub fn add_arc(&self, path_id: u64, link: Arc<BoxLink>) -> Result<(), String> {
        let mut links = self.links.lock().expect("session links");
        if links.insert(path_id, link).is_some() {
            return Err(format!("path {path_id} already has a carrier"));
        }
        Ok(())
    }

    #[must_use]
    pub fn get(&self, path_id: u64) -> Option<Arc<BoxLink>> {
        self.links
            .lock()
            .expect("session links")
            .get(&path_id)
            .cloned()
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<(u64, Arc<BoxLink>)> {
        self.links
            .lock()
            .expect("session links")
            .iter()
            .map(|(path, link)| (*path, link.clone()))
            .collect()
    }

    pub fn remove(&self, path_id: u64, close: bool) -> Option<Arc<BoxLink>> {
        let mut links = self.links.lock().expect("session links");
        let removed = links.remove(&path_id);
        if self.active_path() == path_id {
            if let Some(next) = links.keys().copied().next() {
                self.active_path.store(next, Ordering::Release);
            }
        }
        drop(links);
        if close {
            if let Some(link) = &removed {
                let _ = link.close("session path retired");
            }
        }
        removed
    }

    pub fn send_active(
        &self,
        packet: OutboundPacket,
    ) -> Result<umc_carrier::types::SendResult, CarrierError> {
        self.send_on(self.active_path(), packet)
    }

    pub fn send_on(
        &self,
        path_id: u64,
        packet: OutboundPacket,
    ) -> Result<umc_carrier::types::SendResult, CarrierError> {
        let link = self.get(path_id).ok_or_else(|| {
            CarrierError::new(
                umc_carrier::error::CarrierErrorKind::LinkClosed,
                "path not attached",
            )
        })?;
        link.send(packet)
    }

    pub fn close_all(&self, reason: &str) {
        for (_, link) in self.snapshot() {
            let _ = link.close(reason);
        }
    }

    pub fn request_migration(&self, path_id: u64, keep_old_path: bool) {
        self.pending_migrations
            .lock()
            .expect("session migration")
            .insert(path_id, keep_old_path);
    }

    pub fn take_migration_request(&self, path_id: u64) -> Option<bool> {
        self.pending_migrations
            .lock()
            .expect("session migration")
            .remove(&path_id)
    }
}

pub struct SessionControl {
    pub session: Arc<tokio::sync::Mutex<Session>>,
    /// Kept for compatibility with existing raw-link lifecycle code. New
    /// session traffic uses `links`, which follows path migration.
    pub link: Arc<BoxLink>,
    pub links: Arc<SessionLinkSet>,
}

impl SessionControl {
    #[must_use]
    #[allow(dead_code)]
    pub fn new(session: Arc<tokio::sync::Mutex<Session>>, link: Arc<BoxLink>) -> Self {
        let links = SessionLinkSet::from_arc(0, link.clone());
        Self {
            session,
            link,
            links,
        }
    }

    #[must_use]
    pub fn new_with_links(
        session: Arc<tokio::sync::Mutex<Session>>,
        link: Arc<BoxLink>,
        links: Arc<SessionLinkSet>,
    ) -> Self {
        Self {
            session,
            link,
            links,
        }
    }
}

impl fmt::Debug for SessionControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionControl").finish_non_exhaustive()
    }
}

/// One live session: the peer endpoint id, the carrier it rides on, when it
/// became active, and a handle to abort the wire-loop task.
#[derive(Debug)]
pub struct SessionEntry {
    /// Peer endpoint id. Provisional until the client's identity binding
    /// arrives in `CLIENT_AUTH`: derived deterministically from the client's
    /// hello ephemeral and exposed in the control session summary.
    pub peer_endpoint_id: [u8; 32],
    /// Carrier type id, e.g. `ump.tcp/1`, exposed in the control session
    /// summary.
    pub carrier_type: String,
    /// Aborts the session task at shutdown. The task itself is awaited by a
    /// watcher in the accept loop, which records the `session_closed` event.
    pub task: AbortHandle,
    /// Wall-clock millisecond timestamp of the `session_active` transition.
    pub established_at_ms: u64,
    /// Privacy profile negotiated for this session (0 = p0 through 3 = p3).
    pub privacy_profile: u8,
    /// Whether the session may use a direct path under its negotiated policy.
    pub direct_path_allowed: bool,
    /// Whether fixed-size traffic padding is active for this session.
    pub traffic_padding_active: bool,
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
    #[cfg(test)]
    pub fn register(&self, session_id: u64, entry: SessionEntry) {
        self.sessions
            .lock()
            .expect("session registry")
            .insert(session_id, Arc::new(entry));
    }

    /// Register a session only when the profile hard limit has capacity.
    /// Replacing an existing id remains allowed so cleanup/retry paths cannot
    /// strand a slot while preserving the monotonic id contract.
    pub fn try_register(&self, session_id: u64, entry: SessionEntry, max_sessions: usize) -> bool {
        let mut sessions = self.sessions.lock().expect("session registry");
        if !sessions.contains_key(&session_id) && sessions.len() >= max_sessions {
            return false;
        }
        sessions.insert(session_id, Arc::new(entry));
        true
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

    /// Remove a session after its reader and writer tasks have both stopped.
    /// Returning the entry lets callers retain the abort handle or metadata
    /// while completing cleanup without leaving stale control handles behind.
    pub fn remove(&self, session_id: u64) -> Option<Arc<SessionEntry>> {
        self.sessions
            .lock()
            .expect("session registry")
            .remove(&session_id)
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

    /// Number of currently registered live sessions. The completion watcher
    /// removes entries after the wire task exits, so this is safe for status
    /// and metrics surfaces.
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
                privacy_profile: 0,
                direct_path_allowed: true,
                traffic_padding_active: false,
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
    async fn try_register_enforces_profile_session_limit() {
        let manager = SessionManager::new();
        let entry = || SessionEntry {
            peer_endpoint_id: [9u8; 32],
            carrier_type: "ump.test/1".into(),
            task: tokio::spawn(async {}).abort_handle(),
            established_at_ms: 0,
            privacy_profile: 0,
            direct_path_allowed: true,
            traffic_padding_active: false,
        };
        assert!(manager.try_register(1, entry(), 1));
        assert!(!manager.try_register(2, entry(), 1));
        assert_eq!(manager.count(), 1);
        assert!(manager.remove(1).is_some());
        assert!(manager.try_register(3, entry(), 1));
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
                    privacy_profile: 0,
                    direct_path_allowed: true,
                    traffic_padding_active: false,
                },
            );
        }
        let snapshot = manager.snapshot();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].0, 1, "snapshot is ordered by session id");
        assert_eq!(snapshot[0].1.peer_endpoint_id, [7u8; 32]);
        assert_eq!(snapshot[1].0, 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remove_releases_live_entry() {
        let manager = SessionManager::new();
        let id = manager.next_id();
        manager.register(
            id,
            SessionEntry {
                peer_endpoint_id: [3u8; 32],
                carrier_type: "ump.tcp/1".into(),
                task: tokio::spawn(async {}).abort_handle(),
                established_at_ms: 1,
                privacy_profile: 0,
                direct_path_allowed: true,
                traffic_padding_active: false,
            },
        );
        assert!(manager.remove(id).is_some());
        assert!(manager.lookup(id).is_none());
        assert_eq!(manager.count(), 0);
        assert!(manager.remove(id).is_none());
    }
}
