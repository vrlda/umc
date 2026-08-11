use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

/// One request's cancellation state. The atomic makes cancellation visible to
/// synchronous checks; the notify wakes an async operation without polling.
#[derive(Clone, Debug)]
pub(crate) struct CancellationHandle {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CancellationHandle {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Mark the request cancelled. Returns `true` only for the first mark.
    pub(crate) fn cancel(&self) -> bool {
        let first = !self.cancelled.swap(true, Ordering::AcqRel);
        if first {
            self.notify.notify_one();
        }
        first
    }

    #[must_use]
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Wait until cancellation is observed. The notification future is
    /// created before the atomic check so a concurrent cancel cannot be lost.
    pub(crate) async fn cancelled(&self) {
        let notified = self.notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

/// Per-control-connection table of currently executing request IDs.
#[derive(Clone, Debug, Default)]
pub(crate) struct CancellationRegistry {
    active: Arc<Mutex<HashMap<u64, CancellationHandle>>>,
}

impl CancellationRegistry {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register(&self, request_id: u64) -> Option<CancellationHandle> {
        let handle = CancellationHandle::new();
        let mut active = self.active.lock().expect("cancellation registry");
        if active.contains_key(&request_id) {
            return None;
        }
        active.insert(request_id, handle.clone());
        Some(handle)
    }

    pub(crate) fn remove(&self, request_id: u64) {
        self.active
            .lock()
            .expect("cancellation registry")
            .remove(&request_id);
    }

    pub(crate) fn cancel(&self, request_id: u64) -> bool {
        self.active
            .lock()
            .expect("cancellation registry")
            .get(&request_id)
            .is_some_and(CancellationHandle::cancel)
    }

    pub(crate) fn cancel_all(&self) {
        let handles: Vec<CancellationHandle> = self
            .active
            .lock()
            .expect("cancellation registry")
            .values()
            .cloned()
            .collect();
        for handle in handles {
            handle.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_handle_notifies_waiters_and_is_idempotent() {
        let handle = CancellationHandle::new();
        assert!(!handle.is_cancelled());
        let waiter = handle.clone();
        let waiting = tokio::spawn(async move {
            waiter.cancelled().await;
            waiter.is_cancelled()
        });
        assert!(handle.cancel());
        assert!(!handle.cancel());
        assert!(waiting.await.expect("cancellation waiter"));
    }

    #[test]
    fn registry_rejects_request_id_collisions_until_completion() {
        let registry = CancellationRegistry::new();
        assert!(registry.register(7).is_some());
        assert!(registry.register(7).is_none());
        registry.remove(7);
        assert!(registry.register(7).is_some());
    }
}
