//! Session bus: cross-session delivery within one daemon (relay forwarding,
//! future bundle delivery). A session registers one inbound channel (bus →
//! session processing) and one outbound channel (daemon → session link).

use std::collections::HashMap;
use tokio::sync::mpsc;

/// Cross-session delivery failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusError {
    /// No session is registered for the peer endpoint id.
    NoSession,
    /// The session's channel is closed (its task has exited).
    ChannelClosed,
}

/// Shared registry of live sessions and their bus channels.
#[derive(Debug, Default)]
pub struct SessionBus {
    /// Peer endpoint id -> session id.
    by_peer: HashMap<Vec<u8>, u64>,
    /// Session id -> peer endpoint id.
    by_id: HashMap<u64, Vec<u8>>,
    /// Session id -> inbound channel (bus -> session processing).
    inbound: HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>,
    /// Session id -> outbound channel (daemon -> session link).
    outbound: HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>,
}

impl SessionBus {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a live session under `session_id`. Prior entries for the
    /// same session id are overwritten, including any stale peer mapping.
    pub fn register(
        &mut self,
        peer_endpoint_id: Vec<u8>,
        session_id: u64,
        inbound: mpsc::UnboundedSender<Vec<u8>>,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
    ) {
        if let Some(prior_peer) = self.by_id.remove(&session_id) {
            if self.by_peer.get(&prior_peer) == Some(&session_id) {
                self.by_peer.remove(&prior_peer);
            }
        }
        self.by_peer.insert(peer_endpoint_id.clone(), session_id);
        self.by_id.insert(session_id, peer_endpoint_id);
        self.inbound.insert(session_id, inbound);
        self.outbound.insert(session_id, outbound);
    }

    /// Remove a session's registration; called when its task exits.
    pub fn unregister(&mut self, session_id: u64) {
        self.by_id.remove(&session_id);
        self.by_peer.retain(|_, id| *id != session_id);
        self.inbound.remove(&session_id);
        self.outbound.remove(&session_id);
    }

    /// The session id registered for a peer endpoint id, if any.
    #[must_use]
    pub fn lookup(&self, peer_endpoint_id: &[u8]) -> Option<u64> {
        self.by_peer.get(peer_endpoint_id).copied()
    }

    /// Return the endpoint id associated with a live session id. Relay expiry
    /// sweeps use this reverse lookup to address close notifications without
    /// exposing the bus's internal channel maps.
    #[must_use]
    pub fn peer_for_session(&self, session_id: u64) -> Option<Vec<u8>> {
        self.by_id.get(&session_id).cloned()
    }

    /// Push bytes INTO a session's processing; the session task treats the
    /// buffer like a carrier packet (relay forwarding destination, future
    /// bundle delivery).
    #[allow(dead_code)] // reserved for bundle delivery and routing loops
    pub fn inject_inbound(&self, peer_endpoint_id: &[u8], bytes: Vec<u8>) -> Result<(), BusError> {
        let session_id = self.lookup(peer_endpoint_id).ok_or(BusError::NoSession)?;
        self.inbound
            .get(&session_id)
            .ok_or(BusError::NoSession)?
            .send(bytes)
            .map_err(|_| BusError::ChannelClosed)
    }

    /// Push bytes OUT of a session; the session task sends the buffer over
    /// the session's link (relay data handoff to a destination session).
    pub fn inject_outbound(&self, peer_endpoint_id: &[u8], bytes: Vec<u8>) -> Result<(), BusError> {
        let session_id = self.lookup(peer_endpoint_id).ok_or(BusError::NoSession)?;
        self.outbound
            .get(&session_id)
            .ok_or(BusError::NoSession)?
            .send(bytes)
            .map_err(|_| BusError::ChannelClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER_A: &[u8] = b"peer-a";
    const PEER_B: &[u8] = b"peer-b";

    fn registered_pair() -> (
        SessionBus,
        mpsc::UnboundedReceiver<Vec<u8>>,
        mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let mut bus = SessionBus::new();
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        bus.register(PEER_A.to_vec(), 1, in_tx, out_tx);
        (bus, in_rx, out_rx)
    }

    #[test]
    fn register_and_lookup() {
        let mut bus = SessionBus::new();
        assert_eq!(bus.lookup(PEER_A), None);
        let (in_tx, _in_rx) = mpsc::unbounded_channel();
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        bus.register(PEER_A.to_vec(), 1, in_tx, out_tx);
        assert_eq!(bus.lookup(PEER_A), Some(1));
        // Re-registering a session id under a new peer replaces the mapping.
        let (in_tx, _in_rx) = mpsc::unbounded_channel();
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        bus.register(PEER_B.to_vec(), 1, in_tx, out_tx);
        assert_eq!(bus.lookup(PEER_A), None);
        assert_eq!(bus.lookup(PEER_B), Some(1));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inject_inbound_delivers_to_processing() {
        let (bus, mut in_rx, _out_rx) = registered_pair();
        bus.inject_inbound(PEER_A, b"carrier-like".to_vec())
            .unwrap();
        assert_eq!(in_rx.recv().await.unwrap(), b"carrier-like");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inject_outbound_delivers_to_link() {
        let (bus, _in_rx, mut out_rx) = registered_pair();
        bus.inject_outbound(PEER_A, b"frame".to_vec()).unwrap();
        assert_eq!(out_rx.recv().await.unwrap(), b"frame");
    }

    #[test]
    fn unregister_removes_all_entries() {
        let (mut bus, _in_rx, _out_rx) = registered_pair();
        bus.unregister(1);
        assert_eq!(bus.lookup(PEER_A), None);
        assert_eq!(
            bus.inject_inbound(PEER_A, Vec::new()),
            Err(BusError::NoSession)
        );
        assert_eq!(
            bus.inject_outbound(PEER_A, Vec::new()),
            Err(BusError::NoSession)
        );
    }

    #[test]
    fn inject_to_unknown_peer_is_no_session() {
        let (bus, _in_rx, _out_rx) = registered_pair();
        assert_eq!(
            bus.inject_inbound(b"ghost", Vec::new()),
            Err(BusError::NoSession)
        );
        assert_eq!(
            bus.inject_outbound(b"ghost", Vec::new()),
            Err(BusError::NoSession)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inject_to_closed_channel_is_channel_closed() {
        let (bus, in_rx, out_rx) = registered_pair();
        drop(in_rx);
        drop(out_rx);
        assert_eq!(
            bus.inject_inbound(PEER_A, Vec::new()),
            Err(BusError::ChannelClosed)
        );
        assert_eq!(
            bus.inject_outbound(PEER_A, Vec::new()),
            Err(BusError::ChannelClosed)
        );
    }
}
