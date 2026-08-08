//! Relay service (relay.md §8-24): the daemon's in-memory circuit registry,
//! admission, forwarding, and closure. Persistence lands in Phase 12; the
//! registry is process-local for now.
use crate::event_log::{DaemonEvent, DaemonEvents};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use umc_relay::admission::{evaluate_open, AdmissionDecision, AdmissionLimits, RelayPolicy};
use umc_relay::circuit::{Circuit, CircuitState};
use umc_relay::close::{close_circuit, RelayReason};
use umc_relay::forward::{accept_upstream_data, ForwardError};
use umc_types::runtime::Instant;
use umc_wire::frames::relay::RelayDataFrame;

/// What a peer asked for in `RELAY_OPEN` (relay.md §13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitOpenRequest {
    /// Circuits this peer already holds; admission caps per peer (relay.md §34).
    pub peer_circuits: usize,
    pub requested_lifetime_ms: u64,
    pub requested_byte_quota: u64,
    pub flags: u8,
    pub bidirectional: bool,
    pub private_handling: bool,
    /// Peer endpoint id the opener wants relayed data delivered to
    /// (`RELAY_OPEN.next_hop_hint`); empty means no forwarding target.
    pub destination_hint: Vec<u8>,
}

/// What the relay granted (relay.md §13.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitOpenResult {
    pub circuit_id: u64,
    pub granted_lifetime_ms: u64,
    pub granted_byte_quota: u64,
    pub maximum_relay_payload: usize,
}

/// Process-local circuit registry with admission policy.
#[derive(Debug)]
pub struct RelayService {
    circuits: HashMap<u64, Circuit>,
    next_circuit_id: u64,
    /// Circuit id -> session id of the session that opened it. The opening
    /// session is the circuit's other (peer) end for `RELAY_DATA` forwarding.
    circuit_owners: HashMap<u64, u64>,
    /// Circuit id -> destination peer endpoint id (the open frame's
    /// `next_hop_hint`): where `RELAY_DATA` on the circuit is forwarded.
    destination_hints: HashMap<u64, Vec<u8>>,
    /// Peer endpoint id -> circuit ids it owns, most recent last; the
    /// forwarding lookup for a destination peer (relay.md §18).
    circuits_by_owner: HashMap<Vec<u8>, Vec<u64>>,
    pub limits: AdmissionLimits,
    events: Arc<Mutex<DaemonEvents>>,
}

/// One control-surface circuit snapshot (task F4): the circuit clone plus
/// its owner peer endpoint id and destination hint.
#[derive(Debug, Clone)]
pub struct CircuitSnapshot {
    pub circuit_id: u64,
    pub circuit: Circuit,
    pub owner_peer: Option<Vec<u8>>,
    pub destination: Option<Vec<u8>>,
}

impl RelayService {
    #[must_use]
    pub fn new(events: Arc<Mutex<DaemonEvents>>) -> Self {
        Self {
            circuits: HashMap::new(),
            next_circuit_id: 1,
            // Community relay: open by default so the daemon can relay for
            // its mesh, while per-peer and resource limits still apply.
            circuit_owners: HashMap::new(),
            destination_hints: HashMap::new(),
            circuits_by_owner: HashMap::new(),
            limits: AdmissionLimits {
                policy: RelayPolicy::Community,
                ..AdmissionLimits::default()
            },
            events,
        }
    }

    /// Evaluate `RELAY_OPEN` and allocate a circuit when admitted (relay.md
    /// §13, §34). `owner_peer` is the opening session's peer endpoint id;
    /// the circuit becomes a forwarding target for that peer.
    ///
    /// # Errors
    ///
    /// Returns a message when admission refuses the open.
    pub fn open_circuit(
        &mut self,
        request: &CircuitOpenRequest,
        owner_peer: Vec<u8>,
        now: Instant,
    ) -> Result<CircuitOpenResult, String> {
        let decision = evaluate_open(
            &self.limits,
            request.peer_circuits,
            request.requested_lifetime_ms,
            request.requested_byte_quota,
            request.flags,
        );
        let (granted_lifetime_ms, granted_byte_quota, maximum_relay_payload) = match decision {
            AdmissionDecision::Accepted {
                granted_lifetime_ms,
                granted_byte_quota,
                maximum_relay_payload,
            } => (
                granted_lifetime_ms,
                granted_byte_quota,
                maximum_relay_payload,
            ),
            other => return Err(format!("open refused: {other:?}")),
        };
        let circuit_id = self.next_circuit_id;
        self.next_circuit_id += 1;
        let circuit = Circuit::new(
            circuit_id,
            now,
            granted_lifetime_ms,
            granted_byte_quota,
            request.bidirectional,
            request.private_handling,
        );
        self.circuits.insert(circuit_id, circuit);
        self.destination_hints
            .insert(circuit_id, request.destination_hint.clone());
        self.circuits_by_owner
            .entry(owner_peer)
            .or_default()
            .push(circuit_id);
        self.events.lock().expect("event log").push(DaemonEvent {
            kind: "circuit_opened".into(),
            at_ms: now.0,
            detail: format!("circuit {circuit_id}"),
        });
        Ok(CircuitOpenResult {
            circuit_id,
            granted_lifetime_ms,
            granted_byte_quota,
            maximum_relay_payload,
        })
    }

    /// Record the session that opened a circuit. The opening session is the
    /// circuit's peer end: `RELAY_DATA` arriving for the circuit is destined
    /// for it (relay.md §16-18).
    pub fn record_circuit_owner(&mut self, circuit_id: u64, session_id: u64) {
        self.circuit_owners.insert(circuit_id, session_id);
    }

    /// The session that opened `circuit_id`, if any.
    #[must_use]
    pub fn circuit_owner(&self, circuit_id: u64) -> Option<u64> {
        self.circuit_owners.get(&circuit_id).copied()
    }

    /// Circuits opened by one peer session; feeds the per-peer admission
    /// cap (relay.md §34).
    #[must_use]
    pub fn circuits_for_peer(&self, session_id: u64) -> usize {
        self.circuit_owners
            .values()
            .filter(|owner| **owner == session_id)
            .count()
    }

    /// The most recent live circuit owned by a peer endpoint id, if any:
    /// the forwarding target for `RELAY_DATA` toward that peer (relay.md
    /// §18). Closed circuits are skipped.
    #[must_use]
    pub fn circuit_for_destination(&self, destination: &[u8]) -> Option<u64> {
        let owned = self.circuits_by_owner.get(destination)?;
        owned.iter().rev().copied().find(|id| {
            self.circuits
                .get(id)
                .is_some_and(|circuit| circuit.state != CircuitState::Closed)
        })
    }

    /// Forward one accepted `RELAY_DATA` payload to the circuit's
    /// destination peer (relay.md §18): allocate a fresh sequence on the
    /// destination peer's most recent circuit and encode a new
    /// `RELAY_DATA` frame for it. Returns the destination peer endpoint id
    /// and the encoded frame, ready for the session bus.
    ///
    /// # Errors
    ///
    /// Returns a message when the circuit has no destination hint
    /// (`UnknownCircuit`) or the destination peer has no circuit
    /// (`NoDestinationCircuit`).
    pub fn forward_data(
        &mut self,
        circuit_id: u64,
        data: &[u8],
        now: Instant,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let destination = self
            .destination_hints
            .get(&circuit_id)
            .ok_or_else(|| format!("unknown circuit {circuit_id}"))?;
        let destination = destination.clone();
        let dest_circuit = self
            .circuit_for_destination(&destination)
            .ok_or_else(|| "no circuit for destination peer".to_string())?;
        let sequence = self
            .circuits
            .get_mut(&dest_circuit)
            .ok_or_else(|| format!("unknown destination circuit {dest_circuit}"))?
            .allocate_sequence();
        let frame = RelayDataFrame {
            circuit_id: dest_circuit,
            relay_sequence: sequence,
            fin: false,
            ack_requested: false,
            high_priority: false,
            data: data.to_vec(),
        };
        let encoded = frame
            .encode()
            .map_err(|e| format!("forward encode: {e:?}"))?;
        self.events.lock().expect("event log").push(DaemonEvent {
            kind: "relay_data_forwarded".into(),
            at_ms: now.0,
            detail: format!(
                "circuit {circuit_id} -> destination circuit {dest_circuit} ({} bytes)",
                data.len()
            ),
        });
        Ok((destination, encoded))
    }

    /// Accept one `RELAY_DATA` from the upstream peer (relay.md §16-18).
    ///
    /// # Errors
    ///
    /// Returns a message for unknown circuits, closed circuits, replayed
    /// sequences, oversized or empty payloads, and quota exhaustion.
    pub fn accept_upstream(
        &mut self,
        circuit_id: u64,
        sequence: u64,
        fin: bool,
        data: &[u8],
        now: Instant,
    ) -> Result<(), String> {
        let circuit = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or_else(|| format!("unknown circuit {circuit_id}"))?;
        match accept_upstream_data(circuit, sequence, fin, data, self.limits.max_payload) {
            Ok(_) => {
                circuit.touch(now);
                Ok(())
            }
            Err(ForwardError::DuplicateDiscarded) => Ok(()),
            Err(e) => Err(format!("forward rejected: {e:?}")),
        }
    }

    /// Close a circuit, entering the CLOSING drain (relay.md §9.5, §23-24).
    ///
    /// # Errors
    ///
    /// Returns a message when the circuit id is unknown.
    pub fn close_circuit(
        &mut self,
        circuit_id: u64,
        reason: u64,
        now: Instant,
    ) -> Result<(), String> {
        let circuit = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or_else(|| format!("unknown circuit {circuit_id}"))?;
        close_circuit(
            circuit,
            RelayReason::from_u64(reason).unwrap_or(RelayReason::NoError),
            now,
            None,
        );
        self.circuit_owners.remove(&circuit_id);
        self.destination_hints.remove(&circuit_id);
        self.circuits_by_owner.retain(|_, owned| {
            owned.retain(|id| *id != circuit_id);
            !owned.is_empty()
        });
        self.events.lock().expect("event log").push(DaemonEvent {
            kind: "circuit_closed".into(),
            at_ms: now.0,
            detail: format!("circuit {circuit_id}"),
        });
        Ok(())
    }

    /// Number of live (non-closed) circuits.
    #[must_use]
    pub fn circuit_count(&self) -> usize {
        self.circuits
            .values()
            .filter(|c| !matches!(c.state, umc_relay::circuit::CircuitState::Closed))
            .count()
    }

    /// Control-surface snapshot (task F4): every circuit with its owner
    /// peer endpoint id and destination hint, for `GetRelayStatus` and
    /// `ListRelayCircuits`. The `Circuit` fields are all public, so the
    /// caller shapes the proto summary.
    #[must_use]
    pub fn snapshot(&self) -> Vec<CircuitSnapshot> {
        let mut owner_by_circuit: HashMap<u64, Vec<u8>> = HashMap::new();
        for (peer, owned) in &self.circuits_by_owner {
            for circuit_id in owned {
                owner_by_circuit.insert(*circuit_id, peer.clone());
            }
        }
        self.circuits
            .iter()
            .map(|(circuit_id, circuit)| CircuitSnapshot {
                circuit_id: *circuit_id,
                circuit: circuit.clone(),
                owner_peer: owner_by_circuit.get(circuit_id).cloned(),
                destination: self.destination_hints.get(circuit_id).cloned(),
            })
            .collect()
    }

    // circuit_count() is the live count the control surface reads; len and
    // is_empty are test-only helpers until a diagnostics surface needs the
    // raw registry size.
    #[allow(dead_code)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.circuits.len()
    }

    #[allow(dead_code)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_bus::SessionBus;
    use umc_wire::frames::relay::RelayDataFrame as WireRelayDataFrame;

    fn service() -> RelayService {
        RelayService::new(Arc::new(Mutex::new(DaemonEvents::new(200))))
    }

    fn open_request() -> CircuitOpenRequest {
        CircuitOpenRequest {
            peer_circuits: 0,
            requested_lifetime_ms: 600_000,
            requested_byte_quota: 1_048_576,
            flags: 0,
            bidirectional: true,
            private_handling: false,
            destination_hint: Vec::new(),
        }
    }

    #[test]
    fn open_forward_close_lifecycle() {
        let mut relay = service();
        let result = relay
            .open_circuit(&open_request(), b"peer".to_vec(), Instant(0))
            .unwrap();
        assert_eq!(result.granted_lifetime_ms, 600_000);
        assert_eq!(result.granted_byte_quota, 1_048_576);
        let id = result.circuit_id;

        relay
            .accept_upstream(id, 0, false, b"inner-ump-packet", Instant(10))
            .unwrap();
        // Exact duplicate is discarded, not an error.
        relay
            .accept_upstream(id, 0, false, b"inner-ump-packet", Instant(10))
            .unwrap();
        // A different byte at a replayed sequence conflicts.
        assert!(relay
            .accept_upstream(id, 0, false, b"tampered", Instant(10))
            .is_err());
        // FIN with empty data is legal.
        relay
            .accept_upstream(id, 1, true, b"", Instant(10))
            .unwrap();

        relay.close_circuit(id, 0, Instant(20)).unwrap();
        assert_eq!(relay.circuit_count(), 1);
        assert!(relay.close_circuit(999, 0, Instant(20)).is_err());
        assert_eq!(
            relay.circuits[&id].state,
            umc_relay::circuit::CircuitState::Closing
        );
    }

    #[test]
    fn circuit_ids_increment_and_quota_enforced() {
        let mut relay = service();
        let first = relay
            .open_circuit(&open_request(), b"peer".to_vec(), Instant(0))
            .unwrap();
        let second = relay
            .open_circuit(&open_request(), b"peer".to_vec(), Instant(0))
            .unwrap();
        assert_eq!(second.circuit_id, first.circuit_id + 1);

        let mut small = open_request();
        small.requested_byte_quota = 10;
        let tiny = relay
            .open_circuit(&small, b"peer".to_vec(), Instant(0))
            .unwrap();
        relay
            .accept_upstream(tiny.circuit_id, 0, false, b"0123456789", Instant(0))
            .unwrap();
        assert!(relay
            .accept_upstream(tiny.circuit_id, 1, false, b"x", Instant(0))
            .is_err());
    }

    #[test]
    fn admission_refuses_when_policy_disabled() {
        let mut relay = service();
        relay.limits.policy = RelayPolicy::Disabled;
        assert!(relay
            .open_circuit(&open_request(), b"peer".to_vec(), Instant(0))
            .is_err());
        assert!(relay.is_empty());
    }

    #[test]
    fn unknown_flags_rejected() {
        let mut relay = service();
        let mut request = open_request();
        request.flags = 0x10;
        assert!(relay
            .open_circuit(&request, b"peer".to_vec(), Instant(0))
            .is_err());
    }

    #[test]
    fn circuit_owners_track_the_opening_session() {
        let mut relay = service();
        let id = relay
            .open_circuit(&open_request(), b"peer-a".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        assert!(relay.circuit_owner(id).is_none());
        relay.record_circuit_owner(id, 7);
        assert_eq!(relay.circuit_owner(id), Some(7));
        assert_eq!(relay.circuits_for_peer(7), 1);
        let other = relay
            .open_circuit(&open_request(), b"peer-b".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        relay.record_circuit_owner(other, 9);
        assert_eq!(relay.circuits_for_peer(7), 1);
        assert_eq!(relay.circuits_for_peer(9), 1);
        relay.close_circuit(id, 0, Instant(10)).unwrap();
        assert!(relay.circuit_owner(id).is_none(), "close forgets the owner");
    }

    #[test]
    fn open_pushes_event() {
        let events = Arc::new(Mutex::new(DaemonEvents::new(200)));
        let mut relay = RelayService::new(events.clone());
        relay
            .open_circuit(&open_request(), b"peer".to_vec(), Instant(5))
            .unwrap();
        let recent = events.lock().unwrap().recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].kind, "circuit_opened");
        assert_eq!(recent[0].at_ms, 5);
    }

    #[test]
    fn close_pushes_event() {
        let events = Arc::new(Mutex::new(DaemonEvents::new(200)));
        let mut relay = RelayService::new(events.clone());
        let id = relay
            .open_circuit(&open_request(), b"peer".to_vec(), Instant(5))
            .unwrap()
            .circuit_id;
        relay.close_circuit(id, 0, Instant(20)).unwrap();
        let recent = events.lock().unwrap().recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].kind, "circuit_closed");
        assert_eq!(recent[0].at_ms, 20);
    }

    #[test]
    fn forward_data_errors_and_close_removes_target() {
        let mut relay = service();
        let mut toward_b = open_request();
        toward_b.destination_hint = b"peer-b".to_vec();
        let a_circuit = relay
            .open_circuit(&toward_b, b"peer-a".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;

        // Unknown circuit: no destination hint recorded.
        assert!(relay.forward_data(999, b"x", Instant(0)).is_err());
        // Destination peer has no circuit yet.
        assert!(relay.forward_data(a_circuit, b"x", Instant(0)).is_err());

        // B opens a circuit back toward A, forwards, then closes it: the
        // closed circuit is no longer a forwarding target.
        let mut toward_a = open_request();
        toward_a.destination_hint = b"peer-a".to_vec();
        let b_circuit = relay
            .open_circuit(&toward_a, b"peer-b".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        assert!(relay.forward_data(a_circuit, b"x", Instant(0)).is_ok());
        relay.close_circuit(b_circuit, 0, Instant(1)).unwrap();
        assert_eq!(relay.circuit_for_destination(b"peer-b"), None);
        assert!(relay.forward_data(a_circuit, b"x", Instant(0)).is_err());

        // A circuit opened without a destination hint forwards nowhere.
        let loose = relay
            .open_circuit(&open_request(), b"peer-a".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        assert!(relay.forward_data(loose, b"x", Instant(0)).is_err());
    }

    /// Integration of the bus and the relay service (no daemon): data
    /// accepted on A's circuit is pushed as a fresh `RELAY_DATA` frame into
    /// the destination session's outbound channel, ready for its link.
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_data_forwarded_between_two_sessions() {
        let events = Arc::new(Mutex::new(DaemonEvents::new(200)));
        let mut relay = RelayService::new(events.clone());
        let mut bus = SessionBus::new();
        let (in_a_tx, _in_a_rx) = tokio::sync::mpsc::unbounded_channel();
        let (out_a_tx, _out_a_rx) = tokio::sync::mpsc::unbounded_channel();
        let (in_b_tx, in_b_rx) = tokio::sync::mpsc::unbounded_channel();
        let (out_b_tx, mut out_b_rx) = tokio::sync::mpsc::unbounded_channel();
        bus.register(b"peer-a".to_vec(), 1, in_a_tx, out_a_tx);
        bus.register(b"peer-b".to_vec(), 2, in_b_tx, out_b_tx);

        // A opens a circuit toward B; B opens one back toward A.
        let mut toward_b = open_request();
        toward_b.destination_hint = b"peer-b".to_vec();
        let a_circuit = relay
            .open_circuit(&toward_b, b"peer-a".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        relay.record_circuit_owner(a_circuit, 1);
        let mut toward_a = open_request();
        toward_a.destination_hint = b"peer-a".to_vec();
        let b_circuit = relay
            .open_circuit(&toward_a, b"peer-b".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        relay.record_circuit_owner(b_circuit, 2);

        // A's data is accepted on its circuit and forwarded toward B.
        relay
            .accept_upstream(a_circuit, 0, false, b"inner-packet", Instant(1))
            .unwrap();
        let (dest_peer, frame_bytes) = relay
            .forward_data(a_circuit, b"inner-packet", Instant(1))
            .unwrap();
        assert_eq!(dest_peer, b"peer-b");
        bus.inject_outbound(&dest_peer, frame_bytes).unwrap();

        // The destination session's outbound channel carries a fresh
        // `RELAY_DATA` frame on B's circuit with the same payload.
        let received = out_b_rx.recv().await.unwrap();
        let (ty, n) = umc_wire::varint::decode(&received).unwrap();
        assert_eq!(
            umc_types::frame::FrameType(ty),
            umc_types::frame::FrameType::RELAY_DATA
        );
        let frame = WireRelayDataFrame::decode(&received[n..]).unwrap().0;
        assert_eq!(frame.circuit_id, b_circuit);
        assert_eq!(frame.relay_sequence, 0);
        assert!(!frame.fin);
        assert_eq!(frame.data, b"inner-packet");

        // The per-direction sequence advances on the destination circuit:
        // the next forward allocates sequence 1.
        let (_dest, next) = relay.forward_data(a_circuit, b"more", Instant(2)).unwrap();
        let (ty, n) = umc_wire::varint::decode(&next).unwrap();
        assert_eq!(
            umc_types::frame::FrameType(ty),
            umc_types::frame::FrameType::RELAY_DATA
        );
        let next = WireRelayDataFrame::decode(&next[n..]).unwrap().0;
        assert_eq!(next.circuit_id, b_circuit);
        assert_eq!(next.relay_sequence, 1);
        assert_eq!(next.data, b"more");

        // The forward is recorded in the event log.
        let recent = events.lock().unwrap().recent(10);
        assert_eq!(
            recent
                .iter()
                .filter(|e| e.kind == "relay_data_forwarded")
                .count(),
            2
        );
        let _ = in_b_rx;
    }
}
