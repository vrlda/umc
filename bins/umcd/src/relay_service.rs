//! Relay service (relay.md §8-24): the daemon's in-memory circuit registry,
//! admission, forwarding, and closure. Persistence lands in Phase 12; the
//! registry is process-local for now.
use crate::event_log::{DaemonEvent, DaemonEvents};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use umc_relay::admission::{evaluate_open, AdmissionDecision, AdmissionLimits, RelayPolicy};
use umc_relay::circuit::Circuit;
use umc_relay::close::{close_circuit, RelayReason};
use umc_relay::forward::{accept_upstream_data, ForwardError};
use umc_types::runtime::Instant;

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
    pub limits: AdmissionLimits,
    events: Arc<Mutex<DaemonEvents>>,
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
            limits: AdmissionLimits {
                policy: RelayPolicy::Community,
                ..AdmissionLimits::default()
            },
            events,
        }
    }

    /// Evaluate `RELAY_OPEN` and allocate a circuit when admitted (relay.md
    /// §13, §34).
    ///
    /// # Errors
    ///
    /// Returns a message when admission refuses the open.
    pub fn open_circuit(
        &mut self,
        request: &CircuitOpenRequest,
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
        }
    }

    #[test]
    fn open_forward_close_lifecycle() {
        let mut relay = service();
        let result = relay.open_circuit(&open_request(), Instant(0)).unwrap();
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
        let first = relay.open_circuit(&open_request(), Instant(0)).unwrap();
        let second = relay.open_circuit(&open_request(), Instant(0)).unwrap();
        assert_eq!(second.circuit_id, first.circuit_id + 1);

        let mut small = open_request();
        small.requested_byte_quota = 10;
        let tiny = relay.open_circuit(&small, Instant(0)).unwrap();
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
        assert!(relay.open_circuit(&open_request(), Instant(0)).is_err());
        assert!(relay.is_empty());
    }

    #[test]
    fn unknown_flags_rejected() {
        let mut relay = service();
        let mut request = open_request();
        request.flags = 0x10;
        assert!(relay.open_circuit(&request, Instant(0)).is_err());
    }

    #[test]
    fn circuit_owners_track_the_opening_session() {
        let mut relay = service();
        let id = relay
            .open_circuit(&open_request(), Instant(0))
            .unwrap()
            .circuit_id;
        assert!(relay.circuit_owner(id).is_none());
        relay.record_circuit_owner(id, 7);
        assert_eq!(relay.circuit_owner(id), Some(7));
        assert_eq!(relay.circuits_for_peer(7), 1);
        let other = relay
            .open_circuit(&open_request(), Instant(0))
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
        relay.open_circuit(&open_request(), Instant(5)).unwrap();
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
            .open_circuit(&open_request(), Instant(5))
            .unwrap()
            .circuit_id;
        relay.close_circuit(id, 0, Instant(20)).unwrap();
        let recent = events.lock().unwrap().recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].kind, "circuit_closed");
        assert_eq!(recent[0].at_ms, 20);
    }
}
