//! Relay service (relay.md §8-24): the daemon's in-memory circuit registry,
//! admission, forwarding, and closure. Persistence lands in Phase 12; the
//! registry is process-local for now.
use crate::event_log::{DaemonEvent, DaemonEvents};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use umc_relay::admission::{evaluate_open, AdmissionDecision, AdmissionLimits, RelayPolicy};
use umc_relay::circuit::{Circuit, CircuitState};
use umc_relay::close::{close_circuit, drain_circuit, expiry_reason, RelayReason};
use umc_relay::forward::{accept_upstream_data, ForwardError};
use umc_relay::status::RelayStatus;
use umc_types::runtime::Instant;
use umc_wire::frames::relay::{RelayCloseFrame, RelayDataFrame, RelayOpenFrame, RelayStatusFrame};

const MAX_STATUS_HISTORY_CIRCUITS: usize = 1_024;
const MAX_OPEN_REPLAY_ENTRIES: usize = 1_024;
const MAX_PENDING_DATA_FRAMES_PER_CIRCUIT: usize = 64;

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
    /// Per-adjacent-peer status replay state. Keeping a small sequence window
    /// makes duplicate status retransmission idempotent without allowing an
    /// unbounded control-frame cache.
    status_history: HashMap<(Vec<u8>, u64), BTreeMap<u64, RelayStatusFrame>>,
    /// Wire circuit IDs are scoped to one adjacent session while the circuit
    /// registry uses process-local IDs. Keep both directions explicit so
    /// inbound data/close frames and forwarded frames use the correct scope.
    wire_to_internal: HashMap<(u64, u64), u64>,
    internal_to_wire: HashMap<(u64, u64), u64>,
    /// Explicit paired legs. Destination-peer lookup alone is insufficient
    /// when two circuits share an adjacent peer; each upstream circuit must
    /// forward to its own reciprocal downstream leg.
    paired_circuits: HashMap<u64, u64>,
    /// Circuits whose downstream leg has received `ACCEPTED`. Nested opens
    /// remain paired but cannot forward until this gate is set.
    ready_circuits: HashSet<u64>,
    /// Bounded data accepted while a nested downstream open is in flight.
    pending_data: HashMap<u64, VecDeque<RelayDataFrame>>,
    /// Bounded replay state for `RELAY_OPEN`. An identical duplicate receives
    /// the prior status without allocating another circuit; a changed body
    /// using the same wire ID is surfaced as a conflict.
    open_replays: HashMap<(u64, u64), RelayOpenReplay>,
    open_replay_order: VecDeque<(u64, u64)>,
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

/// One expiry/idle notification for a paired circuit. The session task turns
/// both legs into peer-scoped `RELAY_CLOSE` frames and then the bounded sweep
/// drains the local state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayExpiryNotification {
    pub reason: RelayReason,
    pub upstream_session: Option<u64>,
    pub upstream_wire_id: u64,
    pub upstream_final_sequence: u64,
    pub downstream_session: Option<u64>,
    pub downstream_wire_id: Option<u64>,
    pub downstream_final_sequence: Option<u64>,
}

/// Result of consuming one inbound `RELAY_STATUS` sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayStatusDisposition {
    New,
    Duplicate,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayStatusError {
    UnknownCode(u64),
    ConflictingDuplicate,
}

/// Replay classification for one peer-scoped `RELAY_OPEN` identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayOpenDisposition {
    New,
    Duplicate(RelayStatusFrame),
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayOpenReplay {
    request: RelayOpenFrame,
    status: RelayStatusFrame,
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
            status_history: HashMap::new(),
            wire_to_internal: HashMap::new(),
            internal_to_wire: HashMap::new(),
            paired_circuits: HashMap::new(),
            ready_circuits: HashSet::new(),
            pending_data: HashMap::new(),
            open_replays: HashMap::new(),
            open_replay_order: VecDeque::new(),
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
    #[allow(clippy::needless_pass_by_value)]
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
            .entry(owner_peer.clone())
            .or_default()
            .push(circuit_id);
        // A relay circuit is a paired pair of directional legs. Match a new
        // leg only with an unpaired reciprocal leg (owner and destination
        // exchange); never fall back to whichever circuit happened to be
        // opened most recently for that peer.
        if !request.destination_hint.is_empty() {
            let reciprocal = self
                .circuits_by_owner
                .get(&request.destination_hint)
                .and_then(|candidates| {
                    candidates.iter().rev().copied().find(|candidate| {
                        !self.paired_circuits.contains_key(candidate)
                            && self
                                .destination_hints
                                .get(candidate)
                                .is_some_and(|destination| destination == &owner_peer)
                    })
                });
            if let Some(reciprocal) = reciprocal {
                self.paired_circuits.insert(circuit_id, reciprocal);
                self.paired_circuits.insert(reciprocal, circuit_id);
                self.ready_circuits.insert(circuit_id);
                self.ready_circuits.insert(reciprocal);
            }
        }
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

    /// Return the wire status that cheap admission would produce without
    /// reserving circuit state. The session layer uses this to preserve the
    /// relay status registry when `RELAY_OPEN` is refused before allocation.
    #[must_use]
    pub fn admission_status(&self, request: &CircuitOpenRequest) -> u64 {
        match evaluate_open(
            &self.limits,
            request.peer_circuits,
            request.requested_lifetime_ms,
            request.requested_byte_quota,
            request.flags,
        ) {
            AdmissionDecision::Accepted { .. } => RelayStatus::Accepted as u64,
            AdmissionDecision::Refused => RelayStatus::Refused as u64,
            AdmissionDecision::NoRoute => RelayStatus::NoRoute as u64,
            AdmissionDecision::AuthFailed => RelayStatus::AuthFailed as u64,
            AdmissionDecision::ResourceLimit => RelayStatus::ResourceLimit as u64,
            AdmissionDecision::UnsupportedFlags => RelayStatus::UnsupportedFlags as u64,
        }
    }

    /// Validate and consume one inbound `RELAY_STATUS` frame. Status sequence
    /// numbers are scoped to the adjacent peer and circuit. Exact duplicate
    /// bytes are harmless; conflicting bytes at one sequence are rejected.
    /// Older unseen sequences are ignored as stale and never mutate state.
    pub fn observe_status(
        &mut self,
        peer_endpoint_id: &[u8],
        status: &RelayStatusFrame,
    ) -> Result<RelayStatusDisposition, RelayStatusError> {
        if !(0..=11).contains(&status.status_code) {
            return Err(RelayStatusError::UnknownCode(status.status_code));
        }
        let key = (peer_endpoint_id.to_vec(), status.circuit_id);
        if !self.status_history.contains_key(&key)
            && self.status_history.len() >= MAX_STATUS_HISTORY_CIRCUITS
        {
            if let Some(oldest) = self.status_history.keys().next().cloned() {
                self.status_history.remove(&oldest);
            }
        }
        let history = self.status_history.entry(key).or_default();
        if let Some(previous) = history.get(&status.status_sequence) {
            return if previous == status {
                Ok(RelayStatusDisposition::Duplicate)
            } else {
                Err(RelayStatusError::ConflictingDuplicate)
            };
        }
        if history
            .keys()
            .next_back()
            .is_some_and(|latest| status.status_sequence < *latest)
        {
            return Ok(RelayStatusDisposition::Stale);
        }
        history.insert(status.status_sequence, status.clone());
        while history.len() > 8 {
            let Some(oldest) = history.keys().next().copied() else {
                break;
            };
            history.remove(&oldest);
        }
        Ok(RelayStatusDisposition::New)
    }

    /// Classify a peer-scoped `RELAY_OPEN` before any admission or
    /// allocation. Identical bytes replay the prior status; a changed body
    /// using the same wire ID is a circuit-scope conflict.
    #[must_use]
    pub fn observe_open(&self, session_id: u64, open: &RelayOpenFrame) -> RelayOpenDisposition {
        let key = (session_id, open.circuit_id);
        if let Some(replay) = self.open_replays.get(&key) {
            return if replay.request == *open {
                RelayOpenDisposition::Duplicate(replay.status.clone())
            } else {
                RelayOpenDisposition::Conflict
            };
        }
        if self.wire_to_internal.contains_key(&key) {
            RelayOpenDisposition::Conflict
        } else {
            RelayOpenDisposition::New
        }
    }

    /// Remember the terminal status for a new `RELAY_OPEN`. The bounded FIFO
    /// is independent from live circuit state so a retransmission after close
    /// remains idempotent without retaining unbounded metadata.
    pub fn remember_open(
        &mut self,
        session_id: u64,
        open: RelayOpenFrame,
        status: RelayStatusFrame,
    ) {
        let key = (session_id, open.circuit_id);
        if self.open_replays.contains_key(&key) {
            return;
        }
        if self.open_replay_order.len() >= MAX_OPEN_REPLAY_ENTRIES {
            if let Some(oldest) = self.open_replay_order.pop_front() {
                self.open_replays.remove(&oldest);
            }
        }
        self.open_replay_order.push_back(key);
        self.open_replays.insert(
            key,
            RelayOpenReplay {
                request: open,
                status,
            },
        );
    }

    /// Record the session that opened a circuit. The opening session is the
    /// circuit's peer end: `RELAY_DATA` arriving for the circuit is destined
    /// for it (relay.md §16-18).
    pub fn record_circuit_owner(&mut self, circuit_id: u64, session_id: u64) {
        self.circuit_owners.insert(circuit_id, session_id);
    }

    /// Bind a peer-selected wire circuit id to a process-local circuit id.
    /// The pair is scoped to the adjacent session, so equal wire IDs on two
    /// sessions remain independent.
    pub fn bind_wire_circuit(
        &mut self,
        session_id: u64,
        wire_circuit_id: u64,
        internal_circuit_id: u64,
    ) -> Result<(), String> {
        let key = (session_id, wire_circuit_id);
        if self.wire_to_internal.contains_key(&key) {
            return Err(format!(
                "wire circuit {wire_circuit_id} already exists on session {session_id}"
            ));
        }
        self.wire_to_internal.insert(key, internal_circuit_id);
        self.internal_to_wire
            .insert((session_id, internal_circuit_id), wire_circuit_id);
        Ok(())
    }

    /// Attach a destination leg when the target endpoint is already connected
    /// to this relay but has not sent its own `RELAY_OPEN`. The leg uses the
    /// opener's wire id on the destination session, which lets the endpoint
    /// create a bounded opaque handoff without learning relay-local ids.
    pub fn attach_destination_leg(
        &mut self,
        source_circuit_id: u64,
        destination_session: u64,
        destination_wire_id: u64,
        source_peer: &[u8],
        destination_peer: &[u8],
        now: Instant,
    ) -> Result<u64, String> {
        if self.paired_circuits.contains_key(&source_circuit_id) {
            return Err("circuit already has a destination leg".into());
        }
        let source = self
            .circuits
            .get(&source_circuit_id)
            .cloned()
            .ok_or_else(|| format!("unknown circuit {source_circuit_id}"))?;
        let lifetime = source.expires_at.duration_since(now).as_millis().max(1_000);
        let destination_circuit_id = self.next_circuit_id;
        self.next_circuit_id = self.next_circuit_id.saturating_add(1);
        let mut destination = Circuit::new(
            destination_circuit_id,
            now,
            lifetime,
            source.granted_byte_quota,
            source.bidirectional,
            source.private_handling,
        );
        if source.state != CircuitState::Opening {
            destination.accept(now);
        }
        self.circuits.insert(destination_circuit_id, destination);
        self.circuit_owners
            .insert(destination_circuit_id, destination_session);
        self.destination_hints
            .insert(destination_circuit_id, source_peer.to_vec());
        self.circuits_by_owner
            .entry(destination_peer.to_vec())
            .or_default()
            .push(destination_circuit_id);
        self.paired_circuits
            .insert(source_circuit_id, destination_circuit_id);
        self.paired_circuits
            .insert(destination_circuit_id, source_circuit_id);
        self.ready_circuits.insert(source_circuit_id);
        self.ready_circuits.insert(destination_circuit_id);
        if let Err(error) = self.bind_wire_circuit(
            destination_session,
            destination_wire_id,
            destination_circuit_id,
        ) {
            self.paired_circuits.remove(&source_circuit_id);
            self.paired_circuits.remove(&destination_circuit_id);
            self.ready_circuits.remove(&source_circuit_id);
            self.ready_circuits.remove(&destination_circuit_id);
            self.circuit_owners.remove(&destination_circuit_id);
            self.destination_hints.remove(&destination_circuit_id);
            self.circuits.remove(&destination_circuit_id);
            if let Some(owned) = self.circuits_by_owner.get_mut(destination_peer) {
                owned.retain(|id| *id != destination_circuit_id);
            }
            return Err(error);
        }
        self.events.lock().expect("event log").push(DaemonEvent {
            kind: "circuit_destination_attached".into(),
            at_ms: now.0,
            detail: format!(
                "circuit {source_circuit_id} -> destination leg {destination_circuit_id}"
            ),
        });
        Ok(destination_circuit_id)
    }

    /// Join an upstream circuit to a circuit opened toward the next relay.
    ///
    /// The two wire circuit identifiers are scoped to different adjacent
    /// sessions, so the relay keeps a private process-local pair and rewrites
    /// each leg's destination hint to the peer on the opposite side.  The
    /// downstream relay therefore receives a fresh identifier while the
    /// upstream endpoint never learns local circuit state (relay.md §15).
    #[allow(clippy::too_many_arguments)]
    pub fn attach_downstream_leg(
        &mut self,
        source_circuit_id: u64,
        downstream_circuit_id: u64,
        downstream_session: u64,
        downstream_wire_id: u64,
        source_peer: &[u8],
        downstream_peer: &[u8],
        now: Instant,
    ) -> Result<u64, String> {
        if source_circuit_id == downstream_circuit_id {
            return Err("upstream and downstream circuits must differ".into());
        }
        if self.paired_circuits.contains_key(&source_circuit_id)
            || self.paired_circuits.contains_key(&downstream_circuit_id)
        {
            return Err("circuit already has a destination leg".into());
        }
        let source = self
            .circuits
            .get(&source_circuit_id)
            .cloned()
            .ok_or_else(|| format!("unknown circuit {source_circuit_id}"))?;
        if !self.circuits.contains_key(&downstream_circuit_id) {
            return Err(format!("unknown circuit {downstream_circuit_id}"));
        }

        let prior_source_hint = self
            .destination_hints
            .get(&source_circuit_id)
            .cloned()
            .unwrap_or_default();
        self.destination_hints
            .insert(source_circuit_id, downstream_peer.to_vec());
        self.destination_hints
            .insert(downstream_circuit_id, source_peer.to_vec());
        self.circuit_owners
            .insert(downstream_circuit_id, downstream_session);
        if let Some(downstream) = self.circuits.get_mut(&downstream_circuit_id) {
            downstream.expires_at = downstream.expires_at.min(source.expires_at);
            downstream.idle_deadline = downstream.idle_deadline.min(source.idle_deadline);
            downstream.granted_byte_quota =
                downstream.granted_byte_quota.min(source.granted_byte_quota);
            downstream.bidirectional &= source.bidirectional;
            downstream.private_handling &= source.private_handling;
        }
        self.paired_circuits
            .insert(source_circuit_id, downstream_circuit_id);
        self.paired_circuits
            .insert(downstream_circuit_id, source_circuit_id);
        if let Err(error) = self.bind_wire_circuit(
            downstream_session,
            downstream_wire_id,
            downstream_circuit_id,
        ) {
            self.paired_circuits.remove(&source_circuit_id);
            self.paired_circuits.remove(&downstream_circuit_id);
            self.ready_circuits.remove(&source_circuit_id);
            self.ready_circuits.remove(&downstream_circuit_id);
            self.circuit_owners.remove(&downstream_circuit_id);
            self.destination_hints
                .insert(source_circuit_id, prior_source_hint);
            self.destination_hints.remove(&downstream_circuit_id);
            self.circuits.remove(&downstream_circuit_id);
            let remove_owner = if let Some(owned) = self.circuits_by_owner.get_mut(downstream_peer)
            {
                owned.retain(|id| *id != downstream_circuit_id);
                owned.is_empty()
            } else {
                false
            };
            if remove_owner {
                self.circuits_by_owner.remove(downstream_peer);
            }
            return Err(error);
        }
        self.events.lock().expect("event log").push(DaemonEvent {
            kind: "circuit_downstream_attached".into(),
            at_ms: now.0,
            detail: format!(
                "circuit {source_circuit_id} -> downstream circuit {downstream_circuit_id}"
            ),
        });
        Ok(downstream_circuit_id)
    }

    /// Resolve a wire circuit id received from one adjacent session.
    #[must_use]
    pub fn resolve_wire_circuit(&self, session_id: u64, wire_circuit_id: u64) -> Option<u64> {
        self.wire_to_internal
            .get(&(session_id, wire_circuit_id))
            .copied()
    }

    /// Translate a process-local circuit id into the wire id used by its
    /// owning adjacent session. Local unit-test circuits without an alias use
    /// the process-local id as their wire id.
    #[must_use]
    pub fn wire_circuit_id(&self, session_id: u64, internal_circuit_id: u64) -> u64 {
        self.internal_to_wire
            .get(&(session_id, internal_circuit_id))
            .copied()
            .unwrap_or(internal_circuit_id)
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
    #[allow(dead_code)]
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
    #[cfg(test)]
    pub fn forward_data(
        &mut self,
        circuit_id: u64,
        data: &[u8],
        now: Instant,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.forward_data_frame(
            &RelayDataFrame {
                circuit_id,
                relay_sequence: 0,
                fin: false,
                ack_requested: false,
                high_priority: false,
                data: data.to_vec(),
            },
            now,
        )
    }

    /// Whether a paired downstream leg has completed its open handshake.
    #[must_use]
    pub fn downstream_ready(&self, circuit_id: u64) -> bool {
        self.ready_circuits.contains(&circuit_id)
    }

    /// Whether the circuit has any paired downstream leg, even if that leg
    /// is still waiting for its `RELAY_OPEN` acceptance.
    #[must_use]
    pub fn has_paired_circuit(&self, circuit_id: u64) -> bool {
        self.paired_circuits.contains_key(&circuit_id)
    }

    /// Queue accepted data while a nested downstream `RELAY_OPEN` is pending.
    /// The queue is circuit-scoped and bounded; callers close the circuit when
    /// the bound is reached rather than dropping accepted bytes silently.
    pub fn queue_pending_data(
        &mut self,
        circuit_id: u64,
        frame: RelayDataFrame,
    ) -> Result<(), String> {
        let queue = self.pending_data.entry(circuit_id).or_default();
        if queue.len() >= MAX_PENDING_DATA_FRAMES_PER_CIRCUIT {
            return Err("pending downstream data queue is full".into());
        }
        queue.push_back(frame);
        Ok(())
    }

    /// Mark a downstream wire circuit accepted and release queued data from
    /// both directions of the paired local mapping.
    pub fn activate_downstream(
        &mut self,
        downstream_session: u64,
        status: &RelayStatusFrame,
    ) -> Result<Vec<RelayDataFrame>, String> {
        if status.status_code != RelayStatus::Accepted as u64 {
            return Ok(Vec::new());
        }
        let downstream_internal = self
            .resolve_wire_circuit(downstream_session, status.circuit_id)
            .ok_or_else(|| {
                format!(
                    "unknown downstream wire circuit {} on session {downstream_session}",
                    status.circuit_id
                )
            })?;
        let upstream_internal = self
            .paired_circuits
            .get(&downstream_internal)
            .copied()
            .ok_or_else(|| "downstream circuit has no upstream leg".to_string())?;
        self.ready_circuits.insert(downstream_internal);
        self.ready_circuits.insert(upstream_internal);
        let mut queued = self
            .pending_data
            .remove(&upstream_internal)
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        queued.extend(
            self.pending_data
                .remove(&downstream_internal)
                .unwrap_or_default(),
        );
        Ok(queued)
    }

    /// Forward one accepted frame while preserving its terminal and delivery
    /// flags. The destination circuit receives a fresh sequence number, but
    /// `FIN`, ACK-request, and priority semantics belong to the payload and
    /// must survive every relay hop (relay.md §18).
    pub fn forward_data_frame(
        &mut self,
        upstream: &RelayDataFrame,
        now: Instant,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        if !self.downstream_ready(upstream.circuit_id) {
            return Err("downstream leg is still opening".into());
        }
        let destination = self
            .destination_hints
            .get(&upstream.circuit_id)
            .ok_or_else(|| format!("unknown circuit {}", upstream.circuit_id))?;
        let destination = destination.clone();
        let dest_circuit = self
            .paired_circuits
            .get(&upstream.circuit_id)
            .copied()
            .filter(|circuit_id| {
                self.circuits
                    .get(circuit_id)
                    .is_some_and(|circuit| circuit.state != CircuitState::Closed)
            })
            .ok_or_else(|| "no paired circuit for destination peer".to_string())?;
        let sequence = self
            .circuits
            .get_mut(&dest_circuit)
            .ok_or_else(|| format!("unknown destination circuit {dest_circuit}"))?
            .allocate_sequence();
        let frame = RelayDataFrame {
            circuit_id: self
                .circuit_owner(dest_circuit)
                .map_or(dest_circuit, |session_id| {
                    self.wire_circuit_id(session_id, dest_circuit)
                }),
            relay_sequence: sequence,
            fin: upstream.fin,
            ack_requested: upstream.ack_requested,
            high_priority: upstream.high_priority,
            data: upstream.data.clone(),
        };
        let encoded = frame
            .encode()
            .map_err(|e| format!("forward encode: {e:?}"))?;
        self.events.lock().expect("event log").push(DaemonEvent {
            kind: "relay_data_forwarded".into(),
            at_ms: now.0,
            detail: format!(
                "circuit {} -> destination circuit {dest_circuit} ({} bytes)",
                upstream.circuit_id,
                upstream.data.len()
            ),
        });
        Ok((destination, encoded))
    }

    /// Map a downstream `RELAY_STATUS` back to the upstream wire scope. The
    /// status is control-plane metadata, not circuit payload, so it follows
    /// the private pair mapping without touching sequence or quota counters.
    pub fn forward_status_frame(
        &self,
        downstream_session: u64,
        status: &RelayStatusFrame,
    ) -> Result<(u64, RelayStatusFrame), String> {
        let downstream_internal = self
            .resolve_wire_circuit(downstream_session, status.circuit_id)
            .ok_or_else(|| {
                format!(
                    "unknown downstream wire circuit {} on session {downstream_session}",
                    status.circuit_id
                )
            })?;
        let upstream_internal = self
            .paired_circuits
            .get(&downstream_internal)
            .copied()
            .ok_or_else(|| "downstream circuit has no upstream leg".to_string())?;
        let upstream_session = self
            .circuit_owners
            .get(&upstream_internal)
            .copied()
            .ok_or_else(|| "upstream circuit has no owner session".to_string())?;
        let mut forwarded = status.clone();
        forwarded.circuit_id = self.wire_circuit_id(upstream_session, upstream_internal);
        Ok((upstream_session, forwarded))
    }

    /// Build a close notification for the paired destination leg before the
    /// local circuit mappings are removed. Close reason and final sequence
    /// remain circuit-scoped control semantics across the hop.
    pub fn forward_close(
        &self,
        circuit_id: u64,
        reason_code: u64,
        final_relay_sequence: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let destination = self
            .destination_hints
            .get(&circuit_id)
            .ok_or_else(|| format!("unknown circuit {circuit_id}"))?
            .clone();
        let destination_circuit = self
            .paired_circuits
            .get(&circuit_id)
            .copied()
            .filter(|destination_circuit| {
                self.circuits
                    .get(destination_circuit)
                    .is_some_and(|circuit| circuit.state != CircuitState::Closed)
            })
            .ok_or_else(|| "no paired circuit for destination peer".to_string())?;
        let frame = RelayCloseFrame {
            circuit_id: self
                .circuit_owner(destination_circuit)
                .map_or(destination_circuit, |session_id| {
                    self.wire_circuit_id(session_id, destination_circuit)
                }),
            reason_code,
            final_relay_sequence,
        };
        let encoded = frame
            .encode()
            .map_err(|error| format!("forward close encode: {error:?}"))?;
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
        if circuit.state == CircuitState::HalfClosedUpstream {
            return Err("forward rejected: upstream direction already half-closed".into());
        }
        match accept_upstream_data(circuit, sequence, fin, data, self.limits.max_payload) {
            Ok(_) => {
                // A relay circuit is allocated in `Opening` until its first
                // valid payload arrives. Keep rejected data from activating
                // the circuit (relay.md §9.2).
                if circuit.state == CircuitState::Opening {
                    circuit.accept(now);
                }
                if fin {
                    umc_relay::forward::apply_fin(circuit, true)
                        .map_err(|error| format!("forward rejected: {error:?}"))?;
                }
                circuit.touch(now);
                Ok(())
            }
            Err(ForwardError::DuplicateDiscarded) => Ok(()),
            Err(e) => Err(format!("forward rejected: {e:?}")),
        }
    }

    /// Advance relay lifetime/idle expiry and closing drains. Expiring a
    /// paired circuit closes both local legs and returns the peer-scoped wire
    /// IDs needed for close notifications; metadata is retained through the
    /// two-stage drain and then purged.
    pub fn sweep(&mut self, now: Instant) -> Vec<RelayExpiryNotification> {
        let ids: Vec<u64> = self.circuits.keys().copied().collect();
        let mut notifications = Vec::new();
        for circuit_id in ids {
            let Some(state) = self.circuits.get(&circuit_id).map(|circuit| circuit.state) else {
                continue;
            };
            if matches!(state, CircuitState::Closing | CircuitState::Draining) {
                if let Some(circuit) = self.circuits.get_mut(&circuit_id) {
                    drain_circuit(circuit, now);
                }
                continue;
            }
            let Some(reason) = self
                .circuits
                .get(&circuit_id)
                .and_then(|circuit| expiry_reason(circuit, now))
            else {
                continue;
            };
            let paired_id = self.paired_circuits.get(&circuit_id).copied();
            let upstream_session = self.circuit_owners.get(&circuit_id).copied();
            let upstream_wire_id = upstream_session.map_or(circuit_id, |session_id| {
                self.wire_circuit_id(session_id, circuit_id)
            });
            let upstream_final_sequence = self
                .circuits
                .get(&circuit_id)
                .map_or(0, |circuit| circuit.next_relay_sequence.saturating_sub(1));
            let (downstream_session, downstream_wire_id, downstream_final_sequence) = paired_id
                .map_or((None, None, None), |paired| {
                    let session = self.circuit_owners.get(&paired).copied();
                    (
                        session,
                        Some(session.map_or(paired, |session_id| {
                            self.wire_circuit_id(session_id, paired)
                        })),
                        self.circuits
                            .get(&paired)
                            .map(|circuit| circuit.next_relay_sequence.saturating_sub(1)),
                    )
                });
            if let Some(circuit) = self.circuits.get_mut(&circuit_id) {
                close_circuit(circuit, reason, now, None);
            }
            if let Some(paired) = paired_id {
                if let Some(circuit) = self.circuits.get_mut(&paired) {
                    if !matches!(
                        circuit.state,
                        CircuitState::Closing | CircuitState::Draining
                    ) {
                        close_circuit(circuit, reason, now, None);
                    }
                }
            }
            self.events.lock().expect("event log").push(DaemonEvent {
                kind: "circuit_expiring".into(),
                at_ms: now.0,
                detail: format!("circuit {circuit_id}: {reason:?}"),
            });
            notifications.push(RelayExpiryNotification {
                reason,
                upstream_session,
                upstream_wire_id,
                upstream_final_sequence,
                downstream_session,
                downstream_wire_id,
                downstream_final_sequence,
            });
        }
        let closed: Vec<u64> = self
            .circuits
            .iter()
            .filter_map(|(id, circuit)| (circuit.state == CircuitState::Closed).then_some(*id))
            .collect();
        for circuit_id in closed {
            self.purge_closed_circuit(circuit_id, now);
        }
        notifications
    }

    fn purge_closed_circuit(&mut self, circuit_id: u64, now: Instant) {
        self.circuits.remove(&circuit_id);
        self.circuit_owners.remove(&circuit_id);
        self.wire_to_internal
            .retain(|_, internal| *internal != circuit_id);
        self.internal_to_wire
            .retain(|(_, internal), _| *internal != circuit_id);
        if let Some(paired) = self.paired_circuits.remove(&circuit_id) {
            self.paired_circuits.remove(&paired);
        }
        self.ready_circuits.remove(&circuit_id);
        self.pending_data.remove(&circuit_id);
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
        if !self.circuits.contains_key(&circuit_id) {
            return Err(format!("unknown circuit {circuit_id}"));
        }
        let paired = self.paired_circuits.get(&circuit_id).copied();
        let reason = RelayReason::from_u64(reason).unwrap_or(RelayReason::NoError);
        let mut legs = Vec::with_capacity(2);
        legs.push(circuit_id);
        if let Some(paired) = paired {
            if paired != circuit_id {
                legs.push(paired);
            }
        }
        // A close on either directional leg closes its reciprocal leg too;
        // leaving the destination leg active would leak quota and permit a
        // half-dead circuit to be selected for later forwarding.
        for leg in &legs {
            if let Some(circuit) = self.circuits.get_mut(leg) {
                close_circuit(circuit, reason, now, None);
            }
        }
        for leg in &legs {
            self.circuit_owners.remove(leg);
            self.wire_to_internal
                .retain(|_, internal| *internal != *leg);
            self.internal_to_wire
                .retain(|(_, internal), _| *internal != *leg);
            self.destination_hints.remove(leg);
            self.ready_circuits.remove(leg);
            self.pending_data.remove(leg);
            self.circuits_by_owner.retain(|_, owned| {
                owned.retain(|id| *id != *leg);
                !owned.is_empty()
            });
            self.events.lock().expect("event log").push(DaemonEvent {
                kind: "circuit_closed".into(),
                at_ms: now.0,
                detail: format!("circuit {leg}"),
            });
        }
        if let Some(paired) = paired {
            self.paired_circuits.remove(&circuit_id);
            self.paired_circuits.remove(&paired);
        }
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
    use umc_wire::frames::relay::RelayCloseFrame as WireRelayCloseFrame;
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

    fn status(sequence: u64, code: u64) -> RelayStatusFrame {
        RelayStatusFrame {
            circuit_id: 7,
            status_sequence: sequence,
            status_code: code,
            bidirectional_granted: code == RelayStatus::Accepted as u64,
            private_handling_granted: false,
            multipath_granted: false,
            downstream_authenticated: false,
            retryable: false,
            granted_lifetime: if code == RelayStatus::Accepted as u64 {
                1_000
            } else {
                0
            },
            granted_byte_quota: 1_024,
            maximum_relay_payload: 1_024,
            diagnostic: Vec::new(),
            authentication: Vec::new(),
        }
    }

    fn open_frame(circuit_id: u64, quota: u64) -> RelayOpenFrame {
        RelayOpenFrame {
            circuit_id,
            bidirectional: true,
            store_forward_allowed: false,
            private_circuit: false,
            multipath_allowed: false,
            requested_lifetime: 1_000,
            requested_byte_quota: quota,
            next_hop_hint: Vec::new(),
            authorization: Vec::new(),
        }
    }

    #[test]
    fn relay_status_sequences_are_idempotent_and_bounded() {
        let mut relay = service();
        let accepted = status(0, RelayStatus::Accepted as u64);
        assert_eq!(
            relay.observe_status(b"peer", &accepted),
            Ok(RelayStatusDisposition::New)
        );
        assert_eq!(
            relay.observe_status(b"peer", &accepted),
            Ok(RelayStatusDisposition::Duplicate)
        );
        let mut conflict = accepted.clone();
        conflict.retryable = true;
        assert_eq!(
            relay.observe_status(b"peer", &conflict),
            Err(RelayStatusError::ConflictingDuplicate)
        );
        assert_eq!(
            relay.observe_status(b"peer", &status(1, RelayStatus::Degraded as u64)),
            Ok(RelayStatusDisposition::New)
        );
        assert_eq!(
            relay.observe_status(b"peer", &status(0, RelayStatus::Accepted as u64)),
            Ok(RelayStatusDisposition::Duplicate)
        );
        assert_eq!(
            relay.observe_status(b"peer", &status(99, 12)),
            Err(RelayStatusError::UnknownCode(12))
        );
    }

    #[test]
    fn relay_open_replay_is_stable_and_conflicts_do_not_rebind() {
        let mut relay = service();
        let open = open_frame(7, 1_024);
        let accepted = status(0, RelayStatus::Accepted as u64);
        relay.remember_open(11, open.clone(), accepted.clone());
        assert_eq!(
            relay.observe_open(11, &open),
            RelayOpenDisposition::Duplicate(accepted)
        );
        let mut conflict = open.clone();
        conflict.requested_byte_quota += 1;
        assert_eq!(
            relay.observe_open(11, &conflict),
            RelayOpenDisposition::Conflict
        );
        assert_eq!(
            relay.observe_open(12, &open_frame(7, 1_024)),
            RelayOpenDisposition::New
        );
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
    fn upstream_fin_half_closes_and_blocks_later_data() {
        let mut relay = service();
        let circuit = relay
            .open_circuit(&open_request(), b"peer".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        relay
            .accept_upstream(circuit, 0, true, b"final", Instant(1))
            .expect("terminal data accepted");
        assert!(relay
            .accept_upstream(circuit, 1, false, b"after-fin", Instant(2))
            .is_err());
        assert!(relay
            .accept_upstream(circuit, 1, true, b"duplicate-fin", Instant(2))
            .is_err());
    }

    #[test]
    fn invalid_first_data_does_not_activate_circuit() {
        let mut relay = service();
        let circuit = relay
            .open_circuit(&open_request(), b"peer".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        assert_eq!(relay.circuits[&circuit].state, CircuitState::Opening);
        assert!(relay
            .accept_upstream(circuit, 0, false, &[], Instant(1))
            .is_err());
        assert_eq!(relay.circuits[&circuit].state, CircuitState::Opening);
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
    fn destination_leg_can_be_attached_without_peer_relay_open() {
        let mut relay = service();
        let mut request = open_request();
        request.destination_hint = b"peer-b".to_vec();
        let source = relay
            .open_circuit(&request, b"peer-a".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        relay.record_circuit_owner(source, 10);
        relay.bind_wire_circuit(10, 77, source).unwrap();

        let destination = relay
            .attach_destination_leg(source, 20, 77, b"peer-a", b"peer-b", Instant(0))
            .expect("destination leg");
        assert_eq!(relay.circuit_owner(destination), Some(20));
        assert_eq!(relay.resolve_wire_circuit(20, 77), Some(destination));
        let (peer, bytes) = relay
            .forward_data_frame(
                &RelayDataFrame {
                    circuit_id: source,
                    relay_sequence: 0,
                    fin: false,
                    ack_requested: false,
                    high_priority: false,
                    data: b"inner".to_vec(),
                },
                Instant(1),
            )
            .expect("forward to attached destination");
        assert_eq!(peer, b"peer-b");
        let (_, type_len) = umc_wire::varint::decode(&bytes).unwrap();
        assert_eq!(
            RelayDataFrame::decode(&bytes[type_len..])
                .unwrap()
                .0
                .circuit_id,
            77
        );
    }

    #[test]
    fn downstream_leg_pairs_two_relay_hops_with_scoped_wire_ids() {
        let mut relay = service();
        let mut toward_destination = open_request();
        toward_destination.destination_hint = b"peer-d".to_vec();
        let source = relay
            .open_circuit(&toward_destination, b"peer-a".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        relay.record_circuit_owner(source, 10);
        relay.bind_wire_circuit(10, 11, source).unwrap();

        let downstream = relay
            .open_circuit(&toward_destination, b"peer-b".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        relay
            .attach_downstream_leg(source, downstream, 20, 22, b"peer-a", b"peer-b", Instant(1))
            .unwrap();
        let mut accepted = status(0, RelayStatus::Accepted as u64);
        accepted.circuit_id = 22;
        relay.activate_downstream(20, &accepted).unwrap();
        assert_eq!(relay.circuit_owner(downstream), Some(20));
        assert_eq!(relay.resolve_wire_circuit(20, 22), Some(downstream));

        let source_frame = RelayDataFrame {
            circuit_id: source,
            relay_sequence: 0,
            fin: false,
            ack_requested: false,
            high_priority: false,
            data: b"forward".to_vec(),
        };
        let (peer, bytes) = relay.forward_data_frame(&source_frame, Instant(2)).unwrap();
        assert_eq!(peer, b"peer-b");
        let (_, type_len) = umc_wire::varint::decode(&bytes).unwrap();
        assert_eq!(
            RelayDataFrame::decode(&bytes[type_len..])
                .unwrap()
                .0
                .circuit_id,
            22
        );

        let downstream_frame = RelayDataFrame {
            circuit_id: downstream,
            relay_sequence: 0,
            fin: false,
            ack_requested: false,
            high_priority: false,
            data: b"reverse".to_vec(),
        };
        let (peer, bytes) = relay
            .forward_data_frame(&downstream_frame, Instant(3))
            .unwrap();
        assert_eq!(peer, b"peer-a");
        let (_, type_len) = umc_wire::varint::decode(&bytes).unwrap();
        assert_eq!(
            RelayDataFrame::decode(&bytes[type_len..])
                .unwrap()
                .0
                .circuit_id,
            11
        );
    }

    #[test]
    fn downstream_status_maps_back_to_upstream_wire_scope() {
        let mut relay = service();
        let mut request = open_request();
        request.destination_hint = b"peer-d".to_vec();
        let source = relay
            .open_circuit(&request, b"peer-a".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        relay.record_circuit_owner(source, 10);
        relay.bind_wire_circuit(10, 11, source).unwrap();
        let downstream = relay
            .open_circuit(&request, b"peer-b".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        relay
            .attach_downstream_leg(source, downstream, 20, 22, b"peer-a", b"peer-b", Instant(1))
            .unwrap();

        let mut status = status(3, RelayStatus::Accepted as u64);
        status.circuit_id = 22;
        let (upstream_session, forwarded) = relay
            .forward_status_frame(20, &status)
            .expect("status mapping");
        assert_eq!(upstream_session, 10);
        assert_eq!(forwarded.circuit_id, 11);
        assert_eq!(forwarded.status_sequence, 3);
        assert_eq!(forwarded.status_code, RelayStatus::Accepted as u64);
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

    #[test]
    fn close_propagates_to_the_paired_destination_leg() {
        let mut relay = service();
        let mut toward_b = open_request();
        toward_b.destination_hint = b"peer-b".to_vec();
        let a_circuit = relay
            .open_circuit(&toward_b, b"peer-a".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        let mut toward_a = open_request();
        toward_a.destination_hint = b"peer-a".to_vec();
        let b_circuit = relay
            .open_circuit(&toward_a, b"peer-b".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;

        let (destination, bytes) = relay.forward_close(a_circuit, 7, 11).expect("paired close");
        assert_eq!(destination, b"peer-b");
        let (frame_type, type_len) = umc_wire::varint::decode(&bytes).expect("frame type");
        assert_eq!(
            umc_types::frame::FrameType(frame_type),
            umc_types::frame::FrameType::RELAY_CLOSE
        );
        let frame = WireRelayCloseFrame::decode(&bytes[type_len..])
            .expect("close frame")
            .0;
        assert_eq!(frame.circuit_id, b_circuit);
        assert_eq!(frame.reason_code, 7);
        assert_eq!(frame.final_relay_sequence, 11);

        relay.close_circuit(a_circuit, 7, Instant(20)).unwrap();
        assert_eq!(relay.circuits[&a_circuit].state, CircuitState::Closing);
        assert_eq!(relay.circuits[&b_circuit].state, CircuitState::Closing);
        assert!(relay
            .forward_data(a_circuit, b"after-close", Instant(20))
            .is_err());
        assert_eq!(relay.circuit_owner(a_circuit), None);
        assert_eq!(relay.circuit_owner(b_circuit), None);
        relay.sweep(Instant(1_020));
        assert_eq!(relay.circuits[&a_circuit].state, CircuitState::Draining);
        assert_eq!(relay.circuits[&b_circuit].state, CircuitState::Draining);
        relay.sweep(Instant(2_020));
        assert_eq!(relay.circuit_count(), 0);
    }

    #[test]
    fn forwarding_keeps_multiple_reciprocal_legs_isolated() {
        let mut relay = service();
        let mut toward_b = open_request();
        toward_b.destination_hint = b"peer-b".to_vec();
        let a_first = relay
            .open_circuit(&toward_b, b"peer-a".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        let mut toward_a = open_request();
        toward_a.destination_hint = b"peer-a".to_vec();
        let b_first = relay
            .open_circuit(&toward_a, b"peer-b".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        let a_second = relay
            .open_circuit(&toward_b, b"peer-a".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        let b_second = relay
            .open_circuit(&toward_a, b"peer-b".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;

        let first = RelayDataFrame {
            circuit_id: a_first,
            relay_sequence: 0,
            fin: false,
            ack_requested: false,
            high_priority: false,
            data: b"first".to_vec(),
        };
        let (_, first_bytes) = relay.forward_data_frame(&first, Instant(1)).unwrap();
        let (_, first_len) = umc_wire::varint::decode(&first_bytes).unwrap();
        assert_eq!(
            RelayDataFrame::decode(&first_bytes[first_len..])
                .unwrap()
                .0
                .circuit_id,
            b_first
        );

        let second = RelayDataFrame {
            circuit_id: a_second,
            relay_sequence: 0,
            fin: false,
            ack_requested: false,
            high_priority: false,
            data: b"second".to_vec(),
        };
        let (_, second_bytes) = relay.forward_data_frame(&second, Instant(1)).unwrap();
        let (_, second_len) = umc_wire::varint::decode(&second_bytes).unwrap();
        assert_eq!(
            RelayDataFrame::decode(&second_bytes[second_len..])
                .unwrap()
                .0
                .circuit_id,
            b_second
        );
    }

    #[test]
    fn sweep_expires_and_drains_paired_circuits() {
        let mut relay = service();
        let mut toward_b = open_request();
        toward_b.requested_lifetime_ms = 1_000;
        toward_b.destination_hint = b"peer-b".to_vec();
        let a_circuit = relay
            .open_circuit(&toward_b, b"peer-a".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        let mut toward_a = open_request();
        toward_a.requested_lifetime_ms = 1_000;
        toward_a.destination_hint = b"peer-a".to_vec();
        let b_circuit = relay
            .open_circuit(&toward_a, b"peer-b".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        relay.record_circuit_owner(a_circuit, 1);
        relay.record_circuit_owner(b_circuit, 2);

        let expired = relay.sweep(Instant(1_000));
        assert_eq!(expired.len(), 1, "paired legs expire as one circuit");
        assert_eq!(expired[0].reason, RelayReason::Expired);
        let mut sessions = [expired[0].upstream_session, expired[0].downstream_session];
        sessions.sort_unstable();
        assert_eq!(sessions, [Some(1), Some(2)]);
        assert_eq!(relay.circuit_count(), 2, "both legs drain before purge");
        assert!(relay.sweep(Instant(2_000)).is_empty());
        assert_eq!(relay.circuit_count(), 2);
        assert!(relay.sweep(Instant(3_000)).is_empty());
        assert_eq!(relay.circuit_count(), 0, "drained legs are reclaimed");
    }

    #[test]
    fn sweep_closes_idle_circuit_with_idle_timeout_reason() {
        let mut relay = service();
        let mut request = open_request();
        request.requested_lifetime_ms = 300_000;
        let circuit_id = relay
            .open_circuit(&request, b"peer-a".to_vec(), Instant(0))
            .unwrap()
            .circuit_id;
        let expired = relay.sweep(Instant(120_000));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].reason, RelayReason::IdleTimeout);
        assert_eq!(expired[0].upstream_session, None);
        assert_eq!(expired[0].upstream_wire_id, circuit_id);
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
        let upstream = RelayDataFrame {
            circuit_id: a_circuit,
            relay_sequence: 0,
            fin: false,
            ack_requested: true,
            high_priority: true,
            data: b"inner-packet".to_vec(),
        };
        relay
            .accept_upstream(a_circuit, 0, upstream.fin, &upstream.data, Instant(1))
            .unwrap();
        let (dest_peer, frame_bytes) = relay.forward_data_frame(&upstream, Instant(1)).unwrap();
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
        assert!(frame.ack_requested);
        assert!(frame.high_priority);
        assert_eq!(frame.data, b"inner-packet");

        // A terminal frame preserves FIN and advances the destination
        // circuit's independent sequence.
        let terminal = RelayDataFrame {
            circuit_id: a_circuit,
            relay_sequence: 1,
            fin: true,
            ack_requested: false,
            high_priority: false,
            data: b"final".to_vec(),
        };
        relay
            .accept_upstream(a_circuit, 1, true, &terminal.data, Instant(2))
            .unwrap();
        let (_dest, next) = relay.forward_data_frame(&terminal, Instant(2)).unwrap();
        bus.inject_outbound(b"peer-b", next).unwrap();
        let received = out_b_rx.recv().await.unwrap();
        let (ty, n) = umc_wire::varint::decode(&received).unwrap();
        assert_eq!(
            umc_types::frame::FrameType(ty),
            umc_types::frame::FrameType::RELAY_DATA
        );
        let next = WireRelayDataFrame::decode(&received[n..]).unwrap().0;
        assert_eq!(next.circuit_id, b_circuit);
        assert_eq!(next.relay_sequence, 1);
        assert!(next.fin);
        assert_eq!(next.data, b"final");

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
