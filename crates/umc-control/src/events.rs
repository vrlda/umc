//! Event subscriptions (control-api.md §38-41): bounded queues, sequence
//! tracking, CRITICAL events never silently dropped.
use std::collections::{HashMap, VecDeque};

use blake2::{Blake2s256, Digest};
use prost::Message;

use crate::proto::umc::api::v1 as api;

pub const DEFAULT_EVENT_BACKLOG: usize = 1_024;
pub const DEFAULT_EVENT_BACKLOG_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EVENT_STREAMS_PER_CLIENT: usize = 8;
pub const EVENT_CURSOR_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const EVENT_CURSOR_MAGIC: &[u8; 4] = b"UEC1";
const EVENT_CURSOR_BYTES: usize = 76;

/// Opaque, authenticated position in the bounded event journal.
///
/// The wire representation intentionally contains no subscription handle:
/// handles are connection-scoped, while this cursor is safe to present on a
/// later subscription as long as its principal, filter, journal generation,
/// expiry, and MAC all still validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventResumeCursor {
    generation: [u8; 16],
    principal_id: u64,
    filter_digest: [u8; 16],
    sequence: u64,
    expires_at_ms: u64,
}

impl EventResumeCursor {
    #[must_use]
    pub fn encode(
        principal_id: u64,
        generation: [u8; 16],
        filter_digest: [u8; 16],
        sequence: u64,
        expires_at_ms: u64,
        key: &[u8; 32],
    ) -> Vec<u8> {
        let mut body = Vec::with_capacity(EVENT_CURSOR_BYTES - 16);
        body.extend_from_slice(EVENT_CURSOR_MAGIC);
        body.extend_from_slice(&generation);
        body.extend_from_slice(&principal_id.to_be_bytes());
        body.extend_from_slice(&filter_digest);
        body.extend_from_slice(&sequence.to_be_bytes());
        body.extend_from_slice(&expires_at_ms.to_be_bytes());
        let mac = cursor_mac(&body, key);
        body.extend_from_slice(&mac);
        body
    }

    #[must_use]
    pub fn decode(bytes: &[u8], key: &[u8; 32]) -> Option<Self> {
        if bytes.len() != EVENT_CURSOR_BYTES || &bytes[..4] != EVENT_CURSOR_MAGIC {
            return None;
        }
        let body_len = EVENT_CURSOR_BYTES - 16;
        let expected = cursor_mac(&bytes[..body_len], key);
        if !constant_time_equal(&bytes[body_len..], &expected) {
            return None;
        }
        let generation = bytes.get(4..20)?.try_into().ok()?;
        let principal_id = u64::from_be_bytes(bytes.get(20..28)?.try_into().ok()?);
        let filter_digest = bytes.get(28..44)?.try_into().ok()?;
        let sequence = u64::from_be_bytes(bytes.get(44..52)?.try_into().ok()?);
        let expires_at_ms = u64::from_be_bytes(bytes.get(52..60)?.try_into().ok()?);
        Some(Self {
            generation,
            principal_id,
            filter_digest,
            sequence,
            expires_at_ms,
        })
    }

    #[must_use]
    pub fn validate(
        &self,
        principal_id: u64,
        generation: [u8; 16],
        filter_digest: [u8; 16],
        now_ms: u64,
    ) -> bool {
        self.principal_id == principal_id
            && self.generation == generation
            && self.filter_digest == filter_digest
            && now_ms <= self.expires_at_ms
    }

    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

#[must_use]
pub fn event_filter_digest(filter: &api::EventFilter) -> [u8; 16] {
    let mut hasher = Blake2s256::new();
    hasher.update(filter.encode_to_vec());
    let digest = hasher.finalize();
    let mut output = [0u8; 16];
    output.copy_from_slice(&digest[..16]);
    output
}

fn cursor_mac(body: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Blake2s256::new();
    hasher.update(key);
    hasher.update(body);
    let digest = hasher.finalize();
    let mut output = [0u8; 16];
    output.copy_from_slice(&digest[..16]);
    output
}

fn constant_time_equal(left: &[u8], right: &[u8; 16]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (actual, expected) in left.iter().zip(right) {
        difference |= actual ^ expected;
    }
    difference == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventClass {
    Critical,
    State,
    Edge,
    Sample,
}

#[derive(Debug, Clone)]
pub struct UmpEvent {
    pub class: EventClass,
    pub event_type: String,
    pub resource: Option<Vec<u8>>,
    pub payload: Vec<u8>,
    pub occurred_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: u64,
    pub next_sequence: u64,
    pub out_of_sync: bool,
    pub out_of_sync_from: Option<u64>,
    pub out_of_sync_to: Option<u64>,
    pub queue: VecDeque<(u64, u64, UmpEvent)>,
    pub queue_bytes: usize,
    pub max_backlog: usize,
    /// Sequence and payload size for events handed to the transport but not
    /// yet acknowledged. Retaining only metadata keeps the event payload
    /// allocation single-owned while still charging the bounded backlog.
    in_flight: VecDeque<(u64, usize)>,
    in_flight_bytes: usize,
}

impl Subscription {
    #[must_use]
    pub const fn new(id: u64, max_backlog: usize) -> Self {
        Self {
            id,
            next_sequence: 1,
            out_of_sync: false,
            out_of_sync_from: None,
            out_of_sync_to: None,
            queue: VecDeque::new(),
            queue_bytes: 0,
            max_backlog,
            in_flight: VecDeque::new(),
            in_flight_bytes: 0,
        }
    }

    /// Returns `Ok(sequence)` if delivered, or `Err(SampleDropped)` for a
    /// dropped SAMPLE-class event, or `Err(OutOfSync)` if a CRITICAL event
    /// was dropped.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::SampleDropped`] when a SAMPLE event is dropped
    /// (silently) and [`EventError::OutOfSync`] when a CRITICAL/STATE event
    /// is dropped, flagging the subscription.
    pub fn push(&mut self, event: UmpEvent) -> Result<u64, EventError> {
        self.push_with_journal_sequence(event, 0)
    }

    /// Queue an event and retain the global journal sequence used to build a
    /// resumable cursor. A zero sequence denotes a synthetic initial snapshot
    /// event that is not part of the live journal.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::SampleDropped`] for a sample that exceeds the
    /// bounded backlog, or [`EventError::OutOfSync`] when a stateful event
    /// cannot be retained.
    pub fn push_with_journal_sequence(
        &mut self,
        event: UmpEvent,
        journal_sequence: u64,
    ) -> Result<u64, EventError> {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        if self.queue.len() + self.in_flight.len() >= self.max_backlog
            || self
                .queue_bytes
                .saturating_add(self.in_flight_bytes)
                .saturating_add(event.payload.len())
                > DEFAULT_EVENT_BACKLOG_BYTES
        {
            if event.class == EventClass::Sample {
                return Err(EventError::SampleDropped);
            }
            self.out_of_sync = true;
            self.out_of_sync_from.get_or_insert(sequence);
            self.out_of_sync_to = Some(sequence);
            return Err(EventError::OutOfSync);
        }
        self.queue_bytes += event.payload.len();
        self.queue.push_back((sequence, journal_sequence, event));
        Ok(sequence)
    }

    pub fn pop(&mut self) -> Option<UmpEvent> {
        self.pop_with_sequence().map(|(_, event)| event)
    }

    /// Moves the oldest queued event to the transport in-flight set and
    /// returns its per-subscription sequence alongside the payload for wire
    /// framing. The event remains charged against the bounded backlog until
    /// [`Subscription::ack`] receives a contiguous acknowledgement.
    pub fn pop_with_sequence(&mut self) -> Option<(u64, UmpEvent)> {
        let (sequence, _journal_sequence, event) = self.queue.pop_front()?;
        Some(self.pop_queued(sequence, event))
    }

    /// Variant of [`Self::pop_with_sequence`] that also returns the global
    /// journal sequence for cursor construction.
    pub fn pop_with_sequence_and_journal(&mut self) -> Option<(u64, u64, UmpEvent)> {
        let (sequence, journal_sequence, event) = self.queue.pop_front()?;
        let payload_len = event.payload.len();
        self.queue_bytes = self.queue_bytes.saturating_sub(payload_len);
        self.in_flight_bytes = self.in_flight_bytes.saturating_add(payload_len);
        self.in_flight.push_back((sequence, payload_len));
        Some((sequence, journal_sequence, event))
    }

    fn pop_queued(&mut self, sequence: u64, event: UmpEvent) -> (u64, UmpEvent) {
        self.queue_bytes = self.queue_bytes.saturating_sub(event.payload.len());
        self.in_flight_bytes = self.in_flight_bytes.saturating_add(event.payload.len());
        self.in_flight.push_back((sequence, event.payload.len()));
        (sequence, event)
    }

    pub fn ack(&mut self, highest_contiguous: u64) {
        while self
            .in_flight
            .front()
            .is_some_and(|(sequence, _)| *sequence <= highest_contiguous)
        {
            if let Some((_sequence, payload_len)) = self.in_flight.pop_front() {
                self.in_flight_bytes = self.in_flight_bytes.saturating_sub(payload_len);
            }
        }
        self.out_of_sync = false;
        self.out_of_sync_from = None;
        self.out_of_sync_to = None;
    }

    /// Takes the current missing sequence range so the transport can emit an
    /// explicit `EVENT_GAP` notification. The gap is considered reported;
    /// the client may still acknowledge it to clear any future range.
    pub fn take_event_gap(&mut self) -> Option<(u64, u64)> {
        let from = self.out_of_sync_from.take()?;
        let to = self.out_of_sync_to.take().unwrap_or(from);
        self.out_of_sync = false;
        Some((from, to))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventError {
    SampleDropped,
    OutOfSync,
}

#[derive(Debug, Default)]
pub struct EventBus {
    subscriptions: HashMap<u64, Subscription>,
    next_id: u64,
    history: VecDeque<(u64, UmpEvent)>,
    history_bytes: usize,
    next_event_sequence: u64,
}

impl EventBus {
    #[must_use]
    pub fn new() -> Self {
        Self {
            subscriptions: HashMap::new(),
            next_id: 1,
            history: VecDeque::new(),
            history_bytes: 0,
            next_event_sequence: 0,
        }
    }

    #[must_use]
    pub fn subscribe(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.subscriptions
            .insert(id, Subscription::new(id, DEFAULT_EVENT_BACKLOG));
        id
    }

    pub fn unsubscribe(&mut self, id: u64) {
        self.subscriptions.remove(&id);
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn publish(&mut self, event: UmpEvent) {
        self.next_event_sequence = self.next_event_sequence.saturating_add(1);
        let journal_sequence = self.next_event_sequence;
        self.history_bytes = self.history_bytes.saturating_add(event.payload.len());
        self.history.push_back((journal_sequence, event.clone()));
        while self.history.len() > DEFAULT_EVENT_BACKLOG
            || self.history_bytes > DEFAULT_EVENT_BACKLOG_BYTES
        {
            if let Some((_, old_event)) = self.history.pop_front() {
                self.history_bytes = self.history_bytes.saturating_sub(old_event.payload.len());
            } else {
                break;
            }
        }
        // push sets its own out_of_sync flag on failure (CRITICAL/STATE
        // drops); SAMPLE drops are silent by design. Collect the failed ids
        // for the daemon to close unrecoverable streams (control-api.md §39).
        let _failed: Vec<u64> = self
            .subscriptions
            .iter_mut()
            .filter_map(|(_, sub)| {
                sub.push_with_journal_sequence(event.clone(), journal_sequence)
                    .err()
                    .map(|_| sub.id)
            })
            .collect();
    }

    #[must_use]
    pub const fn latest_event_sequence(&self) -> u64 {
        self.next_event_sequence
    }

    /// Returns live journal entries after `after_sequence`. A cursor older
    /// than the bounded history is explicitly rejected so callers can take a
    /// fresh snapshot instead of silently receiving an incomplete stream.
    ///
    /// # Errors
    ///
    /// Returns [`EventHistoryError::OutOfRange`] when the cursor points past
    /// the live journal or before its retained oldest entry.
    pub fn history_after(
        &self,
        after_sequence: u64,
    ) -> Result<Vec<(u64, UmpEvent)>, EventHistoryError> {
        if after_sequence > self.next_event_sequence {
            return Err(EventHistoryError::OutOfRange);
        }
        if self.history.is_empty() && after_sequence < self.next_event_sequence {
            return Err(EventHistoryError::OutOfRange);
        }
        if let Some((oldest, _)) = self.history.front() {
            if after_sequence.saturating_add(1) < *oldest {
                return Err(EventHistoryError::OutOfRange);
            }
        }
        Ok(self
            .history
            .iter()
            .filter(|(sequence, _)| *sequence > after_sequence)
            .cloned()
            .collect())
    }

    pub fn subscription(&mut self, id: u64) -> Option<&mut Subscription> {
        self.subscriptions.get_mut(&id)
    }

    #[must_use]
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventHistoryError {
    OutOfRange,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::umc::api::v1 as api;

    fn event(class: EventClass, payload_len: usize) -> UmpEvent {
        UmpEvent {
            class,
            event_type: "test".into(),
            resource: None,
            payload: vec![0u8; payload_len],
            occurred_at_ms: 0,
        }
    }

    #[test]
    fn sequences_increment_per_subscription() {
        let mut bus = EventBus::new();
        let id = bus.subscribe();
        bus.publish(event(EventClass::Edge, 8));
        bus.publish(event(EventClass::Edge, 8));
        let sub = bus.subscription(id).unwrap();
        assert_eq!(sub.next_sequence, 3);
        assert_eq!(sub.pop().unwrap().class, EventClass::Edge);
        assert_eq!(sub.pop().unwrap().class, EventClass::Edge);
        assert!(sub.pop().is_none());
    }

    #[test]
    fn critical_events_never_silently_dropped() {
        let mut bus = EventBus::new();
        let id = bus.subscribe();
        // Fill the backlog with small state events.
        for _ in 0..DEFAULT_EVENT_BACKLOG {
            bus.publish(event(EventClass::State, 1));
        }
        bus.publish(event(EventClass::Critical, 1));
        let sub = bus.subscription(id).unwrap();
        assert!(sub.out_of_sync, "CRITICAL drop must mark out of sync");
    }

    #[test]
    fn sample_events_may_drop() {
        let mut bus = EventBus::new();
        let id = bus.subscribe();
        for _ in 0..DEFAULT_EVENT_BACKLOG {
            bus.publish(event(EventClass::State, 1));
        }
        // SAMPLE drops without marking out of sync.
        bus.publish(event(EventClass::Sample, 1));
        let sub = bus.subscription(id).unwrap();
        assert!(!sub.out_of_sync);
    }

    #[test]
    fn ack_recovers_out_of_sync() {
        let mut bus = EventBus::new();
        let id = bus.subscribe();
        for _ in 0..DEFAULT_EVENT_BACKLOG {
            bus.publish(event(EventClass::State, 1));
        }
        bus.publish(event(EventClass::Critical, 1));
        let sub = bus.subscription(id).unwrap();
        assert!(sub.out_of_sync);
        sub.ack(1);
        assert!(!sub.out_of_sync);
    }

    #[test]
    fn critical_drop_exposes_missing_sequence_range() {
        let mut bus = EventBus::new();
        let id = bus.subscribe();
        for _ in 0..DEFAULT_EVENT_BACKLOG {
            bus.publish(event(EventClass::State, 1));
        }
        bus.publish(event(EventClass::Critical, 1));
        let sub = bus.subscription(id).unwrap();
        assert_eq!(sub.take_event_gap(), Some((1025, 1025)));
        assert!(!sub.out_of_sync);
    }

    #[test]
    fn journal_rejects_cursor_before_retained_history() {
        let mut bus = EventBus::new();
        for _ in 0..=DEFAULT_EVENT_BACKLOG {
            bus.publish(event(EventClass::State, 1));
        }
        assert!(matches!(
            bus.history_after(0),
            Err(EventHistoryError::OutOfRange)
        ));
        assert_eq!(
            bus.history_after(1).expect("retained history").len(),
            DEFAULT_EVENT_BACKLOG
        );
    }

    #[test]
    fn unacknowledged_delivery_consumes_backlog_until_acknowledged() {
        let mut sub = Subscription::new(7, 1);
        sub.push(event(EventClass::State, 4)).expect("first event");
        assert!(sub.pop_with_sequence().is_some());

        assert_eq!(
            sub.push(event(EventClass::State, 4)),
            Err(EventError::OutOfSync),
            "delivered but unacknowledged events still consume the bounded backlog"
        );
        sub.ack(1);
        sub.push(event(EventClass::State, 4))
            .expect("ack releases the retained event");
    }

    #[test]
    fn resume_cursor_is_authenticated_and_bound_to_subscription_context() {
        let key = [7u8; 32];
        let generation = [9u8; 16];
        let filter = api::EventFilter {
            include_initial_snapshot: true,
            ..Default::default()
        };
        let digest = event_filter_digest(&filter);
        let encoded = EventResumeCursor::encode(42, generation, digest, 17, 1_000, &key);
        let cursor = EventResumeCursor::decode(&encoded, &key).expect("valid cursor");
        assert_eq!(cursor.sequence(), 17);
        assert!(cursor.validate(42, generation, digest, 999));
        assert!(!cursor.validate(43, generation, digest, 999));
        assert!(!cursor.validate(42, [8u8; 16], digest, 999));
        assert!(!cursor.validate(42, generation, [0u8; 16], 999));
        assert!(!cursor.validate(42, generation, digest, 1_001));

        let mut tampered = encoded;
        tampered[40] ^= 1;
        assert!(EventResumeCursor::decode(&tampered, &key).is_none());
    }
}
