//! Event subscriptions (control-api.md §38-41): bounded queues, sequence
//! tracking, CRITICAL events never silently dropped.
use std::collections::{HashMap, VecDeque};

pub const DEFAULT_EVENT_BACKLOG: usize = 1_024;
pub const DEFAULT_EVENT_BACKLOG_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EVENT_STREAMS_PER_CLIENT: usize = 8;

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
    pub queue: VecDeque<(u64, UmpEvent)>,
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
        self.queue.push_back((sequence, event));
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
        let (sequence, event) = self.queue.pop_front()?;
        self.queue_bytes = self.queue_bytes.saturating_sub(event.payload.len());
        self.in_flight_bytes = self.in_flight_bytes.saturating_add(event.payload.len());
        self.in_flight.push_back((sequence, event.payload.len()));
        Some((sequence, event))
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
}

impl EventBus {
    #[must_use]
    pub fn new() -> Self {
        Self {
            subscriptions: HashMap::new(),
            next_id: 1,
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
        // push sets its own out_of_sync flag on failure (CRITICAL/STATE
        // drops); SAMPLE drops are silent by design. Collect the failed ids
        // for the daemon to close unrecoverable streams (control-api.md §39).
        let _failed: Vec<u64> = self
            .subscriptions
            .iter_mut()
            .filter_map(|(_, sub)| sub.push(event.clone()).err().map(|_| sub.id))
            .collect();
    }

    pub fn subscription(&mut self, id: u64) -> Option<&mut Subscription> {
        self.subscriptions.get_mut(&id)
    }

    #[must_use]
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
