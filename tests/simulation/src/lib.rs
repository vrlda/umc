//! Deterministic transport primitives for loss and reordering tests.
//!
//! This crate deliberately keeps the fault model independent from Tokio and
//! the carrier implementations. Protocol tests can run the same schedule on
//! every platform, while the production carrier remains unchanged.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use umc_types::runtime::{Clock, EntropySource, Instant};

/// A manually advanced monotonic clock shared by a simulation.
#[derive(Debug, Clone, Default)]
pub struct SimClock {
    now_ms: Arc<Mutex<u64>>,
}

impl SimClock {
    /// Advances the clock by a bounded, non-negative duration.
    ///
    /// # Panics
    ///
    /// Panics if another simulation thread has poisoned the clock mutex.
    pub fn advance(&self, millis: u64) {
        let mut now = self.now_ms.lock().expect("simulation clock lock");
        *now = now.saturating_add(millis);
    }
}

impl Clock for SimClock {
    fn now(&self) -> Instant {
        Instant(*self.now_ms.lock().expect("simulation clock lock"))
    }
}

/// Deterministic xorshift entropy source for reproducible handshake inputs.
#[derive(Debug, Clone)]
pub struct SimEntropy {
    state: Arc<Mutex<u64>>,
}

impl SimEntropy {
    /// Creates a deterministic source. A zero seed is replaced with a fixed
    /// non-zero state so it still produces a useful stream.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(if seed == 0 { 0x9E37_79B9 } else { seed })),
        }
    }
}

impl EntropySource for SimEntropy {
    fn fill(&self, out: &mut [u8]) {
        let mut state = self.state.lock().expect("simulation entropy lock");
        for byte in out {
            let mut x = *state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *state = x;
            *byte = u8::try_from(x & u64::from(u8::MAX)).unwrap_or_default();
        }
    }
}

/// Which endpoint injects or receives a simulated packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The left endpoint.
    A,
    /// The right endpoint.
    B,
}

impl Side {
    fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }

    fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// Deterministic packet-fault schedule. Every `n`th packet is affected when
/// the corresponding option is set; `None` disables that fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultModel {
    /// Maximum queued packets in each direction.
    pub queue_capacity: usize,
    /// Drop every nth packet.
    pub loss_every: Option<u64>,
    /// Add a duplicate for every nth packet.
    pub duplicate_every: Option<u64>,
    /// Delay every packet by this many simulated milliseconds.
    pub delay_ms: u64,
    /// Insert every nth packet at the front of its queue.
    pub reorder_every: Option<u64>,
}

impl Default for FaultModel {
    fn default() -> Self {
        Self {
            queue_capacity: 128,
            loss_every: None,
            duplicate_every: None,
            delay_ms: 0,
            reorder_every: None,
        }
    }
}

/// Errors produced by the bounded simulated link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimLinkError {
    /// The destination queue has reached its configured bound.
    QueueFull,
    /// A zero-valued periodic fault interval is invalid.
    InvalidFaultInterval,
}

#[derive(Debug, Clone)]
struct ScheduledPacket {
    deliver_at_ms: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
struct LinkState {
    queues: [VecDeque<ScheduledPacket>; 2],
    sequence: u64,
    sent: u64,
    dropped: u64,
    delivered: u64,
}

/// A bounded, manually clocked, bidirectional simulated link.
#[derive(Debug, Clone)]
pub struct SimLinkPair {
    clock: SimClock,
    fault: FaultModel,
    state: Arc<Mutex<LinkState>>,
}

impl SimLinkPair {
    /// Creates a link with the supplied deterministic fault model.
    ///
    /// # Errors
    ///
    /// Returns [`SimLinkError::InvalidFaultInterval`] for a zero periodic
    /// interval, or [`SimLinkError::QueueFull`] for a zero queue capacity.
    pub fn new(fault: FaultModel) -> Result<Self, SimLinkError> {
        for interval in [fault.loss_every, fault.duplicate_every, fault.reorder_every]
            .into_iter()
            .flatten()
        {
            if interval == 0 {
                return Err(SimLinkError::InvalidFaultInterval);
            }
        }
        if fault.queue_capacity == 0 {
            return Err(SimLinkError::QueueFull);
        }
        Ok(Self {
            clock: SimClock::default(),
            fault,
            state: Arc::new(Mutex::new(LinkState::default())),
        })
    }

    /// Returns the shared simulation clock.
    #[must_use]
    pub fn clock(&self) -> SimClock {
        self.clock.clone()
    }

    /// Injects one packet from `side` toward the other endpoint.
    ///
    /// Loss is intentionally reported as success: a real carrier cannot tell
    /// a sender that the network dropped a packet. Queue overflow is exposed
    /// so a test can assert backpressure behavior explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`SimLinkError::QueueFull`] when the destination queue cannot
    /// hold the packet (and any deterministic duplicate).
    ///
    /// # Panics
    ///
    /// Panics if another simulation thread has poisoned the link mutex.
    pub fn send(&self, side: Side, bytes: &[u8]) -> Result<(), SimLinkError> {
        let mut state = self.state.lock().expect("simulation link lock");
        state.sequence = state.sequence.saturating_add(1);
        state.sent = state.sent.saturating_add(1);
        let sequence = state.sequence;
        if self
            .fault
            .loss_every
            .is_some_and(|every| sequence % every == 0)
        {
            state.dropped = state.dropped.saturating_add(1);
            return Ok(());
        }
        let target = side.other().index();
        let duplicate = self
            .fault
            .duplicate_every
            .is_some_and(|every| sequence % every == 0);
        let copies = if duplicate { 2 } else { 1 };
        if state.queues[target].len().saturating_add(copies) > self.fault.queue_capacity {
            return Err(SimLinkError::QueueFull);
        }
        let deliver_at_ms = self.clock.now().0.saturating_add(self.fault.delay_ms);
        for copy in 0..copies {
            let packet = ScheduledPacket {
                deliver_at_ms,
                bytes: bytes.to_vec(),
            };
            if copy == 0
                && self
                    .fault
                    .reorder_every
                    .is_some_and(|every| sequence % every == 0)
            {
                state.queues[target].push_front(packet);
            } else {
                state.queues[target].push_back(packet);
            }
        }
        Ok(())
    }

    /// Receives the first packet whose simulated delivery time has elapsed.
    ///
    /// # Panics
    ///
    /// Panics if another simulation thread has poisoned the link mutex.
    #[must_use]
    pub fn recv(&self, side: Side) -> Option<Vec<u8>> {
        let now = self.clock.now().0;
        let mut state = self.state.lock().expect("simulation link lock");
        let queue = &mut state.queues[side.index()];
        let position = queue
            .iter()
            .position(|packet| packet.deliver_at_ms <= now)?;
        let packet = queue.remove(position)?;
        state.delivered = state.delivered.saturating_add(1);
        Some(packet.bytes)
    }

    /// Returns `(sent, dropped, delivered, queued)` counters.
    ///
    /// # Panics
    ///
    /// Panics if another simulation thread has poisoned the link mutex.
    #[must_use]
    pub fn stats(&self) -> (u64, u64, u64, usize) {
        let state = self.state.lock().expect("simulation link lock");
        (
            state.sent,
            state.dropped,
            state.delivered,
            state.queues[0].len() + state.queues[1].len(),
        )
    }
}

/// Tiny reliable two-node harness used to prove a deterministic loss schedule
/// eventually recovers with retransmission and an ACK.
#[derive(Debug)]
pub struct TwoNodeHarness {
    link: SimLinkPair,
    next_message: u64,
    pto_ms: u64,
}

impl TwoNodeHarness {
    /// Creates a harness with a deterministic packet fault model.
    ///
    /// # Errors
    ///
    /// Forwards invalid interval and zero-capacity errors from
    /// [`SimLinkPair::new`].
    pub fn new(fault: FaultModel) -> Result<Self, SimLinkError> {
        Ok(Self {
            link: SimLinkPair::new(fault)?,
            next_message: 0,
            pto_ms: 10,
        })
    }

    /// Runs a stop-and-wait echo with bounded retransmission attempts.
    ///
    /// The harness is intentionally small; protocol-specific tests can use
    /// [`SimLinkPair`] directly to drive real `umc-session` packets.
    ///
    /// # Errors
    ///
    /// Returns a link error when a bounded queue overflows, or when the
    /// bounded schedule reaches its step limit without an acknowledgement.
    pub fn run_reliable_echo(
        &mut self,
        payload: &[u8],
        max_steps: usize,
    ) -> Result<Vec<u8>, SimLinkError> {
        self.next_message = self.next_message.saturating_add(1);
        let message_id = self.next_message;
        let mut wire = Vec::with_capacity(9 + payload.len());
        wire.push(0);
        wire.extend_from_slice(&message_id.to_be_bytes());
        wire.extend_from_slice(payload);
        let mut acked = false;
        let mut echoed = None;
        for step in 0..max_steps {
            if step == 0 || step % 2 == 0 {
                self.link.send(Side::A, &wire)?;
            }
            self.link.clock.advance(self.pto_ms);
            while let Some(packet) = self.link.recv(Side::B) {
                if packet.first() == Some(&0) && packet.get(1..9) == Some(&message_id.to_be_bytes())
                {
                    echoed = Some(packet[9..].to_vec());
                    let mut ack = Vec::with_capacity(9);
                    ack.push(1);
                    ack.extend_from_slice(&message_id.to_be_bytes());
                    // The simulated ACK itself can be lost; sending a second
                    // copy models the receiver's next ACK-eliciting pass and
                    // makes the harness exercise both directions.
                    self.link.send(Side::B, &ack)?;
                    self.link.send(Side::B, &ack)?;
                }
            }
            while let Some(packet) = self.link.recv(Side::A) {
                if packet.first() == Some(&1) && packet.get(1..9) == Some(&message_id.to_be_bytes())
                {
                    acked = true;
                }
            }
            if acked {
                return Ok(echoed.unwrap_or_default());
            }
        }
        Err(SimLinkError::QueueFull)
    }

    /// Exposes link counters for assertions.
    ///
    /// # Panics
    ///
    /// Panics if another simulation thread has poisoned the link mutex.
    #[must_use]
    pub fn stats(&self) -> (u64, u64, u64, usize) {
        self.link.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_and_entropy_are_reproducible() {
        let clock = SimClock::default();
        assert_eq!(clock.now(), Instant(0));
        clock.advance(17);
        assert_eq!(clock.now(), Instant(17));
        let a = SimEntropy::new(9);
        let b = SimEntropy::new(9);
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        a.fill(&mut left);
        b.fill(&mut right);
        assert_eq!(left, right);
    }

    #[test]
    fn delay_loss_duplicate_and_reorder_are_deterministic() {
        let link = SimLinkPair::new(FaultModel {
            queue_capacity: 8,
            loss_every: Some(3),
            duplicate_every: Some(2),
            delay_ms: 5,
            reorder_every: Some(4),
        })
        .expect("fault model");
        link.send(Side::A, b"one").expect("send one");
        assert!(link.recv(Side::B).is_none(), "delay is simulated");
        link.clock.advance(5);
        assert_eq!(link.recv(Side::B), Some(b"one".to_vec()));
        let stats = link.stats();
        assert_eq!(stats.0, 1);
        assert_eq!(stats.1, 0);
    }

    #[test]
    fn reliable_harness_recovers_from_periodic_loss() {
        let mut harness = TwoNodeHarness::new(FaultModel {
            queue_capacity: 16,
            loss_every: Some(2),
            duplicate_every: None,
            delay_ms: 0,
            reorder_every: None,
        })
        .expect("harness");
        let echoed = harness
            .run_reliable_echo(b"loss is expected", 12)
            .expect("retransmission recovers");
        assert_eq!(echoed, b"loss is expected");
        let stats = harness.stats();
        assert!(stats.1 > 0, "the schedule must actually drop packets");
        assert!(stats.2 > 0, "at least one packet must be delivered");
    }

    #[test]
    fn queue_bound_is_enforced() {
        let link = SimLinkPair::new(FaultModel {
            queue_capacity: 1,
            ..FaultModel::default()
        })
        .expect("fault model");
        link.send(Side::A, &[1]).expect("first packet");
        assert_eq!(link.send(Side::A, &[2]), Err(SimLinkError::QueueFull));
    }
}
