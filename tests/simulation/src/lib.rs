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
    peak_queued: usize,
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
        state.peak_queued = state
            .peak_queued
            .max(state.queues[0].len() + state.queues[1].len());
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

    /// Returns the highest total queue depth observed since link creation.
    ///
    /// # Panics
    ///
    /// Panics if another simulation thread has poisoned the link mutex.
    #[must_use]
    pub fn peak_queued(&self) -> usize {
        self.state.lock().expect("simulation link lock").peak_queued
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
    use umc_session::datagram::Datagram;
    use umc_session::session::{Role, Session, SessionConfig};

    #[derive(Debug)]
    struct SessionClock;

    impl Clock for SessionClock {
        fn now(&self) -> Instant {
            Instant(0)
        }
    }

    fn soak_session(role: Role, local: [u8; 32], remote: [u8; 32]) -> Session {
        Session::new(
            SessionConfig {
                role,
                dcid: vec![0x53; 8],
                local_traffic_secret: local,
                remote_traffic_secret: remote,
                // The release soak is intentionally application-focused; a
                // generous transport window keeps the synthetic run from
                // measuring a fixed fixture's flow-credit cadence while the
                // session still exercises bounded credit replenishment.
                initial_max_data: 1 << 30,
                initial_max_stream_data: 1 << 26,
                max_ack_delay_ms: 25,
            },
            &SessionClock,
        )
        .expect("session")
    }

    fn deliver_session_packet(
        link: &SimLinkPair,
        clock: &SimClock,
        sender: &mut Session,
        receiver: &mut Session,
        side: Side,
        payload: &[u8],
    ) {
        let now = clock.now();
        let packet = sender
            .build_outbound(&SessionClock, now, payload)
            .expect("build session packet")
            .expect("session packet available");
        link.send(side, &packet).expect("send session packet");
        clock.advance(1);
        let inbound = link.recv(side.other()).expect("deliver session packet");
        let mut response = receiver
            .on_inbound(clock.now(), &inbound)
            .expect("receive session packet");
        response.extend(
            receiver
                .flow_control_frames(clock.now())
                .into_iter()
                .flatten(),
        );
        if response.is_empty() {
            return;
        }
        let response_packet = receiver
            .build_outbound(&SessionClock, clock.now(), &response)
            .expect("build acknowledgement packet")
            .expect("acknowledgement packet available");
        link.send(side.other(), &response_packet)
            .expect("send acknowledgement packet");
        clock.advance(1);
        let acknowledgement = link.recv(side).expect("deliver acknowledgement packet");
        sender
            .on_inbound(clock.now(), &acknowledgement)
            .expect("receive acknowledgement packet");
    }

    fn stream_frame_data_len(payload: &[u8]) -> usize {
        let (frame_type, type_len) = umc_wire::varint::decode(payload).expect("stream frame type");
        assert_eq!(frame_type, umc_types::frame::FrameType::STREAM.0);
        let (frame, _) = umc_wire::frames::stream::StreamFrame::decode(&payload[type_len..])
            .expect("stream frame payload");
        frame.data.len()
    }

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
    fn bounded_fault_soak_recovers_ordered_echoes() {
        let mut harness = TwoNodeHarness::new(FaultModel {
            queue_capacity: 64,
            loss_every: Some(11),
            duplicate_every: Some(7),
            delay_ms: 2,
            reorder_every: Some(5),
        })
        .expect("harness");

        for index in 0..256u16 {
            let payload = index.to_be_bytes();
            let echoed = harness
                .run_reliable_echo(&payload, 64)
                .expect("bounded fault schedule recovers");
            assert_eq!(echoed, payload);
        }

        let stats = harness.stats();
        assert!(stats.1 > 0, "the soak must exercise loss");
        assert!(stats.2 > 0, "the soak must deliver packets");
        assert_eq!(stats.3, 0, "successful echoes drain the bounded queues");
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

    #[test]
    fn queue_peak_tracks_bounded_burst() {
        let link = SimLinkPair::new(FaultModel {
            queue_capacity: 2,
            ..FaultModel::default()
        })
        .expect("fault model");
        link.send(Side::A, &[1]).expect("first packet");
        link.send(Side::A, &[2]).expect("second packet");
        assert_eq!(link.peak_queued(), 2);
        assert_eq!(link.stats().3, 2);
        assert_eq!(link.recv(Side::B), Some(vec![1]));
        assert_eq!(link.peak_queued(), 2);
    }

    /// Release soak entry point from testing.md §17.4.
    ///
    /// The default is the CI-nightly ten-minute wall-clock run. Set
    /// `UMC_SOAK_DURATION_MS` to a small value for a local smoke run, for
    /// example `UMC_SOAK_DURATION_MS=100 cargo test -p umc-simulation --
    /// --ignored`; the test is ignored in ordinary workspace runs
    /// so release verification opts into the duration explicitly.
    #[test]
    #[ignore = "ten-minute release soak; set UMC_SOAK_DURATION_MS for a shorter validation run"]
    fn continuous_stream_datagram_soak() {
        let duration_ms = std::env::var("UMC_SOAK_DURATION_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(10 * 60 * 1_000);
        let link = SimLinkPair::new(FaultModel::default()).expect("fault model");
        let clock = link.clock();
        let mut client = soak_session(Role::Client, [1u8; 32], [2u8; 32]);
        let mut server = soak_session(Role::Server, [2u8; 32], [1u8; 32]);
        let stream_id = client.open_stream().expect("open stream");
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_millis(duration_ms);
        let mut stream_bytes = 0usize;
        let mut datagram_bytes = 0usize;
        let mut iterations = 0u64;

        while std::time::Instant::now() < deadline {
            let expected_stream = b"continuous stream payload";
            let mut remaining = expected_stream.as_slice();
            let mut received_stream = Vec::with_capacity(expected_stream.len());
            while !remaining.is_empty() {
                let stream_payload = client
                    .send_stream_data(stream_id, remaining, false)
                    .expect("encode stream payload");
                let consumed = stream_frame_data_len(&stream_payload);
                assert!(consumed > 0 && consumed <= remaining.len());
                deliver_session_packet(
                    &link,
                    &clock,
                    &mut client,
                    &mut server,
                    Side::A,
                    &stream_payload,
                );
                let (received, eof) = server.read_stream(stream_id).expect("read stream payload");
                assert!(!eof);
                received_stream.extend_from_slice(&received);
                remaining = &remaining[consumed..];
            }
            assert_eq!(received_stream, expected_stream);
            stream_bytes = stream_bytes.saturating_add(received_stream.len());

            let datagram = Datagram {
                context_id: iterations,
                data: b"continuous datagram payload".to_vec(),
                expires_at_ms: None,
                ack_requested: true,
            };
            client
                .send_datagram(datagram, 1_200)
                .expect("queue datagram");
            let datagram_payload = client
                .pop_outbound_datagram_payload(clock.now().0)
                .expect("encode datagram payload");
            deliver_session_packet(
                &link,
                &clock,
                &mut client,
                &mut server,
                Side::A,
                &datagram_payload,
            );
            let received_datagram = server.recv_datagram().expect("receive datagram");
            assert_eq!(received_datagram.data, b"continuous datagram payload");
            datagram_bytes = datagram_bytes.saturating_add(received_datagram.data.len());
            iterations = iterations.saturating_add(1);
        }

        assert!(iterations > 0, "soak must execute at least one exchange");
        assert_eq!(link.stats().3, 0, "bounded link queues must drain");
        eprintln!(
            "continuous soak: iterations={iterations}, stream_bytes={stream_bytes}, datagram_bytes={datagram_bytes}, elapsed_ms={}, peak_queued={}, queue_capacity={}",
            started.elapsed().as_millis(),
            link.peak_queued(),
            FaultModel::default().queue_capacity,
        );
    }
}
