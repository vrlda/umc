//! Carrier-backed data transport for the embedded SDK backend.
//!
//! The embedded backend is synchronous at its request boundary, so this
//! adapter deliberately uses the synchronous `Carrier`/`Link` contract. It
//! keeps accepted application frames bounded until `recv()` returns them, or
//! until the link emits a terminal event. Only the latter case is reported as
//! delivery loss; queue rejection remains caller-owned backpressure.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use umc_carrier::error::{CarrierError, CarrierErrorKind};
use umc_carrier::types::{
    CarrierCapabilities, CarrierTypeId, ConnectionModel, InboundPacket, LinkEvent, LinkProperties,
    Ordering, OutboundPacket, PacketMode, QueueState, Reliability, SendResult,
};
use umc_carrier::{BoxLink, Carrier, Link, Listener};
use umc_types::runtime::Instant;

pub(crate) const STREAM_FRAME: u8 = 1;
pub(crate) const DATAGRAM_FRAME: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EmbeddedFrame {
    Stream {
        stream_id: u64,
        fin: bool,
        data: Vec<u8>,
    },
    Datagram {
        context_id: u64,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingDelivery {
    Stream { stream_id: u64, offset: u64 },
    Datagram { context_id: u64 },
}

#[derive(Debug, Default)]
pub(crate) struct TransportPoll {
    pub(crate) inbound: Vec<EmbeddedFrame>,
    pub(crate) lost: Vec<PendingDelivery>,
    /// Link state transitions observed while servicing this operation.  The
    /// embedded backend translates these into the same typed path vocabulary
    /// as the daemon instead of silently discarding carrier state changes.
    pub(crate) events: Vec<LinkEvent>,
    pub(crate) terminal: bool,
}

#[derive(Debug)]
pub(crate) enum TransportError {
    Carrier(CarrierError),
    MalformedFrame,
}

impl TransportError {
    pub(crate) fn status(&self) -> umc_control::proto::umc::api::v1::StatusCode {
        use umc_control::proto::umc::api::v1::StatusCode;
        match self {
            Self::MalformedFrame => StatusCode::DataLoss,
            Self::Carrier(error) => match error.kind {
                CarrierErrorKind::InvalidArgument | CarrierErrorKind::AddressInvalid => {
                    StatusCode::InvalidArgument
                }
                CarrierErrorKind::PermissionDenied | CarrierErrorKind::PolicyDenied => {
                    StatusCode::PermissionDenied
                }
                CarrierErrorKind::QueueFull | CarrierErrorKind::PacketTooLarge => {
                    StatusCode::ResourceExhausted
                }
                CarrierErrorKind::WouldBlock | CarrierErrorKind::NotRunning => {
                    StatusCode::Unavailable
                }
                CarrierErrorKind::LinkClosed
                | CarrierErrorKind::LinkFailed
                | CarrierErrorKind::Unreachable => StatusCode::Unavailable,
                _ => StatusCode::Internal,
            },
        }
    }
}

pub(crate) struct EmbeddedTransport {
    links: HashMap<u64, BoxLink>,
    active_path: u64,
    pending: VecDeque<PendingDelivery>,
    terminal: bool,
}

impl fmt::Debug for EmbeddedTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddedTransport")
            .field("paths", &self.links.len())
            .field("active_path", &self.active_path)
            .field("pending", &self.pending.len())
            .field("terminal", &self.terminal)
            .finish()
    }
}

impl EmbeddedTransport {
    pub(crate) fn properties(&self) -> LinkProperties {
        self.links
            .get(&self.active_path)
            .expect("active embedded path")
            .properties()
    }

    pub(crate) fn path_count(&self) -> usize {
        self.links.len()
    }

    pub(crate) fn dial(carrier: &dyn Carrier, remote: String) -> Result<Self, TransportError> {
        let link = carrier.dial(remote).map_err(TransportError::Carrier)?;
        let mut links = HashMap::new();
        links.insert(0, link);
        Ok(Self {
            links,
            active_path: 0,
            pending: VecDeque::new(),
            terminal: false,
        })
    }

    pub(crate) fn migrate(
        &mut self,
        carrier: &dyn Carrier,
        remote: String,
        keep_old_path: bool,
    ) -> Result<u64, TransportError> {
        if self.terminal {
            return Err(TransportError::Carrier(CarrierError::new(
                CarrierErrorKind::LinkClosed,
                "migrate",
            )));
        }
        let link = carrier.dial(remote).map_err(TransportError::Carrier)?;
        let path_id = self
            .links
            .keys()
            .copied()
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        self.links.insert(path_id, link);
        let old_path = self.active_path;
        self.active_path = path_id;
        if !keep_old_path {
            if let Some(old) = self.links.remove(&old_path) {
                let _ = old.close("embedded path migrated");
            }
        }
        Ok(path_id)
    }

    pub(crate) fn send(
        &mut self,
        frame: Vec<u8>,
        pending: PendingDelivery,
    ) -> Result<TransportPoll, TransportError> {
        if self.terminal {
            return Err(TransportError::Carrier(CarrierError::new(
                CarrierErrorKind::LinkClosed,
                "send",
            )));
        }
        match self
            .links
            .get(&self.active_path)
            .expect("active embedded path")
            .send(OutboundPacket {
                bytes: frame,
                control: false,
                deadline_ms: None,
            })
            .map_err(TransportError::Carrier)?
        {
            SendResult::Accepted { .. } => self.pending.push_back(pending),
            SendResult::WouldBlock => {
                return Err(TransportError::Carrier(CarrierError::new(
                    CarrierErrorKind::WouldBlock,
                    "send",
                )))
            }
            SendResult::QueueFull => {
                return Err(TransportError::Carrier(CarrierError::new(
                    CarrierErrorKind::QueueFull,
                    "send",
                )))
            }
        }
        self.poll()
    }

    pub(crate) fn poll(&mut self) -> Result<TransportPoll, TransportError> {
        if self.terminal {
            return Ok(TransportPoll {
                terminal: true,
                ..Default::default()
            });
        }
        let mut poll = TransportPoll::default();
        let mut terminal = false;
        for link in self.links.values() {
            loop {
                match link.recv() {
                    Ok(packet) => {
                        let frame = decode_frame(&packet.bytes)
                            .map_err(|()| TransportError::MalformedFrame)?;
                        let pending = match &frame {
                        EmbeddedFrame::Stream { stream_id, .. } => self
                            .pending
                            .iter()
                            .position(|item| matches!(item, PendingDelivery::Stream { stream_id: id, .. } if id == stream_id)),
                        EmbeddedFrame::Datagram { context_id, .. } => self
                            .pending
                            .iter()
                            .position(|item| matches!(item, PendingDelivery::Datagram { context_id: id } if id == context_id)),
                    };
                        if let Some(index) = pending {
                            self.pending.remove(index);
                        }
                        poll.inbound.push(frame);
                    }
                    Err(error) if error.kind == CarrierErrorKind::WouldBlock => break,
                    Err(error)
                        if matches!(
                            error.kind,
                            CarrierErrorKind::LinkClosed | CarrierErrorKind::LinkFailed
                        ) =>
                    {
                        terminal = true;
                        break;
                    }
                    Err(error) => return Err(TransportError::Carrier(error)),
                }
            }
        }
        for link in self.links.values() {
            loop {
                match link.events() {
                    Ok(LinkEvent::Closed | LinkEvent::Failed) => {
                        terminal = true;
                        break;
                    }
                    Ok(event) => poll.events.push(event),
                    Err(error) if error.kind == CarrierErrorKind::WouldBlock => break,
                    Err(error)
                        if matches!(
                            error.kind,
                            CarrierErrorKind::LinkClosed | CarrierErrorKind::LinkFailed
                        ) =>
                    {
                        terminal = true;
                        break;
                    }
                    Err(error) => return Err(TransportError::Carrier(error)),
                }
            }
        }
        if terminal {
            self.mark_terminal(&mut poll);
        }
        Ok(poll)
    }

    pub(crate) fn close(&mut self, reason: &str) -> Result<(), TransportError> {
        if self.terminal {
            return Err(TransportError::Carrier(CarrierError::new(
                CarrierErrorKind::LinkClosed,
                "close",
            )));
        }
        for link in self.links.values() {
            link.close(reason).map_err(TransportError::Carrier)?;
        }
        self.links.clear();
        self.terminal = true;
        self.pending.clear();
        Ok(())
    }

    fn mark_terminal(&mut self, poll: &mut TransportPoll) {
        self.terminal = true;
        poll.terminal = true;
        poll.lost.extend(self.pending.drain(..));
    }
}

pub(crate) fn encode_stream_frame(stream_id: u64, fin: bool, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + data.len());
    frame.push(STREAM_FRAME);
    frame.push(u8::from(fin));
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(&(u32::try_from(data.len()).unwrap_or(u32::MAX)).to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

pub(crate) fn encode_datagram_frame(context_id: u64, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(13 + data.len());
    frame.push(DATAGRAM_FRAME);
    frame.extend_from_slice(&context_id.to_be_bytes());
    frame.extend_from_slice(&(u32::try_from(data.len()).unwrap_or(u32::MAX)).to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

fn decode_frame(frame: &[u8]) -> Result<EmbeddedFrame, ()> {
    let (kind, header_len, fin) = match frame.first().copied() {
        Some(STREAM_FRAME) => (STREAM_FRAME, 14, frame.get(1).copied().ok_or(())? != 0),
        Some(DATAGRAM_FRAME) => (DATAGRAM_FRAME, 13, false),
        _ => return Err(()),
    };
    if frame.len() < header_len {
        return Err(());
    }
    let id_start = if kind == STREAM_FRAME { 2 } else { 1 };
    let id = u64::from_be_bytes(frame[id_start..id_start + 8].try_into().map_err(|_| ())?);
    let len_start = id_start + 8;
    let length = usize::try_from(u32::from_be_bytes(
        frame[len_start..len_start + 4].try_into().map_err(|_| ())?,
    ))
    .map_err(|_| ())?;
    let data = frame
        .get(header_len..)
        .filter(|data| data.len() == length)
        .ok_or(())?;
    if kind == STREAM_FRAME {
        Ok(EmbeddedFrame::Stream {
            stream_id: id,
            fin,
            data: data.to_vec(),
        })
    } else {
        Ok(EmbeddedFrame::Datagram {
            context_id: id,
            data: data.to_vec(),
        })
    }
}

/// Settings for the built-in bounded loopback carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopbackCarrierConfig {
    /// Maximum bytes accepted by one link before `QUEUE_FULL`.
    pub queue_capacity_bytes: usize,
    /// Number of accepted packets to discard before failing the link.
    /// This is intended for deterministic loss/recovery tests.
    pub drop_next_packets: usize,
}

impl Default for LoopbackCarrierConfig {
    fn default() -> Self {
        Self {
            queue_capacity_bytes: 2 * 1024 * 1024,
            drop_next_packets: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoopbackCarrier {
    config: LoopbackCarrierConfig,
}

impl LoopbackCarrier {
    #[must_use]
    pub fn new(config: LoopbackCarrierConfig) -> Self {
        Self {
            config: LoopbackCarrierConfig {
                queue_capacity_bytes: config.queue_capacity_bytes.max(1),
                ..config
            },
        }
    }
}

impl Default for LoopbackCarrier {
    fn default() -> Self {
        Self::new(LoopbackCarrierConfig::default())
    }
}

impl Carrier for LoopbackCarrier {
    fn type_id(&self) -> CarrierTypeId {
        CarrierTypeId("embedded-loopback".into())
    }

    fn capabilities(&self) -> CarrierCapabilities {
        CarrierCapabilities {
            api_version: 1,
            carrier_type: self.type_id(),
            packet_mode: PacketMode::Datagram,
            reliability: Reliability::ReliableUntilLinkFailure,
            ordering: Ordering::Ordered,
            connection_model: ConnectionModel::Connected,
            supports_listen: true,
            supports_dial: true,
            supports_discovery: false,
            minimum_packet_size: 1,
            maximum_packet_size: 256 * 1024,
            scope_classes: vec!["process".into()],
        }
    }

    fn listen(&self, _bind: String) -> Result<Box<dyn Listener + Send + Sync>, CarrierError> {
        Ok(Box::new(LoopbackListener {
            closed: Mutex::new(false),
        }))
    }

    fn dial(&self, _remote: String) -> Result<BoxLink, CarrierError> {
        Ok(Box::new(LoopbackLink {
            state: Mutex::new(LoopbackLinkState {
                queue: VecDeque::new(),
                queue_bytes: 0,
                capacity: self.config.queue_capacity_bytes,
                drop_next: self.config.drop_next_packets,
                events: VecDeque::from([LinkEvent::Active]),
                closed: false,
            }),
        }))
    }
}

struct LoopbackListener {
    closed: Mutex<bool>,
}

impl fmt::Debug for LoopbackListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("LoopbackListener").finish()
    }
}

impl Listener for LoopbackListener {
    fn accept(&self) -> Result<BoxLink, CarrierError> {
        if *self.closed.lock().map_err(|_| internal_error("accept"))? {
            return Err(CarrierError::new(CarrierErrorKind::LinkClosed, "accept"));
        }
        Err(CarrierError::new(CarrierErrorKind::WouldBlock, "accept"))
    }

    fn close(&self) -> Result<(), CarrierError> {
        *self.closed.lock().map_err(|_| internal_error("close"))? = true;
        Ok(())
    }
}

struct LoopbackLink {
    state: Mutex<LoopbackLinkState>,
}

impl fmt::Debug for LoopbackLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("LoopbackLink").finish()
    }
}

struct LoopbackLinkState {
    queue: VecDeque<InboundPacket>,
    queue_bytes: usize,
    capacity: usize,
    drop_next: usize,
    events: VecDeque<LinkEvent>,
    closed: bool,
}

impl Link for LoopbackLink {
    fn properties(&self) -> LinkProperties {
        let state = self.state.lock().expect("loopback link lock");
        LinkProperties {
            reliability: Reliability::ReliableUntilLinkFailure,
            ordering: Ordering::Ordered,
            current_mtu: 256 * 1024,
            queue_bytes: state.queue_bytes,
            queue_capacity: state.capacity,
            estimated_rtt_ms: Some(0),
            estimated_loss: None,
            metered: false,
        }
    }

    fn send(&self, packet: OutboundPacket) -> Result<SendResult, CarrierError> {
        let mut state = self.state.lock().map_err(|_| internal_error("send"))?;
        if state.closed {
            return Err(CarrierError::new(CarrierErrorKind::LinkClosed, "send"));
        }
        if packet.bytes.len() > 256 * 1024 {
            return Err(CarrierError::new(CarrierErrorKind::PacketTooLarge, "send"));
        }
        if state.drop_next > 0 {
            state.drop_next -= 1;
            state.events.push_back(LinkEvent::Failed);
            state.closed = true;
            return Ok(SendResult::Accepted {
                queue_state: QueueState::SentToMedium,
            });
        }
        if state.queue_bytes.saturating_add(packet.bytes.len()) > state.capacity {
            return Ok(SendResult::QueueFull);
        }
        state.queue_bytes += packet.bytes.len();
        state.queue.push_back(InboundPacket {
            bytes: packet.bytes,
            received_at: Instant(now_millis()),
        });
        Ok(SendResult::Accepted {
            queue_state: QueueState::QueuedBounded,
        })
    }

    fn recv(&self) -> Result<InboundPacket, CarrierError> {
        let mut state = self.state.lock().map_err(|_| internal_error("recv"))?;
        if let Some(packet) = state.queue.pop_front() {
            state.queue_bytes = state.queue_bytes.saturating_sub(packet.bytes.len());
            return Ok(packet);
        }
        if state.closed {
            return Err(CarrierError::new(CarrierErrorKind::LinkClosed, "recv"));
        }
        Err(CarrierError::new(CarrierErrorKind::WouldBlock, "recv"))
    }

    fn events(&self) -> Result<LinkEvent, CarrierError> {
        let mut state = self.state.lock().map_err(|_| internal_error("events"))?;
        state
            .events
            .pop_front()
            .ok_or_else(|| CarrierError::new(CarrierErrorKind::WouldBlock, "events"))
    }

    fn close(&self, _reason: &str) -> Result<(), CarrierError> {
        let mut state = self.state.lock().map_err(|_| internal_error("close"))?;
        if !state.closed {
            state.closed = true;
            state.events.push_back(LinkEvent::Closed);
        }
        Ok(())
    }
}

fn internal_error(operation: &'static str) -> CarrierError {
    CarrierError::new(CarrierErrorKind::Internal, operation)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_link_is_bounded_and_round_trips_frames() {
        let carrier = LoopbackCarrier::default();
        let mut transport =
            EmbeddedTransport::dial(&carrier, "embedded://test".into()).expect("dial loopback");
        let poll = transport
            .send(
                encode_stream_frame(7, true, b"hello"),
                PendingDelivery::Stream {
                    stream_id: 7,
                    offset: 5,
                },
            )
            .expect("send");
        assert_eq!(poll.lost, Vec::<PendingDelivery>::new());
        assert_eq!(poll.inbound.len(), 1);
        assert_eq!(
            poll.inbound[0],
            EmbeddedFrame::Stream {
                stream_id: 7,
                fin: true,
                data: b"hello".to_vec(),
            }
        );
    }

    #[test]
    fn accepted_packet_becomes_lost_only_on_terminal_link_failure() {
        let carrier = LoopbackCarrier::new(LoopbackCarrierConfig {
            drop_next_packets: 1,
            ..Default::default()
        });
        let mut transport =
            EmbeddedTransport::dial(&carrier, "embedded://test".into()).expect("dial loopback");
        let poll = transport
            .send(
                encode_stream_frame(3, false, b"lost"),
                PendingDelivery::Stream {
                    stream_id: 3,
                    offset: 4,
                },
            )
            .expect("accepted by link");
        assert!(poll.inbound.is_empty());
        assert_eq!(
            poll.lost,
            vec![PendingDelivery::Stream {
                stream_id: 3,
                offset: 4
            }]
        );
        assert!(poll.terminal);
    }

    #[test]
    fn queue_full_does_not_transfer_pending_ownership() {
        let carrier = LoopbackCarrier::new(LoopbackCarrierConfig {
            queue_capacity_bytes: 1,
            ..Default::default()
        });
        let mut transport =
            EmbeddedTransport::dial(&carrier, "embedded://test".into()).expect("dial loopback");
        let error = transport
            .send(
                encode_stream_frame(1, false, b"too large"),
                PendingDelivery::Stream {
                    stream_id: 1,
                    offset: 9,
                },
            )
            .expect_err("bounded queue");
        assert!(
            matches!(error, TransportError::Carrier(error) if error.kind == CarrierErrorKind::QueueFull)
        );
    }
}
