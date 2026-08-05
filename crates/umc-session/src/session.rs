use super::ack::{AckReceiveState, AckSendState};
use super::datagram::{Datagram, DatagramQueue};
use super::flow::FlowControl;
use super::loss::LossDetector;
use super::packet::build_protected_packet;
use super::rtt::RttEstimator;
use super::sent_packet::SentPacket;
use super::spaces::{PacketSpace, PacketSpaceState};
use super::stream::{Stream, StreamError};
use std::collections::HashMap;
use umc_crypto::aead::PacketKeys;
use umc_types::runtime::{Clock, Instant};
use umc_wire::header::ShortPacketSpace;
use umc_wire::packet::PacketContext;

pub const DEFAULT_DCID_LEN: usize = 8;
pub const INITIAL_STREAMS: u64 = 16;
pub const DEFAULT_INITIAL_MAX_DATA: u64 = 4 * 1024 * 1024;
pub const DEFAULT_INITIAL_MAX_STREAM_DATA: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Draining,
    Closed,
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub role: Role,
    pub dcid: Vec<u8>,
    pub local_traffic_secret: [u8; 32],
    pub remote_traffic_secret: [u8; 32],
    pub initial_max_data: u64,
    pub initial_max_stream_data: u64,
    pub max_ack_delay_ms: u64,
}

#[derive(Debug)]
pub struct Session {
    pub role: Role,
    pub state: SessionState,
    local_keys: PacketKeys,
    remote_keys: PacketKeys,
    spaces: HashMap<PacketSpace, PacketSpaceState>,
    sent: AckSendState,
    recv_acks: HashMap<PacketSpace, AckReceiveState>,
    rtt: RttEstimator,
    #[allow(dead_code)]
    loss: LossDetector,
    pub streams: HashMap<u64, Stream>,
    next_outgoing_stream: u64,
    flow: FlowControl,
    datagrams: DatagramQueue,
    dcid: Vec<u8>,
}

impl Session {
    /// Create a session with negotiated traffic secrets.
    ///
    /// The `clock` parameter is reserved for the runtime and is currently
    /// ignored; it is kept for API stability.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::BadConnectionId`] if `dcid` is not exactly
    /// [`DEFAULT_DCID_LEN`] bytes, and [`SessionError::BadKeys`] if a traffic
    /// secret cannot be expanded into packet keys.
    pub fn new(config: SessionConfig, clock: &dyn Clock) -> Result<Self, SessionError> {
        let _ = clock;
        if config.dcid.len() != DEFAULT_DCID_LEN {
            return Err(SessionError::BadConnectionId);
        }
        let mut spaces = HashMap::new();
        for s in [
            PacketSpace::SessionData,
            PacketSpace::PathControl,
            PacketSpace::RelayData,
        ] {
            spaces.insert(s, PacketSpaceState::new(s));
        }
        Ok(Self {
            role: config.role,
            state: SessionState::Active,
            local_keys: PacketKeys::from_traffic_secret(&config.local_traffic_secret)
                .map_err(|_| SessionError::BadKeys)?,
            remote_keys: PacketKeys::from_traffic_secret(&config.remote_traffic_secret)
                .map_err(|_| SessionError::BadKeys)?,
            spaces,
            sent: AckSendState::new(),
            recv_acks: HashMap::new(),
            rtt: RttEstimator::new(),
            loss: LossDetector::new(config.max_ack_delay_ms),
            streams: HashMap::new(),
            next_outgoing_stream: 0,
            flow: FlowControl::new(config.initial_max_data, INITIAL_STREAMS, INITIAL_STREAMS),
            datagrams: DatagramQueue::new(),
            dcid: config.dcid,
        })
    }

    pub fn open_stream(&mut self) -> u64 {
        let id = self.next_outgoing_stream;
        self.next_outgoing_stream += 2; // initiator bidirectional: low bits 00
        let max_data = self.flow.max_data_remote;
        self.streams
            .insert(id, Stream::new(id, Vec::new(), max_data));
        id
    }

    /// Build the payload for a STREAM frame carrying `data`.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::StreamNotFound`] if the stream does not exist,
    /// [`SessionError::Stream`] if the stream cannot accept the data, and
    /// [`SessionError::Encode`] if frame encoding fails.
    pub fn send_stream_data(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<Vec<u8>, SessionError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(SessionError::StreamNotFound)?;
        let (offset, chunk) = stream.send_ready(data).map_err(SessionError::Stream)?;
        let mut payload = Vec::new();
        let frame = umc_wire::frames::stream::StreamFrame {
            stream_id,
            fin,
            offset_present: offset != 0,
            len_present: true,
            open: offset == 0,
            unidirectional: false,
            offset,
            data: chunk,
            protocol_id: stream.protocol_id.clone(),
            metadata: Vec::new(),
        };
        umc_wire::varint::encode_into(&mut payload, umc_types::frame::FrameType::STREAM.0)
            .map_err(|_| SessionError::Encode)?;
        payload.extend_from_slice(&frame.encode().map_err(|_| SessionError::Encode)?[1..]);
        Ok(payload)
    }

    /// Queue an outbound datagram.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Datagram`] when the queue rejects the datagram.
    pub fn send_datagram(&mut self, d: Datagram, max_size: usize) -> Result<(), SessionError> {
        self.datagrams
            .enqueue_outbound(d, max_size)
            .map_err(SessionError::Datagram)
    }

    pub fn recv_datagram(&mut self) -> Option<Datagram> {
        self.datagrams.pop_inbound()
    }

    /// Read all contiguous delivered bytes from a stream.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::StreamNotFound`] if the stream does not exist.
    pub fn read_stream(&mut self, stream_id: u64) -> Result<(Vec<u8>, bool), SessionError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(SessionError::StreamNotFound)?;
        Ok(stream.read_available())
    }

    /// Build the next outbound protected packet (control or data).
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::NoSpace`] if the session data space is
    /// missing, [`SessionError::Space`] if packet numbers are exhausted, and
    /// [`SessionError::Packet`] if packet assembly fails.
    pub fn build_outbound(
        &mut self,
        clock: &dyn Clock,
        now: Instant,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, SessionError> {
        let _ = clock;
        if self.state != SessionState::Active {
            return Ok(None);
        }
        let space = self
            .spaces
            .get_mut(&PacketSpace::SessionData)
            .ok_or(SessionError::NoSpace)?;
        let pn = space
            .allocate_packet_number()
            .map_err(SessionError::Space)?;
        let sent = SentPacket::new(
            pn,
            PacketSpace::SessionData,
            now,
            payload.len() + 64,
            true,
            0,
        );
        self.sent.record_sent(sent);
        let keys = &self.local_keys;
        let pkt = build_protected_packet(
            keys,
            ShortPacketSpace::SessionData,
            &self.dcid,
            0,
            pn,
            false,
            payload,
        )
        .map_err(SessionError::Packet)?;
        Ok(Some(pkt))
    }

    /// Process an inbound protected packet. Returns ACK payload to send (may be empty).
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Packet`] if parsing or decryption fails,
    /// [`SessionError::Space`] if the packet number is a duplicate or stale,
    /// [`SessionError::Stream`] / [`SessionError::Flow`] /
    /// [`SessionError::Datagram`] if a frame cannot be applied, and
    /// [`SessionError::Encode`] if ACK encoding fails.
    pub fn on_inbound(&mut self, now: Instant, bytes: &[u8]) -> Result<Vec<u8>, SessionError> {
        let (space_kind, _dcid, _path, truncated_pn, payload) =
            super::packet::parse_protected_packet(&self.remote_keys, bytes)
                .map_err(SessionError::Packet)?;
        let space = match space_kind {
            ShortPacketSpace::SessionData => PacketSpace::SessionData,
            ShortPacketSpace::PathControl => PacketSpace::PathControl,
            ShortPacketSpace::RelayData => PacketSpace::RelayData,
        };
        let space_state = self.spaces.get_mut(&space).ok_or(SessionError::NoSpace)?;
        let pn = space_state
            .admit_received(truncated_pn, 16)
            .map_err(SessionError::Space)?;
        self.recv_acks.entry(space).or_default().record(pn);
        let parsed =
            umc_wire::packet::parse_payload(&PacketContext::Protected(space_kind), &payload)
                .map_err(SessionError::WirePacket)?;
        for frame in parsed.frames {
            match frame {
                umc_wire::frame::Frame::Stream(f) => {
                    self.apply_stream_frame(&f)?;
                }
                umc_wire::frame::Frame::Datagram(d) => {
                    self.datagrams
                        .enqueue_inbound(Datagram {
                            context_id: d.context_id,
                            data: d.data,
                            expires_at_ms: None,
                            ack_requested: d.ack_requested,
                        })
                        .map_err(SessionError::Datagram)?;
                }
                umc_wire::frame::Frame::ConnectionClose(_) => {
                    self.state = SessionState::Closed;
                }
                _ => {}
            }
        }
        // Build an ACK if needed.
        let mut ack_payload = Vec::new();
        if let Some(state) = self.recv_acks.get_mut(&space) {
            if state.take_needs_ack() {
                if let Some((largest, delay, first_len, extra)) = state.build_ack(0) {
                    umc_wire::varint::encode_into(
                        &mut ack_payload,
                        umc_types::frame::FrameType::ACK.0,
                    )
                    .map_err(|_| SessionError::Encode)?;
                    umc_wire::varint::encode_into(&mut ack_payload, largest)
                        .map_err(|_| SessionError::Encode)?;
                    umc_wire::varint::encode_into(&mut ack_payload, delay)
                        .map_err(|_| SessionError::Encode)?;
                    umc_wire::varint::encode_into(&mut ack_payload, extra.len() as u64 + 1)
                        .map_err(|_| SessionError::Encode)?;
                    umc_wire::varint::encode_into(&mut ack_payload, first_len)
                        .map_err(|_| SessionError::Encode)?;
                    for (gap, len) in extra {
                        umc_wire::varint::encode_into(&mut ack_payload, gap)
                            .map_err(|_| SessionError::Encode)?;
                        umc_wire::varint::encode_into(&mut ack_payload, len)
                            .map_err(|_| SessionError::Encode)?;
                    }
                }
            }
        }
        let _ = now;
        Ok(ack_payload)
    }

    fn apply_stream_frame(
        &mut self,
        f: &umc_wire::frames::stream::StreamFrame,
    ) -> Result<(), SessionError> {
        let stream = self.streams.entry(f.stream_id).or_insert_with(|| {
            Stream::new(f.stream_id, f.protocol_id.clone(), self.flow.max_data_local)
        });
        stream
            .receive(f.offset, &f.data, f.fin)
            .map_err(SessionError::Stream)?;
        self.flow
            .consume(f.offset + f.data.len() as u64)
            .map_err(SessionError::Flow)
    }

    /// Apply a peer ACK to the sent-packet state.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Ack`] if the ACK acknowledges unsent packets.
    pub fn on_peer_ack(
        &mut self,
        now: Instant,
        largest: u64,
        first_len: u64,
        ranges: &[(u64, u64)],
    ) -> Result<(), SessionError> {
        let _ = now;
        let mut flat = Vec::new();
        flat.push((first_len, 0));
        flat.extend_from_slice(ranges);
        let _ = self
            .sent
            .apply_ack(largest, &flat)
            .map_err(SessionError::Ack)?;
        Ok(())
    }

    #[must_use]
    pub fn rtt(&self) -> &RttEstimator {
        &self.rtt
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    BadConnectionId,
    BadKeys,
    NoSpace,
    Space(super::spaces::SpaceError),
    Packet(super::packet::PacketBuildError),
    WirePacket(umc_wire::packet::PacketError),
    Stream(StreamError),
    Flow(super::flow::FlowError),
    Datagram(super::datagram::DatagramError),
    Encode,
    StreamNotFound,
    Ack(super::ack::AckError),
}

impl From<StreamError> for SessionError {
    fn from(e: StreamError) -> Self {
        SessionError::Stream(e)
    }
}
