use super::ack::{AckReceiveState, AckSendState};
use super::congestion::{CongestionController, RenoCongestionController};
use super::datagram::{Datagram, DatagramQueue};
use super::flow::FlowControl;
use super::loss::LossDetector;
use super::packet::build_protected_packet;
use super::rtt::RttEstimator;
use super::sent_packet::SentPacket;
use super::spaces::{PacketSpace, PacketSpaceState};
use super::stream::{Stream, StreamError};
use std::collections::{HashMap, HashSet};
use umc_crypto::aead::PacketKeys;
use umc_crypto::header_protection::header_protection_key;
use umc_types::runtime::{Clock, Duration, EntropySource, Instant};
use umc_wire::header::ShortPacketSpace;
use umc_wire::packet::PacketContext;

pub const DEFAULT_DCID_LEN: usize = 8;
pub const INITIAL_STREAMS: u64 = 16;
pub const DEFAULT_INITIAL_MAX_DATA: u64 = 4 * 1024 * 1024;
pub const DEFAULT_INITIAL_MAX_STREAM_DATA: u64 = 256 * 1024;
/// Cap on remembered closed stream ids (session.md §29): ids are kept only
/// to reject reuse, so the set is bounded with FIFO eviction.
pub const MAX_CLOSED_STREAM_IDS: usize = 1_024;
/// Hard cap on concurrent open streams per session (resource-limits.md §20):
/// exceeding it is a [`SessionError::StreamLimit`] on both the outbound and
/// inbound paths.
pub const MAX_STREAMS_PER_SESSION: usize = 1_024;
/// Idle timeout (session.md §22): a session that has not touched its idle
/// timer for this long is closed locally with an `IDLE_TIMEOUT` close.
pub const IDLE_TIMEOUT_MS: u64 = 30_000;
/// Transport error code carried by an idle-timeout `CONNECTION_CLOSE`
/// (wire-format.md §64: `0x16` = `IDLE_TIMEOUT`).
pub const CLOSE_REASON_IDLE_TIMEOUT: u64 = 0x16;
/// Minimum draining period (session.md §6.4): 1 s.
pub const MIN_DRAIN_MS: u64 = 1_000;
/// Rate limit between emitted stateless resets (session.md §31): 1 per
/// minute per connection.
pub const STATELESS_RESET_INTERVAL_MS: u64 = 60_000;
/// Fixed payload size used by the traffic-padding policy. The target is
/// deliberately modest and applies only to packets carrying non-control
/// data; cover traffic uses the same target when P3 is active.
pub const TRAFFIC_PADDING_TARGET: usize = 1_024;

/// Bounded set of stream ids that reached EOF and were read: re-opening
/// (or delivering to) a closed id is a protocol violation (session.md §29).
#[derive(Debug, Default)]
struct ClosedStreamRegistry {
    ids: std::collections::HashSet<u64>,
    order: std::collections::VecDeque<u64>,
}

impl ClosedStreamRegistry {
    fn contains(&self, stream_id: u64) -> bool {
        self.ids.contains(&stream_id)
    }

    fn insert(&mut self, stream_id: u64) {
        if self.ids.insert(stream_id) {
            self.order.push_back(stream_id);
            if self.order.len() > MAX_CLOSED_STREAM_IDS {
                if let Some(oldest) = self.order.pop_front() {
                    self.ids.remove(&oldest);
                }
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.ids.len()
    }
}

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

pub struct Session {
    pub role: Role,
    pub state: SessionState,
    local_keys: PacketKeys,
    remote_keys: PacketKeys,
    /// Header protection keys (wire-format §18), derived from the traffic
    /// secrets at construction: the local key masks outbound headers, the
    /// remote key unmasks inbound ones.
    local_hp_key: [u8; 32],
    remote_hp_key: [u8; 32],
    spaces: HashMap<PacketSpace, PacketSpaceState>,
    sent: AckSendState,
    /// Congestion controller (congestion.md §7): bounds in-flight bytes
    /// and gates sends in [`Session::build_outbound`]. Defaults to Reno;
    /// the daemon keeps the default, tests may inject a mock.
    congestion: Box<dyn CongestionController>,
    /// Payloads of built packets keyed by packet number. Lost packets leave
    /// the sent queue (their `SentPacket` is dropped by loss detection), so
    /// the payload is retained here until acknowledged or retransmitted
    /// (session.md §14.3).
    retransmit_payloads: HashMap<u64, Vec<u8>>,
    recv_acks: HashMap<PacketSpace, AckReceiveState>,
    rtt: RttEstimator,
    loss: LossDetector,
    pub streams: HashMap<u64, Stream>,
    next_outgoing_stream: u64,
    next_outgoing_unidirectional: u64,
    closed_streams: ClosedStreamRegistry,
    flow: FlowControl,
    /// Bytes received but not yet delivered per open stream id. This keeps
    /// unread-buffer pressure separate from application-consumption credit.
    stream_consumed: HashMap<u64, u64>,
    /// Bytes delivered to the application per stream (session.md §20.3):
    /// drives `MAX_STREAM_DATA` emission even when the unread buffer is
    /// drained immediately.
    stream_app_consumed: HashMap<u64, u64>,
    reset_final_sizes: HashSet<u64>,
    peer_initiated_streams: usize,
    default_max_stream_data: u64,
    /// Highest `MAX_STREAMS` limit offered so far; the initial transport
    /// parameter already granted [`INITIAL_STREAMS`].
    max_streams_sent: u64,
    datagrams: DatagramQueue,
    dcid: Vec<u8>,
    key_update: crate::key_update::KeyUpdateState,
    pub paths: HashMap<u64, crate::path::Path>,
    /// Highest authenticated `MIGRATE` sequence accepted for this session.
    last_migration_sequence: u64,
    /// Most recent successful primary-path migration, consumed by the
    /// runtime event adapter without changing the session handle.
    last_path_migration: Option<(u64, u64, bool)>,
    /// Most recent path validation, consumed by the runtime event adapter.
    last_path_validation: Option<u64>,
    /// Primary carrier path used for new outbound packets. Packet numbers,
    /// streams, flow-control state, and traffic keys remain session-scoped;
    /// only this routing selector changes during migration.
    primary_path_id: u64,
    /// Monotonic sequence allocated by the local MIGRATE sender.
    next_migration_sequence: u64,
    #[allow(dead_code)]
    cids: crate::cid::ConnectionIdManager,
    /// Whether this session may use a direct carrier path (privacy.md §45).
    /// P2 route policy turns this off before adding or migrating paths.
    direct_path_allowed: bool,
    /// When the idle timer was last reset (session.md §22): every inbound
    /// packet carrying at least one real frame resets it, and the daemon
    /// touches it at app-originated send sites. Probes, retransmits,
    /// duplicates, and padding-only packets must NOT reset it — a dead peer
    /// replaying bytes must not keep the session alive. `None` until the
    /// first activity, so a fresh session is never idle.
    last_activity: Option<Instant>,
    /// Absolute deadline of the draining period (session.md §6.4), set by
    /// [`Session::close`]; `None` until the session starts draining.
    draining_deadline: Option<Instant>,
    /// Stateless-reset secret (session.md §31): `None` disables reset
    /// detection and emission for this session.
    stateless_reset_secret: Option<[u8; 32]>,
    /// Millisecond instant of the last emitted stateless reset: emission is
    /// rate-limited to one per [`STATELESS_RESET_INTERVAL_MS`] per
    /// connection (session.md §31).
    last_reset_ms: Option<u64>,
    /// Whether application data should be padded to
    /// [`TRAFFIC_PADDING_TARGET`] bytes before encryption (privacy.md §P3).
    /// P3 enables this automatically; ACK/PING control payloads are never
    /// padded.
    traffic_padding: bool,
    /// Maximum randomized delay applied by the daemon to application sends
    /// under P3 (privacy.md §27). The session stores policy only; the daemon
    /// supplies entropy and performs the asynchronous sleep.
    timing_jitter_ms: u64,
    /// Negotiated privacy profile level (privacy.md §42). The session layer
    /// stores the numeric wire level so the daemon can expose the exact
    /// handshake result without depending on its policy crate.
    privacy_profile: u8,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The congestion controller is opaque (a `Box<dyn ...>`), so the
        // dump reports the session identity fields only.
        f.debug_struct("Session")
            .field("role", &self.role)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
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
            local_hp_key: header_protection_key(&config.local_traffic_secret),
            remote_hp_key: header_protection_key(&config.remote_traffic_secret),
            spaces,
            sent: AckSendState::new(),
            congestion: Box::new(RenoCongestionController::new()),
            retransmit_payloads: HashMap::new(),
            recv_acks: HashMap::new(),
            rtt: RttEstimator::new(),
            loss: LossDetector::new(config.max_ack_delay_ms),
            streams: HashMap::new(),
            next_outgoing_stream: 0,
            next_outgoing_unidirectional: 0,
            closed_streams: ClosedStreamRegistry::default(),
            flow: FlowControl::new(config.initial_max_data, INITIAL_STREAMS, INITIAL_STREAMS),
            stream_consumed: HashMap::new(),
            stream_app_consumed: HashMap::new(),
            reset_final_sizes: HashSet::new(),
            peer_initiated_streams: 0,
            default_max_stream_data: config.initial_max_stream_data,
            max_streams_sent: INITIAL_STREAMS,
            datagrams: DatagramQueue::new(),
            dcid: config.dcid,
            key_update: crate::key_update::KeyUpdateState::new(
                config.local_traffic_secret,
                config.remote_traffic_secret,
            ),
            paths: HashMap::new(),
            last_migration_sequence: 0,
            last_path_migration: None,
            last_path_validation: None,
            primary_path_id: super::packet::DEFAULT_PATH_ID,
            next_migration_sequence: 0,
            cids: crate::cid::ConnectionIdManager::new(crate::cid::DEFAULT_ACTIVE_LIMIT),
            direct_path_allowed: true,
            last_activity: None,
            draining_deadline: None,
            stateless_reset_secret: None,
            last_reset_ms: None,
            traffic_padding: false,
            timing_jitter_ms: 0,
            privacy_profile: 0,
        })
    }

    /// Supply the session's stateless-reset secret (session.md §31): the
    /// first 16 bytes are the connection's stateless-reset token. The daemon
    /// fills it from its handshake-derived session secrets right after
    /// construction; without it the session neither detects nor emits
    /// stateless resets.
    pub fn set_stateless_reset_secret(&mut self, secret: [u8; 32]) {
        self.stateless_reset_secret = Some(secret);
    }

    /// Open a new initiator-bidirectional stream.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::StreamLimit`] when the session already holds
    /// [`MAX_STREAMS_PER_SESSION`] concurrent streams (resource-limits.md
    /// §20).
    pub fn open_stream(&mut self) -> Result<u64, SessionError> {
        self.open_stream_kind(false)
    }

    fn open_stream_kind(&mut self, unidirectional: bool) -> Result<u64, SessionError> {
        if self.streams.len() >= MAX_STREAMS_PER_SESSION {
            return Err(SessionError::StreamLimit);
        }
        let sequence = if unidirectional {
            let sequence = self.next_outgoing_unidirectional;
            self.next_outgoing_unidirectional =
                sequence.checked_add(1).ok_or(SessionError::StreamLimit)?;
            sequence
        } else {
            let sequence = self.next_outgoing_stream;
            self.next_outgoing_stream = sequence.checked_add(1).ok_or(SessionError::StreamLimit)?;
            sequence
        };
        let initiator = match self.role {
            Role::Client => 0,
            Role::Server => 1,
        };
        let direction = u64::from(unidirectional) << 1;
        let id = sequence
            .checked_mul(4)
            .and_then(|value| value.checked_add(initiator | direction))
            .ok_or(SessionError::StreamLimit)?;
        self.streams.insert(
            id,
            Stream::new(id, Vec::new(), self.default_max_stream_data),
        );
        if let Some(stream) = self.streams.get_mut(&id) {
            stream.unidirectional = unidirectional;
        }
        Ok(id)
    }

    /// Open an application stream with its protocol identifier and direction
    /// metadata carried in the first STREAM frame.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Encode`] when the protocol identifier exceeds
    /// the wire limit, or [`SessionError::StreamLimit`] when no stream slot is
    /// available.
    pub fn open_stream_with_protocol(
        &mut self,
        protocol_id: &[u8],
        unidirectional: bool,
    ) -> Result<u64, SessionError> {
        if protocol_id.len() > umc_wire::frames::stream::MAX_PROTOCOL_ID_LEN {
            return Err(SessionError::Encode);
        }
        let stream_id = self.open_stream_kind(unidirectional)?;
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.protocol_id = protocol_id.to_vec();
            stream.unidirectional = unidirectional;
        }
        Ok(stream_id)
    }

    /// Validate the low-bit stream identifier encoding (wire-format.md §29).
    /// `initiator_bit` is supplied separately so callers can validate a
    /// frame before deciding whether that initiator is local or remote.
    #[must_use]
    pub fn validate_stream_id(
        &self,
        stream_id: u64,
        initiator_bit: u64,
        unidirectional: bool,
    ) -> bool {
        let direction_bit = if unidirectional { 0b10 } else { 0 };
        initiator_bit <= 1 && (stream_id & 0b11) == (initiator_bit | direction_bit)
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
        // A FIN is valid only when this frame carries the complete caller
        // payload. Flow-control credit may accept a prefix; never mark that
        // prefix as the final size and silently discard the remainder.
        let fin = fin && chunk.len() == data.len();
        let mut payload = Vec::new();
        let frame = umc_wire::frames::stream::StreamFrame {
            stream_id,
            fin,
            offset_present: offset != 0,
            len_present: true,
            open: offset == 0,
            unidirectional: stream.unidirectional,
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

    /// Build a zero-length FIN frame for the stream's send direction.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::StreamNotFound`] when the stream is unknown,
    /// [`SessionError::Stream`] when its send side is already closed, or
    /// [`SessionError::Encode`] when frame encoding fails.
    pub fn close_stream_send_payload(&mut self, stream_id: u64) -> Result<Vec<u8>, SessionError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(SessionError::StreamNotFound)?;
        if matches!(
            stream.send_state,
            super::stream::SendState::DataAcked
                | super::stream::SendState::ResetAcked
                | super::stream::SendState::ResetSent
        ) {
            return Err(SessionError::Stream(StreamError::AlreadyClosed));
        }
        let frame = umc_wire::frames::stream::StreamFrame {
            stream_id,
            fin: true,
            offset_present: stream.next_send_offset != 0,
            len_present: true,
            open: stream.next_send_offset == 0,
            unidirectional: stream.unidirectional,
            offset: stream.next_send_offset,
            data: Vec::new(),
            protocol_id: if stream.next_send_offset == 0 {
                stream.protocol_id.clone()
            } else {
                Vec::new()
            },
            metadata: Vec::new(),
        };
        stream.send_state = super::stream::SendState::DataSent;
        frame.encode().map_err(|_| SessionError::Encode)
    }

    /// Build a `RESET_STREAM` frame and stop local writes for the stream.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::StreamNotFound`] when the stream is unknown, or
    /// [`SessionError::Encode`] when frame encoding fails.
    pub fn reset_stream_payload(
        &mut self,
        stream_id: u64,
        application_error_code: u64,
    ) -> Result<Vec<u8>, SessionError> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(SessionError::StreamNotFound)?;
        stream.send_state = super::stream::SendState::ResetSent;
        umc_wire::frames::stream::ResetStreamFrame {
            stream_id,
            app_error_code: application_error_code,
            final_size: stream.next_send_offset,
        }
        .encode()
        .map_err(|_| SessionError::Encode)
    }

    /// Build a `STOP_SENDING` frame for the peer's send direction.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::StreamNotFound`] when the stream is unknown, or
    /// [`SessionError::Encode`] when frame encoding fails.
    pub fn stop_stream_payload(
        &mut self,
        stream_id: u64,
        application_error_code: u64,
    ) -> Result<Vec<u8>, SessionError> {
        if !self.streams.contains_key(&stream_id) {
            return Err(SessionError::StreamNotFound);
        }
        umc_wire::frames::stream::StopSendingFrame {
            stream_id,
            app_error_code: application_error_code,
        }
        .encode()
        .map_err(|_| SessionError::Encode)
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

    /// Pop one non-expired queued datagram and encode its wire frame. The
    /// caller still passes the resulting payload through `build_outbound` so
    /// congestion, amplification, retransmission, and padding rules remain
    /// centralized in the session.
    pub fn pop_outbound_datagram_payload(&mut self, now_ms: u64) -> Option<Vec<u8>> {
        let datagram = self.datagrams.pop_outbound(now_ms)?;
        umc_wire::frames::datagram::DatagramFrame {
            context_id: datagram.context_id,
            ack_requested: datagram.ack_requested,
            duplicate_suppression: false,
            expiration_delta: datagram
                .expires_at_ms
                .map(|expires_at| expires_at.saturating_sub(now_ms)),
            data: datagram.data,
        }
        .encode()
        .ok()
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
        if stream.recv_state == super::stream::RecvState::ResetRecvd {
            // The peer reset its send side: the buffered data is unreachable
            // (session.md §18.5).
            stream.recv_state = super::stream::RecvState::ResetRead;
            return Err(SessionError::Stream(StreamError::ResetByPeer));
        }
        if stream.recv_state == super::stream::RecvState::ResetRead {
            return Err(SessionError::Stream(StreamError::AlreadyClosed));
        }
        let (data, eof) = stream.read_available();
        if !data.is_empty() {
            // Keep unread-buffer accounting separate from §20.3 application
            // consumption. The former protects local memory; the latter
            // earns fresh peer credit even when the application drains every
            // read immediately.
            if let Some(consumed) = self.stream_consumed.get_mut(&stream_id) {
                *consumed = consumed.saturating_sub(data.len() as u64);
            }
            let app_consumed = self.stream_app_consumed.entry(stream_id).or_insert(0);
            *app_consumed = app_consumed.saturating_add(data.len() as u64);
        }
        if eof {
            // The final size was reached and read: the id is closed and any
            // further delivery on it is a protocol violation (session.md §29).
            self.closed_streams.insert(stream_id);
            self.stream_consumed.remove(&stream_id);
            self.stream_app_consumed.remove(&stream_id);
            self.reset_final_sizes.remove(&stream_id);
        }
        Ok((data, eof))
    }

    /// Return the peer application error for a received `RESET_STREAM`.
    #[must_use]
    pub fn stream_reset_error(&self, stream_id: u64) -> Option<u64> {
        self.streams
            .get(&stream_id)
            .and_then(|stream| stream.reset_error_code)
    }

    /// Build `MAX_DATA` / `MAX_STREAM_DATA` / `MAX_STREAMS` payloads when a
    /// local credit watermark is crossed (session.md §20): each limit is
    /// doubled when more than half of it has been consumed. Grants never
    /// decrease, so a watermark re-arms only after the doubled limit is half
    /// consumed again. Payloads include the frame type byte, matching
    /// [`Session::send_stream_data`]. The daemon appends the returned
    /// payloads to its combined outbound packet.
    #[must_use]
    pub fn flow_control_frames(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let _ = now;
        let mut frames = Vec::new();
        // Connection-level credit: more than half consumed.
        if self.flow.credit_remaining_local() < self.flow.max_data_local / 2 {
            let new_max = self.flow.max_data_local.saturating_mul(2);
            if new_max > self.flow.max_data_local {
                self.flow.grant_more(new_max);
                if let Ok(enc) = (umc_wire::frames::flow::MaxDataFrame {
                    maximum_data: new_max,
                })
                .encode()
                {
                    frames.push(enc);
                }
            }
        }
        // Per-stream credit: more than half of the stream's limit consumed.
        let mut stream_ids: HashSet<u64> = self.stream_consumed.keys().copied().collect();
        stream_ids.extend(self.stream_app_consumed.keys().copied());
        for stream_id in stream_ids {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                continue;
            };
            let unread = self.stream_consumed.get(&stream_id).copied().unwrap_or(0);
            let app_consumed = self
                .stream_app_consumed
                .get(&stream_id)
                .copied()
                .unwrap_or(0);
            let below_unread_watermark = stream.max_stream_data_local.saturating_sub(unread)
                < stream.max_stream_data_local / 2;
            let below_consumption_watermark =
                stream.max_stream_data_local.saturating_sub(app_consumed)
                    < stream.max_stream_data_local / 2;
            if below_unread_watermark || below_consumption_watermark {
                let new_max = stream.max_stream_data_local.saturating_mul(2);
                if new_max > stream.max_stream_data_local {
                    stream.max_stream_data_local = new_max;
                    if let Ok(enc) = (umc_wire::frames::flow::MaxStreamDataFrame {
                        stream_id,
                        maximum_stream_data: new_max,
                    })
                    .encode()
                    {
                        frames.push(enc);
                    }
                }
            }
        }
        // Stream count: the peer's initial grant is INITIAL_STREAMS; double
        // it once open streams exceed that, then again when the doubled
        // grant is exceeded in turn.
        if (self.peer_initiated_streams as u64) > INITIAL_STREAMS
            && (self.peer_initiated_streams as u64).saturating_mul(2) > self.max_streams_sent
        {
            let new_count = (self.peer_initiated_streams as u64).saturating_mul(2);
            self.max_streams_sent = new_count;
            self.flow.max_bidirectional_streams_local = new_count;
            if let Ok(enc) = (umc_wire::frames::flow::MaxStreamsFrame {
                bidirectional: true,
                maximum_streams: new_count,
            })
            .encode()
            {
                frames.push(enc);
            }
        }
        frames
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
        self.build_outbound_on_path(self.primary_path_id, clock, now, payload)
    }

    /// Build an outbound packet on a specific validated (or currently
    /// validating control) path. This is used for `PATH_RESPONSE` and
    /// `MIGRATE`:
    /// validation responses must return on the candidate path, while the
    /// migration command is sent on the old primary path before the local
    /// selector flips.
    ///
    /// # Errors
    ///
    /// Returns the same packet-space, congestion, amplification, and packet
    /// assembly errors as [`Self::build_outbound`].
    pub fn build_outbound_on_path(
        &mut self,
        path_id: u64,
        clock: &dyn Clock,
        now: Instant,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, SessionError> {
        let _ = clock;
        self.build_outbound_inner(path_id, now, payload)
    }

    fn build_outbound_inner(
        &mut self,
        path_id: u64,
        now: Instant,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, SessionError> {
        if self.state != SessionState::Active {
            return Ok(None);
        }
        let payload = self.outbound_payload(payload);
        // Anti-amplification (congestion.md §18): before validation a path
        // may send at most 3x the bytes it has received. Control payloads
        // are exempt — ACKs and PINGs are a few bytes, and refusing them
        // would stall the protocol (session.md §26). The gate only applies
        // when a path record exists: sessions without path accounting send
        // unrestricted.
        if let Some(path) = self.paths.get(&path_id) {
            if !path.validated
                && !payload_is_exempt(&payload)
                && payload.len() as u64 > path.send_allowance()
            {
                return Err(SessionError::AmplificationLimit);
            }
        }
        // Congestion window (congestion.md §7.1): sends are bounded by the
        // controller's allowance — cwnd minus in-flight bytes. ACK and PING
        // payloads carry the same exemption as the anti-amplification gate
        // (congestion.md §7.3 control reserve): they are small and refusing
        // them would break the acknowledgment loop or stall the PTO probe
        // with a full window.
        //
        // The gate must run before packet assembly, so the protected size is
        // bounded by `payload.len() + PROTECTED_OVERHEAD_ESTIMATE` — the
        // wire bytes (which charge in-flight) always include the header,
        // dcid, path id, packet number, and the AEAD tag beyond the payload.
        if !payload_is_exempt(&payload)
            && payload.len() + PROTECTED_OVERHEAD_ESTIMATE > self.congestion.send_allowance()
        {
            return Err(SessionError::CongestionLimited);
        }
        // NOTE: this builder serves retransmits and PTO probes too, so it
        // must NOT touch the idle timer (session.md §22 resets on receives
        // and daemon app-originated sends only; see `Session::touch`).
        let space = self
            .spaces
            .get_mut(&PacketSpace::SessionData)
            .ok_or(SessionError::NoSpace)?;
        let pn = space
            .allocate_packet_number()
            .map_err(SessionError::Space)?;
        let keys = &self.local_keys;
        let pkt = build_protected_packet(
            keys,
            &self.local_hp_key,
            ShortPacketSpace::SessionData,
            &self.dcid,
            path_id,
            pn,
            false,
            &payload,
        )
        .map_err(SessionError::Packet)?;
        let sent = SentPacket::new(pn, PacketSpace::SessionData, now, pkt.len(), true, 0);
        self.retransmit_payloads.insert(pn, payload);
        if let Some((lost_pn, lost_size)) = self.sent.record_sent(sent) {
            // Cap eviction (MAX_OUTSTANDING_PACKETS): the evicted packet is
            // beyond recovery, so drop its retained payload. Its bytes are
            // released from the congestion controller's in-flight count as
            // if acknowledged — they are gone from the sent queue and would
            // otherwise leak the window forever (resource-limits.md §24).
            // This is NOT a loss event: the controller's loss counter must
            // not trip.
            self.retransmit_payloads.remove(&lost_pn);
            self.congestion.on_packet_acknowledged(lost_size);
        }
        // Charge the budget for the actual wire bytes (congestion.md §18);
        // only unvalidated paths carry a budget.
        if let Some(path) = self.paths.get_mut(&path_id) {
            if !path.validated {
                path.record_sent(pkt.len() as u64);
            }
        }
        // Congestion accounting (congestion.md §7.2): the wire bytes are
        // in flight until acknowledged or declared lost.
        self.congestion.on_packet_sent(pkt.len());
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
    #[allow(clippy::too_many_lines)] // per-frame dispatch arms; each is a few lines
    pub fn on_inbound(&mut self, now: Instant, bytes: &[u8]) -> Result<Vec<u8>, SessionError> {
        let expected = self
            .spaces
            .get(&PacketSpace::SessionData)
            .map_or(0, |s| s.largest_received().saturating_add(1));
        let (space_kind, _dcid, path_id, pn, payload) = match super::packet::parse_protected_packet(
            &self.remote_keys,
            &self.remote_hp_key,
            expected,
            bytes,
        ) {
            Ok(parsed) => parsed,
            Err(e) => {
                // session.md §31: a packet that cannot be authenticated
                // may be a stateless reset — a short-header packet
                // carrying our token at the fixed slot of the canonical
                // layout. The check runs on ANY parse failure: with a
                // random token the header parse can fail before reaching
                // the AEAD tag. A match closes the session without a
                // response.
                if let Some(secret) = self.stateless_reset_secret {
                    let token = crate::reset::reset_token(&secret);
                    if crate::reset::token_matches(bytes, &token) {
                        self.state = SessionState::Closed;
                        return Err(SessionError::StatelessReset);
                    }
                }
                return Err(SessionError::Packet(e));
            }
        };
        let space = match space_kind {
            ShortPacketSpace::SessionData => PacketSpace::SessionData,
            ShortPacketSpace::PathControl => PacketSpace::PathControl,
            ShortPacketSpace::RelayData => PacketSpace::RelayData,
        };
        let space_state = self.spaces.get_mut(&space).ok_or(SessionError::NoSpace)?;
        // Reject duplicates/stale packets BEFORE touching the idle timer: a
        // replayed packet must not keep a zombie session alive (session.md
        // §22).
        // The full pn was already reconstructed for the AEAD open; the replay
        // window admits it directly (no second reconstruction).
        let pn = space_state
            .admit_reconstructed(pn)
            .map_err(SessionError::Space)?;
        self.recv_acks.entry(space).or_default().record(pn);
        // Anti-amplification accounting (congestion.md §18): every admitted
        // packet grows the 3x send budget of the path it arrived on. A path
        // id not in the map falls back to the default path; with no path
        // record at all there is nothing to account.
        let budget_path = if self.paths.contains_key(&path_id) {
            path_id
        } else {
            super::packet::DEFAULT_PATH_ID
        };
        if let Some(path) = self.paths.get_mut(&budget_path) {
            path.record_received(bytes.len() as u64, now);
        }
        let parsed =
            umc_wire::packet::parse_payload(&PacketContext::Protected(space_kind), &payload)
                .map_err(SessionError::WirePacket)?;
        // A new authenticated packet carrying at least one real frame resets
        // the idle timer (session.md §22); padding-only packets do not.
        if parsed
            .frames
            .iter()
            .any(|f| !matches!(f, umc_wire::frame::Frame::Padding))
        {
            self.last_activity = Some(now);
        }
        // Path responses and other generated control frames are returned
        // alongside the ACK so the daemon can send them in the same packet.
        let mut response_payload = Vec::new();
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
                umc_wire::frame::Frame::ResetStream(f) => {
                    // The peer reset its send side (session.md §18.5): our
                    // recv side is reset — buffered data becomes unreachable
                    // and reading reports the reset. Reuse of a closed id is
                    // a protocol violation (session.md §29); an unknown id
                    // is a no-op (a retransmitted RESET after our side
                    // closed must not drop co-carried frames).
                    if self.closed_streams.contains(f.stream_id) {
                        return Err(SessionError::StreamClosed);
                    }
                    let Some(stream) = self.streams.get_mut(&f.stream_id) else {
                        continue;
                    };
                    // §18.5 MUST: account the reset's final size against
                    // connection flow control exactly once, and reject a
                    // final size below any received offset or conflicting
                    // with a known final size. The max received offset comes
                    // from the stream's own reassembly state (delivered
                    // prefix plus the highest buffered end).
                    let max_received = stream.max_received_offset();
                    if f.final_size < max_received {
                        return Err(SessionError::Flow(super::flow::FlowError::ExceedsCredit));
                    }
                    if let Some(known) = stream.final_size {
                        if known != f.final_size {
                            return Err(SessionError::Flow(super::flow::FlowError::ExceedsCredit));
                        }
                    }
                    if self.reset_final_sizes.insert(f.stream_id) {
                        if let Err(e) = self.flow.consume(f.final_size) {
                            return Err(SessionError::Flow(e));
                        }
                    }
                    stream.recv_state = super::stream::RecvState::ResetRecvd;
                    stream.reset_error_code = Some(f.app_error_code);
                    self.stream_consumed.remove(&f.stream_id);
                    self.stream_app_consumed.remove(&f.stream_id);
                }
                umc_wire::frame::Frame::StopSending(f) => {
                    // The peer stopped reading our send side (session.md
                    // §18.5): the send side is stopped and `send_ready`
                    // refuses further data. Unknown ids are a no-op (the
                    // stream may already be closed).
                    if let Some(stream) = self.streams.get_mut(&f.stream_id) {
                        stream.send_state = super::stream::SendState::ResetSent;
                    }
                }
                umc_wire::frame::Frame::MaxData(f) => {
                    // Peer send credit is monotonic (session.md §20.3).
                    if f.maximum_data > self.flow.max_data_remote {
                        self.flow.max_data_remote = f.maximum_data;
                    }
                }
                umc_wire::frame::Frame::MaxStreamData(f) => {
                    // A credit update may race stream teardown; an unknown
                    // stream is retained as a no-op until its OPEN arrives.
                    if let Some(stream) = self.streams.get_mut(&f.stream_id) {
                        stream.max_stream_data_remote =
                            stream.max_stream_data_remote.max(f.maximum_stream_data);
                    }
                }
                umc_wire::frame::Frame::MaxStreams(f) => {
                    let limit = if f.bidirectional {
                        &mut self.flow.max_bidirectional_streams_local
                    } else {
                        &mut self.flow.max_unidirectional_streams_local
                    };
                    *limit = (*limit).max(f.maximum_streams);
                }
                umc_wire::frame::Frame::ConnectionClose(_) => {
                    self.state = SessionState::Closed;
                }
                umc_wire::frame::Frame::NewConnectionId(frame) => {
                    // Packet parsing uses a fixed 8-byte destination CID in
                    // this protocol version. Do not install a CID that the
                    // short-header parser could not later decode.
                    if frame.connection_id.len() != DEFAULT_DCID_LEN {
                        return Err(SessionError::BadConnectionId);
                    }
                    self.dcid = frame.connection_id;
                }
                umc_wire::frame::Frame::RetireConnectionId(frame) => {
                    // Unknown retirements are harmless duplicates; retained
                    // reset tokens stay in the manager until its bounded
                    // pruning pass (session.md §30.3).
                    let _ = self.cids.retire(frame.sequence);
                }
                umc_wire::frame::Frame::Ack(ack) => {
                    self.apply_peer_ack(&ack, now)?;
                }
                umc_wire::frame::Frame::KeyUpdate(update) => {
                    self.on_key_update(update.update_sequence)?;
                }
                umc_wire::frame::Frame::PathChallenge(challenge) => {
                    response_payload
                        .extend_from_slice(&self.on_path_challenge(path_id, challenge.data));
                }
                umc_wire::frame::Frame::PathResponse(response) => {
                    self.on_path_response(path_id, response.data)?;
                }
                umc_wire::frame::Frame::Migrate(migrate) => {
                    if migrate.migration_sequence > self.last_migration_sequence {
                        if migrate.old_path_id != self.primary_path_id {
                            return Err(SessionError::PathMigration);
                        }
                        self.last_migration_sequence = migrate.migration_sequence;
                        if migrate.make_primary {
                            self.migrate_to(migrate.new_path_id, migrate.keep_old_path, now)?;
                        }
                    }
                }
                _ => {}
            }
        }
        // Build an ACK if needed.
        let mut ack_payload = response_payload;
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
        Ok(ack_payload)
    }

    fn apply_stream_frame(
        &mut self,
        f: &umc_wire::frames::stream::StreamFrame,
    ) -> Result<(), SessionError> {
        // The low two bits carry initiator and direction. A new stream must
        // be peer-initiated; a bidirectional stream already opened locally
        // may receive data from the peer as well.
        let peer_initiator = match self.role {
            Role::Client => 1,
            Role::Server => 0,
        };
        let local_initiator = 1 - peer_initiator;
        if !self.validate_stream_id(f.stream_id, f.stream_id & 1, f.unidirectional) {
            return Err(SessionError::InvalidStreamId);
        }
        let existing_stream = self.streams.get(&f.stream_id);
        if let Some(stream) = existing_stream {
            if (f.stream_id & 1) == local_initiator && stream.unidirectional {
                return Err(SessionError::InvalidStreamId);
            }
            if stream.unidirectional != f.unidirectional {
                return Err(SessionError::InvalidStreamId);
            }
        } else if (f.stream_id & 1) != peer_initiator {
            return Err(SessionError::InvalidStreamId);
        }
        // A stream id that was closed (final size reached, read to EOF) or
        // reset MUST NOT receive more data (session.md §29).
        if self.closed_streams.contains(f.stream_id) {
            return Err(SessionError::StreamClosed);
        }
        // A new inbound stream is subject to the hard cap (resource-limits.md
        // §20); existing streams keep receiving within their limits.
        if !self.streams.contains_key(&f.stream_id) && self.streams.len() >= MAX_STREAMS_PER_SESSION
        {
            return Err(SessionError::StreamLimit);
        }
        let is_new = !self.streams.contains_key(&f.stream_id);
        let stream = self.streams.entry(f.stream_id).or_insert_with(|| {
            Stream::new(
                f.stream_id,
                f.protocol_id.clone(),
                self.default_max_stream_data,
            )
        });
        if is_new {
            self.peer_initiated_streams += 1;
            stream.unidirectional = f.unidirectional;
        } else if stream.unidirectional != f.unidirectional {
            return Err(SessionError::InvalidStreamId);
        }
        if matches!(
            stream.recv_state,
            super::stream::RecvState::DataRead
                | super::stream::RecvState::ResetRead
                | super::stream::RecvState::ResetRecvd
        ) {
            return Err(SessionError::StreamClosed);
        }
        let new_bytes = stream
            .receive(f.offset, &f.data, f.fin)
            .map_err(SessionError::Stream)?;
        // A fully duplicated segment consumes no flow credit: it was already
        // accounted when first received.
        self.flow
            .consume(new_bytes as u64)
            .map_err(SessionError::Flow)?;
        // Unread bytes drive the local memory watermark. Application reads
        // are tracked separately so credit can be replenished when the
        // receive buffer is drained immediately.
        *self.stream_consumed.entry(f.stream_id).or_insert(0) += new_bytes as u64;
        Ok(())
    }

    /// Apply a peer ACK to the sent-packet state and sample RTT
    /// (congestion.md §8): each newly acknowledged packet yields a sample of
    /// `now - sent_at` minus the peer's reported ack delay; non-positive
    /// samples are skipped. Returns the acknowledged packet numbers.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Ack`] if the ACK acknowledges unsent packets.
    pub fn apply_peer_ack(
        &mut self,
        ack: &umc_wire::frame::AckFrame,
        now: Instant,
    ) -> Result<Vec<u64>, SessionError> {
        let mut flat = Vec::with_capacity(ack.additional_ranges.len() + 1);
        flat.push((ack.first_ack_range, 0));
        flat.extend(ack.additional_ranges.iter().map(|r| (r.gap, r.length)));
        let sent_at_by_pn: HashMap<u64, Instant> = self
            .sent
            .sent()
            .iter()
            .map(|p| (p.packet_number, p.sent_at))
            .collect();
        let size_by_pn: HashMap<u64, usize> = self
            .sent
            .sent()
            .iter()
            .map(|p| (p.packet_number, p.size))
            .collect();
        let acked = self
            .sent
            .apply_ack(ack.largest_acknowledged, &flat)
            .map_err(SessionError::Ack)?;
        for pn in &acked {
            self.retransmit_payloads.remove(pn);
        }
        // Congestion feedback (congestion.md §14.2/§14.3): every acked
        // packet releases its bytes from in-flight, and the aggregate
        // drives window growth (slow start or congestion avoidance).
        let mut acked_bytes = 0usize;
        for pn in &acked {
            if let Some(size) = size_by_pn.get(pn) {
                self.congestion.on_packet_acknowledged(*size);
                acked_bytes += *size;
            }
        }
        if acked_bytes > 0 {
            self.congestion.on_ack(acked_bytes);
        }
        // RFC 9002 §5.3: latest_rtt is sampled only from the newest acked
        // packet (the acked list is ascending by packet number); min_rtt and
        // smoothed_rtt still sample every packet below.
        let newest_sample = acked
            .last()
            .and_then(|pn| sent_at_by_pn.get(pn))
            .map(|sent_at| {
                now.duration_since(*sent_at)
                    .as_millis()
                    .saturating_sub(ack.ack_delay)
            });
        for pn in &acked {
            if let Some(sent_at) = sent_at_by_pn.get(pn) {
                let sample = now
                    .duration_since(*sent_at)
                    .as_millis()
                    .saturating_sub(ack.ack_delay);
                if sample > 0 {
                    self.rtt.sample(sample);
                }
            }
        }
        if let Some(sample) = newest_sample.filter(|s| *s > 0) {
            self.rtt.latest_rtt = sample;
        }
        Ok(acked)
    }

    #[must_use]
    pub fn rtt(&self) -> &RttEstimator {
        &self.rtt
    }

    /// Expected next packet number for a space (the reconstruction anchor
    /// for the AEAD open — the largest received pn plus one).
    #[must_use]
    pub fn expected_pn(&self, space: PacketSpace) -> u64 {
        self.spaces
            .get(&space)
            .map_or(0, |s| s.largest_received().saturating_add(1))
    }

    /// Connection-level flow bytes consumed so far (observability/test
    /// accessor; drives `MAX_DATA` emission).
    #[must_use]
    pub fn flow_consumed(&self) -> u64 {
        self.flow.consumed
    }

    #[must_use]
    pub fn sent_state(&self) -> &AckSendState {
        &self.sent
    }

    pub fn sent_state_mut(&mut self) -> &mut AckSendState {
        &mut self.sent
    }

    /// Replace the congestion controller (tests inject mocks; the daemon
    /// keeps the Reno default).
    pub fn set_congestion_controller(&mut self, controller: Box<dyn CongestionController>) {
        self.congestion = controller;
    }

    /// Mutable access to the congestion controller: the daemon's loss path
    /// feeds [`CongestionController::on_packet_lost`].
    pub fn congestion_mut(&mut self) -> &mut dyn CongestionController {
        self.congestion.as_mut()
    }

    #[must_use]
    pub fn loss_detector(&self) -> &LossDetector {
        &self.loss
    }

    /// Re-send the payload of packet `pn` under a fresh packet number
    /// (session.md §14.3): loss detection drops every lost packet from the
    /// sent queue, so the retained-payload table is the only source. Returns
    /// the freshly built packet bytes, or `None` when `pn` has no retained
    /// payload (never built, already acked, or already retransmitted).
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::NoSpace`] if the session data space is
    /// missing, [`SessionError::Space`] if packet numbers are exhausted, and
    /// [`SessionError::Packet`] if packet assembly fails.
    pub fn retransmit(&mut self, pn: u64, now: Instant) -> Result<Option<Vec<u8>>, SessionError> {
        let Some(payload) = self.retransmit_payloads.get(&pn).cloned() else {
            return Ok(None);
        };
        let bytes = self.build_outbound_inner(self.primary_path_id, now, &payload)?;
        self.retransmit_payloads.remove(&pn);
        Ok(bytes)
    }

    /// Drop the retained payload of a lost packet that must not be
    /// retransmitted (e.g. a non-ack-eliciting packet). The table is keyed
    /// by packet number, so pruning an absent entry is a no-op.
    pub fn prune_retransmit_payload(&mut self, pn: u64) {
        self.retransmit_payloads.remove(&pn);
    }

    /// Reset the idle timer (session.md §22): called by the daemon at
    /// app-originated send sites (echo writer, outbound arm, control
    /// frames) for traffic the session layer cannot observe itself. Probes
    /// and retransmits must NOT call this.
    pub fn touch(&mut self, now: Instant) {
        self.last_activity = Some(now);
    }

    /// The most recent activity instant (session.md §22), or `None` before
    /// the first authenticated packet. Read-only: the daemon's keepalive
    /// sweep measures idle time without mutating the session.
    #[must_use]
    pub fn last_activity(&self) -> Option<Instant> {
        self.last_activity
    }

    /// Whether the idle timeout elapsed since the last activity (session.md
    /// §22). A session with no activity yet (`None`) is never idle: the
    /// timer cannot fire before the first packet.
    #[must_use]
    pub fn idle_expired(&self, now: Instant) -> bool {
        self.last_activity
            .is_some_and(|activity| now.duration_since(activity).as_millis() >= IDLE_TIMEOUT_MS)
    }

    /// Build the `CONNECTION_CLOSE` payload for an idle-timeout close
    /// (session.md §22): a transport close with the `IDLE_TIMEOUT` error
    /// code (wire-format.md §64). Returns `None` while the session is not
    /// idle.
    #[must_use]
    pub fn build_idle_close(&self, now: Instant) -> Option<Vec<u8>> {
        if !self.idle_expired(now) {
            return None;
        }
        let frame = umc_wire::frame::ConnectionCloseFrame {
            error_code: CLOSE_REASON_IDLE_TIMEOUT,
            trigger_frame_type: 0,
            reason: b"idle timeout".to_vec(),
        };
        let enc = frame.encode().ok()?;
        let mut payload = Vec::with_capacity(enc.len());
        umc_wire::varint::encode_into(
            &mut payload,
            umc_types::frame::FrameType::CONNECTION_CLOSE.0,
        )
        .ok()?;
        // The frame's encoding includes its type byte (CONNECTION_CLOSE is a
        // 1-byte varint): strip it and re-prefix the payload with the type.
        payload.extend_from_slice(&enc[1..]);
        Some(payload)
    }

    /// Enter the draining period (session.md §6.4): after sending or
    /// receiving `CONNECTION_CLOSE` the endpoint stops opening streams,
    /// sending application data, and migrating paths. The draining deadline
    /// is at least three times the current probe timeout with a 1-second
    /// minimum. Re-entry is a no-op: an already-draining session never
    /// extends its deadline, and a closed session never transitions
    /// backward.
    pub fn close(&mut self, now: Instant) {
        if self.state != SessionState::Active {
            return;
        }
        self.state = SessionState::Draining;
        let pto_ms = self.loss.pto(&self.rtt).as_millis();
        let drain_ms = (3 * pto_ms).max(MIN_DRAIN_MS);
        self.draining_deadline = Some(now + Duration::from_millis(drain_ms));
    }

    /// Whether the draining period (session.md §6.4) has elapsed; afterwards
    /// the transport state is released via [`Session::finalize_close`].
    #[must_use]
    pub fn draining_expired(&self, now: Instant) -> bool {
        self.draining_deadline
            .is_some_and(|deadline| now >= deadline)
    }

    /// Release the session transport state after the draining period:
    /// transition to `CLOSED` (session.md §6.5).
    pub fn finalize_close(&mut self) {
        self.state = SessionState::Closed;
    }

    /// Build a stateless-reset packet (session.md §31), rate-limited to one
    /// per [`STATELESS_RESET_INTERVAL_MS`] per connection. The daemon calls
    /// this when a packet arrives for a session that no longer exists (an
    /// inbound that failed authentication, or a closed session) and sends
    /// the bytes on the link as ordinary traffic. Returns `None` when the
    /// session has no configured reset secret or the rate limit has not
    /// elapsed.
    pub fn maybe_emit_stateless_reset(
        &mut self,
        now: Instant,
        entropy: &dyn EntropySource,
        trigger_len: usize,
    ) -> Option<Vec<u8>> {
        let secret = self.stateless_reset_secret?;
        if self
            .last_reset_ms
            .is_some_and(|last| now.0.saturating_sub(last) < STATELESS_RESET_INTERVAL_MS)
        {
            return None;
        }
        self.last_reset_ms = Some(now.0);
        let mut reset =
            crate::reset::build_stateless_reset(&crate::reset::reset_token(&secret), entropy);
        // Amplification guard (wire-format.md §76): the reset must be no
        // larger than the triggering packet; small triggers are answered
        // with a shorter reset (never below the minimum packet size).
        let max_len = trigger_len.clamp(crate::reset::MIN_RESET_LEN, reset.len());
        reset.truncate(max_len);
        Some(reset)
    }

    /// Replay-window footprint in bytes for `space` (session.md §8.2): a
    /// fixed 512 bytes no matter how many packets were received.
    #[must_use]
    pub fn replay_bytes(&self, space: PacketSpace) -> Option<usize> {
        self.spaces.get(&space).map(PacketSpaceState::replay_bytes)
    }

    /// Initiate a key update; returns the `KEY_UPDATE` frame payload.
    ///
    /// # Errors
    /// Returns [`SessionError::KeyUpdate`] if a previous update is still
    /// awaiting confirmation, and [`SessionError::Encode`] if frame encoding
    /// fails.
    pub fn initiate_key_update(&mut self) -> Result<Vec<u8>, SessionError> {
        let sequence = self
            .key_update
            .initiate()
            .map_err(|_| SessionError::KeyUpdate)?;
        let frame = umc_wire::frames::path::KeyUpdateFrame {
            update_sequence: sequence,
            request_peer_update: false,
        };
        let enc = frame.encode().map_err(|_| SessionError::Encode)?;
        // The frame's own encoding includes its type varint, which is 2 bytes
        // for KEY_UPDATE (0x44 > 63); strip it by width, not by one byte, and
        // re-prefix the frame payload with the type.
        let type_len = umc_wire::varint::encode(umc_types::frame::FrameType::KEY_UPDATE.0)
            .map_err(|_| SessionError::Encode)?
            .len();
        let mut payload = Vec::with_capacity(enc.len());
        umc_wire::varint::encode_into(&mut payload, umc_types::frame::FrameType::KEY_UPDATE.0)
            .map_err(|_| SessionError::Encode)?;
        payload.extend_from_slice(&enc[type_len..]);
        Ok(payload)
    }

    /// Process a `KEY_UPDATE` frame: derive the peer's next secret and install it
    /// after the first authenticated decrypt (session.md §24.2).
    ///
    /// # Errors
    /// Returns [`SessionError::KeyUpdate`] if the sequence number is neither
    /// the current nor the next expected sequence.
    pub fn on_key_update(&mut self, sequence: u64) -> Result<(), SessionError> {
        if sequence != self.key_update.update_sequence + 1
            && sequence != self.key_update.update_sequence
        {
            return Err(SessionError::KeyUpdate);
        }
        if sequence > self.key_update.update_sequence {
            let next_secret =
                umc_crypto::key_update::next_traffic_secret(&self.key_update.remote_secret);
            self.key_update.confirm_remote_phase(next_secret);
            self.key_update.update_sequence = sequence;
        }
        // An authenticated packet in the new phase confirms; the session loop
        // calls mark_confirmed after decrypting with the new keys.
        self.key_update.mark_confirmed();
        Ok(())
    }

    /// Register a candidate path and start validation (session.md §26).
    ///
    /// # Errors
    /// Returns [`SessionError::PathBudget`] when the candidate-path or
    /// challenge budget is exhausted.
    pub fn add_path(
        &mut self,
        path_id: u64,
        carrier_type: String,
        local: Vec<u8>,
        remote: Vec<u8>,
        now: Instant,
    ) -> Result<(), SessionError> {
        self.add_path_with_challenge(path_id, carrier_type, local, remote, now)
            .map(|_| ())
    }

    /// Register candidate path and return unpredictable challenge bytes that
    /// the caller must send on that path. Keeping challenge ownership in the
    /// session prevents a carrier adapter from fabricating validation state.
    ///
    /// # Errors
    ///
    /// Returns `PathBudget` when the path or challenge budget is exhausted, or
    /// `DirectPathForbidden` when privacy policy rejects the carrier.
    pub fn add_path_with_challenge(
        &mut self,
        path_id: u64,
        carrier_type: String,
        local: Vec<u8>,
        remote: Vec<u8>,
        now: Instant,
    ) -> Result<[u8; 8], SessionError> {
        let mut challenge = [0u8; 8];
        Self::entropy_fill(&mut challenge);
        self.add_path_with_challenge_bytes(path_id, carrier_type, local, remote, now, challenge)
    }

    /// Runtime-backed variant. Daemons MUST pass their OS CSPRNG here; the
    /// deterministic helper above exists only for protocol-pure tests.
    ///
    /// # Errors
    ///
    /// Returns the same path-policy and budget errors as
    /// [`Self::add_path_with_challenge`].
    pub fn add_path_with_entropy(
        &mut self,
        path_id: u64,
        carrier_type: String,
        local: Vec<u8>,
        remote: Vec<u8>,
        now: Instant,
        entropy: &dyn EntropySource,
    ) -> Result<[u8; 8], SessionError> {
        let mut challenge = [0u8; 8];
        entropy.fill(&mut challenge);
        self.add_path_with_challenge_bytes(path_id, carrier_type, local, remote, now, challenge)
    }

    fn add_path_with_challenge_bytes(
        &mut self,
        path_id: u64,
        carrier_type: String,
        local: Vec<u8>,
        remote: Vec<u8>,
        now: Instant,
        challenge: [u8; 8],
    ) -> Result<[u8; 8], SessionError> {
        if self.paths.contains_key(&path_id) {
            return Err(SessionError::PathBudget);
        }
        if !self.direct_path_allowed && is_direct_carrier(&carrier_type) {
            return Err(SessionError::DirectPathForbidden);
        }
        let active = self
            .paths
            .values()
            .filter(|p| {
                matches!(
                    p.state,
                    crate::path::PathState::Validated | crate::path::PathState::Degraded
                )
            })
            .count();
        let validating = self
            .paths
            .values()
            .filter(|p| p.state == crate::path::PathState::Validating)
            .count();
        if active + validating >= 1 + crate::path::MAX_CANDIDATE_PATHS {
            return Err(SessionError::PathBudget);
        }
        let mut path = crate::path::Path::new(path_id, carrier_type, local, remote, now);
        let pto = self.loss.pto(&self.rtt).as_millis();
        path.start_validation(challenge, now, pto)
            .map_err(|_| SessionError::PathBudget)?;
        self.paths.insert(path_id, path);
        Ok(challenge)
    }

    /// `PATH_CHALLENGE` from the peer on a candidate path (session.md §26).
    pub fn on_path_challenge(&mut self, path_id: u64, challenge: [u8; 8]) -> Vec<u8> {
        let mut payload = Vec::new();
        umc_wire::varint::encode_into(&mut payload, umc_types::frame::FrameType::PATH_RESPONSE.0)
            .ok();
        let frame = umc_wire::frames::path::PathResponseFrame { data: challenge };
        if let Ok(enc) = frame.encode() {
            let type_len = umc_wire::varint::encode(umc_types::frame::FrameType::PATH_RESPONSE.0)
                .map_or(0, |encoded| encoded.len());
            if type_len <= enc.len() {
                payload.extend_from_slice(&enc[type_len..]);
            }
        }
        let _ = path_id;
        payload
    }

    /// `PATH_RESPONSE` confirming a challenge on the given path.
    ///
    /// # Errors
    /// Returns [`SessionError::PathNotFound`] for an unknown path and
    /// [`SessionError::PathValidation`] if the response matches no outstanding
    /// challenge.
    pub fn on_path_response(
        &mut self,
        path_id: u64,
        response: [u8; 8],
    ) -> Result<(), SessionError> {
        let path = self
            .paths
            .get_mut(&path_id)
            .ok_or(SessionError::PathNotFound)?;
        path.confirm(&response)
            .map_err(|_| SessionError::PathValidation)?;
        self.last_path_validation = Some(path_id);
        Ok(())
    }

    /// Migrate the primary path (session.md §27): the new path must be
    /// `VALIDATED`; migration never touches packet numbers or stream state.
    ///
    /// # Errors
    /// Returns [`SessionError::PathNotFound`] for an unknown path and
    /// [`SessionError::PathNotValidated`] if the path has not been validated.
    pub fn migrate_to(
        &mut self,
        new_path_id: u64,
        keep_old: bool,
        now: Instant,
    ) -> Result<(), SessionError> {
        let path = self
            .paths
            .get(&new_path_id)
            .ok_or(SessionError::PathNotFound)?;
        if !self.direct_path_allowed && is_direct_carrier(&path.carrier_type) {
            return Err(SessionError::DirectPathForbidden);
        }
        if path.state != crate::path::PathState::Validated {
            return Err(SessionError::PathNotValidated);
        }
        if !keep_old {
            // Retire all other paths.
            let ids: Vec<u64> = self
                .paths
                .keys()
                .copied()
                .filter(|id| *id != new_path_id)
                .collect();
            for id in ids {
                if let Some(p) = self.paths.get_mut(&id) {
                    p.mark_failed();
                }
            }
        }
        let old_path_id = self.primary_path_id;
        self.primary_path_id = new_path_id;
        self.last_path_migration = Some((old_path_id, new_path_id, keep_old));
        let _ = now;
        Ok(())
    }

    /// Current primary path selector. The value is session state, not a
    /// carrier handle, so changing carriers never creates a new app session.
    #[must_use]
    pub const fn primary_path_id(&self) -> u64 {
        self.primary_path_id
    }

    /// Build a MIGRATE frame with a fresh monotonic sequence. The path is not
    /// switched until `migrate_to` succeeds after `PATH_RESPONSE` validation.
    ///
    /// # Errors
    ///
    /// Returns `PathNotFound`, `PathNotValidated`, or `Encode` when the
    /// candidate cannot be selected or the frame cannot be encoded.
    pub fn build_migrate_payload(
        &mut self,
        new_path_id: u64,
        keep_old_path: bool,
        duplicate_critical_frames: bool,
    ) -> Result<Vec<u8>, SessionError> {
        let path = self
            .paths
            .get(&new_path_id)
            .ok_or(SessionError::PathNotFound)?;
        if path.state != crate::path::PathState::Validated {
            return Err(SessionError::PathNotValidated);
        }
        self.next_migration_sequence = self.next_migration_sequence.saturating_add(1);
        umc_wire::frames::path::MigrateFrame {
            old_path_id: self.primary_path_id,
            new_path_id,
            migration_sequence: self.next_migration_sequence,
            make_primary: true,
            keep_old_path,
            duplicate_critical_frames,
        }
        .encode()
        .map_err(|_| SessionError::Encode)
    }

    /// Expose the negotiated destination connection id for runtime routing of
    /// an established-session attach packet.
    #[must_use]
    pub fn dcid(&self) -> &[u8] {
        &self.dcid
    }

    /// Takes the most recent successful path migration for event delivery.
    #[must_use]
    pub fn take_path_migration(&mut self) -> Option<(u64, u64, bool)> {
        self.last_path_migration.take()
    }

    /// Takes the most recent successful path validation for event delivery.
    #[must_use]
    pub fn take_path_validation(&mut self) -> Option<u64> {
        self.last_path_validation.take()
    }

    #[must_use]
    pub fn path(&self, path_id: u64) -> Option<&crate::path::Path> {
        self.paths.get(&path_id)
    }

    /// Mark a path degraded after persistent congestion (congestion.md
    /// §14.4): the state flips to `Degraded` and the path's rtt is marked
    /// stale (`rtt_ms = 0`). Idempotent: a second call is a no-op. Returns
    /// whether the path transitioned, so the daemon can push its one-shot
    /// `path_degraded` event only on the transition. Migration is operator
    /// policy — this accessor only records the degradation; an unknown path
    /// id is a no-op.
    pub fn mark_path_degraded(&mut self, path_id: u64) -> bool {
        let Some(path) = self.paths.get_mut(&path_id) else {
            return false;
        };
        if path.state == crate::path::PathState::Degraded {
            return false;
        }
        path.state = crate::path::PathState::Degraded;
        path.rtt_ms = 0;
        true
    }

    /// Whether the path is currently degraded (congestion.md §14.4).
    #[must_use]
    pub fn is_path_degraded(&self, path_id: u64) -> bool {
        self.paths
            .get(&path_id)
            .is_some_and(|p| p.state == crate::path::PathState::Degraded)
    }

    /// Test helper: mark a path validated without challenge/response. The
    /// daemon drives the real `PATH_CHALLENGE`/`PATH_RESPONSE` flow.
    pub fn force_validate(&mut self, path_id: u64) {
        if let Some(path) = self.paths.get_mut(&path_id) {
            path.validated = true;
            path.state = crate::path::PathState::Validated;
            path.sent_bytes_unvalidated = 0;
            path.received_bytes_unvalidated = 0;
        }
    }

    /// Enables or disables direct-carrier paths for this session.
    pub fn set_direct_path_allowed(&mut self, allowed: bool) {
        self.direct_path_allowed = allowed;
    }

    /// Returns whether direct-carrier paths are permitted.
    #[must_use]
    pub fn direct_path_allowed(&self) -> bool {
        self.direct_path_allowed
    }

    /// Records the transcript-negotiated privacy profile (`p0`..`p3`).
    /// Unknown levels are clamped to the highest profile defined by v1 so a
    /// malformed caller cannot expose an invalid value.
    pub fn set_privacy_profile(&mut self, profile: u8) {
        self.privacy_profile = profile.min(3);
        // P3 traffic shaping is a profile requirement, not a hidden opt-in.
        // An explicit traffic-padding setting may still enable it for lower
        // profiles, but selecting P3 always enables fixed-size data packets.
        if self.privacy_profile >= 3 {
            self.traffic_padding = true;
        }
    }

    /// Returns the transcript-negotiated privacy profile level.
    #[must_use]
    pub fn privacy_profile(&self) -> u8 {
        self.privacy_profile
    }

    /// Issue a fresh connection identifier for the peer and return the
    /// encoded `NEW_CONNECTION_ID` frame that advertises it. The current
    /// packet destination remains unchanged until the peer sends its own
    /// `NEW_CONNECTION_ID`; this method rotates the identifier advertised by
    /// this endpoint without exposing endpoint identity material.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::ConnectionIdLimit`] when the bounded active
    /// CID pool cannot issue another identifier, or [`SessionError::Encode`]
    /// if the advertised frame cannot be encoded.
    pub fn issue_connection_id(
        &mut self,
        entropy: &dyn EntropySource,
    ) -> Result<Vec<u8>, SessionError> {
        let cid = self
            .cids
            .issue(DEFAULT_DCID_LEN, entropy)
            .ok_or(SessionError::ConnectionIdLimit)?;
        let retire_prior_to = cid.sequence.saturating_sub(1);
        if retire_prior_to > 0 {
            let _ = self.cids.retire_prior_to(retire_prior_to);
        }
        umc_wire::frames::path::NewConnectionIdFrame {
            sequence: cid.sequence,
            retire_prior_to,
            connection_id: cid.bytes,
            reset_token: cid.reset_token,
        }
        .encode()
        .map_err(|_| SessionError::Encode)
    }

    /// Returns the destination connection identifier currently used for
    /// outbound packets. This is intentionally opaque to applications; it is
    /// exposed only for transport/session tests and diagnostics.
    #[must_use]
    pub fn destination_connection_id(&self) -> &[u8] {
        &self.dcid
    }

    /// Enables or disables fixed-size padding for application data packets.
    /// Control packets (ACK/PING) and payloads already at or above the target
    /// remain unchanged.
    pub fn set_traffic_padding(&mut self, enabled: bool) {
        self.traffic_padding = enabled;
    }

    /// Returns whether fixed-size traffic padding is enabled.
    #[must_use]
    pub fn traffic_padding_active(&self) -> bool {
        self.traffic_padding
    }

    /// Sets the P3 application-send jitter ceiling in milliseconds. Zero
    /// disables timing jitter for constrained deployments.
    pub fn set_timing_jitter_ms(&mut self, jitter_ms: u64) {
        self.timing_jitter_ms = jitter_ms.min(10_000);
    }

    /// Returns the configured P3 application-send jitter ceiling.
    #[must_use]
    pub fn timing_jitter_ms(&self) -> u64 {
        self.timing_jitter_ms
    }

    fn outbound_payload(&self, payload: &[u8]) -> Vec<u8> {
        if !self.traffic_padding
            || payload_is_exempt(payload)
            || payload.len() >= TRAFFIC_PADDING_TARGET
        {
            return payload.to_vec();
        }
        let mut padded = Vec::with_capacity(TRAFFIC_PADDING_TARGET);
        padded.extend_from_slice(payload);
        padded.resize(TRAFFIC_PADDING_TARGET, 0);
        padded
    }

    fn entropy_fill(out: &mut [u8]) {
        // The session holds no entropy source directly in Phase 4; the daemon
        // supplies challenges through Node. For library tests, a deterministic
        // fill keeps behavior reproducible.
        out.fill(0xAB);
    }
}

fn is_direct_carrier(carrier_type: &str) -> bool {
    !carrier_type.contains("relay") && !carrier_type.contains("route")
}

/// Upper bound on the protected-packet overhead beyond the payload (short
/// header byte, 8-byte dcid, path varint, 2-byte packet number, 16-byte
/// AEAD tag): the congestion gate runs before packet assembly, so the wire
/// size is estimated as `payload.len() + 64`.
const PROTECTED_OVERHEAD_ESTIMATE: usize = 64;

/// Whether `payload`'s first frame is exempt from the send gates. ACK/PING
/// keep recovery alive; `PATH_CHALLENGE/PATH_RESPONSE/MIGRATE` are bounded path
/// control and must be allowed before a candidate path has received bytes.
#[must_use]
pub fn payload_is_exempt(payload: &[u8]) -> bool {
    umc_wire::varint::decode(payload).is_ok_and(|(frame_type, _)| {
        let frame_type = umc_types::frame::FrameType(frame_type);
        frame_type == umc_types::frame::FrameType::ACK
            || frame_type == umc_types::frame::FrameType::PING
            || frame_type == umc_types::frame::FrameType::PATH_CHALLENGE
            || frame_type == umc_types::frame::FrameType::PATH_RESPONSE
            || frame_type == umc_types::frame::FrameType::MIGRATE
    })
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
    /// Delivery on a stream id that was already closed (final size reached
    /// and read, or reset): stream ids MUST NOT be reused (session.md §29).
    StreamClosed,
    /// The peer used an invalid stream initiator or direction bit pattern
    /// (wire-format.md §29).
    InvalidStreamId,
    /// The session already holds [`MAX_STREAMS_PER_SESSION`] concurrent
    /// streams: opening a new one is refused (resource-limits.md §20).
    StreamLimit,
    Ack(super::ack::AckError),
    KeyUpdate,
    PathBudget,
    PathNotFound,
    PathNotValidated,
    /// A MIGRATE frame did not identify this session's current primary path.
    PathMigration,
    PathValidation,
    /// The anti-amplification budget of the unvalidated path is exhausted:
    /// the send would exceed 3x the bytes received on that path
    /// (congestion.md §18). ACK payloads are exempt.
    AmplificationLimit,
    /// The congestion controller's allowance (cwnd minus in-flight) is
    /// exhausted: the send would exceed it (congestion.md §7.1). ACK
    /// payloads are exempt.
    CongestionLimited,
    /// The privacy policy forbids using a direct carrier path for this
    /// session (privacy.md §45).
    DirectPathForbidden,
    /// The bounded connection-ID issuance pool is exhausted.
    ConnectionIdLimit,
    /// The peer sent a stateless reset (session.md §31): the packet could
    /// not be authenticated and carried the session's reset token. The
    /// session transitions to `Closed`; the daemon logs the event and
    /// answers with its own rate-limited reset.
    StatelessReset,
}

impl From<StreamError> for SessionError {
    fn from(e: StreamError) -> Self {
        SessionError::Stream(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestClock;

    impl Clock for TestClock {
        fn now(&self) -> Instant {
            Instant(0)
        }
    }

    struct TestEntropy;

    impl EntropySource for TestEntropy {
        fn fill(&self, out: &mut [u8]) {
            out.fill(0xCD);
        }
    }

    fn session() -> Session {
        Session::new(
            SessionConfig {
                role: Role::Server,
                dcid: vec![0u8; DEFAULT_DCID_LEN],
                local_traffic_secret: [1u8; 32],
                remote_traffic_secret: [2u8; 32],
                initial_max_data: 1_000_000,
                initial_max_stream_data: DEFAULT_INITIAL_MAX_STREAM_DATA,
                max_ack_delay_ms: 25,
            },
            &TestClock,
        )
        .expect("session")
    }

    #[test]
    fn private_path_policy_rejects_direct_carriers() {
        let mut session = session();
        session.set_direct_path_allowed(false);
        assert!(!session.direct_path_allowed());
        assert_eq!(
            session.add_path(1, "ump.tcp/1".into(), vec![], vec![], Instant(0)),
            Err(SessionError::DirectPathForbidden)
        );
        session
            .add_path(1, "ump.relay/1".into(), vec![], vec![], Instant(0))
            .expect("relay path is allowed by the private policy");
        session.force_validate(1);
        session
            .migrate_to(1, true, Instant(0))
            .expect("validated relay path can become primary");
        assert_eq!(session.take_path_migration(), Some((0, 1, true)));
    }

    #[test]
    fn migration_switches_primary_and_keeps_packet_path_state() {
        let mut session = session();
        session
            .add_path_with_entropy(
                1,
                "ump.relay/1".into(),
                vec![],
                vec![],
                Instant(0),
                &TestEntropy,
            )
            .expect("candidate path");
        session.force_validate(1);
        let migrate = session
            .build_migrate_payload(1, true, true)
            .expect("migrate frame");
        assert!(payload_is_exempt(&migrate));
        let packet = session
            .build_outbound_on_path(0, &TestClock, Instant(1), &migrate)
            .expect("packet build")
            .expect("active session");
        session
            .migrate_to(1, true, Instant(1))
            .expect("switch primary");
        assert_eq!(session.primary_path_id(), 1);
        let (_, _, path_id, _, _) = crate::packet::parse_protected_packet(
            &session.local_keys,
            &session.local_hp_key,
            0,
            &packet,
        )
        .expect("packet parses with peer keys");
        assert_eq!(path_id, 0);
    }

    #[test]
    fn validated_path_is_available_to_runtime_event_adapter() {
        let mut session = session();
        session
            .add_path(1, "ump.relay/1".into(), vec![], vec![], Instant(0))
            .expect("candidate path");
        let challenge = session
            .path(1)
            .expect("path")
            .challenges
            .first()
            .expect("challenge")
            .data;
        session
            .on_path_response(1, challenge)
            .expect("path response");
        assert_eq!(session.take_path_validation(), Some(1));
        assert_eq!(session.take_path_validation(), None);
    }

    #[test]
    fn privacy_profile_defaults_to_p0_and_records_negotiation() {
        let mut session = session();
        assert_eq!(session.privacy_profile(), 0);
        assert!(!session.traffic_padding_active());
        session.set_privacy_profile(2);
        assert_eq!(session.privacy_profile(), 2);
        assert!(!session.traffic_padding_active());
        session.set_privacy_profile(99);
        assert_eq!(session.privacy_profile(), 3);
        assert!(session.traffic_padding_active());
    }

    #[test]
    fn timing_jitter_policy_is_bounded() {
        let mut session = session();
        assert_eq!(session.timing_jitter_ms(), 0);
        session.set_timing_jitter_ms(25);
        assert_eq!(session.timing_jitter_ms(), 25);
        session.set_timing_jitter_ms(u64::MAX);
        assert_eq!(session.timing_jitter_ms(), 10_000);
    }

    #[test]
    fn traffic_padding_uniforms_small_data_packets_when_enabled() {
        let mut padded = session();
        padded.set_traffic_padding(true);
        assert!(padded.traffic_padding_active());
        let first = padded
            .build_outbound(&TestClock, Instant(0), &[0x0A, 0x01])
            .expect("first packet")
            .expect("active session");
        let second = padded
            .build_outbound(&TestClock, Instant(1), &[0x0A, 0x01, 0xAA, 0xBB, 0xCC])
            .expect("second packet")
            .expect("active session");
        assert_eq!(first.len(), second.len());

        let mut plain = session();
        let unpadded = plain
            .build_outbound(&TestClock, Instant(0), &[0x0A, 0x01])
            .expect("plain packet")
            .expect("active session");
        assert_ne!(unpadded.len(), first.len());
    }

    #[test]
    fn connection_id_rotation_advertises_bounded_fresh_id() {
        let mut session = session();
        let encoded = session
            .issue_connection_id(&TestEntropy)
            .expect("connection id frame");
        assert_eq!(
            encoded[0],
            u8::try_from(umc_types::frame::FrameType::NEW_CONNECTION_ID.0).unwrap()
        );
        let (frame, used) =
            umc_wire::frames::path::NewConnectionIdFrame::decode(&encoded[1..]).expect("decode");
        assert_eq!(used + 1, encoded.len());
        assert_eq!(frame.connection_id.len(), DEFAULT_DCID_LEN);
        assert_eq!(session.cids.active_count(), 1);
    }

    #[test]
    fn authenticated_new_connection_id_updates_peer_destination() {
        let mut sender = Session::new(
            SessionConfig {
                role: Role::Client,
                dcid: vec![0u8; DEFAULT_DCID_LEN],
                local_traffic_secret: [1u8; 32],
                remote_traffic_secret: [2u8; 32],
                initial_max_data: 1_000_000,
                initial_max_stream_data: DEFAULT_INITIAL_MAX_STREAM_DATA,
                max_ack_delay_ms: 25,
            },
            &TestClock,
        )
        .expect("sender");
        let mut receiver = Session::new(
            SessionConfig {
                role: Role::Server,
                dcid: vec![0u8; DEFAULT_DCID_LEN],
                local_traffic_secret: [2u8; 32],
                remote_traffic_secret: [1u8; 32],
                initial_max_data: 1_000_000,
                initial_max_stream_data: DEFAULT_INITIAL_MAX_STREAM_DATA,
                max_ack_delay_ms: 25,
            },
            &TestClock,
        )
        .expect("receiver");
        let frame = sender
            .issue_connection_id(&TestEntropy)
            .expect("new CID frame");
        let packet = sender
            .build_outbound(&TestClock, Instant(0), &frame)
            .expect("packet")
            .expect("active");
        receiver
            .on_inbound(Instant(0), &packet)
            .expect("authenticated");
        assert_eq!(
            receiver.destination_connection_id(),
            &[0xCD; DEFAULT_DCID_LEN]
        );
    }

    #[test]
    fn inbound_control_frames_update_limits_and_key_phase() {
        let mut sender = Session::new(
            SessionConfig {
                role: Role::Client,
                dcid: vec![0u8; DEFAULT_DCID_LEN],
                local_traffic_secret: [1u8; 32],
                remote_traffic_secret: [2u8; 32],
                initial_max_data: 1_000_000,
                initial_max_stream_data: DEFAULT_INITIAL_MAX_STREAM_DATA,
                max_ack_delay_ms: 25,
            },
            &TestClock,
        )
        .expect("sender");
        let mut receiver = Session::new(
            SessionConfig {
                role: Role::Server,
                dcid: vec![0u8; DEFAULT_DCID_LEN],
                local_traffic_secret: [2u8; 32],
                remote_traffic_secret: [1u8; 32],
                initial_max_data: 1_000_000,
                initial_max_stream_data: DEFAULT_INITIAL_MAX_STREAM_DATA,
                max_ack_delay_ms: 25,
            },
            &TestClock,
        )
        .expect("receiver");

        let mut payload = Vec::new();
        payload.extend_from_slice(
            &umc_wire::frames::flow::MaxDataFrame {
                maximum_data: 2_000_000,
            }
            .encode()
            .expect("max data"),
        );
        payload.extend_from_slice(
            &umc_wire::frames::flow::MaxStreamsFrame {
                bidirectional: true,
                maximum_streams: 32,
            }
            .encode()
            .expect("max streams"),
        );
        let packet = sender
            .build_outbound(&TestClock, Instant(0), &payload)
            .expect("packet")
            .expect("active");
        receiver
            .on_inbound(Instant(0), &packet)
            .expect("control frames");
        assert_eq!(receiver.flow.max_data_remote, 2_000_000);
        assert_eq!(receiver.flow.max_bidirectional_streams_local, 32);

        let key_update = sender.initiate_key_update().expect("key update");
        let packet = sender
            .build_outbound(&TestClock, Instant(1), &key_update)
            .expect("packet")
            .expect("active");
        receiver
            .on_inbound(Instant(1), &packet)
            .expect("key update");
        assert_eq!(receiver.key_update.update_sequence, 1);
    }

    #[test]
    fn inbound_path_challenge_returns_a_decodable_response() {
        let mut sender = Session::new(
            SessionConfig {
                role: Role::Client,
                dcid: vec![0u8; DEFAULT_DCID_LEN],
                local_traffic_secret: [1u8; 32],
                remote_traffic_secret: [2u8; 32],
                initial_max_data: 1_000_000,
                initial_max_stream_data: DEFAULT_INITIAL_MAX_STREAM_DATA,
                max_ack_delay_ms: 25,
            },
            &TestClock,
        )
        .expect("sender");
        let mut receiver = Session::new(
            SessionConfig {
                role: Role::Server,
                dcid: vec![0u8; DEFAULT_DCID_LEN],
                local_traffic_secret: [2u8; 32],
                remote_traffic_secret: [1u8; 32],
                initial_max_data: 1_000_000,
                initial_max_stream_data: DEFAULT_INITIAL_MAX_STREAM_DATA,
                max_ack_delay_ms: 25,
            },
            &TestClock,
        )
        .expect("receiver");
        let challenge = [0xA5; 8];
        let packet = sender
            .build_outbound(
                &TestClock,
                Instant(0),
                &umc_wire::frames::path::PathChallengeFrame { data: challenge }
                    .encode()
                    .expect("challenge"),
            )
            .expect("packet")
            .expect("active");
        let response = receiver.on_inbound(Instant(0), &packet).expect("challenge");
        let frames = umc_wire::frame::decode_frames(&response).expect("response frames");
        assert!(frames.iter().any(|frame| {
            matches!(
                frame,
                umc_wire::frame::Frame::PathResponse(
                    umc_wire::frames::path::PathResponseFrame { data }
                ) if data == &challenge
            )
        }));
    }

    /// Test controller that never limits sends: for tests exercising other
    /// session mechanics (e.g. the outstanding-packet cap) beyond the Reno
    /// window.
    struct UnlimitedCongestion;

    impl CongestionController for UnlimitedCongestion {
        fn on_ack(&mut self, _newly_acked_bytes: usize) {}
        fn on_loss(&mut self, _lost_bytes: usize) {}
        fn on_packet_sent(&mut self, _bytes: usize) {}
        fn on_packet_acknowledged(&mut self, _bytes: usize) {}
        fn on_packet_lost(&mut self, _bytes: usize) {}
        fn send_allowance(&self) -> usize {
            usize::MAX
        }
        fn cwnd(&self) -> usize {
            usize::MAX
        }
        fn in_flight(&self) -> usize {
            0
        }
        fn reset(&mut self) {}
    }

    fn stream_frame(
        stream_id: u64,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) -> umc_wire::frames::stream::StreamFrame {
        umc_wire::frames::stream::StreamFrame {
            stream_id,
            fin,
            offset_present: true,
            len_present: true,
            open: offset == 0,
            unidirectional: false,
            offset,
            data: data.to_vec(),
            protocol_id: vec![],
            metadata: vec![],
        }
    }

    #[test]
    fn closed_stream_id_rejects_further_delivery() {
        let mut s = session();
        // Deliver the full stream (fin at offset 3), read it to EOF.
        s.apply_stream_frame(&stream_frame(0, 0, b"abc", true))
            .unwrap();
        let (data, eof) = s.read_stream(0).unwrap();
        assert_eq!(data, b"abc");
        assert!(eof);
        // The id is closed: more data (even at a valid next offset) fails.
        assert_eq!(
            s.apply_stream_frame(&stream_frame(0, 3, b"x", false)),
            Err(SessionError::StreamClosed)
        );
        // Re-opening the id with OPEN also fails.
        assert_eq!(
            s.apply_stream_frame(&stream_frame(0, 0, b"new", true)),
            Err(SessionError::StreamClosed)
        );
    }

    #[test]
    fn opened_stream_carries_protocol_and_direction_metadata() {
        let mut s = session();
        let stream_id = s
            .open_stream_with_protocol(b"org.example.chat/1", false)
            .expect("open");
        let stream = s.streams.get(&stream_id).expect("stream");
        assert_eq!(stream.protocol_id, b"org.example.chat/1");
        assert_eq!(stream_id & 0x03, 0x01);
    }

    #[test]
    fn stream_ids_encode_role_and_direction() {
        let mut client = Session::new(
            SessionConfig {
                role: Role::Client,
                dcid: vec![0; DEFAULT_DCID_LEN],
                local_traffic_secret: [1; 32],
                remote_traffic_secret: [2; 32],
                initial_max_data: 1_000_000,
                initial_max_stream_data: DEFAULT_INITIAL_MAX_STREAM_DATA,
                max_ack_delay_ms: 25,
            },
            &TestClock,
        )
        .expect("client");
        assert_eq!(client.open_stream().expect("bidi"), 0);
        assert_eq!(
            client
                .open_stream_with_protocol(b"ump.test/1", true)
                .expect("uni"),
            2
        );

        let mut server = session();
        assert_eq!(server.open_stream().expect("bidi"), 1);
        assert_eq!(
            server
                .open_stream_with_protocol(b"ump.test/1", true)
                .expect("uni"),
            3
        );
        assert!(server.validate_stream_id(4, 0, false));
        assert!(server.validate_stream_id(6, 0, true));
        assert!(!server.validate_stream_id(4, 0, true));
        assert!(server.validate_stream_id(1, 1, false));
    }

    #[test]
    fn inbound_stream_rejects_local_initiator_and_direction_mismatch() {
        let mut server = session();
        assert_eq!(
            server.apply_stream_frame(&stream_frame(1, 0, b"bad", true)),
            Err(SessionError::InvalidStreamId)
        );
        assert_eq!(
            server.apply_stream_frame(&stream_frame(2, 0, b"bad", true)),
            Err(SessionError::InvalidStreamId)
        );
    }

    #[test]
    fn application_control_frames_are_encoded_from_session_state() {
        let mut s = session();
        let stream_id = s
            .open_stream_with_protocol(b"org.example.chat/1", false)
            .expect("open");
        let fin = s.close_stream_send_payload(stream_id).expect("fin");
        assert_eq!(
            umc_wire::varint::decode(&fin).unwrap().0,
            umc_types::frame::FrameType::STREAM.0
        );
        let reset = s.reset_stream_payload(stream_id, 17).expect("reset");
        assert_eq!(
            umc_wire::varint::decode(&reset).unwrap().0,
            umc_types::frame::FrameType::RESET_STREAM.0
        );
        let stop = s.stop_stream_payload(stream_id, 19).expect("stop");
        assert_eq!(
            umc_wire::varint::decode(&stop).unwrap().0,
            umc_types::frame::FrameType::STOP_SENDING.0
        );
    }

    #[test]
    fn queued_datagram_can_be_encoded_for_transport() {
        let mut s = session();
        s.send_datagram(
            crate::datagram::Datagram {
                context_id: 5,
                data: b"hello".to_vec(),
                expires_at_ms: None,
                ack_requested: true,
            },
            1_200,
        )
        .expect("queue");
        let payload = s.pop_outbound_datagram_payload(10).expect("payload");
        assert_eq!(
            umc_wire::varint::decode(&payload).unwrap().0,
            umc_types::frame::FrameType::DATAGRAM.0
        );
    }

    #[test]
    fn unread_final_size_is_not_closed() {
        let mut s = session();
        // FIN received but never read: not yet closed, delivery continues.
        s.apply_stream_frame(&stream_frame(4, 0, b"abc", true))
            .unwrap();
        assert!(s
            .apply_stream_frame(&stream_frame(4, 0, b"abc", true))
            .is_ok());
    }

    #[test]
    fn closed_stream_registry_evicts_fifo() {
        let mut registry = ClosedStreamRegistry::default();
        for id in 0..MAX_CLOSED_STREAM_IDS as u64 * 2 {
            registry.insert(id);
        }
        assert_eq!(registry.len(), MAX_CLOSED_STREAM_IDS);
        // The oldest ids were evicted; the newest survive.
        assert!(!registry.contains(0));
        assert!(registry.contains(MAX_CLOSED_STREAM_IDS as u64));
    }

    #[test]
    fn apply_peer_ack_rejects_zero_first_range() {
        let mut s = session();
        s.sent.record_sent(SentPacket::new(
            1,
            PacketSpace::SessionData,
            Instant(0),
            64,
            true,
            0,
        ));
        let ack = umc_wire::frame::AckFrame {
            largest_acknowledged: 1,
            ack_delay: 0,
            first_ack_range: 0,
            additional_ranges: Vec::new(),
        };
        assert_eq!(
            s.apply_peer_ack(&ack, Instant(5)),
            Err(SessionError::Ack(crate::ack::AckError::EmptyRange))
        );
    }

    #[test]
    fn latest_rtt_comes_from_newest_acked_packet() {
        let mut s = session();
        s.sent.record_sent(SentPacket::new(
            1,
            PacketSpace::SessionData,
            Instant(10),
            64,
            true,
            0,
        ));
        s.sent.record_sent(SentPacket::new(
            2,
            PacketSpace::SessionData,
            Instant(40),
            64,
            true,
            0,
        ));
        let ack = umc_wire::frame::AckFrame {
            largest_acknowledged: 2,
            ack_delay: 0,
            first_ack_range: 2,
            additional_ranges: Vec::new(),
        };
        let acked = s.apply_peer_ack(&ack, Instant(50)).unwrap();
        assert_eq!(acked, vec![1, 2]);
        // latest_rtt samples only the newest acked packet (RFC 9002 §5.3);
        // min_rtt still reflects every packet.
        assert_eq!(s.rtt().latest_rtt, 10);
        assert_eq!(s.rtt().min_rtt, 10);
    }

    #[test]
    fn mark_path_degraded_idempotent() {
        let mut s = session();
        s.add_path(0, "ump.tcp/1".into(), vec![], vec![], Instant(0))
            .unwrap();
        assert!(!s.is_path_degraded(0));
        // First call transitions the path (Validating -> Degraded) and marks
        // its rtt stale; the second call is a no-op (one-shot degradation).
        assert!(s.mark_path_degraded(0));
        assert!(s.is_path_degraded(0));
        assert_eq!(s.path(0).unwrap().state, crate::path::PathState::Degraded);
        assert_eq!(s.path(0).unwrap().rtt_ms, 0);
        assert!(!s.mark_path_degraded(0));
        assert!(s.is_path_degraded(0));
        // An unknown path id never transitions.
        assert!(!s.mark_path_degraded(99));
        assert!(!s.is_path_degraded(99));
    }

    #[test]
    fn cap_eviction_prunes_retransmit_payload() {
        let mut s = session();
        // The cap test fills the outstanding queue far beyond the Reno
        // window, so the congestion gate must not interfere: inject a
        // controller that never limits sends.
        s.set_congestion_controller(Box::new(UnlimitedCongestion));
        // Fill the outstanding queue to the cap, then one more build
        // evicts the oldest ack-eliciting packet (pn 0).
        for i in 0..=crate::ack::MAX_OUTSTANDING_PACKETS as u64 {
            s.build_outbound(&TestClock, Instant(i), b"x")
                .unwrap()
                .expect("built packet");
        }
        // The evicted packet is beyond recovery: its payload was pruned, so
        // retransmission finds nothing.
        assert_eq!(s.retransmit(0, Instant(0)).unwrap(), None);
    }
}
