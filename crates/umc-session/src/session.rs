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
use umc_types::runtime::{Clock, Duration, Instant};
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

#[derive(Debug)]
pub struct Session {
    pub role: Role,
    pub state: SessionState,
    local_keys: PacketKeys,
    remote_keys: PacketKeys,
    spaces: HashMap<PacketSpace, PacketSpaceState>,
    sent: AckSendState,
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
    closed_streams: ClosedStreamRegistry,
    flow: FlowControl,
    datagrams: DatagramQueue,
    dcid: Vec<u8>,
    key_update: crate::key_update::KeyUpdateState,
    pub paths: HashMap<u64, crate::path::Path>,
    #[allow(dead_code)]
    cids: crate::cid::ConnectionIdManager,
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
            retransmit_payloads: HashMap::new(),
            recv_acks: HashMap::new(),
            rtt: RttEstimator::new(),
            loss: LossDetector::new(config.max_ack_delay_ms),
            streams: HashMap::new(),
            next_outgoing_stream: 0,
            closed_streams: ClosedStreamRegistry::default(),
            flow: FlowControl::new(config.initial_max_data, INITIAL_STREAMS, INITIAL_STREAMS),
            datagrams: DatagramQueue::new(),
            dcid: config.dcid,
            key_update: crate::key_update::KeyUpdateState::new(
                config.local_traffic_secret,
                config.remote_traffic_secret,
            ),
            paths: HashMap::new(),
            cids: crate::cid::ConnectionIdManager::new(crate::cid::DEFAULT_ACTIVE_LIMIT),
            last_activity: None,
            draining_deadline: None,
        })
    }

    /// Open a new initiator-bidirectional stream.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::StreamLimit`] when the session already holds
    /// [`MAX_STREAMS_PER_SESSION`] concurrent streams (resource-limits.md
    /// §20).
    pub fn open_stream(&mut self) -> Result<u64, SessionError> {
        if self.streams.len() >= MAX_STREAMS_PER_SESSION {
            return Err(SessionError::StreamLimit);
        }
        let id = self.next_outgoing_stream;
        self.next_outgoing_stream += 2; // initiator bidirectional: low bits 00
        let max_data = self.flow.max_data_remote;
        self.streams
            .insert(id, Stream::new(id, Vec::new(), max_data));
        Ok(id)
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
        let (data, eof) = stream.read_available();
        if eof {
            // The final size was reached and read: the id is closed and any
            // further delivery on it is a protocol violation (session.md §29).
            self.closed_streams.insert(stream_id);
        }
        Ok((data, eof))
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
        self.build_outbound_inner(now, payload)
    }

    fn build_outbound_inner(
        &mut self,
        now: Instant,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, SessionError> {
        if self.state != SessionState::Active {
            return Ok(None);
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
        let sent = SentPacket::new(
            pn,
            PacketSpace::SessionData,
            now,
            payload.len() + 64,
            true,
            0,
        );
        self.retransmit_payloads.insert(pn, payload.to_vec());
        if let Some(lost_pn) = self.sent.record_sent(sent) {
            // Cap eviction (MAX_OUTSTANDING_PACKETS): the evicted packet is
            // beyond recovery, so drop its retained payload. The daemon's
            // loss handling does not need to know about cap evictions — the
            // packet number is gone from both structures (resource-limits.md
            // §24).
            self.retransmit_payloads.remove(&lost_pn);
        }
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
        // Reject duplicates/stale packets BEFORE touching the idle timer: a
        // replayed packet must not keep a zombie session alive (session.md
        // §22).
        let pn = space_state
            .admit_received(truncated_pn, 16)
            .map_err(SessionError::Space)?;
        self.recv_acks.entry(space).or_default().record(pn);
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
                umc_wire::frame::Frame::Ack(ack) => {
                    self.apply_peer_ack(&ack, now)?;
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
        Ok(ack_payload)
    }

    fn apply_stream_frame(
        &mut self,
        f: &umc_wire::frames::stream::StreamFrame,
    ) -> Result<(), SessionError> {
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
        let stream = self.streams.entry(f.stream_id).or_insert_with(|| {
            Stream::new(f.stream_id, f.protocol_id.clone(), self.flow.max_data_local)
        });
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
            .map_err(SessionError::Flow)
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
        let acked = self
            .sent
            .apply_ack(ack.largest_acknowledged, &flat)
            .map_err(SessionError::Ack)?;
        for pn in &acked {
            self.retransmit_payloads.remove(pn);
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

    #[must_use]
    pub fn sent_state(&self) -> &AckSendState {
        &self.sent
    }

    pub fn sent_state_mut(&mut self) -> &mut AckSendState {
        &mut self.sent
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
        let bytes = self.build_outbound_inner(now, &payload)?;
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
        let mut challenge = [0u8; 8];
        Self::entropy_fill(&mut challenge);
        let mut path = crate::path::Path::new(path_id, carrier_type, local, remote, now);
        let pto = self.loss.pto(&self.rtt).as_millis();
        path.start_validation(challenge, now, pto)
            .map_err(|_| SessionError::PathBudget)?;
        self.paths.insert(path_id, path);
        Ok(())
    }

    /// `PATH_CHALLENGE` from the peer on a candidate path (session.md §26).
    pub fn on_path_challenge(&mut self, path_id: u64, challenge: [u8; 8]) -> Vec<u8> {
        let mut payload = Vec::new();
        umc_wire::varint::encode_into(&mut payload, umc_types::frame::FrameType::PATH_RESPONSE.0)
            .ok();
        let frame = umc_wire::frames::path::PathResponseFrame { data: challenge };
        if let Ok(enc) = frame.encode() {
            payload.extend_from_slice(&enc[1..]);
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
            .map_err(|_| SessionError::PathValidation)
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
        let _ = now;
        Ok(())
    }

    #[must_use]
    pub fn path(&self, path_id: u64) -> Option<&crate::path::Path> {
        self.paths.get(&path_id)
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

    fn entropy_fill(out: &mut [u8]) {
        // The session holds no entropy source directly in Phase 4; the daemon
        // supplies challenges through Node. For library tests, a deterministic
        // fill keeps behavior reproducible.
        out.fill(0xAB);
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
    /// Delivery on a stream id that was already closed (final size reached
    /// and read, or reset): stream ids MUST NOT be reused (session.md §29).
    StreamClosed,
    /// The session already holds [`MAX_STREAMS_PER_SESSION`] concurrent
    /// streams: opening a new one is refused (resource-limits.md §20).
    StreamLimit,
    Ack(super::ack::AckError),
    KeyUpdate,
    PathBudget,
    PathNotFound,
    PathNotValidated,
    PathValidation,
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
    fn cap_eviction_prunes_retransmit_payload() {
        let mut s = session();
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
