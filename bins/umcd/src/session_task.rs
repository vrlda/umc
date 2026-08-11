//! Wire session loop (core.md §8): read inbound packets off the link, feed
//! the session state machine, send the ACK payloads it produces, and
//! dispatch stream data to registered applications (core.md §9.6).
//!
//! Two tasks share the session: the reader feeds `on_inbound` and forwards
//! matching streams into the application's inbound channel, while the
//! session writer drains the application's outbound channel and sends the
//! echoes back on the same stream. The link recv is blocking, so the echo
//! drain must run on its own task to reach the peer without waiting for
//! more inbound traffic.
//!
//! The session layer applies stream, datagram, and ACK semantics only; the
//! relay, bundle, routing, and key-update frames riding the same protected
//! packets are parsed here (with a key copy held by the daemon) and
//! dispatched to the runtime services (core.md §8).
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::task::JoinHandle;
use umc_carrier::error::CarrierErrorKind;
use umc_carrier::types::OutboundPacket;
use umc_carrier::BoxLink;
use umc_core::app_io::{AppRx, AppTx};
use umc_crypto::aead::PacketKeys;
use umc_session::loss::{detect_lost_packets, PtoState};
use umc_session::session::{
    payload_is_exempt, Session, SessionError, SessionState, IDLE_TIMEOUT_MS,
};
use umc_session::stream::StreamError;
use umc_types::runtime::{Clock, Instant};
use umc_wire::frame::Frame;
use umc_wire::frames::bundle::{BundleFrame, MAX_BUNDLE_PAYLOAD};
use umc_wire::frames::relay::{RelayCloseFrame, RelayOpenFrame, RelayStatusFrame};

/// Opaque destination handle carried by a P2 relay circuit.  A relay routes
/// this token through its locally learned route table; it never needs the
/// destination endpoint id that originated the request (privacy.md §§9-12).
const PRIVATE_ROUTE_TOKEN_PREFIX: &[u8] = b"UMP-P2-ROUTE\0";
const PRIVATE_ROUTE_TOKEN_NONCE_LEN: usize = 16;

/// Build the stable, non-reversible destination token used by private relay
/// construction.  The route cache is keyed by the same hash, so each relay
/// can resolve only its immediate next leg from local authenticated evidence.
#[must_use]
#[allow(dead_code)]
pub fn privacy_route_token(destination: &[u8]) -> Vec<u8> {
    privacy_route_token_with_nonce(destination, [0u8; PRIVATE_ROUTE_TOKEN_NONCE_LEN])
}

/// Build a route-scoped token with caller-provided entropy. The destination
/// hash remains the lookup handle, while the nonce prevents repeated private
/// connections from sharing a stable route identifier.
#[must_use]
pub fn privacy_route_token_with_nonce(
    destination: &[u8],
    nonce: [u8; PRIVATE_ROUTE_TOKEN_NONCE_LEN],
) -> Vec<u8> {
    let mut token =
        Vec::with_capacity(PRIVATE_ROUTE_TOKEN_PREFIX.len() + 32 + PRIVATE_ROUTE_TOKEN_NONCE_LEN);
    token.extend_from_slice(PRIVATE_ROUTE_TOKEN_PREFIX);
    token.extend_from_slice(&hash_destination(destination));
    token.extend_from_slice(&nonce);
    token
}

fn decode_privacy_route_token(token: &[u8]) -> Option<[u8; 32]> {
    let hash = token.strip_prefix(PRIVATE_ROUTE_TOKEN_PREFIX)?;
    let hash = hash.get(..32)?;
    if token.len() != PRIVATE_ROUTE_TOKEN_PREFIX.len() + 32 + PRIVATE_ROUTE_TOKEN_NONCE_LEN {
        return None;
    }
    hash.try_into().ok()
}
use umc_wire::frames::routing::RouteResponseFrame;
use umc_wire::header::ShortPacketSpace;
use umc_wire::packet::{parse_payload, PacketContext};

use crate::relay_auth::RelayAuthorization;
use crate::relay_link::RelayLink;
use crate::relay_service::{CircuitOpenRequest, RelayOpenDisposition};
use crate::runtime_adapters::OsEntropy;
use crate::session_manager::SessionLinkSet;
use crate::state::{metric_names, RuntimeState};
use umc_routing::paths::{
    decode_path_metadata, encode_path_metadata, PathHop, PathPolicy, PATH_METADATA_MAGIC,
};
use umc_routing::response::validate_response;

/// Poll interval when the link reports `WouldBlock`.
pub const RECV_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Poll interval of the echo drain when no echo is pending.
pub const ECHO_POLL_INTERVAL: Duration = Duration::from_millis(5);
/// Period of the reader's idle/draining sweep (session.md §6.4, §22). The
/// sweep only checks the session's idle and draining timers; it never
/// touches the PTO schedule.
pub const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// Pause after processing a packet before the next blocking recv. The TCP
/// carrier serializes reads and writes behind one mutex, so a recv in
/// flight starves the carrier's background writer; the pause gives queued
/// ACKs and echoes a window to flush (carriers/tcp.md).
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(5);
/// The daemon initiates a key update after this much session lifetime
/// (session.md §24): every 10 minutes, while the previous update has
/// completed.
pub const KEY_UPDATE_INTERVAL_MS: u64 = 10 * 60 * 1000;
/// Rotate the endpoint's advertised connection ID on the same cadence as
/// key updates (privacy.md §7, session.md §30).
pub const DCID_ROTATION_INTERVAL_MS: u64 = 10 * 60 * 1000;
/// Pending-bundle delivery sweep interval (bundles.md §10.1).
pub const BUNDLE_FLUSH_INTERVAL_MS: u64 = 30 * 1000;
/// Maximum bundle frames wrapped per delivery sweep; bundle payloads can
/// approach the packet-size cap, so sweeps drip at most one frame per
/// sweep (the 30s interval bounds the drip).
pub const BUNDLES_PER_FLUSH: usize = 1;
/// Headroom reserved for packet headers and AEAD tags when fitting a
/// `BUNDLE` frame into a protected packet (wire-format §17).
pub const BUNDLE_PACKET_HEADROOM: usize = 256;
/// Leave room for the bundle header, destination hint, and AEAD overhead so
/// every packet-sized chunk remains encodable on the wire.
pub const BUNDLE_FRAME_CHUNK_SIZE: usize = MAX_BUNDLE_PAYLOAD.saturating_sub(1_024);

/// `RELAY_STATUS` result codes (relay.md §12.2).
pub const RELAY_STATUS_PENDING: u64 = 0;
pub const RELAY_STATUS_ACCEPTED: u64 = 1;
pub const RELAY_STATUS_REFUSED: u64 = 2;
pub const RELAY_STATUS_NO_ROUTE: u64 = 3;
pub const RELAY_STATUS_AUTH_FAILED: u64 = 4;
pub const RELAY_STATUS_RESOURCE_LIMIT: u64 = 5;
pub const RELAY_STATUS_DESTINATION_REJECTED: u64 = 6;
pub const RELAY_STATUS_DEGRADED: u64 = 7;
pub const RELAY_STATUS_QUOTA_WARNING: u64 = 8;
pub const RELAY_STATUS_EXPIRING: u64 = 9;
pub const RELAY_STATUS_CLOSED: u64 = 10;
pub const RELAY_STATUS_UNSUPPORTED_FLAGS: u64 = 11;
const RELAY_STATUS_CODES: [u64; 12] = [
    RELAY_STATUS_PENDING,
    RELAY_STATUS_ACCEPTED,
    RELAY_STATUS_REFUSED,
    RELAY_STATUS_NO_ROUTE,
    RELAY_STATUS_AUTH_FAILED,
    RELAY_STATUS_RESOURCE_LIMIT,
    RELAY_STATUS_DESTINATION_REJECTED,
    RELAY_STATUS_DEGRADED,
    RELAY_STATUS_QUOTA_WARNING,
    RELAY_STATUS_EXPIRING,
    RELAY_STATUS_CLOSED,
    RELAY_STATUS_UNSUPPORTED_FLAGS,
];
/// Routing error-code registry (routing.md §27). Values are stable on the
/// wire even though diagnostics remain intentionally sparse.
pub const ROUTE_NOT_FOUND: u64 = 1;
pub const ROUTE_RESOURCE_LIMIT: u64 = 3;
pub const ROUTE_EXPIRED: u64 = 4;
pub const ROUTE_POLICY_REJECTED: u64 = 5;

/// Ticket-issuance material for one session (handshake.md §35): the daemon
/// seals the session's resumption secret into a session ticket when the
/// session closes cleanly (the idle-close path) so the peer can resume with
/// IK mode. `None` for resumed sessions: the v1 scheme issues no tickets on
/// resumed sessions (a single resumption hop; a fresh full handshake
/// re-arms the chain).
#[derive(Debug, Clone)]
pub struct TicketMaterial {
    /// The daemon's session-ticket key (`RuntimeState::ticket_key`).
    pub ticket_key: [u8; 32],
    /// The session's shared resumption secret (handshake.md §26).
    pub resumption_secret: [u8; 32],
    /// The peer's endpoint id, bound into the ticket.
    pub peer_endpoint_id: [u8; 32],
    /// This node's endpoint id, bound into the ticket.
    pub server_endpoint_id: [u8; 32],
}

/// Runtime traffic-defense policy derived once from local config and the
/// negotiated privacy floor. P3 enables padding, bounded timing jitter, and
/// policy-controlled route/CID rotation; cover packets remain opt-in.
#[derive(Debug, Clone, Copy)]
pub struct PrivacyRuntimePolicy {
    profile: u8,
    traffic_padding: bool,
    timing_jitter_ms: u64,
    cover_traffic: bool,
    cover_interval_ms: u64,
    cover_budget_bps: u64,
    route_rotation_interval_ms: u64,
}

impl PrivacyRuntimePolicy {
    #[must_use]
    pub fn from_config(
        profile: u8,
        traffic_padding: bool,
        timing_jitter_ms: u64,
        cover_traffic: bool,
        cover_interval_ms: u64,
        cover_budget_bps: u64,
        route_rotation_interval_ms: u64,
    ) -> Self {
        let profile = profile.min(3);
        Self {
            profile,
            traffic_padding: traffic_padding || profile >= 3,
            timing_jitter_ms: if profile >= 3 {
                timing_jitter_ms.min(10_000)
            } else {
                0
            },
            cover_traffic: cover_traffic && profile >= 3,
            cover_interval_ms: cover_interval_ms.clamp(100, 60_000),
            cover_budget_bps: cover_budget_bps.min(64 * 1_024),
            route_rotation_interval_ms: route_rotation_interval_ms
                .clamp(60_000, 24 * 60 * 60 * 1_000),
        }
    }

    #[must_use]
    pub const fn profile(self) -> u8 {
        self.profile
    }

    #[must_use]
    pub const fn traffic_padding(self) -> bool {
        self.traffic_padding
    }

    #[must_use]
    pub const fn timing_jitter_ms(self) -> u64 {
        self.timing_jitter_ms
    }

    #[must_use]
    pub const fn cover_traffic(self) -> bool {
        self.cover_traffic
    }

    #[must_use]
    pub const fn cover_interval_ms(self) -> u64 {
        self.cover_interval_ms
    }

    #[must_use]
    pub const fn cover_budget_bps(self) -> u64 {
        self.cover_budget_bps
    }

    #[must_use]
    pub const fn route_rotation_interval_ms(self) -> u64 {
        self.route_rotation_interval_ms
    }
}

/// Build the encoded `SESSION_TICKET` frame for a session's clean close
/// (handshake.md §35): a fresh ticket sealing the session's resumption
/// secret under the daemon's ticket key, one per session close. The frame's
/// own nonce field stays empty — the ticket carries its nonce in the v1
/// clear prefix.
#[must_use]
fn build_session_ticket(
    material: &TicketMaterial,
    now_ms: u64,
    entropy: &dyn umc_types::runtime::EntropySource,
) -> Option<Vec<u8>> {
    let mut nonce = [0u8; umc_handshake::ticket::TICKET_ENTROPY];
    entropy.fill(&mut nonce);
    let mut ticket_id = [0u8; 16];
    entropy.fill(&mut ticket_id);
    let payload = umc_handshake::ticket::TicketPayload {
        version: umc_handshake::ticket::TICKET_VERSION,
        ticket_id,
        client_endpoint_id_hash: material.peer_endpoint_id,
        server_endpoint_id_hash: material.server_endpoint_id,
        resumption_secret: material.resumption_secret,
        issued_at_ms: now_ms,
        expires_at_ms: now_ms.saturating_add(umc_handshake::ticket::MAX_TICKET_LIFETIME_MS),
        protocol_version: umc_handshake::xx::SUPPORTED_PROTOCOL_VERSION,
        crypto_profile: umc_handshake::xx::CRYPTO_PROFILE.to_vec(),
        nonce,
    };
    let ticket = umc_handshake::ticket::issue_ticket(&material.ticket_key, &payload);
    umc_wire::frames::handshake::SessionTicketFrame {
        lifetime: umc_handshake::ticket::MAX_TICKET_LIFETIME_MS,
        age_add: 0,
        nonce: Vec::new(),
        ticket,
    }
    .encode()
    .ok()
}

/// Sleep until the PTO deadline, or forever when no deadline is armed.
async fn pto_sleep(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// PTO deadline offset from the session's in-flight state and backoff state
/// (session.md §14.3, congestion.md §10.3): a probe fires `pto * multiplier`
/// ms after the last arming while any ack-eliciting packet is outstanding;
/// no deadline when nothing is in flight.
fn pto_deadline_ms(session: &Session, pto_state: &PtoState) -> Option<u64> {
    let in_flight = session
        .sent_state()
        .sent()
        .iter()
        .any(|p| p.ack_eliciting && p.in_flight);
    if !in_flight {
        return None;
    }
    let pto = session.loss_detector().pto(session.rtt());
    Some(pto_state.next_deadline(pto, Instant(0)).0)
}

/// PTO deadline from the session's in-flight state (session.md §14.3): a
/// probe fires `pto * multiplier` after the last arming while any
/// ack-eliciting packet is outstanding; no deadline when nothing is in
/// flight.
fn pto_deadline_at(session: &Session, pto_state: &PtoState) -> Option<tokio::time::Instant> {
    Some(tokio::time::Instant::now() + Duration::from_millis(pto_deadline_ms(session, pto_state)?))
}

/// PTO deadline for the next loop iteration. An armed deadline is kept while
/// ack-eliciting packets remain in flight and cleared once they are all
/// acknowledged; with nothing armed the deadline is armed from now whenever
/// ack-eliciting packets are in flight (which covers every send site: the
/// session writer, the bus, probes, and retransmits). Plain inbound
/// processing, retransmits, and new sends never extend an armed deadline, so
/// sustained traffic cannot push the probe out (RFC 9002 §6.2.1 arms the PTO
/// timer only when it is not already set).
fn pto_deadline_after(
    session: &Session,
    pto_state: &PtoState,
    armed: Option<tokio::time::Instant>,
) -> Option<tokio::time::Instant> {
    let in_flight = session
        .sent_state()
        .sent()
        .iter()
        .any(|p| p.ack_eliciting && p.in_flight);
    if !in_flight {
        return None;
    }
    armed.or_else(|| pto_deadline_at(session, pto_state))
}

/// One idle/draining sweep on the reader's 1 s interval arm (session.md
/// §6.4, §22): when the session has been idle past the timeout while still
/// `Active`, build a `CONNECTION_CLOSE` packet — carrying the session
/// ticket (handshake.md §35) when `ticket_material` is present — and enter
/// draining; once the draining deadline has passed, finalize the close.
/// Returns the built idle close packet and the built keepalive ping (the
/// caller sends them after dropping the session guard) and whether the
/// reader loop should exit (the draining period ended).
///
/// When the session is `Active` but not yet idle-expired, an idle time of at
/// least half the timeout builds a `PING` keepalive (session.md §22) and
/// resets the idle timer, so a quiet-but-live circuit is never closed by
/// the sweep. The close path takes precedence: an idle-expired session is
/// closed, not kept alive.
fn handle_idle_timers(
    session: &mut Session,
    clock: &dyn Clock,
    now: Instant,
    ticket_material: Option<&TicketMaterial>,
) -> (Option<Vec<u8>>, Option<Vec<u8>>, bool) {
    if session.draining_expired(now) {
        session.finalize_close();
        return (None, None, true);
    }
    if session.state == SessionState::Active && session.idle_expired(now) {
        // The clean-close path (handshake.md §35): one ticket rides the
        // final `CONNECTION_CLOSE` packet, so the peer can resume after the
        // close. Issued once — the session is closed right after.
        let mut close_payload = session.build_idle_close(now);
        if let (Some(payload), Some(material)) = (&mut close_payload, ticket_material) {
            if let Some(ticket_frame) = build_session_ticket(material, now.0, &OsEntropy) {
                payload.extend_from_slice(&ticket_frame);
            }
        }
        let built = close_payload
            .and_then(|payload| session.build_outbound(clock, now, &payload).ok().flatten());
        session.close(now);
        return (built, None, false);
    }
    // Keepalive (session.md §22): half the idle timeout into a quiet Active
    // session, build a PING and reset the idle timer. The touch suppresses
    // the idle close for another full timeout.
    if session.state == SessionState::Active {
        let half_idle = IDLE_TIMEOUT_MS / 2;
        let idle_since = session
            .last_activity()
            .map(|activity| now.duration_since(activity).as_millis());
        if idle_since.is_some_and(|idle| idle >= half_idle) {
            let ping =
                umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap_or_default();
            let built = session.build_outbound(clock, now, &ping).ok().flatten();
            if built.is_some() {
                session.touch(now);
            }
            return (None, built, false);
        }
    }
    (None, None, false)
}

/// Spawn the per-session wire loop. The tasks exit when `link.recv` errors
/// or the daemon's shutdown flag is set.
///
/// `app_channels` maps a protocol ID to the inbound channel of the
/// application registered under it; stream data received on a matching
/// protocol ID is forwarded there. `app_echo_rx` holds the applications'
/// outbound receivers; the session writer drains them and sends the frames
/// back on the same stream IDs.
///
/// `runtime` is the daemon's shared state; the reader locks it only when an
/// inbound packet carries control frames (relay/bundle/routing/key-update)
/// or a delivery sweep is due, so contention with the control socket stays
/// low. `remote_keys` is the daemon's copy of the peer's traffic keys for
/// parsing the control frames the session layer does not expose, with
/// `remote_hp_key` its header-protection key (wire-format §18).
///
/// The session's bus channels are registered by the caller (which holds the
/// runtime state lock at the spawn site) with the tx sides of
/// `bus_inbound_rx` and `bus_outbound_rx`; the reader selects over the
/// carrier pump, the bus-inbound channel, and the bus-outbound channel.
pub struct SpawnedSession {
    pub task: JoinHandle<()>,
    pub session: Arc<tokio::sync::Mutex<Session>>,
    pub link: Arc<BoxLink>,
    pub links: Arc<SessionLinkSet>,
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)] // shared runtime handles cloned for the spawned tasks
pub fn spawn_session_task(
    clock: Arc<dyn Clock>,
    shutdown_flag: Arc<AtomicBool>,
    link: BoxLink,
    session: Session,
    session_id: u64,
    app_channels: Arc<Mutex<HashMap<Vec<u8>, AppTx>>>,
    app_echo_rx: Arc<Mutex<HashMap<Vec<u8>, AppRx>>>,
    runtime: Arc<Mutex<RuntimeState>>,
    privacy_policy: PrivacyRuntimePolicy,
    remote_keys: PacketKeys,
    remote_hp_key: [u8; 32],
    ticket_material: Option<TicketMaterial>,
    bus_inbound_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    bus_outbound_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) -> SpawnedSession {
    let links = SessionLinkSet::single(umc_session::packet::DEFAULT_PATH_ID, link);
    let link = links
        .get(umc_session::packet::DEFAULT_PATH_ID)
        .expect("initial session path");
    let session = Arc::new(tokio::sync::Mutex::new(session));
    let ended = Arc::new(AtomicBool::new(false));
    // The blocking carrier pump is not abortable by Tokio. Keep a dedicated
    // cancellation flag and let the coordinator's drop guard stop it when a
    // session is closed by abort or daemon shutdown.
    let pump_stop = Arc::new(AtomicBool::new(false));

    // The carrier API is blocking (Handle::block_on internally); it runs on
    // its own pump task so the reader's select can serve the session bus
    // channels while the link is idle. The pump exits on link failure or
    // shutdown; dropping the packet channel ends the reader.
    //
    // The TCP carrier serializes reads and writes behind one mutex, so a
    // recv in flight starves the carrier's background writer; the pause
    // after each handoff gives queued ACKs, echoes, and bus-outbound
    // frames a window to flush (carriers/tcp.md).
    let (packet_tx, packet_rx) = tokio::sync::mpsc::unbounded_channel::<(u64, Vec<u8>)>();
    // The carrier API is blocking and internally `block_on`s, so the pump
    // must run on a blocking thread (spawn_blocking) — block_on on a tokio
    // worker panics, and block_in_place nests dangerously here.
    let pump_links = links.clone();
    let pump_shutdown = shutdown_flag.clone();
    let pump_cancel = pump_stop.clone();
    tokio::task::spawn_blocking(move || loop {
        if pump_shutdown.load(Ordering::Relaxed) || pump_cancel.load(Ordering::Relaxed) {
            break;
        }
        // A carrier failure removes its path from the set.  Once the last
        // path is gone, terminate the pump so the reader/writer lifecycle
        // closes too; otherwise an orphaned session can keep draining the
        // shared application channel after its link has already died.
        if pump_links.snapshot().is_empty() {
            break;
        }
        let mut received = false;
        for (path_id, pump_link) in pump_links.snapshot() {
            match pump_link.recv() {
                Ok(packet) => {
                    received = true;
                    log::debug!(
                        "[session {session_id}] path {path_id} recv {} bytes",
                        packet.bytes.len()
                    );
                    if packet_tx.send((path_id, packet.bytes)).is_err() {
                        return;
                    }
                    std::thread::sleep(FLUSH_INTERVAL);
                }
                Err(e) if e.kind == CarrierErrorKind::WouldBlock => {}
                Err(e) => {
                    log::debug!("[session {session_id}] path {path_id} recv error: {e:?}");
                    pump_links.remove(path_id, true);
                }
            }
        }
        if !received {
            std::thread::sleep(RECV_POLL_INTERVAL);
        }
    });

    // Keep one lifecycle handle for BOTH halves of the session. Returning the
    // writer handle alone lets it exit early when no application receiver is
    // registered, causing the watcher to unregister a still-live bus entry;
    // it also leaves the reader/pump detached when CloseSession aborts.
    let mut tasks = tokio::task::JoinSet::new();
    let reader_links = links.clone();
    let reader_session = session.clone();
    let reader_shutdown = shutdown_flag.clone();
    let reader_clock = clock.clone();
    let reader_ended = ended.clone();
    let reader_runtime = runtime.clone();
    tasks.spawn(async move {
        reader_loop(
            &reader_links,
            &reader_session,
            &reader_clock,
            &reader_shutdown,
            &reader_ended,
            &app_channels,
            &reader_runtime,
            privacy_policy,
            &remote_keys,
            &remote_hp_key,
            ticket_material,
            session_id,
            packet_rx,
            bus_inbound_rx,
            bus_outbound_rx,
        )
        .await;
    });

    let writer_links = links.clone();
    let writer_session = session.clone();
    let writer_clock = clock.clone();
    tasks.spawn(async move {
        writer_loop(
            &writer_links,
            &writer_session,
            &writer_clock,
            &shutdown_flag,
            &ended,
            &app_echo_rx,
            session_id,
            privacy_policy,
        )
        .await;
    });

    let task = tokio::spawn(async move {
        let _pump_guard = PumpStopGuard(pump_stop);
        while tasks.join_next().await.is_some() {}
    });
    SpawnedSession {
        task,
        session,
        link,
        links,
    }
}

/// Sets the non-abortable carrier pump's cancellation flag when the session
/// coordinator exits normally or is aborted.
struct PumpStopGuard(Arc<AtomicBool>);

impl Drop for PumpStopGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Per-session schedule state threaded through inbound processing: session
/// establishment time, key/CID rotation, and bundle flush cadence.
#[derive(Debug)]
struct SweepState {
    established: Option<Instant>,
    last_key_update: Option<Instant>,
    last_dcid_rotation: Option<Instant>,
    last_bundle_flush: Option<Instant>,
    route_rotation_interval_ms: u64,
}

impl Default for SweepState {
    fn default() -> Self {
        Self {
            established: None,
            last_key_update: None,
            last_dcid_rotation: None,
            last_bundle_flush: None,
            route_rotation_interval_ms: DCID_ROTATION_INTERVAL_MS,
        }
    }
}

impl SweepState {
    fn for_policy(policy: PrivacyRuntimePolicy) -> Self {
        Self {
            route_rotation_interval_ms: policy.route_rotation_interval_ms(),
            ..Self::default()
        }
    }
}

/// One-second rolling cover-traffic budget (privacy.md §28). Budget state is
/// local to a session, so a peer cannot consume another peer's allowance or
/// amplify cover generation through unauthenticated input.
#[derive(Debug)]
struct CoverBudget {
    window_started: tokio::time::Instant,
    bytes_sent: u64,
}

impl CoverBudget {
    fn new(now: tokio::time::Instant) -> Self {
        Self {
            window_started: now,
            bytes_sent: 0,
        }
    }

    fn reserve(&mut self, now: tokio::time::Instant, bytes: usize, budget_bps: u64) -> bool {
        if now.duration_since(self.window_started) >= Duration::from_secs(1) {
            self.window_started = now;
            self.bytes_sent = 0;
        }
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        let Some(next) = self.bytes_sent.checked_add(bytes) else {
            return false;
        };
        if budget_bps == 0 || next > budget_bps {
            return false;
        }
        self.bytes_sent = next;
        true
    }
}

/// Derive a bounded, unbiased-enough delay from OS entropy. The delay is
/// applied only to application-originated sends; ACK, retransmit, and relay
/// control paths remain latency-sensitive.
fn privacy_jitter_delay_ms(max_ms: u64) -> u64 {
    if max_ms == 0 {
        return 0;
    }
    let mut bytes = [0u8; 8];
    umc_types::runtime::EntropySource::fill(&OsEntropy, &mut bytes);
    u64::from_le_bytes(bytes) % max_ms.saturating_add(1)
}

/// Authenticated cover payload. Leading `PADDING` keeps the session's normal
/// P3 padding policy engaged while the trailing `PING` makes the packet
/// ack-eliciting and indistinguishable from a transport probe to observers.
fn cover_payload() -> Vec<u8> {
    let mut payload = vec![0u8];
    payload.extend_from_slice(
        &umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap_or_default(),
    );
    payload
}

/// Reader loop: pull packets off the carrier pump or the session bus, feed
/// the session state machine, send the ACKs it produces, forward stream
/// data to applications, and dispatch control frames (relay/bundle/routing/
/// key-update) to the runtime services.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn reader_loop(
    links: &Arc<SessionLinkSet>,
    session: &Arc<tokio::sync::Mutex<Session>>,
    clock: &Arc<dyn Clock>,
    shutdown_flag: &Arc<AtomicBool>,
    ended: &Arc<AtomicBool>,
    app_channels: &Arc<Mutex<HashMap<Vec<u8>, AppTx>>>,
    runtime: &Arc<Mutex<RuntimeState>>,
    privacy_policy: PrivacyRuntimePolicy,
    remote_keys: &PacketKeys,
    remote_hp_key: &[u8; 32],
    ticket_material: Option<TicketMaterial>,
    session_id: u64,
    mut packet_rx: tokio::sync::mpsc::UnboundedReceiver<(u64, Vec<u8>)>,
    mut bus_inbound_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    mut bus_outbound_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let mut sweep = SweepState::for_policy(privacy_policy);
    // PTO probe schedule (session.md §14.3): the deadline is armed when
    // nothing is armed and ack-eliciting packets are in flight, re-armed
    // (with a doubled backoff) when it fires and a probe was sent, and
    // cleared once everything is acknowledged. An armed deadline is never
    // extended by inbound traffic, so the probe cannot be starved.
    let mut pto_deadline: Option<tokio::time::Instant> = None;
    let mut pto_state = PtoState::default();
    // Idle/draining sweep (session.md §6.4, §22): checks the session's idle
    // timer and draining deadline; it must not interfere with the PTO
    // schedule (an armed PTO deadline is never extended by this arm).
    let mut idle_sweep = tokio::time::interval(IDLE_SWEEP_INTERVAL);
    let cover_interval = Duration::from_millis(privacy_policy.cover_interval_ms());
    let mut cover_tick =
        tokio::time::interval_at(tokio::time::Instant::now() + cover_interval, cover_interval);
    let mut cover_budget = CoverBudget::new(tokio::time::Instant::now());
    loop {
        if shutdown_flag.load(Ordering::Relaxed) {
            break;
        }
        tokio::select! {
            recv = packet_rx.recv() => {
                match recv {
                    Some((path_id, bytes)) => {
                        if process_inbound_packet_on_links(
                            links,
                            session,
                            clock,
                            app_channels,
                            runtime,
                            remote_keys,
                            remote_hp_key,
                            session_id,
                            path_id,
                            &bytes,
                            &mut sweep,
                        )
                        .await
                        {
                            pto_state.on_ack();
                        }
                    }
                    None => break,
                }
            }
            recv = bus_inbound_rx.recv() => {
                match recv {
                    Some(bytes) => {
                        if process_inbound_packet_on_links(
                            links,
                            session,
                            clock,
                            app_channels,
                            runtime,
                            remote_keys,
                            remote_hp_key,
                            session_id,
                            links.active_path(),
                            &bytes,
                            &mut sweep,
                        )
                        .await
                        {
                            pto_state.on_ack();
                        }
                    }
                    None => break,
                }
            }
            recv = bus_outbound_rx.recv() => {
                match recv {
                    Some(bytes) => {
                        let now = clock.now();
                        // Bus messages are frame payloads, not carrier
                        // packets. Protect them with this session's traffic
                        // keys before putting them on the link (relay,
                        // routing, and bundle forwarding all use this path).
                        let packet = {
                            let mut session = session.lock().await;
                            match session.build_outbound(clock.as_ref(), now, &bytes) {
                                Ok(Some(packet)) => {
                                    session.touch(now);
                                    Some(packet)
                                }
                                Ok(None) => None,
                                Err(e) => {
                                    log::debug!(
                                        "[session {session_id}] bus payload build error: {e:?}"
                                    );
                                    None
                                }
                            }
                        };
                        if let Some(packet) = packet {
                            let sent = tokio::task::block_in_place(|| {
                                links.send_active(OutboundPacket {
                                    bytes: packet,
                                    control: false,
                                    deadline_ms: None,
                                })
                            });
                            if let Err(e) = sent {
                                log::debug!("[session {session_id}] send error: {e:?}");
                            }
                        }
                    }
                    None => break,
                }
            }
            _ = cover_tick.tick(), if privacy_policy.cover_traffic() => {
                if privacy_policy.profile() < 3 {
                    continue;
                }
                // Reserve against the fixed-size packet estimate before
                // building, so a rejected budget cannot leave a retained
                // retransmit payload in the session state.
                let now = clock.now();
                let estimate = umc_session::session::TRAFFIC_PADDING_TARGET + 96;
                if !cover_budget.reserve(
                    tokio::time::Instant::now(),
                    estimate,
                    privacy_policy.cover_budget_bps(),
                ) {
                    continue;
                }
                let packet = {
                    let mut session = session.lock().await;
                    match session.build_outbound(clock.as_ref(), now, &cover_payload()) {
                        Ok(Some(packet)) => Some(packet),
                        Ok(None) | Err(_) => None,
                    }
                };
                if let Some(bytes) = packet {
                    let sent = tokio::task::block_in_place(|| {
                        links.send_active(OutboundPacket {
                            bytes,
                            // Cover packets use the ordinary data queue so
                            // carrier metadata does not reveal their role.
                            control: false,
                            deadline_ms: None,
                        })
                    });
                    if let Err(e) = sent {
                        log::debug!("[session {session_id}] cover send error: {e:?}");
                    }
                }
            }
            _ = idle_sweep.tick() => {
                let now = clock.now();
                {
                    let mut runtime = runtime.lock().expect("runtime state");
                    flush_relay_expiry_notifications(&mut runtime, now);
                }
                // Build the idle close / keepalive (if any) under the guard;
                // the sends happen after it is dropped — the carrier API is
                // blocking. The clean close carries the session ticket
                // (handshake.md §35) when this session is ticket-bearing.
                let (built_close, built_keepalive, done) = {
                    let mut session = session.lock().await;
                    handle_idle_timers(
                        &mut session,
                        clock.as_ref(),
                        now,
                        ticket_material.as_ref(),
                    )
                };
                if let Some(bytes) = built_close {
                    let sent = tokio::task::block_in_place(|| {
                        links.send_active(OutboundPacket {
                            bytes,
                            control: false,
                            deadline_ms: None,
                        })
                    });
                    if let Err(e) = sent {
                        log::debug!("[session {session_id}] idle close send error: {e:?}");
                    }
                }
                if let Some(bytes) = built_keepalive {
                    let sent = tokio::task::block_in_place(|| {
                        links.send_active(OutboundPacket {
                            bytes,
                            control: false,
                            deadline_ms: None,
                        })
                    });
                    if let Err(e) = sent {
                        log::debug!("[session {session_id}] keepalive send error: {e:?}");
                    }
                }
                // Rotate the advertised CID from the periodic sweep as well
                // as from inbound traffic, so an otherwise quiet session
                // still gets the privacy benefit of identifier churn.
                let built_dcid = {
                    let mut session = session.lock().await;
                    let due = sweep.established.is_some_and(|started| {
                        dcid_rotation_due(
                            now,
                            started,
                            sweep.last_dcid_rotation,
                            sweep.route_rotation_interval_ms,
                        )
                    });
                    if due {
                        if let Some(payload) = maybe_rotate_dcid(&mut session, &OsEntropy) {
                            match session.build_outbound(clock.as_ref(), now, &payload) {
                                Ok(packet) => {
                                    if packet.is_some() {
                                        sweep.last_dcid_rotation = Some(now);
                                    }
                                    packet
                                }
                                Err(_) => None,
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };
                if let Some(bytes) = built_dcid {
                    let sent = tokio::task::block_in_place(|| {
                        links.send_active(OutboundPacket {
                            bytes,
                            control: true,
                            deadline_ms: None,
                        })
                    });
                    if let Err(e) = sent {
                        log::debug!("[session {session_id}] CID rotation send error: {e:?}");
                    }
                }
                if done {
                    log::debug!("[session {session_id}] draining period ended, closing session");
                    break;
                }
            }
            () = pto_sleep(pto_deadline) => {
                let now = clock.now();
                let probe = {
                    let mut session = session.lock().await;
                    let in_flight = session
                        .sent_state()
                        .sent()
                        .iter()
                        .any(|p| p.ack_eliciting && p.in_flight);
                    if in_flight {
                        let ping = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0)
                            .unwrap_or_default();
                        match session.build_outbound(clock.as_ref(), now, &ping) {
                            Ok(Some(bytes)) => Some(bytes),
                            _ => None,
                        }
                    } else {
                        None
                    }
                };
                if let Some(bytes) = probe {
                    let sent = tokio::task::block_in_place(|| {
                        links.send_active(OutboundPacket {
                            bytes,
                            control: false,
                            deadline_ms: None,
                        })
                    });
                    if sent.is_ok() {
                        // The backoff doubles only when a probe was actually
                        // sent (session.md §14.3); a failed send leaves the
                        // state unchanged.
                        pto_state.on_expiry();
                    } else if let Err(e) = sent {
                        log::debug!("[session {session_id}] PTO probe send error: {e:?}");
                    }
                }
                // The deadline just fired: re-arm from now while ack-eliciting
                // packets remain in flight (disarmed once they are all acked).
                let session = session.lock().await;
                pto_deadline = pto_deadline_at(&session, &pto_state);
            }
        }
        // Give the carrier's background writer a window to flush before the
        // next recv takes the stream lock (carriers/tcp.md).
        tokio::time::sleep(FLUSH_INTERVAL).await;
        // Arm when nothing is armed (a new ack-eliciting send without an
        // armed deadline, e.g. from the session writer); keep an armed
        // deadline untouched and clear it once nothing remains in flight.
        // Inbound processing never extends an armed deadline here.
        {
            let session = session.lock().await;
            pto_deadline = pto_deadline_after(&session, &pto_state, pto_deadline);
        }
    }
    ended.store(true, Ordering::Relaxed);
    // NOTE: the bus unregister lives in the WATCHER (main.rs), which runs on
    // normal exit AND on abort; a task-local unregister would leak bus
    // entries when the task is aborted (CloseSession). The watcher owns the
    // JoinHandle and performs the cleanup after it resolves either way.
}

/// Process one inbound byte buffer — from the carrier pump or the session
/// bus — as a carrier packet: feed the session state machine, send the ACK
/// payloads it produces, dispatch control frames, and forward matching
/// stream data to registered applications. Returns whether the packet
/// carried an ACK frame (the reader resets the PTO backoff on ACKs).
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
async fn process_inbound_packet(
    link: &Arc<BoxLink>,
    session: &Arc<tokio::sync::Mutex<Session>>,
    clock: &Arc<dyn Clock>,
    app_channels: &Arc<Mutex<HashMap<Vec<u8>, AppTx>>>,
    runtime: &Arc<Mutex<RuntimeState>>,
    remote_keys: &PacketKeys,
    remote_hp_key: &[u8; 32],
    session_id: u64,
    bytes: &[u8],
    sweep: &mut SweepState,
) -> bool {
    let links = SessionLinkSet::from_arc(umc_session::packet::DEFAULT_PATH_ID, link.clone());
    process_inbound_packet_on_links(
        &links,
        session,
        clock,
        app_channels,
        runtime,
        remote_keys,
        remote_hp_key,
        session_id,
        umc_session::packet::DEFAULT_PATH_ID,
        bytes,
        sweep,
    )
    .await
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn process_inbound_packet_on_links(
    links: &Arc<SessionLinkSet>,
    session: &Arc<tokio::sync::Mutex<Session>>,
    clock: &Arc<dyn Clock>,
    app_channels: &Arc<Mutex<HashMap<Vec<u8>, AppTx>>>,
    runtime: &Arc<Mutex<RuntimeState>>,
    remote_keys: &PacketKeys,
    remote_hp_key: &[u8; 32],
    session_id: u64,
    ingress_path_id: u64,
    bytes: &[u8],
    sweep: &mut SweepState,
) -> bool {
    let now = clock.now();
    // The control frames the session layer does not expose: relay,
    // bundle, routing, and key updates. The parse needs the reconstruction
    // anchor (the session's expected pn) or the AEAD open fails once the
    // wire pn wraps past the truncated width — control frames would be
    // silently dropped.
    let expected = session
        .lock()
        .await
        .expected_pn(umc_session::spaces::PacketSpace::SessionData);
    let frames = parse_control_frames(remote_keys, remote_hp_key, expected, bytes);
    let mut outbound = None;
    let mut retransmits: Vec<Vec<u8>> = Vec::new();
    let mut pending: Vec<(Vec<u8>, u64, Vec<u8>, bool)> = Vec::new();
    let mut pending_resets: Vec<(u64, u64)> = Vec::new();
    let mut incoming_datagrams = Vec::new();
    let path_migration: Option<(u64, u64, bool)>;
    let path_validation: Option<u64>;
    let mut automatic_migration: Option<(u64, u64, bool, Vec<u8>)> = None;
    {
        let mut session = session.lock().await;
        let ack_payload = match session.on_inbound(now, bytes) {
            Ok(payload) => payload,
            Err(SessionError::StatelessReset) => {
                // session.md §31: the packet could not be authenticated and
                // carried the session's reset token — the peer reset us and
                // the session is now Closed. Answer with our own
                // rate-limited stateless reset so the peer learns the
                // connection is dead from its side too; no ACK or frame
                // processing follows.
                log::debug!("[session {session_id}] stateless reset received; session closed");
                outbound = session.maybe_emit_stateless_reset(now, &OsEntropy, bytes.len());
                Vec::new()
            }
            Err(e) => {
                log::debug!("[session {session_id}] inbound error: {e:?}");
                return false;
            }
        };
        path_migration = session.take_path_migration();
        path_validation = session.take_path_validation();
        while let Some(datagram) = session.recv_datagram() {
            incoming_datagrams.push(datagram);
        }
        // Count only AUTHENTICATED packets: the metric must not inflate
        // under forged-traffic floods.
        runtime
            .lock()
            .expect("runtime state")
            .metrics
            .incr(metric_names::PACKETS_RECEIVED, 1);
        // Loss detection (session.md §14) runs only for the session data
        // space: an ACK of a packet at least three numbers higher declares
        // older packets lost; their retained payloads are re-sent under
        // fresh packet numbers. Every lost packet leaves the sent queue;
        // non-ack-eliciting ones only have their retained payload pruned.
        if let Some((space, path_id, control_frames)) = frames.as_ref() {
            if *space == ShortPacketSpace::SessionData {
                if let Some(largest_acked) = control_frames
                    .iter()
                    .filter_map(|f| match f {
                        Frame::Ack(ack) => Some(ack.largest_acknowledged),
                        _ => None,
                    })
                    .max()
                {
                    let rtt = session.rtt().clone();
                    let detector = session.loss_detector().clone();
                    // Congestion feedback (congestion.md §14.4): every lost
                    // packet releases its bytes from in-flight.
                    // `detect_lost_packets` drops the lost packets from the
                    // sent queue, so their sizes and sent timestamps are
                    // captured beforehand.
                    let sizes_by_pn: HashMap<u64, usize> = session
                        .sent_state()
                        .sent()
                        .iter()
                        .map(|p| (p.packet_number, p.size))
                        .collect();
                    let sent_at_by_pn: HashMap<u64, (Instant, bool)> = session
                        .sent_state()
                        .sent()
                        .iter()
                        .map(|p| (p.packet_number, (p.sent_at, p.ack_eliciting)))
                        .collect();
                    let lost = detect_lost_packets(
                        session.sent_state_mut(),
                        &rtt,
                        now,
                        largest_acked,
                        &detector,
                    );
                    if !lost.is_empty() {
                        // Persistent congestion (congestion.md §14.4): when
                        // the lost batch spans at least three PTOs the path
                        // is degraded — one-shot, recorded on the session —
                        // and the daemon is notified via a `path_degraded`
                        // event. Migration is operator/daemon policy; the
                        // event is the hook, not an automatic switch.
                        let pto = detector.pto(&rtt);
                        // §14.4: the span endpoints must be ACK-ELICITING
                        // packets; a late ack-only loss must not degrade.
                        let oldest = lost
                            .iter()
                            .filter_map(|pn| sent_at_by_pn.get(pn))
                            .filter(|(_sent_at, ack_eliciting)| *ack_eliciting)
                            .map(|(sent_at, _)| sent_at)
                            .min();
                        let newest = lost
                            .iter()
                            .filter_map(|pn| sent_at_by_pn.get(pn))
                            .filter(|(_sent_at, ack_eliciting)| *ack_eliciting)
                            .map(|(sent_at, _)| sent_at)
                            .max();
                        if let (Some(oldest), Some(newest)) = (oldest, newest) {
                            if detector.persistent_congestion(pto, *oldest, *newest)
                                && session.mark_path_degraded(*path_id)
                            {
                                let span = newest.duration_since(*oldest).as_millis();
                                let mut state = runtime.lock().expect("runtime state");
                                state.metrics.incr(metric_names::PATH_DEGRADED_EVENTS, 1);
                                push_event(
                                    &mut state,
                                    "path_degraded",
                                    now,
                                    format!(
                                        "path {path_id}: loss span {span} ms >= 3 x PTO ({} ms)",
                                        pto.as_millis()
                                    ),
                                );
                            }
                        }
                    }
                    for pn in lost {
                        if let Some(size) = sizes_by_pn.get(&pn) {
                            session.congestion_mut().on_packet_lost(*size);
                        }
                        match session.retransmit(pn, now) {
                            Ok(Some(bytes)) => {
                                runtime
                                    .lock()
                                    .expect("runtime state")
                                    .metrics
                                    .incr(metric_names::RETRANSMISSIONS, 1);
                                retransmits.push(bytes);
                            }
                            Ok(None) => session.prune_retransmit_payload(pn),
                            Err(e) => {
                                // A gated retransmit (CongestionLimited) is a
                                // transient condition: the payload must
                                // survive for the next detection pass or PTO
                                // (session.md §14.3). Pruning here would
                                // destroy the only copy of the data.
                                log::debug!(
                                    "[session {session_id}] retransmit of pn {pn} deferred ({e:?}); payload kept"
                                );
                            }
                        }
                    }
                }
            }
        }
        // Pacing (congestion.md §12): feed the controller the session's
        // smoothed RTT so the pacing rate tracks the measured round trip.
        // Until the first RTT sample the rate stays 0 = unlimited, so
        // pacing changes nothing (the default controller runs un-paced).
        let smoothed_rtt = session.rtt().smoothed_rtt;
        // `now` anchors the re-rate: the pending pacing refill is credited
        // at the old rate up to the current instant before the bucket
        // re-rates (congestion.md §12) — elapsed before the sample must not
        // be refunded at the new rate.
        session.congestion_mut().set_smoothed_rtt(smoothed_rtt, now);
        let mut combined = ack_payload;
        // Flow-control credit (session.md §20): MAX_DATA / MAX_STREAM_DATA /
        // MAX_STREAMS payloads are emitted when a local watermark is crossed.
        for credit in session.flow_control_frames(now) {
            combined.extend_from_slice(&credit);
        }
        let sweep_due = bundle_flush_due(now, sweep.last_bundle_flush);
        let hint_due = sweep.established.is_none() || sweep_due;
        let rotation_due = sweep
            .established
            .is_some_and(|started| key_rotation_due(now, started, sweep.last_key_update));
        let dcid_due = sweep.established.is_some_and(|started| {
            dcid_rotation_due(
                now,
                started,
                sweep.last_dcid_rotation,
                sweep.route_rotation_interval_ms,
            )
        });
        if sweep.established.is_none() {
            sweep.established = Some(now);
        }
        if frames.is_some() || hint_due || sweep_due || rotation_due || dcid_due {
            let mut state = runtime.lock().expect("runtime state");
            if let Some((_space, _path_id, control_frames)) = &frames {
                if let Some(payload) =
                    handle_control_frames(&mut state, session_id, &mut session, control_frames, now)
                {
                    combined.extend_from_slice(&payload);
                }
            }
            if sweep_due {
                let payload = flush_pending_bundles(&mut state, crate::state::wall_now());
                combined.extend_from_slice(&payload);
                sweep.last_bundle_flush = Some(now);
            }
            if hint_due {
                let mesh_secret = state.config.mesh_secret.as_deref().map(str::as_bytes);
                if let Some(hint) =
                    state
                        .discovery
                        .build_hint_with_mesh_secret(32, now, mesh_secret)
                {
                    if let Ok(payload) = hint.encode() {
                        combined.extend_from_slice(&payload);
                    }
                }
            }
            if rotation_due {
                if let Some(started) = sweep.established {
                    if let Some(payload) =
                        maybe_rotate_keys(&mut session, now, started, &mut sweep.last_key_update)
                    {
                        combined.extend_from_slice(&payload);
                    }
                }
            }
            if dcid_due {
                if let Some(payload) = maybe_rotate_dcid(&mut session, &OsEntropy) {
                    combined.extend_from_slice(&payload);
                    sweep.last_dcid_rotation = Some(now);
                }
            }
        }
        if !combined.is_empty() {
            let egress_path_id = frames
                .as_ref()
                .map_or(ingress_path_id, |(_, path_id, _)| *path_id);
            let built =
                session.build_outbound_on_path(egress_path_id, clock.as_ref(), now, &combined);
            outbound = match built {
                Ok(outbound) => {
                    if outbound.is_some() {
                        // App-originated traffic (ACK/control replies, bundle
                        // sweeps, key rotation): resets the idle timer
                        // (session.md §22). Probes and retransmits do not.
                        session.touch(now);
                    }
                    outbound
                }
                Err(e) => {
                    log::debug!("[session {session_id}] ack build error: {e:?}");
                    None
                }
            };
        }
        // Forward contiguous data of streams whose protocol ID has an
        // application channel; reading drains the session buffer, which
        // is the app-layer delivery.
        let stream_ids: Vec<u64> = session.streams.keys().copied().collect();
        for stream_id in stream_ids {
            let protocol_id = session
                .streams
                .get(&stream_id)
                .map(|s| s.protocol_id.clone())
                .unwrap_or_default();
            if !app_channels
                .lock()
                .expect("app channels")
                .contains_key(&protocol_id)
            {
                continue;
            }
            match session.read_stream(stream_id) {
                Ok((data, eof)) => {
                    if !data.is_empty() || eof {
                        pending.push((protocol_id, stream_id, data, eof));
                    }
                }
                Err(SessionError::Stream(StreamError::ResetByPeer)) => {
                    pending_resets.push((
                        stream_id,
                        session.stream_reset_error(stream_id).unwrap_or_default(),
                    ));
                }
                Err(_) => {}
            }
        }
    }
    if let Some(new_path_id) = path_validation {
        if let Some(keep_old_path) = links.take_migration_request(new_path_id) {
            let mut session = session.lock().await;
            let old_path_id = session.primary_path_id();
            if let Ok(payload) = session.build_migrate_payload(new_path_id, keep_old_path, true) {
                if let Ok(Some(packet)) =
                    session.build_outbound_on_path(old_path_id, clock.as_ref(), now, &payload)
                {
                    if session.migrate_to(new_path_id, keep_old_path, now).is_ok() {
                        automatic_migration =
                            Some((old_path_id, new_path_id, keep_old_path, packet));
                    }
                }
            }
        }
    }
    if let Some((_, new_path_id, keep_old)) = path_migration {
        if let Err(error) = links.set_active_path(new_path_id) {
            log::debug!("[session {session_id}] migration path attach error: {error}");
        }
        if !keep_old {
            for (path_id, _) in links.snapshot() {
                if path_id != new_path_id {
                    links.remove(path_id, true);
                }
            }
        }
    }
    if let Some(path_id) = path_validation {
        let mut state = runtime.lock().expect("runtime state");
        push_event(
            &mut state,
            "path_validated",
            now,
            format!("path {path_id} session {session_id}"),
        );
    }
    if let Some((old_path_id, new_path_id, keep_old)) = path_migration {
        let mut state = runtime.lock().expect("runtime state");
        push_event(
            &mut state,
            "path_migrated",
            now,
            format!("path {old_path_id} new_path {new_path_id} session {session_id}"),
        );
        if !keep_old {
            push_event(
                &mut state,
                "path_failed",
                now,
                format!("path {old_path_id} session {session_id}"),
            );
        }
    }
    if !pending_resets.is_empty() {
        let mut state = runtime.lock().expect("runtime state");
        for (stream_id, error_code) in pending_resets {
            if let Err(error) = state
                .application_data
                .mark_stream_reset_for_session(session_id, stream_id, error_code)
            {
                log::debug!(
                    "[session {session_id}] application reset delivery rejected: {error:?}"
                );
            }
        }
    }
    for (protocol_id, stream_id, data, eof) in pending {
        let routed = runtime
            .lock()
            .expect("runtime state")
            .application_data
            .route_stream_data(session_id, stream_id, &protocol_id, data.clone(), eof);
        match routed {
            Ok(true) => continue,
            Err(error) => {
                log::debug!("[session {session_id}] application stream queue rejected: {error:?}");
                continue;
            }
            Ok(false) => {}
        }
        let channel = app_channels
            .lock()
            .expect("app channels")
            .get(&protocol_id)
            .expect("channel exists")
            .clone();
        log::debug!(
            "[session {session_id}] dispatch stream {stream_id} to {:?} ({} bytes)",
            protocol_id,
            data.len()
        );
        if channel.send_stream_frame(stream_id, data).await.is_err() {
            break;
        }
    }
    if !incoming_datagrams.is_empty() {
        let mut state = runtime.lock().expect("runtime state");
        for datagram in incoming_datagrams {
            let expired = datagram
                .expires_at_ms
                .is_some_and(|expires_at| expires_at <= now.0);
            if let Err(error) = state.application_data.push_datagram(
                session_id,
                datagram.context_id,
                datagram.data,
                expired,
            ) {
                log::debug!(
                    "[session {session_id}] application datagram queue rejected: {error:?}"
                );
            }
        }
    }
    if let Some(outbound) = outbound {
        // Carrier backpressure (congestion.md §16): a combined payload
        // without an ACK/PING lead frame (flow-control credit, bundle,
        // key-update) is skipped when the carrier queue is past 80% — the
        // next inbound round rebuilds it. ACK-led payloads are exempt and
        // always sent, so the acknowledgment loop keeps running.
        let path_link = links
            .get(links.active_path())
            .or_else(|| links.get(ingress_path_id));
        if path_link
            .as_ref()
            .is_some_and(|link| should_backpressure(link, &outbound))
        {
            log::debug!(
                "[session {session_id}] combined outbound backpressured (carrier queue >80%)"
            );
        } else {
            let sent = tokio::task::block_in_place(|| {
                links.send_on(
                    ingress_path_id,
                    OutboundPacket {
                        bytes: outbound,
                        control: false,
                        deadline_ms: None,
                    },
                )
            });
            if let Err(e) = sent {
                log::debug!("[session {session_id}] send error: {e:?}");
            }
        }
    }
    for bytes in retransmits {
        let sent = tokio::task::block_in_place(|| {
            links.send_on(
                links.active_path(),
                OutboundPacket {
                    bytes,
                    control: false,
                    deadline_ms: None,
                },
            )
        });
        if let Err(e) = sent {
            log::debug!("[session {session_id}] retransmit send error: {e:?}");
        }
    }
    if let Some((old_path_id, new_path_id, keep_old_path, bytes)) = automatic_migration {
        let sent = tokio::task::block_in_place(|| {
            links.send_on(
                old_path_id,
                OutboundPacket {
                    bytes,
                    control: true,
                    deadline_ms: None,
                },
            )
        });
        if sent.is_ok() {
            let _ = links.set_active_path(new_path_id);
            if !keep_old_path {
                links.remove(old_path_id, true);
            }
        } else if let Err(error) = sent {
            log::debug!("[session {session_id}] migration send error: {error:?}");
        }
    }
    frames
        .as_ref()
        .is_some_and(|(_space, _path_id, fs)| fs.iter().any(|f| matches!(f, Frame::Ack(_))))
}

/// Parse the control frames out of an inbound protected packet with the
/// daemon's copy of the peer's traffic keys. The session layer applies
/// stream/datagram/ACK frames itself; this read-only parse (with the same
/// keys, so it never disturbs session state) exposes the packet's space, its
/// path id, and the relay, bundle, routing, and key-update frames for daemon
/// dispatch.
fn parse_control_frames(
    remote_keys: &PacketKeys,
    remote_hp_key: &[u8; 32],
    expected_pn: u64,
    bytes: &[u8],
) -> Option<(ShortPacketSpace, u64, Vec<Frame>)> {
    let (space, _dcid, path_id, _pn, payload) =
        umc_session::packet::parse_protected_packet(remote_keys, remote_hp_key, expected_pn, bytes)
            .ok()?;
    let parsed = parse_payload(&PacketContext::Protected(space), &payload).ok()?;
    Some((space, path_id, parsed.frames))
}

fn relay_profile_capacity_available(state: &RuntimeState) -> bool {
    state.relay.circuit_count()
        < state
            .config
            .resource_profile()
            .limits()
            .active_relay_circuits
}

/// Dispatch the control frames of one inbound packet to the runtime
/// services (core.md §8): relay open/data/close, bundle admission, route
/// requests and responses, and session key updates. Returns the outbound
/// frame payload to send back, if any (e.g. a `RELAY_STATUS` answer to a
/// `RELAY_OPEN`).
#[allow(clippy::too_many_lines)]
fn handle_control_frames(
    state: &mut RuntimeState,
    session_id: u64,
    session: &mut Session,
    frames: &[Frame],
    now: Instant,
) -> Option<Vec<u8>> {
    let peer_endpoint_id = state
        .sessions
        .lookup(session_id)
        .map(|entry| entry.peer_endpoint_id)
        .unwrap_or_default();
    let mut outbound = Vec::new();
    for frame in frames {
        match frame {
            Frame::RelayOpen(open) => {
                match state.relay.observe_open(session_id, open) {
                    RelayOpenDisposition::Duplicate(status) => {
                        // Relay opens are retransmittable control frames. An
                        // identical duplicate must replay the stable status
                        // without allocating another circuit or changing
                        // quota/accounting state.
                        if let Ok(encoded) = status.encode() {
                            outbound.extend_from_slice(&encoded);
                        }
                        continue;
                    }
                    RelayOpenDisposition::Conflict => {
                        // A peer-scoped wire ID cannot be rebound to a
                        // different open body. Keep the existing circuit
                        // untouched and return a fail-closed status rather
                        // than allocating state. The status avoids leaking
                        // whether the prior request was accepted; the
                        // adjacent session remains responsible for applying
                        // its protocol-error/draining policy.
                        push_event(
                            state,
                            "relay_open_rejected",
                            now,
                            format!(
                                "session {session_id}: conflicting open for circuit {}",
                                open.circuit_id
                            ),
                        );
                        let status = RelayStatusFrame {
                            circuit_id: open.circuit_id,
                            status_sequence: 0,
                            status_code: RELAY_STATUS_AUTH_FAILED,
                            bidirectional_granted: false,
                            private_handling_granted: false,
                            multipath_granted: false,
                            downstream_authenticated: false,
                            retryable: false,
                            granted_lifetime: 0,
                            granted_byte_quota: 0,
                            maximum_relay_payload: 0,
                            diagnostic: Vec::new(),
                            authentication: Vec::new(),
                        };
                        if let Ok(encoded) = status.encode() {
                            outbound.extend_from_slice(&encoded);
                        }
                        continue;
                    }
                    RelayOpenDisposition::New => {}
                }
                let authorization_valid = if open.authorization.is_empty() {
                    // Empty authorization is the legacy capability shape. It
                    // remains accepted for compatibility in community mode,
                    // but FRIENDS_ONLY must require a signed scoped grant.
                    state.relay.limits.policy != umc_relay::admission::RelayPolicy::FriendsOnly
                } else {
                    RelayAuthorization::decode(&open.authorization)
                        .and_then(|authorization| {
                            authorization.verify(&state.node_identity.identity, now.0)
                        })
                        .is_ok()
                };
                let public_relay_disabled =
                    state.config.disable_public_relay && !open.private_circuit;
                let circuit_request = CircuitOpenRequest {
                    peer_circuits: state.relay.circuits_for_peer(session_id),
                    requested_lifetime_ms: open.requested_lifetime,
                    requested_byte_quota: open.requested_byte_quota,
                    flags: relay_request_flags(open),
                    bidirectional: open.bidirectional,
                    private_handling: open.private_circuit,
                    destination_hint: open.next_hop_hint.clone(),
                };
                let admission_status = state.relay.admission_status(&circuit_request);
                let (code, retryable, granted) = match (authorization_valid, public_relay_disabled)
                {
                    (false, _) => {
                        push_event(
                            state,
                            "relay_authorization_rejected",
                            now,
                            format!("session {session_id}: invalid authorization"),
                        );
                        (RELAY_STATUS_AUTH_FAILED, false, None)
                    }
                    (true, true) => {
                        push_event(
                            state,
                            "relay_public_disabled",
                            now,
                            format!("session {session_id}: public relay disabled"),
                        );
                        (RELAY_STATUS_REFUSED, false, None)
                    }
                    (true, false) if !relay_profile_capacity_available(state) => {
                        push_event(
                            state,
                            "relay_profile_limit",
                            now,
                            format!("session {session_id}: profile relay circuit cap reached"),
                        );
                        (RELAY_STATUS_RESOURCE_LIMIT, true, None)
                    }
                    (true, false) => match state.relay.open_circuit(
                        &circuit_request,
                        peer_endpoint_id.to_vec(),
                        now,
                    ) {
                        Ok(accepted) => {
                            let circuit_id = accepted.circuit_id;
                            state.relay.record_circuit_owner(circuit_id, session_id);
                            if state
                                .relay
                                .bind_wire_circuit(session_id, open.circuit_id, circuit_id)
                                .is_err()
                            {
                                let _ = state.relay.close_circuit(
                                    circuit_id,
                                    umc_relay::close::RelayReason::ProtocolError as u64,
                                    now,
                                );
                                (RELAY_STATUS_REFUSED, false, None)
                            } else {
                                // If the target endpoint is already an
                                // authenticated adjacent session, allocate
                                // its reciprocal leg immediately. This is the
                                // relay-backed endpoint handoff path; a target
                                // that is not currently connected can still
                                // complete the legacy reciprocal-open flow.
                                // P2 uses an opaque destination token. Keep a
                                // raw-hint compatibility path for older relay
                                // fixtures, but never resolve a private token
                                // as an endpoint id.
                                let destination_session =
                                    decode_privacy_route_token(&open.next_hop_hint)
                                        .is_none()
                                        .then(|| {
                                            state
                                                .bus
                                                .lock()
                                                .expect("session bus")
                                                .lookup(&open.next_hop_hint)
                                        })
                                        .flatten();
                                let mut downstream_ready = !open.private_circuit;
                                if let Some(destination_session) =
                                    destination_session.filter(|candidate| {
                                        *candidate != session_id && open.private_circuit
                                    })
                                {
                                    if let Err(error) = state.relay.attach_destination_leg(
                                        circuit_id,
                                        destination_session,
                                        open.circuit_id,
                                        &peer_endpoint_id,
                                        &open.next_hop_hint,
                                        now,
                                    ) {
                                        push_event(
                                            state,
                                            "relay_destination_attach_failed",
                                            now,
                                            format!("circuit {circuit_id}: {error}"),
                                        );
                                    } else {
                                        downstream_ready = true;
                                    }
                                }
                                if open.private_circuit && !downstream_ready {
                                    // A private circuit may extend through a
                                    // live adjacent relay. The route cache is
                                    // consulted only after direct delivery
                                    // fails, so a local destination always
                                    // wins over a broader route.
                                    let next_hop = relay_next_hop_for_destination(
                                        state,
                                        &open.next_hop_hint,
                                        &peer_endpoint_id,
                                        now,
                                    );
                                    if let Some(next_hop) = next_hop {
                                        let next_hop_session = state
                                            .bus
                                            .lock()
                                            .expect("session bus")
                                            .lookup(&next_hop.peer);
                                        if let Some(next_hop_session) = next_hop_session {
                                            if next_hop.terminal {
                                                if let Err(error) =
                                                    state.relay.attach_destination_leg(
                                                        circuit_id,
                                                        next_hop_session,
                                                        open.circuit_id,
                                                        &peer_endpoint_id,
                                                        &next_hop.peer,
                                                        now,
                                                    )
                                                {
                                                    push_event(
                                                        state,
                                                        "relay_destination_attach_failed",
                                                        now,
                                                        format!("circuit {circuit_id}: {error}"),
                                                    );
                                                } else {
                                                    downstream_ready = true;
                                                }
                                            } else {
                                                let downstream_wire_id =
                                                    fresh_relay_wire_id(state, next_hop_session);
                                                let downstream_request = CircuitOpenRequest {
                                                    peer_circuits: state
                                                        .relay
                                                        .circuits_for_peer(next_hop_session),
                                                    requested_lifetime_ms: open.requested_lifetime,
                                                    requested_byte_quota: open.requested_byte_quota,
                                                    flags: relay_request_flags(open),
                                                    bidirectional: open.bidirectional,
                                                    private_handling: true,
                                                    destination_hint: open.next_hop_hint.clone(),
                                                };
                                                let downstream =
                                                    if relay_profile_capacity_available(state) {
                                                        state.relay.open_circuit(
                                                            &downstream_request,
                                                            next_hop.peer.clone(),
                                                            now,
                                                        )
                                                    } else {
                                                        Err("profile relay circuit cap reached"
                                                            .into())
                                                    };
                                                match downstream {
                                                    Ok(downstream) => {
                                                        let attached =
                                                            state.relay.attach_downstream_leg(
                                                                circuit_id,
                                                                downstream.circuit_id,
                                                                next_hop_session,
                                                                downstream_wire_id,
                                                                &peer_endpoint_id,
                                                                &next_hop.peer,
                                                                now,
                                                            );
                                                        if attached.is_ok() {
                                                            // Authorization is
                                                            // relay-identity
                                                            // scoped. A downstream
                                                            // relay independently
                                                            // authenticates this
                                                            // hop; forwarding an
                                                            // opaque grant would
                                                            // fail closed under a
                                                            // different identity.
                                                            let nested = RelayOpenFrame {
                                                                circuit_id: downstream_wire_id,
                                                                bidirectional: open.bidirectional,
                                                                store_forward_allowed: open
                                                                    .store_forward_allowed,
                                                                private_circuit: true,
                                                                multipath_allowed: open
                                                                    .multipath_allowed,
                                                                requested_lifetime: open
                                                                    .requested_lifetime,
                                                                requested_byte_quota: open
                                                                    .requested_byte_quota,
                                                                next_hop_hint: open
                                                                    .next_hop_hint
                                                                    .clone(),
                                                                authorization: Vec::new(),
                                                            };
                                                            let nested_result = nested
                                                                .encode()
                                                                .map_err(|error| {
                                                                    format!(
                                                                        "nested relay open encode: {error:?}"
                                                                    )
                                                                })
                                                                .and_then(|bytes| {
                                                                    state
                                                                        .bus
                                                                        .lock()
                                                                        .expect("session bus")
                                                                        .inject_outbound(
                                                                            &next_hop.peer,
                                                                            bytes,
                                                                        )
                                                                        .map_err(|error| {
                                                                            format!(
                                                                                "nested relay open send: {error:?}"
                                                                            )
                                                                        })
                                                                });
                                                            match nested_result {
                                                                Ok(()) => downstream_ready = true,
                                                                Err(error) => push_event(
                                                                    state,
                                                                    "relay_downstream_open_failed",
                                                                    now,
                                                                    format!(
                                                                        "circuit {circuit_id} via {:?}: {error:?}",
                                                                        next_hop.peer
                                                                    ),
                                                                ),
                                                            }
                                                        } else if let Err(error) = attached {
                                                            push_event(
                                                                state,
                                                                "relay_downstream_attach_failed",
                                                                now,
                                                                format!(
                                                                    "circuit {circuit_id} via {:?}: {error}",
                                                                    next_hop.peer
                                                                ),
                                                            );
                                                        }
                                                    }
                                                    Err(error) => push_event(
                                                        state,
                                                        "relay_downstream_open_failed",
                                                        now,
                                                        format!(
                                                            "circuit {circuit_id} via {:?}: {error}",
                                                            next_hop.peer
                                                        ),
                                                    ),
                                                }
                                            }
                                        }
                                    }
                                }
                                if open.private_circuit && !downstream_ready {
                                    let _ = state.relay.close_circuit(
                                        circuit_id,
                                        umc_relay::close::RelayReason::NoRoute as u64,
                                        now,
                                    );
                                    (RELAY_STATUS_NO_ROUTE, false, None)
                                } else {
                                    state.metrics.incr(metric_names::RELAY_CIRCUITS_OPENED, 1);
                                    (RELAY_STATUS_ACCEPTED, false, Some(accepted))
                                }
                            }
                        }
                        Err(_) => (
                            admission_status,
                            admission_status == RELAY_STATUS_RESOURCE_LIMIT,
                            None,
                        ),
                    },
                };
                let status = RelayStatusFrame {
                    circuit_id: open.circuit_id,
                    status_sequence: 0,
                    status_code: code,
                    bidirectional_granted: open.bidirectional && code == RELAY_STATUS_ACCEPTED,
                    private_handling_granted: open.private_circuit && code == RELAY_STATUS_ACCEPTED,
                    multipath_granted: open.multipath_allowed && code == RELAY_STATUS_ACCEPTED,
                    downstream_authenticated: false,
                    retryable,
                    granted_lifetime: granted.as_ref().map_or(0, |g| g.granted_lifetime_ms),
                    granted_byte_quota: granted.as_ref().map_or(0, |g| g.granted_byte_quota),
                    maximum_relay_payload: granted.map_or(0, |g| g.maximum_relay_payload as u64),
                    diagnostic: Vec::new(),
                    authentication: Vec::new(),
                };
                state
                    .relay
                    .remember_open(session_id, open.clone(), status.clone());
                debug_assert!(RELAY_STATUS_CODES.contains(&status.status_code));
                if let Ok(encoded) = status.encode() {
                    outbound.extend_from_slice(&encoded);
                }
            }
            Frame::RelayStatus(status) => {
                match state.relay.observe_status(&peer_endpoint_id, status) {
                    Ok(disposition) => {
                        let pending = if status.status_code == RELAY_STATUS_ACCEPTED {
                            state
                                .relay
                                .activate_downstream(session_id, status)
                                .unwrap_or_default()
                        } else {
                            Vec::new()
                        };
                        push_event(
                            state,
                            "relay_status_received",
                            now,
                            format!(
                                "session {session_id}: circuit {} status {} sequence {} ({disposition:?})",
                                status.circuit_id, status.status_code, status.status_sequence
                            ),
                        );
                        if disposition != crate::relay_service::RelayStatusDisposition::Stale {
                            if let Ok((upstream_session, forwarded)) =
                                state.relay.forward_status_frame(session_id, status)
                            {
                                let peer = state
                                    .bus
                                    .lock()
                                    .expect("session bus")
                                    .peer_for_session(upstream_session);
                                if let Some(peer) = peer {
                                    if let Ok(encoded) = forwarded.encode() {
                                        let _ = state
                                            .bus
                                            .lock()
                                            .expect("session bus")
                                            .inject_outbound(&peer, encoded);
                                    }
                                }
                            }
                        }
                        flush_pending_relay_data(state, pending, now);
                        if !matches!(
                            status.status_code,
                            RELAY_STATUS_PENDING | RELAY_STATUS_ACCEPTED
                        ) {
                            if let Some(internal) = state
                                .relay
                                .resolve_wire_circuit(session_id, status.circuit_id)
                            {
                                let _ = state.relay.close_circuit(
                                    internal,
                                    umc_relay::close::RelayReason::DownstreamFailed as u64,
                                    now,
                                );
                            }
                        }
                    }
                    Err(error) => push_event(
                        state,
                        "relay_status_rejected",
                        now,
                        format!(
                            "session {session_id}: circuit {} status {} sequence {}: {error:?}",
                            status.circuit_id, status.status_code, status.status_sequence
                        ),
                    ),
                }
            }
            Frame::RelayData(data) => {
                let internal_circuit_id = state
                    .relay
                    .resolve_wire_circuit(session_id, data.circuit_id)
                    .unwrap_or(data.circuit_id);
                // A relay-delivered Initial may be the first packet of an
                // endpoint session rather than a relay circuit opened by this
                // daemon. Keep the handoff bounded and keyed to the
                // authenticated adjacent session plus wire id; subsequent
                // packets feed the same opaque link without being parsed by
                // the relay layer.
                let handoff_key = (session_id, data.circuit_id);
                if let Some(incoming) = state.relay_endpoint_handoffs.get(&handoff_key).cloned() {
                    if incoming.try_send(data.data.clone()).is_err() {
                        state.relay_endpoint_handoffs.remove(&handoff_key);
                        push_event(
                            state,
                            "relay_endpoint_handoff_dropped",
                            now,
                            format!("session {session_id}: handoff queue closed"),
                        );
                    }
                    continue;
                }
                if state.relay.circuit_owner(internal_circuit_id) != Some(session_id)
                    && data.relay_sequence == 0
                    && umc_handshake::initial::try_parse_initial(&data.data).is_some()
                {
                    const MAX_ENDPOINT_HANDOFFS: usize = 64;
                    if state.relay_endpoint_handoffs.len() >= MAX_ENDPOINT_HANDOFFS {
                        push_event(
                            state,
                            "relay_endpoint_handoff_rejected",
                            now,
                            "endpoint handoff capacity exhausted".into(),
                        );
                        continue;
                    }
                    let (incoming, receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(16);
                    if incoming.try_send(data.data.clone()).is_err() {
                        continue;
                    }
                    state.relay_endpoint_handoffs.insert(handoff_key, incoming);
                    let Some(runtime) = state.self_arc.upgrade() else {
                        state.relay_endpoint_handoffs.remove(&handoff_key);
                        continue;
                    };
                    let bus = state.bus.clone();
                    let relay_peer = peer_endpoint_id;
                    let wire_circuit_id = data.circuit_id;
                    tokio::task::spawn_blocking(move || {
                        let link = RelayLink::from_incoming(
                            bus,
                            relay_peer.to_vec(),
                            wire_circuit_id,
                            receiver,
                        );
                        let tracker = std::sync::Mutex::new(
                            crate::handshake_timeout::HandshakeTracker::new(),
                        );
                        let result = crate::handle_inbound_link(
                            &runtime,
                            "ump.relay/1",
                            Box::new(link),
                            &tracker,
                        );
                        if let Err(error) = result {
                            log::debug!("[relay endpoint] handoff rejected: {error}");
                            if let Ok(mut runtime_state) = runtime.lock() {
                                runtime_state.relay_endpoint_handoffs.remove(&handoff_key);
                            }
                        }
                    });
                    push_event(
                        state,
                        "relay_endpoint_handoff_started",
                        now,
                        format!("session {session_id}: circuit {}", data.circuit_id),
                    );
                    continue;
                }
                // The circuit's peer end is the session that opened it: only
                // the owning session may send `RELAY_DATA` on the circuit
                // (relay.md §16-18).
                if state.relay.circuit_owner(internal_circuit_id) != Some(session_id) {
                    push_event(
                        state,
                        "relay_data_rejected",
                        now,
                        format!(
                            "circuit {}: sender is not the circuit owner",
                            data.circuit_id
                        ),
                    );
                    continue;
                }
                let internal_data = umc_wire::frames::relay::RelayDataFrame {
                    circuit_id: internal_circuit_id,
                    ..data.clone()
                };
                match state.relay.accept_upstream(
                    internal_circuit_id,
                    data.relay_sequence,
                    data.fin,
                    &data.data,
                    now,
                ) {
                    Ok(()) => {
                        if !state.relay.downstream_ready(internal_circuit_id) {
                            if !state.relay.has_paired_circuit(internal_circuit_id) {
                                append_downstream_failed_close(
                                    state,
                                    &mut outbound,
                                    data.circuit_id,
                                    internal_circuit_id,
                                    data.relay_sequence,
                                    now,
                                );
                                continue;
                            }
                            if let Err(error) = state
                                .relay
                                .queue_pending_data(internal_circuit_id, internal_data.clone())
                            {
                                push_event(
                                    state,
                                    "relay_pending_data_rejected",
                                    now,
                                    format!("circuit {}: {error}", data.circuit_id),
                                );
                                append_downstream_failed_close(
                                    state,
                                    &mut outbound,
                                    data.circuit_id,
                                    internal_circuit_id,
                                    data.relay_sequence,
                                    now,
                                );
                            }
                            continue;
                        }
                        // Cross-session forwarding (relay.md §18): the
                        // circuit's destination peer gets a fresh
                        // `RELAY_DATA` pushed into its session via the bus.
                        match state.relay.forward_data_frame(&internal_data, now) {
                            Ok((dest_peer, frame_bytes)) => {
                                let injected = state
                                    .bus
                                    .lock()
                                    .expect("session bus")
                                    .inject_outbound(&dest_peer, frame_bytes);
                                if let Err(e) = injected {
                                    push_event(
                                        state,
                                        "relay_forward_dropped",
                                        now,
                                        format!("circuit {}: {e:?}", data.circuit_id),
                                    );
                                    append_downstream_failed_close(
                                        state,
                                        &mut outbound,
                                        data.circuit_id,
                                        internal_circuit_id,
                                        data.relay_sequence,
                                        now,
                                    );
                                }
                            }
                            Err(e) => {
                                push_event(
                                    state,
                                    "relay_forward_dropped",
                                    now,
                                    format!("circuit {}: {e}", data.circuit_id),
                                );
                                append_downstream_failed_close(
                                    state,
                                    &mut outbound,
                                    data.circuit_id,
                                    internal_circuit_id,
                                    data.relay_sequence,
                                    now,
                                );
                            }
                        }
                    }
                    Err(e) => push_event(
                        state,
                        "relay_data_rejected",
                        now,
                        format!("circuit {}: {e}", data.circuit_id),
                    ),
                }
            }
            Frame::RelayClose(close) => {
                // A relay endpoint handoff has no local relay-service circuit
                // on the destination daemon. Dropping its bounded ingress
                // sender closes the adapter's receiver and lets the normal
                // session task terminate cleanly.
                if state
                    .relay_endpoint_handoffs
                    .remove(&(session_id, close.circuit_id))
                    .is_some()
                {
                    push_event(
                        state,
                        "relay_endpoint_handoff_closed",
                        now,
                        format!("session {session_id}: circuit {}", close.circuit_id),
                    );
                    continue;
                }
                let internal_circuit_id = state
                    .relay
                    .resolve_wire_circuit(session_id, close.circuit_id)
                    .unwrap_or(close.circuit_id);
                if state.relay.circuit_owner(internal_circuit_id) != Some(session_id) {
                    push_event(
                        state,
                        "relay_close_rejected",
                        now,
                        format!(
                            "circuit {}: sender is not the circuit owner",
                            close.circuit_id
                        ),
                    );
                    continue;
                }
                // Capture the paired leg before close_circuit removes the
                // destination mapping, then propagate the control frame on
                // the destination session when a paired circuit exists.
                let downstream = state.relay.forward_close(
                    internal_circuit_id,
                    close.reason_code,
                    close.final_relay_sequence,
                );
                match state
                    .relay
                    .close_circuit(internal_circuit_id, close.reason_code, now)
                {
                    Ok(()) => {
                        state.metrics.incr(metric_names::RELAY_CIRCUITS_CLOSED, 1);
                        if let Ok((destination, frame_bytes)) = downstream {
                            let inject_result = {
                                let bus = state.bus.lock().expect("session bus");
                                bus.inject_outbound(&destination, frame_bytes)
                            };
                            if let Err(error) = inject_result {
                                push_event(
                                    state,
                                    "relay_close_forward_dropped",
                                    now,
                                    format!("circuit {}: {error:?}", close.circuit_id),
                                );
                            }
                        }
                    }
                    Err(error) => push_event(
                        state,
                        "relay_close_rejected",
                        now,
                        format!("circuit {}: {error}", close.circuit_id),
                    ),
                }
            }
            Frame::Bundle(bundle) => {
                let admitted = state.bundle.admit_frame(bundle, &peer_endpoint_id, now);
                match admitted {
                    Ok(Some(id)) => {
                        state.metrics.incr(metric_names::BUNDLES_ADMITTED, 1);
                        push_event(
                            state,
                            "bundle_admitted",
                            now,
                            format!(
                                "frame id {} -> local {} ({} bytes from {peer_endpoint_id:02x?})",
                                String::from_utf8_lossy(&bundle.bundle_id),
                                hex_id(&id),
                                bundle.payload.len()
                            ),
                        );
                    }
                    Ok(None) => push_event(
                        state,
                        "bundle_chunk_received",
                        now,
                        format!(
                            "frame id {} chunk {}",
                            String::from_utf8_lossy(&bundle.bundle_id),
                            bundle.chunk_index
                        ),
                    ),
                    Err(e) => push_event(
                        state,
                        "bundle_rejected",
                        now,
                        format!(
                            "frame id {}: {e:?}",
                            String::from_utf8_lossy(&bundle.bundle_id)
                        ),
                    ),
                }
            }
            Frame::BundleAck(ack) => {
                let status = match ack.status {
                    0 => umc_bundle::manager::BundleStatus::Received,
                    1 => umc_bundle::manager::BundleStatus::CustodyAccepted,
                    2 => umc_bundle::manager::BundleStatus::Forwarded,
                    3 => umc_bundle::manager::BundleStatus::Delivered,
                    4 => umc_bundle::manager::BundleStatus::Rejected,
                    5 => umc_bundle::manager::BundleStatus::Expired,
                    _ => umc_bundle::manager::BundleStatus::Evicted,
                };
                if ack.bundle_id.len() == 32 {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&ack.bundle_id);
                    if state.bundle.record(&id).is_some() {
                        if status == umc_bundle::manager::BundleStatus::Delivered {
                            let _ = state.bundle.manager.release_custody(&id);
                        } else {
                            state.bundle.mark_status(&id, status);
                        }
                    }
                }
            }
            Frame::PeerHint(hint) => {
                let mesh_secret = state.config.mesh_secret.as_deref().map(str::as_bytes);
                match state.discovery.apply_received_hints_with_mesh_secret(
                    hint,
                    &peer_endpoint_id,
                    now,
                    mesh_secret,
                ) {
                    Ok(accepted) => push_event(
                        state,
                        "peer_hints_received",
                        now,
                        format!("session {session_id}: {accepted} candidate(s)"),
                    ),
                    Err(error) => push_event(
                        state,
                        "peer_hints_rejected",
                        now,
                        format!("session {session_id}: {error:?}"),
                    ),
                }
            }
            Frame::RouteRequest(request) => {
                state.metrics.incr(metric_names::ROUTE_REQUESTS_RECEIVED, 1);
                let request_id = internal_route_request_id(request.request_id);
                let peers: Vec<Vec<u8>> = state
                    .sessions
                    .snapshot()
                    .into_iter()
                    .filter_map(|(candidate_id, entry)| {
                        if candidate_id == session_id
                            || entry.peer_endpoint_id.as_slice() == peer_endpoint_id
                            || request
                                .path_exclusions
                                .iter()
                                .any(|excluded| excluded.as_slice() == entry.peer_endpoint_id)
                        {
                            None
                        } else {
                            Some(entry.peer_endpoint_id.to_vec())
                        }
                    })
                    .collect();
                // A destination hint that names a live adjacent endpoint is a
                // local match. An empty hint retains the direct-service
                // behavior used by local callers; otherwise the bounded peer
                // snapshot supplies forwarding candidates.
                let local_destination_match = !request.destination_hint.is_empty()
                    && state.node_identity.endpoint_id().as_slice() == request.destination_hint;
                let destination_peer_match = !request.destination_hint.is_empty()
                    && peers.iter().any(|peer| peer == &request.destination_hint);
                let local_match = request.destination_hint.is_empty()
                    || local_destination_match
                    || destination_peer_match
                    // A node with no forwarding candidates retains the
                    // legacy direct-service answer path for non-relay
                    // requests; a relay-capable request must have an actual
                    // adjacent candidate before it can claim reachability.
                    || (peers.is_empty() && !request.allow_relay);
                let candidates = if local_match { Vec::new() } else { peers };
                let flags = route_request_flags(request);
                let admission = state.routing.admit_route_request(
                    &request_id,
                    &peer_endpoint_id,
                    flags,
                    request.hop_limit,
                    request.expiration_delta,
                    &candidates,
                    now,
                );
                if matches!(
                    &admission,
                    Ok(umc_routing::request::Admission::Admit { .. })
                ) {
                    state.routing.remember_route_request_with_constraints(
                        request_id,
                        hash_destination(&request.destination_hint),
                        route_scope_from_request(request),
                        request.require_private_response,
                        request.hop_limit,
                        if request.allow_relay {
                            umc_routing::paths::DEFAULT_MAX_RELAYS
                        } else {
                            0
                        },
                        request.allow_relay,
                        now,
                    );
                }
                if !request.allow_relay && !local_match {
                    append_route_error(&mut outbound, request.request_id, ROUTE_NOT_FOUND);
                    continue;
                }
                match admission {
                    Ok(umc_routing::request::Admission::Admit {
                        hop_limit: 0,
                        forward_to,
                        ..
                    }) if !forward_to.is_empty() => {
                        // A request that still has forwarding candidates but
                        // no remaining hop cannot be represented as a direct
                        // route at this node (routing.md §8.2).
                        append_route_error(&mut outbound, request.request_id, ROUTE_EXPIRED);
                    }
                    Ok(umc_routing::request::Admission::Admit {
                        hop_limit,
                        remaining_lifetime_ms: _,
                        forward_to,
                    }) if !forward_to.is_empty() && hop_limit > 0 => {
                        let mut path_exclusions = request.path_exclusions.clone();
                        let local_endpoint = state.node_identity.endpoint_id().to_vec();
                        if !path_exclusions
                            .iter()
                            .any(|excluded| excluded == &local_endpoint)
                        {
                            if path_exclusions.len()
                                >= umc_wire::frames::routing::MAX_PATH_EXCLUSIONS
                            {
                                append_route_error(
                                    &mut outbound,
                                    request.request_id,
                                    ROUTE_RESOURCE_LIMIT,
                                );
                                continue;
                            }
                            path_exclusions.push(local_endpoint);
                        }
                        let forwarded = umc_wire::frames::routing::RouteRequestFrame {
                            hop_limit,
                            path_exclusions,
                            ..request.clone()
                        }
                        .encode();
                        let mut delivered = false;
                        if let Ok(bytes) = forwarded {
                            for next_hop in forward_to {
                                if state
                                    .bus
                                    .lock()
                                    .expect("session bus")
                                    .inject_outbound(&next_hop, bytes.clone())
                                    .is_ok()
                                {
                                    delivered = true;
                                }
                            }
                        }
                        if !delivered {
                            append_route_error(&mut outbound, request.request_id, ROUTE_NOT_FOUND);
                        }
                    }
                    Ok(umc_routing::request::Admission::Admit {
                        remaining_lifetime_ms,
                        ..
                    }) => {
                        let private_relay = request.require_private_response
                            && request.allow_relay
                            && (local_destination_match || destination_peer_match);
                        if request.require_private_response && !private_relay {
                            // A direct local match cannot satisfy a caller's
                            // private-route requirement. Do not advertise a
                            // weaker route for the requester to reject later.
                            append_route_error(
                                &mut outbound,
                                request.request_id,
                                ROUTE_POLICY_REJECTED,
                            );
                            continue;
                        }
                        let response_scope = route_scope_from_request(request);
                        let response_hops = if local_destination_match {
                            vec![PathHop {
                                peer: state.node_identity.endpoint_id().to_vec(),
                                scope: response_scope,
                                failure_domain: Vec::new(),
                                relay: false,
                            }]
                        } else {
                            let mut hops = vec![PathHop {
                                peer: state.node_identity.endpoint_id().to_vec(),
                                scope: response_scope,
                                failure_domain: Vec::new(),
                                relay: true,
                            }];
                            if destination_peer_match {
                                hops.push(PathHop {
                                    peer: request.destination_hint.clone(),
                                    scope: response_scope,
                                    failure_domain: Vec::new(),
                                    relay: false,
                                });
                            }
                            hops
                        };
                        let Ok(route_metadata) = encode_path_metadata(&response_hops) else {
                            append_route_error(
                                &mut outbound,
                                request.request_id,
                                ROUTE_RESOURCE_LIMIT,
                            );
                            continue;
                        };
                        let response = RouteResponseFrame {
                            request_id: request.request_id,
                            response_sequence: 0,
                            direct: !private_relay,
                            relay_required: private_relay,
                            store_forward_available: request.allow_store_forward,
                            local_path: true,
                            gateway_path: false,
                            route_lifetime: remaining_lifetime_ms,
                            next_hop_hint: if private_relay && !local_destination_match {
                                state.node_identity.endpoint_id().to_vec()
                            } else if local_destination_match || destination_peer_match {
                                request.destination_hint.clone()
                            } else {
                                peer_endpoint_id.to_vec()
                            },
                            route_metadata,
                            authentication: Vec::new(),
                        };
                        if let Ok(encoded) = response.encode() {
                            outbound.extend_from_slice(&encoded);
                        }
                    }
                    Ok(umc_routing::request::Admission::Suppress) => {}
                    Ok(umc_routing::request::Admission::Drop) => {
                        append_route_error(
                            &mut outbound,
                            request.request_id,
                            ROUTE_POLICY_REJECTED,
                        );
                    }
                    Err(error) => {
                        let code = match error {
                            umc_routing::request::AdmissionError::HopLimitZero
                            | umc_routing::request::AdmissionError::HopLimitExceeded => {
                                ROUTE_EXPIRED
                            }
                            umc_routing::request::AdmissionError::LifetimeTooLong => ROUTE_EXPIRED,
                            umc_routing::request::AdmissionError::FanoutExceeded
                            | umc_routing::request::AdmissionError::RateLimited => {
                                ROUTE_RESOURCE_LIMIT
                            }
                            umc_routing::request::AdmissionError::UnknownFlag => {
                                ROUTE_POLICY_REJECTED
                            }
                        };
                        append_route_error(&mut outbound, request.request_id, code);
                    }
                }
            }
            Frame::RouteResponse(response) => {
                let request_id = internal_route_request_id(response.request_id);
                let Some(remaining_lifetime_ms) = state
                    .routing
                    .reverse
                    .remaining_lifetime_ms(&request_id, now)
                else {
                    push_event(
                        state,
                        "route_response_rejected",
                        now,
                        format!("request {} has no live reverse state", response.request_id),
                    );
                    continue;
                };
                if let Err(error) = validate_response(response, remaining_lifetime_ms) {
                    push_event(
                        state,
                        "route_response_rejected",
                        now,
                        format!("request {}: {error:?}", response.request_id),
                    );
                    continue;
                }
                if state
                    .config
                    .effective_privacy_profile()
                    .includes(umc_core::privacy::PrivacyProfile::P2)
                    && response.direct
                {
                    push_event(
                        state,
                        "route_response_rejected",
                        now,
                        format!(
                            "request {} direct route violates effective private-route policy",
                            response.request_id
                        ),
                    );
                    continue;
                }
                let context = state.routing.route_context(&request_id, now);
                let (
                    destination_hash,
                    scope,
                    require_private_response,
                    max_hops,
                    max_relays,
                    allow_relay,
                ) = context.clone().map_or(
                    (
                        hash_destination(&response.next_hop_hint),
                        umc_routing::types::RouteScope::General,
                        false,
                        umc_routing::types::DEFAULT_HOP_LIMIT,
                        umc_routing::paths::DEFAULT_MAX_RELAYS,
                        true,
                    ),
                    |context| {
                        (
                            context.destination_hash,
                            context.scope,
                            context.require_private_response,
                            context.max_hops,
                            context.max_relays,
                            context.allow_relay,
                        )
                    },
                );
                if require_private_response && response.direct {
                    push_event(
                        state,
                        "route_response_rejected",
                        now,
                        format!(
                            "request {} direct route violates request privacy requirement",
                            response.request_id
                        ),
                    );
                    continue;
                }
                if response.relay_required && !allow_relay {
                    push_event(
                        state,
                        "route_response_rejected",
                        now,
                        format!(
                            "request {} relay route violates request policy",
                            response.request_id
                        ),
                    );
                    continue;
                }
                let upstream_peer = state.routing.reverse.upstream_of(&request_id, now);
                let mut forwarded_response = response.clone();
                if response.route_metadata.is_empty() {
                    if response.relay_required {
                        push_event(
                            state,
                            "route_response_rejected",
                            now,
                            format!(
                                "request {} relay route has no canonical path metadata",
                                response.request_id
                            ),
                        );
                        continue;
                    }
                } else if response.route_metadata.starts_with(PATH_METADATA_MAGIC) {
                    let mut path_hops = match decode_path_metadata(&response.route_metadata) {
                        Ok(hops) => hops,
                        Err(error) => {
                            push_event(
                                state,
                                "route_response_rejected",
                                now,
                                format!("request {} path metadata: {error:?}", response.request_id),
                            );
                            continue;
                        }
                    };
                    if upstream_peer.as_ref().is_some_and(|peer| !peer.is_empty()) {
                        let local_endpoint = state.node_identity.endpoint_id();
                        path_hops.insert(
                            0,
                            PathHop {
                                peer: local_endpoint.to_vec(),
                                scope,
                                failure_domain: Vec::new(),
                                relay: true,
                            },
                        );
                        forwarded_response.route_metadata = match encode_path_metadata(&path_hops) {
                            Ok(metadata) => metadata,
                            Err(error) => {
                                push_event(
                                    state,
                                    "route_response_rejected",
                                    now,
                                    format!(
                                        "request {} path metadata: {error:?}",
                                        response.request_id
                                    ),
                                );
                                continue;
                            }
                        };
                    }
                    let hops = match decode_path_metadata(&forwarded_response.route_metadata) {
                        Ok(hops) => hops,
                        Err(error) => {
                            push_event(
                                state,
                                "route_response_rejected",
                                now,
                                format!("request {} path metadata: {error:?}", response.request_id),
                            );
                            continue;
                        }
                    };
                    let policy = PathPolicy {
                        max_hops: usize::try_from(max_hops).unwrap_or(usize::MAX),
                        max_relays: if allow_relay { max_relays } else { 0 },
                        allow_direct: true,
                        ..PathPolicy::default()
                    };
                    if let Err(error) = state.routing.construct_path(scope, &[], &hops, policy) {
                        push_event(
                            state,
                            "route_response_rejected",
                            now,
                            format!("request {} path policy: {error:?}", response.request_id),
                        );
                        continue;
                    }
                } else if response.relay_required {
                    push_event(
                        state,
                        "route_response_rejected",
                        now,
                        format!(
                            "request {} relay route metadata is not canonical",
                            response.request_id
                        ),
                    );
                    continue;
                }
                if require_private_response {
                    // Do not forward the full downstream path back through
                    // an intermediate relay. Each branch carries only the
                    // local adjacent leg; the originator still receives an
                    // authenticated first-hop candidate and relays perform
                    // their own next-hop resolution.
                    forwarded_response.route_metadata = private_cache_path_metadata(
                        state,
                        &forwarded_response.route_metadata,
                        true,
                    );
                }
                let upstream = state.routing.reverse.route_response_with_sequence(
                    &request_id,
                    response.response_sequence,
                    now,
                );
                if upstream.is_none() {
                    push_event(
                        state,
                        "route_response_rejected",
                        now,
                        format!("request {} response sequence rejected", response.request_id),
                    );
                    continue;
                }
                let key = umc_routing::types::RouteKey {
                    destination_profile: 0,
                    destination_hash,
                    scope,
                    policy_class: 0,
                };
                let fallback_next_hop = state.sessions.lookup(session_id).map_or_else(
                    || peer_endpoint_id.to_vec(),
                    |entry| entry.peer_endpoint_id.to_vec(),
                );
                let cache_metadata = private_cache_path_metadata(
                    state,
                    &forwarded_response.route_metadata,
                    require_private_response,
                );
                let record = state.routing.record_route_response_with_metadata(
                    key,
                    // The response arrived over the authenticated adjacent
                    // session. That peer is the next leg this node can
                    // actually instantiate; the responder's hint describes
                    // a downstream leg and must not skip over it.
                    route_next_hop_label(&fallback_next_hop, &fallback_next_hop),
                    response.route_lifetime,
                    now,
                    upstream,
                    if response.route_metadata.starts_with(PATH_METADATA_MAGIC)
                        || !response.authentication.is_empty()
                    {
                        cache_metadata
                    } else {
                        Vec::new()
                    },
                );
                push_event(
                    state,
                    "route_learned",
                    now,
                    format!(
                        "request {} hop {} ({} ms)",
                        response.request_id, record.next_hop, response.route_lifetime
                    ),
                );
                if !record.source_peer.is_empty() {
                    if let Ok(encoded) = forwarded_response.encode() {
                        let _ = state
                            .bus
                            .lock()
                            .expect("session bus")
                            .inject_outbound(&record.source_peer, encoded);
                    }
                }
            }
            Frame::RouteError(error) => {
                let request_id = internal_route_request_id(error.request_id);
                if let Some(upstream) = state.routing.reverse.route_response(&request_id, now) {
                    if let Ok(encoded) = error.encode() {
                        let _ = state
                            .bus
                            .lock()
                            .expect("session bus")
                            .inject_outbound(&upstream, encoded);
                    }
                }
            }
            Frame::KeyUpdate(update) => {
                if let Err(e) = session.on_key_update(update.update_sequence) {
                    push_event(
                        state,
                        "key_update_rejected",
                        now,
                        format!("sequence {}: {e:?}", update.update_sequence),
                    );
                }
            }
            Frame::SessionTicket(ticket) => {
                // A ticket from the peer's daemon (handshake.md §35): the
                // credential for resuming THIS daemon as a client. The v1
                // daemon has no dial path, so the ticket is recorded — a
                // future resume attempt consumes it.
                push_event(
                    state,
                    "session_ticket_received",
                    now,
                    format!(
                        "lifetime {} ms, {} ticket bytes",
                        ticket.lifetime,
                        ticket.ticket.len()
                    ),
                );
            }
            _ => {}
        }
    }
    if outbound.is_empty() {
        None
    } else {
        Some(outbound)
    }
}

/// Wrapper for a pending-bundle delivery sweep: evict expired bundles, then
/// wrap the stored ciphertext of the next undelivered bundle in a `BUNDLE`
/// frame (bundles.md §10.1). One frame per sweep: bundle payloads can
/// approach the packet-size cap.
fn flush_pending_bundles(state: &mut RuntimeState, now: Instant) -> Vec<u8> {
    let mut outbound = Vec::new();
    // Evict expired bundles FIRST (bundles.md §11): they are removed (records
    // + object store) and never selected for delivery.
    let expired = state.bundle.expire_old(now);
    state
        .metrics
        .incr(metric_names::BUNDLES_EXPIRED, expired.len() as u64);
    let pending = state.bundle.pending_delivery(now);
    for id in pending.into_iter().take(BUNDLES_PER_FLUSH) {
        let Ok(Some((record, payload, chunk_index, chunk_final))) = state
            .bundle
            .next_delivery_chunk(&id, BUNDLE_FRAME_CHUNK_SIZE)
        else {
            continue;
        };
        let frame = BundleFrame {
            bundle_id: id.to_vec(),
            custody_requested: record.custody,
            delivery_ack_requested: true,
            do_not_replicate: false,
            local_scope_only: false,
            high_sensitivity: false,
            priority: record.priority,
            creation_time: record.created_at.0,
            expiration_time: record.expires_at.0,
            replication_limit: record.replication_limit,
            destination_hint: record.destination_hint.clone(),
            payload,
            bundle_auth: Vec::new(),
            chunk_index,
            chunk_final,
        };
        let Ok(encoded) = frame.encode() else {
            continue;
        };
        // One bundle per protected packet: a frame that cannot fit with
        // headers and AEAD tags is left for a later sweep.
        if encoded.len() + BUNDLE_PACKET_HEADROOM > umc_types::version::MAX_PACKET_SIZE {
            continue;
        }
        if chunk_final {
            state.bundle.mark_forwarded(&id);
        }
        push_event(
            state,
            "bundle_forwarded",
            now,
            format!("bundle {} chunk {} over session", hex_id(&id), chunk_index),
        );
        outbound.extend_from_slice(&encoded);
        break;
    }
    outbound
}

/// The 30-second pending-bundle sweep is due (bundles.md §10.1): at session
/// establishment and then every [`BUNDLE_FLUSH_INTERVAL_MS`].
fn bundle_flush_due(now: Instant, last: Option<Instant>) -> bool {
    last.map_or(true, |last| {
        now.0.saturating_sub(last.0) >= BUNDLE_FLUSH_INTERVAL_MS
    })
}

/// A key update is due: every [`KEY_UPDATE_INTERVAL_MS`] of session
/// lifetime, once the previous update completed (session.md §24).
fn key_rotation_due(now: Instant, established: Instant, last: Option<Instant>) -> bool {
    now.0.saturating_sub(established.0) >= KEY_UPDATE_INTERVAL_MS
        && last.map_or(true, |last| {
            now.0.saturating_sub(last.0) >= KEY_UPDATE_INTERVAL_MS
        })
}

/// A connection-ID rotation is due once per interval after session
/// establishment. Keeping this independent from key-update state lets the
/// privacy schedule proceed even when a key update is waiting for peer
/// confirmation.
fn dcid_rotation_due(
    now: Instant,
    established: Instant,
    last: Option<Instant>,
    interval_ms: u64,
) -> bool {
    now.0.saturating_sub(established.0) >= interval_ms
        && last.map_or(true, |last| now.0.saturating_sub(last.0) >= interval_ms)
}

/// Initiate a key update when due; returns the `KEY_UPDATE` frame payload.
/// A still-pending update (the peer has not confirmed) is not an error —
/// the next packet retries without advancing the schedule.
fn maybe_rotate_keys(
    session: &mut Session,
    now: Instant,
    established: Instant,
    last: &mut Option<Instant>,
) -> Option<Vec<u8>> {
    if !key_rotation_due(now, established, *last) {
        return None;
    }
    match session.initiate_key_update() {
        Ok(payload) => {
            *last = Some(now);
            Some(payload)
        }
        Err(_) => None,
    }
}

/// Issue and encode one fresh endpoint connection ID. The peer adopts the
/// advertised value when it receives `NEW_CONNECTION_ID`; local outbound
/// packets continue using the peer's current destination CID.
fn maybe_rotate_dcid(
    session: &mut Session,
    entropy: &dyn umc_types::runtime::EntropySource,
) -> Option<Vec<u8>> {
    session.issue_connection_id(entropy).ok()
}

/// Rebuild the relay-request flags byte from a decoded `RELAY_OPEN`
/// (relay.md §11.2, wire-format §46).
fn relay_request_flags(open: &umc_wire::frames::relay::RelayOpenFrame) -> u8 {
    let mut flags = 0u8;
    if open.bidirectional {
        flags |= 0x01;
    }
    if open.store_forward_allowed {
        flags |= 0x02;
    }
    if open.private_circuit {
        flags |= 0x04;
    }
    if open.multipath_allowed {
        flags |= 0x08;
    }
    flags
}

/// Stop accepting a circuit when its downstream leg disappears and notify
/// the upstream owner. Relay policy forbids accepting bytes and silently
/// dropping them when no destination leg is usable (relay.md §§19, 25).
fn append_downstream_failed_close(
    state: &mut RuntimeState,
    outbound: &mut Vec<u8>,
    wire_circuit_id: u64,
    internal_circuit_id: u64,
    final_relay_sequence: u64,
    now: Instant,
) {
    let _ = state.relay.close_circuit(
        internal_circuit_id,
        umc_relay::close::RelayReason::DownstreamFailed as u64,
        now,
    );
    if let Ok(encoded) = (RelayCloseFrame {
        circuit_id: wire_circuit_id,
        reason_code: umc_relay::close::RelayReason::DownstreamFailed as u64,
        final_relay_sequence,
    })
    .encode()
    {
        outbound.extend_from_slice(&encoded);
    }
}

/// Drain data accepted while a nested downstream leg was in `OPENING`.
/// Admission and quota accounting happened when the frames arrived; this
/// pass only performs the now-authorized wire translation.
fn flush_pending_relay_data(
    state: &mut RuntimeState,
    pending: Vec<umc_wire::frames::relay::RelayDataFrame>,
    now: Instant,
) {
    for frame in pending {
        let Ok((destination, encoded)) = state.relay.forward_data_frame(&frame, now) else {
            push_event(
                state,
                "relay_pending_data_dropped",
                now,
                format!("circuit {} lost its downstream leg", frame.circuit_id),
            );
            let _ = state.relay.close_circuit(
                frame.circuit_id,
                umc_relay::close::RelayReason::DownstreamFailed as u64,
                now,
            );
            continue;
        };
        let injection = {
            let bus = state.bus.lock().expect("session bus");
            bus.inject_outbound(&destination, encoded)
        };
        if let Err(error) = injection {
            push_event(
                state,
                "relay_pending_data_dropped",
                now,
                format!("circuit {}: {error:?}", frame.circuit_id),
            );
            let _ = state.relay.close_circuit(
                frame.circuit_id,
                umc_relay::close::RelayReason::DownstreamFailed as u64,
                now,
            );
        }
    }
}

/// Deliver close notifications produced by the bounded relay lifetime/idle
/// sweep. The sweep runs from every live session's timer, but its state pass
/// is serialized, so only the first timer that observes an expiry emits the
/// two peer-scoped notifications.
fn flush_relay_expiry_notifications(state: &mut RuntimeState, now: Instant) {
    let notifications = state.relay.sweep(now);
    for notification in notifications {
        let targets = [
            notification.upstream_session.map(|session_id| {
                (
                    session_id,
                    notification.upstream_wire_id,
                    notification.upstream_final_sequence,
                )
            }),
            notification.downstream_session.and_then(|session_id| {
                Some((
                    session_id,
                    notification.downstream_wire_id?,
                    notification.downstream_final_sequence?,
                ))
            }),
        ];
        for target in targets.into_iter().flatten() {
            let Some(peer) = state
                .bus
                .lock()
                .expect("session bus")
                .peer_for_session(target.0)
            else {
                continue;
            };
            let Ok(encoded) = (RelayCloseFrame {
                circuit_id: target.1,
                reason_code: notification.reason as u64,
                final_relay_sequence: target.2,
            })
            .encode() else {
                continue;
            };
            let inject_result = {
                let bus = state.bus.lock().expect("session bus");
                bus.inject_outbound(&peer, encoded)
            };
            if let Err(error) = inject_result {
                push_event(
                    state,
                    "relay_close_forward_dropped",
                    now,
                    format!(
                        "expired circuit {}: {error:?}",
                        notification.upstream_wire_id
                    ),
                );
            }
        }
    }
}

/// Rebuild the route-request flags byte from a decoded `ROUTE_REQUEST`
/// (routing.md §10, wire-format §52).
fn route_request_flags(request: &umc_wire::frames::routing::RouteRequestFrame) -> u8 {
    let mut flags = 0u8;
    if request.allow_relay {
        flags |= 0x01;
    }
    if request.allow_store_forward {
        flags |= 0x02;
    }
    if request.require_private_response {
        flags |= 0x04;
    }
    if request.local_scope_only {
        flags |= 0x08;
    }
    if request.gateway_query {
        flags |= 0x10;
    }
    flags
}

/// The frozen `ROUTE_REQUEST` flags distinguish local propagation from general
/// routing. Preserve that bounded scope in local reverse context; richer
/// introduced authorization remains represented by requester authentication.
fn route_scope_from_request(
    request: &umc_wire::frames::routing::RouteRequestFrame,
) -> umc_routing::types::RouteScope {
    if request.local_scope_only {
        umc_routing::types::RouteScope::LocalMesh
    } else {
        umc_routing::types::RouteScope::General
    }
}

fn append_route_error(outbound: &mut Vec<u8>, request_id: u64, error_code: u64) {
    let error = umc_wire::frames::routing::RouteErrorFrame {
        request_id,
        error_code,
        failed_hop_index: umc_wire::frames::routing::RouteErrorFrame::UNKNOWN_HOP,
        diagnostic: Vec::new(),
    };
    if let Ok(encoded) = error.encode() {
        outbound.extend_from_slice(&encoded);
    }
}

/// The wire routing frames carry a 64-bit request id; the routing service's
/// reverse table uses a fixed 128-bit key for compatibility with future
/// request-id extensions. Keep the zero-extension canonical at every wire
/// boundary so route errors and responses find the same reverse entry.
fn internal_route_request_id(request_id: u64) -> [u8; 16] {
    let mut internal = [0u8; 16];
    internal[..8].copy_from_slice(&request_id.to_be_bytes());
    internal
}

/// Route-cache destination hash for a route response's next-hop hint
/// (routing.md §17): `BLAKE2s-256("UMP-ROUTE-DEST-v1" || hint)`.
#[must_use]
pub fn hash_destination(hint: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    let mut hasher = blake2::Blake2s256::new();
    hasher.update(b"UMP-ROUTE-DEST-v1");
    hasher.update(hint);
    hasher.finalize().into()
}

/// Keep only the adjacent leg in a private route record. The originator may
/// retain the complete path it selected, but an intermediate relay must not
/// persist downstream destination/relay metadata merely because it forwarded
/// a route response (privacy.md §§9-12; routing.md §24).
fn private_cache_path_metadata(
    state: &RuntimeState,
    metadata: &[u8],
    private_route: bool,
) -> Vec<u8> {
    if !private_route || !metadata.starts_with(PATH_METADATA_MAGIC) {
        return metadata.to_vec();
    }
    let Ok(path) = decode_path_metadata(metadata) else {
        return Vec::new();
    };
    let local = state.node_identity.endpoint_id().to_vec();
    let next = path.iter().find(|hop| hop.peer != local).cloned();
    let Some(next) = next else {
        return Vec::new();
    };
    encode_path_metadata(&[
        PathHop {
            peer: local,
            scope: next.scope,
            failure_domain: Vec::new(),
            relay: true,
        },
        PathHop {
            peer: next.peer,
            scope: next.scope,
            failure_domain: Vec::new(),
            relay: next.relay,
        },
    ])
    .unwrap_or_default()
}

/// Keep a route's next-hop hint useful after it crosses the string-backed
/// cache/control surfaces. Human-readable hints remain unchanged for legacy
/// callers; binary endpoint identifiers use lowercase hex so they are stable,
/// reversible labels rather than lossy UTF-8 replacements.
fn route_next_hop_label(hint: &[u8], fallback: &[u8]) -> String {
    let bytes = if hint.is_empty() { fallback } else { hint };
    if bytes
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut label = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(label, "{byte:02x}");
    }
    label
}

/// Decode the stable route-cache label back to an endpoint id. Binary
/// endpoint ids cross the control/cache string boundary as lowercase hex;
/// human-readable legacy peer labels remain byte strings.
fn decode_route_next_hop(label: &str) -> Option<Vec<u8>> {
    let bytes = label.as_bytes();
    if bytes.len() == 64 && bytes.iter().all(u8::is_ascii_hexdigit) {
        let mut decoded = Vec::with_capacity(32);
        for pair in bytes.chunks_exact(2) {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            decoded.push(u8::try_from((high << 4) | low).ok()?);
        }
        return Some(decoded);
    }
    (!bytes.is_empty()).then(|| bytes.to_vec())
}

/// Select a live adjacent hop for a private relay extension. A route cache
/// record describes the final destination, but its `next_hop` is always the
/// immediate authenticated peer learned on this node; never skip directly to
/// the terminal endpoint (routing.md §§17, 22-24; relay.md §15).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayRouteHop {
    peer: Vec<u8>,
    terminal: bool,
}

fn relay_next_hop_for_destination(
    state: &RuntimeState,
    destination: &[u8],
    incoming_peer: &[u8],
    now: Instant,
) -> Option<RelayRouteHop> {
    use umc_routing::paths::{decode_path_metadata, PathPolicy, PATH_METADATA_MAGIC};
    use umc_routing::types::{RouteKey, RouteScope, RouteState, DEFAULT_HOP_LIMIT};

    let destination_hash =
        decode_privacy_route_token(destination).unwrap_or_else(|| hash_destination(destination));
    // Prefer the narrowest valid scope. If a local route disappears, a
    // broader authenticated route can still service the private circuit.
    for scope in [
        RouteScope::LinkLocal,
        RouteScope::LocalMesh,
        RouteScope::Introduced,
        RouteScope::General,
    ] {
        let key = RouteKey {
            destination_profile: 0,
            destination_hash,
            scope,
            policy_class: 0,
        };
        let Some(record) = state
            .routing
            .diverse_route_candidates(&key, now, umc_routing::cache::DEFAULT_CACHE_TARGET)
            .into_iter()
            .next()
        else {
            continue;
        };
        if record.state != RouteState::Usable || record.is_expired(now) {
            continue;
        }
        // Private relay extension requires canonical path evidence. This
        // prevents an old direct-route snapshot from silently becoming a
        // multi-hop relay route.
        if !record.metadata.starts_with(PATH_METADATA_MAGIC) {
            continue;
        }
        let Ok(path) = decode_path_metadata(&record.metadata) else {
            continue;
        };
        let policy = PathPolicy {
            max_hops: usize::try_from(DEFAULT_HOP_LIMIT).unwrap_or(usize::MAX),
            max_relays: umc_routing::paths::DEFAULT_MAX_RELAYS,
            allow_direct: false,
            ..PathPolicy::default()
        };
        if state
            .routing
            .construct_path(scope, &[], &path, policy)
            .is_err()
        {
            continue;
        }
        let Some(next_hop) = decode_route_next_hop(&record.next_hop) else {
            continue;
        };
        let next_hop = if state
            .bus
            .lock()
            .expect("session bus")
            .lookup(&next_hop)
            .is_some()
        {
            next_hop
        } else {
            let Some(endpoint) = state
                .config
                .static_peers
                .iter()
                .find(|peer| peer.address == record.next_hop)
                .and_then(|peer| crate::static_peers::parse_endpoint_id(&peer.endpoint_id).ok())
            else {
                continue;
            };
            endpoint.to_vec()
        };
        if next_hop == incoming_peer {
            continue;
        }
        let live = state
            .bus
            .lock()
            .expect("session bus")
            .lookup(&next_hop)
            .is_some();
        if live {
            let terminal = path
                .last()
                .is_some_and(|last| !last.relay && last.peer == next_hop);
            return Some(RelayRouteHop {
                peer: next_hop,
                terminal,
            });
        }
    }
    None
}

/// Allocate a peer-scoped wire id for a relay extension. The process-local
/// circuit id is deliberately never exposed on the next session.
fn fresh_relay_wire_id(state: &RuntimeState, session_id: u64) -> u64 {
    use rand_core::RngCore;
    loop {
        let mut bytes = [0u8; 8];
        rand_core::OsRng.fill_bytes(&mut bytes);
        let wire_id = u64::from_be_bytes(bytes) & ((1u64 << 62) - 1);
        let wire_id = wire_id.max(1);
        if state
            .relay
            .resolve_wire_circuit(session_id, wire_id)
            .is_none()
        {
            return wire_id;
        }
    }
}

/// Compact hex of a 32-byte id for event details.
fn hex_id(id: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(16);
    for b in &id[..8] {
        write!(out, "{b:02x}").expect("write to string");
    }
    out
}

fn push_event(state: &mut RuntimeState, kind: &str, now: Instant, detail: String) {
    state
        .events
        .lock()
        .expect("event log")
        .push(crate::event_log::DaemonEvent {
            kind: kind.to_string(),
            at_ms: now.0,
            detail,
        });
}

/// Carrier backpressure gate (congestion.md §16): when the link's carrier
/// queue is past 80% of its capacity, non-exempt (data) payloads are held
/// back from the wire so the queue can drain. ACK and PING payloads are
/// always sent — refusing them would stall the acknowledgment loop or the
/// PTO probe, and they are a few bytes at most. The dropped payload is a
/// fresh packet the session already recorded (it was built by
/// `build_outbound`): the peer re-requests stream data, or the session's
/// loss/PTO path retransmits it, so no data is lost.
fn should_backpressure(link: &BoxLink, payload: &[u8]) -> bool {
    let props = link.properties();
    !payload_is_exempt(payload)
        && props.queue_capacity > 0
        && props.queue_bytes > props.queue_capacity * 4 / 5
}

/// Session writer: drain the applications' outbound channels and send the
/// echoed frames back on the same streams. Runs independently of the link
/// recv so echoes reach the peer without further inbound traffic.
///
/// This is the only paced send arm (congestion.md §12): the echo path
/// carries the bulk app data, so it waits for the controller's pacing
/// schedule before the wire and consumes the pacing tokens at the real
/// send time. The reader's ACK/control tail, the bus arm, keepalives, PTO
/// probes, and retransmits all send immediately — control and recovery
/// traffic must not be delayed (congestion.md §12.2).
#[allow(clippy::too_many_arguments)]
async fn writer_loop(
    links: &Arc<SessionLinkSet>,
    session: &Arc<tokio::sync::Mutex<Session>>,
    clock: &Arc<dyn Clock>,
    shutdown_flag: &Arc<AtomicBool>,
    ended: &Arc<AtomicBool>,
    app_echo_rx: &Arc<Mutex<HashMap<Vec<u8>, AppRx>>>,
    session_id: u64,
    privacy_policy: PrivacyRuntimePolicy,
) {
    loop {
        if shutdown_flag.load(Ordering::Relaxed) || ended.load(Ordering::Relaxed) {
            break;
        }
        let echo = {
            let mut map = app_echo_rx.lock().expect("app echo receivers");
            let mut all_disconnected = true;
            let mut frame = None;
            for receiver in map.values_mut() {
                match receiver.try_recv_stream_frame() {
                    Ok(f) => {
                        all_disconnected = false;
                        frame = Some(f);
                        break;
                    }
                    Err(TryRecvError::Empty) => {
                        all_disconnected = false;
                    }
                    Err(TryRecvError::Disconnected) => {}
                }
            }
            if frame.is_none() && all_disconnected {
                break;
            }
            frame
        };
        let Some((stream_id, data)) = echo else {
            tokio::time::sleep(ECHO_POLL_INTERVAL).await;
            continue;
        };
        let jitter_ms = if privacy_policy.timing_jitter_ms() > 0 {
            privacy_jitter_delay_ms(privacy_policy.timing_jitter_ms())
        } else {
            0
        };
        if jitter_ms > 0 {
            tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
        }
        let now = clock.now();
        let payload = {
            let mut session = session.lock().await;
            match session.send_stream_data(stream_id, &data, false) {
                Ok(payload) => payload,
                Err(e) => {
                    log::debug!("[session {session_id}] echo send error: {e:?}");
                    continue;
                }
            }
        };
        let (outbound, pace_wait) = {
            let mut session = session.lock().await;
            match session.build_outbound(clock.as_ref(), now, &payload) {
                Ok(Some(outbound)) => {
                    // App-originated echo traffic: resets the idle timer
                    // (session.md §22).
                    session.touch(now);
                    // Pacing (congestion.md §12): the echo send is the main
                    // data path, so it waits for the pacing bucket before
                    // the wire. The reader's ACK/control tail, the bus arm,
                    // keepalives, probes, and retransmits skip pacing —
                    // control and recovery traffic must not be delayed.
                    let pace_wait = session.congestion_mut().next_send_time(now, outbound.len());
                    (outbound, pace_wait)
                }
                _ => continue,
            }
        };
        // Carrier backpressure (congestion.md §16): when the carrier's
        // outbound queue is past 80% of capacity, the fresh data packet is
        // skipped rather than piled onto the queue. The session recorded
        // the payload on `build_outbound`; the peer re-requests stream
        // data, or the loss/PTO path retransmits it. ACK/PING payloads are
        // exempt and always sent.
        let Some(active_link) = links.get(links.active_path()) else {
            break;
        };
        if should_backpressure(&active_link, &outbound) {
            log::debug!("[session {session_id}] echo send backpressured (carrier queue >80%)");
            continue;
        }
        // Sleep out the spacing interval (congestion.md §12.1): the wait is
        // `deficit / rate` past `now`, so the send lands on the pacing
        // schedule. Pacing is off until the session's RTT has a sample.
        if let Some(wait) = pace_wait {
            let delay_ms = wait.duration_since(clock.now()).as_millis();
            if delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
        log::debug!(
            "[session {session_id}] echo stream {stream_id} ({} bytes)",
            data.len()
        );
        let wire_bytes = outbound.len();
        let sent = tokio::task::block_in_place(|| {
            links.send_active(OutboundPacket {
                bytes: outbound,
                control: false,
                deadline_ms: None,
            })
        });
        if sent.is_ok() {
            // Consume the pacing tokens at the real send time, so the token
            // clock never drifts across the paced sleep (congestion.md §12).
            let mut session = session.lock().await;
            session
                .congestion_mut()
                .consume_pacing(wire_bytes, clock.now());
        } else if let Err(e) = sent {
            log::debug!("[session {session_id}] echo send error: {e:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use crate::session_manager::SessionEntry;
    use std::sync::atomic::{AtomicU64, Ordering};
    use umc_session::congestion::SMSS;
    use umc_session::sent_packet::SentPacket;
    use umc_session::session::{
        Role, Session, SessionConfig, SessionError, SessionState, CLOSE_REASON_IDLE_TIMEOUT,
        IDLE_TIMEOUT_MS, MIN_DRAIN_MS,
    };
    use umc_session::spaces::PacketSpace;
    use umc_wire::frame::Frame as WireFrame;
    use umc_wire::frames::path::KeyUpdateFrame;
    use umc_wire::frames::relay::{RelayDataFrame, RelayOpenFrame, RelayStatusFrame};
    use umc_wire::frames::routing::RouteRequestFrame;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_state() -> (RuntimeState, tokio::sync::mpsc::Sender<()>) {
        let dir = std::env::temp_dir().join(format!(
            "umcd-session-task-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let config = NodeConfig {
            data_dir: dir,
            ..NodeConfig::default()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel::<()>(1);
        let state = RuntimeState::new(config, tx.clone()).expect("runtime state");
        state.sessions.register(
            1,
            SessionEntry {
                peer_endpoint_id: [7u8; 32],
                carrier_type: "ump.tcp/1".into(),
                task: tokio::spawn(async {}).abort_handle(),
                established_at_ms: 0,
                privacy_profile: 0,
                direct_path_allowed: true,
                traffic_padding_active: false,
            },
        );
        (state, tx)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn private_route_cache_metadata_keeps_only_adjacent_leg() {
        let (state, _tx) = test_state();
        let local = state.node_identity.endpoint_id();
        let next = [8u8; 32];
        let destination = [9u8; 32];
        let metadata = encode_path_metadata(&[
            PathHop {
                peer: local.to_vec(),
                scope: umc_routing::types::RouteScope::General,
                failure_domain: Vec::new(),
                relay: true,
            },
            PathHop {
                peer: next.to_vec(),
                scope: umc_routing::types::RouteScope::General,
                failure_domain: Vec::new(),
                relay: true,
            },
            PathHop {
                peer: destination.to_vec(),
                scope: umc_routing::types::RouteScope::General,
                failure_domain: Vec::new(),
                relay: false,
            },
        ])
        .expect("path metadata");
        let redacted = private_cache_path_metadata(&state, &metadata, true);
        let hops = decode_path_metadata(&redacted).expect("redacted metadata");
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].peer, local);
        assert_eq!(hops[1].peer, next);
        assert!(!redacted
            .windows(destination.len())
            .any(|window| window == destination));
        assert_ne!(
            privacy_route_token_with_nonce(&destination, [1u8; 16]),
            privacy_route_token_with_nonce(&destination, [2u8; 16]),
            "route tokens must be scoped per private connection"
        );
    }

    fn test_session() -> Session {
        let mut session = Session::new(
            SessionConfig {
                role: Role::Client,
                dcid: vec![3u8; 8],
                local_traffic_secret: [1u8; 32],
                remote_traffic_secret: [2u8; 32],
                initial_max_data: umc_session::session::DEFAULT_INITIAL_MAX_DATA,
                initial_max_stream_data: umc_session::session::DEFAULT_INITIAL_MAX_STREAM_DATA,
                max_ack_delay_ms: 25,
            },
            &crate::runtime_adapters::OsClock,
        )
        .expect("session");
        // The shared stateless-reset secret (handshake.md §26): both sides
        // derive the same token.
        session.set_stateless_reset_secret([9u8; 32]);
        session
    }

    /// Peer session with swapped traffic secrets so the two can exchange
    /// protected packets (the client builds with `[1u8; 32]`, the peer
    /// parses with the same key).
    fn peer_session() -> Session {
        let mut session = Session::new(
            SessionConfig {
                role: Role::Server,
                dcid: vec![3u8; 8],
                local_traffic_secret: [2u8; 32],
                remote_traffic_secret: [1u8; 32],
                initial_max_data: umc_session::session::DEFAULT_INITIAL_MAX_DATA,
                initial_max_stream_data: umc_session::session::DEFAULT_INITIAL_MAX_STREAM_DATA,
                max_ack_delay_ms: 25,
            },
            &crate::runtime_adapters::OsClock,
        )
        .expect("peer session");
        session.set_stateless_reset_secret([9u8; 32]);
        session
    }

    /// Deterministic clock for loss-detection timing.
    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now(&self) -> Instant {
            Instant(self.0)
        }
    }

    /// Runtime duration (the `Duration` in scope at module level is the std
    /// one for tokio timers; `Instant` arithmetic needs the runtime type).
    fn ms(millis: u64) -> umc_types::runtime::Duration {
        umc_types::runtime::Duration::from_millis(millis)
    }

    /// Link that records every outbound packet.
    #[derive(Default)]
    struct RecordingLink {
        sent: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl umc_carrier::Link for RecordingLink {
        fn properties(&self) -> umc_carrier::types::LinkProperties {
            umc_carrier::types::LinkProperties {
                reliability: umc_carrier::types::Reliability::ReliableUntilLinkFailure,
                ordering: umc_carrier::types::Ordering::Ordered,
                current_mtu: 65_535,
                queue_bytes: 0,
                queue_capacity: 2 * 1024 * 1024,
                estimated_rtt_ms: None,
                estimated_loss: None,
                metered: false,
            }
        }
        fn send(
            &self,
            p: umc_carrier::types::OutboundPacket,
        ) -> Result<umc_carrier::types::SendResult, umc_carrier::error::CarrierError> {
            self.sent.lock().expect("link sent").push(p.bytes);
            Ok(umc_carrier::types::SendResult::Accepted {
                queue_state: umc_carrier::types::QueueState::SentToMedium,
            })
        }
        fn recv(
            &self,
        ) -> Result<umc_carrier::types::InboundPacket, umc_carrier::error::CarrierError> {
            Err(umc_carrier::error::CarrierError::new(
                umc_carrier::error::CarrierErrorKind::WouldBlock,
                "recv",
            ))
        }
        fn events(
            &self,
        ) -> Result<umc_carrier::types::LinkEvent, umc_carrier::error::CarrierError> {
            Err(umc_carrier::error::CarrierError::new(
                umc_carrier::error::CarrierErrorKind::WouldBlock,
                "events",
            ))
        }
        fn close(&self, _reason: &str) -> Result<(), umc_carrier::error::CarrierError> {
            Ok(())
        }
    }

    /// Link reporting a configurable queue fill (carrier backpressure,
    /// congestion.md §16).
    struct BackpressuredLink {
        queue_bytes: usize,
        sent: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl umc_carrier::Link for BackpressuredLink {
        fn properties(&self) -> umc_carrier::types::LinkProperties {
            umc_carrier::types::LinkProperties {
                reliability: umc_carrier::types::Reliability::ReliableUntilLinkFailure,
                ordering: umc_carrier::types::Ordering::Ordered,
                current_mtu: 65_535,
                queue_bytes: self.queue_bytes,
                queue_capacity: 2 * 1024 * 1024,
                estimated_rtt_ms: None,
                estimated_loss: None,
                metered: false,
            }
        }
        fn send(
            &self,
            p: umc_carrier::types::OutboundPacket,
        ) -> Result<umc_carrier::types::SendResult, umc_carrier::error::CarrierError> {
            self.sent.lock().expect("link sent").push(p.bytes);
            Ok(umc_carrier::types::SendResult::Accepted {
                queue_state: umc_carrier::types::QueueState::SentToMedium,
            })
        }
        fn recv(
            &self,
        ) -> Result<umc_carrier::types::InboundPacket, umc_carrier::error::CarrierError> {
            Err(umc_carrier::error::CarrierError::new(
                umc_carrier::error::CarrierErrorKind::WouldBlock,
                "recv",
            ))
        }
        fn events(
            &self,
        ) -> Result<umc_carrier::types::LinkEvent, umc_carrier::error::CarrierError> {
            Err(umc_carrier::error::CarrierError::new(
                umc_carrier::error::CarrierErrorKind::WouldBlock,
                "events",
            ))
        }
        fn close(&self, _reason: &str) -> Result<(), umc_carrier::error::CarrierError> {
            Ok(())
        }
    }

    /// Decode a combined outbound payload into its frames.
    fn decode_outbound(payload: &[u8]) -> Vec<WireFrame> {
        umc_wire::frame::decode_frames(payload).expect("frames")
    }

    /// The body of a single-frame payload with the given type. `RELAY_STATUS`
    /// is a length-delimited type the generic frame parser refuses, so the
    /// status answer is decoded body-first.
    fn body_of(payload: &[u8], expected: umc_types::frame::FrameType) -> &[u8] {
        let (ty, n) = umc_wire::varint::decode(payload).expect("type varint");
        assert_eq!(umc_types::frame::FrameType(ty), expected);
        &payload[n..]
    }

    fn relay_status_of(payload: &[u8]) -> umc_wire::frames::relay::RelayStatusFrame {
        let body = body_of(payload, umc_types::frame::FrameType::RELAY_STATUS);
        umc_wire::frames::relay::RelayStatusFrame::decode_length_delimited(body)
            .expect("relay status body")
            .0
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relay_open_answered_with_status() {
        let (mut state, _tx) = test_state();
        let open = RelayOpenFrame {
            circuit_id: 5,
            bidirectional: true,
            store_forward_allowed: false,
            private_circuit: false,
            multipath_allowed: false,
            requested_lifetime: 600_000,
            requested_byte_quota: 1_048_576,
            next_hop_hint: Vec::new(),
            authorization: Vec::new(),
        };
        let mut session = test_session();
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayOpen(open.clone())],
            Instant(0),
        )
        .expect("relay open must be answered");
        let status = relay_status_of(&outbound);
        assert_eq!(status.circuit_id, 5);
        assert_eq!(status.status_code, RELAY_STATUS_ACCEPTED);
        assert_eq!(status.granted_lifetime, 600_000);
        assert_eq!(status.granted_byte_quota, 1_048_576);
        assert!(status.bidirectional_granted);
        // The opening session becomes the circuit's peer end.
        assert_eq!(state.relay.circuit_owner(1), Some(1));
        let duplicate = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayOpen(open.clone())],
            Instant(1),
        )
        .expect("identical relay open must replay its status");
        assert_eq!(relay_status_of(&duplicate), status);
        assert_eq!(state.relay.circuit_count(), 1);
        let mut conflict = open.clone();
        conflict.requested_byte_quota += 1;
        let conflict_response = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayOpen(conflict)],
            Instant(2),
        )
        .expect("conflicting relay open must receive a fail-closed status");
        assert_eq!(
            relay_status_of(&conflict_response).status_code,
            RELAY_STATUS_AUTH_FAILED
        );
        assert_eq!(state.relay.circuit_count(), 1);
        // Admission counts the peer's circuits: a second open still admits.
        let second = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayOpen(RelayOpenFrame {
                circuit_id: 6,
                ..open
            })],
            Instant(0),
        )
        .expect("second open answered");
        let second_status = relay_status_of(&second);
        assert_eq!(second_status.circuit_id, 6);
        assert_eq!(second_status.status_code, RELAY_STATUS_ACCEPTED);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::too_many_lines)]
    async fn private_relay_open_negotiates_scoped_downstream_hop() {
        let (mut state, _tx) = test_state();
        let next_hop = [8u8; 32];
        let destination = [9u8; 32];
        state.sessions.register(
            2,
            SessionEntry {
                peer_endpoint_id: next_hop,
                carrier_type: "ump.tcp/1".into(),
                task: tokio::spawn(async {}).abort_handle(),
                established_at_ms: 0,
                privacy_profile: 0,
                direct_path_allowed: true,
                traffic_padding_active: false,
            },
        );
        let (in_tx, _in_rx) = tokio::sync::mpsc::unbounded_channel();
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
        let (origin_in_tx, _origin_in_rx) = tokio::sync::mpsc::unbounded_channel();
        let (origin_out_tx, mut origin_out_rx) = tokio::sync::mpsc::unbounded_channel();
        state
            .bus
            .lock()
            .expect("bus")
            .register(next_hop.to_vec(), 2, in_tx, out_tx);
        state
            .bus
            .lock()
            .expect("bus")
            .register(vec![7u8; 32], 1, origin_in_tx, origin_out_tx);
        let metadata = encode_path_metadata(&[
            PathHop {
                peer: next_hop.to_vec(),
                scope: umc_routing::types::RouteScope::General,
                failure_domain: Vec::new(),
                relay: true,
            },
            PathHop {
                peer: destination.to_vec(),
                scope: umc_routing::types::RouteScope::General,
                failure_domain: Vec::new(),
                relay: false,
            },
        ])
        .expect("path metadata");
        let _ = state.routing.record_route_response_with_metadata(
            umc_routing::types::RouteKey {
                destination_profile: 0,
                destination_hash: hash_destination(&destination),
                scope: umc_routing::types::RouteScope::General,
                policy_class: 0,
            },
            route_next_hop_label(&next_hop, &next_hop),
            60_000,
            Instant(0),
            None,
            metadata,
        );
        let open = RelayOpenFrame {
            circuit_id: 55,
            bidirectional: true,
            store_forward_allowed: false,
            private_circuit: true,
            multipath_allowed: false,
            requested_lifetime: 60_000,
            requested_byte_quota: 1_024,
            next_hop_hint: privacy_route_token(&destination),
            authorization: Vec::new(),
        };
        let mut session = test_session();
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayOpen(open)],
            Instant(1),
        )
        .expect("relay open status");
        let status = relay_status_of(&outbound);
        assert_eq!(status.status_code, RELAY_STATUS_ACCEPTED);
        assert!(status.private_handling_granted);
        assert_eq!(state.relay.circuit_count(), 2);

        let nested = out_rx.recv().await.expect("nested relay open");
        let frames = decode_outbound(&nested);
        let nested = frames
            .into_iter()
            .find_map(|frame| match frame {
                WireFrame::RelayOpen(open) => Some(open),
                _ => None,
            })
            .expect("nested open frame");
        assert_ne!(nested.circuit_id, 55);
        assert_eq!(nested.next_hop_hint, privacy_route_token(&destination));
        assert!(!nested
            .next_hop_hint
            .windows(destination.len())
            .any(|window| window == destination));
        assert!(nested.private_circuit);

        let mut origin_session = test_session();
        let _ = handle_control_frames(
            &mut state,
            1,
            &mut origin_session,
            &[WireFrame::RelayData(RelayDataFrame {
                circuit_id: 55,
                relay_sequence: 0,
                fin: false,
                ack_requested: false,
                high_priority: false,
                data: b"opaque".to_vec(),
            })],
            Instant(2),
        );
        assert!(
            out_rx.try_recv().is_err(),
            "data waits for downstream acceptance"
        );

        let downstream_status = RelayStatusFrame {
            circuit_id: nested.circuit_id,
            status_sequence: 0,
            status_code: RELAY_STATUS_ACCEPTED,
            bidirectional_granted: true,
            private_handling_granted: true,
            multipath_granted: false,
            downstream_authenticated: false,
            retryable: false,
            granted_lifetime: 60_000,
            granted_byte_quota: 1_024,
            maximum_relay_payload: 64 * 1024,
            diagnostic: Vec::new(),
            authentication: Vec::new(),
        };
        let mut next_hop_session = test_session();
        let _ = handle_control_frames(
            &mut state,
            2,
            &mut next_hop_session,
            &[WireFrame::RelayStatus(downstream_status)],
            Instant(3),
        );
        let forwarded_status = origin_out_rx.recv().await.expect("upstream status");
        assert_eq!(
            relay_status_of(&forwarded_status).circuit_id,
            55,
            "downstream status must be rewritten to the origin wire id"
        );

        let forwarded_data = out_rx.recv().await.expect("downstream data");
        let frames = decode_outbound(&forwarded_data);
        let forwarded_data = frames
            .into_iter()
            .find_map(|frame| match frame {
                WireFrame::RelayData(data) => Some(data),
                _ => None,
            })
            .expect("forwarded relay data");
        assert_eq!(forwarded_data.circuit_id, nested.circuit_id);
        assert_eq!(forwarded_data.data, b"opaque");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::too_many_lines)]
    async fn private_relay_open_repeats_extension_at_second_relay() {
        let destination = [9u8; 32];
        let first_hop = [8u8; 32];
        let second_hop = [10u8; 32];
        let (mut first, _tx) = test_state();
        first.sessions.register(
            2,
            SessionEntry {
                peer_endpoint_id: first_hop,
                carrier_type: "ump.tcp/1".into(),
                task: tokio::spawn(async {}).abort_handle(),
                established_at_ms: 0,
                privacy_profile: 0,
                direct_path_allowed: true,
                traffic_padding_active: false,
            },
        );
        let (first_in_tx, _first_in_rx) = tokio::sync::mpsc::unbounded_channel();
        let (first_out_tx, mut first_out_rx) = tokio::sync::mpsc::unbounded_channel();
        first
            .bus
            .lock()
            .expect("bus")
            .register(first_hop.to_vec(), 2, first_in_tx, first_out_tx);
        let first_metadata = encode_path_metadata(&[
            PathHop {
                peer: first_hop.to_vec(),
                scope: umc_routing::types::RouteScope::General,
                failure_domain: Vec::new(),
                relay: true,
            },
            PathHop {
                peer: destination.to_vec(),
                scope: umc_routing::types::RouteScope::General,
                failure_domain: Vec::new(),
                relay: false,
            },
        ])
        .expect("first path metadata");
        let _ = first.routing.record_route_response_with_metadata(
            umc_routing::types::RouteKey {
                destination_profile: 0,
                destination_hash: hash_destination(&destination),
                scope: umc_routing::types::RouteScope::General,
                policy_class: 0,
            },
            route_next_hop_label(&first_hop, &first_hop),
            60_000,
            Instant(0),
            None,
            first_metadata,
        );
        let mut first_session = test_session();
        let first_open = RelayOpenFrame {
            circuit_id: 55,
            bidirectional: true,
            store_forward_allowed: false,
            private_circuit: true,
            multipath_allowed: false,
            requested_lifetime: 60_000,
            requested_byte_quota: 1_024,
            next_hop_hint: privacy_route_token(&destination),
            authorization: Vec::new(),
        };
        let first_status = handle_control_frames(
            &mut first,
            1,
            &mut first_session,
            &[WireFrame::RelayOpen(first_open)],
            Instant(1),
        )
        .expect("first relay status");
        assert_eq!(
            relay_status_of(&first_status).status_code,
            RELAY_STATUS_ACCEPTED
        );
        let first_nested_bytes = first_out_rx.recv().await.expect("first nested open");
        let first_nested = decode_outbound(&first_nested_bytes)
            .into_iter()
            .find_map(|frame| match frame {
                WireFrame::RelayOpen(open) => Some(open),
                _ => None,
            })
            .expect("first nested frame");

        let (mut second, _tx) = test_state();
        second.sessions.register(
            2,
            SessionEntry {
                peer_endpoint_id: second_hop,
                carrier_type: "ump.tcp/1".into(),
                task: tokio::spawn(async {}).abort_handle(),
                established_at_ms: 0,
                privacy_profile: 0,
                direct_path_allowed: true,
                traffic_padding_active: false,
            },
        );
        let (second_in_tx, _second_in_rx) = tokio::sync::mpsc::unbounded_channel();
        let (second_out_tx, mut second_out_rx) = tokio::sync::mpsc::unbounded_channel();
        second.bus.lock().expect("bus").register(
            second_hop.to_vec(),
            2,
            second_in_tx,
            second_out_tx,
        );
        let second_metadata = encode_path_metadata(&[
            PathHop {
                peer: second_hop.to_vec(),
                scope: umc_routing::types::RouteScope::General,
                failure_domain: Vec::new(),
                relay: true,
            },
            PathHop {
                peer: destination.to_vec(),
                scope: umc_routing::types::RouteScope::General,
                failure_domain: Vec::new(),
                relay: false,
            },
        ])
        .expect("second path metadata");
        let _ = second.routing.record_route_response_with_metadata(
            umc_routing::types::RouteKey {
                destination_profile: 0,
                destination_hash: hash_destination(&destination),
                scope: umc_routing::types::RouteScope::General,
                policy_class: 0,
            },
            route_next_hop_label(&second_hop, &second_hop),
            60_000,
            Instant(0),
            None,
            second_metadata,
        );
        let mut second_session = test_session();
        let second_status = handle_control_frames(
            &mut second,
            1,
            &mut second_session,
            &[WireFrame::RelayOpen(first_nested.clone())],
            Instant(2),
        )
        .expect("second relay status");
        assert_eq!(
            relay_status_of(&second_status).status_code,
            RELAY_STATUS_ACCEPTED
        );
        let second_nested_bytes = second_out_rx.recv().await.expect("second nested open");
        let second_nested = decode_outbound(&second_nested_bytes)
            .into_iter()
            .find_map(|frame| match frame {
                WireFrame::RelayOpen(open) => Some(open),
                _ => None,
            })
            .expect("second nested frame");
        assert_ne!(first_nested.circuit_id, second_nested.circuit_id);
        assert_eq!(
            second_nested.next_hop_hint,
            privacy_route_token(&destination)
        );
        assert!(second_nested.private_circuit);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn private_relay_token_attaches_only_at_terminal_hop() {
        let (mut state, _tx) = test_state();
        let destination = [9u8; 32];
        let (destination_in_tx, _destination_in_rx) = tokio::sync::mpsc::unbounded_channel();
        let (destination_out_tx, mut destination_out_rx) = tokio::sync::mpsc::unbounded_channel();
        state.bus.lock().expect("bus").register(
            destination.to_vec(),
            3,
            destination_in_tx,
            destination_out_tx,
        );
        let metadata = encode_path_metadata(&[PathHop {
            peer: destination.to_vec(),
            scope: umc_routing::types::RouteScope::General,
            failure_domain: Vec::new(),
            relay: false,
        }])
        .expect("terminal metadata");
        let _ = state.routing.record_route_response_with_metadata(
            umc_routing::types::RouteKey {
                destination_profile: 0,
                destination_hash: hash_destination(&destination),
                scope: umc_routing::types::RouteScope::General,
                policy_class: 0,
            },
            route_next_hop_label(&destination, &destination),
            60_000,
            Instant(0),
            None,
            metadata,
        );
        let (origin_in_tx, _origin_in_rx) = tokio::sync::mpsc::unbounded_channel();
        let (origin_out_tx, _origin_out_rx) = tokio::sync::mpsc::unbounded_channel();
        state
            .bus
            .lock()
            .expect("bus")
            .register(vec![7u8; 32], 1, origin_in_tx, origin_out_tx);
        let open = RelayOpenFrame {
            circuit_id: 55,
            bidirectional: true,
            store_forward_allowed: false,
            private_circuit: true,
            multipath_allowed: false,
            requested_lifetime: 60_000,
            requested_byte_quota: 1_024,
            next_hop_hint: privacy_route_token(&destination),
            authorization: Vec::new(),
        };
        let mut session = test_session();
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayOpen(open)],
            Instant(1),
        )
        .expect("terminal relay status");
        assert_eq!(
            relay_status_of(&outbound).status_code,
            RELAY_STATUS_ACCEPTED
        );
        assert_eq!(state.relay.circuit_count(), 2);
        assert!(destination_out_rx.try_recv().is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relay_data_resolves_peer_selected_wire_circuit_id() {
        let (mut state, _tx) = test_state();
        let open = RelayOpenFrame {
            circuit_id: 55,
            bidirectional: true,
            store_forward_allowed: false,
            private_circuit: false,
            multipath_allowed: false,
            requested_lifetime: 60_000,
            requested_byte_quota: 1_024,
            next_hop_hint: Vec::new(),
            authorization: Vec::new(),
        };
        let mut session = test_session();
        let _ = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayOpen(open)],
            Instant(0),
        );
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayData(RelayDataFrame {
                circuit_id: 55,
                relay_sequence: 0,
                fin: false,
                ack_requested: false,
                high_priority: false,
                data: b"payload".to_vec(),
            })],
            Instant(1),
        )
        .expect("wire id must reach the internal circuit");
        let close = decode_outbound(&outbound)
            .into_iter()
            .find_map(|frame| match frame {
                WireFrame::RelayClose(close) => Some(close),
                _ => None,
            })
            .expect("missing downstream failure close");
        assert_eq!(close.circuit_id, 55);
        assert!(!state
            .events
            .lock()
            .expect("events")
            .recent(20)
            .iter()
            .any(|event| event.kind == "relay_data_rejected"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inbound_relay_status_is_sequence_checked() {
        let (mut state, _tx) = test_state();
        let status = RelayStatusFrame {
            circuit_id: 77,
            status_sequence: 0,
            status_code: RELAY_STATUS_ACCEPTED,
            bidirectional_granted: true,
            private_handling_granted: false,
            multipath_granted: false,
            downstream_authenticated: false,
            retryable: false,
            granted_lifetime: 10_000,
            granted_byte_quota: 1_024,
            maximum_relay_payload: 1_024,
            diagnostic: Vec::new(),
            authentication: Vec::new(),
        };
        let mut session = test_session();
        assert!(handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayStatus(status.clone())],
            Instant(1),
        )
        .is_none());
        assert!(handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayStatus(status.clone())],
            Instant(2),
        )
        .is_none());
        let mut conflicting = status.clone();
        conflicting.retryable = true;
        assert!(handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayStatus(conflicting)],
            Instant(3),
        )
        .is_none());
        let mut invalid = status;
        invalid.status_code = 99;
        assert!(handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayStatus(invalid)],
            Instant(4),
        )
        .is_none());
        let events = state.events.lock().expect("events").recent(20);
        assert!(events
            .iter()
            .any(|event| event.kind == "relay_status_received"));
        assert!(events
            .iter()
            .any(|event| event.kind == "relay_status_rejected"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn friends_only_rejects_empty_relay_authorization() {
        let (mut state, _tx) = test_state();
        state.relay.limits.policy = umc_relay::admission::RelayPolicy::FriendsOnly;
        let open = RelayOpenFrame {
            circuit_id: 9,
            bidirectional: true,
            store_forward_allowed: false,
            private_circuit: false,
            multipath_allowed: false,
            requested_lifetime: 60_000,
            requested_byte_quota: 1_024,
            next_hop_hint: Vec::new(),
            authorization: Vec::new(),
        };
        let mut session = test_session();
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayOpen(open)],
            Instant(1_000),
        )
        .expect("friends-only refusal status");
        assert_eq!(
            relay_status_of(&outbound).status_code,
            RELAY_STATUS_AUTH_FAILED
        );
        assert_eq!(state.relay.circuit_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relay_authorization_accepts_valid_and_rejects_forged_or_expired() {
        let (mut state, _tx) = test_state();
        let valid = RelayAuthorization::issue(&state.node_identity.identity, 10_000, [3u8; 16]);
        let mut session = test_session();
        let open = RelayOpenFrame {
            circuit_id: 7,
            bidirectional: true,
            store_forward_allowed: false,
            private_circuit: false,
            multipath_allowed: false,
            requested_lifetime: 60_000,
            requested_byte_quota: 1_024,
            next_hop_hint: Vec::new(),
            authorization: valid,
        };
        let accepted = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayOpen(open.clone())],
            Instant(1_000),
        )
        .expect("valid authorization gets a status");
        assert_eq!(
            relay_status_of(&accepted).status_code,
            RELAY_STATUS_ACCEPTED
        );

        let mut forged = open.clone();
        let last = forged.authorization.len() - 1;
        forged.authorization[last] ^= 1;
        let refused = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayOpen(forged)],
            Instant(1_000),
        )
        .expect("forged authorization gets a refusal status");
        assert_eq!(
            relay_status_of(&refused).status_code,
            RELAY_STATUS_AUTH_FAILED
        );

        let expired = RelayAuthorization::issue(&state.node_identity.identity, 999, [4u8; 16]);
        let mut expired_open = open;
        expired_open.circuit_id = 8;
        expired_open.authorization = expired;
        let refused = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayOpen(expired_open)],
            Instant(1_000),
        )
        .expect("expired authorization gets a refusal status");
        assert_eq!(
            relay_status_of(&refused).status_code,
            RELAY_STATUS_AUTH_FAILED
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relay_resource_exhaustion_uses_resource_limit_status() {
        let (mut state, _tx) = test_state();
        state.relay.limits.max_circuits_per_peer = 0;
        let open = RelayOpenFrame {
            circuit_id: 10,
            bidirectional: true,
            store_forward_allowed: false,
            private_circuit: false,
            multipath_allowed: false,
            requested_lifetime: 60_000,
            requested_byte_quota: 1_024,
            next_hop_hint: Vec::new(),
            authorization: Vec::new(),
        };
        let mut session = test_session();
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayOpen(open)],
            Instant(1_000),
        )
        .expect("resource refusal status");
        let status = relay_status_of(&outbound);
        assert_eq!(status.status_code, RELAY_STATUS_RESOURCE_LIMIT);
        assert!(status.retryable);
        assert_eq!(state.relay.circuit_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn configured_profile_caps_live_relay_circuits() {
        let (mut state, _tx) = test_state();
        state.config.profile = "constrained".into();
        state.relay.limits.max_circuits_per_peer = 1_024;
        let mut session = test_session();
        let mut accepted = 0usize;
        for circuit_id in 0..=256u64 {
            let open = RelayOpenFrame {
                circuit_id,
                bidirectional: true,
                store_forward_allowed: false,
                private_circuit: false,
                multipath_allowed: false,
                requested_lifetime: 60_000,
                requested_byte_quota: 1_024,
                next_hop_hint: Vec::new(),
                authorization: Vec::new(),
            };
            let outbound = handle_control_frames(
                &mut state,
                1,
                &mut session,
                &[WireFrame::RelayOpen(open)],
                Instant(1_000),
            )
            .expect("profile cap status");
            if relay_status_of(&outbound).status_code == RELAY_STATUS_ACCEPTED {
                accepted += 1;
            } else {
                assert_eq!(
                    relay_status_of(&outbound).status_code,
                    RELAY_STATUS_RESOURCE_LIMIT
                );
            }
        }
        assert_eq!(accepted, 256);
        assert_eq!(state.relay.circuit_count(), 256);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bundle_frame_admitted_and_swept() {
        let (mut state, _tx) = test_state();
        let bundle = BundleFrame {
            bundle_id: b"frame-bundle".to_vec(),
            custody_requested: false,
            delivery_ack_requested: true,
            do_not_replicate: false,
            local_scope_only: false,
            high_sensitivity: false,
            priority: 1,
            creation_time: 1_000,
            expiration_time: 61_000,
            replication_limit: 3,
            destination_hint: b"dest".to_vec(),
            payload: b"ciphertext".to_vec(),
            bundle_auth: Vec::new(),
            chunk_index: 0,
            chunk_final: true,
        };
        let mut session = test_session();
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::Bundle(bundle)],
            Instant(0),
        );
        assert!(outbound.is_none(), "bundle admission sends nothing back");
        assert_eq!(state.bundle.count(), 1);
        let id = state.bundle.list()[0].0.clone();
        let id32: [u8; 32] = id.as_slice().try_into().unwrap();
        assert_eq!(state.bundle.payload(&id32).unwrap(), b"ciphertext");

        // The delivery sweep wraps the stored ciphertext into a BUNDLE frame
        // and marks it forwarded.
        let swept = flush_pending_bundles(&mut state, Instant(5_000));
        assert!(!swept.is_empty());
        let frames = decode_outbound(&swept);
        assert!(matches!(&frames[0], WireFrame::Bundle(f) if f.payload == b"ciphertext"));
        assert!(matches!(
            state.bundle.record(&id32).map(|r| r.status.clone()),
            Some(umc_bundle::manager::BundleStatus::Forwarded)
        ));
        // Nothing left to deliver.
        assert!(flush_pending_bundles(&mut state, Instant(5_000)).is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn expired_bundles_evicted_by_sweep() {
        let (mut state, _tx) = test_state();
        let expired_id = state
            .bundle
            .admit(
                b"expired-payload",
                b"sender-a",
                b"dest",
                1,
                1_000,
                3,
                false,
                Instant(0),
            )
            .unwrap();
        let live_id = state
            .bundle
            .admit(
                b"live-payload",
                b"sender-b",
                b"dest",
                1,
                umc_bundle::manager::DEFAULT_LIFETIME_MS,
                3,
                false,
                Instant(0),
            )
            .unwrap();
        assert_eq!(state.bundle.count(), 2);

        // The sweep evicts expired bundles BEFORE delivery selection
        // (bundles.md §11): the expired bundle is removed (records + object
        // store) and never wrapped; the live bundle survives.
        let swept = flush_pending_bundles(&mut state, Instant(1_001));
        assert!(!swept.is_empty(), "live bundle still swept");
        assert!(state.bundle.find(&expired_id).is_none());
        assert!(state.bundle.payload(&expired_id).is_none());
        assert_eq!(state.bundle.count(), 1);
        assert!(state.bundle.find(&live_id).is_some());
        let recent = state.events.lock().unwrap().recent(10);
        assert!(recent.iter().any(|e| e.kind == "bundle_expired"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn route_request_answered_directly() {
        let (mut state, _tx) = test_state();
        let request = RouteRequestFrame {
            request_id: 99,
            allow_relay: false,
            allow_store_forward: false,
            require_private_response: false,
            local_scope_only: false,
            gateway_query: false,
            hop_limit: 8,
            expiration_delta: 30_000,
            destination_hint: b"dest-token".to_vec(),
            path_exclusions: vec![],
            requester_auth: vec![],
        };
        let mut session = test_session();
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteRequest(request.clone())],
            Instant(0),
        )
        .expect("route request must be answered");
        let mut found = None;
        for frame in decode_outbound(&outbound) {
            if let WireFrame::RouteResponse(response) = frame {
                found = Some(response);
            }
        }
        let response = found.expect("ROUTE_RESPONSE");
        assert_eq!(response.request_id, 99);
        assert!(response.direct);
        assert!(!response.relay_required);
        assert!(response.local_path);
        assert_eq!(response.route_lifetime, 30_000);
        // The direct route points back at the requesting session's peer.
        assert_eq!(response.next_hop_hint, [7u8; 32]);

        let mut private_request = request;
        private_request.request_id = 100;
        private_request.require_private_response = true;
        let private_outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteRequest(private_request)],
            Instant(1),
        )
        .expect("private direct match must return a policy error");
        assert!(matches!(
            decode_outbound(&private_outbound).as_slice(),
            [WireFrame::RouteError(error)] if error.error_code == ROUTE_POLICY_REJECTED
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn direct_route_response_points_at_matched_destination_peer() {
        let (mut state, _tx) = test_state();
        let destination = [8u8; 32];
        state.sessions.register(
            2,
            SessionEntry {
                peer_endpoint_id: destination,
                carrier_type: "ump.udp/1".into(),
                task: tokio::spawn(async {}).abort_handle(),
                established_at_ms: 0,
                privacy_profile: 0,
                direct_path_allowed: true,
                traffic_padding_active: false,
            },
        );
        let request = RouteRequestFrame {
            request_id: 101,
            allow_relay: false,
            allow_store_forward: false,
            require_private_response: false,
            local_scope_only: false,
            gateway_query: false,
            hop_limit: 8,
            expiration_delta: 30_000,
            destination_hint: destination.to_vec(),
            path_exclusions: vec![],
            requester_auth: vec![],
        };
        let mut session = test_session();
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteRequest(request.clone())],
            Instant(0),
        )
        .expect("route request must be answered");
        let response = decode_outbound(&outbound)
            .into_iter()
            .find_map(|frame| match frame {
                WireFrame::RouteResponse(response) => Some(response),
                _ => None,
            })
            .expect("direct route response");
        assert!(response.direct);
        assert_eq!(response.next_hop_hint, destination);

        let private_request = RouteRequestFrame {
            request_id: 102,
            allow_relay: true,
            require_private_response: true,
            ..request
        };
        let private_outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteRequest(private_request)],
            Instant(1),
        )
        .expect("private adjacent destination must return a relay route");
        let private_response = decode_outbound(&private_outbound)
            .into_iter()
            .find_map(|frame| match frame {
                WireFrame::RouteResponse(response) => Some(response),
                _ => None,
            })
            .expect("private relay route response");
        assert!(!private_response.direct);
        assert!(private_response.relay_required);
        assert_eq!(
            private_response.next_hop_hint,
            state.node_identity.endpoint_id().to_vec()
        );
        let hops = decode_path_metadata(&private_response.route_metadata)
            .expect("canonical private route metadata");
        assert_eq!(hops.len(), 2);
        assert!(hops[0].relay);
        assert!(!hops[1].relay);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn route_request_recognizes_local_destination_for_private_hop() {
        let (mut state, _tx) = test_state();
        let destination = state.node_identity.endpoint_id();
        let request = RouteRequestFrame {
            request_id: 103,
            allow_relay: true,
            allow_store_forward: false,
            require_private_response: true,
            local_scope_only: false,
            gateway_query: false,
            hop_limit: 8,
            expiration_delta: 30_000,
            destination_hint: destination.to_vec(),
            path_exclusions: Vec::new(),
            requester_auth: Vec::new(),
        };
        let mut session = test_session();
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteRequest(request)],
            Instant(0),
        )
        .expect("local destination must answer route request");
        let response = decode_outbound(&outbound)
            .into_iter()
            .find_map(|frame| match frame {
                WireFrame::RouteResponse(response) => Some(response),
                _ => None,
            })
            .expect("private local-destination response");
        assert!(!response.direct);
        assert!(response.relay_required);
        let hops = decode_path_metadata(&response.route_metadata)
            .expect("canonical local-destination metadata");
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].peer, destination);
        assert!(!hops[0].relay);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relay_data_without_downstream_closes_the_circuit() {
        let (mut state, _tx) = test_state();
        let circuit = state
            .relay
            .open_circuit(
                &crate::relay_service::CircuitOpenRequest {
                    peer_circuits: 0,
                    requested_lifetime_ms: 600_000,
                    requested_byte_quota: 1_048_576,
                    flags: 0,
                    bidirectional: true,
                    private_handling: false,
                    destination_hint: b"missing-downstream".to_vec(),
                },
                vec![7u8; 32],
                Instant(0),
            )
            .expect("circuit admission")
            .circuit_id;
        state.relay.record_circuit_owner(circuit, 1);
        let data = RelayDataFrame {
            circuit_id: circuit,
            relay_sequence: 0,
            fin: false,
            ack_requested: false,
            high_priority: false,
            data: b"payload".to_vec(),
        };
        let mut session = test_session();
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RelayData(data)],
            Instant(1),
        )
        .expect("downstream failure must notify upstream");
        let close = decode_outbound(&outbound)
            .into_iter()
            .find_map(|frame| match frame {
                WireFrame::RelayClose(close) => Some(close),
                _ => None,
            })
            .expect("RELAY_CLOSE");
        assert_eq!(close.circuit_id, circuit);
        assert_eq!(
            close.reason_code,
            umc_relay::close::RelayReason::DownstreamFailed as u64
        );
        assert_eq!(close.final_relay_sequence, 0);
        assert!(state.relay.circuit_owner(circuit).is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn route_request_forwards_to_bounded_peers_and_decrements_ttl() {
        let (mut state, _tx) = test_state();
        let local_endpoint = state.node_identity.endpoint_id();
        let mut receives = Vec::new();
        for (id, peer) in [(2u64, [8u8; 32]), (3, [9u8; 32]), (4, [10u8; 32])] {
            state.sessions.register(
                id,
                SessionEntry {
                    peer_endpoint_id: peer,
                    carrier_type: "ump.tcp/1".into(),
                    task: tokio::spawn(async {}).abort_handle(),
                    established_at_ms: 0,
                    privacy_profile: 0,
                    direct_path_allowed: true,
                    traffic_padding_active: false,
                },
            );
            let (in_tx, _in_rx) = tokio::sync::mpsc::unbounded_channel();
            let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
            state
                .bus
                .lock()
                .expect("bus")
                .register(peer.to_vec(), id, in_tx, out_tx);
            receives.push(out_rx);
        }
        let request = RouteRequestFrame {
            request_id: 100,
            allow_relay: true,
            allow_store_forward: false,
            require_private_response: false,
            local_scope_only: false,
            gateway_query: false,
            hop_limit: 8,
            expiration_delta: 30_000,
            destination_hint: b"remote-destination".to_vec(),
            path_exclusions: vec![],
            requester_auth: b"scope".to_vec(),
        };
        let mut session = test_session();
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteRequest(request)],
            Instant(0),
        );
        assert!(
            outbound.is_none(),
            "forwarded requests await a downstream response"
        );
        for mut rx in receives {
            let bytes = rx.recv().await.expect("forwarded request");
            let (kind, type_len) = umc_wire::varint::decode(&bytes).expect("frame type");
            assert_eq!(kind, umc_types::frame::FrameType::ROUTE_REQUEST.0);
            let (forwarded, _) = RouteRequestFrame::decode(&bytes[type_len..]).expect("request");
            assert_eq!(forwarded.request_id, 100);
            assert_eq!(forwarded.hop_limit, 7);
            assert_eq!(forwarded.destination_hint, b"remote-destination");
            assert!(forwarded
                .path_exclusions
                .iter()
                .any(|excluded| excluded.as_slice() == local_endpoint));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn route_request_with_exhausted_hops_does_not_claim_direct_reachability() {
        let (mut state, _tx) = test_state();
        let peer = [8u8; 32];
        state.sessions.register(
            2,
            SessionEntry {
                peer_endpoint_id: peer,
                carrier_type: "ump.tcp/1".into(),
                task: tokio::spawn(async {}).abort_handle(),
                established_at_ms: 0,
                privacy_profile: 0,
                direct_path_allowed: true,
                traffic_padding_active: false,
            },
        );
        let (in_tx, _in_rx) = tokio::sync::mpsc::unbounded_channel();
        let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel();
        state
            .bus
            .lock()
            .expect("bus")
            .register(peer.to_vec(), 2, in_tx, out_tx);

        let request = RouteRequestFrame {
            request_id: 101,
            allow_relay: true,
            allow_store_forward: false,
            require_private_response: false,
            local_scope_only: false,
            gateway_query: false,
            hop_limit: 1,
            expiration_delta: 30_000,
            destination_hint: b"remote-destination".to_vec(),
            path_exclusions: vec![],
            requester_auth: vec![],
        };
        let mut session = test_session();
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteRequest(request)],
            Instant(0),
        )
        .expect("expired request must return an error");
        let frames = decode_outbound(&outbound);
        assert!(matches!(
            frames.as_slice(),
            [WireFrame::RouteError(error)] if error.error_code == ROUTE_EXPIRED
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn route_error_returns_to_request_upstream() {
        let (mut state, _tx) = test_state();
        let (in_tx, _in_rx) = tokio::sync::mpsc::unbounded_channel();
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
        state
            .bus
            .lock()
            .expect("bus")
            .register([8u8; 32].to_vec(), 2, in_tx, out_tx);
        let mut request_id = [0u8; 16];
        request_id[..8].fill(0x2A);
        state
            .routing
            .admit_route_request(&request_id, &[8u8; 32], 0, 8, 30_000, &[], Instant(0))
            .expect("reverse state");
        let mut session = test_session();
        let error = umc_wire::frames::routing::RouteErrorFrame {
            request_id: u64::from_be_bytes(request_id[..8].try_into().unwrap()),
            error_code: 4,
            failed_hop_index: 0,
            diagnostic: Vec::new(),
        };
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteError(error)],
            Instant(1),
        );
        assert!(outbound.is_none());
        let bytes = tokio::time::timeout(Duration::from_secs(1), out_rx.recv())
            .await
            .expect("route error forwarding timed out")
            .expect("error forwarded upstream");
        let (kind, type_len) = umc_wire::varint::decode(&bytes).expect("frame type");
        assert_eq!(kind, umc_types::frame::FrameType::ROUTE_ERROR.0);
        let (forwarded, _) =
            umc_wire::frames::routing::RouteErrorFrame::decode(&bytes[type_len..]).unwrap();
        assert_eq!(forwarded.error_code, 4);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn route_response_requires_live_branch_and_monotonic_sequence() {
        let (mut state, _tx) = test_state();
        let mut request_id = [0u8; 16];
        request_id[..8].fill(0x31);
        let (in_tx, _in_rx) = tokio::sync::mpsc::unbounded_channel();
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
        state
            .bus
            .lock()
            .expect("session bus")
            .register([8u8; 32].to_vec(), 2, in_tx, out_tx);
        state
            .routing
            .admit_route_request(&request_id, &[8u8; 32], 0, 8, 30_000, &[], Instant(0))
            .expect("reverse state");
        let destination_hash = hash_destination(b"target");
        state.routing.remember_route_request(
            request_id,
            destination_hash,
            umc_routing::types::RouteScope::LocalMesh,
            Instant(0),
        );

        let mut session = test_session();
        let invalid = RouteResponseFrame {
            request_id: u64::from_be_bytes(request_id[..8].try_into().unwrap()),
            response_sequence: 0,
            direct: true,
            relay_required: false,
            store_forward_available: false,
            local_path: true,
            gateway_path: false,
            route_lifetime: 0,
            next_hop_hint: b"next-hop".to_vec(),
            route_metadata: Vec::new(),
            authentication: Vec::new(),
        };
        assert!(handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteResponse(invalid)],
            Instant(1),
        )
        .is_none());
        assert!(
            out_rx.try_recv().is_err(),
            "invalid response must not forward"
        );

        let valid = RouteResponseFrame {
            request_id: u64::from_be_bytes(request_id[..8].try_into().unwrap()),
            response_sequence: 0,
            direct: true,
            relay_required: false,
            store_forward_available: false,
            local_path: true,
            gateway_path: false,
            route_lifetime: 29_999,
            next_hop_hint: b"next-hop".to_vec(),
            route_metadata: Vec::new(),
            authentication: Vec::new(),
        };
        assert!(handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteResponse(valid.clone())],
            Instant(1),
        )
        .is_none());
        assert!(
            out_rx.try_recv().is_ok(),
            "valid response must return upstream"
        );
        let key = umc_routing::types::RouteKey {
            destination_profile: 0,
            destination_hash,
            scope: umc_routing::types::RouteScope::LocalMesh,
            policy_class: 0,
        };
        assert_eq!(state.routing.cache.candidates(&key, Instant(1)).len(), 1);
        assert_eq!(
            state.routing.cache.candidates(&key, Instant(1))[0].next_hop,
            "07".repeat(32),
            "a forwarded response must select the authenticated adjacent responder"
        );

        assert!(handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteResponse(valid)],
            Instant(2),
        )
        .is_none());
        assert!(
            out_rx.try_recv().is_err(),
            "duplicate sequence must be dropped"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn route_response_path_metadata_is_policy_checked_before_cache() {
        let (mut state, _tx) = test_state();
        let metadata = umc_routing::paths::encode_path_metadata(&[
            PathHop {
                peer: vec![8],
                scope: umc_routing::types::RouteScope::General,
                failure_domain: Vec::new(),
                relay: true,
            },
            PathHop {
                peer: vec![9],
                scope: umc_routing::types::RouteScope::General,
                failure_domain: Vec::new(),
                relay: false,
            },
        ])
        .expect("path metadata");
        let response = |request_id: u64| RouteResponseFrame {
            request_id,
            response_sequence: 0,
            direct: true,
            relay_required: false,
            store_forward_available: false,
            local_path: false,
            gateway_path: false,
            route_lifetime: 5_000,
            next_hop_hint: vec![9],
            route_metadata: metadata.clone(),
            authentication: Vec::new(),
        };

        let rejected_id = internal_route_request_id(0x52);
        state
            .routing
            .reverse
            .create(rejected_id, Vec::new(), Instant(0));
        state.routing.remember_route_request_with_constraints(
            rejected_id,
            hash_destination(b"restricted"),
            umc_routing::types::RouteScope::General,
            false,
            8,
            0,
            false,
            Instant(0),
        );
        let mut session = test_session();
        assert!(handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteResponse(response(0x52))],
            Instant(1),
        )
        .is_none());
        assert!(state
            .routing
            .cache
            .candidates(
                &umc_routing::types::RouteKey {
                    destination_profile: 0,
                    destination_hash: hash_destination(b"restricted"),
                    scope: umc_routing::types::RouteScope::General,
                    policy_class: 0,
                },
                Instant(1),
            )
            .is_empty());

        let accepted_id = internal_route_request_id(0x53);
        state
            .routing
            .reverse
            .create(accepted_id, Vec::new(), Instant(0));
        state.routing.remember_route_request_with_constraints(
            accepted_id,
            hash_destination(b"allowed"),
            umc_routing::types::RouteScope::General,
            false,
            8,
            1,
            true,
            Instant(0),
        );
        assert!(handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteResponse(response(0x53))],
            Instant(1),
        )
        .is_none());
        let key = umc_routing::types::RouteKey {
            destination_profile: 0,
            destination_hash: hash_destination(b"allowed"),
            scope: umc_routing::types::RouteScope::General,
            policy_class: 0,
        };
        assert_eq!(state.routing.cache.candidates(&key, Instant(1)).len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn p2_rejects_direct_route_responses_before_cache_insertion() {
        let (mut state, _tx) = test_state();
        state.config.privacy_profile = "p2".into();
        let mut request_id = [0u8; 16];
        request_id[..8].fill(0x41);
        state
            .routing
            .admit_route_request(&request_id, &[7u8; 32], 0, 8, 30_000, &[], Instant(0))
            .expect("reverse state");
        let destination_hash = hash_destination(b"private-target");
        state.routing.remember_route_request(
            request_id,
            destination_hash,
            umc_routing::types::RouteScope::General,
            Instant(0),
        );
        let response = RouteResponseFrame {
            request_id: u64::from_be_bytes(request_id[..8].try_into().unwrap()),
            response_sequence: 0,
            direct: true,
            relay_required: false,
            store_forward_available: false,
            local_path: true,
            gateway_path: false,
            route_lifetime: 29_999,
            next_hop_hint: b"direct-peer".to_vec(),
            route_metadata: Vec::new(),
            authentication: Vec::new(),
        };
        let mut session = test_session();
        assert!(handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteResponse(response)],
            Instant(1),
        )
        .is_none());
        let key = umc_routing::types::RouteKey {
            destination_profile: 0,
            destination_hash,
            scope: umc_routing::types::RouteScope::General,
            policy_class: 0,
        };
        assert!(
            state.routing.cache.candidates(&key, Instant(1)).is_empty(),
            "P2 must not cache a direct route candidate"
        );
        assert!(state
            .events
            .lock()
            .expect("events")
            .recent(10)
            .iter()
            .any(|event| event.kind == "route_response_rejected"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn private_route_request_rejects_direct_response_without_global_p2() {
        let (mut state, _tx) = test_state();
        let mut request_id = [0u8; 16];
        request_id[..8].fill(0x42);
        state
            .routing
            .admit_route_request(&request_id, &[7u8; 32], 0x04, 8, 30_000, &[], Instant(0))
            .expect("reverse state");
        let destination_hash = hash_destination(b"request-private-target");
        state.routing.remember_route_request_with_policy(
            request_id,
            destination_hash,
            umc_routing::types::RouteScope::General,
            true,
            Instant(0),
        );
        let response = RouteResponseFrame {
            request_id: u64::from_be_bytes(request_id[..8].try_into().unwrap()),
            response_sequence: 0,
            direct: true,
            relay_required: false,
            store_forward_available: false,
            local_path: true,
            gateway_path: false,
            route_lifetime: 29_999,
            next_hop_hint: b"direct-peer".to_vec(),
            route_metadata: Vec::new(),
            authentication: Vec::new(),
        };
        let mut session = test_session();
        assert!(handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::RouteResponse(response)],
            Instant(1),
        )
        .is_none());
        let key = umc_routing::types::RouteKey {
            destination_profile: 0,
            destination_hash,
            scope: umc_routing::types::RouteScope::General,
            policy_class: 0,
        };
        assert!(state.routing.cache.candidates(&key, Instant(1)).is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_hint_is_applied_and_persisted_as_a_candidate() {
        let (mut state, _tx) = test_state();
        let hint = umc_wire::frames::misc::PeerHintFrame {
            entries: vec![umc_wire::frames::misc::PeerHintEntry {
                temporary_peer_id: 77u64.to_be_bytes().to_vec(),
                carrier_type: b"ump.udp/1".to_vec(),
                connection_hint: b"127.0.0.1:9002".to_vec(),
                expiration_time: u64::MAX,
                public: true,
                introduced: false,
                local: false,
                ephemeral: false,
                do_not_reshare: false,
                authenticator: Vec::new(),
            }],
        };
        let mut session = test_session();
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::PeerHint(hint)],
            Instant(5),
        );
        assert!(outbound.is_none());
        let candidates = state.discovery.candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].candidate_id, 77);
        assert_eq!(
            candidates[0].source,
            umc_discovery::provider::CandidateSource::PeerHint
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn key_update_frame_applied_to_session() {
        let (mut state, _tx) = test_state();
        let mut session = test_session();
        // A fresh session expects sequence 1 as its first update.
        let outbound = handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::KeyUpdate(KeyUpdateFrame {
                update_sequence: 1,
                request_peer_update: false,
            })],
            Instant(0),
        );
        assert!(outbound.is_none());
        let rejected = state
            .events
            .lock()
            .unwrap()
            .recent(10)
            .iter()
            .any(|e| e.kind == "key_update_rejected");
        assert!(!rejected, "valid update must not be rejected");
        // An out-of-range sequence is rejected loudly.
        handle_control_frames(
            &mut state,
            1,
            &mut session,
            &[WireFrame::KeyUpdate(KeyUpdateFrame {
                update_sequence: 7,
                request_peer_update: false,
            })],
            Instant(0),
        );
        let rejected = state
            .events
            .lock()
            .unwrap()
            .recent(10)
            .iter()
            .any(|e| e.kind == "key_update_rejected");
        assert!(rejected, "out-of-range update must be rejected");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn key_rotation_schedule_and_frame() {
        assert!(!key_rotation_due(Instant(0), Instant(0), None));
        assert!(!key_rotation_due(
            Instant(KEY_UPDATE_INTERVAL_MS - 1),
            Instant(0),
            None
        ));
        assert!(key_rotation_due(
            Instant(KEY_UPDATE_INTERVAL_MS),
            Instant(0),
            None
        ));
        assert!(key_rotation_due(
            Instant(KEY_UPDATE_INTERVAL_MS),
            Instant(0),
            Some(Instant(0))
        ));
        assert!(!key_rotation_due(
            Instant(KEY_UPDATE_INTERVAL_MS),
            Instant(0),
            Some(Instant(KEY_UPDATE_INTERVAL_MS))
        ));

        let mut session = test_session();
        let mut last = None;
        let payload = maybe_rotate_keys(
            &mut session,
            Instant(KEY_UPDATE_INTERVAL_MS),
            Instant(0),
            &mut last,
        )
        .expect("rotation produces a KEY_UPDATE frame");
        let frames = decode_outbound(&payload);
        assert!(matches!(
            &frames[0],
            WireFrame::KeyUpdate(update) if update.update_sequence == 1
        ));
        // Not due again until the next interval elapses.
        assert!(maybe_rotate_keys(
            &mut session,
            Instant(KEY_UPDATE_INTERVAL_MS),
            Instant(0),
            &mut last
        )
        .is_none());
        // Due again, but the previous update is still awaiting confirmation:
        // the session declines and the schedule does not advance.
        assert!(maybe_rotate_keys(
            &mut session,
            Instant(2 * KEY_UPDATE_INTERVAL_MS),
            Instant(0),
            &mut last
        )
        .is_none());
        assert!(
            last == Some(Instant(KEY_UPDATE_INTERVAL_MS)),
            "a declined update must not advance the schedule"
        );
    }

    #[test]
    fn dcid_rotation_schedule_and_frame() {
        assert!(!dcid_rotation_due(
            Instant(0),
            Instant(0),
            None,
            DCID_ROTATION_INTERVAL_MS
        ));
        assert!(!dcid_rotation_due(
            Instant(DCID_ROTATION_INTERVAL_MS - 1),
            Instant(0),
            None,
            DCID_ROTATION_INTERVAL_MS
        ));
        assert!(dcid_rotation_due(
            Instant(DCID_ROTATION_INTERVAL_MS),
            Instant(0),
            None,
            DCID_ROTATION_INTERVAL_MS
        ));
        assert!(!dcid_rotation_due(
            Instant(DCID_ROTATION_INTERVAL_MS),
            Instant(0),
            Some(Instant(DCID_ROTATION_INTERVAL_MS)),
            DCID_ROTATION_INTERVAL_MS
        ));

        let mut session = test_session();
        let payload = maybe_rotate_dcid(&mut session, &OsEntropy).expect("new CID frame");
        let frames = decode_outbound(&payload);
        assert!(matches!(
            &frames[0],
            WireFrame::NewConnectionId(frame)
                if frame.connection_id.len() == umc_session::session::DEFAULT_DCID_LEN
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bundle_sweep_schedule() {
        assert!(bundle_flush_due(Instant(0), None));
        assert!(bundle_flush_due(
            Instant(BUNDLE_FLUSH_INTERVAL_MS),
            Some(Instant(0))
        ));
        assert!(!bundle_flush_due(Instant(10_000), Some(Instant(0))));
        assert!(!bundle_flush_due(
            Instant(0),
            Some(Instant(BUNDLE_FLUSH_INTERVAL_MS))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn destination_hash_is_stable_and_bound() {
        assert_eq!(hash_destination(b"hop-a"), hash_destination(b"hop-a"));
        assert_ne!(hash_destination(b"hop-a"), hash_destination(b"hop-b"));
        assert_ne!(hash_destination(b"hop-a"), [0u8; 32]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn route_next_hop_label_preserves_text_and_binary_ids() {
        assert_eq!(route_next_hop_label(b"peer-a", b"fallback"), "peer-a");
        assert_eq!(
            route_next_hop_label(&[0, 0xab, 0xcd], b"fallback"),
            "00abcd"
        );
        assert_eq!(route_next_hop_label(&[], b"fallback"), "fallback");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ack_triggers_loss_detection_and_retransmit() {
        let (state, _tx) = test_state();
        let runtime = Arc::new(std::sync::Mutex::new(state));
        let now = Instant(1_000_000);
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(now.0));
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let link: Arc<BoxLink> = Arc::new(Box::new(RecordingLink {
            sent: recorded.clone(),
        }));
        let remote_keys =
            umc_crypto::aead::PacketKeys::from_traffic_secret(&[2u8; 32]).expect("remote keys");
        let remote_hp_key = umc_crypto::header_protection::header_protection_key(&[2u8; 32]);

        // The daemon's session sends four PING packets (pn 0..3).
        let mut client = test_session();
        let ping = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap();
        let mut packets = Vec::new();
        for _ in 0..4 {
            let pkt = client
                .build_outbound(clock.as_ref(), now, &ping)
                .unwrap()
                .unwrap();
            packets.push(pkt);
        }

        // The peer receives only the newest packet and ACKs it: pn 0 is then
        // packet-threshold lost (acked three numbers higher, session.md §14.1)
        // while pn 1/2 stay inside the 9/8 RTT time threshold.
        let mut peer = peer_session();
        let ack_payload = peer
            .on_inbound(Instant(1_000_010), &packets[3])
            .expect("peer recv");
        let ack_pkt = peer
            .build_outbound(clock.as_ref(), Instant(1_000_010), &ack_payload)
            .unwrap()
            .unwrap();

        let session = Arc::new(tokio::sync::Mutex::new(client));
        let app_channels: Arc<std::sync::Mutex<HashMap<Vec<u8>, AppTx>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let mut sweep = SweepState::default();
        process_inbound_packet(
            &link,
            &session,
            &clock,
            &app_channels,
            &runtime,
            &remote_keys,
            &remote_hp_key,
            1,
            &ack_pkt,
            &mut sweep,
        )
        .await;

        {
            let session = session.lock().await;
            let sent = session.sent_state().sent();
            assert!(
                !sent.iter().any(|p| p.packet_number == 0),
                "lost packet leaves the sent state"
            );
            assert!(
                sent.iter().any(|p| p.packet_number == 4 && p.ack_eliciting),
                "retransmitted packet queued under a fresh packet number"
            );
        }
        // The retransmit travels after the ACK reply on the link.
        let sent = recorded.lock().expect("link sent");
        assert!(sent.len() >= 2, "ACK reply plus retransmit");
        let retransmitted = sent.last().expect("retransmit bytes");
        let keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&[1u8; 32]).unwrap();
        let hp_key = umc_crypto::header_protection::header_protection_key(&[1u8; 32]);
        let (space, _dcid, _path, _pn, payload) =
            umc_session::packet::parse_protected_packet(&keys, &hp_key, 0, retransmitted).unwrap();
        let parsed = umc_wire::packet::parse_payload(
            &umc_wire::packet::PacketContext::Protected(space),
            &payload,
        )
        .unwrap();
        assert!(
            parsed.frames.iter().any(|f| matches!(f, WireFrame::Ping)),
            "retransmitted packet carries PING"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gated_loss_keeps_payload_for_retry() {
        let (state, _tx) = test_state();
        let runtime = Arc::new(std::sync::Mutex::new(state));
        let t0 = Instant(1_000_000);
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(t0.0));
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let link: Arc<BoxLink> = Arc::new(Box::new(RecordingLink {
            sent: recorded.clone(),
        }));
        let remote_keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&[2u8; 32]).unwrap();
        let remote_hp_key = umc_crypto::header_protection::header_protection_key(&[2u8; 32]);

        // Fill the send window with stream data: in-flight reaches the
        // 10 × SMSS cwnd and the gate shuts.
        let mut client = test_session();
        let sid = client.open_stream().expect("stream");
        let mut packets = Vec::new();
        loop {
            let payload = client
                .send_stream_data(sid, &[0xAB; 25], false)
                .expect("data payload");
            match client.build_outbound(clock.as_ref(), t0, &payload) {
                Ok(Some(pkt)) => packets.push(pkt),
                Err(SessionError::CongestionLimited) => break,
                other => panic!("unexpected build result: {other:?}"),
            }
        }
        assert_eq!(
            client.congestion_mut().cwnd(),
            10 * usize::try_from(SMSS).expect("SMSS fits usize")
        );
        let newest = packets.last().expect("window filled");

        // The peer ACKs only the newest packet: everything at least three
        // numbers lower is packet-threshold lost (session.md §14.1); the
        // elapsed time stays below the 9/8 RTT time threshold.
        let mut peer = peer_session();
        let ack_payload = peer.on_inbound(t0 + ms(10), newest).expect("peer recv");
        let ack_pkt = peer
            .build_outbound(clock.as_ref(), t0 + ms(10), &ack_payload)
            .unwrap()
            .unwrap();

        let session = Arc::new(tokio::sync::Mutex::new(client));
        let app_channels: Arc<std::sync::Mutex<HashMap<Vec<u8>, AppTx>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let mut sweep = SweepState::default();
        process_inbound_packet(
            &link,
            &session,
            &clock,
            &app_channels,
            &runtime,
            &remote_keys,
            &remote_hp_key,
            1,
            &ack_pkt,
            &mut sweep,
        )
        .await;

        {
            let mut session = session.lock().await;
            // The three-strike loss response halved the window — repeatedly,
            // the loss count here is far past the threshold — down to the
            // 2 × SMSS floor.
            assert_eq!(
                session.congestion_mut().cwnd(),
                2 * usize::try_from(SMSS).expect("SMSS fits usize")
            );
            // The gate was shut when the loss pass retransmitted: the
            // payload of a gated lost packet must survive for the next
            // detection pass / PTO (session.md §14.3). Once the controller
            // recovers — the peer acks the retransmitted packets and the
            // in-flight bytes drain — the same packet number retransmits
            // fine.
            let largest = session
                .sent_state()
                .sent()
                .back()
                .expect("retransmitted packets in flight")
                .packet_number;
            session
                .apply_peer_ack(
                    &umc_wire::frame::AckFrame {
                        largest_acknowledged: largest,
                        ack_delay: 0,
                        first_ack_range: largest + 1,
                        additional_ranges: Vec::new(),
                    },
                    t0 + ms(20),
                )
                .expect("recovery ack");
            assert!(
                session.retransmit(2, t0).expect("retransmit").is_some(),
                "gated retransmit keeps the payload for a later attempt"
            );
        }
    }

    /// Fill the sent state for a persistent-congestion scenario: `pn 0..5`
    /// with `pn 0..2` spanning `span_ms` (pn 2 sent at t0 + span). pn 5 sits
    /// at `t0` so the peer ACK of pn 5 samples no rtt (sample 0 is skipped)
    /// and the session's PTO stays at its 1 s default; the ACK of pn 5
    /// declares `pn 0..2` packet-threshold lost (three numbers higher,
    /// session.md §14.1).
    fn fill_loss_window(session: &mut Session, t0: Instant, span_ms: u64) {
        for (pn, at) in [
            (0u64, t0),
            (1, t0 + ms(1_000)),
            (2, t0 + ms(span_ms)),
            (3, t0 + ms(span_ms)),
            (4, t0 + ms(span_ms)),
            (5, t0),
        ] {
            session.sent_state_mut().record_sent(SentPacket::new(
                pn,
                PacketSpace::SessionData,
                at,
                64,
                true,
                0,
            ));
        }
    }

    /// Protected packet from the peer `ACKing` only packet number 5 (a real
    /// sent packet) with an empty first range: a hand-encoded ACK frame
    /// wrapped by the peer session's outbound builder.
    fn loss_ack_packet(clock: &Arc<dyn Clock>, t0: Instant) -> Vec<u8> {
        let ack_payload = umc_wire::frame::AckFrame {
            largest_acknowledged: 5,
            ack_delay: 0,
            first_ack_range: 1,
            additional_ranges: Vec::new(),
        }
        .encode()
        .expect("ack frame");
        let mut peer = peer_session();
        peer.build_outbound(clock.as_ref(), t0, &ack_payload)
            .unwrap()
            .expect("ack packet")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn persistent_congestion_marks_path_degraded() {
        let (state, _tx) = test_state();
        let runtime = Arc::new(std::sync::Mutex::new(state));
        let t0 = Instant(1_000_000);
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(t0.0));
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let link: Arc<BoxLink> = Arc::new(Box::new(RecordingLink {
            sent: recorded.clone(),
        }));
        let remote_keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&[2u8; 32]).unwrap();
        let remote_hp_key = umc_crypto::header_protection::header_protection_key(&[2u8; 32]);

        let mut client = test_session();
        client
            .add_path(0, "ump.tcp/1".into(), vec![], vec![], t0)
            .expect("default path added");
        // Losses spanning exactly 3 x PTO (1 s default): persistent
        // congestion (congestion.md §14.4).
        fill_loss_window(&mut client, t0, 3_000);
        let ack_pkt = loss_ack_packet(&clock, t0);

        let session = Arc::new(tokio::sync::Mutex::new(client));
        let app_channels: Arc<std::sync::Mutex<HashMap<Vec<u8>, AppTx>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let mut sweep = SweepState::default();
        process_inbound_packet(
            &link,
            &session,
            &clock,
            &app_channels,
            &runtime,
            &remote_keys,
            &remote_hp_key,
            1,
            &ack_pkt,
            &mut sweep,
        )
        .await;

        {
            let session = session.lock().await;
            assert!(
                session.is_path_degraded(0),
                "persistent congestion marks the path degraded"
            );
            assert_eq!(session.path(0).unwrap().rtt_ms, 0, "rtt marked stale");
        }
        let recent = runtime.lock().unwrap().events.lock().unwrap().recent(10);
        let degraded = recent
            .iter()
            .find(|e| e.kind == "path_degraded")
            .expect("path_degraded event pushed");
        assert!(
            degraded.detail.contains("path 0") && degraded.detail.contains("3000"),
            "event carries the path id and the loss span: {}",
            degraded.detail
        );
        // The degradation is one-shot: a second persistent-congestion pass
        // must not push another event.
        let before = recent.len();
        process_inbound_packet(
            &link,
            &session,
            &clock,
            &app_channels,
            &runtime,
            &remote_keys,
            &remote_hp_key,
            1,
            &ack_pkt,
            &mut sweep,
        )
        .await;
        let again = runtime.lock().unwrap().events.lock().unwrap().recent(10);
        assert_eq!(
            again.len(),
            before,
            "no second path_degraded event once degraded"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn short_loss_span_does_not_degrade() {
        let (state, _tx) = test_state();
        let runtime = Arc::new(std::sync::Mutex::new(state));
        let t0 = Instant(1_000_000);
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(t0.0));
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let link: Arc<BoxLink> = Arc::new(Box::new(RecordingLink {
            sent: recorded.clone(),
        }));
        let remote_keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&[2u8; 32]).unwrap();
        let remote_hp_key = umc_crypto::header_protection::header_protection_key(&[2u8; 32]);

        let mut client = test_session();
        client
            .add_path(0, "ump.tcp/1".into(), vec![], vec![], t0)
            .expect("default path added");
        // Losses spanning only 2 s: below the 3 x PTO (1 s) persistent
        // congestion threshold, so the path stays untouched.
        fill_loss_window(&mut client, t0, 2_000);
        let ack_pkt = loss_ack_packet(&clock, t0);

        let session = Arc::new(tokio::sync::Mutex::new(client));
        let app_channels: Arc<std::sync::Mutex<HashMap<Vec<u8>, AppTx>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let mut sweep = SweepState::default();
        process_inbound_packet(
            &link,
            &session,
            &clock,
            &app_channels,
            &runtime,
            &remote_keys,
            &remote_hp_key,
            1,
            &ack_pkt,
            &mut sweep,
        )
        .await;

        {
            let session = session.lock().await;
            assert!(
                !session.is_path_degraded(0),
                "losses under 3 x PTO must not degrade the path"
            );
        }
        let recent = runtime.lock().unwrap().events.lock().unwrap().recent(10);
        assert!(
            !recent.iter().any(|e| e.kind == "path_degraded"),
            "no path_degraded event for a short loss span"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pto_deadline_arms_only_with_in_flight_packets() {
        let mut session = test_session();
        let pto_state = PtoState::default();
        assert!(
            pto_deadline_at(&session, &pto_state).is_none(),
            "no deadline with nothing in flight"
        );
        let ping = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap();
        session
            .build_outbound(&crate::runtime_adapters::OsClock, Instant(0), &ping)
            .unwrap()
            .unwrap();
        assert!(
            pto_deadline_at(&session, &pto_state).is_some(),
            "deadline armed while ack-eliciting packets are in flight"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pto_deadline_not_extended_by_inbound_traffic() {
        let mut session = test_session();
        let ping = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap();
        session
            .build_outbound(&crate::runtime_adapters::OsClock, Instant(0), &ping)
            .unwrap()
            .unwrap();
        let pto_state = PtoState::default();
        let armed = pto_deadline_at(&session, &pto_state).expect("deadline armed");
        // Inbound processing that sends nothing must not extend the armed
        // deadline: the stale deadline fires on schedule instead of being
        // pushed back, so the PTO probe cannot be starved by traffic.
        assert_eq!(
            pto_deadline_after(&session, &pto_state, Some(armed)),
            Some(armed)
        );
        // No deadline armed with in-flight: the deadline is armed.
        let mut fresh = test_session();
        fresh
            .build_outbound(&crate::runtime_adapters::OsClock, Instant(0), &ping)
            .unwrap()
            .unwrap();
        assert!(pto_deadline_after(&fresh, &PtoState::default(), None).is_some());
        // Acking every in-flight packet clears the deadline.
        let ack = umc_wire::frame::AckFrame {
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 1,
            additional_ranges: Vec::new(),
        };
        fresh.apply_peer_ack(&ack, Instant(1)).unwrap();
        assert_eq!(
            pto_deadline_after(&fresh, &PtoState::default(), Some(armed)),
            None,
            "no in-flight packets means no deadline"
        );
        // Nothing in flight, nothing armed: stays disarmed.
        let idle = test_session();
        assert!(pto_deadline_after(&idle, &PtoState::default(), None).is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pto_backoff_doubles_until_capped() {
        let mut session = test_session();
        let ping = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap();
        session
            .build_outbound(&crate::runtime_adapters::OsClock, Instant(0), &ping)
            .unwrap()
            .unwrap();
        let mut pto = PtoState::default();
        let base = pto_deadline_ms(&session, &pto).expect("deadline armed");
        // Each consecutive PTO expiry doubles the armed deadline (1x, 2x,
        // 4x, ...) until the 64x cap (congestion.md §10.3).
        let mut expect = base;
        for _ in 0..6 {
            pto.on_expiry();
            expect *= 2;
            assert_eq!(
                pto_deadline_ms(&session, &pto).expect("deadline armed"),
                expect
            );
        }
        assert_eq!(pto.multiplier(), 64, "6 doublings cap the multiplier");
        pto.on_expiry();
        assert_eq!(
            pto_deadline_ms(&session, &pto).expect("deadline armed"),
            base * 64,
            "deadline capped at 64x the base PTO"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pto_backoff_resets_on_ack() {
        let mut session = test_session();
        let ping = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap();
        session
            .build_outbound(&crate::runtime_adapters::OsClock, Instant(0), &ping)
            .unwrap()
            .unwrap();
        let mut pto = PtoState::default();
        let base = pto_deadline_ms(&session, &pto).expect("deadline armed");
        for _ in 0..4 {
            pto.on_expiry();
        }
        assert_eq!(pto_deadline_ms(&session, &pto).unwrap(), base * 16);
        // An ACK-bearing inbound resets the backoff: the next deadline is
        // back at 1x the base PTO.
        pto.on_ack();
        assert_eq!(pto.multiplier(), 1);
        assert_eq!(pto_deadline_ms(&session, &pto).unwrap(), base);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn idle_timeout_sends_close_and_drains() {
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let link: Arc<BoxLink> = Arc::new(Box::new(RecordingLink {
            sent: recorded.clone(),
        }));
        let clock = FixedClock(1_000_000);
        let mut session = test_session();
        let t0 = Instant(1_000_000);
        session.touch(t0);

        // Before the timeout the interval sweep is a no-op.
        let (built, keepalive, done) = handle_idle_timers(
            &mut session,
            &clock,
            Instant(1_000_000 + IDLE_TIMEOUT_MS / 2 - 1),
            None,
        );
        assert!(!done);
        assert!(built.is_none());
        assert!(keepalive.is_none(), "no keepalive before half idle");
        assert_eq!(session.state, SessionState::Active);
        assert!(recorded.lock().unwrap().is_empty());

        // Past the idle timeout: a CONNECTION_CLOSE is built and the session
        // enters draining; the caller sends the bytes and the loop keeps
        // running.
        let now = Instant(1_000_000 + IDLE_TIMEOUT_MS);
        let (built, keepalive, done) = handle_idle_timers(&mut session, &clock, now, None);
        assert!(!done);
        assert!(
            keepalive.is_none(),
            "close path takes precedence over keepalive"
        );
        assert_eq!(session.state, SessionState::Draining);
        let close_bytes = built.expect("idle close built");
        link.send(OutboundPacket {
            bytes: close_bytes,
            control: false,
            deadline_ms: None,
        })
        .expect("recording link accepts");
        let sent = recorded.lock().expect("link sent");
        assert_eq!(sent.len(), 1, "exactly one idle close packet");
        let keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&[1u8; 32]).unwrap();
        let hp_key = umc_crypto::header_protection::header_protection_key(&[1u8; 32]);
        let (space, _dcid, _path, _pn, payload) =
            umc_session::packet::parse_protected_packet(&keys, &hp_key, 0, &sent[0]).unwrap();
        let parsed = umc_wire::packet::parse_payload(
            &umc_wire::packet::PacketContext::Protected(space),
            &payload,
        )
        .unwrap();
        assert!(parsed.frames.iter().any(|f| matches!(
            f,
            WireFrame::ConnectionClose(cc)
                if cc.error_code == CLOSE_REASON_IDLE_TIMEOUT && cc.reason == b"idle timeout"
        )));
        drop(sent);

        // Inside the drain window the sweep stays quiet and the session is
        // not yet expired...
        assert!(!session.draining_expired(Instant(now.0 + 3 * 1_000 - 1)));
        // ...and once draining expires the loop must exit with the session
        // finalized as closed.
        let (built, _keepalive, done) =
            handle_idle_timers(&mut session, &clock, Instant(now.0 + 3 * 1_000), None);
        assert!(built.is_none());
        assert!(done);
        assert_eq!(session.state, SessionState::Closed);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn idle_close_carries_session_ticket() {
        let material = TicketMaterial {
            ticket_key: [11u8; 32],
            resumption_secret: [12u8; 32],
            peer_endpoint_id: [13u8; 32],
            server_endpoint_id: [14u8; 32],
        };
        let t0 = Instant(1_000_000);
        let clock = FixedClock(t0.0);
        let mut session = test_session();
        session.touch(t0);
        let (built, keepalive, done) = handle_idle_timers(
            &mut session,
            &clock,
            t0 + ms(IDLE_TIMEOUT_MS),
            Some(&material),
        );
        assert!(keepalive.is_none(), "close path takes precedence");
        assert!(!done);
        assert_eq!(session.state, SessionState::Draining);
        let close_bytes = built.expect("idle close built");
        let keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&[1u8; 32]).unwrap();
        let hp_key = umc_crypto::header_protection::header_protection_key(&[1u8; 32]);
        let (space, _dcid, _path, _pn, payload) =
            umc_session::packet::parse_protected_packet(&keys, &hp_key, 0, &close_bytes).unwrap();
        let parsed = umc_wire::packet::parse_payload(
            &umc_wire::packet::PacketContext::Protected(space),
            &payload,
        )
        .unwrap();
        let ticket_frame = parsed
            .frames
            .iter()
            .find_map(|f| match f {
                WireFrame::SessionTicket(t) => Some(t),
                _ => None,
            })
            .expect("the close packet carries a SESSION_TICKET frame");
        // The ticket validates under the daemon's key and restores the
        // session's resumption secret and endpoint bindings.
        let back = umc_handshake::ticket::validate_ticket(
            &material.ticket_key,
            &ticket_frame.ticket,
            t0.0 + IDLE_TIMEOUT_MS + 1,
        )
        .expect("ticket validates under the daemon's key");
        assert_eq!(back.resumption_secret, [12u8; 32]);
        assert_eq!(back.client_endpoint_id_hash, [13u8; 32]);
        assert_eq!(back.server_endpoint_id_hash, [14u8; 32]);
        // The v1 clear nonce prefix lets the bearer derive the PSK without
        // the key; a wrong key cannot open the seal.
        assert_eq!(
            ticket_frame.ticket.first(),
            Some(&umc_handshake::ticket::TICKET_VERSION)
        );
        let nonce =
            umc_handshake::ticket::ticket_nonce(&ticket_frame.ticket).expect("clear nonce prefix");
        assert_eq!(nonce.len(), umc_handshake::ticket::TICKET_ENTROPY);
        let psk = umc_session::ticket::resumption_psk(&back.resumption_secret, &nonce);
        assert_ne!(psk, [0u8; 32]);
        assert!(
            umc_handshake::ticket::validate_ticket(&[0u8; 32], &ticket_frame.ticket, t0.0).is_err(),
            "a wrong ticket key must not open the ticket"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn draining_not_extended_by_idle_sweep() {
        let t0 = Instant(1_000_000);
        let clock = FixedClock(t0.0);
        let mut session = test_session();
        // Inflate the probe timeout so the draining window outlives the idle
        // timeout: the idle branch can then fire while still draining.
        session.sent_state_mut().record_sent(SentPacket::new(
            0,
            PacketSpace::SessionData,
            Instant(0),
            64,
            true,
            0,
        ));
        session
            .apply_peer_ack(
                &umc_wire::frame::AckFrame {
                    largest_acknowledged: 0,
                    ack_delay: 0,
                    first_ack_range: 1,
                    additional_ranges: Vec::new(),
                },
                Instant(100_000),
            )
            .expect("rtt sample");
        let pto = session.loss_detector().pto(session.rtt()).as_millis();
        let drain_ms = (3 * pto).max(MIN_DRAIN_MS);
        let d = t0 + ms(drain_ms);

        session.touch(t0);
        session.close(t0);
        assert_eq!(session.state, SessionState::Draining);

        // A later sweep, inside the drain window with the idle timer expired
        // (close sends do not touch): must not re-send the close or re-extend
        // the draining deadline.
        let (built, _keepalive, done) =
            handle_idle_timers(&mut session, &clock, t0 + ms(30_000), None);
        assert!(built.is_none(), "no second idle close while draining");
        assert!(!done);
        assert!(
            session.draining_expired(d),
            "draining deadline must not be re-extended by an idle sweep"
        );
        // Finalization still happens at the original deadline.
        let (built, _keepalive, done) = handle_idle_timers(&mut session, &clock, d, None);
        assert!(built.is_none());
        assert!(
            done,
            "draining expires and finalizes at the original deadline"
        );
        assert_eq!(session.state, SessionState::Closed);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn idle_probe_does_not_extend_idle_deadline() {
        let t0 = Instant(1_000_000);
        let clock = FixedClock(t0.0);
        let mut session = test_session();
        session.touch(t0);
        let ping = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap();
        // The PTO probe builder (reader loop) sends through build_outbound:
        // a probe to a possibly-dead peer must not re-arm the idle timer
        // (session.md §22 resets on receives, not on sends).
        session
            .build_outbound(&clock, t0 + ms(10_000), &ping)
            .expect("probe build")
            .expect("probe bytes");
        // The retransmit path re-sends a lost payload under a fresh packet
        // number (session.md §14.3): also not new traffic, so no re-arm.
        session
            .retransmit(0, t0 + ms(10_000))
            .expect("retransmit build")
            .expect("retransmit bytes");
        assert!(
            session.idle_expired(t0 + ms(30_000)),
            "PTO probes and retransmits must not extend the idle deadline"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn duplicate_replay_does_not_extend_idle() {
        let t0 = Instant(1_000_000);
        let clock = FixedClock(t0.0);
        let mut client = test_session();
        let ping = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap();
        let pkt = client
            .build_outbound(&clock, t0, &ping)
            .expect("build")
            .expect("bytes");
        let mut peer = peer_session();
        // First delivery anchors the peer's idle timer at t0.
        peer.on_inbound(t0, &pkt).expect("first delivery");
        // A replayed packet (same packet number) is rejected; it must not
        // re-arm the idle timer (session.md §22) or a zombie replaying the
        // same bytes would keep the session alive forever.
        assert!(
            peer.on_inbound(t0 + ms(29_000), &pkt).is_err(),
            "duplicate packet number must be rejected"
        );
        assert!(peer.idle_expired(t0 + ms(30_000)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn padding_only_packet_does_not_extend_idle() {
        let t0 = Instant(1_000_000);
        let clock = FixedClock(t0.0);
        let mut client = test_session();
        let padding = umc_wire::varint::encode(umc_types::frame::FrameType::PADDING.0).unwrap();
        let pkt = client
            .build_outbound(&clock, t0, &padding)
            .expect("build")
            .expect("bytes");
        let mut peer = peer_session();
        peer.touch(t0);
        // A padding-only packet carries no real frames: it must not reset the
        // idle timer (session.md §22 — only ack-eliciting/ACKed packets do).
        peer.on_inbound(t0 + ms(29_000), &pkt)
            .expect("padding packet parses");
        assert!(peer.idle_expired(t0 + ms(30_000)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn keepalive_ping_sent_at_half_idle() {
        let t0 = Instant(1_000_000);
        let clock = FixedClock(t0.0);
        let mut session = test_session();
        session.touch(t0);

        // At half the idle timeout the sweep builds a PING keepalive packet
        // for the caller to send (same drop-guard pattern as the close);
        // the session stays Active and no close is produced.
        let (close, keepalive, done) =
            handle_idle_timers(&mut session, &clock, t0 + ms(IDLE_TIMEOUT_MS / 2), None);
        assert!(!done);
        assert!(close.is_none(), "no close while idle not expired");
        let bytes = keepalive.expect("keepalive built at half idle");
        let keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&[1u8; 32]).unwrap();
        let hp_key = umc_crypto::header_protection::header_protection_key(&[1u8; 32]);
        let (space, _dcid, _path, _pn, payload) =
            umc_session::packet::parse_protected_packet(&keys, &hp_key, 0, &bytes).unwrap();
        let parsed = umc_wire::packet::parse_payload(
            &umc_wire::packet::PacketContext::Protected(space),
            &payload,
        )
        .unwrap();
        assert!(
            parsed.frames.iter().any(|f| matches!(f, WireFrame::Ping)),
            "keepalive packet carries PING"
        );
        assert_eq!(session.state, SessionState::Active);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn keepalive_extends_idle_deadline() {
        let t0 = Instant(1_000_000);
        let clock = FixedClock(t0.0);
        let mut session = test_session();
        session.touch(t0);

        // The keepalive at half idle touches the session: the idle deadline
        // moves out by another full timeout, suppressing the idle close.
        let (close, keepalive, done) =
            handle_idle_timers(&mut session, &clock, t0 + ms(IDLE_TIMEOUT_MS / 2), None);
        assert!(close.is_none());
        assert!(keepalive.is_some(), "keepalive built at half idle");
        assert!(!done);
        assert!(
            !session.idle_expired(t0 + ms(IDLE_TIMEOUT_MS)),
            "keepalive suppresses the idle close"
        );
        // A full timeout after the keepalive the session is idle again and
        // the close path runs; no further keepalive.
        let (close, keepalive, done) = handle_idle_timers(
            &mut session,
            &clock,
            t0 + ms(IDLE_TIMEOUT_MS + IDLE_TIMEOUT_MS / 2),
            None,
        );
        assert!(close.is_some(), "idle close after a full timeout");
        assert!(
            keepalive.is_none(),
            "close path takes precedence over keepalive"
        );
        assert!(!done);
        assert_eq!(session.state, SessionState::Draining);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn no_keepalive_when_idle_expired() {
        let t0 = Instant(1_000_000);
        let clock = FixedClock(t0.0);
        let mut session = test_session();
        session.touch(t0);

        // Idle-expired at the timeout: the close path runs and no keepalive
        // is produced — the keepalive branch only fires while not
        // idle-expired.
        let (close, keepalive, done) =
            handle_idle_timers(&mut session, &clock, t0 + ms(IDLE_TIMEOUT_MS), None);
        assert!(!done);
        assert!(close.is_some(), "close path runs at the idle timeout");
        assert!(keepalive.is_none(), "no keepalive when idle expired");
        assert_eq!(session.state, SessionState::Draining);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bus_outbound_touches_idle() {
        let (state, _tx) = test_state();
        let runtime = Arc::new(std::sync::Mutex::new(state));
        let t0 = Instant(1_000_000);
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(t0.0 + 1_000));
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let link: Arc<BoxLink> = Arc::new(Box::new(RecordingLink {
            sent: recorded.clone(),
        }));
        let session = Arc::new(tokio::sync::Mutex::new(test_session()));
        {
            let mut session = session.lock().await;
            session.touch(t0);
        }
        let remote_keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&[2u8; 32]).unwrap();
        let remote_hp_key = umc_crypto::header_protection::header_protection_key(&[2u8; 32]);

        // The reader loop's bus-outbound arm receives one relay payload; the
        // packet and inbound channels stay open (empty) so the select cannot
        // break before the send, and the outbound sender is dropped after
        // the item so the loop exits after processing it.
        let links = SessionLinkSet::from_arc(0, link.clone());
        let (_packet_tx, packet_rx) = tokio::sync::mpsc::unbounded_channel::<(u64, Vec<u8>)>();
        let (_inbound_tx, bus_inbound_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (outbound_tx, bus_outbound_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        outbound_tx
            .send(b"relay-bytes".to_vec())
            .expect("queue bus outbound");
        drop(outbound_tx);

        let app_channels: Arc<std::sync::Mutex<HashMap<Vec<u8>, AppTx>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let ended = Arc::new(AtomicBool::new(false));
        reader_loop(
            &links,
            &session,
            &clock,
            &shutdown_flag,
            &ended,
            &app_channels,
            &runtime,
            PrivacyRuntimePolicy::from_config(
                0,
                false,
                0,
                false,
                1_000,
                0,
                DCID_ROTATION_INTERVAL_MS,
            ),
            &remote_keys,
            &remote_hp_key,
            None,
            1,
            packet_rx,
            bus_inbound_rx,
            bus_outbound_rx,
        )
        .await;

        // The relay payload reached the link as a protected session packet.
        {
            let sent = recorded.lock().expect("link sent");
            assert_eq!(sent.len(), 1, "bus-outbound bytes sent once");
            let local_keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&[1u8; 32]).unwrap();
            let local_hp = umc_crypto::header_protection::header_protection_key(&[1u8; 32]);
            let (_, _, _, _, payload) =
                umc_session::packet::parse_protected_packet(&local_keys, &local_hp, 0, &sent[0])
                    .expect("bus payload is protected");
            assert_eq!(payload, b"relay-bytes");
        }
        // ...and the successful send reset the idle timer: a session last
        // active at t0 would be idle at the close instant, but the relay
        // send at t0+1s keeps it alive (session.md §22).
        let session = session.lock().await;
        assert_eq!(
            session.last_activity(),
            Some(Instant(t0.0 + 1_000)),
            "bus outbound resets the idle timer"
        );
        assert!(
            !session.idle_expired(Instant(t0.0 + 1_000 + IDLE_TIMEOUT_MS - 1)),
            "bus outbound traffic keeps the destination session alive"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn closed_session_sends_stateless_reset() {
        let (state, _tx) = test_state();
        let runtime = Arc::new(std::sync::Mutex::new(state));
        let t0 = Instant(1_000_000);
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(t0.0));
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let link: Arc<BoxLink> = Arc::new(Box::new(RecordingLink {
            sent: recorded.clone(),
        }));
        let remote_keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&[2u8; 32]).unwrap();
        let remote_hp_key = umc_crypto::header_protection::header_protection_key(&[2u8; 32]);

        // A drained session is finalized as Closed; traffic on it must be
        // answered with a stateless reset (session.md §31).
        let mut session = test_session();
        session.close(t0);
        session.finalize_close();
        assert_eq!(session.state, SessionState::Closed);

        // The peer (who shares the stateless-reset secret) sends a reset.
        let token = umc_session::reset::reset_token(&[9u8; 32]);
        let reset_pkt =
            umc_session::reset::build_stateless_reset(&token, &crate::runtime_adapters::OsEntropy);
        assert!(umc_session::reset::token_matches(&reset_pkt, &token));

        let session = Arc::new(tokio::sync::Mutex::new(session));
        let app_channels: Arc<std::sync::Mutex<HashMap<Vec<u8>, AppTx>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let mut sweep = SweepState::default();
        process_inbound_packet(
            &link,
            &session,
            &clock,
            &app_channels,
            &runtime,
            &remote_keys,
            &remote_hp_key,
            1,
            &reset_pkt,
            &mut sweep,
        )
        .await;

        // The daemon answers with one rate-limited reset carrying the
        // session's token, and the session stays closed.
        {
            let sent = recorded.lock().expect("link sent");
            assert_eq!(sent.len(), 1, "the daemon answers with exactly one reset");
            let reset = &sent[0];
            assert!(reset.len() >= 32, "reset is at least as long as a packet");
            assert!(
                umc_session::reset::token_matches(reset, &token),
                "the emitted reset carries the session's token"
            );
        }
        let session = session.lock().await;
        assert_eq!(session.state, SessionState::Closed);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn paced_send_respects_interval() {
        let t0 = Instant(1_000_000);
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(t0.0));
        let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let link: Arc<BoxLink> = Arc::new(Box::new(RecordingLink {
            sent: recorded.clone(),
        }));
        let mut client = test_session();
        let sid = client.open_stream().expect("stream");
        // A sampled RTT activates pacing (congestion.md §12): the 12,000-
        // byte window over a 100 ms RTT paces at 960,000 bits/s with a
        // 6,000-byte burst.
        client.congestion_mut().set_smoothed_rtt(100, t0);
        assert_eq!(client.congestion_mut().pacing_rate_bps(), 960_000);
        // Exhaust the bucket: the next echo send must wait out its spacing
        // interval (~8 ms for a ~1 KB packet) instead of going out at once.
        client.congestion_mut().consume_pacing(6_000, t0);
        let session = Arc::new(tokio::sync::Mutex::new(client));
        let echo_rx: Arc<std::sync::Mutex<HashMap<Vec<u8>, AppRx>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let (tx, rx) = umc_core::app_io::spawn_app_channel(1);
        tx.send_stream_frame(sid, vec![0xCD; 1_000])
            .await
            .expect("queue echo");
        drop(tx);
        echo_rx.lock().expect("echo map").insert(vec![], rx);
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let ended = Arc::new(AtomicBool::new(false));

        // The writer loop exits once the only echo receiver disconnects.
        let start = tokio::time::Instant::now();
        let links = SessionLinkSet::from_arc(0, link.clone());
        writer_loop(
            &links,
            &session,
            &clock,
            &shutdown_flag,
            &ended,
            &echo_rx,
            1,
            PrivacyRuntimePolicy::from_config(
                0,
                false,
                0,
                false,
                1_000,
                0,
                DCID_ROTATION_INTERVAL_MS,
            ),
        )
        .await;
        let elapsed = start.elapsed();

        // The echo reached the link, held back by the pacing interval: a
        // 1,000-byte payload builds to ~1,036 wire bytes and the empty
        // bucket computes 1036 × 8000 / 960000 ≈ 8 ms of spacing.
        assert!(
            !recorded.lock().expect("link sent").is_empty(),
            "paced echo reaches the link"
        );
        assert!(
            elapsed >= std::time::Duration::from_millis(8),
            "paced send waits out its spacing interval (elapsed {elapsed:?})"
        );
        // The tokens were consumed at the real send time: a follow-up send
        // must wait again — the accessor reports the full delay. The fixed
        // test clock never advances past t0, so the 1,036-byte wire send
        // earned no refill during its sleep: the bucket honestly carries
        // the overdraw as debt (congestion.md §12 fractional-token
        // accounting), and the next 1,200-byte packet waits
        // (1200 + 1036) × 8000 / 960000 ≈ 18 ms to repay it.
        let mut session = session.lock().await;
        let next = session
            .congestion_mut()
            .next_send_time(t0, 1_200)
            .expect("pacing active after a sample");
        assert_eq!(
            next.duration_since(t0).as_millis(),
            18,
            "empty bucket with overdraw debt spaces a 1200-byte packet at 960,000 bits/s"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn backpressured_data_send_skipped_ack_still_sent() {
        // Carrier queue at 90% of capacity (congestion.md §16): the gate
        // opens past 80%, so data payloads must be held back while the ACK
        // loop keeps running.
        let link: BoxLink = Box::new(BackpressuredLink {
            queue_bytes: 2 * 1024 * 1024 * 9 / 10,
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        });
        let data = umc_wire::varint::encode(umc_types::frame::FrameType::STREAM.0).unwrap();
        let ack = umc_wire::frame::AckFrame {
            largest_acknowledged: 3,
            ack_delay: 0,
            first_ack_range: 1,
            additional_ranges: Vec::new(),
        }
        .encode()
        .expect("ack frame");
        let ping = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap();
        assert!(
            should_backpressure(&link, &data),
            "data payload gated at 90% queue"
        );
        assert!(
            !should_backpressure(&link, &ack),
            "ACK payload always sent, even backpressured"
        );
        assert!(
            !should_backpressure(&link, &ping),
            "PING payload always sent, even backpressured"
        );
        // Under the threshold the same data payload goes through.
        let open: BoxLink = Box::new(BackpressuredLink {
            queue_bytes: 1024,
            sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        });
        assert!(
            !should_backpressure(&open, &data),
            "data payload below the 80% threshold is sent"
        );
    }

    #[test]
    fn control_frames_parse_after_pn_wrap() {
        // Regression for the AEAD anchor: parse_control_frames must open
        // packets whose wire pn has wrapped past the truncated width (the
        // old expected=0 anchor failed and silently dropped control frames).
        let secret = [1u8; 32];
        let keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&secret).unwrap();
        let hp_key = umc_crypto::header_protection::header_protection_key(&secret);
        let dcid = vec![7u8; 8];
        let relay_open = RelayOpenFrame {
            circuit_id: 1,
            bidirectional: false,
            store_forward_allowed: false,
            private_circuit: false,
            multipath_allowed: false,
            requested_lifetime: 600_000,
            requested_byte_quota: 1_048_576,
            next_hop_hint: vec![1u8; 32],
            authorization: Vec::new(),
        }
        .encode()
        .unwrap();
        // pn 70 000 > 65 535: the truncated 16-bit wire value is 4 465.
        let pkt = umc_session::packet::build_protected_packet(
            &keys,
            &hp_key,
            umc_wire::header::ShortPacketSpace::SessionData,
            &dcid,
            0,
            70_000,
            false,
            &relay_open,
        )
        .unwrap();
        // The correct anchor (expected = 70 001) opens and the control
        // frame is visible.
        let frames = parse_control_frames(&keys, &hp_key, 70_001, &pkt).expect("control frames");
        assert!(
            frames
                .2
                .iter()
                .any(|f| matches!(f, WireFrame::RelayOpen(_))),
            "relay open must survive the pn wrap"
        );
        // The old anchor (0) reconstructs to the truncated value and fails
        // the AEAD open.
        assert!(parse_control_frames(&keys, &hp_key, 0, &pkt).is_none());
    }

    #[test]
    fn p3_policy_enables_padding_but_keeps_cover_opt_in() {
        let p3 = PrivacyRuntimePolicy::from_config(3, false, 25, false, 1_000, 4_096, 600_000);
        assert_eq!(p3.profile(), 3);
        assert!(p3.traffic_padding());
        assert_eq!(p3.timing_jitter_ms(), 25);
        assert!(!p3.cover_traffic());

        let p2 = PrivacyRuntimePolicy::from_config(2, false, 25, true, 1_000, 4_096, 600_000);
        assert!(!p2.traffic_padding());
        assert_eq!(p2.timing_jitter_ms(), 0);
        assert!(!p2.cover_traffic());
    }

    #[test]
    fn cover_budget_is_bounded_per_second() {
        let start = tokio::time::Instant::now();
        let mut budget = CoverBudget::new(start);
        assert!(budget.reserve(start, 100, 200));
        assert!(budget.reserve(start, 100, 200));
        assert!(!budget.reserve(start, 1, 200));
        let next = start + Duration::from_secs(1);
        assert!(budget.reserve(next, 200, 200));
    }

    #[test]
    fn cover_payload_is_padding_then_ping() {
        let payload = cover_payload();
        assert_eq!(payload[0], 0, "cover payload must engage padding policy");
        let (frame_type, used) = umc_wire::varint::decode(&payload[1..]).expect("ping");
        assert_eq!(frame_type, umc_types::frame::FrameType::PING.0);
        assert_eq!(used + 1, payload.len());
    }
}
