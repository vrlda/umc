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
use umc_session::loss::detect_lost_packets;
use umc_session::session::{Session, SessionState, IDLE_TIMEOUT_MS};
use umc_types::runtime::{Clock, Instant};
use umc_wire::frame::Frame;
use umc_wire::frames::bundle::BundleFrame;
use umc_wire::frames::relay::RelayStatusFrame;
use umc_wire::frames::routing::RouteResponseFrame;
use umc_wire::header::ShortPacketSpace;
use umc_wire::packet::{parse_payload, PacketContext};

use crate::relay_service::CircuitOpenRequest;
use crate::state::RuntimeState;

/// Poll interval when the link reports `WouldBlock`.
pub const RECV_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Poll interval of the echo drain when no echo is pending.
pub const ECHO_POLL_INTERVAL: Duration = Duration::from_millis(5);
/// Period of the reader's idle/draining sweep (session.md §6.4, §22). The
/// sweep only checks the session's idle and draining timers; it never
/// touches the PTO schedule.
pub const IDLE_SWEEP_INTERVAL: Duration = Duration::from_millis(1_000);
/// Pause after processing a packet before the next blocking recv. The TCP
/// carrier serializes reads and writes behind one mutex, so a recv in
/// flight starves the carrier's background writer; the pause gives queued
/// ACKs and echoes a window to flush (carriers/tcp.md).
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(5);
/// The daemon initiates a key update after this much session lifetime
/// (session.md §24): every 10 minutes, while the previous update has
/// completed.
pub const KEY_UPDATE_INTERVAL_MS: u64 = 10 * 60 * 1000;
/// Pending-bundle delivery sweep interval (bundles.md §10.1).
pub const BUNDLE_FLUSH_INTERVAL_MS: u64 = 30 * 1000;
/// Maximum bundle frames wrapped per delivery sweep; bundle payloads can
/// approach the packet-size cap, so sweeps drip at most one frame per
/// sweep (the 30s interval bounds the drip).
pub const BUNDLES_PER_FLUSH: usize = 1;
/// Headroom reserved for packet headers and AEAD tags when fitting a
/// `BUNDLE` frame into a protected packet (wire-format §17).
pub const BUNDLE_PACKET_HEADROOM: usize = 256;

/// `RELAY_STATUS` result codes (relay.md §12.2).
pub const RELAY_STATUS_ACCEPTED: u64 = 1;
pub const RELAY_STATUS_REFUSED: u64 = 2;

/// Sleep until the PTO deadline, or forever when no deadline is armed.
async fn pto_sleep(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// PTO deadline from the session's in-flight state (session.md §14.3): a
/// probe fires `pto * multiplier` after the last arming while any
/// ack-eliciting packet is outstanding; no deadline when nothing is in
/// flight.
fn pto_deadline_at(session: &Session, multiplier: u32) -> Option<tokio::time::Instant> {
    let in_flight = session
        .sent_state()
        .sent()
        .iter()
        .any(|p| p.ack_eliciting && p.in_flight);
    if !in_flight {
        return None;
    }
    let ms = session
        .loss_detector()
        .pto(session.rtt())
        .as_millis()
        .saturating_mul(u64::from(multiplier));
    Some(tokio::time::Instant::now() + Duration::from_millis(ms))
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
    multiplier: u32,
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
    armed.or_else(|| pto_deadline_at(session, multiplier))
}

/// One idle/draining sweep on the reader's 1 s interval arm (session.md
/// §6.4, §22): when the session has been idle past the timeout while still
/// `Active`, build a `CONNECTION_CLOSE` packet and enter draining; once the
/// draining deadline has passed, finalize the close. Returns the built idle
/// close packet and the built keepalive ping (the caller sends them after
/// dropping the session guard) and whether the reader loop should exit (the
/// draining period ended).
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
) -> (Option<Vec<u8>>, Option<Vec<u8>>, bool) {
    if session.draining_expired(now) {
        session.finalize_close();
        return (None, None, true);
    }
    if session.state == SessionState::Active && session.idle_expired(now) {
        let built = session
            .build_idle_close(now)
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
/// parsing the control frames the session layer does not expose.
///
/// The session's bus channels are registered by the caller (which holds the
/// runtime state lock at the spawn site) with the tx sides of
/// `bus_inbound_rx` and `bus_outbound_rx`; the reader selects over the
/// carrier pump, the bus-inbound channel, and the bus-outbound channel.
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
    remote_keys: PacketKeys,
    bus_inbound_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    bus_outbound_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) -> JoinHandle<()> {
    let link = Arc::new(link);
    let session = Arc::new(tokio::sync::Mutex::new(session));
    let ended = Arc::new(AtomicBool::new(false));

    // The carrier API is blocking (Handle::block_on internally); it runs on
    // its own pump task so the reader's select can serve the session bus
    // channels while the link is idle. The pump exits on link failure or
    // shutdown; dropping the packet channel ends the reader.
    //
    // The TCP carrier serializes reads and writes behind one mutex, so a
    // recv in flight starves the carrier's background writer; the pause
    // after each handoff gives queued ACKs, echoes, and bus-outbound
    // frames a window to flush (carriers/tcp.md).
    let (packet_tx, packet_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    // The carrier API is blocking and internally `block_on`s, so the pump
    // must run on a blocking thread (spawn_blocking) — block_on on a tokio
    // worker panics, and block_in_place nests dangerously here.
    let pump_link = link.clone();
    let pump_shutdown = shutdown_flag.clone();
    tokio::task::spawn_blocking(move || loop {
        if pump_shutdown.load(Ordering::Relaxed) {
            break;
        }
        let inbound = pump_link.recv();
        match inbound {
            Ok(packet) => {
                #[cfg(debug_assertions)]
                println!("[session {session_id}] recv {} bytes", packet.bytes.len());
                if packet_tx.send(packet.bytes).is_err() {
                    break;
                }
                std::thread::sleep(FLUSH_INTERVAL);
            }
            Err(e) if e.kind == CarrierErrorKind::WouldBlock => {
                std::thread::sleep(RECV_POLL_INTERVAL);
            }
            Err(e) => {
                #[cfg(debug_assertions)]
                println!("[session {session_id}] recv error: {e:?}");
                break;
            }
        }
    });

    let reader_link = link.clone();
    let reader_session = session.clone();
    let reader_shutdown = shutdown_flag.clone();
    let reader_clock = clock.clone();
    let reader_ended = ended.clone();
    let reader_runtime = runtime.clone();
    tokio::spawn(async move {
        reader_loop(
            &reader_link,
            &reader_session,
            &reader_clock,
            &reader_shutdown,
            &reader_ended,
            &app_channels,
            &reader_runtime,
            &remote_keys,
            session_id,
            packet_rx,
            bus_inbound_rx,
            bus_outbound_rx,
        )
        .await;
    });

    let writer_link = link.clone();
    let writer_session = session.clone();
    let writer_clock = clock.clone();
    tokio::spawn(async move {
        writer_loop(
            &writer_link,
            &writer_session,
            &writer_clock,
            &shutdown_flag,
            &ended,
            &app_echo_rx,
            session_id,
        )
        .await;
    })
}

/// Per-session schedule state threaded through inbound processing: session
/// establishment time, the last key update, the last bundle sweep.
#[derive(Default)]
struct SweepState {
    established: Option<Instant>,
    last_key_update: Option<Instant>,
    last_bundle_flush: Option<Instant>,
}

/// Reader loop: pull packets off the carrier pump or the session bus, feed
/// the session state machine, send the ACKs it produces, forward stream
/// data to applications, and dispatch control frames (relay/bundle/routing/
/// key-update) to the runtime services.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn reader_loop(
    link: &Arc<BoxLink>,
    session: &Arc<tokio::sync::Mutex<Session>>,
    clock: &Arc<dyn Clock>,
    shutdown_flag: &Arc<AtomicBool>,
    ended: &Arc<AtomicBool>,
    app_channels: &Arc<Mutex<HashMap<Vec<u8>, AppTx>>>,
    runtime: &Arc<Mutex<RuntimeState>>,
    remote_keys: &PacketKeys,
    session_id: u64,
    mut packet_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    mut bus_inbound_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    mut bus_outbound_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let mut sweep = SweepState::default();
    // PTO probe schedule (session.md §14.3): the deadline is armed when
    // nothing is armed and ack-eliciting packets are in flight, re-armed
    // (with a doubled multiplier) when it fires and a probe was sent, and
    // cleared once everything is acknowledged. An armed deadline is never
    // extended by inbound traffic, so the probe cannot be starved.
    let mut pto_deadline: Option<tokio::time::Instant> = None;
    let mut pto_multiplier: u32 = 1;
    // Idle/draining sweep (session.md §6.4, §22): checks the session's idle
    // timer and draining deadline; it must not interfere with the PTO
    // schedule (an armed PTO deadline is never extended by this arm).
    let mut idle_sweep = tokio::time::interval(IDLE_SWEEP_INTERVAL);
    loop {
        if shutdown_flag.load(Ordering::Relaxed) {
            break;
        }
        tokio::select! {
            recv = packet_rx.recv() => {
                match recv {
                    Some(bytes) => {
                        if process_inbound_packet(
                            link,
                            session,
                            clock,
                            app_channels,
                            runtime,
                            remote_keys,
                            session_id,
                            &bytes,
                            &mut sweep,
                        )
                        .await
                        {
                            pto_multiplier = 1;
                        }
                    }
                    None => break,
                }
            }
            recv = bus_inbound_rx.recv() => {
                match recv {
                    Some(bytes) => {
                        if process_inbound_packet(
                            link,
                            session,
                            clock,
                            app_channels,
                            runtime,
                            remote_keys,
                            session_id,
                            &bytes,
                            &mut sweep,
                        )
                        .await
                        {
                            pto_multiplier = 1;
                        }
                    }
                    None => break,
                }
            }
            recv = bus_outbound_rx.recv() => {
                match recv {
                    Some(bytes) => {
                        let now = clock.now();
                        let sent = tokio::task::block_in_place(|| {
                            link.send(OutboundPacket {
                                bytes,
                                control: false,
                                deadline_ms: None,
                            })
                        });
                        if sent.is_ok() {
                            // Bus-outbound traffic is app-originated (relay
                            // forwarding, bundle delivery): resets the idle
                            // timer (session.md §22) so a one-way relay flow
                            // keeps the destination session from idle-closing
                            // a live circuit.
                            let mut session = session.lock().await;
                            session.touch(now);
                        } else if let Err(e) = sent {
                            #[cfg(debug_assertions)]
                            println!("[session {session_id}] send error: {e:?}");
                        }
                    }
                    None => break,
                }
            }
            _ = idle_sweep.tick() => {
                let now = clock.now();
                // Build the idle close / keepalive (if any) under the guard;
                // the sends happen after it is dropped — the carrier API is
                // blocking.
                let (built_close, built_keepalive, done) = {
                    let mut session = session.lock().await;
                    handle_idle_timers(&mut session, clock.as_ref(), now)
                };
                if let Some(bytes) = built_close {
                    let sent = tokio::task::block_in_place(|| {
                        link.send(OutboundPacket {
                            bytes,
                            control: false,
                            deadline_ms: None,
                        })
                    });
                    if let Err(e) = sent {
                        #[cfg(debug_assertions)]
                        println!("[session {session_id}] idle close send error: {e:?}");
                    }
                }
                if let Some(bytes) = built_keepalive {
                    let sent = tokio::task::block_in_place(|| {
                        link.send(OutboundPacket {
                            bytes,
                            control: false,
                            deadline_ms: None,
                        })
                    });
                    if let Err(e) = sent {
                        #[cfg(debug_assertions)]
                        println!("[session {session_id}] keepalive send error: {e:?}");
                    }
                }
                if done {
                    #[cfg(debug_assertions)]
                    println!("[session {session_id}] draining period ended, closing session");
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
                        link.send(OutboundPacket {
                            bytes,
                            control: false,
                            deadline_ms: None,
                        })
                    });
                    if sent.is_ok() {
                        // The backoff doubles only when a probe was actually
                        // sent (session.md §14.3); a failed send leaves the
                        // multiplier unchanged.
                        pto_multiplier = pto_multiplier.saturating_mul(2);
                    } else if let Err(e) = sent {
                        #[cfg(debug_assertions)]
                        println!("[session {session_id}] PTO probe send error: {e:?}");
                    }
                }
                // The deadline just fired: re-arm from now while ack-eliciting
                // packets remain in flight (disarmed once they are all acked).
                let session = session.lock().await;
                pto_deadline = pto_deadline_at(&session, pto_multiplier);
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
            pto_deadline = pto_deadline_after(&session, pto_multiplier, pto_deadline);
        }
    }
    ended.store(true, Ordering::Relaxed);
    runtime
        .lock()
        .expect("runtime state")
        .bus
        .lock()
        .expect("session bus")
        .unregister(session_id);
}

/// Process one inbound byte buffer — from the carrier pump or the session
/// bus — as a carrier packet: feed the session state machine, send the ACK
/// payloads it produces, dispatch control frames, and forward matching
/// stream data to registered applications. Returns whether the packet
/// carried an ACK frame (the reader resets the PTO backoff on ACKs).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn process_inbound_packet(
    link: &Arc<BoxLink>,
    session: &Arc<tokio::sync::Mutex<Session>>,
    clock: &Arc<dyn Clock>,
    app_channels: &Arc<Mutex<HashMap<Vec<u8>, AppTx>>>,
    runtime: &Arc<Mutex<RuntimeState>>,
    remote_keys: &PacketKeys,
    session_id: u64,
    bytes: &[u8],
    sweep: &mut SweepState,
) -> bool {
    let now = clock.now();
    // The control frames the session layer does not expose: relay,
    // bundle, routing, and key updates.
    let frames = parse_control_frames(remote_keys, bytes);
    let mut outbound = None;
    let mut retransmits: Vec<Vec<u8>> = Vec::new();
    let mut pending: Vec<(Vec<u8>, u64, Vec<u8>)> = Vec::new();
    {
        let mut session = session.lock().await;
        let ack_payload = match session.on_inbound(now, bytes) {
            Ok(payload) => payload,
            Err(e) => {
                #[cfg(debug_assertions)]
                println!("[session {session_id}] inbound error: {e:?}");
                return false;
            }
        };
        // Loss detection (session.md §14) runs only for the session data
        // space: an ACK of a packet at least three numbers higher declares
        // older packets lost; their retained payloads are re-sent under
        // fresh packet numbers. Every lost packet leaves the sent queue;
        // non-ack-eliciting ones only have their retained payload pruned.
        if let Some((space, control_frames)) = frames.as_ref() {
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
                    let lost = detect_lost_packets(
                        session.sent_state_mut(),
                        &rtt,
                        now,
                        largest_acked,
                        &detector,
                    );
                    for pn in lost {
                        if let Ok(Some(bytes)) = session.retransmit(pn, now) {
                            retransmits.push(bytes);
                        } else {
                            session.prune_retransmit_payload(pn);
                        }
                    }
                }
            }
        }
        let mut combined = ack_payload;
        // Flow-control credit (session.md §20): MAX_DATA / MAX_STREAM_DATA /
        // MAX_STREAMS payloads are emitted when a local watermark is crossed.
        for credit in session.flow_control_frames(now) {
            combined.extend_from_slice(&credit);
        }
        let sweep_due = bundle_flush_due(now, sweep.last_bundle_flush);
        let rotation_due = sweep
            .established
            .is_some_and(|started| key_rotation_due(now, started, sweep.last_key_update));
        if sweep.established.is_none() {
            sweep.established = Some(now);
        }
        if frames.is_some() || sweep_due || rotation_due {
            let mut state = runtime.lock().expect("runtime state");
            if let Some((_space, control_frames)) = &frames {
                if let Some(payload) =
                    handle_control_frames(&mut state, session_id, &mut session, control_frames, now)
                {
                    combined.extend_from_slice(&payload);
                }
            }
            if sweep_due {
                let payload = flush_pending_bundles(&mut state, now);
                combined.extend_from_slice(&payload);
                sweep.last_bundle_flush = Some(now);
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
        }
        if !combined.is_empty() {
            let built = session.build_outbound(clock.as_ref(), now, &combined);
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
                    #[cfg(debug_assertions)]
                    println!("[session {session_id}] ack build error: {e:?}");
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
            if let Ok((data, _eof)) = session.read_stream(stream_id) {
                if !data.is_empty() {
                    pending.push((protocol_id, stream_id, data));
                }
            }
        }
    }
    for (protocol_id, stream_id, data) in pending {
        let channel = app_channels
            .lock()
            .expect("app channels")
            .get(&protocol_id)
            .expect("channel exists")
            .clone();
        #[cfg(debug_assertions)]
        println!(
            "[session {session_id}] dispatch stream {stream_id} to {:?} ({} bytes)",
            protocol_id,
            data.len()
        );
        if channel.send_stream_frame(stream_id, data).await.is_err() {
            break;
        }
    }
    if let Some(outbound) = outbound {
        let sent = tokio::task::block_in_place(|| {
            link.send(OutboundPacket {
                bytes: outbound,
                control: false,
                deadline_ms: None,
            })
        });
        if let Err(e) = sent {
            #[cfg(debug_assertions)]
            println!("[session {session_id}] send error: {e:?}");
        }
    }
    for bytes in retransmits {
        let sent = tokio::task::block_in_place(|| {
            link.send(OutboundPacket {
                bytes,
                control: false,
                deadline_ms: None,
            })
        });
        if let Err(e) = sent {
            #[cfg(debug_assertions)]
            println!("[session {session_id}] retransmit send error: {e:?}");
        }
    }
    frames
        .as_ref()
        .is_some_and(|(_space, fs)| fs.iter().any(|f| matches!(f, Frame::Ack(_))))
}

/// Parse the control frames out of an inbound protected packet with the
/// daemon's copy of the peer's traffic keys. The session layer applies
/// stream/datagram/ACK frames itself; this read-only parse (with the same
/// keys, so it never disturbs session state) exposes the packet's space and
/// the relay, bundle, routing, and key-update frames for daemon dispatch.
fn parse_control_frames(
    remote_keys: &PacketKeys,
    bytes: &[u8],
) -> Option<(ShortPacketSpace, Vec<Frame>)> {
    let (space, _dcid, _path, _pn, payload) =
        umc_session::packet::parse_protected_packet(remote_keys, bytes).ok()?;
    let parsed = parse_payload(&PacketContext::Protected(space), &payload).ok()?;
    Some((space, parsed.frames))
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
                let result = state.relay.open_circuit(
                    &CircuitOpenRequest {
                        peer_circuits: state.relay.circuits_for_peer(session_id),
                        requested_lifetime_ms: open.requested_lifetime,
                        requested_byte_quota: open.requested_byte_quota,
                        flags: relay_request_flags(open),
                        bidirectional: open.bidirectional,
                        private_handling: open.private_circuit,
                        destination_hint: open.next_hop_hint.clone(),
                    },
                    peer_endpoint_id.to_vec(),
                    now,
                );
                let (code, retryable, granted) = match result {
                    Ok(accepted) => {
                        let circuit_id = accepted.circuit_id;
                        state.relay.record_circuit_owner(circuit_id, session_id);
                        (RELAY_STATUS_ACCEPTED, false, Some(accepted))
                    }
                    Err(_) => (RELAY_STATUS_REFUSED, true, None),
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
                if let Ok(encoded) = status.encode() {
                    outbound.extend_from_slice(&encoded);
                }
            }
            Frame::RelayData(data) => {
                // The circuit's peer end is the session that opened it: only
                // the owning session may send `RELAY_DATA` on the circuit
                // (relay.md §16-18).
                if state.relay.circuit_owner(data.circuit_id) != Some(session_id) {
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
                match state.relay.accept_upstream(
                    data.circuit_id,
                    data.relay_sequence,
                    data.fin,
                    &data.data,
                    now,
                ) {
                    Ok(()) => {
                        // Cross-session forwarding (relay.md §18): the
                        // circuit's destination peer gets a fresh
                        // `RELAY_DATA` pushed into its session via the bus.
                        match state.relay.forward_data(data.circuit_id, &data.data, now) {
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
                                }
                            }
                            Err(e) => push_event(
                                state,
                                "relay_forward_dropped",
                                now,
                                format!("circuit {}: {e}", data.circuit_id),
                            ),
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
                if let Err(e) = state
                    .relay
                    .close_circuit(close.circuit_id, close.reason_code, now)
                {
                    push_event(
                        state,
                        "relay_close_rejected",
                        now,
                        format!("circuit {}: {e}", close.circuit_id),
                    );
                }
            }
            Frame::Bundle(bundle) => {
                let lifetime = bundle.expiration_time.saturating_sub(bundle.creation_time);
                let admitted = state.bundle.admit(
                    &bundle.payload,
                    &peer_endpoint_id,
                    &bundle.destination_hint,
                    bundle.priority,
                    lifetime.max(1_000),
                    bundle.replication_limit,
                    bundle.custody_requested,
                    now,
                );
                match admitted {
                    Ok(id) => push_event(
                        state,
                        "bundle_admitted",
                        now,
                        format!(
                            "frame id {} -> local {} ({} bytes from {peer_endpoint_id:02x?})",
                            String::from_utf8_lossy(&bundle.bundle_id),
                            hex_id(&id),
                            bundle.payload.len()
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
                        state.bundle.mark_status(&id, status);
                    }
                }
            }
            Frame::RouteRequest(request) => {
                let mut request_id = [0u8; 16];
                request_id[..8].copy_from_slice(&request.request_id.to_be_bytes());
                let candidates: Vec<Vec<u8>> = if request.destination_hint.is_empty() {
                    Vec::new()
                } else {
                    vec![request.destination_hint.clone()]
                };
                let flags = route_request_flags(request);
                if let Ok(umc_routing::request::Admission::Admit {
                    remaining_lifetime_ms,
                    ..
                }) = state.routing.admit_route_request(
                    &request_id,
                    &peer_endpoint_id,
                    flags,
                    request.hop_limit,
                    request.expiration_delta,
                    &candidates,
                    now,
                ) {
                    let response = RouteResponseFrame {
                        request_id: request.request_id,
                        response_sequence: 0,
                        direct: true,
                        relay_required: false,
                        store_forward_available: request.allow_store_forward,
                        local_path: true,
                        gateway_path: false,
                        route_lifetime: remaining_lifetime_ms,
                        next_hop_hint: peer_endpoint_id.to_vec(),
                        route_metadata: Vec::new(),
                        authentication: Vec::new(),
                    };
                    if let Ok(encoded) = response.encode() {
                        outbound.extend_from_slice(&encoded);
                    }
                }
            }
            Frame::RouteResponse(response) => {
                let mut request_id = [0u8; 16];
                request_id[..8].copy_from_slice(&response.request_id.to_be_bytes());
                let key = umc_routing::types::RouteKey {
                    destination_profile: 0,
                    destination_hash: hash_destination(&response.next_hop_hint),
                    scope: umc_routing::types::RouteScope::General,
                    policy_class: 0,
                };
                let record = state.routing.record_route_response(
                    key,
                    request_id,
                    format!("session {session_id}"),
                    response.route_lifetime,
                    now,
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
            _ => {}
        }
    }
    if outbound.is_empty() {
        None
    } else {
        Some(outbound)
    }
}

/// Wrapper for a pending-bundle delivery sweep: wrap the stored ciphertext
/// of the next undelivered bundle in a `BUNDLE` frame (bundles.md §10.1).
/// One frame per sweep: bundle payloads can approach the packet-size cap.
fn flush_pending_bundles(state: &mut RuntimeState, now: Instant) -> Vec<u8> {
    let mut outbound = Vec::new();
    let pending = state.bundle.pending_delivery(now);
    for id in pending.into_iter().take(BUNDLES_PER_FLUSH) {
        let Some(record) = state.bundle.record(&id) else {
            continue;
        };
        let Some(payload) = state.bundle.payload(&id) else {
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
        };
        let Ok(encoded) = frame.encode() else {
            continue;
        };
        // One bundle per protected packet: a frame that cannot fit with
        // headers and AEAD tags is left for a later sweep.
        if encoded.len() + BUNDLE_PACKET_HEADROOM > umc_types::version::MAX_PACKET_SIZE {
            continue;
        }
        state.bundle.mark_forwarded(&id);
        push_event(
            state,
            "bundle_forwarded",
            now,
            format!("bundle {} over session", hex_id(&id)),
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

/// Session writer: drain the applications' outbound channels and send the
/// echoed frames back on the same streams. Runs independently of the link
/// recv so echoes reach the peer without further inbound traffic.
async fn writer_loop(
    link: &Arc<BoxLink>,
    session: &Arc<tokio::sync::Mutex<Session>>,
    clock: &Arc<dyn Clock>,
    shutdown_flag: &Arc<AtomicBool>,
    ended: &Arc<AtomicBool>,
    app_echo_rx: &Arc<Mutex<HashMap<Vec<u8>, AppRx>>>,
    session_id: u64,
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
        let now = clock.now();
        let payload = {
            let mut session = session.lock().await;
            match session.send_stream_data(stream_id, &data, false) {
                Ok(payload) => payload,
                Err(e) => {
                    #[cfg(debug_assertions)]
                    println!("[session {session_id}] echo send error: {e:?}");
                    continue;
                }
            }
        };
        let outbound = {
            let mut session = session.lock().await;
            match session.build_outbound(clock.as_ref(), now, &payload) {
                Ok(Some(outbound)) => {
                    // App-originated echo traffic: resets the idle timer
                    // (session.md §22).
                    session.touch(now);
                    outbound
                }
                _ => continue,
            }
        };
        #[cfg(debug_assertions)]
        println!(
            "[session {session_id}] echo stream {stream_id} ({} bytes)",
            data.len()
        );
        let sent = tokio::task::block_in_place(|| {
            link.send(OutboundPacket {
                bytes: outbound,
                control: false,
                deadline_ms: None,
            })
        });
        if let Err(e) = sent {
            #[cfg(debug_assertions)]
            println!("[session {session_id}] echo send error: {e:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use crate::session_manager::SessionEntry;
    use std::sync::atomic::{AtomicU64, Ordering};
    use umc_session::sent_packet::SentPacket;
    use umc_session::session::{
        Role, Session, SessionConfig, SessionState, CLOSE_REASON_IDLE_TIMEOUT, IDLE_TIMEOUT_MS,
        MIN_DRAIN_MS,
    };
    use umc_session::spaces::PacketSpace;
    use umc_wire::frame::Frame as WireFrame;
    use umc_wire::frames::path::KeyUpdateFrame;
    use umc_wire::frames::relay::RelayOpenFrame;
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
            },
        );
        (state, tx)
    }

    fn test_session() -> Session {
        Session::new(
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
        .expect("session")
    }

    /// Peer session with swapped traffic secrets so the two can exchange
    /// protected packets (the client builds with `[1u8; 32]`, the peer
    /// parses with the same key).
    fn peer_session() -> Session {
        Session::new(
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
        .expect("peer session")
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
            &[WireFrame::RouteRequest(request)],
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
        let (space, _dcid, _path, _pn, payload) =
            umc_session::packet::parse_protected_packet(&keys, retransmitted).unwrap();
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
    async fn pto_deadline_arms_only_with_in_flight_packets() {
        let mut session = test_session();
        assert!(
            pto_deadline_at(&session, 1).is_none(),
            "no deadline with nothing in flight"
        );
        let ping = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap();
        session
            .build_outbound(&crate::runtime_adapters::OsClock, Instant(0), &ping)
            .unwrap()
            .unwrap();
        assert!(
            pto_deadline_at(&session, 1).is_some(),
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
        let armed = pto_deadline_at(&session, 1).expect("deadline armed");
        // Inbound processing that sends nothing must not extend the armed
        // deadline: the stale deadline fires on schedule instead of being
        // pushed back, so the PTO probe cannot be starved by traffic.
        assert_eq!(pto_deadline_after(&session, 1, Some(armed)), Some(armed));
        // No deadline armed with in-flight: the deadline is armed.
        let mut fresh = test_session();
        fresh
            .build_outbound(&crate::runtime_adapters::OsClock, Instant(0), &ping)
            .unwrap()
            .unwrap();
        assert!(pto_deadline_after(&fresh, 1, None).is_some());
        // Acking every in-flight packet clears the deadline.
        let ack = umc_wire::frame::AckFrame {
            largest_acknowledged: 0,
            ack_delay: 0,
            first_ack_range: 1,
            additional_ranges: Vec::new(),
        };
        fresh.apply_peer_ack(&ack, Instant(1)).unwrap();
        assert_eq!(
            pto_deadline_after(&fresh, 1, Some(armed)),
            None,
            "no in-flight packets means no deadline"
        );
        // Nothing in flight, nothing armed: stays disarmed.
        let idle = test_session();
        assert!(pto_deadline_after(&idle, 1, None).is_none());
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
        let (built, keepalive, done) = handle_idle_timers(&mut session, &clock, now);
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
        let (space, _dcid, _path, _pn, payload) =
            umc_session::packet::parse_protected_packet(&keys, &sent[0]).unwrap();
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
            handle_idle_timers(&mut session, &clock, Instant(now.0 + 3 * 1_000));
        assert!(built.is_none());
        assert!(done);
        assert_eq!(session.state, SessionState::Closed);
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
        let (built, _keepalive, done) = handle_idle_timers(&mut session, &clock, t0 + ms(30_000));
        assert!(built.is_none(), "no second idle close while draining");
        assert!(!done);
        assert!(
            session.draining_expired(d),
            "draining deadline must not be re-extended by an idle sweep"
        );
        // Finalization still happens at the original deadline.
        let (built, _keepalive, done) = handle_idle_timers(&mut session, &clock, d);
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
            handle_idle_timers(&mut session, &clock, t0 + ms(IDLE_TIMEOUT_MS / 2));
        assert!(!done);
        assert!(close.is_none(), "no close while idle not expired");
        let bytes = keepalive.expect("keepalive built at half idle");
        let keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&[1u8; 32]).unwrap();
        let (space, _dcid, _path, _pn, payload) =
            umc_session::packet::parse_protected_packet(&keys, &bytes).unwrap();
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
            handle_idle_timers(&mut session, &clock, t0 + ms(IDLE_TIMEOUT_MS / 2));
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
            handle_idle_timers(&mut session, &clock, t0 + ms(IDLE_TIMEOUT_MS));
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

        // The reader loop's bus-outbound arm receives one relay payload; the
        // packet and inbound channels stay open (empty) so the select cannot
        // break before the send, and the outbound sender is dropped after
        // the item so the loop exits after processing it.
        let (_packet_tx, packet_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
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
            &link,
            &session,
            &clock,
            &shutdown_flag,
            &ended,
            &app_channels,
            &runtime,
            &remote_keys,
            1,
            packet_rx,
            bus_inbound_rx,
            bus_outbound_rx,
        )
        .await;

        // The relay bytes reached the link...
        {
            let sent = recorded.lock().expect("link sent");
            assert_eq!(sent.len(), 1, "bus-outbound bytes sent once");
            assert_eq!(sent[0], b"relay-bytes");
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
}
