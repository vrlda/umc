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
use umc_session::session::Session;
use umc_types::runtime::Clock;

/// Poll interval when the link reports `WouldBlock`.
pub const RECV_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Poll interval of the echo drain when no echo is pending.
pub const ECHO_POLL_INTERVAL: Duration = Duration::from_millis(5);
/// Pause after processing a packet before the next blocking recv. The TCP
/// carrier serializes reads and writes behind one mutex, so a recv in
/// flight starves the carrier's background writer; the pause gives queued
/// ACKs and echoes a window to flush (carriers/tcp.md).
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(5);

/// Spawn the per-session wire loop. The tasks exit when `link.recv` errors
/// or the daemon's shutdown flag is set.
///
/// `app_channels` maps a protocol ID to the inbound channel of the
/// application registered under it; stream data received on a matching
/// protocol ID is forwarded there. `app_echo_rx` holds the applications'
/// outbound receivers; the session writer drains them and sends the frames
/// back on the same stream IDs.
///
/// The runtime state lives behind one mutex in the daemon; the session loop
/// only needs the clock, the shutdown flag, and the application channels,
/// so it takes clones and never touches the shared context.
#[allow(clippy::needless_pass_by_value)] // shared runtime handles cloned for the spawned tasks
pub fn spawn_session_task(
    clock: Arc<dyn Clock>,
    shutdown_flag: Arc<AtomicBool>,
    link: BoxLink,
    session: Session,
    session_id: u64,
    app_channels: Arc<Mutex<HashMap<Vec<u8>, AppTx>>>,
    app_echo_rx: Arc<Mutex<HashMap<Vec<u8>, AppRx>>>,
) -> JoinHandle<()> {
    let link = Arc::new(link);
    let session = Arc::new(tokio::sync::Mutex::new(session));
    let ended = Arc::new(AtomicBool::new(false));

    let reader_link = link.clone();
    let reader_session = session.clone();
    let reader_shutdown = shutdown_flag.clone();
    let reader_clock = clock.clone();
    let reader_ended = ended.clone();
    tokio::spawn(async move {
        reader_loop(
            &reader_link,
            &reader_session,
            &reader_clock,
            &reader_shutdown,
            &reader_ended,
            &app_channels,
            session_id,
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

/// Reader loop: pull packets off the link, feed the session state machine,
/// send the ACKs it produces, and forward stream data to applications.
async fn reader_loop(
    link: &Arc<BoxLink>,
    session: &Arc<tokio::sync::Mutex<Session>>,
    clock: &Arc<dyn Clock>,
    shutdown_flag: &Arc<AtomicBool>,
    ended: &Arc<AtomicBool>,
    app_channels: &Arc<Mutex<HashMap<Vec<u8>, AppTx>>>,
    session_id: u64,
) {
    loop {
        if shutdown_flag.load(Ordering::Relaxed) {
            break;
        }
        // The carrier API is blocking (Handle::block_on internally);
        // move off the async machinery for the call.
        let inbound = tokio::task::block_in_place(|| link.recv());
        let packet = match inbound {
            Ok(packet) => packet,
            Err(e) if e.kind == CarrierErrorKind::WouldBlock => {
                tokio::time::sleep(RECV_POLL_INTERVAL).await;
                continue;
            }
            Err(_) => break,
        };
        #[cfg(debug_assertions)]
        println!("[session {session_id}] recv {} bytes", packet.bytes.len());
        let now = clock.now();
        let mut outbound = None;
        let mut pending: Vec<(Vec<u8>, u64, Vec<u8>)> = Vec::new();
        {
            let mut session = session.lock().await;
            let ack_payload = match session.on_inbound(now, &packet.bytes) {
                Ok(payload) => payload,
                Err(e) => {
                    #[cfg(debug_assertions)]
                    println!("[session {session_id}] inbound error: {e:?}");
                    continue;
                }
            };
            if !ack_payload.is_empty() {
                let built = session.build_outbound(clock.as_ref(), now, &ack_payload);
                outbound = match built {
                    Ok(outbound) => outbound,
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
        // Give the carrier's background writer a window to flush before the
        // next recv takes the stream lock (carriers/tcp.md).
        tokio::time::sleep(FLUSH_INTERVAL).await;
    }
    ended.store(true, Ordering::Relaxed);
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
                Ok(Some(outbound)) => outbound,
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
