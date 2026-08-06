//! Wire session loop (core.md §8): read inbound packets off the link, feed
//! the session state machine, and send the ACK payloads it produces.
//!
//! App-layer framing (streams to the control API) lands in Task 20+.
use crate::state::RuntimeState;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use umc_carrier::error::CarrierErrorKind;
use umc_carrier::types::OutboundPacket;
use umc_carrier::BoxLink;
use umc_session::session::Session;

/// Poll interval when the link reports `WouldBlock`.
pub const RECV_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Spawn the per-session wire loop. The task exits when `link.recv` errors
/// or the daemon's shutdown flag is set.
pub fn spawn_session_task(
    state: Arc<RuntimeState>,
    link: BoxLink,
    mut session: Session,
    session_id: u64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let clock = state.node.clock.clone();
        loop {
            if state.shutdown_requested.load(Ordering::Relaxed) {
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
            let ack_payload = match session.on_inbound(now, &packet.bytes) {
                Ok(payload) => payload,
                Err(e) => {
                    #[cfg(debug_assertions)]
                    println!("[session {session_id}] inbound error: {e:?}");
                    continue;
                }
            };
            if ack_payload.is_empty() {
                continue;
            }
            let Ok(Some(outbound)) = session.build_outbound(clock.as_ref(), now, &ack_payload)
            else {
                continue;
            };
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
    })
}
