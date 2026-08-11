//! Application layer wiring (core.md §9.6): the daemon's reference
//! application (echo) and its channels. Registration happens in
//! `RuntimeState::new`; this module installs the echo application's channel
//! pair and spawns its task at startup.
use crate::state::RuntimeState;
use umc_core::app_io::spawn_app_channel;
use umc_core::echo::echo_loop;
use umc_core::well_known::WELL_KNOWN_APP;

/// Service name the echo application registers under.
pub const ECHO_APP_NAME: &str = "echo";
/// Bounded capacity of each per-application channel.
pub const APP_CHANNEL_BUFFER: usize = 64;

/// Install the echo application's channels and spawn its task.
///
/// The session tasks forward inbound streams with a matching protocol ID
/// into the inbound channel (`app_channels`); the echo loop reflects every
/// frame into the outbound channel (`app_echo_rx`), which the session
/// writers drain back onto the same stream.
pub fn install_echo_app(state: &mut RuntimeState) {
    let (in_tx, mut in_rx) = spawn_app_channel(APP_CHANNEL_BUFFER);
    let (out_tx, out_rx) = spawn_app_channel(APP_CHANNEL_BUFFER);
    state
        .app_channels
        .lock()
        .expect("app channels")
        .insert(WELL_KNOWN_APP.to_vec(), in_tx);
    state
        .app_echo_rx
        .lock()
        .expect("app echo receivers")
        .insert(WELL_KNOWN_APP.to_vec(), out_rx);
    tokio::spawn(async move {
        echo_loop(&mut in_rx, &out_tx).await;
    });
}
