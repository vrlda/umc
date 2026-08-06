mod carriers;
mod config;
mod doctor;
mod handshake_responder;
mod handshake_timeout;
mod initial;
mod runtime_adapters;
mod server;
mod session_manager;
mod session_task;
mod state;

use clap::Parser;
use config::NodeConfig;
use state::RuntimeState;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use umc_carrier::types::OutboundPacket;
use umc_carrier::{BoxLink, Listener};
use umc_crypto::signatures::StaticHandshakePublicKey;

#[derive(Parser)]
#[command(name = "umcd", about = "Universal Mesh Core daemon")]
struct Args {
    /// Path to the node configuration file.
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    /// Run an initialization pass and exit (core.md §19).
    #[arg(long)]
    init: bool,
    /// Override the control socket path (layering: CLI beats config file).
    #[arg(long)]
    socket: Option<String>,
    /// Run diagnostics and exit.
    #[arg(long)]
    doctor: bool,
}

fn main() {
    let args = Args::parse();
    let mut config = NodeConfig::load(args.config.as_ref()).expect("valid config");
    if let Some(socket) = args.socket {
        config.control_socket = socket.into();
    }
    if args.init {
        init_node(&config, args.config.as_ref());
        return;
    }
    if args.doctor {
        let report = doctor::run_doctor(&config);
        for check in report.checks {
            println!(
                "{}: {} ({})",
                if check.passed { "[ok]" } else { "[FAIL]" },
                check.name,
                check.detail
            );
        }
        return;
    }
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(run(config));
}

/// Main startup sequence (core.md §18): state -> carriers -> control socket
/// -> shutdown.
async fn run(config: NodeConfig) {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    let mut state = state::RuntimeState::new(config, shutdown_tx).expect("runtime state");
    println!(
        "data directory: {}",
        state.config.resolved_data_dir().display()
    );
    println!("started at: {}ms", state.started_at.0);
    println!("node endpoint: {:02x?}", state.node_identity.endpoint_id());
    println!(
        "mesh mode: {}",
        if state.mesh.enable_lan_discovery {
            "local"
        } else {
            "endpoint"
        }
    );

    carriers::wire_carriers(&mut state);
    let mut listeners: std::collections::VecDeque<Box<dyn Listener + Send + Sync>> =
        state.listeners.drain(..).collect();
    println!("carrier listeners: {} bound", listeners.len());
    let state = Arc::new(state);

    // One accept loop per bound listener, paired with its carrier type
    // (carriers.rs pushes listeners in config order).
    let carrier_types = state.config.carriers.clone();
    for carrier_type in carrier_types {
        if matches!(carrier_type.as_str(), "ump.tcp/1" | "ump.udp/1") {
            if let Some(listener) = listeners.pop_front() {
                let accept_state = state.clone();
                tokio::spawn(async move {
                    accept_loop(accept_state, carrier_type, listener).await;
                });
            }
        }
    }

    let server_state = state.clone();
    let server_task = tokio::spawn(server::run(server_state));

    // Graceful shutdown: SIGINT sets the flag and releases the channel.
    let shutdown_flag = state.shutdown_requested.clone();
    let shutdown_tx = state.shutdown_channel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        println!("shutdown: signal received");
        shutdown_flag.store(true, Ordering::Relaxed);
        let _ = shutdown_tx.send(()).await;
    });

    let _ = shutdown_rx.recv().await;
    println!("shutdown: complete");
    // Wait for the control socket to finish closing before exiting.
    let _ = server_task.await;
}

/// Per-listener accept loop (core.md §8): accept a link, hand it to the
/// inbound handler, and keep accepting. The handshake tracker is shared
/// across links so per-connection-id retry storms are capped.
async fn accept_loop(
    state: Arc<RuntimeState>,
    carrier_type: String,
    listener: Box<dyn Listener + Send + Sync>,
) {
    let tracker = Arc::new(std::sync::Mutex::new(
        handshake_timeout::HandshakeTracker::new(),
    ));
    loop {
        if state.shutdown_requested.load(Ordering::Relaxed) {
            break;
        }
        let Ok(link) = tokio::task::block_in_place(|| listener.accept()) else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let link_state = state.clone();
        let link_carrier = carrier_type.clone();
        let link_tracker = tracker.clone();
        if carrier_type == "ump.udp/1" {
            // The UDP association's first datagram is consumed by accept to
            // learn the remote; the hello must be read before the next
            // accept(), otherwise a second accept() steals it from the
            // link's recv() (both pull from the same socket).
            if let Err(e) = handle_inbound_link(link_state, &link_carrier, link, &link_tracker) {
                println!("[session] link rejected: {e}");
            }
        } else {
            tokio::spawn(async move {
                if let Err(e) = handle_inbound_link(link_state, &link_carrier, link, &link_tracker)
                {
                    println!("[session] link rejected: {e}");
                }
            });
        }
    }
}

/// Handle one inbound link: extract the `CLIENT_HELLO` from the first
/// packet, answer with `SERVER_HELLO`, build the server session, and start
/// the wire loop.
// The Arc is handed (cloned) to the spawned session task below.
#[allow(clippy::needless_pass_by_value)]
fn handle_inbound_link(
    state: Arc<RuntimeState>,
    carrier_type: &str,
    link: BoxLink,
    tracker: &std::sync::Mutex<handshake_timeout::HandshakeTracker>,
) -> Result<(), String> {
    // The first framed packet is the CLIENT_HELLO: either an Initial
    // long-header packet (wire-format §24-25) or, on the raw path used by
    // `Node::connect`, the hello body itself.
    let first = tokio::task::block_in_place(|| link.recv())
        .map_err(|e| format!("recv first packet: {e:?}"))?
        .bytes;
    let parsed_initial = initial::try_parse_initial(&first);
    let hello_bytes = match &parsed_initial {
        Some((_dcid, _pn, payload, _scid)) => payload.clone(),
        None => first.clone(),
    };
    let hello_bytes = initial::decode_client_hello(&hello_bytes)?;
    let hello = umc_handshake::xx::ClientHello::decode(&hello_bytes)
        .map_err(|e| format!("client hello: {e:?}"))?;

    // The session's DCID: the Initial header's when present and 8 bytes
    // long (umc-session requires exactly 8), otherwise derived from the
    // hello's ephemeral.
    let dcid = match &parsed_initial {
        Some((header_dcid, _, _, _)) if header_dcid.len() == 8 => header_dcid.clone(),
        _ => session_dcid(&hello),
    };
    let peer_endpoint_id = provisional_peer_id(&hello);

    let now = state.node.clock.as_ref().now();
    tracker
        .lock()
        .expect("handshake tracker")
        .check(&dcid, now)
        .map_err(|e| format!("handshake rejected: {e}"))?;

    // The client's static handshake key arrives in CLIENT_AUTH (handshake.md
    // §18); until Task 20+ parses it, session secrets are provisional (the
    // SERVER_HELLO itself binds only DH_ee and the transcript).
    let client_static = StaticHandshakePublicKey([0u8; 32]);
    let (server_hello_bytes, secrets) = handshake_responder::respond_hello(
        &state,
        carrier_type.as_bytes(),
        &hello_bytes,
        &client_static,
    )?;
    let send_result = tokio::task::block_in_place(|| {
        link.send(OutboundPacket {
            bytes: server_hello_bytes,
            control: true,
            deadline_ms: Some(3_000),
        })
    });
    if let Err(e) = send_result {
        return Err(format!("send server hello: {e:?}"));
    }
    tracker
        .lock()
        .expect("handshake tracker")
        .record(&dcid, now);

    let session = umc_session::session::Session::new(
        umc_session::session::SessionConfig {
            role: umc_session::session::Role::Server,
            dcid,
            local_traffic_secret: secrets.server,
            remote_traffic_secret: secrets.client,
            initial_max_data: umc_session::session::DEFAULT_INITIAL_MAX_DATA,
            initial_max_stream_data: umc_session::session::DEFAULT_INITIAL_MAX_STREAM_DATA,
            max_ack_delay_ms: 25,
        },
        state.node.clock.as_ref(),
    )
    .map_err(|e| format!("session: {e:?}"))?;
    let session_id = state.sessions.next_id();
    let task = session_task::spawn_session_task(state.clone(), link, session, session_id);
    state.sessions.register(
        session_id,
        session_manager::SessionEntry {
            peer_endpoint_id,
            carrier_type: carrier_type.to_string(),
            task,
        },
    );
    println!("[session] active with peer {peer_endpoint_id:02x?}");
    Ok(())
}

/// Stable 8-byte session DCID for the raw-hello path: the hello carries no
/// connection id, so derive one from the client's ephemeral public key.
fn session_dcid(hello: &umc_handshake::xx::ClientHello) -> Vec<u8> {
    let mut ikm = Vec::with_capacity(32);
    ikm.extend_from_slice(b"UMP-SESSION-DCID-v1");
    ikm.extend_from_slice(&hello.client_ephemeral_public_key);
    umc_crypto::hkdf::extract(&[0u8; 32], &ikm)[..8].to_vec()
}

/// Provisional peer endpoint id until the client's identity binding arrives
/// in `CLIENT_AUTH` (handshake.md §18).
fn provisional_peer_id(hello: &umc_handshake::xx::ClientHello) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32);
    ikm.extend_from_slice(b"UMP-PEER-PROVISIONAL-v1");
    ikm.extend_from_slice(&hello.client_ephemeral_public_key);
    umc_crypto::hkdf::extract(&[0u8; 32], &ikm)
}

fn init_node(config: &NodeConfig, config_path: Option<&PathBuf>) {
    let data_dir = config.resolved_data_dir();
    std::fs::create_dir_all(data_dir.join("objects")).expect("create data dir");
    let keystore_dir = config.resolved_keystore_dir();
    std::fs::create_dir_all(&keystore_dir).expect("create keystore dir");
    let config_file = config_path
        .cloned()
        .unwrap_or_else(|| data_dir.join("node.json"));
    let json = serde_json::to_string_pretty(config).expect("serialize config");
    std::fs::write(&config_file, json).expect("write config");
    println!("node data directory: {}", data_dir.display());
    println!("keystore directory: {}", keystore_dir.display());
    println!("config file: {}", config_file.display());
    println!("public relay: disabled (default)");
    println!("telemetry: disabled (default)");
}
