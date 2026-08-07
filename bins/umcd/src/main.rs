mod app_layer;
mod bundle_service;
mod carriers;
mod config;
mod discovery_service;
mod doctor;
mod event_log;
mod handshake_responder;
mod handshake_timeout;
mod initial;
mod relay_service;
mod routing_service;
mod runtime_adapters;
mod server;
mod session_bus;
mod session_manager;
mod session_task;
mod state;

use clap::Parser;
use config::NodeConfig;
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
    // The echo application's channels and task are installed at startup
    // (core.md §9.6); registration happened inside the runtime state.
    app_layer::install_echo_app(&mut state);
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
    // The runtime state is the daemon's shared mutable context (core.md §8):
    // the accept loops and the control socket both mutate it, so it rides
    // behind one mutex.
    let state = Arc::new(std::sync::Mutex::new(state));

    // One accept loop per bound listener, paired with its carrier type
    // (carriers.rs pushes listeners in config order).
    let carrier_types = state.lock().expect("state").config.carriers.clone();
    for carrier_type in carrier_types {
        if matches!(carrier_type.as_str(), "ump.tcp/1" | "ump.udp/1") {
            if let Some(listener) = listeners.pop_front() {
                let accept_state = state.clone();
                tokio::spawn(async move {
                    accept_loop(&accept_state, carrier_type, listener).await;
                });
            }
        }
    }

    let server_state = state.clone();
    let server_task = tokio::spawn(server::run(server_state));

    // Graceful shutdown: SIGINT sets the flag and releases the channel.
    let (shutdown_flag, shutdown_tx) = {
        let state = state.lock().expect("state");
        (
            state.shutdown_requested.clone(),
            state.shutdown_channel.clone(),
        )
    };
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
    state: &Arc<std::sync::Mutex<state::RuntimeState>>,
    carrier_type: String,
    listener: Box<dyn Listener + Send + Sync>,
) {
    let tracker = Arc::new(std::sync::Mutex::new(
        handshake_timeout::HandshakeTracker::new(),
    ));
    loop {
        if state
            .lock()
            .expect("state")
            .shutdown_requested
            .load(Ordering::Relaxed)
        {
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
            if let Err(e) = handle_inbound_link(&link_state, &link_carrier, link, &link_tracker) {
                println!("[session] link rejected: {e}");
                record_handshake_failure(&link_state, e);
            }
        } else {
            tokio::spawn(async move {
                if let Err(e) = handle_inbound_link(&link_state, &link_carrier, link, &link_tracker)
                {
                    println!("[session] link rejected: {e}");
                    record_handshake_failure(&link_state, e);
                }
            });
        }
    }
}

/// Record a failed inbound handshake in the daemon event log (core.md §8).
fn record_handshake_failure(state: &Arc<std::sync::Mutex<state::RuntimeState>>, detail: String) {
    let Ok(state) = state.lock() else {
        return;
    };
    let now = state.node.clock.as_ref().now();
    state
        .events
        .lock()
        .expect("event log")
        .push(event_log::DaemonEvent {
            kind: "handshake_failed".into(),
            at_ms: now.0,
            detail,
        });
}

/// Handle one inbound link: extract the `CLIENT_HELLO` from the first
/// packet, answer with `SERVER_HELLO`, build the server session, and start
/// the wire loop. The caller holds the state mutex for the connection
/// setup; per-packet work runs on the session task.
fn handle_inbound_link(
    state: &Arc<std::sync::Mutex<state::RuntimeState>>,
    carrier_type: &str,
    link: BoxLink,
    tracker: &std::sync::Mutex<handshake_timeout::HandshakeTracker>,
) -> Result<(), String> {
    handle_inbound_link_locked(state, carrier_type, link, tracker)
}

#[allow(clippy::too_many_lines)] // one connection setup path: hello, session, registry
fn handle_inbound_link_locked(
    state: &Arc<std::sync::Mutex<state::RuntimeState>>,
    carrier_type: &str,
    link: BoxLink,
    tracker: &std::sync::Mutex<handshake_timeout::HandshakeTracker>,
) -> Result<(), String> {
    let runtime = state.clone();
    let state = state.lock().expect("state");
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
    // §18); the accept loop's CLIENT_AUTH read lands with the wire wiring,
    // so the client's ephemeral stands in for it to keep the DH chain
    // (es/se/ss) symmetric on both sides (the SERVER_HELLO itself binds only
    // DH_ee and the transcript).
    let client_static = StaticHandshakePublicKey(hello.client_ephemeral_public_key);
    let (server_hello_bytes, pending) = handshake_responder::respond_hello(
        &state,
        carrier_type.as_bytes(),
        &hello_bytes,
        &client_static,
    )?;
    let secrets = pending.session_secrets();
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

    let mut session = umc_session::session::Session::new(
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
    // Register the default data path so the anti-amplification budget is
    // active on the session's primary path (session.md §26).
    session
        .add_path(
            umc_session::packet::DEFAULT_PATH_ID,
            carrier_type.to_string(),
            Vec::new(),
            Vec::new(),
            now,
        )
        .map_err(|e| format!("add path 0: {e:?}"))?;
    let session_id = state.sessions.next_id();
    let remote_keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&secrets.client)
        .map_err(|e| format!("remote keys: {e:?}"))?;
    // The session's bus channels: created here so the registration can
    // happen under the state lock the caller already holds (the task itself
    // must not re-lock it); the rx sides move into the wire loop.
    let (bus_inbound_tx, bus_inbound_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (bus_outbound_tx, bus_outbound_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let task = session_task::spawn_session_task(
        state.node.clock.clone(),
        state.shutdown_requested.clone(),
        link,
        session,
        session_id,
        state.app_channels.clone(),
        state.app_echo_rx.clone(),
        runtime,
        remote_keys,
        bus_inbound_rx,
        bus_outbound_rx,
    );
    state.bus.lock().expect("session bus").register(
        peer_endpoint_id.to_vec(),
        session_id,
        bus_inbound_tx,
        bus_outbound_tx,
    );
    // The session task's JoinHandle moves into a watcher that records
    // `session_closed` when the wire loop exits; the registry keeps an
    // AbortHandle so shutdown can still cancel the task.
    let abort_handle = task.abort_handle();
    let session_events = state.events.clone();
    let closed_at_ms = now.0;
    tokio::spawn(async move {
        let _ = task.await;
        session_events
            .lock()
            .expect("event log")
            .push(event_log::DaemonEvent {
                kind: "session_closed".into(),
                at_ms: closed_at_ms,
                detail: format!("session {session_id} closed"),
            });
    });
    state.sessions.register(
        session_id,
        session_manager::SessionEntry {
            peer_endpoint_id,
            carrier_type: carrier_type.to_string(),
            task: abort_handle,
            established_at_ms: now.0,
        },
    );
    state
        .events
        .lock()
        .expect("event log")
        .push(event_log::DaemonEvent {
            kind: "session_active".into(),
            at_ms: now.0,
            detail: format!("session {session_id} peer {peer_endpoint_id:02x?} via {carrier_type}"),
        });
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
    // Seed the keystore with the node identity (core.md §19): generated on
    // first init, reused on subsequent passes so the endpoint id stays
    // stable. `UMC_KEYSTORE_PASSWORD` guards the keystore when set.
    let identity = state::load_or_create_identity(config).expect("node identity");
    let config_file = config_path
        .cloned()
        .unwrap_or_else(|| data_dir.join("node.json"));
    let json = serde_json::to_string_pretty(config).expect("serialize config");
    std::fs::write(&config_file, json).expect("write config");
    println!("node data directory: {}", data_dir.display());
    println!("keystore directory: {}", keystore_dir.display());
    println!("config file: {}", config_file.display());
    println!("node endpoint: {:02x?}", identity.endpoint_id());
    println!("public relay: disabled (default)");
    println!("telemetry: disabled (default)");
}
