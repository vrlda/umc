mod app_layer;
mod backup;
mod bundle_service;
mod carriers;
mod config;
mod discovery_service;
mod doctor;
mod event_log;
mod handshake_responder;
mod handshake_timeout;
mod initial;
mod logging;
mod relay_auth;
mod relay_service;
mod routing_service;
mod runtime_adapters;
mod server;
mod session_bus;
mod session_manager;
mod session_task;
mod state;
mod static_peers;
mod telemetry;

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
    /// Back up the node data dir (database, keystore, objects) to a directory and exit.
    #[arg(long)]
    backup: Option<PathBuf>,
    /// Restore the node data dir from a backup directory and exit.
    #[arg(long)]
    restore: Option<PathBuf>,
}

fn main() {
    logging::init_logging();
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
            log::info!(
                "{}: {} ({})",
                if check.passed { "[ok]" } else { "[FAIL]" },
                check.name,
                check.detail
            );
        }
        return;
    }
    if args.backup.is_some() && args.restore.is_some() {
        log::error!("--backup and --restore are mutually exclusive");
        std::process::exit(2);
    }
    if let Some(out_dir) = args.backup {
        backup::backup(&config, &out_dir).expect("backup failed");
        log::info!("backup written to {}", out_dir.display());
        return;
    }
    if let Some(in_dir) = args.restore {
        backup::restore(&config, &in_dir).expect("restore failed");
        log::info!("restore complete from {}", in_dir.display());
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
    log::info!(
        "data directory: {}",
        state.config.resolved_data_dir().display()
    );
    log::info!("started at: {}ms", state.started_at.0);
    log::info!(
        "node endpoint: {}",
        logging::redact(&state.node_identity.endpoint_id())
    );
    log::info!(
        "mesh mode: {}",
        if state.mesh.enable_lan_discovery {
            "local"
        } else {
            "endpoint"
        }
    );

    // Telemetry opt-in (core.md §61, privacy.md §38): off by default; with
    // `telemetry_enabled` the daemon appends a bounded JSONL metrics file
    // every 60 s.
    if state.config.telemetry_enabled {
        let metrics = state.metrics.clone();
        let path = state.config.resolved_data_dir().join("telemetry.jsonl");
        let clock = state.node.clock.clone();
        telemetry::spawn_telemetry_dump(metrics, path.clone(), clock);
        log::info!("[telemetry] enabled → {}", path.display());
    } else {
        log::info!("[telemetry] disabled (default)");
    }

    carriers::wire_carriers(&mut state);
    let mut listeners: std::collections::VecDeque<Box<dyn Listener + Send + Sync>> =
        state.listeners.drain(..).collect();
    log::info!("carrier listeners: {} bound", listeners.len());
    // The runtime state is the daemon's shared mutable context (core.md §8):
    // the accept loops and the control socket both mutate it, so it rides
    // behind one mutex.
    let state = Arc::new(std::sync::Mutex::new(state));
    state.lock().expect("state").self_arc = Arc::downgrade(&state);

    // One accept loop per bound listener, paired with its carrier type
    // (carriers.rs pushes listeners in config order).
    let carrier_types = state.lock().expect("state").config.carriers.clone();
    for carrier_type in carrier_types {
        if matches!(carrier_type.as_str(), "ump.tcp/1" | "ump.udp/1") {
            if state
                .lock()
                .expect("state")
                .config
                .carrier_disabled(&carrier_type)
            {
                log::warn!("[carrier] {carrier_type} disabled; accept loop not started");
                continue;
            }
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

    let static_peers = state.lock().expect("state").config.static_peers.clone();
    if !static_peers.is_empty() {
        static_peers::dial_all(&state, &static_peers).await;
    }

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
        log::info!("shutdown: signal received");
        shutdown_flag.store(true, Ordering::Relaxed);
        let _ = shutdown_tx.send(()).await;
    });

    // Retry static bootstrap contacts after a bounded interval. The first
    // interval tick is consumed so startup dialing above is not duplicated.
    let mut static_retry = tokio::time::interval(Duration::from_secs(30));
    static_retry.tick().await;
    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => break,
            _ = static_retry.tick() => {
                static_peers::dial_all(&state, &static_peers).await;
            }
        }
    }
    log::info!("shutdown: complete");
    // Wait for the control socket to finish closing before exiting.
    let _ = server_task.await;
}

/// Per-listener accept loop (core.md §8): accept a link, hand it to the
/// inbound handler, and keep accepting. The handshake tracker is shared
/// across links so per-connection-id retry storms are capped.
pub(crate) async fn accept_loop(
    state: &Arc<std::sync::Mutex<state::RuntimeState>>,
    carrier_type: String,
    listener: Box<dyn Listener + Send + Sync>,
) {
    let tracker = Arc::new(std::sync::Mutex::new(
        handshake_timeout::HandshakeTracker::new(),
    ));
    loop {
        let (shutdown, disabled) = {
            let state = state.lock().expect("state");
            (
                state.shutdown_requested.load(Ordering::Relaxed),
                state.config.carrier_disabled(&carrier_type),
            )
        };
        if shutdown {
            break;
        }
        if disabled {
            log::warn!("[carrier] {carrier_type} disabled; accept loop stopped");
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
                log::warn!("[session] link rejected: {e}");
                record_handshake_failure(&link_state, e);
            }
        } else {
            tokio::spawn(async move {
                if let Err(e) = handle_inbound_link(&link_state, &link_carrier, link, &link_tracker)
                {
                    log::warn!("[session] link rejected: {e}");
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
        .metrics
        .incr(state::metric_names::HANDSHAKE_FAILURES, 1);
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

#[allow(clippy::too_many_lines)] // one connection setup path: hello, auth, session, registry
fn handle_inbound_link_locked(
    state: &Arc<std::sync::Mutex<state::RuntimeState>>,
    carrier_type: &str,
    link: BoxLink,
    tracker: &std::sync::Mutex<handshake_timeout::HandshakeTracker>,
) -> Result<(), String> {
    // The state lock is held only for the responder + registration steps:
    // the wire waits (hello, then CLIENT_AUTH) happen WITHOUT it, so one
    // slow handshake cannot stall the other accept loops or the control
    // socket.
    // The first framed packet is the CLIENT_HELLO: an Initial long-header
    // packet (wire-format §13), or — on the transitional raw path kept for
    // the pre-D1 test harnesses — the hello body itself. The raw path is
    // removed once the harnesses migrate to protected Initials (plan
    // D2/D3); the response always mirrors the request's form.
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
    // The client's SCID (its own connection id), for the Version-
    // Negotiation echo: VN DCID ← client SCID, VN SCID ← client DCID (RFC
    // 9000 §17.2.1). Empty on the transitional raw path.
    let vn_scid = match &parsed_initial {
        Some((_dcid, _pn, _payload, return_to)) => return_to.clone(),
        None => Vec::new(),
    };

    let now = state.lock().expect("state").node.clock.as_ref().now();
    tracker
        .lock()
        .expect("handshake tracker")
        .check(&dcid, now)
        .map_err(|e| format!("handshake rejected: {e}"))?;

    // Emergency security controls apply before both the resumed IK path and
    // the full XX responder. A disabled protocol produces a raw VN packet
    // listing no enabled versions; disabled carriers/profiles close without
    // revealing handshake state.
    let (carrier_disabled, crypto_disabled, protocol_disabled) = {
        let state = state.lock().expect("state");
        (
            state.config.carrier_disabled(carrier_type),
            state
                .config
                .crypto_profile_disabled(umc_handshake::xx::CRYPTO_PROFILE),
            state
                .config
                .protocol_version_disabled(umc_handshake::xx::SUPPORTED_PROTOCOL_VERSION),
        )
    };
    if carrier_disabled {
        return Err(format!("disabled carrier: {carrier_type}"));
    }
    if crypto_disabled {
        return Err(format!(
            "disabled crypto profile: {}",
            String::from_utf8_lossy(umc_handshake::xx::CRYPTO_PROFILE)
        ));
    }
    if protocol_disabled {
        let bytes = umc_handshake::xx::build_version_negotiation(&vn_scid, &dcid, &[]);
        tokio::task::block_in_place(|| {
            link.send(OutboundPacket {
                bytes,
                control: true,
                deadline_ms: Some(3_000),
            })
        })
        .map_err(|e| format!("send disabled-version negotiation: {e:?}"))?;
        return Err("unsupported protocol version: disabled by policy".into());
    }

    // Session resumption (handshake.md §35, IK mode): a hello offering the
    // IK handshake mode carries a session ticket in `retry_token` (the
    // SANCTIONED v1 ticket carrier — the field is otherwise unused). A
    // ticket that validates under the daemon's key takes the short resume
    // path (handle_resumed_link); an invalid or expired ticket falls back
    // to the full XX path below — the client then sees a mode-XX
    // `SERVER_HELLO` and must fall back to a full connect.
    let resumed_ticket = if hello
        .supported_handshake_modes
        .iter()
        .any(|m| m.as_slice() == umc_handshake::ik::MODE_IK)
    {
        let state = state.lock().expect("state");
        umc_handshake::ticket::validate_ticket(&state.ticket_key, &hello.retry_token, now.0).ok()
    } else {
        None
    };
    if let Some(ticket) = resumed_ticket {
        // Single-use enforcement (handshake.md §35): the clear nonce is
        // the ticket id; a nonce seen before means the ticket was already
        // consumed — refuse the short path and fall back to the full XX
        // path below, so one stolen ticket grants at most one session.
        let state_guard = state.lock().expect("state");
        let fresh = state_guard
            .ticket_replay_cache
            .lock()
            .expect("ticket replay cache")
            .insert(ticket.nonce);
        drop(state_guard);
        if fresh {
            return handle_resumed_link(
                state,
                carrier_type,
                link,
                &hello,
                &hello_bytes,
                parsed_initial.as_ref(),
                &dcid,
                &vn_scid,
                now,
                tracker,
                &ticket,
            );
        }
    }

    // The client's static handshake key arrives in CLIENT_AUTH (handshake.md
    // §18); until the accept loop reads it (below), the client's ephemeral
    // stands in for it so the DH chain (es/se/ss) and the client-auth key
    // stay symmetric on both sides (the SERVER_HELLO itself binds only
    // DH_ee and the transcript). The CLIENT_AUTH payload carries the REAL
    // static + identity binding + signature, which complete() verifies.
    let responder_outcome = {
        let state = state.lock().expect("state");
        let client_static = StaticHandshakePublicKey(hello.client_ephemeral_public_key);
        handshake_responder::respond_hello(
            &state,
            carrier_type.as_bytes(),
            &hello_bytes,
            &client_static,
            &dcid,
            &vn_scid,
        )?
    };
    let (server_hello_bytes, pending) = match responder_outcome {
        handshake_responder::ResponderResponse::ServerHello { bytes, pending } => (bytes, pending),
        handshake_responder::ResponderResponse::VersionNegotiation { bytes } => {
            // Version negotiation (compatibility.md §5.2): the client's
            // offered protocol versions exclude the supported one. A VN
            // packet is never protected (no keys exist before version
            // agreement), so it travels raw even on the live path. Send
            // it, then close the connection: the client retries with a
            // fresh connection offering a supported version.
            let send_result = tokio::task::block_in_place(|| {
                link.send(OutboundPacket {
                    bytes,
                    control: true,
                    deadline_ms: Some(3_000),
                })
            });
            if let Err(e) = send_result {
                return Err(format!("send version negotiation: {e:?}"));
            }
            return Err("version negotiation: client offered no supported version".into());
        }
    };
    // SERVER_HELLO travels in the same form as the request: Initial-
    // protected when the client spoke Initial, raw on the transitional
    // path. For the protected response the keys derive from the client's
    // DCID, the response's DCID is the client's SCID (the QUIC echo rule),
    // and the daemon's own SCID is the derived session DCID.
    let response_bytes = match &parsed_initial {
        Some((origin, _pn, _payload, return_to)) => {
            let keys = umc_handshake::initial::derive_initial_keys(origin).server;
            initial::build_initial_packet(
                return_to,
                &session_dcid(&hello),
                0,
                &server_hello_bytes,
                &keys,
            )?
        }
        None => server_hello_bytes,
    };
    let send_result = tokio::task::block_in_place(|| {
        link.send(OutboundPacket {
            bytes: response_bytes,
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

    // The client's CLIENT_AUTH completes the two-step responder
    // (handshake.md §18): a second packet in the same form as the hello —
    // Initial-protected on the live path, raw on the transitional path.
    // The TCP carrier's recv yields WouldBlock while no frame is buffered
    // (carriers/tcp.md), and the client sends CLIENT_AUTH only after
    // processing the SERVER_HELLO, so poll briefly for it instead of
    // refusing the link. `complete` decrypts the auth with the client-auth
    // key, verifies the real client static key against the identity
    // binding, validates the binding and the transcript-bound signature; a
    // refusal drops the link and no session is registered.
    let auth_packet = {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            match tokio::task::block_in_place(|| link.recv()) {
                Ok(packet) => break packet.bytes,
                Err(e)
                    if e.kind == umc_carrier::error::CarrierErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(format!("recv client auth: {e:?}")),
            }
        }
    };
    let auth_bytes = decode_client_auth(&auth_packet)?;
    let (server_finished, secrets, peer) = {
        let state = state.lock().expect("state");
        pending
            .complete(&state, &auth_bytes, now.0)
            .map_err(|e| format!("client auth refused: {e}"))?
    };
    // The peer identity recovered from CLIENT_AUTH: the real endpoint id
    // from the client's identity binding (the provisional hello derivation
    // is gone; the session registers under the verified identity).
    let peer_endpoint_id = peer.binding.endpoint_id;
    state
        .lock()
        .expect("state")
        .validate_peer_binding(&peer.binding, now.0)?;

    // SERVER_FINISHED (handshake.md §19): the daemon's reply after a
    // verified CLIENT_AUTH — the server signature + finished MAC, as a raw
    // framed handshake message on the transitional wire path.
    let mut server_finished_frame = Vec::new();
    umc_handshake::encoding::encode_message(
        &mut server_finished_frame,
        umc_handshake::encoding::SERVER_FINISHED,
        &server_finished,
    )
    .map_err(|e| format!("server finished framing: {e:?}"))?;
    if let Err(e) = tokio::task::block_in_place(|| {
        link.send(OutboundPacket {
            bytes: server_finished_frame,
            control: true,
            deadline_ms: Some(3_000),
        })
    }) {
        return Err(format!("send server finished: {e:?}"));
    }

    // CLIENT_FINISHED (handshake.md §20): the client's confirmation MAC
    // over the transcript INCLUDING SERVER_FINISHED, as a raw framed
    // message. The TCP carrier's recv yields WouldBlock while no frame is
    // buffered, so poll briefly — the same bounded-wait pattern as the
    // CLIENT_AUTH read. A missing or tampered confirmation refuses the
    // session BEFORE anything is registered.
    let finished_packet = {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            match tokio::task::block_in_place(|| link.recv()) {
                Ok(packet) => break packet.bytes,
                Err(e)
                    if e.kind == umc_carrier::error::CarrierErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(format!("recv client finished: {e:?}")),
            }
        }
    };
    let client_finished = decode_client_finished(&finished_packet)?;
    pending
        .verify_client_finished(&auth_bytes, &server_finished, &client_finished)
        .map_err(|e| format!("client finished refused: {e}"))?;

    // Register the verified session (the full XX path). The peer identity
    // was recovered from CLIENT_AUTH; the session carries its stateless-
    // reset secret and its resumption secret for ticket issuance at the
    // clean close.
    register_session(
        state,
        carrier_type,
        link,
        dcid,
        secrets.server,
        secrets.client,
        Some(secrets.stateless_reset),
        Some(secrets.resumption),
        peer_endpoint_id,
        now,
    )
}

/// The resume path (handshake.md §35, IK mode): the hello offered the IK
/// handshake mode and its `retry_token` validated as a session ticket under
/// the daemon's ticket key. Answers with a `SERVER_HELLO` that selects IK
/// and carries NO encrypted server auth, derives the resumed session
/// secrets (the ticket's PSK replaces the identity binding), and registers
/// the session DIRECTLY — the `CLIENT_AUTH`/`SERVER_FINISHED` exchange is
/// skipped for resumed sessions (the ticket is the credential; the resumed
/// secrets ARE the traffic keys). Resumed sessions issue no further tickets
/// (the v1 scheme is a single resumption hop).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // one resume path: hello, secrets, registration
fn handle_resumed_link(
    state: &Arc<std::sync::Mutex<state::RuntimeState>>,
    carrier_type: &str,
    link: BoxLink,
    hello: &umc_handshake::xx::ClientHello,
    hello_bytes: &[u8],
    parsed_initial: Option<&umc_handshake::initial::ParsedInitial>,
    dcid: &[u8],
    vn_scid: &[u8],
    now: umc_types::runtime::Instant,
    tracker: &std::sync::Mutex<handshake_timeout::HandshakeTracker>,
    ticket: &umc_handshake::ticket::TicketPayload,
) -> Result<(), String> {
    let server_eid = {
        let state = state.lock().expect("state");
        state.node_identity.endpoint_id()
    };
    // Version negotiation (compatibility.md §5.2): a resume hello offering
    // no supported version gets the same Version-Negotiation answer as the
    // XX path.
    if umc_handshake::xx::select_version(&hello.supported_protocol_versions).is_none() {
        let bytes = umc_handshake::xx::build_version_negotiation(
            vn_scid,
            dcid,
            &[umc_handshake::xx::SUPPORTED_PROTOCOL_VERSION],
        );
        if let Err(e) = tokio::task::block_in_place(|| {
            link.send(OutboundPacket {
                bytes,
                control: true,
                deadline_ms: Some(3_000),
            })
        }) {
            return Err(format!("send version negotiation: {e:?}"));
        }
        return Err("version negotiation: resume hello offered no supported version".into());
    }
    // Capability negotiation (compatibility.md §5.4): the resume hello must
    // bind the canonical capability set like any other hello.
    if hello.capabilities_hash
        != umc_handshake::xx::capabilities_hash(&umc_handshake::xx::canonical_capabilities())
    {
        return Err("client capabilities hash mismatch".into());
    }
    // The ticket must belong to this node and this protocol: an endpoint or
    // profile mismatch refuses the resume (the accept loop already fell
    // back to the XX path only for invalid/expired tickets).
    if ticket.server_endpoint_id_hash != server_eid {
        return Err("ticket not issued by this node".into());
    }
    if ticket.protocol_version != umc_handshake::xx::SUPPORTED_PROTOCOL_VERSION {
        return Err("ticket protocol version mismatch".into());
    }
    if ticket.crypto_profile != umc_handshake::xx::CRYPTO_PROFILE.to_vec() {
        return Err("ticket crypto profile mismatch".into());
    }

    let server_ephemeral = umc_crypto::signatures::StaticHandshakeKeyPair::generate();
    let mut server_random = [0u8; 32];
    umc_types::runtime::EntropySource::fill(&runtime_adapters::OsEntropy, &mut server_random);
    // The resume transcript binds both hello messages under the IK mode
    // (handshake.md §35); the client derives the same context.
    let mut transcript = umc_handshake::transcript::Transcript::new(
        umc_handshake::ik::MODE_IK,
        umc_handshake::xx::CRYPTO_PROFILE,
        carrier_type.as_bytes(),
    );
    transcript
        .update_message(umc_handshake::encoding::CLIENT_HELLO, hello_bytes)
        .map_err(|e| format!("transcript: {e:?}"))?;
    let server_hello = umc_handshake::xx::ServerHello {
        server_random,
        server_ephemeral_public_key: server_ephemeral.public().0,
        selected_protocol_version: umc_handshake::xx::SUPPORTED_PROTOCOL_VERSION,
        selected_crypto_profile: umc_handshake::xx::CRYPTO_PROFILE.to_vec(),
        selected_handshake_mode: umc_handshake::ik::MODE_IK.to_vec(),
        // No encrypted server auth: the resumed session skips the identity
        // exchange entirely (the ticket is the credential).
        encrypted_server_authentication: Vec::new(),
        // The server's capabilities hash rides in the padding prefix, as on
        // the XX path (compatibility.md §5.4).
        padding: {
            let mut padding = Vec::with_capacity(64);
            padding.extend_from_slice(&umc_handshake::xx::capabilities_hash(
                &umc_handshake::xx::canonical_capabilities(),
            ));
            padding.extend_from_slice(&[0u8; 32]);
            padding
        },
    };
    let server_hello_bytes = server_hello
        .encode()
        .map_err(|e| format!("server hello: {e:?}"))?;
    transcript
        .update_message(umc_handshake::encoding::SERVER_HELLO, &server_hello_bytes)
        .map_err(|e| format!("transcript: {e:?}"))?;
    let final_transcript = transcript.hash;

    // The resumed traffic secrets: ee = DH(eph, eph) extracted under the
    // PSK (which both sides derive from the previous session's resumption
    // secret and the ticket's clear nonce).
    let psk = umc_session::ticket::resumption_psk(&ticket.resumption_secret, &ticket.nonce);
    let resume = umc_handshake::ik::derive_resumption_secrets(
        &psk,
        &server_ephemeral,
        &hello.client_ephemeral_public_key,
        &final_transcript,
    );

    // The `SERVER_HELLO` travels in the same form as the request (Initial-
    // protected or raw), mirroring the XX path.
    let response_bytes = match parsed_initial {
        Some((origin, _pn, _payload, return_to)) => {
            let keys = umc_handshake::initial::derive_initial_keys(origin).server;
            initial::build_initial_packet(
                return_to,
                &session_dcid(hello),
                0,
                &server_hello_bytes,
                &keys,
            )?
        }
        None => server_hello_bytes,
    };
    if let Err(e) = tokio::task::block_in_place(|| {
        link.send(OutboundPacket {
            bytes: response_bytes,
            control: true,
            deadline_ms: Some(3_000),
        })
    }) {
        return Err(format!("send server hello: {e:?}"));
    }
    tracker.lock().expect("handshake tracker").record(dcid, now);
    state
        .lock()
        .expect("state")
        .metrics
        .incr(state::metric_names::RESUMPTION_SESSIONS, 1);
    // The resumed session registers under the identity the ticket binds —
    // the ticket's client endpoint hash (the v1 resume carries no identity
    // proof; the ticket is the credential).
    register_session(
        state,
        carrier_type,
        link,
        dcid.to_vec(),
        resume.server,
        resume.client,
        None,
        None,
        ticket.client_endpoint_id_hash,
        now,
    )
}

/// Register a session with the runtime (core.md §8-9): build the session
/// state from the traffic secrets, spawn the wire task, and register the
/// session, its bus channels, and its events. Shared by the full XX path
/// and the IK resume path.
///
/// `stateless_reset_secret` is `Some` for XX sessions (session.md §31) and
/// `None` for resumed sessions (the v1 resume derives no stateless-reset
/// secret — documented). `resumption_secret` is `Some` for XX sessions —
/// the daemon issues one ticket at the session's clean close (handshake.md
/// §35) — and `None` for resumed sessions (no ticket re-issuance).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn register_session(
    state: &Arc<std::sync::Mutex<state::RuntimeState>>,
    carrier_type: &str,
    link: BoxLink,
    dcid: Vec<u8>,
    local_traffic_secret: [u8; 32],
    remote_traffic_secret: [u8; 32],
    stateless_reset_secret: Option<[u8; 32]>,
    resumption_secret: Option<[u8; 32]>,
    peer_endpoint_id: [u8; 32],
    now: umc_types::runtime::Instant,
) -> Result<(), String> {
    let runtime = state.clone();
    let state = state.lock().expect("state");
    // Blocklist admission (security-operations.md §16.2): a blocked peer's
    // session attempt is refused before any session state is built or
    // registered (`PeerService.BlockPeer` wires the blocklist).
    state.refuse_if_trust_disallowed(&peer_endpoint_id)?;
    state.refuse_if_blocked(&peer_endpoint_id, now)?;
    let mut session = umc_session::session::Session::new(
        umc_session::session::SessionConfig {
            role: umc_session::session::Role::Server,
            dcid,
            local_traffic_secret,
            remote_traffic_secret,
            initial_max_data: umc_session::session::DEFAULT_INITIAL_MAX_DATA,
            initial_max_stream_data: umc_session::session::DEFAULT_INITIAL_MAX_STREAM_DATA,
            max_ack_delay_ms: 25,
        },
        state.node.clock.as_ref(),
    )
    .map_err(|e| format!("session: {e:?}"))?;
    // Stateless-reset support (session.md §31): the token is derived from
    // the handshake's shared `stateless reset` secret (handshake.md §26).
    if let Some(secret) = stateless_reset_secret {
        session.set_stateless_reset_secret(secret);
    }
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
    let remote_keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&remote_traffic_secret)
        .map_err(|e| format!("remote keys: {e:?}"))?;
    let remote_hp_key =
        umc_crypto::header_protection::header_protection_key(&remote_traffic_secret);
    // Ticket-issuance material (handshake.md §35): XX sessions carry their
    // resumption secret to the clean-close path; resumed sessions issue no
    // ticket (single resumption hop).
    let ticket_material = resumption_secret.map(|resumption_secret| session_task::TicketMaterial {
        ticket_key: state.ticket_key,
        resumption_secret,
        peer_endpoint_id,
        server_endpoint_id: state.node_identity.endpoint_id(),
    });
    // The session's bus channels: created here so the registration can
    // happen under the state lock the caller already holds (the task itself
    // must not re-lock it); the rx sides move into the wire loop.
    let (bus_inbound_tx, bus_inbound_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (bus_outbound_tx, bus_outbound_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let cleanup_runtime = runtime.clone();
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
        remote_hp_key,
        ticket_material,
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
        // Cleanup runs for BOTH normal exits and aborts (CloseSession):
        // the bus must not keep stale entries pointing at a dead session.
        cleanup_runtime
            .lock()
            .expect("runtime state")
            .bus
            .lock()
            .expect("session bus")
            .unregister(session_id);
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
    state.metrics.incr(state::metric_names::SESSIONS_TOTAL, 1);
    state.metrics.set(
        state::metric_names::SESSIONS_ACTIVE,
        u64::try_from(state.sessions.count()).unwrap_or(u64::MAX),
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
    log::info!("{}", logging::session_active_line(&peer_endpoint_id));
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

/// Extract the `CLIENT_AUTH` message body from the second inbound packet:
/// either the decrypted Initial payload or the raw framed message (the
/// transitional dual-mode, mirroring [`decode_client_hello`]).
///
/// # Errors
///
/// Returns a message when the bytes decode to neither an Initial packet nor
/// a handshake message, or the message type is not `CLIENT_AUTH`.
fn decode_client_auth(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let body = match initial::try_parse_initial(bytes) {
        Some((_dcid, _pn, payload, _scid)) => payload,
        None => bytes.to_vec(),
    };
    let (message, _) = umc_handshake::encoding::decode_message(&body)
        .map_err(|e| format!("client auth framing: {e:?}"))?;
    if message.message_type != umc_handshake::encoding::CLIENT_AUTH {
        return Err(format!(
            "expected CLIENT_AUTH, got message type {}",
            message.message_type
        ));
    }
    Ok(message.body)
}

/// Extract the `CLIENT_FINISHED` message body from the third inbound
/// packet: a raw framed handshake message on the transitional path (the
/// client's confirmation MAC, handshake.md §20; mirroring
/// [`decode_client_auth`]).
///
/// # Errors
///
/// Returns a message when the bytes do not decode as a handshake message,
/// or the message type is not `CLIENT_FINISHED`.
fn decode_client_finished(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let (message, _) = umc_handshake::encoding::decode_message(bytes)
        .map_err(|e| format!("client finished framing: {e:?}"))?;
    if message.message_type != umc_handshake::encoding::CLIENT_FINISHED {
        return Err(format!(
            "expected CLIENT_FINISHED, got message type {}",
            message.message_type
        ));
    }
    Ok(message.body)
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
    log::info!("node data directory: {}", data_dir.display());
    log::info!("keystore directory: {}", keystore_dir.display());
    log::info!("config file: {}", config_file.display());
    log::info!(
        "node endpoint: {}",
        logging::redact(&identity.endpoint_id())
    );
    log::info!("public relay: disabled (default)");
    log::info!("telemetry: disabled (default)");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake_timeout::HandshakeTracker;
    use std::sync::Mutex as StdMutex;
    use umc_carrier::error::{CarrierError, CarrierErrorKind};
    use umc_carrier::types::{
        InboundPacket, LinkEvent, LinkProperties, Ordering, QueueState, Reliability, SendResult,
    };
    use umc_carrier::Link;
    use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
    use umc_handshake::encoding::{
        CLIENT_AUTH, CLIENT_FINISHED, CLIENT_HELLO, SERVER_FINISHED, SERVER_HELLO,
    };
    use umc_handshake::identity::{endpoint_id, IdentityBinding};
    use umc_handshake::transcript::Transcript;
    use umc_handshake::xx::{
        build_client_auth_plaintext, client_signature_input, decrypt_server_auth,
        encrypt_client_auth, verify_server_finished_and_build_confirmation, ClientHello,
        ServerHello, CRYPTO_PROFILE, MODE_XX,
    };
    use umc_types::runtime::Instant as RuntimeInstant;

    fn test_state() -> Arc<std::sync::Mutex<state::RuntimeState>> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "umcd-accept-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let config = NodeConfig {
            data_dir: dir,
            ..NodeConfig::default()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        Arc::new(std::sync::Mutex::new(
            state::RuntimeState::new(config, tx).expect("state"),
        ))
    }

    /// A link that plays the client's side of the wire: `recv` returns the
    /// `CLIENT_HELLO` first, then — once `send` captured the daemon's
    /// `SERVER_HELLO` — the client's real `CLIENT_AUTH` (built exactly like
    /// `Node::connect`), then — once `send` captured the daemon's
    /// `SERVER_FINISHED` — the `CLIENT_FINISHED` confirmation MAC, then
    /// fails. `tamper` flips a byte inside the client signature before
    /// sealing so the daemon must refuse the auth; `tamper_finished` flips
    /// a byte in the confirmation MAC so the daemon must refuse the
    /// finished exchange.
    struct AuthScriptedLink {
        client_identity: IdentityKeyPair,
        client_static: StaticHandshakeKeyPair,
        client_ephemeral: StaticHandshakeKeyPair,
        hello: ClientHello,
        hello_bytes: Vec<u8>,
        server_binding: IdentityBinding,
        stage: StdMutex<usize>,
        server_hello_bytes: StdMutex<Vec<u8>>,
        server_finished_bytes: StdMutex<Vec<u8>>,
        sends: StdMutex<usize>,
        auth_body: StdMutex<Vec<u8>>,
        secret4: StdMutex<[u8; 32]>,
        tamper: bool,
        tamper_finished: bool,
    }

    impl AuthScriptedLink {
        fn new(
            server_binding: IdentityBinding,
            tamper: bool,
            tamper_finished: bool,
        ) -> (Self, [u8; 32]) {
            let client_identity = IdentityKeyPair::generate();
            let client_static = StaticHandshakeKeyPair::generate();
            let client_ephemeral = StaticHandshakeKeyPair::generate();
            let hello = ClientHello::new(&crate::runtime_adapters::OsEntropy, &client_ephemeral);
            let hello_bytes = hello.encode().expect("hello");
            let client_eid = endpoint_id(&client_identity.public());
            (
                Self {
                    client_identity,
                    client_static,
                    client_ephemeral,
                    hello,
                    hello_bytes,
                    server_binding,
                    stage: StdMutex::new(0),
                    server_hello_bytes: StdMutex::new(Vec::new()),
                    server_finished_bytes: StdMutex::new(Vec::new()),
                    sends: StdMutex::new(0),
                    auth_body: StdMutex::new(Vec::new()),
                    secret4: StdMutex::new([0u8; 32]),
                    tamper,
                    tamper_finished,
                },
                client_eid,
            )
        }

        /// The client's `CLIENT_AUTH` against the captured `SERVER_HELLO`:
        /// the real static + the client's own identity binding + the
        /// transcript-bound signature, sealed with the provisional-chain
        /// client-auth key (the ephemeral stood in for the static in the DH
        /// chain on both sides, so the key matches the responder's).
        #[allow(clippy::similar_names)]
        fn build_client_auth(&self, server_hello: &ServerHello) -> Result<Vec<u8>, String> {
            let mut transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, b"ump.tcp/1");
            transcript
                .update_message(CLIENT_HELLO, &self.hello.encode().expect("hello"))
                .expect("transcript");
            let server_auth_transcript = transcript.hash;
            let dh_ee = self
                .client_ephemeral
                .diffie_hellman(&StaticHandshakePublicKey(
                    server_hello.server_ephemeral_public_key,
                ));
            let extract1 = umc_crypto::hkdf::extract(&[0u8; 32], &dh_ee);
            let server_block = decrypt_server_auth(
                &extract1,
                &server_auth_transcript,
                &server_hello.encrypted_server_authentication,
                &server_hello.server_ephemeral_public_key,
                &server_hello.server_random,
                &server_hello.selected_crypto_profile,
            )
            .map_err(|e| format!("{e:?}"))?;
            let server_static_pub = StaticHandshakePublicKey(server_block.server_static_public_key);
            transcript
                .update_message(SERVER_HELLO, &server_hello.encode().expect("server hello"))
                .expect("transcript");
            // The provisional chain: the ephemeral stands in for the static
            // (the responder's DH chain used the hello ephemeral), so the
            // client-auth key matches on both sides; the REAL static rides
            // only in the plaintext below.
            let dh_es = self.client_ephemeral.diffie_hellman(&server_static_pub);
            let secret2 = umc_crypto::hkdf::extract(&extract1, &dh_es);
            let dh_se = self
                .client_ephemeral
                .diffie_hellman(&StaticHandshakePublicKey(
                    server_hello.server_ephemeral_public_key,
                ));
            let secret3 = umc_crypto::hkdf::extract(&secret2, &dh_se); // provisional chain
            let auth_key =
                handshake_responder::expand(&secret3, b"client auth key", &transcript.hash);
            // The provisional DH_ss: the ephemeral stands in for the static
            // on both sides, so secret4 matches the responder's and derives
            // the finished keys for the CLIENT_FINISHED confirmation.
            let dh_ss = self.client_ephemeral.diffie_hellman(&server_static_pub);
            let secret4 = umc_crypto::hkdf::extract(&secret3, &dh_ss);
            let client_eid = endpoint_id(&self.client_identity.public());
            let server_eid = endpoint_id(&self.server_binding.identity_public_key);
            let sig_input = client_signature_input(
                &transcript.hash,
                &client_eid,
                &server_eid,
                &self.client_static.public().0,
                &server_static_pub.0,
            );
            let signature = self.client_identity.sign(&sig_input);
            let client_binding = IdentityBinding::sign(
                &self.client_identity,
                &self.client_static.public(),
                0,
                u64::MAX,
                0,
                [0u8; 32],
            );
            let mut plaintext = build_client_auth_plaintext(
                &self.client_static.public().0,
                &client_binding,
                &signature,
            );
            if self.tamper {
                // Flip a byte INSIDE the transcript signature section so
                // the AEAD still opens but the identity proof fails.
                let last = plaintext.len() - 1;
                plaintext[last] ^= 0x01;
            }
            let ciphertext = encrypt_client_auth(&auth_key, &transcript.hash, &plaintext);
            let mut auth_body = Vec::new();
            umc_wire::bytes::encode(&mut auth_body, &ciphertext, 16_384)
                .map_err(|_| "bytes".to_string())?;
            *self.auth_body.lock().expect("auth body") = auth_body.clone();
            *self.secret4.lock().expect("secret4") = secret4;
            let mut frame = Vec::new();
            umc_handshake::encoding::encode_message(&mut frame, CLIENT_AUTH, &auth_body)
                .map_err(|e| format!("{e:?}"))?;
            Ok(frame)
        }

        /// The client's `CLIENT_FINISHED` confirmation against the captured
        /// `SERVER_FINISHED`: verify the daemon's finished MAC and signature
        /// (handshake.md §19) and return the confirmation MAC over the
        /// transcript including `SERVER_FINISHED` (handshake.md §20),
        /// framed as a raw handshake message. `tamper_finished` flips a
        /// byte in the MAC so the daemon must refuse the exchange.
        fn build_client_finished(&self) -> Result<Vec<u8>, String> {
            let server_hello_bytes = self.server_hello_bytes.lock().expect("captured");
            let server_hello =
                ServerHello::decode(&server_hello_bytes).expect("captured server hello");
            let mut transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, b"ump.tcp/1");
            transcript
                .update_message(CLIENT_HELLO, &self.hello_bytes)
                .map_err(|e| format!("{e:?}"))?;
            transcript
                .update_message(SERVER_HELLO, &server_hello.encode().expect("server hello"))
                .map_err(|e| format!("{e:?}"))?;
            let auth_body = self.auth_body.lock().expect("auth body").clone();
            let secret4 = self.secret4.lock().expect("secret4");
            let server_eid = endpoint_id(&self.server_binding.identity_public_key);
            let client_eid = endpoint_id(&self.client_identity.public());
            let server_finished_bytes = self.server_finished_bytes.lock().expect("captured");
            let (finished_message, _) =
                umc_handshake::encoding::decode_message(&server_finished_bytes)
                    .map_err(|e| format!("{e:?}"))?;
            if finished_message.message_type != SERVER_FINISHED {
                return Err(format!(
                    "expected SERVER_FINISHED, got message type {}",
                    finished_message.message_type
                ));
            }
            let mut confirmation = verify_server_finished_and_build_confirmation(
                &mut transcript,
                &secret4,
                &self.server_binding.identity_public_key,
                &server_eid,
                &client_eid,
                &self.server_binding.static_handshake_public_key.0,
                &self.client_static.public().0,
                &auth_body,
                &finished_message.body,
            )
            .map_err(|e| format!("server finished refused: {e}"))?;
            if self.tamper_finished {
                confirmation[0] ^= 0x01;
            }
            let mut frame = Vec::new();
            umc_handshake::encoding::encode_message(&mut frame, CLIENT_FINISHED, &confirmation)
                .map_err(|e| format!("{e:?}"))?;
            Ok(frame)
        }
    }

    impl Link for AuthScriptedLink {
        fn properties(&self) -> LinkProperties {
            LinkProperties {
                reliability: Reliability::ReliableUntilLinkFailure,
                ordering: Ordering::Ordered,
                current_mtu: 65_535,
                queue_bytes: 0,
                queue_capacity: 2 * 1024 * 1024,
                estimated_rtt_ms: None,
                estimated_loss: None,
                metered: false,
            }
        }

        fn send(&self, packet: OutboundPacket) -> Result<SendResult, CarrierError> {
            let mut sends = self.sends.lock().expect("sends");
            if *sends == 0 {
                *self.server_hello_bytes.lock().expect("server hello") = packet.bytes;
            } else {
                *self.server_finished_bytes.lock().expect("server finished") = packet.bytes;
            }
            *sends += 1;
            Ok(SendResult::Accepted {
                queue_state: QueueState::SentToMedium,
            })
        }

        fn recv(&self) -> Result<InboundPacket, CarrierError> {
            let mut stage = self.stage.lock().expect("stage");
            match *stage {
                0 => {
                    *stage += 1;
                    Ok(InboundPacket {
                        bytes: self.hello_bytes.clone(),
                        received_at: RuntimeInstant(0),
                    })
                }
                1 => {
                    *stage += 1;
                    let server_hello_bytes = self.server_hello_bytes.lock().expect("captured");
                    let server_hello =
                        ServerHello::decode(&server_hello_bytes).expect("captured server hello");
                    let frame = self.build_client_auth(&server_hello).expect("client auth");
                    Ok(InboundPacket {
                        bytes: frame,
                        received_at: RuntimeInstant(0),
                    })
                }
                2 => {
                    *stage += 1;
                    let frame = self.build_client_finished().expect("client finished");
                    Ok(InboundPacket {
                        bytes: frame,
                        received_at: RuntimeInstant(0),
                    })
                }
                _ => Err(CarrierError::new(
                    CarrierErrorKind::LinkFailed,
                    "script exhausted",
                )),
            }
        }

        fn events(&self) -> Result<LinkEvent, CarrierError> {
            Err(CarrierError::new(CarrierErrorKind::WouldBlock, "events"))
        }

        fn close(&self, _reason: &str) -> Result<(), CarrierError> {
            Ok(())
        }
    }

    /// The accept loop (`handle_inbound_link`) reads the client's `CLIENT_AUTH`
    /// after the `SERVER_HELLO`, completes the two-step responder with it,
    /// and registers the session under the client's REAL endpoint id from
    /// the verified identity binding (handshake.md §18) — not a derivation
    /// of the hello ephemeral.
    #[tokio::test(flavor = "multi_thread")]
    async fn accept_loop_verifies_client_auth() {
        let state = test_state();
        let (server_identity, server_static) = {
            let state = state.lock().expect("state");
            (
                state.node_identity.identity.clone(),
                state.node_identity.static_handshake.public(),
            )
        };
        let server_binding =
            IdentityBinding::sign(&server_identity, &server_static, 0, u64::MAX, 0, [0u8; 32]);
        let (link, client_eid) = AuthScriptedLink::new(server_binding, false, false);
        let tracker = StdMutex::new(HandshakeTracker::new());
        handle_inbound_link(&state, "ump.tcp/1", Box::new(link), &tracker).expect("accept");

        let session_id = state
            .lock()
            .expect("state")
            .sessions
            .lookup(1)
            .expect("session registered");
        assert_eq!(
            session_id.peer_endpoint_id, client_eid,
            "the session registers the real peer endpoint id from CLIENT_AUTH"
        );
        // The session bus is reachable under the real peer id (the relay
        // path keys cross-session delivery on it).
        assert_eq!(
            state
                .lock()
                .expect("state")
                .bus
                .lock()
                .expect("bus")
                .lookup(&client_eid),
            Some(1)
        );
    }

    /// The daemon sends `SERVER_FINISHED` and the client answers with a
    /// verified `CLIENT_FINISHED` confirmation: only then does the session
    /// activate. The `session_active` event fires after the confirmation
    /// MAC is verified (handshake.md §20).
    #[tokio::test(flavor = "multi_thread")]
    async fn accept_loop_verifies_client_finished() {
        let state = test_state();
        let (server_identity, server_static) = {
            let state = state.lock().expect("state");
            (
                state.node_identity.identity.clone(),
                state.node_identity.static_handshake.public(),
            )
        };
        let server_binding =
            IdentityBinding::sign(&server_identity, &server_static, 0, u64::MAX, 0, [0u8; 32]);
        let (link, client_eid) = AuthScriptedLink::new(server_binding, false, false);
        let tracker = StdMutex::new(HandshakeTracker::new());
        handle_inbound_link(&state, "ump.tcp/1", Box::new(link), &tracker).expect("accept");

        let session_id = state
            .lock()
            .expect("state")
            .sessions
            .lookup(1)
            .expect("session registered");
        assert_eq!(session_id.peer_endpoint_id, client_eid);
        let events = state.lock().expect("state").events.clone();
        assert!(
            events
                .lock()
                .expect("event log")
                .recent(10)
                .iter()
                .any(|e| e.kind == "session_active"),
            "session_active must fire once the confirmation is verified"
        );
    }

    /// A `CLIENT_FINISHED` whose confirmation MAC is tampered with fails
    /// the daemon's verification: the accept loop refuses the session and
    /// registers nothing (no `session_active` event).
    #[tokio::test(flavor = "multi_thread")]
    async fn accept_loop_refuses_tampered_client_finished() {
        let state = test_state();
        let (server_identity, server_static) = {
            let state = state.lock().expect("state");
            (
                state.node_identity.identity.clone(),
                state.node_identity.static_handshake.public(),
            )
        };
        let server_binding =
            IdentityBinding::sign(&server_identity, &server_static, 0, u64::MAX, 0, [0u8; 32]);
        let (link, _client_eid) = AuthScriptedLink::new(server_binding, false, true);
        let tracker = StdMutex::new(HandshakeTracker::new());
        let err = handle_inbound_link(&state, "ump.tcp/1", Box::new(link), &tracker)
            .expect_err("tampered confirmation must be refused");
        assert!(err.contains("client finished"), "{err}");
        assert_eq!(
            state.lock().expect("state").sessions.count(),
            0,
            "no session may be registered for a refused confirmation"
        );
        let events = state.lock().expect("state").events.clone();
        assert!(
            !events
                .lock()
                .expect("event log")
                .recent(10)
                .iter()
                .any(|e| e.kind == "session_active"),
            "no session_active event may fire for a refused session"
        );
    }

    /// A link that plays the client's side of a RESUMED handshake
    /// (handshake.md §35): `recv` returns the resume `CLIENT_HELLO` (IK
    /// mode, the ticket in `retry_token`) exactly once, then fails loud —
    /// the accept loop's resume path must NOT ask for `CLIENT_AUTH` or
    /// `CLIENT_FINISHED`. `send` captures the daemon's `SERVER_HELLO`.
    struct ResumeScriptedLink {
        hello_bytes: Vec<u8>,
        server_hello_bytes: Arc<StdMutex<Vec<u8>>>,
        stage: StdMutex<usize>,
    }

    impl Link for ResumeScriptedLink {
        fn properties(&self) -> LinkProperties {
            LinkProperties {
                reliability: Reliability::ReliableUntilLinkFailure,
                ordering: Ordering::Ordered,
                current_mtu: 65_535,
                queue_bytes: 0,
                queue_capacity: 2 * 1024 * 1024,
                estimated_rtt_ms: None,
                estimated_loss: None,
                metered: false,
            }
        }

        fn send(&self, packet: OutboundPacket) -> Result<SendResult, CarrierError> {
            *self.server_hello_bytes.lock().expect("server hello") = packet.bytes;
            Ok(SendResult::Accepted {
                queue_state: QueueState::SentToMedium,
            })
        }

        fn recv(&self) -> Result<InboundPacket, CarrierError> {
            let mut stage = self.stage.lock().expect("stage");
            match *stage {
                0 => {
                    *stage += 1;
                    Ok(InboundPacket {
                        bytes: self.hello_bytes.clone(),
                        received_at: RuntimeInstant(0),
                    })
                }
                _ => Err(CarrierError::new(
                    CarrierErrorKind::LinkFailed,
                    "script exhausted — the resume path must not read again",
                )),
            }
        }

        fn events(&self) -> Result<LinkEvent, CarrierError> {
            Err(CarrierError::new(CarrierErrorKind::WouldBlock, "events"))
        }

        fn close(&self, _reason: &str) -> Result<(), CarrierError> {
            Ok(())
        }
    }

    /// A ticket sealed with the daemon's own ticket key, bound to the
    /// daemon's endpoint id (the shape the clean-close path issues).
    fn daemon_ticket(state: &Arc<std::sync::Mutex<state::RuntimeState>>) -> Vec<u8> {
        let state = state.lock().expect("state");
        umc_handshake::ticket::issue_ticket(
            &state.ticket_key,
            &umc_handshake::ticket::TicketPayload {
                version: 1,
                ticket_id: [0x11u8; 16],
                client_endpoint_id_hash: [0xAAu8; 32],
                server_endpoint_id_hash: state.node_identity.endpoint_id(),
                resumption_secret: [0x42u8; 32],
                issued_at_ms: state.node.clock.as_ref().now().0,
                expires_at_ms: state.node.clock.as_ref().now().0 + 3_600_000,
                protocol_version: 1,
                crypto_profile: umc_handshake::xx::CRYPTO_PROFILE.to_vec(),
                nonce: [0x55u8; 16],
            },
        )
    }

    /// The accept loop's resume path (handshake.md §35): a `CLIENT_HELLO`
    /// offering IK mode with a valid ticket in `retry_token` gets a
    /// `SERVER_HELLO` selecting IK, the session registers WITHOUT the
    /// `CLIENT_AUTH`/`SERVER_FINISHED` exchange, and the peer identity is
    /// the ticket's client endpoint hash.
    #[tokio::test(flavor = "multi_thread")]
    async fn accept_loop_resumes_without_client_auth() {
        let state = test_state();
        let ticket = daemon_ticket(&state);
        let client_ephemeral = umc_crypto::signatures::StaticHandshakeKeyPair::generate();
        let mut hello = ClientHello::new(&crate::runtime_adapters::OsEntropy, &client_ephemeral);
        hello.supported_handshake_modes = vec![umc_handshake::ik::MODE_IK.to_vec()];
        hello.retry_token = ticket;
        let hello_bytes = hello.encode().expect("hello");
        let server_hello_bytes = Arc::new(StdMutex::new(Vec::new()));
        let link = ResumeScriptedLink {
            hello_bytes,
            server_hello_bytes: server_hello_bytes.clone(),
            stage: StdMutex::new(0),
        };
        let tracker = StdMutex::new(HandshakeTracker::new());
        handle_inbound_link(&state, "ump.tcp/1", Box::new(link), &tracker).expect("resume accept");

        // The daemon answered with a mode-IK `SERVER_HELLO` carrying no
        // encrypted server auth.
        let captured = server_hello_bytes.lock().expect("captured");
        let server_hello = ServerHello::decode(&captured).expect("captured server hello");
        assert_eq!(
            server_hello.selected_handshake_mode,
            umc_handshake::ik::MODE_IK.to_vec(),
            "the resume server hello must select IK mode"
        );
        assert!(
            server_hello.encrypted_server_authentication.is_empty(),
            "the resumed session skips the server auth block"
        );
        drop(captured);

        let session_id = state
            .lock()
            .expect("state")
            .sessions
            .lookup(1)
            .expect("resumed session registered");
        assert_eq!(
            session_id.peer_endpoint_id, [0xAAu8; 32],
            "the resumed session registers under the ticket's client endpoint hash"
        );
        let events = state.lock().expect("state").events.clone();
        assert!(
            events
                .lock()
                .expect("event log")
                .recent(10)
                .iter()
                .any(|e| e.kind == "session_active"),
            "the resumed session activates without CLIENT_AUTH"
        );
    }

    /// A ticket is single-use (handshake.md §35): after a successful
    /// resume, presenting the same ticket again (same clear nonce) is a
    /// replay — the daemon refuses the short path and falls back to the
    /// full XX path, so one stolen ticket grants at most one session.
    #[tokio::test(flavor = "multi_thread")]
    async fn accept_loop_refuses_replayed_ticket() {
        let state = test_state();
        let ticket = daemon_ticket(&state);
        let client_ephemeral = umc_crypto::signatures::StaticHandshakeKeyPair::generate();
        let mut hello = ClientHello::new(&crate::runtime_adapters::OsEntropy, &client_ephemeral);
        hello.supported_handshake_modes = vec![umc_handshake::ik::MODE_IK.to_vec()];
        hello.retry_token = ticket;
        let hello_bytes = hello.encode().expect("hello");

        let resume = |captured: Arc<StdMutex<Vec<u8>>>| {
            let link = ResumeScriptedLink {
                hello_bytes: hello_bytes.clone(),
                server_hello_bytes: captured,
                stage: StdMutex::new(0),
            };
            let tracker = StdMutex::new(HandshakeTracker::new());
            handle_inbound_link(&state, "ump.tcp/1", Box::new(link), &tracker)
        };

        // First use of the ticket: the resume path is taken and the
        // session registers.
        let first = Arc::new(StdMutex::new(Vec::new()));
        resume(first.clone()).expect("first use of the ticket resumes");
        let captured = first.lock().expect("captured");
        let server_hello = ServerHello::decode(&captured).expect("captured server hello");
        assert_eq!(
            server_hello.selected_handshake_mode,
            umc_handshake::ik::MODE_IK.to_vec(),
            "the first use must take the IK resume path"
        );
        drop(captured);
        assert_eq!(state.lock().expect("state").sessions.count(), 1);

        // Replay of the same ticket: refused — the daemon falls back to
        // the full XX path, where the scripted link ends.
        let err = resume(Arc::new(StdMutex::new(Vec::new())))
            .expect_err("a replayed ticket must not resume again");
        assert!(
            err.contains("client auth"),
            "the replay must fall back to the XX path: {err}"
        );
        assert_eq!(
            state.lock().expect("state").sessions.count(),
            1,
            "no second session may be registered for a replayed ticket"
        );
    }

    /// An invalid ticket (garbage in `retry_token`) falls back to the full
    /// XX path: the daemon answers with a mode-XX `SERVER_HELLO` and then
    /// expects the `CLIENT_AUTH` continuation — the scripted link fails
    /// there, proving the short path was NOT taken.
    #[tokio::test(flavor = "multi_thread")]
    async fn accept_loop_falls_back_to_xx_on_invalid_ticket() {
        let state = test_state();
        let client_ephemeral = umc_crypto::signatures::StaticHandshakeKeyPair::generate();
        let mut hello = ClientHello::new(&crate::runtime_adapters::OsEntropy, &client_ephemeral);
        hello.supported_handshake_modes = vec![umc_handshake::ik::MODE_IK.to_vec()];
        hello.retry_token = b"not-a-ticket".to_vec();
        let hello_bytes = hello.encode().expect("hello");
        let link = ResumeScriptedLink {
            hello_bytes,
            server_hello_bytes: Arc::new(StdMutex::new(Vec::new())),
            stage: StdMutex::new(0),
        };
        let tracker = StdMutex::new(HandshakeTracker::new());
        let err = handle_inbound_link(&state, "ump.tcp/1", Box::new(link), &tracker)
            .expect_err("the fallback must continue into the XX path");
        assert!(
            err.contains("client auth"),
            "the daemon must have awaited CLIENT_AUTH on the XX path: {err}"
        );
        assert_eq!(
            state.lock().expect("state").sessions.count(),
            0,
            "no session may be registered for an invalid ticket"
        );
    }

    /// A `CLIENT_AUTH` whose transcript signature is tampered with passes
    /// the AEAD open (it was sealed honestly) but fails identity
    /// verification: the accept loop refuses the session and registers
    /// nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn accept_loop_refuses_tampered_client_auth() {
        let state = test_state();
        let (server_identity, server_static) = {
            let state = state.lock().expect("state");
            (
                state.node_identity.identity.clone(),
                state.node_identity.static_handshake.public(),
            )
        };
        let server_binding =
            IdentityBinding::sign(&server_identity, &server_static, 0, u64::MAX, 0, [0u8; 32]);
        let (link, _client_eid) = AuthScriptedLink::new(server_binding, true, false);
        let tracker = StdMutex::new(HandshakeTracker::new());
        let err = handle_inbound_link(&state, "ump.tcp/1", Box::new(link), &tracker)
            .expect_err("tampered auth must be refused");
        assert!(err.contains("client auth"), "{err}");
        assert_eq!(
            state.lock().expect("state").sessions.count(),
            0,
            "no session may be registered for a refused auth"
        );
    }
}
