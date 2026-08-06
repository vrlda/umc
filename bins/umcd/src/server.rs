//! Control socket server: Unix stream socket, framing, connection handling,
//! and the service-backed envelope dispatcher (control-api.md §16-24).
use crate::config::NodeConfig;
use crate::doctor;
use crate::relay_service::CircuitOpenRequest;
use crate::state::RuntimeState;
use prost::Message;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use umc_bundle::manager::BundleStatus;
use umc_control::framing::{frame_envelope, EnvelopeDecoder};
use umc_control::proto::umc::api::v1 as api;
use umc_storage::sqlite::SqliteStore;

const DEFAULT_ENVELOPE_MAX: usize = 4 * 1024 * 1024;

/// Concurrent control connections are capped (control-api.md §16): the 65th
/// connection is refused until an earlier one closes.
pub const MAX_CONTROL_CONNECTIONS: usize = 64;

/// Wire request for `RelayService.OpenCircuit` (relay.md §13). No proto
/// message exists yet; the control surface carries these fields until the
/// API spec gains a relay-open method.
#[derive(Clone, PartialEq, prost::Message)]
struct OpenCircuitRequest {
    #[prost(uint64, tag = "1")]
    requested_lifetime_ms: u64,
    #[prost(uint64, tag = "2")]
    requested_byte_quota: u64,
    #[prost(uint32, tag = "3")]
    flags: u32,
    #[prost(bool, tag = "4")]
    bidirectional: bool,
    #[prost(bool, tag = "5")]
    private_handling: bool,
    #[prost(uint32, tag = "6")]
    peer_circuits: u32,
}

/// Wire response for `RelayService.OpenCircuit` (relay.md §13.3).
#[derive(Clone, PartialEq, prost::Message)]
struct OpenCircuitResponse {
    #[prost(uint64, tag = "1")]
    circuit_id: u64,
    #[prost(uint64, tag = "2")]
    granted_lifetime_ms: u64,
    #[prost(uint64, tag = "3")]
    granted_byte_quota: u64,
    #[prost(uint32, tag = "4")]
    maximum_relay_payload: u32,
}

/// Wire request for `RelayService.CloseCircuit` (relay.md §23-24).
#[derive(Clone, PartialEq, prost::Message)]
struct CloseCircuitRequest {
    #[prost(uint64, tag = "1")]
    circuit_id: u64,
    #[prost(uint64, tag = "2")]
    reason: u64,
}

/// Wire response for `PeerService.ListCandidates`: a bounded discovery
/// snapshot (discovery.md §6). No proto message exists yet.
#[derive(Clone, PartialEq, prost::Message)]
struct ListCandidatesResponse {
    #[prost(message, repeated, tag = "1")]
    candidates: Vec<CandidateSummary>,
    #[prost(uint32, tag = "2")]
    total: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct CandidateSummary {
    #[prost(uint64, tag = "1")]
    candidate_id: u64,
    #[prost(string, tag = "2")]
    carrier_type: String,
    #[prost(uint64, tag = "3")]
    expires_at_ms: u64,
    #[prost(bool, tag = "4")]
    public: bool,
}

pub async fn run(state: Arc<Mutex<RuntimeState>>) {
    let data_dir = {
        let state = state.lock().expect("runtime state");
        state.config.resolved_data_dir()
    };
    std::fs::create_dir_all(&data_dir).expect("data dir");
    let store = state.lock().expect("runtime state").store.clone();
    println!("data directory: {}", data_dir.display());

    if let Ok((profile, carriers)) = load_node_state(&store) {
        println!(
            "node state: profile {profile}, carriers [{}]",
            carriers.join(", ")
        );
    }
    let config = state.lock().expect("runtime state").config.clone();
    persist_node_state(&store, &config).expect("persist node state");

    let socket_path = state.lock().expect("runtime state").control_socket.clone();
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).expect("socket dir");
    }
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind socket");
    println!("control socket: {}", socket_path.display());
    println!("node initialized");

    // Concurrent control connections are capped: each live connection holds
    // one permit for its lifetime (control-api.md §16).
    let connections = Arc::new(tokio::sync::Semaphore::new(MAX_CONTROL_CONNECTIONS));

    loop {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(200)) => {
                if state.lock().expect("runtime state").shutdown_requested.load(Ordering::Relaxed) {
                    break;
                }
            }
            accepted = listener.accept() => {
                if let Ok((stream, _)) = accepted {
                    let state = state.clone();
                    if !admit_connection(&connections, stream, state) {
                        println!("control socket: connection refused (cap {MAX_CONTROL_CONNECTIONS})");
                    }
                }
            }
        }
    }
    let _ = std::fs::remove_file(&socket_path);
    println!("control socket: closed");
}

/// Admit one control connection under the concurrent-connection cap. The
/// permit is held for the connection's lifetime; returns `false` when the
/// cap is reached and the connection is refused.
fn admit_connection(
    connections: &Arc<tokio::sync::Semaphore>,
    stream: UnixStream,
    state: Arc<Mutex<RuntimeState>>,
) -> bool {
    let Ok(permit) = connections.clone().try_acquire_owned() else {
        return false;
    };
    tokio::spawn(handle_connection(stream, state, permit));
    true
}

async fn handle_connection(
    mut stream: UnixStream,
    state: Arc<Mutex<RuntimeState>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let mut decoder = EnvelopeDecoder::new(DEFAULT_ENVELOPE_MAX);
    let mut buf = [0u8; 8 * 1024];
    // The credential presented at hello time gates every request on this
    // connection (control-api.md §11, §23).
    let mut presented_token: Option<Vec<u8>> = None;
    loop {
        let Ok(n) = stream.read(&mut buf).await else {
            break;
        };
        if n == 0 {
            break;
        }
        let Ok(envelopes) = decoder.feed(&buf[..n]) else {
            break;
        };
        for envelope in envelopes {
            let Ok(msg) = api::Envelope::decode(envelope.as_slice()) else {
                break;
            };
            let response = {
                let mut state = state.lock().expect("runtime state");
                match msg.body {
                    Some(api::envelope::Body::ClientHello(hello)) => {
                        presented_token = hello_token(&hello);
                        handle_hello(&hello, &state.store)
                    }
                    Some(api::envelope::Body::Request(request)) => {
                        dispatch_request(&mut state, &request, presented_token.as_deref())
                    }
                    _ => continue,
                }
            };
            let mut out = Vec::new();
            if frame_envelope(&mut out, &response, DEFAULT_ENVELOPE_MAX).is_ok() {
                let _ = stream.write_all(&out).await;
            }
        }
    }
}

/// The credential a client presented in `ClientHello`: the bearer or
/// development token bytes when the hello carried either (control-api.md
/// §11.2-11.3).
fn hello_token(hello: &api::ClientHello) -> Option<Vec<u8>> {
    match &hello.authentication.as_ref()?.method {
        Some(api::client_authentication::Method::Development(auth)) => Some(auth.token.clone()),
        Some(api::client_authentication::Method::Bearer(auth)) => Some(auth.token.clone()),
        _ => None,
    }
}

fn handle_hello(hello: &api::ClientHello, store: &SqliteStore) -> Vec<u8> {
    let _ = (hello, store);
    let server_hello = api::ServerHello {
        selected_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        node_state: 0,
        connection_id: vec![0u8; 16],
        principal_id: vec![],
        negotiated_envelope_size: u32::try_from(DEFAULT_ENVELOPE_MAX).expect("fits u32"),
        ..Default::default()
    };
    let envelope = api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence: 1,
        body: Some(api::envelope::Body::ServerHello(server_hello)),
    };
    let mut out = Vec::new();
    Message::encode(&envelope, &mut out).expect("encode");
    out
}

/// Service-backed envelope dispatch (control-api.md §16-24). Methods without
/// a service implementation return `Unimplemented`.
///
/// When the daemon is configured with a development token, requests whose
/// connection did not present that exact token at hello time are rejected
/// with `Unauthenticated` before dispatch (control-api.md §11.3).
fn dispatch_request(
    state: &mut RuntimeState,
    request: &api::Request,
    presented_token: Option<&[u8]>,
) -> Vec<u8> {
    if let Some(configured) = &state.development_token {
        let matches = presented_token.is_some_and(|token| token == configured.as_slice());
        if !matches {
            return response_envelope(request, api::StatusCode::Unauthenticated as i32, None);
        }
    }
    let (code, payload) = match (request.service.as_str(), request.method.as_str()) {
        ("NodeAdmin", "GetStatus") => get_status(state),
        ("PeerService" | "DiscoveryService", "ListCandidates") => list_candidates(state),
        ("BundleService", "GetBundles" | "ListBundles") => list_bundles(state),
        ("BundleService", "CreateBundle") => create_bundle(state, request),
        ("RelayService", "OpenCircuit") => open_circuit(state, request),
        ("RelayService", "CloseCircuit") => close_circuit(state, request),
        ("NodeAdmin" | "ConfigService", "GetConfig") => get_config(state),
        ("NodeAdmin", "GetEvents") => get_events(state),
        ("DiagnosticsService" | "NodeAdmin", "RunDoctor" | "Doctor") => run_doctor(state),
        ("ConfigService", "SetConfig") | ("NodeAdmin", "UpdateConfig") => {
            set_config(state, request)
        }
        _ => (api::StatusCode::Unimplemented as i32, None),
    };
    response_envelope(request, code, payload)
}

/// Frame one response envelope for `request`.
fn response_envelope(request: &api::Request, code: i32, payload: Option<Vec<u8>>) -> Vec<u8> {
    let envelope = api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence: 1,
        body: Some(api::envelope::Body::Response(api::Response {
            request_id: request.request_id,
            status: Some(api::Status {
                code,
                ..Default::default()
            }),
            payload: payload.unwrap_or_default(),
            ..Default::default()
        })),
    };
    let mut out = Vec::new();
    Message::encode(&envelope, &mut out).expect("encode");
    out
}

/// `NodeAdmin.GetStatus`: real counts from the live services.
fn get_status(state: &RuntimeState) -> (i32, Option<Vec<u8>>) {
    let now = state.node.clock.as_ref().now();
    let status = api::NodeStatus {
        state: api::NodeLifecycleState::Running as i32,
        software_version: env!("CARGO_PKG_VERSION").to_string(),
        started_at_unix_ms: i64::try_from(state.started_at.0).unwrap_or(i64::MAX),
        uptime_ms: now.0.saturating_sub(state.started_at.0),
        pressure: api::ResourcePressure::Normal as i32,
        active_sessions: u32::try_from(state.sessions.count()).unwrap_or(u32::MAX),
        active_links: u32::try_from(state.sessions.count()).unwrap_or(u32::MAX),
        active_relay_circuits: u32::try_from(state.relay.circuit_count()).unwrap_or(u32::MAX),
        pending_handshakes: 0,
        ..Default::default()
    };
    let response = api::GetStatusResponse {
        status: Some(status),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `PeerService.ListCandidates`: discovery table snapshot.
fn list_candidates(state: &RuntimeState) -> (i32, Option<Vec<u8>>) {
    let snapshot = state.discovery.candidates();
    let candidates = snapshot
        .iter()
        .map(|c| CandidateSummary {
            candidate_id: c.candidate_id,
            carrier_type: c.carrier_type.clone(),
            expires_at_ms: c.expires_at.0,
            public: c.sharing_policy == umc_discovery::provider::SharingPolicy::ShareGeneral,
        })
        .collect();
    let response = ListCandidatesResponse {
        candidates,
        total: u32::try_from(snapshot.len()).unwrap_or(u32::MAX),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `BundleService.ListBundles`: bundle listing, bounded to 100.
fn list_bundles(state: &RuntimeState) -> (i32, Option<Vec<u8>>) {
    let bundles = state
        .bundle
        .list()
        .into_iter()
        .map(|(id, size, status)| api::BundleSummary {
            bundle_id: id,
            payload_size: u64::try_from(size).unwrap_or(u64::MAX),
            state: bundle_state(&status) as i32,
            ..Default::default()
        })
        .collect();
    let response = api::ListBundlesResponse {
        bundles,
        ..Default::default()
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn bundle_state(status: &BundleStatus) -> api::BundleState {
    match status {
        BundleStatus::Received | BundleStatus::CustodyAccepted => api::BundleState::Stored,
        BundleStatus::Forwarded => api::BundleState::Forwarded,
        BundleStatus::Delivered => api::BundleState::Delivered,
        BundleStatus::Expired => api::BundleState::Expired,
        BundleStatus::Evicted => api::BundleState::Evicted,
        BundleStatus::Rejected => api::BundleState::Rejected,
    }
}

/// `NodeAdmin.GetConfig`: the current node configuration as `ConfigEntry`s
/// (control-api.md §24). The development token is never exposed.
fn get_config(state: &RuntimeState) -> (i32, Option<Vec<u8>>) {
    let config = node_config_message(&state.config);
    let mut payload = Vec::new();
    Message::encode(
        &api::GetConfigResponse {
            config: Some(config),
        },
        &mut payload,
    )
    .expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// The current configuration as the control-surface `NodeConfig` message
/// (control-api.md §24). The development token is never exposed.
fn node_config_message(config: &NodeConfig) -> api::NodeConfig {
    let entries = vec![
        api::ConfigEntry {
            key: "profile".into(),
            value: config.profile.clone(),
            sensitive_present: false,
        },
        api::ConfigEntry {
            key: "public_relay".into(),
            value: config.public_relay.to_string(),
            sensitive_present: false,
        },
        api::ConfigEntry {
            key: "mesh".into(),
            value: config.mesh.to_string(),
            sensitive_present: false,
        },
        api::ConfigEntry {
            key: "telemetry".into(),
            value: config.telemetry.to_string(),
            sensitive_present: false,
        },
        api::ConfigEntry {
            key: "carriers".into(),
            value: config.carriers.join(","),
            sensitive_present: false,
        },
    ];
    api::NodeConfig {
        resource_profile: config.profile.clone(),
        telemetry_enabled: config.telemetry,
        public_relay_enabled: config.public_relay,
        entries,
        ..Default::default()
    }
}

/// `ConfigService.SetConfig`: validate the mutation, persist the config file,
/// and update the in-memory config (control-api.md §24). Only `set_value`
/// mutations of the documented keys are accepted; unsupported keys and
/// secret mutations are `InvalidArgument`. The mutations apply atomically:
/// a failing entry leaves the daemon config untouched.
fn set_config(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(mutation) = api::UpdateConfigRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let mut updated = state.config.clone();
    for change in &mutation.mutations {
        let Some(value) = (match &change.operation {
            Some(api::config_mutation::Operation::SetValue(value)) => Some(value.clone()),
            Some(
                api::config_mutation::Operation::SetSecret(_)
                | api::config_mutation::Operation::Clear(_),
            )
            | None => None,
        }) else {
            return (api::StatusCode::InvalidArgument as i32, None);
        };
        if let Err(e) = updated.set_entry(&change.key, &value) {
            println!("[config] set {}/{} rejected: {e}", change.key, value);
            return (api::StatusCode::InvalidArgument as i32, None);
        }
    }
    if let Err(e) = updated.persist() {
        println!("[config] persist failed: {e}");
        return (api::StatusCode::Internal as i32, None);
    }
    state.config = updated;
    let config = node_config_message(&state.config);
    let mut payload = Vec::new();
    Message::encode(
        &api::UpdateConfigResponse {
            config: Some(config),
            effects: Vec::new(),
        },
        &mut payload,
    )
    .expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `BundleService.CreateBundle`: admit a bundle over the control surface
/// (bundles.md §8.1) and return its id. The chunk upload is treated as the
/// complete bundle payload for now.
fn create_bundle(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(create) = api::CreateBundleRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let now = state.node.clock.as_ref().now();
    let sender = create
        .application_handle
        .as_ref()
        .map(|handle| handle.value.clone())
        .unwrap_or_default();
    let expires_at_ms = u64::try_from(create.expires_at_unix_ms).unwrap_or(now.0);
    let lifetime_ms = expires_at_ms.saturating_sub(now.0).max(1_000);
    match state.bundle.admit(
        &create.payload_chunk,
        &sender,
        &create.destination_hint,
        u64::from(create.priority),
        lifetime_ms,
        umc_bundle::manager::DEFAULT_MAX_REPLICATION,
        false,
        now,
    ) {
        Ok(id) => {
            let record = state.bundle.record(&id).expect("just admitted");
            let summary = api::BundleSummary {
                bundle_id: id.to_vec(),
                owner_endpoint_id: record.sender.clone(),
                destination_hint_hash: umc_bundle::id::bundle_id(
                    &umc_bundle::envelope::BundleEnvelope {
                        sender_ephemeral_public_key: [0u8; 32],
                        encrypted_payload: create.payload_chunk.clone(),
                    },
                    &record.destination_hint,
                )
                .to_vec(),
                state: api::BundleState::Stored as i32,
                payload_size: record.size as u64,
                priority: u32::try_from(record.priority).unwrap_or(u32::MAX),
                created_at_unix_ms: i64::try_from(record.created_at.0).unwrap_or(i64::MAX),
                expires_at_unix_ms: i64::try_from(record.expires_at.0).unwrap_or(i64::MAX),
            };
            let response = api::CreateBundleResponse {
                bundle: Some(summary),
                upload_handle: None,
            };
            let mut payload = Vec::new();
            Message::encode(&response, &mut payload).expect("encode");
            (api::StatusCode::Ok as i32, Some(payload))
        }
        Err(e) => {
            println!("[bundle] create rejected: {e:?}");
            (api::StatusCode::InvalidArgument as i32, None)
        }
    }
}

/// `NodeAdmin.GetEvents`: the bounded recent event log, newest first
/// (core.md §8, control-api.md §38-41).
fn get_events(state: &RuntimeState) -> (i32, Option<Vec<u8>>) {
    let events = state
        .events
        .lock()
        .expect("event log")
        .recent(100)
        .into_iter()
        .map(|event| api::EventRecord {
            kind: event.kind,
            at_ms: i64::try_from(event.at_ms).unwrap_or(i64::MAX),
            detail: event.detail,
        })
        .collect();
    let response = api::GetEventsResponse { events };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `DiagnosticsService.RunDoctor`: the doctor check suite (core.md §43),
/// mapped onto `DiagnosticResult`s.
fn run_doctor(state: &RuntimeState) -> (i32, Option<Vec<u8>>) {
    let results = doctor::run_doctor(&state.config)
        .checks
        .into_iter()
        .map(|check| api::DiagnosticResult {
            check_id: check.name.to_string(),
            severity: if check.passed {
                api::DiagnosticSeverity::Info as i32
            } else {
                api::DiagnosticSeverity::Error as i32
            },
            summary: if check.passed {
                "ok".into()
            } else {
                "failed".into()
            },
            detail: check.detail,
            remediation: Vec::new(),
        })
        .collect();
    let response = api::RunDoctorResponse {
        operation_handle: None,
        results,
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `RelayService.OpenCircuit`: relay admission + circuit allocation.
fn open_circuit(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(open) = OpenCircuitRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let now = state.node.clock.as_ref().now();
    let circuit_request = CircuitOpenRequest {
        peer_circuits: usize::try_from(open.peer_circuits).unwrap_or(usize::MAX),
        requested_lifetime_ms: open.requested_lifetime_ms,
        requested_byte_quota: open.requested_byte_quota,
        flags: u8::try_from(open.flags).unwrap_or(u8::MAX),
        bidirectional: open.bidirectional,
        private_handling: open.private_handling,
        // Control-opened circuits carry no wire destination hint; forwarding
        // targets come from `RELAY_OPEN.next_hop_hint` on session circuits.
        destination_hint: Vec::new(),
    };
    match state.relay.open_circuit(&circuit_request, Vec::new(), now) {
        Ok(result) => {
            let response = OpenCircuitResponse {
                circuit_id: result.circuit_id,
                granted_lifetime_ms: result.granted_lifetime_ms,
                granted_byte_quota: result.granted_byte_quota,
                maximum_relay_payload: u32::try_from(result.maximum_relay_payload)
                    .unwrap_or(u32::MAX),
            };
            let mut payload = Vec::new();
            Message::encode(&response, &mut payload).expect("encode");
            (api::StatusCode::Ok as i32, Some(payload))
        }
        Err(_) => (api::StatusCode::FailedPrecondition as i32, None),
    }
}

/// `RelayService.CloseCircuit`: close by circuit id (relay.md §23-24).
fn close_circuit(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(close) = CloseCircuitRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let now = state.node.clock.as_ref().now();
    match state
        .relay
        .close_circuit(close.circuit_id, close.reason, now)
    {
        Ok(()) => (api::StatusCode::Ok as i32, None),
        Err(_) => (api::StatusCode::NotFound as i32, None),
    }
}

/// Persist node state at shutdown and reload at startup (storage.md §22).
pub fn persist_node_state(store: &SqliteStore, config: &NodeConfig) -> Result<(), String> {
    use umc_storage::store::{Namespace, Store};
    store
        .put(Namespace::Config, b"profile", config.profile.as_bytes())
        .map_err(|e| format!("{e:?}"))?;
    let carriers = serde_json::to_vec(&config.carriers).map_err(|e| e.to_string())?;
    store
        .put(Namespace::Config, b"carriers", &carriers)
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

pub fn load_node_state(store: &SqliteStore) -> Result<(String, Vec<String>), String> {
    use umc_storage::store::{Namespace, Store};
    let profile = store
        .get(Namespace::Config, b"profile")
        .map_err(|e| format!("{e:?}"))?
        .map(|v| String::from_utf8(v).map_err(|_| "invalid profile".to_string()))
        .transpose()?
        .unwrap_or_else(|| "standard".to_string());
    let carriers = store
        .get(Namespace::Config, b"carriers")
        .map_err(|e| format!("{e:?}"))?
        .map(|v| serde_json::from_slice::<Vec<String>>(&v).map_err(|e| e.to_string()))
        .transpose()?
        .unwrap_or_default();
    Ok((profile, carriers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_state() -> (RuntimeState, tokio::sync::mpsc::Sender<()>) {
        let dir = std::env::temp_dir().join(format!(
            "umcd-server-state-{}-{}",
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
        (state, tx)
    }

    fn request(service: &str, method: &str, payload: Vec<u8>) -> api::Request {
        api::Request {
            request_id: 1,
            service: service.to_string(),
            method: method.to_string(),
            payload,
            ..Default::default()
        }
    }

    fn decode_response(bytes: &[u8]) -> api::Response {
        let envelope = api::Envelope::decode(bytes).expect("envelope");
        match envelope.body {
            Some(api::envelope::Body::Response(response)) => response,
            _ => panic!("expected a response envelope"),
        }
    }

    #[tokio::test]
    async fn get_status_reports_real_counts() {
        let (mut state, _tx) = test_state();
        let bytes = dispatch_request(&mut state, &request("NodeAdmin", "GetStatus", vec![]), None);
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let status = api::GetStatusResponse::decode(response.payload.as_slice())
            .expect("payload")
            .status
            .expect("status");
        assert_eq!(status.active_sessions, 0);
        assert_eq!(status.active_relay_circuits, 0);
        // Register a session; the count moves.
        state.sessions.register(
            state.sessions.next_id(),
            crate::session_manager::SessionEntry {
                peer_endpoint_id: [1u8; 32],
                carrier_type: "ump.tcp/1".into(),
                task: tokio::spawn(async {}).abort_handle(),
                established_at_ms: 0,
            },
        );
        let bytes = dispatch_request(&mut state, &request("NodeAdmin", "GetStatus", vec![]), None);
        let response = decode_response(&bytes);
        let status = api::GetStatusResponse::decode(response.payload.as_slice())
            .expect("payload")
            .status
            .expect("status");
        assert_eq!(status.active_sessions, 1);
    }

    #[test]
    fn dispatcher_open_and_close_circuit() {
        let (mut state, _tx) = test_state();
        let open = OpenCircuitRequest {
            requested_lifetime_ms: 600_000,
            requested_byte_quota: 1_048_576,
            flags: 0,
            bidirectional: true,
            private_handling: false,
            peer_circuits: 0,
        };
        let mut payload = Vec::new();
        Message::encode(&open, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("RelayService", "OpenCircuit", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let granted = OpenCircuitResponse::decode(response.payload.as_slice()).expect("payload");
        assert_eq!(granted.granted_lifetime_ms, 600_000);

        let close = CloseCircuitRequest {
            circuit_id: granted.circuit_id,
            reason: 0,
        };
        let mut payload = Vec::new();
        Message::encode(&close, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("RelayService", "CloseCircuit", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Ok as i32
        );

        // Unknown circuit id is a NotFound, not Ok.
        let unknown = CloseCircuitRequest {
            circuit_id: 999,
            reason: 0,
        };
        let mut payload = Vec::new();
        Message::encode(&unknown, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("RelayService", "CloseCircuit", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
    }

    #[test]
    fn unknown_methods_are_unimplemented() {
        let (mut state, _tx) = test_state();
        let bytes = dispatch_request(
            &mut state,
            &request("NodeAdmin", "NoSuchMethod", vec![]),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Unimplemented as i32
        );
    }

    #[test]
    fn set_config_validates_persists_and_applies() {
        let (mut state, _tx) = test_state();
        // A malformed payload is not a valid mutation set.
        let bytes = dispatch_request(
            &mut state,
            &request("ConfigService", "SetConfig", b"not-prost".to_vec()),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::InvalidArgument as i32
        );

        let mutations = api::UpdateConfigRequest {
            mutations: vec![
                api::ConfigMutation {
                    key: "profile".into(),
                    operation: Some(api::config_mutation::Operation::SetValue("relay".into())),
                },
                api::ConfigMutation {
                    key: "mesh".into(),
                    operation: Some(api::config_mutation::Operation::SetValue("true".into())),
                },
            ],
            ..Default::default()
        };
        let mut payload = Vec::new();
        Message::encode(&mutations, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("ConfigService", "SetConfig", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let updated = api::UpdateConfigResponse::decode(response.payload.as_slice())
            .expect("payload")
            .config
            .expect("config");
        assert_eq!(updated.resource_profile, "relay");

        // The in-memory config updated and the file persists: a fresh load
        // sees the same values.
        assert_eq!(state.config.profile, "relay");
        assert!(state.config.mesh);
        let reloaded = NodeConfig::load(Some(&state.config.resolved_config_path())).unwrap();
        assert_eq!(reloaded.profile, "relay");
        assert!(reloaded.mesh);
    }

    #[test]
    fn set_config_rejects_bad_values_atomically() {
        let (mut state, _tx) = test_state();
        let mutations = api::UpdateConfigRequest {
            mutations: vec![api::ConfigMutation {
                key: "profile".into(),
                operation: Some(api::config_mutation::Operation::SetValue("bogus".into())),
            }],
            ..Default::default()
        };
        let mut payload = Vec::new();
        Message::encode(&mutations, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("ConfigService", "SetConfig", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::InvalidArgument as i32
        );
        assert_eq!(
            state.config.profile, "standard",
            "rejected set leaves config untouched"
        );

        // Unsupported keys are InvalidArgument too.
        let mutations = api::UpdateConfigRequest {
            mutations: vec![api::ConfigMutation {
                key: "no_such_key".into(),
                operation: Some(api::config_mutation::Operation::SetValue("1".into())),
            }],
            ..Default::default()
        };
        let mut payload = Vec::new();
        Message::encode(&mutations, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("ConfigService", "SetConfig", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::InvalidArgument as i32
        );
    }

    #[test]
    fn create_bundle_round_trips_through_list() {
        let (mut state, _tx) = test_state();
        let now_ms = state.node.clock.as_ref().now().0;
        let create = api::CreateBundleRequest {
            application_handle: Some(api::OpaqueHandle {
                value: b"sender-a".to_vec(),
            }),
            destination_hint: b"dest-token".to_vec(),
            priority: 1,
            // The node clock is monotonic; the handler compares against it.
            expires_at_unix_ms: i64::try_from(now_ms + 60_000).unwrap(),
            payload_chunk: b"ciphertext".to_vec(),
            payload_complete: true,
            upload_handle: None,
        };
        let mut payload = Vec::new();
        Message::encode(&create, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("BundleService", "CreateBundle", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let created = api::CreateBundleResponse::decode(response.payload.as_slice())
            .expect("payload")
            .bundle
            .expect("bundle");
        assert_eq!(created.payload_size, 10);
        assert_eq!(created.bundle_id.len(), 32);

        // The id round-trips through ListBundles.
        let bytes = dispatch_request(
            &mut state,
            &request("BundleService", "ListBundles", vec![]),
            None,
        );
        let listing = api::ListBundlesResponse::decode(decode_response(&bytes).payload.as_slice())
            .expect("payload")
            .bundles;
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].bundle_id, created.bundle_id);
    }

    #[test]
    fn list_bundles_round_trip() {
        let (mut state, _tx) = test_state();
        let now = state.node.clock.as_ref().now();
        state
            .bundle
            .admit(
                b"payload",
                b"sender-a",
                b"dest-hint",
                1,
                umc_bundle::manager::DEFAULT_LIFETIME_MS,
                3,
                false,
                now,
            )
            .unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("BundleService", "ListBundles", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let listing = api::ListBundlesResponse::decode(response.payload.as_slice())
            .expect("payload")
            .bundles;
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].payload_size, 7);
    }

    #[test]
    fn list_candidates_round_trip() {
        let (mut state, _tx) = test_state();
        state
            .discovery
            .record_candidate(
                umc_discovery::provider::PeerCandidate {
                    candidate_id: 42,
                    carrier_type: "ump.udp/1".into(),
                    connection_hint: vec![],
                    source: umc_discovery::provider::CandidateSource::PeerHint,
                    created_at: state.node.clock.as_ref().now(),
                    expires_at: state.node.clock.as_ref().now(),
                    sharing_policy: umc_discovery::provider::SharingPolicy::ShareGeneral,
                    authentication: umc_discovery::provider::CandidateAuth::Unauthenticated,
                    local: false,
                },
                state.node.clock.as_ref().now(),
            )
            .unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "ListCandidates", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let listing = ListCandidatesResponse::decode(response.payload.as_slice()).expect("payload");
        assert_eq!(listing.total, 1);
        assert_eq!(listing.candidates[0].candidate_id, 42);
    }

    #[test]
    fn proto_round_trip() {
        let hello = api::ClientHello {
            supported_versions: vec![api::ApiVersion { major: 1, minor: 0 }],
            ..Default::default()
        };
        let envelope = api::Envelope {
            api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
            sequence: 1,
            body: Some(api::envelope::Body::ClientHello(hello)),
        };
        let mut bytes = Vec::new();
        Message::encode(&envelope, &mut bytes).unwrap();
        let decoded = api::Envelope::decode(bytes.as_slice()).unwrap();
        assert!(matches!(
            decoded.body,
            Some(api::envelope::Body::ClientHello(_))
        ));
    }

    #[test]
    fn node_state_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("umcd-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.db");
        let _ = std::fs::remove_file(&path);
        let store = SqliteStore::open(&path).unwrap();
        let config = NodeConfig {
            profile: "relay".to_string(),
            carriers: vec!["ump.udp/1".to_string()],
            ..Default::default()
        };
        persist_node_state(&store, &config).unwrap();
        drop(store);

        let reopened = SqliteStore::open(&path).unwrap();
        let (profile, carriers) = load_node_state(&reopened).unwrap();
        assert_eq!(profile, "relay");
        assert_eq!(carriers, vec!["ump.udp/1"]);
    }

    #[test]
    fn get_config_reports_current_entries() {
        let (mut state, _tx) = test_state();
        state.config.profile = "relay".into();
        state.config.carriers = vec!["ump.udp/1".into()];
        let bytes = dispatch_request(&mut state, &request("NodeAdmin", "GetConfig", vec![]), None);
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let config = api::GetConfigResponse::decode(response.payload.as_slice())
            .expect("payload")
            .config
            .expect("config");
        assert_eq!(config.resource_profile, "relay");
        assert!(config
            .entries
            .iter()
            .any(|e| e.key == "profile" && e.value == "relay"));
        assert!(config
            .entries
            .iter()
            .any(|e| e.key == "carriers" && e.value == "ump.udp/1"));
        assert!(config.entries.iter().any(|e| e.key == "public_relay"));
    }

    #[test]
    fn get_events_returns_recent_log() {
        let (mut state, _tx) = test_state();
        state
            .events
            .lock()
            .expect("event log")
            .push(crate::event_log::DaemonEvent {
                kind: "session_active".into(),
                at_ms: 7,
                detail: "session 1".into(),
            });
        let bytes = dispatch_request(&mut state, &request("NodeAdmin", "GetEvents", vec![]), None);
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let events = api::GetEventsResponse::decode(response.payload.as_slice())
            .expect("payload")
            .events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "session_active");
        assert_eq!(events[0].at_ms, 7);
    }

    #[test]
    fn discovery_alias_and_doctor_round_trip() {
        let (mut state, _tx) = test_state();
        let bytes = dispatch_request(
            &mut state,
            &request("DiscoveryService", "ListCandidates", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        assert!(ListCandidatesResponse::decode(response.payload.as_slice())
            .expect("payload")
            .candidates
            .is_empty());

        let bytes = dispatch_request(
            &mut state,
            &request("DiagnosticsService", "RunDoctor", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let results = api::RunDoctorResponse::decode(response.payload.as_slice())
            .expect("payload")
            .results;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.check_id == "database"));
    }

    #[test]
    fn development_token_gates_requests() {
        let (mut state, _tx) = test_state();
        state.development_token = Some(b"dev-token".to_vec());
        // No credential presented: rejected before dispatch.
        let bytes = dispatch_request(&mut state, &request("NodeAdmin", "GetStatus", vec![]), None);
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Unauthenticated as i32
        );
        // Wrong credential: rejected.
        let bytes = dispatch_request(
            &mut state,
            &request("NodeAdmin", "GetStatus", vec![]),
            Some(b"wrong".as_slice()),
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Unauthenticated as i32
        );
        // Matching credential: dispatched.
        let bytes = dispatch_request(
            &mut state,
            &request("NodeAdmin", "GetStatus", vec![]),
            Some(b"dev-token".as_slice()),
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Ok as i32
        );
    }

    #[test]
    fn no_token_configured_accepts_anonymous_requests() {
        let (mut state, _tx) = test_state();
        let bytes = dispatch_request(&mut state, &request("NodeAdmin", "GetStatus", vec![]), None);
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Ok as i32
        );
    }

    #[tokio::test]
    async fn concurrent_control_connection_cap_enforced() {
        let (state, _tx) = test_state();
        let state = Arc::new(Mutex::new(state));
        let connections = Arc::new(tokio::sync::Semaphore::new(MAX_CONTROL_CONNECTIONS));
        // Fill the cap: every admitted connection holds a permit while its
        // peer end stays open.
        let mut peers = Vec::new();
        for _ in 0..MAX_CONTROL_CONNECTIONS {
            let (stream, peer) = UnixStream::pair().expect("pair");
            peers.push(peer);
            assert!(
                admit_connection(&connections, stream, state.clone()),
                "connection {MAX_CONTROL_CONNECTIONS} within cap must be admitted"
            );
        }
        // The 65th connection is refused while the cap is full.
        let (stream, peer) = UnixStream::pair().expect("pair");
        assert!(
            !admit_connection(&connections, stream, state.clone()),
            "65th control connection must be refused"
        );
        drop(peer);
        // Closing one admitted connection releases its permit; the next is
        // admitted. `peers` holds the peer ends of the 64 admitted
        // connections; dropping one delivers EOF and ends its task.
        peers.pop();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if connections.clone().try_acquire_owned().is_ok() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("permit released after connection close");
        let (stream, peer) = UnixStream::pair().expect("pair");
        peers.push(peer);
        assert!(admit_connection(&connections, stream, state.clone()));
    }
}
