//! Control socket server: Unix stream socket, framing, connection handling,
//! and the service-backed envelope dispatcher (control-api.md §16-24).
use crate::config::NodeConfig;
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
                    tokio::spawn(handle_connection(stream, state));
                }
            }
        }
    }
    let _ = std::fs::remove_file(&socket_path);
    println!("control socket: closed");
}

async fn handle_connection(mut stream: UnixStream, state: Arc<Mutex<RuntimeState>>) {
    let mut decoder = EnvelopeDecoder::new(DEFAULT_ENVELOPE_MAX);
    let mut buf = [0u8; 8 * 1024];
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
                        handle_hello(&hello, &state.store)
                    }
                    Some(api::envelope::Body::Request(request)) => {
                        dispatch_request(&mut state, &request)
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
fn dispatch_request(state: &mut RuntimeState, request: &api::Request) -> Vec<u8> {
    let (code, payload) = match (request.service.as_str(), request.method.as_str()) {
        ("NodeAdmin", "GetStatus") => get_status(state),
        ("PeerService", "ListCandidates") => list_candidates(state),
        ("BundleService", "GetBundles" | "ListBundles") => list_bundles(state),
        ("RelayService", "OpenCircuit") => open_circuit(state, request),
        ("RelayService", "CloseCircuit") => close_circuit(state, request),
        _ => (api::StatusCode::Unimplemented as i32, None),
    };
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
    };
    match state.relay.open_circuit(&circuit_request, now) {
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
        let bytes = dispatch_request(&mut state, &request("NodeAdmin", "GetStatus", vec![]));
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
                task: tokio::spawn(async {}),
            },
        );
        let bytes = dispatch_request(&mut state, &request("NodeAdmin", "GetStatus", vec![]));
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
        let bytes = dispatch_request(&mut state, &request("RelayService", "OpenCircuit", payload));
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
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
    }

    #[test]
    fn unknown_methods_are_unimplemented() {
        let (mut state, _tx) = test_state();
        let bytes = dispatch_request(&mut state, &request("NodeAdmin", "GetConfig", vec![]));
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Unimplemented as i32
        );
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
        let bytes = dispatch_request(&mut state, &request("BundleService", "ListBundles", vec![]));
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
}
