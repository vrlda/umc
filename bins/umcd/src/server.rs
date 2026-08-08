//! Control socket server: Unix stream socket, framing, connection handling,
//! and the service-backed envelope dispatcher (control-api.md §16-24).
use crate::config::NodeConfig;
use crate::doctor;
use crate::relay_service::CircuitOpenRequest;
use crate::runtime_adapters::OsEntropy;
use crate::state::{metric_names, wall_now, RuntimeState};
use prost::Message;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use umc_bundle::manager::BundleStatus;
use umc_control::conn::SequenceTracker;
use umc_control::framing::{frame_envelope, EnvelopeDecoder};
use umc_control::pages::PageToken;
use umc_control::proto::umc::api::v1 as api;
use umc_storage::sqlite::SqliteStore;

const DEFAULT_ENVELOPE_MAX: usize = 4 * 1024 * 1024;

/// Concurrent control connections are capped (control-api.md §16): the 65th
/// connection is refused until an earlier one closes.
pub const MAX_CONTROL_CONNECTIONS: usize = 64;

/// Idempotency replay retention (control-api.md §18): the gap-closure plan
/// calls for 10 minutes; the spec's 24-hour retention needs the persistent
/// store that lands in a later phase.
const IDEMPOTENCY_TTL_MS: u64 = 10 * 60 * 1000;
/// Idempotency replay entries retained per connection (bounded FIFO).
const IDEMPOTENCY_CACHE_CAP: usize = 1_024;
/// Default list page size (control-api.md §37).
const DEFAULT_PAGE_SIZE: usize = 100;
/// Page-size cap for list methods (task F1): tighter than the spec's
/// hard maximum of 1,000.
const MAX_PAGE_SIZE: usize = 100;

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
    log::info!("data directory: {}", data_dir.display());

    if let Ok((profile, carriers)) = load_node_state(&store) {
        log::info!(
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
    // OS peer-credential authorization (control-api.md §11.1): the daemon's
    // uid is the control socket's owner — the daemon bound it (std has no
    // geteuid, so the socket owner stands in for the daemon's uid; the two
    // differ only for a setuid daemon, which umcd does not support).
    let daemon_uid = std::os::unix::fs::MetadataExt::uid(
        &std::fs::metadata(&socket_path).expect("control socket metadata"),
    );
    log::info!("control socket: {}", socket_path.display());
    log::info!("node initialized");

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
                    if !admit_connection(&connections, stream, state, daemon_uid) {
                        log::warn!("control socket: connection refused (cap {MAX_CONTROL_CONNECTIONS})");
                    }
                }
            }
        }
    }
    let _ = std::fs::remove_file(&socket_path);
    log::info!("control socket: closed");
}

/// Admit one control connection under the concurrent-connection cap. The
/// permit is held for the connection's lifetime; returns `false` when the
/// cap is reached and the connection is refused.
fn admit_connection(
    connections: &Arc<tokio::sync::Semaphore>,
    stream: UnixStream,
    state: Arc<Mutex<RuntimeState>>,
    daemon_uid: u32,
) -> bool {
    let Ok(permit) = connections.clone().try_acquire_owned() else {
        return false;
    };
    tokio::spawn(handle_connection(stream, state, permit, daemon_uid));
    true
}

async fn handle_connection(
    mut stream: UnixStream,
    state: Arc<Mutex<RuntimeState>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    daemon_uid: u32,
) {
    // OS peer-credential authorization (control-api.md §11.1): the peer uid
    // on the Unix control socket must equal the daemon's uid; any other
    // local user's connection is refused before any envelope is read. The
    // control socket is always a Unix stream socket (config.rs
    // `control_socket`), so no TCP or non-Unix path exists to skip; a
    // hypothetical loopback-TCP transport would have to bypass this check
    // (control-api.md §48.7 — loopback TCP lacks peer credentials).
    if !os_peer_authorized(&stream, daemon_uid) {
        log::warn!("control socket: peer uid mismatch, refusing connection");
        return;
    }
    let mut decoder = EnvelopeDecoder::new(DEFAULT_ENVELOPE_MAX);
    let mut buf = [0u8; 8 * 1024];
    let mut conn = ConnectionState::new();
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
                handle_envelope(&mut conn, &mut state, msg)
            };
            let Some(response) = response else {
                continue;
            };
            let mut out = Vec::new();
            if frame_envelope(&mut out, &response, DEFAULT_ENVELOPE_MAX).is_ok() {
                let _ = stream.write_all(&out).await;
            }
        }
        if conn.draining {
            // GoAway: the current batch drained; close the connection
            // (control-api.md §6.4).
            log::info!("[control] connection drained after go-away, closing");
            break;
        }
    }
}

/// Unix-socket peer-credential check (control-api.md §11.1): the peer must
/// report the daemon's uid via `SO_PEERCRED` (tokio `peer_cred`).
fn os_peer_authorized(stream: &UnixStream, daemon_uid: u32) -> bool {
    match stream.peer_cred() {
        Ok(peer) => peer.uid() == daemon_uid,
        Err(_) => false,
    }
}

/// Per-connection control protocol state (control-api.md §6-7): the
/// credential presented at hello, the per-connection envelope sequence
/// tracker, the draining flag set by a peer `GoAway`, and the bounded
/// idempotency replay cache. Dispatch is strictly sequential — one
/// envelope at a time — so `Cancel` and `GoAway` can only arrive between
/// requests.
#[derive(Debug)]
struct ConnectionState {
    presented_token: Option<Vec<u8>>,
    sequences: SequenceTracker,
    draining: bool,
    idempotent: IdempotencyCache,
}

impl ConnectionState {
    #[must_use]
    fn new() -> Self {
        Self {
            presented_token: None,
            sequences: SequenceTracker::new(),
            draining: false,
            idempotent: IdempotencyCache::new(),
        }
    }
}

/// Bounded per-connection idempotency replay cache (control-api.md §18):
/// `(request_id, idempotency_key)` → stored response bytes, 10-minute TTL,
/// FIFO eviction at 1,024 entries. A replay returns the stored bytes
/// without re-dispatching.
#[derive(Debug, Default)]
/// Idempotency key: (service, method, client key) — scoped per
/// control-api.md §18.
type IdempotencyKey = (String, String, Vec<u8>);

struct IdempotencyCache {
    entries: HashMap<IdempotencyKey, (Vec<u8>, u64)>,
    order: VecDeque<IdempotencyKey>,
}

impl IdempotencyCache {
    #[must_use]
    fn new() -> Self {
        Self::default()
    }

    /// Store `response` for `key` stamped at `now_ms`; re-keying an existing
    /// entry refreshes it, otherwise the oldest entry is evicted once the
    /// FIFO cap is exceeded.
    fn insert(&mut self, key: (String, String, Vec<u8>), response: Vec<u8>, now_ms: u64) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.0 = response;
            entry.1 = now_ms;
            return;
        }
        self.entries.insert(key.clone(), (response, now_ms));
        self.order.push_back(key);
        while self.order.len() > IDEMPOTENCY_CACHE_CAP {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    /// The stored bytes for `key` when it is fresh at `now_ms`.
    fn get(&self, key: &IdempotencyKey, now_ms: u64) -> Option<Vec<u8>> {
        let (response, inserted_at) = self.entries.get(key)?;
        (now_ms < inserted_at + IDEMPOTENCY_TTL_MS).then(|| response.clone())
    }
}

/// Handle one decoded envelope on a connection. Returns the response bytes
/// to write back, or `None` when the envelope is dropped or produces no
/// response.
///
/// Envelope sequences must be monotonic per connection (control-api.md §7):
/// zero, reuse, or decrease drops the envelope silently (task F1 — the
/// spec's close-on-conflict is softened because sequential dispatch makes
/// conflicts harmless).
///
/// `Cancel` is a logged no-op: dispatch is sequential, so the request it
/// targets already completed (control-api.md §21). `GoAway` sets the
/// draining flag — later requests fail with `Unavailable` and the
/// connection closes after the current batch.
fn handle_envelope(
    conn: &mut ConnectionState,
    state: &mut RuntimeState,
    envelope: api::Envelope,
) -> Option<Vec<u8>> {
    if conn.sequences.observe(envelope.sequence).is_err() {
        log::debug!(
            "[control] dropped envelope with sequence {}",
            envelope.sequence
        );
        return None;
    }
    match envelope.body {
        Some(api::envelope::Body::ClientHello(hello)) => {
            conn.presented_token = hello_token(&hello);
            Some(handle_hello(&hello, &state.store))
        }
        Some(api::envelope::Body::Request(request)) => {
            if conn.draining {
                // GoAway received: new requests fail (control-api.md §6.4).
                return Some(response_envelope(
                    &request,
                    api::StatusCode::Unavailable as i32,
                    None,
                ));
            }
            if !request.idempotency_key.is_empty() {
                // Scoped per control-api.md §18: service+method+key, so the
                // same key on a different method cannot replay another
                // method's response.
                let key = (
                    request.service.clone(),
                    request.method.clone(),
                    request.idempotency_key.clone(),
                );
                let now_ms = wall_now().0;
                if let Some(stored) = conn.idempotent.get(&key, now_ms) {
                    log::debug!(
                        "[control] idempotent replay for request {}",
                        request.request_id
                    );
                    return Some(stored);
                }
                let response = dispatch_request(state, &request, conn.presented_token.as_deref());
                conn.idempotent.insert(key, response.clone(), now_ms);
                return Some(response);
            }
            Some(dispatch_request(
                state,
                &request,
                conn.presented_token.as_deref(),
            ))
        }
        Some(api::envelope::Body::Cancel(cancel)) => {
            // Sequential dispatch makes cancellation moot (control-api.md
            // §21): the targeted request completed before this envelope was
            // read. Logged, never answered.
            log::debug!(
                "[control] cancel for request {} ignored (sequential dispatch)",
                cancel.request_id
            );
            None
        }
        Some(api::envelope::Body::GoAway(go_away)) => {
            log::info!(
                "[control] go-away received (reason {}): draining",
                go_away.reason
            );
            conn.draining = true;
            None
        }
        _ => None,
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
    // One request counter per service (core.md §42): the name is flat, the
    // service distinction is baked into it.
    let service_counter = match request.service.as_str() {
        "NodeAdmin" => metric_names::CONTROL_REQUESTS_NODEADMIN,
        "PeerService" | "DiscoveryService" => metric_names::CONTROL_REQUESTS_PEERSERVICE,
        "BundleService" => metric_names::CONTROL_REQUESTS_BUNDLE,
        "RelayService" => metric_names::CONTROL_REQUESTS_RELAY,
        "SessionService" => metric_names::CONTROL_REQUESTS_SESSION,
        "RouteService" => metric_names::CONTROL_REQUESTS_ROUTE,
        "ConfigService" => metric_names::CONTROL_REQUESTS_CONFIG,
        "DiagnosticsService" => metric_names::CONTROL_REQUESTS_DIAGNOSTICS,
        _ => metric_names::CONTROL_REQUESTS_OTHER,
    };
    state.metrics.incr(service_counter, 1);
    let (code, payload) = match (request.service.as_str(), request.method.as_str()) {
        ("NodeAdmin", "GetStatus") => get_status(state),
        ("PeerService" | "DiscoveryService", "ListCandidates") => list_candidates(state),
        ("PeerService", "ListPeers") => list_peers(state, request),
        ("SessionService", "ListSessions") => list_sessions(state, request),
        ("SessionService", "GetSession") => get_session(state, request),
        ("RouteService", "ListRoutes") => list_routes(state, request),
        ("BundleService", "GetBundles" | "ListBundles") => list_bundles(state, request),
        ("BundleService", "CreateBundle") => create_bundle(state, request),
        ("RelayService", "OpenCircuit") => open_circuit(state, request),
        ("RelayService", "CloseCircuit") => close_circuit(state, request),
        ("NodeAdmin" | "ConfigService", "GetConfig") => get_config(state),
        ("NodeAdmin", "GetEvents") => get_events(state),
        ("DiagnosticsService" | "NodeAdmin", "RunDoctor" | "Doctor") => run_doctor(state),
        ("DiagnosticsService", "GetMetricsSnapshot") => get_metrics_snapshot(state, request),
        ("DiagnosticsService", "GetSubsystemHealth") => get_subsystem_health(state, request),
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

/// Resolve the `(offset, page_size)` window for one list request
/// (control-api.md §37): `page_size` 0 means the default, anything above
/// the cap is clamped to 100, and the offset comes from the validated page
/// token — bound to the placeholder principal 0 (no principal model exists
/// yet) and the method name, expiring after 5 minutes.
fn page_window(page: Option<&api::PageRequest>, method: &str) -> Result<(usize, usize), ()> {
    let page = page.cloned().unwrap_or_default();
    let page_size = if page.page_size == 0 {
        DEFAULT_PAGE_SIZE
    } else {
        usize::try_from(page.page_size).unwrap_or(DEFAULT_PAGE_SIZE)
    }
    .min(MAX_PAGE_SIZE);
    if page.page_token.is_empty() {
        return Ok((0, page_size));
    }
    let token = PageToken::decode(&page.page_token).ok_or(())?;
    if !token.validate(0, method, wall_now().0) {
        return Err(());
    }
    let offset = usize::try_from(token.offset).unwrap_or(usize::MAX);
    Ok((offset, page_size))
}

/// `PageInfo` for a windowed result (control-api.md §37): a fresh
/// `next_page_token` when more items follow, the total as the size hint.
fn page_info(total: usize, offset: usize, page_size: usize, method: &str) -> api::PageInfo {
    let next_page_token = if offset.saturating_add(page_size) < total {
        PageToken::issue(
            u64::try_from(offset.saturating_add(page_size)).unwrap_or(u64::MAX),
            0,
            method,
            wall_now().0,
            &OsEntropy,
        )
        .encode()
    } else {
        Vec::new()
    };
    api::PageInfo {
        next_page_token,
        snapshot_token: Vec::new(),
        total_size_hint: u64::try_from(total).unwrap_or(u64::MAX),
    }
}

/// `PeerService.ListPeers`: the discovery candidate table snapshot
/// (discovery.md §6) as the v1 peer table. The candidate id is the peer's
/// provisional id; the carrier type doubles as the label. Paginated
/// (control-api.md §37).
fn list_peers(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(list) = api::ListPeersRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok((offset, page_size)) = page_window(list.page.as_ref(), "ListPeers") else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let all: Vec<_> = state.discovery.candidates();
    let total = all.len();
    let peers = all
        .into_iter()
        .skip(offset)
        .take(page_size)
        .map(|candidate| api::PeerSummary {
            endpoint_id: candidate.candidate_id.to_be_bytes().to_vec(),
            label: candidate.carrier_type.clone(),
            trust_state: api::TrustState::Observed as i32,
            last_seen_unix_ms: i64::try_from(candidate.expires_at.0).unwrap_or(i64::MAX),
            carrier_hint_count: 1,
            ..Default::default()
        })
        .collect();
    let response = api::ListPeersResponse {
        peers,
        page: Some(page_info(total, offset, page_size, "ListPeers")),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `SessionService.ListSessions`: the live session registry (core.md §9.5).
/// The v1 registry tracks the carrier a session rides on, not a separate
/// protocol id, so the carrier type rides in `protocol_id`. Paginated
/// (control-api.md §37).
fn list_sessions(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(list) = api::ListSessionsRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok((offset, page_size)) = page_window(list.page.as_ref(), "ListSessions") else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let all = state.sessions.snapshot();
    let total = all.len();
    let sessions = all
        .into_iter()
        .skip(offset)
        .take(page_size)
        .map(|(id, entry)| session_summary(id, &entry))
        .collect();
    let response = api::ListSessionsResponse {
        sessions,
        page: Some(page_info(total, offset, page_size, "ListSessions")),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `SessionService.GetSession`: one registry entry by handle. Unknown
/// handles are `NotFound`.
fn get_session(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(get) = api::GetSessionRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(session_id) = get
        .session_handle
        .as_ref()
        .and_then(|handle| <[u8; 8]>::try_from(handle.value.as_slice()).ok())
        .map(u64::from_be_bytes)
    else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(entry) = state.sessions.lookup(session_id) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let response = api::GetSessionResponse {
        session: Some(session_summary(session_id, &entry)),
        // The v1 registry does not track per-path state; the summary only.
        paths: Vec::new(),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// One `SessionSummary` from a registry entry (core.md §9.5): the session
/// id as the opaque handle, the peer endpoint id, the carrier as
/// `protocol_id` (see [`list_sessions`]), and the established-at stamp.
fn session_summary(id: u64, entry: &crate::session_manager::SessionEntry) -> api::SessionSummary {
    api::SessionSummary {
        session_handle: Some(api::OpaqueHandle {
            value: id.to_be_bytes().to_vec(),
        }),
        remote_endpoint_id: entry.peer_endpoint_id.to_vec(),
        state: api::SessionState::Active as i32,
        protocol_id: entry.carrier_type.clone(),
        active_paths: 1,
        created_at_unix_ms: i64::try_from(entry.established_at_ms).unwrap_or(i64::MAX),
        ..Default::default()
    }
}

/// `RouteService.ListRoutes`: the persisted route snapshots (storage.md
/// §15.1) — the same table the cache restores from at startup (§15.2), so
/// restored routes list as `candidate` until revalidated. Paginated
/// (control-api.md §37).
fn list_routes(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(list) = api::ListRoutesRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok((offset, page_size)) = page_window(list.page.as_ref(), "ListRoutes") else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let snapshots = match umc_storage::records::list_routes(state.store.as_ref()) {
        Ok(snapshots) => snapshots,
        Err(e) => {
            log::error!("[routing] route listing failed: {e:?}");
            return (api::StatusCode::Internal as i32, None);
        }
    };
    let total = snapshots.len();
    let routes = snapshots
        .into_iter()
        .skip(offset)
        .take(page_size)
        .map(|snapshot| api::RouteSummary {
            route_handle: Some(api::OpaqueHandle {
                value: snapshot.key_hash.clone(),
            }),
            destination_hint_hash: snapshot.key_hash,
            scope: route_scope_from_u8(snapshot.scope),
            state: "candidate".into(),
            // The proto has no next-hop field; the hop label rides in
            // `carrier_class` (the v1 snapshot's only other string field).
            carrier_class: String::from_utf8_lossy(&snapshot.next_hop).into_owned(),
            expires_at_unix_ms: i64::try_from(
                snapshot.learned_at_ms.saturating_add(snapshot.lifetime_ms),
            )
            .unwrap_or(i64::MAX),
            ..Default::default()
        })
        .collect();
    let response = api::ListRoutesResponse {
        routes,
        page: Some(page_info(total, offset, page_size, "ListRoutes")),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// Stable route-scope encoding (storage.md §15.1), matching the variant
/// order declared in `umc-routing` `types.rs` (see `scope_from_u8` in
/// `routing_service.rs`).
fn route_scope_from_u8(scope: u8) -> i32 {
    match scope {
        0 => api::RouteScope::LinkLocal as i32,
        1 => api::RouteScope::LocalMesh as i32,
        2 => api::RouteScope::Introduced as i32,
        3 => api::RouteScope::General as i32,
        _ => api::RouteScope::Unspecified as i32,
    }
}

/// `BundleService.ListBundles`: bundle listing, bounded to 100 per page
/// (control-api.md §37).
fn list_bundles(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(list) = api::ListBundlesRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok((offset, page_size)) = page_window(list.page.as_ref(), "ListBundles") else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let all: Vec<_> = state.bundle.list();
    let total = all.len();
    let bundles = all
        .into_iter()
        .skip(offset)
        .take(page_size)
        .map(|(id, size, status)| api::BundleSummary {
            bundle_id: id,
            payload_size: u64::try_from(size).unwrap_or(u64::MAX),
            state: bundle_state(&status) as i32,
            ..Default::default()
        })
        .collect();
    let response = api::ListBundlesResponse {
        bundles,
        page: Some(page_info(total, offset, page_size, "ListBundles")),
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
            key: "telemetry_enabled".into(),
            value: config.telemetry_enabled.to_string(),
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
        telemetry_enabled: config.telemetry_enabled,
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
            log::warn!("[config] set {}/{} rejected: {e}", change.key, value);
            return (api::StatusCode::InvalidArgument as i32, None);
        }
    }
    if let Err(e) = updated.persist() {
        log::error!("[config] persist failed: {e}");
        return (api::StatusCode::Internal as i32, None);
    }
    let telemetry_now_enabled = updated.telemetry_enabled && !state.config.telemetry_enabled;
    state.config = updated;
    // core.md §61: telemetry is opt-in at runtime too — flipping the flag
    // via SetConfig spawns the dump task reactively (disable = config-file
    // restart; the flag is forced false on load).
    if telemetry_now_enabled {
        crate::telemetry::spawn_telemetry_dump_no_clock(
            state.metrics.clone(),
            state.config.resolved_data_dir().join("telemetry.jsonl"),
        );
        log::info!(
            "[telemetry] enabled (reactive SetConfig) → {}",
            state
                .config
                .resolved_data_dir()
                .join("telemetry.jsonl")
                .display()
        );
    }
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
    let now = crate::state::wall_now();
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
            state.metrics.incr(metric_names::BUNDLES_ADMITTED, 1);
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
            log::warn!("[bundle] create rejected: {e:?}");
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

/// `DiagnosticsService.GetMetricsSnapshot`: the metrics registry snapshot
/// as `MetricPoint`s (core.md §42, control-api.md §42). A non-empty
/// `metric_prefixes` list filters the series by name prefix.
// Counters ride the proto's `double` value field; u64 counters beyond 2^53
// lose precision there, which the daemon's counters never approach.
#[allow(clippy::cast_precision_loss)]
fn get_metrics_snapshot(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let prefixes = match api::GetMetricsSnapshotRequest::decode(request.payload.as_slice()) {
        Ok(re) => re.metric_prefixes,
        Err(_) => return (api::StatusCode::InvalidArgument as i32, None),
    };
    let now = crate::state::wall_now();
    let points = state
        .metrics
        .snapshot()
        .into_iter()
        .filter(|(name, _)| prefixes.is_empty() || prefixes.iter().any(|p| name.starts_with(p)))
        .map(|(name, value)| api::MetricPoint {
            name,
            value: value as f64,
            labels: Vec::new(),
            observed_at_unix_ms: i64::try_from(now.0).unwrap_or(i64::MAX),
        })
        .collect();
    let response = api::GetMetricsSnapshotResponse { points };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `DiagnosticsService.GetSubsystemHealth`: the core subsystems each report
/// `healthy` with their live counts (control-api.md §42). A non-empty
/// `subsystems` list filters the report by name.
fn get_subsystem_health(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let requested = match api::GetSubsystemHealthRequest::decode(request.payload.as_slice()) {
        Ok(re) => re.subsystems,
        Err(_) => return (api::StatusCode::InvalidArgument as i32, None),
    };
    let now = crate::state::wall_now();
    let all = vec![
        (
            "sessions".to_string(),
            format!("{} active", state.sessions.count()),
        ),
        (
            "relay".to_string(),
            format!("{} circuits", state.relay.circuit_count()),
        ),
        (
            "bundle".to_string(),
            format!("{} stored", state.bundle.count()),
        ),
        (
            "routing".to_string(),
            format!("{} cached routes", state.routing.cache.len()),
        ),
    ];
    let health = all
        .into_iter()
        .filter(|(subsystem, _)| requested.is_empty() || requested.contains(subsystem))
        .map(|(subsystem, summary)| api::SubsystemHealth {
            subsystem,
            state: "healthy".into(),
            summary,
            changed_at_unix_ms: i64::try_from(now.0).unwrap_or(i64::MAX),
        })
        .collect();
    let response = api::GetSubsystemHealthResponse { health };
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
            state.metrics.incr(metric_names::RELAY_CIRCUITS_OPENED, 1);
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
        Ok(()) => {
            state.metrics.incr(metric_names::RELAY_CIRCUITS_CLOSED, 1);
            (api::StatusCode::Ok as i32, None)
        }
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
        // Bundle times are wall-clock epoch ms (restart-safe): the request
        // must be stamped against the same clock the restore compares with.
        let now_ms = crate::state::wall_now().0;
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

    #[tokio::test]
    async fn bundles_survive_state_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "umcd-bundle-reopen-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let config = NodeConfig {
            data_dir: dir,
            ..NodeConfig::default()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel::<()>(1);
        let mut state = RuntimeState::new(config.clone(), tx).expect("runtime state");
        // Bundle times are wall-clock epoch ms (restart-safe): the request
        // must be stamped against the same clock the restore compares with.
        let now_ms = crate::state::wall_now().0;
        let create = api::CreateBundleRequest {
            application_handle: Some(api::OpaqueHandle {
                value: b"sender-a".to_vec(),
            }),
            destination_hint: b"dest-token".to_vec(),
            priority: 1,
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
        drop(state);

        // A fresh daemon over the same data dir restores the bundle from
        // persisted metadata (storage.md §6.3): the listing round-trips.
        let (tx2, _rx2) = tokio::sync::mpsc::channel::<()>(1);
        let mut reopened = RuntimeState::new(config, tx2).expect("reopened runtime state");
        let bytes = dispatch_request(
            &mut reopened,
            &request("BundleService", "ListBundles", vec![]),
            None,
        );
        let listing = api::ListBundlesResponse::decode(decode_response(&bytes).payload.as_slice())
            .expect("payload")
            .bundles;
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].bundle_id, created.bundle_id);
        assert_eq!(listing[0].payload_size, 10);
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

    fn register_session(state: &RuntimeState, id: u64, peer: [u8; 32]) {
        state.sessions.register(
            id,
            crate::session_manager::SessionEntry {
                peer_endpoint_id: peer,
                carrier_type: "ump.tcp/1".into(),
                task: tokio::spawn(async {}).abort_handle(),
                established_at_ms: 1_000,
            },
        );
    }

    fn route_key(n: u8) -> umc_routing::types::RouteKey {
        umc_routing::types::RouteKey {
            destination_profile: 0,
            destination_hash: [n; 32],
            scope: umc_routing::types::RouteScope::General,
            policy_class: 0,
        }
    }

    #[tokio::test]
    async fn list_sessions_round_trip() {
        let (mut state, _tx) = test_state();
        register_session(&state, state.sessions.next_id(), [7u8; 32]);
        register_session(&state, state.sessions.next_id(), [8u8; 32]);
        let bytes = dispatch_request(
            &mut state,
            &request("SessionService", "ListSessions", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let sessions = api::ListSessionsResponse::decode(response.payload.as_slice())
            .expect("payload")
            .sessions;
        assert_eq!(sessions.len(), 2);
        let first = &sessions[0];
        let handle = first
            .session_handle
            .as_ref()
            .expect("handle")
            .value
            .as_slice();
        let id = u64::from_be_bytes(handle.try_into().expect("8-byte handle"));
        assert_eq!(id, 1, "handles round-trip the session id");
        assert_eq!(first.remote_endpoint_id, [7u8; 32]);
        assert_eq!(
            first.protocol_id, "ump.tcp/1",
            "carrier rides in protocol_id"
        );
        assert_eq!(first.created_at_unix_ms, 1_000);
        assert_eq!(
            first.state,
            api::SessionState::Active as i32,
            "registry entries are active sessions"
        );
    }

    #[tokio::test]
    async fn get_session_by_handle_and_not_found() {
        let (mut state, _tx) = test_state();
        let id = state.sessions.next_id();
        register_session(&state, id, [9u8; 32]);

        let get = api::GetSessionRequest {
            session_handle: Some(api::OpaqueHandle {
                value: id.to_be_bytes().to_vec(),
            }),
        };
        let mut payload = Vec::new();
        Message::encode(&get, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("SessionService", "GetSession", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let session = api::GetSessionResponse::decode(response.payload.as_slice())
            .expect("payload")
            .session
            .expect("session");
        assert_eq!(session.remote_endpoint_id, [9u8; 32]);

        // An unknown handle is NotFound, not Ok.
        let get = api::GetSessionRequest {
            session_handle: Some(api::OpaqueHandle {
                value: 999u64.to_be_bytes().to_vec(),
            }),
        };
        let mut payload = Vec::new();
        Message::encode(&get, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("SessionService", "GetSession", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
    }

    #[test]
    fn list_routes_round_trip_from_persisted_table() {
        let (mut state, _tx) = test_state();
        // Learn a route through the routing service: it persists to the
        // node database, which is the route listing's backing table.
        let rid = [1u8; 16];
        let now = state.node.clock.as_ref().now();
        state
            .routing
            .admit_route_request(&rid, b"upstream", 0, 8, 30_000, &[], now)
            .unwrap();
        let _ =
            state
                .routing
                .record_route_response(route_key(3), rid, "hop-a".into(), 600_000, now);

        let bytes = dispatch_request(
            &mut state,
            &request("RouteService", "ListRoutes", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let routes = api::ListRoutesResponse::decode(response.payload.as_slice())
            .expect("payload")
            .routes;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination_hint_hash, [3u8; 32]);
        assert_eq!(routes[0].scope, api::RouteScope::General as i32);
        assert_eq!(
            routes[0].state, "candidate",
            "persisted routes list as candidates"
        );
        assert_eq!(routes[0].carrier_class, "hop-a");
    }

    #[test]
    fn list_peers_round_trip_from_candidate_table() {
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
            &request("PeerService", "ListPeers", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let peers = api::ListPeersResponse::decode(response.payload.as_slice())
            .expect("payload")
            .peers;
        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[0].endpoint_id,
            42u64.to_be_bytes(),
            "the candidate id is the v1 peer id"
        );
        assert_eq!(peers[0].label, "ump.udp/1");
        assert_eq!(peers[0].trust_state, api::TrustState::Observed as i32);
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
    fn get_metrics_snapshot_round_trips_registry() {
        let (mut state, _tx) = test_state();
        state
            .metrics
            .incr(crate::state::metric_names::SESSIONS_TOTAL, 3);
        state
            .metrics
            .set(crate::state::metric_names::SESSIONS_ACTIVE, 2);
        let bytes = dispatch_request(
            &mut state,
            &request("DiagnosticsService", "GetMetricsSnapshot", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let points = api::GetMetricsSnapshotResponse::decode(response.payload.as_slice())
            .expect("payload")
            .points;
        assert!(
            points
                .iter()
                .any(|p| p.name == "sessions_total" && (p.value - 3.0).abs() < f64::EPSILON),
            "sessions_total missing from snapshot: {points:?}"
        );
        assert!(
            points
                .iter()
                .any(|p| p.name == "sessions_active" && (p.value - 2.0).abs() < f64::EPSILON),
            "sessions_active missing from snapshot: {points:?}"
        );
    }

    #[test]
    fn get_metrics_snapshot_filters_by_prefix() {
        let (mut state, _tx) = test_state();
        state
            .metrics
            .incr(crate::state::metric_names::SESSIONS_TOTAL, 1);
        state
            .metrics
            .incr(crate::state::metric_names::PACKETS_RECEIVED, 5);
        let mut payload = Vec::new();
        api::GetMetricsSnapshotRequest {
            metric_prefixes: vec!["packets".into()],
        }
        .encode(&mut payload)
        .expect("encode");
        let bytes = dispatch_request(
            &mut state,
            &request("DiagnosticsService", "GetMetricsSnapshot", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let points = api::GetMetricsSnapshotResponse::decode(response.payload.as_slice())
            .expect("payload")
            .points;
        assert_eq!(points.len(), 1, "prefix filter must keep one series");
        assert_eq!(points[0].name, "packets_received");
        assert!((points[0].value - 5.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn get_subsystem_health_reports_live_counts() {
        let (mut state, _tx) = test_state();
        state.sessions.register(
            state.sessions.next_id(),
            crate::session_manager::SessionEntry {
                peer_endpoint_id: [1u8; 32],
                carrier_type: "ump.tcp/1".into(),
                task: tokio::spawn(async {}).abort_handle(),
                established_at_ms: 0,
            },
        );
        let bytes = dispatch_request(
            &mut state,
            &request("DiagnosticsService", "GetSubsystemHealth", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let health = api::GetSubsystemHealthResponse::decode(response.payload.as_slice())
            .expect("payload")
            .health;
        assert_eq!(health.len(), 4);
        for entry in &health {
            assert_eq!(entry.state, "healthy");
        }
        let sessions = health
            .iter()
            .find(|h| h.subsystem == "sessions")
            .expect("sessions subsystem");
        assert!(
            sessions.summary.contains("1 active"),
            "unexpected sessions summary: {}",
            sessions.summary
        );
    }

    #[test]
    fn get_subsystem_health_filters_by_requested_subsystem() {
        let (mut state, _tx) = test_state();
        let mut payload = Vec::new();
        api::GetSubsystemHealthRequest {
            subsystems: vec!["relay".into()],
        }
        .encode(&mut payload)
        .expect("encode");
        let bytes = dispatch_request(
            &mut state,
            &request("DiagnosticsService", "GetSubsystemHealth", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let health = api::GetSubsystemHealthResponse::decode(response.payload.as_slice())
            .expect("payload")
            .health;
        assert_eq!(health.len(), 1);
        assert_eq!(health[0].subsystem, "relay");
        assert_eq!(health[0].state, "healthy");
    }

    #[test]
    fn dispatch_counts_requests_per_service() {
        let (mut state, _tx) = test_state();
        dispatch_request(&mut state, &request("NodeAdmin", "GetStatus", vec![]), None);
        dispatch_request(
            &mut state,
            &request("DiagnosticsService", "RunDoctor", vec![]),
            None,
        );
        assert_eq!(
            state
                .metrics
                .get(crate::state::metric_names::CONTROL_REQUESTS_NODEADMIN),
            Some(1)
        );
        assert_eq!(
            state
                .metrics
                .get(crate::state::metric_names::CONTROL_REQUESTS_DIAGNOSTICS),
            Some(1)
        );
        dispatch_request(&mut state, &request("NodeAdmin", "GetStatus", vec![]), None);
        assert_eq!(
            state
                .metrics
                .get(crate::state::metric_names::CONTROL_REQUESTS_NODEADMIN),
            Some(2)
        );
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
        // The daemon uid for the peer-credential check: a file this process
        // created is owned by its own uid.
        let daemon_uid = std::os::unix::fs::MetadataExt::uid(
            &std::fs::metadata(&state.lock().expect("runtime state").config.data_dir)
                .expect("data dir metadata"),
        );
        // Fill the cap: every admitted connection holds a permit while its
        // peer end stays open.
        let mut peers = Vec::new();
        for _ in 0..MAX_CONTROL_CONNECTIONS {
            let (stream, peer) = UnixStream::pair().expect("pair");
            peers.push(peer);
            assert!(
                admit_connection(&connections, stream, state.clone(), daemon_uid),
                "connection {MAX_CONTROL_CONNECTIONS} within cap must be admitted"
            );
        }
        // The 65th connection is refused while the cap is full.
        let (stream, peer) = UnixStream::pair().expect("pair");
        assert!(
            !admit_connection(&connections, stream, state.clone(), daemon_uid),
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
        assert!(admit_connection(
            &connections,
            stream,
            state.clone(),
            daemon_uid
        ));
    }

    // --- Task F1: envelope-level protocol completion ---

    fn envelope(sequence: u64, body: api::envelope::Body) -> api::Envelope {
        api::Envelope {
            api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
            sequence,
            body: Some(body),
        }
    }

    fn request_envelope(sequence: u64, req: api::Request) -> api::Envelope {
        envelope(sequence, api::envelope::Body::Request(req))
    }

    #[test]
    fn duplicate_or_stale_envelope_sequence_is_dropped_silently() {
        let (mut state, _tx) = test_state();
        let mut conn = ConnectionState::new();
        // Sequence 1 (hello) is accepted; replaying it is a duplicate and
        // must not produce any response (control-api.md §7).
        assert!(handle_envelope(
            &mut conn,
            &mut state,
            envelope(
                1,
                api::envelope::Body::ClientHello(api::ClientHello::default())
            ),
        )
        .is_some());
        let req = request("NodeAdmin", "GetStatus", vec![]);
        assert!(handle_envelope(&mut conn, &mut state, request_envelope(2, req.clone())).is_some());
        assert!(
            handle_envelope(&mut conn, &mut state, request_envelope(2, req)).is_none(),
            "a reused sequence must be dropped silently"
        );
        assert!(
            handle_envelope(
                &mut conn,
                &mut state,
                request_envelope(1, request("NodeAdmin", "GetStatus", vec![])),
            )
            .is_none(),
            "a stale (decreasing) sequence must be dropped silently"
        );
        // Gaps are tolerated: 9 after 2 advances the tracker.
        assert!(handle_envelope(
            &mut conn,
            &mut state,
            request_envelope(9, request("NodeAdmin", "GetStatus", vec![])),
        )
        .is_some());
    }

    #[test]
    fn go_away_drains_then_rejects_new_requests() {
        let (mut state, _tx) = test_state();
        let mut conn = ConnectionState::new();
        assert!(!conn.draining);
        assert!(handle_envelope(
            &mut conn,
            &mut state,
            envelope(
                1,
                api::envelope::Body::GoAway(api::GoAway {
                    reason: api::GoAwayReason::Normal as i32,
                    ..Default::default()
                }),
            ),
        )
        .is_none());
        assert!(conn.draining, "go-away sets the draining flag");
        // New requests after GoAway fail with Unavailable (control-api.md
        // §6.4).
        let bytes = handle_envelope(
            &mut conn,
            &mut state,
            request_envelope(2, request("NodeAdmin", "GetStatus", vec![])),
        )
        .expect("draining request response");
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Unavailable as i32
        );
    }

    #[test]
    fn idempotent_replay_returns_stored_bytes_without_redispatch() {
        let (mut state, _tx) = test_state();
        let mut conn = ConnectionState::new();
        let mut req = request("NodeAdmin", "GetStatus", vec![]);
        req.idempotency_key = b"retry-key".to_vec();
        let first = handle_envelope(&mut conn, &mut state, request_envelope(1, req.clone()))
            .expect("first dispatch");
        assert_eq!(
            state
                .metrics
                .get(crate::state::metric_names::CONTROL_REQUESTS_NODEADMIN),
            Some(1)
        );
        let replay = handle_envelope(&mut conn, &mut state, request_envelope(2, req))
            .expect("replay response");
        assert_eq!(
            first, replay,
            "a replay must return the byte-identical stored response"
        );
        assert_eq!(
            state
                .metrics
                .get(crate::state::metric_names::CONTROL_REQUESTS_NODEADMIN),
            Some(1),
            "a replay must not re-dispatch"
        );
        // A different key is a fresh request.
        let mut other = request("NodeAdmin", "GetStatus", vec![]);
        other.idempotency_key = b"another-key".to_vec();
        handle_envelope(&mut conn, &mut state, request_envelope(3, other));
        assert_eq!(
            state
                .metrics
                .get(crate::state::metric_names::CONTROL_REQUESTS_NODEADMIN),
            Some(2)
        );
    }

    #[test]
    fn unauthenticated_responses_are_byte_identical_across_services() {
        let (mut state, _tx) = test_state();
        state.development_token = Some(b"dev-token".to_vec());
        let mut conn = ConnectionState::new();
        // Same request_id against a real service, a private service, and a
        // nonexistent service: byte-identical Unauthenticated responses so
        // service existence cannot be enumerated (privacy.md §68).
        let real = handle_envelope(
            &mut conn,
            &mut state,
            request_envelope(1, request("NodeAdmin", "GetStatus", vec![])),
        )
        .expect("response");
        let private = handle_envelope(
            &mut conn,
            &mut state,
            request_envelope(2, request("SessionService", "ListSessions", vec![])),
        )
        .expect("response");
        let nonexistent = handle_envelope(
            &mut conn,
            &mut state,
            request_envelope(3, request("NoSuchService", "NoSuchMethod", vec![])),
        )
        .expect("response");
        assert_eq!(
            real, private,
            "a private service must not be distinguishable"
        );
        assert_eq!(
            real, nonexistent,
            "a nonexistent service must not be distinguishable"
        );
        assert_eq!(
            decode_response(&real).status.unwrap().code,
            api::StatusCode::Unauthenticated as i32
        );
        // An invalid credential gets the identical response too.
        let hello = api::ClientHello {
            authentication: Some(api::ClientAuthentication {
                method: Some(api::client_authentication::Method::Development(
                    api::DevelopmentAuthentication {
                        token: b"wrong".to_vec(),
                    },
                )),
            }),
            ..Default::default()
        };
        handle_envelope(
            &mut conn,
            &mut state,
            envelope(4, api::envelope::Body::ClientHello(hello)),
        );
        let wrong_cred = handle_envelope(
            &mut conn,
            &mut state,
            request_envelope(5, request("NodeAdmin", "GetStatus", vec![])),
        )
        .expect("response");
        assert_eq!(
            real, wrong_cred,
            "an invalid credential must be indistinguishable"
        );
    }

    #[tokio::test]
    async fn list_sessions_paginates_with_cap_and_next_token() {
        let (mut state, _tx) = test_state();
        for _ in 0..250 {
            register_session(&state, state.sessions.next_id(), [7u8; 32]);
        }
        let mut payload = Vec::new();
        api::ListSessionsRequest {
            page: Some(api::PageRequest {
                page_size: 500,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode(&mut payload)
        .expect("encode");
        let bytes = dispatch_request(
            &mut state,
            &request("SessionService", "ListSessions", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let list = api::ListSessionsResponse::decode(response.payload.as_slice()).expect("payload");
        assert_eq!(list.sessions.len(), 100, "page_size is capped at 100");
        let page = list.page.expect("page info");
        assert_eq!(page.total_size_hint, 250);
        assert!(!page.next_page_token.is_empty(), "more pages remain");

        // Follow the token to page 2 (offset 100).
        let mut payload = Vec::new();
        api::ListSessionsRequest {
            page: Some(api::PageRequest {
                page_token: page.next_page_token,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode(&mut payload)
        .expect("encode");
        let bytes = dispatch_request(
            &mut state,
            &request("SessionService", "ListSessions", payload),
            None,
        );
        let list = api::ListSessionsResponse::decode(decode_response(&bytes).payload.as_slice())
            .expect("payload");
        assert_eq!(list.sessions.len(), 100);
        let page = list.page.expect("page info");
        assert_eq!(page.total_size_hint, 250);
        assert!(!page.next_page_token.is_empty());

        // Page 3 (offset 200) returns the remaining 50 and no next token.
        let mut payload = Vec::new();
        api::ListSessionsRequest {
            page: Some(api::PageRequest {
                page_token: page.next_page_token,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode(&mut payload)
        .expect("encode");
        let bytes = dispatch_request(
            &mut state,
            &request("SessionService", "ListSessions", payload),
            None,
        );
        let list = api::ListSessionsResponse::decode(decode_response(&bytes).payload.as_slice())
            .expect("payload");
        assert_eq!(list.sessions.len(), 50);
        assert!(list.page.expect("page info").next_page_token.is_empty());

        // A garbage token is InvalidArgument, not a silent reset.
        let mut payload = Vec::new();
        api::ListSessionsRequest {
            page: Some(api::PageRequest {
                page_token: b"garbage".to_vec(),
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode(&mut payload)
        .expect("encode");
        let bytes = dispatch_request(
            &mut state,
            &request("SessionService", "ListSessions", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::InvalidArgument as i32
        );
    }

    #[test]
    fn idempotency_cache_evicts_fifo_and_expires() {
        let mut cache = IdempotencyCache::new();
        let key = |n: u64| {
            (
                "NodeAdmin".to_string(),
                "GetStatus".to_string(),
                n.to_be_bytes().to_vec(),
            )
        };
        for i in 0..(IDEMPOTENCY_CACHE_CAP + 5) as u64 {
            cache.insert(key(i), vec![0xAA], 1_000);
        }
        assert!(
            cache.get(&key(0), 1_000).is_none(),
            "the oldest entry is evicted once the FIFO cap is exceeded"
        );
        assert!(
            cache
                .get(&key((IDEMPOTENCY_CACHE_CAP + 4) as u64), 1_000)
                .is_some(),
            "the newest entry survives"
        );
        // TTL: an entry older than 10 minutes is a miss.
        cache.insert(key(9_999), vec![0xBB], 5_000);
        assert!(cache.get(&key(9_999), 5_000 + IDEMPOTENCY_TTL_MS).is_none());
        assert!(cache
            .get(&key(9_999), 5_000 + IDEMPOTENCY_TTL_MS - 1)
            .is_some());
    }

    #[tokio::test]
    async fn os_peer_authorized_matches_daemon_uid() {
        let (stream, _peer) = UnixStream::pair().expect("pair");
        // A file this process just created is owned by its own uid, which
        // equals the uid the pair's peer reports (control-api.md §11.1).
        let dir = std::env::temp_dir().join(format!("umcd-peercred-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let own_uid =
            std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).expect("metadata"));
        assert!(os_peer_authorized(&stream, own_uid));
        assert!(
            !os_peer_authorized(&stream, own_uid ^ 1),
            "a foreign uid must be refused"
        );
    }
}
